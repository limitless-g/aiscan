# -*- coding: utf-8 -*-
"""
WSTG-SESS 会话管理（11 项）
==========================
会话是「一次登录换来的临时身份」。这类问题多数可以从不带凭据的响应里看出来：
Cookie 属性、令牌格式、是否出现在 URL、前端是否存了不该存的字段。

真正需要登录态才能判定的（会话固定、并发会话、空闲超时）走人工指引。
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from urllib.parse import urljoin

from engine.checks.base import (
    find_forms, finding_evidence, is_real_hit, ok, found, na, pending,
    probe_or_none, scan_paths, no_target_outcome,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)
from engine import recon_identity as recon_id

SESSION_COOKIE_RE = re.compile(
    r"(session|sess|sid|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|"
    r"token|auth|jwt|ticket|csrftoken|xsrf)", re.I)

# JWT 形态：三段、前两段以 eyJ 开头（Base64URL 编码的 {" 固定产出 eyJ）
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")

# 受保护端点的语义线索：这些路径「理应」要求登录，是伪造令牌回验的最佳靶子
_AUTH_ENDPOINT_RE = re.compile(
    r"/(me|whoami|self|profile|account|user|member|order|basket|cart|address|"
    r"orderhistory|dashboard)(/|$|\?)", re.I)


def _cookie_records(ctx: DetectorContext) -> list[dict[str, str]]:
    """把 Set-Cookie 拆成结构化记录。"""
    raw = ctx.root_headers.get("set-cookie", "")
    if not raw:
        # requests 会把多个 Set-Cookie 合并，退化用 cookies 列表
        names = getattr(ctx.root, "cookies", []) or []
        return [{"name": n, "raw": f"{n}=<value>"} for n in names]
    out = []
    # 粗略按逗号+关键字切分（Expires 中含逗号，需排除）
    parts = re.split(r",(?=\s*[\w\-]+\s*=)", raw)
    for p in parts:
        m = re.match(r"\s*([^=]+)=([^;]*)", p)
        if not m:
            continue
        out.append({"name": m.group(1).strip(), "raw": p.strip(),
                    "value": m.group(2).strip()})
    return out


def _attr(rec: dict[str, str], name: str) -> str:
    m = re.search(rf";\s*{name}\s*=\s*([^;]+)", rec.get("raw", ""), re.I)
    return m.group(1).strip() if m else ""


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# ======================================================================
# WSTG-SESS-01 会话管理方案
# ======================================================================
@make_auto("WSTG-SESS-01", name="会话管理方案识别与审查", tool="Cookie 与前端分析",
           risk=RISK_SAFE, evidence_kind="会话凭据实测",
           detector_ref="checks/session.py:sess01")
def sess01(ctx: DetectorContext):
    findings = []
    recs = _cookie_records(ctx)
    sess = [r for r in recs if SESSION_COOKIE_RE.search(r["name"])]

    if not sess:
        return ok(f"未在匿名响应中发现会话类 Cookie（共 {len(recs)} 个 Cookie），"
                  "会话机制需登录后确认", probes=1, evidence_kind="Cookie 清单")

    names = ", ".join(r["name"] for r in sess)
    url_session = bool(re.search(r"(?:jsessionid|phpsessid|sid)=([^&\s]+)",
                                 ctx.baseline_body, re.I))
    if url_session:
        findings.append(make_finding(
            "WSTG-SESS-01", "会话标识出现在 URL 中（URL 重写会话）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("会话标识作为 URL 参数出现，而不是只存在于 Cookie 中。"
                         "浏览器通常在禁用 Cookie 时会退化到这种模式。"),
            technical_detail=f"页面正文中出现会话参数。会话 Cookie：{names}",
            impact=("URL 会被写入浏览器历史、代理与服务端日志、Referer 头。"
                    "会话标识一旦进入这些位置，攻击者可据此直接冒用身份，无需口令。"),
            reproduction="在页面源码或响应中检索 jsessionid= / PHPSESSID= 等参数。",
            remediation=("关闭 URL 重写会话（Java：`<tracking-mode>COOKIE</tracking-mode>` 并移除 URL 分支）；"
                         "仅通过 HttpOnly Cookie 承载会话；"
                         "若历史 URL 已带过会话标识，应在服务端使该会话立即失效。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / CWE-598",
            evidence=[finding_evidence("response", f"会话 Cookie：{names}", "会话承载方式")],
            grading_basis="实测会话标识出现在 URL，定中危",
        ))

    ctx._cache["sess_cookies"] = sess
    note = f"会话类 Cookie {len(sess)} 个：{names}；URL 承载会话：{'是' if url_session else '否'}"
    return found(note, findings, probes=1, evidence_kind="会话凭据实测")


# ======================================================================
# WSTG-SESS-02 Cookie 属性
# ======================================================================
@make_auto("WSTG-SESS-02", name="Cookie 安全属性核查", tool="响应头实测",
           risk=RISK_SAFE, evidence_kind="Cookie 属性实测",
           detector_ref="checks/session.py:sess02")
def sess02(ctx: DetectorContext):
    findings = []
    recs = _cookie_records(ctx)
    if not recs:
        return no_target_outcome(ctx, "会话 Cookie（目标未下发任何凭据）", probes=1, evidence_kind="Cookie 清单")

    problems = []
    for r in recs:
        name = r["name"]
        is_session = bool(SESSION_COOKIE_RE.search(name))
        raw = r.get("raw", "")
        missing = []
        if "httponly" not in raw.lower():
            missing.append("HttpOnly")
        if "secure" not in raw.lower():
            missing.append("Secure")
        if "samesite" not in raw.lower():
            missing.append("SameSite")
        dom = _attr(r, "Domain")
        if dom.startswith(".") and dom.count(".") == 1:
            missing.append(f"Domain 过宽（{dom}，作用于全部子域）")
        if missing:
            problems.append((name, is_session, missing))

    session_problems = [p for p in problems if p[1]]
    other_problems = [p for p in problems if not p[1]]

    if session_problems:
        worst = "中危" if any(
            "HttpOnly" in p[2] or "Secure" in p[2] for p in session_problems) else "低危"
        findings.append(make_finding(
            "WSTG-SESS-02", f"会话类 Cookie 缺少安全属性（{len(session_problems)} 个）",
            ctx.target_name, endpoint=ctx.target_url,
            param=", ".join(p[0] for p in session_problems)[:200],
            severity=worst, confidence="High", evidence_level="A",
            description=("承载会话身份识别的 Cookie 没有完整设置 HttpOnly / Secure / SameSite。"
                         "这三个属性分别防的是：脚本窃取、明文截获、跨站携带。"),
            technical_detail="Cookie 属性缺失情况：\n" + "\n".join(
                f"  · {n}  缺少：{'、'.join(m)}" for n, _, m in session_problems),
            impact=("缺少 HttpOnly → 任意 XSS 都能用 document.cookie 直接读走会话，"
                    "攻击者无需口令即可冒用身份；"
                    "缺少 Secure → 明文通道或降级场景下会话可被截获；"
                    "缺少 SameSite → 跨站请求会自动携带会话，扩大 CSRF 面。"),
            reproduction=f"curl -sI {ctx.target_url} | grep -i set-cookie",
            remediation=("会话 Cookie 统一设置：\n"
                         "  Set-Cookie: SESSION=<value>; HttpOnly; Secure; SameSite=Lax; Path=/\n"
                         "若业务确需跨子域共享，用具体子域而非泛域，并配合 __Host- / __Secure- 前缀。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / OWASP ASVS 3.4",
            evidence=[finding_evidence("header", str(session_problems), "Cookie 属性")],
            grading_basis="Cookie 属性经实测确认缺失，可被 XSS / 中间人利用，定中危 / 低危",
        ))

    if other_problems:
        findings.append(make_finding(
            "WSTG-SESS-02", f"非会话 Cookie 缺少安全属性（{len(other_problems)} 个）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="信息", confidence="High", evidence_level="A",
            description="这些 Cookie 不直接承载会话，但仍建议补齐安全属性，作为纵深防御。",
            technical_detail="\n".join(f"  · {n}  缺少：{'、'.join(m)}" for n, _, m in other_problems),
            impact="影响有限，但属性齐全可避免在后续功能演进中被误用为会话载体。",
            reproduction=f"curl -sI {ctx.target_url} | grep -i set-cookie",
            remediation="所有 Cookie 默认加 HttpOnly（除确需 JS 读取的）+ Secure + SameSite。",
            compliance="OWASP ASVS 3.4",
            evidence=[finding_evidence("header", str(other_problems), "Cookie 属性")],
            grading_basis="非会话 Cookie 属性缺失，属加固建议",
        ))

    note = (f"核查 {len(recs)} 个 Cookie 的属性，会话类问题 {len(session_problems)} 个，"
            f"其他 {len(other_problems)} 个")
    return found(note, findings, probes=1, evidence_kind="Cookie 属性实测")


# ======================================================================
# WSTG-SESS-03 会话固定
# ======================================================================
@make_auto("WSTG-SESS-03", name="会话固定风险检测（匿名分支）", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="会话接受性实测",
           detector_ref="checks/session.py:sess03")
def sess03(ctx: DetectorContext):
    """匿名视角能查的部分：应用是否接受外部提供的会话标识。"""
    findings = []
    probes = 0
    sess_cookies = ctx._cache.get("sess_cookies") or [
        r for r in _cookie_records(ctx) if SESSION_COOKIE_RE.search(r["name"])]
    if not sess_cookies:
        return no_target_outcome(ctx, "会话 Cookie", probes=1, evidence_kind="无会话 Cookie")

    name = sess_cookies[0]["name"]
    # 用一个明显伪造的会话标识请求，观察是否被原样接受（回显 / 不重置）
    import requests
    forged = "aiscanfixedsession1234567890"
    try:
        ctx._client._throttle()
        r = requests.get(ctx.target_url, timeout=ctx._client.timeout, verify=False,
                         headers={**dict(ctx._client.session.headers),
                                  "Cookie": f"{name}={forged}"})
        probes += 1
        sc = r.headers.get("Set-Cookie", "")
        body = r.text or ""
        if forged in sc:
            findings.append(make_finding(
                "WSTG-SESS-03", "服务端原样接受外部提供的会话标识",
                ctx.target_name, endpoint=ctx.target_url, param=name,
                severity="高危", confidence="High", evidence_level="A",
                description=(f"提交一个自定义的会话标识后，服务器把它原样写回了 Set-Cookie。"
                             "这说明服务端不校验会话标识的来源。"
                             "若登录成功后仍沿用这个标识，就构成会话固定漏洞。"),
                technical_detail=(f"提交：Cookie: {name}={forged}\n"
                                  f"响应：Set-Cookie 中含同一值\n"
                                  f"响应头：{sc[:400]}"),
                impact=("攻击者可以预先设定一个会话标识并诱导受害者点击（通过链接注入 Cookie 或"
                        "子域写入），受害者登录后该会话即携带其身份，"
                        "攻击者用同一个标识直接进入已登录状态，无需口令。"),
                reproduction=(f"curl -si -H 'Cookie: {name}={forged}' {ctx.target_url} | grep -i set-cookie\n"
                              "# 再走一次登录流程，观察登录后会话标识是否变化"),
                remediation=("登录成功时必须**重新生成**会话标识（session ID rotation）："
                             "Java `request.changeSessionId()` / "
                             "PHP `session_regenerate_id(true)` / "
                             "框架层开启 session fixation protection。"
                             "同时拒绝接受未知的会话标识（视为无效会话）。"),
                compliance="等保2.0 安全计算环境-身份鉴别 / CWE-384",
                evidence=[finding_evidence("header", sc[:600], "会话标识回显")],
                grading_basis="实测服务端接受外部会话标识，登录后是否沿用需人工确认，"
                              "按 A 级证据定高危",
            ))
            ctx._cache["sess_fixed_probe"] = True
    except Exception:  # noqa: BLE001
        pass

    status = ("疑似会话固定（服务端接受外部会话标识，需人工确认登录后是否沿用）"
              if findings else "未发现服务端原样接受外部会话标识")
    note = f"伪造会话标识测试：{status}；会话 Cookie {name}"
    return found(note, findings, probes=probes, evidence_kind="会话接受性实测")


# ======================================================================
# WSTG-SESS-04 会话变量暴露
# ======================================================================
@make_auto("WSTG-SESS-04", name="会话信息暴露核查", tool="Cookie 与前端分析",
           risk=RISK_SAFE, evidence_kind="会话内容实测",
           detector_ref="checks/session.py:sess04")
def sess04(ctx: DetectorContext):
    findings = []
    recs = _cookie_records(ctx)
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])

    # 1) Cookie 值里直接可解码的业务信息（明文 JSON / base64 JSON）
    exposed = []
    for r in recs:
        val = r.get("value", "")
        if len(val) < 12:
            continue
        decoded = ""
        try:
            pad = val + "=" * (-len(val) % 4)
            decoded = base64.b64decode(pad).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            decoded = ""
        candidate = decoded if re.search(r"[{}\[\"]", decoded or "") else val
        if re.search(r"(user|role|admin|phone|mobile|email|id|balance|permission)",
                     candidate, re.I) and re.search(r"[:=]", candidate):
            exposed.append((r["name"], candidate[:300]))

    if exposed:
        n, sample = exposed[0]
        findings.append(make_finding(
            "WSTG-SESS-04", f"Cookie 中直接存放可读的业务信息（{n}）",
            ctx.target_name, endpoint=ctx.target_url, param=n,
            severity="中危", confidence="High", evidence_level="A",
            description=("Cookie 的值可以直接解码成业务字段（用户标识、角色、权限等）。"
                         "客户端能看到的内容，客户端就能修改。"),
            technical_detail=(f"Cookie：{n}\n解码内容（已脱敏截断）：\n{sample}"),
            impact=("① 信息泄露：攻击者从 Cookie 直接读出角色、用户 ID、权限范围；"
                    "② 篡改风险：若服务端信任 Cookie 中的角色 / 权限字段而不是重新查询，"
                    "改为管理员角色即可提权。"),
            reproduction=f"curl -sI {ctx.target_url} | grep -i set-cookie  # 解码 Cookie 值",
            remediation=("Cookie / Token 中只放随机标识，服务端按标识查会话数据；"
                         "如需携带状态，必须做完整性签名（HMAC）并在服务端二次校验权限。"),
            compliance="等保2.0 安全计算环境-访问控制 / CWE-315",
            evidence=[finding_evidence("header", sample, f"Cookie {n} 解码内容")],
            grading_basis="实测 Cookie 含可读业务信息，篡改是否生效未验证，定中危",
        ))

    # 2) 前端存储中存放敏感字段
    storage_hits = []
    for pat, desc in ((r"localStorage\.setItem\(\s*[\"'](\w*(?:token|user|role|auth|permission)\w*)",
                       "localStorage 存储认证类数据"),
                      (r"sessionStorage\.setItem\(\s*[\"'](\w*(?:token|user|role)\w*)",
                       "sessionStorage 存储认证类数据")):
        for m in re.finditer(pat, blobs, re.I):
            storage_hits.append((desc, m.group(1)))

    if storage_hits:
        findings.append(make_finding(
            "WSTG-SESS-04", f"前端持久化存储中存放认证类数据（{len(storage_hits)} 处）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("前端把令牌 / 用户角色写入 localStorage 或 sessionStorage。"
                         "这两个位置对同源的任何脚本完全开放。"),
            technical_detail="命中位置：\n" + "\n".join(
                f"  · {d}：{k}" for d, k in storage_hits[:10]),
            impact=("一旦出现 XSS（即使是一次性的、第三方组件引入的），"
                    "攻击脚本可以一行代码读走令牌，实现长期账号接管。"
                    "HttpOnly Cookie 不存在这个问题——这正是它存在的意义。"),
            reproduction="在浏览器控制台执行 localStorage 或 sessionStorage 查看存储内容。",
            remediation=("认证令牌改用 HttpOnly + Secure Cookie，不放 localStorage；"
                         "确需前端存储的只放非敏感的展示数据（如用户名）。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / OWASP ASVS 3.4",
            evidence=[finding_evidence("file", str(storage_hits[:10]), "前端存储命中")],
            grading_basis="实测前端持久化存储认证数据，配合 XSS 可致账号接管，定中危",
        ))

    note = (f"Cookie {len(recs)} 个，其中可解码业务信息 {len(exposed)} 个；"
            f"前端存储敏感项 {len(storage_hits)} 处")
    return found(note, findings, probes=1, evidence_kind="会话内容实测")


# ======================================================================
# WSTG-SESS-05 跨站请求伪造（CSRF）
# ======================================================================
@make_auto("WSTG-SESS-05", name="CSRF 防护核查", tool="表单与 Cookie 分析",
           risk=RISK_SAFE, evidence_kind="防护措施实测",
           detector_ref="checks/session.py:sess05")
def sess05(ctx: DetectorContext):
    findings = []
    forms = find_forms(ctx)
    recs = _cookie_records(ctx)
    body = ctx.baseline_body

    # 1) 表单是否有 CSRF token
    state_forms = [f for f in forms if f["method"] in ("POST", "PUT", "PATCH", "DELETE")]
    tokened, untokened = [], []
    for f in state_forms:
        if re.search(r"(csrf|xsrf|_token|authenticity_token|nonce)", f["raw"], re.I) or \
           re.search(r"(csrf|xsrf|_token)", " ".join(f["inputs"]), re.I):
            tokened.append(f["action"] or f["page"])
        else:
            untokened.append(f["action"] or f["page"])

    # 2) SameSite 防护
    samesite_ok = any("samesite" in r.get("raw", "").lower() for r in recs)

    issues = []
    if untokened:
        issues.append(f"{len(untokened)} 个写操作表单未见 CSRF token")
    if recs and not samesite_ok:
        issues.append("会话 Cookie 未设置 SameSite，跨站请求会自动携带凭据")
    if not recs:
        issues.append("匿名视角未取到会话 Cookie，SameSite 状态需登录后确认")

    if issues and (untokened or not samesite_ok):
        findings.append(make_finding(
            "WSTG-SESS-05", "CSRF 防护措施不完整",
            ctx.target_name,
            endpoint=(untokened[0] if untokened else ctx.target_url),
            method="POST",
            severity="中危" if untokened else "低危",
            confidence="Medium" if untokened else "High", evidence_level="B",
            description=("写操作缺少 CSRF 防护。攻击者可以构造一个页面，"
                         "让已登录的用户在不知情的情况下提交请求，"
                         "以用户的身份完成操作。"),
            technical_detail=("发现的问题：\n" + "\n".join(f"  · {i}" for i in issues)
                              + f"\n\n写操作表单：{len(state_forms)} 个"
                              f"（含 token {len(tokened)} 个，不含 {len(untokened)} 个）\n"
                              + (f"未见 token 的提交地址：\n"
                                 + "\n".join(f"  · {u}" for u in untokened[:10]) if untokened else "")),
            impact=("可被用于以受害者身份执行敏感操作：改密码、改绑定手机、下单、审批、"
                    "删除数据。危害取决于该操作本身——如果是改密码或改绑定手机，"
                    "等同于账号接管。"),
            reproduction=("构造一个自动提交到上述地址的 HTML 页面，"
                          "用已登录用户打开，观察请求是否被服务端接受。"),
            remediation=("① 所有写操作校验 CSRF token（同步令牌模式，与会话绑定、一次性）；"
                         "② 会话 Cookie 设置 SameSite=Lax 或 Strict；"
                         "③ 敏感操作（改密码 / 改绑定）要求二次验证；"
                         "④ 校验 Origin / Referer 作为辅助手段（不作为唯一防线）。"),
            compliance="等保2.0 安全计算环境-入侵防范 / OWASP ASVS 4.2",
            evidence=[finding_evidence("response", "\n".join(issues), "CSRF 防护核查结果")],
            grading_basis="表单层防护缺失可确证，服务端是否另有校验未实证，按 B 级定中危 / 低危",
        ))

    note = (f"写操作表单 {len(state_forms)} 个（含 token {len(tokened)}、无 token {len(untokened)}）；"
            f"SameSite：{'已设置' if samesite_ok else '未见设置'}")
    return found(note, findings, probes=1 + len(forms), evidence_kind="CSRF 防护核查")


# ======================================================================
# WSTG-SESS-06 登出功能
# ======================================================================
@make_auto("WSTG-SESS-06", name="登出功能核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="登出端点实测",
           detector_ref="checks/session.py:sess06")
def sess06(ctx: DetectorContext):
    findings = []
    body = ctx.baseline_body + "\n".join(ctx.js_result.get("bodies") or [])
    has_logout_ui = bool(re.search(r"(logout|signout|sign-out|log-out|退出登录|注销)", body, re.I))

    paths = ["logout", "signout", "sign-out", "log-out", "user/logout",
             "account/logout", "api/logout", "auth/logout", "session/logout"]
    hits = scan_paths(ctx, paths)
    probes = len(paths) + 1

    if not has_logout_ui and not hits:
        findings.append(make_finding(
            "WSTG-SESS-06", "未发现任何登出入口",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Low", evidence_level="C",
            description=("在匿名可访问的页面与前端产物中都没有找到登出入口。"
                         "注意：登出通常位于登录后的页面，本次为匿名视角，"
                         "结论需人工确认。"),
            technical_detail=f"检查范围：首页正文、{len(ctx.js_result.get('bodies') or [])} 份前端产物、"
                             f"{len(paths)} 个常见登出路径",
            impact="缺少登出会导致用户在共用终端上无法主动结束会话，会话将持续存活直到超时。",
            reproduction="使用测试账号登录后，检查是否存在登出按钮。",
            remediation="提供明确的登出入口，登出时在服务端销毁会话（而非仅清除客户端 Cookie）。",
            compliance="等保2.0 安全计算环境-身份鉴别",
            evidence=[finding_evidence("file", "未发现登出入口", "匿名视角检查")],
            grading_basis="匿名视角未见，置信度低，仅作提示",
        ))

    note = (f"前端出现登出标识：{'是' if has_logout_ui else '否'}；"
            f"常见登出路径可达 {len(hits)} 个"
            + (f"：{', '.join(list(hits)[:4])}" if hits else ""))
    return found(note, findings, probes=probes, evidence_kind="登出端点实测")


# ======================================================================
# WSTG-SESS-07 会话超时
# ======================================================================
@make_auto("WSTG-SESS-07", name="会话有效期核查", tool="Cookie 过期属性分析",
           risk=RISK_SAFE, evidence_kind="Cookie 有效期实测",
           detector_ref="checks/session.py:sess07")
def sess07(ctx: DetectorContext):
    findings = []
    recs = _cookie_records(ctx)
    sess = [r for r in recs if SESSION_COOKIE_RE.search(r["name"])]
    if not sess:
        return ok("未发现会话 Cookie，会话超时需登录后按人工指引验证", probes=1,
                  evidence_kind="无会话 Cookie")

    long_lived = []
    for r in sess:
        expires = _attr(r, "Expires")
        maxage = _attr(r, "Max-Age")
        secs = 0
        if maxage.isdigit():
            secs = int(maxage)
        elif expires:
            try:
                from email.utils import parsedate_to_datetime
                from datetime import datetime, timezone
                dt = parsedate_to_datetime(expires)
                secs = int((dt - datetime.now(timezone.utc)).total_seconds())
            except Exception:  # noqa: BLE001
                secs = 0
        if secs > 86400 * 7:
            long_lived.append((r["name"], secs))

    if long_lived:
        n, secs = long_lived[0]
        findings.append(make_finding(
            "WSTG-SESS-07", f"会话有效期过长（{n}：约 {secs // 86400} 天）",
            ctx.target_name, endpoint=ctx.target_url, param=n,
            severity="低危", confidence="High", evidence_level="A",
            description=("会话 Cookie 的有效期设置超过 7 天。"
                         "有效期越长，被窃取的会话可用时间越久。"),
            technical_detail=f"Cookie：{n}\n有效期：约 {secs} 秒（{secs / 86400:.1f} 天）",
            impact="会话被窃取（XSS、共用终端、日志泄露）后，攻击者可在整个有效期内使用，"
                   "用户改口令也不一定使该会话失效。",
            reproduction=f"curl -sI {ctx.target_url} | grep -i set-cookie",
            remediation=("会话 Cookie 使用会话级（无 Expires / Max-Age）或 ≤ 8 小时有效期；"
                         "服务端同时设置空闲超时（管理类 ≤ 15 分钟）；"
                         "「记住我」使用独立的、可吊销的长期令牌，不延长主会话。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / OWASP ASVS 3.3",
            evidence=[finding_evidence("header", f"{n} 有效期 {secs} 秒", "会话有效期")],
            grading_basis="有效期过长经实测确认，危害依赖其他前置条件，定低危",
        ))

    note = (f"会话 Cookie {len(sess)} 个，其中有效期 > 7 天的 {len(long_lived)} 个"
            "（空闲超时需登录后人工验证）")
    return found(note, findings, probes=1, evidence_kind="Cookie 有效期实测")


# ======================================================================
# WSTG-SESS-08 会话困惑
# ======================================================================
@make_auto("WSTG-SESS-08", name="多会话标识冲突检测", tool="Cookie 分析",
           risk=RISK_SAFE, evidence_kind="Cookie 清单实测",
           detector_ref="checks/session.py:sess08")
def sess08(ctx: DetectorContext):
    findings = []
    recs = _cookie_records(ctx)
    sess = [r["name"] for r in recs if SESSION_COOKIE_RE.search(r["name"])]
    # 同名不同 Path / Domain 的重复会话 Cookie
    names = [r["name"] for r in recs]
    dup = {n: names.count(n) for n in set(names) if names.count(n) > 1}

    if len(set(sess)) >= 3 or dup:
        detail = []
        if len(set(sess)) >= 3:
            detail.append(f"存在 {len(set(sess))} 个不同名的会话类 Cookie：{', '.join(sess)}")
        if dup:
            detail.append("存在同名重复 Cookie：" + ", ".join(
                f"{n} ×{c}" for n, c in dup.items()))
        findings.append(make_finding(
            "WSTG-SESS-08", "存在多套 / 重叠的会话标识",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="B",
            description=("响应中出现了多个会话类 Cookie 或同名重复 Cookie。"
                         "这通常意味着应用迁移遗留（如同时存在旧框架与新框架的会话）、"
                         "或多子系统共用域名但各自下发会话。"),
            technical_detail="\n".join(f"  · {d}" for d in detail),
            impact=("多套会话会导致行为不一致：登出只清掉一个、"
                    "旧的会话仍有效；同名不同 Path 的 Cookie 可能互相覆盖，"
                    "出现「登出后仍是登录态」的现象。"),
            reproduction=f"curl -sI {ctx.target_url} | grep -i set-cookie",
            remediation=("清理历史遗留的会话 Cookie（设置过期删除）；"
                         "同名 Cookie 统一 Path；子系统会话统一由网关管理。"),
            compliance="ISO 27001 A.8.5",
            evidence=[finding_evidence("header", "\n".join(detail), "会话 Cookie 清单")],
            grading_basis="多会话标识属实测，是否有实际危害需登录态验证，按 B 级定低危",
        ))

    note = f"识别会话类 Cookie {len(set(sess))} 个，同名重复 {len(dup)} 组"
    return found(note, findings, probes=1, evidence_kind="Cookie 清单")


# ======================================================================
# WSTG-SESS-09 会话劫持
# ======================================================================
@make_auto("WSTG-SESS-09", name="会话标识强度分析", tool="Cookie 熵值分析",
           risk=RISK_SAFE, evidence_kind="会话标识统计实测",
           detector_ref="checks/session.py:sess09")
def sess09(ctx: DetectorContext):
    findings = []
    sess = [r for r in _cookie_records(ctx) if SESSION_COOKIE_RE.search(r["name"])]
    if not sess:
        return ok("未取到会话 Cookie，无法分析标识强度（需登录后按人工指引验证）",
                  probes=1, evidence_kind="无会话 Cookie")

    weak = []
    for r in sess:
        val = r.get("value", "")
        if not val or val.startswith("<"):
            continue
        entropy = _shannon(val)
        # 长度过短或字符集过窄
        if len(val) < 24 or entropy < 3.0:
            weak.append((r["name"], len(val), round(entropy, 2)))
        # 递增 / 时间戳形态
        elif re.fullmatch(r"\d+", val) and len(val) <= 16:
            weak.append((r["name"], len(val), round(entropy, 2)))

    if weak:
        n, ln, ent = weak[0]
        findings.append(make_finding(
            "WSTG-SESS-09", f"会话标识随机性不足（{n}：长度 {ln}，熵 {ent}）",
            ctx.target_name, endpoint=ctx.target_url, param=n,
            severity="中危", confidence="Medium", evidence_level="B",
            description=("会话标识偏短或字符集偏窄，随机性不足，"
                         "存在被枚举或预测的可能。"),
            technical_detail="标识统计：\n" + "\n".join(
                f"  · {nm}  长度 {l}  香农熵 {e}" for nm, l, e in weak)
                + "\n（会话标识值本身不在报告中记录）",
            impact=("若标识可预测（如递增数字、时间戳拼接），"
                    "攻击者可按顺序猜测有效会话，直接冒用他人身份，无需口令。"),
            reproduction="连续多次获取新会话，比较长度与字符分布是否规律。",
            remediation=("会话标识使用密码学安全随机数生成器，长度 ≥ 128 位（32 字节），"
                         "由框架默认实现即可，不要自行拼接用户信息或时间戳。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / OWASP ASVS 3.2",
            evidence=[finding_evidence("header", str(weak), "会话标识统计")],
            grading_basis="标识强度不足属实测，可预测性未实证，按 B 级定中危",
        ))

    note = (f"分析 {len(sess)} 个会话标识的长度与熵值，"
            f"其中偏弱 {len(weak)} 个"
            + (f"；示例：{weak[0][0]} 长度 {weak[0][1]}、熵 {weak[0][2]}" if weak else ""))
    return found(note, findings, probes=1, evidence_kind="会话标识统计")


# ======================================================================
# WSTG-SESS-10 JSON Web Token（JWT）
#
# 2026-10-10 改造（Juice Shop 基准实测逼出来的）：
#   清单一开始就写着本项的 verify 是「脚本构造篡改令牌 + 确证服务端接受」，
#   但旧实现只做**静态结构分析** —— 把采集到的令牌解码，看 alg 字段写了什么、
#   有没有 exp。那是「疑似」，不是「证明」：alg 字段写着 none 与服务端
#   **接受** alg=none，是两件完全不同的事（基准答案表明确按半自动计分，
#   理由就是「差一步就是疑似和证明的区别」，红线 1：通过只能来自真实执行）。
#
#   本次补上真正的回验：取一条真实令牌 → 改造成 alg=none / 空签名变体 →
#   拿去访问「匿名被挡、登录可进」的受保护端点，三路对照（匿名 / 真令牌 /
#   伪造令牌）同时成立才判确证（红线 9：孤立信号不得当正面证据）。
#
#   另一处同源缺陷：旧实现在匿名视角采不到 JWT 时返回 ok()，配合适用性判定
#   「目标不具备会话」直接变成 N/A。而 SPA + JWT 型应用的根响应既不下发
#   Cookie 也不带令牌（令牌存在 localStorage 里，登录后才有）——
#   于是「这次没看见」被写成「目标没有」（红线 49 弱证据 N/A）。
#   现在采不到令牌一律判「待确认」并写明没做到的原因，不碰「通过 / N/A」。
# ======================================================================
def _b64_json(part: str) -> dict:
    """Base64URL 段 → dict。解不出来返回空（调用方按「不可解析」处理）。"""
    try:
        pad = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(pad))
    except Exception:  # noqa: BLE001
        return {}


def _b64_enc(obj: dict) -> str:
    """dict → Base64URL 段（去掉填充，与常见实现一致）。"""
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _account_tokens(ctx: DetectorContext) -> list[tuple[str, str]]:
    """从会话池取「已确认登录态」账号手上的 JWT。

    只认回验通过的登录态（`LOGIN_OK`）：没回验的凭据可能是错的，
    拿错凭据的令牌去做伪造对照，两边都会被挡，结论会变成「服务端不接受伪造」
    —— 那是假通过，比不测更糟。
    """
    try:
        from engine.sessionpool import LOGIN_OK  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, str]] = []
    for a in (getattr(ctx, "accounts", None) or []):
        if a.get("rejected") or not a.get("authorized"):
            continue
        if a.get("login_state") != LOGIN_OK:
            continue
        name = str(a.get("name") or "账号")
        for k, v in (a.get("headers") or {}).items():
            if str(k).lower() == "authorization":
                m = _JWT_RE.search(str(v))
                if m:
                    out.append((name, m.group(0)))
        for v in (a.get("cookies") or {}).values():
            m = _JWT_RE.search(str(v))
            if m:
                out.append((name, m.group(0)))
    return out


def _forge_variants(token: str) -> list[tuple[str, str]]:
    """构造伪造变体：(变体名, 令牌)。

    三个变体覆盖服务端三类典型翻车点，缺一个都可能漏掉真实可利用的实现：
      · alg_none   —— header 的 alg 改成 none、签名留空（最经典的一条）
      · sig_strip  —— 保留原 alg（多为 RS/HS），只把签名抹掉：
                      服务端若只解载荷不验签，这条照样通过
      · none_admin —— alg=none 且把载荷里的角色声明改成 admin：
                      既验「接受伪造」，也验「伪造的**权限**是否被采信」
    """
    parts = token.split(".")
    if len(parts) != 3:
        return []
    h, p, _sig = parts
    header = _b64_json(h)
    payload = _b64_json(p)
    if not header or not payload:
        return []

    out: list[tuple[str, str]] = []
    h_none = dict(header)
    h_none["alg"] = "none"
    out.append(("alg=none", f"{_b64_enc(h_none)}.{p}."))
    out.append(("抹掉签名（保留原 alg）", f"{h}.{p}."))
    p_admin = dict(payload)
    for k in ("role", "roles", "authorities", "group"):
        if k in p_admin:
            p_admin[k] = "admin" if k != "roles" else ["admin"]
    p_admin["is_admin"] = True
    p_admin["admin"] = True
    out.append(("alg=none + 载荷角色改成 admin",
                f"{_b64_enc(h_none)}.{_b64_enc(p_admin)}."))
    return out


def _auth_candidates(ctx: DetectorContext) -> list[str]:
    """受保护端点候选：会话池回验地址优先，其次语义端点，最后是常见兜底。"""
    out: list[str] = []
    for a in (getattr(ctx, "accounts", None) or []):
        vp = str(a.get("verify_path") or "").strip()
        if not vp:
            continue
        u = vp if vp.startswith("http") else urljoin(ctx.target_url, vp.lstrip("/"))
        if ctx.domain in u:
            out.append(u)
    for u in (ctx.js_result.get("urls") or []):
        if isinstance(u, str) and _AUTH_ENDPOINT_RE.search(u) and ctx.domain in u:
            out.append(u)
    for p in (ctx.fp_result.get("path_probes") or {}):
        if isinstance(p, str) and _AUTH_ENDPOINT_RE.search("/" + p.lstrip("/")):
            out.append(urljoin(ctx.target_url, p.lstrip("/")))
    for p in ("api/Users", "rest/user/whoami", "api/user/me", "api/me",
              "rest/user/authentication-details", "api/Orders"):
        out.append(urljoin(ctx.target_url, p))
    return list(dict.fromkeys(out))[:12]


def _pick_protected_endpoint(ctx: DetectorContext, account: dict,
                             probes: list[int]) -> tuple[str, dict, dict]:
    """挑一个「匿名被挡、真令牌可进」的端点 —— 伪造回验必须建在这个对照上。

    两个端点性质缺一不可：
      · 匿名能进 → 端点本就没挂权限，伪造「成功」说明不了任何问题；
      · 真令牌进不去 → 端点不是用这个令牌鉴权的，判据同样不成立。
    返回 (url, 匿名响应, 真令牌响应)；找不到返回空串。
    """
    for url in _auth_candidates(ctx):
        anon = recon_id._ident_fetch(url, None, ctx=ctx)
        probes[0] += 1
        if anon.get("err") or not recon_id._blocked_by_control(anon):
            continue
        legit = recon_id._ident_fetch(url, recon_id._ident_of(account), ctx=ctx)
        probes[0] += 1
        if legit.get("err"):
            continue
        try:
            st = int(legit.get("status") or 0)
        except (TypeError, ValueError):
            continue
        if not (200 <= st < 300) or len(legit.get("body") or "") < 50:
            continue
        return url, anon, legit
    return "", {}, {}


@make_auto("WSTG-SESS-10", name="JWT 安全性分析（含伪造回验）", tool="令牌解码与伪造回验",
           risk=RISK_STANDARD, evidence_kind="JWT 结构与伪造回验实测",
           detector_ref="checks/session.py:sess10")
def sess10(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body,
                                                                 ctx.root_headers.get("set-cookie", "")])
    tokens = set(_JWT_RE.findall(blobs))
    recs = _cookie_records(ctx)
    for r in recs:
        v = r.get("value", "")
        if v.count(".") == 2 and v.startswith("eyJ"):
            tokens.add(v)

    # ---------- 主动伪造回验（本项的真正判据，见本节头注释） ----------
    acct_tokens = _account_tokens(ctx)
    all_tokens = [(n, t) for n, t in acct_tokens] + [("匿名素材", t) for t in list(tokens)[:3]]
    forgery_note = ""
    if acct_tokens:
        account = None
        for a in (getattr(ctx, "accounts", None) or []):
            if str(a.get("name")) == acct_tokens[0][0] and not a.get("rejected"):
                account = a
                break
        if account is not None and ctx.risk_allowed(RISK_STANDARD):
            pc = [0]
            url, anon, legit = _pick_protected_endpoint(ctx, account, pc)
            probes += pc[0]
            if url:
                anon_body = anon.get("body") or ""
                anon_hash = hash(anon_body)
                legit_len = max(len(legit.get("body") or ""), 1)
                for label, forged in _forge_variants(acct_tokens[0][1]):
                    res = recon_id._ident_fetch(
                        url, {"headers": {"Authorization": f"Bearer {forged}"},
                              "cookies": {}}, ctx=ctx)
                    probes += 1
                    try:
                        st = int(res.get("status") or 0)
                    except (TypeError, ValueError):
                        continue
                    body = res.get("body") or ""
                    # 三条同时成立才算「服务端接受了伪造令牌」：
                    #   ① 2xx；② 不是被挡/弹登录页；③ 拿到的正文与匿名响应
                    #      **不同**（SPA 对任意路径都返回首页，200 不构成证据
                    #      —— 这正是 regself 实测踩过的第一个坑）
                    if (200 <= st < 300 and not recon_id._blocked_by_control(res)
                            and body and hash(body) != anon_hash
                            and len(body) >= legit_len * 0.3):
                        findings.append(make_finding(
                            "WSTG-SESS-10", "JWT 可被伪造：服务端接受篡改后的令牌",
                            ctx.target_name, endpoint=url, method="GET",
                            param="Authorization",
                            severity="严重", confidence="High", evidence_level="A",
                            description=(f"取一条真实登录令牌，改造成「{label}」后重新请求"
                                         "受保护端点，服务端**照常返回业务数据**。"
                                         "说明服务端没有校验令牌签名（或直接信任了"
                                         "令牌里自报的算法），攻击者不需要任何密钥"
                                         "就能造出任意身份的令牌。"),
                            technical_detail=(
                                f"对照端点：{url}\n"
                                f"匿名请求：HTTP {anon.get('status')}（被访问控制挡住）\n"
                                f"真实令牌：HTTP {legit.get('status')}（正常返回业务内容）\n"
                                f"伪造令牌（{label}）：HTTP {st}（同样返回业务内容）\n"
                                f"伪造令牌头部（解码后）：{_b64_json(forged.split('.')[0])}\n"
                                "（令牌完整值不写入报告）"),
                            impact=("攻击者可自造任意用户（含管理员）身份的令牌，"
                                    "绕过全部身份认证与权限校验，直接读取和操作他人数据。"
                                    "这是身份鉴别体系的完全失效。"),
                            reproduction=(
                                f"# 1) 匿名请求（应当被拒）\ncurl -i '{url}'\n"
                                f"# 2) 带真实令牌（200）\n"
                                f"# 3) 把令牌 header 的 alg 改为 none、签名置空后重放（仍 200）\n"
                                "python - <<'PY'\n"
                                "import base64, json\n"
                                "h, p, _ = '<真实令牌>'.split('.')\n"
                                "d = lambda s: json.loads(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))\n"
                                "e = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip('=')\n"
                                "hd = d(h); hd['alg'] = 'none'\n"
                                f"print(e(hd) + '.' + p + '.')\nPY"),
                            remediation=("① 服务端固定**预期算法白名单**（如只认 RS256），"
                                         "绝不接受令牌头部自报的 alg；"
                                         "② 显式拒绝 alg=none 与空签名；"
                                         "③ 每次请求都做签名校验，校验失败即 401；"
                                         "④ 权限以服务端查库结果为准，不采信令牌载荷里的角色声明。"),
                            compliance="等保2.0 安全计算环境-身份鉴别 / OWASP ASVS 3.5 / CWE-347",
                            evidence=[finding_evidence(
                                "response",
                                f"伪造令牌（{label}）→ HTTP {st}\n正文前 400 字：\n{body[:400]}",
                                f"伪造回验 {url}")],
                            grading_basis=("三路对照实测：匿名被挡、真令牌可进、伪造令牌同样可进，"
                                           "证据级 A，定严重"),
                        ))
                        break
                if not findings:
                    forgery_note = (f"；伪造回验：对 {url} 试了 3 种篡改变体"
                                    f"（alg=none / 抹签名 / 改角色），服务端全部拒绝")
            else:
                forgery_note = ("；伪造回验未建立对照：本次没能找到「匿名被挡、"
                                "登录可进」的受保护端点，判据不成立，本项不判通过")
        else:
            forgery_note = "；伪造回验未执行（当前档位不允许发起身份对照请求）"
    elif not tokens:
        # 采不到令牌时绝不能写「通过」，也不能写「不适用」——
        # SPA + JWT 型应用的令牌只在登录后出现，匿名视角看不见是**常态**
        # （红线 49：弱证据 N/A 不得擦掉此前已确证的发现，也不得冒充结论）。
        cookie_session = any(
            (a.get("cookies") or {}) for a in (getattr(ctx, "accounts", None) or [])
            if not a.get("rejected"))
        if cookie_session:
            return na("目标使用 Cookie 会话、本次未发现任何 JWT 令牌，本项不适用",
                      probes=probes or 1, evidence_kind="无 JWT 令牌")
        return pending("本次未取到 JWT 令牌（未登录或令牌未出现在已采集素材中），"
                       "**未做伪造回验** —— 本项不能判通过。补齐方式：提供授权测试账号"
                       "（或由红队自取注册）后重扫",
                       probes=probes or 1, evidence_kind="未取到令牌")

    # 伪造回验确证即收口：静态特征（弱算法、缺 exp）在「已被证明可伪造」面前
    # 是更弱的证据，同时列两条会让读者分不清哪条才是真正的判据。
    if findings:
        return found("伪造回验确证：服务端接受了篡改后的令牌（可伪造任意身份）",
                     findings, probes=probes, evidence_kind="JWT 伪造回验实测")

    issues = []
    parsed_any = False
    for tok in (list(tokens)[:3] + [t for _n, t in acct_tokens[:2]]):
        try:
            h_b64, p_b64, sig = tok.split(".")
            pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
            header = json.loads(base64.urlsafe_b64decode(pad(h_b64)))
            payload = json.loads(base64.urlsafe_b64decode(pad(p_b64)))
            parsed_any = True
        except Exception:  # noqa: BLE001
            continue
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            issues.append(("alg=none 被接受", "令牌可被完全伪造，无需任何密钥"))
        if alg in ("hs256", "hs384", "hs512"):
            issues.append((f"使用对称算法 {alg.upper()}",
                           "密钥若为弱口令可被离线爆破；若服务端同时接受 RS256 公钥当 HMAC 密钥"
                           "（算法混淆），可伪造任意令牌"))
        if not sig:
            issues.append(("签名为空", "令牌未签名"))
        if "exp" not in payload:
            issues.append(("缺少 exp 声明", "令牌永不过期，泄露后长期可用"))
        for claim in ("role", "admin", "is_admin", "permissions", "user_id", "tenant"):
            if claim in payload:
                issues.append((f"载荷含权限相关声明 {claim}",
                               "若服务端直接信任该字段而非查库校验，改字段即可提权"))
        if isinstance(payload.get("exp"), (int, float)):
            import time
            if payload["exp"] - time.time() > 86400 * 30:
                issues.append(("有效期超过 30 天", "令牌泄露后可用时间过长"))

    if issues:
        seen = set()
        uniq = []
        for name, why in issues:
            if name in seen:
                continue
            seen.add(name)
            uniq.append((name, why))
        findings.append(make_finding(
            "WSTG-SESS-10", f"JWT 使用存在 {len(uniq)} 处安全问题",
            ctx.target_name, endpoint=ctx.target_url, param="Authorization / Cookie",
            severity="高危" if any("none" in n or "对称算法" in n for n, _ in uniq) else "中危",
            confidence="High" if parsed_any else "Medium", evidence_level="A" if parsed_any else "B",
            description="对采集到的 JWT 做结构分析，发现以下与安全实现相关的特征。",
            technical_detail="发现的问题：\n" + "\n".join(f"  · {n}  —— {w}" for n, w in uniq)
                             + "\n（令牌完整值不在报告中记录）",
            impact=("alg 相关配置不当可导致令牌被伪造，攻击者可直接生成任意用户"
                    "（含管理员）身份的令牌；"
                    "载荷含权限声明且服务端信任时，改字段即可提权；"
                    "缺少 exp 会让泄露的令牌永久有效。"),
            reproduction="取一条令牌，Base64 解码其 header 与 payload，核对 alg 与 exp 字段。",
            remediation=("① 服务端固定预期算法（白名单），拒绝 alg=none；"
                         "② 优先 RS256 / ES256，密钥长度达标；"
                         "③ 必带 exp（≤ 2 小时）与 iat，配置刷新令牌独立管控；"
                         "④ 权限不从令牌载荷直接采信，每次请求查库或缓存校验；"
                         "⑤ 令牌放 HttpOnly Cookie，不放 localStorage。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / OWASP ASVS 3.5",
            evidence=[finding_evidence("token", "\n".join(f"{n} | {w}" for n, w in uniq),
                                       "JWT 结构分析")],
            grading_basis="令牌结构经实测解码确认，伪造可行性依赖服务端实现，定高危 / 中危",
        ))

    if findings:
        note = (f"采集到 {len(tokens)} 个 JWT，结构分析发现 "
                f"{len(findings[0].technical_detail.splitlines()) - 1} 处特征")
    else:
        note = f"采集到 {len(tokens)} 个 JWT，未发现明显配置问题"
    # 伪造回验的结果必须挂在结论里：只写静态分析会让人以为「验过了」。
    return found(note + forgery_note, findings,
                 probes=probes or 1, evidence_kind="JWT 结构与伪造回验实测")


# ======================================================================
# WSTG-SESS-11 并发会话
# ======================================================================
@make_manual(
    "WSTG-SESS-11", name="并发会话控制测试",
    procedure=("⚠️ 使用同一个测试账号在两台设备 / 两个浏览器上操作。\n"
               "1) 账号 A 在浏览器 1 登录，保持登录态；\n"
               "2) 用同一账号在浏览器 2 登录，回到浏览器 1 检查是否仍可操作；\n"
               "3) 判断策略属于哪一种：\n"
               "   a. 允许并发（多端同时在线）→ 需确认是否有登录通知与在线设备列表；\n"
               "   b. 后登录踢前者（互踢）→ 确认被踢方是否收到提示；\n"
               "   c. 后登录被拒绝 → 确认提示是否泄露账号已被占用；\n"
               "4) 登出后检查其他端是否同步失效；\n"
               "5) 改口令后检查所有端是否全部失效（应当全部失效）。"),
    expect="存在明确的并发策略；用户可查看与管理在线设备；"
           "改口令与登出后全部会话失效；无策略时至少要有登录通知与异常登录告警。",
    why_manual="需要同一账号的多次真实登录与多端状态交叉观察，匿名视角无法判定。",
    requires=["测试账号"], risk=RISK_STANDARD, tool="人工核查",
    recon=recon_id.recon_sess11,
)
def _sess11(ctx: DetectorContext):  # pragma: no cover
    return ok("")
