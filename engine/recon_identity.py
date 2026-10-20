# -*- coding: utf-8 -*-
"""
ATHN / SESS / CRYP 人工项的自动前置侦察
==========================================
这三类里有一部分检查项**必须**人工执行（认证与锁定的真伪、并发策略、padding
oracle），但「必须人工」不等于「全推给人」。真正该人做的只有最后那一个判断；
在这之前有一大堆枯燥准备活是可以自动做的：

    · 找登录 / 重置 / 改密接口在哪（不要人肉翻源码）
    · 记录表单字段名、是否要求原密码、token 走 GET 还是 POST
    · 盘点现有防护（验证码 / 限流头 / 锁定策略文案）
    · 定位候选密文参数并判定是否可做只读差分

把这些做掉之后，人工接手时看到的是「接口是这个、字段是这些、已排除这些」，
而不是「请从零开始测」。

本模块与 engine.business 的侦察层同构（返回 ReconOutcome，三态读法一致），
区别只在侦察内容。三态仍严格区分：
  ① 侦察确证问题 → 该项「不通过」；
  ② 侦察跑了但没确证 → 仍是「待人工执行」；
  ③ 侦察没跑起来 → 仍是「待人工执行」，**显式写出原因**。

━━ 红线（本模块里最容易被违反的一条）━━
认证类侦察**绝不尝试真实登录爆破**。触发锁定、触发重置短信 / 邮件都会对真实
账号与真实用户产生副作用，属「必须人工且必须在受控环境做」的范畴。
因此本模块只做两件事：
  · 对**匿名可见**的页面做静态分析；
  · 对**已登记授权的测试账号**做已经授权的最小动作（如再登录一次以观察并发会话）。
未经授权的账号、以及任何「用不存在 / 真实用户名试一次」的探测，一律不做，
并在 note 里写明没做的原因 —— 沉默的缺失会被读成「已经查过了」。
"""

from __future__ import annotations

import base64
import binascii
import random
import re
import string
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.registry import (  # noqa: E402
    RISK_DEEP,
    RISK_STANDARD,
    DetectorContext,
    ReconOutcome,
    make_finding,
)
from engine.checks.base import finding_evidence  # noqa: E402

# 登录 / 认证 / 重置相关路径候选。只做 GET，且只用它们定位入口。
AUTH_PATHS = (
    "login", "signin", "sign-in", "user/login", "users/sign_in", "account/login",
    "admin/login", "manage/login", "passport/login", "auth/login", "sso/login",
    "logon", "session/new", "portal/login", "console/login",
)
RESET_PATHS = (
    "forgot", "forgot-password", "password/forgot", "password/reset",
    "user/forgot", "account/reset", "reset", "resetpassword", "retrieve",
    "password/find", "account/recover", "users/password/new",
)
CHANGE_PWD_PATHS = (
    "profile/password", "user/password", "account/password", "settings/password",
    "password/change", "changepwd", "member/password", "security/password",
)
SECURITY_Q_HINTS = ("安全问题", "密保", "security question", "secret question",
                    "找回问题", "密保问题")

# 反自动化控制的静态特征。只做「页面上看得见什么」的判断，
# 不去实际触发它们 —— 触发的代价是锁定真实账号。
_ANTIBOT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("图形验证码", r"captcha|verifycode|verify_code|checkcode|kaptcha|"
                   r"validatecode|authcode|图形验证码|验证码"),
    ("行为式验证", r"geetest|gt-manual|gecaptcha|smartcaptcha|captcha-container|"
                   r"turnstile|hcaptcha|recaptcha|行为验证|滑块"),
    ("短信验证码", r"smscode|sms_code|mobilecode|短信验证码|手机验证码"),
    ("一次性口令", r"otp|totp|one-?time|动态口令|谷歌验证|authenticator"),
    ("滑动 / 点选", r"slider|puzzle|clickverify|点选|滑动验证"),
)
# 限流 / 锁定相关的响应头。注意：**只读**观察，不构造触发条件。
_RATELIMIT_HEADERS = (
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "retry-after",
)
_LOCKOUT_TEXT = re.compile(
    r"连续\s*\d+\s*次|错误\s*\d+\s*次|已达上限|账号已锁定|账户已锁定|"
    r"锁定\s*\d+\s*分钟|try again in|too many (?:failed )?attempts|"
    r"account (?:is )?locked|temporarily locked", re.I)

# 密文候选：Base64 / 十六进制长串。长度门槛用来避开普通 ID 与短 token。
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

# ----------------------------------------------------------------------
# ATHZ-03（垂直越权）/ EXT-DP-03（导出越界）的候选特征
# ----------------------------------------------------------------------
# 管理 / 高权限语义的路径特征。只用来从**已采集素材**里挑出「值得做权限比对」
# 的端点 —— 挑对象而已，不承担任何授权判定。
_ADMIN_SEMANTIC = re.compile(
    r"(?:^|[/_\-.])(?:admin|administrator|manage|manager|management|console|"
    r"backend|backstage|dashboard|system|sys|internal|superuser|role|roles|"
    r"permission|permissions|authz|grant|audit|setting|settings|config|"
    r"batch|export|report|userlist|user_list)(?:[/_\-.]|$)", re.I)

# 角色名 → 权限序。**只用于从多个测试身份里挑出最低权的那个**，
# 不参与任何「是否越权」的判定 —— 判定靠的是两条客观事实
# （匿名被挡 + 低权 2xx），与角色叫什么名字无关。
_ROLE_RANK: dict[str, int] = {
    "guest": 0, "visitor": 0, "游客": 0, "匿名": 0, "匿名用户": 0, "public": 0,
    "user": 10, "normal": 10, "member": 10, "customer": 10, "client": 10,
    "普通用户": 10, "会员": 10, "客户": 10, "业务员": 15, "sales": 15,
    "staff": 20, "employee": 20, "员工": 20, "operator": 20, "运营": 20,
    "manager": 30, "leader": 30, "主管": 30, "经理": 30, "组长": 30,
    "admin": 90, "administrator": 90, "管理员": 90, "后台管理员": 90,
    "superadmin": 99, "super": 99, "root": 99, "超级管理员": 99,
}

# 导出 / 下载类端点的路径语义。
_EXPORT_SEMANTIC = re.compile(
    r"(?:^|[/_\-.])(?:export|exports|download|downloads|dump|backup|extract|"
    r"report|reports|invoice|invoices|statement|exportdata|export_data|"
    r"batchdownload|导出|下载)(?:[/_\-.]|$)", re.I)

# 导出类响应的 Content-Type 特征。**这是「导出越界」唯一的区分力所在**：
# 导出接口与普通页面同样返回 200，只看状态码分不出「拿到的是一份数据文件」
# 还是「一张 HTML 页面」。缺了它，判定就只剩下「200 = 有东西」这一句空话。
_EXPORT_CT = (
    "spreadsheet", "ms-excel", "csv", "xlsx", "xls",
    "octet-stream", "zip", "pdf", "vnd.ms", "officedocument",
    "json", "xml", "text/plain",
)


# ======================================================================
# 通用小工具
# ======================================================================
def _attr(obj: object, name: str, default: object = "") -> object:
    """同时兼容 HttpProbe 对象与自测用的 dict 替身。"""
    if obj is None:
        return default
    if isinstance(obj, dict):
        v = obj.get(name, default)
    else:
        v = getattr(obj, name, default)
    return default if v is None else v


def _txt(probe: object) -> str:
    return str(_attr(probe, "body_snippet", "") or "")


def _status(probe: object) -> int:
    try:
        return int(_attr(probe, "status", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _hdrs(probe: object) -> dict[str, str]:
    h = _attr(probe, "headers", {}) or {}
    if not isinstance(h, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in h.items()}


def _reachable(probe: object) -> bool:
    return _status(probe) > 0 and not _attr(probe, "error", "")


def _is_login_page(text: str, url: str = "") -> bool:
    t = (text or "").lower()
    if re.search(r'type\s*=\s*["\']password["\']', t):
        return True
    if "password" in url.lower() or "login" in url.lower():
        return bool(re.search(r'name\s*=\s*["\'][^"\']*(pass|pwd)', t))
    return False


def _forms(text: str) -> list[dict[str, object]]:
    """粗粒度表单提取。刻意用正则而非 bs4 —— 运行环境没有 bs4。

    只取到「这个表单有哪些字段」这一层，够用来判断
    「有没有要求原密码」「有没有验证码字段」。
    """
    out: list[dict[str, object]] = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", text or "",
                         re.S | re.I):
        attrs, inner = m.group(1), m.group(2)
        action = ""
        am = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        if am:
            action = am.group(1)
        method = "get"
        mm = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        if mm:
            method = mm.group(1).lower()
        fields: list[str] = []
        for im in re.finditer(r"<input\b([^>]*)>", inner, re.I):
            a = im.group(1)
            nm = re.search(r'name\s*=\s*["\']([^"\']*)["\']', a, re.I)
            if nm:
                fields.append(nm.group(1))
        out.append({"action": action, "method": method, "fields": fields,
                    "html": inner})
    return out


def _antibot_controls(text: str, headers: dict[str, str]) -> tuple[list[str], list[str]]:
    """返回（已检出的控制项, 检出依据）。纯静态识别，不触发任何验证。"""
    t = (text or "").lower()
    hits: list[str] = []
    for label, pat in _ANTIBOT_PATTERNS:
        if re.search(pat, t, re.I):
            hits.append(label)
    for h in _RATELIMIT_HEADERS:
        if h in headers:
            hits.append(f"限流响应头 {h}: {headers[h][:40]}")
    lm = _LOCKOUT_TEXT.search(text or "")
    if lm:
        hits.append(f"页面披露锁定策略（命中「{lm.group(0)[:24]}」）")
    return hits, []


def _probe_paths(ctx: DetectorContext, paths: tuple[str, ...]) -> dict[str, object]:
    """批量探查候选路径，返回「命中的路径 → 探针」。

    安全档不执行：一次十几条路径的批量探测与安全档「最低干扰」的定义冲突。
    档位不足时返回空字典，由调用方转成 ran=False + 原因，
    报告上会显示「侦察未执行」而不是一份空清单。
    """
    if not ctx.risk_allowed(RISK_STANDARD):
        return {}
    try:
        got = ctx.probe_many(list(paths))
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, object] = {}
    for p, pr in (got or {}).items():
        st = _status(pr)
        # 只认「确实由应用处理并返回了内容」的响应。
        # 3xx/401/403 一律不算入口 —— 前者是跳转、后者可能是整站统一拦截，
        # 拿它们当「找到了登录页」会让人工按照错误的对象去测。
        if st == 200 and len(_txt(pr)) > 40:
            out[p] = pr
    return out


def _cfg(ctx: DetectorContext) -> tuple[bool, list[dict]]:
    """是否允许做需要测试账号的动作，以及可用账号列表。

    「可用」的判据必须与 `SessionPool.authenticated_pairs()` 用的是**同一个常量**。
    这里曾经写死字面量 `login_state == "ok"`，而状态实际取值是「已登录」——
    条件恒为假，等于「凭据配好了也永远当作没有账号」：认证类检查项会永远
    显示「无可用测试账号」，看起来像目标不支持，实际是自己把账号全滤掉了。
    """
    from engine.sessionpool import LOGIN_OK  # noqa: PLC0415

    accounts = [a for a in (getattr(ctx, "accounts", None) or [])
                if not a.get("rejected")]
    authorized = [a for a in accounts
                  if a.get("authorized") and a.get("login_state") == LOGIN_OK]
    return bool(authorized), authorized


def _manual_only(reason: str, extra: str = "") -> ReconOutcome:
    return ReconOutcome(ran=False, error=reason,
                        note=(extra + "\n" if extra else ""))


def _no_entry(ctx: DetectorContext, tried: int, what: str) -> ReconOutcome:
    """没找到入口时的原因必须分清「档位不足」与「真的没有」。

    两者都报 ran=False，但原因不同 —— 前者补档位就能跑，后者说明目标
    压根没有这个入口。写混了会让人在错误的方向上排查。
    """
    if not ctx.risk_allowed(RISK_STANDARD):
        return _manual_only(
            f"当前档位不允许批量路径探测（{what}），本次未执行 —— "
            f"提到 standard 档后即可自动完成")
    return _manual_only(f"未探测到匿名可达的{what}（已试 {tried} 条常见路径，"
                        f"均非 200 且含内容）")


# ----------------------------------------------------------------------
# ATHZ-03 / EXT-DP-03 共用的支撑函数
# ----------------------------------------------------------------------
def _role_rank(role: str) -> int:
    """角色名 → 权限序。未知角色给 50（居中），宁可挑偏中间的也不乱挑。"""
    r = (role or "").strip().lower()
    if not r:
        return 50
    if r in _ROLE_RANK:
        return _ROLE_RANK[r]
    best: int | None = None
    for k, v in _ROLE_RANK.items():
        if k in r:
            best = v if best is None else min(best, v)
    return 50 if best is None else best


def _lowest_privileged(accounts: list[dict]) -> dict:
    """挑出权限最低的可用测试身份。

    越权结论只由「同一条 URL 的两次对照请求」构成；挑最低权只是让这个对照
    更敏感 —— 低权都能进，说明端点压根没按角色校验。
    """
    return min(accounts, key=lambda a: _role_rank(str(a.get("role") or "")))


def _ident_of(account: dict) -> dict:
    """把会话池账号记录裁成 `sessionpool._fetch` 认的形状。"""
    return {"headers": dict(account.get("headers") or {}),
            "cookies": dict(account.get("cookies") or {})}


def _ident_fetch(url: str, account: dict | None = None, ctx: object = None) -> dict:
    """发一次带（或不带）身份的 GET，返回 `sessionpool._fetch` 的字典。

    刻意复用 `sessionpool._fetch`：它已经把「被弹回认证页 / 401 / 403 /
    含登录表单」四种表现归一化好了，另写一份必然与回验逻辑漂移。
    `account=None` 即**对照请求**（不带任何凭据）。
    """
    try:
        from engine.sessionpool import _fetch  # noqa: PLC0415
    except Exception as e:  # noqa: BLE001
        return {"err": f"sessionpool 不可用：{type(e).__name__}", "status": 0}
    try:
        res = _fetch(url, account, 12)
    except Exception as e:  # noqa: BLE001
        return {"err": f"{type(e).__name__}: {str(e)[:100]}", "status": 0}
    # 身份请求走的是 sessionpool 自己的通道，绕开了 ctx 的守门；这里补喂一次，
    # 免得在拦截页上跑完一整轮比对却没人发现边界已经封了。
    if ctx is not None and res.get("status"):
        try:
            feed = getattr(ctx, "_feed_guard", None)
            if callable(feed):
                feed(url, {"status": res.get("status"),
                           "body_snippet": res.get("body", "")})
        except Exception:  # noqa: BLE001
            pass
    return res


def _blocked_by_control(res: dict) -> bool:
    """这次响应是否表示「服务端按访问控制挡住了这个身份」。"""
    try:
        st = int(res.get("status") or 0)
    except (TypeError, ValueError):
        st = 0
    return bool(res.get("denied")) or bool(res.get("bounced")) or st in (401, 403)


def _ok_body(res: dict, min_len: int = 200) -> bool:
    """这次响应是否表示「确实拿到了业务内容」。"""
    try:
        st = int(res.get("status") or 0)
    except (TypeError, ValueError):
        st = 0
    if st < 200 or st >= 300:
        return False
    if res.get("bounced") or res.get("login_form"):
        return False
    return len(str(res.get("body") or "")) >= min_len


def _sitewide_denies(ctx: object) -> tuple[int, float, int]:
    """整站是否「对任意路径返回同一个 401/403/405」。

    红线：这类状态码只有在**不是整站同码**时才可作为「该路径受保护 / 存在」
    的证据。命中时调用方必须直接转「待确认」，既不报有也不报无。
    """
    try:
        from engine.checks.base import sitewide_guard  # noqa: PLC0415

        st, ratio, n = sitewide_guard(ctx)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        return 0, 0.0, 0
    return int(st or 0), float(ratio or 0.0), int(n or 0)


def _same_host(base: str, url: str, domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    d = (domain or "").lower()
    if not host or not d:
        return False
    return host == d or host.endswith("." + d)


def _pick_semantic_urls(ctx: DetectorContext, pattern: re.Pattern[str],
                        limit: int) -> list[str]:
    """按路径语义从**已采集素材**里挑候选端点。**不额外发请求。**

    来源两类：前端产物地址、以及指纹阶段的路径探测结果。
    挑不出来就如实报「无对象可比对」—— 盲目枚举一堆路径会把请求量打上去，
    而且在有边界防护的目标上等于帮对方把封禁坐实。
    """
    out: list[str] = []
    seen: set[str] = set()
    target_url = str(_attr(ctx, "target_url", "") or "")
    domain = str(_attr(ctx, "domain", "") or "")

    def _push(u: str) -> None:
        if not u or u in seen:
            return
        full = u if u.startswith("http") else urljoin(target_url, u)
        if not _same_host(target_url, full, domain):
            return
        if not pattern.search(urlparse(full).path or ""):
            return
        seen.add(u)
        out.append(full)

    for u in (getattr(ctx, "js_result", None) or {}).get("urls") or []:
        if isinstance(u, str):
            _push(u)

    for p, pr in ((getattr(ctx, "fp_result", None) or {}).get("path_probes")
                  or {}).items():
        st = pr.get("status") if isinstance(pr, dict) else None
        if st in (0, None, 404):
            continue
        _push("/" + str(p).lstrip("/"))

    return out[:limit]


def _admin_candidates(ctx: DetectorContext, limit: int = 10) -> list[str]:
    """疑似管理 / 高权限端点。"""
    return _pick_semantic_urls(ctx, _ADMIN_SEMANTIC, limit)


def _export_candidates(ctx: DetectorContext, limit: int = 8) -> list[str]:
    """疑似导出 / 下载端点。"""
    return _pick_semantic_urls(ctx, _EXPORT_SEMANTIC, limit)


# ======================================================================
# WSTG-ATHN-03 登录锁定机制测试
# ======================================================================
def recon_athn03(ctx: DetectorContext) -> ReconOutcome:
    """定位登录入口 + 静态盘点现有反自动化控制。

    **不做**重复失败登录：那会锁定真实账号（业务副作用），
    「锁定是否真的触发、阈值是多少」只能由人工在受控环境用测试账号做。
    """
    logins = _probe_paths(ctx, AUTH_PATHS)
    if not logins:
        return _no_entry(ctx, len(AUTH_PATHS), "登录入口")

    lead: list[str] = []
    parts: list[str] = []
    findings: list[Any] = []
    for path, pr in logins.items():
        url = str(_attr(pr, "url", path))
        text = _txt(pr)
        headers = _hdrs(pr)
        controls, _ = _antibot_controls(text, headers)
        forms = _forms(text)
        pwd_forms = [f for f in forms
                     if re.search(r"pass|pwd", " ".join(f["fields"]), re.I)]
        lead.append(f"登录入口 `{url}`（状态 {_status(pr)}，"
                    f"表单 {len(forms)} 个，含口令字段的表单 {len(pwd_forms)} 个）")
        if pwd_forms:
            for f in pwd_forms[:2]:
                lead.append(f"　· 表单字段：{'、'.join(f['fields'][:12])}"
                            f"　method={f['method']}")
        if controls:
            lead.append(f"　· 已检出的反自动化控制：{'；'.join(controls)}")
        else:
            lead.append("　· 静态未检出任何反自动化控制（无验证码字段、"
                        "无限流响应头、页面未披露锁定策略）—— **这是高危信号**")
        parts.append(f"[{url}] 反自动化控制静态盘点："
                     + ("、".join(controls) if controls else "无"))

        # 只有「登录页上什么都没有」才够格直接下结论 ——
        # 反过来说，页面上有验证码**不等于**锁定机制到位，所以不能反向判通过。
        if not controls and pwd_forms:
            findings.append(make_finding(
                "WSTG-ATHN-03", "登录入口未部署任何反自动化控制（可无限次尝试）",
                str(_attr(ctx, "target", "") or ""), endpoint=url,
                method="GET", severity="中危", confidence="Medium",
                evidence_level="B",
                description=("登录页面上未发现验证码字段、未返回任何限流响应头、"
                             "也未披露锁定策略。攻击者可对同一账号持续尝试口令，"
                             "不存在任何服务端可见的阻拦信号。"),
                technical_detail=f"命中路径：{path}；表单字段："
                                 f"{pwd_forms[0]['fields'][:12]}；"
                                 f"响应头仅 {len(headers)} 项，无 X-RateLimit-* / Retry-After",
                impact="为口令爆破与撞库提供无摩擦入口；"
                       "若账号体系无强口令策略，可导致账号被接管。",
                reproduction=(f"1) 匿名 GET {url}，确认返回登录表单且无验证码字段；\n"
                              "2) 检查响应头，确认无 X-RateLimit-* / Retry-After；\n"
                              "3) 页面上未出现任何锁定策略描述。\n"
                              "（本次**未**做重复失败登录 —— 那会锁定真实账号。"
                              "「阈值是多少、多久解锁」仍需人工在受控环境确认。）"),
                remediation=("在登录接口前置验证码或行为验证；对同账号 + 同源 IP 的"
                             "失败计数做服务端限流与渐进延迟；连续失败达阈值后锁定"
                             "并通知账号持有人。"),
                compliance="等保2.0 身份鉴别 / OWASP ASVS V2.2",
                grading_basis="静态特征实测（登录页 + 响应头 + 页面文案）",
            ))

    note = "\n".join(parts)
    note += ("\n\n⚠ 本次**未执行**重复失败登录尝试：触发锁定属于对真实账号的"
             "业务副作用（可能导致该账号被锁、触发告警），必须由人工用测试账号"
             "在受控环境执行。因此「锁定阈值 / 解锁方式 / 锁定粒度（账号 or IP）"
             "」三项仍无结论。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=len(AUTH_PATHS))


# ======================================================================
# WSTG-ATHN-08 密保问题安全性测试
# ======================================================================
def recon_athn08(ctx: DetectorContext) -> ReconOutcome:
    """定位找回流程 + 静态盘点密保问题与防枚举控制。

    **不做**「用某个用户名试一次」的探测：那会给真实账号触发重置短信 / 邮件，
    属于副作用。账号枚举是否存在只能由人工判断或由已授权测试账号验证。
    """
    pages = _probe_paths(ctx, RESET_PATHS)
    if not pages:
        return _no_entry(ctx, len(RESET_PATHS), "找回 / 重置入口")

    lead: list[str] = []
    parts: list[str] = []
    findings: list[Any] = []
    for path, pr in pages.items():
        url = str(_attr(pr, "url", path))
        text = _txt(pr)
        headers = _hdrs(pr)
        controls, _ = _antibot_controls(text, headers)
        lead.append(f"找回入口 `{url}`（状态 {_status(pr)}）")
        qs: list[str] = []
        for m in re.finditer(r"<select\b[^>]*>(.*?)</select>", text, re.S | re.I):
            for om in re.finditer(r"<option\b[^>]*>([^<]{2,80})</option>",
                                  m.group(1), re.I):
                qs.append(om.group(1).strip())
        qs = [q for q in qs if any(h in q.lower() or h in q
                                   for h in ("?", "？"))] or qs
        if qs:
            lead.append("　· 页面上直接可见的密保问题候选："
                        + "；".join(qs[:8]))
        else:
            hint = next((h for h in SECURITY_Q_HINTS
                         if h.lower() in text.lower()), "")
            lead.append("　· 页面上未见问题清单"
                        + (f"（命中提示词「{hint}」）" if hint else ""))
        lead.append("　· 反枚举 / 反自动化控制："
                    + ("、".join(controls) if controls else "静态未检出"))
        parts.append(f"[{url}] 密保问题静态盘点："
                     + (f"候选问题 {len(qs)} 条" if qs else "未暴露问题清单"))

        weak = [q for q in qs if _weak_question(q)]
        if weak:
            findings.append(make_finding(
                "WSTG-ATHN-08", "密保问题可被公开信息猜中（弱问题）",
                str(_attr(ctx, "target", "") or ""), endpoint=url, method="GET",
                severity="中危", confidence="Medium", evidence_level="C",
                description=("找回流程使用基于公开信息的密保问题。此类问题的答案"
                             "通常能通过社交资料、公开档案或有限次猜测得到，"
                             "相当于给口令找回留了一条弱于口令本身的旁路。"),
                technical_detail="命中问题：" + "；".join(weak[:6]),
                impact="攻击者可绕过口令直接走找回流程接管账号。",
                reproduction=(f"匿名 GET {url}，在页面中读取密保问题清单，"
                              f"确认存在基于公开信息的弱问题（如 {weak[0][:24]}）。\n"
                              "（本次未提交任何账号做找回尝试 —— 会触发真实短信 / 邮件。）"),
                remediation=("取消基于公开信息的密保问题，改用邮箱 / 短信一次性"
                             "验证码 + 风险评分；保留问题时必须限定次数、"
                             "失败计入风控并通知账号持有人。"),
                compliance="等保2.0 身份鉴别 / OWASP ASVS V2.5",
                grading_basis="页面静态特征实测（问题清单）",
            ))

    note = "\n".join(parts)
    note += ("\n⚠ 本次**未执行**账号存在性探测：对真实账号发起找回会触发短信 / 邮件，"
             "属副作用。提交不存在的账号与存在的账号响应是否可区分"
             "（账号枚举）这一判定点仍无结论，需人工用测试账号执行。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=len(RESET_PATHS))


# ======================================================================
# WSTG-ATHN-09 密码修改与重置流程测试
# ======================================================================
def recon_athn09(ctx: DetectorContext) -> ReconOutcome:
    """定位改密 / 重置入口，静态判定四件事：

      ① 改密表单是否要求输入原密码（不要求 = 可被会话劫持后直接改密）；
      ② 重置凭据是否走 URL（GET 泄露到日志 / Referer / 浏览器历史）；
      ③ 是否明文 HTTP；
      ④ 口令强度策略是否只在客户端校验。
    """
    pages = dict(_probe_paths(ctx, CHANGE_PWD_PATHS))
    pages.update(_probe_paths(ctx, RESET_PATHS))
    if not pages:
        return _no_entry(
            ctx, len(CHANGE_PWD_PATHS) + len(RESET_PATHS),
            "改密 / 重置入口（改密通常需要登录态，匿名访问不到属正常，"
            "此时应提供测试账号）")

    ok_accounts, authorized = _cfg(ctx)
    lead: list[str] = []
    parts: list[str] = []
    findings: list[Any] = []
    for path, pr in pages.items():
        url = str(_attr(pr, "url", path))
        text = _txt(pr)
        scheme = urlparse(url).scheme
        forms = _forms(text)
        new_forms = [f for f in forms
                     if re.search(r"pass|pwd", " ".join(f["fields"]), re.I)]
        lead.append(f"改密 / 重置入口 `{url}`（{scheme}://，状态 {_status(pr)}）")
        if new_forms:
            fields = "、".join(new_forms[0]["fields"][:14])
            lead.append(f"　· 表单字段：{fields}（method={new_forms[0]['method']}）")
            has_old = bool(re.search(r"old|current|原|旧", fields, re.I))
            lead.append("　· 是否要求原密码：" + ("是" if has_old else "**否**"))
            if not has_old and "change" in path.lower():
                findings.append(make_finding(
                    "WSTG-ATHN-09", "改密表单未要求校验原密码",
                    str(_attr(ctx, "target", "") or ""), endpoint=url,
                    severity="高危", confidence="Medium", evidence_level="C",
                    description=("改密页面只要求新口令，未要求先输入原口令。"
                                 "任何拿到有效会话的攻击者（XSS 窃取、会话固定、"
                                 "共用终端未登出）都可直接把口令改掉，"
                                 "从而把账号永久据为己有。"),
                    technical_detail=f"表单字段：{fields}；未见 old/current/原密码 字段",
                    impact="会话被劫持即可完成账号接管，且受害者失去找回能力。",
                    reproduction=(f"1) 打开 {url}；\n"
                                  "2) 表单只需新口令与确认口令，无处输入原口令；\n"
                                  "3) 提交后口令即被修改。\n"
                                  "（本次为静态表单结构分析；实际提交改密需人工用"
                                  "测试账号执行 —— 属写操作。）"),
                    remediation=("改密必须校验原口令；敏感操作要求二次认证；"
                                 "改密成功后强制所有会话失效并通知账号持有人。"),
                    compliance="等保2.0 身份鉴别 / OWASP ASVS V2.1",
                    grading_basis="页面静态特征实测（表单字段结构）",
                ))
        token_in_url = bool(re.search(
            r"[?&](token|code|key|sign|ticket|verify)=[A-Za-z0-9._\-]{8,}", url, re.I))
        if token_in_url:
            findings.append(make_finding(
                "WSTG-ATHN-09", "重置凭据经 URL 明文传递（可被日志 / Referer 泄露）",
                str(_attr(ctx, "target", "") or ""), endpoint=url, severity="中危",
                confidence="High", evidence_level="A",
                description="重置 token 出现在 URL 查询串中，会被浏览器历史、"
                            "服务端访问日志、Referer 头与代理日志记录。",
                technical_detail=f"URL：{url}",
                impact="凭据泄露后可直接重置他人口令。",
                reproduction=f"GET {url}，观察 token 位于查询串而非请求体 / 片段",
                remediation="token 走 POST 请求体或在客户端用 fragment 承载，"
                            "一次有效、短时效、绑定账号与会话。",
                compliance="等保2.0 数据保密性",
                grading_basis="URL 结构实测",
            ))
        if scheme == "http":
            lead.append("　· **明文 HTTP**：改密凭据将明文过网")
        parts.append(f"[{url}] 表单 {len(forms)} 个，口令表单 {len(new_forms)} 个，"
                     f"scheme={scheme or '未知'}")

    note = "\n".join(parts)
    note += (f"\n\n本次可用的授权测试账号会话：{'有' if ok_accounts else '无'}"
             f"（已授权且已验证登录的账号 {len(authorized)} 个）。"
             "改密链路的后半段（提交后是否全端失效、是否校验口令强度策略）"
             "属写操作，须人工用测试账号执行。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=len(pages))


# ======================================================================
# WSTG-ATHZ-03 权限提升（垂直越权）—— 自动前置侦察
# ======================================================================
def _jwt_payload_of(account: dict) -> dict:
    """取账号令牌的载荷（用于拿到「这个账号自己的对象标识」）。"""
    import base64 as _b64
    import json as _json

    for k, v in (account.get("headers") or {}).items():
        if str(k).lower() != "authorization":
            continue
        m = re.search(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*",
                      str(v))
        if not m:
            continue
        part = m.group(0).split(".")[1]
        try:
            return _json.loads(_b64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _identity_markers(account: dict) -> tuple[str, str]:
    """账号自己的 (对象标识, 身份特征串)。

    身份特征串用来在响应里认出「这是 A 的数据」—— 没有它，B 拿到 200 也
    证明不了那是不是别人的东西（红线 19：同类发现必须同类判据）。
    """
    p = _jwt_payload_of(account)
    data = p.get("data") if isinstance(p.get("data"), dict) else p
    ident = str(data.get("id") or p.get("userId") or p.get("user_id") or "")
    email = str(data.get("email") or p.get("email") or p.get("sub") or "")
    if not ident:
        ident = str(account.get("name") or "")
    return ident, email


def _object_templates(ctx: DetectorContext, limit: int = 8) -> list[str]:
    """带对象标识的端点模板（URL 里含数字段或 {id} 占位）。"""
    out: list[str] = []
    pat = re.compile(r"/(\d{1,9})(?:/|$|\?)")
    for u in (ctx.js_result.get("urls") or []):
        if isinstance(u, str) and pat.search(u) and _same_host(ctx.target_url, u, ctx.domain):
            out.append(u)
    for p in (ctx.fp_result.get("path_probes") or {}):
        if isinstance(p, str) and pat.search("/" + p.lstrip("/")):
            out.append(urljoin(ctx.target_url, p.lstrip("/")))
    for p in ("rest/basket/1", "api/Orders/1", "api/Users/1", "api/Addresss/1",
              "api/PaymentMethods/1", "api/Cards/1"):
        out.append(urljoin(ctx.target_url, p))
    return list(dict.fromkeys(out))[:limit]


def _horizontal_idor(ctx: DetectorContext, accounts: list[dict],
                     probes: list[int]) -> tuple[list[Any], list[str]]:
    """水平越权（同权互看对象）自动对照。

    判据链（缺一条都不成，红线 9）：
      · A 能读到**自己的**对象（端点可用、且 A 的标识确实对应一个对象）；
      · B 能读到**自己的**对象（B 的令牌与端点配合正常，排除「B 根本没权限」）；
      · B 用 A 的标识去读，返回 2xx 且正文里出现**A 的身份特征**
        （A 的邮箱 / id），且与 B 读自己时的响应**不同**（排除 SPA 兜底页）。
    """
    findings: list[Any] = []
    lead: list[str] = []
    a, b = accounts[0], accounts[1]
    a_id, a_email = _identity_markers(a)
    _b_id, _b_email = _identity_markers(b)
    marker = a_email or a_id
    if not marker:
        lead.append("　· 水平越权未执行：未能从令牌载荷中取到账号「%s」的标识，"
                    "无法构造「别人的对象 id」" % a.get("name"))
        return findings, lead

    pat = re.compile(r"/(\d{1,9})(?:/|$|\?)")
    for tmpl in _object_templates(ctx):
        m = pat.search(tmpl)
        if not m:
            continue
        url_a = tmpl[:m.start(1)] + str(a_id) + tmpl[m.end(1):]
        url_b = tmpl[:m.start(1)] + str(_b_id) + tmpl[m.end(1):]
        if url_a == url_b:
            continue
        res_a = _ident_fetch(url_a, _ident_of(a), ctx=ctx)
        probes[0] += 1
        res_b_own = _ident_fetch(url_b, _ident_of(b), ctx=ctx)
        probes[0] += 1
        if (res_a.get("err") or res_b_own.get("err")
                or not _ok_body(res_a, min_len=40)
                or not _ok_body(res_b_own, min_len=40)):
            continue
        res_cross = _ident_fetch(url_a, _ident_of(b), ctx=ctx)
        probes[0] += 1
        try:
            st = int(res_cross.get("status") or 0)
        except (TypeError, ValueError):
            st = 0
        body = res_cross.get("body") or ""
        if not (200 <= st < 300) or not body:
            lead.append(f"　· {url_a}：B 读 A 的对象被挡（HTTP {st}）—— 归属校验生效")
            continue
        if body == res_b_own.get("body"):
            lead.append(f"　· {url_a}：B 读 A 与读自己返回**完全相同**的响应"
                        f"（疑似 SPA 兜底页），不作判据")
            continue
        # 身份特征有两类，命中任一即可，缺一不可互为补充：
        #   · email —— 通用，但 basket / order 这类对象的响应里常常只有
        #     对象 id、不含邮箱（2026-10-10 Juice Shop「View Basket」
        #     实测因此漏报：email 判据永远 miss，id 判据从来没被尝试）；
        #   · 对象 id —— 必须结构化匹配（"id":1 / "Basket with id 1"），
        #     裸数字「1」在正文里太常见会误报；且 A 读自己的响应里
        #     **同样**要含这个形态（自证 id 与对象关联），B 读自己的
        #     响应里**不含**（排除全局共享 id 的混淆）。
        id_pat = (re.compile(rf'(?:\bid"\s*:\s*"?{re.escape(str(a_id))}"?\b'
                             rf'|[Ii]d\s+{re.escape(str(a_id))}\b)')
                  if a_id else None)
        marker_hit = ""
        if marker and marker in body:
            marker_hit = f"邮箱/标识「{marker}」"
        elif (id_pat and id_pat.search(body)
              and id_pat.search(res_a.get("body") or "")
              and not id_pat.search(res_b_own.get("body") or "")):
            marker_hit = f"对象 id {a_id}（结构化匹配，且仅出现在 A 的响应中）"
        if not marker_hit:
            lead.append(f"　· {url_a}：B 读 A 的对象返回 2xx，但正文未出现 A 的身份特征，"
                        f"无法确认那是 A 的数据，不作判据")
            continue
        frag = body[:400]
        findings.append(make_finding(
            "WSTG-ATHZ-03", "水平越权：一个账号可直接读取另一个账号的对象数据",
            str(_attr(ctx, "target", "") or ""), endpoint=url_a, method="GET",
            param="对象标识",
            severity="高危", confidence="High", evidence_level="A",
            description=(f"用账号「{b.get('name')}」的登录态去请求账号"
                         f"「{a.get('name')}」的对象地址（对象标识 {a_id}），"
                         f"服务端返回 HTTP {st} 并带回了**属于 A 的数据**"
                         f"（响应中出现 A 的身份特征：{marker_hit}）。"
                         "说明该接口只校验了「有没有登录」，没有校验"
                         "「这个对象是不是你的」。"),
            technical_detail=(f"对照实验（同一端点三次请求）：\n"
                              f"  · A（{a.get('name')}）读自己的 {url_a} → HTTP {res_a.get('status')}\n"
                              f"  · B（{b.get('name')}）读自己的 {url_b} → HTTP {res_b_own.get('status')}\n"
                              f"  · B 读 A 的 {url_a} → HTTP {st}，正文含 A 的身份特征\n"
                              f"A 的身份特征：{marker_hit}\n"
                              f"响应片段：{frag}"),
            impact=("任意登录用户改一下对象标识就能读到别人的业务数据"
                    "（购物车、订单、地址、支付信息等）。标识连续时可脚本化"
                    "批量遍历，影响面通常是全量用户。"),
            reproduction=(f"# 用 A 的令牌\ncurl -s '{url_a}' -H 'Authorization: Bearer <A_TOKEN>'\n"
                          f"# 换成 B 的令牌请求**同一个地址**\n"
                          f"curl -s '{url_a}' -H 'Authorization: Bearer <B_TOKEN>'"),
            remediation=("① 每个对象访问都在服务端校验归属（当前用户 == 资源所有者）；"
                         "② 对象标识换 UUID 只是缓解，不能替代归属校验；"
                         "③ 统一走同一个归属校验组件，避免逐个接口漏做。"),
            compliance="OWASP ASVS 4.2 / CWE-639 / 等保2.0 安全计算环境-访问控制",
            evidence=[finding_evidence("response", frag, f"B 读 A 对象 {url_a}")],
            grading_basis="三次对照实测，B 读到 A 的数据且可区分于自身响应，证据级 A，定高危",
        ))
        break
    return findings, lead


def recon_athz03(ctx: DetectorContext) -> ReconOutcome:
    """垂直越权 + 水平越权两段**各自独立**地跑，再合并结论。

    为什么要拆开（2026-10-10 实测逼出来的）：
      水平越权只需要「两组已登录身份 + 一个带对象标识的端点」，
      它**不依赖**垂直越权那套「管理端点候选」——后者常常一个都定位不到
      （SPA 的管理入口不在路径探测里），于是函数在垂直分支上提前返回，
      水平那段永远跑不到，报告上却写着「水平越权属人工范畴」。
      这正是红线 14 盯的形态：**未实现的路径静默跳过**。
    """
    vert = _athz03_vertical(ctx)
    authorized = _cfg(ctx)[1]
    findings = list(vert.findings)
    lead = list(vert.lead)
    probes = int(vert.probes or 0)
    hori_ran = False

    if len(authorized) >= 2 and ctx.risk_allowed(RISK_STANDARD) and not findings:
        hp = [0]
        hf, hl = _horizontal_idor(ctx, authorized[:2], hp)
        probes += hp[0]
        hori_ran = True
        lead.extend(hl)
        findings.extend(hf)
    elif len(authorized) >= 2 and findings:
        lead.append("　· 水平越权未跑：垂直越权已确证，本项结论已成立，不再追加请求")
    else:
        lead.append("　· 水平越权未跑：已确认登录态不足 2 个"
                    "（互读对方对象需要两组身份，缺一组就没有对照基线）")

    if hori_ran:
        note = "\n".join(lead)
        note += ("\n\n⚠ 水平越权只做**只读 GET 互读**（A 读自己 / B 读自己 / B 读 A "
                 "三次对照）。跨租户越权、「改自己的角色字段实现自提权」两类仍需人工 —— "
                 "前者需要另一租户的标识，后者是写操作。")
        return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                            probes=probes)
    if not vert.ran:
        # 两段都没跑起来 —— 原因用垂直那段的（它把「为什么没有可比对端点」
        # 说得最具体），但水平那段的说明也要带上，否则读者以为只试了垂直。
        # 注意：**补齐方式必须落进 note** —— 报告与自测都从 note 里读它，
        # 只写进 error 会让「下一步该怎么补」这句话在报告上消失
        # （内建自测专门钉这一条）。
        return ReconOutcome(ran=False, findings=findings, lead=lead,
                            note=("\n".join(lead) + "\n" if lead else "")
                            + f"水平越权同样未执行（{lead[-1].strip() if lead else '无身份'}）\n"
                            + f"垂直越权未执行原因：{vert.error}\n"
                            + str(vert.note or ""),
                            error=vert.error, probes=probes)
    note = "\n".join(lead)
    note += ("\n\n⚠ 本次只做「匿名 vs 低权身份」对同一端点的两次**只读 GET**，"
             "水平越权未跑（见上文原因）。跨租户越权与「改自己的角色字段实现"
             "自提权」两类同样属人工范畴。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=probes)


def _athz03_vertical(ctx: DetectorContext) -> ReconOutcome:
    """用「两条客观事实」把垂直越权从「必须人工」压到「多数情况可自动确证」。

    判定需要**同时**成立：
      ① 匿名请求该端点被访问控制挡住（401 / 403 / 跳登录页）——
         说明服务端确实给这个端点挂了权限要求；
      ② 低权测试身份请求同一地址返回 2xx 业务内容 ——
         说明这个权限要求没有按角色生效。

    两条事实同源于「同一条 URL 的两次真实请求」，复测即得，不依赖推断。

    反向一律**不报**（注意：不报 ≠ 通过）：
      · 匿名自己就能进的端点 → 那是「未授权访问」而不是「提权」，
        报成提权会被当场驳回 —— 连身份都没有，何来权限提升；
      · 两个身份都被挡住 → 权限校验生效，本项无发现；
      · 整站统一 401/403/405 → 拿不到「该路径受保护」的证据，
        按红线一律待确认，既不报有也不报无。

    水平越权（两个同权账号互看对方对象）需要各自的**对象标识**，
    外部扫描无从知道哪条记录属于谁，仍然人工。
    """
    cands = _admin_candidates(ctx)
    if not cands:
        return _manual_only(
            "未能在已采集素材中定位到任何管理 / 高权限语义的端点"
            "（前端产物地址与路径探测结果里都没有 admin / manage / role / export 一类路径）",
            extra="补齐方式：① 用 standard 以上档位重扫，让路径探测覆盖更多候选；"
                  "② 或把登录后可见的前端产物通过 --js 提供给扫描器；"
                  "③ 若系统确实没有可枚举的管理端点，本项转为纯人工核查"
                  "（用两组账号在站内逐接口比对）。")
    if not ctx.risk_allowed(RISK_STANDARD):
        return _manual_only(
            "当前档位不允许对候选端点逐一发起身份对照请求"
            "（垂直越权必须用「匿名」与「低权身份」两次真实请求对照）")

    uniform_st, uniform_ratio, uniform_n = _sitewide_denies(ctx)
    if uniform_st in (401, 403, 405):
        return _manual_only(
            f"目标对任意路径统一返回 HTTP {uniform_st}"
            f"（{uniform_n} 个样本中 {uniform_ratio:.0%} 同码），"
            f"无法区分「该端点受访问控制保护」与「整站边缘拦截」——"
            f"在拿到可区分的响应前，本项既不报有也不报无",
            extra="补齐方式：确认扫描来源 IP 未被边界防护拦截后重扫；"
                  "或在放行后的网络环境下用两组账号人工比对。")

    ok_accounts, authorized = _cfg(ctx)
    lead: list[str] = []
    findings: list[Any] = []
    denied: list[tuple[str, int]] = []      # 匿名被挡 → 可用于建立基线的端点
    open_to_anon: list[str] = []            # 匿名自己就能进 → 不构成提权
    probes = 0

    for url in cands:
        res = _ident_fetch(url, None, ctx=ctx)
        probes += 1
        try:
            st = int(res.get("status") or 0)
        except (TypeError, ValueError):
            st = 0
        if res.get("err") or st == 0:
            continue
        if _blocked_by_control(res):
            denied.append((url, st))
            lead.append(f"候选 `{url}`：匿名 HTTP {st}（受访问控制保护）")
        elif _ok_body(res, min_len=100):
            open_to_anon.append(url)
            lead.append(f"候选 `{url}`：匿名即可访问（HTTP {st}）—— "
                        f"属「未授权访问」而非「权限提升」，不计入提权发现")
        else:
            lead.append(f"候选 `{url}`：匿名 HTTP {st}"
                        f"（既未被挡也无业务内容，不作判据）")

    if open_to_anon:
        lead.append("　· 匿名可达的候选共 %d 个，已单独列出（不计入提权）：%s"
                    % (len(open_to_anon), "、".join(open_to_anon[:5])))

    if not denied:
        return _manual_only(
            f"探测 {len(cands)} 个候选端点，没有任何一个对匿名返回「被访问控制挡住」"
            f"的表现 —— 缺少「该端点确实挂了权限要求」这一半客观事实，"
            f"无法建立垂直越权的判定基线",
            extra="补齐方式：确认候选端点是否正确（管理入口若不在该域名下，"
                  "请提供登录后的前端产物或接口清单）。")
    if not ok_accounts:
        return _manual_only(
            f"已定位 {len(denied)} 个「匿名被访问控制挡住」的候选端点"
            f"（{'、'.join(u for u, _ in denied[:4])}），"
            f"但没有可用于比对的低权测试身份 —— 垂直越权必须用"
            f"「匿名不能进」与「低权能进」两条客观事实对照才能确证",
            extra="补齐方式：`aiscan.py creds --target <域名> --set <角色>` 登记一个"
                  "**最低权限**的测试账号（普通用户 / 业务员），并把 verify_path 指到"
                  "一个需要登录才能访问的页面；凭据就位后本项会自动补跑。")

    low = _lowest_privileged(authorized)
    lead.append(f"比对身份：`{low.get('name')}`（角色 {low.get('role')}）"
                f"—— 已授权且回验为已登录，取其中权限最低者")
    for url, anon_status in denied[:6]:
        res = _ident_fetch(url, _ident_of(low), ctx=ctx)
        probes += 1
        try:
            i_status = int(res.get("status") or 0)
        except (TypeError, ValueError):
            i_status = 0
        if res.get("err") or i_status == 0:
            lead.append(f"　· {url}：低权身份请求失败"
                        f"（{str(res.get('err'))[:60]}），未判定")
            continue
        if _blocked_by_control(res):
            lead.append(f"　· {url}：低权身份同样被挡（HTTP {i_status}）"
                        f"—— 权限校验生效，无发现")
            continue
        if _ok_body(res):
            lead.append(f"　· {url}：低权身份返回 HTTP {i_status} 且含业务内容"
                        f"—— 确证越权")
            findings.append(_athz03_finding(ctx, url, anon_status, low, i_status, res))
        else:
            lead.append(f"　· {url}：低权身份 HTTP {i_status} 但无业务内容，不作判据")

    if not findings:
        lead.append("　· 所有「匿名被挡」端点在低权身份下**同样被挡** —— "
                    "未发现可自动确证的垂直越权")

    # 水平越权不在这里跑 —— 它不依赖管理端点候选，挂在垂直分支下面会被
    # 上面的提前返回整段吃掉（见 recon_athz03 的说明）。
    note = "\n".join(lead)
    note += ("\n\n⚠ 本段只做「匿名 vs 低权身份」对同一端点的两次**只读 GET**"
             "（垂直越权）。水平越权由 recon_athz03 独立执行。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=probes)


def _athz03_finding(ctx: DetectorContext, url: str, anon_status: int,
                    account: dict, ident_status: int, res: dict) -> Any:
    name = str(account.get("name") or "低权测试账号")
    role = str(account.get("role") or "未标注")
    frag = str(res.get("body") or "")[:400]
    return make_finding(
        "WSTG-ATHZ-03", "低权账号可访问管理 / 高权限端点（垂直越权）",
        str(_attr(ctx, "target", "") or ""), endpoint=url, method="GET",
        severity="高危", confidence="High", evidence_level="A",
        description=(f"该端点对匿名请求返回 HTTP {anon_status}（受访问控制保护），"
                     f"但用低权限测试身份「{name}」（角色 {role}）请求同一地址时"
                     f"返回 HTTP {ident_status} 并带回业务内容。"
                     "说明该端点的权限校验只拦住了「未登录」，"
                     "没有按角色 / 权限级别生效 —— 低权用户可直接调用管理接口。"),
        technical_detail=(f"对照实验结果（同一 URL 两次请求）：\n"
                          f"  · 匿名（不带任何凭据）→ HTTP {anon_status}\n"
                          f"  · 身份「{name}」（角色 {role}）→ HTTP {ident_status}\n"
                          f"端点：{url}\n"
                          f"低权身份响应片段（已截断）：\n{frag}"),
        impact=("低权账号即可读取或操作本应仅管理角色可见的数据与功能。"
                "若该端点涉及用户管理、角色配置或数据导出，"
                "等同于权限体系在最关键的一环失效 —— "
                "普通账号到全量数据之间只差一次请求。"),
        reproduction=(f"1) 不带凭据请求：curl -s -o /dev/null -w '%{{http_code}}\\n' "
                      f"'{url}'   → HTTP {anon_status}\n"
                      f"2) 带上低权测试身份的 Cookie 请求同一地址 "
                      f"→ HTTP {ident_status} 且返回业务内容\n"
                      "3) 对比两次响应即可复现（两次都是只读 GET，无副作用）。\n"
                      "（水平越权需再用两个同权账号交叉比对，见本项人工步骤。）"),
        remediation=("① 权限校验下沉到服务端每个接口，按角色 / 权限点判定，"
                     "不依赖前端菜单隐藏；"
                     "② 管理类接口统一挂权限注解或网关策略，"
                     "评审时以「接口清单」为单位逐个勾选，避免遗漏；"
                     "③ 建立越权自动化测试：每条管理接口都必须有一条"
                     "「低权身份应得 403」的用例。"),
        compliance="等保2.0 安全计算环境-访问控制 / OWASP ASVS V4.1 / CWE-269",
        grading_basis=("双身份对照实测（匿名被挡 + 低权 2xx 且含业务内容），"
                       "两条客观事实同源可复测；"
                       "本次未评估响应内容的敏感程度，故定高危而非严重"),
    )


# ======================================================================
# WSTG-SESS-11 并发会话控制测试
# ======================================================================
def recon_sess11(ctx: DetectorContext) -> ReconOutcome:
    """用同一测试账号再登录一次，观察旧会话是否仍然有效。

    「再登录一次」本身只创建会话、不修改业务数据，代价与一次普通登录相同；
    且**只对已登记 authorized: true 的测试账号**执行。若两次会话同时有效，
    即可确证「未做并发会话控制」—— 这半块是可以自动证的。
    人工仍需回答的是**策略问题**：并发是否被允许、有无在线设备管理、
    有无登录通知。
    """
    ok, accounts = _cfg(ctx)
    if not ok:
        return _manual_only(
            "无「已授权且登录成功」的测试账号 —— 并发会话验证必须用同一账号"
            "做两次真实登录，匿名视角无法完成。",
            extra="本项的自动前置部分（多端状态交叉观察）未执行，"
                  "需先在账号配置中登记 authorized: true 的测试账号。")
    if not ctx.risk_allowed(RISK_STANDARD):
        return _manual_only("当前档位不允许执行二次登录（会在服务端创建会话）")

    acc = accounts[0]
    lead: list[str] = []
    findings: list[Any] = []
    notes: list[str] = [f"使用测试账号「{acc.get('name')}」（角色 {acc.get('role')}）"
                        f"做二次登录，观察既有会话是否仍被接受"]

    try:
        from engine.sessionpool import (  # noqa: PLC0415
            AccountSpec, LOGIN_OK, login_one, verify_session,
        )
    except Exception as e:  # noqa: BLE001
        return _manual_only(f"会话池模块不可用：{type(e).__name__}: {str(e)[:120]}")

    spec = AccountSpec(name=str(acc.get("name") or "测试账号"),
                       role=str(acc.get("role") or ""),
                       headers=dict(acc.get("headers") or {}),
                       cookies=dict(acc.get("cookies") or {}),
                       authorized=True, source="reuse")
    target_url = str(getattr(ctx, "target_url", "") or "")
    try:
        spec2 = login_one(spec, target_url)
    except Exception as e:  # noqa: BLE001
        return _manual_only(f"二次登录执行异常：{type(e).__name__}: {str(e)[:120]}")

    if getattr(spec2, "rejected", ""):
        # 后登录被拒 → 可能是「不允许并发」，也可能是别的原因；
        # 这一支不能当结论，只能当线索交人工。
        lead.append("二次登录被拒绝：" + str(spec2.rejected)[:120])
        notes.append("二次登录未能建立新会话 —— 这**可能**意味着服务端不允许"
                     "并发登录，也可能是账号策略 / 风控导致。判据不足以定论，"
                     "交人工确认提示文案与实际策略。")
        return ReconOutcome(ran=True, findings=[], lead=lead,
                            note="\n".join(notes), probes=2)

    new_session = {"headers": dict(spec2.headers), "cookies": dict(spec2.cookies)}
    lead.append("二次登录成功，已建立第二个会话")
    # 回验路径必须沿用账号自己声明的「登录后页面」：拿站点首页回验时，
    # 新旧两个会话都会「没被弹回」，据此得出的「两处会话并存」是假的。
    vpath = str(acc.get("verify_path") or "")
    try:
        old_state, old_why = verify_session(dict(acc), target_url, vpath)
    except Exception as e:  # noqa: BLE001
        old_state, old_why = "", f"{type(e).__name__}: {str(e)[:100]}"
    try:
        new_state, new_why = verify_session(new_session, target_url, vpath)
    except Exception as e:  # noqa: BLE001
        new_state, new_why = "", f"{type(e).__name__}: {str(e)[:100]}"

    lead.append(f"　· 旧会话：{old_state or '未知'}（{str(old_why)[:70]}）")
    lead.append(f"　· 新会话：{new_state or '未知'}（{str(new_why)[:70]}）")
    notes.append(f"旧会话状态 {old_state}，新会话状态 {new_state}")

    if old_state == LOGIN_OK and new_state == LOGIN_OK:
        endpoint = target_url or str(_attr(ctx, "target", ""))
        findings.append(make_finding(
            "WSTG-SESS-11", "并发会话不受控制：同一账号可同时保持多个有效会话",
            str(_attr(ctx, "target", "") or ""), endpoint=endpoint, severity="低危",
            confidence="High", evidence_level="A",
            description=("同一账号二次登录后，此前建立的会话**仍然有效**，"
                         "服务端未做会话互斥或旧会话失效处理。"
                         "被窃取的会话不会因为账号再次登录而失效，"
                         "受害者无法通过「重新登录」把攻击者踢下线。"),
            technical_detail=(f"账号「{acc.get('name')}」二次登录成功；"
                              f"旧会话 verify={old_state}，新会话 verify={new_state}"),
            impact="会话劫持的窗口被无限延长：受害者改口令 / 重登录均无法挤出攻击者。",
            reproduction=("1) 用测试账号在会话 A 登录并确认可用；\n"
                          "2) 用同一账号再登录一次得到会话 B；\n"
                          "3) 用会话 A 再次访问需要登录的页面，仍返回已登录内容。\n"
                          "（本条由自动前置侦察复现；判定为「不通过」仅针对"
                          "「会话未互斥」这一可自动证部分。）"),
            remediation=("作为策略选择其一并明确落地：① 后登录踢前者并及时提示；"
                         "② 限制单账号并发会话数；③ 允许并发但必须提供在线设备"
                         "列表与远程下线能力，并对新登录发通知。"),
            compliance="OWASP ASVS V3.3 / 等保2.0 会话管理",
            grading_basis="两次真实登录 + 双会话可用性实测（测试账号）",
        ))
    else:
        notes.append("未观察到「双会话同时有效」，但不等于并发控制到位 —— "
                     "verify 结果受验证路径与登录态判定影响，交人工确认。")

    return ReconOutcome(ran=True, findings=findings, lead=lead,
                        note="\n".join(notes), probes=2)


# ======================================================================
# WSTG-CRYP-02 Padding Oracle
# ======================================================================
def recon_cryp02(ctx: DetectorContext) -> ReconOutcome:
    """定位密文候选参数，并对**只读**参数做单字节翻转差分。

    判定 padding oracle 的核心是「密文被篡改后，响应是否可区分」。
    单字节翻转 + 响应比对是只读动作（GET 且参数不改变业务状态），
    可以自动做；批量解密触碰真实数据，仍然人工。
    """
    cands = _cipher_candidates(ctx)
    if not cands:
        return _manual_only(
            "在已采集的页面 / 前端产物中未发现密文形态参数"
            "（Base64 ≥20 字符或十六进制 ≥32 字符）—— 没有可分析的密文对象")

    lead: list[str] = []
    findings: list[Any] = []
    parts: list[str] = [f"密文候选参数 {len(cands)} 个"]
    probed = 0

    for endpoint, param, value in cands[:8]:
        lead.append(f"密文候选 `{param}` @ {endpoint}（形态 {_shape(value)}，"
                    f"长度 {len(value)}）")
        if not ctx.risk_allowed(RISK_STANDARD):
            continue
        verdict, detail = _flip_probe(ctx, endpoint, param, value)
        probed += 1
        parts.append(f"[{param}@{endpoint}] 单字节翻转差分：{verdict} —— {detail}")
        lead.append(f"　· 单字节翻转差分：{verdict}")
        if verdict == "可区分":
            findings.append(make_finding(
                "WSTG-CRYP-02", "密文篡改产生可区分响应（疑似 padding oracle）",
                str(_attr(ctx, "target", "") or ""), endpoint=endpoint,
                param=param, method="GET", severity="高危", confidence="Medium",
                evidence_level="B",
                description=("对密文参数做单字节翻转后重新提交，服务端返回的响应"
                             "与基线可稳定区分（状态码 / 响应长度 / 正文特征之一"
                             "发生变化）。这是 padding oracle 的必要条件："
                             "攻击者可借此逐字节恢复明文。"),
                technical_detail=f"参数 {param}（{_shape(value)}）；{detail}",
                impact=("可导致加密参数被解密（如加密的用户 ID / 订单号），"
                        "进而访问他人数据；对加密会话态参数则可能导致会话伪造。"),
                reproduction=(f"1) 取基线请求：GET {endpoint}，记录状态码与响应长度；\n"
                              f"2) 将参数 {param} 的密文末字节翻转 1 位后重放；\n"
                              "3) 观察响应与基线是否稳定可区分。\n"
                              "（本次只做单字节翻转，未做批量解密。）"),
                remediation=("改用 AEAD（AES-GCM / ChaCha20-Poly1305）；"
                             "若必须用 CBC，则先加密后 MAC（EtM）且解密失败一律"
                             "返回统一错误与统一耗时；加密参数改为服务端会话态存储。"),
                compliance="等保2.0 数据保密性 / OWASP ASVS V6.2",
                grading_basis="单字节翻转差分实测（只读参数）",
            ))

    note = "\n".join(parts)
    note += ("\n\n⚠ 本次只做单字节翻转的只读差分；批量解密、以及写操作类密文参数"
             "（会修改数据）均未执行。判定为「可区分」也不等于已解密成功 —— "
             "是否构成可利用的 oracle 需人工用标准工具在测试环境确认。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=probed * 2)


# ----------------------------------------------------------------------
# CRYP-02 的支撑函数
# ----------------------------------------------------------------------
def _shape(value: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]+", value or ""):
        return "十六进制"
    return "Base64"


def _weak_question(q: str) -> bool:
    t = (q or "").lower()
    return bool(re.search(r"生日|出生|手机|电话|父亲|母亲|母亲|老婆|丈夫|"
                          r"名字|姓名|学号|工号|毕业|老家|籍贯|宠物|"
                          r"birth|mother|father|mobile|phone|hometown|pet",
                          t))


def _cipher_candidates(ctx: DetectorContext) -> list[tuple[str, str, str]]:
    """从已采集页面 / 前端产物里找密文形态参数。**不再发起新请求。**"""
    out: list[tuple[str, str, str]] = []
    try:
        from engine.business import _collect_blobs  # noqa: PLC0415
        blobs = _collect_blobs(ctx)
    except Exception:  # noqa: BLE001
        blobs = []
    seen: set[tuple[str, str, str]] = set()
    for page, text in blobs:
        base = page.split("?")[0]
        for m in re.finditer(r"[?&#\"']([A-Za-z_][\w\-\.]{0,40})="
                             r"([A-Za-z0-9+/=_\-%]{20,})", text or ""):
            param, raw = m.group(1), m.group(2)
            val = _maybe_b64(raw)
            if not val:
                continue
            key = (base, param, val[:24])
            if key in seen:
                continue
            seen.add(key)
            out.append((base, param, val))
    return out


def _maybe_b64(raw: str) -> str:
    """把候选值规范化成密文串；不像密文的返回空串。

    必须做**熵检查**：`aaaa...`(32 个 a) 也符合 [0-9a-f]{32,}，
    但它是明显的占位串。把占位串当密文去翻转，只会产出噪声结论。
    """
    v = raw.strip()
    if not v:
        return ""
    if _HEX_RE.fullmatch(v):
        return v if _entropy_ok(v) else ""
    if _B64_RE.fullmatch(v):
        return v if _entropy_ok(v) else ""
    try:
        pad = v + "=" * (-len(v) % 4)
        dec = base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return v if len(dec) >= 8 else ""


def _entropy_ok(v: str) -> bool:
    uniq = len(set(v))
    return uniq >= 12 and uniq >= len(v) * 0.3


def _flip_probe(ctx: DetectorContext, endpoint: str, param: str, value: str
                ) -> tuple[str, str]:
    """翻转密文一个字符重新请求，比较响应是否可区分。只做只读 GET。"""
    from engine.business import unsafe_reason  # noqa: PLC0415

    why = ""
    try:
        why = unsafe_reason(endpoint) or ""
    except Exception:  # noqa: BLE001
        why = ""
    if why:
        return "未执行", f"目标不安全，跳过（{why}）"

    try:
        base_probe = ctx.get(endpoint)
    except Exception as e:  # noqa: BLE001
        return "未执行", f"基线请求失败：{type(e).__name__}"
    b_status, b_len = _status(base_probe), len(_txt(base_probe))

    flipped = _flip(value)
    if not flipped:
        return "未执行", "无法构造翻转值（格式不合法）"
    url = _replace_param(endpoint, param, flipped)
    try:
        t_probe = ctx.get(url)
    except Exception as e:  # noqa: BLE001
        return "未执行", f"翻转请求失败：{type(e).__name__}"
    t_status, t_len = _status(t_probe), len(_txt(t_probe))

    if not (_reachable(base_probe) and _reachable(t_probe)):
        return "未执行", "有一侧请求未触达应用（拦截页或不可达），不作判定"
    if t_status != b_status:
        return "可区分", f"状态码 {b_status} → {t_status}"
    if b_len and abs(t_len - b_len) / max(b_len, 1) > 0.05:
        return "可区分", f"响应长度 {b_len} → {t_len}"
    if not ctx.content_matches(endpoint, _txt(t_probe)):
        return "可区分", "正文与基线不一致（内容级差异）"
    return "不可区分", f"状态码与长度一致（{b_status} / {b_len}B）"


def _flip(value: str) -> str:
    """末字符翻转。十六进制改一个十六进制位，Base64 改一个字母。

    Base64 的 `=` 是填充符，改它等于没改（解码结果相同），
    所以要在**最后一个数据字符**上动手 —— 那才是真正影响密文块的字节。
    """
    if not value:
        return ""
    core = value.rstrip("=")
    if not core:
        return ""
    last = core[-1]
    if re.fullmatch(r"[0-9a-fA-F]", last) and re.fullmatch(r"[0-9a-fA-F]+", core):
        rep = random.choice([c for c in "0123456789abcdef" if c != last.lower()])
    elif re.fullmatch(r"[A-Za-z0-9+/]", last):
        rep = random.choice([c for c in string.ascii_letters if c != last])
    else:
        return ""
    return core[:-1] + rep + value[len(core):]


def _replace_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    m = re.search(rf"([?&]{re.escape(param)}=)([^&]*)", url)
    if not m:
        return url
    new_q = re.sub(rf"([?&]{re.escape(param)}=)([^&]*)",
                   lambda mm: mm.group(1) + value, url)
    return urlunparse(parts._replace(query=new_q.split("?", 1)[-1])) \
        if "?" in new_q else url


# ======================================================================
# EXT-DP-03 导出范围越界 —— 自动前置侦察
# ======================================================================
def recon_dp03(ctx: DetectorContext) -> ReconOutcome:
    """把「导出范围是否越界」里可外部确证的那一半自动做掉。

    可确证的一半：**导出端点是否对「不该有的身份」直接吐数据文件。**
    判据必须落在响应类型上 —— 导出接口和普通页面一样返回 200，
    只看状态码分不出「拿到的是一份数据文件」还是「一张 HTML 页面」。
    所以这里用 Content-Type（spreadsheet / csv / pdf / octet-stream …）
    作为「服务端真的在导出数据」的客观特征。

    反向一律**不报**（不报 ≠ 通过）：
      · 匿名被 401/403/跳登录挡住 → 访问控制到位，本项无自动发现；
      · 返回 text/html → 只是个页面，不是导出产物，不作判据；
      · 整站统一 401/403/405 → 按红线转待确认。

    仍属人工的另一半：**导出内容是否超出该账号在页面上的可见范围**
    （A 部门账号导出 B 部门数据、字段是否脱敏、行数是否设上限）——
    这需要知道「哪条记录属于谁」，外部扫描无从判断。
    """
    cands = _export_candidates(ctx)
    if not cands:
        return _manual_only(
            "未能在已采集素材中定位到导出 / 下载类端点"
            "（前端产物地址与路径探测结果里都没有 export / download / report 一类路径）",
            extra="补齐方式：① 用 standard 以上档位重扫；"
                  "② 或提供登录后的前端产物（--js）；"
                  "③ 导出入口若只在登录后可见，请同时登记测试账号。")
    if not ctx.risk_allowed(RISK_STANDARD):
        return _manual_only("当前档位不允许对导出端点发起匿名探测请求")

    uniform_st, uniform_ratio, uniform_n = _sitewide_denies(ctx)
    if uniform_st in (401, 403, 405):
        return _manual_only(
            f"目标对任意路径统一返回 HTTP {uniform_st}"
            f"（{uniform_n} 个样本中 {uniform_ratio:.0%} 同码），"
            f"无法区分「导出端点确实存在且被挡」与「整站边缘拦截」——"
            f"在拿到可区分的响应前，本项既不报有也不报无",
            extra="补齐方式：确认扫描来源 IP 未被边界防护拦截后重扫。")

    lead: list[str] = []
    findings: list[Any] = []
    probes = 0
    reached = 0
    for url in cands:
        res = _ident_fetch(url, None, ctx=ctx)
        probes += 1
        try:
            st = int(res.get("status") or 0)
        except (TypeError, ValueError):
            st = 0
        if res.get("err") or st == 0:
            lead.append(f"`{url}`：请求未触达（{str(res.get('err'))[:60]}），未判定")
            continue
        reached += 1
        ctype = str(res.get("ctype") or "").lower()
        if _blocked_by_control(res):
            lead.append(f"`{url}`：匿名被挡（HTTP {st}）—— 访问控制生效，无自动发现")
            continue
        if st < 200 or st >= 300:
            lead.append(f"`{url}`：匿名 HTTP {st}（非 2xx，不作判据）")
            continue
        if not any(t in ctype for t in _EXPORT_CT):
            lead.append(f"`{url}`：匿名 HTTP {st}，但响应类型为 "
                        f"{ctype or '未知'}（不是导出产物），不作判据")
            continue
        lead.append(f"`{url}`：匿名 HTTP {st}，响应类型 {ctype} —— 确证可匿名导出")
        findings.append(_dp03_finding(ctx, url, st, ctype, res))

    if reached == 0 and not findings:
        return _manual_only(
            f"定位到 {len(cands)} 个导出 / 下载类候选端点，但逐一请求后全部未触达"
            f"（不可达或被拦截）—— 没有得到任何可用于判定的响应",
            extra="补齐方式：确认目标可达且扫描来源 IP 未被边界防护拦截后重扫。")

    note = "\n".join(lead)
    if findings:
        note += ("\n\n⚠ 本次证实的是「**无需身份**即可拿到导出产物」。"
                 "导出内容是否超出权限范围、字段是否脱敏、行数是否设上限，"
                 "仍需人工用低权账号比对（见本项人工步骤）。")
    else:
        note += ("\n\n本次为**匿名视角**探测：未发现可匿名下载的导出产物。"
                 "但「已登录低权账号的导出口径是否越界」无法由外部判定 —— "
                 "需人工用低权账号实际导出一次，比对行数与字段脱敏情况。")
    return ReconOutcome(ran=True, findings=findings, lead=lead, note=note,
                        probes=probes)


def _dp03_finding(ctx: DetectorContext, url: str, status: int, ctype: str,
                  res: dict) -> Any:
    frag = str(res.get("body") or "")[:300]
    return make_finding(
        "EXT-DP-03", "导出 / 下载接口无需身份即可获取数据文件",
        str(_attr(ctx, "target", "") or ""), endpoint=url, method="GET",
        severity="高危", confidence="High", evidence_level="A",
        description=(f"该地址在**不带任何凭据**的情况下返回 HTTP {status}，"
                     f"且响应类型为 {ctype} —— 服务端直接输出了数据文件，"
                     "既没有要求登录，也没有按数据权限过滤。"),
        technical_detail=(f"端点：{url}\n"
                          f"匿名请求：HTTP {status}\n"
                          f"Content-Type：{ctype}\n"
                          f"响应开头（已截断；若含真实数据请按内部流程处置）：\n{frag}"),
        impact=("① 导出产物通常是全量业务数据的快照，匿名可取意味着"
                "**无需任何账号**即可完成批量数据泄露；"
                "② 若产物内含个人信息，构成个人信息泄露事件，"
                "需按 PIPL / 数据安全法评估上报与告知义务；"
                "③ 导出接口往往还缺少行数上限，单次请求即可拖走全量。"),
        reproduction=(f"curl -sD - -o /tmp/out.bin '{url}' | head -20\n"
                      f"# 观察：HTTP {status}，Content-Type: {ctype}，且无需任何 Cookie\n"
                      "# 再检查 /tmp/out.bin 的行数与字段是否为真实业务数据"),
        remediation=("① 导出接口与查询接口共用同一套数据权限校验，"
                     "落到查询条件上而不是仅在前端过滤；"
                     "② 导出行数与时间范围设硬上限，超限转异步任务并留审计日志；"
                     "③ 产物下载链接使用一次性签名，短时效、绑定账号。"),
        compliance="PIPL 第 51 条 / 数据安全法第 27 条 / 等保2.0 数据保密性 / CWE-284",
        grading_basis=("匿名实测拿到导出产物（Content-Type 为数据文件类型），"
                       "危害可直接验证、可复测，定高危"),
    )


# ======================================================================
# 自测
# ======================================================================
def _selftest() -> int:
    """离线自测：侦察的「三态」必须分得清，且不得做有副作用的动作。"""
    problems: list[str] = []

    # ① 密文识别：低熵占位串不得被当密文（否则翻一个字符就能「造」出可区分响应）
    if _maybe_b64("a" * 32):
        problems.append("低熵占位串被识别为密文 —— 翻转它只会产出噪声结论")
    if not _maybe_b64("5f2b9c1d7a3e6f80b4c2d9e15a7f3b60"):
        problems.append("合法十六进制密文未被识别")
    if _maybe_b64("short"):
        problems.append("短串不应被识别为密文")
    if not _maybe_b64("dGhpcyBpcyBhIHNlY3JldCB0b2tlbiB2YWx1ZQ=="):
        problems.append("合法 Base64 密文未被识别")

    # ② 翻转：长度不变且内容确实变了
    v = "5f2b9c1d7a3e6f80b4c2d9e15a7f3b60"
    fv = _flip(v)
    if len(fv) != len(v) or fv == v:
        problems.append("翻转必须长度不变且内容确实发生变化")
    b = "dGhpcyBpcyBhIHNlY3JldCB0b2tlbg=="
    fb = _flip(b)
    if len(fb) != len(b) or fb == b:
        problems.append("Base64 翻转异常")

    # ③ 表单解析：能不能判断「要求原密码」
    html = ('<form action="/pwd" method="post">'
            '<input name="old_password"><input name="new_password"></form>')
    fs = _forms(html)
    if len(fs) != 1 or "old_password" not in fs[0]["fields"]:
        problems.append("表单字段提取异常，无法判断是否要求原密码")
    html2 = ('<form action="/pwd" method="post">'
             '<input name="new_password"><input name="confirm"></form>')
    if re.search(r"old|current|原|旧", " ".join(_forms(html2)[0]["fields"]), re.I):
        problems.append("不要求原密码的表单被误判为要求原密码")

    # ④ 反自动化控制：**有验证码**与**什么都没有**必须区分开
    if not _antibot_controls('<input name="captcha">', {})[0]:
        problems.append("验证码字段未被识别为反自动化控制")
    if _antibot_controls("<html>登录</html>", {})[0]:
        problems.append("无任何控制时不得无中生有")
    if not _antibot_controls("", {"x-ratelimit-limit": "10"})[0]:
        problems.append("限流响应头未被识别")
    if not _antibot_controls("连续 5 次密码错误将锁定账号 30 分钟", {})[0]:
        problems.append("页面披露的锁定策略未被识别")

    # ⑤ 弱密保问题
    for q, expect in (("你的生日是？", True), ("你的母亲姓名是？", True),
                      ("请设置一个自定义提示词", False)):
        if _weak_question(q) != expect:
            problems.append(f"弱密保问题判定错误：{q!r} 应为 {expect}")

    # ⑥ 无输入时必须 ran=False 并写出原因 —— 不能给一份「看起来做过功课」的空清单
    class _Ctx:
        target = "t.example.com"
        target_url = "https://t.example.com/"
        accounts: list = []
        probe_count = 0
        _cache: dict = {}

        def probe_many(self, paths, base=None):
            return {p: {"status": 0, "body_snippet": "", "error": "不可达"}
                    for p in paths}

        def risk_allowed(self, risk):
            return True

        def get(self, url, method="GET", allow_redirects=True):
            return {"status": 0, "body_snippet": "", "error": "不可达"}

        def note(self, msg):
            pass

        def content_matches(self, path, body):
            return True

    c = _Ctx()
    for fn, label in ((recon_athn03, "ATHN-03 无入口"), (recon_athn08, "ATHN-08 无入口"),
                      (recon_athn09, "ATHN-09 无入口")):
        ro = fn(c)
        if ro.ran is not False:
            problems.append(f"{label}：拿不到任何页面时必须 ran=False"
                            f"（报告要显示「侦察未执行」），实际 ran={ro.ran}")
        if not ro.error:
            problems.append(f"{label}：ran=False 时必须写出原因")
    ro11 = recon_sess11(c)
    if ro11.ran is not False or "测试账号" not in ro11.error:
        problems.append("SESS-11 无授权测试账号时必须 ran=False 且点明缺什么")
    if recon_cryp02(c).ran is not False:
        problems.append("CRYP-02 找不到密文候选时必须 ran=False，"
                        "不能报「没发现 oracle」（那是把没测说成没问题）")

    # ⑦ 侦察确证 → 必须给出 finding，且 lead 要指认到具体入口
    class _CtxLogin(_Ctx):
        def probe_many(self, paths, base=None):
            out = {}
            for p in paths:
                if p in ("login", "user/login"):
                    out[p] = {"status": 200, "headers": {},
                              "body_snippet": ('<form action="/do_login" method="post">'
                                               '<input name="username">'
                                               '<input name="password" '
                                               'type="password"></form>')}
                else:
                    out[p] = {"status": 404, "body_snippet": "not found"}
            return out

    ro = recon_athn03(_CtxLogin())
    if not ro.ran or not ro.findings:
        problems.append("登录页无任何反自动化控制时必须确证（这是可静态证的部分）")
    if not any("login" in str(x).lower() for x in ro.lead):
        problems.append("侦察必须把已定位的登录入口写进 lead 清单")
    if "未执行" not in ro.note or "副作用" not in ro.note:
        problems.append("必须写明「未做重复失败登录」及原因 —— "
                        "沉默的缺失会被读成「已经查过了」")

    # ⑧ 垂直越权（ATHZ-03）与导出越界（DP-03）：正反两侧都必须立得住。
    #    这两个函数全部走 `sessionpool._fetch`，所以这里用桩替换它来造场景。
    from engine.sessionpool import LOGIN_OK as _LOGIN_OK  # noqa: PLC0415
    from engine import sessionpool as _sp  # noqa: PLC0415

    def _mkc(cls):
        o = cls()
        o._cache = {}          # 每个场景独占缓存：sitewide 结论按 ctx 缓存，
        return o               # 共用一份会让下一个场景读到上一个场景的结论

    def _res(status, body="", ctype="text/html", denied=False, bounced=False,
             login_form=False, err=""):
        return {"err": err, "status": status, "body": body, "ctype": ctype,
                "denied": denied, "bounced": bounced, "login_form": login_form}

    class _CtxAz(_Ctx):
        domain = "t.example.com"
        js_result = {"urls": ["/admin/users", "/api/admin/roles"]}
        accounts = [{"name": "低权账号", "role": "普通用户", "authorized": True,
                     "login_state": _LOGIN_OK,
                     "headers": {"Cookie": "sid=low"}, "cookies": {}}]

    class _CtxAzNoAcct(_CtxAz):
        accounts: list = []

    class _CtxAzUniform(_CtxAz):
        fp_result = {"path_probes": {f"p{i}": {"status": 403} for i in range(6)}}

    class _CtxDp(_Ctx):
        domain = "t.example.com"
        js_result = {"urls": ["/export/orders"]}

    _real_fetch = _sp._fetch
    try:
        # —— ATHZ-03 ①：确证（匿名被挡 + 低权 2xx）——
        def _az_confirm(url, account, timeout):
            if account is None:
                return _res(403, "forbidden", denied=True)
            if url.endswith("/admin/users"):
                return _res(200, '{"users":[' + "x" * 300 + "]}",
                            ctype="application/json")
            return _res(403, "forbidden", denied=True)

        _sp._fetch = _az_confirm
        ro = recon_athz03(_mkc(_CtxAz))
        if not ro.ran or len(ro.findings) != 1:
            problems.append("ATHZ-03 确证场景：匿名被挡 + 低权返回业务内容时"
                            f"必须给出 1 条发现，实际 ran={ro.ran} "
                            f"findings={len(ro.findings)}")
        elif ro.findings[0].item_id != "WSTG-ATHZ-03":
            problems.append("ATHZ-03 确证的发现必须归到 WSTG-ATHZ-03")
        else:
            _td = str(ro.findings[0].technical_detail)
            if "403" not in _td or "200" not in _td:
                problems.append("ATHZ-03 的发现必须把两次对照的状态码都写进证据 —— "
                                "只写一侧读者无法复核")

        # —— ATHZ-03 ②：反向对照，匿名自己就能进 → 不得报「提权」——
        def _az_open(url, account, timeout):
            return _res(200, "x" * 300)

        _sp._fetch = _az_open
        ro = recon_athz03(_mkc(_CtxAz))
        if ro.ran is not False or ro.findings:
            problems.append("ATHZ-03 反向对照：匿名即可访问的端点**不是**权限提升"
                            "（属未授权访问），必须不报并说明缺少判定基线，"
                            f"实际 ran={ro.ran} findings={len(ro.findings)}")

        # —— ATHZ-03 ③：反向对照，两个身份都被挡 → 权限校验生效，无发现 ——
        def _az_both_denied(url, account, timeout):
            return _res(403, "forbidden", denied=True)

        _sp._fetch = _az_both_denied
        ro = recon_athz03(_mkc(_CtxAz))
        if not ro.ran or ro.findings:
            problems.append("ATHZ-03 反向对照：匿名与低权身份都被挡时必须判「无发现」"
                            f"（侦察跑了 + 0 条发现），实际 ran={ro.ran} "
                            f"findings={len(ro.findings)}")
        elif not any("权限校验生效" in str(x) for x in ro.lead):
            problems.append("ATHZ-03 无发现时必须在 lead 里写明「权限校验生效」，"
                            "否则读者无法区分「校验通过」与「没测」")

        # —— ATHZ-03 ④：无低权身份时必须 ran=False，且补齐方式要写出来 ——
        _sp._fetch = _az_both_denied
        ro = recon_athz03(_mkc(_CtxAzNoAcct))
        if ro.ran is not False or not ro.error:
            problems.append("ATHZ-03 无可用测试身份时必须 ran=False 并写明原因")
        elif "测试身份" not in ro.error:
            problems.append("ATHZ-03 无身份时必须点明缺的是「测试身份」")
        if "aiscan.py creds" not in (ro.note or ""):
            problems.append("ATHZ-03 无身份时必须给出补齐方式（creds 登记命令），"
                            "否则「怎么补」这句话会被丢掉")

        # —— ATHZ-03 ⑤：整站同码 → 红线，既不报有也不报无 ——
        _sp._fetch = _az_both_denied
        ro = recon_athz03(_mkc(_CtxAzUniform))
        if ro.ran is not False or ro.findings:
            problems.append("ATHZ-03 整站统一 403 时不得下任何结论"
                            "（405/403/401 只在非整站同码时才有证据力）")
        elif "既不报有也不报无" not in (ro.error or ""):
            problems.append("ATHZ-03 整站同码时必须明确写「既不报有也不报无」")

        # —— DP-03 ①：确证（匿名 200 + 数据文件类型）——
        def _dp_confirm(url, account, timeout):
            return _res(200, "order_id,amount\n" + "1,2\n" * 40,
                        ctype="application/vnd.ms-excel")

        _sp._fetch = _dp_confirm
        ro = recon_dp03(_mkc(_CtxDp))
        if not ro.ran or len(ro.findings) != 1:
            problems.append("DP-03 确证场景：匿名拿到导出文件时必须给出 1 条发现，"
                            f"实际 ran={ro.ran} findings={len(ro.findings)}")
        elif ro.findings[0].item_id != "EXT-DP-03":
            problems.append("DP-03 确证的发现必须归到 EXT-DP-03")
        elif "Content-Type" not in str(ro.findings[0].technical_detail):
            problems.append("DP-03 的发现必须把 Content-Type 写进证据 —— "
                            "没有它就分不出「数据文件」与「一张网页」")

        # —— DP-03 ②：反向对照，匿名被挡 → 访问控制生效，不得报导出越界 ——
        _sp._fetch = _az_both_denied
        ro = recon_dp03(_mkc(_CtxDp))
        if not ro.ran or ro.findings:
            problems.append("DP-03 反向对照：匿名被 403 挡住时必须判「无发现」，"
                            f"实际 ran={ro.ran} findings={len(ro.findings)}")

        # —— DP-03 ③：反向对照，返回 HTML → 不是导出产物，不得报 ——
        def _dp_html(url, account, timeout):
            return _res(200, "<html><body>" + "登录" * 200 + "</body></html>",
                        ctype="text/html; charset=utf-8")

        _sp._fetch = _dp_html
        ro = recon_dp03(_mkc(_CtxDp))
        if not ro.ran or ro.findings:
            problems.append("DP-03 反向对照：响应类型是 text/html 时不得判「导出越界」"
                            f"（那只是一张页面），实际 ran={ro.ran} "
                            f"findings={len(ro.findings)}")
        elif not any("不是导出产物" in str(x) for x in ro.lead):
            problems.append("DP-03 遇到 HTML 响应时必须写明「不是导出产物」及不作判据的理由")
    finally:
        _sp._fetch = _real_fetch

    # ⑨ 角色排序只用于挑最低权身份，不得悄悄变成授权判定
    if _role_rank("普通用户") >= _role_rank("管理员"):
        problems.append("角色权限序必须让「普通用户」低于「管理员」")
    if _role_rank("") != 50 or _role_rank("某个没见过的角色") != 50:
        problems.append("未知角色必须给中性档位（50），不得猜成高权或低权")
    _picked = _lowest_privileged([{"name": "A", "role": "管理员"},
                                  {"name": "B", "role": "普通用户"},
                                  {"name": "C", "role": "运营"}])
    if _picked.get("name") != "B":
        problems.append("_lowest_privileged 必须挑出权限最低的那个身份"
                        "（越权对照要用它，挑错了对照就没有敏感度）")
    if problems:
        print("认证类侦察自测不通过：")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print("认证类侦察自测通过：密文候选排除低熵串、翻转只改单字符、"
          "「是否要求原密码」可判、反自动化控制不无中生有、"
          "无输入一律 ran=False 并写明原因、确证时指认具体入口、"
          "未做有副作用动作已写明原因；"
          "垂直越权正反双向对照（确认证、匿名可进不报、两侧都被挡不报、"
          "无身份要求补齐方式、整站同码转待确认）、"
          "导出越界正反双向对照（确认证、匿名被挡不报、返回 HTML 不报）、"
          "角色排序仅供挑最低权身份")
    return 0


# ======================================================================
# 归口登记
# ======================================================================
RECON_MAP = {
    "WSTG-ATHN-03": recon_athn03,
    "WSTG-ATHN-08": recon_athn08,
    "WSTG-ATHN-09": recon_athn09,
    "WSTG-ATHZ-03": recon_athz03,
    "WSTG-SESS-11": recon_sess11,
    "WSTG-CRYP-02": recon_cryp02,
    "EXT-DP-03": recon_dp03,
}


if __name__ == "__main__":  # pragma: no cover
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
