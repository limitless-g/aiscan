"""红队自取 · 通用取号：开放注册自建测试身份。

通用设计（2026-10-09，Juice Shop 基准第八轮前置确立）—— 不绑死任何
一种注册形态，按「先 API 后表单」两路探测，字段名全靠启发式映射：

    JSON API 路：常见注册接口路径 + JS 提取端点 → 载荷矩阵
                 （基础 / 带安全问题 / 仅账密 / 表单编码）
    HTML 表单路：常见注册页路径 → 解析 <form> → 启发式填字段
                 （email / password / confirm / username / 条款勾选），
                 隐藏域原样带回（CSRF 令牌），带会话 Cookie 提交

取号决策链（本模块是第 1 条，2-4 条由既有模块承担）：
    1. 开放注册自建（regself，本模块）
    2. 认产品 → 出厂默认口令受控尝试（credhunt，双重上限 12/3）
    3. 联网检索已泄露凭据（credosint，只产候选）
    4. 全部失败 → 待人工执行 + 报告写清补齐路径（不静默）

授权门控（两把锁同时开，与受控写同款纪律 —— 红线 24）：
  注册会在服务端创建持久状态（用户记录、可能的欢迎邮件 / 日志），性质是写：
    · 档位必须是 deep（standard / safe 不做）
    · 台账必须显式 --allow-write（deep 档 ≠ 被授权写）
    · 环境变量 AISCAN_REGSELF=off 一票否决
    · 每轮最多注册 2 个（越权判定所需的最小数量），单路失败不换路硬试
  任何一条不过 → 具名跳过（写进报告），**不是静默不做**。

纪律：
  · 口令是随机强口令（secrets 生成），不是弱口令爆破 —— 与 credhunt 的
    「弱口令准入」通道语义完全不同，不许混用同一套上限；
  · 口令只写进本机凭据库（write_role 已有权限收紧 + 自动备份），
    不进报告 / manifest / 对话；
  · 失败必须具名（验证码 / 邮箱激活 / 载荷被拒……各是各的原因），
    「没测」要说清为什么没测；
  · POST 预算封顶（每目标 ≤12 发）：注册不是爆破，命中不了就具名退场，
    加大火力是 DoS 的形状。
"""

from __future__ import annotations

import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

# ---- JSON API 路的候选（JS 提取端点由调用方传入，针对性更强）----
_REGISTER_API_PATHS = [
    "/api/Users", "/api/users", "/api/register", "/api/signup",
    "/api/v1/users", "/api/v1/register", "/rest/user/registration",
]
# ---- HTML 表单路的候选页 ----
_REGISTER_PAGE_PATHS = [
    "/register", "/signup", "/join", "/user/register",
    "/account/register", "/member/register", "/en/register",
]
# 登录接口候选（回验用；调用方可传探测到的登录入口）
_LOGIN_API_PATHS = [
    "/rest/user/login", "/api/login", "/api/auth/login",
    "/api/session", "/api/sessions",
]
_LOGIN_PAGE_PATHS = [
    "/login", "/signin", "/user/login", "/account/login",
    "/member/login", "/en/login",
]
# 回验页候选：必须是「登录后才能访问」的页面。是否有区分力由匿名对照
# 实验判定（whoami 类对匿名也返 200 的会被筛掉），不靠白名单猜。
_VERIFY_PATHS = [
    "/rest/basket/1", "/rest/wallet/balance", "/api/privacy",
    "/api/me", "/api/user/me", "/api/account", "/api/profile",
    "/rest/user/whoami", "/api/whoami",
]
# GET 探测里「端点存在」的状态码。401/403 是「存在但要登录」，405 是
# 「存在但方法不符」——都不等于「没有注册功能」，不能拿 404 的语义去读。
_EXISTS_STATUSES = {200, 201, 400, 401, 403, 405}
_TOKEN_RE = re.compile(
    r'"(?:token|access_token|accessToken|jwt|session)"\s*:\s*"([^"]{10,})"')
# 「邮箱已被占用」特征 —— 随机邮箱不该出现，出现说明接口对邮箱做了归一化。
_TAKEN_RE = re.compile(
    r"(?i)already\s+(exists|registered)|已被注册|已经注册|duplicate\s+key")
# 验证码特征：出现即具名退场（不做验证码识别 —— 那是绕过防护，不是测试）
_CAPTCHA_RE = re.compile(
    r"(?i)captcha|recaptcha|hcaptcha|geetest|turnstile|极验|验证码")
_FORM_RE = re.compile(
    r"<form\b[^>]*>", re.I)
_FORM_INPUT_RE = re.compile(
    r"<input\b[^>]*>", re.I)
_TAG_ATTR_RE = re.compile(r'([a-zA-Z-]+)\s*=\s*["\']([^"\']*)["\']')
# 每个目标的 POST 预算（注册载荷矩阵 × 账号数 × 登录回验）。到顶即停。
_POST_BUDGET = 12


@dataclass
class RegResult:
    """单个自取身份的结果。password 只进凭据库，不进任何 dataclass 字段。"""
    role: str = ""
    email: str = ""
    login_url: str = ""
    login_field: str = ""       # 登录接口认的字段名（email / username / 表单字段名）
    cookie_login: bool = False  # 表单 / Cookie 型登录（成功判据交给默认 Cookie 检查）
    verify_path: str = ""
    ok: bool = False
    evidence: str = ""           # 证据特征（不含口令）
    reason: str = ""             # 失败 / 跳过的具名原因


def env_off() -> bool:
    """AISCAN_REGSELF=off 一票否决（与 AISCAN_CREDHUNT 等开关同风格）。"""
    return str(os.environ.get("AISCAN_REGSELF", "")).strip().lower() == "off"


def gate_reason(profile_key: str, ledger_write_ok: bool) -> str:
    """门控不通过时返回具名原因；通过返回空串。

    单独成函数是为了让自测能钉住每一条门（一条锁一断，整条路就不走），
    也让 orchestrator 的接入处不重复实现判定逻辑。
    """
    if env_off():
        return "AISCAN_REGSELF=off（操作者显式关闭红队自取注册）"
    if profile_key != "deep":
        return (f"档位为 {profile_key} —— 注册会在服务端创建持久状态，"
                "只有 deep 档 + 台账写授权同时成立才允许（两把锁，红线 24）")
    if not ledger_write_ok:
        return ("台账未显式授权受控写（--allow-write）—— deep 档只说明"
                "「本档位允许写」，不等于「这一次被授权写」")
    return ""


class _Budget:
    """POST 预算。到顶后再发任何请求都会被拒 —— 由调用方检查并在
    notes 里具名说明「预算耗尽」，绝不静默。

    404/405 的存在性探测可以退款（一次探测不该烧掉一发预算 —— 否则
    登录候选路径的 404 探测就能把预算吃光，真正的表单登录反而没子弹）。
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def spend(self, n: int = 1) -> bool:
        if self.used + n > self.limit:
            return False
        self.used += n
        return True

    def refund(self, n: int = 1) -> None:
        self.used = max(0, self.used - n)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit


def _abs(target_url: str, path: str) -> str:
    return target_url.rstrip("/") + path


def _new_identity(domain: str) -> tuple[str, str]:
    """生成一对随机身份：邮箱 + 强口令。

    邮箱域名用目标自己的域（实测 Juice Shop 接受 aiscan-<hex>@localhost，
    对内部系统通常也成立 —— 大多数注册只校验「含 @ 的格式」）。
    口令是随机强口令 —— 这里没有「弱口令准入」问题，因为不是在爆破，
    是在建号。
    """
    local = f"aiscan-{secrets.token_hex(4)}"
    email = f"{local}@{domain or 'localhost'}"
    password = "Rs-" + secrets.token_urlsafe(12)
    return email, password


def _get(sess: Any, url: str, timeout: int) -> tuple[int, str]:
    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
        return r.status_code, (r.text or "")
    except Exception:  # noqa: BLE001
        return 0, ""


def _post_json(sess: Any, url: str, payload: dict, timeout: int) -> tuple[int, str]:
    try:
        r = sess.post(url, json=payload, timeout=timeout, allow_redirects=True)
        # 注意：正文**不截断**。JWT 令牌动辄 700+ 字符，截到 400 会把闭合
        # 引号切掉 → 令牌正则匹配不上 → 真登录被误判「未下发令牌」
        # （与 D5 同根因：截断必须可见、且不能发生在判据读的窗口上）。
        return r.status_code, (r.text or "")
    except Exception:  # noqa: BLE001
        return 0, ""


def _post_form(sess: Any, url: str, payload: dict, timeout: int) -> tuple[int, str]:
    try:
        r = sess.post(url, data=payload, timeout=timeout, allow_redirects=True)
        return r.status_code, (r.text or "")
    except Exception:  # noqa: BLE001
        return 0, ""


# ==============================================================================
# HTML 表单解析（通用注册路的核心 —— 不依赖任何具体产品）
# ==============================================================================

def _parse_forms(html: str) -> list[dict[str, Any]]:
    """把页面里的 <form> 解析成 {action, method, inputs:[{name,type,value}]}。

    只用正则（运行环境无 bs4，红线：禁引新依赖）。SPA 页面的表单是
    客户端渲染的，静态 HTML 里没有 <form> —— 解析结果为空，自然退回
    API 路，不误判。
    """
    forms: list[dict[str, Any]] = []
    for fm in _FORM_RE.finditer(html):
        tag = fm.group(0)
        attrs = dict(_TAG_ATTR_RE.findall(tag))
        # 找该 form 的闭合范围（form 不嵌套，取到下一个 <form 或文档尾）
        nxt = html.find("<form", fm.end())
        seg = html[fm.end(): nxt if nxt > 0 else len(html)]
        inputs: list[dict[str, str]] = []
        for im in _FORM_INPUT_RE.finditer(seg):
            ia = dict(_TAG_ATTR_RE.findall(im.group(0)))
            name = ia.get("name") or ia.get("id") or ""
            if not name:
                continue
            inputs.append({"name": name,
                           "type": (ia.get("type") or "text").lower(),
                           "value": ia.get("value") or ""})
        if inputs:
            forms.append({"action": attrs.get("action") or "",
                          "method": (attrs.get("method") or "get").upper(),
                          "inputs": inputs,
                          "raw": tag})
    return forms


def _field_kind(inp: dict[str, str]) -> str:
    """启发式判定字段类别：email / password / confirm / username /
    agree（条款勾选）/ hidden / other。"""
    name = (inp["name"] or "").lower()
    typ = (inp.get("type") or "").lower()
    if typ == "hidden":
        return "hidden"
    if "email" in name or typ == "email" or "mail" in name:
        return "email"
    if typ == "password":
        if re.search(r"confirm|repeat|retype|again|2|verify", name):
            return "confirm"
        return "password"
    if re.search(r"agree|term|accept|policy|privacy|consent", name) \
            or typ == "checkbox":
        return "agree"
    if re.search(r"^(username|user|login|nickname|name)$", name) or typ == "text":
        return "username"
    return "other"


def _is_register_form(form: dict[str, Any], page_url: str) -> bool:
    """这个 form 是不是注册表单：有口令框 +（邮箱框 或 页面/动作名像注册）。

    登录表单也有口令框，靠「邮箱框」「action 关键词」「confirm 框」区分；
    分不清时不硬猜 —— 误把登录表单当注册提交等于拿随机身份去登录，
    那是 credhunt 的语义不是本模块的。
    """
    kinds = {_field_kind(i) for i in form["inputs"]}
    if "password" not in kinds:
        return False
    hints = (form["action"] + " " + page_url).lower()
    like_reg = any(k in hints for k in ("register", "signup", "sign-up", "join"))
    return "email" in kinds or "confirm" in kinds or like_reg


def _is_login_form(form: dict[str, Any], page_url: str) -> bool:
    kinds = {_field_kind(i) for i in form["inputs"]}
    if "password" not in kinds:
        return False
    # 登录表单：有口令框但没有确认框 / 邮箱注册特征
    return "confirm" not in kinds


def _fill_register_form(form: dict[str, Any], email: str, password: str,
                        page_url: str) -> tuple[dict[str, str], str]:
    """按启发式填注册表单。返回 (载荷, 疑点说明)。

    hidden 域（CSRF 令牌等）原样带回 —— 落掉它注册必失败，且失败原因
    显示成「载荷被拒」，排查方向整个是错的。
    """
    payload: dict[str, str] = {}
    local = email.split("@")[0]
    for inp in form["inputs"]:
        kind = _field_kind(inp)
        if kind == "hidden":
            payload[inp["name"]] = inp["value"]
        elif kind == "email":
            payload[inp["name"]] = email
        elif kind in ("password", "confirm"):
            payload[inp["name"]] = password
        elif kind == "agree":
            payload[inp["name"]] = "on"
        elif kind == "username":
            payload[inp["name"]] = local
        # other：不填，交给服务端默认值 / 校验说话
    return payload, ""


def _form_action_url(page_url: str, action: str) -> str:
    if not action:
        return page_url
    if action.startswith("http"):
        return action
    from urllib.parse import urljoin
    return urljoin(page_url, action)


# ==============================================================================
# 两路注册
# ==============================================================================

def _find_api_endpoint(sess: Any, target_url: str, timeout: int,
                       js_endpoints: list[str]) -> tuple[str, str]:
    """探测 JSON API 注册端点。返回 (端点, 证据)；找不到返回 ("", 具名原因)。"""
    cands: list[str] = []
    for ep in js_endpoints:
        low = str(ep).lower()
        if str(ep).startswith("/") and any(
                k in low for k in ("user", "register", "signup", "account")):
            if _abs(target_url, ep) not in cands:
                cands.append(_abs(target_url, ep))
    for p in _REGISTER_API_PATHS:
        if _abs(target_url, p) not in cands:
            cands.append(_abs(target_url, p))
    for url in cands[:12]:
        st, body = _get(sess, url, timeout)
        if st == 0:
            continue
        if st in _EXISTS_STATUSES:
            return url, f"GET {url} → {st}（端点存在；注册是否开放由 POST 判定）"
        time.sleep(0.2)
    return "", "API 路：未探测到注册端点（候选全部 404 / 不可达）"


def _find_register_page(sess: Any, target_url: str, timeout: int,
                        js_endpoints: list[str]) -> tuple[str, str, str]:
    """探测含注册表单的页面。返回 (页面URL, 表单, 证据)；失败 ("","",原因)。

    SPA 注册页（/#/register）静态 HTML 里没有 <form>，解析为空 →
    如实返回「页面存在但表单是客户端渲染」，不硬猜。
    """
    cands = [_abs(target_url, p) for p in _REGISTER_PAGE_PATHS]
    for ep in js_endpoints:
        if str(ep).startswith("/") and any(
                k in str(ep).lower() for k in ("register", "signup", "join")):
            if _abs(target_url, ep) not in cands:
                cands.append(_abs(target_url, ep))
    for url in cands[:10]:
        st, html = _get(sess, url, timeout)
        if st != 200 or not html:
            time.sleep(0.2)
            continue
        if _CAPTCHA_RE.search(html[:20000]):
            return "", "", f"表单路：{url} 存在验证码 —— 不做验证码识别（能力缺口，需人工）"
        forms = _parse_forms(html)
        for f in forms:
            if _is_register_form(f, url):
                return url, f, f"GET {url} → 解析到注册表单（{len(f['inputs'])} 个字段）"
        if forms:
            return "", "", (f"表单路：{url} 有表单但不像注册（无口令+邮箱/确认组合，"
                            "页面可能是 SPA 客户端渲染）")
        time.sleep(0.2)
    return "", "", "表单路：未探测到注册页（候选全部 404 / 无表单）"


def _try_register_api(sess: Any, url: str, email: str, password: str,
                      secq: dict | None, timeout: int,
                      budget: _Budget) -> tuple[bool, str]:
    """对单个 API 端点按载荷矩阵尝试。矩阵刻意很小（≤4 发 POST）。"""
    local = email.split("@")[0]
    base = {"email": email, "password": password, "passwordRepeat": password}
    variants: list[tuple[str, dict]] = [("json", base)]
    if secq:
        variants.append(("json", dict(base, securityQuestion=secq,
                                       securityAnswer="aiscan")))
    variants.append(("json", {"email": email, "password": password}))
    variants.append(("json", dict(base, username=local)))
    for kind, payload in variants:
        if not budget.spend():
            return False, "POST 预算耗尽"
        st, body = _post_json(sess, url, payload, timeout)
        if st in (200, 201) and not _TAKEN_RE.search(body):
            return True, f"POST {url}（{kind}）→ {st}"
        if st == 0:
            break   # 请求发不出去，后面的变体也不会成
        time.sleep(0.2)
    return False, f"POST {url} 载荷变体全部被拒"


def _try_register_formpage(sess: Any, page_url: str, form: dict[str, Any],
                           email: str, password: str, timeout: int,
                           budget: _Budget) -> tuple[bool, str]:
    """提交解析到的注册表单（CSRF 已由 hidden 域带回 + 会话 Cookie 携带）。"""
    payload, _ = _fill_register_form(form, email, password, page_url)
    action = _form_action_url(page_url, form.get("action") or "")
    if not budget.spend():
        return False, "POST 预算耗尽"
    st, body = _post_form(sess, action, payload, timeout)
    if st in (200, 201, 302) and not _TAKEN_RE.search(body):
        # 302 / 200 只是「提交被受理」，号能不能用由登录回验判
        return True, f"POST {action}（表单，{len(payload)} 字段）→ {st}"
    return False, f"POST {action}（表单）→ {st} 被拒"


# ==============================================================================
# 登录回验（两路：API JSON + HTML 表单）
# ==============================================================================

def _try_login(sess: Any, target_url: str, email: str, password: str,
               login_url_hint: str, timeout: int,
               budget: _Budget) -> tuple[str, str, str, str, bool, str]:
    """注册成功后立刻回验登录。

    返回 (登录URL, 用户字段名, 令牌, 证据, 是否Cookie型登录, 口令字段名)；
    失败时 url 为空、末位附原因在证据位。

    「注册接口返回 201」≠「这个号能登录」——有些系统注册后要邮箱激活。
    不回验就入库，等于把一个未必存在的身份当成了测试资产。
    """
    # 路 A：JSON 登录接口
    cands: list[str] = []
    if login_url_hint:
        cands.append(login_url_hint if login_url_hint.startswith("http")
                     else _abs(target_url, login_url_hint))
    for p in _LOGIN_API_PATHS:
        u = _abs(target_url, p)
        if u not in cands:
            cands.append(u)
    for url in cands:
        _url_dead = False
        for fname, payload in (("email", {"email": email, "password": password}),
                               ("username", {"username": email,
                                             "password": password})):
            if not budget.spend():
                return "", "", "", "登录回验失败：POST 预算耗尽", False, ""
            st, body = _post_json(sess, url, payload, timeout)
            if st in (404, 405):
                # 端点不存在：退款 + 跳过该 URL 剩余的变体
                # （不退款的实测后果：5 个候选路径 × 变体把 12 发预算
                #  烧光，真正的表单登录反而一发都发不出去）
                budget.refund()
                _url_dead = True
                break
            if st == 200:
                m = _TOKEN_RE.search(body)
                if m:
                    return url, fname, m.group(1), \
                        f"POST {url}（{fname} 字段）→ 200 且下发令牌", False, "password"
            time.sleep(0.2)
        if _url_dead:
            continue
    # 路 B：HTML 登录表单（Cookie 型会话）
    pages = ([login_url_hint] if login_url_hint else [])
    pages += [_abs(target_url, p) for p in _LOGIN_PAGE_PATHS
              if _abs(target_url, p) not in pages]
    for page in pages[:6]:
        st, html = _get(sess, page, timeout)
        if st != 200 or not html:
            continue
        if _CAPTCHA_RE.search(html[:20000]):
            return "", "", "", f"登录回验失败：{page} 存在验证码（能力缺口）", False, ""
        for f in _parse_forms(html):
            if not _is_login_form(f, page):
                continue
            payload: dict[str, str] = {}
            pw_name = ""
            for inp in f["inputs"]:
                k = _field_kind(inp)
                if k == "hidden":
                    payload[inp["name"]] = inp["value"]
                elif k == "password":
                    # 口令框的真实字段名必须带出（可能是 pass / pwd /
                    # loginPassword……）—— 不记录，会话池合成登录时按默认
                    # password 发，对方不认 → 401 →「未下发会话凭据」
                    pw_name = pw_name or inp["name"]
                    payload[inp["name"]] = password
                elif k in ("email", "username"):
                    payload[inp["name"]] = email
            action = _form_action_url(page, f.get("action") or "")
            if not budget.spend():
                return "", "", "", "登录回验失败：POST 预算耗尽", False, ""
            st2, body2 = _post_form(sess, action, payload, timeout)
            if st2 in (200, 302):
                m = _TOKEN_RE.search(body2)
                if m:
                    return action, "form", m.group(1), \
                        f"POST {action}（表单登录）→ {st2} 且下发令牌", False, pw_name
                if sess.cookies:
                    fname = next((i["name"] for i in f["inputs"]
                                  if _field_kind(i) in ("email", "username")), "username")
                    return action, fname, "", \
                        f"POST {action}（表单登录）→ {st2} 且下发会话 Cookie", \
                        True, pw_name
            time.sleep(0.2)
    return "", "", "", "登录回验失败：候选登录入口均未产生会话（可能需要邮箱激活）", False, ""


def _find_verify_path(sess: Any, target_url: str, token: str,
                      js_endpoints: list[str], timeout: int) -> str:
    """匿名对照实验找回验页：匿名被拒（401/403）+ 带凭据 200 才有区分力。

    匿名探针用**全新会话**（不带 Cookie）—— 复用注册会话会把登录态
    泄进「匿名」侧，对照实验就废了。带凭据侧同时覆盖两型登录：
    Bearer 令牌（API 路）与会话 Cookie（表单路）。
    不能靠猜：Juice Shop 的 /rest/user/whoami 匿名也是 200（空 user），
    拿它回验会把「未登录」判成「已登录」—— 用对照实验筛而不是白名单。
    """
    import requests

    anon = requests.Session()
    anon.trust_env = False
    cands = list(_VERIFY_PATHS)
    for ep in (js_endpoints or [])[:20]:
        if ep and str(ep).startswith("/") and ep not in cands:
            cands.append(ep)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    for path in cands:
        url = _abs(target_url, path)
        anon_st, _ = _get(anon, url, timeout)
        if anon_st not in (401, 403):
            continue
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=False,
                         headers=headers)
            if r.status_code == 200:
                return path
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.1)
    return ""


# ==============================================================================
# 主入口
# ==============================================================================

def _regself_live_state(credguide: Any, cred_file: Any, role: str,
                        sess: Any, timeout: int) -> bool | None:
    """三角判活，专门解决「凭据库有号就跳过」在实例重置后的假阴性。

    返回：
      · True   凭据库账号能真登录（靶场可达 + 号有效）
      · False  靶场可达但号已失效（应 prune 并重注册）
      · None   靶场不可达 / 瞬断，无法判定（保持原样，不当成活也不当死亡）

    不猜：连不上时绝不把残留凭据当「活的」用，也绝不误删 —— 避免靶场瞬断
    把一堆好号清掉，或把孤儿号当可用（红线 18：登记了却不生效比没登记更危险）。
    """
    rec = credguide.credentials_full(role, cred_file)
    u = (rec.get("username") or "").strip()
    pw = (rec.get("password") or "").strip()
    lu = (rec.get("login_url") or "").strip()
    if not (u and pw and lu):
        return False
    field = rec.get("login_username_field") or "email"
    body_marker = rec.get("login_success_body") or ""
    try:
        resp = sess.post(lu, json={field: u, "password": pw},
                         timeout=timeout, allow_redirects=False)
    except Exception:
        return None  # 靶场不可达
    if resp.status_code != 200:
        return False
    if body_marker and body_marker in resp.text:
        return True
    for _k in resp.cookies:
        if any(t in _k.lower() for t in ("token", "session", "auth")):
            return True
    return False


def run(target_url: str, domain: str, cred_file: Any,
        js_endpoints: list[str] | None = None, login_url_hint: str = "",
        want: int = 2, timeout: int = 15) -> tuple[list[RegResult], list[str]]:
    """主入口：自注册 want 个测试身份并写入本机凭据库。

    返回 (结果列表, 报告 notes)。口令只进凭据库文件（write_role 收紧
    权限 + 覆盖前自动备份），notes / RegResult 里都不出现口令原文。
    """
    import requests

    from engine import credguide

    notes: list[str] = []
    results: list[RegResult] = []
    sess = requests.Session()
    sess.verify = False
    # 禁信环境代理 —— 与 HttpProbeClient 同一纪律（fingerprint.py 的
    # disable_ambient_proxy 注释里写的四条后果全部适用）。实测教训
    # （2026-10-09，Juice Shop）：沙箱代理在 keep-alive 复用连接上会把
    # 第二个请求（POST 注册）错误路由到站点根 → 返回 SPA 首页 200 →
    # 「注册成功」是假的、「登录未下发令牌」也是假的 —— 两层假象同源。
    # 扫描主链路因 fingerprint 导入即清代理而幸免；本模块独立建 Session，
    # 必须自己关掉 trust_env。
    sess.trust_env = False
    js_endpoints = [str(e) for e in (js_endpoints or []) if e]
    budget = _Budget(_POST_BUDGET)

    # 幂等：凭据库里已有 regself_ 前缀的身份，且「确证还能登录」才跳过。
    # 跨轮幂等比轮内去重更重要 —— 季度扫描每次都建两个新号，几轮之后
    # 目标系统里就躺着一排无人认领的测试账号（那本身就是个卫生问题）。
    # 但「凭据库有号」≠「号还能用」：容器重建 / 实例重置后旧号被清、凭据
    # 却残留，直接跳过会让越权 / IDOR 类检查整轮拿不到双账号（第 28 轮分数
    # 倒退根因）。所以这里逐个真登录校验：确证存活才计入幂等、确证死亡
    # 就 prune、连不上（靶场不可达）的保持原样不 prune 也不虚报存活。
    raw_existing = [r for r in credguide.read_roles(cred_file)
                    if str(r).startswith("regself_")
                    and credguide.has_credentials(r, cred_file)]
    _live, _dead, _unknown, _reachable = [], [], [], False
    for _r in raw_existing:
        _st = _regself_live_state(credguide, cred_file, _r, sess, timeout)
        if _st is True:
            _live.append(_r); _reachable = True
        elif _st is False:
            _dead.append(_r); _reachable = True
        else:
            _unknown.append(_r)
    for _r in _dead:
        _ok, _msg = credguide.clear_role(cred_file, _r)
        notes.append(f"[红队自取·注册] 凭据库里的 {_r} 登录校验失败"
                     f"（靶场可达但号已失效）—— 已清除，本轮重新注册"
                     + ("" if _ok else f"（清除失败：{_msg}）"))
    existing = _live + _unknown
    if len(existing) >= want:
        if _reachable and not _dead:
            notes.append(f"[红队自取·注册] 凭据库已有 {len(_live)} 个自取身份"
                         f"（{', '.join(sorted(_live))}）且本轮已联网校验存活"
                         " —— 不重复注册")
        else:
            notes.append(f"[红队自取·注册] 凭据库已有 {len(existing)} 个自取身份"
                         "（靶场不可达、未联网校验存活）—— 不重复注册"
                         "（靶场恢复后若号已失效会被自动清除并重注册）")
        return results, notes

    # 两路探测：API 优先（针对性更强），表单兜底（通用性更强）
    api_url, api_ev = _find_api_endpoint(sess, target_url, timeout, js_endpoints)
    page_url, page_form, page_ev = ("", None, "")
    if not api_url:
        page_url, page_form, page_ev = _find_register_page(
            sess, target_url, timeout, js_endpoints)
    if not api_url and not page_url:
        why = page_ev or api_ev
        notes.append(f"[红队自取·注册] 未执行：{why}—— 转入默认口令 / 联网检索"
                     "通道，仍无果则相关项记「待人工执行」")
        return results, notes

    secq = None
    if api_url:
        secq = _find_security_question(sess, target_url, timeout)

    made = 0
    for i in range(want - len(existing)):
        role = f"regself_{len(existing) + i + 1}"
        email, password = _new_identity(domain)

        if api_url:
            ok, ev = _try_register_api(sess, api_url, email, password,
                                       secq, timeout, budget)
            how = "API"
        else:
            ok, ev = _try_register_formpage(sess, page_url, page_form,
                                            email, password, timeout, budget)
            how = "表单"
        if not ok:
            results.append(RegResult(role=role, email=email, reason=ev))
            notes.append(f"[红队自取·注册] {role} 注册失败（{how} 路）：{ev}"
                         " —— 能力缺口，本轮不换路硬试（那是爆破的形状）")
            break

        login_url, field, token, lev, cookie_login, pw_field = _try_login(
            sess, target_url, email, password, login_url_hint, timeout, budget)
        if not login_url:
            results.append(RegResult(role=role, email=email, reason=lev))
            notes.append(f"[红队自取·注册] {role} 注册成功但{lev}")
            break

        vpath = _find_verify_path(sess, target_url, token,
                                  js_endpoints, timeout)
        login_extra: dict[str, Any] = {
            "login_username_field": field if field != "form" else "username",
            "login_no_form_discover": True,
        }
        if not cookie_login:
            # token-in-body 型：必须显式给成功判据，否则会话池按
            # 「Cookie 判据」合成登录，号是好的也会被判「未下发会话凭据」
            login_extra["login_success_status"] = 200
            login_extra["login_success_body"] = "token"
        else:
            # Cookie 型：让登录页自身可被再发现（form action 里有真实提交地址）
            login_extra["login_no_form_discover"] = False
            # 表单里口令框的真实字段名（pass / pwd / …，缺省才是 password）
            if pw_field and pw_field != "password":
                login_extra["login_password_field"] = pw_field
        if vpath:
            login_extra["verify_path"] = vpath
        w_ok, w_note = credguide.write_role(
            cred_file, role, cookies={}, headers={}, username=email,
            password=password, login_url=login_url, login_extra=login_extra)
        if not w_ok:
            results.append(RegResult(role=role, email=email, reason=w_note))
            notes.append(f"[红队自取·注册] {role} 注册成功但写入凭据库失败：{w_note}")
            break
        made += 1
        results.append(RegResult(
            role=role, email=email, login_url=login_url, login_field=field,
            cookie_login=cookie_login, verify_path=vpath, ok=True,
            evidence=f"{'注册 ' + (api_ev or page_ev)}；{ev}；{lev}"
                     + (f"；回验页 {vpath}（匿名 401/403 + 带令牌 200，"
                        "有区分力）" if vpath else
                        "；未找到有区分力的回验页（登录态只能记未验证）")))
        notes.append(
            f"[红队自取·注册] {role} 已建立：{email} 注册成功、登录已回验"
            f"（{'令牌下发' if not cookie_login else '会话 Cookie 下发'}），"
            f"凭据已写入本机凭据库（口令不落报告）；{ev}；{lev}")
        if budget.exhausted:
            notes.append("[红队自取·注册] POST 预算耗尽 —— 后续身份本轮不再尝试")
            break

    if made:
        notes.append(f"[红队自取·注册] 本轮自建 {made} 个测试身份 —— 越权 / "
                    "IDOR 类检查将以此身份执行；该动作已按受控写纪律"
                    "（deep 档 + 台账写授权）放行并在此留痕")
    return results, notes


def _find_security_question(sess: Any, target_url: str,
                            timeout: int) -> dict | None:
    """Juice Shop 式注册需要安全问题。探到就用，探不到不加该字段。"""
    st, body = _get(sess, _abs(target_url, "/api/SecurityQuestions"), timeout)
    if st == 200 and '"question"' in body:
        m = re.search(r'"id"\s*:\s*(\d+)[^}]*?"question"\s*:\s*"([^"]+)"', body)
        if m:
            return {"id": int(m.group(1)), "question": m.group(2)}
        m2 = re.search(r'"question"\s*:\s*"([^"]+)"[^}]*?"id"\s*:\s*(\d+)', body)
        if m2:
            return {"id": int(m2.group(2)), "question": m2.group(1)}
    return None
