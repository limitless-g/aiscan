"""黑客视角的凭据获取（credential hunting）。

为什么需要它
----------------------------------------------------------------------------
上一版的处理是：扫描中途发现缺登录凭据 → **暂停 30 分钟等运维把凭据递过来**。
这个流程在红队视角下是错的，而且错得很具体：

① 真实攻击者不会等 —— 他手里没有测试账号，他要**自己弄一个**。
   站在公网、零凭据地把「登录入口 + 弱口令」试出来，本来就是攻击路径的一部分
   （对应检查项 WSTG-ATHN-02「默认凭据」，其 verify 期望写的正是「受控尝试、限次」）。
② 一份「要凭据」的暂停提示，会把红队报告变成一份「需要业务方配合才能完成」的
   自查表 —— 而通晒版面向的是攻击视角的实测结论。
③ 挂起 30 分钟在无人值守场景（批量 / 定时）里就是纯粹的空转。

所以本模块做三件事，对应黑客的三条路：

| 黑客的路 | 本模块的做法 | 档位 |
|---|---|---|
| ① 找登录入口 | 登录入口发现（复用指纹阶段的证据，必要时在**已知路径清单**内补探） | standard 起 |
| ② 猜 / 撞口令 | 受限默认口令尝试（极小字典 + 硬上限 + 命中风控即停） | standard 起（safe 恒 0） |
| ③ 从外部泄露信息找线索 | 只出线索与检索指引，**不自动联网检索**（交人工） | 任意档（纯提示） |

不可回退的红线（每条都有自测钉住）
----------------------------------------------------------------------------
1. **双重硬上限**：总尝试次数与单账号尝试次数同时封顶，取档位配置与模块内
   常量中更小的那个。安全档恒为 0（一个请求都不发）。
2. **命中风控即停**：出现验证码 / 锁定 / 频繁 / 429 / 403 → 立即停止，
   整项记「待确认」，不继续试（账号锁定的副作用不可逆，属清单里明列的人工项）。
3. **口令原文不落盘**：每次尝试只记账号名与口令的散列指纹，扫描留痕与报告里
   不出现口令原文。（例外说明：复现脚本内嵌的是那份**公开的**教科书级默认口令
   字典 —— 与 nuclei 的 default-login 模板同理，它不含目标特有的任何凭据；
   报告披露的命中信息只有账号名与指纹。）
4. **同源约束**：只打目标主机下的端点；不在探测到的登录入口之外的域名发请求。
5. **成功必须回验**：命中的会话必须走 sessionpool 的「匿名对照实验」回验，
   否则不算「已登录」—— 否则一次「登录成功」的假象会被用于后续越权测试。
6. **逐次留痕**：每次尝试写进报告（第 4 章授权与范围），可被审计复算。
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

# 默认口令字典：只放「教科书级」的组合。刻意保持极小 ——
# 这份字典每多一条，生产系统的账号锁定风险就多一分，
# 而命中率并不会显著提高（真实弱口令系统几乎都是这几个）。
DEFAULT_PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "P@ssw0rd"),
    ("test", "test"),
    ("test", "test123"),
    ("test", "123456"),
    ("guest", "guest"),
    ("root", "root"),
    ("sysadmin", "sysadmin"),
    ("user", "user"),
    ("demo", "demo"),
)

# 模块级硬上限：任何档位、任何配置都不能越过它。
HARD_MAX_TOTAL_ATTEMPTS = 12
HARD_MAX_PER_ACCOUNT = 3
# 单次扫描内两次登录尝试之间的最小间隔（秒）—— 反自动化频控的第一道自约束。
MIN_GAP_SECONDS = 1.5

# 登录入口候选。**这是「已知路径清单」，不是目录爆破** ——
# 与 credguide.LOGIN_PATHS 同源语义，仅用于「没探到入口时补几个 GET」。
FALLBACK_LOGIN_PATHS: tuple[str, ...] = (
    "/login", "/signin", "/user/login", "/account/login", "/admin/login",
    "/api/login", "/api/auth/login", "/auth/login", "/sso/login",
)

# 「这个地址自己就长得像个登录入口」——用于判断「无表单页时能不能直接 POST」。
# 为什么要卡这一道：无表单页的入口可能是 POST-only 的 JSON 接口，
# 也可能是 SPA 外壳、或者一个恰好只收 POST 的业务接口（`/api/order/create`）。
# 只有路径名自己点明是登录，才允许我们在**不知道字段名**的情况下直接提交口令 ——
# 往一个名字与登录无关的 POST 接口灌口令，是纯粹的越界动作。
LOGIN_LIKE_RE = re.compile(
    r"(login|signin|sign-in|logon|auth|passport|session|token)", re.I)

# 无表单页时假定的字段名。选 `username` / `password` 是因为它是压倒性主流；
# **假定就意味着可能猜错**，所以：
#   · 结果里必须记 `assumed_fields=True`，报告要写清「字段名是假定的」；
#   · 猜错的表现是「服务端拒收 / 一直认证失败」，与「口令不对」无法区分 ——
#     因此这种情形下的「未命中」**不能**推断为系统不存在弱口令（报告里写明）。
ASSUMED_FIELD_PAIR: tuple[str, str] = ("username", "password")

# 风控 / 锁定信号：命中任一即停。
LOCKOUT_PATTERNS = re.compile(
    r"(验证码|captcha|图形码|短信验证|锁定|已锁|冻结|账号被停用|"
    r"尝试次数过多|操作过于频繁|请稍后再试|稍后重试|访问过于频繁|"
    r"too\s+many|locked|temporarily\s+blocked|rate\s+limit|try\s+again\s+later)",
    re.I)

# 认证失败信号：出现即判「这组口令不对」（比「未出现成功信号」保守，
# 避免把「参数名猜错」当成「口令不对」）。
FAIL_PATTERNS = re.compile(
    r"(密码错误|账号或密码|用户名或密码|登录失败|认证失败|凭据无效|"
    r"invalid\s+(password|credential)|incorrect|authentication\s+failed|"
    r"wrong\s+password|bad\s+credentials)",
    re.I)

# 会话凭据特征
SESSION_HEADER_RE = re.compile(r"(set-cookie|authorization)", re.I)
SESSION_VALUE_RE = re.compile(
    r"(session|jsessionid|token|ticket|remember|sid|auth)", re.I)
TOKEN_BODY_RE = re.compile(
    r"\"?(access_?token|id_?token|token|ticket)\"?\s*[:=]\s*\"([^\"]{8,})\"", re.I)

USER_FIELD_RE = re.compile(r"(user|account|login|name|phone|mobile|email)", re.I)
PASS_FIELD_RE = re.compile(r"(pass|pwd|secret|credential)", re.I)
FORM_RE = re.compile(r"(?is)<form\b.*?</form>")
INPUT_RE = re.compile(r"(?is)<input\b[^>]*>")
ACTION_RE = re.compile(r"(?is)<form[^>]*\baction=[\"']?([^\"'\s>]+)")
NAME_RE = re.compile(r"(?is)\bname=[\"']?([^\"'\s>]+)")
TYPE_RE = re.compile(r"(?is)\btype=[\"']?([^\"'\s>]+)")
HAS_PASSWORD_RE = re.compile(r"(?i)type=[\"']?password")


def _pw_fingerprint(account: str, password: str) -> str:
    """口令指纹：只留不可逆散列，报告里可复算、不可还原。

    加盐用账号名 —— 否则同一份字典在不同目标上产生同一串指纹，
    一眼就能反查（字典只有一百多条，不做盐等于明文）。
    """
    raw = f"{account}:{password}:aiscan".encode()
    return hashlib.sha256(raw).hexdigest()[:12]


@dataclass
class HuntAttempt:
    """一次登录尝试的留痕。**不含口令原文**。"""

    url: str
    account: str
    pw_fp: str
    outcome: str            # 认证失败 / 疑似成功 / 风控拦截 / 请求异常
    status: int = 0
    note: str = ""
    elapsed_ms: int = 0
    #: 这一组口令是**从哪来的**（通用字典 / 本地产品默认口令库 / 公开资料检索·产品名）。
    #: 必须逐条记：报告里「未命中」这一句的含义，取决于试的是通用字典
    #: 还是该产品的出厂默认值 —— 后者未命中，信息量高得多。
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url, "account": self.account, "pw_fingerprint": self.pw_fp,
            "outcome": self.outcome, "status": self.status,
            "note": self.note, "elapsed_ms": self.elapsed_ms,
            "source": self.source,
        }


@dataclass
class HuntResult:
    """一次凭据获取的全部结果。"""

    enabled: bool = False
    reason: str = ""                     # 未启用 / 停下的原因
    entry_url: str = ""                  # 实际使用的登录入口
    entry_source: str = ""               # path_probe / fallback / accounts_config
    attempts: list[HuntAttempt] = field(default_factory=list)
    found: list[dict[str, Any]] = field(default_factory=list)   # 会话池兼容记录
    stopped_reason: str = ""
    notes: list[str] = field(default_factory=list)
    #: 提交时用的字段名是**假定**的（登录入口没有表单页，无法读出字段名）。
    #: 必须单独落一个标志位：这种情形下「未命中」的含义与「有表单页时未命中」
    #: 完全不同 —— 前者可能是字段名就猜错了，压根没试对口令校验那一层。
    assumed_fields: bool = False
    #: 口令来源构成：来源标签 -> 条数。报告要能回答「这次试的到底是什么」，
    #: 只写「共 N 组」是不够的 —— 试了 6 组产品默认值和试了 9 组通用弱口令，
    #: 是两种完全不同的检测强度。
    pair_source_counts: dict[str, int] = field(default_factory=dict)

    @property
    def tried(self) -> int:
        return len(self.attempts)

    @property
    def lockout_hit(self) -> bool:
        return any(a.outcome == "风控拦截" for a in self.attempts)

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        if not self.enabled:
            lines.append(f"[凭据获取] 未执行：{self.reason}")
            return lines
        if not self.entry_url:
            lines.append(f"[凭据获取] 未定位到登录入口：{self.stopped_reason or self.reason}")
            return lines
        lines.append(f"[凭据获取] 登录入口 {self.entry_url}"
                     f"（来源：{self.entry_source}）；尝试 {self.tried} 组口令")
        if self.pair_source_counts:
            _desc = "、".join(f"{k} {v} 组"
                              for k, v in self.pair_source_counts.items())
            lines.append(f"[凭据获取] 口令来源构成：{_desc}")
        if self.found:
            names = "、".join(str(r.get("name")) for r in self.found)
            lines.append(f"[凭据获取] 命中 {len(self.found)} 个身份：{names}"
                         " —— 已用于认证 / 越权类检查（口令原文不入报告）")
        elif self.lockout_hit:
            lines.append("[凭据获取] 命中风控 / 锁定信号，已立即停止（副作用不可逆，"
                         "剩余组合不再尝试）；「默认凭据」记「待确认」")
        else:
            lines.append("[凭据获取] 全部尝试均未命中 —— 「默认凭据」本项到此为止，"
                         "但这不等于系统不存在弱口令（口令来源与规模均受限，"
                         "属受控尝试）")
        if self.stopped_reason:
            lines.append(f"[凭据获取] 停止原因：{self.stopped_reason}")
        return lines

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled, "reason": self.reason,
            "entry_url": self.entry_url, "entry_source": self.entry_source,
            "tried": self.tried,
            "found_identities": [str(r.get("name")) for r in self.found],
            "stopped_reason": self.stopped_reason,
            "lockout_hit": self.lockout_hit,
            "assumed_fields": self.assumed_fields,
            "pair_source_counts": dict(self.pair_source_counts),
            "attempts": [a.to_dict() for a in self.attempts],
            "notes": list(self.notes),
        }


# ==============================================================================
# 登录入口发现
# ==============================================================================
def discover_login_entry(client: Any, target_url: str,
                         path_probes: dict[str, Any] | None = None,
                         allow_probe: bool = True) -> tuple[str, str, str]:
    """定位登录入口。返回 (url, 证据说明, 来源)。

    顺序刻意如此：**先用已有证据**（指纹阶段探过的路径），拿不到再在
    已知路径清单内补探。绝不为了「找到入口」去猜站外地址。
    """
    from engine import credguide  # noqa: PLC0415

    u, ev, src = credguide.find_login_entry(path_probes or {})
    if u:
        return u, ev, src or "path_probe"

    if not allow_probe:
        return "", "未探到登录入口（本档位不做补探）", "none"

    base = target_url.rstrip("/")
    host = urlparse(base).netloc
    # `Allow` 头命中先攒着，**不能第一个就返回** —— 见下面的对照实验。
    _allow_hits: list[tuple[str, str, str]] = []   # (url, path, 证据)
    _n405 = 0
    _n405_allow = 0
    _probed_n = 0
    for path in FALLBACK_LOGIN_PATHS:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            p = client.fetch(url)
        except Exception:  # noqa: BLE001
            continue
        _probed_n += 1
        st = int(getattr(p, "status", 0) or 0)
        body = str(getattr(p, "body_snippet", "") or "")
        if st in (200, 401, 403) and (HAS_PASSWORD_RE.search(body)
                                      or re.search(r"(login|登录)", body, re.I)):
            return url, f"补探命中 {path}（HTTP {st}，页面含登录特征）", "fallback"
        # POST-only 的登录接口（GET 405）也算命中 —— 判据与 credguide 共用
        # 同一个函数，不另写一套：两个模块对同一个响应给出相反结论，
        # 正是这一类缺陷最典型的成因（特征表说「有登录」，凭据指引说「未命中」）。
        if st == 405:
            _n405 += 1
            _po = credguide._post_only_evidence(p)
            if _po:
                _n405_allow += 1
                _allow_hits.append((url, path, _po))

    # `Allow` 头证据的**对照实验**（与 credguide.find_login_entry 同一判据，
    # 不能只在一处做）：若这批 405 里大多数都带着同一个 `Allow`，
    # 那是站点/边缘的默认响应头，不是「这个路径只收 POST」的特征。
    # 不做这道对照的后果是**假阳性** —— 明明整站被拦截，
    # 却报出「补探命中 /login，是 POST-only 登录接口」，
    # 比漏报更糟：读者会据此以为应用可达、甚至去追一个不存在的接口。
    _allow_trustworthy = not (_n405 >= 2 and _n405_allow * 2 >= _n405)
    if _allow_hits and _allow_trustworthy:
        url, path, ev = _allow_hits[0]
        return url, f"补探命中 {path}：{ev}", "fallback"
    if _allow_hits:
        return "", (f"补探 {_probed_n} 个常见登录路径：{_n405} 个返回 HTTP 405，"
                    f"其中 {_n405_allow} 个都带同一个 `Allow` 头声明允许 POST —— "
                    "属**站点级默认响应头**，**不构成**登录接口的证据。"
                    "**请用 --login-url 明确告知登录入口**"), "none"
    # 补探也没找到时，**用指纹阶段那份更具体的原因**，不用这句笼统的兜底话术。
    # 两者信息量差得很远：「其中 login 返回 HTTP 405 且不带 Allow 头」
    # 直接告诉读者「有东西挡着」；「均未命中」会被读成「这系统没有登录功能」。
    if ev:
        return "", ev, "none"
    return "", (f"已探测 {len(FALLBACK_LOGIN_PATHS)} 个常见登录路径（{host}）"
                "均未命中含登录特征的页面"), "none"


# ==============================================================================
# 口令尝试
# ==============================================================================
def _extract_form(url: str, client: Any) -> tuple[str, str, str, int]:
    """从登录页里取 (提交地址, 账号字段名, 口令字段名, GET 状态码)。

    状态码是必须带出来的：**「没有表单页」有两种完全不同的成因**，
    处置动作也完全相反（见 hunt 里的分支）：

      · GET 返回 405 —— 这个地址根本不响应 GET，它只接受 POST。
        没有页面可读，字段名只能按约定假定 —— 那就假定，然后试。
      · GET 返回 200 却没有口令字段 —— 页面明确告诉我们「这里不收口令」
        （验证码 / 短信验证 / SSO 单点 / 第三方登录跳转）。
        此时硬提交等于明知不可为而为之：服务端一定拒收，还会留下
        一串无意义的失败登录记录。停止并交人工才是对的。
    """
    try:
        page = client.fetch(url)
    except Exception:  # noqa: BLE001
        return url, "", "", 0
    status = int(getattr(page, "status", 0) or 0)
    body = str(getattr(page, "body_snippet", "") or "")
    m = FORM_RE.search(body)
    form = m.group(0) if m else ""
    if not form:
        # 不是表单页（JSON 接口 / SPA）—— 提交地址就用入口本身
        return url, "", "", status
    action = (ACTION_RE.search(form).group(1) if ACTION_RE.search(form) else "") or url
    action = urljoin(url, action)
    user_field = pass_field = ""
    for inp in INPUT_RE.findall(form):
        t = (TYPE_RE.search(inp).group(1) if TYPE_RE.search(inp) else "").lower()
        nm = NAME_RE.search(inp).group(1) if NAME_RE.search(inp) else ""
        if not nm:
            continue
        if t == "password" or PASS_FIELD_RE.search(nm):
            pass_field = pass_field or nm
        elif USER_FIELD_RE.search(nm):
            user_field = user_field or nm
    return action, user_field, pass_field, status


def _classify(status: int, headers: dict[str, Any], body: str,
              final_url: str, entry_url: str) -> tuple[str, str]:
    """判定一次尝试的结果。返回 (结果类别, 说明)。"""
    hdr = {str(k).lower(): v for k, v in (headers or {}).items()}
    if LOCKOUT_PATTERNS.search(body) or status == 429:
        return "风控拦截", f"响应出现风控 / 锁定信号（HTTP {status}）"

    set_cookie = hdr.get("set-cookie", "")
    sessionish = bool(SESSION_VALUE_RE.search(str(set_cookie)))
    fail = FAIL_PATTERNS.search(body)
    token_m = TOKEN_BODY_RE.search(body or "")
    redirected_in = status in (301, 302, 303, 307)
    left_login = bool(final_url) and not re.search(
        r"(login|signin|logon|sso|passport)", str(final_url), re.I)

    if fail and not token_m:
        return "认证失败", "响应含认证失败特征"
    if token_m:
        return "疑似成功", f"响应体含会话令牌字段（{token_m.group(1)}）"
    if set_cookie and sessionish:
        return "疑似成功", "响应下发了会话类 Cookie"
    if redirected_in and left_login and urlparse(final_url).netloc:
        return "疑似成功", f"提交后被重定向到登录页之外的地址（{final_url[:80]}）"
    if status in (401, 403):
        return "认证失败", f"服务端返回 {status}"
    if status in (400, 422):
        return "认证失败", f"请求被拒（HTTP {status}，疑似参数名不匹配）"
    # 200 且没有任何成功/失败特征 —— 不下结论，按失败处理但如实说明
    return "认证失败", "响应既无成功特征也无失败特征（按未命中处理）"


def hunt(
    client: Any,
    target_url: str,
    profile: dict[str, Any] | None = None,
    profile_key: str = "standard",
    path_probes: dict[str, Any] | None = None,
    log_fn: Any = None,
    guard: Any = None,
    extra_pairs: list[tuple[str, str]] | None = None,
    pair_sources: dict[tuple[str, str], str] | None = None,
) -> HuntResult:
    """执行一次黑客视角的凭据获取。

    `extra_pairs` 是 `engine.credosint` 产出的候选口令（按识别到的产品生成，
    或从公开资料里检索到并经准入的）。它们**排在最前面**：识别出是 Nacos 之后
    还先去试 admin/admin，是在浪费本就极少的尝试配额。
    无论候选从哪来，本函数的三条硬约束一律生效（次数上限 / 风控即停 / 不留原文）。

    前置条件（缺一即整段跳过并说明原因，绝不静默）：
      · 档位配置 `credential_hunt.enabled` 为真（安全档恒假）
      · 目标可达且未被边界全量拦截（调用方保证）
      · `AISCAN_CREDHUNT` 未被置为 off
    """
    import os

    res = HuntResult()
    cfg = dict(((profile or {}).get("credential_hunt") or {}))
    enabled = bool(cfg.get("enabled", False))
    if os.environ.get("AISCAN_CREDHUNT", "").strip().lower() in ("off", "0", "false"):
        res.reason = "已由 AISCAN_CREDHUNT=off 显式关闭"
        return res
    if not enabled:
        res.reason = (f"档位「{profile_key}」未启用口令探测"
                      "（安全档恒不启用：登录尝试会在服务端留下失败日志，"
                      "且可能触发账号锁定）")
        return res

    res.enabled = True
    # 三重封顶取最小：档位配置 / 模块硬上限 / 单账号硬上限
    max_total = min(int(cfg.get("max_attempts", HARD_MAX_TOTAL_ATTEMPTS)),
                    HARD_MAX_TOTAL_ATTEMPTS)
    max_per_account = min(int(cfg.get("max_per_account", HARD_MAX_PER_ACCOUNT)),
                          HARD_MAX_PER_ACCOUNT)
    allow_probe = bool(cfg.get("discover_login", True))
    # 尝试间隔：默认取模块常量（1.5s），档位配置可调整（自测会压到 0.01s）。
    # 这里不做「只能收紧」的钳制 —— 真正的硬约束是**尝试次数上限**与
    # **命中风控即停**，间隔是辅助手段；把它钳死后自测每次要跑十几秒，
    # 得不偿失。
    min_gap = max(0.0, float(cfg.get("min_gap_seconds", MIN_GAP_SECONDS)) or 0.0)
    if max_total <= 0:
        res.reason = "档位配置的尝试上限为 0"
        return res

    entry, ev, src = discover_login_entry(
        client, target_url, path_probes=path_probes, allow_probe=allow_probe)
    res.entry_source = src
    if ev:
        res.notes.append(f"[凭据获取] 入口判定依据：{ev}")
    if not entry:
        res.stopped_reason = ev
        return res

    # 同源约束：入口必须与目标同主机。**要在把 URL 记进结果之前判** ——
    # 先记后判会让「已放弃的越界地址」留在结果里，下游一旦照着它发请求
    # 就越出授权范围了（有自测钉这一条）。
    if (urlparse(entry).netloc
            and urlparse(entry).netloc != urlparse(target_url).netloc):
        res.enabled = False
        res.reason = (f"登录入口 {urlparse(entry).netloc} 与目标 "
                      f"{urlparse(target_url).netloc} 不同源，已放弃（越界）")
        res.notes.append(f"[凭据获取] 放弃越界入口：{entry[:120]}")
        res.stopped_reason = res.reason
        return res

    res.entry_url = entry

    action, user_field, pass_field, _get_status = _extract_form(entry, client)
    if not (user_field and pass_field):
        # 登录入口没有可解析的表单页。**两种成因的区别是这里唯一的判据**：
        #   ① GET 返回 405（这个地址只收 POST，压根没有页面）→ 直接按约定字段名
        #      提交。表单读不出来就换一种问法再问一次 —— 黑客就是这么干的。
        #      路径名必须自己点明是登录：往 `/api/order/create` 这种几十个
        #      只收 POST 的业务接口灌口令，是纯粹的越界动作。
        #   ② GET 返回页面，但页面里没有口令字段 → 页面明确说了「这里不收口令」
        #      （验证码 / 短信 / SSO 单点 / 第三方跳转）。不提交：服务端必然拒收，
        #      还会在对方日志里留下一串无意义的失败登录记录。
        if _get_status == 405 and LOGIN_LIKE_RE.search(
                urlparse(entry).path or ""):
            user_field, pass_field = ASSUMED_FIELD_PAIR
            action = entry
            res.assumed_fields = True
            res.notes.append(
                f"[凭据获取] 入口 `{entry}` 对 GET 返回 405（只接受 POST），"
                f"无可读页面：字段名按最常见约定**假定**为 "
                f"`{user_field}` / `{pass_field}`。注意这层假定 —— "
                "若服务端用的是别的字段名，本次全部尝试都会表现为认证失败，"
                "与「口令不对」无法区分，**不能据此推断系统不存在弱口令**")
        else:
            res.stopped_reason = (
                f"登录入口对 GET 返回 HTTP {_get_status}，但页面中未识别出"
                "账号 / 口令字段（可能是验证码 / 短信 / SSO 单点登录）—— "
                "交人工，不猜字段名硬提交")
            return res
    res.notes.append(f"[凭据获取] 提交地址 {action}，字段 {user_field} / {pass_field}")

    # ---------- 尝试序列：产品候选优先，通用字典兜底 ----------
    # 归一化键与 credosint.OsintResult.pair_sources 保持一致（账号名大小写不敏感），
    # 否则 Zabbix 那种 `Admin`（大写 A）会查不到来源，留痕里来源列就成了空白 ——
    # 空白会被读成「没有来源」，而事实是「有来源但没对上」。
    def _pk(a: Any, p: Any) -> tuple[str, str]:
        return (str(a).strip().lower(), str(p))

    _psrc = {_pk(k[0], k[1]): v for k, v in (pair_sources or {}).items() if k}
    pairs: list[tuple[str, str]] = []
    _seen_pairs: set[tuple[str, str]] = set()
    for _a, _p in (extra_pairs or []):
        k = _pk(_a, _p)
        if k in _seen_pairs:
            continue
        _seen_pairs.add(k)
        pairs.append((str(_a), str(_p)))
    _n_extra = len(pairs)
    for _a, _p in DEFAULT_PAIRS:
        k = _pk(_a, _p)
        if k in _seen_pairs:
            continue
        _seen_pairs.add(k)
        pairs.append((_a, _p))
    if _n_extra:
        res.notes.append(
            f"[凭据获取] 候选口令 {_n_extra} 组来自凭据情报（产品默认值 / 公开资料），"
            "已排在最前；通用默认口令字典作为兜底排在后面")
    _extra_set = {_pk(a, p) for a, p in pairs[:_n_extra]}

    per_account: dict[str, int] = {}
    last_attempt_at = 0.0
    for account, password in pairs:
        if len(res.attempts) >= max_total:
            res.stopped_reason = f"已达尝试上限（{max_total} 组）"
            break
        if per_account.get(account, 0) >= max_per_account:
            continue
        if guard is not None and bool(
                getattr(getattr(guard, "report", None), "terminal", False)):
            res.stopped_reason = "边界封禁守门已触发（封禁未恢复），停止口令尝试"
            break

        # 反频控自约束：两次尝试之间强制间隔
        wait = min_gap - (time.time() - last_attempt_at)
        if last_attempt_at and wait > 0:
            time.sleep(min(wait, 10.0))
        per_account[account] = per_account.get(account, 0) + 1

        _src = _psrc.get(_pk(account, password), "")
        if not _src:
            _src = ("凭据情报（产品默认口令）" if _pk(account, password) in _extra_set
                    else "通用默认口令字典")
        t0 = time.time()
        status, headers, body, final_url, err = _post_login(
            action, user_field, pass_field, account, password, timeout=12)
        last_attempt_at = time.time()
        if err:
            outcome, note = "请求异常", err
        else:
            outcome, note = _classify(status, headers, body, final_url, entry)
        res.attempts.append(HuntAttempt(
            url=action, account=account, pw_fp=_pw_fingerprint(account, password),
            outcome=outcome, status=status, note=note, source=_src,
            elapsed_ms=int((time.time() - t0) * 1000)))
        res.pair_source_counts[_src] = res.pair_source_counts.get(_src, 0) + 1

        if outcome == "风控拦截":
            res.stopped_reason = (f"第 {len(res.attempts)} 次尝试命中风控 / 锁定信号 —— "
                                  "立即停止（继续试会坐实账号锁定，副作用不可逆）")
            res.notes.append(f"[凭据获取] {res.stopped_reason}")
            break
        if outcome == "疑似成功":
            rec = _found_record(account, final_url or action, headers, body)
            if rec:
                res.found.append(rec)
                res.notes.append(f"[凭据获取] 账号 {account} 疑似可登录，"
                                 "待会话回验确认（未回验不算「已登录」）")
            # 命中即停：一个弱口令账号已足以证明问题，继续试只会加压
            res.stopped_reason = "已命中可登录的默认 / 弱口令，停止后续尝试"
            break

    return res


def _post_login(url: str, user_field: str, pass_field: str,
                account: str, password: str,
                timeout: int = 12) -> tuple[int, dict, str, str, str]:
    """发一次登录请求。返回 (状态码, 响应头, 正文, 跳转目标绝对地址, 错误)。

    第 4 项是**解析后的绝对地址**（由 Location 头 urljoin 而来），不是原始头值 ——
    判据里要比较主机名，相对路径比不出来（见下方注释）。

    刻意不复用 `HttpProbeClient`：那个客户端的硬约束是「只发 SAFE_METHODS」，
    是别的模块依赖的保证（有自测断言）。为了口令尝试去放宽它，
    等于让全工具链都能发 POST —— 用一个局部需求换掉一条全局安全性质，不划算。
    这里的替代方案是**更严**的自约束：只打一个地址、次数封顶、强制间隔。
    """
    import requests

    try:
        r = requests.post(
            url, data={user_field: account, pass_field: password},
            timeout=timeout, verify=False, allow_redirects=False,
            headers={"User-Agent": ("Mozilla/5.0 (compatible; aiscan-security-"
                                    "assessment; authorized-pentest)"),
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as e:  # noqa: BLE001
        return 0, {}, "", "", f"{type(e).__name__}: {str(e)[:100]}"
    body = ""
    try:
        raw = r.content or b""
        for enc in ("utf-8", "gb18030"):
            try:
                body = raw[:40000].decode(enc)
                break
            except Exception:  # noqa: BLE001
                continue
        else:
            body = raw[:40000].decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        body = ""
    loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
    # Location 必须解析成**绝对地址**再交给判据。
    # 真实站点绝大多数回的是相对路径（`/home`），而 urlparse("/home").netloc 是空串 ——
    # 直接传原始值会让 _classify 里「跳转到登录页之外 = 疑似成功」这条判据
    # 永远不成立（死代码），表现为**真实存在的弱口令被判成认证失败**。
    # 这是最贵的一类漏报：命中了却报没命中，报告上只剩一句「未发现」。
    final_url = urljoin(url, loc) if loc else ""
    return (int(getattr(r, "status_code", 0) or 0),
            {k: v for k, v in (r.headers or {}).items()},
            body, final_url, "")


def _found_record(account: str, url: str, headers: dict[str, Any],
                  body: str) -> dict[str, Any] | None:
    """把一次成功登录转成**会话池兼容**的账号记录（带凭据，仅内存传递）。"""
    hdr = {str(k).lower(): v for k, v in (headers or {}).items()}
    cookies: dict[str, str] = {}
    raw_cookie = hdr.get("set-cookie")
    if raw_cookie:
        cookie_str = raw_cookie if isinstance(raw_cookie, str) else str(raw_cookie)
        for part in cookie_str.split(";"):
            if "=" in part:
                k, _, v = part.strip().partition("=")
                if k and v:
                    cookies[k] = v
    auth: dict[str, str] = {}
    m = TOKEN_BODY_RE.search(body or "")
    if m:
        auth["Authorization"] = f"Bearer {m.group(2)}"
    if not cookies and not auth:
        return None
    role = "admin" if re.search(r"(admin|manage|root|sysadmin)", account, re.I) else "user"
    return {
        "name": f"credhunt_{account}",
        "role": role,
        "tenant": "",
        "authorized": True,
        "cookies": cookies,
        "headers": auth,
        "verify_path": "",
        "source": "credhunt",
        "note": (f"由默认 / 弱口令受控尝试获得（账号 {account}，"
                 "口令原文不入报告），登录入口 " + str(url)[:120]),
    }


def grade_findings(res: HuntResult, target_name: str) -> list[Any]:
    """把「命中弱口令」转成一条可交付的发现（绑定 WSTG-ATHN-02）。

    只在真实命中时返回；未命中时**不产生任何发现** ——
    「没试出来」不等于「不存在弱口令」，更不是一条「未发现缺陷」的结论。
    """
    if not res.found:
        return []
    from engine.registry import make_finding  # noqa: PLC0415

    f = res.found[0]
    account = str(f.get("name", "")).replace("credhunt_", "")
    inner = [a for a in res.attempts if a.outcome == "疑似成功"]
    tries = res.tried
    return [make_finding(
        "WSTG-ATHN-02", f"存在默认 / 弱口令可登录（账号 {account}）", target_name,
        endpoint=res.entry_url, method="POST",
        param="登录表单账号 / 口令字段",
        severity="高危", confidence="High", evidence_level="A",
        description=(f"在公网零凭据条件下，用 {tries} 组常见默认口令组合尝试登录，"
                     f"账号 {account} 可成功登录并下发了会话凭据；"
                     "系统既未强制修改默认口令，也未在多次失败后阻断尝试。"),
        technical_detail=(f"登录入口：{res.entry_url}\n"
                          f"尝试组数：{tries}（逐次留痕见报告第 4 章）\n"
                          f"命中账号：{account}\n"
                          f"命中响应：{inner[0].note if inner else '疑似成功'}\n"
                          "（口令原文不在报告中记录，仅保留散列指纹）"),
        impact=("外部攻击者无需任何账号信息即可直接登录系统，获得该账号的全部权限。"
                "若为管理类账号，等同于系统被接管。"),
        reproduction=(f"向 {res.entry_url} 提交常见默认口令组合（字典与尝试次数见"
                      "第 4 章留痕），观察是否下发会话凭据 / 跳转至登录后页面。"),
        remediation=("① 首次登录强制修改初始口令；② 口令策略禁止常见弱口令与账号同名；"
                     "③ 登录接口接入频控与失败告警。"),
        evidence=[],
        # 复现方式显式声明，别让框架去猜：默认口令这类发现既没有可注入参数，
        # 也不能用「响应特征差异」比对 —— 复现模板是「重放受控字典」。
        # 猜错的代价是这条实测命中的高危发现被准入闸门判成「未复现」而踢出清单。
        extra={"credhunt": True,
               "repro": {"kind": "weak_login",
                         "path": _path_of(res.entry_url),
                         "method": "POST"}},
    )]


def _path_of(url: str) -> str:
    """把入口 URL 归一成路径（复现脚本按 target + path 组装地址）。"""
    m = re.match(r"^https?://[^/]+(/.*)?$", str(url or ""))
    if m:
        return m.group(1) or "/"
    return str(url or "/")


def _selftest() -> int:
    """离线自测：本地假登录页，验证上限 / 停止条件 / 留痕 / 命中识别。"""
    import json
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    ok = 0
    fails: list[str] = []

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        if cond:
            ok += 1
        else:
            fails.append(msg)

    state = {"attempts": [], "mode": "wrong", "locked": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: ANN002
            pass

        def do_GET(self):  # noqa: N802
            if state["mode"] == "allowall":
                # 站点级默认响应头形态：**每个**路径都 405，且都带同一个 `Allow`。
                # 逐条看像「这是只收 POST 的接口」，横向一比就是噪声 ——
                # 补探若不做对照，会在这里报出「命中登录接口」的假阳性。
                self._send(405, "", {"Allow": "GET, HEAD, POST"})
                return
            if self.path.startswith("/login"):
                if state["mode"] == "postonly":
                    # POST-only 的登录接口：GET 一律 405，但带 `Allow: POST`
                    # 声明自己接受什么 —— 这正是「真接口」与「WAF 拦截」的分水岭
                    self._send(405, "", {"Allow": "POST"})
                elif state["mode"] == "bare405":
                    # 只有 405、没有 `Allow` —— 边缘防护拦截形态。
                    # 它**不能**被当成登录接口：认了就会往拦截页灌一串口令
                    # （全被丢掉），报告上却写成「已试过 N 组，未命中」。
                    self._send(405, "", {"Server": "AliyunWAF/1.0"})
                elif state["mode"] == "noform":
                    # SSO 形态：只有跳转按钮，没有口令字段 —— 没有可提交的东西
                    body = ('<html><form action="/sso/redirect" method="post">'
                            '<input name="tenant"></form>'
                            '<a href="/sso">统一身份登录</a></html>')
                    self._send(200, body, {})
                else:
                    body = ('<html><form action="/api/login" method="post">'
                            '<input name="username"><input type="password" name="pwd">'
                            '</form></html>')
                    self._send(200, body, {})
            elif self.path.startswith("/home"):
                if "SESSION" in (self.headers.get("Cookie") or ""):
                    self._send(200, "<h1>我的工作台</h1>", {})
                else:
                    self._send(403, "forbidden", {})
            else:
                self._send(404, "not found", {})

        def do_POST(self):  # noqa: N802
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln).decode("utf-8", "replace")
            from urllib.parse import parse_qs
            q = parse_qs(raw)
            u = (q.get("username") or [""])[0]
            # POST-only 接口按假定字段名收 `password`；表单页用 `pwd`
            p = (q.get("password") or q.get("pwd") or [""])[0]
            state["attempts"].append((u, p))
            if state["mode"] == "lock":
                self._send(200, "尝试次数过多，请稍后再试（需要验证码）", {})
                return
            if state["mode"] in ("success", "postonly") and u == "admin" \
                    and p == "admin123":
                self._send(302, "", {"Location": "/home",
                                     "Set-Cookie": "SESSION=abc123; Path=/"})
                return
            self._send(200, "用户名或密码错误", {})

        def _send(self, st: int, body: str, extra: dict) -> None:
            data = body.encode("utf-8")
            self.send_response(st)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    class _Client:
        """最小 fetch 替身：只用 GET 探入口。"""

        def fetch(self, url, **kw):  # noqa: ANN003
            import requests

            class P:
                pass

            pr = P()
            try:
                r = requests.get(url, timeout=5)
                pr.status = r.status_code
                pr.body_snippet = r.text[:4000]
                # headers 必须带出来：判断「405 是真接口还是 WAF 拦截」
                # 唯一的分水岭就在 `Allow` 头上
                pr.headers = dict(r.headers or {})
            except Exception as e:  # noqa: BLE001
                pr.status = 0
                pr.body_snippet = ""
                pr.headers = {}
                pr.error = str(e)
            return pr

    client = _Client()
    prof_on = {"credential_hunt": {"enabled": True, "max_attempts": 6,
                                   "min_gap_seconds": 0.01}}

    # ① 安全档：恒不启用，且零请求
    state["attempts"].clear()
    r_safe = hunt(client, base, profile={"credential_hunt": {"enabled": False}},
                  profile_key="safe")
    check(r_safe.enabled is False, "安全档必须不启用口令探测")
    check(len(state["attempts"]) == 0, "安全档必须零登录请求")
    check(any("安全档" in x for x in r_safe.summary_lines()), "未启用必须说明原因")

    # ② 环境变量开关
    import os as _os
    _os.environ["AISCAN_CREDHUNT"] = "off"
    r_env = hunt(client, base, profile=prof_on, profile_key="standard")
    check(r_env.enabled is False and "AISCAN_CREDHUNT" in r_env.reason,
          "AISCAN_CREDHUNT=off 必须关闭并说明")
    _os.environ.pop("AISCAN_CREDHUNT", None)

    # ③ 未命中：尝试次数受上限约束、逐次留痕、口令不落盘
    state["mode"] = "wrong"
    state["attempts"].clear()
    r_miss = hunt(client, base, profile=prof_on, profile_key="standard")
    check(r_miss.enabled and r_miss.entry_url.startswith(base), "应定位到登录入口")
    check(r_miss.tried <= 6, f"尝试次数不得超上限（实际 {r_miss.tried}）")
    check(len(state["attempts"]) == r_miss.tried, "服务端收到的尝试数应与留痕一致")
    dump = json.dumps(r_miss.to_dict(), ensure_ascii=False)
    check(not any(p in dump for p in ("admin123", "P@ssw0rd", "123456")),
          "留痕中不得出现口令原文")
    check(all(a.pw_fp for a in r_miss.attempts), "每次尝试必须带口令指纹")
    check(not r_miss.found, "未命中时不得产出身份")

    # ④ 命中：识别成功、产出会话记录、命中即停
    state["mode"] = "success"
    state["attempts"].clear()
    r_hit = hunt(client, base, profile=prof_on, profile_key="standard")
    check(bool(r_hit.found), "命中默认口令时必须产出身份记录")
    check(r_hit.tried <= 2, f"命中后应立即停止（实际尝试 {r_hit.tried} 次）")
    check(r_hit.found[0]["cookies"].get("SESSION") == "abc123", "必须取到会话 Cookie")
    finds = grade_findings(r_hit, "自测目标")
    check(len(finds) == 1 and finds[0].item_id == "WSTG-ATHN-02",
          "命中必须产出绑定 WSTG-ATHN-02 的发现")

    # ⑤ 风控信号：立即停止，且不再尝试
    state["mode"] = "lock"
    state["attempts"].clear()
    r_lock = hunt(client, base, profile=prof_on, profile_key="standard")
    check(r_lock.lockout_hit, "必须识别风控 / 锁定信号")
    check(r_lock.tried == 1, f"命中风控信号必须立即停止（实际 {r_lock.tried} 次）")
    check(not r_lock.found, "风控场景不得产出身份")
    check(any("风控" in x for x in r_lock.summary_lines()), "风控必须在摘要里说明")

    # ⑥ 字段识别失败（SSO / 无口令字段）不得硬提交
    state["mode"] = "noform"
    state["attempts"].clear()
    r_nofield = hunt(client, base, profile=prof_on, profile_key="standard",
                     path_probes={})
    check(len(state["attempts"]) == 0,
          f"未识别出口令字段时不得盲目提交（实际提交 {len(state['attempts'])} 次）")
    check("字段名" in r_nofield.stopped_reason or "口令字段" in r_nofield.stopped_reason,
          "必须说明停止原因是字段识别失败")

    # ⑦ 档位配置的尝试上限只能收紧，不能放宽
    prof_wide = {"credential_hunt": {"enabled": True, "max_attempts": 999,
                                     "min_gap_seconds": 0.01}}
    state["mode"] = "wrong"
    state["attempts"].clear()
    r_wide = hunt(client, base, profile=prof_wide, profile_key="standard")
    check(r_wide.tried <= HARD_MAX_TOTAL_ATTEMPTS,
          f"档位配置不得突破模块硬上限（实际 {r_wide.tried}）")

    # ⑧ 同源约束：入口与目标不同源必须放弃（哪怕它来自「探测证据」）
    class _CrossProbe:
        reachable = True
        status = 200
        url = "https://other.example.com/login"
        body_snippet = "<html>login</html>"

    r_cross = hunt(client, f"http://127.0.0.1:{port}", profile=prof_on,
                   profile_key="standard", path_probes={"login": _CrossProbe()})
    check(r_cross.entry_url == "" or "other.example.com" not in r_cross.entry_url,
          "不得对站外主机的登录入口发请求（授权范围外）")
    check(not r_cross.found, "越界场景不得产出身份")

    # ⑨ 未命中必须产出「没有结论」的措辞，不得写成「不存在弱口令」
    lines = " ".join(r_miss.summary_lines())
    check("未命中" in lines and "不等于系统不存在弱口令" in lines,
          "未命中必须如实说明字典受限，不得当成已排除")

    # ⑩ POST-only 登录接口（GET 405 + Allow: POST）：必须能进去试
    # 这一条守的是「有登录页却进不去」的一类漏测：接口只收 POST、没有页面可读，
    # 于是「找不到表单」被当成「没有可提交的东西」直接放弃 —— 而黑客会直接
    # 换 POST 再问一次。守两个方向：
    #   · 有 `Allow: POST` 的 405 → 认定是登录接口，按假定字段名提交；
    #   · 提交时必须**显式标注字段名是假定的**，因为猜错字段名与服务端
    #     真的拒收口令无法区分，不能被读成「不存在弱口令」。
    state["mode"] = "postonly"
    state["attempts"].clear()
    r_po = hunt(client, base, profile=prof_on, profile_key="standard",
                path_probes={})
    check(bool(r_po.entry_url), "POST-only 登录接口必须能被定位为入口")
    check(r_po.assumed_fields is True,
          "无表单页直接提交时，必须标记字段名是假定的")
    check(r_po.to_dict().get("assumed_fields") is True,
          "假定字段名必须落进结果数据（报告与批量统计都要能读到）")
    check(len(state["attempts"]) > 0,
          f"POST-only 登录接口必须真的提交过（实际 {len(state['attempts'])} 次）")
    check(bool(r_po.found), "假站上 admin/admin123 应能被试出来")
    check(any("假定" in x and "不存在弱口令" in x for x in r_po.notes),
          "假定字段名时必须同时写明「不能据此推断不存在弱口令」")

    # ⑪ 反向：GET 405 但**不带 Allow 头** → 不认，也不提交
    # 这一条防的是把 WAF 对敏感路径的拦截当成登录接口：认了它就会往拦截页
    # 灌一串口令（全被丢掉），报告上却写成「已试过 N 组，未命中」。
    class _Bare405:
        """指纹阶段的探测结果：405，无 `Allow`（边缘防护形态）。"""

        reachable = True
        status = 405
        url = f"http://127.0.0.1:{port}/login"
        body_snippet = ""
        headers = {"Server": "AliyunWAF/1.0"}

    state["mode"] = "bare405"
    state["attempts"].clear()
    r_bare = hunt(client, f"http://127.0.0.1:{port}", profile=prof_on,
                  profile_key="standard",
                  path_probes={"login": _Bare405()})
    check(r_bare.entry_url == "",
          "405 不带 Allow 头不得被认定为登录入口（那是拦截特征，不是接口）")
    check(len(state["attempts"]) == 0,
          f"未认定入口时不得提交任何口令（实际 {len(state['attempts'])} 次）")
    check("405" in r_bare.stopped_reason and "Allow" in r_bare.stopped_reason,
          "停止原因必须点明「405 且不带 Allow 头」，"
          "否则读者分不清是「没有登录功能」还是「被挡住了」")
    check("均未命中" not in r_bare.stopped_reason,
          "有更具体的原因时不得退回「均未命中」这句笼统话术 —— "
          "它会被读成「这系统没有登录功能」")

    # ⑫ 站点级 `Allow` 头：**每个**路径都 405 且都带同一个 Allow → 不得认成接口
    # 这一条是 ⑩ 的对照实验。只看单个响应时，⑫ 里那个 Allow 跟 ⑩ 里的一模一样，
    # 分不出真假 —— 唯一的区别是「别的路径是不是也这样」。
    # 漏了这道对照的后果是**假阳性**：整站被拦，却报出「命中 POST-only 登录接口」，
    # 比漏报更糟（读者会据此以为应用可达，甚至去追一个不存在的接口）。
    state["mode"] = "allowall"
    state["attempts"].clear()
    r_aa = hunt(client, f"http://127.0.0.1:{port}", profile=prof_on,
                profile_key="standard", path_probes={})
    check(r_aa.entry_url == "",
          "站点级 `Allow` 头不得被认定为登录入口（那是默认响应头，不是该路径的特征）")
    check(len(state["attempts"]) == 0,
          f"站点级 Allow 时不得提交任何口令（实际 {len(state['attempts'])} 次）")
    check("默认响应头" in r_aa.stopped_reason,
          "停止原因必须说清是「站点级默认响应头」，"
          "不能说成「没找到登录页」—— 后者会被读成「没有登录功能」")

    # ⑬ 凭据情报候选（engine.credosint 的产物）接入后的**接口契约**：
    #     顺序 / 来源留痕 / 与通用字典去重 / 仍受三重硬上限约束。
    #     这一段存在的理由：候选来自外部检索时，最容易出的错不是「试错了口令」，
    #     而是「试了但说不清试的是什么」—— 读者会以为在用通用字典，
    #     从而把「该产品的出厂默认值没打通」误读成「常见弱口令没打通」。
    state["mode"] = "wrong"
    state["attempts"].clear()
    _extra = [("nacos", "nacos"), ("admin", "admin"), ("tomcat", "tomcat"),
              ("admin", "admin123")]
    _psrc = {k: f"本地产品默认口令库·{k[0]}" for k in _extra}
    r_ex = hunt(client, base, profile=prof_on, profile_key="standard",
                path_probes={}, extra_pairs=_extra, pair_sources=_psrc)
    _sent = [u for u, _p in state["attempts"]]
    check(_sent[:2] == ["nacos", "admin"],
          f"凭据情报候选必须排在最前（实际提交顺序 {_sent[:4]}）")
    check(len(state["attempts"]) == len(set(state["attempts"])),
          "候选与通用字典重叠时（admin/admin）必须去重 —— 重复提交只是给目标加压")
    check(_sent.count("nacos") == 1, "同一组候选不得被提交两次")
    check(len(r_ex.attempts) <= HARD_MAX_TOTAL_ATTEMPTS,
          f"候选再多也不得突破硬上限（实际 {len(r_ex.attempts)} 次）")
    check(bool(r_ex.attempts) and all(a.source for a in r_ex.attempts),
          "每一次尝试都必须带来源标注（报告要能回答「试的到底是什么」）")
    check(bool(r_ex.attempts) and r_ex.attempts[0].source == "本地产品默认口令库·nacos",
          f"来源标注未透传到留痕："
          f"{r_ex.attempts[0].source if r_ex.attempts else '（无尝试）'!r}")
    check(any("本地产品默认口令库" in k for k in r_ex.pair_source_counts),
          f"来源构成未汇总：{r_ex.pair_source_counts}")
    check(any("通用默认口令字典" in k for k in r_ex.pair_source_counts),
          "通用字典的尝试也要单独计数 —— 否则看不出检测强度由什么构成")
    check(any("凭据情报" in x for x in r_ex.notes),
          "候选来源必须在注记里说明（不能只体现在表里）")
    check(all("source" in a for a in r_ex.to_dict()["attempts"]),
          "来源标注必须落进结果数据（报告与批量统计都要能读到）")
    # 反向：不传候选时，来源必须标为通用字典，**不得留空**。
    # 空白来源会被读成「没有来源」，而事实是「有来源」。
    state["attempts"].clear()
    r_no = hunt(client, base, profile=prof_on, profile_key="standard",
                path_probes={})
    check(bool(r_no.attempts)
          and all(a.source == "通用默认口令字典" for a in r_no.attempts),
          "未传候选时来源必须标为通用字典（不得留空）")

    srv.shutdown()
    # 终态行必须与成功时**不同**：若只打印「通过 N 项」，失败时那一行照样会
    # 出现（N 是**已通过**数），把「通过标记」当判据的调用方会被骗过去 ——
    # credguide / sessionctx 是同型问题，一起改了。
    if fails:
        for f in fails:
            print(f"  ✗ {f}")
        print(f"凭据获取自测：失败（{len(fails)} 项未通过，{ok} 项通过）")
        return 1
    print(f"凭据获取自测：通过 {ok} 项")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys as _sys
    from pathlib import Path as _Path

    # 直接以脚本方式跑自测时，仓库根不在 sys.path 上（本模块内部会
    # `from engine import credguide` 复用登录入口判定）—— 显式补上，
    # 免得自测因为 ImportError 看起来像「模块坏了」。
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    raise SystemExit(_selftest())
