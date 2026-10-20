"""攻击链补证器：把「候选链」上缺的那一环**真的打一枪**。

为什么需要这个模块
==================

`engine/attackchain.py` 组合出候选链之后，链上写的是「待确认清单」——
它回答的是「下一枪该往哪打」。但**红队交付的不是「有哪些洞」，而是
「这条路能打到什么资产」**。停在待确认清单上，等于把最后一步交回给人，
而这一步恰恰是自动化最有价值的部分：它只是发几个只读请求。

同时这里有个很容易犯的错：**用推演代替实测**。候选链说「APIT-03 提供了
读取业务数据的能力」，那是**能力表推出来的**；本次是否真的读到了，
要真的发一次请求才知道。所以本模块只做一件事：

    对「到目标只差一环」的链，派发受控实测，把结论换成实测的。

严格边界（改这个模块前先读）
==========================

1. **只补「差一环」的链**（`AttackChain.testable`）。缺两环以上的链是纸面
   推演，派发实测只是把猜测再跑一遍 —— 那种链由 attackchain 标为
   「纸面推演」，本模块**不碰**。
2. **只补「证明器覆盖不到」的能力**。`engine/proofs.py` 已经有的判据
   （SQL 注入 / IDOR / 命令执行 / 文件读取 / 管理后台）**绝不重写** ——
   同类发现必须同类判据，写两份迟早会给出相反结论（红线 19）。
   本模块补的是证明器**根本没有**的那批：过度数据暴露、XSS 系会话能力等。
3. **每个验证体必须带对照实验**（红线 9）。没有对照的命中是孤立信号。
4. **没有验证体的能力必须显式产出「能力缺口」**（红线 14），
   不许静默跳过 —— 静默跳过与「测了没问题」在报告上长得一样。
5. **一律只读**。本模块不做任何写操作（红线 11 / 33）；写类能力
   （改数据、上传、执行）一律落「能力缺口」，并写明为什么不做。
6. **跑了没确证 = 未能验证，绝不等于「打不穿」**，更不等于通过（红线 1）。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

# 允许直接 `python engine/chainclose.py` 运行自测（回归脚本就是这么调的）。
# 以模块方式导入时 __package__ 有值，这段不生效。
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.redteam import (  # noqa: E402
    INCONCLUSIVE,
    NOT_PROVEN,
    PROVEN,
)

from engine.attackchain import (  # noqa: E402
    CAP_ADMIN,
    CAP_AUTH_BYPASS,
    CAP_CRED,
    CAP_EXEC,
    CAP_FILE_READ,
    CAP_FILE_WRITE,
    CAP_IDOR,
    CAP_INFO,
    CAP_INTERNAL,
    CAP_NOSQL,
    CAP_PRIV,
    CAP_READ,
    CAP_SESSION,
    CAP_SQLI,
    CAP_SSRF,
    CAP_WRITE,
    CAPABILITY_LABEL,
    AttackChain,
    ChainNode,
)


# ======================================================================
# 结论
# ======================================================================


@dataclass
class VerifyOutcome:
    """一次能力补证的结论。三态，不可混淆。"""

    cap: str = ""
    proven: bool = False
    inconclusive: bool = False
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    probes: int = 0
    #: 没能测时的原因。**空串只在「测了且有了结论」时允许出现。**
    gap_reason: str = ""

    @property
    def state(self) -> str:
        if self.proven:
            return PROVEN
        if self.inconclusive:
            return INCONCLUSIVE
        return NOT_PROVEN

    @property
    def has_verifier(self) -> bool:
        """有没有真正跑过验证体（False = 能力缺口，必须写原因）。"""
        return self.probes > 0 or (not self.gap_reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cap": self.cap,
            "cap_label": CAPABILITY_LABEL.get(self.cap, self.cap),
            "state": self.state,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "probes": self.probes,
            "gap_reason": self.gap_reason,
        }


def _outcome(cap: str) -> VerifyOutcome:
    return VerifyOutcome(cap=cap)


def _gap(cap: str, reason: str) -> VerifyOutcome:
    """「没测」——必须写原因，与「测了没打成」分开。"""
    o = VerifyOutcome(cap=cap, inconclusive=True, gap_reason=reason)
    return o


# ======================================================================
# 通用小工具
# ======================================================================


def _probe(ctx: Any, url: str) -> Any:
    """发一次只读请求。任何异常都要变成「没能测」，绝不能让流程崩掉。"""
    try:
        return ctx.get(url)
    except Exception:  # noqa: BLE001
        return None


def _status(p: Any) -> int:
    if p is None:
        return 0
    return int(getattr(p, "status", 0) or 0)


def _body(p: Any) -> str:
    if p is None:
        return ""
    return str(getattr(p, "body_snippet", "") or "")


def _control_url(base: str) -> str:
    """对照组地址：同一站点上一个必然不存在的路径。

    对照的意义：命中判据若对「随便什么响应」都成立，那它证明的不是能力，
    而是判据太松。所有验证体都必须用它做反证。
    """
    try:
        root = f"{urlparse(base).scheme}://{urlparse(base).netloc}/"
    except Exception:  # noqa: BLE001
        return ""
    return urljoin(root, "aiscan-chainclose-control-9f3c1d")


def _abs(ctx: Any, url: str) -> str:
    """相对路径补成绝对地址（发现里的 endpoint 可能是路径也可能是全 URL）。"""
    url = str(url or "").strip()
    if not url:
        return ""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    try:
        return urljoin(str(getattr(ctx, "target_url", "") or "").rstrip("/") + "/",
                       url.lstrip("/"))
    except Exception:  # noqa: BLE001
        return url


# ======================================================================
# 能力验证体（补的是证明器覆盖不到的那批能力）
# ======================================================================


def _data_signals(body: str) -> list[str]:
    """复用了检测器与证明器**同一套**数据信号判据 —— 不另起一套。"""
    try:
        from engine.proofs import _data_signals_in, _looks_like_structured_data
    except Exception:  # noqa: BLE001
        return []
    hits = list(_data_signals_in(body) or [])
    ok, why = _looks_like_structured_data(body)
    if ok and why:
        hits.append(f"结构化数据（{why}）")
    return hits


def _verify_read_data(ctx: Any, node: ChainNode,
                      chain: AttackChain) -> VerifyOutcome:
    """「真的能读到业务数据」——对链上端点无凭据再读一次。

    判据与检测器一致（同一套数据信号 + 结构化判据），并且必须过对照：
    对照组（必然不存在的路径）上同样跑一遍判据，若它也「命中」，
    说明判据在这里不成立，本次只能记未能验证。
    """
    o = _outcome(CAP_READ)
    url = _abs(ctx, node.endpoint)
    if not url:
        return _gap(CAP_READ, "该发现未记录端点地址，无法派发实测")

    p = _probe(ctx, url)
    o.probes += 1
    if _status(p) == 0:
        return _gap(CAP_READ, f"请求未取得响应（{url}）")
    if _status(p) >= 400:
        o.inconclusive = True
        o.detail = f"以无凭据身份请求该端点返回 HTTP {_status(p)}，本次未读到数据"
        return o

    hits = _data_signals(_body(p))
    ctl = _probe(ctx, _control_url(url))
    o.probes += 1
    ctl_hits = _data_signals(_body(ctl)) if ctl is not None else []

    if hits and not ctl_hits:
        o.proven = True
        o.detail = (f"无凭据请求 {url} 返回 HTTP {_status(p)}，"
                    f"响应中命中数据信号：{'、'.join(hits[:4])}；"
                    f"对照地址未命中同类信号")
        o.evidence = [f"GET {url} → {_status(p)}",
                      f"数据信号：{'、'.join(hits[:6])}",
                      f"对照 {_control_url(url)} → {_status(ctl)}（未命中）"]
    elif hits and ctl_hits:
        o.inconclusive = True
        o.detail = ("命中了数据信号，但对照地址同样命中 —— "
                    "该判据在本目标上不成立（可能是通用页面特征），无法据此定论")
    else:
        o.inconclusive = True
        o.detail = f"请求成功（HTTP {_status(p)}）但响应未命中业务数据信号"
    return o


def _admin_markers(body: str) -> list[str]:
    low = (body or "").lower()
    marks = []
    for kw, label in (("administration", "管理后台特征"),
                      ("admin panel", "管理面板特征"),
                      ("user management", "用户管理特征"),
                      ("dashboard", "仪表盘特征"),
                      ("/api/users", "用户管理接口"),
                      ("configuration", "配置界面特征")):
        if kw in low:
            marks.append(label)
    return marks[:3]


def _verify_admin(ctx: Any, node: ChainNode,
                  chain: AttackChain) -> VerifyOutcome:
    """「管理功能真的可达」——无凭据访问管理端点，并要求过对照。"""
    o = _outcome(CAP_ADMIN)
    cands: list[str] = []
    if node.endpoint:
        cands.append(_abs(ctx, node.endpoint))
    try:
        from engine.proofs import _admin_candidates
        cands += [str(u) for u in (_admin_candidates(ctx, limit=4) or [])]
    except Exception:  # noqa: BLE001
        pass
    cands = [c for c in cands if c][:4]
    if not cands:
        return _gap(CAP_ADMIN, "未取得任何管理端点候选，无法派发实测")

    ctl = _control_url(cands[0])
    ctl_p = _probe(ctx, ctl)
    o.probes += 1
    ctl_marks = _admin_markers(_body(ctl_p))

    for u in cands:
        p = _probe(ctx, u)
        o.probes += 1
        if _status(p) == 0 or _status(p) >= 400:
            continue
        marks = _admin_markers(_body(p))
        extra = [m for m in marks if m not in ctl_marks]
        if extra:
            o.proven = True
            o.detail = (f"无凭据访问 {u} 返回 HTTP {_status(p)}，"
                        f"命中管理特征：{'、'.join(extra)}（对照地址未命中）")
            o.evidence = [f"GET {u} → {_status(p)}",
                          f"管理特征：{'、'.join(extra)}",
                          f"对照 {ctl} → {_status(ctl_p)}（未命中）"]
            return o
    o.inconclusive = True
    o.detail = (f"探测了 {len(cands)} 个管理端点候选，均未在无凭据状态下"
                "命中管理特征（对照同样未命中，判据可用）")
    return o


def _verify_auth_bypass(ctx: Any, node: ChainNode,
                        chain: AttackChain) -> VerifyOutcome:
    """「认证真的可绕过」——带凭据 / 不带凭据同一资源对比。

    需要多账号配置才能做对照；没有账号时**如实记缺口**，绝不猜。
    """
    o = _outcome(CAP_AUTH_BYPASS)
    accounts = list(getattr(ctx, "accounts", None) or [])
    if not accounts:
        return _gap(CAP_AUTH_BYPASS,
                    "需要至少一个已登录身份做对照（--accounts），本次未提供；"
                    "没有对照的「能访问」证明不了绕过，只能算未验证")

    url = _abs(ctx, node.endpoint)
    if not url:
        return _gap(CAP_AUTH_BYPASS, "该发现未记录端点地址，无法派发实测")

    # 带凭据（走客户端会话）与不带凭据（剥掉 Cookie / Authorization）各一次
    with_p = _probe(ctx, url)
    o.probes += 1
    try:
        without_p = ctx.raw_request("GET", url, headers={"Cookie": "",
                                                         "Authorization": ""})
        o.probes += 1
    except Exception:  # noqa: BLE001
        without_p = None

    if _status(with_p) == 0:
        return _gap(CAP_AUTH_BYPASS, "带凭据请求未取得响应，无法比对")

    s_with, s_without = _status(with_p), _status(without_p)
    b_with, b_without = _body(with_p), _body(without_p)

    if s_without == 0:
        o.inconclusive = True
        o.detail = "未能取得「不带凭据」的对照响应，无法判断是否存在绕过"
        return o

    if 200 <= s_with < 400 and 200 <= s_without < 400 and b_with and \
            b_with[:200] == b_without[:200]:
        o.proven = True
        o.detail = (f"同一资源 {url}：不带凭据（HTTP {s_without}）与带凭据"
                    f"（HTTP {s_with}）返回一致内容 —— 认证未生效")
        o.evidence = [f"带凭据 GET {url} → {s_with}",
                      f"不带凭据 GET {url} → {s_without}",
                      "两者响应首部一致"]
    else:
        o.inconclusive = True
        o.detail = (f"带凭据 HTTP {s_with} / 不带凭据 HTTP {s_without}，"
                    "两者不一致，本次未观察到认证绕过")
    return o


def _sensitive_marks(body: str) -> list[str]:
    import re

    low = body or ""
    marks = []
    pats = (
        (r"BEGIN [A-Z ]*PRIVATE KEY", "私钥"),
        (r"(aws_access_key_id|AKIA[0-9A-Z]{16})", "云凭据"),
        (r"(password|passwd|pwd)\s*[=:]\s*\S{4,}", "口令字段"),
        (r"INSERT\s+INTO\s+\w+", "数据库转储"),
        (r"CREATE\s+TABLE\s+\w+", "表结构"),
        (r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}", "令牌"),
    )
    for pat, label in pats:
        if re.search(pat, low, re.I):
            marks.append(label)
    return marks[:4]


def _verify_file_read(ctx: Any, node: ChainNode,
                      chain: AttackChain) -> VerifyOutcome:
    """「文件真的能读到、且内容确实敏感」——下下来看，但不 dump 全文。

    证明即止（红线 11）：只报命中了哪类敏感特征，**不把内容写进报告**。
    """
    o = _outcome(node.provides[0] if node.provides else CAP_FILE_READ)
    cap = node.provides[0] if node.provides else CAP_FILE_READ
    o.cap = cap
    url = _abs(ctx, node.endpoint)
    if not url:
        return _gap(cap, "该发现未记录端点地址，无法派发实测")

    p = _probe(ctx, url)
    o.probes += 1
    if _status(p) == 0:
        return _gap(cap, f"请求未取得响应（{url}）")
    if _status(p) >= 400:
        o.inconclusive = True
        o.detail = f"该文件地址返回 HTTP {_status(p)}，本次未能读到内容"
        return o

    marks = _sensitive_marks(_body(p))
    ctl_p = _probe(ctx, _control_url(url))
    o.probes += 1
    ctl_marks = _sensitive_marks(_body(ctl_p)) if ctl_p is not None else []

    extra = [m for m in marks if m not in ctl_marks]
    if extra:
        o.proven = True
        o.detail = (f"读取 {url}（HTTP {_status(p)}）命中敏感内容特征："
                    f"{'、'.join(extra)}（对照未命中）。"
                    "证据只记录特征类别，不记录文件内容。")
        o.evidence = [f"GET {url} → {_status(p)}",
                      f"敏感特征：{'、'.join(extra)}",
                      f"对照 {_control_url(url)} → {_status(ctl_p)}（未命中）"]
    else:
        o.inconclusive = True
        o.detail = (f"文件可读（HTTP {_status(p)}），但未命中敏感内容特征；"
                    "「能下载」本身不等于「造成了危害」")
    return o


def _verify_session(ctx: Any, node: ChainNode,
                    chain: AttackChain) -> VerifyOutcome:
    """「注入的脚本真的能执行」——反射型 XSS 的**前半段**实测。

    ⚠ 这里有个必须说清的界：能证明的是「payload 落入可执行上下文」，
    **证明不了「会话被窃取」** —— 后者需要外带通道（外部接收端），
    本工具零外部出口（红线：base 不联网）。所以本验证体**最高只能判
    「未能验证」**，并在 detail 里写明差哪一步，绝不能冒充已达成。
    """
    o = _outcome(CAP_SESSION)
    url = _abs(ctx, node.endpoint)
    if not url:
        return _gap(CAP_SESSION, "该发现未记录端点地址，无法派发实测")

    marker = "aiscanchainclose1"
    from urllib.parse import quote, urlencode, parse_qsl, urlsplit, urlunsplit

    def _with(v: str) -> str:
        try:
            parts = urlsplit(url)
            q = dict(parse_qsl(parts.query))
            if not q:
                return url + ("&" if "?" in url else "?") + f"q={quote(v)}"
            k = next(iter(q))
            q[k] = v
            return urlunsplit((parts.scheme, parts.netloc, parts.path,
                               urlencode(q), parts.fragment))
        except Exception:  # noqa: BLE001
            return url

    payload = f"<svg onload=alert({marker})>"
    p_pay = _probe(ctx, _with(payload))
    o.probes += 1
    p_ctl = _probe(ctx, _with(marker))
    o.probes += 1

    b_pay, b_ctl = _body(p_pay), _body(p_ctl)
    # 可执行上下文：标签未被转义（< 没变成 &lt;）即视为落入标签上下文
    hit = "<svg" in b_pay or "onload=" in b_pay
    escaped = "&lt;svg" in b_pay or "&lt;svg" in b_pay.lower()
    ctl_hit = "<svg" in b_ctl or "onload=" in b_ctl

    if hit and not escaped and not ctl_hit:
        o.inconclusive = True
        o.detail = (
            f"注入的标签被原样反射进响应（HTTP {_status(p_pay)}），"
            f"中性对照值未触发同类结构 —— 可确认「脚本可注入」。"
            "但这只走完前半段：**会话是否真被窃取需要外带通道验证**，"
            "本工具不建立外部接收端，因此判「未能验证」，不冒充已达成。")
        o.evidence = [f"payload 响应：HTTP {_status(p_pay)}，标签未转义",
                      f"对照（中性值）：HTTP {_status(p_ctl)}，未出现同类结构"]
    else:
        o.inconclusive = True
        o.detail = (f"本次未观察到标签落入可执行上下文"
                    f"（payload HTTP {_status(p_pay)} / 对照 HTTP {_status(p_ctl)}）")
    return o


#: 能力 → 验证体。**这张表是精确枚举，不是前缀通配**（红线 13 同族：
#: 宽前缀会变成伪装成白名单的黑名单）。
CAP_VERIFIERS: dict[str, Callable[[Any, ChainNode, AttackChain],
                                  VerifyOutcome]] = {
    CAP_READ: _verify_read_data,
    CAP_ADMIN: _verify_admin,
    CAP_AUTH_BYPASS: _verify_auth_bypass,
    CAP_FILE_READ: _verify_file_read,
    CAP_INFO: _verify_file_read,
    CAP_SESSION: _verify_session,
}

#: 明确**没有自动验证体**的能力，以及为什么不做。
#: 少一个 key 就会变成静默跳过（与「测了没问题」在报告上长得一样）——
#: 所以这里必须与 `CAP_VERIFIERS` 一起维护，并由自测①卡住。
CAP_NO_VERIFIER: dict[str, str] = {
    CAP_WRITE: "修改业务数据需要真实写操作，自动化触碰会造成不可逆副作用（红线 11/33）",
    CAP_FILE_WRITE: "文件上传 / 写入会留下真实产物，不在自动范围（红线 33）",
    CAP_EXEC: "命令执行类已有 proofs 的证明器；本模块不重复实现同一判据（红线 19）",
    CAP_SQLI: "SQL 注入类已有 proofs 的证明器（含 sqlmap 受控阶段），不重复实现",
    CAP_NOSQL: "NoSQL 注入类已有 WSTG-INPV-24 的实测判据，不重复实现",
    CAP_IDOR: "IDOR 需要多账号横向对照（--accounts），由 proofs 的证明器负责",
    CAP_CRED: "凭据可用性验证由 credhunt 的受控循环负责，本模块不另开登录循环",
    CAP_SSRF: "外带型 SSRF 需要外部接收端，本工具不建立外部出口",
    CAP_INTERNAL: "内网可达性判定以公网基线为准，不做内网横向",
    CAP_PRIV: "权限提升需真实多角色账号对照，超出自动范围",
}


def verify_capability(ctx: Any, cap: str, node: ChainNode,
                      chain: AttackChain) -> VerifyOutcome:
    """对一个能力派发一次补证实测。没有验证体时产出具名的能力缺口。"""
    fn = CAP_VERIFIERS.get(cap)
    if fn is None:
        return _gap(cap, CAP_NO_VERIFIER.get(
            cap, f"「{CAPABILITY_LABEL.get(cap, cap)}」尚无自动验证体（能力缺口）"))
    try:
        out = fn(ctx, node, chain)
    except Exception as e:  # noqa: BLE001
        out = _outcome(cap)
        out.inconclusive = True
        out.gap_reason = f"验证体异常：{type(e).__name__}: {str(e)[:100]}"
    out.cap = cap
    return out


# ======================================================================
# 门面：对候选链派发补证
# ======================================================================


#: 「缺某个能力」时，下一步该去哪拿。
#: 没有这张表，缺口就只是一串能力名 —— 读者知道缺什么，不知道怎么办，
#: 于是这一节和「待确认清单」没有区别。红队的人会说「缺身份，去自己注册一个」，
#: 不会停在「缺凭据」四个字上。
_GAP_ACTION: dict[str, str] = {
    CAP_CRED: ("证明「攻击者能取得身份」—— 开放注册自建（regself）→ "
               "默认口令受控尝试（credhunt）→ 联网检索（credosint）。"
               "红队入场不伸手要账号，自己找凭据；"
               "本次凭据获取情况见报告「凭据缺口」一节"),
    CAP_AUTH_BYPASS: ("需人工复核授权判定逻辑 —— 多账号越权属业务语义，"
                      "自动化不触碰（红线 33），须由人工按复现脚本确认"),
    CAP_ADMIN: ("需确认管理入口的真实可达性与角色判定 —— 管理后台类结论"
                "不作自动定论，先确认入口再做角色校验"),
    CAP_SESSION: ("会话类能力需外带通道才能证明「真的拿到了会话」"
                  "（脚本可注入只是前半段），本工具不建立外部接收端"),
    CAP_EXEC: ("执行类结论需由命令执行 / 反序列化等实测证明器给出，"
               "不靠链推导"),
    CAP_WRITE: ("写类能力需显式受控写授权（deep 档 + 台账 write），"
                "且只做无害标记与回滚，不在自动范围"),
    CAP_IDOR: ("对象越权需多账号横向对照（--accounts），单一身份无法定论"),
    CAP_INTERNAL: ("内网可达性以公网基线判定，不做内网横向"),
    CAP_SSRF: ("外带型验证需要外部接收端，本工具不建立外部出口"),
    CAP_PRIV: ("权限提升需真实多角色账号对照，超出自动范围"),
    CAP_FILE_WRITE: ("文件上传 / 写入会留下真实产物，不在自动范围（红线 33）"),
    CAP_SQLI: ("由 SQL 注入实测证明器（含 sqlmap 受控阶段）定论"),
    CAP_NOSQL: ("由 NoSQL 注入实测判据（WSTG-INPV-24）定论"),
}


def capability_gap_summary(chains: list[AttackChain]) -> list[dict[str, Any]]:
    """统计未达成的链**共同**缺哪些能力，并给出「去哪拿」。

    为什么要有这个：一次扫描里往往有好几条链，它们缺的常常是**同一个东西**
    （最常见是「没有任何有效身份」）。逐条列「待确认」看不出这个共性，
    读者会以为要分别验证 3 件事，实际只要先解决 1 件。
    """
    from collections import Counter

    try:
        from engine.attackchain import route_to
    except Exception:  # noqa: BLE001
        return []

    cnt: Counter = Counter()
    conds: dict[str, list[str]] = {}
    for c in chains or []:
        if c.state == PROVEN:
            continue
        caps: set[str] = set()
        proven_caps: set[str] = set()
        for n in c.nodes:
            caps |= set(n.provides)
            if n.evidence_state == PROVEN:
                proven_caps |= set(n.provides)
        for frm, to, cond in route_to(c.goal, caps):
            # 「路径上会用到、但本次没有任何实测节点提供」的能力 = 真缺口
            if frm not in proven_caps:
                cnt[frm] += 1
                conds.setdefault(frm, [])
                if cond and cond not in conds[frm]:
                    conds[frm].append(cond)

    out: list[dict[str, Any]] = []
    for cap, n in cnt.most_common():
        out.append({
            "cap": cap,
            "cap_label": CAPABILITY_LABEL.get(cap, cap),
            "chains": int(n),
            "conditions": conds.get(cap, [])[:3],
            "action": _GAP_ACTION.get(cap, "该能力尚无自动验证体，需人工验证"),
        })
    return out


@dataclass
class ClosureReport:
    """本轮链补证的完整产出。"""

    results: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    upgraded: list[str] = field(default_factory=list)   # 由候选升为已达成的链
    gaps: list[str] = field(default_factory=list)       # 具名的能力缺口
    #: 未达成链的**共同**缺口（含「去哪拿」）。逐条列待确认看不出共性，
    #: 而共性往往只有一条：本次没拿到身份。
    common_gaps: list[dict[str, Any]] = field(default_factory=list)

    @property
    def gap_summary(self) -> list[dict[str, Any]]:
        return list(self.common_gaps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": list(self.results),
            "notes": list(self.notes),
            "upgraded": list(self.upgraded),
            "gaps": list(self.gaps),
            "common_gaps": list(self.common_gaps),
            "ran": self.ran,
        }

    @property
    def ran(self) -> int:
        return len(self.results)


def close_chains(ctx: Any, chains: list[AttackChain], *,
                 max_chains: int = 3,
                 max_probes_per_chain: int = 6) -> ClosureReport:
    """对「到目标只差一环」的候选链派发受控实测。

    ⚠ 只处理 `AttackChain.testable` 的链。纸面推演链（缺 ≥2 环）不派发 ——
    给它发请求只是把猜测再跑一遍，并不会让猜测变得更可信。
    """
    rep = ClosureReport()
    if not chains:
        rep.notes.append("本次没有攻击链，不需要补证。")
        return rep

    targets = [c for c in chains
               if c.state != PROVEN and getattr(c, "testable", False)]
    inferred = [c for c in chains
                if c.state != PROVEN and not getattr(c, "testable", False)]
    if inferred:
        rep.notes.append(
            f"另有 {len(inferred)} 条链为纸面推演（缺环 ≥2），"
            "不派发实测 —— 这类链要先逐个验证中间环节，"
            "直接发请求只会把猜测再跑一遍。")

    if not targets:
        rep.notes.append("本次没有「只差一环」的候选链，无需派发补证实测。")
        # 没派发不等于没事可做：这批链缺的常常是**同一个东西**。
        # 只说「没有可补证的链」，读者会以为这一节结束了；说清「共同缺什么、
        # 去哪拿」，这一节才对下一步有指导意义。
        rep.common_gaps = capability_gap_summary(chains)
        if rep.common_gaps:
            top = rep.common_gaps[0]
            n_acct = len(list(getattr(ctx, "accounts", None) or []))
            # ⚠ 措辞必须分清两件事，否则会当面说假话：
            #   链上缺的 CAP_CRED 是「攻击者能否**通过漏洞**取得他人身份」，
            #   不是「测试方自己带没带账号」。有 2 个测试账号却写「缺凭据」，
            #   读者会以为自取的账号没生效 —— 实际是两码事。
            if top["cap"] == CAP_CRED and n_acct:
                tail = (f"；注意这与「测试身份够不够」是两回事 —— 本次已就位 "
                        f"{n_acct} 个测试身份，但链上缺的是「攻击者能否通过漏洞"
                        f"取得他人身份」这一环，自有账号补不上这个缺口")
            elif top["cap"] == CAP_CRED:
                tail = "；本次**没有任何测试身份就位**，先按上述顺序补齐"
            else:
                tail = ""
            rep.notes.append(
                f"未达成的链共同缺的是「{top['cap_label']}」"
                f"（{top['chains']} 条链都卡在这里）—— {top['action']}{tail}")
        return rep

    done = 0
    for chain in targets:
        if done >= max_chains:
            break
        # 只补「还没被实测证明」的节点；已证明的节点不重复发请求。
        pending = [n for n in chain.nodes if n.evidence_state != PROVEN]
        if not pending:
            continue
        for node in pending[:2]:
            caps = [c for c in node.provides]
            for cap in caps[:2]:
                out = verify_capability(ctx, cap, node, chain)
                rep.results.append({
                    "chain_id": chain.chain_id,
                    "item_id": node.item_id,
                    "cap": cap,
                    **out.to_dict(),
                })
                if out.gap_reason:
                    rep.gaps.append(
                        f"{node.item_id}（{CAPABILITY_LABEL.get(cap, cap)}）："
                        f"{out.gap_reason}")
                elif out.proven:
                    node.evidence_state = PROVEN
                    node.basis = (f"{node.basis}；【链补证实测】{out.detail}").strip("；")
                else:
                    node.evidence_state = INCONCLUSIVE
        done += 1

        # 补证后重判：链上节点全部实测已证、且目标能力已在能力集合里 → 已达成
        caps_now: set[str] = set()
        for n in chain.nodes:
            caps_now |= set(n.provides)
        if all(n.evidence_state == PROVEN for n in chain.nodes) and \
                chain.goal in caps_now:
            chain.state = PROVEN
            chain.gap_hops = 0
            chain.tier = "可验证"
            chain.note = ("经链补证实测：链上各环均已取得实测证据，"
                          "结论可直接采信。")
            chain.missing = []
            rep.upgraded.append(chain.chain_id)

    if not rep.results:
        rep.notes.append("候选链上没有需要补证的环节（各环均已实测证明）。")
    # 派发过也要说共同缺口：补证只覆盖了「只差一环」的部分，
    # 纸面推演链缺的那一环才是下一步真正要解决的。
    rep.common_gaps = capability_gap_summary(chains)
    return rep


# ======================================================================
# 自测
# ======================================================================


def _selftest() -> int:
    """离线自测：不发真实网络请求，全部用假 client。"""
    problems: list[str] = []

    # --- ① 能力覆盖自洽：验证体表 + 缺口表必须覆盖全部能力 ---
    from engine.attackchain import (  # noqa: PLC0415
        CAP_BRUTE, _PROGRESS_RANK,
    )

    all_caps = set(_PROGRESS_RANK)
    covered = set(CAP_VERIFIERS) | set(CAP_NO_VERIFIER)
    missing_caps = sorted(all_caps - covered - {CAP_BRUTE})
    if missing_caps:
        problems.append(
            f"能力覆盖不自洽：{missing_caps} 既无验证体也无缺口说明 —— "
            "会静默变成「没测也没说」，与「测了没问题」在报告上长得一样")
    overlap = set(CAP_VERIFIERS) & set(CAP_NO_VERIFIER)
    if overlap:
        problems.append(f"能力覆盖冲突：{sorted(overlap)} 同时登记了验证体与缺口")

    # --- ② 假 client ---
    class _P:
        def __init__(self, status, body=""):
            self.status = status
            self.body_snippet = body
            self.headers = {}
            self.elapsed_ms = 10
            self.error = ""

    class _Ctx:
        def __init__(self, mapping):
            self.mapping = mapping
            self.target_url = "https://t.test/"
            self.accounts = []
            self.allow_write = False
            self.probe_count = 0

        def get(self, url, method="GET", allow_redirects=True):
            self.probe_count += 1
            return self.mapping.get(url, _P(404, ""))

        def raw_request(self, method, url, **kw):
            self.probe_count += 1
            return self.mapping.get("RAW::" + url, _P(401, ""))

    # --- ③ 读取业务数据：命中 + 对照未命中 → 已达成 ---
    body = ('{"data":[{"email":"a@b.com","password":"x","token":"abc"}]}')
    ctx = _Ctx({"https://t.test/api/Users": _P(200, body)})
    node = ChainNode(node_id="N01", item_id="WSTG-APIT-03", title="过度数据暴露",
                     endpoint="/api/Users", provides=[CAP_READ])
    chain = AttackChain(chain_id="C1", objective="READ_DATA", goal=CAP_READ,
                        state=INCONCLUSIVE, nodes=[node], gap_hops=1)
    out = verify_capability(ctx, CAP_READ, node, chain)
    if not out.proven:
        problems.append(f"读取业务数据：应判已达成，实际 {out.state} / {out.detail[:80]}")
    if out.probes < 2:
        problems.append(f"验证体必须带对照实验（实得 {out.probes} 次探测）")

    # --- ④ 对照也命中 → 判据不成立，只能是未能验证 ---
    ctx2 = _Ctx({"https://t.test/api/Users": _P(200, body),
                 "https://t.test/aiscan-chainclose-control-9f3c1d": _P(200, body)})
    out2 = verify_capability(ctx2, CAP_READ, node, chain)
    if out2.proven:
        problems.append("对照同样命中时不得判已达成（判据在本目标上不成立）")
    if out2.state != INCONCLUSIVE:
        problems.append(f"对照命中应判未能验证，实际 {out2.state}")

    # --- ⑤ 无验证体的能力 → 具名缺口，不得静默 ---
    out3 = verify_capability(ctx, CAP_WRITE, node, chain)
    if not out3.gap_reason:
        problems.append("没有验证体的能力必须产出具名的能力缺口（不得静默跳过）")
    if out3.state != INCONCLUSIVE:
        problems.append(f"能力缺口必须判未能验证，实际 {out3.state}")

    # --- ⑥ XSS 会话能力：最高只能判未能验证（外带缺通道） ---
    xss_node = ChainNode(node_id="N02", item_id="WSTG-INPV-01", title="反射 XSS",
                         endpoint="/search?q=x", provides=[CAP_SESSION])
    ctx3 = _Ctx({"https://t.test/search?q=%3Csvg+onload%3Dalert%28aiscanchainclose1%29%3E":
                 _P(200, "<div><svg onload=alert(aiscanchainclose1)></div>")})
    out4 = verify_capability(ctx3, CAP_SESSION, xss_node, chain)
    if out4.proven:
        problems.append("会话能力不得由「脚本可注入」直接判已达成（外带未验证）")

    # --- ⑦ close_chains 只处理可验证链 ---
    c_testable = AttackChain(chain_id="C-T", objective="READ_DATA", goal=CAP_READ,
                             state=INCONCLUSIVE,
                             nodes=[ChainNode(node_id="N10", item_id="WSTG-APIT-03",
                                              title="过度数据暴露",
                                              endpoint="/api/Users",
                                              provides=[CAP_READ])],
                             gap_hops=1, tier="可验证")
    c_inferred = AttackChain(chain_id="C-I", objective="MODIFY_DATA",
                             goal=CAP_WRITE, state=INCONCLUSIVE,
                             nodes=[ChainNode(node_id="N11", item_id="EXT-RB-01",
                                              title="无限速", endpoint="/api/X",
                                              provides=[CAP_READ])],
                             gap_hops=3, tier="纸面推演")
    rep = close_chains(_Ctx({"https://t.test/api/Users": _P(200, body)}),
                       [c_testable, c_inferred])
    if not any(r["chain_id"] == "C-T" for r in rep.results):
        problems.append("可验证链必须被派发补证实测")
    if any(r["chain_id"] == "C-I" for r in rep.results):
        problems.append("纸面推演链不得派发实测（发请求只是把猜测再跑一遍）")
    if not any("纸面推演" in n for n in rep.notes):
        problems.append("未派发的纸面推演链必须被具名说明（不得静默）")

    # --- ⑧ 补证成功后链应升级为已达成 ---
    if c_testable.state != PROVEN:
        problems.append(f"补证成功后链应升为已达成，实际 {c_testable.state}")
    if not rep.upgraded:
        problems.append("链升级必须被记录（upgraded 为空）")

    # --- ⑨ 无可验证链时，必须说出「共同缺什么、去哪拿」 ---
    # 只说「没有可补证的链」，读者会以为这一节结束了。实测里最常见的情况
    # 是好几条链卡在同一个缺口上（通常是「没拿到任何身份」），
    # 那是**下一步唯一要做的事**，必须被点名。
    rep2 = close_chains(_Ctx({}), [c_inferred])
    if not rep2.common_gaps:
        problems.append("未达成链的共同缺口必须被统计出来（否则读者要逐条猜）")
    else:
        if not rep2.common_gaps[0].get("action"):
            problems.append("共同缺口必须给出去哪拿的行动指引，不能只写能力名")
        if not any("共同缺" in n for n in rep2.notes):
            problems.append("共同缺口必须写进 notes（报告要靠它指导下一步）")

    if problems:
        print("自测不通过：")
        for p in problems:
            print("  ✗", p)
        return 1
    # 分组登记行：回归脚本的运行标记挂在这些真实输出上。
    # 标记必须对「模块真的会打印什么」写，不能对「我以为它会打印什么」写。
    print("  ✓ ① 能力覆盖自洽：验证体 + 缺口说明覆盖全部能力，无静默空档")
    print("  ✓ ② 读取业务数据：命中判据且对照未命中 → 实测已证")
    print("  ✓ ③ 验证体带对照实验（探测次数 ≥2）")
    print("  ✓ ④ 对照同样命中 → 判据不成立，只判未能验证")
    print("  ✓ ⑤ 无验证体的能力 → 具名能力缺口，不静默")
    print("  ✓ ⑥ 会话能力不得由「脚本可注入」直接判已达成（外带未验证）")
    print("  ✓ ⑦ 只派发可验证链；纸面推演链不派发且被具名说明")
    print("  ✓ ⑧ 补证成功后链升为已达成并记录 upgraded")
    print("  ✓ ⑨ 无可验证链时说出「共同缺什么、去哪拿」，不空手结束")
    print("链补证器自测：全部 9 组断言通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
