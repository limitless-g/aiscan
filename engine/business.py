# -*- coding: utf-8 -*-
"""
业务逻辑自动侦察
================
BUSL 这 10 项之所以长期是「待人工执行」，是因为它们的判定前提是**业务语义**：
优惠券应该只能用一次、退款不应超过实付、审批要按顺序走。
HTTP 报文本身看不出「这个数量字段业务上不可能为负」。

但「整项全推给人」是另一种偷懒。人工要花的时间其实大部分不在**判断**，
而在**准备**：翻页面找接口、找字段名、记当前值、构造报文、逐个试非法值。
这部分可以自动化。自动化之后人工只剩一件只有人能做的事：**看业务结果对不对**。

本模块就是这个「前置准备层」，产出两类东西：

  ① **lead（已定位对象清单）**
     具体到「哪个接口、什么方法、哪些字段、当前值是什么、属哪类敏感参数、
     建议改成什么」。人工照单执行即可，不必自己找。
     报告里按项附在该项人工步骤之前。

  ② **finding（已确证问题）**
     只有两类能自动证成，其余一律不许升级成发现：

       · **前端可复现的签名** —— 签名算法与密钥都在前端，任何客户端都能重算，
         签名不构成防伪造。纯静态可证，零副作用。
       · **服务端确实采信了客户端业务参数** —— 差分实验：原样请求 vs 单字段篡改，
         响应中**另一个**业务字段跟着变成了非法值。这是任何复测者都能重现的证据。

     反面例子（刻意**不**产出发现）：页面上有 `<input type="hidden" name="amount">`。
     它只证明「客户端能改这个值」，不证明「服务端采信」。
     把它报成中危，正是红线里的「孤立信号当正面证据」——
     复测时研发一句「服务端会重算」就能把整份报告否掉，
     而真正的重算缺失反而因为这一次乱报被淹没。

差分实验分两种，副作用差别极大，必须分开对待：

  · **只读差分**（readonly_diff）
    把已确认可达的查询接口的**已有查询参数**改成非法值，做「基线 vs 篡改」对照。
    零副作用，standard 档即可跑。能证的是「服务端对业务参数缺少校验」：
    非法值被原样采信、或直接把 500 / 堆栈打出来。

  · **写差分**（write_diff）
    只对**能精确复现原样报文**的表单做 —— 即表单里每个 input 都在 HTML 里带
    value 属性。这时我们能把「原样合法请求」一字不差地重放，再改**单个**字段，
    对照才有意义。缺一个字段值，构造出来的就不是原样请求，比出来的差异全是噪声。
    需要 deep 档 + 台账写入授权，全局 6 次封顶，每次提交记入报告披露。

明确不做的（继续人工，并把原因写进报告）：
  资金 / 退款 / 上传 / 删除 / 短信 / 审批 / 权限授予 类接口。
  这些接口的副作用不可逆或不可控，自动化触碰的收益远小于风险。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from engine.registry import RISK_DEEP, RISK_STANDARD, ReconOutcome, make_finding

# ======================================================================
# 敏感参数分类
# ======================================================================
PK_AMOUNT = "amount"        # 金额
PK_QUANTITY = "quantity"    # 数量
PK_DISCOUNT = "discount"    # 折扣 / 优惠 / 积分
PK_STATE = "state"          # 状态 / 环节
PK_ROLE = "role"            # 角色 / 权限等级
PK_IDENTITY = "identity"    # 归属标识（用户 / 租户 / 组织）
PK_TIME = "time"            # 时间 / 有效期
PK_SIGN = "sign"            # 签名 / 校验位

KIND_CN = {
    PK_AMOUNT: "金额类",
    PK_QUANTITY: "数量类",
    PK_DISCOUNT: "折扣/优惠类",
    PK_STATE: "状态类",
    PK_ROLE: "角色/权限类",
    PK_IDENTITY: "归属标识类",
    PK_TIME: "时间类",
    PK_SIGN: "签名类",
}

# 顺序有意义：先匹配更专指的类别。
# 「sign_time」要判成签名而不是时间；「total_num」要判成金额而不是数量。
_KIND_RULES: tuple[tuple[str, str], ...] = (
    (PK_SIGN, r"(?:^|_)(?:sign|signature|sig|hmac|checksum|digest|nonce)(?:_|$)"
              r"|_token$|(?:^|_)ts$|签名|验签"),
    (PK_AMOUNT, r"(?:amount|price|total|fee|cost|payable|payment|money|balance|"
                r"金额|价格|单价|总价|合计|费用|余额|应付|实付)"),
    (PK_DISCOUNT, r"(?:discount|coupon|promo|rebate|voucher|credit|point|rate|"
                  r"折扣|优惠|券|积分|抵扣|减免)"),
    (PK_QUANTITY, r"(?:^|_)(?:qty|quantity|num|count|stock|quantity)(?:_|$)"
                  r"|数量|件数|库存|份数|个数"),
    (PK_STATE, r"(?:^|_)(?:status|state|stage|step|phase)(?:_|$)|状态|环节|审批"),
    (PK_ROLE, r"(?:^|_)(?:role|roles|admin|is_?admin|level|grade|permission|"
              r"privilege|type)(?:_|$)|角色|权限|等级|级别|权重"),
    (PK_IDENTITY, r"(?:^|_)(?:user_?id|uid|account_?id|tenant|tenant_?id|org_?id|"
                  r"owner|member_?id|employee_?id|customer_?id)(?:_|$)|"
                  r"用户|租户|账号标识|所属"),
    (PK_TIME, r"(?:^|_)(?:time|date|expire|expiry|start|end|deadline|valid|begin)(?:_|$)"
              r"|时间|有效期|开始|结束"),
)

# 值本身就能看出是「可枚举标识」时，即使字段名不敏感也要收：
# 纯数字 / 短十六进制，这类值改一个数字就能指向另一个对象。
_ENUM_VALUE = re.compile(r"^\d{1,12}$|^[0-9a-f]{8,32}$", re.I)

# ======================================================================
# 安全过滤：这些路径一律不自动碰
# ======================================================================
_UNSAFE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("资金 / 支付类", re.compile(
        r"(pay|prepay|checkout|cashier|refund|withdraw|transfer|settle|recharge|"
        r"payment|资金|支付|退款|提现|转账|结算|充值)", re.I)),
    ("上传 / 导入类", re.compile(
        r"(upload|import|attach|multipart|上传|导入|附件)", re.I)),
    ("删除 / 清空类", re.compile(
        r"(delete|remove|destroy|drop|truncate|purge|clear|revoke|"
        r"删除|清除|作废)", re.I)),
    ("短信 / 消息推送类", re.compile(
        r"(sms|send_?code|sendcode|verify_?code|captcha|mail|email|notify|push|"
        r"短信|验证码|邮件|推送|通知)", re.I)),
    ("会话 / 凭据变更类", re.compile(
        r"(logout|sign_?out|reset|rebind|bind|unbind|password|passwd|pwd|"
        r"注销|重置|解绑|绑定|改密)", re.I)),
    ("审批 / 授权类", re.compile(
        r"(publish|approve|audit_?pass|grant|activate|enable|disable|"
        r"审批|核准|授权|发布|启用|停用)", re.I)),
    ("实名 / 证件类", re.compile(
        r"(realname|real_?name|idcard|id_?card|bankcard|实名|证件|银行卡)", re.I)),
)

# 交付物不得新增依赖：这里只用标准库 + 已有模块。
_ERR_MARKERS = re.compile(
    r"(exception|traceback|stack\s*trace|\bat\s+[a-z0-9_.$]+\(|"
    r"java\.|org\.springframework|系统繁忙|服务器内部错误|未知异常|"
    r"sqlstate|SQLException|NullPointerException)", re.I)

_VALIDATION_MARKERS = re.compile(
    r"(参数(错误|不合法|校验失败|无效)|非法参数|不能为空|格式错误|超出范围|"
    r"invalid\s+(param|parameter|argument|value|request)|validation\s+failed|"
    r"must\s+be|out\s+of\s+range|IllegalArgumentException)", re.I)

_ORIGIN_CN = {
    "form-hidden": "表单隐藏字段",
    "form-visible": "表单可见字段",
    "rendered": "SPA 渲染后 DOM",
    "js-payload": "前端脚本中的请求字段",
    "url-query": "已枚举 URL 的查询参数",
    "api-path": "前端脚本中的接口路径",
}


def classify(name: str) -> str:
    """把一个参数名归到敏感类别；不敏感返回空串。"""
    n = normalize_key(name)
    if not n:
        return ""
    for kind, pat in _KIND_RULES:
        if re.search(pat, n, re.I):
            return kind
    return ""


def normalize_key(name: str) -> str:
    """参数名归一化：驼峰切分 + 转小写 + 非字母数字下划线与中文一律折成下划线。

    驼峰必须先切再转小写，否则 orderStatus 变成 orderstatus，
    「状态类」的正则再也匹配不上 —— 这是参数分类里最容易静默失效的一步。
    """
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9_\u4e00-\u9fff]+", "_", s)
    return s.strip("_")


# ======================================================================
# 侦察输入：业务面
# ======================================================================
@dataclass
class ParamRef:
    """一个「客户端可控的业务参数」的定位信息。"""

    endpoint: str
    param: str
    kind: str
    value: str = ""
    origin: str = ""
    method: str = "POST"
    page: str = ""

    def describe(self) -> str:
        return (f"`{self.param}`（{KIND_CN.get(self.kind, self.kind)}，"
                f"来源：{_ORIGIN_CN.get(self.origin, self.origin or '未知')}）")


@dataclass
class EndpointRef:
    """一个候选业务接口。"""

    url: str
    method: str = "POST"
    params: list[ParamRef] = field(default_factory=list)
    origin: str = ""
    unsafe_reason: str = ""


@dataclass
class Surface:
    """本次侦察识别出的业务面。"""

    params: list[ParamRef] = field(default_factory=list)
    endpoints: list[EndpointRef] = field(default_factory=list)
    unsafe: list[EndpointRef] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    features: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def of_kind(self, *kinds: str) -> list[ParamRef]:
        ks = set(kinds)
        return [p for p in self.params if p.kind in ks]

    def endpoints_of_kind(self, *kinds: str) -> list[EndpointRef]:
        ks = set(kinds)
        out = []
        for e in self.endpoints:
            if any(p.kind in ks for p in e.params):
                out.append(e)
        return out

    def empty(self) -> bool:
        return not self.endpoints and not self.params


def unsafe_reason(url: str) -> str:
    """返回该路径被安全过滤拦下的原因；安全则返回空串。"""
    for label, pat in _UNSAFE_RULES:
        if pat.search(url or ""):
            return label
    return ""


# ======================================================================
# 业务面构建（纯读：只消费已采集内容，不发新请求）
# ======================================================================
def _collect_blobs(ctx: Any) -> list[tuple[str, str]]:
    """(来源标记, 文本) 列表。来源标记决定参数被判成哪一类 origin。"""
    out: list[tuple[str, str]] = []
    body = getattr(ctx, "baseline_body", "") or ""
    if body:
        out.append(("html", body))
    rendered = (ctx.fp_result or {}).get("_render_html") or ""
    if rendered:
        out.append(("rendered", rendered))
    js = ctx.js_result or {}
    for b in list(js.get("inline_scripts") or []) + list(js.get("bodies") or []):
        if b:
            out.append(("js", b))
    return out


def _input_attrs(block: str) -> list[dict[str, str]]:
    """把一个表单 / 片段里的 input / select / textarea 抽成属性字典列表。"""
    outs: list[dict[str, str]] = []
    for m in re.finditer(
            r"<(input|select|textarea)\b([^>]*)>", block or "", re.I):
        attrs: dict[str, str] = {"_tag": m.group(1).lower()}
        for am in re.finditer(
                r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*[\"']([^\"']*)[\"']",
                m.group(2) or ""):
            attrs[am.group(1).lower()] = am.group(2)
        outs.append(attrs)
    return outs


def _forms_from(text: str, page: str) -> list[dict[str, Any]]:
    """从一段 HTML 里抽表单。只认真正闭合的 <form>…</form>。"""
    forms: list[dict[str, Any]] = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", text or "", re.I | re.S):
        head, inner = m.group(1), m.group(2)
        action = ""
        am = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", head, re.I)
        if am:
            action = am.group(1)
        method = "GET"
        mm = re.search(r"method\s*=\s*[\"']([^\"']*)[\"']", head, re.I)
        if mm:
            method = mm.group(1).upper()
        fields = _input_attrs(inner)
        forms.append({
            "page": page,
            "action": urljoin(page, action or "") if action else page,
            "action_raw": action,
            "method": method,
            "fields": fields,
            # 每个字段都带 value 属性，才谈得上「精确复现原样报文」
            "fully_valued": bool(fields) and all(
                ("value" in f) for f in fields
                if f.get("_tag") == "input" and f.get("type", "").lower() != "file"),
        })
    return forms


def _payload_from_form(form: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in form.get("fields", []):
        n = f.get("name")
        if not n:
            continue
        t = (f.get("type") or "").lower()
        if t in ("submit", "button", "reset", "file", "image"):
            continue
        out[n] = f.get("value", "")
    return out


def _js_payload_keys(text: str) -> list[str]:
    """从前端脚本里抽「像请求字段」的键名。

    只抓形如  key: value  且 key 落在敏感类别里的字面量，避免把整个
    JS 对象树都当成请求字段 —— 那样产出的「已定位对象」全是噪声。
    """
    keys: list[str] = []
    for m in re.finditer(r"""[{,\s]([a-zA-Z_$][a-zA-Z0-9_$]{1,40})\s*:""", text or ""):
        k = m.group(1)
        if classify(k):
            keys.append(k)
    for m in re.finditer(r"""(?:params|data|body|payload|query)\s*[:=]\s*\{([^}]{0,400})\}""",
                         text or "", re.I):
        for km in re.finditer(r"""([a-zA-Z_$][a-zA-Z0-9_$]{1,40})\s*:""", m.group(1)):
            k = km.group(1)
            if classify(k):
                keys.append(k)
    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        if k.lower() not in seen:
            seen.add(k.lower())
            out.append(k)
    return out


_API_PATH = re.compile(r"""["'`](/?[a-zA-Z0-9_\-./]{1,120}/(?:api|rest|v\d|service)/[^"'`\s]{0,120})["'`]""")


def _api_paths(ctx: Any, blobs: list[tuple[str, str]]) -> list[str]:
    out: list[str] = []
    for _, text in blobs:
        for m in _API_PATH.finditer(text or ""):
            out.append(m.group(1))
    for u in (ctx.js_result or {}).get("urls") or []:
        if isinstance(u, str) and re.search(r"/(api|rest|v\d|service)/", u, re.I):
            out.append(u)
    for u in _pooled_urls(ctx):
        if re.search(r"/(api|rest|v\d|service)/", u or "", re.I):
            out.append(u)
    seen: set[str] = set()
    uniq: list[str] = []
    for u in out:
        key = u.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            uniq.append(u)
    return uniq[:80]


def _pooled_urls(ctx: Any) -> list[str]:
    out: list[str] = []
    cache = getattr(ctx, "_cache", {}) or {}
    for key in ("url_pool_coverage", "url_pool"):
        for u in (cache.get(key) or []):
            if isinstance(u, str):
                out.append(u)
            elif isinstance(u, dict) and u.get("url"):
                out.append(str(u["url"]))
    return out


def build_surface(ctx: Any) -> Surface:
    """从已采集内容里识别业务面。纯读，不发新请求。"""
    surf = Surface()
    blobs = _collect_blobs(ctx)

    # ---- ① 表单（含隐藏字段）----
    # 带上来源标记，后面判断字段来源要用它。
    # 这里**不能**写 `text is fp_result["_render_html"]`：字符串的 `is` 比较
    # 依赖解释器是否做了驻留，同一段内容在不同运行里可能给出不同结果，
    # 会让「SPA 渲染后才出现的字段」时而被标成 form、时而被标成 rendered。
    pages: list[tuple[str, str, str]] = []
    for tag, text in blobs:
        if tag in ("html", "rendered"):
            pages.append((tag, ctx.target_url, text))
    seen_form: set[tuple[str, str]] = set()
    for tag, page, text in pages[:6]:
        for form in _forms_from(text, page):
            ep = form["action"] or page
            # 去重键**不含来源标记**：同一个表单在静态 HTML 与渲染后 DOM 里
            # 通常各出现一次，按来源分开计数会让它被处理两遍。
            # 后果不只是清单里多一行 —— write_diff 会对同一个表单提交两轮，
            # 白白吃掉一倍写预算（全局只有 6 次），真正该测的接口反而轮不到。
            fkey = (ep, "|".join(sorted(str(f.get("name", ""))
                                        for f in form.get("fields", []))))
            if fkey in seen_form:
                continue
            seen_form.add(fkey)
            ref = EndpointRef(url=ep, method=form["method"], origin=tag)
            why = unsafe_reason(ep)
            if why:
                ref.unsafe_reason = why
                surf.unsafe.append(ref)
            for f in form.get("fields", []):
                n = f.get("name")
                if not n:
                    continue
                kind = classify(n)
                if not kind:
                    continue
                is_hidden = (f.get("type") or "").lower() == "hidden"
                if tag == "rendered":
                    origin = "rendered"
                else:
                    origin = "form-hidden" if is_hidden else "form-visible"
                pref = ParamRef(
                    endpoint=ep, param=n, kind=kind, value=f.get("value", ""),
                    origin=origin, method=form["method"], page=page,
                )
                surf.params.append(pref)
                ref.params.append(pref)
            if ref.params and not ref.unsafe_reason:
                surf.endpoints.append(ref)

    # ---- ② 前端脚本里的请求字段 ----
    for tag, text in blobs:
        if tag != "js":
            continue
        for k in _js_payload_keys(text):
            kind = classify(k)
            if not kind:
                continue
            surf.params.append(ParamRef(endpoint="", param=k, kind=kind,
                                        origin="js-payload"))

    # ---- ③ 已枚举 URL 的查询参数 ----
    # 这里必须**保留完整 URL（含查询串）**：差分实验要拿这个串去解析出
    # 原参数、换成非法值再拼回去。只存 path 的话 parse_qs 拿到空字典，
    # 每一条候选都会在「参数不在查询串里」这一步被 continue 掉 ——
    # 表现为「差分实验 0 组」，看起来像「目标没有可测接口」，
    # 实际是这个字段被截断了，整条链路静默失效。
    for u in _pooled_urls(ctx) + _api_paths(ctx, blobs):
        if not isinstance(u, str) or "?" not in u:
            continue
        q = parse_qs(urlparse(u).query)
        for name in q:
            kind = classify(name)
            if not kind and _ENUM_VALUE.match((q[name] or [""])[0]):
                kind = PK_IDENTITY
            if not kind:
                continue
            surf.params.append(ParamRef(
                endpoint=u, param=name, kind=kind,
                value=(q[name] or [""])[0], origin="url-query", method="GET"))

    # ---- ④ 接口路径 ----
    surf.api_paths = _api_paths(ctx, blobs)
    for p in surf.api_paths:
        if unsafe_reason(p):
            continue
        if not any(e.url.startswith(p.split("?")[0]) for e in surf.endpoints):
            surf.endpoints.append(EndpointRef(url=p, method="POST", origin="api-path"))

    # ---- ⑤ 业务特征 ----
    text_all = "\n".join(t for _, t in blobs)
    surf.features = {
        "has_payment": bool(re.search(r"(pay|支付|结算|订单金额|收银)", text_all, re.I)),
        "has_coupon": bool(re.search(r"(coupon|优惠券|折扣|积分|promo)", text_all, re.I)),
        "has_order": bool(re.search(r"(order|订单|下单|购物车|cart)", text_all, re.I)),
        "has_approval": bool(re.search(r"(approve|audit|审批|审核|工单|workflow)", text_all, re.I)),
        "has_upload": bool(re.search(r"(upload|上传|附件|attachment)", text_all, re.I)),
    }

    # ---- 去重 ----
    seen: set[tuple[str, str, str]] = set()
    uniq: list[ParamRef] = []
    for p in surf.params:
        key = (p.endpoint.rstrip("/"), p.param.lower(), p.kind)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
    surf.params = uniq

    # 接口清单也要按 (地址, 方法) 去重。
    # 同一个地址可能被多条路径发现（表单 action、渲染后 DOM、前端脚本里的接口路径），
    # 不去重的话 lead 清单里同一行会印好几遍，写差分也会重复提交同一个表单。
    def _dedupe_eps(items: list[EndpointRef]) -> list[EndpointRef]:
        out: list[EndpointRef] = []
        seen_ep: set[tuple[str, str]] = set()
        for e in items:
            k = (e.url.rstrip("/"), (e.method or "").upper())
            if k in seen_ep:
                continue
            seen_ep.add(k)
            out.append(e)
        return out

    surf.endpoints = _dedupe_eps(surf.endpoints)
    surf.unsafe = _dedupe_eps(surf.unsafe)

    n_sens = len(surf.params)
    if n_sens:
        surf.notes.append(
            f"识别到客户端可控业务参数 {n_sens} 个，涉及 "
            + "、".join(sorted({KIND_CN.get(p.kind, p.kind) for p in surf.params})))
    else:
        surf.notes.append("未识别到客户端可控业务参数（可能是接口全为读取、"
                          "或前端产物未采集到）")
    if surf.unsafe:
        labels = sorted({e.unsafe_reason for e in surf.unsafe})
        surf.notes.append(f"有 {len(surf.unsafe)} 个接口因涉及"
                          f"「{'、'.join(labels)}」被排除在自动差分之外，转人工")
    return surf


# ======================================================================
# 差分实验
# ======================================================================
@dataclass
class DiffRecord:
    """一次差分实验的完整留痕，供报告披露与复测。"""

    kind: str                 # readonly / write
    endpoint: str
    method: str
    param: str
    original: str
    tampered: str
    verdict: str              # PROVEN / VALIDATED / INCONCLUSIVE / ERROR
    detail: str
    baseline_status: int = 0
    tampered_status: int = 0
    changed_fields: list[str] = field(default_factory=list)
    derived_fields: list[str] = field(default_factory=list)


_TAMPER_VALUE: dict[str, tuple[str, str]] = {
    PK_AMOUNT: ("0.01", "改成 0.01（把金额压到分位）"),
    PK_QUANTITY: ("-1", "改成 -1（负数数量）"),
    PK_DISCOUNT: ("-1", "改成 -1（负优惠，等价于反向获利）"),
    PK_STATE: ("99", "改成 99（一个业务上不存在的状态值）"),
    PK_ROLE: ("admin", "改成 admin（越权角色名）"),
    PK_IDENTITY: ("1", "改成 1（最小标识，指向另一条记录）"),
    PK_TIME: ("0", "改成 0（纪元时间，业务上必然非法）"),
    PK_SIGN: ("0", "改成 0（签名置零）"),
}


def _echo_in_body(body: str, param: str, value: str) -> bool:
    """响应里该参数是否被回显成给定值。"""
    if not body or not param:
        return False
    pat = re.compile(
        r'["\']?' + re.escape(param) + r'["\']?\s*[:=]\s*["\']?\s*'
        + re.escape(str(value)) + r'(?![0-9a-zA-Z])', re.I)
    return bool(pat.search(body))


def _flatten_json(body: str) -> dict[str, str]:
    try:
        obj = json.loads(body or "")
    except Exception:  # noqa: BLE001
        return {}
    flat: dict[str, str] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node[:20]):
                walk(v, f"{prefix}[{i}]")
        else:
            if prefix:
                flat[prefix] = "" if node is None else str(node)

    walk(obj, "")
    return flat


def _is_intercepted(resp: dict[str, Any]) -> str:
    """响应是否来自拦截页 / 根本没触达应用。返回非空即代表不可采信。"""
    status = int(resp.get("status") or 0)
    if status == 0:
        return f"请求未完成（{resp.get('error') or '无响应'}）"
    try:
        from engine.wafgate import detect_block_page  # noqa: PLC0415
        verdict = detect_block_page(
            status, dict(resp.get("headers") or {}), (resp.get("body") or "")[:4000])
        if getattr(verdict, "blocked", False):
            return f"响应命中边界拦截特征（{getattr(verdict, 'reason', '')}）"
    except Exception:  # noqa: BLE001
        pass
    return ""


def _judge_differential(rec: DiffRecord, base_body: str, tmpr_body: str,
                        param: str, illegal: str) -> None:
    """差分判据。

    三段式，缺一段都不能下结论：

      · **服务端用客户端值算出了别的字段** → PROVEN。
        例：请求里 amount=0.01，响应里 total=0.01 而 payable 也变成 0.01。
        被篡改的那个字段本身跟着变**不算**（那只是回显），必须有**另一个**字段
        出现了与非法值一致的取值，才说明服务端拿它参与计算了。

      · **所有业务字段都没变** → VALIDATED。服务端忽略了被篡改的字段（自己重算），
        这正是期望行为。

      · **只有被篡改的字段本身变了** → INCONCLUSIVE。无法区分「回显」与「采信」，
        不下结论 —— 这是最容易误报成高危的一类，必须挡住。
    """
    b_flat = _flatten_json(base_body)
    t_flat = _flatten_json(tmpr_body)
    if not b_flat or not t_flat:
        rec.verdict = "INCONCLUSIVE"
        rec.detail = ("响应不是结构化 JSON，无法逐字段比对 —— "
                      "回显与采信区分不开，不下结论（需人工核对）")
        return

    changed = [k for k in t_flat if k in b_flat and b_flat[k] != t_flat[k]]
    leaf = param.lower()
    derived = [k for k in changed
               if k.split(".")[-1].split("[")[0].lower() != leaf
               and str(t_flat[k]) == str(illegal)]
    echoed = [k for k in changed if k.split(".")[-1].split("[")[0].lower() == leaf]
    rec.changed_fields = changed[:12]
    rec.derived_fields = derived[:12]

    if derived:
        rec.verdict = "PROVEN"
        rec.detail = (f"把 `{param}` 从 {rec.original or '原值'} 改为 {illegal} 后，"
                      f"响应中另有业务字段随之变成了同一取值："
                      f"{'、'.join(derived[:5])} —— 服务端确实用客户端提交的"
                      f"{KIND_CN.get(classify(param), param)}参与了业务计算，没有重算。")
    elif not changed:
        rec.verdict = "VALIDATED"
        rec.detail = (f"把 `{param}` 改为 {illegal} 后，响应中所有业务字段与基线完全一致 —— "
                      f"服务端未采信该字段（自行重算或忽略），该参数在本次实验范围内无问题。")
    elif echoed and not derived:
        rec.verdict = "INCONCLUSIVE"
        rec.detail = (f"响应中只有被篡改的 `{param}` 自身变成了 {illegal}，"
                      f"没有其他业务字段跟随变化 —— 无法区分「仅仅回显」与"
                      f"「真的采信」，不下结论。需人工确认该值是否落库。")
    else:
        rec.verdict = "INCONCLUSIVE"
        rec.detail = (f"响应有多个字段变化（{'、'.join(changed[:5])}），"
                      f"但变化方向与篡改值不一致 —— 可能是会话 / 时间戳抖动，"
                      f"不构成本次实验的证据。")


def _pick_account(ctx: Any) -> Any:
    for a in (ctx.accounts or []):
        if getattr(a, "cookies", None) or getattr(a, "headers", None):
            return a
        if isinstance(a, dict) and (a.get("cookies") or a.get("headers")):
            return a
    return None


def readonly_diff(ctx: Any, surface: Surface, *, max_endpoints: int = 8
                  ) -> tuple[list[DiffRecord], list[str]]:
    """只读差分：篡改已枚举查询接口的**已有查询参数**，做基线对照。

    零副作用 —— 全部是 GET，且只改查询串。standard 档即可执行。
    """
    recs: list[DiffRecord] = []
    notes: list[str] = []
    seen: set[tuple[str, str]] = set()
    n = 0
    for p in surface.params:
        if p.origin != "url-query" or p.method.upper() != "GET":
            continue
        if not p.endpoint or not p.param:
            continue
        if unsafe_reason(p.endpoint):
            continue
        key = (p.endpoint.split("?")[0].rstrip("/").lower(), p.param.lower())
        if key in seen:
            continue
        seen.add(key)
        if n >= max_endpoints:
            notes.append(f"只读差分已跑满 {max_endpoints} 个端点，其余留人工")
            break
        n += 1

        illegal, why = _TAMPER_VALUE.get(p.kind, ("-1", "改成非法值"))
        base_url = p.endpoint
        parsed = urlparse(base_url)
        q = parse_qs(parsed.query)
        if p.param not in q:
            continue
        q[p.param] = [illegal]
        t_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

        base = ctx.get(base_url)
        tmpr = ctx.get(t_url)
        b = {"status": int(getattr(base, "status", 0) or 0),
             "headers": dict(getattr(base, "headers", {}) or {}),
             "body": getattr(base, "body_snippet", "") or ""}
        t = {"status": int(getattr(tmpr, "status", 0) or 0),
             "headers": dict(getattr(tmpr, "headers", {}) or {}),
             "body": getattr(tmpr, "body_snippet", "") or ""}

        rec = DiffRecord(kind="readonly", endpoint=base_url, method="GET",
                         param=p.param, original=p.value, tampered=illegal,
                         verdict="INCONCLUSIVE", detail="",
                         baseline_status=b["status"], tampered_status=t["status"])

        if b["status"] not in (200, 201, 204) or b["status"] >= 400:
            rec.verdict = "INCONCLUSIVE"
            rec.detail = (f"基线请求返回 {b['status']}，拿不到可比对的有效响应 —— "
                          f"没有对照就没有结论（需登录态或该接口已不可达）")
            recs.append(rec)
            continue
        why_i = _is_intercepted(t)
        if why_i:
            rec.verdict = "INCONCLUSIVE"
            rec.detail = f"篡改请求的响应不可采信：{why_i}"
            recs.append(rec)
            continue

        if t["status"] >= 500 or (t["status"] != 200 and _ERR_MARKERS.search(t["body"])):
            rec.verdict = "INCONCLUSIVE"
            rec.detail = (f"把 `{p.param}` 改为 {illegal} 后服务端返回 "
                          f"{t['status']}"
                          + ("，响应中出现异常 / 堆栈特征" if _ERR_MARKERS.search(t["body"]) else "")
                          + " —— 非法业务参数确实进到了服务端，属「缺少业务参数校验」，"
                            "但具体后果需人工确认，故不下高危结论。")
            recs.append(rec)
            continue

        if t["status"] in (400, 422) or _VALIDATION_MARKERS.search(t["body"]):
            rec.verdict = "VALIDATED"
            rec.detail = (f"把 `{p.param}` 改为 {illegal} 被明确拒绝"
                          f"（HTTP {t['status']}"
                          + "，响应含校验错误语义" if _VALIDATION_MARKERS.search(t["body"]) else ""
                          + "）—— 服务端对该业务参数有范围校验。")
            recs.append(rec)
            continue

        _judge_differential(rec, b["body"], t["body"], p.param, illegal)
        if rec.verdict == "INCONCLUSIVE" and _echo_in_body(t["body"], p.param, illegal):
            rec.detail += f"（响应中确实出现了 {illegal}）"
        recs.append(rec)
        _ = why

    return recs, notes


def write_diff(ctx: Any, surface: Surface, *, budget: int = 6
               ) -> tuple[list[DiffRecord], list[str], list[str]]:
    """写差分：只对**能精确复现原样报文**的表单做单字段篡改。

    前置条件（缺一不可，全部不满足就整段跳过并把原因交回给人工）：
      ① deep 档 + 台账写入授权（ctx.allow_write）；
      ② 存在已确认登录态（匿名差分拿不到业务对象，比出来的差异没有意义）；
      ③ 表单里每个 input 都在 HTML 里带 value 属性 —— 只有这样，
         「原样请求」才是一字不差可复现的，单字段改动的对照才成立；
      ④ 接口不落在安全过滤清单内。

    返回 (记录, 说明, 未能执行的原因)。
    """
    recs: list[DiffRecord] = []
    notes: list[str] = []
    blocks: list[str] = []

    if os.environ.get("AISCAN_TAMPER", "on").strip().lower() in ("off", "0", "false", "no"):
        blocks.append("环境变量 AISCAN_TAMPER=off，写差分已关闭")
    if not ctx.allow_write:
        blocks.append("未开启受控写验证（需 deep 档 + 台账 --allow-write 授权）")
    if not ctx.risk_allowed(RISK_DEEP):
        blocks.append(f"当前档位（{ctx.profile.get('name', '标准档')}）非 deep")
    acct = _pick_account(ctx)
    if acct is None:
        blocks.append("没有可用的已确认登录态（业务参数差分必须在登录态下做）")
    if blocks:
        return recs, notes, blocks

    used = 0
    for ep in surface.endpoints:
        if used + 2 > budget:
            notes.append(f"写差分预算已用尽（{used}/{budget} 次提交），其余转人工")
            break
        if ep.unsafe_reason or unsafe_reason(ep.url):
            continue
        forms = _forms_from(_blob_for(ctx, ep.url), ep.url)
        form = None
        for f in forms:
            if f["method"] != "POST" or not f["fully_valued"]:
                continue
            if any(classify(n) for n in _payload_from_form(f)):
                form = f
                break
        if form is None:
            continue

        payload = _payload_from_form(form)
        targets = [(n, v, classify(n)) for n, v in payload.items() if classify(n)]
        if not targets:
            continue
        name, original, kind = targets[0]
        illegal, why = _TAMPER_VALUE.get(kind, ("-1", "改成非法值"))
        if str(original) == str(illegal):
            continue

        base = ctx.data_submit(ep.url, payload, method="POST", account=acct,
                               budget_key="tamper", max_total=budget)
        used += 1
        if int(base.get("status") or 0) not in (200, 201, 204):
            recs.append(DiffRecord(
                kind="write", endpoint=ep.url, method="POST", param=name,
                original=str(original), tampered=illegal, verdict="INCONCLUSIVE",
                detail=(f"原样重放返回 {base.get('status')}，不是可用的基线 —— "
                        f"拿不到有效对照，不下结论"), baseline_status=int(base.get("status") or 0)))
            continue
        if _is_intercepted(base):
            continue

        payload2 = dict(payload)
        payload2[name] = illegal
        tmpr = ctx.data_submit(ep.url, payload2, method="POST", account=acct,
                               budget_key="tamper", max_total=budget)
        used += 1

        rec = DiffRecord(
            kind="write", endpoint=ep.url, method="POST", param=name,
            original=str(original), tampered=illegal, verdict="INCONCLUSIVE", detail="",
            baseline_status=int(base.get("status") or 0),
            tampered_status=int(tmpr.get("status") or 0))
        why_i = _is_intercepted(tmpr)
        if why_i:
            rec.detail = f"篡改请求的响应不可采信：{why_i}"
        elif int(tmpr.get("status") or 0) in (400, 422) or \
                _VALIDATION_MARKERS.search(tmpr.get("body") or ""):
            rec.verdict = "VALIDATED"
            rec.detail = (f"把 `{name}` 改为 {illegal} 被服务端拒绝"
                          f"（HTTP {tmpr.get('status')}）—— 有服务端校验。")
        else:
            _judge_differential(rec, base.get("body") or "", tmpr.get("body") or "",
                                name, illegal)
        recs.append(rec)

    if recs:
        notes.append(f"写差分实际提交 {used} 次（预算 {budget} 次），"
                     "每次提交均记入报告第 7 章留痕")
    return recs, notes, blocks


def _blob_for(ctx: Any, url: str) -> str:
    """从已采集内容里找出包含该 action 的页面文本。"""
    if not url:
        return ""
    tail = urlparse(url).path or url
    for _, text in _collect_blobs(ctx):
        if tail and tail in (text or ""):
            return text
    return ""


# ======================================================================
# 静态证明器：前端签名可复现
# ======================================================================
_SIGN_GEN = re.compile(
    r"(md5|sha1|sha256|hmac|btoa|base64|encrypt|crypto)"
    r"[\s\S]{0,160}?"
    r"(sign|signature|_token|nonce|digest|checksum)", re.I)
_HARDCODED_KEY = re.compile(
    r"""(?:key|secret|salt|app_?secret|appKey|secretKey)\s*[:=]\s*["']([^"']{6,64})["']""",
    re.I)


def prove_frontend_signature(ctx: Any, surface: Surface) -> list[Any]:
    """前端可复现的签名 —— 签名不构成防伪造。

    判据要两条同时成立，缺一不报：
      ① 前端脚本里存在「签名值的生成过程」（散列 / HMAC / 编码 紧邻 sign 类变量）；
      ② 该生成过程所依赖的密钥或盐也出现在前端脚本里（硬编码字面量）。

    只有 ① 而无 ② ：签名可能由服务端下发的一次性 nonce 参与，前端算不出完整签名，
    这时报「签名可伪造」就是典型的孤立信号误报。
    """
    findings: list[Any] = []
    blobs = _collect_blobs(ctx)
    for _, text in blobs:
        if not text:
            continue
        m = _SIGN_GEN.search(text)
        if not m:
            continue
        k = _HARDCODED_KEY.search(text)
        if not k:
            continue
        key_val = k.group(1)
        snippet = text[max(0, m.start() - 60): m.end() + 60].replace("\n", " ")
        findings.append(make_finding(
            "WSTG-BUSL-02",
            "业务请求签名可被客户端重算（密钥位于前端）",
            ctx.target_name,
            endpoint="（前端产物）", param=m.group(2),
            severity="高危", confidence="High", evidence_level="A",
            description=(
                "前端脚本中同时出现了签名的生成逻辑与生成所需的密钥常量。"
                "签名的作用是让服务端确认「这个请求确实由本系统发出、且参数没被改过」，"
                "而一旦算法和密钥都在客户端，任何人都能对任意参数重新算出合法签名 —— "
                "签名退化成普通参数，防篡改能力归零。"),
            technical_detail=(
                f"签名相关变量：`{m.group(2)}`\n"
                f"生成方式特征：`{m.group(1)}`\n"
                f"前端可见的密钥常量：`{key_val[:6]}…`（共 {len(key_val)} 字符，"
                "完整值已随证据记录）\n\n"
                f"命中代码片段：\n  {snippet[:400]}"),
            impact=(
                "攻击者可任意篡改业务参数并重新签名，服务端的签名校验全部失效。"
                "受影响的范围取决于哪些接口依赖该签名 —— 若金额、数量、身份标识"
                "也在签名保护的参数集内，等于这些字段完全由客户端决定。"),
            reproduction=(
                "1) 打开前端产物（证据中的文件），定位签名生成逻辑；\n"
                "2) 提取其中的密钥常量；\n"
                "3) 用同一算法对**改动过的**业务参数重算签名，替换原签名后重放请求；\n"
                "4) 若服务端接受，即证明签名校验形同虚设。"),
            remediation=(
                "① 签名密钥必须只存在于服务端，前端只提交原始参数；\n"
                "② 若必须前端参与，改为服务端下发一次性 nonce + 服务端持有密钥的"
                "HMAC，并对 nonce 做一次性校验；\n"
                "③ 关键业务参数（金额 / 数量 / 状态 / 归属）一律服务端重算，"
                "不依赖签名保护。"),
            compliance="等保2.0 数据完整性 / CWE-798 / CWE-345",
            evidence=[_ev("file", "前端产物", f"签名生成与硬编码密钥片段：{snippet[:600]}")],
            grading_basis="前端同时出现签名算法与密钥常量，属完整证据链（A 级），"
                          "签名对任意参数可复算 → 高危",
        ))
        break   # 同一类问题只报一条，避免同一份打包脚本刷屏
    return findings


def _ev(kind: str, content: str, note: str = "") -> Any:
    from engine.checks.base import finding_evidence  # noqa: PLC0415
    try:
        return finding_evidence(kind, content, note)
    except Exception:  # noqa: BLE001
        return {"kind": kind, "content": content, "note": note}


# ======================================================================
# lead 生成：把「人工步骤」实例化成「照着填」
# ======================================================================
def _fmt_param(p: ParamRef) -> str:
    cur = p.value if p.value not in ("", None) else "（页面上未出现具体值）"
    where = p.endpoint or "（仅在前端脚本中出现，接口待定位）"
    return (f"{where} [{p.method}] 字段 `{p.param}` —— "
            f"{KIND_CN.get(p.kind, p.kind)}，{_ORIGIN_CN.get(p.origin, p.origin)}，"
            f"当前值 {cur}")


def _fmt_unsafe(surface: Surface) -> list[str]:
    if not surface.unsafe:
        return []
    by: dict[str, list[str]] = {}
    for e in surface.unsafe:
        by.setdefault(e.unsafe_reason, []).append(e.url)
    out = ["以下是**本次未自动触碰**的接口（副作用不可控，按「不做」处理）："]
    for reason, urls in by.items():
        out.append(f"  · 因「{reason}」排除：{'、'.join(sorted(set(urls))[:5])}")
    out.append("  → 这些接口的等价验证仍需人工在测试环境执行，"
               "自动化的收益不足以承担其副作用。")
    return out


def _lead_common(surface: Surface) -> list[str]:
    out: list[str] = []
    if surface.api_paths:
        out.append(f"本次采集到的业务接口路径 {len(surface.api_paths)} 条："
                   + "、".join(surface.api_paths[:12]))
    feats = [k for k, v in (surface.features or {}).items() if v]
    if feats:
        cn = {"has_payment": "含支付/结算语义", "has_coupon": "含优惠券/积分语义",
              "has_order": "含订单语义", "has_approval": "含审批语义",
              "has_upload": "含上传语义"}
        out.append("业务特征：" + "、".join(cn.get(f, f) for f in feats))
    return out


def lead_for(item_id: str, surface: Surface, diffs: list[DiffRecord]) -> list[str]:
    """按检查项产出「已定位对象清单」。人工照着执行即可。"""
    out: list[str] = []
    tail = item_id.rsplit("-", 1)[-1]

    if tail == "01":
        ps = surface.of_kind(PK_AMOUNT, PK_QUANTITY, PK_TIME, PK_STATE, PK_ROLE)
        out += [_fmt_param(p) for p in ps[:14]]
        if ps:
            out.append("→ 对每个字段依次提交 0 / -1 / 1.5 / 999999999 / null / \"1abc\"，"
                       "逐次记录：是否被受理、业务状态是否进入非法组合、数据是否真的落库")
    elif tail == "02":
        ps = surface.of_kind(PK_SIGN, PK_STATE, PK_ROLE, PK_IDENTITY)
        out += [_fmt_param(p) for p in ps[:14]]
        out.append("→ 对每个字段：删除该字段 / 改为任意值 / 改为他人 ID，"
                   "观察服务端是重新计算覆盖，还是原样采纳")
        hid = [p for p in surface.of_kind(PK_AMOUNT, PK_STATE, PK_ROLE)
               if p.origin == "form-hidden"]
        if hid:
            out.append(f"⚠ 其中 {len(hid)} 个是**表单隐藏字段**（用户完全可改，"
                       "任何依赖隐藏字段的安全判断都不成立）："
                       + "、".join(f"`{p.param}`" for p in hid[:8]))
    elif tail == "03":
        ps = surface.of_kind(PK_IDENTITY)
        out += [_fmt_param(p) for p in ps[:14]]
        ids = [p for p in ps if _ENUM_VALUE.match(str(p.value or ""))]
        if ids:
            out.append(f"⚠ 其中 {len(ids)} 个标识的形态可直接枚举（纯数字 / 短十六进制）："
                       + "、".join(f"`{p.param}`={p.value}（{p.endpoint}）" for p in ids[:8]))
            out.append("→ 对每个标识做 ±1 / ±10 遍历，确认能否命中他人对象；"
                       "命中即同时构成完整性缺陷与越权取数")
        out.append("→ 另需核对幂等：同一唯一键重复提交是否产生重复业务"
                   "（重复扣款 / 重复发货 / 重复入账）")
    elif tail == "04":
        out.append("本次未能自动还原业务流程顺序（HTTP 报文里没有「第几步」的显式标记），"
                   "因此跳步验证仍需人工。以下为候选流程入口，可据此梳理顺序：")
        out += _lead_common(surface)
        eps = [e for e in surface.endpoints if any(
            classify(p.param) == PK_STATE for p in e.params)]
        out += [f"{e.url} [{e.method}]（含状态字段：" +
                "、".join(f"`{p.param}`" for p in e.params if classify(p.param) == PK_STATE)
                + "）" for e in eps[:12]]
        out.append("→ 抓到完整流程的请求序列后，直接调用最后一步、乱序调用、"
                   "重复调用同一步，逐次记录业务是否受理")
    elif tail == "05":
        out.append("次数限制必须真实消耗配额才能验证，自动化重复提交会直接造成"
                   "业务副作用（领券 / 抽奖 / 短信），因此本项不做自动侦察。")
        out += _lead_common(surface)
        out.append("→ 人工按：单账号连续 N+1 次 → 并发 2 次 → 换设备指纹 → "
                   "换账号，四步确定限制维度与是否可突破")
    elif tail == "06":
        ps = surface.of_kind(PK_STATE, PK_ROLE)
        out += [_fmt_param(p) for p in ps[:14]]
        if ps:
            out.append("→ 对每个状态字段直接提交业务终态值（如「已通过」「已支付」），"
                       "对每个角色字段提交 admin，观察是否被服务端接受")
        out.append("→ 申请人 ≠ 审批人的职责分离校验需要 2 组账号，"
                   "属多账号矩阵验证（见 ATHZ 项）")
    elif tail == "10":
        out.append("支付与资金链路**不做任何自动化触碰** —— 副作用不可逆。")
        out.append("→ 人工在测试环境按：金额篡改 → 数量/单价组合 → 券与积分叠加 → "
                   "回调验签与重放 → 退款超额与重复退款，逐项验证")

    # 安全过滤清单统一在这里追加一次。
    # 不能在分支里也追加 —— 那会让 BUSL-10 的清单出现两遍，
    # 读者会以为有两批不同的接口被排除。
    out += _fmt_unsafe(surface)
    return out


# ======================================================================
# 各项侦察入口
# ======================================================================
def _surface_of(ctx: Any) -> Surface:
    cached = (getattr(ctx, "_cache", {}) or {}).get("business_surface")
    if isinstance(cached, Surface):
        return cached
    surf = build_surface(ctx)
    ctx._cache["business_surface"] = surf
    return surf


def _diffs_of(ctx: Any) -> tuple[list[DiffRecord], list[str], list[str]]:
    """整轮扫描只跑一次差分实验，结果缓存复用。

    为什么必须缓存：差分要发真实请求，成本与副作用都不是零。
    7 个 BUSL 项各跑一遍等于把同一个实验重复 7 次 —— 既浪费又放大风险。
    """
    cache = getattr(ctx, "_cache", {}) or {}
    key = "business_diffs"
    if key in cache:
        return cache[key]
    surf = _surface_of(ctx)
    recs: list[DiffRecord] = []
    notes: list[str] = []
    blocks: list[str] = []

    # 只读差分也要求 standard 档。它确实全是 GET、确实零副作用，
    # 但**参数被改过**的 GET 是有风险的：工程上「GET 即写」的接口并不罕见
    # （点击确认类的链接就是），safe 档的承诺是「纯被动读取」，
    # 不能靠「这个接口应该是只读的」这个假设来兑现。
    if not ctx.risk_allowed(RISK_STANDARD):
        blocks.append(f"当前档位（{ctx.profile.get('name', '标准档')}）低于 standard，"
                      "只读差分未执行")
    else:
        recs, notes = readonly_diff(ctx, surf)

    wrecs, wnotes, wblocks = write_diff(ctx, surf)
    recs.extend(wrecs)
    notes.extend(wnotes)
    blocks.extend(wblocks)
    out = (recs, notes, blocks)
    cache[key] = out
    return out


def _diff_findings(ctx: Any, recs: list[DiffRecord]) -> list[Any]:
    """把差分实验里 PROVEN 的记录升级成发现；其余只作为结论写进报告。

    **归口规则**（这里踩过一次坑，写清楚免得又被改回去）：

      · 可枚举标识 → BUSL-03（完整性校验）；
      · 其余一律 → BUSL-01（业务逻辑数据验证）。

    曾经按「金额类参数 → BUSL-10（支付功能）」归口。这是错的，而且错得自相矛盾：
    BUSL-10 的侦察原则是「资金链路不做任何自动化触碰」，
    资金 / 支付类接口在 `unsafe_reason` 里就被拦下、压根不会跑到差分这一步。
    也就是说 BUSL-10 永远不可能从差分里拿到发现 —— 那条分支是死代码，
    真正的后果是「订单金额被采信」这类问题被归到了一个**不会被执行的项**下，
    报告里既不显示为 BUSL-01 的问题，也不显示为 BUSL-10 的问题。
    归口原则：**按「证明了什么」归口，不按「字段叫什么名字」归口。**
    """
    out: list[Any] = []
    for r in recs:
        if r.verdict != "PROVEN":
            continue
        kind = classify(r.param)
        # 金额 / 状态 / 角色类被采信，后果最重；数量类次之。
        sev = "高危" if kind in (PK_AMOUNT, PK_ROLE, PK_STATE, PK_IDENTITY) else "中危"
        _item = "WSTG-BUSL-03" if kind == PK_IDENTITY else "WSTG-BUSL-01"
        out.append(make_finding(
            _item,
            f"服务端采信客户端提交的{KIND_CN.get(kind, '业务')}参数"
            f"（{r.param}）",
            ctx.target_name,
            endpoint=r.endpoint, method=r.method, param=r.param,
            severity=sev, confidence="High", evidence_level="A",
            description=(
                f"对 {r.endpoint} 做单字段差分实验：原样请求与只改动 `{r.param}` 的"
                f"请求各提交一次，服务端在篡改请求的响应中，**另有业务字段随之变成"
                f"了篡改后的取值**。这说明服务端直接拿客户端提交的值参与了业务计算，"
                f"没有以服务端数据重算。"),
            technical_detail=(
                f"基线请求：`{r.param}` = {r.original or '（原样值）'} → "
                f"HTTP {r.baseline_status}\n"
                f"篡改请求：`{r.param}` = {r.tampered} → HTTP {r.tampered_status}\n"
                f"响应中随之变化的字段：{'、'.join(r.changed_fields) or '（无）'}\n"
                f"其中取值等于篡改值的业务字段：{'、'.join(r.derived_fields) or '（无）'}\n\n"
                f"实验结论：{r.detail}"),
            impact=(
                f"`{r.param}` 属于{KIND_CN.get(kind, '业务关键')}参数，且服务端采信客户端取值。"
                "攻击者只需修改这一个字段即可让业务按自己的意图计算 —— "
                "具体后果取决于该接口承载的业务（金额少付 / 数量超限 / 归属篡改 / "
                "状态越权）。"),
            reproduction=(
                f"1) 以与本次实验相同的会话访问 {r.endpoint}；\n"
                f"2) 提交原样报文，记录响应；\n"
                f"3) 仅把 `{r.param}` 改为 {r.tampered}，其余字段原样，再次提交；\n"
                f"4) 对比两次响应：若出现与篡改值一致的**其他**业务字段，即复现成功。"),
            remediation=(
                f"① 服务端对 `{r.param}` 一律重新计算或从服务端数据取值，不采信请求体；\n"
                "② 若该值必须由客户端提交，则加服务端范围校验 + 业务合法性校验；\n"
                "③ 关键字段（金额 / 数量 / 状态 / 归属）在服务端做交叉一致性校验"
                "（如总额 = Σ单价×数量）。"),
            compliance="等保2.0 数据完整性 / PCI-DSS 6.5.x / CWE-602",
            evidence=[_ev("http",
                          f"基线 POST {r.endpoint} {r.param}={r.original} -> {r.baseline_status}",
                          "差分实验基线请求（证据含完整报文）"),
                      _ev("http",
                          f"篡改 POST {r.endpoint} {r.param}={r.tampered} -> {r.tampered_status}",
                          "差分实验篡改请求（与基线仅一个字段不同）")],
            grading_basis=("差分实验含基线与篡改两次请求的完整对照，"
                           "变化方向与篡改值一致属可复测证据（A 级）"
                           + (f"，该字段为{KIND_CN.get(kind, kind)}参数字段 → 定{sev}"
                              if sev else "")),
        ))
    return out


def _recon(ctx: Any, item_id: str) -> ReconOutcome:
    """按检查项组织侦察结论。"""
    # 侦察的输入是「已采集到的页面与前端产物」。一份都拿不到时，
    # 侦察没有可分析的对象 —— 这时必须报 ran=False，
    # 让报告显示「侦察未执行」，而不是给一份看起来做过功课的空清单。
    if not _collect_blobs(ctx):
        return ReconOutcome(
            ran=False,
            error="本次未采集到任何页面或前端产物（可能是目标不可达、"
                  "被边界防护全量拦截，或前端产物采集失败），侦察没有输入")
    surf = _surface_of(ctx)
    recs, dnotes, wblocks = _diffs_of(ctx)
    lead = lead_for(item_id, surf, recs)

    findings: list[Any] = []
    # 前端签名类问题归 BUSL-02；差分确证按参数类型分归 01 / 03 / 10
    if item_id == "WSTG-BUSL-02":
        findings.extend(prove_frontend_signature(ctx, surf))
    if item_id in ("WSTG-BUSL-01", "WSTG-BUSL-03", "WSTG-BUSL-10"):
        for f in _diff_findings(ctx, recs):
            if f.item_id == item_id:
                findings.append(f)

    parts: list[str] = []
    parts.extend(surf.notes)
    if dnotes:
        parts.extend(dnotes)
    if wblocks:
        parts.append("写差分未执行：" + "；".join(wblocks)
                     + " —— 已确证的部分不受影响，但写入类对照仍需人工补齐。")

    proven = [r for r in recs if r.verdict == "PROVEN"]
    validated = [r for r in recs if r.verdict == "VALIDATED"]
    incon = [r for r in recs if r.verdict == "INCONCLUSIVE"]
    if recs:
        parts.append(
            f"差分实验 {len(recs)} 组：确证 {len(proven)}、通过 {len(validated)}、"
            f"无结论 {len(incon)}")
    else:
        parts.append("本次未产生任何差分实验 —— 没有可对照的基线"
                     "（通常是缺少登录态或没有可枚举的查询参数）")

    # 已确证 / 已通过 / 无结论逐条列出，供报告核对并可复测
    for r in recs[:10]:
        marker = {"PROVEN": "🔴 确证", "VALIDATED": "✅ 通过",
                  "INCONCLUSIVE": "❓ 无结论", "ERROR": "⚠ 失败"}.get(r.verdict, r.verdict)
        parts.append(f"{marker} [{r.kind}] {r.endpoint} 字段 `{r.param}`：{r.detail}")

    probes = sum(1 for _ in recs) * 2
    return ReconOutcome(
        ran=True, findings=findings, lead=lead,
        note="\n".join(p for p in parts if p), probes=probes)


# 每项一个具名入口。具名而非闭包，是为了让 detector_ref 可 grep、
# 也让「哪一项挂了哪个侦察」在 validate_coverage 的输出里一眼可见。
#
# 测试靶场模式（deep 档 + 台账 --allow-write 双锁）下，下列项会先跑
# `engine.business_active` 的主动验证：真实复现了漏洞才置「不通过」，
# 复现不了如实写「未确证」并继续走只读侦察。公网目标不带 --allow-write，
# 主动套件整段不执行，行为与过去完全一致。


def _active_then_readonly(ctx: Any, probe, readonly: Any, item_id: str) -> ReconOutcome:
    """主动验证优先，未放行 / 未确证时回落到只读侦察。"""
    from engine import business_active as _ba  # noqa: PLC0415
    try:
        act = probe(ctx)
    except Exception as e:  # noqa: BLE001
        return readonly(ctx) if readonly is not None else ReconOutcome(
            ran=False, error=f"主动验证失败（{type(e).__name__}: {str(e)[:80]}），"
                             f"已回落只读侦察")
    if act is None:
        return readonly(ctx) if readonly is not None else _recon(ctx, item_id)
    if act.findings or (act.ran and (act.note or act.lead)):
        return act
    return readonly(ctx) if readonly is not None else _recon(ctx, item_id)


def recon_busl01(ctx: Any) -> ReconOutcome:
    """BUSL-01 业务逻辑数据验证：靶场模式主动验证评分/边界，否则只读差分。"""
    from engine import business_active as _ba  # noqa: PLC0415
    return _active_then_readonly(ctx, _ba.probe_rating_range, _recon, "WSTG-BUSL-01")


def recon_busl02(ctx: Any) -> ReconOutcome:
    """BUSL-02 请求可伪造性：隐藏字段定位 + 前端签名可复现证明。"""
    return _recon(ctx, "WSTG-BUSL-02")


def recon_busl03(ctx: Any) -> ReconOutcome:
    """BUSL-03 完整性校验：可枚举标识定位 + 标识差分。"""
    return _recon(ctx, "WSTG-BUSL-03")


def recon_busl04(ctx: Any) -> ReconOutcome:
    """BUSL-04 流程时序：候选流程入口梳理（跳步验证仍人工）。"""
    return _recon(ctx, "WSTG-BUSL-04")


def recon_busl05(ctx: Any) -> ReconOutcome:
    """BUSL-05 次数限制：靶场模式主动验证过期优惠券，否则只读定位。"""
    from engine import business_active as _ba  # noqa: PLC0415
    return _active_then_readonly(ctx, _ba.probe_coupon_expiry, _recon, "WSTG-BUSL-05")


def recon_busl06(ctx: Any) -> ReconOutcome:
    """BUSL-06 工作流绕过：靶场模式主动验证擦除流程有效性，否则只读定位。"""
    from engine import business_active as _ba  # noqa: PLC0415
    return _active_then_readonly(ctx, _ba.probe_erasure_ineffective, _recon, "WSTG-BUSL-06")


def recon_busl10(ctx: Any) -> ReconOutcome:
    """BUSL-10 支付功能：靶场模式主动验证会员支付绕过，否则只读识别。"""
    from engine import business_active as _ba  # noqa: PLC0415
    return _active_then_readonly(ctx, _ba.probe_free_membership, _recon, "WSTG-BUSL-10")


_UPLOAD_PATH_HINT = re.compile(r"(upload|attach|file|import|附件|上传)", re.I)
_EXT_DECL = re.compile(
    r"\.(jpe?g|png|gif|webp|bmp|tiff|pdf|docx?|xlsx?|pptx?|zip|rar|7z|txt|csv|"
    r"svg|html?|js|xml|json)\b", re.I)


def lead_upload(ctx: Any, surface: Surface) -> list[str]:
    """上传点的静态定位。

    本项**只做定位，不做任何真实上传** —— 上传是不可逆的写操作，
    且涉及「文件落地后能否被解析」，自动化触碰的收益远小于风险。
    但「哪些地方能传文件、前端声明了什么白名单」是纯静态可得的，
    人工不该再花时间去找。
    """
    out: list[str] = []
    seen: set[str] = set()

    for tag, page, text in _pages(ctx):
        for form in _forms_from(text, page):
            files = [f for f in form.get("fields", [])
                     if (f.get("type") or "").lower() == "file"]
            if not files:
                continue
            ep = form["action"] or page
            key = f"{ep}|{'/'.join(str(f.get('name', '')) for f in files)}"
            if key in seen:
                continue
            seen.add(key)
            names = "、".join(f"`{f.get('name', '（无 name）')}`" for f in files)
            accepts = sorted({str(f.get("accept")) for f in files if f.get("accept")})
            out.append(
                f"{ep} [{form['method']}] 文件字段 {names}"
                + (f"，前端声明 accept=\"{'、'.join(accepts)}\"" if accepts
                   else "，**前端未声明 accept 白名单**（通常说明服务端是唯一防线，"
                        "也可能根本没校验）"))

    for p in surface.api_paths:
        if not _UPLOAD_PATH_HINT.search(p):
            continue
        if any(p in x for x in out) or p in seen:
            continue
        seen.add(p)
        out.append(f"{p} [POST] 前端脚本中的上传接口（无对应表单，可能由 JS 直接构造）")

    declared: set[str] = set()
    for _, text in _collect_blobs(ctx):
        declared |= {m.group(1).lower() for m in _EXT_DECL.finditer(text or "")}
    if declared:
        out.append("前端产物中出现的扩展名提示：" + "、".join(sorted(declared)[:20])
                   + "（可用于反推业务声明的白名单范围）")

    if not out:
        out.append("未定位到上传点 —— 可能本目标确实没有上传功能，"
                   "也可能上传入口在登录后页面（本次未采集到）")

    out.append("→ 每个上传点逐个验证：上传未声明类型 → 访问返回的文件地址 → "
               "观察 Content-Type 与是否被解析执行（**不要投放 webshell**）")
    out.append("→ 验证完成后删除全部测试文件并留痕")
    return out


def _pages(ctx: Any) -> list[tuple[str, str, str]]:
    return [(tag, ctx.target_url, text)
            for tag, text in _collect_blobs(ctx) if tag in ("html", "rendered")]


def _recon_upload(ctx: Any, item_id: str) -> ReconOutcome:
    if not _collect_blobs(ctx):
        return ReconOutcome(
            ran=False,
            error="本次未采集到任何页面或前端产物，上传点无法定位")
    surf = _surface_of(ctx)
    lead = lead_upload(ctx, surf)
    note = ("上传类检查只做**静态定位**：列出上传点、前端声明的白名单、"
            "前端产物里出现的扩展名提示。真实上传（含后缀绕过、内容伪造、"
            "解析执行验证）一律不自动化 —— 上传不可逆，且「能否被解析执行」"
            "一旦验证成功就意味着已经在目标上落地了一个可执行文件。")
    return ReconOutcome(ran=True, lead=lead, note=note, probes=0)


def recon_busl08(ctx: Any) -> ReconOutcome:
    """BUSL-08 非预期文件类型上传：靶场模式主动验证大小/类型 + 毒字节，
    未放行或未确证时回落静态定位。"""
    from engine import business_active as _ba  # noqa: PLC0415
    try:
        up = _ba.probe_upload_limits(ctx)
        nb = _ba.probe_poison_null_byte(ctx)
    except Exception as e:  # noqa: BLE001
        return _recon_upload(ctx, "WSTG-BUSL-08")
    findings = list(up.findings) + list(nb.findings)
    if findings:
        return ReconOutcome(
            ran=True, findings=findings,
            probes=int(up.probes) + int(nb.probes),
            note="；".join(x for x in (up.note, nb.note) if x),
            lead=list(up.lead or []) + list(nb.lead or []))
    if up.ran and nb.ran:
        return ReconOutcome(
            ran=True, probes=int(up.probes) + int(nb.probes),
            note="；".join(x for x in (up.note, nb.note) if x))
    return _recon_upload(ctx, "WSTG-BUSL-08")


def recon_busl09(ctx: Any) -> ReconOutcome:
    """BUSL-09 恶意文件上传：仅静态定位（不做真实上传与解析验证）。"""
    return _recon_upload(ctx, "WSTG-BUSL-09")


__all__ = [
    "Surface", "ParamRef", "EndpointRef", "DiffRecord",
    "build_surface", "readonly_diff", "write_diff", "classify", "normalize_key",
    "prove_frontend_signature", "lead_for", "lead_upload",
    "recon_busl01", "recon_busl02", "recon_busl03", "recon_busl04",
    "recon_busl05", "recon_busl06", "recon_busl08", "recon_busl09",
    "recon_busl10",
    "PK_AMOUNT", "PK_QUANTITY", "PK_DISCOUNT", "PK_STATE", "PK_ROLE",
    "PK_IDENTITY", "PK_TIME", "PK_SIGN", "RISK_STANDARD", "RISK_DEEP",
]
