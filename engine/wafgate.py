# -*- coding: utf-8 -*-
"""边界防护（WAF / 拦截页）识别
==============================

**为什么需要它**

目标可能把**所有**请求都挡在边缘，统一返回一张拦截页。这时检测器看到的不是
应用，而是拦截页。不识别会出现两类严重后果：

1. **把拦截页当成应用页面**，据此产出误报 —— 报告里写了一条真实环境复测不出来的
   「漏洞」，整份报告的可信度归零；
2. **把「没采到」当成「目标没有该功能」** —— 用一次失败的采集把风险判成 N/A，
   这是比误报更隐蔽的错误：它让风险从报告里消失。

**识别方式必须两层，缺一不可**

- **特征匹配**：拦截页正文 / 响应头命中已知厂商特征（各厂商的拦截页都有固定文案）；
- **一致性验证**：请求一个**随机、必然不存在**的路径，若它的响应与根路径
  逐字节相同，说明所有请求都被同一个边缘组件接管了。
  真实应用不可能对任意路径返回同一张页面 —— 这一步把「碰巧命中一个静态错误页」
  与「全站被接管」区分开。

只做特征匹配会漏（厂商改文案就失效），只做一致性会误判（有些 SPA 就是全路径
返回同一页）。两者同时成立才判「被边界防护阻断」，这是个保守判据。
"""

from __future__ import annotations

import difflib
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

# 归一化后相似度达到这个阈值即视为「同一张模板页」。
# 定高一些（0.98）是因为这是「全量接管」的正面判据，宁可漏判也不误判 ——
# 误判的代价是把一个正常站点写成「没触达」，漏判只是退回保守结论。
SAME_PAGE_RATIO = 0.98

# 拦截页通常伴随这些状态码之一。200 不在其中 —— 返回 200 的「软拦截」
# 只能靠一致性 + 特征确认，那种情况本模块保持保守，不轻易断言。
BLOCK_STATUSES = {401, 403, 405, 406, 412, 418, 429, 451, 500, 501, 503}

# 厂商特征：命中任意一条即认为正文是拦截页
# 顺序有意义 —— 越具体的越靠前，避免被通用词抢先匹配。
VENDOR_SIGNATURES: list[tuple[str, str, str]] = [
    # (厂商, 匹配类型 body/header/cookie, 正则)
    ("阿里云 WAF", "body", r"errors\.aliyun\.com"),
    ("阿里云 WAF", "body", r"访问的URL有可能对网站造成安全威胁"),
    ("阿里云 WAF", "body", r"has been blocked as it may cause potential threats"),
    ("阿里云 WAF", "cookie", r"acw_tc="),
    ("阿里云 WAF", "header", r"yundun"),
    ("腾讯云 WAF", "body", r"(?:waf\.tencent|腾讯云.*(?:拦截|阻断))"),
    ("Cloudflare", "body", r"(?:Attention Required|Just a moment|__cf_chl)"),
    ("Cloudflare", "header", r"cf-ray|cf-mitigated"),
    ("安全狗", "body", r"(?:safedog|安全狗)"),
    ("创宇盾", "body", r"(?:yundun|知道创宇)"),
    ("长亭雷池", "body", r"(?:safeline|雷池)[^a-z]"),
    ("Imperva", "body", r"(?:Incapsula|incident_id)"),
    ("F5 BIG-IP ASM", "body", r"The requested URL was rejected"),
    ("华为云 WAF", "body", r"(?:hwclouds|华为云).{0,20}(?:拦截|阻断)"),
    ("通用拦截", "body", r"(?:您的请求被拦截|请求被阻断|访问被拒绝|Request Rejected|"
                          r"Access Denied|Request Blocked|Illegal request)"),
]

# HTTP 库 / 命令行工具的默认 UA。部分边缘防护按此直接阻断，
# 命中时单独提示 —— 这是「扫描器自身特征被拦」，不是目标的问题。
SCANNER_UA_HINT = re.compile(
    r"(?i)(python-requests|curl/|wget|nmap|sqlmap|nikto|nuclei|masscan|go-http-client)")

# ----------------------------------------------------------------------
# DNS CNAME 线索（**线索，不是判据**）
# ----------------------------------------------------------------------
# CNAME 是**边界识别的前置线索**，理由是它不需要任何 HTTP 请求就能拿到：
# 资产测绘阶段解析域名时顺手就得到了，可以在发第一枪之前就知道「边缘是谁家」。
#
# ⚠️ 但它绝不能当判据，三个反例都在本项目实测范围内：
#   ① 同一家的 CDN 与 WAF **共用 CNAME 后缀** —— `*.kunlun.com` 既可能是纯 CDN
#      也可能是挂了 WAF 的 CDN，CNAME 上分不出来；
#   ② **源站直连型 WAF 的域名是直接 A 记录到 WAF VIP 的**，CNAME 上什么都不体现
#      —— 按 CNAME 判「无防护」会整类漏判；
#   ③ 反过来，CNAME 指向阿里云边缘而响应完全没有拦截特征，也是常见形态
#      （域名走了 CDN，WAF 没开或没触发）。
#
# 所以本表只有两个用途：
#   · **具名记录**：报告里写清「DNS 线索指向谁家边缘」，让读者知道流量去哪了；
#   · **一致性加权**：响应特征命中某厂商时，若 CNAME 也指向同一家，
#     厂商判定的置信度提高（两条独立通道指向同一结论）。
# 禁止：用本表的结果直接判 `blocked`。红线「孤立信号不得当正面证据」。
CNAME_SUFFIX_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("阿里云 WAF/CDN", ("waf.aliyuncs.com", "yundun.com", "kunlun.com",
                        "kunlunaq.com", "cdngslb.com", "aliyungslb.com")),
    ("腾讯云 WAF/CDN", ("qcloudwaf.com", "tencentwaf.com", "dnsv1.com",
                        "cdntip.com", "tencentcdn.com", "tencent-cloud.net")),
    ("Cloudflare", ("cloudflare.net", "cloudflare.com")),
    ("创宇盾 CDN/WAF", ("yunaq.com", "365cyd.com", "365cyd.net")),
    ("华为云 WAF/CDN", ("hwclouds.com", "huaweicloud.com", "hwcdn.net")),
    ("Akamai", ("akamaiedge.net", "edgekey.net", "edgesuite.net",
                "akamai.net", "akamaiedge.com")),
    ("AWS CloudFront", ("cloudfront.net",)),
    ("网宿 CDN", ("wscloudcdn.com", "wscdns.com", "ourwebcdn.com", "lxdns.com")),
]


def cname_vendor_hints(cnames: Any) -> list[str]:
    """从 CNAME 记录里提取**边缘服务商线索**（去重、按表序）。

    返回的是厂商名列表，不是判定结果。调用方只能把它写进 notes / 用作
    一致性加权 —— 见 `CNAME_SUFFIX_HINTS` 上方的三条反例。
    """
    out: list[str] = []
    for raw in (cnames or []):
        name = str(raw or "").strip().rstrip(".").lower()
        if not name:
            continue
        for vendor, suffixes in CNAME_SUFFIX_HINTS:
            # 按「域名边界」匹配：等值或 `.<后缀>` 结尾。
            # 直接 endswith 会把 `notkunlun.com` 也算成 `kunlun.com`。
            if any(name == s or name.endswith("." + s) for s in suffixes):
                if vendor not in out:
                    out.append(vendor)
    return out


@dataclass
class BlockVerdict:
    """边界防护判定结果。"""

    blocked: bool = False
    vendor: str = ""
    status: int = 0
    signature: str = ""
    uniform: bool = False
    root_hash: str = ""
    probe_hash: str = ""
    evidence: str = ""
    notes: list[str] = field(default_factory=list)
    #: DNS CNAME 指向的边缘服务商**线索**（见 CNAME_SUFFIX_HINTS）。
    #: 只用于披露与一致性加权，**不参与 blocked 判定**。
    vendor_hints: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.vendor:
            return f"{self.vendor} 拦截"
        # 没有厂商特征时不要写成「边界防护拦截」—— 同一种现象也可能是
        # 自研网关或站点级统一鉴权造成的。措辞要覆盖这三种可能，
        # 因为对扫描而言它们的后果完全一样：**请求没有触达应用**。
        return "边界防护接管" if self.signature else "统一响应接管"

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "vendor": self.vendor,
            "status": self.status,
            "signature": self.signature,
            "uniform": self.uniform,
            "evidence": self.evidence,
            "notes": list(self.notes),
            "vendor_hints": list(self.vendor_hints),
        }


# 拦截页里**每次请求都会变**的内容。不剔除它们，「同一张页面」永远比不出来：
# 阿里云 WAF 的拦截页内嵌 traceid、请求时间、请求 URL，逐字节比对必然不等 ——
# 实测踩过这个坑，第一版就是这么漏判的。
_VOLATILE_TOKENS: list[re.Pattern[str]] = [
    re.compile(r"\b[0-9a-fA-F]{8,}\b"),          # traceid / request id / 内容哈希
    re.compile(r"\b\d{6,}\b"),                    # 时间戳 / 自增 id
    re.compile(r"\b[A-Za-z0-9+/=_\-]{24,}\b"),    # 长 token / base64 / cookie 值
    re.compile(r"https?://[^\s\"'<>]+"),          # 页面内回显的请求地址
]


def _normalize_for_compare(text: str) -> str:
    """把「同一张模板页」归一化到可比形态。

    只保留结构与文案，剔掉每次请求都会变的标识符 —— 这是「同一个边缘组件
    接管了所有请求」这个判断能够成立的前提。
    """
    t = re.sub(r"\s+", " ", (text or "").strip())
    for pat in _VOLATILE_TOKENS:
        t = pat.sub("#", t)
    return t


def _body_hash(text: str) -> str:
    """归一化后取哈希，避免把「同页面不同缩进 / 不同 traceid」判成不同页。"""
    return hashlib.sha256(
        _normalize_for_compare(text).encode("utf-8", "ignore")).hexdigest()[:16]


def _similarity(a: str, b: str) -> float:
    """两段文本的结构相似度。用于哈希不等时兜底判断「是否同一张模板页」。

    拦截页通常只有 2–3KB，用精确 ratio 足够快，也避免 quick_ratio 的上界
    过高导致误判。
    """
    if not a or not b:
        return 0.0
    if abs(len(a) - len(b)) > max(len(a), len(b)) * 0.2:
        return 0.0  # 长度差太大，不必做昂贵的比对
    return difflib.SequenceMatcher(None, a, b).ratio()


def match_signature(body: str, headers: dict[str, Any] | None = None,
                    cookies: list[str] | None = None) -> tuple[str, str]:
    """按厂商特征匹配拦截页。返回 (厂商, 依据) 或 ("", "")。"""
    hdr_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    ck_blob = " ".join(cookies or [])
    for vendor, where, pat in VENDOR_SIGNATURES:
        blob = {"body": body or "", "header": hdr_blob, "cookie": ck_blob}[where]
        m = re.search(pat, blob, re.I)
        if m:
            return vendor, f"{where} 命中 /{pat}/ → {m.group(0)[:60]}"
    return "", ""


# ----------------------------------------------------------------------
# 「整站同一响应」守卫
# ----------------------------------------------------------------------
# 与边界防护同源、但更普适的一类陷阱：目标对**任意路径**返回同一个响应。
# 触发它不必是 WAF —— 反向代理配错、nginx 全站 return 405、错误的路由规则
# 都会造成同样效果。
#
# 危害在于：很多判定把「非 200 的某个状态码」当作「这个路径存在」的证据
# （405 = 路径在但方法不对，401/403 = 路径在但需鉴权）。一旦整站同码，
# 这些推断会**同时**全部成立 —— 实测踩过：某站点全站 405，
# 于是 /login、/admin、/api、/graphql 全部被判定为「存在」，
# 15 项特征凭空变成「具备」，适用性被抬到 124 项。
#
# 所以：先看状态码分布，整站同码时禁止把状态码当作路径存在的证据。
SITEWIDE_MIN_SAMPLES = 5      # 样本太少时统计没有意义
SITEWIDE_DOMINANCE = 0.8      # 众数占比达到这个水平即视为「整站同一响应」
SITEWIDE_STATUSES = {401, 403, 405, 406, 429, 451, 503}


def sitewide_uniform_status(probes: Any) -> tuple[int, float, int]:
    """从路径探测结果判断目标是否「整站同一个响应」。

    probes 可以是：
      - {路径: {"status": int, ...}} 的字典，或
      - 可迭代的 (路径, 探针对象/字典) 序列

    返回 (众数状态码, 占比, 样本数)。未构成「整站同一响应」时返回 (0, 0.0, n)。
    """
    statuses: list[int] = []

    def _status_of(obj: Any) -> int:
        if isinstance(obj, dict):
            return int(obj.get("status") or 0)
        return int(getattr(obj, "status", 0) or 0)

    if isinstance(probes, dict):
        for _k, v in probes.items():
            s = _status_of(v)
            if s:
                statuses.append(s)
    else:
        for pair in probes or []:
            try:
                _k, v = pair
            except Exception:  # noqa: BLE001
                continue
            s = _status_of(v)
            if s:
                statuses.append(s)

    n = len(statuses)
    if n < SITEWIDE_MIN_SAMPLES:
        return 0, 0.0, n
    hist: dict[int, int] = {}
    for s in statuses:
        hist[s] = hist.get(s, 0) + 1
    modal, count = max(hist.items(), key=lambda kv: kv[1])
    ratio = count / n
    if modal in SITEWIDE_STATUSES and ratio >= SITEWIDE_DOMINANCE:
        return modal, ratio, n
    return 0, 0.0, n


def _iter_probes(probes: Any) -> list[Any]:
    """把 dict / 序列两种入参统一成「探针对象或字典」的列表。"""
    if isinstance(probes, dict):
        return list(probes.values())
    out = []
    for pair in probes or []:
        try:
            _k, v = pair
        except Exception:  # noqa: BLE001
            continue
        out.append(v)
    return out


def _probe_body(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("body_snippet") or obj.get("body") or "")
    return str(getattr(obj, "body_snippet", "") or getattr(obj, "body", "") or "")


def status_mix(probes: Any) -> tuple[int, float, int]:
    """返回状态码分布中「最占优」的那个码及其占比，**不做任何门控**。

    与 `sitewide_uniform_status` 的关系是「事实陈述 vs 判据」：
    后者达标才返回非 0，未达标一律返回 `(0, 0.0, n)`；因此在「状态码是混的、
    众数占比 55%」这种场合，判据给出的占比是 **0%**。若把 0% 原样写进报告，
    读者会以为样本为空 —— 事实恰恰相反：样本充足，只是分布被打散了。

    `_guard_why()` 之类的披露文案需要的是**真实占比**，所以单独开这个函数。
    """
    statuses: list[int] = []
    for o in _iter_probes(probes):
        s = int(o.get("status") or 0) if isinstance(o, dict) else int(
            getattr(o, "status", 0) or 0)
        if s:
            statuses.append(s)
    n = len(statuses)
    if not n:
        return 0, 0.0, 0
    hist: dict[int, int] = {}
    for s in statuses:
        hist[s] = hist.get(s, 0) + 1
    modal, count = max(hist.items(), key=lambda kv: kv[1])
    return modal, count / n, n


def sitewide_uniform_body(probes: Any) -> tuple[str, float, int]:
    """判断目标是否对任意路径返回**同一张页面**（按归一化正文）。

    这是「整站同一响应」的**第二个口径**，与状态码口径互补 —— 二者的失效方式
    完全不同，缺一个就会留出一个静默失效的场合：

      · 状态码口径（`sitewide_uniform_status`）：边缘防护若对同一批请求返回
        **不同**状态码（限速 / 挑战 / 部分放行 / 多节点行为不一致），众数占比
        就跌破阈值，判据返回「非同码」—— 而 405/403/401 随即又被当成
        「路径存在」的证据。**2026-09-29 实测踩到**：同一目标同一代码，
        一次探测拿到的状态码是混的，适用性从 67 项被抬到 124 项，
        没有任何提示。**状态码不统一 ≠ 没有整站接管。**
      · 正文口径（本函数）：即便状态码是混的，只要**页面正文归一化后相同**，
        就说明这批响应的来源是同一个组件。

    ⚠️ 但**正文同码本身不足以判定「边缘拦截」**：正常应用里也能出现
    「整站同一张页」（SPA 兜底路由把任意路径都渲染成首页），那是应用自身
    的行为，不是拦截。所以调用方必须再叠加**拦截页厂商特征**（`detect_block_page`）
    才能下拦截结论 —— 本函数只回答「是不是同一张页」，不回答「是谁的页」。

    返回 (归一化正文哈希, 占比, 样本数)；不构成「整站同一页」时返回 ("", 0.0, n)。
    """
    bodies = [_probe_body(o) for o in _iter_probes(probes) if _probe_body(o)]
    n = len(bodies)
    if n < SITEWIDE_MIN_SAMPLES:
        return "", 0.0, n
    hist: dict[str, int] = {}
    for b in bodies:
        h = _body_hash(b)
        hist[h] = hist.get(h, 0) + 1
    modal_hash, count = max(hist.items(), key=lambda kv: kv[1])
    ratio = count / n
    if ratio >= SITEWIDE_DOMINANCE:
        return modal_hash, ratio, n
    return "", 0.0, n


def representative_probe(probes: Any, body_hash: str = "") -> Any | None:
    """取一条「代表探针」，供调用方跑拦截页特征判定。

    `body_hash` 非空时取归一化正文命中该哈希的第一条；为空时取第一条可达的。
    优先取 `status` 非 0 的，避免拿一条连接失败的样本去判厂商特征。
    """
    cands = _iter_probes(probes)
    cands = [o for o in cands if _probe_body(o)]
    if not cands:
        return None
    if body_hash:
        hit = [o for o in cands if _body_hash(_probe_body(o)) == body_hash]
        if hit:
            cands = hit
    for o in cands:
        st = int(o.get("status") or 0) if isinstance(o, dict) else int(
            getattr(o, "status", 0) or 0)
        if st:
            return o
    return cands[0]


def detect_block_page(status: int, headers: dict[str, Any] | None = None,
                      body: str = "", cookies: list[str] | None = None) -> tuple[bool, str, str]:
    """单次响应层面的判定。

    返回 (是否疑似拦截页, 厂商, 依据)。这是**弱判据**：只有特征命中 + 状态码落在
    拦截常见区间才算数。最终结论由 assess_boundary 用一致性实验复核。
    """
    vendor, why = match_signature(body, headers, cookies)
    if not vendor:
        return False, "", ""
    if status not in BLOCK_STATUSES and status != 200:
        return False, "", f"特征命中（{why}）但状态码 {status} 不在拦截常见区间，暂不下结论"
    return True, vendor, why


#: 边缘服务商「家名」关键词 —— 把 DNS 线索名与拦截页厂商名对上。
#: 两侧名称来自不同的表（线索表写「阿里云 WAF/CDN」，特征表写「阿里云 WAF」），
#: 不能直接字符串相等，按家名归一。
_EDGE_FAMILIES = ("阿里云", "腾讯云", "华为云", "Cloudflare", "创宇盾",
                  "Akamai", "AWS", "网宿", "安全狗", "长亭", "Imperva", "F5")


def same_edge_family(a: str, b: str) -> bool:
    """两个名称是否指向同一家边缘服务商（用于一致性加权，不用于判定）。"""
    la, lb = (a or "").lower(), (b or "").lower()
    return any(kw.lower() in la and kw.lower() in lb for kw in _EDGE_FAMILIES)


def _hint_note(v: BlockVerdict, matched: bool) -> None:
    """把 DNS CNAME 线索写进 notes。

    `matched=True`：响应特征命中了厂商，线索用于**一致性加权**（两条独立
    通道是否指向同一家）。`matched=False`：没命中特征，线索只作披露，
    并**明说不得据此判拦截** —— 否则就是把孤立信号当了正面证据。
    """
    if not v.vendor_hints:
        return
    joined = "、".join(v.vendor_hints)
    if matched:
        if same_edge_family(v.vendor, joined):
            v.notes.append(
                f"DNS 线索与响应特征**一致**：CNAME 指向 {joined} 边缘节点，"
                f"响应正文亦命中 {v.vendor} 拦截页特征 —— 两条相互独立的"
                "通道指向同一家，厂商判定置信度提高。")
        else:
            v.notes.append(
                f"DNS 线索：CNAME 指向 {joined}，而响应特征命中 {v.vendor}；"
                "两者不一致，按**响应特征**定厂商（回源链路可能经过了多层代理，"
                "CNAME 上看到的不一定是拦截发生的那一层）。")
    else:
        v.notes.append(
            f"DNS 线索：CNAME 指向 {joined} 边缘节点。"
            "**这只是线索，不是拦截判据** —— 同一家的 CDN 与 WAF 共用 CNAME "
            "后缀，源站直连型 WAF 更是完全不体现在 CNAME 上；"
            "本次响应未命中其拦截页特征，故不据此判拦截。")


def assess_boundary(root: dict[str, Any], control_fetcher: Any = None,
                    base_url: str = "", path_probes: Any = None,
                    cnames: Any = None) -> BlockVerdict:
    """综合判定「本次采集是否被边界防护全量接管」。

    root              —— 根路径探测结果（dict，含 status/headers/body 或 body_snippet）
    control_fetcher   —— 可调用的 (url) -> (status, headers, body)；请求随机不存在路径做对照
    path_probes       —— **指纹阶段已经探过的路径**（{路径: 探针}）。
                         这是最可靠的一致性证据：样本多、且不需要额外发请求。
    cnames            —— 资产测绘阶段拿到的 CNAME 记录（**线索，非判据**）。
                         用于具名披露「边缘是谁家」+ 厂商判定的一致性加权，
                         不参与 blocked 判定。见 `CNAME_SUFFIX_HINTS`。

    判据有两条，**同时成立**才判「被全量接管」（保守判据）：
      ① 正文命中已知厂商的拦截页特征；
      ② 一致性：随机不存在路径（或指纹阶段探测的一整批路径）
         返回与根路径**同一张模板页**。

    一致性证据优先用 path_probes。只依赖一次根路径重取是单点故障：
    那一次请求只要返回了限流页或空正文，边界结论就会静默翻转成
    「未发现拦截」，随后引擎会把拦截页当应用扫，产出一整份复测不出来的
    「漏洞」——实测出过这个事故。
    """
    v = BlockVerdict()
    status = int(root.get("status") or 0)
    headers = root.get("headers") or {}
    body = root.get("body_snippet") or root.get("body") or ""
    cookies = root.get("cookies") or []
    v.status = status
    v.vendor_hints = cname_vendor_hints(cnames)

    def _get(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    items: list[tuple[str, Any]] = []
    if isinstance(path_probes, dict):
        items = list(path_probes.items())

    # ---- ① 特征匹配：根路径或任一已探测路径命中即算命中 ----
    hit, vendor, why = detect_block_page(status, headers, body, cookies)
    if not hit:
        for path, pr in items:
            ps = int(_get(pr, "status", 0) or 0)
            pb = _get(pr, "body_snippet", "") or ""
            h2, v2, w2 = detect_block_page(
                ps, _get(pr, "headers", {}) or {}, pb, _get(pr, "cookies", []) or [])
            if h2:
                hit, vendor, why = True, v2, f"已探测路径 {path}：{w2}"
                if not (body or "").strip():
                    body, status = pb, ps
                    v.status = ps
                break

    if not hit:
        # 正文为空也值得一提：目标不可达与被拦截无法区分，交给上层判「未执行」
        if not (body or "").strip():
            v.notes.append("根路径正文为空，无法区分「目标不可达」与「被拦截」")
        if why:
            v.notes.append(why)
        _hint_note(v, matched=False)

        # 特征没命中，但若整批路径返回同一个非 2xx 响应，仍应提示 ——
        # 这未必有厂商特征，但对「把状态码当路径存在证据」的判定同样致命。
        modal, ratio, n = sitewide_uniform_status(path_probes) if items else (0, 0.0, 0)
        if modal:
            v.notes.append(
                f"整站同一响应提示：{n} 个已探测路径中有 {ratio:.0%} 返回 "
                f"HTTP {modal}，目标疑似对任意路径返回同一张页面；"
                "本报告不将状态码作为「路径存在」的证据。")

            # ---- 无厂商特征时的兜底判定 ----
            # 有些防护是自研的，或者拦截页里不留任何厂商标识，此时「特征匹配」
            # 这条判据整体失效。另一条判据仍然成立：**随机不存在的路径**与
            # 根路径返回同一张非 2xx 页面 —— 真实应用不可能这样。
            #
            # 必须用**随机路径**做对照：只用「一批敏感路径」同码是不够的，
            # 那完全可能只是边界防护只拦敏感路径（路径级拦截），
            # 而普通路径仍可正常访问 —— 两种情况处置完全相反。
            #
            # 也要求「非 2xx」：SPA 恰恰会对任意路径返回同一个 200 外壳页，
            # 那是完全正常的应用行为（SITEWIDE_STATUSES 已排除 200）。
            if (modal == status and n >= SITEWIDE_MIN_SAMPLES
                    and control_fetcher is not None and base_url):
                _bodies = [(_get(pr, "body_snippet", "") or "") for _p, pr in items]
                _hashes = [_body_hash(b) for b in _bodies if b.strip()]
                _cu = (base_url.rstrip("/") + "/" + secrets.token_hex(8)
                       + "-" + secrets.token_hex(4) + ".html")
                try:
                    _cs, _ch, _cb = control_fetcher(_cu)
                except Exception as e:  # noqa: BLE001
                    v.notes.append(f"兜底判定所需的随机路径对照未完成"
                                   f"（{type(e).__name__}: {str(e)[:60]}）")
                    return v
                v.probe_hash = _body_hash(_cb or "")
                _ref = (_body_hash(body) if (body or "").strip()
                        else (_hashes[0] if _hashes else ""))
                _cmp_src = (body if (body or "").strip()
                            else (_bodies[0] if _bodies else ""))
                _same = bool((_cb or "").strip()) and bool(_ref) and (
                    v.probe_hash == _ref
                    or _similarity(_normalize_for_compare(_cmp_src),
                                   _normalize_for_compare(_cb or "")) >= SAME_PAGE_RATIO)
                if int(_cs or 0) == modal and _same:
                    v.uniform = True
                    v.blocked = True
                    v.root_hash = _ref
                    v.evidence = (
                        f"未匹配到已知厂商特征，但**随机不存在的路径**"
                        f"（`/{_cu.rsplit('/', 1)[-1]}`）与根路径返回同一张 "
                        f"HTTP {modal} 页面（归一化内容哈希 `{_ref}`）；"
                        f"另有 {n} 个已探测路径中有 {ratio:.0%} 返回同一状态码。"
                        "真实应用不会对「存在的页面」与「不存在的随机路径」"
                        "返回同一张页面，说明**请求未触达应用**"
                        "（可能是自研边界防护、反向代理配置错误，"
                        "或站点级统一鉴权 / 网关）。"
                        "**本报告不对应用本身下任何结论。**")
                    v.notes.append(
                        "本判定未依赖厂商特征，属一致性判定，置信度低于特征命中："
                        "若确认是站点级统一鉴权而非边界防护，请核对后重扫。")
        return v

    v.vendor = vendor
    v.signature = why
    v.root_hash = _body_hash(body)
    _hint_note(v, matched=True)

    # ---- ② 一致性实验 A：指纹阶段已探过的一整批路径 ----
    # 这是「免费」的对照：样本是十几个路径，而不是一次额外请求。
    if items:
        hashes: list[str] = []
        for _path, pr in items:
            pb = _get(pr, "body_snippet", "") or ""
            if pb.strip():
                hashes.append(_body_hash(pb))
        if len(hashes) >= SITEWIDE_MIN_SAMPLES:
            uniq = set(hashes)
            v.probe_hash = hashes[0]
            if len(uniq) == 1 and hashes[0] == v.root_hash:
                v.uniform = True
                v.notes.append(
                    f"一致性证据：指纹阶段探测的 {len(hashes)} 个路径"
                    f"返回**归一化后完全相同**的页面（哈希 {v.root_hash}），"
                    "与根路径一致。")
            elif len(uniq) == 1:
                # 整批路径彼此相同，但与根路径不同（根路径可能被单独重取过）
                v.uniform = True
                v.notes.append(
                    f"一致性证据：指纹阶段探测的 {len(hashes)} 个路径"
                    f"返回归一化后完全相同的页面（哈希 {hashes[0]}），"
                    "与根路径的哈希不同（根路径可能被重取或被单独限流），"
                    "按整批路径的同质性判定为全量接管。")

    # ---- ② 一致性实验 B：随机不存在路径（未由 A 结论时补做） ----
    if not v.uniform and control_fetcher is not None and base_url:
        probe_path = f"/{secrets.token_hex(8)}-{secrets.token_hex(4)}.html"
        try:
            c_status, c_headers, c_body = control_fetcher(base_url.rstrip("/") + probe_path)
            v.probe_hash = _body_hash(c_body)
            if v.probe_hash and v.probe_hash == v.root_hash:
                v.uniform = True
            else:
                # 归一化哈希不等时再看相似度：拦截页里可能还残留我们没枚举到的
                # 动态位（如随机 nonce）。相似度高说明仍是同一张模板页。
                ratio = _similarity(
                    _normalize_for_compare(body), _normalize_for_compare(c_body))
                if c_status == status and ratio >= SAME_PAGE_RATIO:
                    v.uniform = True
                    v.notes.append(
                        f"归一化后仍有差异，但结构相似度 {ratio:.1%}"
                        f"（同一张模板页），按全量接管判定")
                else:
                    v.notes.append(
                        f"对照实验：随机路径返回的内容与根路径不同"
                        f"（状态码 {c_status}，结构相似度 {ratio:.1%}），"
                        "拦截可能只针对特定路径，未按全量接管处理")
        except Exception as e:  # noqa: BLE001
            v.notes.append(f"对照实验未完成（{type(e).__name__}: {str(e)[:80]}），"
                           "按特征命中保守判定")
            v.uniform = True
    elif not v.uniform:
        v.notes.append("未执行对照实验（缺少对照取数器）")

    if v.uniform:
        v.blocked = True
        v.evidence = (
            f"根路径与随机不存在路径返回**同一张拦截页**"
            f"（归一化内容哈希 {v.root_hash}），"
            f"且正文命中 {vendor} 拦截页特征（{v.signature}），"
            f"HTTP 状态码 {status}。说明所有请求在边缘即被接管，"
            f"**本次采集未触达应用**。")
    else:
        # 特征命中但对照实验不一致 —— 保守处理，不宣称全量接管
        v.evidence = (f"正文命中 {vendor} 拦截页特征（{v.signature}），"
                      f"但随机路径响应与之不同，无法确认全量接管。")
    return v


def scanner_ua_flagged(user_agent: str) -> bool:
    """请求头是否暴露了「这是扫描器」。披露用，不用于绕过。"""
    return bool(SCANNER_UA_HINT.search(user_agent or ""))


if __name__ == "__main__":
    import sys

    sys.stdout.reconfigure(encoding="utf-8")

    # 自测 1：阿里云 WAF 拦截页（真实样本，取自 errors.aliyun.com 的 405 页）
    ali_body = ('<!doctypehtml><html lang="zh-cn"><title>405</title>'
                '<script>function getRenderData(){}</script>'
                '<img src="https://errors.aliyun.com/images/TB1.png">'
                '<div>很抱歉，由于您访问的URL有可能对网站造成安全威胁，您的访问被阻断。</div></html>')
    hit, vendor, why = detect_block_page(405, {"Server": "Tengine"}, ali_body,
                                         ["acw_tc=2f6a1f9d17899746003241687e1872b9c51d32860d0d3ac7e45c17b371582f"])
    assert hit and vendor == "阿里云 WAF", (hit, vendor)
    print(f"✓ 阿里云 WAF 拦截页识别：{vendor} / {why[:70]}")

    # 自测 2：正常业务页面不应被误判
    normal = "<html><head><title>内部生产系统</title></head><body><div id=app></div>" \
             "<script src=/static/app.js></script></body></html>"
    assert not detect_block_page(200, {"Server": "nginx"}, normal)[0], "正常页面被误判为拦截页"
    print("✓ 正常业务页面未误判")

    # 自测 3：一致性实验 —— 两个路径同内容 → 判全量接管
    root = {"status": 405, "headers": {"Server": "Tengine"}, "body_snippet": ali_body,
            "cookies": ["acw_tc=abc"]}
    v = assess_boundary(root, control_fetcher=lambda u: (405, {}, ali_body),
                        base_url="https://example.test")
    assert v.blocked and v.uniform, v
    print(f"✓ 一致性实验：全量接管已确认 → {v.label}")

    # 自测 3.5：拦截页带**每次请求都变**的 traceid 时仍应判为同一张页面。
    # 这一条是踩坑之后补的：第一版用逐字节比对，被 traceid 差异骗成
    # 「拦截只针对特定路径」，于是全量拦截被判成普通站点。
    b_root = {"status": 405, "headers": {"Server": "Tengine"},
              "body_snippet": ('<div>很抱歉，由于您访问的URL有可能对网站造成安全威胁，您的访问被阻断。</div>'
                               '<textarea id="renderData" style="display:none">'
                               '{"traceid":"2f6a1ffc17899746284496708e4d21","lang":"cn"}</textarea>'
                               '<img src="https://errors.aliyun.com/images/TB1.png">'),
              "cookies": ["acw_tc=abc"]}
    b_probe = b_root["body_snippet"].replace(
        "2f6a1ffc17899746284496708e4d21", "9c1d77aa9912304755610293ff01ba92")
    assert b_probe != b_root["body_snippet"], "构造样本失败：两次响应内容应不同"
    v35 = assess_boundary(b_root,
                         control_fetcher=lambda u: (405, {}, b_probe),
                         base_url="https://example.test")
    assert v35.blocked, f"traceid 差异导致漏判：{v35.notes}"
    print("✓ 拦截页含动态 traceid 时仍判定为全量接管（剔除易变标识后比对）")

    # 自测 4：特征命中但对照不一致 → 不宣称全量接管
    v2 = assess_boundary(root,
                         control_fetcher=lambda u: (404, {}, "<html>404 not found</html>"),
                         base_url="https://example.test")
    assert not v2.blocked, "对照不一致时不应判定全量接管"
    print("✓ 对照不一致时保守处理，未宣称全量接管")

    # 自测 5：正文为空的提示
    v3 = assess_boundary({"status": 0, "body_snippet": ""})
    assert not v3.blocked and v3.notes, v3
    print(f"✓ 正文为空的提示：{v3.notes[0]}")

    # 自测 6：扫描器 UA 识别
    assert scanner_ua_flagged("python-requests/2.31")
    assert not scanner_ua_flagged("Mozilla/5.0 (Windows NT 10.0) Chrome/126")
    print("✓ 扫描器 UA 指纹识别")

    # 自测 7：指纹阶段的整批路径本身即可作为一致性证据。
    # 这一条是事故之后补的：边界判定原先只靠**一次**根路径重取，
    # 那一次请求只要返回了限流页 / 空正文，结论就静默翻成「未发现拦截」，
    # 引擎随即把拦截页当应用扫，产出一整份复测不出来的「漏洞」。
    _bp = {f"/p{i}": {"status": 405, "body_snippet": ali_body} for i in range(12)}
    v7 = assess_boundary({"status": 405, "headers": {"Server": "Tengine"},
                          "body_snippet": "", "cookies": []},
                         control_fetcher=None, base_url="https://example.test",
                         path_probes=_bp)
    assert v7.blocked and v7.uniform, f"整批路径同页未判为全量接管：{v7.notes} → {v7.to_dict()}"
    print(f"✓ 指纹阶段整批路径同页即可确认全量接管（{len(_bp)} 个样本，无需额外请求）")

    # 自测 7.5：对照组 —— 根路径正文为空且**没有**整批路径证据时，
    # 不应凭空宣称全量接管。证明 7 的结论确实来自 path_probes 而非别的路径。
    _v75 = assess_boundary({"status": 0, "headers": {}, "body_snippet": "",
                            "cookies": []}, path_probes={})
    assert not _v75.blocked, "无任何证据却判全量接管"
    print("✓ 对照组：无正文、无整批路径证据时不宣称全量接管")

    # 自测 8：整站同一响应的识别（不依赖厂商特征）
    _same = {f"/q{i}": {"status": 405} for i in range(8)}
    modal, ratio, n = sitewide_uniform_status(_same)
    assert modal == 405 and ratio == 1.0 and n == 8, (modal, ratio, n)
    print(f"✓ 整站同一响应识别：HTTP {modal}，占比 {ratio:.0%}，样本 {n}")

    # 自测 8.5：状态码分散时不应误报「整站同一响应」
    _mixed = {"/a": {"status": 200}, "/b": {"status": 404}, "/c": {"status": 302},
              "/d": {"status": 200}, "/e": {"status": 500}, "/f": {"status": 200}}
    modal2, ratio2, _ = sitewide_uniform_status(_mixed)
    assert modal2 == 0, f"状态码分散却被判整站同码：{modal2} {ratio2}"
    print("✓ 状态码分散时未误报整站同一响应")

    # 自测 8.6：样本不足时不下结论
    modal3, _, n3 = sitewide_uniform_status({"/a": {"status": 405}, "/b": {"status": 405}})
    assert modal3 == 0 and n3 == 2, (modal3, n3)
    print("✓ 样本不足（2 个）时不下「整站同一响应」结论")

    # 自测 9：整站同码但**没有随机路径对照**时，只给提示、不判全量接管 ——
    # 样本全是一批敏感路径时，「同码」也可能是「只有这些路径被拦」。
    v9 = assess_boundary({"status": 405, "headers": {}, "body_snippet": "<html>405</html>"},
                         path_probes={f"/z{i}": {"status": 405, "body_snippet": "<html>405</html>"}
                                      for i in range(7)})
    assert not v9.blocked and any("整站同一响应" in x for x in v9.notes), v9.notes
    print("✓ 无厂商特征且无随机路径对照时，只提示、不判全量接管")

    # 自测 9.5：无厂商特征时的兜底判定**必须**依赖随机路径对照。
    # 只靠一批「敏感路径」同码就判全量接管，会把「边界防护只拦敏感路径」
    # （普通路径仍可正常访问）误判成「所有请求都被接管」—— 两者处置完全相反。
    _sens = {f"/admin{i}": {"status": 403, "body_snippet": "<html>403 Forbidden</html>"}
             for i in range(8)}

    def _ctrl_same(_u: str):
        return 403, {}, "<html>403 Forbidden</html>"

    v95a = assess_boundary(
        {"status": 403, "headers": {}, "body_snippet": "<html>403 Forbidden</html>"},
        control_fetcher=_ctrl_same, base_url="https://x.test", path_probes=_sens)
    assert v95a.blocked and v95a.uniform, "随机路径与根路径同页时应判全量接管"
    print("✓ 无厂商特征但随机路径同页：判为全量接管")

    def _ctrl_diff(_u: str):
        return 404, {}, "<html>404 Not Found</html>"

    v95b = assess_boundary(
        {"status": 403, "headers": {}, "body_snippet": "<html>403 Forbidden</html>"},
        control_fetcher=_ctrl_diff, base_url="https://x.test", path_probes=_sens)
    assert not v95b.blocked, "随机路径返回不同页面时不得判全量接管（那只是路径级拦截）"
    print("✓ 仅敏感路径被拦、随机路径不同：不判全量接管（路径级拦截）")

    # 自测 9.6：SPA 对任意路径返回同一个 200 外壳页是**正常应用行为**，
    # 绝不能判成全量接管 —— 否则会把一个完全正常的应用整场判成「未执行」。
    _spa = "<html><head><title>App</title></head><body><div id=root></div></body></html>"

    def _ctrl_spa(_u: str):
        return 200, {}, _spa

    v96 = assess_boundary(
        {"status": 200, "headers": {}, "body_snippet": _spa},
        control_fetcher=_ctrl_spa, base_url="https://s.test",
        path_probes={f"/s{i}": {"status": 200, "body_snippet": _spa} for i in range(8)})
    assert not v96.blocked, "SPA 全路径同一 200 外壳页是正常行为，不得判接管"
    print("✓ SPA 全路径同一 200 外壳页不误判为全量接管")

    # 自测 10：**混合状态码**下的第二个口径。
    # 这是 2026-09-29 实测踩到的静默失效：边缘对同一批请求返回不同状态码
    # （限速 / 挑战 / 部分放行 / 多节点不一致），众数占比跌破 80%，
    # `sitewide_uniform_status` 判「非同码」→ 405/403 又被当成「路径存在」，
    # 适用性从 67 项抬到 124 项，**一条提示都没打**。
    # 唯一还能用的线索是：正文归一化之后仍然完全相同。
    _mix_st = {}
    for i in range(12):
        # 状态码打散：405 只占 5/12 ≈ 42%，远低于 80%
        _mix_st[f"/m{i}"] = {"status": 405 if i < 5 else (403 if i < 9 else 200),
                             "body_snippet": ali_body}
    _ms, _mr, _mn = sitewide_uniform_status(_mix_st)
    assert _ms == 0, f"混合状态码不该被状态码口径判成整站同码：{_ms} {_mr}"
    _msm, _msr, _msn = status_mix(_mix_st)
    assert _msm == 405 and 0.4 < _msr < 0.5 and _msn == 12, (_msm, _msr, _msn)
    print(f"✓ 混合状态码时状态码口径不判整站同码（最高频者 HTTP {_msm} 仅占 {_msr:.0%}）")

    _bh10, _br10, _bn10 = sitewide_uniform_body(_mix_st)
    assert _bh10 and _br10 == 1.0 and _bn10 == 12, (_bh10, _br10, _bn10)
    print(f"✓ 混合状态码时正文口径仍能识别「整站同一张页」（100% / {_bn10} 个样本）")

    _rp10 = representative_probe(_mix_st, _bh10)
    assert _rp10 is not None, "取不到代表探针"
    _bl10, _vd10, _wh10 = detect_block_page(
        int(_rp10.get("status") or 0), {}, str(_rp10.get("body_snippet") or ""), [])
    assert _bl10, f"代表探针应命中拦截页特征：{_wh10}"
    print(f"✓ 代表探针命中拦截页厂商特征（{_vd10 or _wh10}）→ 两口径叠加可判拦截")

    # 自测 10.5：反向误杀 —— SPA 的整站同一张页**不得**因正文口径被判拦截。
    # 正文同码只说「是同一张页」，不说「是谁的页」，必须再叠加厂商特征。
    _spa10 = {f"/p{i}": {"status": 200, "body_snippet": _spa} for i in range(10)}
    _bh105, _, _ = sitewide_uniform_body(_spa10)
    assert _bh105, "SPA 全路径同页应被正文口径识别为「同一张页」"
    _rp105 = representative_probe(_spa10, _bh105)
    _bl105, _, _ = detect_block_page(
        int(_rp105.get("status") or 0), {}, str(_rp105.get("body_snippet") or ""), [])
    assert not _bl105, "SPA 外壳页不得命中拦截页特征"
    assert not (bool(_bh105) and _bl105), "SPA 不得被正文口径判成拦截"
    print("✓ 正文同码但非拦截页（SPA 兜底）不判拦截 —— 正文口径不单独构成拦截结论")

    # 自测 10.6：正文口径同样失败关闭 —— 样本不足时不得下结论
    _few = {f"/f{i}": {"status": 405, "body_snippet": ali_body} for i in range(3)}
    _bh106, _, _n106 = sitewide_uniform_body(_few)
    assert not _bh106 and _n106 == 3, (_bh106, _n106)
    print("✓ 正文口径样本不足（3 个）时不下「整站同一张页」结论")

    # 自测 11：DNS CNAME 线索 —— **只作披露与加权，绝不单独判拦截**
    _normal_page = "<html><head><title>内部生产系统</title></head><body>正常</body></html>"
    v11 = assess_boundary({"status": 200, "body_snippet": _normal_page},
                          cnames=["内部生产系统.example.com.w.kunlunaq.com"])
    assert not v11.blocked, "只有 DNS 线索时不得判拦截（孤立信号不得当正面证据）"
    assert v11.vendor_hints == ["阿里云 WAF/CDN"], v11.vendor_hints
    assert any("只是线索" in n for n in v11.notes), v11.notes
    print(f"✓ DNS 线索只作披露，未据此判拦截：{v11.vendor_hints}")

    # 自测 11.5：线索与响应特征**一致** → 两条独立通道互证，置信度加权
    v115 = assess_boundary({**root, "cookies": ["acw_tc=abc"]},
                           control_fetcher=lambda u: (405, {}, ali_body),
                           base_url="https://example.test",
                           cnames=["内部生产系统.example.com.waf.aliyuncs.com"])
    assert v115.blocked and any("一致" in n for n in v115.notes), v115.notes
    print("✓ DNS 线索与响应特征一致 → 两条独立通道互证，置信度加权")

    # 自测 11.6：线索与响应特征**冲突** → 按响应特征定厂商，不按线索
    v116 = assess_boundary({**root, "cookies": ["acw_tc=abc"]},
                           control_fetcher=lambda u: (405, {}, ali_body),
                           base_url="https://example.test",
                           cnames=["内部生产系统.example.com.cdn.cloudflare.net"])
    assert v116.blocked and any("不一致" in n for n in v116.notes), v116.notes
    assert v116.vendor == "阿里云 WAF", v116.vendor
    print("✓ 线索与特征冲突时以响应特征为准（CNAME 上看到的未必是拦截发生的那层）")

    # 自测 11.7：CNAME 后缀表本身的匹配（含不命中与去重）
    assert cname_vendor_hints(["a.kunlun.com", "b.kunlunaq.com"]) == ["阿里云 WAF/CDN"]
    assert cname_vendor_hints(["cdn.cloudflare.net"]) == ["Cloudflare"]
    assert cname_vendor_hints(["oss-cn-hangzhou.aliyuncs.com"]) == [], \
        "OSS 桶域名只是存储，不得当成边缘 WAF/CDN 线索"
    assert cname_vendor_hints([]) == [] and cname_vendor_hints(None) == []
    print("✓ CNAME 后缀线索表：命中、去重、不误判存储域名")

    print("\n全部断言通过。")
