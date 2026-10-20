# -*- coding: utf-8 -*-
"""
前端产物汇聚（Frontend Asset Assembly）
=======================================
把「目标的前端产物」从单一采集阶段解耦出来，做成一件事：
**只要手上还有任何一份页面内容，就尽力从中榨出可用于分析的前端素材。**

为什么需要这个模块
------------------
全量检查项里有 17 项声明 `requires=["js"]`（DOM XSS、原型污染、客户端模板注入、
浏览器存储、postMessage、弱加密原语、Source Map 泄露、第三方外链……）。
它们的判据全部落在 `ctx.js_result` 的 `bodies` / `inline_scripts` / `urls` 上。

过去这些素材只有**一个来源**：L2 采集阶段里的那次 `JsAnalyzer.analyze()`。
于是形成一条很脆的链路：

    L2 采集阶段没跑完 / 被跳过 / 请求被封禁
        → js_result = {}
        → 17 项集体落「未执行」
        → 报告里只剩一句「该目标未采集到前端产物」

问题在于：**这句话经常是不准确的。** 实测里最常见的情形是：

  · L1 阶段其实已经用无头浏览器渲染过入口页，渲染后的 DOM
    就在 `fp_result["_render_html"]` 里 —— 里面有真实的 `<script src>`、
    真实的内联脚本、真实的前端路由链接。这份数据**已经在手上**，
    却从没被喂给 JS 分析。
  · 现代构建产物（Vite / webpack 5）把入口脚本写成
    `<link rel="modulepreload" href="/assets/index-xxxx.js">` 或
    `<script type="module" src=...>`，而老的提取正则只认
    `<script ... src=...>` —— 骨架页里唯一的入口引用就这么漏了。
  · 入口 chunk 里还有一层 `import("./Page-xxxx.js")` 动态分包，
    里面才是真正的业务接口地址。只抓入口不追这一层，
    接口清单基本是空的，「未取得带参数的接口端点」于是成片出现。

本模块把这三件事一次补齐，并且**不改变任何判定口径**：它只负责
「把素材拿到、把来源说清」，判不判得出问题仍然由各检测器自己决定。

覆盖度必须如实披露
------------------
拿到素材 ≠ 覆盖完整。渲染后的 DOM 可能只是骨架、脚本可能只取到一部分、
兜底探测可能全 404。这些都会通过 `coverage_note()` 写进报告，
并且在 `degraded` 为真时明确禁止把该批结果读成「未见异常」。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

# ==============================================================================
# 脚本引用提取
# ==============================================================================
# 老正则 `<script[^>]+src=...>` 漏掉的现代形态，逐个补上：
#   · <script type="module" src=...>        —— src 属性在 type 之后也照样匹配，
#                                              但 crossorigin / defer 在前时
#                                              老正则的 `[^>]+` 能吃下去，问题不在这
#   · <link rel="modulepreload" href=...>   —— **Vite 构建的入口就靠它**，
#                                              只有 href、没有 src，老正则必然漏
#   · <link rel="preload" as="script" href=...>
#   · <link rel="prefetch" as="script" href=...>
SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
LINK_JS_HREF = re.compile(
    r"""<link\b[^>]*\bhref\s*=\s*["']([^"']+\.(?:js|mjs))["']""", re.I)
# 属性顺序不定：rel 与 href 谁先都可能，所以分两条分别锚定
_MODPRELOAD_A = re.compile(
    r"""<link\b[^>]*\brel\s*=\s*["'](?:modulepreload|preload|prefetch)["'][^>]*"""
    r"""\bhref\s*=\s*["']([^"']+)["']""", re.I)
_MODPRELOAD_B = re.compile(
    r"""<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*"""
    r"""\brel\s*=\s*["'](?:modulepreload|preload|prefetch)["']""", re.I)
INLINE_SCRIPT = re.compile(r"""<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>""", re.I | re.S)

# 动态分包引用：import("./x.js") / import('/assets/x.js') / from "./x.mjs"
_DYN_IMPORT = re.compile(
    r"""(?:import\s*\(|from\s*)\s*["']([^"']+\.(?:js|mjs))["']""", re.I)
# 产物里以字符串形式写死的同源 .js 地址（手工拼 <script> 的写法）
_JS_STRING = re.compile(r"""["'`](/[^"'`\s]{1,200}\.(?:js|mjs))["'`]""", re.I)

# SPA 构建产物兜底路径：仅在「页面里一条脚本引用都没提取到」时动用。
# 这些是各主流脚手架默认输出位置，命中率不高但成本极低，
# 且只在极端降级场景才发请求，不会污染正常扫描的请求预算。
SPA_BUILD_PATHS = [
    "main.js", "app.js", "bundle.js", "index.js", "vendor.js",
    "js/app.js", "js/main.js", "js/bundle.js", "js/index.js",
    "static/js/main.js", "static/js/app.js", "assets/index.js",
]

# 各档位允许抓取的脚本份数上限。上限是「克制度」而不是「能力」：
# 一个 400 请求的预算被一个前端站点吃光，后面的注入/越权检查就没得做了。
SCRIPT_FETCH_CAP = {"safe": 6, "standard": 24, "deep": 48}
# 动态分包追击只做一层 —— 追第二层开始收敛极慢且收益断崖式下降
CHUNK_FETCH_CAP = {"safe": 4, "standard": 16, "deep": 32}

# 内联脚本保留上限（字符）。个别站点把整包数据塞进内联脚本，
# 不设限会让内存与后续正则扫描代价失控。
INLINE_KEEP_CHARS = 200_000

_SKIP_JS_SUFFIX = re.compile(r"\.(?:map|d\.ts)$", re.I)


#: 前端分析素材的四个来源。**任何一个非空就足以让检测器跑起来** ——
#: 它们覆盖的能力并不相同，所以不能「凑数」：
#:   · bodies         —— 脚本正文，DOM XSS / 原型污染 / 弱加密原语必需
#:   · inline_scripts —— 内联脚本，配置与拼装地址主要在这里
#:   · urls           —— 接口地址，注入面与越权面识别靠它
#:   · components     —— 组件清单，版本类结论靠它
FRONTEND_MATERIAL_KEYS = ("bodies", "inline_scripts", "urls", "components")


def has_material(js: Any) -> bool:
    """js_result 里是否存在**任何**可用作静态分析的素材。

    这是「未执行」与「跑了但可能待确认」的分界线，也是全项目唯一的判据
    实现处（注册表的 `requires=["js"]` 闸门直接调它，避免两处各写一份走偏）。

    注意空壳对象：`{"spa": {"detected": True}}` 这类**不算素材**。
    它混过闸门的后果是检测器在空数据上跑完并报「通过」——
    最坏的一种假阴性：报告写着「已检查、未见异常」，而实际上没有数据。
    """
    js = js or {}
    for k in FRONTEND_MATERIAL_KEYS:
        v = js.get(k)
        if isinstance(v, (list, tuple, set)) and len(v) > 0:
            return True
    return False


@dataclass
class FrontendAssets:
    """一次前端产物汇聚的全部产出与来源账目。"""

    target: str = ""
    #: 来源名 -> 字符数。报告靠它说明「素材是从哪来的」
    html_sources: dict[str, int] = field(default_factory=dict)
    script_refs: list[str] = field(default_factory=list)
    fetched: list[str] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)
    inline: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    #: 兜底探测实际请求过的构建产物路径
    build_probes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    request_count: int = 0
    tier: str = "standard"
    #: 由调用方注入：渲染是否检测到 SPA（影响覆盖度措辞）
    spa_detected: bool = False
    spa_endpoints: list[str] = field(default_factory=list)
    #: 来源名 -> 页面正文。只在本次调用内使用，不进报告（report 只用长度）。
    pages: dict[str, str] = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------- 判据
    @property
    def has_html(self) -> bool:
        return bool(self.html_sources)

    @property
    def material_count(self) -> int:
        """可用分析素材条数：脚本正文 + 内联脚本 + 提取到的接口。"""
        return len(self.bodies) + len(self.inline) + len(self.endpoints)

    @property
    def has_material(self) -> bool:
        """是否存在**任何**可用于静态分析的素材。

        这是「未执行」与「跑了但可能待确认」的分界线。
        判据直接委托模块级 `has_material()`，保证与注册表闸门同源。
        """
        return has_material({"bodies": self.bodies,
                             "inline_scripts": self.inline,
                             "urls": self.endpoints})

    @property
    def degraded(self) -> bool:
        """覆盖度是否下降。为真时报告必须写明，不得当成完整覆盖。"""
        if not self.has_html:
            return True
        if not self.bodies and not self.inline:
            # 有 HTML 但一点脚本正文都没拿到：DOM XSS / 原型污染这类
            # 依赖代码内容的检查实际上没有材料可查。
            return True
        if self.script_refs and not self.fetched:
            return True        # 页面引了脚本，但一份都没取到
        return False

    # ---------------------------------------------------------------- 输出
    def coverage_note(self) -> str:
        """一句话说清素材来源与缺口。必须能被原样写进报告。"""
        if not self.has_html:
            return ("前端产物：**未取到任何页面内容** —— "
                    "不产生任何前端侧结论"
                    + (f"（原因：{'；'.join(self.errors[:2])}）" if self.errors else ""))
        src = "、".join(f"{k} {v} 字符" for k, v in self.html_sources.items())
        got = (f"脚本引用 {len(self.script_refs)} 个、取到正文 {len(self.fetched)} 份、"
               f"内联脚本 {len(self.inline)} 段、提取接口 {len(self.endpoints)} 条")
        parts = [f"前端产物：来源 {src}；{got}"]
        if not self.script_refs and self.build_probes:
            parts.append(f"页面无脚本引用，已兜底探测 {len(self.build_probes)} 条常见构建路径")
        if self.degraded:
            why = []
            if not self.bodies and not self.inline:
                why.append("未取到任何脚本正文（依赖代码内容的检查缺料）")
            if self.script_refs and not self.fetched:
                why.append("页面引用了脚本但一份都没取到")
            if self.spa_detected and not self.spa_endpoints:
                why.append("检测到前端渲染应用但未捕获到 XHR 接口")
            parts.append("⚠ 覆盖度下降：" + "；".join(why or ["来源不完整"]))
        return "；".join(parts)

    def to_js_result(self) -> dict[str, Any]:
        """转成检测器消费的 js_result 结构（与 JsAnalyzer 输出同形）。"""
        urls: list[str] = []
        seen: set[str] = set()
        for u in list(self.fetched) + list(self.endpoints) + list(self.spa_endpoints):
            if u not in seen:
                seen.add(u)
                urls.append(u)
        return {
            "urls": urls,
            "bodies": list(self.bodies),
            "inline_scripts": list(self.inline),
            "components": [],
            "collected_by": "frontend",
            "collect_note": self.coverage_note(),
            "degraded": self.degraded,
        }


# ==============================================================================
# 主入口
# ==============================================================================
def collect(
    client: Any,
    target_url: str,
    *,
    render_html: str = "",
    entry_paths: tuple[str, ...] = ("login", "index", "home"),
    tier: str = "standard",
    allow_requests: bool = True,
    extra_html: tuple[str, ...] = (),
    spa_detected: bool = False,
    spa_endpoints: tuple[str, ...] | list[str] = (),
) -> FrontendAssets:
    """汇聚前端产物。

    `allow_requests=False` 时**只做纯静态提取**，一个请求都不发 ——
    边界防护已经全量拦截的场景下必须用这个模式：此时再发请求既无意义
    (拿回来的都是拦截页)，又会把「拦截页」混进素材里当应用内容分析。
    但**已经在手上的**内容（尤其是 L1 渲染后的 DOM）仍然要榨干。

    ⚠ `spa_detected` / `spa_endpoints` 由编排层注入（渲染阶段看到的东西），
    本函数只做静态提取，看不到渲染后的 XHR。
    **这两个参数必须在签名里存在** —— 编排层是按关键字传的，少一个就会抛
    `TypeError: collect() got an unexpected keyword argument 'spa_endpoints'`，
    而调用点把它包在 `except Exception` 里 → 补采**每一次扫描都静默失败**，
    症状是「明明修好了多源汇聚，报告里脚本数还是 0」。
    历史上正是这个不一致，让「渲染后 DOM 从未喂给 JS 分析」的修复白做了一轮。
    **改这个签名时，务必同步跑 `selftest_engine.py` 的补采接线断言。**
    """
    tier = (tier or "standard").lower()
    assets = FrontendAssets(target=target_url, tier=tier)

    # ---- 1) 收集页面内容（多源，任何一源失败都不致命）----
    _add_page(assets, "渲染后 DOM（L1 无头浏览器）", render_html)
    for i, h in enumerate(extra_html or ()):
        _add_page(assets, f"附加页面 {i + 1}", h)

    if allow_requests:
        _home = _fetch_text(client, target_url, assets, "入口页", max_bytes=200_000)
        _add_page(assets, "入口页（直取）", _home)
        for ep in entry_paths:
            u = urljoin(target_url, "/" + ep.lstrip("/"))
            _t = _fetch_text(client, u, assets, f"/{ep}", max_bytes=200_000,
                             quiet_on_miss=True)
            _add_page(assets, f"入口页 /{ep}", _t)

    pages = list(assets.html_sources.keys())

    # ---- 2) 脚本引用 ----
    refs: list[str] = []
    for name in pages:
        html = _page_of(assets, name)
        for rx in (SCRIPT_SRC, LINK_JS_HREF, _MODPRELOAD_A, _MODPRELOAD_B):
            for m in rx.finditer(html):
                _push_url(refs, urljoin(target_url, m.group(1)), target_url)

    # 内联脚本里以字符串形式写死的同源 .js（手工拼 <script> 的写法）
    inline_text = "\n".join(_inline_of(_page_of(assets, n)) for n in pages)
    for m in _JS_STRING.finditer(inline_text):
        _push_url(refs, urljoin(target_url, m.group(1)), target_url)

    assets.script_refs = refs

    # ---- 3) 抓取脚本正文 ----
    if allow_requests and refs:
        cap = SCRIPT_FETCH_CAP.get(tier, SCRIPT_FETCH_CAP["standard"])
        for u in refs[:cap]:
            _fetch_script(client, u, target_url, assets)

    # ---- 4) 追一层动态分包 ----
    # 入口 chunk 通常只是个壳，真正的业务接口地址在它 import 出来的分包里。
    # 不追这一层，接口清单基本是空的 —— 大量「未取得带参数的接口端点」
    # 就是这么来的。
    #
    # ⚠ 相对路径必须**以脚本自身的地址为基准**解析。
    # `import("./Page-home.js")` 在 `/assets/entry.js` 里，指的是
    # `/assets/Page-home.js`；按站点根拼会变成 `/Page-home.js`（404），
    # 而症状是「分包追了但一个都没追到」—— 一个不会报错、只会让
    # 接口清单悄悄变短的错误。
    if allow_requests and assets.bodies:
        chunk_cap = CHUNK_FETCH_CAP.get(tier, CHUNK_FETCH_CAP["standard"])
        found: list[str] = []
        for owner, body in zip(assets.fetched, assets.bodies):
            for m in _DYN_IMPORT.finditer(body):
                _push_url(found, urljoin(owner, m.group(1)), target_url)
        fresh = [u for u in found if u not in assets.fetched][:chunk_cap]
        for u in fresh:
            _fetch_script(client, u, target_url, assets, tag="动态分包")

    # ---- 5) 兜底：页面拿到了，但里面一条脚本引用都没有 ----
    # 前提是**手上确实有一份页面**。连页面都没取到时不做这件事 ——
    # 那说明目标不可达或整站被拦，此时按 12 条常见路径盲猜既没有依据，
    # 又是在对着一个够不着的目标白撞（真有边界封禁时还会帮着把封禁坐实）。
    if allow_requests and assets.has_html and not assets.script_refs:
        for p in SPA_BUILD_PATHS:
            u = urljoin(target_url, "/" + p)
            assets.build_probes.append("/" + p)
            pr = _fetch_script(client, u, target_url, assets, quiet_on_miss=True)
            if pr:
                break          # 命中一个就够：它的 import 图会带出其余分包

    # ---- 6) 内联脚本正文 ----
    assets.inline = _collect_inline([_page_of(assets, n) for n in pages])

    # ---- 7) 接口地址提取 ----
    assets.endpoints = _extract_endpoints(
        "\n".join(assets.bodies) + "\n" + "\n".join(assets.inline),
        target_url, assets.fetched)

    # ---- 8) 并入渲染阶段观察到的 XHR 端点 ----
    # 这些端点**不是**从脚本正文里静态提的，而是无头浏览器实际发出的请求，
    # 证据强度更高。编排层在渲染阶段已经把它们并进 js_result["urls"] 了，
    # 这里并进来是为了让「提取接口 N 条」这句覆盖度说明与事实一致 ——
    # 否则报告会写「提取接口 0 条」而检测器手里明明有一堆端点。
    assets.spa_detected = bool(spa_detected) or bool(spa_endpoints)
    if spa_endpoints:
        seen_ep = set(assets.endpoints)
        for u in spa_endpoints:
            if u and u not in seen_ep:
                seen_ep.add(u)
                assets.endpoints.append(u)
        assets.spa_endpoints = [u for u in spa_endpoints if u]
    else:
        assets.spa_endpoints = []

    return assets


# ==============================================================================
# 内部工具
# ==============================================================================
def _page_of(assets: FrontendAssets, name: str) -> str:
    return assets.pages.get(name, "")


def _add_page(assets: FrontendAssets, name: str, html: str) -> None:
    """登记一份页面内容。空内容不登记 —— 「有来源」必须意味着「有内容」。"""
    text = html or ""
    if not text.strip():
        return
    # 同一来源名重复出现时取最长的那份（渲染后 DOM 常比原始 HTML 长）
    prev = assets.pages.get(name, "")
    if len(text) <= len(prev):
        return
    assets.pages[name] = text
    assets.html_sources[name] = len(text)


def _inline_of(html: str) -> str:
    return "\n".join(m.group(1) for m in INLINE_SCRIPT.finditer(html or ""))


def _collect_inline(pages: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[int] = set()
    total = 0
    for html in pages:
        for m in INLINE_SCRIPT.finditer(html or ""):
            blob = m.group(1)
            if not blob.strip():
                continue
            h = hash(blob)
            if h in seen:
                continue
            seen.add(h)
            if total + len(blob) > INLINE_KEEP_CHARS:
                blob = blob[: max(0, INLINE_KEEP_CHARS - total)]
            if not blob.strip():
                break
            out.append(blob)
            total += len(blob)
    return out


def _push_url(bucket: list[str], url: str, base: str) -> None:
    """同站、非 .map、未重复的地址才入桶。

    同站判据与 `JsAnalyzer._is_third_party` **保持一致**（按主域比较）：
    两个模块对同一批地址若给出不同结论，报告里的「脚本引用 N 个」就
    对不上实际抓取数，排查时会把人绕进去。
    站外 CDN 不属于授权范围，一律不主动请求。
    """
    u = (url or "").strip()
    if not u or u in bucket:
        return
    if _SKIP_JS_SUFFIX.search(u):
        return
    if _same_site(base, u):
        bucket.append(u)


def _same_site(base: str, url: str) -> bool:
    try:
        bh = urlparse(base).hostname or ""
        uh = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return False
    if not uh:
        return False

    def root(h: str) -> str:
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h

    return bool(bh) and root(bh) == root(uh)


def _fetch_text(client: Any, url: str, assets: FrontendAssets, label: str,
                max_bytes: int = 4000, quiet_on_miss: bool = False) -> str:
    """取一份文本。失败只记账不抛异常 —— 单源失败不该让整轮汇聚失败。"""
    try:
        pr = _call_fetch(client, url, max_bytes)
        assets.request_count += 1
    except Exception as e:  # noqa: BLE001
        assets.errors.append(f"{label}: {type(e).__name__}: {str(e)[:80]}")
        return ""
    if getattr(pr, "status", 0) != 200:
        if not quiet_on_miss:
            assets.errors.append(
                f"{label}: HTTP {getattr(pr, 'status', 0) or '无响应'}"
                + (f"（{pr.error}）" if getattr(pr, "error", "") else ""))
        return ""
    return getattr(pr, "body_snippet", "") or ""


def _fetch_script(client: Any, url: str, base: str, assets: FrontendAssets,
                  tag: str = "脚本", quiet_on_miss: bool = False) -> str:
    """抓一份脚本正文。走 fetch_asset（全文），失败则退回 fetch（截断）。"""
    if url in assets.fetched:
        return ""
    try:
        pr = _call_fetch_asset(client, url)
        assets.request_count += 1
    except Exception as e:  # noqa: BLE001
        assets.errors.append(f"{tag} {url}: {type(e).__name__}: {str(e)[:80]}")
        return ""
    st = getattr(pr, "status", 0)
    if st != 200:
        if not quiet_on_miss:
            assets.errors.append(f"{tag} {url}: HTTP {st or '无响应'}")
        return ""
    text = getattr(pr, "body_snippet", "") or ""
    # 反爬 / 兜底页识别：静态资源返回 HTML 说明不是真产物
    if re.search(r"<html[\s>]", text[:200], re.I):
        if not quiet_on_miss:
            assets.errors.append(f"{tag} {url}: 返回 HTML 而非脚本内容")
        return ""
    # 正文被上限截断必须留痕（缺陷 D5）：截断点之后的接口地址会整批
    # 静默丢失，不留痕就会被读成「脚本里没有这些接口」。
    if getattr(pr, "body_truncated", False):
        assets.errors.append(
            f"{tag} {url}: 正文超过保留上限被截断（截断点之后的内容未参与分析）")
    assets.fetched.append(url)
    assets.bodies.append(text)
    return text


def _call_fetch(client: Any, url: str, max_bytes: int | None = None) -> Any:
    """调 fetch。真实客户端支持 max_body；自测桩通常只有 fetch(url)，
    多传参数会 TypeError —— 退回单参形式，而不是把桩判成用不了。"""
    if max_bytes is None:
        return client.fetch(url)
    try:
        return client.fetch(url, max_body=int(max_bytes))
    except TypeError:
        return client.fetch(url)


def _call_fetch_asset(client: Any, url: str) -> Any:
    """优先用 fetch_asset（静态产物取全文）；没有就退回 fetch。"""
    fa = getattr(client, "fetch_asset", None)
    if callable(fa):
        return fa(url)
    return _call_fetch(client, url, None)


def _extract_endpoints(blob: str, base: str, scripts: list[str]) -> list[str]:
    """从脚本正文提取接口地址。

    与 `JsAnalyzer._extract_endpoints` 口径一致（模板字符串里的 ${...}
    替换为占位值，保证带参接口仍能被参数提取器解析），这里独立实现
    是为了让本模块能在不依赖 js_analyzer 的情况下单独自测。
    """
    out: list[str] = []
    seen: set[str] = set()

    def push(u: str) -> None:
        u = (u or "").strip()
        if not u or len(u) > 300 or u in seen:
            return
        if any(c in u for c in (" ", "\n", "\t", "\\", "<", ">", "(", ")")):
            return
        if u.startswith(("javascript:", "data:", "mailto:", "#")):
            return
        seen.add(u)
        out.append(u)

    for s in scripts:
        push(s)

    try:
        base_host = urlparse(base).hostname or ""
    except Exception:  # noqa: BLE001
        base_host = ""

    for m in re.finditer(r"[\"'](https?://[^\"'\s]+)[\"']", blob):
        u = m.group(1)
        if base_host and base_host not in u:
            continue
        push(u)

    for m in re.finditer(r"[\"'`]((?:/)[A-Za-z0-9_\-./{}:$~%?&=#+]{1,240})[\"'`]", blob):
        push(re.sub(r"\$\{[^}]*\}", "1", m.group(1)))

    for m in re.finditer(r"[\"'`]((?:/)(?:[A-Za-z0-9_\-.]|\$\{[^}]*\}){1,240})[\"'`]"
                         r"(?:\s*\+|\s*`)", blob):
        push(re.sub(r"\$\{[^}]*\}", "1", m.group(1)))

    # 「变量前缀 + 路径」的模板字符串（`${host}/rest/products/search?q=${e}`）
    # —— 上面三条都要求字符串**以 / 开头**，以 ${...} 开头的会整条静默丢失
    # （2026-10-09 Juice Shop 基准三轮实测：/rest/products/search?q= 就是
    # 这么丢的，3 条 SQLi 挑战全灭）。与 JsAnalyzer 口径保持一致。
    for m in re.finditer(r"[\"'`]\$\{[^}]*\}((?:/)[A-Za-z0-9_\-./{}:$~%?&=#+]{1,240})[\"'`]",
                         blob):
        push(re.sub(r"\$\{[^}]*\}", "1", m.group(1)))

    return out[:400]


# ==============================================================================
# 与 js_result 的合并策略
# ==============================================================================
def merge_into_js_result(js_result: dict[str, Any], assets: FrontendAssets) -> dict[str, Any]:
    """把汇聚结果并入已有 js_result。

    合并规则是**只补不覆盖**：
      · 已有素材（采集阶段真抓到的）优先，汇聚只补空缺。
      · 来源说明与降级标记**总是**写入 —— 报告必须能看出这批素材
        是完整采集来的，还是从渲染 DOM 里补出来的。
      · 素材从无到有这件事要留痕（`collected_by`），否则复测的人
        会以为「当初就是这样」。
    """
    out = dict(js_result or {})
    payload = assets.to_js_result()
    if not out:
        return payload

    def _merge(key: str) -> None:
        cur = list(out.get(key) or [])
        for x in list(payload.get(key) or []):
            if x not in cur:
                cur.append(x)
        if cur:
            out[key] = cur

    for k in ("urls", "bodies", "inline_scripts"):
        _merge(k)

    # 来源与降级信息始终以汇聚结果为准：它掌握多源账目
    out["collect_note"] = assets.coverage_note()
    out["degraded"] = bool(out.get("degraded")) and assets.degraded
    if not out.get("collected_by"):
        out["collected_by"] = "collect+frontend"
    return out
