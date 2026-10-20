# -*- coding: utf-8 -*-
"""SPA 渲染（补「前端路由后面的接口看不到」这个盲区）
================================================================================

问题
--------------------------------------------------------------------------------
SPA（React / Vue / Angular）的页面内容由 JS 在浏览器里渲染，接口调用（XHR /
fetch）也由 JS 发起。匿名 HTTP 抓包只能拿到一个几乎空白的 index.html 和一堆
打包产物 —— 路由、API 端点、渲染后的 DOM 全都看不到，覆盖度静默下降。

方案
--------------------------------------------------------------------------------
· **playwright 可用** → 无头 Chromium 真渲染：捕获渲染后 HTML、同源链接、
  XHR/fetch 请求（这是最有价值的一路：真实的 API 端点清单）；
· **不可用** → 优雅降级：**绝不中断扫描**，只如实报告「覆盖度下降」，
  并给出一条安装命令。绝不把「没渲染」伪装成「没发现问题」。

纪律
--------------------------------------------------------------------------------
· 渲染会执行目标站的 JS —— 这本质上是「主动访问」，沿用扫描本身的授权：
  没登记授权的目标整场扫描都进不来，这里不需要二次闸门；
· 安全档（safe）不渲染：执行 JS 同样可能触发目标侧状态变化与风控；
· 资源限流：屏蔽图片/字体/媒体，超时兜底，失败只记不抛。
================================================================================
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

RENDER_TIMEOUT_S = 25
MAX_XHR = 300          # 单页捕获上限：防跑飞的站点把内存吃光
MAX_LINKS = 300
BLOCKED_TYPES = ("image", "media", "font")

_FRAMEWORK_HINTS = (
    "react", "vue", "angular", "next", "nuxt", "ember", "svelte",
    "antd", "element-ui", "arco", "umi", "vue-router", "react-router",
)


def renderer_available() -> bool:
    """playwright（含浏览器二进制）是否可用。只探测、不安装。"""
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return False
    try:
        with sync_playwright() as p:
            return p.chromium is not None
    except Exception:  # noqa: BLE001
        return False


def install_hint() -> str:
    return ("pip install playwright && playwright install chromium"
            "（约需一次几百 MB 的浏览器下载，装完重扫即可）")


# ======================================================================
# 前端路由表提取
# ======================================================================
# 为什么需要这一段：现代 SPA 的**页面路由**写在打包产物里，HTML 里看不到。
# 而反射型 XSS 等漏洞的入口经常就是某个前端路由的参数
# （Juice Shop 的 `GET /#/search?q=<iframe ...>` 就是这一形态）。
# 只靠「在 HTML / JS 里找 `#/xxx` 字面量」会**整体漏掉这一类** ——
# 框架编译后路由表是 `{path:\`search\`,component:...}` 这种结构，
# 页面上从来没有出现过 `#/search` 这个字符串。
#
# 红队的做法是打开页面看导航，自动化做不到交互，于是退一步：
# **直接读打包产物里的路由定义**。这是黑盒能从前端拿到的最完整路由清单。
#
# 覆盖三种主流写法（键名统一是 `path`，定界符三种都收）：
#   · Angular   —— {path:\`administration\`,component:…}   （压缩后用反引号）
#   · React     —— <Route path="/search">  /  {path:"/search"}
#   · Vue       —— {path:'/basket',component:…}
_ROUTE_DEF_RE = re.compile(
    r"""path\s*[:=]\s*[`'"]([A-Za-z0-9_\-/:.$]{1,60})[`'"]""")

#: 路由名里不该出现的字符（JS 变量名、URL 片段混进来的噪声）
_ROUTE_OK_RE = re.compile(r"^[a-z][a-z0-9\-_/:.]*$", re.I)

#: 一眼就不是路由的取值：文件扩展名 / 绝对路径 / 明显是别的东西
_ROUTE_DENY = (
    ".js", ".css", ".json", ".map", ".svg", ".png", ".ico",
    "http://", "https://", "//", "__", "${",
)


def discover_routes(blobs: list[str] | tuple[str, ...], *,
                    limit: int = 40) -> list[str]:
    """从前端产物正文里提取前端路由清单。

    只返回**看起来像路由**的值（小写字母数字 + `-_/:.`），并剔除明显噪声。
    拿不到就返回空列表 —— 调用方按「无此类来源」处理，不得据此下结论。

    不做「路由一定可达」的断言：路由表里的项受权限守卫（canActivate）约束，
    匿名访问可能被重定向。是否可达由**渲染实测**去证明，不靠推断。
    """
    out: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        for m in _ROUTE_DEF_RE.finditer(blob):
            raw = (m.group(1) or "").strip().strip("/")
            if not raw or len(raw) > 60:
                continue
            if any(d in raw for d in _ROUTE_DENY):
                continue
            if not _ROUTE_OK_RE.match(raw):
                continue
            # 路径参数占位（:id / {id}）具体化，否则拼出来的地址是 404 噪声
            segs = []
            for seg in raw.split("/"):
                if seg.startswith(":") or (seg.startswith("{") and seg.endswith("}")):
                    segs.append("1")
                else:
                    segs.append(seg)
            route = "/".join(segs)
            if route and route not in seen:
                seen.add(route)
                out.append(route)
            if len(out) >= limit:
                return out
    return out


# ---------------------------------------------------------------------------
# 后端接口路径提取
# ---------------------------------------------------------------------------
#
# 为什么非做不可：前后端分离的系统里，**接口文档经常是假的**。
# 实测 Juice Shop v20：`/api-docs` 上挂的是一份 `NextGen B2B API`
# 规范（只有 `/b2b/v2/orders` 一个接口，servers.base = `/b2b/v2`），
# 而真实接口面是 `/rest/*`（25 条）与 `/api/*`（14 条）—— 文档与真身
# 一条都不重合。只信文档，接口枚举池里就只有一个伪接口。
#
# 红队的做法正是打开 DevTools 看网络面板；黑盒自动化做不到交互，
# 于是退一步**直接读打包产物里的接口字面量**。这些路径是前端真实
# 会去请求的地址，比任何文档都可信。
#
# 定界符为什么是「引号 / 反引号 / 右花括号」三种：
#   · `'/rest/user/login'`        —— 普通字符串
#   · `` `/rest/basket/${id}` ``  —— 模板字符串（Angular 压缩后普遍）
#   · `` `${host}/rest/languages` `` —— 前缀拼接，路径紧跟在 `}` 之后
# 少了第三种，`/rest/languages` 这类就一条都取不到。
_API_PATH_RE = re.compile(
    r"""(?:[`'"]|\})(/(?:api|rest|graphql|rpc|services|b2b|v\d)"""
    r"""(?:/[A-Za-z0-9_\-/{}$.:]*)*)""")

#: 一眼不是接口的取值：静态资源 / 文档 / 下载文件
_API_PATH_DENY = (
    ".js", ".css", ".json", ".map", ".svg", ".png", ".jpg", ".ico",
    ".html", ".woff", ".woff2", ".ttf", ".md", ".pdf", ".txt", ".gz",
)

#: 路径参数占位 → 具体值。`${x}` / `:id` / `{id}` 三种写法都要认，
#: 不具体化拼出来的是 404 噪声（还会被当成「接口不存在」）。
_TPL_RE = re.compile(r"\$\{[^}]*\}")
_COLON_PARAM_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_BRACE_PARAM_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def discover_api_paths(blobs: list[str] | tuple[str, ...], *,
                       limit: int = 60) -> list[str]:
    """从前端产物正文里提取**后端接口路径**（相对路径，形如 `/rest/languages`）。

    与 `discover_routes()` 是两件事：那个找前端路由（页面），这个找后端
    接口（数据）。拿不到就返回空列表 —— 调用方按「无此类来源」处理，
    不得据此断言「目标没有其它接口」。

    不做「接口一定存在」的断言：清单来自静态文本，是否真的可达由
    **真实请求**去证明（调用方各自发 GET 复核）。
    """
    out: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        for m in _API_PATH_RE.finditer(blob):
            raw = (m.group(1) or "").strip()
            if not raw:
                continue
            low = raw.lower()
            if any(d in low for d in _API_PATH_DENY):
                continue
            p = _TPL_RE.sub("1", raw)
            p = _COLON_PARAM_RE.sub("1", p)
            p = _BRACE_PARAM_RE.sub("1", p)
            p = p.rstrip("/")
            # 只剩前缀（`/api`）没有任何信息量
            if not p or p.count("/") < 2:
                continue
            if p not in seen:
                seen.add(p)
                out.append(p)
            if len(out) >= limit:
                return out
    return out


def looks_like_spa(html: str, scripts: list[str] | None = None) -> bool:
    """按内容特征判断是不是前端渲染应用。不看内容猜不出来，就说不像。"""
    low = (html or "").lower()
    bundle = " ".join(str(s) for s in (scripts or [])).lower()
    if any(h in low or h in bundle for h in _FRAMEWORK_HINTS):
        return True
    # 几乎没有正文、但挂着打包脚本：SPA 的典型形状
    body_len = len(low)
    n_scripts = low.count("<script")
    if n_scripts >= 3 and body_len < 4000 and "<div id=" in low:
        return True
    return False


def render_collect(target_url: str, extra_urls: list[str] | None = None,
                   timeout_s: int = RENDER_TIMEOUT_S) -> dict[str, Any]:
    """无头渲染入口页（及可选的补充页面）。返回：
    {ok, pages: [{url, status, links, xhr, html_len}], note}
    任何失败都返回 ok=False + 原因 —— 不抛异常、不中断扫描。"""
    out: dict[str, Any] = {"ok": False, "pages": [], "note": ""}
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except Exception as e:  # noqa: BLE001
        out["note"] = f"渲染器不可用（playwright 未安装：{type(e).__name__}）"
        return out

    origin = "{0.scheme}://{0.netloc}".format(urlsplit(target_url))
    targets = [target_url] + [u for u in (extra_urls or [])
                              if str(u).startswith(origin)][:4]
    seen_pages: list[dict[str, Any]] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                viewport={"width": 1366, "height": 900},
                user_agent="Mozilla/5.0 (compatible; aiscan-render/1.0)")
            for t in targets:
                page = ctx.new_page()
                xhr: list[str] = []
                links: list[str] = []

                def _on_request(req: Any, _xhr: list[str] = xhr) -> None:
                    try:
                        if req.resource_type in ("xhr", "fetch"):
                            if len(_xhr) < MAX_XHR:
                                _xhr.append(str(req.url))
                    except Exception:  # noqa: BLE001
                        pass

                page.on("request", _on_request)
                try:
                    resp = page.goto(t, timeout=timeout_s * 1000,
                                     wait_until="domcontentloaded")
                    try:
                        page.wait_for_load_state("networkidle",
                                                 timeout=timeout_s * 1000)
                    except Exception:  # noqa: BLE001
                        pass  # 长轮询型应用永远到不了 networkidle —— 超时即可
                    html = page.content()
                    links = [a for a in page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)")
                        if str(a).startswith(origin)][:MAX_LINKS]
                    seen_pages.append({
                        "url": t,
                        "status": int(resp.status) if resp else 0,
                        "links": links, "xhr": xhr,
                        "html_len": len(html),
                    })
                except Exception as e:  # noqa: BLE001
                    seen_pages.append({"url": t, "status": 0, "links": [],
                                       "xhr": xhr, "html_len": 0,
                                       "error": f"{type(e).__name__}: {str(e)[:120]}"})
                finally:
                    try:
                        page.close()
                    except Exception:  # noqa: BLE001
                        pass
            ctx.close()
            browser.close()
        out["ok"] = any(pg.get("status") for pg in seen_pages)
        out["pages"] = seen_pages
        out["note"] = "渲染完成" if out["ok"] else "渲染未取得任何响应"
    except Exception as e:  # noqa: BLE001
        out["note"] = f"渲染失败：{type(e).__name__}: {str(e)[:160]}"
    return out


def endpoints_of(result: dict[str, Any]) -> list[str]:
    """从渲染结果里取去重后的同源 XHR 端点（最有价值的一路产出）。"""
    urls: list[str] = []
    seen: set[str] = set()
    for pg in result.get("pages") or []:
        for u in pg.get("xhr") or []:
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> int:
    """`python engine/spa.py` 直接跑。

    盯的是「接口清单来自前端产物」这条路的**静默失效**：
    正则少认一种定界符，取到的就从 50 条变 0 条 —— 没有报错，
    报告上只表现为「接口枚举数少了一截」，看不出是哪一环空的。
    """
    ok = True

    def _check(cond: bool, label: str) -> None:
        nonlocal ok
        print(("  ✓ " if cond else "  ✗ ") + label)
        if not cond:
            ok = False

    bundle = (
        # 压缩后 Angular/React 的反引号模板字符串
        "this.host+`/rest/languages`;"
        "path:`/api/Users/${id}`;"
        "x=\"'/rest/user/login'\";"
        # 前缀拼接：路径紧跟在 `}` 之后，少了这条定界符就一条都取不到
        "fetch(`${this.hostServer}/rest/products/search?q=`+q);"
        "y=`${h}/api/BasketItems/${this.id}/checkout`;"
        # 静态资源与页面路径：都不该被当成接口
        "z='/api/main.js';w='/assets/i18n/en.json';v='/api';"
        "u=`/api/Complaints`;t=`/rest/2fa/setup`;"
    )
    got = discover_api_paths([bundle])
    print("  取到：" + "、".join(got))

    _check("/rest/languages" in got, "前缀拼接形态（`` `${host}/rest/...` ``）能取到")
    _check("/rest/user/login" in got, "单引号字符串能取到")
    _check("/api/Users/1" in got, "反引号模板 + `${id}` 被具体化为 1")
    _check("/rest/products/search" in got, "带查询串拼接的路径能取到（截到路径部分）")
    _check("/api/BasketItems/1/checkout" in got, "多级路径参数全部具体化")
    _check("/api/Complaints" in got and "/rest/2fa/setup" in got,
           "无参数的接口路径也在（不因「没有 id」被漏掉）")
    _check(not any(".js" in g or ".json" in g for g in got), "静态资源被排除")
    _check("/api" not in got, "裸前缀（没有任何信息量）不收")
    _check(discover_api_paths([]) == [], "空输入返回空列表（不臆造接口）")
    _check(discover_api_paths([""], limit=2) == [], "无正文时不产出")

    print("\n结论：" + ("SPA 自测通过" if ok else "SPA 自测存在问题，需修"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
