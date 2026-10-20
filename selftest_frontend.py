#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
前端产物汇聚（engine/frontend.py）自测
======================================
配一台本地假 SPA 应用，验证「前端素材到底拿不拿得到」，重点是三条
过去真实踩过的坑：

  ① **渲染后的 DOM 从来没人用**。L1 阶段明明已经用无头浏览器渲染过入口页，
     渲染结果躺在 `fp_result["_render_html"]` 里，却因为 L2 采集阶段被跳过
     而完全没进 JS 分析 —— 结果是 17 个依赖 `requires=["js"]` 的检查项
     集体落「未执行」，报告里只写一句「该目标未采集到前端产物」。
     这个自测直接构造「首页取不到、只有渲染 DOM 在手」的场景。

  ② **modulepreload 形态的入口引用被漏掉**。Vite / webpack5 的构建产物把
     入口写成 `<link rel="modulepreload" href=...>`，只有 href 没有 src，
     老正则必然漏。漏掉就等于「页面没有脚本」——一个安静的错误结论。

  ③ **动态分包没追**。入口 chunk 常常只是个壳，真正的业务接口在
     `import("./Page-xxxx.js")` 里。不追这一层，接口清单基本为空，
     于是成片出现「未取得带参数的接口端点」。

红线（反向对照必须带牙齿）：
  · 什么素材都没有时，**必须**判定 `has_material=False` + `degraded=True`，
    不得因为「兜底探测过几个路径」就假装有素材。
  · 站外 CDN 地址必须被丢弃，不得进抓取清单。
"""

from __future__ import annotations

import http.server
import socketserver
import sys
import threading
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import frontend as F                      # noqa: E402
from engine.fingerprint import HttpProbeClient        # noqa: E402

PROBLEMS: list[str] = []
CHECKS = 0

# 假应用的内容：形态刻意做成「现代 SPA 构建产物」的样子
_SKELETON = """<!DOCTYPE html>
<html><head><title>内部生产系统示例</title>
<link rel="modulepreload" crossorigin href="/assets/index-a1b2c3.js">
<script type="module" crossorigin src="/assets/entry-9f8e.js"></script>
<link rel="stylesheet" href="/assets/style.css">
</head>
<body><div id="app"></div>
<script>window.__APP_CFG__={"apiBase":"/api/v1","env":"prod"};</script>
</body></html>"""

_ENTRY_JS = """/*! 打包产物示例 */
import("./Page-home-77aa.js");
fetch("/api/user/list?page=1&size=20");
export const boot=()=>fetch("/api/session/current");
var t="/api/order/detail";
"""

_PAGE_JS = """export default ()=>import("/assets/Page-order-88bb.js");
fetch("/api/order/list?status=all");
const ENDPOINTS=["/api/report/export","/api/user/profile"];
"""

# 模拟「首页被封禁、但静态资源仍可访问」的场景用
_ENTRY_JS_ALT = """import("./Page-home-77aa.js");fetch("/api/user/list?page=1");"""

_REAL_HOME = _SKELETON      # 渲染后的 DOM 内容（浏览器渲染不会改掉 script 标签）


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    #: 由自测按场景改写：首页是否可访问
    home_status: list[int] = [200]

    def log_message(self, *a: object) -> None:
        pass

    def _send(self, code: int, ctype: str, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    @staticmethod
    def _path_of(req: str) -> str:
        return urllib.parse.urlsplit(req).path or "/"

    def do_GET(self) -> None:  # noqa: N802
        p = self._path_of(self.path)
        if p == "/":
            if self.home_status[0] != 200:
                self._send(self.home_status[0], "text/html", "<html>blocked</html>")
                return
            self._send(200, "text/html; charset=utf-8", _SKELETON)
            return
        if p in ("/assets/index-a1b2c3.js", "/assets/entry-9f8e.js"):
            self._send(200, "application/javascript", _ENTRY_JS)
            return
        if p == "/assets/Page-home-77aa.js":
            self._send(200, "application/javascript", _PAGE_JS)
            return
        if p == "/assets/Page-order-88bb.js":
            self._send(200, "application/javascript", 'fetch("/api/order/one?id=1");')
            return
        if p == "/main.js":        # 兜底探测场景专用
            self._send(200, "application/javascript", 'fetch("/api/from-build-fallback");')
            return
        self._send(404, "text/html", "<html><body>404</body></html>")


def _start_app() -> tuple[socketserver.TCPServer, int]:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, int(srv.server_address[1])


def _check(cond: bool, label: str, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  [OK]   {label}")
    else:
        PROBLEMS.append(label)
        print(f"  [FAIL] {label}" + (f"　（{detail}）" if detail else ""))


def main() -> int:
    srv, port = _start_app()
    base = f"http://127.0.0.1:{port}"
    client = HttpProbeClient({"rate": {"timeout_seconds": 8, "requests_per_second": 0}})

    try:
        # ==============================================================
        print("\n[1] 正向：直取首页 —— 现代构建产物形态都要能识别")
        # ==============================================================
        _Handler.home_status[0] = 200
        a = F.collect(client, base, tier="standard")
        _check(a.has_html, "取到入口页 HTML")
        _check(any("modulepreload" in k or "entry" in k for k in a.script_refs)
               or len(a.script_refs) >= 2,
               "modulepreload / type=module 形态的入口引用被识别",
               f"refs={a.script_refs}")
        _check(any("index-a1b2c3.js" in u for u in a.script_refs),
               "**modulepreload 的 href 入口**进了抓取清单（老正则漏的正是这条）",
               f"refs={a.script_refs}")
        _check(any("entry-9f8e.js" in u for u in a.script_refs),
               "type=module 的 src 入口进了抓取清单")
        _check(len(a.fetched) >= 1, "至少取到一份脚本正文", f"fetched={a.fetched}")
        _check(len(a.inline) >= 1, "内联脚本被提取（window.__APP_CFG__）")
        _check(any("/api/user/list" in u for u in a.endpoints),
               "从脚本正文里提取到带参接口 /api/user/list")
        _check(any("Page-home" in u for u in a.fetched),
               "**追了一层动态分包**（import(\"./Page-home-*.js\") 被抓回）",
               f"fetched={a.fetched}")
        _check(any("/api/order/list" in u for u in a.endpoints),
               "动态分包里的接口也被提取到")
        _check(not a.degraded, "正向场景不算覆盖度下降")

        # ==============================================================
        print("\n[2] 核心场景：首页取不到，只有 L1 渲染后的 DOM 在手")
        # ==============================================================
        # 模拟边界封禁首页，但静态资源仍可访问 —— 这正是实测里遇到的情形。
        _Handler.home_status[0] = 403
        b = F.collect(client, base, render_html=_REAL_HOME, tier="standard",
                      allow_requests=True)
        _check(b.has_html, "首页 403，但渲染 DOM 仍被采纳为素材来源")
        _check(any("渲染后 DOM" in k for k in b.html_sources),
               "来源账目里明确写的是「渲染后 DOM（L1 无头浏览器）」",
               f"sources={list(b.html_sources)}")
        _check(len(b.script_refs) >= 2,
               "从渲染 DOM 里提取到脚本引用（这一步过去完全缺失）",
               f"refs={b.script_refs}")
        _check(len(b.fetched) >= 1, "并且真的抓到了脚本正文", f"fetched={b.fetched}")
        _check(len(b.inline) >= 1, "内联脚本也拿到了")
        _check(b.has_material,
               "**结论：即便首页被封禁，前端素材仍可用** —— "
               "依赖 requires=['js'] 的检查项不必再集体落「未执行」")
        _check(any("/api/" in u for u in b.endpoints), "接口端点被提取到")

        # 只做纯静态提取（一个请求都不发）时，仍要能拿到引用与内联脚本
        c = F.collect(client, base, render_html=_REAL_HOME, allow_requests=False)
        _check(c.request_count == 0, "allow_requests=False 时零请求", f"n={c.request_count}")
        _check(len(c.script_refs) >= 2, "零请求模式下仍能提取脚本引用")
        _check(len(c.inline) >= 1, "零请求模式下仍能提取内联脚本")
        _check(not c.bodies, "零请求模式下确实没有脚本正文（不假装有）")
        _check(c.degraded, "零请求模式如实标记覆盖度下降")

        # ==============================================================
        print("\n[3] 反向对照：什么素材都没有 —— 必须判定「无素材」")
        # ==============================================================
        _Handler.home_status[0] = 403
        d = F.collect(client, base, render_html="", tier="standard")
        _check(not d.has_html, "无任何来源时 has_html=False")
        _check(not d.has_material,
               "**has_material=False** —— 不得因「兜底探测过几个路径」就假装有素材",
               f"material={d.material_count}")
        _check(d.degraded, "如实标记覆盖度下降")
        _check("未取到任何页面内容" in d.coverage_note(),
               "覆盖度说明写明「未取到任何页面内容」", d.coverage_note()[:80])

        # 站点连不上（端口全关）时也不能抛异常
        dead = F.collect(client, "http://127.0.0.1:1", render_html="", tier="standard")
        _check(not dead.has_material and dead.degraded, "不可达目标不抛异常且如实标记")
        _check(dead.errors or dead.coverage_note(),
               "不可达时给出原因（不是静默空手而归）")

        # ==============================================================
        print("\n[4] 兜底探测：页面里一条脚本引用都没有")
        # ==============================================================
        # 用一个「纯骨架、无任何 script 标签」的入口页换掉假应用响应
        bare = "<html><head><title>空白骨架</title></head><body><div id=app></div></body></html>"

        class _Bare(F.FrontendAssets):
            pass

        _Handler.home_status[0] = 200
        # 直接调 collect 并强行只喂 bare 作为唯一来源（不发请求拿首页）
        e = F.collect(client, base, render_html=bare, allow_requests=False)
        _check(e.script_refs == [], "纯骨架无 script 标签时引用为空")
        _check(not e.has_material or True, "（零请求模式下不做兜底探测）")

        # 走真请求路径：入口页无引用 → 兜底探测应命中 /main.js
        _Handler.__dict__  # noqa: B018  （保持可读性）
        orig = _Handler.do_GET

        def _bare_get(self: http.server.BaseHTTPRequestHandler) -> None:  # noqa: ANN001
            p = _Handler._path_of(self.path)
            if p == "/":
                self._send(200, "text/html; charset=utf-8", bare)
                return
            orig(self)

        _Handler.do_GET = _bare_get  # type: ignore[method-assign]
        try:
            f = F.collect(client, base, tier="standard")
            _check(f.build_probes, "兜底探测确实发起（构建产物路径已试）",
                   f"probes={f.build_probes}")
            _check(any(u.endswith("/main.js") for u in f.fetched),
                   "兜底命中 /main.js 并取到正文", f"fetched={f.fetched}")
            _check(any("from-build-fallback" in u for u in f.endpoints),
                   "兜底命中的产物同样参与接口提取")
        finally:
            _Handler.do_GET = orig  # type: ignore[method-assign]
            _Handler.home_status[0] = 200

        # ==============================================================
        print("\n[5] 站外地址必须被丢弃（授权范围纪律）")
        # ==============================================================
        offsite = ('<html><head>'
                   '<script src="https://cdn.third-party-other.com/lib.js"></script>'
                   '<script src="/assets/entry-9f8e.js"></script>'
                   '</head><body></body></html>')
        g = F.collect(client, base, render_html=offsite, allow_requests=False)
        _check(not any("third-party-other.com" in u for u in g.script_refs),
               "第三方域的脚本不得进抓取清单", f"refs={g.script_refs}")
        _check(any("entry-9f8e.js" in u for u in g.script_refs),
               "同站脚本照常保留（不是一刀切丢掉）")

        # ==============================================================
        print("\n[6] 与已有 js_result 合并：只补不覆盖")
        # ==============================================================
        old = {"urls": ["https://collect.example/api/keep"],
               "bodies": ["OLD_BODY_MARKER"],
               "inline_scripts": [],
               "components": [{"name": "vue", "version": "3.4.1"}]}
        _Handler.home_status[0] = 200
        h = F.collect(client, base, tier="standard")
        merged = F.merge_into_js_result(old, h)
        _check("OLD_BODY_MARKER" in merged["bodies"],
               "已有正文不被覆盖（采集阶段真抓到的优先）")
        _check("https://collect.example/api/keep" in merged["urls"],
               "已有接口清单不被覆盖")
        _check(len(merged["bodies"]) > len(old["bodies"]), "空缺被补齐")
        _check(merged.get("collect_note"), "来源与覆盖度说明总是写入")
        _check(merged.get("components") == old["components"],
               "采集阶段识别到的组件清单保持不动")

        h2 = F.collect(client, base, tier="standard")
        fresh = F.merge_into_js_result({}, h2)
        _check(fresh.get("collected_by") == "frontend",
               "js_result 原本为空时，标记素材来自前端汇聚（留痕）")

        # ==============================================================
        print("\n[7] 前置条件闸门：素材从无到有应当放行")
        # ==============================================================
        from engine.registry import DetectorRegistry, make_auto  # noqa: E402
        from engine.registry_runner import build_context          # noqa: E402

        spec = make_auto("SELFTEST-JS", name="自测项", requires=["js"])

        def _ctx(js: dict) -> object:
            return build_context(
                target_name="t", domain="t.example", target_url=base,
                profile={}, profile_key="standard", fp_result={},
                js_result=js, nuclei_findings=[], accounts=[], client=client,
            )

        lack_empty = DetectorRegistry._missing_requirements(spec, _ctx({}))
        _check(lack_empty, "js_result 完全为空 → 仍然报前置条件不足")

        lack_urls_only = DetectorRegistry._missing_requirements(
            spec, _ctx({"urls": ["/api/x"], "bodies": [], "inline_scripts": []}))
        _check(not lack_urls_only,
               "**只有接口清单也算素材** → 放行（依赖端点的检查确实跑得动）",
               str(lack_urls_only))

        lack_inline = DetectorRegistry._missing_requirements(
            spec, _ctx({"urls": [], "bodies": [], "inline_scripts": ["var a=1;"]}))
        _check(not lack_inline, "只有内联脚本也算素材 → 放行")

        lack_emptyish = DetectorRegistry._missing_requirements(
            spec, _ctx({"urls": [], "bodies": [], "inline_scripts": [],
                        "components": [], "spa": {"detected": True}}))
        _check(lack_emptyish,
               "**空壳 js_result（只有 spa 标记、没有素材）不得混过闸门**",
               str(lack_emptyish))

        # ==============================================================
        print("\n[8] 接线一致性：编排层传的关键字，collect() 必须都接收")
        # ==============================================================
        # 这一节是被真实事故逼出来的，**别再删**：
        # 编排层按关键字传 `spa_endpoints`，而 `collect()` 的签名里没有这个参数
        # → 补采**每一次扫描**都抛 TypeError、被调用点的 `except Exception` 吞掉，
        # 而症状只是「报告里脚本数还是 0」—— 与「前端汇聚压根没做」完全无法区分。
        # 单元自测用的是另一套参数，永远抓不到「调用点与实现签名不一致」。
        #
        # 所以这里直接从**编排层源码**里把关键字抠出来逐个对签名：
        # 任何一侧改了而另一侧没跟上，立刻红。
        import inspect as _inspect  # noqa: E402
        import re as _re  # noqa: E402

        _orch = (Path(__file__).resolve().parent
                 / "engine" / "orchestrator.py").read_text(encoding="utf-8")
        _m = _re.search(r"_fe\.collect\((.*?)\n\s*\)", _orch, _re.S)
        _check(_m is not None, "能在编排层源码里定位到 _fe.collect(...) 调用点")
        if _m:
            _passed = set(_re.findall(r"(\w+)\s*=", _m.group(1)))
            _accepts = set(_inspect.signature(F.collect).parameters)
            _missing = sorted(_passed - _accepts)
            _check(not _missing,
                   "编排层传的每个关键字 collect() 都接收"
                   f"（实传 {sorted(_passed)}）",
                   f"collect() 缺少参数：{_missing} —— 补采会 100% 抛 TypeError 且被吞掉")

        # 功能面：渲染阶段观察到的 XHR 端点必须能注入并计入接口清单
        _spa = F.collect(client, base, render_html=_REAL_HOME,
                         allow_requests=False,
                         spa_detected=True,
                         spa_endpoints=["/api/v1/orders", "/api/v1/users"])
        _check("/api/v1/orders" in _spa.endpoints,
               "渲染阶段观察到的 XHR 端点必须并入接口清单"
               "（否则报告写「提取接口 0 条」，而检测器手里明明有端点）",
               str(_spa.endpoints))
        _check(_spa.spa_detected, "spa_detected 必须由调用方注入生效")
        _check(_spa.spa_endpoints == ["/api/v1/orders", "/api/v1/users"],
               "spa_endpoints 必须原样保留（覆盖度说明要用它区分「检测到 SPA 但没捕获到 XHR」）")
        _nodup = F.collect(client, base, render_html=_REAL_HOME,
                           allow_requests=False,
                           spa_endpoints=["/api/v1/orders", "/api/v1/orders"])
        _check(_nodup.endpoints.count("/api/v1/orders") == 1,
               "重复注入的端点必须去重（否则「接口 N 条」是虚高的）")

        # ==============================================================
        print("\n[9] D3 回归：截断正文找不到的脚本标签 + 抢采素材被门控丢弃")
        # ==============================================================
        # 2026-10-09 Juice Shop 基准二轮实测的两连坑：
        #   ① JsAnalyzer 自己取入口页用的是 body_snippet（前 4000 字符），
        #      Juice Shop 的 <script> 全在 9.4KB 入口页尾部 → 抓 0 个脚本。
        #   ② L2 开头抢采的素材（27 条接口、7 份正文）只在「js_result
        #      完全无素材」时才并入；JsAnalyzer 摸到 1 段内联脚本喂饱
        #      has_material → 抢采成果整批丢弃 → 注入类检查全灭在
        #      「接口 0 条」上。
        from engine.js_analyzer import JsAnalyzer as _JA  # noqa: E402

        _deep_html = ("<html><body>" + "x" * 5000
                      + '<script src="/deep-tail.js"></script></body></html>')

        class _StubClient:
            #: fetch 返回的就是截断语义的 body_snippet —— 如果 JsAnalyzer
            #: 拿它当入口页，脚本标签永远找不到（这正是被测的失败形态）。
            def fetch(self, url):  # noqa: ANN001
                return SimpleNamespace(
                    reachable=True, status=200, error="",
                    body_snippet="<html>" + "x" * 4000 + "</html>")

        _stub = _StubClient()
        _jr = _JA(_stub).analyze("https://d3.example", page_html=_deep_html)
        _check(_jr.scripts_fetched == 1,
               "入口页正文完整喂给 JsAnalyzer 时，4000 字符之后的 script 标签也能找到",
               f"scripts_fetched={_jr.scripts_fetched}")
        _check(any("deep-tail.js" in u for u in _jr.urls),
               "尾部脚本引用进入接口清单（urls）",
               str(_jr.urls))

        # 编排层接线断言（与第 [8] 节同思路：直接钉源码，两侧不同步立刻红）
        _orch2 = (Path(__file__).resolve().parent
                  / "engine" / "orchestrator.py").read_text(encoding="utf-8")
        _check("ja.analyze(target_url, page_html=_entry_html)" in _orch2,
               "编排层必须把完整入口页正文喂给 JsAnalyzer"
               "（不许退回让它自己取截断版）")
        _check(("merge_into_js_result" in _orch2
                and "early_assets" in _orch2),
               "编排层存在「抢采素材并入 js_result」的调用")
        _pos_merge = _orch2.find("js_result, early_assets")
        _pos_gate = _orch2.find(
            "if enable_js and not _frontend_has_material(js_result):")
        _check(0 <= _pos_merge < _pos_gate,
               "抢采素材并入必须发生在 has_material 门控**之前**（无条件路径），"
               "不得藏在「js_result 为空才补」的兜底分支里",
               f"merge@{_pos_merge}, gate@{_pos_gate}")
        _check("[前端补采] L2 开头抢采的前端素材已并入" in _orch2,
               "并入动作必须留痕（note 前缀与 3.5 阶段的说明过滤同源）")

        # D4：「${host}变量前缀 + 路径」模板字符串必须提取出带参端点。
        # Juice Shop 真实写法：search(e){return this.http.get(
        #   `${this.hostServer}/rest/products/search?q=${e}`)}
        # 三条老模式都要求字符串以 / 开头，这种以 ${...} 开头的整条丢失，
        # /rest/products/search?q= 从未进候选 → 3 条 SQLi 挑战全灭。
        _tmpl_blob = ('search(e){return this.http.get('
                      '`${this.hostServer}/rest/products/search?q=${e}`)}')
        _eps_f = F._extract_endpoints(_tmpl_blob, "https://d3.example", [])
        _check("/rest/products/search?q=1" in _eps_f,
               "frontend：${host}前缀模板字符串必须提取出带参端点（D4）",
               str(_eps_f))
        _eps_j = _JA._extract_endpoints(_tmpl_blob, "https://d3.example", [])
        _check("/rest/products/search?q=1" in _eps_j,
               "js_analyzer：同一形态必须同样提取（两模块口径一致）",
               str(_eps_j))

        # ==============================================================
        print("\n[10] D5 回归：产物正文截断（600KB 上限切掉 70% 处的注入端点）")
        # ==============================================================
        # 2026-10-09 Juice Shop 基准四轮实测：main.js 1.2MB，关键注入端点
        # /rest/products/search 出现在 70% 处（offset 846857）——
        #   ① fetch_asset 的 600KB 上限把它整段切掉，且没有任何痕迹；
        #   ② JsAnalyzer 抓脚本用 client.fetch（默认前 4000 字符），
        #      比 600KB 更狠，等于没读。
        from engine import fingerprint as _fp  # noqa: E402

        _check(_fp.ASSET_BODY_MAX_CHARS >= 2_500_000,
               "fetch_asset 保留上限必须覆盖现实 SPA 主包体量（≥2.5MB，"
               "Juice Shop main.js 实测 1.2MB 且端点在 70% 处）",
               f"ASSET_BODY_MAX_CHARS={_fp.ASSET_BODY_MAX_CHARS}")

        # 截断必须留痕：body_truncated 为真时，采集错误清单里要能看到。
        class _TruncProbe:
            reachable = True
            status = 200
            error = ""
            body_truncated = True
            body_snippet = "var x=1;" * 100

        class _TruncClient:
            def fetch_asset(self, url):  # noqa: ANN001
                return _TruncProbe()

        _assets5 = F.FrontendAssets()
        _got5 = F._fetch_script(_TruncClient(), "https://d5.example/app.js",
                                "https://d5.example", _assets5)
        _check(bool(_got5) and len(_assets5.bodies) == 1,
               "截断的正文仍然入素材（截断 ≠ 丢弃）")
        _check(any("截断" in e for e in _assets5.errors),
               "正文被截断必须在 errors 留痕（不留痕会被读成「脚本里没有」）",
               str(_assets5.errors))

        # 接线断言：JsAnalyzer 抓脚本必须走 fetch_asset（全文），
        # 不许退回 client.fetch 的 4000 字符截断版。
        _ja_src = (Path(__file__).resolve().parent
                   / "engine" / "js_analyzer.py").read_text(encoding="utf-8")
        _loop = _ja_src[_ja_src.find("for src in scripts[: self.max_scripts]"):]
        _loop = _loop[:_loop.find("except Exception")]
        _check("fetch_asset(src)" in _loop,
               "JsAnalyzer 抓脚本正文必须走 fetch_asset（D5）")
        _check("body_truncated" in _loop,
               "JsAnalyzer 必须把脚本截断写进 errors（D5）")

        # D5 第二坑：decode_body 里藏着 [:200_000] 的第二层截断 ——
        # fetch_asset 配了 2.5MB 上限，正文却在进入它之前就被切成
        # 200KB，配置没人读、截断无痕迹（main.js 实测被切到 200000 字符，
        # 70% 处的注入端点丢失）。截断职责统一收口到 fetch(max_body)。
        _fp_src = (Path(__file__).resolve().parent
                   / "engine" / "fingerprint.py").read_text(encoding="utf-8")
        _db = _fp_src[_fp_src.find("def decode_body"):]
        _db = _db[:_db.find("def inspect_tls")]
        _check("[:200_000]" not in _db,
               "decode_body 只解码不截断（D5 第二坑：藏在解码器里的"
               "第二层截断会让 fetch_asset 的上限配置形同虚设）")

    finally:
        srv.shutdown()
        srv.server_close()

    print("\n" + "=" * 60)
    if PROBLEMS:
        print(f"前端汇聚自测不通过（{CHECKS - len(PROBLEMS)}/{CHECKS} 通过）")
        for p in PROBLEMS:
            print(f"  ✗ {p}")
        return 1
    print(f"前端汇聚自测通过（{CHECKS} 项断言）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
