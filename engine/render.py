# -*- coding: utf-8 -*-
"""SPA 渲染（P3：把「没看到」和「不存在」分开）
================================================================================

要解决的问题
--------------------------------------------------------------------------------
现代前端应用（Vue / React / Angular 打包产物）首屏返回的 HTML 是一具**骨架**：
`<div id="app"></div>` 加几个 `<script src="...">`，正文里没有菜单、没有表单、
没有「管理后台」四个字。于是所有基于关键词与结构的判断全部落空 ——

  · 拿不到链接 → URL 枚举退化成「只有字典」，真实路由一条没进池子
  · 拿不到表单 → `has_input` 判「无」→ 上传 / CSRF / 注入类检查项集体判 N/A
  · 拿不到文案 → 管理入口、敏感信息、内部地址一概不可见

**关键危害不是「漏」，而是「说错」。** N/A 与「通过」在报告里读起来像
「这个功能不存在，所以不用测」，而事实是「我们没看到页面」。这两件事
被混为一谈的时候，一份格式规范、逐项有结论的报告会给出虚假的安全感。

================================================================================
设计要点（四条，都有对应的自测不变量）
================================================================================

1. **零新依赖。** 本机自带的 Edge / Chrome 就有 `--headless --dump-dom`，
   它会把**执行完 JS 之后的 DOM** 打到标准输出。用系统浏览器即可，
   不必引入 playwright —— 「检测器一律用正则、禁止引入新依赖」这条红线不用破。

2. **渲染是有副作用的动作，必须挂档位门控。**
   渲染会**在真实浏览器里执行目标页面的 JavaScript**：会触发前端埋点、
   会发起额外的接口调用、极端情况下会触发页面上被自动执行的动作。
   因此安全档不渲染（与 sqlmap 同理），并且这个理由要写在结论里，不能静默跳过。

3. **渲染结果必须带来源标记，不能悄悄替换掉直连正文。**
   报告里「直连 HTML 里看到的」和「浏览器渲染后看到的」是两种证据：
   前者任何人 curl 一下就能复现；后者需要打开浏览器。混在一起会让
   「按复现方式复测」这个交付标准失效。所以渲染正文单独存放、单独标注。

4. **渲染失败绝不能等于「这些功能不存在」。**
   浏览器没装 / 启动超时 / 目标把无头 UA 拦了 —— 这些情况下必须记
   「未渲染 + 后果」，并让适用性判定退回「未知」。把「没渲染成功」当成
   「页面上没有表单」，是本项目红线（孤立信号不得当正面证据）的直接违反，
   因为它把一次工具失效当成了关于目标的结论。

================================================================================
为什么没有用 playwright
--------------------------------------------------------------------------------
playwright 需要额外安装浏览器内核（数百 MB），而项目运行环境是隔离 venv、
规则是「禁止引入新依赖」。系统浏览器方案在能力上覆盖了本项目实际需要的
全部场景（首屏渲染 + 链接 + 表单 + 文案），代价只是没有精细的等待控制 ——
用 `--virtual-time-budget` 已经够用。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable

# ==============================================================================
# 状态与常量
# ==============================================================================
STATE_RENDERED = "已渲染"
STATE_SKIPPED = "未渲染"
STATE_FAILED = "渲染失败"

# 浏览器候选位置：Windows 优先（本项目实际运行环境），其余平台一并列出，
# 换到 Linux / macOS 跑时不必改代码。
_BROWSER_CANDIDATES: tuple[str, ...] = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/microsoft-edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)

_TAG_RE = re.compile(r"(?is)<(script|style|noscript)\b.*?</\1>")
_TAG_ANY_RE = re.compile(r"(?s)<[^>]+>")

# 骨架页特征：空挂载点 / 框架专有挂载点
_SKELETON_ROOT_RE = re.compile(
    r"""(?is)<(?:div|main)\b[^>]*\bid\s*=\s*["']?(?:app|root|__next|mount|main)["']?[^>]*>\s*</""")
_EMPTY_TAG_RE = re.compile(r"(?is)<(app-root|app-vue|div\s+id=[\"']app[\"'])\s*>\s*</")

# 交互性特征（用于判断「渲染后是否多出了真东西」）
_INTERACTIVE_RE = re.compile(
    r"(?is)<(form|input|button|select|textarea)\b")


def strip_tags(html: str) -> str:
    """去掉 script / style 与标签，只留可见文本，用于比较渲染前后的正文量。"""
    if not html:
        return ""
    txt = _TAG_RE.sub(" ", html)
    txt = _TAG_ANY_RE.sub(" ", txt)
    return re.sub(r"\s+", " ", txt).strip()


# ==============================================================================
# 计划（档位门控）
# ==============================================================================
@dataclass
class RenderPlan:
    enabled: bool
    reason: str = ""
    browser: str = ""
    timeout: int = 60
    budget_ms: int = 5000
    max_pages: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "reason": self.reason,
                "browser": os.path.basename(self.browser) if self.browser else "",
                "budget_ms": self.budget_ms, "max_pages": self.max_pages}


def find_browsers() -> list[str]:
    """返回全部可用浏览器的绝对路径（按候选顺序）；找不到返回空列表。

    与 find_browser() 的区别：那只拿「第一个存在的」，但「存在」不等于
    「能用」——本机 Edge 曾出现进程正常退出（rc=0）却不输出任何 DOM 的
    故障形态（2026-10-09 Juice Shop 基准实测），若只认第一个候选，
    渲染会整体失明。渲染侧据此做逐浏览器回退。
    """
    env = os.environ.get("AISCAN_BROWSER", "").strip()
    if env:
        return [env] if os.path.exists(env) else []
    out = [cand for cand in _BROWSER_CANDIDATES if os.path.exists(cand)]
    for name in ("msedge", "google-chrome", "chromium", "chrome"):
        p = shutil.which(name)
        if p and p not in out:
            out.append(p)
    return out


def find_browser() -> str:
    """返回首选浏览器的绝对路径；找不到返回空串。"""
    browsers = find_browsers()
    return browsers[0] if browsers else ""


# 本进程内已确认「起不来 / 起得来但不输出 DOM」的浏览器。
#
# 为什么必须记住：一次扫描里会发起十几次渲染（多路由渲染 + hash 路由
# 验证 + 各检测器的渲染补采）。已知坏掉的那一个每次都还要**完整启动一遍**
# 才失败（本机 Edge 是 rc=0 却不输出 DOM，启动就要十几秒），这些纯浪费的
# 进程不仅拖长扫描，还会把内存压高 —— 高负载下**好用的那个**浏览器
# 也开始超时，于是「越扫到后面渲染成功率越低」，最后整片渲染失败。
# 2026-10-10 第 14 轮实测就是这条链：Edge 空转 → Chrome 60s 超时 →
# INPV-01 的 hash 路由验证全部报「渲染失败」，而单独复现同一 URL 秒回。
_BROKEN_BROWSERS: set[str] = set()


def forget_broken_browsers() -> None:
    """清空坏浏览器记忆（自测与换新环境时用）。"""
    _BROKEN_BROWSERS.clear()


def plan_for(profile_key: str) -> RenderPlan:
    """按档位与环境变量决定是否渲染。

    开关：AISCAN_RENDER = auto（默认）/ on / off
      · off           → 一律不渲染
      · on            → 一律渲染（安全档也渲染，由使用者显式承担副作用）
      · auto（默认）  → 安全档不渲染，其余档渲染
    无论走哪条分支都要给理由 —— 静默跳过会让「为什么首页没渲染」无从解释。
    """
    mode = (os.environ.get("AISCAN_RENDER") or "auto").strip().lower()
    browser = find_browser()

    if mode == "off":
        return RenderPlan(False, "已通过 AISCAN_RENDER=off 显式关闭渲染", "", 0, 0)
    if not browser:
        return RenderPlan(
            False,
            "本机未找到 Edge / Chrome —— 未执行渲染。受影响的是 SPA 类目标的"
            "链接 / 表单 / 文案判定：这些项的「不适用」未必是真不适用，"
            "而是「没看到」，需要人工用浏览器确认",
            "", 0, 0)
    if mode == "auto" and (profile_key or "").lower() == "safe":
        return RenderPlan(
            False,
            "安全档不执行渲染：渲染会在浏览器里执行目标页面的 JavaScript，"
            "会触发前端埋点与额外接口调用，属于对目标产生状态变化的动作",
            browser)
    if mode == "auto" and (profile_key or "").lower() == "standard":
        # 标准档也渲染：SPA 在现代业务系统里已是主流形态，
        # 不渲染等于对这类目标整体失明。代价是每个入口页一次浏览器启动。
        pass
    return RenderPlan(True, f"AISCAN_RENDER={mode}，档位 "
                            f"{(profile_key or 'standard')}", browser)


# ==============================================================================
# 执行
# ==============================================================================
@dataclass
class RenderOutcome:
    ok: bool
    html: str = ""
    url: str = ""
    state: str = STATE_SKIPPED
    reason: str = ""
    elapsed_ms: int = 0
    browser: str = ""
    skeleton_before: bool = False
    text_before: int = 0
    text_after: int = 0
    #: 每一次尝试的**具名**结果（浏览器 / 超时 / 无 DOM / 不存在）。
    #: 为什么要单独存一个字段而不是只拼进 reason：渲染的失败是**连锁**的
    #: （首选挂 → 回退也挂），只留一句「渲染失败」的话，读者（和自测）
    #: 分不清是哪一环空的，也就无从判断要不要重试、换浏览器还是换机器。
    attempts: list[str] = field(default_factory=list)

    @property
    def refilled(self) -> bool:
        """渲染后是否真的多出了内容。这是「渲染有没有用」的客观判据。

        判据要同时容纳两种形态：
          · 骨架页（可见文本 ≈ 0）：只要多出实质内容（≥10 字）就算增补。
            用「增长 1.5 倍」这种相对阈值在这里会失效 —— 0 的 1.5 倍还是 0，
            加一个绝对下限（120 字）又会把「整页就十来字」的小应用判成没增补，
            于是渲染成功却被记成「没用」，下次就没人信这个结论了。
          · 内容页：要求增长达到 1.5 倍，避免把正常波动当增补。
        """
        if not self.ok:
            return False
        gain = self.text_after - self.text_before
        if gain < 10:
            return False
        if self.text_before == 0:
            return True
        return self.text_after >= self.text_before * 1.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state, "url": self.url, "reason": self.reason,
            "ok": self.ok, "elapsed_ms": self.elapsed_ms,
            "browser": os.path.basename(self.browser) if self.browser else "",
            "skeleton_before": self.skeleton_before,
            "text_before": self.text_before, "text_after": self.text_after,
            "refilled": self.refilled,
        }

    def summary_line(self) -> str:
        if self.state == STATE_RENDERED:
            return (f"入口页已由浏览器渲染（{self.text_before} → "
                    f"{self.text_after} 字可见文本"
                    + ("，渲染前确认是骨架页" if self.skeleton_before else "")
                    + f"，耗时 {self.elapsed_ms}ms）")
        return f"入口页未渲染：{self.reason}"


def _default_runner(browser: str, argv: list[str],
                    timeout: int) -> tuple[int, bytes, bytes]:
    """真实执行：调本机浏览器 --dump-dom。"""
    kw: dict[str, Any] = {}
    if sys.platform.startswith("win"):
        # 不弹控制台窗口。渲染过程对使用者应当是静默的。
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # 低影响运行：浏览器**单独**降优先级（父进程的优先级不会被继承），
    # 并注入 OMP 等线程池上限。渲染是整条链路里最重的一枪，这一处不降
    # 就等于前面所有降级都白做。
    try:
        from engine import resources as _res  # noqa: PLC0415
        _kw = _res.child_kwargs()
        kw["env"] = _kw["env"]
        if "creationflags" in _kw:
            kw["creationflags"] = kw.get("creationflags", 0) | _kw["creationflags"]
    except Exception:  # noqa: BLE001
        pass
    proc = subprocess.Popen(  # noqa: S603
        [browser] + argv,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out or b"", (err or b"") + b"\n[timeout]"
    return proc.returncode or 0, out or b"", err or b""


def _decode(data: bytes) -> str:
    """浏览器把 DOM 以 UTF-8 写到标准输出。

    这里也必须做多编码尝试：与 HTTP 正文的 charset 坑同源 ——
    若按系统默认编码（Windows 上是 GBK）解，中文标题会变成乱码，
    之后所有中文关键词判定会静默失效。
    """
    if not data:
        return ""
    for enc in ("utf-8", "gb18030"):
        try:
            txt = data.decode(enc)
        except UnicodeDecodeError:
            continue
        if "\ufffd" not in txt:
            return txt
    return data.decode("utf-8", "replace")


def _build_argv(url: str, plan: RenderPlan, profile_dir: str) -> list[str]:
    """构造浏览器命令行。

    安全相关项说明（这些不是可有可无的净化，而是「把浏览器当不可信页面的
    隔离容器」这个前提的落地）：
      · --user-data-dir 指向一次性临时目录：绝不复用使用者的浏览器配置，
        避免读到已登录 Cookie（那是拿使用者的身份去访问目标），
        也避免污染使用者自己的配置。
      · --no-first-run / --no-default-browser-check / --disable-sync：
        阻止浏览器在启动时联网做与我们无关的事。
      · --no-proxy-server：与 HTTP 探测一致，不吃系统代理。
        本机代理会让所有请求落到代理上（不变量 ⑬ 记过这个坑），
        渲染若走代理，拿到的会是代理的页面而不是目标的页面。
      · 不加 --no-sandbox：Windows 上沙箱是可用的，关掉它等于降低
        执行不可信 JS 时的隔离度。只有在容器里跑时才需要，交由使用者
        用 AISCAN_BROWSER_EXTRA_ARGS 显式追加。
      · 资源收口（--renderer-process-limit / --js-flags / --disable-features）：
        浏览器是整条链路里**单进程内存最大**的一环，而它只在渲染一瞬间用得上。
        收口的收益是「渲染时电脑不卡」；代价是极端复杂的前端页面可能渲染不全。
        所以只在低影响模式下收口，全速模式保持浏览器默认（要最大渲染保真度）。
    """
    try:
        from engine import resources as _res  # noqa: PLC0415
        _low = _res.budget().low_impact
    except Exception:  # noqa: BLE001
        _low = True     # 资源模块不可用时按保守（低影响）处理

    argv = [
        "--headless=new",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-plugins",
        "--disable-sync",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-proxy-server",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--hide-scrollbars",
        "--mute-audio",
        f"--user-data-dir={profile_dir}",
        f"--virtual-time-budget={plan.budget_ms}",
        "--dump-dom",
    ]
    if _low:
        argv[1:1] = [
            # 单渲染进程：默认会按页面里的 iframe / 站点隔离再起几个进程，
            # 每个都是几十到上百 MB。扫描只需要一个页面渲染完的 DOM。
            "--renderer-process-limit=1",
            # V8 堆上限。这是浏览器侧最有效的一条内存约束：脚本跑飞 / 站点
            # 内存泄漏时，浏览器会按自己的默认值一路吃到几百 MB 甚至 GB。
            "--js-flags=--max-old-space-size=256",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-breakpad",
            "--disable-crash-reporter",
            "--metrics-recording-only",
            # 关掉一批与「取回渲染后 DOM」无关的后台子系统（翻译、媒体路由、
            # 原生窗口遮挡计算等）。它们各自不重，叠起来占的常驻内存不小。
            "--disable-features=Translate,MediaRouter,OptimizationHints,"
            "CalculateNativeWinOcclusion,AcceptCHFrame,BackForwardCache",
        ]
    extra = os.environ.get("AISCAN_BROWSER_EXTRA_ARGS", "").strip()
    if extra:
        argv.extend(extra.split())
    argv.append(url)
    return argv


def render(url: str, plan: RenderPlan, *, before_html: str = "",
           runner: Callable[[str, list[str], int], tuple[int, bytes, bytes]] | None = None,
           ) -> RenderOutcome:
    """渲染单个地址。

    runner 是注入点（自测用）：签名与 _default_runner 一致。
    自测必须能在**任何环境**跑出同一结果，所以真启动浏览器的那条路径
    在自测里被替换掉，而「启动失败 / 超时 / 空输出」等分支照样被覆盖。
    """
    out = RenderOutcome(False, url=url, browser=plan.browser)
    if not plan.enabled:
        out.state = STATE_SKIPPED
        out.reason = plan.reason
        out.text_before = len(strip_tags(before_html))
        return out
    if not (url or "").strip():
        out.state = STATE_SKIPPED
        out.reason = "无有效地址，未执行渲染"
        return out

    out.text_before = len(strip_tags(before_html))
    out.skeleton_before = looks_like_skeleton(before_html)
    run = runner or _default_runner

    # 逐浏览器回退：首选（plan.browser）失败后按候选表继续试。
    # 「存在」不等于「能用」——本机 Edge 曾 rc=0 却不输出任何 DOM
    # （2026-10-09 Juice Shop 基准实测），不回退就是渲染整体失明。
    # 超时（124）同样回退：最初假设「超时是目标侧慢，换浏览器大概率一样」，
    # 但基准五轮实测推翻了它 —— 同一目标、同一代码，第四轮 Chrome 数秒
    # 渲染成功，第五轮首选浏览器挂死 60s 被判整页渲染失败（内存高负载下
    # 首选浏览器启动僵死是浏览器侧故障，不是目标侧慢）。回退成本有界
    # （候选浏览器就 2~3 个），且每次超时都必须具名进 reason。
    browsers: list[str] = []
    if plan.browser:
        browsers.append(plan.browser)
    for b in find_browsers():
        if b not in browsers:
            browsers.append(b)

    attempts: list[str] = []
    # 整段渲染的墙钟预算：单次超时**必须允许再试一次**。
    #
    # 第 22 轮实测的连锁故障：首选浏览器（Edge）正常退出但无 DOM → 记入
    # 坏浏览器名单；回退 Chrome 首次冷启动撞上 60s 超时 → 直接放弃。
    # 结果整轮**一次都没渲染成功**，17 个依赖渲染 DOM 的检查项集体 N/A，
    # 基准分数从 57.5% 掉到 41.2% —— 而同样的 Chrome 上一轮 2.6s 就成功了。
    #
    # 浏览器冷启动在高负载 / 首次运行时慢是**浏览器侧**的偶发，不是目标侧慢，
    # 重试一次通常就好。代价用墙钟预算封顶，不会把扫描拖长。
    # 整段渲染的墙钟预算：单次超时**必须允许再试一次**，且回退浏览器
    # （最后一个候选）要有足够余量跑完它的第二次尝试。
    #
    # 旧公式 max(timeout*2, 90) 在「首选浏览器确定性无 DOM + 回退浏览器首冷
    # 启动超时」时预算被吃光，回退浏览器的第二次重试（往往就成功）被吞，
    # 导致整轮渲染失明 —— 第 14 / 22 轮与 2026-10-15 基准均踩过。
    # 放宽到 max(timeout*3, 180) 给回退浏览器留出完整的两次尝试窗口。
    deadline = time.time() + max(plan.timeout * 3, 180)

    for browser in browsers:
        if browser in _BROKEN_BROWSERS:
            attempts.append(f"{os.path.basename(browser)}：本轮此前已确认不可用，跳过")
            continue
        for attempt_no in (1, 2):
            if attempt_no == 2:
                remain = deadline - time.time()
                if remain < 20 and browser != browsers[-1]:
                    # 非回退浏览器：预算将尽即放弃，把时间留给后续候选。
                    # 回退浏览器（最后一个候选）是最后机会，预算再紧也要给
                    # 它一次重试 —— 否则首选耗尽预算会连环吞掉整轮渲染。
                    attempts.append(
                        f"{os.path.basename(browser)}：超时后不再重试"
                        "（整段渲染的墙钟预算已用尽）")
                    break
            used = _render_once(browser, url, plan, attempt_no, deadline,
                                attempts, out, run)
            if used is None:
                # 「退出但无 DOM」这类是**确定性**故障（已被记入坏浏览器名单），
                # 再试一次只是白白再花一个超时周期；超时类故障才值得重试。
                if browser in _BROKEN_BROWSERS:
                    break
                continue        # 本次失败，交给同浏览器的第二次尝试或下一个浏览器
            return used
        continue
    out.attempts = list(attempts)
    out.state = STATE_FAILED
    out.reason = ("；".join(attempts) if attempts else "无可用浏览器") \
        + "。注意：这是渲染失败，不是「页面上没有内容」"
    return out


def _render_once(browser: str, url: str, plan: RenderPlan, attempt_no: int,
                 deadline: float, attempts: list[str], out: "RenderOutcome",
                 run: "Callable[[str, list[str], int], tuple[int, bytes, bytes]]",
                 ) -> "RenderOutcome | None":
    """单个浏览器的一次渲染尝试。

    成功返回 `out`；失败返回 None（失败原因已**具名**追加进 attempts ——
    只把失败静默吞掉的话，报告上只会剩一句「渲染失败」，
    读者分不清是「没装浏览器」还是「浏览器僵死」）。
    """
    tag = os.path.basename(browser)
    if attempt_no > 1:
        tag += f"（第 {attempt_no} 次尝试）"
    timeout = int(max(10, min(plan.timeout, deadline - time.time())))
    profile_dir = tempfile.mkdtemp(prefix="aiscan-render-")
    argv = _build_argv(url, plan, profile_dir)
    t0 = time.time()
    try:
        rc, stdout, stderr = run(browser, argv, timeout)
    except FileNotFoundError:
        _BROKEN_BROWSERS.add(browser)
        attempts.append(f"{tag}：浏览器可执行文件不存在"
                        "（可能被安全策略移除或路径变更）；本轮后续渲染不再尝试该浏览器")
        return None
    except Exception as e:  # noqa: BLE001
        out.elapsed_ms += int((time.time() - t0) * 1000)
        attempts.append(f"{tag}：渲染执行异常：{type(e).__name__}: {str(e)[:120]}")
        return None
    finally:
        # 一次性配置目录必须清掉：里面可能有目标站点种下的 Cookie / 存储。
        shutil.rmtree(profile_dir, ignore_errors=True)

    out.elapsed_ms += int((time.time() - t0) * 1000)
    html = _decode(stdout)
    err_txt = _decode(stderr)[-400:]
    if rc == 124:
        attempts.append(f"{tag} 渲染超过 {timeout}s 未结束，已终止")
        return None
    if not html.strip():
        # 进程正常退出却不产出 DOM —— 这是浏览器侧的**确定性**故障
        # （本机 Edge 就是这种形态），重试多少次都一样，记住它。
        _BROKEN_BROWSERS.add(browser)
        attempts.append(f"{tag} 未输出 DOM（退出码 {rc}）"
                        + (f"：{err_txt}" if err_txt else "")
                        + "；本轮后续渲染不再尝试该浏览器")
        return None
    # 成功这一次也必须进 attempts：留痕里只有失败记录的话，
    # 读者（和自测）看到的永远是「试过几个都挂了」，看不出最后是怎么成的。
    attempts.append(f"{tag}：渲染成功（{len(html)} 字符 DOM）")
    out.attempts = list(attempts)
    out.ok = True
    out.browser = browser
    out.html = html
    out.state = STATE_RENDERED
    out.text_after = len(strip_tags(html))
    fallback_note = ("；".join(attempts) + "；已回退 "
                     + os.path.basename(browser) + " 成功。") if attempts else ""
    out.reason = fallback_note + ("" if out.refilled else (
        f"渲染成功但可见文本从 {out.text_before} 字变为 {out.text_after} 字，"
        "未见明显增补 —— 该页面可能本就是服务端渲染"))
    return out


def looks_like_skeleton(html: str) -> bool:
    """判断给定 HTML 是否像「JS 渲染前」的骨架页。

    判据（任一成立即认为像骨架）：
      · 命中空挂载点（`<div id="app"></div>` 这类）
      · 可见文本极短（< 200 字）但含脚本引用

    这个函数只用于**决定要不要渲染下一批页面**与**描述现象**，
    不用于下任何关于「功能存在与否」的结论。
    """
    if not html:
        return False
    if _SKELETON_ROOT_RE.search(html) or _EMPTY_TAG_RE.search(html):
        return True
    has_script = bool(re.search(r"(?is)<script\b", html))
    return has_script and len(strip_tags(html)) < 200


# ==============================================================================
# 与编排的接口
# ==============================================================================
@dataclass
class RenderReport:
    """一轮扫描的渲染汇总，供报告与适用性判定使用。"""

    plan: RenderPlan
    entry: RenderOutcome | None = None
    extra: list[RenderOutcome] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def rendered_html(self) -> str:
        return (self.entry.html if self.entry and self.entry.ok else "") or ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "entry": self.entry.to_dict() if self.entry else None,
            "extra": [o.to_dict() for o in self.extra],
            "notes": list(self.notes),
        }


def render_entry(url: str, *, profile_key: str, status: int = 0,
                 content_type: str = "", before_html: str = "",
                 runner: Callable[..., tuple[int, bytes, bytes]] | None = None,
                 plan: RenderPlan | None = None) -> RenderOutcome:
    """入口页渲染。带「值不值得渲染」的前置判断。

    只在「服务端返回了 HTML 且状态正常」时才有渲染的意义：
    405 / 403 这类边缘拦截页渲染出来仍是拦截页，浪费时间还会误导。
    """
    plan = plan or plan_for(profile_key)
    if not plan.enabled:
        o = RenderOutcome(False, url=url, state=STATE_SKIPPED, reason=plan.reason,
                          browser=plan.browser)
        o.text_before = len(strip_tags(before_html))
        return o
    if status and status not in (200, 301, 302):
        o = RenderOutcome(False, url=url, state=STATE_SKIPPED,
                          reason=f"入口页返回 HTTP {status}，非应用页面，跳过渲染",
                          browser=plan.browser)
        return o
    ctl = (content_type or "").lower()
    if ctl and not any(t in ctl for t in ("html", "xml", "text/plain")):
        o = RenderOutcome(False, url=url, state=STATE_SKIPPED,
                          reason=f"入口页内容类型为 {content_type}，非页面，跳过渲染",
                          browser=plan.browser)
        return o
    return render(url, plan, before_html=before_html, runner=runner)


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> int:
    """`python engine/render.py` 直接跑（不启动真实浏览器，runner 走注入）。

    盯的是**渲染整段失明**这条连锁故障（第 22 轮实测）：
    首选浏览器正常退出但无 DOM → 记入坏名单；回退浏览器首次冷启动超时 → 放弃。
    结果 17 个依赖渲染 DOM 的检查项集体 N/A，基准分数 57.5% → 41.2%。
    这一整条链上任何一环退化都不会报错，只会表现为「覆盖率少了一截」。
    """
    ok = True

    def _check(cond: bool, label: str) -> None:
        nonlocal ok
        print(("  ✓ " if cond else "  ✗ ") + label)
        if not cond:
            ok = False

    real_find = find_browsers
    fake_a = "C:/fake/msedge.exe"
    fake_b = "C:/fake/chrome.exe"
    try:
        _real = globals()["find_browsers"]
        globals()["find_browsers"] = lambda: [fake_a, fake_b]
        plan = RenderPlan(enabled=True, browser="", timeout=30)

        # ① 首次超时、第二次成功 —— 必须真的再试一次，而不是整段放弃
        calls: list[str] = []

        def _runner_timeout_then_ok(browser: str, argv: list[str],
                                    timeout: int) -> tuple[int, bytes, bytes]:
            calls.append(browser)
            if len([c for c in calls if c == fake_a]) == 1:
                return 124, b"", b""
            return 0, b"<html><body>ok</body></html>", b""

        forget_broken_browsers()
        out = render("http://t/", plan, runner=_runner_timeout_then_ok)
        _check(out.ok, "首次超时后**再试一次**即可成功（不再整段失明）")
        _check(any("第 2 次尝试" in a for a in out.attempts),
               "重试在留痕里**具名**（否则读者只看到一句「渲染失败」）")
        _check(any("未结束" in a for a in out.attempts), "首次超时的原因也被记下")

        # ② 退出但无 DOM 是确定性故障 —— 记坏名单且**不再重试**
        n_calls = {"n": 0}

        def _runner_no_dom(browser: str, argv: list[str],
                           timeout: int) -> tuple[int, bytes, bytes]:
            n_calls["n"] += 1
            return 0, b"", b""

        forget_broken_browsers()
        out = render("http://t/", plan, runner=_runner_no_dom)
        _check(not out.ok, "所有浏览器都不产出 DOM → 渲染失败")
        _check(n_calls["n"] == 2, "确定性故障只试 2 个浏览器各一次，不做无谓重试")
        _check(any("未输出 DOM" in a for a in out.attempts), "「无 DOM」原因具名")
        _check("不是「页面上没有内容」" in out.reason,
               "失败结论里必须写明「渲染失败 ≠ 页面上没有」")

        # ③ 全部超时 → 失败，且每条尝试都具名、不伪造成功
        def _runner_always_timeout(browser: str, argv: list[str],
                                   timeout: int) -> tuple[int, bytes, bytes]:
            return 124, b"", b""

        forget_broken_browsers()
        out = render("http://t/", plan, runner=_runner_always_timeout)
        _check(not out.ok and not out.html, "全部超时 → 失败且不产出 HTML")
        _check(sum(1 for a in out.attempts if "未结束" in a) >= 2,
               "每次超时都具名进 attempts（不能合并成一句）")

        # ④ 浏览器文件不存在 → 具名，不许当成「目标没内容」
        def _runner_missing(browser: str, argv: list[str],
                            timeout: int) -> tuple[int, bytes, bytes]:
            raise FileNotFoundError(browser)

        forget_broken_browsers()
        out = render("http://t/", plan, runner=_runner_missing)
        _check(not out.ok and any("可执行文件不存在" in a for a in out.attempts),
               "浏览器不存在 → 具名，不静默")
    finally:
        globals()["find_browsers"] = real_find
        forget_broken_browsers()

    print("\n结论：" + ("渲染模块自测：通过" if ok else "渲染模块自测存在问题，需修"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
