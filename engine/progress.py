"""扫描进度显示 —— 让长扫描「看得见在干什么」，并且**死了看得出来**。

问题
----------------------------------------------------------------------------
一次标准档全量扫描要跑十几分钟，其中 L1 指纹、nuclei（实测 5094 份模板 /
跑满 420s）、逐项检测（全量检查项）都是分钟级阻塞。原先前台只有一段 ASCII banner
顶在那里，操作者无法判断「是在跑、还是卡死了、还是等凭据睡着了」——
实测中安全负责人就是在等待阶段误以为扫描已结束（那条等待信息在 40 行横线之后，
前面几分钟没有任何输出）。

设计约束
----------------------------------------------------------------------------
① **只写 stderr**。stdout 是机器可读通道（扫描结果、凭据指引都走它），
   进度是给人看的附属品，不得混进去。
② **任何异常都不得中断扫描**。进度是观测，不是主流程 —— 出问题就静默降级。
③ **非交互环境不用回车刷新**。后台任务 / CI 里日志是一行行追加的，
   `\r` 刷新会变成一坨乱码，所以一律整行输出。
   —— 2026-09-30 补充：**真终端**（`isatty()`）下反过来就该原地刷新，
   那才是「实时进度条」。两者按 TTY 分流，不是二选一。
④ **节流**。全量检查项逐项打印会淹没日志，按百分比跨档输出（默认每 10% 一行），
   并保证「开始 / 结束」两条一定出现。
   —— 补充：**同档位内超过 item_heartbeat_s 也补一行**。只有「跨 10%」一个
   条件时，某项卡住 3 分钟会完全静默，与「卡死」无法区分。
⑤ **长阻塞步骤用心跳**。nuclei 这类一步就吃满几分钟的，没有中间量可报，
   就每隔若干秒打一次「仍在执行（已 Ns / 预算 Ms）」，让读者知道没死。
⑥ **静默看门狗**（2026-09-30 新增）。④⑤ 只能覆盖「引擎知道自己正在等」的场合；
   任何一步若在别处静默卡住，前台依旧一片死寂。看门狗不管当前在做什么，
   只看「距上次输出多久」，超阈值就自动报一行「仍在执行（阶段 X；距上次输出 Ns）」。
⑦ **状态文件 `progress.json`**（2026-09-30 新增）。**这一条来自一次真实事故**：
   一个 18 分钟的扫描在跑完 nuclei 后被杀（父进程随上层会话结束被一并终止），
   归档目录是空的、日志静静停在 `[5m39s]`，**没有任何标记说明它是死是活**。
   光靠 stdout 判断不了这件事，所以要有一份外部随时可读的状态：
   `updated_at` 由看门狗**定期**刷新 —— 因此读者只要看
   「文件时间戳是否还在往前走」就知道进程死没死，而不必读日志。
   写盘用临时文件 + `os.replace`，避免读到写了一半的 JSON。
⑧ **阶段总数由调用方声明，且计划与实际必须核对**（2026-09-30 新增）。
   只有「阶段 7」时读者不知道还剩多少；但总量若写死在进度器里就会漂移，
   所以由 `orchestrator.PLANNED_STAGES` 提供、并在收尾时**核对实到阶段数**
   —— 对不上就明说「进度显示的总量不准」，**不让进度显示自己说谎**
   （本项目红线：不能报错的降级必须能被说出名字）。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

#: 逐项进度在同一档位内的最长静默时间，超过就补一行。
DEFAULT_ITEM_HEARTBEAT_S = 25.0
#: 「距上次输出多久」就算需要报一次存活，秒。
DEFAULT_SILENCE_WARN_S = 45.0
#: 状态文件名（落在本轮归档目录里）。
STATUS_FILE_NAME = "progress.json"


def _fmt_dur(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


class ProgressReporter:
    """扫描进度输出器。

    `enabled=False` 时所有方法都是空操作 —— 自测与库调用默认关闭，
    避免把几十行进度混进断言输出。
    """

    def __init__(self, enabled: bool = True, stream: Any = None,
                 clock: Callable[[], float] = time.time,
                 item_step_percent: int = 10,
                 stage_total: int = 0,
                 item_heartbeat_s: float = DEFAULT_ITEM_HEARTBEAT_S,
                 silence_warn_s: float = DEFAULT_SILENCE_WARN_S,
                 status_path: Any = None):
        self.enabled = bool(enabled) and os.environ.get(
            "AISCAN_PROGRESS", "on").strip().lower() not in ("off", "0", "false")
        self.stream = stream if stream is not None else sys.stderr
        self._clock = clock
        self.t0 = clock()
        self.item_step_percent = max(1, int(item_step_percent))
        self._last_tick = -1
        self.stage_count = 0
        self.lines = 0

        # ---- 阶段总数（0 = 未知，此时不显示分母、收尾也不做计划核对）
        self.stage_total = max(0, int(stage_total or 0))
        self._stage_name = ""
        self._stage_t0 = 0.0

        # ---- 逐项进度
        self._items_done = 0
        self._items_total = 0
        self._items_t0 = 0.0
        self._item_last_at = 0.0
        self.item_heartbeat_s = max(0.05, float(item_heartbeat_s))

        # ---- 静默看门狗
        self.silence_warn_s = max(0.05, float(silence_warn_s))
        self.watch_interval_s = max(0.05, min(5.0, self.silence_warn_s / 3))
        self._stop_evt = threading.Event()
        self._watch_thread: threading.Thread | None = None

        # ---- 状态文件
        self.status_path: Path | None = None
        if status_path:
            self.set_status_path(status_path)

        # ---- 输出通道
        self._lock = threading.RLock()
        self._inline_open = False
        self._inline_width = 0
        self._tty = False
        if os.environ.get("AISCAN_PROGRESS_TTY", "on").strip().lower() not in (
                "off", "0", "false"):
            try:
                self._tty = bool(self.stream.isatty())
            except Exception:  # noqa: BLE001
                self._tty = False

        self._last_emit_at = self.t0
        self._last_emit_text = ""

    # ---------------------------------------------------------------- 基础
    def _write(self, text: str, inline: bool) -> None:
        """真正落笔。TTY 下允许原地刷新，非交互一律整行追加。"""
        st = self.stream
        if not self._tty:
            st.write(text + "\n")
            st.flush()
            return
        if self._inline_open and not inline:
            # 收掉未闭合的原地行，否则后面的整行会压在它上面
            st.write("\r" + " " * self._inline_width + "\r")
            self._inline_open = False
            self._inline_width = 0
        if inline:
            pad = max(0, self._inline_width - len(text))
            st.write("\r" + text + " " * pad)
            self._inline_open = True
            self._inline_width = max(len(text), self._inline_width)
        else:
            st.write(text + "\n")
        st.flush()

    def _emit(self, text: str, inline: bool = False) -> None:
        if not self.enabled:
            return
        try:
            with self._lock:
                self._write(text, inline)
                self.lines += 1
                self._last_emit_at = self._clock()
                self._last_emit_text = text
        except Exception:  # noqa: BLE001
            # 进度不得影响主流程：写不出去就算了（例如 stream 被关闭）
            self.enabled = False
            return
        self._write_status()

    def _stamp(self) -> str:
        return f"[{_fmt_dur(self._clock() - self.t0)}]"

    def _where(self) -> str:
        """「现在在哪」——看门狗与状态文件共用的定位串。"""
        name = self._stage_name or "（阶段之间）"
        idx = self.stage_count
        if idx and self.stage_total > 0:
            base = f"阶段 {idx}/{self.stage_total} {name}"
        elif idx:
            base = f"阶段 {idx} {name}"
        else:
            base = name
        if self._items_total:
            base += f"；逐项 {self._items_done}/{self._items_total}"
        return base

    # ---------------------------------------------------------------- 阶段
    def set_stage_total(self, total: int) -> None:
        """声明计划阶段总数（0 = 未知）。由调用方给，进度器自己不猜。"""
        try:
            self.stage_total = max(0, int(total or 0))
        except Exception:  # noqa: BLE001
            self.stage_total = 0

    def stage_start(self, name: str) -> None:
        self.stage_count += 1
        self._stage_name = name
        self._stage_t0 = self._clock()
        tot = f"/{self.stage_total}" if self.stage_total > 0 else ""
        self._emit(f"{self._stamp()} ▶ 阶段 {self.stage_count}{tot}：{name} ……")
        self._ensure_watchdog()

    def stage_done(self, name: str, status: str = "ok", detail: str = "",
                   duration_ms: int = 0) -> None:
        mark = {"ok": "✓", "failed": "✗", "skipped": "·"}.get(status, "?")
        tail = f"  {detail[:110]}" if detail else ""
        prog = ""
        if self.stage_total > 0:
            prog = f"　[{self.stage_count}/{self.stage_total} 阶段]"
        self._emit(f"{self._stamp()} {mark} {name}（{duration_ms / 1000:.1f}s）{tail}{prog}")

    def note(self, text: str) -> None:
        self._emit(f"{self._stamp()} · {text}")

    # ------------------------------------------------------------ 逐项进度
    def item_tick(self, done: int, total: int, label: str = "") -> None:
        """逐项检测进度。跨档输出，同档位内超时也补一行（防静默）。"""
        if not self.enabled or total <= 0:
            return
        now = self._clock()
        if total != self._items_total:
            self._items_total = total
            self._items_t0 = now
            self._last_tick = -1
            self._item_last_at = 0.0
        self._items_done = done
        pct = int(done * 100 / total)
        step = self.item_step_percent
        bucket = pct // step
        final = done >= total
        advanced = bucket > self._last_tick
        # 只有当**真的开始过**（有上一行）才谈「静默多久」，
        # 否则第一项之前会因为 _item_last_at=0 而误判成超时。
        stale = (self._item_last_at > 0
                 and (now - self._item_last_at) >= self.item_heartbeat_s)
        if not (advanced or final or stale):
            return
        self._last_tick = max(self._last_tick, bucket)
        self._item_last_at = now
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        tail = f"  {label[:40]}" if label else ""
        extra = ""
        elapsed = now - self._items_t0
        if done > 0 and not final and elapsed > 0.5:
            rate = done / elapsed
            if rate > 0:
                extra = f"  剩余约 {_fmt_dur((total - done) / rate)}"
        self._emit(f"{self._stamp()}   [{bar}] {done}/{total}（{pct}%）{tail}{extra}",
                   inline=True)

    # ------------------------------------------------------------ 活动心跳
    def activity(self, label: str, detail: str = "", interval_s: float = 20.0):
        """长阻塞步骤的上下文管理器：进入时打一行，其间按 interval 打心跳。

        用后台线程实现 —— 被包裹的调用（如 nuclei 的 subprocess.run）
        整段阻塞，主线程没有机会插入输出。线程是 daemon，
        上下文退出即停，不会拖住进程。
        """
        return _Activity(self, label, detail, interval_s)

    # ------------------------------------------------------------ 静默看门狗
    def _ensure_watchdog(self) -> None:
        """懒启动：只有在真要开始跑阶段时才起线程（自测里的短命实例不必起）。"""
        if not self.enabled or self._watch_thread is not None:
            return
        try:
            th = threading.Thread(target=self._watch_loop, daemon=True)
            th.start()
            self._watch_thread = th
        except Exception:  # noqa: BLE001
            self._watch_thread = None

    def _watch_loop(self) -> None:
        while not self._stop_evt.wait(self.watch_interval_s):
            if not self.enabled:
                return
            now = self._clock()
            gap = now - self._last_emit_at
            if gap >= self.silence_warn_s:
                # 整行输出：这是「此刻还活着」的证据，必须留在日志里
                self._emit(f"{self._stamp()} · 仍在执行（{self._where()}；"
                           f"距上次输出 {_fmt_dur(gap)}）")
            else:
                # 没到阈值也要刷新状态文件 —— 那正是「进程活着」的凭据。
                self._write_status()

    def _stop_watchdog(self) -> None:
        try:
            self._stop_evt.set()
        except Exception:  # noqa: BLE001
            pass
        th = self._watch_thread
        self._watch_thread = None
        if th is not None and th.is_alive():
            try:
                th.join(timeout=1.0)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------ 状态文件
    def set_status_path(self, path: Any) -> None:
        """指定状态文件位置（一般是本轮归档目录下的 progress.json）。"""
        try:
            self.status_path = Path(path) if path else None
        except Exception:  # noqa: BLE001
            self.status_path = None
        self._write_status()

    def _write_status(self) -> None:
        p = self.status_path
        if p is None or not self.enabled:
            return
        try:
            now = self._clock()
            payload = {
                # updated_at 由看门狗定期刷新 —— 读者只要看它还在不在往前走，
                # 就知道进程死没死，不必去读日志（事故教训，见模块头 ⑦）。
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "updated_epoch": round(time.time(), 3),
                "pid": os.getpid(),
                "elapsed_s": round(now - self.t0, 1),
                "stage_index": self.stage_count,
                "stage_total": self.stage_total,
                "stage": self._stage_name,
                "stage_elapsed_s": (round(now - self._stage_t0, 1)
                                    if self._stage_t0 else None),
                "items_done": self._items_done,
                "items_total": self._items_total,
                "silent_for_s": round(now - self._last_emit_at, 1),
                "last_activity": self._last_emit_text,
                "lines": self.lines,
            }
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                           encoding="utf-8")
            # 原子替换：读者要么读到上一份完整 JSON，要么读到这一份，不会读到半截
            os.replace(tmp, p)
        except Exception:  # noqa: BLE001
            return

    # ---------------------------------------------------------------- 收尾
    def close(self, aborted: bool = False, reason: str = "") -> None:
        """收尾：停看门狗、核对阶段计划、落最终状态。

        **必须在 finally 里调用。** 进程被强杀时这段不会执行 ——
        那种情况靠 progress.json 的 updated_at 不再前进来判断（事故教训 ⑦）。
        """
        self._stop_watchdog()
        if not self.enabled:
            return
        tail = ""
        if self.stage_total > 0:
            if aborted:
                # 提前结束（例如未授权闸门拦下）时，计划与实际本就对不上，
                # 拿它判「计划过期」是误报 —— 明确不据此下结论。
                tail = (f"；本轮未跑完（实到 {self.stage_count}/{self.stage_total} 阶段），"
                        "不据此判断阶段计划是否过期")
            elif self.stage_count == self.stage_total:
                tail = f"；阶段计划核对：计划 {self.stage_total}、实到 {self.stage_count} ✓"
            else:
                # 进度显示自己不准，必须说出来 —— 否则分母会一直骗人。
                tail = (f"；⚠ 阶段计划核对：计划 {self.stage_total}、"
                        f"实到 {self.stage_count} —— 进度显示的总量不准，"
                        "请更新 engine/orchestrator.PLANNED_STAGES")
        head = "扫描异常终止" if aborted else "扫描结束"
        extra = f"：{reason}" if reason else ""
        self._emit(f"{self._stamp()} ■ {head}{extra}"
                   f"（用时 {_fmt_dur(self._clock() - self.t0)}）{tail}")


class _Activity:
    def __init__(self, rep: ProgressReporter, label: str, detail: str,
                 interval_s: float):
        self.rep = rep
        self.label = label
        self.detail = detail
        # 下界只防「0 间隔刷屏」，不设 5s 这种硬底线 ——
        # 自测需要把心跳间隔压到 0.05s 才能验证心跳真的会打出来。
        self.interval = max(0.05, float(interval_s))
        self._stop = threading.Event()
        self._th: threading.Thread | None = None
        self.t0 = 0.0

    def __enter__(self) -> "_Activity":
        self.t0 = self.rep._clock()
        # 实测踩过：nuclei 一步跑满几分钟，前台只有一行「开始」，
        # 操作者无法区分「正在扫」与「卡死」。所以这里把预期耗时也说出来。
        text = f"{self.label} 开始"
        if self.detail:
            text += f"（{self.detail}）"
        self.rep.note(text)
        if self.rep.enabled:
            self._th = threading.Thread(target=self._beat, daemon=True)
            self._th.start()
        return self

    def _beat(self) -> None:
        while not self._stop.wait(self.interval):
            self.rep.note(f"{self.label} 仍在执行（已 "
                          f"{_fmt_dur(self.rep._clock() - self.t0)}）")

    def __exit__(self, *exc: Any) -> bool:
        self._stop.set()
        self.rep.note(f"{self.label} 结束（用时 "
                      f"{_fmt_dur(self.rep._clock() - self.t0)}）")
        return False


class NullProgress(ProgressReporter):
    """空实现：库调用 / 自测里的默认值。"""

    def __init__(self) -> None:
        super().__init__(enabled=False)

    def activity(self, label: str, detail: str = "", interval_s: float = 20.0):
        return NullActivity()


class NullActivity:
    def __enter__(self) -> "NullActivity":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


NULL = NullProgress()


def reporter(enabled: bool = True, **kw: Any) -> ProgressReporter:
    return ProgressReporter(enabled=enabled, **kw) if enabled else NullProgress()


def read_status(path: Any) -> dict[str, Any]:
    """读状态文件。给「扫描跑在别的进程里，我要看一眼现在到哪了」用。

    读不到 / 读坏了都返回 `{}` —— 这是一个观测接口，不抛异常。
    """
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _selftest() -> int:
    """离线自测：输出到哪、有没有节流、关掉是否真静默、看门狗与状态文件。"""
    import io
    import tempfile

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    ok = 0
    fail = []

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        if cond:
            ok += 1
        else:
            fail.append(msg)

    buf = io.StringIO()
    rep = ProgressReporter(enabled=True, stream=buf, item_step_percent=10)
    rep.stage_start("L1 资产测绘")
    rep.stage_done("L1 资产测绘", "ok", "判定目标特征 8 项", 1234)
    for i in range(1, 164):
        rep.item_tick(i, 163, f"ITEM-{i}")
    rep.note("收尾")
    out = buf.getvalue()

    check("▶ 阶段 1" in out, "阶段开始行必须出现")
    check("✓ L1 资产测绘（1.2s）" in out, "阶段结束行必须带耗时与状态")
    lines = [ln for ln in out.splitlines() if "163" in ln]
    check(len(lines) <= 13, f"逐项进度必须节流（163 项最多 12 行，实际 {len(lines)}）")
    check("163/163（100%）" in out, "逐项进度必须出现收尾的 100%")
    check(out.count("168/163") == 0, "不得出现越界进度")
    rep.close()
    check("■ 扫描结束" in buf.getvalue(), "收尾必须有一行明确的「扫描结束」")

    # activity 心跳
    buf2 = io.StringIO()
    rep2 = ProgressReporter(enabled=True, stream=buf2)
    with rep2.activity("nuclei 模板扫描", "5094 份模板", interval_s=0.05):
        time.sleep(0.2)
    o2 = buf2.getvalue()
    check("nuclei 模板扫描 开始" in o2, "活动必须报开始")
    check("结束" in o2, "活动必须报结束")
    check(o2.count("仍在执行") >= 1, "长阻塞步骤必须有心跳行")

    # 关闭即静默
    buf3 = io.StringIO()
    rep3 = ProgressReporter(enabled=False, stream=buf3)
    rep3.stage_start("X")
    rep3.item_tick(1, 10)
    with rep3.activity("Y"):
        pass
    rep3.close()
    check(buf3.getvalue() == "", "enabled=False 时必须完全不输出")
    check(NullProgress().lines == 0, "NullProgress 不得有任何输出")

    # 环境变量开关
    os.environ["AISCAN_PROGRESS"] = "off"
    buf4 = io.StringIO()
    rep4 = ProgressReporter(enabled=True, stream=buf4)
    rep4.stage_start("Z")
    check(buf4.getvalue() == "", "AISCAN_PROGRESS=off 必须静音")
    os.environ.pop("AISCAN_PROGRESS", None)

    # ---- 阶段总数：有分母时要显示，收尾要核对计划 ----
    buf5 = io.StringIO()
    rep5 = ProgressReporter(enabled=True, stream=buf5, stage_total=3)
    rep5.stage_start("A")
    rep5.stage_done("A", "ok", "", 100)
    rep5.stage_start("B")
    rep5.stage_done("B", "ok", "", 100)
    rep5.stage_start("C")
    rep5.stage_done("C", "ok", "", 100)
    rep5.close()
    o5 = buf5.getvalue()
    check("▶ 阶段 1/3" in o5, "声明了总数就必须显示分母（阶段 N/M）")
    check("[1/3 阶段]" in o5, "阶段结束行必须带总体进度")
    check("阶段计划核对：计划 3、实到 3" in o5, "计划与实际一致时必须明说一致")
    check("总量不准" not in o5, "一致时不得报「总量不准」（误报会让真告警被忽略）")

    # 计划对不上：必须说出来，且点名去改哪里
    buf6 = io.StringIO()
    rep6 = ProgressReporter(enabled=True, stream=buf6, stage_total=9)
    rep6.stage_start("A")
    rep6.stage_done("A", "ok", "", 10)
    rep6.close()
    o6 = buf6.getvalue()
    check("总量不准" in o6, "实到阶段数少于计划时必须显式告警")
    check("PLANNED_STAGES" in o6, "告警必须点名去改哪个常量")

    # 提前结束（未授权闸门）：不得据此报「计划过期」
    buf7 = io.StringIO()
    rep7 = ProgressReporter(enabled=True, stream=buf7, stage_total=16)
    rep7.stage_start("运行姿态")
    rep7.stage_done("运行姿态", "ok", "", 10)
    rep7.stage_start("授权闸门")
    rep7.stage_done("授权闸门", "failed", "目标未授权", 10)
    rep7.close(aborted=True, reason="目标未授权")
    o7 = buf7.getvalue()
    check("扫描异常终止" in o7, "提前结束必须明确写「异常终止」")
    check("总量不准" not in o7, "提前结束不得报「阶段计划过期」（那是误报）")
    check("本轮未跑完" in o7, "提前结束必须说明本轮未跑完")

    # ---- 逐项进度的时间兜底：同档位内久无声也必须补一行 ----
    fake = {"t": 1000.0}
    buf8 = io.StringIO()
    rep8 = ProgressReporter(enabled=True, stream=buf8, clock=lambda: fake["t"],
                            item_step_percent=10, item_heartbeat_s=5.0)
    rep8.item_tick(1, 163, "A")          # 首行
    rep8.item_tick(2, 163, "B")          # 同档位、未超时 → 不得输出
    n_before = buf8.getvalue().count("163")
    check(n_before == 1, f"同档位且未超时不得重复输出（实际 {n_before} 行）")
    fake["t"] += 6.0
    rep8.item_tick(3, 163, "C")          # 同档位但已超时 → 必须补一行
    o8 = buf8.getvalue()
    check(o8.count("163") == 2, "同档位内超过心跳间隔必须补一行（否则卡住看不见）")
    check("剩余约" in o8, "逐项进度应给出剩余时间估计")

    # ---- 静默看门狗：长时间没有任何输出时必须自动报「还活着」 ----
    buf9 = io.StringIO()
    rep9 = ProgressReporter(enabled=True, stream=buf9, silence_warn_s=0.3)
    rep9.stage_start("逐项检测")
    time.sleep(0.9)
    rep9.close()
    o9 = buf9.getvalue()
    check(o9.count("仍在执行（阶段") >= 1, "静默超过阈值必须自动报一次存活")
    check("距上次输出" in o9, "存活行必须给出「距上次输出多久」")
    check("逐项检测" in o9, "存活行必须指认当前阶段（否则不知道卡在哪）")

    # ---- 状态文件：外部可读，且 updated_at 必须随手刷新 ----
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td) / STATUS_FILE_NAME
        rep10 = ProgressReporter(enabled=True, stream=io.StringIO(),
                                 stage_total=4, status_path=sp,
                                 silence_warn_s=60.0)
        rep10.stage_start("L1 资产测绘")
        rep10.item_tick(7, 163, "WSTG-INFO-01")
        st = read_status(sp)
        check(st.get("stage") == "L1 资产测绘", "状态文件必须记当前阶段")
        check(st.get("stage_index") == 1 and st.get("stage_total") == 4,
              "状态文件必须记阶段进度 N/M")
        check(st.get("items_done") == 7 and st.get("items_total") == 163,
              "状态文件必须记逐项进度")
        check(isinstance(st.get("pid"), int) and st.get("pid") > 0,
              "状态文件必须记 pid（用来判断进程还在不在）")
        check(isinstance(st.get("updated_epoch"), (int, float)),
              "状态文件必须记 updated_epoch")
        # 看门狗即使不输出，也必须继续刷新 updated_at —— 这正是「活着」的凭据
        t_before = read_status(sp).get("updated_epoch")
        time.sleep(0.2)
        rep10._write_status()
        t_after = read_status(sp).get("updated_epoch")
        check(t_after >= t_before, "状态文件的时间戳必须单调不回退")
        rep10.close()
        check(read_status(sp).get("stage_index") == 1,
              "收尾后状态文件仍须保留最后阶段信息（被杀时它就是唯一的现场）")
        # 读不到时不得抛异常（观测接口）
        check(read_status(Path(td) / "nope.json") == {}, "缺失的状态文件必须返回空字典")
        check(read_status(sp) != {}, "存在且合法的状态文件必须能读出来")

    # 关闭时不得留下看门狗线程（会拖住进程 / 干扰后续自测）
    rep11 = ProgressReporter(enabled=True, stream=io.StringIO())
    rep11.stage_start("X")
    rep11.close()
    check(rep11._watch_thread is None, "收尾后不得仍挂着看门狗线程")

    # 终态行必须与成功时**不同**：上一行在失败时照样会打印（ok 是已通过数），
    # 拿它当「通过标记」的调用方会被骗过去。
    if fail:
        for f in fail:
            print(f"  ✗ {f}")
        print(f"进度显示自测：失败（{len(fail)} 项未通过，{ok} 项通过）")
        return 1
    print(f"进度显示自测：通过 {ok} 项")
    return 0


if __name__ == "__main__":
    import sys as _sys

    try:
        _sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(_selftest())
