# -*- coding: utf-8 -*-
"""运行期边界封禁守门（B 类拦截）
================================

**它解决什么问题**

边界拦截有两种，后果和处置完全不同 —— 混为一谈会让扫描器做出错误动作：

- **A 类「策略级全量拦截」**：开扫时即成立 —— 所有路径（含随机不存在的路径）
  都返回同一张拦截页。这是 `wafgate.assess_boundary` 的职责。
  **等待对它毫无意义**：策略不是临时的，等一小时也不会放行。
- **B 类「频率触发封禁」**：开扫时目标正常响应，扫到一半被拉黑。
  本模块负责这一类。

**为什么 B 类比 A 类更危险**

A 类的结论至少是诚实的「无法评估」；B 类会让引擎把扫描后半段拿到的拦截页
**当成应用页面继续扫完** —— 产出一份格式规范、证据齐全、但复测不出来的假报告。
A 类的错误是「说了不知道」，B 类的错误是「说了错话」。

**处置方式：退避与降速必须绑定**

只等不降速是最常见的错误做法。封禁解除后按原速续扫，几秒内会再次触碰阈值
被封，扫描在「封—解—封」之间空转，耗时不可控。所以恢复后**必须同时降速**。

**判据（与 A 类同源）**

「根路径」与「随机不存在的路径」返回同一张非 2xx 页面 —— 真实应用不会这样。
只比状态码不够：应用自己也可能对某个路径返回 403，但那种情况下随机路径
会得到**不同**的页面。所以「同页」是必要条件，而非充分条件上的修饰。

**三个终态**（都不允许静默继续）

- `resumed`           —— 恢复访问，降速后继续；
- `persistent`        —— 退避序列耗尽仍未恢复，判定为策略级拦截（等同 A 类）；
- `budget_exhausted`  —— 累计等待超出预算，放弃恢复；
- `rounds_exceeded`   —— 反复被封超过容忍轮次，说明降速仍不够。

**抽检是抽样 —— 这是本模块最容易被忽略的漏洞**

按次数节流（`check_every`）意味着两次抽检之间有一段**盲区**。目标若在盲区里被封，
盲区内的检查项全部是在拦截页上跑完的，其中判「通过」的那些**就是假通过** ——
它与「未执行」有本质区别：未执行是「我没说」，假通过是**主动给出的错误结论**，
而报告看起来完全正常。本模块用两条互补的机制消掉这个窗口：

1. **把发现时机提前（缩小窗口）**：`note_response()` 接收每一次探测的响应，
   做**便宜的本地判断**（不额外发请求）—— 同一个「拦截区间状态码 + 同一正文」
   在不同 URL 上重复出现，就说明边缘开始接管。命中即触发一次**真抽检**，
   不再等节流阈值。要求 ≥2 个不同 URL，是因为单次 403 太常见
   （应用自己的鉴权就会返），只有「换个路径还是同一张非基线页」才是封禁特征。
2. **把窗口内的结论作废（消除假通过）**：每个封禁事件都记下
   `window_start`（上一次「干净」抽检时的探测数）到 `window_end`（本次探测数）。
   `is_contaminated(p0, p1)` 回答「这个检查项的取证时段有没有落进窗口」。
   落在窗口里的「通过 / N/A」由调用方改判为「待确认」，`不通过`只加核对标注
   （发现的真伪由复现闸门裁决，不靠这个机制翻案）。

没有第 2 条，第 1 条只是把窗口变小而消不掉；没有第 1 条，第 2 条只能在
「已经被封了很久」之后才生效。两条必须同时有。

**「不再抽检」与「不再被封」是两件事**（2026-09-29 内部生产系统 事故后新增）

`terminal` 的本意是「别再抽检了」，但它一度同时被用来决定「要不要门控」，
后果是逐项检测**整段失去门控**：

    L2 采集期间守门转 persistent → terminal=True
    → tick() 从此恒返回 None
    → 注册表里唯一那句 mark_unexecutable 再也不执行
    →全量检查项在 405 拦截页上全部跑完（73 项假通过、16 项假不通过）

所以两个判断必须分开表达，且**不许再合并**：

- `tick()/note_response()`：终态后不发请求（省请求，也不再消耗对方的容忍度）；
- `currently_blocked()`：**持续状态**查询 —— 终态即「仍在封禁中」，逐项循环
  每个检查项都要重新问一次，据此短路成「未执行」。

判据的口径也随之固定：「此刻是否被封」是**持续状态**，「本轮有没有新事件」是
**瞬时信号**，用同一个标志位表达两者必然出错。
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin

# 允许直接以脚本方式运行本文件里的自测（python engine/banguard.py）。
# 以模块方式导入时 __package__ 有值，这段不生效。
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.wafgate import (  # noqa: E402
    BLOCK_STATUSES,
    SAME_PAGE_RATIO,
    _body_hash,
    _normalize_for_compare,
    _similarity,
    detect_block_page,
)


# ----------------------------------------------------------------------
# 取值辅助：探针可能是 dict，也可能是 HttpProbe 之类的对象
# ----------------------------------------------------------------------
def _val(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ----------------------------------------------------------------------
# 可疑迹象判定（便宜的本地信号，不额外发请求）
# ----------------------------------------------------------------------
#: 同一个「拦截区间状态码 + 同一正文」需要在**多少个不同 URL** 上重复出现，
#: 才认为边缘开始接管。
#:
#: 取 2 的理由：单次 403 太常见 —— 应用自己的鉴权、目录权限都会返，
#: 拿它当封禁信号会触发大量无谓抽检。而「换一个不相关的路径，回来的还是
#: 字节相同的那张非基线页」几乎只有边缘全量接管才会发生。
REPEAT_URLS_FOR_SUSPICION = 2

#: 两次「即时抽检」之间至少要隔多少次探测。可疑信号可能出现得很密集
#: （比如一批路径全部返回同一张拦截页），没有这个下限就会变成抽检风暴 ——
#: 用一个更贵的问题换掉原来的问题。
IMMEDIATE_CHECK_MIN_GAP = 25


@dataclass
class BanEvent:
    """一次「检测到封禁 → 退避处置」的完整记录。"""

    seq: int
    backoff_used: list[float]
    outcome: str          # resumed / persistent / budget_exhausted / rounds_exceeded
    evidence: str
    waited_s: float = 0.0
    speed_after: float = 1.0
    #: 封禁窗口（探测序号区间，左开右闭）：从「上一次干净抽检」到「本次发现封禁」。
    #: 落在这个区间里的检查项，其证据可能取自拦截页 —— 报告要据此作废结论。
    window_start: int = 0
    window_end: int = 0
    #: 本次抽检是被可疑迹象提前触发的，还是到点例行抽检。
    triggered_by: str = "interval"
    #: 拦截页厂商（如「阿里云 WAF」）。**必须结构化落盘**：
    #: 2026-09-29 内部生产系统 实测里它只被拼进了日志消息字符串，报告层取不到，
    #: 只能写「厂商特征未确认」—— 而特征明明命中了。证据在手上却没接到
    #: 消费方，与判据缺失同样要修。
    vendor: str = ""

    @property
    def recovered(self) -> bool:
        return self.outcome == "resumed"

    @property
    def window(self) -> tuple[int, int]:
        return (self.window_start, self.window_end)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "backoff_used_s": list(self.backoff_used),
            "waited_s": round(self.waited_s, 1),
            "outcome": self.outcome,
            "recovered": self.recovered,
            "evidence": self.evidence,
            "vendor": self.vendor,
            "speed_factor_after": round(self.speed_after, 3),
            "window_start_probe": self.window_start,
            "window_end_probe": self.window_end,
            "triggered_by": self.triggered_by,
        }


@dataclass
class GuardReport:
    """整场扫描的边界封禁记录。**必须进入报告** —— 否则「通过」是被污染的。"""

    checks: int = 0
    events: list[BanEvent] = field(default_factory=list)
    total_waited_s: float = 0.0
    speed_factor: float = 1.0
    terminal: bool = False
    terminal_reason: str = ""
    notes: list[str] = field(default_factory=list)
    #: 由可疑迹象提前触发的抽检次数（区别于到点例行抽检）。
    suspicion_checks: int = 0
    #: 因落在封禁窗口内被改判为「待确认」的检查项数（消除假通过的动作量）。
    invalidated_items: int = 0
    #: 因落在封禁窗口内被加核对标注的「不通过」项数（状态不动，只提示）。
    annotated_items: int = 0

    @property
    def occurred(self) -> bool:
        return bool(self.events)

    @property
    def vendor(self) -> str:
        """最近一次封禁事件确认到的拦截页厂商（无则为空串）。

        报告层回填「探测到的防护是哪家」的直接数据源 —— 厂商名只在这
        一处权威存放，generator / orchestrator 都从这里取，不许再各自解析文本。
        """
        for ev in reversed(self.events):
            if ev.vendor:
                return ev.vendor
        return ""

    @property
    def recovered_count(self) -> int:
        return sum(1 for e in self.events if e.recovered)

    def suspect_ranges(self) -> list[tuple[int, int]]:
        """所有封禁窗口（探测序号，左开右闭）。空窗口不计。"""
        return [(e.window_start, e.window_end)
                for e in self.events if e.window_end > e.window_start]

    def to_dict(self) -> dict[str, Any]:
        return {
            "checks": self.checks,
            "occurred": self.occurred,
            "vendor": self.vendor,
            "events": [e.to_dict() for e in self.events],
            "recovered_count": self.recovered_count,
            "total_waited_s": round(self.total_waited_s, 1),
            "speed_factor": round(self.speed_factor, 3),
            "terminal": self.terminal,
            "terminal_reason": self.terminal_reason,
            "notes": list(self.notes),
            "suspicion_checks": self.suspicion_checks,
            "suspect_windows": [list(r) for r in self.suspect_ranges()],
            "invalidated_items": self.invalidated_items,
            "annotated_items": self.annotated_items,
        }

    def summary(self) -> str:
        """给报告用的一句话概括。无封禁时返回空串。"""
        if not self.events:
            return ""
        parts = [f"⚠ 本次扫描期间检测到边界封禁 {len(self.events)} 次"]
        if self.recovered_count:
            parts.append(f"（其中 {self.recovered_count} 次退避后恢复）")
        if self.suspicion_checks:
            parts.append(f"，{self.suspicion_checks} 次由可疑迹象提前触发抽检")
        parts.append(f"，累计退避等待 {self.total_waited_s:.0f} 秒")
        if self.speed_factor < 1.0:
            parts.append(f"，后续扫描速率降至原速的 {self.speed_factor:.0%}")
        if self.invalidated_items:
            parts.append(
                f"；**{self.invalidated_items} 个检查项落在封禁窗口内，"
                "原有结论已改判为「待确认」**（窗口内取证可能是拦截页）")
        if self.annotated_items:
            parts.append(f"；另 {self.annotated_items} 个「不通过」项已标注需核对取证时段")
        if self.terminal:
            parts.append(f"；**{self.terminal_reason}**")
        else:
            parts.append("。")
        return "".join(parts)


class _NullCtx:
    """空上下文：进度模块不可用时也不得让守门报错。"""

    def __enter__(self) -> "_NullCtx":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


class BoundaryGuard:
    """运行期边界封禁守门。

    fetch         —— 可调用的 (url) -> 探针（dict 或对象均可）
    budget_s      —— 整场扫描允许的**总**退避等待秒数上限
    backoff       —— 退避序列（秒）；耗尽仍未恢复即判策略级拦截
    max_rounds    —— 容忍的封禁轮次；超过说明降速仍避开不了阈值
    check_every   —— 每累计多少次探测抽检一次
    sleep         —— 可注入，便于离线自测不真的等待
    """

    def __init__(
        self,
        fetch: Callable[[str], Any],
        *,
        budget_s: float = 600.0,
        backoff: tuple[float, ...] = (30.0, 60.0, 120.0, 300.0),
        max_rounds: int = 3,
        check_every: int = 25,
        speed_step: float = 0.5,
        min_speed: float = 0.1,
        sleep: Callable[[float], None] | None = None,
        enabled: bool = True,
        progress: Any = None,
    ):
        self._fetch = fetch
        self.budget_s = float(budget_s)
        self.backoff = tuple(float(x) for x in backoff)
        self.max_rounds = int(max_rounds)
        self.check_every = int(check_every)
        self.speed_step = float(speed_step)
        self.min_speed = float(min_speed)
        self._sleep = sleep or time.sleep
        self.enabled = bool(enabled)
        #: 进度输出器（可选）。退避等待最长可达 budget_s（默认 600 秒），
        #: 全程一句输出都没有 —— 实测中操作者据此判断「扫描卡死了」，
        #: 而其实是守门在按策略静默等待。不给进度就等于把等待藏起来。
        self._pg = progress

        self.report = GuardReport()
        self._url = ""
        self._base_status = 0
        self._base_hash = ""
        self._next_at = 0
        #: 最近一次判「被封」时的厂商与状态码。厂商进 BanEvent 之外还要留在
        #: 守门实例上 —— `mark_unexecutable` 写短路标记时要直接取用。
        self._last_vendor = ""
        self._last_block_status = 0
        #: 最近一次「干净」抽检时的探测序号。封禁窗口的左端点由它决定：
        #: 窗口 = (clean_probe_at, 发现封禁时的探测序号]。窗口内的取证不可信。
        self.clean_probe_at = 0
        #: 调用方最近一次报告的探测序号（由 tick / note_response 维护）。
        self._probe_now = 0
        self._last_immediate_at = -(10 ** 9)
        #: 见过「拦截区间状态码 + 正文哈希」的不同 URL 集合（可疑迹象判定用）。
        self._seen_pages: dict[tuple[int, str], set[str]] = {}

    # ------------------------------------------------------------------
    # 基线
    # ------------------------------------------------------------------
    def arm(self, probe_url: str, status: int, body: str = "") -> None:
        """记录「正常状态」的基线。

        **这是整套机制的前提**：没有基线就没法区分「中途被封」与
        「目标本来就在返 5xx」—— 那又会退回到「孤立信号当证据」的老错误。
        """
        self._url = probe_url or ""
        self._base_status = int(status or 0)
        self._base_hash = _body_hash(body) if (body or "").strip() else ""
        self._next_at = 0
        self.clean_probe_at = 0
        self._probe_now = 0
        self._last_immediate_at = -(10 ** 9)
        self._seen_pages.clear()
        self._last_vendor = ""
        self._last_block_status = 0

    @property
    def armed(self) -> bool:
        return bool(self._url) and self.enabled

    def currently_blocked(self) -> bool:
        """「此刻是否仍处于封禁中」—— **持续状态**查询。

        与 `tick()` / `note_response()` 的关系必须分清：
          · 抽检（tick / note_response）在终态后**不再发请求** —— 不该再打，
            打了也是白白消耗对方的容忍度；
          · 但**门控判断**必须能独立地问「现在是否被封」。两者混用同一个
            标志位的事故（2026-09-29 内部生产系统）：terminal 之后 tick 恒返回 None，
            逐项门控随之失效，全量检查项在 405 拦截页上全部跑完，
            产出 73 项假通过 —— B 类拦截最危险的失败形态。

        「未恢复」的三种终态（persistent / budget_exhausted / rounds_exceeded）
        都意味着封禁仍在持续，此处一律视为「被封」。
        """
        return bool(self.report.terminal)

    # ------------------------------------------------------------------
    # 判据
    # ------------------------------------------------------------------
    def _rand_url(self, base: str) -> str:
        name = f"{secrets.token_hex(8)}-{secrets.token_hex(4)}.html"
        return urljoin(base.rstrip("/") + "/", name)

    def _same_page(self, p: Any, c: Any) -> bool:
        """两个响应是否「同一张页面」。归一化哈希优先，相似度兜底。"""
        pb = (_val(p, "body_snippet", "") or "")
        cb = (_val(c, "body_snippet", "") or "")
        if not pb.strip() or not cb.strip():
            return False
        if _body_hash(pb) == _body_hash(cb):
            return True
        # 残留动态位（未枚举到的 nonce 之类）时哈希不等，看结构相似度。
        if int(_val(p, "status", 0) or 0) != int(_val(c, "status", 0) or 0):
            return False
        return _similarity(_normalize_for_compare(pb),
                           _normalize_for_compare(cb)) >= SAME_PAGE_RATIO

    def _looks_blocked(self, p: Any, c: Any) -> tuple[bool, str, str]:
        """判断本次抽检是否已被封禁。返回 (是否封禁, 依据, 厂商)。

        必要条件：抽检 URL 与随机不存在路径返回**同一张页面**。
        在此之上还要有拦截迹象，避免把「应用对两者都返回同一个合法页」误判。

        厂商单独返回是硬要求：它不能只活在 `why` 的消息文本里 ——
        那种「证据只进日志不进数据」的写法，报告层就永远取不到
        （2026-09-29 内部生产系统 实测的教训）。
        """
        if p is None:
            return False, "", ""
        ps = int(_val(p, "status", 0) or 0)
        pb = _val(p, "body_snippet", "") or ""
        if not self._same_page(p, c):
            return False, "", ""

        # ① 命中拦截页特征 —— 最强证据
        hit, vendor, why = detect_block_page(
            ps, _val(p, "headers", {}) or {}, pb, _val(p, "cookies", []) or [])
        if hit:
            return True, (f"正文命中 {vendor} 拦截页特征（{why}），"
                          "且与随机不存在路径返回同一张页面"), vendor

        # ② 状态码从基线掉进拦截区间 —— 次强证据，仍需「同页」支撑
        if ps in BLOCK_STATUSES and ps != self._base_status:
            return True, (f"状态码由基线 HTTP {self._base_status} 变为 {ps}，"
                          "且与随机不存在路径返回同一张页面"
                          f"（归一化哈希 {_body_hash(pb)}）"), ""

        return False, "", ""

    # ------------------------------------------------------------------
    # 抽检与处置
    # ------------------------------------------------------------------
    def _looks_suspicious(self, url: str, status: int, body: str) -> bool:
        """便宜的本地判断：边缘是不是开始接管了。**不发任何请求。**

        判据：同一个「拦截区间状态码 + 同一正文（非基线页）」在**不同 URL** 上
        重复出现。单次 403 不算 —— 应用自己的鉴权天天返 403，
        拿它当信号会让每次目录枚举都触发一轮抽检。
        """
        st = int(status or 0)
        if st not in BLOCK_STATUSES:
            return False
        h = _body_hash(body or "")
        if not h or h == self._base_hash:
            # 正文为空（可能是重定向 / 204）或就是基线页本身 —— 都不是新迹象。
            return False
        seen = self._seen_pages.setdefault((st, h), set())
        if url:
            seen.add(url.split("?", 1)[0].split("#", 1)[0])
        return len(seen) >= REPEAT_URLS_FOR_SUSPICION

    def note_response(self, url: str, status: int, body: str = "",
                      probe_count: int | None = None) -> BanEvent | None:
        """喂一个刚拿到的响应，必要时**立刻**抽检（不等节流阈值）。

        返回非 None 表示这次喂入直接触发了封禁处置。调用方（注册表）拿到它
        应当做与该次封禁对应的处置（降速 / 写入终态）。

        为什么必须提前：`tick()` 按探测次数节流（默认 25 次），两次抽检之间
        是盲区。目标在盲区里被封，盲区内的检查项就在拦截页上跑完了 ——
        其中判「通过」的那些是假通过。等下一次到点抽检才发现，窗口已经形成。

        `probe_count` 由调用方传入**当下**的探测数。这是窗口右端点的唯一准确
        来源：按检查项边界维护的计数在单个重型检查项内是滞后的，
        用它算窗口会把窗口内的一部分取证漏掉（漏掉的部分就成了假通过）。
        """
        if not self.armed or self.report.terminal:
            return None
        if probe_count is not None:
            self._probe_now = int(probe_count or 0)
        if not self._looks_suspicious(url, status, body):
            return None
        # 抽检下限：可疑信号可能成片出现（一批路径全返同一张拦截页），
        # 没有这个下限就会从「漏抽检」翻成「抽检风暴」。
        if self._probe_now - self._last_immediate_at < IMMEDIATE_CHECK_MIN_GAP:
            return None
        self._last_immediate_at = self._probe_now
        self.report.suspicion_checks += 1
        ev = self.check(triggered_by="suspicion")
        if ev is None:
            # 抽检结果干净：窗口左端点前移到当下。
            self.clean_probe_at = self._probe_now
        return ev

    def tick(self, probe_count: int) -> BanEvent | None:
        """按探测次数节流地抽检一次。返回 BanEvent 表示检测到封禁。"""
        if not self.armed or self.report.terminal:
            return None
        self._probe_now = int(probe_count or 0)
        if self._probe_now < self._next_at:
            return None
        ev = self.check(triggered_by="interval")
        self._next_at = self._probe_now + self.check_every
        if ev is None:
            self.clean_probe_at = self._probe_now
        return ev

    def check(self, probe_url: str | None = None, *,
              probe_count: int | None = None,
              triggered_by: str = "manual") -> BanEvent | None:
        """抽检一次；检测到封禁则完成退避处置。"""
        if not self.enabled:
            return None
        if probe_count is not None:
            self._probe_now = int(probe_count or 0)
        url = probe_url or self._url
        if not url:
            return None
        self.report.checks += 1

        try:
            p = self._fetch(url)
        except Exception as e:  # noqa: BLE001
            # 网络层面的异常**不当作封禁** —— 那是「取不到数」，不是「被拦住」。
            self.report.notes.append(
                f"第 {self.report.checks} 次抽检未取到数据"
                f"（{type(e).__name__}），不计入封禁")
            return None

        try:
            c = self._fetch(self._rand_url(url))
        except Exception:  # noqa: BLE001
            c = None

        blocked, why, vendor = self._looks_blocked(p, c)
        if not blocked:
            return None
        self._last_vendor = vendor
        self._last_block_status = int(_val(p, "status", 0) or 0)
        return self._handle_ban(why, triggered_by=triggered_by, vendor=vendor)

    def is_contaminated(self, probe_from: int, probe_to: int) -> bool:
        """某个检查项的取证时段（探测区间）是否与任一封禁窗口相交。

        相交即不可信：窗口内我们无法区分响应来自应用还是拦截页。
        窗口是左开右闭的 `(start, end]`，检查项覆盖 `[probe_from, probe_to]`。
        """
        for a, b in self.report.suspect_ranges():
            if probe_to > a and probe_from < b:
                return True
        return False

    def _note(self, text: str) -> None:
        """进度提示。进度是观测不是主流程 —— 出任何问题都不得影响守门。"""
        try:
            if self._pg is not None:
                self._pg.note(text)
        except Exception:  # noqa: BLE001
            pass

    def _activity(self, label: str, detail: str = "", interval_s: float = 20.0):
        """取一个心跳上下文管理器；没有接进度时给空实现。"""
        try:
            if self._pg is not None:
                return self._pg.activity(label, detail, interval_s)
        except Exception:  # noqa: BLE001
            pass
        try:
            from engine.progress import NullActivity  # noqa: PLC0415

            return NullActivity()
        except Exception:  # noqa: BLE001
            return _NullCtx()

    def _handle_ban(self, why: str, triggered_by: str = "interval",
                    vendor: str = "") -> BanEvent:
        seq = len(self.report.events) + 1

        # 轮次上限：反复被封说明降速仍避开不了阈值，再扫也只是拿拦截页
        if seq > self.max_rounds:
            self._note(f"边界封禁守门：第 {seq} 次触发，超过容忍上限"
                       f"（{self.max_rounds} 轮），不再退避等待")
            return self._close(
                seq, [], "rounds_exceeded",
                f"本次扫描第 {seq} 次触发边界封禁，超过容忍上限"
                f"（{self.max_rounds} 轮）—— 反复被封说明降速仍不足以避开阈值。",
                why, triggered_by)

        used: list[float] = []
        outcome = "persistent"
        detail = ("退避序列耗尽仍未恢复访问 —— 这不是短时频率封禁，"
                  "而是策略级拦截，等待无意义。")
        # 退避最长可吃满 budget_s（默认 600 秒）且**全程无输出**，
        # 看上去和卡死完全一样。所以先把「要等多久」说清楚，再用心跳兜住。
        self._note(
            f"边界封禁守门：第 {seq}/{self.max_rounds} 次触发（{triggered_by}）"
            f"—— {why}")
        self._note(
            "进入退避等待，序列 "
            + " / ".join(f"{d:.0f}s" for d in self.backoff)
            + f"，总预算 {self.budget_s:.0f}s（期间会静默等待，不是卡死）")
        _t0 = time.time()
        with self._activity("边界封禁退避等待",
                            f"第 {seq}/{self.max_rounds} 轮，预算 {self.budget_s:.0f}s",
                            interval_s=20.0):
            for delay in self.backoff:
                if self.report.total_waited_s + delay > self.budget_s:
                    outcome = "budget_exhausted"
                    detail = (f"累计退避等待将超出预算上限 {self.budget_s:.0f} 秒，"
                              f"放弃恢复（本轮本可再等 {delay:.0f} 秒）。")
                    break
                self._note(f"退避等待 {delay:.0f}s ……")
                self._sleep(delay)
                used.append(delay)
                self.report.total_waited_s += delay
                try:
                    p2 = self._fetch(self._url)
                    c2 = self._fetch(self._rand_url(self._url))
                except Exception as e:  # noqa: BLE001
                    detail = f"退避后的复探未取到数据（{type(e).__name__}）"
                    continue
                still, _w, _v2 = self._looks_blocked(p2, c2)
                if not still:
                    outcome = "resumed"
                    detail = f"累计退避 {sum(used):.0f} 秒后复探已恢复正常访问。"
                    break
        self._note(f"边界封禁守门：退避结束（{outcome}）—— {detail}"
                   f"（本轮等待 {time.time() - _t0:.0f}s）")
        return self._close(seq, used, outcome, detail, why, triggered_by,
                           vendor=vendor)

    def _close(self, seq: int, used: list[float], outcome: str,
               detail: str, why: str, triggered_by: str = "interval",
               vendor: str = "") -> BanEvent:
        if outcome == "resumed":
            self.report.speed_factor = max(
                self.min_speed, self.report.speed_factor * self.speed_step)
        else:
            self.report.terminal = True
            self.report.terminal_reason = (
                f"{detail}剩余检查项无法在「未触达应用」的状态下继续，"
                "一律按「未执行」记录，不得据此认为通过。")
        ev = BanEvent(
            seq=seq,
            backoff_used=used,
            outcome=outcome,
            evidence=why,
            waited_s=sum(used),
            speed_after=self.report.speed_factor,
            window_start=int(self.clean_probe_at),
            window_end=int(self._probe_now),
            triggered_by=triggered_by,
            vendor=vendor or self._last_vendor,
        )
        self.report.events.append(ev)
        if ev.window_end > ev.window_start:
            self.report.notes.append(
                f"第 {seq} 次封禁的窗口为探测 {ev.window_start}–{ev.window_end}"
                f"（{triggered_by} 触发）：该区间内取到的响应可能来自拦截页，"
                "落在其中的检查项结论不可信，已按窗口作废")
        # 恢复后窗口右端点即新的「干净」基准：窗口之后重新抽检过、确认干净。
        self.clean_probe_at = self._probe_now
        if outcome == "resumed":
            # 恢复后下一次即时抽检的下限重新计时，避免立刻又触发一轮。
            self._last_immediate_at = self._probe_now
        return ev

    # ------------------------------------------------------------------
    # 降速落到客户端
    # ------------------------------------------------------------------
    def apply_speed(self, client: Any) -> float:
        """把降速系数作用到 HTTP 客户端上，返回生效后的速率。

        原始速率在客户端上懒记录一次（`_base_rps`），后续每次降速都相对它计算，
        避免「降速后再降速」变成指数衰减。
        """
        if self.report.speed_factor >= 1.0 or client is None:
            return float(getattr(client, "rps", 0) or 0)
        base = getattr(client, "_base_rps", None)
        if base is None:
            base = float(getattr(client, "rps", 0) or 20.0)
            try:
                client._base_rps = base
            except Exception:  # noqa: BLE001
                pass
        new_rps = max(0.2, float(base) * self.report.speed_factor)
        try:
            client.rps = new_rps
        except Exception:  # noqa: BLE001
            pass
        return new_rps

    # ------------------------------------------------------------------
    def mark_unexecutable(self, ctx: Any) -> None:
        """终态时把事实写进检测上下文，让后续检查项落到「未执行」。

        复用 `boundary_block` 通道：注册表见到它就短路成「未执行」，
        与 A 类的处理保持一致，报告措辞也统一。可重复调用（幂等）：
        终态是持续状态，逐项门控每个检查项都会来问一次。
        """
        if not self.report.terminal:
            return
        cache = getattr(ctx, "_cache", None)
        if not isinstance(cache, dict):
            return
        cache["boundary_block"] = {
            "reason": f"扫描中途被边界封禁（{self.report.terminal_reason}）",
            "vendor": self._last_vendor,
            "status": self._last_block_status,
            "kind": "mid_scan_ban",
        }


#: `hard_limits.stop_on` 的判据常量。
#: ⚠ 与 `config/profiles.yaml` 的注释必须保持一致 —— 配置是规范，代码是执行。
#: 三条判据都自带**反误报限定**（见 TargetHealthWatch 的说明），
#: 这些限定同样要写进 yaml，否则配置与实现的承诺不一致。
HEALTH_5XX_STREAK = 10          # 连续多少次 5xx 判「目标疑似被打挂」
HEALTH_5XX_MIN_URLS = 2         # 这串 5xx 至少跨几个不同 URL 才算数
HEALTH_LATENCY_FACTOR = 10.0    # 响应时间突增倍数
HEALTH_LATENCY_FLOOR_S = 0.8    # 「突增」的绝对下限（防毫秒级抖动误判）
HEALTH_LATENCY_STREAK = 3       # 突增需连续出现几次才判定（防单次网络抖动）
HEALTH_BASELINE_SAMPLES = 20    # 用前多少次响应算基线中位数
#: 基线下限。**只用来挡「基线取不到 / 为 0」这一种情况**，不是「快站点豁免」——
#: 曾写成 0.02s，结果是基线 5ms 的站点被**整体豁免**突增判定：
#: 一个 5ms 的站变成 5 秒（1000 倍）也不会停手，而它正是最该被保护的那类。
#: 毫秒级抖动本来就由 `HEALTH_LATENCY_FLOOR_S`（绝对值 0.8s）挡住，
#: 这里不需要再设一道倍数门槛。
HEALTH_BASELINE_MIN_S = 0.001
#: 宽免（确认入口仍存活 → 不停手）之后要求的降速幅度与绝对下限。
#: 站还活着只意味着「可以继续」，不意味着「可以继续按原速率压」。
REPRIEVE_SPEED_FACTOR = 0.4
REPRIEVE_MIN_RPS = 0.5


class TargetHealthWatch:
    """`hard_limits.stop_on` 的运行期执行体：判「是不是**我们**把目标打挂了」。

    **与 BoundaryGuard 的分工必须泾渭分明** —— 把两者混成一个结论，
    报告里就会出现假话：

    | | BoundaryGuard | TargetHealthWatch |
    |---|---|---|
    | 在说什么 | 「**对方**把我们拦住了」 | 「**我们**可能把对方打挂了」 |
    | 判据 | 403/429、拦截页特征、整站同页 | 连续 5xx、响应时间突增 |
    | 处置 | 退避 + 降速，然后继续 | **立即停手**，不做任何等待重试 |
    | 损失 | 本次扫描被打断 | 可能是一条真实业务故障 |

    停手而不等待的理由是**不可逆性**：目标开始连续 5xx，说明服务很可能已经
    异常；这时候按原速率继续施压只会加重故障，等待也没有意义（不是限流，
    是服务本身出问题了）。这一点上它比「被封」严重得多。

    **判据全部来自已观测到的响应**（`note_response`），**不发任何额外请求** ——
    目标已经不稳的时候再补探测，等于火上浇油。这与 BoundaryGuard 的
    `check()`（要发两次真请求）有本质区别，也是本模块能挂进探测热路径的原因。

    **为什么必须有反误报限定**（本项目红线：孤立信号不得当正面证据）：

    1. **连续** N 次，中间夹一个非 5xx 即清零 —— 单个接口偶尔 500
       （缺参数、资源不存在、上游抖动）在真实系统里天天发生；
    2. 这串 5xx 必须跨 **≥2 个不同 URL** —— 目录枚举时反复打到同一个坏接口，
       会连续凑出一串 5xx，但它说明「那个接口坏了」，不是「整站被压挂了」；
    3. 响应时间突增要**连续** `HEALTH_LATENCY_STREAK` 次，且带绝对下限 ——
       一次 3 秒的响应可能是网络抖动，而基线 20ms 的站「突增 10 倍」
       也只有 200ms，拿它当故障是噪声；
    4. 基线取**前 N 次响应的中位数**（而非均值）—— 均值会被后期的
       慢响应自己拉高，从而慢慢「适应」掉突增，让判据永远不触发。

    未做到第 4 条会有一个很隐蔽的后果：判据随基线漂移而失效，
    看起来「从来没有误报」，实际是**从来没有报**。

    ======================================================================
    2026-10-10 补：判据达标 ≠ 整站故障，停手前必须确认一次
    ======================================================================

    Juice Shop 基准第 15 轮连撞两次，暴露了这条守门的盲区：

        连续 10 次 5xx、跨 10 个不同 URL —— 判据**全部达标**，
        于是后续 87 项整批记「未执行」，整轮召回从 52.5% 塌到 12.5%。
        事后逐条手工复现同一批地址，当时几乎全是 200。

    根因是判据回答的是另一个问题：「连续 5xx」只能证明**这批探测在报错**，
    证明不了**整站被压挂了**。这两件事的处置完全不同：

        整站故障 → 立即停手（不可逆，继续施压会加重故障）
        局部报错 → 降速继续（某些应用对畸形探针返 500 就是它的正常形态，
                    Juice Shop 的 Error Handling 考点恰恰靠这个得分）

    老红队一眼能分开这两种情况：**先打一枪站点首页，看还活着没**。
    所以这里补上这一步 —— 判据达标后对入口 URL 发**一次**确认请求：
        活着 → 判为局部报错：不整轮作废，清零计数 + 请求降速 + 全程留痕；
        挂了 → 照旧立即停手。
    宽免**每轮只有一次**（`max_reprieves=1`）：第二次再达标即硬停，
    免得「确认—继续—再确认」把保护机制架空成永不生效。

    另外补了**样本留痕**：以前只报「跨 10 个不同 URL」却不说是哪 10 个，
    读者和我们自己都无法判断这次停手是真是假 —— 判据产出的值没落到
    消费方能取的字段，等于没产出（红线 52 同一族）。
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        max_5xx_streak: int = HEALTH_5XX_STREAK,
        min_urls: int = HEALTH_5XX_MIN_URLS,
        latency_factor: float = HEALTH_LATENCY_FACTOR,
        latency_floor_s: float = HEALTH_LATENCY_FLOOR_S,
        latency_streak: int = HEALTH_LATENCY_STREAK,
        baseline_samples: int = HEALTH_BASELINE_SAMPLES,
        progress: Any = None,
        confirm_url: str = "",
        confirm_fn: Any = None,
        max_reprieves: int = 1,
        loopback: bool = False,
    ):
        self.enabled = bool(enabled)
        self.max_5xx_streak = int(max_5xx_streak)
        self.min_urls = int(min_urls)
        self.latency_factor = float(latency_factor)
        self.latency_floor_s = float(latency_floor_s)
        self.latency_streak = int(latency_streak)
        self.baseline_samples = int(baseline_samples)
        self._pg = progress
        #: 停手前「打一枪看站还活着没」用的入口地址与请求函数。
        self.confirm_url = str(confirm_url or "")
        self._confirm_fn = confirm_fn
        self.max_reprieves = max(0, int(max_reprieves))
        #: 是否为第一方 / 回环目标（本地自有靶场）。健康度守门的职责是
        #: 「别把**对方**的服务器打挂」，对回环目标不适用 —— 冷启动延迟突增或
        #: 靶场自身 5xx 应答形态不应因此中断测量。loopback=True 时只记录、不主动停手。
        self.loopback = bool(loopback)
        self.loopback_suppressed = False
        self._reprieves = 0
        #: 每次宽免的证据（含确认状态码与当时那批样本）—— 报告必须能取到。
        self.reprieves: list[dict[str, Any]] = []
        #: 宽免后请求编排层降速（继续扫，但别再用原速率压）。
        self.slowdown_requested = False
        #: 触发判据的那批响应样本（url, status），只留最近若干条。
        self._samples: list[tuple[str, int]] = []
        #: **已知正常**的地址（本轮至少返回过一次非 5xx）。
        #: 只有这些地址开始返 5xx 才计入故障判据 —— 见 `_feed_gate`。
        self._known_good: set[str] = set()
        #: 首次见到的地址返 5xx 的次数（枚举噪声，只披露、不入判据）。
        self.noise_5xx = 0

        self._terminal = False
        self._reason = ""
        #: 触发判据（机器可读），报告与 JSON 都取它，不解析 reason 文本。
        self._kind = ""
        self._last_5xx_status = 0
        self._streak = 0
        self._urls_in_streak: set[str] = set()
        self._last_url_key = ""
        self._baseline_s: float = 0.0
        self._latency_samples: list[float] = []
        self._latency_streak = 0
        #: 全过程观测到的最大响应耗时（毫秒），供报告披露用。
        self.max_latency_ms = 0

    # ------------------------------------------------------------------
    @property
    def terminal(self) -> bool:
        return self._terminal

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def kind(self) -> str:
        return self._kind

    def to_dict(self) -> dict[str, Any]:
        return {
            "stopped": self._terminal,
            "kind": self._kind,
            "reason": self._reason,
            "last_5xx_status": self._last_5xx_status,
            "baseline_ms": int(self._baseline_s * 1000),
            "max_latency_ms": int(self.max_latency_ms),
            # 触发判据的实际样本 —— 没有它，读者无法判断这次停手是真是假。
            "samples": [{"url": u, "status": s} for u, s in self._samples],
            "reprieves": list(self.reprieves),
            # 首次枚举到的地址返 5xx 的次数（噪声，不计入故障判据）。
            "noise_5xx": int(self.noise_5xx),
            "known_good_urls": len(self._known_good),
            "loopback": self.loopback,
            "loopback_suppressed": self.loopback_suppressed,
        }

    def _note(self, text: str) -> None:
        try:
            if self._pg is not None:
                self._pg.note(text)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    def _remember(self, url: str, status: int) -> None:
        """记一条触发判据的样本（只留最近 6 条，够定位成因即可）。"""
        try:
            self._samples.append((str(url or "")[:160], int(status or 0)))
            del self._samples[:-6]
        except Exception:  # noqa: BLE001
            pass

    def _sample_text(self) -> str:
        """把样本拼进结论文本 —— 「跨 10 个 URL」必须能说出是哪 10 个。"""
        if not self._samples:
            return ""
        body = "；".join(f"{u}（{s}）" for u, s in self._samples[:4])
        return f"触发样本：{body}"

    def _try_reprieve(self, kind: str, reason: str) -> bool:
        """判据达标后确认一次「站还活着没」。活着 → 不整轮作废，降速继续。

        返回 True 表示已宽免（调用方不要停手）；False 表示确认失败或已用尽。
        """
        if self._reprieves >= self.max_reprieves:
            return False
        if not callable(self._confirm_fn) or not self.confirm_url:
            return False
        self._reprieves += 1
        st = 0
        try:
            st = int(self._confirm_fn(self.confirm_url) or 0)
        except Exception:  # noqa: BLE001
            st = 0
        alive = 200 <= st < 400
        rec = {
            "kind": kind,
            "confirm_url": self.confirm_url,
            "confirm_status": st,
            "alive": alive,
            "samples": [{"url": u, "status": s} for u, s in self._samples],
            "reason": reason,
        }
        self.reprieves.append(rec)
        if not alive:
            # 确认那一枪也挂了 —— 那就是真故障，照样硬停。
            return False
        # 站还活着：这串 5xx 是局部的（某批探测打到会报错的接口，或瞬时抖动），
        # 不是整站被压挂。老红队遇到这种情况是降速接着打，不是收工。
        self._streak = 0
        self._urls_in_streak.clear()
        self._last_url_key = ""
        self._latency_streak = 0
        self.slowdown_requested = True
        self._note(
            f"目标健康度守门：判据达标（{reason[:40]}…），但入口 "
            f"{self.confirm_url} 仍返回 HTTP {st} —— 判为**局部报错**而非整站"
            "故障：不整轮作废，继续扫描但**请求降速**。"
            f"（{self._sample_text()}）")
        return True

    def _trigger(self, kind: str, reason: str) -> str:
        """判据命中：先尝试宽免，宽免不了才硬停。返回停手原因（空串=不停）。

        loopback（第一方/自有靶场）短路：健康度守门的设计意图是
        「别把**对方**的服务器打挂」，对本地自有靶场不适用 —— 延迟突增 / 连续 5xx
        多因冷启动或靶场本身的应答形态，不是我们造成的外界故障。
        故只记录、不「立即停手」，继续扫完以拿到完整测量。
        """
        if self.loopback:
            if not self.loopback_suppressed:
                # loopback 不主动停手：去掉第三方目标才会用的
                # 「后续项按未执行记录」措辞 —— 那句话对自有靶场是假话
                # （我们确实继续扫完了，没有后续项被记成未执行）。
                clean = reason.replace(
                    "本项之后的所有检查项按「未执行」记录。", "").strip()
                self._kind = kind
                self._reason = (
                    clean
                    + "（loopback 自有靶场：健康度守门不主动停手，仅记录异常，"
                      "不因此中断测量；后续检查项照常执行）")
                self.loopback_suppressed = True
                self._note(f"目标健康度守门（loopback 不主动停手）：{clean}")
            return ""
        if self._try_reprieve(kind, reason):
            return ""
        self._stop(kind, reason + (self._sample_text() or ""))
        return self._reason

    def apply_reprieve_slowdown(self, client: Any) -> float:
        """落地宽免的代价：把客户端速率压到原来的 40%（下限 0.5 rps）。

        ⚠️ 调用后必须清标志（本方法内部已清）。宽免不是免费的 ——
        站还活着只说明「可以继续」，不说明「可以继续按原速率压」。
        若忘了清标志，每个响应都会再折一次，速率会指数衰减到 0，
        扫描看起来卡死而日志上什么错都没有。
        """
        self.slowdown_requested = False
        if client is None:
            return 0.0
        try:
            cur = float(getattr(client, "rps", 0) or 0)
        except Exception:  # noqa: BLE001
            cur = 0.0
        target = max(REPRIEVE_MIN_RPS, cur * REPRIEVE_SPEED_FACTOR)
        try:
            client.rps = target
        except Exception:  # noqa: BLE001
            return cur
        self._note(
            f"目标健康度守门：按宽免约定降速 —— 客户端速率 "
            f"{cur:.1f} → {target:.1f} rps")
        return target

    # ------------------------------------------------------------------
    def _stop(self, kind: str, reason: str) -> None:
        self._terminal = True
        self._kind = kind
        self._reason = reason
        self._note(f"目标健康度守门：**立即停手** —— {reason}")

    def note_response(self, url: str, status: int,
                     elapsed_ms: Any = None) -> str:
        """喂一个刚拿到的响应。返回停手原因（空串 = 正常）。

        **热路径**：永不抛异常、永不发请求、永不阻塞。调用方在探测循环里
        每个响应都会调一次，所以这里的每一行都要便宜。
        """
        try:
            if not self.enabled or self._terminal:
                return self._reason if self._terminal else ""
            st = int(status or 0)
            key = _url_key(url)

            # ---- 判据 1：连续 5xx（跨 ≥2 个 URL）----
            if st >= 500:
                # 先过一道「这个地址以前正常过吗」。
                #
                # 为什么必须过：目录枚举 / 字典探测会打到大量**根本不存在**的路径，
                # 很多应用对未定义路由直接抛异常返 500。这种 5xx 说明的是
                # 「这条路径不存在或没实现」，与「整站被压挂」是两回事。
                # 2026-10-10 Juice Shop 基准连撞两次：连续 10 次 5xx 跨 10 个不同
                # URL——判据全部达标，于是后续 87 项整批记「未执行」，整轮召回
                # 从 52.5% 塌到 12.5%；而事后手工复现同一批地址几乎全是 200。
                #
                # 真正的故障信号是「**本来好用的**地址开始报错」。所以首次见到的
                # 地址返 5xx 只计入 noise_5xx（披露用），不进故障判据，
                # 也不打断连续计数 —— 但也不清零，避免枚举噪声把真故障洗掉。
                if key and key not in self._known_good:
                    self.noise_5xx += 1
                    return ""
                if key and key != self._last_url_key:
                    self._urls_in_streak.add(key)
                self._last_url_key = key
                self._streak += 1
                self._last_5xx_status = st
                self._remember(url, st)
                if (self._streak >= self.max_5xx_streak
                        and len(self._urls_in_streak) >= self.min_urls):
                    return self._trigger(
                        "http_5xx_streak",
                        f"目标连续 {self._streak} 次返回 5xx"
                        f"（跨 {len(self._urls_in_streak)} 个不同 URL，"
                        f"最近一次 HTTP {st}），疑似被本次扫描压出故障。"
                        "⚠ 若同期存在边界拦截，该 5xx 也可能来自拦截页 ——"
                        "无论哪种成因，继续按原速率施压都不成立，故立即停手。"
                        "本项之后的所有检查项按「未执行」记录。")
            else:
                if key:
                    self._known_good.add(key)
                self._streak = 0
                self._urls_in_streak.clear()
                self._last_url_key = key

            # ---- 判据 2：响应时间突增 ----
            # 只统计**成功响应**的耗时：5xx 的耗时不是「服务变慢」的度量
            # （错误分支本来就快），混进来会让两个判据互相污染 ——
            # 5xx 已由判据 1 独立管辖。
            if st < 500:
                sec = _to_seconds(elapsed_ms)
                if sec > 0:
                    self.max_latency_ms = max(self.max_latency_ms,
                                              int(sec * 1000))
                    if len(self._latency_samples) < self.baseline_samples:
                        self._latency_samples.append(sec)
                        if len(self._latency_samples) == self.baseline_samples:
                            self._baseline_s = _median(self._latency_samples)
                            self._note(
                                f"目标健康度守门：正常响应基线中位数 "
                                f"{self._baseline_s * 1000:.0f}ms"
                                f"（取前 {self.baseline_samples} 次）")
                    elif self._baseline_s >= HEALTH_BASELINE_MIN_S:
                        thresh = max(self._baseline_s * self.latency_factor,
                                     self.latency_floor_s)
                        if sec >= thresh:
                            self._latency_streak += 1
                            if self._latency_streak >= self.latency_streak:
                                return self._trigger(
                                    "latency_spike",
                                    f"目标响应时间由基线中位数 "
                                    f"{self._baseline_s * 1000:.0f}ms 突增到 "
                                    f"{sec * 1000:.0f}ms"
                                    f"（{sec / self._baseline_s:.1f} 倍，"
                                    f"连续 {self._latency_streak} 次超阈值），"
                                    "疑似触发限流或出现性能故障。"
                                    "本项之后的所有检查项按「未执行」记录。")
                        else:
                            self._latency_streak = 0
            return ""
        except Exception:  # noqa: BLE001
            # 健康监视是保护措施，不是主流程 —— 它自己的故障不得中断扫描。
            return ""

    # ------------------------------------------------------------------
    def mark_unexecutable(self, ctx: Any) -> None:
        """终态时把事实写进检测上下文，让后续检查项落到「未执行」。

        **用独立的 cache 键**，不与 `boundary_block` 复用：两者的报告措辞
        完全不同（「请求未到达应用」vs「请求到达了应用、但目标在报错」），
        共用一个键就会写出假话。注册表按 `target_unhealthy` 优先处理。
        可重复调用（幂等）。
        """
        if not self._terminal:
            return
        cache = getattr(ctx, "_cache", None)
        if not isinstance(cache, dict):
            return
        cache["target_unhealthy"] = {
            "reason": self._reason,
            "kind": self._kind,
            "status": self._last_5xx_status,
        }


def _host_is_loopback(host: str) -> bool:
    """判断 host 是否为本机回环地址（localhost / 127.0.0.1 / ::1 / 0.0.0.0）。

    健康度守门只对**第三方**目标有意义 —— 它的职责是「别把对方的服务器打挂」。
    回环地址 = 自有靶场（本地 Juice Shop 基准等），不受该约束：慢 / 5xx 多因冷启动
    或靶场自身应答形态，不是我们造成的外界故障，不应因此中断测量。
    """
    h = (host or "").strip().lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _url_key(url: str) -> str:
    """URL → 归一化键（去 query / fragment）。

    归一化的必要性：同一路径带不同参数在目录枚举里会被算成「不同 URL」，
    于是「跨 ≥2 个 URL」这个限定形同没有 —— 而它正是防误报的那道闸。
    """
    u = (url or "").strip()
    if not u:
        return ""
    return u.split("?", 1)[0].split("#", 1)[0].rstrip("/").lower()


def _to_seconds(v: Any) -> float:
    """把 `elapsed_ms` 归一成秒。取不到就返回 0（=不参与判定）。"""
    if v is None:
        return 0.0
    try:
        return max(0.0, float(v) / 1000.0)
    except (TypeError, ValueError):
        return 0.0


def _median(xs: list[float]) -> float:
    """中位数。用中位数而非均值：均值会被后期慢响应自己拉高，
    从而慢慢「适应」掉突增，让判据永远不触发（见类文档第 4 条）。"""
    ys = sorted(x for x in xs if x > 0)
    if not ys:
        return 0.0
    n = len(ys)
    mid = n // 2
    return ys[mid] if n % 2 else (ys[mid - 1] + ys[mid]) / 2.0


def _selftest() -> int:
    """离线自测：不需要网络，用假 fetch + 假 sleep 驱动全部走法。

    提成函数而不是只写在 `__main__` 里，是为了让引擎回归（不变量 ⑮/㉘）
    能把它一起跑了 —— 只靠手动 `python engine/banguard.py` 触发的自测，
    等于永远不会在回归里被执行，那正是「静默失效」的典型形态。
    """
    # ------------------------------------------------------------------
    # 离线自测：不需要网络，用假 fetch + 假 sleep 驱动全部走法
    # ------------------------------------------------------------------
    #: 已执行的分组数 —— **数出来的**，不是写在结尾的常量。
    #: 写死的数字与「跑了几组」无关：中间整段删掉也照样宣布通过。
    _ran = [0]

    def _done(msg: str) -> None:
        _ran[0] += 1
        print(msg)
    BLOCK = "<html><body><h1>405 Not Allowed</h1></body></html>"
    HOME = "<html><body><h1>首页</h1></body></html>"

    class FakeFetch:
        """按脚本化的响应序列返回。"""

        def __init__(self, seq):
            self.seq = list(seq)
            self.i = 0
            self.calls = []

        def __call__(self, url):
            self.calls.append(url)
            if self.i < len(self.seq):
                r = self.seq[self.i]
                self.i += 1
            else:
                r = self.seq[-1]
            status, body = r
            return {"status": status, "body_snippet": body, "headers": {},
                    "cookies": []}

    slept: list[float] = []

    def fake_sleep(s):
        slept.append(s)

    # --- 自测 1：正常站点不该触发任何封禁 ---
    f1 = FakeFetch([(200, HOME)])
    g1 = BoundaryGuard(f1, sleep=fake_sleep)
    g1.arm("https://a.test/", 200, HOME)
    assert g1.check() is None, "正常响应不得判封禁"
    assert not g1.report.occurred
    _done("✓ 自测 1：抽检到正常响应时不触发封禁")

    # --- 自测 2：中途被封 → 第一次退避就恢复 → 必须降速 ---
    f2 = FakeFetch([(405, BLOCK), (405, BLOCK), (200, HOME), (200, HOME)])
    g2 = BoundaryGuard(f2, sleep=fake_sleep)
    g2.arm("https://b.test/", 200, HOME)
    ev2 = g2.check()
    assert ev2 is not None and ev2.outcome == "resumed", f"应恢复，实为 {ev2}"
    assert g2.report.speed_factor == 0.5, "恢复后必须降速到一半"
    assert slept == [30.0], f"应在 30s 后首次复探，实为 {slept}"
    _done("✓ 自测 2：中途被封 → 退避恢复 → 速率降至原速 50%")

    # --- 自测 3：退避序列耗尽 → 判策略级拦截并转终态 ---
    slept.clear()
    f3 = FakeFetch([(403, BLOCK)])          # 永远被封
    g3 = BoundaryGuard(f3, sleep=fake_sleep, budget_s=1000.0)
    g3.arm("https://c.test/", 200, HOME)
    ev3 = g3.check()
    assert ev3 is not None and ev3.outcome == "persistent", f"应为 persistent，实为 {ev3}"
    assert g3.report.terminal and g3.report.terminal_reason
    assert slept == [30.0, 60.0, 120.0, 300.0], f"退避序列应为 30/60/120/300，实为 {slept}"
    _done("✓ 自测 3：退避序列耗尽仍未恢复 → 判定策略级拦截并转入终态")

    # --- 自测 4：等待预算必须真正生效（不能无限等） ---
    slept.clear()
    f4 = FakeFetch([(403, BLOCK)])
    g4 = BoundaryGuard(f4, sleep=fake_sleep, budget_s=100.0)
    g4.arm("https://d.test/", 200, HOME)
    ev4 = g4.check()
    assert ev4 is not None and ev4.outcome == "budget_exhausted", f"应为预算耗尽，实为 {ev4}"
    assert sum(slept) <= 100.0, f"等待总量不得超过预算，实为 {sum(slept)}"
    _done("✓ 自测 4：总等待预算生效，不会无限等待")

    # --- 自测 5：反复被封超过轮次上限 → 直接停，不再尝试恢复 ---
    slept.clear()
    f5 = FakeFetch([(405, BLOCK), (405, BLOCK), (200, HOME), (200, HOME)])
    g5 = BoundaryGuard(f5, sleep=fake_sleep, max_rounds=1)
    g5.arm("https://e.test/", 200, HOME)
    g5.check()
    assert g5.report.events and g5.report.events[0].outcome == "resumed"
    slept.clear()
    f5b = FakeFetch([(405, BLOCK)])
    g5._fetch = f5b
    ev5 = g5.check()
    assert ev5 is not None and ev5.outcome == "rounds_exceeded", f"应超轮次，实为 {ev5}"
    assert slept == [], "超轮次时不得再做任何退避等待"
    _done("✓ 自测 5：反复被封超过轮次上限 → 直接停，不再空等")

    # --- 自测 6：SPA 场景不得误判（整站返回同一个 200 外壳页）---
    f6 = FakeFetch([(200, HOME)])
    g6 = BoundaryGuard(f6, sleep=fake_sleep)
    g6.arm("https://f.test/", 200, HOME)
    assert g6.check() is None, "对任意路径返回同一个 200 页面是正常应用行为，不得判封禁"
    _done("✓ 自测 6：SPA 全路径同一 200 外壳页不误判为封禁")

    # --- 自测 7：取不到数据不等于被封 ---
    class Boom:
        def __call__(self, url):
            raise TimeoutError("connect timeout")

    g7 = BoundaryGuard(Boom(), sleep=fake_sleep)
    g7.arm("https://g.test/", 200, HOME)
    assert g7.check() is None and not g7.report.occurred
    assert g7.report.notes, "取数失败应留下说明"
    _done("✓ 自测 7：网络异常记「未取到数据」，不当作封禁")

    # --- 自测 8：终态必须让后续检查项落到「未执行」---
    f8 = FakeFetch([(403, BLOCK)])
    g8 = BoundaryGuard(f8, sleep=fake_sleep, budget_s=50.0)
    g8.arm("https://h.test/", 200, HOME)

    class Ctx:
        _cache: dict = {}

    ctx8 = Ctx()
    g8.check()
    assert g8.report.terminal
    g8.mark_unexecutable(ctx8)
    assert ctx8._cache.get("boundary_block", {}).get("kind") == "mid_scan_ban", \
        "终态必须写入 boundary_block，否则后续项会被当成正常执行"
    _done("✓ 自测 8：终态写入上下文，后续检查项短路为「未执行」")

    # --- 自测 9：降速作用到客户端且不指数衰减 ---
    class Cli:
        rps = 20.0

    c9 = Cli()
    g9 = BoundaryGuard(FakeFetch([(200, HOME)]), sleep=fake_sleep)
    g9.arm("https://i.test/", 200, HOME)
    g9.report.speed_factor = 0.5
    r1 = g9.apply_speed(c9)
    g9.report.speed_factor = 0.25
    r2 = g9.apply_speed(c9)
    assert abs(r1 - 10.0) < 1e-6 and abs(r2 - 5.0) < 1e-6, \
        f"降速应相对原始速率计算，实为 {r1} / {r2}"
    _done("✓ 自测 9：降速相对原始速率计算（0.5→10rps，0.25→5rps）")

    # --- 自测 10：报告措辞必须显式承认「不得据此认为通过」---
    f10 = FakeFetch([(403, BLOCK)])
    g10 = BoundaryGuard(f10, sleep=fake_sleep, budget_s=50.0)
    g10.arm("https://j.test/", 200, HOME)
    g10.check()
    s10 = g10.report.summary()
    assert "未执行" in g10.report.terminal_reason and "不得据此认为通过" in g10.report.terminal_reason, \
        "终态理由必须明确禁止把未执行当通过"
    assert "边界封禁" in s10
    _done("✓ 自测 10：终态措辞明确禁止把「未执行」读成「通过」")

    # --- 自测 11：封禁窗口必须被记下来（消除假通过的前提）---
    slept.clear()

    class SeqFetch:
        """按调用次数返回不同响应，便于模拟「先正常后被封」。

        与 FakeFetch 一样返回**探针形状**的 dict —— 守门读的是
        `status` / `body_snippet` 字段，返回裸元组会被当成「取不到数」。
        """

        def __init__(self, normal, blocked_after: int):
            self.normal = normal
            self.blocked_after = blocked_after
            self.n = 0

        def __call__(self, url):
            self.n += 1
            status, body = (self.normal if self.n <= self.blocked_after
                            else (403, BLOCK))
            return {"status": status, "body_snippet": body, "headers": {},
                    "cookies": []}

    f11 = SeqFetch((200, HOME), 2)
    g11 = BoundaryGuard(f11, sleep=fake_sleep, budget_s=50.0)
    g11.arm("https://k.test/", 200, HOME)
    assert g11.tick(100) is None, "此时应仍是正常响应"
    assert g11.clean_probe_at == 100, f"干净抽检后窗口左端点应为 100，实为 {g11.clean_probe_at}"
    ev11 = g11.tick(130)
    assert ev11 is not None, "目标已被封，抽检必须检出"
    assert ev11.window == (100, 130), f"窗口应为 (100, 130]，实为 {ev11.window}"
    assert g11.report.suspect_ranges() == [(100, 130)]
    assert any("探测 100–130" in n for n in g11.report.notes), \
        "窗口必须写进 notes（否则没人知道该怀疑哪一段）"
    _done("✓ 自测 11：封禁窗口 (100, 130] 被记录并写入说明")

    # --- 自测 12：窗口相交判定必须是闭区间语义，不能误伤窗口外的项 ---
    assert g11.is_contaminated(120, 130), "完全落在窗口内的项应判被污染"
    assert g11.is_contaminated(95, 105), "与窗口部分相交的项应判被污染"
    assert not g11.is_contaminated(0, 100), "窗口左端点之前的项不得被判污染"
    assert not g11.is_contaminated(131, 200), "窗口之后的项不得被判污染"
    _done("✓ 自测 12：窗口相交判定精确到端点，窗口外的结论不被误伤")

    # --- 自测 13：可疑迹象必须提前触发抽检，但有下限防风暴 ---
    counted = {"checks": 0}

    class CountFetch:
        def __init__(self):
            self.n = 0

        def __call__(self, url):
            counted["checks"] += 1
            self.n += 1
            # 抽检结果是干净的（同样是探针形状）
            return {"status": 200, "body_snippet": HOME, "headers": {},
                    "cookies": []}

    g13 = BoundaryGuard(CountFetch(), sleep=fake_sleep)
    g13.arm("https://l.test/", 200, HOME)
    g13.tick(0)
    before = g13.report.checks
    # 同一个 URL 反复返回同一张 403 页 —— 不算可疑（应用自己的鉴权就这样）
    g13.note_response("https://l.test/admin", 403, BLOCK, probe_count=10)
    g13.note_response("https://l.test/admin", 403, BLOCK, probe_count=12)
    assert g13.report.checks == before, \
        "同一 URL 上的 403 不得触发抽检（否则每次目录枚举都要多打两枪）"
    assert g13.report.suspicion_checks == 0
    # 换成第二个不同 URL 返回同一张非基线 403 页 —— 这才是「边缘开始接管」
    ev13 = g13.note_response("https://l.test/manage", 403, BLOCK, probe_count=15)
    assert g13.report.checks == before + 1, "两个不同 URL 返回同一张拦截页应立刻抽检"
    assert g13.report.suspicion_checks == 1
    assert ev13 is None, "抽检结果是干净的，不该产出封禁事件"
    assert g13.clean_probe_at == 15, "干净抽检后窗口左端点应前移"
    # 紧接着第三个 URL —— 距上次即时抽检不足下限，必须压住
    g13.note_response("https://l.test/console", 403, BLOCK, probe_count=18)
    assert g13.report.suspicion_checks == 1, \
        "即时抽检必须有下限，否则会变成抽检风暴（用一个更贵的问题换掉原问题）"
    # 距上次超过下限后，新的可疑迹象应重新触发
    g13.note_response("https://l.test/ops", 403, BLOCK, probe_count=45)
    assert g13.report.suspicion_checks == 2, "越过下限后新的可疑迹象应重新触发抽检"
    _done("✓ 自测 13：可疑迹象提前触发抽检（≥2 个不同 URL），且有下限防风暴")

    # --- 自测 14：不算可疑的情形必须真的不算 ---
    g14 = BoundaryGuard(FakeFetch([(200, HOME)]), sleep=fake_sleep)
    g14.arm("https://m.test/", 200, HOME)
    g14.note_response("https://m.test/a", 200, "<html>别的页面</html>", probe_count=10)
    assert g14.report.suspicion_checks == 0, "非拦截区间状态码不得触发抽检"
    g14.note_response("https://m.test/b", 403, HOME, probe_count=11)
    assert g14.report.suspicion_checks == 0, \
        "正文与基线页相同不得触发抽检（同一张页在不同状态码下出现≠被封）"
    _done("✓ 自测 14：非拦截状态码与「就是基线页本身」都不触发抽检")

    # --- 自测 15：作废动作量必须进摘要（否则没人知道假通过被清掉了多少）---
    g11.report.invalidated_items = 7
    g11.report.annotated_items = 2
    s15 = g11.report.summary()
    assert "7 个检查项" in s15 and "待确认" in s15, "摘要必须披露被改判的项数"
    assert "2 个" in s15, "被标注的「不通过」项数也要披露"
    d15 = g11.report.to_dict()
    assert d15["suspect_windows"] == [[100, 130]] and d15["invalidated_items"] == 7, \
        "窗口与作废数必须落盘（批量统计只看 JSON）"
    _done("✓ 自测 15：封禁窗口与被改判项数进入摘要与落盘数据")

    # --- 自测 16：退避等待必须有进度输出（否则看上去就是卡死）---
    # 实测事故：内部生产系统 扫到 nuclei 结束后触发封禁守门，退避等待最长 600s 且
    # **全程无输出**，操作者据此判断「扫描卡死了」并中断。等待不是错，藏起来才是。
    class _RecProg:
        """记录 note 与 activity 的假进度器。"""

        def __init__(self):
            self.notes = []
            self.acts = []

        def note(self, text):
            self.notes.append(text)

        def activity(self, label, detail="", interval_s=20.0):
            self.acts.append((label, detail))
            out = self

            class _C:
                def __enter__(self_c):
                    return self_c

                def __exit__(self_c, *exc):
                    return False

            return _C()

    _rp = _RecProg()
    g16 = BoundaryGuard(FakeFetch([(403, BLOCK)]), sleep=fake_sleep,
                        progress=_rp)
    g16.arm("https://p.test/", 200, HOME)
    assert g16.check() is not None, "自测 16：应判定为封禁"
    assert _rp.acts, "退避等待必须报一个「活动」（含心跳），不能全程静默"
    assert any("退避" in n for n in _rp.notes), "退避开始/结束必须留下说明行"
    assert any("不是卡死" in n for n in _rp.notes), \
        "退避说明必须点明「期间会静默等待，不是卡死」—— 这正是被误判成挂死的地方"
    assert any("总预算" in n for n in _rp.notes), "必须说出预算是多少，读者才知道要等多久"
    _done("✓ 自测 16：封禁退避等待输出进度与预算（不再静默）")

    # 进度器故障不得影响守门本身
    class _BadProg:
        def note(self, text):
            raise RuntimeError("进度坏了")

        def activity(self, *a, **kw):
            raise RuntimeError("进度坏了")

    g17 = BoundaryGuard(FakeFetch([(403, BLOCK)]), sleep=fake_sleep,
                        progress=_BadProg())
    g17.arm("https://q.test/", 200, HOME)
    assert g17.check() is not None, "进度器抛异常不得吞掉封禁判定"
    _done("✓ 自测 17：进度器故障不得影响守门判定")

    # --- 自测 18：拦截页厂商必须结构化落盘并能回填到报告 ---
    # 事故（2026-09-29 内部生产系统）：厂商名命中了（errors.aliyun.com），但只被拼进
    # 日志消息字符串，报告层取不到，只能写「厂商特征未确认」。
    # 「证据在手上却没接到消费方」与「没探到」是两回事，必须分开守。
    ALIYUN = ("<html><head><title>405</title></head><body><h1>405 Not Allowed</h1>"
              "<p>访问被拦截，详情见 <a href='https://errors.aliyun.com'>"
              "errors.aliyun.com</a></p></body></html>")
    f18 = FakeFetch([(405, ALIYUN)])
    g18 = BoundaryGuard(f18, sleep=fake_sleep, budget_s=1000.0)
    g18.arm("https://r.test/", 200, HOME)
    ev18 = g18.check()
    assert ev18 is not None and ev18.outcome == "persistent", \
        f"应判 persistent，实为 {ev18}"
    assert not ev18.recovered
    assert ev18.vendor == "阿里云 WAF", f"事件必须带厂商，实为 {ev18.vendor!r}"
    assert g18.report.vendor == "阿里云 WAF", "报告层要能直接取到厂商（不许解析文本）"
    assert ev18.to_dict()["vendor"] == "阿里云 WAF", "事件落盘 JSON 必须含厂商"
    assert g18.report.to_dict()["vendor"] == "阿里云 WAF", "整场记录落盘 JSON 必须含厂商"

    class Ctx18:
        _cache: dict = {}

    ctx18 = Ctx18()
    g18.mark_unexecutable(ctx18)
    _blk18 = ctx18._cache.get("boundary_block") or {}
    assert _blk18.get("vendor") == "阿里云 WAF", \
        "短路标记必须带厂商 —— 报告「探测到的防护」直接读它"
    assert int(_blk18.get("status") or 0) == 405, "短路标记要带拦截页状态码"
    _done("✓ 自测 18：拦截页厂商结构化落盘（事件 / 记录 / 短路标记三处都带）")

    # --- 自测 19：「不再抽检」≠「不再被封」（终态是持续状态）---
    # 事故（2026-09-29 内部生产系统）：terminal 之后 tick() 恒返回 None，注册表里
    # 唯一那句门控跟着失效，全量检查项在 405 拦截页上全部跑完（73 项假通过）。
    f19 = FakeFetch([(403, BLOCK)])
    g19 = BoundaryGuard(f19, sleep=fake_sleep, budget_s=50.0)
    g19.arm("https://s.test/", 200, HOME)
    assert g19.currently_blocked() is False, "未封禁时不得报「仍在封禁中」"
    g19.check()
    assert g19.report.terminal, "本轮应转入终态"
    assert g19.currently_blocked() is True, \
        "终态后必须能持续问到「仍在封禁中」—— 门控靠这个判断，不是靠 tick 的返回值"
    _calls19 = len(f19.calls)
    assert g19.tick(10 ** 6) is None, "终态后不再发抽检请求"
    assert len(f19.calls) == _calls19, \
        "终态后 tick 不得再打请求（省自己的时间，也省对方的容忍度）"
    assert g19.currently_blocked() is True, \
        "「不再抽检」与「不再被封」是两件事：状态查询仍必须为真"

    # 负向：清掉终态标记后，状态查询必须跟着变假 —— 否则它是写死的 True
    g19.report.terminal = False
    assert g19.currently_blocked() is False, \
        "currently_blocked 必须真的读状态，不许写死"
    _done("✓ 自测 19：终态=持续状态，不抽检但门控照常生效（含负向验证）")

    # --- 自测 20：恢复过的封禁不得被当成「此刻仍被封」---
    # 封过又恢复是常见情形（降速后继续跑）。若把「发生过」当成「仍被封」，
    # 整轮剩下的检查项会被全部误判成「未执行」—— 又是一种用错误替换错误。
    slept.clear()
    f20 = FakeFetch([(405, BLOCK), (405, BLOCK), (200, HOME), (200, HOME)])
    g20 = BoundaryGuard(f20, sleep=fake_sleep)
    g20.arm("https://t.test/", 200, HOME)
    ev20 = g20.check()
    assert ev20 is not None and ev20.outcome == "resumed"
    assert g20.report.occurred, "发生过封禁要如实记录"
    assert g20.currently_blocked() is False, \
        "已恢复的封禁不得报「仍在封禁中」—— 否则后续检查项会被误短路成未执行"
    _done("✓ 自测 20：已恢复的封禁不报「仍在封禁中」（发生 ≠ 持续）")

    # ==================================================================
    # TargetHealthWatch（hard_limits.stop_on 的执行体）
    # 正向与**反向**都要测：反误报限定只写在注释里就等于没有 ——
    # 少测反向，判据会在正常扫描里误停，比不实现更坏。
    # ==================================================================
    class _H:
        """最小可用上下文：只需要一个 `_cache`。"""
        def __init__(self):
            self._cache = {}

    def _primed(*urls: str) -> TargetHealthWatch:
        """造一个「这些地址本轮已经正常过」的守门。

        为什么要先喂一遍 200：故障判据现在只认**已知正常**地址上的 5xx。
        直接用没见过的地址喂 5xx，等于拿「枚举噪声」当故障证据 ——
        那正是第 15 轮连撞两次的根因。
        """
        h = TargetHealthWatch()
        for u in urls:
            h.note_response(u, 200)
        return h

    # --- 自测 21：连续 5xx 跨 ≥2 个 URL → 立即停手 ---
    h21 = _primed(*(f"https://p.test/a{i}" for i in range(10)))
    for i in range(9):
        assert h21.note_response(f"https://p.test/a{i}", 500) == "", \
            f"第 {i + 1} 次 5xx 不该停手（阈值 {HEALTH_5XX_STREAK} 次）"
    assert not h21.terminal, "未达阈值不得停手"
    _r21 = h21.note_response("https://p.test/a9", 503)
    assert h21.terminal, "连续满 10 次 5xx 必须停手"
    assert h21.kind == "http_5xx_streak"
    assert "连续" in _r21 and "5xx" in _r21
    assert "未执行" in _r21, "停手理由必须写清后续项按「未执行」处理"
    assert "拦截页" in _r21, \
        "必须带上「若同期有拦截，5xx 也可能来自拦截页」的双向读数 —— 否则会写成单一成因"
    _done("✓ 自测 21：连续 10 次 5xx（跨 ≥2 个 URL）→ 立即停手并给具名理由")

    # --- 自测 22：同一个 URL 反复 5xx **不**停手（反误报核心）---
    # 目录枚举反复打到同一个坏接口，会连续凑出一串 5xx；它说明「那个接口坏了」，
    # 不是「整站被压挂」。少了这道闸，正常扫描会被误停。
    h22 = _primed("https://q.test/broken")
    for _ in range(30):
        assert h22.note_response("https://q.test/broken", 500) == "", \
            "同一 URL 反复 5xx 不得触发停手（那是单个坏接口，不是整站故障）"
    assert not h22.terminal
    _done("✓ 自测 22：同一 URL 反复 5xx 不停手（单个坏接口 ≠ 整站被打挂）")

    # --- 自测 23：中间夹一个非 5xx → 连续计数清零 ---
    h23 = _primed(*(f"https://r.test/a{i}" for i in range(9)))
    for i in range(9):
        h23.note_response(f"https://r.test/a{i}", 500)
    h23.note_response("https://r.test/ok", 200)      # 清零
    assert h23._streak == 0, "非 5xx 必须把连续计数清零"
    _r23 = h23.note_response("https://r.test/b1", 500)
    assert _r23 == "" and not h23.terminal, \
        "清零后只累计到 1 次，不得停手 —— 否则「连续」二字形同虚设"
    _done("✓ 自测 23：非 5xx 打断连续计数（「连续」必须真的连续）")

    # --- 自测 24：响应时间突增需连续 3 次、超 10 倍、且 ≥0.8s ---
    h24 = TargetHealthWatch()
    for _ in range(HEALTH_BASELINE_SAMPLES):
        h24.note_response("https://s.test/x", 200, 100)   # 基线 100ms
    assert abs(h24._baseline_s - 0.1) < 1e-6, \
        f"基线应取前 {HEALTH_BASELINE_SAMPLES} 次的耗时，实得 {h24._baseline_s}"
    # 9 倍（未达 10 倍）→ 不得触发
    assert h24.note_response("https://s.test/x", 200, 900) == "", \
        "9 倍未达 10 倍阈值，不得触发"
    assert h24._latency_streak == 0, "未达阈值必须清零突增计数"
    # 单次 20 倍 → 不够（要连续 3 次）
    assert h24.note_response("https://s.test/x", 200, 2000) == ""
    assert h24.note_response("https://s.test/x", 200, 2000) == ""
    assert not h24.terminal, "只连续 2 次不得停手"
    _r24 = h24.note_response("https://s.test/x", 200, 2000)
    assert h24.terminal and h24.kind == "latency_spike", "连续 3 次超阈值必须停手"
    assert "基线中位数" in _r24 and "未执行" in _r24
    _done("✓ 自测 24：响应时间突增（>10 倍且连续 3 次）才停手，9 倍与 2 次都不触发")

    # --- 自测 25：基线用中位数 —— 不许被后期慢响应「适应」掉 ---
    # 若基线改用均值且随样本累积重算，判据会被自己观测到的慢响应慢慢抬高，
    # 最终**永远不触发**（看起来「从来没误报」，实际是从来没报）。
    h25 = TargetHealthWatch()
    for _ in range(HEALTH_BASELINE_SAMPLES):
        h25.note_response("https://u.test/x", 200, 100)
    _b25 = h25._baseline_s
    for _ in range(5):
        h25.note_response("https://u.test/x", 200, 50_000)   # 大量慢响应
    assert abs(h25._baseline_s - _b25) < 1e-9, \
        "基线一旦定型就不得被后续慢响应抬高（否则判据会静默失效）"
    _done("✓ 自测 25：延迟基线取中位数且定型后不漂移（防「判据自我适应」）")

    # --- 自测 26：快站点不得被豁免突增判定 ---
    # 曾把基线下限设成 20ms，结果是基线 5ms 的站点**整体不判突增**：
    # 5ms → 5s（1000 倍）也不停手。毫秒级抖动由绝对值下限 0.8s 挡住，
    # 不需要再设一道「基线太小的站点不判」的门槛。
    h26 = TargetHealthWatch()
    for _ in range(HEALTH_BASELINE_SAMPLES):
        h26.note_response("https://v.test/x", 200, 5)      # 基线 5ms
    for _ in range(10):
        h26.note_response("https://v.test/x", 200, 200)    # 40 倍，但绝对值仅 200ms
    assert not h26.terminal, \
        "绝对值 <0.8s 的抖动不得判故障（倍数高 ≠ 有故障）"
    for _ in range(HEALTH_LATENCY_STREAK):
        h26.note_response("https://v.test/x", 200, 5000)   # 5s，绝对值远超下限
    assert h26.terminal, \
        "基线 5ms 的站点变慢到 5s（1000 倍）必须判故障 —— 快站点不得被豁免"
    _done("✓ 自测 26：抖动不触发，但快站点严重变慢照样触发（不豁免）")

    # --- 自测 27：短路标记写独立通道，措辞与「被拦截」严格区分 ---
    # 复用 boundary_block 会让报告写出「请求未到达应用」——
    # 而事实是请求**到了**、应用自己在报错。那是写假话，比不给结论更坏。
    h27 = _primed(*(f"https://w.test/p{i}" for i in range(HEALTH_5XX_STREAK)))
    for i in range(HEALTH_5XX_STREAK):
        h27.note_response(f"https://w.test/p{i}", 502)
    c27 = _H()
    h27.mark_unexecutable(c27)
    assert "target_unhealthy" in c27._cache, "必须写独立键 target_unhealthy"
    assert "boundary_block" not in c27._cache, \
        "不得写进 boundary_block —— 两者报告措辞不同，混用即写假话"
    assert c27._cache["target_unhealthy"]["kind"] == "http_5xx_streak"
    # 幂等：逐项门控每个检查项都会问一次
    h27.mark_unexecutable(c27)
    assert h27.terminal, "重复调用不得改变状态"
    # 未触发时不得写任何标记
    h27b = TargetHealthWatch()
    c27b = _H()
    h27b.mark_unexecutable(c27b)
    assert not c27b._cache, "未触发停手时不得写短路标记"
    _done("✓ 自测 27：停手写独立通道 target_unhealthy，不与「被拦截」混用")

    # --- 自测 28：停手后不再累计、不再改判（终态是终态）---
    h28 = _primed(*(f"https://z.test/p{i}" for i in range(HEALTH_5XX_STREAK)))
    for i in range(HEALTH_5XX_STREAK):
        h28.note_response(f"https://z.test/p{i}", 500)
    assert h28.terminal
    _r28a = h28.reason
    h28.note_response("https://z.test/ok", 200)
    h28.note_response("https://z.test/ok2", 200)
    assert h28.terminal and h28.reason == _r28a, \
        "停手之后收到正常响应也不得撤销结论（那会让报告与处置不一致）"
    _done("✓ 自测 28：停手为终态，恢复正常响应也不撤销")

    # --- 自测 29：判据达标但**入口仍存活** → 判局部报错，降速继续，不整轮作废 ---
    # 2026-10-10 实测教训：Juice Shop 基准连撞两次，连续 10 次 5xx、跨 10 个
    # 不同 URL，判据**全部达标**，于是后续 87 项整批记「未执行」，整轮召回
    # 从 52.5% 塌到 12.5%；事后手工复现同一批地址几乎全是 200。
    # 「连续 5xx」证明的是「这批探测在报错」，证明不了「整站被压挂」——
    # 老红队遇到这种情况是打一枪首页看还活着没，而不是收工。
    h29 = _primed(*([f"https://alive.test/p{i}" for i in range(HEALTH_5XX_STREAK)]
                    + [f"https://alive.test/q{i}" for i in range(HEALTH_5XX_STREAK)]))
    h29.confirm_url = "https://alive.test/"
    h29._confirm_fn = lambda u: 200
    for i in range(HEALTH_5XX_STREAK):
        assert h29.note_response(f"https://alive.test/p{i}", 500) == "", \
            "入口确认仍存活时不得停手（局部报错 ≠ 整站故障）"
    assert not h29.terminal, \
        "入口返回 200 说明站还活着 —— 判为局部报错，不该整轮作废"
    assert len(h29.reprieves) == 1, "必须留痕一次宽免（报告要能说出为什么没停）"
    assert h29.reprieves[0]["confirm_status"] == 200
    assert h29.reprieves[0]["alive"] is True
    assert h29.reprieves[0]["samples"], "宽免证据必须带上触发样本"
    assert h29.slowdown_requested, "宽免后必须请求降速（继续扫，但不能按原速率压）"
    assert h29._streak == 0, "宽免后连续计数必须清零，否则下一环立刻再触发"
    # 宽免只有一次：第二次达标即硬停，避免「确认—继续—再确认」把门架空
    for i in range(HEALTH_5XX_STREAK):
        h29.note_response(f"https://alive.test/q{i}", 500)
    assert h29.terminal, "宽免用尽后再次达标必须硬停（每轮只宽免一次）"
    assert "触发样本" in h29.reason, \
        "停手结论必须带上「是哪几个 URL 在 500」—— 否则读者无从判断真假"
    _done("✓ 自测 29：入口仍存活 → 判局部报错、降速继续（每轮只宽免一次）")

    # --- 自测 30：确认那一枪也 5xx → 照旧立即硬停 ---
    h30 = _primed(*(f"https://down.test/p{i}" for i in range(HEALTH_5XX_STREAK)))
    h30.confirm_url = "https://down.test/"
    h30._confirm_fn = lambda u: 503
    for i in range(HEALTH_5XX_STREAK):
        h30.note_response(f"https://down.test/p{i}", 500)
    assert h30.terminal, "入口确认也挂了，必须照旧立即停手"
    assert h30.reprieves[0]["alive"] is False
    _done("✓ 自测 30：确认也 5xx → 照旧立即停手（宽免不得架空保护）")

    # --- 自测 31：没有确认通道 → 保持原行为（立即停手）---
    # 拿不到确认手段时**不许**猜「大概还活着」。取不到 = 不能证明活着 = 停。
    h31 = _primed(*(f"https://nocfn.test/p{i}" for i in range(HEALTH_5XX_STREAK)))
    for i in range(HEALTH_5XX_STREAK):
        h31.note_response(f"https://nocfn.test/p{i}", 500)
    assert h31.terminal, "无确认通道时必须退回硬停（不猜）"
    assert not h31.reprieves, "没有确认通道就不得记录宽免"
    _done("✓ 自测 31：无确认通道 / 确认异常 → 退回硬停，不猜「还活着」")

    # --- 自测 32：首次枚举到的路径返 5xx 只计噪声，不得入故障判据 ---
    # 这是第 15 轮连撞两次的根因：目录枚举打到**根本不存在**的 /api/* 路径，
    # 靶场对未定义路由抛异常返 500，于是凑出「连续 10 次、跨 10 个 URL」。
    # 那道「跨 ≥2 个 URL」的闸挡不住枚举 —— 枚举天然就跨很多 URL。
    # 有效判据只能是「**本来正常**的地址开始报错」。
    h32 = TargetHealthWatch()
    for i in range(50):
        assert h32.note_response(f"https://enum.test/guess{i}", 500) == "", \
            "首次枚举到的路径返 5xx 属预期噪声，不得计入故障判据"
    assert not h32.terminal, "枚举噪声不得触发停手（否则每次枚举都会停）"
    assert h32.noise_5xx == 50, \
        f"噪声必须被如实计数并披露（实得 {h32.noise_5xx}）"
    # 已知正常的地址开始报错 → 立刻计入故障判据（需跨 ≥2 个 URL）
    h32.note_response("https://enum.test/known-a", 200)
    h32.note_response("https://enum.test/known-b", 200)
    _urls = (["https://enum.test/known-a", "https://enum.test/known-b"]
             * HEALTH_5XX_STREAK)
    for i, u in enumerate(_urls[:HEALTH_5XX_STREAK]):
        h32.note_response(u, 500)
    assert h32.terminal and h32.kind == "http_5xx_streak", \
        "本来正常的地址连续报错 → 必须判故障（枚举噪声不得洗掉真故障）"
    _done("✓ 自测 32：枚举噪声不入判据，已知正常地址报错才判故障")

    # --- 自测 33：loopback 目标触发健康度守门但仅记录、不主动停手 ---
    # 本地自有靶场（Juice Shop 基准）：守门职责是「别把**对方**服务器打挂」，
    # 对回环地址不适用。冷启动时延迟突增会被判据命中，但若因此「立即停手」，
    # 后续约 90% 的检查项会被记成「未执行」，整轮召回塌成个位数（实测第 30 轮）。
    # 故 loopback 触发时：记录异常、继续扫描，不写未执行、不短路后续项。
    h33 = TargetHealthWatch(loopback=True)
    for _ in range(HEALTH_BASELINE_SAMPLES):
        assert h33.note_response("http://localhost:3000/x", 200, 100) == ""
    for _ in range(HEALTH_LATENCY_STREAK):
        assert h33.note_response("http://localhost:3000/x", 200, 2000) == "", \
            "loopback 目标不得返回停手原因"
    assert not h33.terminal, \
        "loopback 目标不得进入终态（否则后续项会被判未执行，整轮召回塌方）"
    assert h33.loopback_suppressed, \
        "loopback 触发必须标记 loopback_suppressed（报告据以说明）"
    assert h33.kind == "latency_spike"
    # 继续喂正常响应也不撤销、不短路
    assert h33.note_response("http://localhost:3000/ok", 200, 50) == ""
    assert not h33.terminal
    _d33 = h33.to_dict()
    assert _d33["loopback_suppressed"] is True and _d33["stopped"] is False
    # 独立通道不得写入（loopback 不短路）
    class _H33:
        _cache: dict = {}
    _c33 = _H33()
    h33.mark_unexecutable(_c33)
    assert not _c33._cache, "loopback 触发不得写短路标记（否则后续项判未执行）"
    _done("✓ 自测 33：loopback 目标触发健康度守门但仅记录、不主动停手（继续扫描）")

    # --- 自测 33b：loopback 连续 5xx 同样仅记录、不主动停手（记录真实成因）---
    h33b = TargetHealthWatch(loopback=True)
    for i in range(HEALTH_5XX_STREAK):
        h33b.note_response(f"http://127.0.0.1/p{i}", 200)
    # 在**已知正常**的同一批地址上连续返 5xx —— 这才是故障判据认的「本来好用的
    # 地址开始报错」。换新地址会被判为枚举噪声、不计入故障判据（自测 32 已覆盖）。
    for i in range(HEALTH_5XX_STREAK):
        assert h33b.note_response(f"http://127.0.0.1/p{i}", 500) == "", \
            "loopback 连续 5xx 不得停手"
    assert not h33b.terminal and h33b.loopback_suppressed
    assert h33b.kind == "http_5xx_streak", "loopback 5xx 也要记真实成因"
    _done("✓ 自测 33b：loopback 连续 5xx 同样仅记录、不主动停手（记录真实成因）")

    print(f"\n全部 {_ran[0]} 项断言通过。")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
