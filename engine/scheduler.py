# -*- coding: utf-8 -*-
"""
周期化扫描 —— 调度
====================
`targets.yaml` 里的 `schedule` 段定义「什么时候扫哪些目标」。本模块只做三件事：

  1. **判定「到点了没有」**（`decide`）；
  2. **记住「这个周期已经扫过了」**（状态文件），保证同一周期绝不重复扫；
  3. **把该说清的事说清**：为什么扫、为什么不扫、哪些结果已经过期。

**为什么「为什么没扫」和「扫了什么」一样重要**

调度器最典型的失效形态是**静默不出勤**：cron 表达式写错、状态文件里留了个
错误的时间戳、或者 `enabled` 忘了改 —— 结果是扫描周期性地不执行，而没有任何
迹象。等到某天想起「上周的扫描报告呢」，已经过去一个月。

所以本模块的红线是：

  · **cron 表达式解析不了必须抛错**，绝不静默判「不到期」。
    静默判 False = 扫描永远不执行，且不报错 —— 比报错糟糕得多。
  · **每个目标的判定结果都要带原因**（到点 / 未到点 / 模式不支持 / 已跳过），
    供 CLI 打印与落盘；不允许只输出「本次不执行」。
  · **历史归档只清点、不删除**。保留期到了只列出，删除是破坏性动作，
    交给人确认 —— 自动删历史扫描结果没有任何可接受的失败模式。

**时间基准**

`now` 一律可注入（自测与回放用），默认取本机时间。周期键按**本机时区**计算，
所以跨时区部署时「日报」对应的是本机日期，不是 UTC 日期。
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: 支持的周期模式。`manual` 表示不自动执行（由人触发）。
MODES = ("manual", "daily", "weekly", "monthly")

#: 状态文件名（放在归档根目录下，跟着扫描结果一起走）。
STATE_FILE_NAME = ".schedule_state.json"

#: cron 支持的最小字段数（标准 5 段：分 时 日 月 周）。
#: **不支持**秒级、`@reboot`、`L`/`W`/`#` 这类扩展 —— 与其猜着解析，
#: 不如明确报错。猜错的方向恰好是「永远不跑」。
CRON_FIELDS = 5

_CRON_TOKEN = re.compile(r"^(\*|\d+|\*/\d+|\d+-\d+|\d+-\d+/\d+|\d+(?:,\d+)*)$")


def _cron_field_range(idx: int) -> tuple[int, int]:
    return [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)][idx]


def _parse_cron_field(token: str, idx: int, expr: str) -> set[int]:
    """解析 cron 的单个字段。**不支持的写法一律抛错。**"""
    lo, hi = _cron_field_range(idx)
    if not _CRON_TOKEN.match(token):
        raise ValueError(
            f"cron 表达式不支持的写法：{expr!r} 的第 {idx + 1} 段 {token!r}"
            "（仅支持 * / 数字 / a-b / */n / a-b/n / 逗号列表）")
    out: set[int] = set()
    for part in token.split(","):
        if part == "*":
            out.update(range(lo, hi + 1))
            continue
        step = 1
        if "/" in part:
            base, _, s = part.partition("/")
            step = int(s)
            if step <= 0:
                raise ValueError(f"cron 步长必须为正数：{expr!r}")
            part = base or "*"
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, _, b = part.partition("-")
            start, end = int(a), int(b)
        else:
            start = end = int(part)
        if start < lo or end > hi or start > end:
            raise ValueError(
                f"cron 字段取值越界：{expr!r} 的第 {idx + 1} 段 {token!r}"
                f"（合法范围 {lo}-{hi}）")
        out.update(range(start, end + 1, step))
    return out


def cron_matches(expr: str, now: datetime) -> bool:
    """判断某个时刻是否命中 cron 表达式。表达式非法时抛 ValueError。"""
    fields = (expr or "").split()
    if len(fields) != CRON_FIELDS:
        raise ValueError(
            f"cron 表达式应为 {CRON_FIELDS} 段（分 时 日 月 周），"
            f"实际 {len(fields)} 段：{expr!r}")
    minute, hour, dom, mon, dow = (
        _parse_cron_field(f, i, expr) for i, f in enumerate(fields))
    if now.minute not in minute or now.hour not in hour or now.month not in mon:
        return False
    # cron 语义：日与周都受限时取「或」，否则取「与」。
    # 取反会让「每周日」在「每月 1 号也是周日」之外的日子完全不触发。
    dom_restricted = fields[2] != "*"
    dow_restricted = fields[4] != "*"
    dom_ok = now.day in dom
    dow_ok = now.weekday() + 1 in dow or (now.weekday() == 6 and 0 in dow)
    if dom_restricted and dow_restricted:
        return dom_ok or dow_ok
    return dom_ok and dow_ok


def period_key(mode: str, cron: str, now: datetime) -> str:
    """本周期键。同一键值内不会重复执行 —— 这是调度幂等的依据。"""
    m = (mode or "manual").lower()
    if cron:
        return f"cron:{cron}@{now.strftime('%Y-%m-%d %H:%M')}"
    if m == "daily":
        return f"daily:{now.strftime('%Y-%m-%d')}"
    if m == "weekly":
        iso = now.isocalendar()
        return f"weekly:{iso[0]}-W{iso[1]:02d}"
    if m == "monthly":
        return f"monthly:{now.strftime('%Y-%m')}"
    return ""


@dataclass
class DueDecision:
    target: str
    due: bool
    reason: str
    period_key: str = ""
    last_run: str = ""
    run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "due": self.due, "reason": self.reason,
            "period_key": self.period_key, "last_run": self.last_run,
            "run_count": self.run_count,
        }


@dataclass
class Scheduler:
    """按 targets.yaml 的 schedule 段判定周期与状态。"""

    targets_path: Path
    state_path: Path | None = None
    now: Any = None                      # callable -> datetime，自测可注入
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.targets_path = Path(self.targets_path)
        self._now = self.now or datetime.now
        self.data: dict[str, Any] = {}
        self.schedule: dict[str, Any] = {}
        self.settings: dict[str, Any] = {}
        self.load_error = ""
        try:
            import yaml  # noqa: PLC0415

            self.data = yaml.safe_load(self.targets_path.read_text(encoding="utf-8")) or {}
            self.schedule = self.data.get("schedule") or {}
            self.settings = self.data.get("settings") or {}
        except Exception as e:  # noqa: BLE001
            # 读不了配置不能表现成「没有目标要扫」—— 那是静默不出勤。
            self.load_error = f"{type(e).__name__}: {str(e)[:160]}"
        if self.state_path is None:
            root = self.settings.get("output_root", "outputs")
            self.state_path = (self.targets_path.parent / root / STATE_FILE_NAME)
        self.state_path = Path(self.state_path)
        self._state: dict[str, Any] = self._read_state()

    # ------------------------------------------------------------------
    # 配置
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self.schedule.get("enabled"))

    @property
    def mode(self) -> str:
        return str(self.schedule.get("mode") or "manual").lower()

    @property
    def cron(self) -> str:
        return str(self.schedule.get("cron") or "").strip()

    @property
    def diff_enabled(self) -> bool:
        return bool(self.schedule.get("diff_enabled", True))

    @property
    def retention_days(self) -> int:
        try:
            return int(self.schedule.get("retention_days", 0) or 0)
        except (TypeError, ValueError):
            return 0

    def targets(self) -> list[dict[str, Any]]:
        return list(self.data.get("targets") or [])

    def config_errors(self) -> list[str]:
        """配置层面的问题。**必须在执行前暴露**，不能等到「没目标」才发现。"""
        out = list(self.errors)
        if self.load_error:
            out.append(f"targets.yaml 读取失败：{self.load_error}")
            return out
        if self.mode not in MODES and not self.cron:
            out.append(f"schedule.mode 取值非法：{self.mode!r}"
                       f"（合法值 {'/'.join(MODES)}，或改用 cron）")
        if self.cron:
            try:
                cron_matches(self.cron, self._now())
            except ValueError as e:
                # 这一条是整套机制里最关键的一条：表达式错 = 永远不跑，
                # 而且不报错就没人知道。宁可让调度停下，也不静默不出勤。
                out.append(f"schedule.cron 无法解析：{e}")
        return out

    # ------------------------------------------------------------------
    # 状态
    # ------------------------------------------------------------------
    def _read_state(self) -> dict[str, Any]:
        try:
            if self.state_path.exists():
                return json.loads(self.state_path.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            # 状态损坏时会「重复扫一遍」而不是「不扫」—— 这个方向的失败可接受，
            # 但必须说出来，否则运维看到重复扫描找不到原因。
            self.errors.append(f"调度状态文件损坏（{type(e).__name__}），"
                               "已按「无历史」处理，本周期可能重复执行一次")
        return {}

    def save_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps(self._state, ensure_ascii=False, indent=2),
                encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            # 写不进状态 → 下一个周期会重复扫。必须报出来。
            self.errors.append(f"调度状态写入失败（{type(e).__name__}: {str(e)[:120]}）："
                               "同一周期可能被重复执行")

    def _entry(self, target_name: str) -> dict[str, Any]:
        return (self._state.get("targets") or {}).get(target_name) or {}

    def mark_ran(self, target_name: str, now: datetime | None = None,
                 note: str = "", persist: bool = True) -> None:
        """登记「本周期已执行」。

        默认**立即落盘**：这条记录是防重复扫描的唯一凭据，靠调用方补一次
        save_state() 太脆 —— 中间崩一次，凭据就没了，同一个周期会被再扫一遍。
        persist=False 仅供自测在批量断言后统一保存。
        """
        ts = (now or self._now()).strftime("%Y-%m-%d %H:%M:%S")
        entry = dict(self._entry(target_name))
        entry.update({
            "last_ran": ts,
            "period_key": period_key(self.mode, self.cron, now or self._now()),
            "run_count": int(entry.get("run_count", 0)) + 1,
            "last_note": note,
        })
        self._state.setdefault("version", 1)
        self._state.setdefault("targets", {})[target_name] = entry
        if persist:
            self.save_state()

    # ------------------------------------------------------------------
    # 判定
    # ------------------------------------------------------------------
    def decide(self, target: dict[str, Any], now: datetime | None = None) -> DueDecision:
        now = now or self._now()
        name = target.get("name") or target.get("primary_domain") or "(未命名)"
        entry = self._entry(name)

        if not self.enabled:
            return DueDecision(name, False,
                               "schedule.enabled 为 false（周期化未启用）",
                               last_run=entry.get("last_ran", ""),
                               run_count=int(entry.get("run_count", 0)))
        if not (target.get("primary_domain") or target.get("base_url")):
            return DueDecision(name, False, "目标未登记 primary_domain / base_url")
        if not (target.get("authorization") or {}).get("authorizer"):
            # 没有授权人就是没有扫描依据 —— 不扫，并说清是缺授权而不是「不适用」。
            return DueDecision(name, False,
                               "目标未登记 authorization.authorizer（无授权依据）",
                               last_run=entry.get("last_ran", ""),
                               run_count=int(entry.get("run_count", 0)))

        key = period_key(self.mode, self.cron, now)
        if not key:
            if self.cron:
                # cron 已配置但当前这一分钟不匹配 —— 正常的「不到点」。
                pass
            return DueDecision(name, False,
                               "mode=manual（未配置 cron），周期化扫描未启用",
                               last_run=entry.get("last_ran", ""),
                               run_count=int(entry.get("run_count", 0)))

        if self.cron and not cron_matches(self.cron, now):
            # 注意：cron_matches 非法时抛错，这里只会拿到「语法正确但本次不匹配」。
            return DueDecision(name, False,
                               f"cron {self.cron} 当前时刻不匹配"
                               f"（{now.strftime('%Y-%m-%d %H:%M')}）",
                               period_key=key,
                               last_run=entry.get("last_ran", ""),
                               run_count=int(entry.get("run_count", 0)))

        if entry.get("period_key") == key:
            return DueDecision(name, False,
                               f"本周期（{key}）已执行过，不重复扫描",
                               period_key=key,
                               last_run=entry.get("last_ran", ""),
                               run_count=int(entry.get("run_count", 0)))

        return DueDecision(name, True,
                           f"到点（{key}）", period_key=key,
                           last_run=entry.get("last_ran", ""),
                           run_count=int(entry.get("run_count", 0)))

    def due(self, now: datetime | None = None) -> list[tuple[dict[str, Any], DueDecision]]:
        """列出所有目标及其判定（**包含不到点的**），供 CLI 如实打印。"""
        now = now or self._now()
        return [(t, self.decide(t, now)) for t in self.targets()]

    # ------------------------------------------------------------------
    # 保留期：只清点，不删除
    # ------------------------------------------------------------------
    def stale_archives(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """列出超过保留期的历史归档目录。**只列不删。**

        自动删除历史扫描结果是破坏性动作，而且失败模式完全不可接受
        （删错一个目录，历史比对基线就没了）。所以这里只清点，
        由人决定是否清理。
        """
        days = self.retention_days
        if days <= 0:
            return []
        root = self.targets_path.parent / str(self.settings.get("output_root", "outputs"))
        if not root.exists():
            return []
        now = now or self._now()
        out: list[dict[str, Any]] = []
        try:
            for d in sorted(root.iterdir()):
                if not d.is_dir() or d.name.startswith(("_", ".")):
                    continue
                mtime = datetime.fromtimestamp(d.stat().st_mtime)
                age = (now - mtime).days
                if age >= days:
                    out.append({"path": str(d), "age_days": age,
                                "mtime": mtime.strftime("%Y-%m-%d")})
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"保留期清点失败：{type(e).__name__}: {str(e)[:120]}")
        return out


# ==============================================================================
# 从扫描结果编通知摘要
# ==============================================================================
def summary_from_scan(res: Any, orch: Any = None, diff: Any = None,
                      scan_time: str = "") -> dict[str, Any]:
    """把一次扫描的产出编成通知用的摘要。

    **必须带上「没有结论」的部分**：只报发现数的摘要会把「26 项未执行」
    读成「其余都正常」—— 那是把假通过搬到了通知层。
    """
    counts = {}
    try:
        counts = dict((res.finding_set.counts() if res.finding_set else {}) or {})
    except Exception:  # noqa: BLE001
        counts = {}
    states = {}
    for r in (getattr(res, "item_results", None) or []):
        states[r.state] = states.get(r.state, 0) + 1
    states["合计"] = sum(v for k, v in states.items() if k != "合计")

    det = dict(getattr(res, "detector_summary", None) or {})
    boundary = getattr(orch, "_boundary", None) if orch is not None else None
    boundary_blocked = bool(getattr(boundary, "blocked", False)) or bool(
        det.get("采集充分度", {}).get("blocked"))

    objs: list[dict[str, Any]] = []
    for o in (getattr(orch, "_objectives", None) or []):
        objs.append({"label": getattr(o, "label", ""),
                     "result": getattr(o, "result", "")})

    diff_counts: dict[str, int] = {}
    if diff is not None:
        try:
            diff_counts = dict(diff.summary() or {})
        except Exception:  # noqa: BLE001
            diff_counts = {}

    reports = getattr(res, "reports", None) or {}
    nuc = dict(getattr(res, "nuclei_run", None) or {})
    # 覆盖被截断 = 本轮有一部分压根没跑完。通知里必须说，
    # 否则「零发现」会被读成「干净」。
    partial = bool(nuc.get("partial")) or bool(nuc.get("budget_exhausted"))
    if nuc.get("executed") and str(nuc.get("status") or "") == "timeout":
        partial = True
    # 没有比对 → 该字段「不适用」（None），不能伪造成 True；
    # 有比对但没拿到本轮结论 → False，通知必须提示「已修复」含未执行项。
    diff_state_known: bool | None = None
    if diff is not None:
        diff_state_known = bool(getattr(diff, "states_loaded", False))
    return {
        "target_name": getattr(res, "target_name", ""),
        "domain": getattr(res, "domain", ""),
        "scan_time": scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "profile": det.get("档位") or det.get("profile") or "",
        "counts": counts,
        "item_states": states,
        "retest_rate": float(det.get("可复测率", 0) or 0),
        "boundary_blocked": boundary_blocked,
        "partial": partial,
        # 比对没拿到本轮结论时，「已修复」里可能混着本轮没执行的项 ——
        # 通知必须能说出这一点，不能把脏数字当干净数字发出去。
        "diff_state_known": diff_state_known,
        "objectives": objs,
        "diff": diff_counts or None,
        "report_path": str(reports.get("technical") or
                           (getattr(res, "archive_dir", "") and
                            Path(getattr(res, "archive_dir")) / "报告") or ""),
        "archive_dir": str(getattr(res, "archive_dir", "")),
    }


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> int:
    import tempfile  # noqa: PLC0415

    problems: list[str] = []

    # ① cron 解析：合法写法要能匹配，非法写法必须抛错（不得静默判「不匹配」）
    d = datetime(2026, 9, 20, 2, 0)          # 周日
    checks = [
        ("0 2 * * 0", True), ("0 2 * * *", True), ("1 2 * * 0", False),
        ("*/15 * * * *", False if d.minute else True),
        ("0 2 1-30 * *", True), ("0 2 * 1,3,9 *", True), ("0 2 * 10 *", False),
        ("0 0-6/2 * * *", True),
    ]
    for expr, expect in checks:
        got = cron_matches(expr, d)
        if got != expect:
            problems.append(f"cron {expr!r} 在 {d} 的判定应为 {expect}，实际 {got}")
    for bad in ("0 2 * *", "0 2 * * mon", "60 2 * * 1", "0 25 * * *",
                "0 2 L * *", "0 2 * * #", "@reboot", "a b c d e"):
        try:
            cron_matches(bad, d)
            problems.append(f"非法 cron {bad!r} 未被拒绝 —— 静默判「不匹配」"
                            "等于扫描永远不执行且不报错")
        except ValueError:
            pass
    # 日是周日、同时限定「每月 1 号」时，取「或」语义
    if not cron_matches("0 2 1 * 0", datetime(2026, 9, 20, 2, 0)):
        problems.append("日与周同时受限时应取「或」语义（这是 cron 的约定）")

    # ② 周期键：同周期必须稳定，跨周期必须变化
    if period_key("daily", "", datetime(2026, 9, 20, 1, 0)) != \
            period_key("daily", "", datetime(2026, 9, 20, 23, 59)):
        problems.append("日报周期键同一天内必须一致（否则会重复扫）")
    if period_key("daily", "", datetime(2026, 9, 20)) == \
            period_key("daily", "", datetime(2026, 9, 21)):
        problems.append("日报周期键跨天必须变化（否则第二天不会扫）")
    if period_key("weekly", "", datetime(2026, 9, 20)) == \
            period_key("weekly", "", datetime(2026, 9, 27)):
        problems.append("周报周期键跨周必须变化")
    if period_key("monthly", "", datetime(2026, 9, 20)) == \
            period_key("monthly", "", datetime(2026, 10, 1)):
        problems.append("月报周期键跨月必须变化")
    if period_key("manual", "", d):
        problems.append("manual 模式不应产生周期键（否则会被当成到点）")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "outputs").mkdir()
        tpath = root / "targets.yaml"
        tpl = """
settings: {{profile: standard, output_root: outputs}}
schedule: {sched}
targets:
  - name: 甲系统
    primary_domain: a.example.com
    authorization: {{authorizer: 安全负责人, ref: "授权书-001"}}
  - name: 乙系统
    primary_domain: b.example.com
    authorization: {{authorizer: 安全负责人, ref: "授权书-002"}}
  - name: 无授权系统
    primary_domain: c.example.com
"""
        now = datetime(2026, 9, 20, 2, 0)

        # ③ 未启用周期化 → 一个都不扫，且原因明确
        tpath.write_text(tpl.format(sched="{enabled: false, mode: daily}"),
                         encoding="utf-8")
        s = Scheduler(tpath, now=lambda: now)
        ds = s.due()
        if any(x[1].due for x in ds):
            problems.append("enabled=false 时不得有目标被判到点")
        if not all("enabled" in x[1].reason for x in ds):
            problems.append("未启用时每个目标都要给出同一个明确原因")

        # ④ daily：第一次到点；标记后同周期不再到点；换一天再到点
        tpath.write_text(tpl.format(sched="{enabled: true, mode: daily}"),
                         encoding="utf-8")
        s = Scheduler(tpath, now=lambda: now)
        if s.config_errors():
            problems.append(f"合法配置不应报错：{s.config_errors()}")
        due1 = {x[0]["name"]: x[1] for x in s.due()}
        if not due1["甲系统"].due or not due1["乙系统"].due:
            problems.append("daily 首次应判到点")
        if due1["无授权系统"].due:
            problems.append("未登记授权人的目标不得被判到点（无扫描依据）")
        if "authorizer" not in due1["无授权系统"].reason:
            problems.append("未登记授权的原因要点明缺哪个字段")
        s.mark_ran("甲系统", now=now)
        s.save_state()
        s2 = Scheduler(tpath, now=lambda: now)
        if s2.decide(s2.targets()[0], now).due:
            problems.append("同一周期内已执行过，不得重复判到点")
        if "已执行过" not in s2.decide(s2.targets()[0], now).reason:
            problems.append("「本周期已执行」的原因要写清（否则像配置没生效）")
        if not s2.decide(s2.targets()[0], datetime(2026, 9, 21, 2, 0)).due:
            problems.append("跨天之后应重新判到点")
        if int(s2._entry("甲系统").get("run_count", 0)) != 1:
            problems.append("执行次数未累计（运维看不到这个周期跑了几次）")

        # ⑤ cron 非法 → 必须在执行前就报出来（这是静默不出勤的主因）
        tpath.write_text(tpl.format(sched='{enabled: true, cron: "0 25 * * *"}'),
                         encoding="utf-8")
        s3 = Scheduler(tpath, now=lambda: now)
        errs = s3.config_errors()
        if not any("cron" in e for e in errs):
            problems.append("非法 cron 必须被 config_errors 暴露出来 —— "
                            "静默不出勤是调度器最典型的失效形态")

        # ⑥ cron 到点与幂等
        tpath.write_text(tpl.format(sched='{enabled: true, cron: "0 2 * * 0"}'),
                         encoding="utf-8")
        s4 = Scheduler(tpath, now=lambda: now)
        if s4.config_errors():
            problems.append(f"合法 cron 不应报错：{s4.config_errors()}")
        if not all(x[1].due for x in s4.due() if x[0]["name"] != "无授权系统"):
            problems.append("cron 命中的时刻应判到点")
        s4.mark_ran("甲系统", now=now)
        if Scheduler(tpath, now=lambda: now).decide(
                Scheduler(tpath, now=lambda: now).targets()[0], now).due:
            problems.append("cron 模式同一分钟不得重复执行")

        # ⑦ 状态文件损坏 → 按无历史处理，但必须报出来
        tpath.write_text(tpl.format(sched="{enabled: true, mode: daily}"),
                         encoding="utf-8")
        sp = root / "outputs" / STATE_FILE_NAME
        sp.write_text("{ 这不是 JSON", encoding="utf-8")
        s5 = Scheduler(tpath, now=lambda: now)
        if not any("损坏" in e for e in s5.config_errors()):
            problems.append("状态文件损坏必须留痕（否则重复扫描找不到原因）")
        if not s5.decide(s5.targets()[0], now).due:
            problems.append("状态损坏时应按「无历史」处理 → 判到点（宁可重扫不可漏扫）")
        sp.unlink()

        # ⑧ 保留期只清点、不删除
        old = root / "outputs" / "老归档"
        old.mkdir()
        import os as _os  # noqa: PLC0415

        past = time.mktime(datetime(2026, 1, 1).timetuple())
        _os.utime(old, (past, past))
        tpath.write_text(tpl.format(
            sched="{enabled: true, mode: daily, retention_days: 30}"), encoding="utf-8")
        s6 = Scheduler(tpath, now=lambda: now)
        stale = s6.stale_archives(now)
        if not any("老归档" in x["path"] for x in stale):
            problems.append("超期归档必须被清点出来")
        if not old.exists():
            problems.append("保留期清点**不得删除**任何归档（破坏性动作交给人确认）")
        if not any("_" not in Path(x["path"]).name for x in stale):
            problems.append("清点范围异常")

        # ⑨ 配置读不了 → 不许表现成「没有目标」
        bad = root / "bad.yaml"
        bad.write_text("targets: [", encoding="utf-8")
        s7 = Scheduler(bad, now=lambda: now)
        if not any("读取失败" in e for e in s7.config_errors()):
            problems.append("主配置读不了必须报「读取失败」，"
                            "不能表现成「没有目标要扫」")
        if s7.due():
            problems.append("配置读不了时不应产出「没有目标」的假结论")

    if problems:
        print("周期化调度自测不通过：")
        for x in problems:
            print(f"  ✗ {x}")
        return 1
    print("周期化调度自测通过：cron 非法写法一律抛错（不静默不出勤）、"
          "同周期幂等且原因明确、未授权目标不扫、状态损坏按重扫处理并留痕、"
          "保留期只清点不删除、配置读不了不伪装成「没有目标」")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
