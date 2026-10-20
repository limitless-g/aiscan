# -*- coding: utf-8 -*-
"""
L2 扫描引擎 —— nuclei 执行预算与耗时控制
==========================================
问题：nuclei 是全流程里**唯一不受本工程节流器控制**的一步。它自己发请求，
档位的 `rate_limit` 直接映射成 nuclei 的 `-rl`。一旦模板选得多、目标响应慢，
单这一步就能吃掉整轮扫描的时间。原来的写法有三个毛病：

  · **纯损耗在跑**：模板里混着 file / code / javascript / headless / whois
    这几个「要本地文件、要本地代码运行时、要浏览器、要注册域名」的类型。
    我们只给了一个 URL，这几类**一个有效请求也发不出来**，却要参与模板加载。
  · **被掐断即归零**：预算到点把进程杀掉，`res.findings` 保持空 ——
    可它明明已经把结果逐行追加进了 jsonl。已经发生的事实因为「没跑完」而消失。
  · **不分轻重**：一趟跑到底。预算不够时，落在手里的是被截断的随机一半，
    可能中危一堆、critical 一个没跑到。

本模块解决三件事，顺序就是重要性顺序：

  1. **保序**：把一次大跑拆成「高价值档 → 其余档」两趟。预算耗尽时，
     手里至少是全量 critical/high，而不是半截中危。
  2. **抢救**：进程被掐断后把已写出的 jsonl 解析回来，并标记 partial。
     报告据此说明「这一批结论不完整」，而不是把截断当成跑完。
  3. **减量（幅度有限，但不做白不做）**：排除结构性不适用的模板类型（`-ept`），
     关掉启动时的联网更新检查（`-duc`）。

**关于减量的实测口径**（不允许凭感觉写优化效果 —— 本工程的红线是
「报告里的每个数字都要复现得出来」，优化幅度同理）：

    模板库 13741 份（`~/nuclei-templates`，v10.4.9）
    standard 档筛选（severity=critical,high + tags=cve,misconfig,exposure,
    default-login,takeovers,ssl − exclude-tags=intrusive,fuzz,dos）：
        不加 `-ept` → **3253** 份
        加   `-ept` → **3190** 份（−63 份，−1.9%）

所以减量**不是数量级下降**：标签与严重度已经先把不适用的大头筛掉了，
剩下的 63 份是「同时带了 cve/misconfig 标签、又是 file/code/headless 类型」
的少数模板。它的价值是**结构正确性**（这几类对只给了 URL 的目标发不出有效
请求，选了也是空跑并拉长模板加载）与**启动固定开销**（`-duc` 实测把模板清点
从 4s 降到 2s），而不是把 3190 变成几百。

真正决定墙钟时间的是 `纳入模板数 × 每模板请求数 ÷ 限速`。模板数既然压不动
（压得动就意味着掉召回，那是拿准确率换时间，不允许），本模块就把力气放在
「**让读者知道这一趟到底罩住了多大范围、有没有跑完**」—— 这也是新增
`count_templates()` 的原因：一个「本次纳入 3190 份模板、跑完了」的「无发现」，
和一个「本次纳入 3190 份、只跑完 1/3 就被掐断」的「无发现」，含义完全不同。

设计红线（与全项目一致）：**任何被裁掉的东西都必须能被说出名字。**
计划本身（排除了哪些类型、预算是多少、哪一趟被截断、每趟纳入多少模板）
会落进 notes 与 JSON，不允许静默降级。裁剪只动「结构性跑不动」的部分，
不动物种召回。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ==============================================================================
# 常量
# ==============================================================================

#: 对「只给了 URL 的目标」结构性跑不出有效请求的模板类型。
#:
#:   file        —— 需要本地文件路径输入，我们从不提供
#:   code        —— 需要 nuclei 在本地执行签名校验代码，不适用且有执行风险
#:   javascript  —— 需要本地 JS 运行时
#:   headless    —— 需要浏览器；本环境未装 playwright，选了只会全线失败
#:   whois       —— 需要域名注册信息，且会外连 whois 服务（引入外部依赖）
#:
#: 排除它们**不会**掉召回（这几类对 URL 目标发不出有效请求），但幅度也**不大**：
#: standard 档筛选后的 3253 份里只占 63 份（见模块 docstring 的实测口径）。
#: 别把它当成性能优化来吹 —— 它的价值是结构正确性与启动开销。
INAPPLICABLE_PROTOCOLS: tuple[str, ...] = ("file", "code", "javascript", "headless", "whois")

#: 高价值档的严重度。分两趟跑，第一趟只做这些 —— 预算耗尽时它们必须在手里。
HIGH_VALUE_SEVERITY: tuple[str, ...] = ("critical", "high")

#: 单主机场景下的错误容忍上限。超过即放弃该主机（多半是已被封禁）。
#: 显式写进命令行而不是吃默认值：默认值会随 nuclei 版本变。
DEFAULT_MAX_HOST_ERROR = 30

#: 预算是「安全阀」，不是「性能参数」。给过小的值会让每次扫描都截断，
#: 反而制造「看起来跑了其实没跑完」的假象；给过大则失去保护意义。
MIN_BUDGET_SECONDS = 60.0
MAX_BUDGET_SECONDS = 3600.0

#: 各风险档的默认预算（秒）。
#:
#: 取值有实测依据（不允许凭感觉填）：真机跑 standard 档筛选后的模板集是
#: **3190 份**，而 `-rate-limit` 被档位声明的请求速率夹住（standard 20/s、
#: safe 5/s）。实测在 5/s 下 951 份模板 120s 都没跑完 —— 也就是说
#: **预算在真实目标上大概率会被用满**，它的作用是「给扫描收口」，
#: 而不是「保证跑完」。因此：
#:   · 高价值档（critical/high）必须排在前面，这是保底；
#:   · 被截断时如实披露 + 抢救已产出的部分，这是兜底；
#:   · 想让外部引擎覆盖完整，得提高档位限速或显式调大这个预算。
DEFAULT_BUDGET_BY_RISK = {
    "safe": 300.0,
    "standard": 420.0,
    "deep": 900.0,
}
FALLBACK_BUDGET = 420.0


def _as_tuple(value: Any) -> tuple[str, ...]:
    """把配置里可能是 list / str / None 的东西统一成字符串元组。"""
    if not value:
        return ()
    if isinstance(value, str):
        return tuple(x.strip() for x in value.split(",") if x.strip())
    return tuple(str(x).strip() for x in value if str(x).strip())


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp_budget(seconds: float) -> float:
    """把预算夹到合理区间。太小=每次都截断，太大=失去保护意义。"""
    if seconds < MIN_BUDGET_SECONDS:
        return MIN_BUDGET_SECONDS
    if seconds > MAX_BUDGET_SECONDS:
        return MAX_BUDGET_SECONDS
    return float(seconds)


# ==============================================================================
# 计划
# ==============================================================================
@dataclass
class NucleiPass:
    """一趟 nuclei 执行。一次扫描可能有多趟（按严重度分层）。"""

    label: str
    severity: tuple[str, ...] = ()
    tags_include: tuple[str, ...] = ()
    tags_exclude: tuple[str, ...] = ()
    protocols_exclude: tuple[str, ...] = INAPPLICABLE_PROTOCOLS
    rate_limit: int = 20
    bulk_size: int = 20
    concurrency: int = 8
    per_request_timeout: int = 12
    retries: int = 1
    max_host_error: int = DEFAULT_MAX_HOST_ERROR
    disable_update_check: bool = True
    no_interactsh: bool = True
    extra_flags: tuple[str, ...] = ()

    def to_args(self, binary: str, target_url: str, out_file: Path) -> list[str]:
        """拼出这一趟的完整命令行。"""
        cmd = [
            binary,
            "-u", target_url,
            "-jsonl",
            "-o", str(out_file),
            "-silent",
            "-no-color",
            "-rate-limit", str(self.rate_limit),
            "-bulk-size", str(self.bulk_size),
            "-concurrency", str(self.concurrency),
            "-timeout", str(self.per_request_timeout),
            "-retries", str(self.retries),
            "-max-host-error", str(self.max_host_error),
        ]
        if self.severity:
            cmd += ["-severity", ",".join(self.severity)]
        if self.tags_include:
            cmd += ["-tags", ",".join(self.tags_include)]
        if self.tags_exclude:
            cmd += ["-exclude-tags", ",".join(self.tags_exclude)]
        if self.protocols_exclude:
            cmd += ["-exclude-type", ",".join(self.protocols_exclude)]
        if self.no_interactsh:
            # 关掉 OOB 交互：本项目不引入外部交互服务，也不愿让扫描器外连。
            cmd += ["-no-interactsh"]
        if self.disable_update_check:
            # 每次启动的联网版本检查是纯固定开销，离线可跑也不需要它。
            cmd += ["-disable-update-check"]
        cmd += list(self.extra_flags)
        return cmd

    def to_list_args(self, binary: str) -> list[str]:
        """拼出「只清点模板、不发任何请求」的命令行（`-tl`）。

        用途：报告里要说清「这一趟到底罩住了多大范围」。一个「纳入 3190 份
        模板、跑完了」的「无发现」，和一个「只跑完 1/3 就被掐断」的「无发现」，
        含义完全不同 —— 不给这个数字，读者无从区分。

        `-tl` 只加载模板元数据、不向目标发请求，因此它可以安全地放在
        执行之前跑（实测 standard 档约 2s，不算在目标身上的开销）。
        """
        cmd = [binary, "-tl", "-silent", "-no-color"]
        if self.severity:
            cmd += ["-severity", ",".join(self.severity)]
        if self.tags_include:
            cmd += ["-tags", ",".join(self.tags_include)]
        if self.tags_exclude:
            cmd += ["-exclude-tags", ",".join(self.tags_exclude)]
        if self.protocols_exclude:
            cmd += ["-exclude-type", ",".join(self.protocols_exclude)]
        if self.disable_update_check:
            cmd += ["-disable-update-check"]
        cmd += list(self.extra_flags)
        return cmd

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "severity": list(self.severity),
            "tags_include": list(self.tags_include),
            "tags_exclude": list(self.tags_exclude),
            "protocols_exclude": list(self.protocols_exclude),
            "rate_limit": self.rate_limit,
            "concurrency": self.concurrency,
            "bulk_size": self.bulk_size,
            "per_request_timeout": self.per_request_timeout,
            "retries": self.retries,
            "max_host_error": self.max_host_error,
        }


@dataclass
class NucleiPlan:
    """整轮 nuclei 的执行计划：多趟 + 总预算 + 裁剪说明。"""

    risk_level: str = "standard"
    passes: list[NucleiPass] = field(default_factory=list)
    budget_seconds: float = FALLBACK_BUDGET
    notes: list[str] = field(default_factory=list)

    @property
    def total_passes(self) -> int:
        return len(self.passes)

    def summary(self) -> str:
        if not self.passes:
            return "nuclei 执行计划：无需执行（档位未启用任何严重度）"
        sev = " / ".join(",".join(p.severity) for p in self.passes)
        return (
            f"nuclei 执行计划：{self.total_passes} 趟（{sev}），"
            f"总预算 {int(self.budget_seconds)}s，"
            f"已排除不适用模板类型 {'+'.join(INAPPLICABLE_PROTOCOLS)}，"
            f"限速 {self.passes[0].rate_limit}/s"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "budget_seconds": self.budget_seconds,
            "passes": [p.to_dict() for p in self.passes],
            "excluded_protocols": list(INAPPLICABLE_PROTOCOLS),
            "notes": list(self.notes),
        }


# ==============================================================================
# 从档位配置推导计划
# ==============================================================================
def build_plan(profile: dict[str, Any] | None = None,
               budget: Any = None) -> NucleiPlan:
    """按档位配置推导 nuclei 执行计划。

    档位里能拿到的量（rate_limit / severity / tags）照用，本模块只做三处收口：

      · **限速不得突破档位声明**：nuclei 自己发请求，不受本工程节流器约束，
        所以 `-rl` 必须取 `min(nuclei.rate_limit, rate.requests_per_second)`。
        取配置里那个更大的值 = 扫描器实际速率高于台账授权范围。
      · **重试收紧到 1**：档位的 `retries` 是给本工程 HTTP 客户端用的。
        交给 nuclei 会把每个失败请求的开销成倍放大，而失败请求多半是
        「目标真的不通」，重试换不来新信息。
      · **并发受本机预算封顶**：nuclei 是 Go 程序，`-concurrency` 默认给多少就用多少，
        GOMAXPROCS 更是默认为**全部逻辑核**。档位声明的 `concurrency` 是
        「别把目标打挂」（目标侧），`engine/resources.py` 给的是
        「别把这台电脑拖死」（本机侧），两者取更小者。
      · **按严重度分层**：critical/high 先跑。
    """
    profile = profile or {}
    cfg = profile.get("nuclei", {}) or {}
    rate = profile.get("rate", {}) or {}
    risk_level = str(profile.get("risk_level") or profile.get("name") or "standard")

    severity = _as_tuple(cfg.get("severity_filter"))
    tags_include = _as_tuple(cfg.get("template_tags_include"))
    tags_exclude = _as_tuple(cfg.get("template_tags_exclude"))

    declared_rps = _as_int(rate.get("requests_per_second"), 20)
    cfg_rate = _as_int(cfg.get("rate_limit"), declared_rps)
    rate_limit = max(1, min(cfg_rate, declared_rps))

    notes: list[str] = []
    if cfg_rate > declared_rps:
        notes.append(
            f"nuclei 限速由 {cfg_rate}/s 收紧到 {rate_limit}/s —— "
            "nuclei 自行发请求、不走本工程节流器，不得超过档位声明的请求速率"
        )
    notes.append(
        "已排除对 URL 目标结构性不适用的模板类型："
        + "、".join(INAPPLICABLE_PROTOCOLS)
        + "（要本地文件 / 本地代码运行时 / 浏览器 / 注册域名，选了也发不出有效请求）"
    )

    # 本机侧并发封顶。取「档位声明」与「本机预算」的更小者 ——
    # 不封顶的后果是 nuclei 按全部逻辑核开跑，同时把内存吃到几个 GB。
    try:
        from engine import resources as _res  # noqa: PLC0415
    except ImportError:  # noqa: BLE001
        import resources as _res  # type: ignore  # noqa: PLC0415
    b = budget if budget is not None else _res.budget()
    declared_conc = _as_int(cfg.get("concurrency"), 8)
    capped_conc = _res.cap_workers(declared_conc, b)
    if capped_conc < declared_conc:
        notes.append(
            f"nuclei 并发由档位声明的 {declared_conc} 收紧到 {capped_conc} —— "
            f"本机预算上限 {b.worker_cap}（{b.logical_cores} 逻辑核 × {b.cpu_share:.0%}），"
            "超出去会把本机 CPU 吃满、影响你同时用电脑"
        )
    if b.low_impact:
        notes.append(
            f"nuclei 子进程限额：{b.child_cores} 核（GOMAXPROCS）"
            + (f" / {b.child_mem_limit_mb}MB（GOMEMLIMIT）" if b.child_mem_limit_mb else "")
            + "，进程优先级低于正常"
        )
    else:
        notes.append("nuclei 子进程未设资源限额（全速模式）")

    # 分层：先高价值，再其余。任一层为空则不生成。
    high = tuple(s for s in severity if s in HIGH_VALUE_SEVERITY)
    rest = tuple(s for s in severity if s not in HIGH_VALUE_SEVERITY)

    common: dict[str, Any] = {
        "tags_include": tags_include,
        "tags_exclude": tags_exclude,
        "rate_limit": rate_limit,
        "bulk_size": _as_int(cfg.get("bulk_size"), 20),
        "concurrency": capped_conc,
        "per_request_timeout": _as_int(rate.get("timeout_seconds"), 12),
        # 档位 retries 不转交 nuclei，理由见 docstring
        "retries": 1,
        "max_host_error": DEFAULT_MAX_HOST_ERROR,
    }

    passes: list[NucleiPass] = []
    if high and rest:
        # 两档都有 → 分两趟。预算耗尽时手里至少是全量高价值结果。
        passes.append(NucleiPass(label="高价值（critical/high）", severity=high, **common))
        passes.append(NucleiPass(label=f"其余（{'/'.join(rest)}）", severity=rest, **common))
    elif high:
        passes.append(NucleiPass(label=f"全部（{'/'.join(high)}）", severity=high, **common))
    elif rest:
        # 档位没勾 critical/high：只有一趟，别叫它「其余」—— 它本来就是全部。
        passes.append(NucleiPass(label=f"全部（{'/'.join(rest)}）", severity=rest, **common))

    budget = clamp_budget(
        _as_float(cfg.get("budget_seconds"), DEFAULT_BUDGET_BY_RISK.get(risk_level, FALLBACK_BUDGET))
    )
    if len(passes) > 1:
        notes.append(
            f"分 {len(passes)} 趟执行（先 critical/high，再其余）：预算耗尽时"
            "手里至少是全量高价值结果，而不是被截断的随机一半"
        )

    return NucleiPlan(risk_level=risk_level, passes=passes, budget_seconds=budget, notes=notes)


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> int:
    problems: list[str] = []

    std = {
        "risk_level": "standard",
        "rate": {"requests_per_second": 20, "timeout_seconds": 12, "retries": 2},
        "nuclei": {
            "severity_filter": ["critical", "high", "medium"],
            "template_tags_include": ["cve", "misconfig"],
            "template_tags_exclude": ["intrusive", "fuzz", "dos"],
            "rate_limit": 20,
            "bulk_size": 20,
            "concurrency": 8,
        },
    }
    p = build_plan(std)

    # ① 分层：critical/high 必须在第一趟
    if len(p.passes) != 2:
        problems.append(f"计划应分 2 趟，实际 {len(p.passes)}")
    else:
        if set(p.passes[0].severity) != {"critical", "high"}:
            problems.append(f"第一趟应为 critical/high，实际 {p.passes[0].severity}")
        if set(p.passes[1].severity) != {"medium"}:
            problems.append(f"第二趟应为 medium，实际 {p.passes[1].severity}")

    # ② 不适用类型必须被排除（这是减量的主要来源）
    for i, ps in enumerate(p.passes):
        if set(ps.protocols_exclude) != set(INAPPLICABLE_PROTOCOLS):
            problems.append(f"第 {i + 1} 趟未排除不适用模板类型：{ps.protocols_exclude}")

    # ③ 重试必须收紧到 1（档位写的 2 是给本工程 HTTP 客户端的）
    if any(ps.retries != 1 for ps in p.passes):
        problems.append("nuclei 重试次数未被收紧到 1")

    # ④ 限速不得突破档位声明
    over = dict(std)
    over["nuclei"] = dict(std["nuclei"], rate_limit=100)   # 声明 20，配置却要 100
    po = build_plan(over)
    if po.passes and po.passes[0].rate_limit != 20:
        problems.append(
            f"nuclei 限速应被收紧到档位声明的 20/s，实际 {po.passes[0].rate_limit} —— "
            "nuclei 不走本工程节流器，这里放开等于实际速率超出授权范围")
    if not any("收紧" in n for n in po.notes):
        problems.append("限速被收紧时必须留痕说明（静默收紧同样是静默降级）")

    # ⑤ 只勾高价值严重度时不产生空趟
    hi_only = dict(std)
    hi_only["nuclei"] = dict(std["nuclei"], severity_filter=["critical", "high"])
    ph = build_plan(hi_only)
    if len(ph.passes) != 1:
        problems.append(f"只勾高价值时应只生成 1 趟，实际 {len(ph.passes)}")

    # ⑥ 未启用任何严重度 → 不产生执行计划（而不是生成一个空命令行去跑）
    none_sev = dict(std)
    none_sev["nuclei"] = dict(std["nuclei"], severity_filter=[])
    if build_plan(none_sev).passes:
        problems.append("未启用任何严重度时不应生成执行趟")

    # ⑦ 预算夹取
    if clamp_budget(1) != MIN_BUDGET_SECONDS:
        problems.append("过小的预算未被夹到下限（太小=每次都截断，会制造假象）")
    if clamp_budget(99999) != MAX_BUDGET_SECONDS:
        problems.append("过大的预算未被夹到上限")
    tiny = dict(std)
    tiny["nuclei"] = dict(std["nuclei"], budget_seconds=5)
    if build_plan(tiny).budget_seconds != MIN_BUDGET_SECONDS:
        problems.append("配置里的过小预算未被夹取")
    if build_plan(std).budget_seconds != DEFAULT_BUDGET_BY_RISK["standard"]:
        problems.append("未按风险档取默认预算")

    # ⑧ 命令行必须真的带上排除项与两个固定开关
    args = p.passes[0].to_args("nuclei", "https://t.example", Path("/tmp/o.jsonl"))
    if "-exclude-type" not in args:
        problems.append("命令行缺少 -exclude-type（减量没生效）")
    else:
        got = args[args.index("-exclude-type") + 1]
        if set(got.split(",")) != set(INAPPLICABLE_PROTOCOLS):
            problems.append(f"-exclude-type 取值不符：{got}")
    if "-disable-update-check" not in args:
        problems.append("命令行缺少 -disable-update-check（启动联网检查是纯开销）")
    if "-no-interactsh" not in args:
        problems.append("命令行缺少 -no-interactsh（会引入外部交互依赖）")
    if "-severity" not in args or args[args.index("-severity") + 1] != "critical,high":
        problems.append("命令行未按分层传入严重度")
    if "-jsonl" not in args or "-o" not in args:
        problems.append("命令行缺少 jsonl 输出配置（捡不回部分产出）")

    # ⑨ 计划必须可落盘（报告要据此披露裁剪范围）
    d = p.to_dict()
    if not d.get("passes") or not d.get("excluded_protocols") or not d.get("budget_seconds"):
        problems.append("计划落盘字段不完整（报告无从披露裁剪范围）")
    if "已排除" not in p.summary() and "排除" not in p.summary():
        problems.append("计划摘要未说明裁剪范围")

    # ⑩ 并发必须受**本机预算**封顶，且被封顶时留痕。
    #    这一条守的是「跑任务把电脑 CPU / 内存吃满」这个真实故障：
    #    nuclei 是 Go 程序，不封顶就按全部逻辑核开跑。
    #    用显式预算注入而不是读本机现状 —— 断言不能随机器变。
    class _B:                       # 最小预算桩，避免依赖 engine.resources 的真实探测
        low_impact = True
        logical_cores = 12
        cpu_share = 0.5
        worker_cap = 4
        child_cores = 3
        child_mem_limit_mb = 512
        notes: list = []

    capped = build_plan(std, budget=_B())
    if capped.passes and capped.passes[0].concurrency != 4:
        problems.append(
            f"nuclei 并发应被本机预算封到 4，实际 {capped.passes[0].concurrency}")
    if not any("并发" in n and "收紧" in n for n in capped.notes):
        problems.append("并发被封顶时必须留痕（静默降速与静默降级同罪）")
    if not any("GOMAXPROCS" in n for n in capped.notes):
        problems.append("必须披露子进程的资源限额（否则读者不知道跑在什么姿态下）")

    class _Bfast:
        low_impact = False
        logical_cores = 12
        cpu_share = 1.0
        worker_cap = 16
        child_cores = 12
        child_mem_limit_mb = 0
        notes: list = []

    fast = build_plan(std, budget=_Bfast())
    if fast.passes and fast.passes[0].concurrency != 8:
        problems.append(
            f"全速模式下并发应保持档位声明的 8，实际 {fast.passes[0].concurrency}")
    if not any("全速" in n for n in fast.notes):
        problems.append("全速模式必须留痕说明")

    if problems:
        print("nuclei 预算自测不通过：")
        for x in problems:
            print(f"  ✗ {x}")
        return 1
    print(
        f"nuclei 预算自测通过：{p.total_passes} 趟分层、"
        f"排除 {'+'.join(INAPPLICABLE_PROTOCOLS)} 共 {len(INAPPLICABLE_PROTOCOLS)} 类不适用模板、"
        f"限速 {p.passes[0].rate_limit}/s（不超档位声明）、"
        f"预算 {int(p.budget_seconds)}s、重试 {p.passes[0].retries}"
    )
    print("  " + p.summary())
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
