# -*- coding: utf-8 -*-
"""资源预算与进程优先级 —— 「扫描跑起来，电脑还能干别的」
================================================================================

要解决的问题
--------------------------------------------------------------------------------
一次扫描会把机器吃满：nuclei 是 Go 程序，**默认 GOMAXPROCS = 全部逻辑核**，
模板一多还会把堆吃到 1GB 以上；本机浏览器渲染会再起一个上百 MB 的进程；
Python 侧的并发探测再叠一层。加上扫描进程与用户的前台工作**同为普通优先级**，
结果是「扫描在跑的时候，电脑干什么都卡」。

本模块只做两件事，顺序就是重要性顺序：

  1. **降优先级**（收益最大、代价最小）：扫描进程与它派生的**所有**子进程
     都降到「低于正常」优先级。操作系统的调度器会把 CPU 时间优先给
     用户的前台工作 —— 扫描变慢一点，但**你感觉不到它**。
     这是唯一一条「不牺牲覆盖度就能换来体感流畅」的优化。
  2. **封顶并发**（有代价，必须披露）：按「逻辑核数 × CPU 份额」封住
     Python 线程池与 nuclei 的并发度，并用 `GOMAXPROCS` / `GOMEMLIMIT`
     给 Go 侧划一条硬边界。

红线：**降级必须能被说出名字。**
任何被压下来的并发度都要经 `ResourceBudget.notes` 透出，最终进报告的
「本次扫描的运行姿态」一节。静默降速与静默降级同罪 —— 报告里一个
「本次限速 20/s、纳入 3190 份模板」的结论，如果不说明并发被压到了一半，
读者会拿它跟另一台机器上的扫描结果做不可比的比较。

为什么不用 psutil
--------------------------------------------------------------------------------
项目运行环境是隔离 venv，规则是「禁止引入新依赖」。这里用 `ctypes` 直接调
Windows 的 `GlobalMemoryStatusEx` / `SetPriorityClass`，Linux/macOS 走
`/proc/meminfo`、`os.sysconf` 与 `os.nice`。取不到就**如实返回 None**，
不做猜测 —— 猜出来的内存值会让 GOMEMLIMIT 变成一个错误的上限。

与既有模块的关系
--------------------------------------------------------------------------------
· `profiles.yaml` 的 `rate.concurrency` 仍然是**目标侧**约束（别把目标打挂），
  本模块是**本机侧**约束（别把电脑拖死），最终并发取两者更小者 ——
  这两件事不能互相替代。
· `engine/progress.py` 负责「让人知道它在跑」，本模块负责「让它别挡路」。
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
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

#: 环境变量开关。全部可配，因为在不同机器上「多少才不卡」差别很大。
ENV_LOW_IMPACT = "AISCAN_LOW_IMPACT"          # 1=低影响（默认）/ 0=不干预
ENV_CPU_SHARE = "AISCAN_CPU_SHARE"            # 0.1~1.0，默认 0.5
ENV_MEM_LIMIT = "AISCAN_MEM_LIMIT_MB"         # 子进程内存硬上限 MB
ENV_WORKER_CAP = "AISCAN_WORKER_CAP"          # 直接指定线程并发上限

#: 线程池并发的**绝对下限**。再低会让扫描退化成串行、耗时不可接受，
#: 也会让「限速」失去意义（限速说的是每秒请求数，串行达不到）。
MIN_WORKERS = 2

#: 线程池并发的**绝对上限**。即使机器很空也不超过这个数：
#: 并发本身有收益递减，而对目标而言请求密度是风险。
MAX_WORKERS = 16

#: 默认 CPU 份额。0.5 = 用一半的逻辑核。
#: 为什么是一半而不是「核数 − 1」：还要给浏览器渲染、目标侧假应用、
#: 以及用户自己的前台程序留余量。想全速跑用 AISCAN_CPU_SHARE=1。
DEFAULT_CPU_SHARE = 0.5

#: 默认子进程内存上限（MB）。真正的取值是
#: `min(总内存/8, 可用内存/2)` 再夹到 [MIN, MAX] —— 见 `_mem_limit_mb()`。
#: 取「可用内存的一半」而不是「三分之一」：实测本机常态可用仅 1GB 左右
#: （WorkBuddy + 飞书 + 微信 + 浏览器已占 11GB+），三分之一会把 nuclei 饿到
#: 频繁 GC、扫描时间反而更长 —— 压内存压到拖慢自己就不划算了。
DEFAULT_MEM_LIMIT_MB = 768
MAX_MEM_LIMIT_MB = 4096
MIN_MEM_LIMIT_MB = 256

#: Windows 进程优先级常量（`SetPriorityClass`）。
#: 用 BELOW_NORMAL 而不是 IDLE：IDLE 会让扫描慢到不可用；
#: BELOW_NORMAL 的语义正是「我很闲，把 CPU 让给需要的人」。
IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
PROCESS_MODE_BACKGROUND_END = 0x00200000

#: Unix 侧的 nice 增量。10 = 明显让路，但不到 19 那种「几乎不跑」。
UNIX_NICE_INCREMENT = 10

#: 科学计算库的线程池环境变量。本工程不直接用 numpy/openblas，但浏览器与
#: 第三方二进制的依赖链里可能有 —— 多份线程池叠加会各按「全部逻辑核」开，
#: 是「CPU 明明只跑一个扫描却满核」的一个隐蔽来源。
_THREADPOOL_ENV_VARS = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                        "NUMEXPR_NUM_THREADS")

_MEMORY_STATUS_EX_STRUCT = None


def _truthy(value: Any, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() not in ("0", "false", "no", "off", "")


def _flt(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ==============================================================================
# 机器探测（取不到就返回 None，不猜）
# ==============================================================================

class _MEMORYSTATUSEX(ctypes.Structure):
    """Windows `GlobalMemoryStatusEx` 的结构体定义。

    （函数名叫 "Status" 不是 "StatusEx"，但结构体是 MEMORYSTATUSEX —— 这是
    Win32 API 的历史遗留命名，写错会直接拿到 0，所以在这里记一笔。）
    """

    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _mem_limit_mb(total_mb: int | None, avail_mb: int | None) -> int:
    """算出子进程（nuclei / 浏览器）的内存上限。

    两个口径取更小者，理由各自不同：

      · **总内存 / 8**  —— 「这台机器上单个扫描子进程最多配用多少」。
        上限不随瞬时可用内存抖动：扫描跑到一半，别的程序释放了内存，
        我们不该临时把配额放大（那会在下一个高峰把机器打回 99%）。
      · **可用内存 / 2** —— 「现在真的还有多少能让出来」。
        本机常态可用只有 1GB 左右，这一项才是实际起作用的那个。

    Windows 上 `ullAvailPhys` 已经包含 standby（可立即回收的文件缓存），
    所以它是可复用内存的**上界估计**而不是保守低估 —— 用它做分母是安全的。
    """
    if not total_mb and not avail_mb:
        return DEFAULT_MEM_LIMIT_MB
    cands: list[int] = []
    if total_mb:
        cands.append(max(MIN_MEM_LIMIT_MB, total_mb // 8))
    if avail_mb:
        cands.append(max(MIN_MEM_LIMIT_MB, avail_mb // 2))
    return max(MIN_MEM_LIMIT_MB, min(min(cands), MAX_MEM_LIMIT_MB))


def _kernel32() -> Any:
    """拿到配置好签名的 kernel32。

    **必须显式声明 argtypes/restype —— 这不是风格问题，是正确性问题。**
    `HANDLE` 在 x64 上是 64 位。不声明时 ctypes 把 Python 整数按 32 位 C int
    传参，`GetCurrentProcess()` 的伪句柄 -1 到被调用方手里变成 0x00000000FFFFFFFF，
    `SetPriorityClass` 于是**返回 0（失败）**，而 Python 侧不抛任何异常 ——
    「改了优先级」直接变成一个静默的空操作，测都测不出来。
    （实测：未声明时返回 0，声明后返回 1。）
    """
    k = ctypes.windll.kernel32
    k.GetCurrentProcess.restype = ctypes.c_void_p
    k.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    k.SetPriorityClass.restype = ctypes.c_int
    return k


def physical_cores() -> int | None:
    """物理核数。取不到返回 None（Windows 上用环境变量可读）。"""
    if sys.platform.startswith("win"):
        # NUMBER_OF_PROCESSORS 报的是逻辑核；物理核要走 WMI，这里不引入
        # 额外调用 —— 返回 None 表示「不知道」，由调用方按逻辑核处理。
        return None
    try:
        return int(os.sysconf("SC_NPROCESSORS_ONLN")) or None  # type: ignore[attr-defined]
    except (AttributeError, ValueError, OSError):
        return None


def memory_status() -> tuple[int | None, int | None, int | None]:
    """返回 (总物理内存 MB, 可用物理内存 MB, 内存负载 %)。取不到给 None。

    内存负载单独要一份，是因为它决定**要不要在报告里给出内存告急提示**：
    「可用 1GB」和「可用 1GB 但负载只有 20%」是两种完全不同的处境。
    """
    if sys.platform.startswith("win"):
        global _MEMORY_STATUS_EX_STRUCT
        try:
            if _MEMORY_STATUS_EX_STRUCT is None:
                _MEMORY_STATUS_EX_STRUCT = _MEMORYSTATUSEX()
            st = _MEMORY_STATUS_EX_STRUCT
            st.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return None, None, None
            return (int(st.ullTotalPhys // 2**20), int(st.ullAvailPhys // 2**20),
                    int(st.dwMemoryLoad))
        except Exception:  # noqa: BLE001
            return None, None, None
    total: int | None = None
    avail: int | None = None
    try:                                    # Linux / macOS（sysconf 是权威来源）
        page = os.sysconf("SC_PAGE_SIZE")            # type: ignore[attr-defined]
        total = int(os.sysconf("SC_PHYS_PAGES") * page // 2**20)     # type: ignore[attr-defined]
        avail = int(os.sysconf("SC_AVPHYS_PAGES") * page // 2**20)   # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        try:                                # 兜底读 /proc/meminfo
            text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) // 1024
        except Exception:  # noqa: BLE001
            return None, None, None
    load = int(round((1 - avail / total) * 100)) if total and avail else None
    return total, avail, load


def memory_mb() -> tuple[int | None, int | None]:
    """返回 (总物理内存 MB, 可用物理内存 MB)。取不到给 (None, None)。"""
    total, avail, _ = memory_status()
    return total, avail


# ==============================================================================
# 预算
# ==============================================================================

@dataclass
class ResourceBudget:
    """本机侧的资源预算。所有字段都是「算出来的」，没有一个是拍的。"""

    logical_cores: int = 0
    physical_cores: int | None = None
    mem_total_mb: int | None = None
    mem_avail_mb: int | None = None
    #: 内存负载百分比（Windows 为系统上报值）。用于判断「要不要提示内存告急」。
    mem_load_percent: int | None = None
    #: 低影响模式。关闭时本模块**只探测、不干预**（用于对比基准）。
    low_impact: bool = True
    #: CPU 份额（0.1~1.0）
    cpu_share: float = DEFAULT_CPU_SHARE
    #: 线程池并发上限（本机侧）
    worker_cap: int = MIN_WORKERS
    #: 子进程（nuclei / 浏览器）可用核数与内存上限
    child_cores: int = 1
    child_mem_limit_mb: int = DEFAULT_MEM_LIMIT_MB
    #: 实际生效的降级动作（报告要披露）
    notes: list[str] = field(default_factory=list)
    #: 实际生效的进程优先级名（None = 未干预）
    priority_applied: str | None = None

    # ---- 派生量 ----------------------------------------------------------
    @property
    def concurrency_cap(self) -> int:
        """本机侧并发上限。与档位声明取更小者后才是最终并发。"""
        return self.worker_cap

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_cores": self.logical_cores,
            "physical_cores": self.physical_cores,
            "mem_total_mb": self.mem_total_mb,
            "mem_avail_mb": self.mem_avail_mb,
            "mem_load_percent": self.mem_load_percent,
            "low_impact": self.low_impact,
            "cpu_share": self.cpu_share,
            "worker_cap": self.worker_cap,
            "child_cores": self.child_cores,
            "child_mem_limit_mb": self.child_mem_limit_mb,
            "priority_applied": self.priority_applied,
            "notes": list(self.notes),
        }

    def posture_line(self) -> str:
        """一句话运行姿态（进报告）。无人为干预时也如实说明，不留空。"""
        if not self.low_impact:
            return (f"运行姿态：全速（{self.logical_cores} 逻辑核不设限，"
                    "进程优先级未调整）—— 此时扫描会占满本机 CPU")
        bits = [
            f"低影响模式：并发上限 {self.worker_cap}（{self.logical_cores} 逻辑核 "
            f"× {self.cpu_share:.0%}）",
            f"子进程限 {self.child_cores} 核"
            + (f" / {self.child_mem_limit_mb}MB" if self.child_mem_limit_mb else ""),
        ]
        if self.priority_applied:
            bits.append(f"进程优先级「{self.priority_applied}」")
        return "运行姿态：" + "，".join(bits) + " —— 扫描更慢，但不影响你同时使用电脑"


#: 内存高负载阈值。超过它才提示 —— 阈值定太低会让每份报告都带一条告警，
#: 那等于没有告警。
MEM_PRESSURE_THRESHOLD = 85


def top_memory_processes(limit: int = 3) -> list[tuple[str, int]]:
    """按常驻内存取占用最高的几个进程 -> [(进程名, MB), ...]。

    存在的理由：内存告急时给「关掉一些常驻程序」这种建议等于没说 ——
    用户要的是「关哪个」。所以这里直接报进程名与 MB 数。
    只在**内存已达阈值**时才被调用，正常路径上不花这个时间。

    取不到就返回空列表（不抛、不猜）：这条信息是锦上添花，
    绝不能因为它探测失败而让扫描报错。全程 stdlib，不引入新依赖。
    """
    out: list[tuple[str, int]] = []
    try:
        if sys.platform.startswith("win"):
            p = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=8)
            agg: dict[str, int] = {}
            for line in (p.stdout or "").splitlines():
                cols = [c.strip().strip('"') for c in line.split('","')]
                if len(cols) < 5:
                    continue
                name = cols[0].strip('"')
                # 内存列形如 "1,234,567 K"
                digits = re.sub(r"[^0-9]", "", cols[-1])
                if not name or not digits:
                    continue
                # 同名多实例（chrome.exe 十几个进程）必须合并 ——
                # 否则「谁最占内存」的答案是错的：单个 chrome.exe 进程都不大。
                agg[name] = agg.get(name, 0) + int(digits) // 1024
            out = sorted(agg.items(), key=lambda kv: -kv[1])[:max(1, limit)]
        else:
            agg2: dict[str, int] = {}
            for ent in Path("/proc").iterdir():
                if not ent.name.isdigit():
                    continue
                try:
                    txt = (ent / "status").read_text(encoding="utf-8",
                                                     errors="replace")
                except OSError:
                    continue
                name = rss = ""
                for ln in txt.splitlines():
                    if ln.startswith("Name:"):
                        name = ln.split(":", 1)[1].strip()
                    elif ln.startswith("VmRSS:"):
                        rss = ln.split(":", 1)[1].strip()
                kb = re.sub(r"[^0-9]", "", rss)
                if name and kb:
                    agg2[name] = agg2.get(name, 0) + int(kb) // 1024
            out = sorted(agg2.items(), key=lambda kv: -kv[1])[:max(1, limit)]
    except Exception:  # noqa: BLE001
        return []
    return [(n, mb) for n, mb in out if mb > 0]


def _fmt_mb(mb: int) -> str:
    return f"{mb / 1024:.1f}GB" if mb >= 1024 else f"{mb}MB"


def _pressure_note(budget: ResourceBudget,
                   consumers: list[tuple[str, int]] | None = None) -> None:
    """内存高负载时追加一条定位提示（原地修改 notes）。

    提这条的原因很具体：**内存打满时「变慢」的样子和 CPU 打满完全不同** ——
    CPU 满了是风扇响、进度条还能走；内存满了是整机一顿一顿地卡、
    连打字都延迟，因为要换页。不写清楚，下一次会把换页卡顿当成扫描器缺陷去查。

    `consumers` 可注入，供自测在确定性数据上断言格式（不依赖本机此刻开着什么）。
    """
    pct = budget.mem_load_percent
    if pct is None or pct < MEM_PRESSURE_THRESHOLD:
        return
    if any("换页" in n for n in budget.notes):
        return
    msg = (f"⚠ 本机内存已处于高负载（{pct}%）："
           "扫描期间若出现卡顿，主因通常是内存换页而不是 CPU")
    if consumers is None:
        consumers = top_memory_processes()
    if consumers:
        who = "、".join(f"{n} {_fmt_mb(mb)}" for n, mb in consumers)
        # 点名到进程：泛泛的「关掉一些程序」用户没法执行。
        # 同时明确区分「谁占的」与「本工具占的」——后者是几百 MB 量级，
        # 若读者把这行读成「扫描器吃了 1.6GB」，整条提示就起了反作用。
        msg += (f"；当前占用最高的常驻进程：{who}"
                "（扫描器自身进程通常在数百 MB 量级，"
                "若上面列的主要是浏览器/办公应用，关它们收益最直接）")
    else:
        msg += "；关闭若干常驻程序（浏览器多标签 / 即时通讯客户端）收益最直接"
    budget.notes.append(msg)


def _env_cpu_share() -> float:
    return max(0.1, min(1.0, _flt(os.environ.get(ENV_CPU_SHARE), DEFAULT_CPU_SHARE)))


def detect_budget(profile: dict[str, Any] | None = None,
                  *, low_impact: bool | None = None,
                  cpu_share: float | None = None,
                  mem_limit_mb: int | None = None) -> ResourceBudget:
    """探测本机资源并算出预算。

    优先级：显式入参 > 环境变量 > profiles.yaml 的 `resources` 段 > 常量默认。
    显式入参放在最前，是为了让自测能确定性构造边界（否则测的其实是本机现状）。
    """
    profile = profile or {}
    res_cfg = profile.get("resources", {}) or {}

    cores = os.cpu_count() or 1
    total_mb, avail_mb, load_pct = memory_status()

    if low_impact is None:
        env = os.environ.get(ENV_LOW_IMPACT)
        if env is None or env == "":
            low_impact = _truthy(res_cfg.get("low_impact"), True)
        else:
            low_impact = _truthy(env, True)
    if cpu_share is None:
        cpu_share = _env_cpu_share()
        if ENV_CPU_SHARE not in os.environ and res_cfg.get("cpu_share"):
            cpu_share = _flt(res_cfg.get("cpu_share"), cpu_share)
    # 无论从哪条路来都要夹取一次。放行 0 会让并发归零（扫描直接退化到不能用），
    # 放行 99 会让「份额」这个约束形同不存在 —— 两者都必须在这里被挡住。
    clamped_share = max(0.1, min(1.0, float(cpu_share)))
    share_clamped = abs(clamped_share - float(cpu_share)) > 1e-9
    cpu_share = clamped_share

    budget = ResourceBudget(
        logical_cores=cores,
        physical_cores=physical_cores(),
        mem_total_mb=total_mb,
        mem_avail_mb=avail_mb,
        mem_load_percent=load_pct,
        low_impact=bool(low_impact),
        cpu_share=cpu_share,
    )

    # ---- 线程池上限 ----------------------------------------------------
    env_cap = os.environ.get(ENV_WORKER_CAP)
    if env_cap:
        cap = _as_int(env_cap, MAX_WORKERS)
        budget.worker_cap = max(1, min(cap, MAX_WORKERS))
        budget.notes.append(f"并发上限由环境变量指定为 {budget.worker_cap}")
    elif not budget.low_impact:
        budget.worker_cap = MAX_WORKERS
    else:
        # 按「核数 × 份额」算，再夹到 [MIN_WORKERS, MAX_WORKERS]。
        # 取 floor 而不是 round：宁可少一两个线程，也不要刚好顶到配额。
        cap = int(cores * cpu_share)
        budget.worker_cap = max(MIN_WORKERS, min(cap, MAX_WORKERS))

    # ---- 子进程（Go / 浏览器）------------------------------------------
    if budget.low_impact:
        budget.child_cores = max(1, int(cores * cpu_share))
        if mem_limit_mb is None:
            explicit = os.environ.get(ENV_MEM_LIMIT) or res_cfg.get("child_mem_limit_mb")
            if explicit:
                mem_limit_mb = _as_int(explicit, DEFAULT_MEM_LIMIT_MB)
            else:
                mem_limit_mb = _mem_limit_mb(total_mb, avail_mb)
        budget.child_mem_limit_mb = max(MIN_MEM_LIMIT_MB,
                                        min(int(mem_limit_mb), MAX_MEM_LIMIT_MB))
    else:
        budget.child_cores = cores
        budget.child_mem_limit_mb = 0   # 0 = 不设上限

    if share_clamped:
        budget.notes.append(
            f"⚠ 配置的 CPU 份额超出合法区间 [0.1, 1.0]，已夹取为 {cpu_share:.0%}"
        )
    if budget.low_impact:
        budget.notes.append(
            f"低影响模式生效：Python 并发上限 {budget.worker_cap}、"
            f"子进程限 {budget.child_cores} 核"
            + (f" / {budget.child_mem_limit_mb}MB" if budget.child_mem_limit_mb else "")
            + f"（机器 {cores} 逻辑核，份额 {cpu_share:.0%}）"
        )
        if budget.mem_avail_mb is not None:
            budget.notes.append(
                f"探测时可用物理内存 {budget.mem_avail_mb}MB"
                + (f" / 共 {budget.mem_total_mb}MB" if budget.mem_total_mb else "")
                + (f"（负载 {budget.mem_load_percent}%）"
                   if budget.mem_load_percent is not None else "")
            )
        # 记忆压力提示：本机常态就在 90% 以上，扫描再叠一层就会触发换页，
        # 表现是「CPU 不高但什么都慢」。这条提示是给读者的定位线索，
        # 免得把换页导致的卡顿误判成扫描器有性能缺陷。
        _pressure_note(budget)
    else:
        budget.notes.append(
            "全速模式：并发与子进程均不设限 —— 扫描会占满本机 CPU，"
            "同时使用电脑会明显变卡（这是配置选择，不是故障）"
        )
    return budget


def cap_workers(declared: Any, budget: ResourceBudget | None = None) -> int:
    """把「档位声明的并发」压到本机预算之内。

    两个约束方向不同、不能互相替代，所以取更小者：
      · 档位 `rate.concurrency` —— 别把**目标**打挂（目标侧约束）
      · 本模块 `worker_cap`  —— 别把**本机**拖死（本机侧约束）
    """
    b = budget or _BUDGET
    want = _as_int(declared, b.worker_cap)
    return max(1, min(want, b.worker_cap))


# ==============================================================================
# 进程优先级
# ==============================================================================

def apply_process_priority(low: bool = True) -> str | None:
    """把**当前进程**降到「低于正常」优先级。返回实际生效的优先级名。

    刻意不用 IDLE_PRIORITY_CLASS：那会让扫描慢到不可用，而且某些工具
    在 IDLE 下会被系统饿死。BELOW_NORMAL 的语义正是「把 CPU 让给别人」。
    """
    if not low:
        return None
    if sys.platform.startswith("win"):
        try:
            k = _kernel32()
            if k.SetPriorityClass(k.GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS):
                return "低于正常（BELOW_NORMAL）"
        except Exception:  # noqa: BLE001
            return None
        return None
    try:
        os.nice(UNIX_NICE_INCREMENT)   # type: ignore[attr-defined]
        return f"nice +{UNIX_NICE_INCREMENT}"
    except Exception:  # noqa: BLE001
        return None


def child_creationflags() -> int:
    """子进程创建标志：静默窗口 + 低于正常优先级。

    **子进程必须单独设** —— 父进程的优先级不会被继承，而恰恰是子进程
    （nuclei 是 Go 多核程序、浏览器是无头渲染）把 CPU 吃满。
    只降父进程不降子进程 = 做了功但没效果。
    """
    if not sys.platform.startswith("win"):
        return 0
    flags = 0
    flags |= getattr(subprocess_module(), "CREATE_NO_WINDOW", 0x08000000)
    flags |= getattr(subprocess_module(), "BELOW_NORMAL_PRIORITY_CLASS",
                     BELOW_NORMAL_PRIORITY_CLASS)
    return flags


def subprocess_module() -> Any:
    """延迟导入 subprocess —— 本模块被大量模块导入，避免拉起无关依赖。"""
    import subprocess
    return subprocess


def preexec_fn_low_priority() -> Any:
    """POSIX 侧的子进程降优先级钩子（Windows 不用，返回 None）。

    注意：`preexec_fn` 在 CPython 里是**文档标注为不安全**的（多线程环境下
    可能死锁）。这里只在确有需要时由调用方显式启用，默认不传。
    """
    if sys.platform.startswith("win"):
        return None
    return lambda: os.nice(UNIX_NICE_INCREMENT)   # type: ignore[attr-defined]


_RE_MIB = re.compile(r"^\s*(\d+)\s*(MiB|MB|GiB|GB|KiB|KB|B)?\s*$", re.I)
_MIB_FACTOR = {"": 1, "B": 1 / (1024 * 1024), "KB": 1 / 1024, "KIB": 1 / 1024,
               "MB": 1, "MIB": 1, "GB": 1024, "GIB": 1024}


def _maybe_int(v: Any) -> int | None:
    """能解析成整数就返回，否则 None（区别于 `_as_int`：它吞掉非法值返回默认）。"""
    if v is None or v == "":
        return None
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _parse_mib(v: Any) -> int | None:
    """把 `GOMEMLIMIT` 的写法（`512MiB` / `1GiB` / `1073741824B`）折成 MB。"""
    if v is None:
        return None
    m = _RE_MIB.match(str(v))
    if not m:
        return None
    return max(1, int(int(m.group(1)) * _MIB_FACTOR.get((m.group(2) or "").upper(), 1)))


def _tighten(cur: Any, want: int | None, parse: Any = _maybe_int) -> int | None:
    """取「现有限制」与「本次预算」中**更严**的那个。

    方向很重要：限额是**上限**，所以合并规则是取小，不是覆盖。
    无条件覆盖的后果是把别人设的保护拆掉 —— 具体场景：
    运维为了不让扫描影响生产机，在自己机器上导出 `GOMAXPROCS=2`；
    低影响模式算出 `child_cores=6`，于是把这个 2 改成 6，
    等于**我们主动放宽了操作者设的限制**。这类「优化顺手拆保险」最难发现，
    因为它表现为「扫描一切正常，只是比预期更吃资源」。
    """
    a = parse(cur)
    if a is None:
        return want
    if want is None:
        return a
    return min(a, want)


def apply_child_limits(env: dict[str, str],
                       budget: ResourceBudget | None = None) -> dict[str, str]:
    """在**调用方已构造好的**子进程环境上叠加资源限额（原地改并返回）。

    为什么要这个变体、而不是只用 `child_env()`：`child_env()` 从
    `os.environ` 起底重建一份环境，于是**调用方对环境做的任何剔除都会失效**。
    这不是假想问题 —— 回归入口 `run_all_tests.py` 会先把
    `AISCAN_FEISHU_WEBHOOK` / `AISCAN_FEISHU_SECRET` 从子环境中删掉，
    免得跑测试时真的给全员群发卡片；若这里改用 `child_env()`，
    被删掉的两个变量会被 `os.environ` 原样带回来，**每次回归都会发通知**。

    叠加规则是**取更严者**（见 `_tighten`），不是无条件覆写：
    环境里已经有一个更小的限制时，我们只可能收紧它，绝不放宽。
    """
    b = budget or _BUDGET
    if not b.low_impact:
        # 全速 = 不新增限额。但**不删除**调用方自己设的限额 ——
        # `--full-speed` 的语义是「别替我加限制」，不是「替我把别人的限制删掉」。
        return env
    cores = max(1, b.child_cores)
    env["GOMAXPROCS"] = str(_tighten(env.get("GOMAXPROCS"), cores) or cores)
    if b.child_mem_limit_mb:
        lim = _tighten(env.get("GOMEMLIMIT"), b.child_mem_limit_mb, _parse_mib)
        env["GOMEMLIMIT"] = f"{lim or b.child_mem_limit_mb}MiB"
    # 科学计算库的线程池（numpy/openblas 等）——本工程不用，但浏览器与
    # 第三方二进制可能间接带进来，顺手收口，避免多份线程池叠加。
    for k in _THREADPOOL_ENV_VARS:
        env[k] = str(_tighten(env.get(k), cores) or cores)
    return env


def child_env(extra: dict[str, str] | None = None,
              budget: ResourceBudget | None = None) -> dict[str, str]:
    """构造子进程环境变量：给 Go 运行时划硬边界。

    这一步是**内存优化的关键**：nuclei 是 Go 程序，
      · `GOMAXPROCS`  —— 限死它用几个核（默认是全部核，这就是「CPU 跑满」的来源）
      · `GOMEMLIMIT`  —— 软内存上限，Go 的 GC 会主动贴近它回收。默认无上限，
                        模板库一大就吃几个 GB。设了它会用一点 CPU 换内存。

    注意：本函数从 `os.environ` 起底。若调用方**已经改造过**环境
    （例如剔除了 webhook 之类的敏感项），请改用 `apply_child_limits()`
    叠加到自己的那份环境上，否则改动会被覆盖回去。
    """
    env = dict(os.environ)
    env.update(extra or {})
    return apply_child_limits(env, budget)


def child_kwargs(budget: ResourceBudget | None = None,
                 extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    """一次性拿到子进程该用的 kwargs（不覆盖调用方已有的值）。

    用法：
        subprocess.run(cmd, **resources.child_kwargs())
    """
    b = budget or _BUDGET
    kw: dict[str, Any] = {"env": child_env(extra_env, b)}
    if sys.platform.startswith("win"):
        kw["creationflags"] = child_creationflags()
    return kw


# ==============================================================================
# 全局单例
# ==============================================================================

#: 进程级预算。第一次访问时按环境探测一次，之后复用 ——
#: 反复探测既有开销，也会让「本次用的是什么姿态」在报告里前后不一致。
_BUDGET: ResourceBudget = detect_budget()


def budget() -> ResourceBudget:
    return _BUDGET


def reconfigure(profile: dict[str, Any] | None = None,
                *, low_impact: bool | None = None,
                cpu_share: float | None = None) -> ResourceBudget:
    """按扫描档位重新探测一次（进程级生效，只影响本进程）。"""
    global _BUDGET
    _BUDGET = detect_budget(profile, low_impact=low_impact, cpu_share=cpu_share)
    return _BUDGET


def activate(profile: dict[str, Any] | None = None,
             *, low_impact: bool | None = None,
             cpu_share: float | None = None) -> ResourceBudget:
    """入口处调用一次：重新探测 + 落实进程优先级。幂等。"""
    b = reconfigure(profile, low_impact=low_impact, cpu_share=cpu_share)
    b.priority_applied = apply_process_priority(b.low_impact)
    if b.low_impact and not b.priority_applied:
        b.notes.append(
            "⚠ 进程优先级调整未生效（本平台不支持或调用失败）—— "
            "并发仍受限，但 CPU 抢占不受控"
        )
    return b


# ==============================================================================
# 自测
# ==============================================================================

def _selftest() -> int:
    problems: list[str] = []

    def eq(got: Any, want: Any, what: str) -> None:
        if got != want:
            problems.append(f"{what}：期望 {want}，实际 {got}")

    # ① 低影响模式：并发按「核数 × 份额」，且被夹在 [MIN, MAX]
    b = detect_budget({"resources": {"low_impact": True, "cpu_share": 0.5}},
                      low_impact=True, cpu_share=0.5)
    eq(b.worker_cap, max(MIN_WORKERS, min(int(b.logical_cores * 0.5), MAX_WORKERS)),
       "低影响模式的并发上限")
    if b.worker_cap < MIN_WORKERS or b.worker_cap > MAX_WORKERS:
        problems.append(f"并发上限未被夹取：{b.worker_cap}")
    if b.child_cores < 1:
        problems.append("子进程核数下限必须是 1（0 会让 Go 退化成单核跑不完）")

    # ② 全速模式：不设限，且必须留痕（静默全速会让读者误判扫描姿态）
    f = detect_budget({}, low_impact=False)
    eq(f.worker_cap, MAX_WORKERS, "全速模式的并发上限")
    eq(f.child_mem_limit_mb, 0, "全速模式不得给子进程设内存上限")
    if not any("全速" in n for n in f.notes):
        problems.append("全速模式必须留痕说明（否则报告里看不出姿态）")

    # ③ 份额被夹到合法区间：0 会让并发归零、10 会失控
    tiny = detect_budget({}, low_impact=True, cpu_share=0.0)
    if tiny.cpu_share != 0.1:
        problems.append(f"过小的份额未被夹到 0.1，实际 {tiny.cpu_share}")
    if tiny.worker_cap < MIN_WORKERS:
        problems.append("份额极小的时候并发仍不得低于下限（否则扫描退化成串行）")
    huge = detect_budget({}, low_impact=True, cpu_share=99.0)
    eq(huge.cpu_share, 1.0, "过大的份额夹取")

    # ④ 环境变量可覆盖并发上限（用户手上要有逃生门）
    old = os.environ.get(ENV_WORKER_CAP)
    try:
        os.environ[ENV_WORKER_CAP] = "3"
        ev = detect_budget({}, low_impact=True)
        eq(ev.worker_cap, 3, "环境变量指定的并发上限")
        if not any("环境变量" in n for n in ev.notes):
            problems.append("环境变量覆盖并发上限时必须留痕")
        os.environ[ENV_WORKER_CAP] = "999"
        eq(detect_budget({}, low_impact=True).worker_cap, MAX_WORKERS,
           "环境变量给的过大值也要夹到上限")
    finally:
        if old is None:
            os.environ.pop(ENV_WORKER_CAP, None)
        else:
            os.environ[ENV_WORKER_CAP] = old

    # ⑤ cap_workers 取「档位声明」与「本机预算」的**更小者** —— 这是本模块
    #    存在的意义：两个约束方向不同，谁大听谁的会把另一侧打穿。
    b2 = detect_budget({}, low_impact=True, cpu_share=0.5)
    b2.worker_cap = 4
    eq(cap_workers(20, b2), 4, "档位要 20、本机只给 4 → 必须听本机")
    eq(cap_workers(2, b2), 2, "档位要 2、本机给 4 → 必须听档位（目标侧约束优先）")
    eq(cap_workers(None, b2), 4, "档位没写时用本机上限")
    eq(cap_workers("bad", b2), 4, "非法值不得让并发变成 0")

    # ⑥ 子进程环境：**必须在「无继承限额」的基线上断言**。
    #    这里踩过一次：第一版直接 `child_env(None, b3)` 就断言
    #    `GOMEMLIMIT == "512MiB"`，而回归入口 `run_all_tests.py` 会给每一环
    #    导出 GOMAXPROCS / GOMEMLIMIT。`child_env()` 从 `os.environ` 起底，
    #    于是断言测的其实是「回归入口设了什么」，与本模块无关 —— 在回归里必红，
    #    在手工单跑时却全绿。**同一份自测在两种入口下结论不同，本身就是缺陷。**
    #    所以先把继承来的限额清掉，再依次覆盖三种情形。
    _LIMIT_VARS = ("GOMAXPROCS", "GOMEMLIMIT", *tuple(_THREADPOOL_ENV_VARS))
    _saved = {k: os.environ.get(k) for k in _LIMIT_VARS}
    try:
        for _k in _LIMIT_VARS:
            os.environ.pop(_k, None)

        # ⑥-1 低影响：限额必须真的写进去，且等于预算值
        b3 = detect_budget({}, low_impact=True, cpu_share=0.5)
        b3.child_cores = 3
        b3.child_mem_limit_mb = 512
        env = child_env(None, b3)
        eq(env.get("GOMAXPROCS"), "3", "子进程 GOMAXPROCS")
        eq(env.get("GOMEMLIMIT"), "512MiB", "子进程 GOMEMLIMIT")
        if not env.get("OMP_NUM_THREADS"):
            problems.append("应顺手收口 OMP 等线程池变量（多份线程池叠加会再吃一遍 CPU）")

        # ⑥-2 全速：**不新增**限额，但也不删除调用方已设的限额。
        #     `--full-speed` 的语义是「别替我加限制」，不是「替我把别人的限制删掉」。
        fe = child_env(None, detect_budget({}, low_impact=False))
        if fe.get("GOMAXPROCS") or fe.get("GOMEMLIMIT"):
            problems.append("全速模式不得注入 GOMAXPROCS / GOMEMLIMIT")
        os.environ["GOMAXPROCS"] = "2"
        os.environ["GOMEMLIMIT"] = "256MiB"
        fe2 = child_env(None, detect_budget({}, low_impact=False))
        if fe2.get("GOMAXPROCS") != "2" or fe2.get("GOMEMLIMIT") != "256MiB":
            problems.append("全速模式把调用方自己设的限额删掉了 —— "
                            "操作者手动加的保护不该被我们清掉")

        # ⑥-3 低影响**不得放宽**环境里更严的限额（只能收紧）。
        #     这条是本模块最容易「好心办坏事」的地方：无条件覆写的话，
        #     运维为了不影响生产而在自己机器上设的 GOMAXPROCS=2 / GOMEMLIMIT=128MiB
        #     会被我们按预算改成 6 / 512MiB —— 表现为「扫描一切正常，
        #     只是比预期更吃资源」，没有任何报错。
        os.environ["GOMAXPROCS"] = "1"
        os.environ["GOMEMLIMIT"] = "128MiB"
        os.environ["OMP_NUM_THREADS"] = "1"
        tight = child_env(None, b3)          # 预算想要 3 核 / 512MiB
        eq(tight.get("GOMAXPROCS"), "1", "环境里更严的 GOMAXPROCS 不得被放宽")
        eq(tight.get("GOMEMLIMIT"), "128MiB", "环境里更严的 GOMEMLIMIT 不得被放宽")
        eq(tight.get("OMP_NUM_THREADS"), "1", "环境里更严的线程池上限不得被放宽")

        # ⑥-4 反向：环境值更宽松时必须收紧到预算值
        #     （不能因为「环境里有值」就当它已经是限制而放过）
        os.environ["GOMAXPROCS"] = "64"
        os.environ["GOMEMLIMIT"] = "8GiB"
        os.environ["OMP_NUM_THREADS"] = "64"
        loose = child_env(None, b3)
        eq(loose.get("GOMAXPROCS"), "3", "环境里更宽的 GOMAXPROCS 必须被收紧到预算值")
        eq(loose.get("GOMEMLIMIT"), "512MiB", "环境里更宽的 GOMEMLIMIT 必须被收紧")
        eq(loose.get("OMP_NUM_THREADS"), "3", "环境里更宽的线程池上限必须被收紧")

        # ⑥-5 非法写法不得被当成「没有值」而把无上限放过去
        os.environ["GOMEMLIMIT"] = "not-a-size"
        eq(child_env(None, b3).get("GOMEMLIMIT"), "512MiB",
           "无法解析的 GOMEMLIMIT 应以预算值为准（不得当作无限制）")
        # GiB / 纯数字写法都要能折成 MB，否则「更严的判断」会静默失效
        eq(_parse_mib("1GiB"), 1024, "GiB 折算")
        eq(_parse_mib("1024"), 1024, "纯数字按 MB 理解")
        eq(_parse_mib(""), None, "空值视为未设置")
    finally:
        for _k, _v in _saved.items():
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v

    # ⑥-b apply_child_limits 必须在**调用方那份环境**上叠加，不得把
    #     调用方剔除过的变量从 os.environ 带回来。
    #     真实后果是「回归时给全员群发飞书卡片」—— run_all_tests 会先删掉
    #     AISCAN_FEISHU_WEBHOOK，若这里重建环境就会把它带回来。
    os.environ["AISCAN_FEISHU_WEBHOOK"] = "https://should-not-survive.example/hook"
    try:
        mine = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"}
        apply_child_limits(mine, b3)
        if "AISCAN_FEISHU_WEBHOOK" in mine:
            problems.append(
                "apply_child_limits 把调用方剔除过的环境变量带回来了 —— "
                "回归会因此真的发出飞书通知")
        if mine.get("GOMAXPROCS") != "3":
            problems.append("apply_child_limits 未叠加 GOMAXPROCS")
        if mine.get("PYTHONIOENCODING") != "utf-8":
            problems.append("apply_child_limits 不得改动调用方的其它环境变量")
    finally:
        os.environ.pop("AISCAN_FEISHU_WEBHOOK", None)

    # ⑦ 子进程创建标志：Windows 必须带「低于正常优先级」。
    #    只降父进程不降子进程是本模块最容易犯的错 —— 吃 CPU 的恰恰是子进程。
    if sys.platform.startswith("win"):
        flags = child_creationflags()
        if not (flags & BELOW_NORMAL_PRIORITY_CLASS):
            problems.append("Windows 子进程创建标志缺少 BELOW_NORMAL_PRIORITY_CLASS")
        if not (flags & 0x08000000):
            problems.append("Windows 子进程创建标志缺少 CREATE_NO_WINDOW")
    kw = child_kwargs(b3)
    if "env" not in kw:
        problems.append("child_kwargs 必须给出 env")

    # ⑧ 运行姿态必须可读、且**低影响与全速两种都要说清**
    pl = b3.posture_line()
    if "低影响" not in pl or "不影响你同时使用电脑" not in pl:
        problems.append(f"低影响姿态说明不完整：{pl}")
    pf = detect_budget({}, low_impact=False).posture_line()
    if "全速" not in pf or "占满" not in pf:
        problems.append(f"全速姿态未如实提示会占满 CPU：{pf}")

    # ⑨ 探测失败不得编造数字
    if not isinstance(b3.logical_cores, int) or b3.logical_cores < 1:
        problems.append("逻辑核数必须 ≥ 1（探测不到时也要有可用值）")

    # ⑩ 降优先级真的会调用系统接口（生效与否如实返回，不假装成功）
    name = apply_process_priority(True)
    if sys.platform.startswith("win"):
        if not name:
            problems.append("Windows 上降优先级应返回生效的优先级名")
        elif "BELOW_NORMAL" not in name and "低于正常" not in name:
            problems.append(f"优先级名不符：{name}")
        if apply_process_priority(False) is not None:
            problems.append("关闭低影响时不得再动优先级")
    # 复原：自测不能把调用方进程永久降级（回归里这一环后面还要跑别的）
    _restore_normal_priority()

    # ⑪ 内存上限的取值：两个口径取更小者，且被夹在 [MIN, MAX]
    #    这一组的价值在于**本机的实际处境**：常态可用仅 1GB 左右，
    #    所以真正起作用的必须是「可用内存 / 2」这一项，而不是「总内存 / 8」。
    eq(_mem_limit_mb(16000, 1000), max(MIN_MEM_LIMIT_MB, 500),
       "内存告急时应按可用内存收敛（取更小者）")
    eq(_mem_limit_mb(16000, 8000), 2000, "内存宽裕时按总内存 /8 封顶")
    eq(_mem_limit_mb(32000, 30000), 4000, "内存宽裕的大机器按总内存 /8")
    eq(_mem_limit_mb(128000, 100000), MAX_MEM_LIMIT_MB, "上限必须夹到 MAX")
    eq(_mem_limit_mb(1000, 64), MIN_MEM_LIMIT_MB, "下限必须夹到 MIN（否则子进程被饿死）")
    if _mem_limit_mb(None, None) != DEFAULT_MEM_LIMIT_MB:
        problems.append("探测不到内存时应退回默认值，而不是给 0（0 = 不设限）")
    if _mem_limit_mb(16000, 1000) >= MAX_MEM_LIMIT_MB:
        problems.append("内存告急时不得给出最大配额 —— 那等于没有约束")

    # ⑫ 内存告急必须提示出来（本机常态就在 90%+，不提示会被误判成扫描器缺陷）
    hot = ResourceBudget(low_impact=True, logical_cores=12, cpu_share=0.5,
                         mem_total_mb=16000, mem_avail_mb=900, mem_load_percent=93,
                         worker_cap=6, child_cores=6, child_mem_limit_mb=450)
    _pressure_note(hot)
    if not any("换页" in n for n in hot.notes):
        problems.append("内存负载 ≥85% 时必须给出换页提示")
    cool = ResourceBudget(low_impact=True, logical_cores=12, mem_load_percent=40)
    _pressure_note(cool)
    if any("换页" in n for n in cool.notes):
        problems.append("内存宽裕时不得报警（每份报告都报警等于没报警）")

    # ⑫-b 提示必须**点名到进程**，否则用户没法执行。
    #     用注入的确定性数据断言格式，不依赖本机此刻开着什么。
    hot2 = ResourceBudget(low_impact=True, logical_cores=12, cpu_share=0.5,
                          mem_total_mb=16000, mem_avail_mb=900, mem_load_percent=93)
    _pressure_note(hot2, consumers=[("chrome.exe", 1643), ("python.exe", 236)])
    joined = " ".join(hot2.notes)
    if "chrome.exe" not in joined or "1.6GB" not in joined:
        problems.append(f"内存告急提示未点名到具体进程/用量：{joined!r}")
    if "236MB" not in joined:
        problems.append(f"不足 1GB 的进程应以 MB 显示：{joined!r}")
    if "扫描器自身" not in joined:
        problems.append("点名进程时必须把「谁占的」与「本工具占的」分开说 —— "
                        "否则读者会把浏览器占的 1.6GB 读成扫描器占的")
    # 取不到进程清单时退回泛化建议，不得报错也不得留空
    hot3 = ResourceBudget(low_impact=True, logical_cores=12, mem_load_percent=93)
    _pressure_note(hot3, consumers=[])
    if not any("换页" in n for n in hot3.notes):
        problems.append("拿不到进程清单时仍须给出换页提示（退化为泛化建议）")
    # top_memory_processes 在真实机器上不得抛异常，且合并同名多进程
    try:
        real = top_memory_processes(limit=3)
        if not isinstance(real, list) or any(
                not (isinstance(x, tuple) and len(x) == 2
                     and isinstance(x[0], str) and isinstance(x[1], int))
                for x in real):
            problems.append(f"进程清单格式不对：{real!r}")
        if real and any(mb <= 0 for _n, mb in real):
            problems.append("进程清单里出现了 0 或负的内存值")
        if real and real != sorted(real, key=lambda kv: -kv[1]):
            problems.append("进程清单未按内存降序（读者只会看第一条）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"进程清单探测不得抛异常：{type(e).__name__}: {str(e)[:80]}")

    # ⑬ detect_budget 的默认路径也要带上内存上限与压力提示（端到端，不只看纯函数）
    live = detect_budget({}, low_impact=True)
    if live.child_mem_limit_mb < MIN_MEM_LIMIT_MB:
        problems.append(f"端到端内存上限低于下限：{live.child_mem_limit_mb}")
    if ("GOMEMLIMIT" not in child_env(None, live)):
        problems.append("端到端子进程环境缺少 GOMEMLIMIT")

    if problems:
        print("资源预算自测不通过：")
        for x in problems:
            print(f"  ✗ {x}")
        return 1
    print("资源预算自测：通过（15 组断言）")
    print(f"  {live.posture_line()}")
    print(f"  机器：{live.logical_cores} 逻辑核"
          + (f"，可用内存 {live.mem_avail_mb}MB / 共 {live.mem_total_mb}MB"
             f"（负载 {live.mem_load_percent}%）"
             if live.mem_avail_mb else "，内存探测不可用"))
    print(f"  子进程配额：GOMAXPROCS={child_env(None, live).get('GOMAXPROCS')}"
          f"、GOMEMLIMIT={child_env(None, live).get('GOMEMLIMIT')}")
    return 0


def _restore_normal_priority() -> None:
    """把当前进程优先级复原（自测用）。"""
    if not sys.platform.startswith("win"):
        return
    try:
        k = _kernel32()
        k.SetPriorityClass(k.GetCurrentProcess(), NORMAL_PRIORITY_CLASS)
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
