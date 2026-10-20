# -*- coding: utf-8 -*-
"""
扫描流程编排器
==============
职责：把六个阶段串成一条可重复执行的流水线。

    L1 资产测绘 → L2 扫描采集 → L3 脚本验证 → L4 危害定级 → L5 报告 → L6 复扫比对

设计原则：
  - 阶段隔离：任一阶段失败不导致整体中断，失败信息记入报告附录。
    （扫描工程最常见的问题就是「跑了三小时最后一步挂了，什么都没留下」）
  - 全程留痕：每个阶段的状态、耗时、产出都记录，便于复盘与审计。
  - 结果归档：按「目标 + 时间戳」落盘，为周期化扫描与 diff 预先铺好结构。
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from checklist.loader import Checklist, load_checklist  # noqa: E402
from diff.differ import Differ  # noqa: E402
from engine.applicability import (  # noqa: E402
    ApplicabilityEngine,
    ApplicabilityResult,
    TargetFeatures,
    build_example_features,
)
from engine.authz_matrix import AuthzMatrix, load_accounts  # noqa: E402
from engine.fingerprint import Fingerprinter  # noqa: E402
from engine.frontend import has_material as _frontend_has_material  # noqa: E402
from engine.js_analyzer import JsAnalyzer  # noqa: E402
from engine.nuclei_runner import BuiltinDetector, NucleiRunner  # noqa: E402
from engine.registry import ItemResult  # noqa: E402
from engine.registry_runner import (  # noqa: E402
    build_context, merge_with_legacy, run_all_items, summarize as summarize_detectors,
)
# 扫描模式常量从这里取 —— 默认值（黑客运维视角）只定义在 engine/redteam.py 一处，
# 命令行与引擎共用，避免「命令行说红队、引擎跑合规」的静默不一致。
from engine.redteam import (  # noqa: E402
    DEFAULT_MODE, IMPACT_L2, IMPACT_ORDER, MODE_REDTEAM, SCAN_MODES,
)
# 资源预算：把「别把这台电脑拖垮」变成扫描的默认运行姿态（降优先级 +
# 封并发 + 给子进程划核划内存）。报告要据此披露本次跑在什么姿态下。
from engine import resources  # noqa: E402
from engine.tools import Toolchain  # noqa: E402
from ledger.auth_ledger import AuthLedger  # noqa: E402
from models import Finding, FindingSet  # noqa: E402
from report.generator import ReportContext, ReportGenerator  # noqa: E402
from engine.gate import ReportGate  # noqa: E402
from rules.grading import GradingEngine  # noqa: E402
from verify.framework import ScriptBuilder, VerifyRunner  # noqa: E402


def boundary_short_circuit(boundary_blocked: bool, boundary: Any,
                           guard: Any) -> tuple[dict[str, Any] | None, str]:
    """逐项检测开始前的边界短路标记。返回 (标记, 说明)；不短路时 (None, "")。

    **两类拦截在这一点上同权**：都表示「从此刻起请求不再触达应用」，
    因此后续检查项一律短路成「未执行」，而不是继续在拦截页上跑。

      · A 类：L1 勘察即发现全量拦截（`boundary.blocked`）；
      · B 类：L1 正常，运行期守门转终态且**未恢复**（`guard.report.terminal`）。

    抽成独立函数是为了可断言：2026-09-29 内部生产系统 事故里，B 类这一支**根本不存在**
    （逐项检测只认 A 类），但它在 21 分钟的扫描里一句话都不报 —— 只让全量
    检查项在 405 拦截页上跑完。这类「静默失效」的分支必须有直接断言钉住，
    不能只靠「跑完不报错」证明它有效。
    """
    if boundary_blocked:
        vendor = str(getattr(boundary, "vendor", "") or "")
        status = int(getattr(boundary, "status", 0) or 0)
        return (
            {"reason": (f"边界防护全量拦截（{vendor or '未知厂商'}，"
                        f"HTTP {status}），请求未触达应用"),
             "vendor": vendor, "status": status},
            f"⚠ 边界防护全量拦截（{vendor or '未知厂商'}）："
            "所有检查项按「未执行」记录，报告不对应用本身下任何结论",
        )

    _rep = getattr(guard, "report", None) if guard is not None else None
    if _rep is not None and bool(getattr(_rep, "terminal", False)):
        vendor = str(getattr(_rep, "vendor", "") or "")
        return (
            {"reason": (f"扫描中途被边界封禁且退避未恢复"
                        f"（{vendor or '厂商未确认'}），请求已不再触达应用"),
             "vendor": vendor, "status": 0, "kind": "mid_scan_ban"},
            f"⚠ L2 期间被边界封禁且退避未能恢复（{vendor or '厂商未确认'}）："
            "全部检查项按「未执行」记录，**不得把「未执行」读成「通过」**",
        )

    return None, ""


class _BoundarySkip(Exception):
    """边界防护全量拦截时用于跳过应用侧采集的内部信号。

    单独定义一个异常而不是复用 Exception，是为了让「主动跳过」与
    「真的出错」在上层能区分开 —— 前者记 skipped，后者记 failed。
    """
from verify.mask import Masker  # noqa: E402


def _bypass_worth_probing(boundary: Any) -> str:
    """边界绕过试探的**分流判据**：本轮值不值得烧那十来发流量。

    返回触发原因（人话，直接进进度输出与报告）；返回空串 = 不值得做。

    为什么要分流（2026-09-30）：旧实现无条件跑。目标根本没有边界拦截时，
    12 个变形的结果全是「未被拦」—— 那既不是绕过证据（本来就没拦，
    没有可绕之物），又白白多打一批请求。而**流量本身就是频次封禁的触发器**：
    本项目实测的封禁就是按请求量触发的，这几发可能正是压垮骆驼的那一根。

    边界要划准，两个方向都不能错：
      · 探到拦截行为（全量接管 / 厂商特征 / 整站同码提示）→ **做**。
        这是「有拦可绕」的唯一前提。哪怕此刻基线不成立（本来源已被整体
        拦死），也照样要做 —— 「基线不通、而某个变形通了」恰恰是最值钱的
        绕过发现，由 `wafbypass.summarize()` 的 `bypass_candidates` 承接。
      · 什么拦截迹象都没有 → **不做**。此时变形「未被拦」证明不了任何事。
        跳过必须在报告里具名说明，不得静默 —— 否则读者会把「没试绕过」
        读成「试过了、防护有效」。
    """
    if boundary is None:
        return ""
    if getattr(boundary, "blocked", False):
        return "已判定边界防护全量接管"
    if str(getattr(boundary, "signature", "") or ""):
        return "响应命中边界防护厂商拦截页特征"
    if any("整站同一响应" in str(n)
           for n in (getattr(boundary, "notes", None) or [])):
        return "指纹阶段整站返回同一状态码，疑似统一接管"
    return ""


def bypass_late_probe_reason(l1_blocked: bool, guard_occurred: bool,
                             already_probed: bool) -> str:
    """运行期才出现的封禁（B 类）是否该**补做**一次绕过试探。返回原因；空串 = 不必补。

    为什么要有这个函数（2026-09-30 内部生产系统 实测，真实缺陷）：
    `_bypass_worth_probing` 只在 **L1 时点**评估一次。那时流量通常还没被封，
    判「没有拦可绕」是**当时的事实**，跳过试探也合理。但扫描中段（nuclei 跑了
    7 分钟后）确实触发了封禁 —— 新证据推翻了旧判断，而代码**从不回头重判**。

    后果有两层，第二层更严重：
      ① 该做的绕过试探没做（安全负责人的要求是「被拦 → 尝试绕过 → 出结论」）；
      ② 报告一边写「持续请求累计到一定量后**触发拦截且未恢复**」，
         一边在「绕过尝试」下面写「**本次既没撞上墙**，也就没有可绕之物」——
         **同一节里两句互相矛盾，后一句是假的**。通告要贴进部门大群，
         这种自相矛盾会让读者连前面的真话一起不信。

    判据三态，都不许合并：
      · 已经探过（A 类：L1 就判出要探，那一处已执行）→ 不重复探
      · L1 已判全量接管（A 类）→ 不重复探
      · **只有运行期才出现封禁（B 类）** → 补探 —— 这正是本条要修的情形
    """
    if already_probed or l1_blocked:
        return ""
    if not guard_occurred:
        return ""
    return "运行期触发边界封禁（L1 判定时未探到拦截行为）"


def _health_confirm(url: str) -> int:
    """健康度守门的「打一枪看站还活着没」—— 只在判据达标时调用，全轮最多一次。

    为什么单独写、不走探测客户端：

    1. 这一枪的意义是**存活确认**，必须绕过节流与结果缓存 —— 走探测客户端
       会被限速排到后面，等它排到时结论已经过期了；
    2. `trust_env=False`：不走系统代理。否则「站点还活着」这个结论可能是
       代理给的缓存响应，据此继续施压就守不住门；
    3. 失败（异常 / 超时）一律返回 0 —— 取不到就是「不能证明活着」，
       **不猜**，由守门按真故障处理。
    """
    try:
        import requests  # noqa: PLC0415

        sess = requests.Session()
        sess.trust_env = False
        r = sess.get(
            url, timeout=8, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; aiscan-healthcheck)"})
        return int(getattr(r, "status_code", 0) or 0)
    except Exception:  # noqa: BLE001
        return 0


#: 本编排器**计划**要走的阶段（顺序即实际顺序）。
#:
#: 存在的唯一理由：进度显示要有分母。只有「阶段 7」时读者不知道还剩多少 ——
#: 一次标准档扫描十几分钟，而阶段耗时极不均匀（授权闸门 0.0s、逐项检测 96s），
#: 没有分母就没法估计还要多久。
#:
#: **分母只能由拥有阶段的人给出。** 写死在进度器里一定会漂移（那正是本项目
#: 反复踩的「配了却没人读」家族）；因此这里声明，收尾时
#: `ProgressReporter.close()` 核对「实到 vs 计划」，对不上就在前台明说
#: 「进度显示的总量不准」—— **不让进度显示自己说谎**。
#:
#: 改动阶段序列时必须同步改这里；`selftest_redteam.py` 会对真实扫描的
#: 阶段序列做等值断言，漏改会立刻红（而不是让分母悄悄骗人）。
#:
#: 阶段名里的「多少项」**从清单现读，不写死**（红线 42 同一族：写死的数字
#: 必然与清单漂移 —— 清单从 163 涨到 166 时前台还在报「163 项」，而实际跑了
#: 166 项，读者拿到的覆盖率口径就是错的）。读不到清单时降级为不显示数字，
#: **不猜一个数**（猜出来的数字比没有数字更危险）。
def _checklist_item_count() -> int:
    """清单总项数。读不到返回 0（调用方降级为不带数字的阶段名）。"""
    try:
        return len(load_checklist().items)
    except Exception:
        return 0


_CHECKLIST_N: int = _checklist_item_count()

ITEMS_STAGE_NAME: str = (
    f"L2 逐项检测（{_CHECKLIST_N} 项状态机）" if _CHECKLIST_N else "L2 逐项检测（全量项状态机）"
)

PLANNED_STAGES: tuple[str, ...] = (
    "运行姿态（资源预算）",
    "授权闸门",
    "工具链探测",
    "L1 资产测绘与指纹识别",
    "L2 适用性判定",
    "L1 边界防护与可达性判定",
    "L2 扫描采集",
    "L2 权限矩阵验证",
    ITEMS_STAGE_NAME,
    "L3 脚本验证与准入闸门",
    "L3.5 结果证明（攻击目标达成性）",
    "L4 危害定级",
    "L4.5 攻击目标编排（红队）",
    "L4.6 攻击链组合（发现 → 目标）",
    "L4.7 链补证（派发受控实测）",
    "L5 报告生成",
    "L6 复扫比对",
)


@dataclass
class StageRecord:
    """一个阶段的执行记录。"""

    name: str
    status: str = "pending"      # pending / ok / failed / skipped
    duration_ms: int = 0
    detail: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status,
                "duration_ms": self.duration_ms, "detail": self.detail, "error": self.error}


def wait_for_credentials(build_plan_fn: Any, timeout_s: int,
                         poll_s: float = 10.0,
                         log_fn: Any = None) -> tuple[bool, Any]:
    """等待凭据写入凭据库。`build_plan_fn()` 每次轮询重建凭据计划，
    不再有待补身份即就位。返回 (是否就位, 最终计划)。

    抽成独立函数是为了可测：等待循环是「唯一人工触点」的核心，
    埋在 scan 里就没法不跑全场扫描来验证它了。
    """
    deadline = time.time() + max(1, int(timeout_s))
    started = time.time()
    last_beat = time.time()
    while time.time() < deadline:
        time.sleep(min(poll_s, max(0.5, deadline - time.time())))
        plan = build_plan_fn()
        if plan is not None and not plan.pending:
            return True, plan
        if log_fn is not None and time.time() - last_beat >= 60:
            last_beat = time.time()
            log_fn(f"  … 仍在等待凭据（已等 {int(time.time() - started)} 秒）")
    return False, build_plan_fn()


def _save_cred_needs(archive_dir: Path | str, cred_ask: dict[str, Any]) -> Path | None:
    """把凭据需求清单写进归档。**不含任何凭据原文**，只写「缺哪个身份、去哪拿」。"""
    try:
        from engine import credguide as _cg  # noqa: PLC0415

        p = Path(archive_dir) / _cg.NEED_FILE_NAME
        p.write_text(json.dumps(cred_ask, ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return p
    except Exception:  # noqa: BLE001
        return None


@dataclass
class ScanResult:
    """一次完整扫描的结果。"""

    target_name: str
    domain: str
    archive_dir: Path
    stages: list[StageRecord] = field(default_factory=list)
    finding_set: FindingSet | None = None
    applicability: list[ApplicabilityResult] = field(default_factory=list)
    item_results: list[ItemResult] = field(default_factory=list)
    detector_summary: dict[str, Any] = field(default_factory=dict)
    detector_notes: list[str] = field(default_factory=list)
    reports: dict[str, Path] = field(default_factory=dict)
    diff_markdown: str = ""
    # 外部引擎（nuclei）执行情况。周期化通知要靠它判断本轮覆盖是否被截断
    # —— 截断过的那一轮，任何「没检出」都不能读成「没问题」。
    nuclei_run: dict[str, Any] = field(default_factory=dict)
    # 凭据索取清单（空 = 不需要补）。它对应的检查项状态不变 ——
    # 记录它只是为了「告诉你去哪拿」，不是把未执行悄悄变成已完成。
    cred_ask: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_name,
            "domain": self.domain,
            "archive_dir": str(self.archive_dir),
            "stages": [s.to_dict() for s in self.stages],
            "counts": self.finding_set.counts() if self.finding_set else {},
            "detector_summary": self.detector_summary,
            "reports": {k: str(v) for k, v in self.reports.items()},
            "nuclei": dict(self.nuclei_run or {}),
            "cred_ask": dict(self.cred_ask or {}),
        }


class Orchestrator:
    """扫描流程编排器。"""

    def __init__(
        self,
        config_dir: Path | str | None = None,
        profile: str | None = None,
        ledger_path: Path | str | None = None,
    ):
        self.root = Path(config_dir) if config_dir else ROOT
        self.profile_name = profile or "standard"
        self.profiles = self._load_profiles()
        self.profile = self.profiles.get("profiles", {}).get(self.profile_name, {})
        #: 全档位速率硬上限的**留痕**（空串 = 本次没有被封顶）。
        #: `hard_limits.rate_ceiling_rps` 此前在代码里**零读取点** ——
        #: 档位写着硬上限，实际谁来都拦不住，是典型的「配了却没人读」。
        #: 现在在这里落地：任何档位的速率被顶到这个上限都要留痕并进报告，
        #: 因为「你以为跑在 20 rps，实际被削到 20」这种事必须能被说出来。
        self._rate_ceiling_clamp: str = ""
        self.rate_ceiling_rps: int = 0
        self._apply_hard_limits()
        self.checklist: Checklist = load_checklist()
        self.tools = Toolchain()
        self.ledger = AuthLedger(ledger_path)
        self.masker = Masker("internal")
        self.stages: list[StageRecord] = []
        # 边界防护判定结果（None 表示未判定）。报告必须把「被拦截」写显眼，
        # 否则读者会把「没结论」看成「没问题」。
        self._boundary: Any = None
        # 边界防护绕过试探结果（wafbypass.probe_bypasses 的产出）。
        # 探到防护之后红队的标准动作是试绕过 —— 不试，通告里「防护有效」
        # 就只是「正面硬闯没闯进去」的结论。
        self._bypass_probes: list[dict[str, Any]] = []
        # 绕过试探被**跳过**时的具名原因（空串 = 执行了）。
        # 跳过不是「没做」，必须在报告里说清为什么不做 —— 否则读者会把
        # 「没试绕过」读成「试过了，防护有效」。2026-09-30 起：未探到拦截
        # 行为时不再无条件烧 12 发流量（那 12 发本身就是触发频次封禁的流量）。
        self._bypass_skip_reason: str = ""
        #: 目标健康度守门触发的**停手原因**（空串 = 未触发）。
        #: `hard_limits.stop_on` 的执行结果。必须与「被边界封禁」分开披露：
        #: 前者是「请求没到应用」，后者是「请求到了、应用在报错」——
        #: 措辞互换就是写假话。2026-09-30 起该配置项真正生效。
        self._target_health_stop: str = ""
        #: 健康度守门被 AISCAN_HEALTH_GUARD=off 显式关闭（一次性靶场基准专用
        #: 逃生门：靶场对畸形探针返 5xx 是应用的**正常应答形态**，守门会把
        #: 整轮扫描拦腰截断）。默认 False；为 True 时必须进报告具名披露 ——
        #: 降级/关闭必须能被说出名字，不许静默。
        self._health_guard_off: bool = False
        # 红队模式产出的攻击目标结论（空列表表示未启用红队模式）
        self._objectives: list[Any] = []
        # 最近一次复扫比对结果（None = 首次扫描或比对失败）。周期化通知要用它。
        self._last_diff: Any = None
        # 攻击链组合结果（发现 → 目标的因果链），以及被回填结论的目标清单
        self._chains: list[Any] = []
        self._chain_filled: list[str] = []
        self._chain_notes: list[str] = []
        # 凭据索取：扫描发现「需要登录态但没有」时，必须主动给出取证指引，
        # 而不是记一句「未配置测试账号」就结束。下面三项是生成指引所需的证据。
        self._fp_path_probes: dict[str, Any] = {}
        self._session_accounts: list[dict[str, Any]] = []
        self.last_cred_plan: Any = None
        self._target_url = ""
        # 进度显示。默认 **关闭**：库调用与自测不该被几十行进度淹没；
        # 命令行（aiscan.py cmd_scan）会显式挂上 ProgressReporter。
        self.progress: Any = None
        # 黑客视角的凭据获取结果（engine.credhunt.HuntResult）。
        # 红队不向运维要账号 —— 零凭据自己试入口与默认口令，试到什么算什么。
        self.credhunt: Any = None
        # 凭据情报（engine.credosint.OsintResult）：自己上网找登录凭据。
        # 与 credhunt 的分工是「想试什么」与「怎么试」——本模块只产出候选与线索，
        # 实际提交仍走 credhunt 那一个受控循环，安全边界只需守一处。
        self.credosint: Any = None
        #: 关闭凭据情报 / 只关联网部分（保留本地产品默认口令库）。
        #: CLI `--no-credosint` 与之对应；联网关闭的意义是**不去碰外部检索源**，
        #: 因为每一次检索都会向第三方暴露「有人正在关注该目标」。
        self._no_credosint: bool = False
        self._no_credosint_online: bool = False
        #: 本次需要「登录身份」的检查项（自取身份成功与否都要用到，见
        #: _note_account_gap_if_any —— 它决定我们怎么向读者交代这件事）。
        self._need_accounts_for_note: list[Any] = []
        #: 凭据获取阶段产出的发现（命中默认口令时才有），进入采集阶段后并入总集
        self._credhunt_findings: list[Any] = []
        # 凭据等待秒数：**只在显式指定时生效**（见 scan() 里的门控）。
        self.cred_wait_seconds = 0
        self.cred_wait_explicit = False
        # 默认黑客运维视角。真正的默认值定义在 engine/redteam.py，此处只引用。
        self.mode = DEFAULT_MODE
        # 本次实际生效的**影响级别上限**（档位与台账取更保守的一个）。
        # 报告里要披露它 —— 否则「未能验证」的成因（是打不穿，还是本次授权不够）
        # 无法被读者判断。
        self._impact_cap: str = ""
        #: 本次的运行姿态（ResourceBudget）。None = 资源模块不可用/未启用。
        #: 报告要据此披露「这次跑在什么姿态下」—— 静默降速与静默降级同罪。
        self._resource: Any = None

    # ------------------------------------------------------------------
    def _load_profiles(self) -> dict[str, Any]:
        p = self.root / "config" / "profiles.yaml"
        if not p.exists():
            return {}
        import yaml
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    def _apply_hard_limits(self) -> None:
        """把 `hard_limits` 里对**行为**有约束力的字段真正落到本次档位上。

        存在的理由：`config/profiles.yaml` 的 `hard_limits` 长期只有一个读取点
        （`aiscan.py` 打印 `forbidden_always` 给操作者看），
        `rate_ceiling_rps` 与 `stop_on` 在代码里**没有任何读取点**。
        后果不是「少了一个功能」，而是**虚假保证**：档位文件的措辞让操作者
        以为「无论哪一档，速率都不会超过 200 rps」「目标返 5xx 会自动停」，
        而实际两件事都没发生。按本项目红线 —— 配置承诺了就必须兑现，
        兑现不了就必须能被说出名字。

        这里只处理 `rate_ceiling_rps`（纯配置收敛，无副作用）。
        `stop_on` 依运行期观测触发，不在此处；其执行体见
        `engine.banguard.TargetHealthWatch`，接线在 `engine.registry_runner`。
        """
        hl = self.profiles.get("hard_limits", {}) or {}
        try:
            ceiling = int(hl.get("rate_ceiling_rps") or 0)
        except (TypeError, ValueError):
            ceiling = 0
        self.rate_ceiling_rps = ceiling
        if ceiling <= 0:
            return
        rate = self.profile.setdefault("rate", {})
        clamps: list[str] = []
        for field in ("requests_per_second", "per_host_rps"):
            try:
                v = float(rate.get(field) or 0)
            except (TypeError, ValueError):
                continue
            if v > ceiling:
                rate[field] = ceiling
                clamps.append(f"{field} {v:g}→{ceiling}")
        # nuclei 的 rate_limit 也是「打目标的速率」，必须受同一个上限约束 ——
        # 否则从 nuclei 那条通道绕过了硬上限（一条通道合规、另一条无限制，
        # 整体就不是「硬上限」）。
        nuc = self.profile.get("nuclei", {}) or {}
        try:
            nrl = int(nuc.get("rate_limit") or 0)
        except (TypeError, ValueError):
            nrl = 0
        if nrl > ceiling:
            nuc["rate_limit"] = ceiling
            self.profile["nuclei"] = nuc
            clamps.append(f"nuclei.rate_limit {nrl}→{ceiling}")
        if clamps:
            self._rate_ceiling_clamp = (
                f"档位「{self.profile.get('name') or self.profile_name}」的速率被"
                f"全局硬上限 {ceiling} rps 收敛：{'；'.join(clamps)}")

    def _redteam_config(self) -> dict[str, Any]:
        """红队模式配置（impact_level / objectives）。

        默认影响级别是 L2「证明影响」：能证明「真的读到了数据」，
        但不会执行命令、不写文件。L1 只证明「能到达」，证据强度偏弱；
        L3 会执行命令并取回输出，风险最高，必须由 profiles.yaml 显式开启。
        """
        return dict(self.profile.get("redteam", {}) or {})

    def _ledger_record(self, domain: str) -> Any:
        """按**归一化后**的域名取台账记录。

        ⚠️ 必须归一化：台账的键是 `_norm(domain)`（小写 / 去协议 / 去端口 / 去路径）。
        拿原始输入去查会 miss —— 而 miss 的后果不是报错，是**授权范围被静默放宽**：
        查不到就退回档位默认的全量目标。这类「以为收紧了、其实放宽了」的问题
        比直接拒绝执行危险得多，因为报告上看不出任何异常。
        """
        try:
            return self.ledger.records.get(self.ledger._norm(domain))
        except Exception:  # noqa: BLE001
            return None

    def _ledger_allows_write(self, domain: str) -> bool:
        """台账是否**显式**授权受控写验证（`ledger --allow-write`）。

        ⚠️ 与档位是「与」关系，不是「或」：deep 档只说明「本档位允许写」，
        不等于「这一次被授权写」。授权只能由台账给出 —— 否则档位选择本身
        就变成了写授权的旁路，而档位是随手可切的日常参数。

        未登记 / 查不到一律 False（保守默认），不抛异常。
        """
        try:
            return bool(self.ledger.can_write_test(domain))
        except Exception:  # noqa: BLE001
            return False

    def _authorized_objectives(self, domain: str) -> list[str]:
        """本次授权允许尝试的攻击目标 = 档位默认 ∩ 台账登记。

        台账里没登记的目标一律不执行 —— 结果记「未能验证（未授权）」，
        **不记「未达成」**。这两者在报告里的差别是决定性的：
        前者是「没测」，后者是「试过了打不穿」。

        注意取的是**交集**：台账只能收紧授权范围，不能放宽。
        """
        prof = list(self._redteam_config().get("objectives") or [])
        rec = self._ledger_record(domain)
        led = list(getattr(rec, "objectives", None) or []) if rec is not None else []
        if not led:
            return prof
        return [o for o in prof if o in led]

    # ------------------------------------------------------------------
    # 归因材料：给报告说清「某个攻击目标为什么没做」（详见 redteam 铁律 2b）
    # ------------------------------------------------------------------
    def _redteam_profile_objectives(self) -> list[str]:
        """档位默认允许的攻击目标（不含台账收紧）。"""
        return list(self._redteam_config().get("objectives") or [])

    def _ledger_objectives(self, domain: str) -> list[str]:
        """授权台账对该目标放行的攻击目标。台账未填（空 list）= 不收紧。"""
        rec = self._ledger_record(domain)
        return list(getattr(rec, "objectives", None) or []) if rec is not None else []

    def _profile_label(self) -> str:
        """档位的中文名（如「标准档」），用于报告措辞。"""
        return str(self.profile.get("name") or self.profile_name)

    def _authorized_impact_level(self, domain: str) -> str:
        """本次授权允许的最大影响级别 = min(档位默认, 台账登记)。

        ⚠️ 这里曾经只读档位配置，台账上的 `--impact-level` 字段**写了却没人读** ——
        等于给了一个不生效的限深旋钮：运维以为限到 L1、实际按档位的 L2 跑。
        授权字段只要存在就必须被执行，否则它比没有更危险（给了虚假的安全感）。
        取更保守的一个，保证「登记 L1 却按 L2 执行」不会发生。
        """
        prof = str(self._redteam_config().get("impact_level") or IMPACT_L2)
        prof = prof.strip().upper()
        if prof not in IMPACT_ORDER:
            prof = IMPACT_L2
        rec = self._ledger_record(domain)
        led = str(getattr(rec, "impact_level", "") or "").strip().upper()
        if led not in IMPACT_ORDER:
            return prof
        return led if IMPACT_ORDER[led] < IMPACT_ORDER[prof] else prof

    # ------------------------------------------------------------------
    # 下面两个阶段的逻辑抽成独立方法，**生产与自测共用**。
    # 原因：`selftest_engine` 是手工组装流程的（自己调 run_all_items /
    # ReportGenerator），不走 scan() —— 写在 scan() 里的胶水代码永远不会
    # 被自测覆盖。这个盲区此前已经造成过一次生产事故：ReportGate 漏导入，
    # 自测全绿、真实扫描必崩。把逻辑抽出来，自测就能直接调它。
    # ------------------------------------------------------------------
    def _stage_result_proofs(
        self,
        dctx: Any,
        findings: list[Any],
        item_results: list[Any],
        gate_result: Any = None,
        domain: str = "",
    ) -> dict[str, Any]:
        """结果证明：把「存在型」发现推进到「达成型」结论。"""
        from engine.proofs import ProofRunner

        # 逐项结论注入 ctx —— 这是区分「未达成」与「未能验证」的关键：
        # 检查项确实跑过且判「通过」= 明确的失败证据（该路径不成立）；
        # 该项压根没执行 = 条件不足，只能说「没能验证」，不能说「打不穿」。
        try:
            dctx._cache["item_states"] = {
                r.item_id: r.state for r in item_results}
        except Exception:  # noqa: BLE001
            pass
        dctx.findings = list(findings)

        dom = str(domain or getattr(dctx, "domain", "") or "")
        self._impact_cap = self._authorized_impact_level(dom)
        runner = ProofRunner(dctx, impact_level=self._impact_cap)
        runner.run(list(findings))
        return runner.summary()

    def _stage_objectives(
        self,
        dctx: Any,
        findings: list[Any],
        item_results: list[Any],
        domain: str,
    ) -> list[Any]:
        """攻击目标编排：以「拿数据 / 改数据 / 拿控制权」为目标尝试攻击路径。"""
        from engine.redteam import AttackPlanner

        try:
            dctx._cache["item_states"] = {
                r.item_id: r.state for r in item_results}
        except Exception:  # noqa: BLE001
            pass
        dctx.findings = list(findings)

        self._impact_cap = self._authorized_impact_level(domain)
        planner = AttackPlanner(
            dctx,
            scope=self._authorized_objectives(domain),
            impact_level=self._impact_cap,
            # 归因材料（铁律 2b）：把「档位默认允许什么」与「台账放行什么」
            # 一并交给规划器，它才能在报告里说清某个目标没做的**真实原因**。
            # 只传 scope 的话，规划器只能含糊地说「未纳入执行范围」——
            # 而原先更糟：它一律写成「未在授权台账登记」，把档位强度问题
            # 误导成授权问题（2026-09-29 在 内部生产系统 报告上暴露）。
            profile_objectives=self._redteam_profile_objectives(),
            ledger_objectives=self._ledger_objectives(domain),
            profile_name=self._profile_label(),
        )
        self._objectives = planner.run()
        return self._objectives

    # ------------------------------------------------------------------
    def _stage_attack_chains(
        self,
        dctx: Any,
        findings: list[Any],
        objectives: list[Any],
    ) -> list[Any]:
        """攻击链组合：把分散的发现串成「从入口到目标」的因果链。

        两个作用，职责严格分开：

        1. **产出候选链** —— 告诉人「这些洞连起来能打到哪、还差哪一环」。
        2. **回填能力缺口** —— 某攻击目标没有已实现的攻击路径（结论是
           「未能验证（能力缺口）」），但某条链的链尾能力**已被单点实测证明**时，
           该目标应判「已达成」，并把证据挂到 chain_evidence 上。

        ⚠️ 回填的合法性完全依赖 attackchain 的严格分层：它的「已达成」只认
        **单点实测**，绝不靠升级边推导。所以这里回填的仍然是实测结论，
        只是证据来自组合分析而非独立的攻击路径。报告必须标明来源（chain_note），
        否则读者无法判断「已达成」是打出来的还是推出来的。
        """
        from engine.attackchain import plan_attack_chains

        plan = plan_attack_chains(list(findings), list(objectives or []))
        self._chain_notes = list(plan.notes)
        self._chain_filled = list(plan.filled)
        return list(plan.chains)

    def _stage_chain_closure(
        self,
        dctx: Any,
        chains: list[Any],
        objectives: list[Any],
    ) -> Any:
        """链补证：对「到目标只差一环」的候选链**派发受控实测**。

        没有这一步，攻击链永远停在「待确认清单」—— 它回答的是
        「下一枪该往哪打」，却不去打那一枪。而这一步恰恰是自动化
        最有价值的部分：它只是发几个只读请求。

        ⚠ 只补可验证链；纸面推演链（缺 ≥2 环）不派发 —— 给它发请求
        只是把猜测再跑一遍。补证升级后的链要**再回填一次攻击目标**，
        否则战果挂在链上、目标却仍显示「未能验证」。
        """
        from engine.chainclose import close_chains

        rep = close_chains(dctx, list(chains))
        if rep.upgraded:
            from engine.attackchain import fill_objectives

            extra = fill_objectives(list(chains), list(objectives or []))
            self._chain_filled = list(self._chain_filled or []) + list(extra)
        return rep

    def _stage(self, name: str) -> StageRecord:
        rec = StageRecord(name=name, status="pending")
        self.stages.append(rec)
        # 阶段一开始就报一行 —— 实测踩过：nuclei 那一步要跑满 7 分钟，
        # 前台长时间没有任何输出，操作者无法区分「在跑」与「卡死」。
        self._pg().stage_start(name)
        return rec

    # ------------------------------------------------------------------
    def _pg(self) -> Any:
        """取进度输出器（未挂载时返回空实现，绝不抛异常）。"""
        rep = getattr(self, "progress", None)
        if rep is None:
            from engine.progress import NULL  # noqa: PLC0415

            return NULL
        return rep

    def _pg_stage(self, st: StageRecord) -> None:
        """阶段收尾：报耗时与摘要（进度输出失败不得影响扫描）。"""
        try:
            self._pg().stage_done(st.name, st.status, st.detail or st.error,
                                  st.duration_ms)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _prior_archive_runs(archive_dir: Any) -> list[tuple[Any, Any]]:
        """列出**本轮之前**的历次归档（新→旧）：`[(运行目录, findings 路径), ...]`。

        为什么不能用 `Differ.latest_pair()`：它假定「最新目录 = 本轮」，
        而**本轮的 findings 到报告阶段还没落盘**，于是它必然返回 None。
        改成从目录名倒着扫，逐个挑出真正带发现归档的轮次。

        findings 文件名取 `*_findings.json`（即 `<目标名>_findings.json`）——
        不要用裸 `findings.json`，那份是给外部消费的精简副本；两者内容等价，
        但带前缀的那份才是随报告一起归档、可逐条核对的原件。
        """
        out: list[tuple[Any, Any]] = []
        try:
            parent = Path(archive_dir).parent
            if not parent.exists():
                return out
            me = Path(archive_dir).resolve()
            runs = sorted((p for p in parent.iterdir() if p.is_dir()),
                          key=lambda p: p.name, reverse=True)
            for p in runs:
                if p.resolve() == me:
                    continue
                files = sorted(p.glob("*_findings.json"))
                if files:
                    out.append((p, files[0]))
        except Exception:  # noqa: BLE001
            return out
        return out

    @staticmethod
    def _load_item_states(run_dir: Any) -> dict[str, dict[str, Any]]:
        """读某次历史扫描的逐项结论（`检查项结论.json`）
        → `{item_id: {"state": ..., "weak_na": ...}}`。

        用途只有一个：判断**那次扫描到底测过这一项没有**。历史扫描对某项
        给出「通过」或**强证据** N/A，说明真测过且没问题，更早的报法就不该
        再翻出来；而「未执行 / 待人工执行 / 待确认 / 已跳过」四种都是
        **没人去看**。

        ⚠ 返回的是 dict 而不是纯状态字符串（2026-09-30 改）：**弱证据 N/A
        不是「测过且没问题」**，它的含义是「有限路径探测没看到」。
        把两者混为一谈，会让一次「没看到」把此前实测证实的严重漏洞抹掉：
          第 N 轮 has_storage present → OSS 匿名列举（严重）被实测证实；
          第 N+1 轮 路径探测没命中 → 弱 N/A → 那份严重发现凭空消失。
        对历史轮次同样要能分辨 —— 所以 `weak_na` 必须随归档落盘。
        """
        p = Path(run_dir) / "检查项结论.json"
        if not p.exists():
            return {}
        data = json.loads(p.read_text(encoding="utf-8"))
        items = data.get("items") if isinstance(data, dict) else data
        out: dict[str, dict[str, Any]] = {}
        for it in (items or []):
            iid = str((it or {}).get("item_id") or "")
            if iid:
                out[iid] = {
                    "state": str((it or {}).get("state") or ""),
                    "weak_na": bool((it or {}).get("weak_na", False)),
                }
        return out

    @classmethod
    def _collect_prior_unverified(cls, archive_dir: Any, detector_results: Any,
                                  ) -> list[dict[str, Any]]:
        """收集「历次扫描上报过、本轮没有结论」的发现，供报告承接。

        逐条判据（**只承接，不下结论**）：

        - 本轮该项**有结论**（通过 / 不通过 / **强证据** N/A）→ 本轮已经替它
          说话了，不承接 —— 承接块里塞进已经复看过的项，只会让读者对整块失去信任；
        - 本轮该项**没有结论**（未执行 / 待人工执行 / 待确认 / 已跳过）→
          本轮「没再检出」只说明**没人去看**，不构成修复证据，承接；
        - 本轮该项判 **弱证据 N/A** → 同样按「没有结论」处理。弱 N/A 的确切
          含义是「有限路径探测**没看到**」，不是「确证不具备」。拿它当结论，
          就会用一次「没看到」推翻此前实测证实的严重漏洞（2026-09-30 修）：
            第 N 轮 has_storage present → OSS 匿名列举（严重）被实测证实；
            第 N+1 轮 路径探测没命中 → 弱 N/A → 该严重漏洞从通告里凭空消失。
          这与「被拦截那轮 0 条」是同一类错误，只是入口不同；
        - 同一发现（`item_id + endpoint + 标题`）在多次历史扫描里都报过 →
          只取**最近一次**报过的等级与标题；
        - 某次历史扫描对该项给出了「通过」或**强证据** N/A → 那次确证测过且
          没问题，比它更早的报法不再承接（否则会把已修的东西翻出来）。
          ⚠ 弱 N/A **不得**计入「覆盖掉」—— 它没有推翻历史的资格。

        **必须回溯多轮，不能只看上一轮**：上一轮可能整场被边界拦住、一条
        发现都没有 —— 那一次「0 条」是「没看到」，不是「没有了」。只看上
        一轮，上一次真正报出来的严重漏洞会在后一次无效扫描里凭空消失
        （2026-09-30 安全负责人指出：上一轮报过严重漏洞，本轮却写「问题清单为空」——
        实际归档里，报出严重漏洞那轮与「0 条」那轮中间正好隔了一轮）。
        """
        #: 本轮「该项有结论」的集合。弱 N/A 不在其中 —— 这正是本轮修复的核心。
        cur_states: dict[str, str] = {}
        #: 本轮判弱 N/A 的项：沿用「没有结论」口径，历史发现照常承接。
        cur_weak: set[str] = set()
        try:
            for r in detector_results:
                cur_states[r.item_id] = r.state
                if r.state == "N/A" and bool(getattr(r, "weak_na", False)):
                    cur_weak.add(r.item_id)
        except Exception:  # noqa: BLE001
            cur_states, cur_weak = {}, set()

        seen: set[str] = set()          # 已承接的发现键（新→旧，先到先得）
        cleared: set[str] = set()       # 被某轮以「确证没问题」覆盖掉的项
        out: list[dict[str, Any]] = []
        for run_dir, fpath in cls._prior_archive_runs(archive_dir):
            try:
                pfs = FindingSet.load(fpath)
            except Exception:  # noqa: BLE001
                continue
            try:
                states = cls._load_item_states(run_dir)
            except Exception:  # noqa: BLE001
                states = {}
            for f in pfs.sorted_findings():
                iid = str(getattr(f, "item_id", "") or "")
                if not iid or iid in cleared:
                    continue
                if (cur_states.get(iid) not in Differ.NO_CONCLUSION_STATES
                        and iid not in cur_weak):
                    # 本轮该项有**确证**结论 —— 本轮说了算。
                    continue
                key = f"{iid}|{f.endpoint or ''}|{(f.title or '')[:40]}"
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "title": f.title, "severity": f.severity or "",
                    "endpoint": f.endpoint or "", "item_id": iid,
                    "from_run": run_dir.name,
                })
            # 该轮以「确证没问题」覆盖掉的项，不再从更老的轮次里捞。
            # 弱 N/A 除外：它只是「没看到」，没有推翻历史的资格。
            for iid, info in states.items():
                st = str((info or {}).get("state") or "")
                weak = bool((info or {}).get("weak_na", False))
                if st == "通过" or (st == "N/A" and not weak):
                    cleared.add(iid)
        return out

    @staticmethod
    def _prior_archive_findings(archive_dir: Any) -> Any:
        """上一轮 findings 归档路径（排除本轮）。保留给旧调用点，见
        `_prior_archive_runs` / `_collect_prior_unverified`。

        ⚠ 新代码**不要**再直接用它做承接：只看最近一轮会漏掉「中间隔了一轮
        无效扫描」的情况（见 `_collect_prior_unverified` 的说明）。
        """
        runs = Orchestrator._prior_archive_runs(archive_dir)
        return runs[0][1] if runs else None

    def _note_account_gap_if_any(self, domain: str, target_url: str) -> None:
        """自取身份之后，才谈「哪些项还需要身份」。

        这个方法存在的唯一理由是**顺序**：过去那句「未配置测试账号 → 去拿凭据」
        跑在凭据获取之前，于是操作者最先读到的是「伸手要账号」。现在它跑在
        「自己试」「自己上网找」都做完之后，且措辞必须把三件事分清：

          ① 已经自己做过什么（入口、候选口令、外部检索次数）—— 否则读者
             无从判断「没搞到身份」是「没试」还是「试了不行」；
          ② 结果是什么；
          ③ 剩下的部分属于**哪一类工作**。红队入场按红线 17 的四条链
             自取凭据：regself（开放注册自建）在阶段 9 执行 —— 本段
             （阶段 6）打印时它还没跑，所以话术绝不允许写成「到此为止」
             或「需要业务方提供账号」；只有 regself 也未建成，才谈
             「待人工执行 + 补齐路径」。第 29 轮实测：regself 自建双账号
             后，ATHZ-04 在主流程里确证了归属校验缺失 —— 持账号的越权
             测试本来就是红队主链路的一环，不是另一类工作。
        """
        if not self._need_accounts_for_note:
            return
        n = len(self._need_accounts_for_note)
        got = list(getattr(self.credhunt, "found", None) or [])
        try:
            if got:
                names = "、".join(str(r.get("name")) for r in got)
                print(f"  ✓ 已自行取得身份：{names} —— "
                      f"{n} 项认证 / 越权类检查将以此身份执行"
                      "（**未向业务方索取任何账号**）",
                      file=sys.stderr, flush=True)
                return
            _os_int = self.credosint
            _tried = int(getattr(self.credhunt, "tried", 0) or 0)
            _nq = len(getattr(_os_int, "queries", None) or [])
            _np = len(getattr(_os_int, "products", None) or [])
            print(
                f"  · 凭据自取已完成，未取得身份（{n} 项认证 / 越权类检查"
                f"因此记为「待人工执行」，**不写成通过**）："
                f"识别产品 {_np} 个、提交口令 {_tried} 组、外部检索 {_nq} 次；"
                "试过什么与逐条结果见报告第 4.1 节",
                file=sys.stderr, flush=True)
            print(
                "    说明：本段只覆盖凭据自取的「识别产品 + 默认口令受控尝试 + "
                "联网检索」三条链的结果。**开放注册自建（regself）在阶段 9 "
                "才会执行** —— 目标若开放注册，红队自己建号，不向业务方"
                "索要账号（红线 17①）；regself 也未建成时，相关认证 / 越权类"
                "检查才记「待人工执行」并给出人工补齐路径。",
                file=sys.stderr, flush=True)
        except Exception:  # noqa: BLE001
            pass

    # ==================================================================
    def scan(
        self,
        domain: str,
        target_name: str = "",
        base_url: str | None = None,
        preset_features: dict[str, Any] | None = None,
        authorization: dict[str, Any] | None = None,
        skip_auth_check: bool = False,
        enable_js: bool = True,
        # 权限矩阵：None = 自动（有身份就跑，含凭据中途到位后补跑）、
        # True = 强制、False = 显式关闭。默认自动，理由见 authz 阶段注释。
        enable_authz: bool | None = None,
        accounts_path: Path | str | None = None,
        business_notes: list[str] | None = None,
        mode: str = DEFAULT_MODE,
        # 扫描通告（对外通晒版）是否保留完整复现命令。
        # **默认 False** —— 通告要贴进部门大群，一份带可直接执行命令的
        # 通告等于把验证手册分发给所有能看到群消息的人。要完整版显式指定。
        notice_full_repro: bool = False,
    ) -> ScanResult:
        """执行一次完整扫描。

        mode="redteam"（**默认**）：黑客运维视角。在合规检查的基础上追加
            **攻击目标编排** —— 以「拿到数据 / 修改数据 / 拿到控制权」为目标
            尝试各种攻击路径，终点是「目标是否达成」。逐项结论照旧全跑全报，
            红队是叠加层，不是替代。
        mode="compliance"：只做逐项合规检查，终点是「有哪些漏洞」。
            仅在明确要求「只出合规清单」时使用。
        两者共用同一套检测器与闸门。
        """
        t_start = time.time()
        self.mode = mode if mode in SCAN_MODES else DEFAULT_MODE
        target_name = target_name or domain
        archive_dir = self._make_archive_dir(target_name)
        fs = FindingSet(target=target_name)

        # 进度显示的「分母」与「现场」在这里接上（顺序要紧：要在第一个阶段之前）。
        #   · stage_total —— 让前台能说「阶段 3/16」，而不是干巴巴一个 3；
        #   · status_path —— 本轮归档目录下的 progress.json，外部随时可读。
        #     2026-09-30 事故：一次扫描在跑完 nuclei 后被杀，日志静静停在
        #     [5m39s]、归档为空，**没有任何标记说明它是死是活**。有了这份状态
        #     文件，读者只看它的时间戳还在不在往前走就能判断，不必去读日志。
        #     两个调用都写了异常隔离，绝不允许观测手段影响扫描本身。
        try:
            self._pg().set_stage_total(len(PLANNED_STAGES))
        except Exception:  # noqa: BLE001
            pass
        try:
            self._pg().set_status_path(archive_dir / "progress.json")
        except Exception:  # noqa: BLE001
            pass

        # ---------- 阶段 0（最前）：运行姿态 ----------
        # 必须在任何请求之前落实：降优先级、封并发、给子进程划核与内存上限。
        # 放在最前是因为「授权闸门」之后紧接着就是工具链探测，那里会起外部进程。
        st = self._stage("运行姿态（资源预算）")
        try:
            # 本机资源预算是三个档位共用的一份（config/profiles.yaml 的
            # `resource_defaults`）。档位自己的 `resources` 优先，便于单档覆盖。
            prof_for_res = dict(self.profile)
            if "resources" not in prof_for_res:
                prof_for_res["resources"] = (
                    self.profiles.get("resource_defaults", {}) or {})
            self._resource = resources.reconfigure(prof_for_res)
            self._resource.priority_applied = resources.apply_process_priority(
                self._resource.low_impact)
            st.status = "ok"
            st.detail = self._resource.posture_line()
            if self._resource.notes:
                st.detail += "；" + "；".join(self._resource.notes)
        except Exception as e:  # noqa: BLE001
            # 资源预算失败不能让扫描停下来 —— 它是「体感」优化，不是正确性前提。
            # 但**必须留痕**：静默失效会让人以为是优化没效果，而不是优化没生效。
            self._resource = None
            st.status = "failed"
            st.error = f"{type(e).__name__}: {e}"
            st.detail = "资源预算不可用，本次不做资源限制（按全速运行）"
        self._pg_stage(st)

        # ---------- 阶段 0：授权闸门 ----------
        st = self._stage("授权闸门")
        t0 = time.time()
        if skip_auth_check:
            st.status = "skipped"
            st.detail = "已显式跳过授权检查（仅限内部自测）"
        else:
            ok, msg = self.ledger.check(domain)
            st.status = "ok" if ok else "failed"
            st.detail = msg
            if not ok:
                st.error = "目标未授权，流程终止"
                st.duration_ms = int((time.time() - t0) * 1000)
                self._pg_stage(st)
                # 未授权不继续，这是硬闸门
                return ScanResult(target_name, domain, archive_dir, self.stages, fs)
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        auth = authorization or {}
        if not auth and not skip_auth_check:
            rec = self.ledger.records.get(self.ledger._norm(domain))
            if rec:
                auth = rec.to_dict()

        # ---------- 阶段 0.5：工具链探测 ----------
        st = self._stage("工具链探测")
        t0 = time.time()
        try:
            self.tools.probe_all()
            avail = [t.spec.name for t in self.tools.status.values() if t.available]
            st.status = "ok"
            st.detail = f"可用工具：{', '.join(avail) or '无'}"
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {e}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 1：资产测绘与指纹识别 ----------
        st = self._stage("L1 资产测绘与指纹识别")
        t0 = time.time()
        fp = Fingerprinter(self.profile)
        fp_result: dict[str, Any] = {}
        try:
            fp_result = fp.assess(target_name, domain, base_url, preset_features,
                                  profile_key=self.profile_name)
            # 登录入口是从这批探测结果里推断的（有证据才算），
            # 所以要在扫完之前留住它 —— 扫描结束时才生成凭据索取指引。
            self._fp_path_probes = dict(fp_result.get("path_probes") or {})
            tf: TargetFeatures = fp_result["_features_obj"]
            present = [k for k, f in tf.features.items() if f.present]
            st.status = "ok"
            st.detail = f"判定目标特征 {len(tf.features)} 项，其中具备：{', '.join(present) or '无'}"
            _rr = fp_result.get("render") or {}
            _re = _rr.get("entry") or {}
            if _re:
                st.detail += f"；{_re.get('state', '')}"
                if _re.get("ok"):
                    st.detail += (f"（可见文本 {_re.get('text_before', 0)} → "
                                  f"{_re.get('text_after', 0)} 字）")
            if getattr(tf, "notes", None):
                # 特征层面的重要提示（如「整站同一响应」「未渲染导致覆盖度下降」）
                # 必须往上带，否则模型/读者只看到「具备 N 项」，
                # 不知道这些结论已经被打了折。
                st.detail += "；⚠ " + "；".join(tf.notes)
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}"
            tf = build_example_features(target_name)
            st.detail = "指纹识别失败，退回保守特征集（加大检查覆盖面）"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 2：适用性判定 ----------
        st = self._stage("L2 适用性判定")
        t0 = time.time()
        try:
            app = ApplicabilityEngine().evaluate(self.checklist, tf)
            summary = ApplicabilityEngine.summary(app)
            st.status = "ok"
            st.detail = (f"共 {summary['合计']} 项：适用 {summary['适用']}、"
                         f"N/A {summary['N/A']}、待确认 {summary['待确认']}")
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {e}"
            app = []
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        target_url = (fp_result.get("root_probe", {}) or {}).get("final_url") or base_url or f"https://{domain}"
        self._target_url = target_url

        # ---------- 阶段 2.5：边界防护与可达性判定 ----------
        # 目标可能把**所有**请求都挡在边缘（返回统一的拦截页）。不识别就有两类后果：
        #   ① 把拦截页当成应用页面，据此产出真实环境复测不出来的「漏洞」；
        #   ② 采不到东西被判成 N/A —— 用一次失败的采集把风险判没了。
        # 识别方式：厂商特征 + 「随机不存在路径是否返回同一页」的对照实验，两者同时成立。
        st = self._stage("L1 边界防护与可达性判定")
        t0 = time.time()
        boundary: Any = None
        boundary_blocked = False
        try:
            from engine.wafgate import assess_boundary  # noqa: PLC0415

            _root = dict(fp_result.get("root_probe", {}) or {})
            if not str(_root.get("body_snippet") or "").strip():
                try:
                    _pr = fp.client.fetch(target_url)
                    _root.update({
                        "body_snippet": _pr.body_snippet,
                        "headers": _pr.headers or _root.get("headers", {}),
                        "status": _pr.status or _root.get("status", 0),
                        "cookies": _pr.cookies or [],
                    })
                except Exception as e:  # noqa: BLE001
                    st.error = f"根路径正文回取失败：{type(e).__name__}"

            def _control(u: str):
                p = fp.client.fetch(u)
                return p.status, p.headers, p.body_snippet

            # 一致性证据优先用指纹阶段已经探过的那一批路径：样本多、
            # 不需要额外发请求，也不会因为「某一次重取恰好被限流」而
            # 让整个边界结论静默翻转。control_fetcher 作为兜底。
            # DNS 的 CNAME 在这里作为**线索**接进来（资产测绘阶段已经拿到，
            # 不额外发请求）。它只用于具名披露「边缘是谁家」+ 厂商判定的一致性
            # 加权，**不参与 blocked 判定** —— 同一家的 CDN/WAF 共用 CNAME 后缀，
            # 源站直连型 WAF 更是完全不体现在 CNAME 上。
            _cnames = (fp_result.get("dns") or {}).get("cnames") or []
            boundary = assess_boundary(
                _root, control_fetcher=_control, base_url=target_url,
                path_probes=fp_result.get("path_probes") or {},
                cnames=_cnames)
            boundary_blocked = bool(boundary.blocked)
            if boundary_blocked:
                st.status = "failed"
                st.detail = boundary.evidence
                self._boundary = boundary
            else:
                st.status = "ok"
                st.detail = "；".join(boundary.notes) or "未发现边界防护全量拦截特征"
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 6.1：边界绕过试探 ----------
        # 2026-09-30 修。这已经是第二刀的修理，第一刀修的是「时点」，第二刀
        # 修的是「要不要做」：
        #
        #   第一刀（时点）：旧实现跑在 L2 采集之后，且只在「已探到拦截」时才
        #   触发（`if (_l1_blocked or _guard_occurred)`）—— 也就是**只有本来源
        #   已经被封死时才会去试**；那时连不带变形的普通请求也返回同一张拦截页，
        #   于是 12 个变形「全部被拦住」证明不了任何事，通告却据此写出
        #   「拦截对本来源覆盖完整」——一句没有证据的话。
        #   现在挪到 L1 边界判定之后立即做：此刻流量通常还没被封，基线对照成立。
        #
        #   第二刀（分流）：修完之后它变成**无条件跑**，又走向另一个极端 ——
        #   目标根本没有边界拦截时，12 个变形全「未被拦」，既不是绕过证据
        #   （没有可绕之物），又白打一批请求。分流判据见 `_bypass_worth_probing`。
        #
        # 试探自带基线（结果列表第 0 项），基线不通时整批「被拦」计数不得读成
        # 覆盖率；但**基线不通时的「未被拦」反而是绕过候选**，由 summarize 承接。
        if not self._bypass_probes:
            _why_probe = _bypass_worth_probing(boundary)
            if not _why_probe:
                # 没有拦可绕 → 不发这十来发。**跳过原因必须具名留痕**，
                # 不得静默 —— 否则读者会把「没试绕过」读成「试过了、防护有效」。
                self._bypass_skip_reason = (
                    "未探到边界拦截行为（厂商特征与「全站返回同一响应」"
                    "两个口径均未命中），本轮未执行绕过试探")
                try:
                    self._pg().note(
                        "边界绕过试探：未探到拦截行为，**跳过** —— 没有拦可绕时，"
                        "「变形未被拦」不构成绕过证据；且这批流量本身就可能触发"
                        "按请求量的频次封禁。**这不代表目标没有其他形态的防护。**")
                except Exception:  # noqa: BLE001
                    pass
            else:
                _bs: dict[str, Any] = {}
                try:
                    from engine import wafbypass as _wb  # noqa: PLC0415

                    self._bypass_probes = _wb.probe_bypasses(
                        fp.client, target_url, boundary)
                    _bs = _wb.summarize(self._bypass_probes)
                except Exception as e:  # noqa: BLE001
                    _err = f"{type(e).__name__}: {str(e)[:120]}"
                    try:
                        self._pg().note(f"[绕过试探] 异常（已捕获，未中断）：{_err}")
                    except Exception:  # noqa: BLE001
                        pass
                if _bs:
                    # 进度输出失败不得影响扫描 —— 单独包一层，别让它被外层的
                    # 「绕过试探异常」分支接住，那会把一次输出故障报成探测故障。
                    try:
                        _cands = _bs.get("bypass_candidates") or []
                        self._pg().note(
                            f"边界绕过试探（触发：{_why_probe}）："
                            f"{_bs['tried']} 种变形，{_bs['blocked']} 被拦、"
                            f"{_bs['missed']} 未命中拦截特征；基线对照 HTTP "
                            f"{_bs['baseline_status']}"
                            + ("（成立）" if _bs["baseline_ok"]
                               else "（**不成立 → 本来源已被整体拦死**）")
                            + (f"；其中 {len(_cands)} 个在基线被拦的情况下仍未命中"
                               "拦截特征 → **列为绕过候选，需人工复核**"
                               if _cands else ""))
                    except Exception:  # noqa: BLE001
                        pass

        # ---------- 阶段 2.5：需要登录令牌的项 —— **先说清我们会怎么自己弄** ----------
        # v11.7 起这里不再打印「本次未配置测试账号 → 去拿凭据」。
        #
        # 那句话是**审计方姿态**，不是红队姿态，而且错得很具体：
        #   ① 它跑在凭据获取之前（下一阶段的 credhunt 还没跑），于是操作者
        #      最先看到的是「伸手要账号」，自己试试出来的结果反而在后面 ——
        #      整场扫描的第一印象被定成了「这是个需要业务方配合的自查表」；
        #   ② 真实攻击者零凭据入场，他要的是**自己弄一个身份**：
        #      找登录入口、查这个产品的出厂默认口令、看公开渠道有没有线索。
        #      这些都在本工具有实现，凭什么先去要账号。
        #   ③ 「有账号」是**另一类工作** —— 持账号的认证态越权测试（IDOR /
        #      横向越权 / 并发会话），那需要授权账号，与红队零凭据入场是两码事。
        #      把它写成一个「缺口」，等于用错误的分类制造一个不存在的问题。
        #
        # 现在的分工：
        #   · 自取（本工具做）：入口发现 + 产品默认口令 + 公开资料检索，见下
        #   · 试不出来：如实记「待人工执行」，**并说明这是哪一类工作**
        #   · 确实要跑持账号的边权测试：那是另一条链路（--accounts / creds 通道），
        #     报告里作为独立章节呈现，不冒充红队结论
        self._need_accounts_for_note: list[Any] = []
        if not boundary_blocked and not accounts_path:
            try:
                from engine import credguide as _cg  # noqa: PLC0415

                self._need_accounts_for_note = list(_cg.items_requiring("accounts"))
            except Exception:  # noqa: BLE001
                pass

        # ---------- 阶段 2.55：红队自取身份（凭据情报 + 受控口令尝试） ----------
        # 顺序：**先情报后尝试**。情报决定「试什么」（产品默认口令），
        # 尝试决定「试出什么」。反过来就退化成了拿通用字典瞎撞。
        #
        # 放在封禁守门之前：这一步只有十来个请求、强制间隔，本身风险极低；
        # 而它产出的身份决定后面越权矩阵能不能跑，越早知道越好。
        if not boundary_blocked and not accounts_path:
            try:
                from engine import credhunt as _ch  # noqa: PLC0415
                from engine import credosint as _co  # noqa: PLC0415

                with self._pg().activity("凭据情报（识别产品 + 自己上网找默认口令）"):
                    self.credosint = _co.osint(
                        target_url, domain=domain,
                        evidence=fp_result,
                        profile_key=self.profile_name,
                        enabled=not bool(getattr(self, "_no_credosint", False)),
                        allow_online=not bool(getattr(self, "_no_credosint_online",
                                                      False)))
                for _line in self.credosint.summary_lines():
                    print(f"  {_line}", file=sys.stderr, flush=True)

                _extra = self.credosint.auto_pairs() if self.credosint else []
                with self._pg().activity("凭据获取（登录入口 + 受控口令尝试）"):
                    self.credhunt = _ch.hunt(
                        fp.client, target_url, profile=self.profile,
                        profile_key=self.profile_name,
                        path_probes=self._fp_path_probes, guard=None,
                        extra_pairs=_extra,
                        pair_sources=(self.credosint.pair_sources()
                                      if self.credosint else None))
                for _line in self.credhunt.summary_lines():
                    print(f"  {_line}", file=sys.stderr, flush=True)
                if self.credhunt.found:
                    # 命中的身份要进包内统计并落进报告：这是**实测拿到的东西**，
                    # 不是「配了测试账号」那种前置条件。
                    # ⚠ 这里不能直接 append 到 collected —— 那个列表要到
                    # 「阶段 3 扫描采集」才创建，在此之前引用它必然 NameError，
                    # 而异常会被本块的 except 吞掉，表现为「凭据获取没跑」。
                    # 所以先存到自己名下，进入采集阶段时再合并。
                    self._credhunt_findings = _ch.grade_findings(
                        self.credhunt, target_name)
                    for _f in self._credhunt_findings:
                        fs.add(_f)
                    print(f"  · [凭据获取] 命中默认口令，已产出 "
                          f"{len(self._credhunt_findings)} 条发现"
                          "（绑定 WSTG-ATHN-02）", file=sys.stderr, flush=True)
                self._note_account_gap_if_any(domain, target_url)
            except Exception as e:  # noqa: BLE001
                print(f"  · [凭据获取] 异常（已捕获，未中断）："
                      f"{type(e).__name__}: {str(e)[:120]}", file=sys.stderr, flush=True)
        else:
            # 没跑就要说清「为什么没跑」，不能让它静默消失。
            # 报告 4.1 节存在的意义就是回答「这次工具到底有没有试过口令」——
            # 这一节整段不见了，读者只能自行脑补，而脑补的默认答案是
            # 「试过了、没试出来」（一个比事实更让人安心的答案）。
            # 两种跳过原因分开写，因为处置动作不同：
            #   · 边界拦截 → 重扫即可（不是不做，是这次做不了）；
            #   · 已有测试账号 → 本来就不需要（越权矩阵用的是授权身份）。
            try:
                from engine import credhunt as _ch  # noqa: PLC0415

                _why = ("本次扫描未触达应用（边界拦截），凭据获取未执行"
                        if boundary_blocked else
                        "已提供授权测试账号，无需自行猜测登录凭据"
                        "（越权矩阵使用授权身份）")
                self.credhunt = _ch.HuntResult(enabled=False, reason=_why)
                print(f"  · [凭据获取] 未执行：{_why}", file=sys.stderr, flush=True)
            except Exception:  # noqa: BLE001
                pass  # 连「说明为什么没跑」都失败时，退回「该节不出现」，不中断扫描

        # ---------- 阶段 2.6：运行期封禁守门（B 类拦截） ----------
        # A 类（开扫即被全量拦截）上面已经判掉；那种情况下「中途被封」不成立。
        # B 类是另一种形态：**开扫正常、扫到一半被拉黑**。不监测的后果比 A 类更坏 ——
        # A 类结论是诚实的「无法评估」，B 类会把后半段拿到的拦截页当应用扫完，
        # 产出一份格式规范、证据齐全、却复测不出来的假报告。
        #
        # 基线的来源就是刚才那次根路径探测：**没有基线就无法区分**
        # 「中途被封」与「目标本来就在返 5xx」，又会退回「孤立信号当证据」的老错误。
        guard: Any = None
        if not boundary_blocked:
            try:
                from engine.banguard import BoundaryGuard  # noqa: PLC0415

                _bgc = dict((self.profile or {}).get("boundary_guard") or {})
                guard = BoundaryGuard(
                    fp.client.fetch,
                    budget_s=float(_bgc.get("budget_seconds", 600)),
                    backoff=tuple(_bgc.get("backoff_seconds", [30, 60, 120, 300])),
                    max_rounds=int(_bgc.get("max_rounds", 3)),
                    check_every=int(_bgc.get("check_every_probes", 25)),
                    speed_step=float(_bgc.get("speed_step", 0.5)),
                    min_speed=float(_bgc.get("min_speed_factor", 0.1)),
                    enabled=bool(_bgc.get("enabled", True)),
                    # 退避等待最长可吃满 budget_seconds（默认 600s）且全程无输出，
                    # 前台看上去与卡死无差别 —— 实测就是这么误判的。接上进度。
                    progress=self._pg(),
                )
                guard.arm(
                    target_url,
                    int(_root.get("status") or 0),
                    str(_root.get("body_snippet") or ""),
                )
            except Exception:  # noqa: BLE001
                # 守门是保护措施，不是主流程：创建失败就退回旧行为，不中断扫描。
                guard = None

        # ---------- 阶段 2.7：目标健康度守门（hard_limits.stop_on） ----------
        # 与上面那个守门是**两件不同的事**，分开建、分开报：
        #   · 边界守门：「对方拦住我们」→ 退避 + 降速，然后继续；
        #   · 健康度守门：「我们可能把对方打挂」→ 立即停手，不等不试。
        # 后者的风险是**不可逆的**：目标开始连续 5xx 说明服务可能已经异常，
        # 继续施压只会加重故障。等待在这里没有意义 —— 它不是限流，是故障。
        #
        # 为什么必须在代码里落地：`hard_limits.stop_on` 此前**零读取点**，
        # yaml 里写着「目标返回连续 10 次 5xx → 立即停止」，
        # 而实际没有任何代码会停。配置承诺了却不兑现 = 虚假保证，
        # 比不写这条配置更危险（操作者据此认为有兜底）。
        #
        # 已被边界拦截时不启用：那种情况下每个响应都是拦截页，
        # 拦截页若返 5xx 会被误读成「我们把目标打挂了」—— 结论会写反。
        health: Any = None
        if (os.environ.get("AISCAN_HEALTH_GUARD") or "").strip().lower() == "off":
            # 显式关闭（一次性靶场基准专用）：2026-10-09 Juice Shop 基准实测，
            # 靶场对畸形探针返 500（带堆栈）是其**正常应答形态**（这正是靶场的
            # Error Handling 考点），守门 10 连 5xx 触发后把后续百余项截成
            # 「未执行」。关闭必须能被说出名字 —— stderr + 报告 detector_notes。
            self._health_guard_off = True
            print("  · [健康度守门] 已被 AISCAN_HEALTH_GUARD=off 显式关闭"
                  "（仅限一次性靶场基准，生产目标不得使用）",
                  file=sys.stderr, flush=True)
        elif not boundary_blocked:
            try:
                from engine.banguard import (  # noqa: PLC0415
                    TargetHealthWatch, _host_is_loopback,
                )

                # 回环目标（localhost / 127.0.0.1 / ::1）= 第一方自有靶场。
                # 健康度守门的职责是「别把**对方**的服务器打挂」，对自有靶场不适用：
                # 冷启动延迟突增或靶场自身 5xx 应答形态不应中断测量（实测第 30 轮
                # 因此被「立即停手」截掉约 90% 检查项，整轮召回塌成个位数）。
                # loopback=True 时守门只记录异常、不主动停手，继续扫完拿完整测量。
                _loopback_target = _host_is_loopback(
                    urlparse(target_url).hostname or "")

                health = TargetHealthWatch(
                    progress=self._pg(),
                    # 停手前「打一枪看站还活着没」用的入口地址与请求函数。
                    # 没有它时，守门只能靠「连续 5xx」这一个信号下结论 ——
                    # 而那个信号证明的是「这批探测在报错」，不是「整站挂了」。
                    confirm_url=target_url,
                    confirm_fn=_health_confirm,
                    loopback=_loopback_target,
                )
            except Exception:  # noqa: BLE001
                # 同守门：保护措施创建失败退回旧行为，但必须能被说出名字。
                health = None
                print("  · [健康度守门] 创建失败，本次不监控目标健康度",
                      file=sys.stderr, flush=True)

        # ---------- 阶段 3：扫描采集 ----------
        st = self._stage("L2 扫描采集")
        t0 = time.time()
        collected: list[Finding] = list(self._credhunt_findings)
        notes: list[str] = []
        if self.credosint is not None:
            notes.extend(self.credosint.summary_lines())
        if self.credhunt is not None:
            notes.extend(self.credhunt.summary_lines())
        js_result: dict[str, Any] = {}
        nuclei_findings: list[Finding] = []
        #: 外部引擎（nuclei）本轮的执行情况。必须带进报告：它是唯一自行发请求
        #: 的一步，「跑了多大范围 / 跑完了没有」决定了「没有发现」该怎么读。
        nuclei_run: dict[str, Any] = {}
        #: 采集阶段是否确认了「目标已被拦截 / 够不着」。
        #: 后续的前端产物补采据此决定要不要发请求 —— 目标已经打不开了，
        #: 再对着它发 24 次脚本请求，除了把封禁坐实之外没有任何收获。
        collection_blocked = bool(boundary_blocked)
        #: L2 开头「抢先采集」的前端产物。放在 try 外面声明 —— 后面补采阶段
        #: 要用它判断「是否还需要再发一轮请求」。
        early_assets: Any | None = None
        try:
            if boundary_blocked:
                notes.append(
                    f"{boundary.label}：请求在边缘即被接管，未触达应用。"
                    "已跳过 nuclei / 内置检测器 / JS 分析 —— "
                    "继续跑只会把拦截页当成应用页面。")
                nuclei_run = {
                    "available": True, "executed": False,
                    "reason": f"{boundary.label}：请求在边缘即被接管，外部引擎未执行"
                              "（跑了只会把拦截页当成应用页面）",
                }
                st.status = "skipped"
                st.detail = "；".join(notes)
                raise _BoundarySkip

            # ---------- 前端产物采集：必须抢在 nuclei 之前 ----------
            # 顺序在这里是有代价的，实测踩过：
            # nuclei 是本轮请求量的绝对大头（本次纳入 5094 份模板、跑满 420s），
            # 也**最容易触发边界频率封禁**。而前端采集只发十来个请求就能把
            # 「页面 + 脚本正文 + 内联脚本 + 接口清单」一次拿全
            # （2026-09-28 实测 内部生产系统：8 个请求 → 4 份脚本、400 条接口地址）。
            # 原先这步排在 nuclei 之后，于是：nuclei 触发封禁 → 采集阶段整批
            # 结果作废 → 17 个依赖前端产物的检查项集体落「未执行」，
            # 而这份素材**一开扫就是拿得到的**。
            # 抢在前面 = 把最便宜也最不可替代的素材先落袋，封禁来了也已在手上。
            if enable_js:
                try:
                    from engine import frontend as _fe0  # noqa: PLC0415

                    early_assets = _fe0.collect(
                        fp.client, target_url,
                        render_html=str(fp_result.get("_render_html") or ""),
                        tier=self.profile_name,
                        allow_requests=True,
                        spa_endpoints=(),
                    )
                    notes.append(f"[前端采集] {early_assets.coverage_note()}")
                except Exception as e:  # noqa: BLE001
                    notes.append(f"[前端采集] 异常（已捕获，未中断）："
                                 f"{type(e).__name__}: {str(e)[:120]}")

            nr = NucleiRunner(self.profile)
            if nr.available:
                # nuclei 是本轮请求量的绝对大头（实测 5094 份模板、跑满 420s），
                # 而且整段阻塞、中间没有任何可报的中间量 —— 必须用心跳，
                # 否则前台几分钟没有一行输出，无法区分「在扫」与「卡死」。
                with self._pg().activity(
                        "nuclei 模板扫描",
                        f"预算 {int(getattr(nr, 'timeout', 0) or 0)}s，"
                        f"{len(nr.plan.passes) if getattr(nr, 'plan', None) else 0} 趟",
                        interval_s=20.0):
                    nres = nr.run(target_url)
                collected.extend(nres.findings)
                nuclei_findings.extend(nres.findings)
                nuclei_run = {
                    "available": True,
                    "executed": nres.executed,
                    "error": nres.error,
                    "elapsed": nres.elapsed,
                    "findings": len(nres.findings),
                    "template_count": nres.template_count,
                    "scope_total": nres.scope_total,
                    "scope_known": nres.scope_known,
                    "partial": nres.partial,
                    "budget_exhausted": nres.budget_exhausted,
                    "plan": nres.plan,
                    "passes": nres.pass_results,
                    "notes": list(nres.notes),
                }
                # 用执行摘要而不是一句话「产出 N 条」：被预算截断、某趟没跑、
                # 排除了哪些模板类型，都要能从这里读出来。截断不写进报告，
                # 读者会把「跑了一半」当成「跑完了没发现」。
                notes.append(nres.summary())
                for _n in nres.notes:
                    notes.append(f"nuclei：{_n}")
                if nres.error:
                    notes.append(f"nuclei 提示：{nres.error}")
            else:
                nuclei_run = {
                    "available": False,
                    "executed": False,
                    "reason": "本机未安装 nuclei，本次仅由内置检测器覆盖",
                    "plan": nr.plan.to_dict(),
                }
                notes.append("nuclei 不可用，改用内置检测器")

            # nuclei 是单位时间请求量最大的一步，最容易触发频率封禁。
            # 跑完立刻抽检：若这一步就把目标打进了封禁，它的产出**不可信**，
            # 必须整段丢弃 —— 我们已经无法区分哪些结果来自封禁前、
            # 哪些来自拦截页，留着就是一份复测不出来的假报告。
            if guard is not None and guard.armed:
                try:
                    _ev = guard.check()
                except Exception:  # noqa: BLE001
                    _ev = None
                if _ev is not None:
                    guard.apply_speed(fp.client)
                    notes.append(guard.report.summary())
                    if not _ev.recovered:
                        collected.clear()
                        nuclei_findings.clear()
                        # 结果被丢弃这件事必须跟着 nuclei_run 一起进报告：
                        # 否则第 3.2.2 节会照实写「产出 N 条」，而第 2 章一条都没有。
                        nuclei_run = dict(
                            nuclei_run or {"available": True, "executed": True})
                        nuclei_run.update({
                            "findings": 0,
                            "discarded": True,
                            "discard_reason":
                                "采集阶段即触发边界封禁且退避未恢复 —— "
                                "无法区分哪些产出来自封禁前，该批结果已整体丢弃",
                        })
                        notes.append(
                            "⚠ 采集阶段即触发边界封禁，且退避未能恢复 —— "
                            "已丢弃本阶段全部采集结果（无法区分哪些产出来自封禁前）。"
                            "后续检测项按「未执行」记录。")
                        collection_blocked = True
                        st.status = "skipped"
                        st.detail = "；".join(notes)
                        raise _BoundarySkip

            det = BuiltinDetector(self.profile)
            bfindings = det.run(target_url, fp.client)
            collected.extend(bfindings)
            notes.append(f"内置检测器产出 {len(bfindings)} 条")
            if det.errors:
                notes.append(f"内置检测器异常 {len(det.errors)} 条（已捕获，未中断）")

            if enable_js:
                # JsAnalyzer 绝不能自己用「截断正文」找脚本标签：
                # fp.client.fetch() 的 body_snippet 只保留前 4000 字符
                # （BODY_SNIPPET_CHARS），而 Juice Shop 的 <script type="module">
                # 全部位于 9.4KB 入口页的**尾部** —— 截断版里一个 script
                # 标签都没有。2026-10-09 基准二轮实测症状：JS 分析抓 0 个
                # 产物、接口 0 条，而 L2 开头抢采明明拿到了 3 个脚本引用、
                # 7 份正文、27 条接口。这里把手上已有的完整入口页正文
                # 喂给它；两处都拿不到时才允许它自己取（保留旧行为兜底）。
                _entry_html = ""
                if early_assets is not None:
                    _entry_html = str((getattr(early_assets, "pages", None) or {})
                                      .get("入口页（直取）") or "")
                if not _entry_html:
                    _entry_html = str(fp_result.get("_render_html") or "")
                try:
                    ja = JsAnalyzer(fp.client)
                    jr = ja.analyze(target_url, page_html=_entry_html)
                    collected.extend(jr.findings)
                    js_result = {
                        "urls": list(getattr(jr, "urls", []) or []),
                        "components": list(getattr(jr, "components", []) or []),
                        "bodies": list(getattr(jr, "bodies", []) or []),
                        "inline_scripts": list(getattr(jr, "inline_scripts", []) or []),
                    }
                    notes.append(f"JS 分析：抓取 {jr.scripts_fetched} 个产物，"
                                 f"识别组件 {len(jr.components)} 个，产出 {len(jr.findings)} 条")
                except Exception as e:  # noqa: BLE001
                    notes.append(f"JS 分析失败：{type(e).__name__}: {str(e)[:120]}")

                # ---------- 抢采素材无条件并入 js_result（零请求） ----------
                # 为什么必须无条件：原先只在「js_result 完全无素材」时才并入
                # （阶段 3.5 的门控），而 JsAnalyzer 只要摸到**一段内联脚本**，
                # has_material 即为真 → 抢采的 27 条接口、7 份脚本正文整批
                # 丢弃，注入类检查全灭在「接口 0 条」上（D3 实测）。
                # 「手上已有更全的素材」与「js_result 非空」不互斥 ——
                # merge 只补不覆盖、零额外请求，没有理由把它当兜底路径。
                if (early_assets is not None
                        and getattr(early_assets, "has_material", False)):
                    try:
                        from engine import frontend as _fe_merge  # noqa: PLC0415

                        js_result = _fe_merge.merge_into_js_result(
                            js_result, early_assets)
                        notes.append("[前端补采] L2 开头抢采的前端素材已并入"
                                     " JS 产物（只补不覆盖，不因 JsAnalyzer "
                                     "已有零星素材而丢弃）："
                                     f"{early_assets.coverage_note()}")
                    except Exception as e:  # noqa: BLE001
                        notes.append("[前端补采] 抢采素材并入异常（已捕获，"
                                     f"未中断）：{type(e).__name__}: "
                                     f"{str(e)[:120]}")

            # ---------- SPA 渲染 ----------
            # 前端路由 / XHR 接口只有真浏览器才看得到。渲染成功就把 XHR 端点
            # 并入 JS 产物分析；渲染不可用时**绝不静默** —— 覆盖度下降必须
            # 说出来，不许把「没渲染」冒充「没发现问题」。
            try:
                from engine import spa as _spa_mod  # noqa: PLC0415

                _home_html = ""
                try:
                    _hr = fp.client.get(target_url, timeout=12)
                    _home_html = getattr(_hr, "text", "") or ""
                except Exception:  # noqa: BLE001
                    pass
                if _spa_mod.looks_like_spa(_home_html,
                                           list(js_result.get("urls") or [])):
                    if self.profile_name == "safe":
                        js_result["spa"] = {"detected": True, "rendered": False,
                                            "reason": "安全档不渲染（执行 JS 可能对目标产生状态变化）"}
                        notes.append("[SPA] 检测到前端渲染应用 —— 安全档不渲染，"
                                     "SPA 接口覆盖度下降（如实披露，不计入通过）")
                    elif _spa_mod.renderer_available():
                        _rr = _spa_mod.render_collect(target_url)
                        _eps = _spa_mod.endpoints_of(_rr)
                        js_result["spa"] = {"detected": True,
                                            "rendered": bool(_rr.get("ok")),
                                            "pages": _rr.get("pages", []),
                                            "endpoints": _eps}
                        if _rr.get("ok"):
                            _added = 0
                            for _u in _eps:
                                if _u not in js_result["urls"]:
                                    js_result["urls"].append(_u)
                                    _added += 1
                            notes.append(f"[SPA] 渲染成功 —— 从无头浏览器捕获 "
                                         f"{len(_eps)} 个 XHR 接口端点"
                                         f"（新增 {_added}），已并入 JS 产物分析")
                        else:
                            notes.append(f"[SPA] 检测到前端渲染应用，但渲染失败："
                                         f"{_rr.get('note', '')}")
                    else:
                        js_result["spa"] = {"detected": True, "rendered": False,
                                            "hint": _spa_mod.install_hint()}
                        notes.append("⚠ [SPA] 检测到前端渲染应用，但渲染器不可用 —— "
                                     "SPA 路由与 XHR 接口覆盖度下降，"
                                     "该部分**不会**被写成「未见异常」。安装："
                                     + _spa_mod.install_hint())
            except Exception as e:  # noqa: BLE001
                notes.append(f"[SPA] 渲染模块异常：{type(e).__name__}: {str(e)[:120]}")

            for f in collected:
                f.target = target_name
            st.status = "ok"
            st.detail = "；".join(notes)
        except _BoundarySkip:
            pass  # 主动跳过，状态与说明已在上面写好
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}\n{traceback.format_exc()[:400]}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 3.5：前端产物补采 ----------
        # 为什么必须**独立于上面那个 try**：
        # 上面任何一步抛异常（尤其是「检测到封禁 → 主动跳过采集」）都会直接
        # 跳出，js_result 保持为空。于是 17 个声明 `requires=["js"]` 的检查项
        # 集体落「未执行」，报告里只留一句「该目标未采集到前端产物」——
        # 而事实上 **L1 阶段已经用无头浏览器渲染过入口页**，渲染后的 DOM
        # 就躺在 fp_result 里，里面有真实的 <script src>、真实的内联脚本、
        # 真实的前端路由链接。这份数据一直在手上，却从来没进过 JS 分析。
        #
        # 这一段的职责只有一个：**把已经在手上的素材榨干**。
        # 声明式地写在这里（而不是挂在采集阶段内部），就是要保证
        # 「采集阶段挂了」不再等于「前端侧全无结论」。
        if enable_js and not _frontend_has_material(js_result):
            try:
                from engine import frontend as _fe  # noqa: PLC0415

                _spa_eps = list((js_result.get("spa") or {}).get("endpoints") or [])
                if early_assets is not None and early_assets.has_material:
                    # L2 开头已经抢在 nuclei 之前采过了 —— 这里是它在发挥作用：
                    # 采集阶段（nuclei 等）挂了、结果被丢弃，但前端素材已经在手上。
                    # **不再发一轮请求**：重复抓同一批脚本既浪费，也会给已经被封的
                    # 目标再添几枪。只把渲染阶段看到的 XHR 端点补进去。
                    _assets = early_assets
                    if _spa_eps:
                        _assets.spa_detected = True
                        _seen = set(_assets.spa_endpoints)
                        for _u in _spa_eps:
                            if _u not in _seen:
                                _seen.add(_u)
                                _assets.spa_endpoints.append(_u)
                            if _u not in _assets.endpoints:
                                _assets.endpoints.append(_u)
                    _why = "（本轮采集阶段未产出素材，取自 L2 开头抢采）"
                else:
                    _assets = _fe.collect(
                        fp.client, target_url,
                        render_html=str(fp_result.get("_render_html") or ""),
                        tier=self.profile_name,
                        # 目标已确认够不着时只做纯静态提取：一个请求都不发。
                        # 手上的渲染 DOM 照样能榨出脚本引用与内联脚本。
                        allow_requests=not collection_blocked,
                        spa_endpoints=_spa_eps,
                    )
                    _why = ""
                fp_result["_frontend"] = {
                    "sources": dict(_assets.html_sources),
                    "script_refs": list(_assets.script_refs),
                    "fetched": list(_assets.fetched),
                    "endpoints": len(_assets.endpoints),
                    "request_count": _assets.request_count,
                    "degraded": _assets.degraded,
                    "note": _assets.coverage_note(),
                }
                if _assets.has_material:
                    js_result = _fe.merge_into_js_result(js_result, _assets)
                    notes.append(
                        f"[前端补采] 采集阶段未能产出可用素材，改由多源汇聚补齐{_why}："
                        f"{_assets.coverage_note()}")
                else:
                    # 素材确实一点都没有 —— 明写原因，不写成「目标没问题」。
                    notes.append(f"[前端补采] 未能取得可用素材：{_assets.coverage_note()}")
                    js_result = _fe.merge_into_js_result(js_result, _assets)
            except Exception as e:  # noqa: BLE001
                notes.append(f"[前端补采] 异常（已捕获，未中断）："
                             f"{type(e).__name__}: {str(e)[:120]}")
        # 补采结论要进这一阶段的说明里 —— 否则报告里只看到「采集被跳过」，
        # 看不出前端侧其实还是拿到了素材。抢采（在 nuclei 之前那次）同样要进，
        # 否则「素材到底采到没有」在报告里查无实据。
        _fe_notes = [n for n in notes
                     if n.startswith("[前端补采]") or n.startswith("[前端采集]")]
        if _fe_notes:
            st.detail = (st.detail + "；" if st.detail else "") + "；".join(_fe_notes)

        # 补采本身会发一批请求（抓脚本 / 追分包）。它们走的是 fp.client，
        # 不经过 ctx 的探测热路径，守门看不见 —— 所以这里**主动补一次抽检**，
        # 把「补采期间是否撞上封禁」的发现时机从「逐项检测中途」提前到现在。
        # 不补这一枪，补采就可能在一个已经被封的目标上白撞几十次，
        # 且这批结果会被当成应用内容带进后续判定。
        if (not collection_blocked) and guard is not None and getattr(guard, "armed", False):
            try:
                _ev_fe = guard.check()
            except Exception:  # noqa: BLE001
                _ev_fe = None
            if _ev_fe is not None:
                guard.apply_speed(fp.client)
                notes.append(guard.report.summary())
                if not _ev_fe.recovered:
                    collection_blocked = True
                    notes.append(
                        "⚠ 前端产物补采期间触发边界封禁且退避未恢复 —— "
                        "补采到的脚本正文不予采信（无法区分是否来自拦截页）；"
                        "前端侧结论按「未执行 / 待确认」记录。")
                    st.detail = (st.detail + "；" if st.detail else "") + notes[-1]

        # ---------- 阶段 4：权限矩阵（盲区专项） ----------
        st = self._stage("L2 权限矩阵验证")
        t0 = time.time()
        authz_findings: list[Finding] = []
        #: 矩阵是否真的跑过。跑到过就不再重复跑 —— 越权矩阵是重请求的一步，
        #: 重复跑只会给目标加压并产出重复发现。
        authz_ran = False
        # 档位语义：None = 自动（有身份就跑），True = 强制，False = 关闭。
        # 默认自动是刻意的：越权矩阵是「人工核查项里最能自动化的那一块」，
        # 让它挂在一个需要人记得加 `--authz` 的开关后面，等于默认放弃它。
        if enable_authz is not False and boundary_blocked:
            st.status = "skipped"
            st.detail = (f"{boundary.label}：未触达应用，越权矩阵无法比对"
                         "（所有账号都会拿到同一张拦截页）")
        elif enable_authz is not False:
            try:
                accounts = load_accounts(accounts_path) if accounts_path else []
                endpoints = self._guess_endpoints(fp_result, target_url)
                if accounts:
                    matrix = AuthzMatrix(fp.client, accounts)
                    probes = matrix.verify_endpoints(endpoints)
                    authz_findings = matrix.analyze(probes, target_name)
                    authz_ran = True
                    st.status = "ok"
                    st.detail = f"使用 {len(accounts)} 个测试账号，比对 {len(endpoints)} 个接口，产出 {len(authz_findings)} 条"
                else:
                    st.status = "skipped"
                    st.detail = ("本轮起始时无可用身份 —— 若扫描中途补上凭据，"
                                 "矩阵会在凭据就位后自动补跑（无需人工重扫）")
            except Exception as e:  # noqa: BLE001
                st.status = "failed"
                st.error = f"{type(e).__name__}: {str(e)[:200]}"
        else:
            st.status = "skipped"
            st.detail = "已由 --no-authz 显式关闭"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        for f in authz_findings:
            f.target = target_name
        # 越权类发现单列在报告第 5 章，但也纳入整体统计
        collected.extend(authz_findings)

        # ---------- 阶段 5：逐项检测（全量检查项状态机） ----------
        # 这一阶段是消「假阴性」的关键：清单里的每一项都由注册表显式执行，
        # 没有绑定执行体的项会明确落到「未执行」，绝不再默认成「通过」。
        st = self._stage(ITEMS_STAGE_NAME)
        t0 = time.time()
        detector_results: list[ItemResult] = []
        detector_notes: list[str] = []
        # 运行姿态排在最前：它解释了本次「为什么比全速慢」，也解释了
        # 扫描期间本机的卡顿程度。放在后面会被当成脚注，读的人就少了。
        if self._resource is not None:
            detector_notes.append(self._resource.posture_line())
            detector_notes.extend(self._resource.notes)
        detector_submissions: list[dict[str, Any]] = []
        det_summary: dict[str, Any] = {}
        legacy_findings = list(collected)
        try:
            det_accounts: list[dict[str, Any]] = []
            try:
                from engine.sessionpool import build_pool  # noqa: PLC0415
                from engine import credguide as _cgp  # noqa: PLC0415

                # 会话池：把「有账号记录」变成「有可用会话」。
                # 关键区别 —— 过去账号记录里只有静态 header / cookie，
                # 想用就得人工登录后手工拷贝令牌；现在支持自动登录 + 回验，
                # 且**未回验通过的会话不会被当成「已认证」**：
                # 用游客身份测出来的「越权」，全是噪声。
                _entry_u, _entry_e, _entry_s = _cgp.find_login_entry(
                    self._fp_path_probes)
                _raw_accounts = load_accounts(accounts_path) if accounts_path else []
                # 凭据库身份：不预置 accounts.yaml 的路线 —— 操作者
                # `creds --set` 现场给凭据，这里直接转成会话池身份。
                # 同名时配置文件优先（针对性更强的意图）。
                _store_recs = _cgp.store_account_records(
                    _cgp.session_file_for(domain))
                _cfg_names = {str(a.get("name") if isinstance(a, dict) else
                                  getattr(a, "name", "")) for a in _raw_accounts}
                _raw_all = list(_raw_accounts) + [
                    r for r in _store_recs if r["name"] not in _cfg_names]
                # 凭据获取到的身份（默认 / 弱口令受控尝试）：优先级排在**最后** ——
                # 人工配置的身份更明确、更贴近被测角色，冲突时让人配的赢。
                for _h in (self.credhunt.found if self.credhunt else []):
                    if str(_h.get("name")) not in _cfg_names and all(
                            str(_h.get("name")) != str(x.get("name"))
                            for x in _raw_all):
                        _raw_all.append(_h)

                def _mk_pool(raw: list[Any]) -> Any:
                    return build_pool(
                        [(a.to_pool_dict() if hasattr(a, "to_pool_dict")
                          else (dict(a) if isinstance(a, dict) else {}))
                         for a in raw],
                        target_url=target_url,
                        profile_key=self.profile_name,
                        # 本机凭据库：让操作者不必设环境变量（Windows 上开新终端
                        # 才生效，实际使用中极易被跳过）。**必须传 domain**，
                        # 否则凭据库通道整条是死的 —— 配了账号也永远取不到凭据，
                        # 而表现是「账号没有可用会话」这种看起来很合理的话。
                        domain=domain,
                        # 探测到的登录入口：凭据库「账号+密码」缺 login_url 时兜底
                        login_url=_entry_u,
                    )

                _pool = _mk_pool(_raw_all) if _raw_all else None

                # ---------- 红队自取·注册路：开放注册自建测试身份 ----------
                # 取号决策链第 1 条：目标有开放注册 → 自己注册专用测试号。
                # 第 2/3 条（默认口令 credhunt / 联网检索 credosint）已在
                # 前面跑过；第 4 条是「待人工执行 + 补齐路径」。
                # 注册在服务端创建持久状态（用户记录 / 日志），性质是受控写：
                # 两把锁同时开（deep 档 + 台账 --allow-write）+ 环境开关
                # AISCAN_REGSELF=off 一票否决（红线 24）。已有 ≥2 个已确认
                # 登录态时跳过 —— 幂等，季度扫描不刷号。
                if not boundary_blocked and _cgp.items_requiring("accounts"):
                    _pairs_now = _pool.authenticated_pairs() if _pool else 0
                    if _pairs_now < 2:
                        from engine import regself as _rs  # noqa: PLC0415

                        _gr = _rs.gate_reason(self.profile_name,
                                              self._ledger_allows_write(domain))
                        if _gr:
                            detector_notes.append(
                                f"[红队自取·注册] 未执行：{_gr} —— 需要账号的"
                                "检查项按既有决策链走（默认口令 / 联网检索 /"
                                " 待人工），缺口如实记入报告")
                        else:
                            try:
                                _js_eps = self._guess_endpoints(fp_result,
                                                                target_url)
                                _rs_res, _rs_notes = _rs.run(
                                    target_url=target_url, domain=domain,
                                    cred_file=_cgp.session_file_for(domain),
                                    js_endpoints=_js_eps,
                                    login_url_hint=_entry_u, want=2)
                                detector_notes.extend(_rs_notes)
                                if any(r.ok for r in _rs_res):
                                    # 新身份进了本机凭据库 → 会话池重建，
                                    # 本轮越权 / IDOR 检查直接用上（无需重扫）
                                    _store_recs = _cgp.store_account_records(
                                        _cgp.session_file_for(domain))
                                    _raw_all = list(_raw_accounts) + [
                                        r for r in _store_recs
                                        if r["name"] not in _cfg_names]
                                    _pool = _mk_pool(_raw_all)
                            except Exception as e:  # noqa: BLE001
                                detector_notes.append(
                                    f"[红队自取·注册] 异常（已捕获，未中断）："
                                    f"{type(e).__name__}: {str(e)[:120]}")

                # ---------- 凭据等待：**只在显式要求时才暂停** ----------
                # v11.6 起默认不等待。原因来自一次真实吐槽：
                # 红队视角下的扫描跑到一半弹出「等你把凭据递过来（最长 30 分钟）」，
                # 于是进程就那么睡着 —— 既没出报告，也没人知道它在等。
                # 现实是：攻击者不等人，而无人值守场景（批量 / 定时）里
                # 睡 30 分钟就是纯粹空转。
                #
                # 现在的分工：
                #   · 红队的做法 —— 自己试（上面 credhunt：找入口 + 受控默认口令）
                #   · 试不出来 —— 如实记「待人工执行」并给出补齐命令，扫描继续跑完
                #   · 确实想守着终端等凭据 —— 显式给 `--cred-wait N`
                #     （或设环境变量 AISCAN_CRED_WAIT=N）
                _need_p = _cgp.items_requiring("accounts")
                _wait_s = int(getattr(self, "cred_wait_seconds", 0) or 0)
                _explicit_wait = bool(getattr(self, "cred_wait_explicit", False))
                if _need_p and not boundary_blocked and not _explicit_wait:
                    _why = ("红队默认不等凭据"
                            if self.mode == DEFAULT_MODE else "未显式指定等待")
                    print(f"  · 凭据缺口 {len(_need_p)} 项已如实记入报告（{_why}）；"
                          "需要现场等凭据请加 --cred-wait 1800",
                          file=sys.stderr, flush=True)
                    detector_notes.append(
                        f"[凭据] 本次未挂起等待凭据（{_why}）—— 相关项如实记为"
                        "「未执行 / 待人工执行」，**不写成通过**；"
                        "补凭据后重扫即可（`aiscan.py creds --target "
                        f"{domain} --set <角色> --from-clipboard`）")
                if (_need_p and not boundary_blocked and _wait_s > 0
                        and _explicit_wait):
                    _sf_w = _cgp.session_file_for(domain)
                    _plan_w = _cgp.build_plan(
                        target=domain, target_url=target_url,
                        accounts=(_pool.accounts if _pool else []),
                        path_probes=self._fp_path_probes,
                        login_url=_entry_u, session_file=_sf_w)
                    if _plan_w.pending:
                        print("\n" + "▁" * 40, flush=True)
                        print("⏸ 扫描暂停 —— 需要登录凭据才能执行认证 / 越权类检查",
                              flush=True)
                        print(_cgp.render(_plan_w, target_url), end="", flush=True)
                        print(f"\n⏳ 等待凭据写入凭据库（最长 {int(_wait_s)} 秒；"
                              "写入后本轮自动继续，**无需重扫**）……", flush=True)

                        def _replan() -> Any:
                            return _cgp.build_plan(
                                target=domain, target_url=target_url,
                                accounts=(_pool.accounts if _pool else []),
                                path_probes=self._fp_path_probes,
                                login_url=_entry_u, session_file=_sf_w)

                        _ok_wait, _plan_end = wait_for_credentials(
                            _replan, _wait_s, poll_s=10, log_fn=print)
                        if _ok_wait:
                            print("✓ 收到凭据 —— 会话池按新凭据重建，本轮继续",
                                  flush=True)
                            _store_recs = _cgp.store_account_records(_sf_w)
                            _raw_all = list(_raw_accounts) + [
                                r for r in _store_recs
                                if r["name"] not in _cfg_names]
                            _pool = _mk_pool(_raw_all)
                            detector_notes.append(
                                "[凭据] 等待期间凭据已就位 —— 会话池已重建，"
                                "认证 / 越权类检查本轮继续执行")
                        else:
                            print("⏱ 等待超时 —— 本轮按无凭据继续，"
                                  "缺口如实记入报告（不会写成通过）", flush=True)
                            detector_notes.append(
                                "[凭据] 凭据等待超时 —— 本轮按无凭据继续；"
                                "补齐后重扫即可，相关项仍是「未执行」而非「通过」")

                if _pool is not None:
                    self._session_accounts = list(_pool.accounts)
                    det_accounts = _pool.accounts
                    for _line in _pool.summary_lines():
                        detector_notes.append(f"[会话池] {_line}")
                    if _pool.authenticated_pairs() < 2:
                        detector_notes.append(
                            "[会话池] 已确认登录态不足 2 个 —— 本轮「读到他人数据」"
                            "类判定只能记「未能验证」，不得记「未达成」")

                    # ---------- 凭据就位后的自动补跑 ----------
                    # 权限矩阵在扫描早期就跑了，那时凭据可能还没到位（凭据是
                    # 扫描**中途**才索取到的）。不在这里补跑，就会出现很荒谬的
                    # 结果：报告一边写着「已收到凭据、认证类检查继续执行」，
                    # 一边把越权矩阵记成「未配置测试账号」。
                    # 这是「除给凭据外零人工操作」的最后一块拼图 ——
                    # 操作者给了凭据，矩阵**当轮**就该用上，不需要重扫。
                    if (not authz_ran and enable_authz is not False
                            and not boundary_blocked):
                        _ap = _pool.authenticated_pairs()
                        if _ap >= 1:
                            try:
                                # 身份来源要覆盖**全部通道** —— 早先这里重新
                                # `load_accounts()`，那只读 YAML 文件，于是凭据库
                                # （`creds --set`）与 credhunt 自取的身份全被忽略，
                                # 补跑**永远**走「无可加载身份」分支。而矩阵阶段
                                # 结束时终端还告诉操作者「凭据就位后会自动补跑
                                # （无需人工重扫）」—— 一句不会发生的事
                                # （红线：报告不得说假话）。
                                _accs = list(getattr(_pool, "accounts", None) or [])
                                # 只带**已确认登录态**的账号进矩阵：登录失败 /
                                # 无凭据的账号发出去的是匿名请求，拿游客响应
                                # 冒充「该账号的响应」，比对结果全是噪声
                                # （红线 29③：已确认登录态 < 2 → 只能记未能验证）。
                                from engine.sessionpool import LOGIN_OK  # noqa: PLC0415

                                _accs = [a for a in _accs
                                         if a.get("login_state") == LOGIN_OK
                                         and not a.get("rejected")]
                                if not _accs and accounts_path:
                                    _accs = load_accounts(accounts_path)
                                _eps = self._guess_endpoints(fp_result, target_url)
                                if _accs and _eps:
                                    _m = AuthzMatrix(fp.client, _accs)
                                    _pr = _m.verify_endpoints(_eps)
                                    _late = _m.analyze(_pr, target_name)
                                    for _f in _late:
                                        _f.target = target_name
                                    collected.extend(_late)
                                    legacy_findings.extend(_late)
                                    authz_findings.extend(_late)
                                    authz_ran = True
                                    detector_notes.append(
                                        f"[权限矩阵·补跑] 凭据就位后自动补跑："
                                        f"{_ap} 个已确认登录态、比对 {len(_eps)} 个接口、"
                                        f"产出 {len(_late)} 条")
                                else:
                                    detector_notes.append(
                                        "[权限矩阵·补跑] 未跑："
                                        + ("无可比对接口" if not _eps
                                           else "无可加载身份"))
                            except Exception as e:  # noqa: BLE001
                                detector_notes.append(
                                    f"[权限矩阵·补跑] 异常（已捕获，未中断）："
                                    f"{type(e).__name__}: {str(e)[:120]}")
                        else:
                            detector_notes.append(
                                "[权限矩阵·补跑] 未跑：凭据库有记录但**没有回验通过**的"
                                "登录态（用游客身份比对出来的越权结论全是噪声，"
                                "所以不跑）")
            except Exception as e:  # noqa: BLE001
                detector_notes.append(f"测试账号加载失败：{type(e).__name__}: {str(e)[:120]}")

            dctx = build_context(
                target_name=target_name,
                domain=domain,
                target_url=target_url,
                profile=self.profile,
                profile_key=self.profile_name,
                fp_result=fp_result,
                js_result=js_result,
                nuclei_findings=nuclei_findings,
                accounts=det_accounts,
                client=fp.client,
                ledger_write_authorized=self._ledger_allows_write(domain),
            )
            # 两类边界拦截**同权**短路，判据与理由见 boundary_short_circuit()。
            # B 类那一支是 2026-09-29 内部生产系统 事故的直接修复点：终态若在 L2 期间
            # 就已成立（persistent / budget_exhausted / rounds_exceeded），
            # **逐项检测开始前**就必须与 A 类一样短路 —— 否则全量检查项会在拦截页
            # 上跑完，产出 73 项假通过 + 16 项假不通过，报告三个层次互相矛盾。
            _blk, _blk_note = boundary_short_circuit(boundary_blocked, boundary, guard)
            if _blk is not None:
                dctx._cache["boundary_block"] = _blk
            if _blk_note:
                detector_notes.append(_blk_note)
            detector_results, detector_findings = run_all_items(
                self.checklist, app, dctx, guard=guard, health=health,
                # 逐项进度：每跨 10% 报一行（含正在跑的项名）。
                # 不接这一条，这一阶段就是几分钟的空白。
                progress_fn=self._pg().item_tick)

            # 健康度守门终态：与「被封」分开披露。措辞不能互换 ——
            # 一个是「请求没到应用」，一个是「请求到了、应用在报错」。
            if self._health_guard_off:
                detector_notes.append(
                    "⚠ 目标健康度守门（hard_limits.stop_on：连续 5xx / "
                    "响应时间突增）已被 AISCAN_HEALTH_GUARD=off **显式关闭**："
                    "本次扫描不会因目标连续 5xx 主动停手。该开关仅限一次性"
                    "靶场基准 —— 靶场的 5xx 是应用的正常应答形态；"
                    "**生产目标不得使用**，用它扫生产等于拆掉了"
                    "「不把对方打挂」的最后一道闸。")
            if health is not None and health.terminal:
                detector_notes.append(
                    f"⚠ 逐项检测因**目标健康度异常**而提前停止：{health.reason}"
                    " 之后的检查项已按「未执行」记录 ——"
                    "**这不是被拦截，也不是「通过」**。")
                self._target_health_stop = health.reason
            elif health is not None and getattr(health, "loopback_suppressed", False):
                detector_notes.append(
                    "ℹ 目标健康度守门（hard_limits.stop_on）在 **loopback 自有靶场**"
                    "触发（延迟突增 / 连续 5xx），但本地靶场不受「不把对方打挂」约束："
                    "本次**不主动停手**，仅记录异常，后续检查项照常执行。"
                    "这正是基准要的完整测量，不构成「通过」。")

            if guard is not None and guard.report.occurred:
                detector_notes.append(guard.report.summary())
                if guard.report.terminal:
                    detector_notes.append(
                        "⚠ 逐项检测期间发生边界封禁且退避未能恢复：封禁之后的检查项"
                        "已按「未执行」记录，**不得把「未执行」读成「通过」**。")
                elif guard.report.speed_factor < 1.0:
                    detector_notes.append(
                        f"为避免再次触发封禁，后续扫描速率已降至原速的 "
                        f"{guard.report.speed_factor:.0%}")

            # ---- 外部引擎（nuclei）结果回填检查项 ----
            # 不做这一步，报告会自相矛盾：第 2 章列着一条 nuclei 实测命中的问题、
            # 附请求与响应原文，第 3 章同一个检查项却写着「通过」。
            # 研发按第 3 章看，就会把一个真实问题关掉 —— 而它其实是唯一一条
            # 有现成证据的问题。回填只可能把状态收紧为「不通过」，不可能放宽。
            external_backfill: Any = None
            try:
                from engine.nuclei_map import backfill_external_findings  # noqa: PLC0415
                external_backfill = backfill_external_findings(
                    detector_results, nuclei_findings)
                detector_notes.append(external_backfill.summary())
                detector_notes.extend(external_backfill.notes)
            except Exception as e:  # noqa: BLE001
                detector_notes.append(
                    f"⚠ nuclei 结果回填检查项失败（{type(e).__name__}: {str(e)[:120]}）："
                    "第 3 章的检查项状态可能与该引擎的发现不一致，请人工核对")

            det_summary = summarize_detectors(detector_results)
            # 采集充分度：报告中所有 N/A 结论的可信度取决于它
            collection = dict(dctx._cache.get("collection_report") or {})
            det_summary["采集充分度"] = collection
            if collection.get("summary"):
                detector_notes.append(collection["summary"])
            # 渲染情况要进检测阶段的说明：它是「那些 N/A 该怎么读」的直接依据，
            # 只留在第一章的指纹明细里，读者读到第三章时已经不记得了。
            for _rn in ((fp_result.get("render") or {}).get("notes") or []):
                detector_notes.append(f"[渲染] {_rn}")
            # 新旧两套检测器的产出合并去重，避免同一问题被报两次
            collected = merge_with_legacy(detector_findings, legacy_findings)
            for f in collected:
                f.target = target_name

            detector_notes.append(
                f"逐项执行 {det_summary.get('合计', 0)} 项，"
                f"实际跑通 {det_summary.get('自动执行', 0)} 项，"
                f"其中通过 {det_summary.get('通过', 0)} 项、"
                f"不通过 {det_summary.get('不通过', 0)} 项")
            detector_notes.append(
                f"未执行 {det_summary.get('未执行', 0)} 项、"
                f"待人工执行 {det_summary.get('待人工执行', 0)} 项、"
                f"N/A {det_summary.get('N/A', 0)} 项、"
                f"待确认 {det_summary.get('待确认', 0)} 项")
            if dctx.submissions:
                detector_submissions = list(dctx.submissions)
                detector_notes.append(
                    f"本次主动提交动作 {len(dctx.submissions)} 次（已在报告第 7 章逐条披露）")
            if dctx.errors:
                detector_notes.append(
                    f"检测器执行异常 {len(dctx.errors)} 项（已捕获，结论记为未执行）")
            detector_notes.append(f"累计探测请求约 {dctx.probe_count} 次")

            st.status = "ok"
            st.detail = "；".join(detector_notes)
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}\n{traceback.format_exc()[:400]}"
            detector_notes.append(f"逐项检测阶段失败：{type(e).__name__}: {str(e)[:160]}")
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 6：脚本验证 + 准入闸门 ----------
        # 闸门是本次改动的核心：没通过复现验证的发现，不得进漏洞清单。
        # 报告里写出去的每一条，对方照着脚本都能复测出来。
        st = self._stage("L3 脚本验证与准入闸门")
        t0 = time.time()
        verify_dir = archive_dir / "verify"
        verify_runs: list[dict[str, Any]] = []
        gate_result: Any = None
        try:
            builder = ScriptBuilder(verify_dir)
            builder.generate_all(collected, target_url)
            runs = VerifyRunner(verify_dir).run_all()
            for r in runs:
                verify_runs.append({"script": r.script, "exit_code": r.exit_code,
                                    "status": r.status_text, "duration_ms": r.duration_ms})

            gate_result = ReportGate().evaluate(
                collected, runs=runs, verify_ran=True,
                verify_note=f"生成并执行 {len(runs)} 份复现脚本")
            gs = gate_result.stats()
            n_ok = gs["已复现"]
            st.status = "ok"
            # 越权类复现必须带真实身份：脚本自己从会话文件 / 环境变量取凭据。
            # 这件事必须在阶段详情里说出来 —— 否则「无法判定 N 条」看起来像
            # 工具能力不足，而实际只是操作者还没填那份 JSON。
            session_note = ""
            if builder.session_template is not None:
                session_note = (f"；越权类复现需会话上下文：{builder.session_template_note}"
                                f"（{builder.session_template.name}）")
            st.detail = (f"生成并执行 {len(runs)} 份复现脚本：已复现 {n_ok}、"
                         f"未复现 {gs['未复现']}、无法判定 {gs['无法判定']}、"
                         f"未验证 {gs['未验证']}；可复测率 {gs['可复测率']:.1%}"
                         + session_note)
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}"
            # 复现环节失败时必须显式记录 —— 否则报告会把「没验」当成「验过了」。
            # 注意：兜底分支本身**绝不能抛异常**。之前这里直接调 ReportGate()，
            # 而该类恰恰漏了导入 —— NameError 从未被处理的兜底路径抛出，
            # 把「阶段失败但继续出报告」变成「整份结果全丢」。
            try:
                gate_result = ReportGate().evaluate(
                    collected, runs=None, verify_ran=False,
                    verify_note=f"复现验证环节执行失败：{type(e).__name__}")
            except Exception as inner:  # noqa: BLE001
                gate_result = None
                st.error += f"；兜底建档也失败：{type(inner).__name__}: {str(inner)[:120]}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 6.5：结果证明（把「存在型」升级为「达成型」） ----------
        # 检测器的终点是「漏洞存在」；这一步把它推进到「攻击目标是否达成」。
        # 例：SQL 注入命中的终点不该是「能触发报错」，而是「能不能读出数据」。
        # 结论写回 finding.extra["proof"]，报告据此展示**实测拿到了什么**，
        # 而不是「可能存在什么」。
        st = self._stage("L3.5 结果证明（攻击目标达成性）")
        t0 = time.time()
        proof_summary: dict[str, Any] = {}
        try:
            proof_summary = self._stage_result_proofs(
                dctx,
                list(gate_result.reportable_findings()) if gate_result else [],
                list(detector_results), gate_result, domain=domain)
            st.status = "ok"
            st.detail = (f"对 {proof_summary.get('ran', 0)} 条可证明发现执行结果证明："
                         f"已达成 {proof_summary.get('proved', 0)}、"
                         f"未达成 {proof_summary.get('not_proven', 0)}、"
                         f"未能验证 {proof_summary.get('inconclusive', 0)}")
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 7：定级（仅放行通过闸门的发现） ----------
        st = self._stage("L4 危害定级")
        t0 = time.time()
        blocked: list[Any] = []
        try:
            reportable = gate_result.reportable_findings() if gate_result else []
            allowed = {id(f) for f in reportable}
            graded = GradingEngine().grade_all(collected)
            for f, d in graded:
                if id(f) not in allowed:
                    # 被闸门拦下：不进漏洞清单，但仍会在报告第 7 章如实披露
                    blocked.append(f)
                    continue
                if d.excluded:
                    fs.add_pending(f)
                else:
                    fs.add(f)
            c = fs.counts()
            st.status = "ok"
            st.detail = (f"定级完成：严重 {c['严重']}、高危 {c['高危']}、中危 {c['中危']}、"
                         f"低危 {c['低危']}、信息 {c['信息']}；"
                         f"证据不足转待确认 {len(fs.pending)} 条")
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}"
            for f in collected:
                fs.add(f)
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 8：攻击目标编排（红队模式） ----------
        # 与前面所有阶段的根本区别：判定单元不是「检查项」，而是「攻击目标」。
        # 黑客攻击一定有目的 —— 拿数据 / 改数据 / 拿控制权 —— 为达目的穷尽手段。
        # 结论三态：已达成 / 未达成 / 未能验证，三者严格分开，不得混淆。
        st = self._stage("L4.5 攻击目标编排（红队）")
        t0 = time.time()
        if self.mode == MODE_REDTEAM:
            try:
                _objs = self._stage_objectives(
                    dctx, list(fs.findings), list(detector_results), domain)
                _cnt = {k: sum(1 for o in _objs if o.result == k)
                        for k in ("已达成", "未达成", "未能验证")}
                st.status = "ok"
                st.detail = (f"编排 {len(_objs)} 个攻击目标："
                             f"已达成 {_cnt['已达成']}、未达成 {_cnt['未达成']}、"
                             f"未能验证 {_cnt['未能验证']}")
            except Exception as e:  # noqa: BLE001
                st.status = "failed"
                st.error = f"{type(e).__name__}: {str(e)[:200]}"
        else:
            st.status = "skipped"
            st.detail = "合规模式不执行攻击目标编排（默认即红队，--mode compliance 关闭）"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 8.5：攻击链组合 ----------
        # 单点发现回答「这里有个洞」，攻击链回答「这些洞连起来能打到哪」。
        # 它同时承担一个纠偏职责：某目标报「能力缺口」但链尾能力已被单点实测
        # 证明时，把结论回填成「已达成」——不让实测到的战果因为「没有独立路径」
        # 而被埋成「未能验证」。
        st = self._stage("L4.6 攻击链组合（发现 → 目标）")
        t0 = time.time()
        chains: list[Any] = []
        if self.mode == MODE_REDTEAM:
            try:
                chains = self._stage_attack_chains(
                    dctx, list(fs.findings), list(self._objectives))
                _proven = sum(1 for c in chains if c.state == "已达成")
                _filled = len(getattr(self, "_chain_filled", None) or [])
                st.status = "ok"
                st.detail = (
                    f"从 {len(fs.findings)} 条发现中组合出 {len(chains)} 条攻击链："
                    f"已达成 {_proven}、候选（待逐环确认）{len(chains) - _proven}"
                    + (f"；为 {_filled} 个能力缺口目标回填了实测结论" if _filled else ""))
            except Exception as e:  # noqa: BLE001
                st.status = "failed"
                st.error = f"{type(e).__name__}: {str(e)[:200]}"
        else:
            st.status = "skipped"
            st.detail = "合规模式不做攻击链组合（默认即红队）"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)
        self._chains = chains

        # ---------- 阶段 L4.7：链补证（派发受控实测） ----------
        st = self._stage("L4.7 链补证（派发受控实测）")
        t0 = time.time()
        closure: Any = None
        if self.mode == MODE_REDTEAM:
            try:
                closure = self._stage_chain_closure(
                    dctx, chains, list(self._objectives))
                _res = list(getattr(closure, "results", None) or [])
                _up = list(getattr(closure, "upgraded", None) or [])
                _gaps = list(getattr(closure, "gaps", None) or [])
                st.status = "ok"
                st.detail = (
                    f"派发 {len(_res)} 次能力补证实测"
                    + (f"，{len(_up)} 条链由候选升为已达成" if _up else
                       "，本轮没有候选链被实测升级")
                    + (f"；{len(_gaps)} 项能力缺口已具名（无自动验证体或未授权）"
                       if _gaps else ""))
                for _n in (getattr(closure, "notes", None) or []):
                    detector_notes.append(f"[链补证] {_n}")
            except Exception as e:  # noqa: BLE001
                st.status = "failed"
                st.error = f"{type(e).__name__}: {str(e)[:200]}"
        else:
            st.status = "skipped"
            st.detail = "合规模式不做链补证（默认即红队）"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)
        self._chain_closure = closure

        # ---------- 凭据索取（阶段 7 之前算，报告要引用） ----------
        # 「需要令牌但拿不到」过去是个静默终点：只记一句「未配置测试账号」，
        # 没人知道该去哪拿、怎么给，于是那几项永远停在「未执行」。
        # 这里把它显式化 —— 需要就**主动问**，并给出去哪拿的证据与补法。
        # 注意这不改变任何检查项的状态：凭据未到位时它们仍是「未执行」，
        # 绝不会被写成通过。
        cred_ask: dict[str, Any] = {}
        try:
            from engine import credguide as _cg  # noqa: PLC0415

            _need = _cg.items_requiring("accounts")
            _plan = _cg.build_plan(
                target=domain, target_url=target_url,
                accounts=self._session_accounts,
                path_probes=self._fp_path_probes,
                session_file=_cg.session_file_for(domain))
            self.last_cred_plan = _plan if _plan.pending else None
            # 只在「有项确实依赖账号」且「还有没到位的身份」时才问。
            # 没有依赖项时还去索要凭据，是把噪声当工作。
            if _plan.pending and _need:
                cred_ask = _plan.to_dict()
                _names = "、".join(n.role for n in _plan.pending)
                detector_notes.append(
                    f"[凭据] {len(_plan.pending)} 个身份尚未就位（{_names}）——"
                    f" 影响 {len(_need)} 项依赖登录态的检查；"
                    "取证指引见报告第 3 章「凭据缺口」一节，"
                    "或在终端执行：python aiscan.py creds --target " + domain)
            for _n in _plan.notes:
                detector_notes.append(f"[凭据] {_n}")
        except Exception as e:  # noqa: BLE001
            detector_notes.append(f"[凭据] 需求清单生成失败：{type(e).__name__}: {str(e)[:100]}")

        # ---------- 阶段 7：报告 ----------
        st = self._stage("L5 报告生成")
        t0 = time.time()
        reports: dict[str, Path] = {}
        try:
            # 枚举与端口覆盖范围：报告要能说清「试过什么」，
            # 否则「未发现问题」和「基本没试」在读者眼里没有区别。
            coverage: dict[str, Any] = {}
            try:
                from engine.checks import net as _net  # noqa: PLC0415
                # 可达范围走 base.reachability_scope 这个**唯一入口**，
                # 不在这里另判一套 —— 两处各判一次，迟早一处修了另一处没修
                #（裸 IP 目标取不到 info04_ip 就是这种坑）。
                from engine.checks.base import (  # noqa: PLC0415
                    reachability_scope as _reach,
                )

                _scope, _, _why = _reach(dctx)
                coverage = {
                    "url_pool": list(dctx._cache.get("url_pool_coverage") or []),
                    "url_skipped": list(dctx._cache.get("url_pool_skipped") or []),
                    # 覆盖度说明（例如「接口文档找到了但解不开」）。
                    # 与「刻意剔除」分开存：混在一起会让报告里
                    # 「因破坏性风险剔除 N 个」变成错话。
                    "url_notes": list(dctx._cache.get("url_pool_notes") or []),
                    "ports": _net.port_scan_log(),
                    # 可达范围随端口清单一起进报告 —— 端口类结论的定级完全
                    # 取决于它，不能只在正文里提一句。
                    "reach_scope": _scope,
                    "reach_why": _why,
                }
            except Exception:  # noqa: BLE001
                coverage = {}

            # ---------- 边界防护绕过试探（红队视角）----------
            # 探到了防护（L1 全量拦截，或扫描中途触发过封禁），就该试着
            # 绕过它 —— 否则「防护有效」只是「正面硬闯没闯进去」。
            # 有界（≤12 请求）、无副作用（GET/HEAD，无 payload）。
            _guard_occurred = bool(
                guard is not None and getattr(guard.report, "occurred", False))

            # ---- 边界判定的「证据补足修正」（2026-09-29 内部生产系统 事故）----
            # L1 判定时流量还直达应用，所以当时判「未发现边界防护全量拦截特征」
            # 是**当时的事实**；但运行期守门随后拿到了拦截页厂商特征
            # （如 errors.aliyun.com → 阿里云 WAF）。这份证据必须回填边界判定
            # 并**具名修正**，否则报告里会同时存在两个相反的说法：
            #   L1 阶段说「未发现边界防护」 / 守门说「命中阿里云拦截页特征」
            # —— 读者不知道信哪个。
            #
            # 只补「厂商是谁」，**不把 blocked 翻成 True**：前段流量确实是通的，
            # 翻转会让报告改口说「开扫第一个请求即被接管」，那是另一个错误
            # （A 类与 B 类的处置本来就不同：一个等不回来，一个能等到恢复）。
            if _guard_occurred and guard is not None:
                _gv = guard.report.vendor or ""
                if _gv:
                    if self._boundary is None:
                        # L1 什么都没探到（self._boundary 为空）时也要有载体：
                        # 建一个 blocked=False 的判定，只承载厂商与修正说明。
                        from engine.wafgate import BlockVerdict  # noqa: PLC0415

                        self._boundary = BlockVerdict(blocked=False, vendor=_gv)
                        self._boundary.notes.append(
                            f"运行期证据补足：L1 探测时未拦截（当时请求可达应用），"
                            f"扫描中段起捕获 {_gv} 拦截页特征。"
                            f"边界防护判定修正为「{_gv}（运行期确认），"
                            f"封禁前时段未拦截」。")
                        detector_notes.append(
                            f"边界判定修正（证据补足）：L1 未拦截 → "
                            f"运行期确认 {_gv}，封禁前时段无拦截，"
                            f"封禁后请求未触达应用。")
                    elif not self._boundary.vendor:
                        self._boundary.vendor = _gv
                        self._boundary.notes.append(
                            f"运行期证据补足：拦截页厂商确认为 {_gv}"
                            f"（L1 判定时未取到厂商特征，原「未发现边界防护"
                            f"全量拦截特征」仅对封禁前时段成立）。")
                        detector_notes.append(
                            f"边界判定补充：拦截页厂商确认为 {_gv}。")

            _l1_blocked = bool(getattr(self._boundary, "blocked", False))

            # ---- B 类（运行期才出现的封禁）必须**回头重判**绕过试探 ----
            # 分流判据只在 L1 时点评估一次：那时流量通常还没被封，判「没有拦可绕」
            # 是**当时的事实**。若此后运行期真的触发了封禁，说明那句判断已被新的
            # 证据推翻 —— 不回头重判，报告就会一边写「触发拦截且未恢复」、
            # 一边写「本次既没撞上墙」，同一节自相矛盾（2026-09-30 内部生产系统 实测）。
            # 此时补做也有意义：守门已走完退避（最多 600s），封禁可能是窗口型的
            # （本项目实测过它自行解除），补探恰好能回答「现在还能不能穿过去」。
            _late_why = bypass_late_probe_reason(
                l1_blocked=_l1_blocked,
                guard_occurred=_guard_occurred,
                already_probed=bool(self._bypass_probes))
            if _late_why:
                try:
                    self._pg().note(
                        f"边界绕过试探：{_late_why} —— **补做**"
                        "（L1 那句「无拦可绕」已被运行期证据推翻）。"
                        "此刻基线可能已不成立，结果按「对照不成立」口径解读，"
                        "不作覆盖率结论。")
                except Exception:  # noqa: BLE001
                    pass
                try:
                    from engine import wafbypass as _wb  # noqa: PLC0415

                    self._bypass_probes = _wb.probe_bypasses(
                        fp.client, target_url, self._boundary)
                    # 探过了就不再是「跳过」—— 留着旧原因会让通告渲染成
                    # 「本次未执行」，与事实不符。
                    self._bypass_skip_reason = ""
                except Exception as e:  # noqa: BLE001
                    # 补探失败也要**如实改口径**：不能说「未探到拦截行为」
                    # （那是 L1 的旧话，已被推翻），要说「探了、没探成」。
                    self._bypass_skip_reason = (
                        f"运行期确认发生边界封禁，但补做绕过试探时出错"
                        f"（{type(e).__name__}: {str(e)[:80]}），"
                        f"本轮**没有**取得绕过结论 —— 这既不是「防护有效」，"
                        f"也不是「绕不过去」，是**没测成**")
                    try:
                        self._pg().note(f"[绕过试探·补做] 异常（已捕获，"
                                        f"未中断）：{type(e).__name__}: {e}")
                    except Exception:  # noqa: BLE001
                        pass

            # 绕过试探在「L1 边界判定之后」会立即执行一次（趁本来源还没被封，
            # 基线对照才成立）；B 类的补做见上。这里只负责把结果写进披露 note
            # （报告与通告都要引用）。
            if self._bypass_probes:
                try:
                    from engine import wafbypass as _wb  # noqa: PLC0415

                    _bs2 = _wb.summarize(self._bypass_probes)
                    detector_notes.append(
                        f"边界绕过试探：{_bs2['tried']} 种变形，"
                        f"{_bs2['blocked']} 被拦、{_bs2['missed']} 未命中拦截特征；"
                        f"基线对照 HTTP {_bs2['baseline_status']}"
                        + ("，对照成立" if _bs2["baseline_ok"]
                           else "，**对照不成立 → 整批结论不可采信**；"
                                "此时「被拦住」不能读成「WAF 识别了该变形」，"
                                "只说明本来源已被整体封禁"))
                except Exception:  # noqa: BLE001
                    pass

            # ---- 历次「已上报、本轮未复测」的发现 ----
            # 通告的「问题清单」不能因为本轮没去复看就变成空的：那会让读者把
            # 「没看」读成「没问题」（2026-09-30 安全负责人指出：上一轮报过严重
            # 漏洞，本轮通告却写「问题清单为空」）。这里提前算好交给报告承接。
            prior_unverified: list[dict[str, Any]] = []
            try:
                prior_unverified = self._collect_prior_unverified(
                    archive_dir, detector_results)
            except Exception:  # noqa: BLE001
                prior_unverified = []

            ctx = ReportContext(
                target_name=target_name,
                primary_domain=domain,
                scan_time=datetime.fromtimestamp(t_start).strftime("%Y-%m-%d %H:%M:%S"),
                profile_name=self.profile.get("name", self.profile_name),
                features={k: v.state for k, v in tf.features.items()},
                dns=fp_result.get("dns", {}),
                root_probe=fp_result.get("root_probe", {}),
                authorization=auth,
                tools=self.tools.report_rows(),
                fallbacks=self.tools.fallback_notes(),
                checklist_meta=self.checklist.meta,
                authz_findings=authz_findings,
                verify_runs=verify_runs,
                business_notes=business_notes or [],
                item_results=detector_results,
                detector_summary=det_summary,
                detector_notes=detector_notes,
                external_backfill=external_backfill,
                submissions=detector_submissions,
                collection=collection,
                nuclei_run=nuclei_run,
                render=dict(fp_result.get("render") or {}),
                gate_result=gate_result,
                blocked_findings=blocked,
                coverage=coverage,
                boundary=self._boundary,
                boundary_guard=(guard.report if guard is not None else None),
                bypass_probes=list(self._bypass_probes),
                bypass_skip_reason=self._bypass_skip_reason,
                target_health_stop=self._target_health_stop,
                health_guard_off=self._health_guard_off,
                rate_ceiling_clamp=self._rate_ceiling_clamp,
                objectives=list(self._objectives),
                chains=list(self._chains),
                chain_notes=list(self._chain_notes),
                chain_closure=self._chain_closure,
                mode=self.mode,
                impact_cap=self._impact_cap,
                cred_ask=cred_ask,
                credhunt=(self.credhunt.to_dict() if self.credhunt else {}),
                credosint=(self.credosint.to_dict() if self.credosint else {}),
                prior_unverified=prior_unverified,
                # 声明这是本轮运行内存里的完整上下文：报告据此不写「降级渲染」
                # 横幅（真实运行里 credhunt 之类字段合法为空，不等于缺数据）。
                render_source="run",
            )
            # allow_archive_overwrite=True：本编排器就是这个归档目录的所有者
            # （目录是本轮开头 _make_archive_dir 建的），此刻的 ctx 是本轮跑出来
            # 的完整运行期上下文。其它任何调用方都不得就此目录调 generate() ——
            # 残缺上下文渲染会静默改写交付物，见 generator 里记的 2026-09-30 事故。
            reports = ReportGenerator(archive_dir).generate(
                ctx, fs, app, notice_full_repro=notice_full_repro,
                allow_archive_overwrite=True)
            st.status = "ok"
            st.detail = "已生成技术版、扫描通告、管理层摘要、结构化数据四份产出"
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}\n{traceback.format_exc()[:400]}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 阶段 8：复扫比对 ----------
        st = self._stage("L6 复扫比对")
        t0 = time.time()
        diff_md = ""
        try:
            pair = Differ.latest_pair(archive_dir.parent)
            if pair and pair[0] != pair[1]:
                # 把本轮的逐项结论喂进比对：本轮「未执行 / 待人工执行 / 待确认 /
                # 已跳过 / 弱证据 N/A」的项，不得因为「没再检出」被记成「已修复」。
                # 注意 检查项结论.json 是后面才落盘的，这里必须用内存里的结果。
                # ⚠ 必须走 `Differ.encode_item_states`：它会把弱证据 N/A 映射成
                # 独立的表示，与 `read_item_states`（归档路径）产出一致。
                # 自己写 `{r.item_id: r.state ...}` 会把弱 N/A 原样当「N/A」，
                # 于是一次「没看到」被计成「已修复」—— 给客户的假话。
                states = Differ.encode_item_states(detector_results)
                d = Differ().compare_files(*pair, item_states=states)
                diff_md = d.render_markdown()
                (archive_dir / "复扫比对报告.md").write_text(diff_md, encoding="utf-8")
                reports["diff"] = archive_dir / "复扫比对报告.md"
                self._last_diff = d          # 供周期化通知取「新增/已修复」数字
                s = d.summary()
                st.status = "ok"
                # 「重新归类」必须单列：它长得像「已修复」（上轮有、本轮无），
                # 但问题还在，只是换了上报出口。混进已修复就是假陈述。
                st.detail = (f"与上次扫描比对：新增 {s['新增']}、已修复 {s['已修复']}、"
                             f"仍存在 {s['仍存在']}、重新归类 {s.get('重新归类', 0)}"
                             + (f"、本轮未判定 {s['本轮未判定']}"
                                if s.get("本轮未判定") else ""))
            else:
                st.status = "skipped"
                st.detail = "无历史扫描结果可比对（首次扫描）"
        except Exception as e:  # noqa: BLE001
            st.status = "failed"
            st.error = f"{type(e).__name__}: {str(e)[:200]}"
        st.duration_ms = int((time.time() - t0) * 1000)
        self._pg_stage(st)

        # ---------- 收尾：凭据需求单落盘 ----------
        # 内容在阶段 7 之前就算好了（报告里要引用它），这里只负责写文件。
        if cred_ask:
            _p = _save_cred_needs(archive_dir, cred_ask)
            if _p:
                reports["cred_needs"] = _p

        # ---------- 收尾：落盘 ----------
        findings_path = fs.save(archive_dir / "findings.json")
        # 逐项结论单独落盘：这是「哪些真的测了、哪些没测」的唯一凭据，
        # 复扫比对与审计都依赖它。
        items_path = archive_dir / "检查项结论.json"
        try:
            items_path.write_text(json.dumps({
                "target": target_name,
                "domain": domain,
                "profile": self.profile.get("name", self.profile_name),
                "summary": det_summary,
                "notes": detector_notes,
                "items": [r.to_dict() for r in detector_results],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            reports["item_results"] = items_path
        except Exception as e:  # noqa: BLE001
            print(f"[警告] 检查项结论落盘失败：{type(e).__name__}: {e}", file=sys.stderr)

        self._save_run_manifest(archive_dir, target_name, domain, t_start, fs)
        reports["findings_json"] = findings_path
        if not skip_auth_check:
            self.ledger.mark_scanned(domain)
            self.ledger.save()

        return ScanResult(
            target_name=target_name, domain=domain, archive_dir=archive_dir,
            stages=self.stages, finding_set=fs, applicability=app,
            item_results=detector_results, detector_summary=det_summary,
            detector_notes=detector_notes, nuclei_run=nuclei_run,
            reports=reports, diff_markdown=diff_md, cred_ask=cred_ask,
        )

    # ==================================================================
    def _make_archive_dir(self, target_name: str) -> Path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_name)
        d = self.root / "outputs" / safe / ts
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _save_run_manifest(self, archive_dir: Path, name: str, domain: str,
                           t_start: float, fs: FindingSet) -> None:
        manifest = {
            "target": name,
            "domain": domain,
            "started_at": datetime.fromtimestamp(t_start).isoformat(timespec="seconds"),
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "duration_seconds": round(time.time() - t_start, 1),
            "profile": self.profile_name,
            "checklist_items": len(self.checklist),
            "stages": [s.to_dict() for s in self.stages],
            "counts": fs.counts(),
        }
        (archive_dir / "run-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @staticmethod
    def _guess_endpoints(fp_result: dict[str, Any], target_url: str) -> list[str]:
        """从探测结果里挑出值得做鉴权比对的接口候选。"""
        eps: list[str] = []
        for path, probe in (fp_result.get("path_probes") or {}).items():
            if not isinstance(probe, dict):
                continue
            if probe.get("status") in (200, 401, 403) and probe.get("reachable"):
                url = probe.get("final_url") or probe.get("url")
                if url:
                    eps.append(url)
        if not eps:
            eps = [target_url]
        return eps[:20]


if __name__ == "__main__":
    print("编排器自测（跳过授权检查，仅用于链路验证）")
    print("=" * 70)
    orch = Orchestrator()
    res = orch.scan(
        domain="example.com",
        target_name="链路自测目标",
        base_url="https://example.com",
        skip_auth_check=True,
    )
    print(f"\n归档目录：{res.archive_dir}")
    print(f"\n各阶段执行情况：")
    for s in res.stages:
        mark = {"ok": "✓", "failed": "✗", "skipped": "·"}.get(s.status, "?")
        print(f"  {mark} {s.name:<24} {s.duration_ms:>6}ms  {s.detail[:80]}")
        if s.error:
            print(f"      错误：{s.error[:160]}")
    if res.finding_set:
        print(f"\n发现统计：{res.finding_set.counts()}")
    print(f"\n产出文件：")
    for k, v in res.reports.items():
        print(f"  {k:<10} {v.name}")
