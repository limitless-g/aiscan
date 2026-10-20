"""红队模式：以「攻击目标」驱动的编排层。

与合规模式（全量检查项逐项检查）的根本区别在于**判定终点**：

    合规模式的终点是「有哪些漏洞」；
    红队模式的终点是「攻击目标是否达成」。

黑客攻击一个系统一定有目的 —— 拿到数据 / 修改数据 / 拿到控制权 ——
为达目的会穷尽手段。所以红队模式的判定单元不是「单项检查」，
而是「为某个目标尝试过哪些路径、走到哪一步、最终拿到什么」。

**这是扫描的默认视角**（`--mode compliance` 可显式切回合规视角）。
默认值定义见下方「扫描模式」一节，只定义一次。

=====================================================================
三态判定：必须严格分开，任何一处混淆都是假结论（不可违反）
=====================================================================

    已达成    —— 至少一条路径的终点被**实测证明**（有可复现的证据）
    未达成    —— 所有路径都跑完，且每一条都有明确的失败证据
    未能验证  —— 存在路径因缺少条件（无账号 / 被拦截 / 超时 / 授权不足）
                 没跑成

两个铁律：

  1. **「未达成」必须附带已尝试的手段清单**。没有 attempted 的「未达成」
     与「没测」在报告里长得一模一样 —— 那是最坏的一类假结论：
     读报告的人会以为「试过了，打不穿」，实际是「根本没试」。

  2. **未授权的目标不得执行，且不得记为「未达成」**。未纳入本次执行范围的目标，
     结果是「未能验证（未授权，未执行）」，明确告诉读者这是没测，不是打不穿。

  2b. **「为什么没做」的原因必须归对档位**。一个目标没进执行范围有两种完全不同的
     成因，混淆的代价是把读者引向怀疑扫描的合法性：

        档位默认不含 —— 如 standard 档 `objectives: [READ_DATA, MODIFY_DATA]`，
                        不含 TAKE_CONTROL。这是**扫描强度设定**，与被扫目标
                        是否获得授权**毫无关系**。
        台账未登记   —— 档位默认含、但授权台账对该目标只放行了更窄的范围。
                        这是**授权范围**问题，需要补授权。

     两者在报告里都必须说清是哪一个。2026-09-29 发现原实现把两者一律写成
     「该攻击目标未在授权台账登记」—— 而 internal-app.example.com 明明已在台账
     登记（安全负责人授权 2026-09-21），只是 standard 档默认不含 TAKE_CONTROL。
     那句话会让读者以为该目标没有授权。**归因错误与结论错误同等严重。**

=====================================================================
影响级别与 L3 硬约束
=====================================================================

    L1 证明可达 —— 证明「能到达」：命令执行返回无害系统信息，数据只读一条
    L2 证明影响 —— 读系统文件 / 写无害标记文件（写后必须恢复）
    L3 完整利用 —— 执行命令并取回输出，证明完整控制

L3 是本次授权允许的最高级别，但它带来的硬约束**不是靠运行时拦截实现的**，
而是靠「这类步骤在注册表里根本不存在」实现的：

    - 禁止持久化：没有任何步骤会写后门 / 计划任务 / 账号 —— 不提供该能力
    - 禁止横向移动：没有任何步骤会访问目标之外的资产 —— 不提供该能力

运行时拦截可以被绕过、被改配置；能力不存在则绕不过去。
新增 L3 步骤时，只允许「取回一次输出即终止」的形态。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

# ======================================================================
# 攻击目标
# ======================================================================

OBJ_READ_DATA = "READ_DATA"
OBJ_MODIFY_DATA = "MODIFY_DATA"
OBJ_TAKE_CONTROL = "TAKE_CONTROL"

OBJECTIVES: dict[str, str] = {
    OBJ_READ_DATA: "拿到数据",
    OBJ_MODIFY_DATA: "修改数据",
    OBJ_TAKE_CONTROL: "拿到控制权",
}
OBJECTIVE_ORDER = [OBJ_READ_DATA, OBJ_MODIFY_DATA, OBJ_TAKE_CONTROL]

# ======================================================================
# 扫描模式（单一事实来源，默认值只在这里定义一次）
# ======================================================================

# MODE_REDTEAM —— 黑客运维视角，**默认模式**。判定单元是「攻击目标是否达成」：
#     黑客攻击一定有目的（拿数据 / 改数据 / 拿控制权），为达目的穷尽手段。
#     合规模式的全量检查项逐项记录照旧全跑全报 —— 红队是叠加层，不是替代。
#
# MODE_COMPLIANCE —— 合规检查项视角，终点是「有哪些漏洞」。
#     仅在明确要求「只出合规清单」时使用（--mode compliance 显式切回）。
#
# 为什么默认是黑客运维：2026-09-21 明确要求「默认使用黑客运维视角进行扫描，
# 除非特殊说明」。合规模式保留，因为全量检查项逐项结论本身仍是交付物。
#
# ⚠️ 默认值只在这一处定义。命令行 argparse default、orchestrator.scan() 的
# 签名默认值都从这里取 —— 否则某天只改一处，就会出现「命令行说红队、
# 引擎跑合规」这种最难受的静默不一致。

MODE_COMPLIANCE = "compliance"
MODE_REDTEAM = "redteam"
SCAN_MODES = (MODE_COMPLIANCE, MODE_REDTEAM)

DEFAULT_MODE = MODE_REDTEAM

MODE_LABEL = {
    MODE_COMPLIANCE: "合规检查项视角",
    MODE_REDTEAM: "黑客运维视角",
}

# ======================================================================
# 影响级别
# ======================================================================

IMPACT_L1 = "L1"
IMPACT_L2 = "L2"
IMPACT_L3 = "L3"

IMPACT_ORDER = {IMPACT_L1: 0, IMPACT_L2: 1, IMPACT_L3: 2}
IMPACT_LABEL = {IMPACT_L1: "证明可达", IMPACT_L2: "证明影响", IMPACT_L3: "完整利用"}

# L3 允许的动作形态（白名单，写死在这里供审计）
L3_ALLOWED_ACTIONS = [
    "执行一次无害命令并取回输出（如 whoami / id 等等价物）",
    "读取单个系统文件的一行内容",
]
L3_FORBIDDEN_ACTIONS = [
    "写后门 / 计划任务 / 新建账号（持久化）",
    "访问目标之外的任何资产（横向移动）",
    "修改或删除目标上的真实数据",
    "批量导出数据（只允许读取一条作为存在性证明）",
]

# ======================================================================
# 结论三态
# ======================================================================

PROVEN = "已达成"
NOT_PROVEN = "未达成"
INCONCLUSIVE = "未能验证"

# ======================================================================
# 步骤类型
# ======================================================================

KIND_DETECT = "detect"   # 复用现有检测器的判断：入口/现象是否存在
KIND_PROVE = "prove"     # 结果证明：证明目标真的达成
KIND_ACT = "act"         # 有副作用的动作，须 deep 档 + 显式授权


# ======================================================================
# 数据结构
# ======================================================================


@dataclass
class StepOutcome:
    """一步的执行结论。"""

    step_id: str = ""
    name: str = ""
    result: str = INCONCLUSIVE
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    probes: int = 0
    impact: str = IMPACT_L1
    elapsed_ms: int = 0
    skipped: str = ""        # 非空表示这一步根本没执行，值是原因

    @property
    def ran(self) -> bool:
        return not self.skipped

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "result": self.result,
            "impact": self.impact,
            "impact_label": IMPACT_LABEL.get(self.impact, self.impact),
            "detail": self.detail,
            "evidence": list(self.evidence),
            "probes": self.probes,
            "elapsed_ms": self.elapsed_ms,
            "skipped": self.skipped,
        }


@dataclass
class AttackStep:
    """攻击路径上的一步。

    needs 表达步骤间的因果：「A 的输出是 B 的输入」。
    前置步骤没有证明成功时，本步结果记「未能验证」而不是「未达成」——
    因为本步根本没机会执行。
    """

    step_id: str
    name: str
    objective: str
    kind: str = KIND_DETECT
    impact: str = IMPACT_L1
    requires: list[str] = field(default_factory=list)   # accounts / write
    needs: list[str] = field(default_factory=list)      # 前置步骤 id
    run: Callable[..., StepOutcome] | None = None
    rationale: str = ""


@dataclass
class AttackPath:
    """达成某个攻击目标的一条路径。"""

    path_id: str
    objective: str
    name: str
    steps: list[AttackStep] = field(default_factory=list)
    rationale: str = ""


@dataclass
class PathOutcome:
    """一条路径的执行结论。"""

    path_id: str = ""
    objective: str = ""
    name: str = ""
    result: str = INCONCLUSIVE
    steps: list[StepOutcome] = field(default_factory=list)
    stopped_at: str = ""
    reason: str = ""

    @property
    def chain_text(self) -> str:
        """把路径渲染成「手段 → 手段 → 结果」的可读链条。"""
        if not self.steps:
            return self.name
        return " → ".join(
            f"{s.name}({s.result})" if s.ran else f"{s.name}(未执行)"
            for s in self.steps
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "objective": self.objective,
            "name": self.name,
            "result": self.result,
            "chain": self.chain_text,
            "stopped_at": self.stopped_at,
            "reason": self.reason,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class ObjectiveOutcome:
    """一个攻击目标的最终结论。报告首屏直接渲染它。"""

    objective: str = ""
    label: str = ""
    result: str = INCONCLUSIVE
    paths: list[PathOutcome] = field(default_factory=list)
    authorized: bool = True
    # 未执行的原因归属（见模块头 铁律 2b）。取值：
    #   ""        —— 在范围内，正常执行（或本模块自测直接传 scope 的场合）
    #   "profile" —— 本档位默认不含该攻击目标（扫描强度设定，与授权无关）
    #   "ledger"  —— 档位含、但授权台账未放行该攻击目标（授权范围问题）
    # 报告据此选择措辞。**不得**再用 authorized 一个布尔量兼表两种成因。
    scope_kind: str = ""
    reason: str = ""
    # ---- 结论证据可以来自两条不同的通道（必须能区分）----
    # paths      ：本模块注册的攻击路径，逐步实测。
    # chain_note ：攻击链组合（engine/attackchain.py）的结论 —— 该目标没有独立
    #              攻击路径（能力缺口），但某条链的链尾能力**已被单点实测证明**。
    # 两者都必须基于实测；但来源不同，报告里要分别标明，否则读者无法判断
    # 「已达成」到底是打出来的还是组合出来的。
    chain_note: str = ""
    chain_evidence: list[str] = field(default_factory=list)

    def attempted(self) -> list[str]:
        """已尝试的手段清单。

        「未达成」结论必须附带它 —— 否则与「没测」无法区分。
        """
        out: list[str] = []
        for p in self.paths:
            for s in p.steps:
                if s.skipped:
                    out.append(f"{p.name} → {s.name}：未执行（{s.skipped}）")
                else:
                    out.append(f"{p.name} → {s.name}：{s.result}"
                               + (f"（{s.detail}）" if s.detail else ""))
        return out

    def evidence_chain(self) -> list[str]:
        """达成结论对应的证据链（只取真正证明成功的步骤）。"""
        out: list[str] = []
        for p in self.paths:
            if p.result != PROVEN:
                continue
            for s in p.steps:
                if s.result == PROVEN:
                    out.append(f"[{p.name}] {s.name}：{s.detail}")
                    out.extend(f"    证据：{e}" for e in s.evidence[:3])
        # 攻击链通道的证据同样要露出来 —— 否则首屏写「已达成」，
        # 证据链却空白，读者只能当它是无据结论。
        out.extend(self.chain_evidence)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "label": self.label,
            "result": self.result,
            "authorized": self.authorized,
            "scope_kind": self.scope_kind,
            "reason": self.reason,
            "chain_note": self.chain_note,
            "attempted": self.attempted(),
            "evidence_chain": self.evidence_chain(),
            "paths": [p.to_dict() for p in self.paths],
        }


# ======================================================================
# 路径注册表
# ======================================================================

_PATH_REGISTRY: list[AttackPath] = []


def register_path(path: AttackPath) -> AttackPath:
    """登记一条攻击路径。"""
    _PATH_REGISTRY.append(path)
    return path


def registered_paths() -> list[AttackPath]:
    return list(_PATH_REGISTRY)


def build_paths() -> list[AttackPath]:
    """构造全部攻击路径。

    延迟导入 proofs，避免循环依赖（proofs 需要本模块的数据类）。
    """
    if not _PATH_REGISTRY:
        from engine import proofs  # noqa: F401  导入即注册
    return registered_paths()


# ======================================================================
# 执行器
# ======================================================================


class AttackPlanner:
    """按攻击目标编排并执行攻击路径。"""

    def __init__(
        self,
        ctx: Any,
        scope: list[str] | None = None,
        impact_level: str = IMPACT_L2,
        paths: list[AttackPath] | None = None,
        profile_objectives: list[str] | None = None,
        ledger_objectives: list[str] | None = None,
        profile_name: str = "",
    ):
        self.ctx = ctx
        self.scope = set(scope) if scope else set()
        self.impact_level = impact_level if impact_level in IMPACT_ORDER else IMPACT_L2
        self.paths = paths if paths is not None else build_paths()
        self.steps_run = 0
        self.steps_skipped = 0
        # 未进 scope 的归因材料（见模块头 铁律 2b）。
        # profile_objectives = 档位默认允许的目标；ledger_objectives = 台账放行的目标。
        # 两者都不传时归因退化为「未纳入本次执行范围」，不会瞎猜成「台账未登记」。
        self.profile_objectives = list(profile_objectives or [])
        self.ledger_objectives = list(ledger_objectives or [])
        self.profile_name = profile_name or ""

    # ------------------------------------------------------------------
    def _out_of_scope_kind(self, obj: str) -> str:
        """未进执行范围的成因：``"profile"`` / ``"ledger"`` / ``""``（无从判断）。

        **判不出来时返回空串，不猜。** 给一个可能错的具体归因，比说
        「本次无法归因」有害得多 —— 读者会照着错的那句话去改授权。
        """
        if not self.profile_objectives:
            return ""
        return "profile" if obj not in self.profile_objectives else "ledger"

    def _out_of_scope_reason(self, obj: str) -> str:
        """说清「这个目标为什么没做」—— 档位不覆盖 ≠ 台账没授权。

        两者必须分开说。把它们混成一句话，读者会顺着「台账」二字去怀疑
        扫描的合法性 —— 而归因错误的杀伤力与结论错误相同。
        """
        label = OBJECTIVES.get(obj, obj)
        kind = self._out_of_scope_kind(obj)
        if kind == "profile":
            where = f"本档位（{self.profile_name}）" if self.profile_name else "本档位"
            return (f"{where}**默认不含**该攻击目标（{label}）—— 这是**扫描档位"
                    "的强度设定**，**与目标是否获得授权无关**。**未执行任何尝试**："
                    "这不是「未达成」，是「没测」。需换用更高档位"
                    "（deep 档含全部三个攻击目标）后重扫。")
        if kind == "ledger":
            led = "、".join(OBJECTIVES.get(o, o) for o in self.ledger_objectives)
            return (f"该攻击目标（{label}）**未在授权台账登记**"
                    f"（台账对该目标放行的攻击目标为：{led or '（空）'}）—— "
                    "**未执行任何尝试**。这不是「未达成」，是「没测」；"
                    "需在授权台账扩展该目标的授权范围后重扫。")
        # 归因材料缺失 —— 只说事实，不给可能错误的具体归因。
        return (f"该攻击目标（{label}）**未纳入本次执行范围** —— "
                "**未执行任何尝试**。这不是「未达成」，是「没测」。"
                "（本次未同时拿到档位目标清单与台账目标清单，"
                "**无法判断**是档位设定还是授权范围所致，故不作具体归因。）")

    # ------------------------------------------------------------------
    def run(self) -> list[ObjectiveOutcome]:
        out: list[ObjectiveOutcome] = []
        for obj in OBJECTIVE_ORDER:
            paths = [p for p in self.paths if p.objective == obj]
            oc = ObjectiveOutcome(objective=obj, label=OBJECTIVES.get(obj, obj))

            # 没有任何已实现的攻击路径 —— 这必须**显式产出结论**，
            # 不能静默跳过。静默跳过的后果是：报告里根本不出现这个目标，
            # 读者会把「我们还没有这个能力」读成「这个目标没问题」。
            if not paths:
                oc.result = INCONCLUSIVE
                oc.reason = ("本次未实现该攻击目标的任何攻击路径 —— "
                             "这是**能力缺口**，不代表该目标打不穿。")
                out.append(oc)
                continue

            if self.scope and obj not in self.scope:
                # 未纳入执行范围 → 明确告诉读者这是「没测」，不是「打不穿」，
                # 并且说清是**档位**还是**台账**造成的（铁律 2b）。
                oc.authorized = False
                oc.result = INCONCLUSIVE
                oc.scope_kind = self._out_of_scope_kind(obj)
                oc.reason = self._out_of_scope_reason(obj)
                out.append(oc)
                continue
            for p in paths:
                oc.paths.append(self._run_path(p))
            oc.result = self._aggregate(oc.paths)
            oc.reason = self._reason(oc)
            out.append(oc)
        return out

    # ------------------------------------------------------------------
    def _run_path(self, path: AttackPath) -> PathOutcome:
        po = PathOutcome(path_id=path.path_id, objective=path.objective, name=path.name)
        done: set[str] = set()
        for step in path.steps:
            so = self._run_step(step, done)
            po.steps.append(so)
            if so.result == PROVEN:
                done.add(step.step_id)
                continue
            # 本步没能证明成功 → 本条路径到此为止。
            # 是「未达成」还是「未能验证」由 so.result 决定，不可混淆。
            po.stopped_at = step.step_id
            po.result = so.result
            po.reason = so.skipped or so.detail or "该步骤未取得预期结果"
            return po
        po.result = PROVEN
        po.reason = "路径全部步骤均已实测通过"
        return po

    # ------------------------------------------------------------------
    def _run_step(self, step: AttackStep, done: set[str]) -> StepOutcome:
        so = StepOutcome(step_id=step.step_id, name=step.name, impact=step.impact)

        # 1) 前置因果：上一环没证明成功，本环就没机会执行 → 未能验证
        missing = [n for n in step.needs if n not in done]
        if missing:
            so.skipped = f"前置步骤未成立：{'、'.join(missing)}"
            so.result = INCONCLUSIVE
            self.steps_skipped += 1
            return so

        # 2) 影响级别门控：超授权上限一律不执行
        if IMPACT_ORDER.get(step.impact, 0) > IMPACT_ORDER.get(self.impact_level, 1):
            so.skipped = (f"影响级别 {step.impact}（{IMPACT_LABEL.get(step.impact, '')}）"
                          f"超出本次授权上限 {self.impact_level}"
                          f"（{IMPACT_LABEL.get(self.impact_level, '')}）")
            so.result = INCONCLUSIVE
            self.steps_skipped += 1
            return so

        # 3) 能力依赖门控
        if "accounts" in step.requires and not getattr(self.ctx, "accounts", None):
            so.skipped = "缺少多账号配置（--accounts），无法执行"
            so.result = INCONCLUSIVE
            self.steps_skipped += 1
            return so
        if "write" in step.requires and not getattr(self.ctx, "allow_write", False):
            so.skipped = ("未获得写操作授权（需 `ledger --allow-write` 显式登记；"
                          "档位选 deep 本身不等于授权写）")
            so.result = INCONCLUSIVE
            self.steps_skipped += 1
            return so

        # 4) 执行
        if step.run is None:
            so.skipped = "该步骤未绑定执行体"
            so.result = INCONCLUSIVE
            self.steps_skipped += 1
            return so

        t0 = time.time()
        try:
            got = step.run(self.ctx)
        except Exception as e:  # noqa: BLE001
            so.result = INCONCLUSIVE
            so.detail = f"执行异常：{type(e).__name__}: {str(e)[:120]}"
            so.elapsed_ms = int((time.time() - t0) * 1000)
            return so

        got.step_id = step.step_id
        got.name = step.name
        got.impact = step.impact
        got.elapsed_ms = int((time.time() - t0) * 1000)
        self.steps_run += 1
        return got

    # ------------------------------------------------------------------
    @staticmethod
    def _aggregate(paths: list[PathOutcome]) -> str:
        """聚合路径结论。

        只要有一条走通就是「已达成」；否则只要还有路径没验证成
        （而非明确失败），整体就只能停在「未能验证」—— 不能宣称「未达成」。
        """
        if any(p.result == PROVEN for p in paths):
            return PROVEN
        if any(p.result == INCONCLUSIVE for p in paths):
            return INCONCLUSIVE
        return NOT_PROVEN

    @staticmethod
    def _reason(oc: ObjectiveOutcome) -> str:
        if oc.result == PROVEN:
            return "已实测证明可达该目标，证据链见下。"
        if oc.result == NOT_PROVEN:
            return ("已尝试全部已知路径，每一条都有明确的失败证据。"
                    "注意：这只说明**已尝试的手段**未能达成，"
                    "不代表目标绝对安全。")
        return ("存在未跑完的路径，条件不足以下结论。"
                "未完成原因逐条列在尝试记录中。")

    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        return {
            "impact_level": self.impact_level,
            "scope": sorted(self.scope),
            "steps_run": self.steps_run,
            "steps_skipped": self.steps_skipped,
        }


# ======================================================================
# 渲染辅助
# ======================================================================


def render_matrix(outcomes: list[ObjectiveOutcome]) -> list[str]:
    """红队模式报告首屏：攻击目标达成情况表。"""
    lines = ["| 攻击目标 | 结论 | 说明 |", "|---|---|---|"]
    for oc in outcomes:
        mark = {PROVEN: "⚠ 已达成", NOT_PROVEN: "未达成",
                INCONCLUSIVE: "未能验证"}.get(oc.result, oc.result)
        note = oc.reason
        if not oc.authorized:
            # 未执行的成因必须说清是「档位设定」还是「授权范围」（铁律 2b）——
            # 一律写「未授权」会把档位问题误导成授权问题。
            note = {"profile": "本档位不含该目标，未执行（档位强度设定，与授权无关）",
                    "ledger": "未授权，未执行（需在授权台账扩展该目标）",
                    }.get(oc.scope_kind, "未纳入本次执行范围，未执行")
        lines.append(f"| {oc.label} | {mark} | {note} |")
    return lines


def _selftest() -> int:
    """离线自测：三态判定与门控规则。"""
    from dataclasses import dataclass as _dc

    @_dc
    class _Ctx:
        accounts: list = None
        allow_write: bool = False

    problems: list[str] = []

    def _step(sid, name, result=None, skipped="", needs=None, impact=IMPACT_L1,
              requires=None):
        def _run(ctx):
            return StepOutcome(result=result, detail="实测", skipped=skipped)
        return AttackStep(step_id=sid, name=name, objective=OBJ_READ_DATA,
                          needs=needs or [], impact=impact,
                          requires=requires or [], run=_run)

    # 1) 单路径走通 → 已达成
    p = AttackPath("p1", OBJ_READ_DATA, "路径一",
                   [_step("s1", "第一步", PROVEN), _step("s2", "第二步", PROVEN, needs=["s1"])])
    oc = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], paths=[p]).run()[0]
    if oc.result != PROVEN:
        problems.append(f"路径走通应判已达成，实际 {oc.result}")

    # 2) 全部路径明确失败 → 未达成
    p2 = AttackPath("p2", OBJ_READ_DATA, "路径二", [_step("s1", "第一步", NOT_PROVEN)])
    oc2 = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], paths=[p2]).run()[0]
    if oc2.result != NOT_PROVEN:
        problems.append(f"全部明确失败应判未达成，实际 {oc2.result}")
    if not oc2.attempted():
        problems.append("「未达成」必须附带已尝试手段清单，实际为空")

    # 3) 有一条路径未能验证 → 整体只能到未能验证
    p3 = AttackPath("p3", OBJ_READ_DATA, "路径三", [_step("s2", "第二步", needs=["s1"])])
    oc3 = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], paths=[p2, p3]).run()[0]
    if oc3.result != INCONCLUSIVE:
        problems.append(f"含未验证路径时应判未能验证，实际 {oc3.result}")

    # 4) 未授权目标不得执行，也不得记未达成
    oc4 = AttackPlanner(_Ctx(), scope=[OBJ_TAKE_CONTROL], paths=[p]).run()
    rd = [o for o in oc4 if o.objective == OBJ_READ_DATA]
    if rd and (rd[0].authorized or rd[0].result == NOT_PROVEN or rd[0].paths):
        problems.append("未授权目标必须判未能验证且不得执行任何路径")

    # 4b) 归因必须分清「档位默认不含」与「台账未登记」（铁律 2b）。
    #     2026-09-29 的实际缺陷：standard 档 objectives 不含 TAKE_CONTROL，
    #     但原因被写成「该攻击目标未在授权台账登记」—— 而目标准确登记在台账里，
    #     那句话会让读者以为它没获授权。
    def _step_tc(sid, name, result):
        def _run(ctx):
            return StepOutcome(result=result, detail="实测")
        return AttackStep(step_id=sid, name=name, objective=OBJ_TAKE_CONTROL,
                          run=_run)

    _p_tc = AttackPath("p_tc", OBJ_TAKE_CONTROL, "控制权路径",
                       [_step_tc("s_tc", "控制权步", PROVEN)])

    def _tc_of(objs):
        return [o for o in objs if o.objective == OBJ_TAKE_CONTROL][0]

    # 4b-1 档位默认不含 → 归因 profile，且**不得**出现「授权台账」字样
    _t1 = _tc_of(AttackPlanner(
        _Ctx(), scope=[OBJ_READ_DATA, OBJ_MODIFY_DATA],
        profile_objectives=[OBJ_READ_DATA, OBJ_MODIFY_DATA],
        ledger_objectives=[], profile_name="标准档",
        paths=[_p_tc]).run())
    if _t1.scope_kind != "profile":
        problems.append(f"档位不含该目标应归因 profile，实际 {_t1.scope_kind!r}")
    if "授权台账" in _t1.reason:
        problems.append(f"档位不含时原因不得写成「未在授权台账登记」（误导为未授权）："
                        f"{_t1.reason}")
    if "档位" not in _t1.reason:
        problems.append(f"档位不含时原因必须点名档位设定：{_t1.reason}")

    # 4b-2 档位含、台账不放行 → 归因 ledger，且必须说出台账放行了什么
    _t2 = _tc_of(AttackPlanner(
        _Ctx(), scope=[OBJ_READ_DATA],
        profile_objectives=[OBJ_READ_DATA, OBJ_MODIFY_DATA, OBJ_TAKE_CONTROL],
        ledger_objectives=[OBJ_READ_DATA], profile_name="深度档",
        paths=[_p_tc]).run())
    if _t2.scope_kind != "ledger":
        problems.append(f"台账不放行应归因 ledger，实际 {_t2.scope_kind!r}")
    if "未在授权台账登记" not in _t2.reason:
        problems.append(f"台账不放行时原因必须点名台账：{_t2.reason}")
    if "拿到数据" not in _t2.reason:
        problems.append(f"台账不放行时必须列出台账实际放行了什么：{_t2.reason}")

    # 4b-3 归因材料缺失 → **不猜**：不得凭空给出「台账未登记」这种具体归因
    _t3 = _tc_of(AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA],
                               paths=[_p_tc]).run())
    if _t3.scope_kind:
        problems.append(f"未提供档位目标清单时不得归因，实际 {_t3.scope_kind!r}")
    if "授权台账" in _t3.reason:
        problems.append(f"无从归因时不得凭空指向台账：{_t3.reason}")
    if "未纳入本次执行范围" not in _t3.reason:
        problems.append(f"无从归因时必须只陈述事实：{_t3.reason}")

    # 5) 影响级别门控：L3 步骤在 L2 授权下不执行
    p5 = AttackPath("p5", OBJ_READ_DATA, "路径五",
                    [_step("s3", "完整利用步", PROVEN, impact=IMPACT_L3)])
    oc5 = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], impact_level=IMPACT_L2,
                        paths=[p5]).run()[0]
    if oc5.paths[0].steps[0].ran:
        problems.append("L3 步骤在 L2 授权下不得执行")
    if oc5.result != INCONCLUSIVE:
        problems.append(f"被授权上限拦下应判未能验证，实际 {oc5.result}")

    # 6) 缺少账号 / 写授权时不得执行
    p6 = AttackPath("p6", OBJ_READ_DATA, "路径六",
                    [_step("s4", "越权步", PROVEN, requires=["accounts"])])
    oc6 = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], paths=[p6]).run()[0]
    if oc6.paths[0].steps[0].ran:
        problems.append("缺少多账号配置时越权步不得执行")

    # 7) 未绑定执行体的步骤不得被当成通过
    p7 = AttackPath("p7", OBJ_READ_DATA, "路径七",
                    [AttackStep(step_id="s9", name="空步", objective=OBJ_READ_DATA)])
    oc7 = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], paths=[p7]).run()[0]
    if oc7.result == PROVEN:
        problems.append("未绑定执行体的步骤不得判通过")

    # 8) 未实现攻击路径的目标必须显式产出「能力缺口」结论，不得静默跳过。
    #    静默跳过会让报告里根本不出现这个目标 —— 读者会把「我们还没做过」
    #    读成「这个目标没问题」。
    p8 = AttackPath("p8", OBJ_READ_DATA, "路径八", [_step("s1", "步", PROVEN)])
    oc8 = AttackPlanner(_Ctx(), scope=[OBJ_READ_DATA], paths=[p8]).run()
    labs8 = {o.objective: o for o in oc8}
    if OBJ_TAKE_CONTROL not in labs8:
        problems.append("未实现路径的目标必须显式产出结论，不得静默跳过")
    elif labs8[OBJ_TAKE_CONTROL].result != INCONCLUSIVE:
        problems.append("未实现路径的目标结论应为「未能验证」（能力缺口）")

    # 9) 攻击链通道的证据必须出现在证据链里，且来源必须可区分。
    #    首屏写「已达成」而证据链一片空白，读者只能把它当成无据结论；
    #    「路径实测」与「组合证明」来源不同，报告必须能分别标明。
    oc9 = ObjectiveOutcome(objective=OBJ_READ_DATA, label="拿到数据",
                           result=PROVEN, chain_note="由攻击链组合证明")
    oc9.chain_evidence = ["[攻击链] 未授权接口：实测取回 100 条记录"]
    if not oc9.evidence_chain():
        problems.append("攻击链通道的证据必须出现在证据链里（否则「已达成」无据）")
    if "chain_note" not in oc9.to_dict():
        problems.append("序列化必须带 chain_note，否则报告无法标明结论来源")

    if problems:
        print("红队编排自测失败：")
        for x in problems:
            print("  -", x)
        return 1

    print("红队编排自测通过（10 项）：")
    print("  ✓ 单路径走通判「已达成」")
    print("  ✓ 全部路径明确失败判「未达成」，且强制附带已尝试手段")
    print("  ✓ 含未验证路径时整体降为「未能验证」")
    print("  ✓ 未授权目标不执行任何路径，且不记为「未达成」")
    print("  ✓ 未执行的成因分清「档位默认不含」与「台账未登记」；"
          "归因材料不足时只说事实、不瞎猜")
    print("  ✓ L3 步骤在 L2 授权下被拦，判「未能验证」")
    print("  ✓ 缺账号 / 缺写授权时对应步骤不执行")
    print("  ✓ 未绑定执行体的步骤不得判通过")
    print("  ✓ 未实现路径的目标显式产出「能力缺口」，不静默跳过")
    print("  ✓ 攻击链通道的证据进入证据链，结论来源可区分")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_selftest())
