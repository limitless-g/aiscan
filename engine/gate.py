# -*- coding: utf-8 -*-
"""
发现准入闸门 —— 未经复现验证的发现，不得进入漏洞清单
=====================================================

这是与「清单侧执行状态机」对称的另一半：

    清单侧状态机：没执行的检查项，不许报「通过」（防假阴性）
    发现侧准入闸门：没复现的发现，不许进「漏洞清单」（防假阳性 / 防不可复测）

为什么必须有这道闸门
--------------------
报告里写着「每项均附可独立执行的复现脚本」，但实测 37 条发现有 37 条
verify_script / verify_result 全为空 —— 复现环节在自测路径上根本没跑。
更早的版本里，复现脚本跑出「未复现」的发现照样进漏洞清单。

结果是：报告交出去，对方照着复现步骤走一遍，发现复不上 —— 报告的可信度
就一次性耗光了。所以必须在报告生成之前设闸：

    有脚本 + 已执行 + 复现成功  → 漏洞清单（可复测）
    有脚本 + 已执行 + 未复现    → 证伪记录（仍披露，但不计入漏洞）
    有脚本 + 已执行 + 无法判定  → 待人工复现（单列）
    无脚本 / 未执行             → 未验证（单列，明确写「没验」）

关键：**证伪与未验证的发现仍然出现在报告里**，只是不计入漏洞数。
闸门的作用是「分类」而不是「隐藏」—— 隐藏会变成漏报，
而把没验的混进漏洞清单则会变成不可复测的假报告。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Finding  # noqa: E402

# ---- 判定值 ----
VERDICT_REPORTABLE = "已复现"        # 进漏洞清单
VERDICT_REFUTED = "未复现"           # 进证伪记录
VERDICT_INCONCLUSIVE = "无法判定"    # 进待人工复现清单
VERDICT_UNVERIFIED = "未验证"        # 进未验证清单

ALL_VERDICTS = (VERDICT_REPORTABLE, VERDICT_REFUTED, VERDICT_INCONCLUSIVE,
                VERDICT_UNVERIFIED)

# 复现强度
STRENGTH_STRONG = "strong"
STRENGTH_MEDIUM = "medium"
STRENGTH_WEAK = "weak"

STRENGTH_LABEL = {
    STRENGTH_STRONG: "强",
    STRENGTH_MEDIUM: "中",
    STRENGTH_WEAK: "弱",
}

# 退出码 → 判定值。与 verify 脚本的约定一致：0=复现成功 / 1=未复现 / 2=无法判定
EXIT_CODE_VERDICT = {0: VERDICT_REPORTABLE, 1: VERDICT_REFUTED, 2: VERDICT_INCONCLUSIVE}


@dataclass
class GateDecision:
    """单条发现的准入判定。"""

    finding: Finding
    verdict: str
    reason: str = ""
    strength: str = ""
    script: str = ""
    exit_code: int | None = None
    duration_ms: int = 0

    @property
    def item_id(self) -> str:
        return self.finding.item_id

    @property
    def title(self) -> str:
        return self.finding.title

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "title": self.title,
            "severity": self.finding.severity,
            "endpoint": self.finding.endpoint,
            "verdict": self.verdict,
            "reason": self.reason,
            "strength": self.strength,
            "strength_label": STRENGTH_LABEL.get(self.strength, "未标注"),
            "repro_kind": (self.finding.extra or {}).get("repro_kind", ""),
            "script": self.script,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }


@dataclass
class GateResult:
    """一次扫描的全部准入判定。"""

    decisions: list[GateDecision] = field(default_factory=list)
    verify_ran: bool = False         # 复现验证环节是否真的执行过
    verify_note: str = ""

    # ---- 分类取用 ----
    def by_verdict(self, verdict: str) -> list[GateDecision]:
        return [d for d in self.decisions if d.verdict == verdict]

    @property
    def reportable(self) -> list[GateDecision]:
        """可进入漏洞清单的发现（已复现）。"""
        return self.by_verdict(VERDICT_REPORTABLE)

    @property
    def refuted(self) -> list[GateDecision]:
        return self.by_verdict(VERDICT_REFUTED)

    @property
    def inconclusive(self) -> list[GateDecision]:
        return self.by_verdict(VERDICT_INCONCLUSIVE)

    @property
    def unverified(self) -> list[GateDecision]:
        return self.by_verdict(VERDICT_UNVERIFIED)

    def reportable_findings(self) -> list[Finding]:
        """真正能写进漏洞清单的 Finding 列表，按严重度排序。"""
        return [d.finding for d in self.reportable]

    # ---- 统计 ----
    def stats(self) -> dict[str, Any]:
        total = len(self.decisions)
        rep = len(self.reportable)
        strong = [d for d in self.reportable if d.strength == STRENGTH_STRONG]
        weak = [d for d in self.reportable if d.strength == STRENGTH_WEAK]
        return {
            "发现总数": total,
            "已复现": rep,
            "未复现": len(self.refuted),
            "无法判定": len(self.inconclusive),
            "未验证": len(self.unverified),
            # 可复测率：漏洞清单里的都经独立脚本复现成功
            "可复测率": (rep / total) if total else 0.0,
            "强复现": len(strong),
            "弱复现": len(weak),
            "验证环节已执行": self.verify_ran,
        }

    def gate_summary(self) -> str:
        s = self.stats()
        return (f"发现 {s['发现总数']} 条：已复现 {s['已复现']}、未复现 {s['未复现']}、"
                f"无法判定 {s['无法判定']}、未验证 {s['未验证']}")

    def summary_markdown(self) -> str:
        """供报告渲染的闸门说明段。"""
        s = self.stats()
        L: list[str] = []
        L.append("**准入闸门（未经复现的发现不进漏洞清单）**")
        L.append("")
        if not self.verify_ran:
            L.append("> ⚠ **本次未执行复现验证环节** —— 下方漏洞清单中的发现"
                     "均**未经独立脚本复现**，其可复测性未经验证。")
            L.append("")
        L.append("| 判定 | 数量 | 含义 |")
        L.append("| --- | --- | --- |")
        L.append(f"| 已复现 | {s['已复现']} | 独立脚本执行后复现成功，**计入漏洞清单** |")
        L.append(f"| 未复现 | {s['未复现']} | 脚本执行但未能复现（可能已修复，也可能判据差异），"
                 "见本节末尾「证伪记录」 |")
        L.append(f"| 无法判定 | {s['无法判定']} | 脚本能跑但不足以判定（覆盖面不足 / 缺断言），"
                 "见本节末尾「待人工复现」 |")
        L.append(f"| 未验证 | {s['未验证']} | 未生成或未执行复现脚本，见本节末尾「未验证清单」 |")
        L.append("")
        if s["弱复现"]:
            L.append(f"> 已复现的 {s['已复现']} 条中，**{s['弱复现']} 条为弱复现**"
                     "（脚本只能确认端点可达，不含该类型的专用断言），"
                     "已在漏洞详情中逐条标注，请优先人工核对。")
            L.append("")
        return "\n".join(L)


class ReportGate:
    """准入闸门。把发现按「复现验证结果」分类。"""

    def __init__(self, require_script: bool = True,
                 allow_weak: bool = True,
                 min_strength: str = "") -> None:
        """
        require_script : 无复现脚本的发现一律判「未验证」（默认开启）
        allow_weak     : 弱复现的发现是否允许进清单。默认允许，但在报告中显著标注。
                         设为 False 则弱复现也进「待人工复现」。
        min_strength   : 可选，强制最低复现强度（strong / medium）
        """
        self.require_script = require_script
        self.allow_weak = allow_weak
        self.min_strength = min_strength

    # ------------------------------------------------------------------
    def evaluate(self, findings: list[Finding],
                 runs: list[Any] | None = None,
                 verify_ran: bool = False,
                 verify_note: str = "") -> GateResult:
        """对全部发现做准入判定。

        runs : VerifyRunner.run_all() 的返回，元素需含 script / exit_code /
               duration_ms / output 属性。为空表示复现环节没跑。
        """
        run_index: dict[str, Any] = {}
        for r in (runs or []):
            name = getattr(r, "script", None) or (r.get("script") if isinstance(r, dict) else "")
            if name:
                run_index[name] = r

        result = GateResult(verify_ran=verify_ran, verify_note=verify_note)

        for f in findings:
            result.decisions.append(self._judge(f, run_index))

        return result

    # ------------------------------------------------------------------
    def _judge(self, f: Finding, run_index: dict[str, Any]) -> GateDecision:
        strength = (f.extra or {}).get("verify_strength", "") or ""
        script = f.verify_script or ""

        # ---- 1) 没有复现脚本 ----
        if self.require_script and not script:
            return GateDecision(
                finding=f, verdict=VERDICT_UNVERIFIED, strength=strength,
                reason="未生成独立复现脚本，无法确认该发现可复测。"
                       "报告将如实标注为「未验证」，不计入漏洞清单。",
            )

        # ---- 2) 有脚本但没执行 ----
        run = run_index.get(Path(script).name) if script else None
        if run is None:
            return GateDecision(
                finding=f, verdict=VERDICT_UNVERIFIED, strength=strength,
                script=Path(script).name if script else "",
                reason="已生成复现脚本但未执行，无法确认复现结果。",
            )

        exit_code = getattr(run, "exit_code", None)
        verdict = EXIT_CODE_VERDICT.get(exit_code, VERDICT_INCONCLUSIVE)
        duration = getattr(run, "duration_ms", 0)

        # ---- 3) 由闸门统一回写 Finding 的验证字段 ----
        f.verify_result = {"已复现": "confirmed", "未复现": "refuted",
                           "无法判定": "inconclusive"}.get(verdict, "inconclusive")
        f.verify_output = (getattr(run, "output", "") or "")[:5000]

        # ---- 4) 弱复现的处理 ----
        if verdict == VERDICT_REPORTABLE and strength == STRENGTH_WEAK and not self.allow_weak:
            return GateDecision(
                finding=f, verdict=VERDICT_INCONCLUSIVE, strength=strength,
                script=Path(script).name, exit_code=exit_code, duration_ms=duration,
                reason="复现强度为弱（仅端点可达性），按当前闸门策略不放行至漏洞清单。",
            )

        if verdict == VERDICT_REPORTABLE and self.min_strength:
            order = {STRENGTH_STRONG: 3, STRENGTH_MEDIUM: 2, STRENGTH_WEAK: 1}
            if order.get(strength, 0) < order.get(self.min_strength, 0):
                return GateDecision(
                    finding=f, verdict=VERDICT_INCONCLUSIVE, strength=strength,
                    script=Path(script).name, exit_code=exit_code, duration_ms=duration,
                    reason=f"复现强度低于闸门要求（{STRENGTH_LABEL.get(strength, '未标注')}"
                           f" < {STRENGTH_LABEL.get(self.min_strength, '')}）。",
                )

        reason = {
            VERDICT_REPORTABLE: "独立复现脚本执行成功，该发现可复测。",
            VERDICT_REFUTED: "复现脚本执行后未能复现。可能已修复，"
                             "也可能复现判据与检测判据存在差异，需人工确认。",
            VERDICT_INCONCLUSIVE: "复现脚本能执行，但不足以判定问题是否仍存在"
                                  "（覆盖面不足或该类型缺少专用断言）。",
        }.get(verdict, "")

        return GateDecision(
            finding=f, verdict=verdict, reason=reason, strength=strength,
            script=Path(script).name, exit_code=exit_code, duration_ms=duration,
        )


# ==============================================================================
# CLI：对既有扫描结果离线复核闸门（不重新扫描）
# ==============================================================================
if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="发现准入闸门 —— 离线复核")
    ap.add_argument("findings_json", help="findings.json 路径")
    args = ap.parse_args()

    data = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
    rows = data["findings"] if isinstance(data, dict) else data
    findings = []
    for d in rows:
        findings.append(Finding(
            item_id=d.get("item_id", ""), title=d.get("title", ""),
            target=d.get("target", ""), endpoint=d.get("endpoint", ""),
            severity=d.get("severity", "中危"),
            verify_script=d.get("verify_script", ""),
            verify_result=d.get("verify_result", ""),
            extra=d.get("extra") or {},
        ))

    gate = ReportGate()
    res = gate.evaluate(findings, runs=None, verify_ran=False)
    print(res.gate_summary())
    print()
    for k, v in res.stats().items():
        print(f"  {k}: {v}")
