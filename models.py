# -*- coding: utf-8 -*-
"""
核心数据结构
============
Finding 是整个工程的枢纽：采集层产出它、验证层充实它、定级层裁决它、
报告层渲染它。所有环节共用同一个定义，禁止各自造轮子。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

Severity = Literal["严重", "高危", "中危", "低危", "信息"]
Confidence = Literal["High", "Medium", "Low"]
EvidenceLevel = Literal["A", "B", "C"]

SEVERITY_ORDER = ["信息", "低危", "中危", "高危", "严重"]


def severity_rank(level: str) -> int:
    return SEVERITY_ORDER.index(level) if level in SEVERITY_ORDER else -1


@dataclass
class Evidence:
    """单条原始证据。落盘前必须经过脱敏。"""

    kind: str                  # request / response / header / file / dns / tls
    content: str               # 已脱敏内容
    note: str = ""
    masked: bool = False       # 是否已执行脱敏
    raw_hash: str = ""         # 原始内容哈希（用于证明未篡改，不可逆）

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """一条漏洞发现。字段与规格第 6 章「漏洞详情」要求一一对应。"""

    # ---- 标识 ----
    item_id: str                       # 对应检查项 ID，如 WSTG-INPV-05
    title: str                         # 漏洞标题
    target: str                        # 目标系统名
    endpoint: str = ""                 # 受影响端点 / URL
    method: str = ""                   # HTTP 方法
    param: str = ""                    # 受影响参数

    # ---- 定级 ----
    severity: str = "信息"             # 严重/高危/中危/低危/信息
    confidence: str = "Medium"         # High/Medium/Low
    evidence_level: str = "B"          # A/B/C，决定定级上限
    grading_basis: str = ""            # 定级依据（实测危害描述）
    downgrade_factors: list[str] = field(default_factory=list)
    upgrade_factors: list[str] = field(default_factory=list)

    # ---- 内容 ----
    description: str = ""              # 通俗描述（面向非技术人员）
    technical_detail: str = ""         # 技术细节
    impact: str = ""                   # 影响说明（能拿到什么数据 / 什么权限）
    reproduction: str = ""             # 复现步骤
    remediation: str = ""              # 修复建议
    compliance: str = ""               # 合规映射

    # ---- 证据与复现 ----
    verify_script: str = ""            # verify_xxx.py 相对路径
    verify_result: str = ""            # 验证结论：confirmed / refuted / inconclusive
    verify_output: str = ""            # 脚本实测输出（脱敏）
    evidence: list[Evidence] = field(default_factory=list)

    # ---- 生命周期 ----
    status: str = "open"               # open / fixed / accepted / false_positive / pending
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    source_tool: str = ""              # 由哪个工具/模块发现
    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity_rank"] = severity_rank(self.severity)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @property
    def is_confirmed(self) -> bool:
        return self.verify_result == "confirmed"

    @property
    def max_allowed_severity(self) -> str:
        """按证据分级返回定级上限（规格第 5 章）。"""
        if self.evidence_level == "A":
            return "严重"
        if self.evidence_level == "B":
            return "中危"
        return ""  # C 级不得进入漏洞清单


@dataclass
class FindingSet:
    """一次扫描的全部发现。"""

    target: str
    findings: list[Finding] = field(default_factory=list)
    pending: list[Finding] = field(default_factory=list)   # C 级证据，待确认章节

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def add_pending(self, f: Finding) -> None:
        self.pending.append(f)

    def by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {s: [] for s in reversed(SEVERITY_ORDER)}
        for f in self.findings:
            out.setdefault(f.severity, []).append(f)
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -severity_rank(f.severity))

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in reversed(SEVERITY_ORDER)}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        c["合计"] = len(self.findings)
        c["待确认"] = len(self.pending)
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "pending": [f.to_dict() for f in self.pending],
        }

    def save(self, path: Path | str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return p

    @classmethod
    def load(cls, path: Path | str) -> "FindingSet":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        fs = cls(target=data.get("target", ""))
        for raw in data.get("findings", []):
            fs.findings.append(_finding_from_dict(raw))
        for raw in data.get("pending", []):
            fs.pending.append(_finding_from_dict(raw))
        return fs


def _finding_from_dict(raw: dict[str, Any]) -> Finding:
    ev = [Evidence(**e) for e in raw.pop("evidence", [])]
    raw.pop("severity_rank", None)
    f = Finding(**{k: v for k, v in raw.items() if k in Finding.__dataclass_fields__})
    f.evidence = ev
    return f
