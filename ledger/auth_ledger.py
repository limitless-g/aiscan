# -*- coding: utf-8 -*-
"""
授权台账
========
职责：记录每个已授权目标的授权信息，实现「首次登记、同资产后续免问」。

为什么需要（规格第 8 章）：
  现有扫描流程默认「所有目标视为已授权、不询问」。你自己内部用没问题，
  但一旦这套能力分发给同事批量使用，「不问授权就扫」这个默认值本身就是
  合规风险。轻量闸门的作用：不牺牲日常效率（同一资产只登记一次），
  但确保每个被扫的目标都有书面授权依据可查。

设计要点：
  - 授权是「登记制」而非「询问制」——存量资产一次登记，之后零交互。
  - 未登记资产拒绝执行，并给出补登记指引，不做「先扫后补」。
  - 台账是审计凭证，记录登记时间与最后扫描时间，只追加不覆盖。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass
class AuthRecord:
    """一条授权记录。"""

    domain: str
    target_name: str = ""
    authorizer: str = ""
    authorization_date: str = ""
    authorization_ref: str = ""
    allow_write_test: bool = False
    # ---- 红队模式授权范围（2026-09-21 新增）----
    # objectives  ：允许尝试达成的攻击目标（READ_DATA / MODIFY_DATA / TAKE_CONTROL）。
    #               留空 = 按扫描档位默认（向后兼容旧记录）。
    # impact_level：允许的最大影响级别（L1 证明可达 / L2 证明影响 / L3 完整利用）。
    #               留空 = 取扫描档位默认值。
    # 未登记的攻击目标一律不执行 —— 结果记「未能验证（未授权）」，
    # **不记「未达成」**：前者是「没测」，后者是「试过了打不穿」。
    objectives: list[str] = field(default_factory=list)
    impact_level: str = ""
    registered_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    last_scan_at: str = ""
    scan_count: int = 0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def is_valid(self) -> bool:
        """授权记录是否要素齐全。"""
        return bool(self.domain and self.authorizer and self.authorization_ref)


class AuthLedger:
    """授权台账。"""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else (Path(__file__).resolve().parent / "auth-ledger.yaml")
        self.records: dict[str, AuthRecord] = {}
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            import yaml
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            return
        for rec in (data.get("authorizations") or []):
            try:
                r = AuthRecord(**{k: v for k, v in rec.items()
                                  if k in AuthRecord.__dataclass_fields__})
                self.records[r.domain] = r
            except Exception:  # noqa: BLE001
                continue

    def save(self) -> Path:
        import yaml

        self.path.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "# ==============================================================================\n"
            "# 授权台账\n"
            "# ==============================================================================\n"
            "# 本文件记录每个目标的授权依据，是扫描合法性的凭证。\n"
            "# 规则：同一目标只需首次登记，后续扫描自动放行（零交互）。\n"
            "#       未登记目标将被引擎拒绝，需先补登记。\n"
            "# 注意：本文件只追加、不覆盖历史记录。请勿手工删除已登记条目。\n"
            "# ==============================================================================\n\n"
        )
        body = yaml.safe_dump(
            {"authorizations": [r.to_dict() for r in self.records.values()]},
            allow_unicode=True, sort_keys=False, default_flow_style=False,
        )
        self.path.write_text(header + body, encoding="utf-8")
        return self.path

    # ------------------------------------------------------------------
    def check(self, domain: str) -> tuple[bool, str]:
        """检查目标是否已授权。

        Returns:
            (是否放行, 说明)
        """
        d = self._norm(domain)
        rec = self.records.get(d)
        if not rec:
            return False, (
                f"目标 {domain} 未在授权台账中登记。\n"
                f"  补登记方式：在 {self.path.name} 的 authorizations 段添加一条记录，"
                f"或调用 AuthLedger.register(...) 登记。\n"
                f"  必需字段：domain / authorizer / authorization_ref（授权依据，如邮件编号）。"
            )
        if not rec.is_valid:
            return False, (
                f"目标 {domain} 已有登记但要素不全（缺授权人或授权依据），"
                f"请补全后重试。"
            )
        return True, (
            f"目标 {domain} 已授权（授权人 {rec.authorizer}，"
            f"依据 {rec.authorization_ref}，登记于 {rec.registered_at}）"
        )

    def register(
        self,
        domain: str,
        target_name: str = "",
        authorizer: str = "",
        authorization_ref: str = "",
        authorization_date: str = "",
        allow_write_test: bool = False,
        notes: str = "",
        objectives: list[str] | None = None,
        impact_level: str = "",
    ) -> AuthRecord:
        """登记一个新目标的授权信息。已存在则更新。"""
        d = self._norm(domain)
        rec = self.records.get(d) or AuthRecord(domain=d)
        rec.target_name = target_name or rec.target_name
        rec.authorizer = authorizer or rec.authorizer
        rec.authorization_ref = authorization_ref or rec.authorization_ref
        rec.authorization_date = authorization_date or rec.authorization_date or datetime.now().strftime("%Y-%m-%d")
        rec.allow_write_test = allow_write_test
        rec.notes = notes or rec.notes
        # 红队授权范围：**显式传入才覆盖**，避免重复登记时把范围悄悄放大。
        # 授权范围只应被人为扩大，不应被一次遗漏的参数改写。
        if objectives is not None:
            rec.objectives = [str(o).strip().upper() for o in objectives
                              if str(o).strip()]
        if impact_level:
            rec.impact_level = str(impact_level).strip().upper()
        self.records[d] = rec
        return rec

    def mark_scanned(self, domain: str) -> None:
        """记录一次扫描。"""
        d = self._norm(domain)
        rec = self.records.get(d)
        if not rec:
            return
        rec.last_scan_at = datetime.now().isoformat(timespec="seconds")
        rec.scan_count += 1

    def can_write_test(self, domain: str) -> bool:
        """该目标是否允许受控写验证（规格第 9 章第 3 条约束）。"""
        rec = self.records.get(self._norm(domain))
        return bool(rec and rec.allow_write_test)

    def list_all(self) -> list[AuthRecord]:
        return list(self.records.values())

    @staticmethod
    def _norm(domain: str) -> str:
        d = (domain or "").strip().lower()
        for p in ("https://", "http://"):
            if d.startswith(p):
                d = d[len(p):]
        return d.split("/")[0].split(":")[0]


if __name__ == "__main__":
    print("授权台账自测")
    print("=" * 70)

    tmp = Path(ROOT) / "outputs" / "_selftest" / "auth-ledger.yaml"
    if tmp.exists():
        tmp.unlink()
    ledger = AuthLedger(tmp)

    # 1) 未登记 → 拒绝
    ok, msg = ledger.check("new-system.example.com")
    print(f"\n[未登记目标] 放行={ok}")
    print(f"  {msg}")

    # 2) 登记后 → 放行
    ledger.register(
        "demo.example.com", "示例会员系统",
        authorizer="示例授权人", authorization_ref="邮件《安全评估申请》20260920",
        allow_write_test=False,
    )
    ledger.save()
    ok, msg = ledger.check("https://demo.example.com/some/path")
    print(f"\n[已登记目标] 放行={ok}")
    print(f"  {msg}")

    # 3) 要素不全 → 拒绝
    ledger.register("incomplete.example.com", "要素不全示例")
    ok, msg = ledger.check("incomplete.example.com")
    print(f"\n[要素不全] 放行={ok}")
    print(f"  {msg}")

    # 4) 写验证权限
    print(f"\n[写验证权限] demo={ledger.can_write_test('demo.example.com')}")

    ledger.mark_scanned("demo.example.com")
    ledger.save()
    print(f"\n台账已保存：{tmp}")
    print(f"条目数：{len(ledger.list_all())}")
    assert not AuthLedger(tmp).check("new-system.example.com")[0]
    assert AuthLedger(tmp).check("demo.example.com")[0]
    print("✓ 台账持久化与校验逻辑自测通过")
