# -*- coding: utf-8 -*-
"""
检查项清单加载器
================
职责：把 checklist-wstg.yaml + checklist-extras.yaml 加载、校验、展平成统一的
      CheckItem 列表，供适用性判定 / 扫描引擎 / 定级 / 报告四处共用。

设计要点：
  - 单一数据源。所有环节通过编号（id）引用检查项，禁止各自硬编码。
  - 强制字段校验。缺字段直接抛错，不静默降级 —— 字段缺失会让下游自动化断链。
  - 顺序稳定。按 yaml 中定义的分类顺序展开，保证报告章节每次一致。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("缺少依赖 pyyaml，请执行：pip install pyyaml")

HERE = Path(__file__).resolve().parent
DEFAULT_FILES = ["checklist-wstg.yaml", "checklist-extras.yaml"]

# 每个检查项必须具备的字段。缺一不可。
REQUIRED_FIELDS = ("id", "name", "app", "detect", "verify", "level", "compliance")

# 证据分级 -> 定级上限（与规格第 5 章一致）
EVIDENCE_CAP = {"A": "严重", "B": "中危", "C": None}

SEVERITY_ORDER = ["信息", "低危", "中危", "高危", "严重"]


def severity_rank(level: str) -> int:
    """返回等级序号，越大越严重。未知等级返回 -1。"""
    return SEVERITY_ORDER.index(level) if level in SEVERITY_ORDER else -1


def cap_severity(level: str, evidence: str) -> str:
    """按证据分级对定级设上限。C 级返回空串表示不得进入漏洞清单。"""
    cap = EVIDENCE_CAP.get(evidence, None)
    if evidence == "C":
        return ""
    if cap is None:
        return level
    return level if severity_rank(level) <= severity_rank(cap) else cap


@dataclass
class CheckItem:
    """单个检查项。字段与规格第 4 章严格一致。"""

    id: str
    name: str
    app: str                      # 适用条件变量，见 applicability
    detect: str                   # 检测方法
    verify: str                   # 验证方法
    level: str                    # 定级规则（自然语言，由 rules/grading.py 解析为实测判据）
    compliance: str               # 合规映射
    category: str = ""            # 所属分类代号，如 INFO / EXT-SC
    category_name: str = ""       # 所属分类中文名
    source: str = ""              # 来自哪份清单文件
    verify_script: str = ""       # 对应的 verify_xxx.py 文件名（由 verify 框架回填）

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Checklist:
    """全部检查项的集合，带索引。"""

    items: list[CheckItem] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    # ---- 索引 ----
    def by_id(self, item_id: str) -> CheckItem | None:
        for it in self.items:
            if it.id == item_id:
                return it
        return None

    def by_category(self) -> dict[str, list[CheckItem]]:
        out: dict[str, list[CheckItem]] = {}
        for it in self.items:
            out.setdefault(it.category, []).append(it)
        return out

    def by_app(self, app: str) -> list[CheckItem]:
        return [it for it in self.items if it.app == app]

    def filter_apps(self, apps: set[str]) -> list[CheckItem]:
        """返回 app 取值落在给定集合内的检查项。"""
        return [it for it in self.items if it.app in apps]

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[CheckItem]:
        return iter(self.items)


def _load_yaml(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"清单文件不存在：{path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        raise ValueError(f"清单文件顶层必须是列表：{path}")
    return data


def load_checklist(files: list[str] | None = None, base_dir: Path | None = None) -> Checklist:
    """加载并校验全部检查项清单。

    Args:
        files: 清单文件名列表，默认两份都加载。
        base_dir: 清单所在目录，默认本文件所在目录。

    Raises:
        ValueError: 字段缺失、ID 重复、app 取值非法。
    """
    base = base_dir or HERE
    names = files if files is not None else DEFAULT_FILES

    items: list[CheckItem] = []
    meta: dict[str, Any] = {}
    seen_ids: dict[str, str] = {}
    valid_apps: set[str] = set()

    for name in names:
        blocks = _load_yaml(base / name)
        for blk in blocks:
            if not isinstance(blk, dict):
                continue
            # 收集 meta 与 applicability（只出现在第一份文件里）
            if "meta" in blk:
                meta.update(blk["meta"])
                continue
            if "applicability" in blk:
                valid_apps.update(blk["applicability"].keys())
                continue
            if "severity_model" in blk:
                meta["severity_model"] = blk["severity_model"]
                continue

            cat = blk.get("category", "")
            cat_name = blk.get("name", "")
            if not cat:
                continue

            for raw in blk.get("items", []):
                missing = [f for f in REQUIRED_FIELDS if not raw.get(f)]
                if missing:
                    raise ValueError(
                        f"[{name}] 检查项 {raw.get('id', '<无ID>')} 缺失必填字段："
                        f"{', '.join(missing)}"
                    )
                item_id = raw["id"]
                if item_id in seen_ids:
                    raise ValueError(
                        f"检查项 ID 重复：{item_id}（首见于 {seen_ids[item_id]}，"
                        f"重见于 {name}）"
                    )
                seen_ids[item_id] = name
                items.append(
                    CheckItem(
                        id=item_id,
                        name=raw["name"],
                        app=raw["app"],
                        detect=raw["detect"],
                        verify=raw["verify"],
                        level=raw["level"],
                        compliance=raw["compliance"],
                        category=cat,
                        category_name=cat_name,
                        source=name,
                    )
                )

    # app 取值校验：必须落在已经声明的适用条件枚举内，否则 N/A 判定会失效
    if valid_apps:
        bad = sorted({it.app for it in items if it.app not in valid_apps})
        if bad:
            raise ValueError(
                f"以下 app 取值未在 applicability 枚举中声明，将导致 N/A 判定失效：{bad}"
            )

    meta["wstg_items"] = sum(1 for it in items if it.source == "checklist-wstg.yaml")
    meta["extras_items"] = sum(1 for it in items if it.source == "checklist-extras.yaml")

    return Checklist(items=items, meta=meta)


def load_applicability(base_dir: Path | None = None) -> dict[str, str]:
    """读取适用条件枚举定义（app 变量 -> 中文说明）。"""
    base = base_dir or HERE
    blocks = _load_yaml(base / "checklist-wstg.yaml")
    for blk in blocks:
        if isinstance(blk, dict) and "applicability" in blk:
            return dict(blk["applicability"])
    return {}


if __name__ == "__main__":
    cl = load_checklist()
    print(f"加载检查项：{len(cl)} 项")
    print(f"  WSTG 骨架：{cl.meta.get('wstg_items')} 项")
    print(f"  场景扩展：{cl.meta.get('extras_items')} 项")
    print(f"  分类数：{len(cl.by_category())}")
    for cat, group in cl.by_category().items():
        print(f"    {cat:<12} {group[0].category_name:<16} {len(group):>3} 项")
