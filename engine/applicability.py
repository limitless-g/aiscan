# -*- coding: utf-8 -*-
"""
适用性判定引擎
==============
职责：根据目标的实测特征，对全量检查项逐项推导「适用 / 不适用」，并生成
      N/A 原因文本。这是需求第 4 条「每次检查项一致、不涉及也要说明原因」
      的唯一落地机制。

设计原则：
  - 不适用必须给理由。禁止静默跳过任何一项。
  - 未知不等于不适用。特征无法判定时标 UNKNOWN（待确认），不擅自判 N/A —— 
    否则会以「不适用」的名义漏掉真实风险。
  - 判定可追溯。每一项适用性结论都必须能追溯到特征来源。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from checklist.loader import CheckItem, Checklist, load_applicability, load_checklist  # noqa: E402

FeatureState = Literal["present", "absent", "unknown"]

# 弱证据特征：这些特征的「不存在」很难靠有限路径探测证实。
# 登录、上传、支付等入口完全可能藏在非标准路径下，探测不到不等于没有。
# 对这类特征判 absent 时必须标注证据强度，并在 N/A 原因里提示人工确认，
# 否则会以「不适用」的名义漏掉真实检查项 —— 这是最危险的假阴性。
WEAK_ABSENT_FEATURES = {
    "has_login", "has_account", "has_admin", "has_api", "has_upload",
    "has_download", "has_payment", "has_oauth", "has_graphql", "has_websocket",
    "has_cicd", "has_ai", "has_storage",
    # 2026-09-30 补。`fingerprint` 在**未渲染入口页**时给 `has_input` 判 absent，
    # 证据里已经写明「SPA 的表单只存在于渲染后的 DOM 中，故此项可能是
    # 「没看到」而非「不存在」」—— 证据自己都说是弱结论，却因为不在这张表里
    # 而被按强证据记账（`TargetFeatures.set` 的自动分级只认本表）。
    # 后果：依赖输入入口的检查项（注入类为主）整批判**强 N/A**，
    # 既不进「弱判定 N/A 复核清单」，读者也没有任何提示。
    # 这是最危险的假阴性形态 —— 以「不适用」的名义把检查项取消掉。
    "has_input",
}

# 判定结论
CONCLUSION_PASS_NA = "N/A"
CONCLUSION_PENDING = "待确认"
CONCLUSION_APPLICABLE = "适用"


@dataclass
class Feature:
    """单个目标特征的判定结果，带证据来源与强度。"""

    name: str
    state: FeatureState = "unknown"
    evidence: str = ""          # 判定依据，如「探测到 /login 页面返回 200」
    source: str = "fingerprint"  # 来源：fingerprint / manual / override
    strength: str = "strong"     # strong（确证）/ weak（有限探测推断）

    @property
    def present(self) -> bool:
        return self.state == "present"

    @property
    def absent(self) -> bool:
        return self.state == "absent"

    @property
    def unknown(self) -> bool:
        return self.state == "unknown"

    @property
    def weak(self) -> bool:
        return self.strength == "weak"


@dataclass
class TargetFeatures:
    """一个目标的全部特征集合。"""

    target: str
    features: dict[str, Feature] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def get(self, name: str) -> Feature:
        if name == "always":
            return Feature(name="always", state="present", evidence="目标存在即适用")
        return self.features.get(name, Feature(name=name, state="unknown"))

    def set(self, name: str, state: FeatureState, evidence: str = "",
            source: str = "fingerprint", strength: str | None = None) -> None:
        """设置特征。strength 未指定时按特征类型自动判定。"""
        if strength is None:
            if state == "present":
                strength = "strong"
            elif state == "absent" and name in WEAK_ABSENT_FEATURES:
                strength = "weak"
            else:
                strength = "strong"
        self.features[name] = Feature(
            name=name, state=state, evidence=evidence, source=source, strength=strength
        )

    def all_app_names(self, declared: dict[str, str]) -> list[str]:
        return sorted(set(declared) | set(self.features))


@dataclass
class ApplicabilityResult:
    """单个检查项的适用性结论。"""

    item: CheckItem
    conclusion: str            # 适用 / N/A / 待确认
    reason: str                # N/A 或待确认的原因文本
    feature: Feature           # 依据的特征
    skipped_by_user: bool = False
    skip_reason: str = ""
    weak_na: bool = False      # True 表示该 N/A 基于有限探测推断，建议人工确认

    @property
    def needs_execution(self) -> bool:
        return self.conclusion == CONCLUSION_APPLICABLE and not self.skipped_by_user

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item.id,
            "name": self.item.name,
            "category": self.item.category,
            "category_name": self.item.category_name,
            "app": self.item.app,
            "conclusion": self.conclusion,
            "reason": self.reason,
            "feature_state": self.feature.state,
            "feature_evidence": self.feature.evidence,
            "feature_strength": self.feature.strength,
            "weak_na": self.weak_na,
            "level": self.item.level,
            "compliance": self.item.compliance,
        }


class ApplicabilityEngine:
    """逐项推导检查项适用性。"""

    def __init__(self, declared_apps: dict[str, str] | None = None):
        self.declared = declared_apps if declared_apps is not None else load_applicability()

    def evaluate(
        self,
        checklist: Checklist,
        features: TargetFeatures,
        skip_items: dict[str, str] | None = None,
    ) -> list[ApplicabilityResult]:
        """对全部检查项逐项判定。

        Args:
            checklist: 已加载的检查项清单。
            features: 该目标的实测特征。
            skip_items: 用户显式跳过的项 {item_id: 跳过原因}。

        Returns:
            与 checklist 顺序一致的适用性结论列表。
        """
        skips = skip_items or {}
        results: list[ApplicabilityResult] = []

        for item in checklist:
            feat = features.get(item.app)
            skip_reason = skips.get(item.id, "")

            if item.app == "always":
                concl, reason = CONCLUSION_APPLICABLE, "目标存在即适用"
            elif feat.present:
                concl = CONCLUSION_APPLICABLE
                reason = f"目标具备该特征（{feat.evidence or item.app}）"
            elif feat.absent:
                concl = CONCLUSION_PASS_NA
                weak = feat.weak
                reason = (
                    self._weak_na_reason(item, feat) if weak
                    else self._na_reason(item, feat)
                )
            else:
                concl = CONCLUSION_PENDING
                weak = False
                reason = (
                    f"无法确认目标是否具备「{self.declared.get(item.app, item.app)}」特征，"
                    f"需人工确认后再决定是否执行"
                )

            results.append(
                ApplicabilityResult(
                    item=item,
                    conclusion=concl,
                    reason=reason,
                    feature=feat,
                    skipped_by_user=bool(skip_reason),
                    skip_reason=skip_reason,
                    weak_na=(concl == CONCLUSION_PASS_NA and feat.weak),
                )
            )

        return results

    def _na_reason(self, item: CheckItem, feat: Feature) -> str:
        """生成 N/A 原因（强证据）。格式固定，便于报告逐项列示。"""
        desc = self.declared.get(item.app, item.app)
        ev = feat.evidence or "实测未发现该特征"
        return f"该目标不具备「{desc}」，{item.id} {item.name} 不适用（判定依据：{ev}）"

    def _weak_na_reason(self, item: CheckItem, feat: Feature) -> str:
        """生成 N/A 原因（弱证据）。

        这类 N/A 基于有限路径探测推断得出，不能排除目标存在非标准入口的可能。
        原因文本必须把不确定性讲清楚，并在报告里单列，供人工复核。
        """
        desc = self.declared.get(item.app, item.app)
        ev = feat.evidence or "有限探测未命中"
        return (
            f"该目标未探测到「{desc}」，{item.id} {item.name} 暂判不适用"
            f"（判定依据：{ev}；**该判定基于常见入口的有限探测，"
            f"若目标存在非标准路径入口，本项应重新评估**）"
        )

    @staticmethod
    def summary(results: list[ApplicabilityResult]) -> dict[str, int]:
        """统计各结论数量。"""
        out = {CONCLUSION_APPLICABLE: 0, CONCLUSION_PASS_NA: 0, CONCLUSION_PENDING: 0}
        for r in results:
            out[r.conclusion] = out.get(r.conclusion, 0) + 1
        out["用户跳过"] = sum(1 for r in results if r.skipped_by_user)
        out["弱判定N/A"] = sum(1 for r in results if r.weak_na)
        out["合计"] = len(results)
        return out


def build_example_features(target: str) -> TargetFeatures:
    """构造一个示例特征集，用于链路自测。"""
    tf = TargetFeatures(target=target)
    # 典型前后端分离 Web 系统：有登录、有 API、有会话、无文件上传、无支付
    tf.set("has_login", "present", "探测到 /login 页面返回 200", "fingerprint")
    tf.set("has_account", "present", "存在注册入口", "fingerprint")
    tf.set("has_api", "present", "探测到 /api/ 网关响应", "fingerprint")
    tf.set("has_session", "present", "响应头 Set-Cookie 含会话标识", "fingerprint")
    tf.set("has_client", "present", "页面含前端框架打包产物", "fingerprint")
    tf.set("has_component", "present", "打包产物含第三方库指纹", "fingerprint")
    tf.set("has_input", "present", "存在查询参数与表单", "fingerprint")
    tf.set("has_cloud", "present", "响应头含云厂商特征", "fingerprint")
    tf.set("has_upload", "absent", "全站未发现文件上传入口", "fingerprint")
    tf.set("has_payment", "absent", "该目标不涉及交易", "manual")
    tf.set("has_graphql", "absent", "未探测到 /graphql 端点", "fingerprint")
    tf.set("has_ai", "unknown", "", "fingerprint")
    return tf


if __name__ == "__main__":
    cl = load_checklist()
    tf = build_example_features("demo.example.com")
    eng = ApplicabilityEngine()
    res = eng.evaluate(cl, tf)

    s = ApplicabilityEngine.summary(res)
    print(f"目标：{tf.target}")
    print(f"检查项：{s['合计']} 项")
    print(f"  适用   ：{s[CONCLUSION_APPLICABLE]} 项")
    print(f"  N/A    ：{s[CONCLUSION_PASS_NA]} 项")
    print(f"  待确认 ：{s[CONCLUSION_PENDING]} 项")
    print("\n—— N/A 示例（前 5 条）——")
    shown = 0
    for r in res:
        if r.conclusion == CONCLUSION_PASS_NA:
            print(f"  [{r.item.id}] {r.reason}")
            shown += 1
            if shown >= 5:
                break
    print("\n—— 待确认示例（前 3 条）——")
    shown = 0
    for r in res:
        if r.conclusion == CONCLUSION_PENDING:
            print(f"  [{r.item.id}] {r.reason}")
            shown += 1
            if shown >= 3:
                break
