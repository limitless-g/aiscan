# -*- coding: utf-8 -*-
"""
L6 复扫比对引擎
===============
职责：把两次扫描结果比对，输出「新增 / 已修复 / 仍存在」三类，并标注等级变化。

为什么现在就要做（规格第 11.1 章）：
  当前阶段是单次扫描，但安全负责人明确后续会给域名清单做定期批量扫描。
  比对能力必须在架构里预留好，否则启用周期化时整套结果归档格式都要改。

比对指纹：(item_id, 规范化端点, 参数)
  不用标题做指纹 —— 标题可能因措辞调整而变化，导致误判为「已修复 + 新增」。

⚠️ 但指纹含 item_id 会带来另一类误判：**同一个问题换了上报出口**
（某项改为专责上报，或两个重复发现合并成一条）会表现为「上轮有、本轮无」，
被记成「已修复」。这是假陈述 —— 客户看到「已修复 6」会以为收口已完成，
实际上是同一件事换了个地方写。因此 `compare()` 在判定「已修复」之前会先查
本轮是否还有**别的检查项**在报同一个端点 / 同一批端口：有 → 记为「重新归类」。

⚠️ 第三类误判（周期化扫描下最致命）：**本轮那一项根本没执行**。
预算被掐、配额耗尽、前端产物采集失败都会让检测器整项落「未执行」，
此时「本轮没有再检出」是句空话 —— 不是修好了，是没人去看。
若直接记为「已修复」，等于把假通过从清单层搬到了比对层。
因此 `compare()` 接受本轮的 `item_states`（检查项结论），
凡本项本轮状态属于「没有结论」（未执行 / 待人工执行 / 待确认 / 已跳过）的，
一律改记「本轮未判定」，**不进已修复**。
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Finding, FindingSet, SEVERITY_ORDER, severity_rank  # noqa: E402

#: 弱证据 N/A 在比对层的**独立表示**。必须与普通「N/A」区分开：
#: 普通 N/A 是「确证不具备该特征」，弱 N/A 是「有限路径探测**没看到**」。
#: 混用会让比对层把「没看到」读成「本轮有结论且没问题」，从而把一条历史发现
#: 计入「已修复」—— 那是给客户的一句假话（2026-09-30 修）。
#: 生产链路上由 `read_item_states` 从 `检查项结论.json` 的 `weak_na` 字段映射而来。
WEAK_NA_STATE = "N/A（弱证据）"


@dataclass
class DiffEntry:
    """一条比对结果。"""

    key: str
    title: str
    item_id: str
    endpoint: str
    kind: str                  # new / fixed / persisting / changed / reclassified /
                               # unverified
    old_severity: str = ""
    new_severity: str = ""
    detail: str = ""

    @property
    def severity_delta(self) -> int:
        if not (self.old_severity and self.new_severity):
            return 0
        return severity_rank(self.new_severity) - severity_rank(self.old_severity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "title": self.title, "item_id": self.item_id,
            "endpoint": self.endpoint, "old_severity": self.old_severity,
            "new_severity": self.new_severity, "severity_delta": self.severity_delta,
            "detail": self.detail,
        }


@dataclass
class DiffResult:
    baseline_time: str = ""
    current_time: str = ""
    target: str = ""
    new: list[DiffEntry] = field(default_factory=list)
    fixed: list[DiffEntry] = field(default_factory=list)
    persisting: list[DiffEntry] = field(default_factory=list)
    changed: list[DiffEntry] = field(default_factory=list)
    reclassified: list[DiffEntry] = field(default_factory=list)
    # 本轮那一项没执行 → 既不能说「已修复」也不能说「仍存在」，只能记「未判定」
    unverified: list[DiffEntry] = field(default_factory=list)
    # 本次比对是否拿到了本轮的检查项结论（拿不到 → 已修复数字含未执行项风险）
    states_loaded: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "baseline_time": self.baseline_time,
            "current_time": self.current_time,
            "states_loaded": self.states_loaded,
            "summary": self.summary(),
            "new": [e.to_dict() for e in self.new],
            "fixed": [e.to_dict() for e in self.fixed],
            "persisting": [e.to_dict() for e in self.persisting],
            "changed": [e.to_dict() for e in self.changed],
            "reclassified": [e.to_dict() for e in self.reclassified],
            "unverified": [e.to_dict() for e in self.unverified],
        }

    def summary(self) -> dict[str, int]:
        return {
            "新增": len(self.new),
            "已修复": len(self.fixed),
            "仍存在": len(self.persisting),
            "等级变化": len(self.changed),
            "重新归类": len(self.reclassified),
            "本轮未判定": len(self.unverified),
        }

    def render_markdown(self) -> str:
        """渲染成 Markdown 复扫报告。"""
        L = [f"# 复扫比对报告 — {self.target}", ""]
        L.append(f"| 项目 | 内容 |")
        L.append("| --- | --- |")
        L.append(f"| 基线扫描 | {self.baseline_time} |")
        L.append(f"| 本次扫描 | {self.current_time} |")
        s = self.summary()
        L.append(f"| 新增问题 | {s['新增']} |")
        L.append(f"| 已修复 | {s['已修复']} |")
        L.append(f"| 仍存在 | {s['仍存在']} |")
        L.append(f"| 等级变化 | {s['等级变化']} |")
        L.append(f"| 重新归类（非修复） | {s['重新归类']} |")
        L.append(f"| 本轮未判定（非修复） | {s['本轮未判定']} |")
        L.append("")
        if not self.states_loaded:
            L.append("> ⚠️ 本次比对**未取得本轮的检查项结论**，因此「已修复」"
                     "只能按「本轮没再检出」推断 —— 其中可能混有本轮根本没执行"
                     "的检查项。要拿到干净的修复结论，请从归档目录重新比对"
                     "（需要同目录的 `检查项结论.json`）。")
            L.append("")

        if self.new:
            L.append("## 新增问题（需关注）")
            L.append("")
            L.append("> 注意：「新增」指**本轮首次上报**，不等于问题本轮才出现 ——"
                     "也可能是本轮扩大了覆盖范围（例如某个端口原先无人上报）。")
            L.append("")
            L.append("| 等级 | 标题 | 端点 |")
            L.append("| --- | --- | --- |")
            for e in sorted(self.new, key=lambda x: -severity_rank(x.new_severity)):
                L.append(f"| {e.new_severity} | {e.title} | `{e.endpoint}` |")
            L.append("")

        if self.fixed:
            L.append("## 已修复（本轮未再检出）")
            L.append("")
            L.append("> 「未再检出」= 上轮上报过、本轮没有任何检查项再报同一端点。"
                     "可能是已修复，也可能是端口关闭 / 环境变化 ——"
                     "**重新归类的问题不在此列**（见下一节）。")
            L.append("")
            L.append("| 原等级 | 标题 | 端点 |")
            L.append("| --- | --- | --- |")
            for e in self.fixed:
                L.append(f"| {e.old_severity} | {e.title} | `{e.endpoint}` |")
            L.append("")

        if self.unverified:
            L.append("## 本轮未判定（不是修复）")
            L.append("")
            L.append("> 上轮上报过，本轮**对应检查项根本没执行**（未执行 / 待人工执行 /"
                     " 待确认 / 已跳过），所以「本轮没再检出」不构成修复证据 ——"
                     " 它只说明这次没去看。**这些不得计入「已修复」**，"
                     "补齐后需重跑确认。")
            L.append("")
            L.append("| 原等级 | 标题 | 端点 | 本轮该项状态 |")
            L.append("| --- | --- | --- | --- |")
            for e in self.unverified:
                L.append(f"| {e.old_severity} | {e.title} | `{e.endpoint}` | {e.detail} |")
            L.append("")

        if self.reclassified:
            L.append("## 重新归类（不是修复）")
            L.append("")
            L.append("> 上轮由某个检查项上报，本轮改由另一个检查项上报 ——"
                     "问题本身仍在，只是换了上报出口（通常源于去重 / 职责调整）。"
                     "**这些不得计入「已修复」**。")
            L.append("")
            L.append("| 原等级 | 标题 | 端点 | 说明 |")
            L.append("| --- | --- | --- | --- |")
            for e in self.reclassified:
                L.append(f"| {e.old_severity} | {e.title} | `{e.endpoint}` | {e.detail} |")
            L.append("")

        if self.changed:
            L.append("## 等级变化")
            L.append("")
            L.append("| 标题 | 原等级 | 现等级 | 变化 |")
            L.append("| --- | --- | --- | --- |")
            for e in self.changed:
                d = e.severity_delta
                arrow = f"↑{d}" if d > 0 else f"↓{abs(d)}"
                L.append(f"| {e.title} | {e.old_severity} | {e.new_severity} | {arrow} |")
            L.append("")

        if self.persisting:
            L.append("## 仍存在")
            L.append("")
            L.append("| 等级 | 标题 | 端点 |")
            L.append("| --- | --- | --- |")
            for e in sorted(self.persisting, key=lambda x: -severity_rank(x.new_severity)):
                L.append(f"| {e.new_severity} | {e.title} | `{e.endpoint}` |")
            L.append("")

        if not any([self.new, self.fixed, self.persisting, self.changed,
                    self.reclassified]):
            L.append("本次比对未发现差异。")
            L.append("")
        return "\n".join(L)


class Differ:
    """两次扫描结果的比对器。"""

    @staticmethod
    def fingerprint(f: Finding) -> str:
        """生成比对指纹。刻意不含标题 —— 标题措辞变化不应被当成修复。"""
        ep = Differ._norm_endpoint(f.endpoint)
        return f"{f.item_id}|{ep}|{f.param or ''}"

    @staticmethod
    def _norm_endpoint(ep: str) -> str:
        if not ep:
            return ""
        e = ep.strip().lower()
        for p in ("https://", "http://"):
            if e.startswith(p):
                e = e[len(p):]
        return e.rstrip("/")

    @staticmethod
    def _portlist_ports(ep: str) -> frozenset[int]:
        """端口清单型端点 → 端口集合；非端口清单型返回空集。

        端口清单型指 `10.0.0.1:5432` 或 `10.0.0.1:5432,9200` 这种形态
        （冒号后只有端口号，没有路径 / 协议）。URL 型端点（含路径）返回空集 ——
        否则 `http://host:8000/api` 与 `http://host:8000/` 会因为共用 8000
        被判成「同一件事」，把真正修好的 URL 类发现误判成「重新归类」。
        """
        if not ep:
            return frozenset()
        e = Differ._norm_endpoint(ep)
        if not e or "/" in e or " " in e:
            return frozenset()
        host, _, tail = e.rpartition(":")
        if not host or not tail:
            return frozenset()
        parts = [x for x in tail.split(",") if x.strip().isdigit()]
        if not parts or len(parts) != len(tail.split(",")):
            return frozenset()
        return frozenset(int(x) for x in parts)

    # ------------------------------------------------------------------
    # 「没有结论」的检查项状态：都不足以支撑「已修复」的结论
    #
    # ⚠ 弱证据 N/A 必须单列（2026-09-30 修）。原先只有四态，于是**弱 N/A 被
    # 当成「本轮有结论且没问题」**，一条历史发现会在「没看到」的情况下被计入
    # 「已修复」—— 对客户而言这是一句假话：
    #   · 「N/A」     = 确证不具备该特征 → 可以支撑「已修复 / 不适用」；
    #   · 弱 N/A      = **有限路径探测没看到** → 既不能说存在，也不能说不存在，
    #                    因此它和「未执行」一样**不能支撑任何结论**。
    # 生产链路上弱 N/A 会以 `WEAK_NA_STATE` 的形式传进来（见
    # `read_item_states` / `encode_item_states` 与 `engine.registry.ItemResult.weak_na`）。
    #
    #: 与模块级同名常量同源，在此暴露成类属性：它和 `NO_CONCLUSION_STATES`
    #: 是一对（改一个必须改另一个），放在一起才不会漏改。
    WEAK_NA_STATE = WEAK_NA_STATE  # noqa: PLW0127
    NO_CONCLUSION_STATES = ("未执行", "待人工执行", "待确认", "已跳过",
                            WEAK_NA_STATE)

    def compare(self, baseline: FindingSet, current: FindingSet,
                item_states: dict[str, str] | None = None) -> DiffResult:
        """比对两轮结果。

        item_states：**本轮**的检查项结论（item_id → 状态），用于把
        「本轮该项没执行」的情况从「已修复」里摘出来。不传则退化为旧行为
        （调用方必须自己说明本轮覆盖是否完整）。
        """
        res = DiffResult(
            target=current.target or baseline.target,
            baseline_time=baseline.to_dict().get("scan_time", "（未知）"),
            current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        states = dict(item_states or {})
        res.states_loaded = bool(states)

        base_map: dict[str, Finding] = {}
        for f in baseline.findings:
            base_map[self.fingerprint(f)] = f
        cur_map: dict[str, Finding] = {}
        for f in current.findings:
            cur_map[self.fingerprint(f)] = f

        # 新增
        for k, f in cur_map.items():
            if k not in base_map:
                res.new.append(DiffEntry(
                    key=k, title=f.title, item_id=f.item_id, endpoint=f.endpoint,
                    kind="new", new_severity=f.severity,
                    detail=f"本次新增，等级 {f.severity}",
                ))

        # 已修复 / 重新归类 / 仍存在 / 等级变化
        cur_list = list(current.findings)

        def _taker(old: Finding) -> str:
            """本轮接手该问题的检查项 ID；没有接手方则返回空串。

            指纹含 item_id，所以「换了上报出口」会表现为「上轮有、本轮无」。
            在判「已修复」之前必须先问一句：**这件事真的没人管了吗？**
            判据（任一成立即为重新归类）：
              ① 同一端点（规范化后逐字相同）本轮由另一个检查项上报；
              ② 端口清单型端点：端口集合与另一检查项的端点有交集
                 （合并上报时端点会变成多端口列表，不会逐字相同）。
            """
            oep = Differ._norm_endpoint(old.endpoint)
            if not oep:
                return ""
            for f in cur_list:
                if f.item_id != old.item_id and Differ._norm_endpoint(f.endpoint) == oep:
                    return f.item_id
            opts = Differ._portlist_ports(old.endpoint)
            if opts:
                for f in cur_list:
                    if f.item_id == old.item_id:
                        continue
                    if opts & Differ._portlist_ports(f.endpoint):
                        return f.item_id
            return ""

        for k, old in base_map.items():
            if k not in cur_map:
                # 先问：本轮这项到底跑了没有？
                # 没跑 →「本轮没再检出」是句空话，既非修复也非仍存在。
                st = states.get(old.item_id, "")
                if st in self.NO_CONCLUSION_STATES:
                    # 弱证据 N/A 的成因与「压根没执行」不同，措辞必须分开 ——
                    # 都写「没有人去看」是不准确的：那一项其实探测过，
                    # 只是采用的判据（有限路径）不足以支撑「确证不具备」。
                    _why = ("（**只做了有限路径探测，没看到** —— 不等于不存在，"
                            "也不等于已修复）" if st == WEAK_NA_STATE
                            else "（没有人去看）")
                    res.unverified.append(DiffEntry(
                        key=k, title=old.title, item_id=old.item_id,
                        endpoint=old.endpoint, kind="unverified",
                        old_severity=old.severity,
                        detail=f"本轮该项状态为「{st}」{_why}，"
                               f"不能据此判定已修复",
                    ))
                    continue
                taker = _taker(old)
                if taker:
                    # ⚠️ 这里**不能**记为「已修复」—— 问题还在，只是换了出口。
                    # 把去重 / 职责调整当成修复是假陈述：客户看到「已修复 N」
                    # 会以为收口完成，实际是同一件事换了个地方写。
                    res.reclassified.append(DiffEntry(
                        key=k, title=old.title, item_id=old.item_id,
                        endpoint=old.endpoint, kind="reclassified",
                        old_severity=old.severity,
                        detail=f"上轮由 {old.item_id} 上报，本轮由 {taker} 上报"
                               f"（同一问题换了上报出口，非修复）",
                    ))
                    continue
                res.fixed.append(DiffEntry(
                    key=k, title=old.title, item_id=old.item_id, endpoint=old.endpoint,
                    kind="fixed", old_severity=old.severity,
                    detail="上轮存在，本轮没有任何检查项再检出（已修复或环境变化）",
                ))
                continue
            new = cur_map[k]
            if severity_rank(new.severity) != severity_rank(old.severity):
                res.changed.append(DiffEntry(
                    key=k, title=new.title, item_id=new.item_id, endpoint=new.endpoint,
                    kind="changed", old_severity=old.severity, new_severity=new.severity,
                    detail=f"等级由 {old.severity} 变为 {new.severity}",
                ))
            else:
                res.persisting.append(DiffEntry(
                    key=k, title=new.title, item_id=new.item_id, endpoint=new.endpoint,
                    kind="persisting", old_severity=old.severity, new_severity=new.severity,
                    detail="上轮存在，本轮仍存在",
                ))
        return res

    def compare_files(self, baseline_path: Path | str, current_path: Path | str,
                      item_states: dict[str, str] | None = None) -> DiffResult:
        base = FindingSet.load(baseline_path)
        curr = FindingSet.load(current_path)
        # 本轮结论优先取归档里的「检查项结论.json」—— 只有它知道
        # 哪些项这次真的跑了、哪些项连结论都没有。
        states = dict(item_states or {})
        if not states:
            states = self.read_item_states(current_path)
        res = self.compare(base, curr, item_states=states)
        # 从归档的 context 中读取扫描时间，让报告能显示基线时间点
        res.baseline_time = self._read_scan_time(baseline_path) or res.baseline_time
        res.current_time = self._read_scan_time(current_path) or res.current_time
        return res

    @staticmethod
    def read_item_states(findings_path: Path | str) -> dict[str, str]:
        """从归档目录读本轮的检查项结论（item_id → state）。

        读不到就返回空字典 —— 退回旧口径，**不猜**。调用方可通过
        `DiffResult.states_loaded` 判断本次比对是否带上了覆盖度信息。

        ⚠ 判为**弱证据**的 N/A 映射成 `WEAK_NA_STATE`，不返回「N/A」：
        它的含义是「有限路径探测没看到」，和「未执行」一样不能支撑任何结论。
        原样返回「N/A」会让比对层把它当成「确证没问题」→ 历史发现被计成
        「已修复」（2026-09-30 修）。
        """
        p = Path(findings_path)
        for d in (p.parent, p.parent.parent):
            f = d / "检查项结论.json"
            try:
                if not f.exists():
                    continue
                data = json.loads(f.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            items = (data or {}).get("items") if isinstance(data, dict) else data
            out: dict[str, str] = {}
            for it in (items or []):
                if not (isinstance(it, dict) and it.get("item_id")):
                    continue
                st = str(it.get("state") or "")
                if st == "N/A" and bool(it.get("weak_na", False)):
                    st = WEAK_NA_STATE
                out[str(it["item_id"])] = st
            if out:
                return out
        return {}

    @staticmethod
    def encode_item_states(item_results: Any) -> dict[str, str]:
        """把内存里的 `ItemResult` 列表编成比对层要的 `{item_id: state}`。

        **必须走这个函数，不要自己写 `{r.item_id: r.state for r in ...}`** ——
        那样会把弱证据 N/A 原样写成「N/A」，比对层随即把它当成「确证没问题」，
        把历史发现计成「已修复」。内存路径与归档读取路径（`read_item_states`）
        必须产出同一种表示，否则同一份数据从两条路进来会得到两种价格。
        """
        out: dict[str, str] = {}
        for r in (item_results or []):
            try:
                iid = str(getattr(r, "item_id", "") or "")
                if not iid:
                    continue
                st = str(getattr(r, "state", "") or "")
                if st == "N/A" and bool(getattr(r, "weak_na", False)):
                    st = WEAK_NA_STATE
                out[iid] = st
            except Exception:  # noqa: BLE001
                continue
        return out

    @staticmethod
    def _read_scan_time(path: Path | str) -> str:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return ""
        ctx = data.get("context") or {}
        return str(ctx.get("scan_time") or "")

    # ------------------------------------------------------------------
    @staticmethod
    def latest_pair(target_dir: Path | str) -> tuple[Path, Path] | None:
        """找「本轮」与「上一个**确实有结果**的轮次」，供自动 diff 使用。

        归档结构：outputs/<target>/<timestamp>/..._findings.json

        **为什么不能直接取 `runs[-2]`（2026-09-30 真实事故）：**
        扫描被中断时会在归档根下留一个**空目录**（目录已建、结果尚未落盘就退出了）。
        旧实现把「上一轮」定义成「按名字排序的倒数第二个目录」，于是这个空目录
        顶替了真正的上一轮 → `prev_files` 为空 → `return None` →
        报告写「**无历史扫描结果可比对（首次扫描）**」。

        实测：内部生产系统累计 15 轮扫描，只因为中间一轮中途被杀，下一轮就变成了
        「首次扫描」。这个函数是「本轮没再看 ≠ 已修复」口径的**入口**，
        它静默降级会让一次本该有历史对照的扫描伪装成首次 —— 属于本项目
        最忌的那类「不报错、只把话说错」的缺陷。

        所以判据改成：**本轮 = 最新目录且必须已有 findings**；
        **上一轮 = 往前找第一个真正带 findings 的轮次**（空目录 / 未完成的轮次跳过）。
        都找不到，才是真的首次扫描。
        """
        d = Path(target_dir)
        if not d.exists():
            return None
        runs = sorted(
            [p for p in d.iterdir() if p.is_dir()],
            key=lambda p: p.name,
        )
        if not runs:
            return None
        # 本轮必须已经有 findings。调用时机是「报告阶段先落盘、再做比对」；
        # 若此刻没有，宁可返回 None（本轮不比对），也不能拿上一轮当本轮去比 ——
        # 那是自比自，会产出一份「新增 0、仍存在 N」的假比对。
        curr_files = list(runs[-1].glob("*_findings.json"))
        if not curr_files:
            return None
        for cand in reversed(runs[:-1]):
            cand_files = list(cand.glob("*_findings.json"))
            if cand_files:
                return cand_files[0], curr_files[0]
        return None


if __name__ == "__main__":
    print("复扫比对引擎自测")
    print("=" * 70)

    def mk(item_id, title, ep, sev, param=""):
        return Finding(item_id=item_id, target="示例系统", title=title,
                       endpoint=ep, severity=sev, param=param)

    base = FindingSet(target="示例系统")
    base.add(mk("WSTG-CONF-07", "HTTP 安全响应头缺失", "https://a.example.com/", "低危"))
    base.add(mk("WSTG-INFO-02", "服务器组件版本信息泄露", "https://a.example.com/", "低危"))
    base.add(mk("WSTG-CONF-04", "敏感文件可公开访问：.env", "https://a.example.com/.env", "高危"))
    base.add(mk("WSTG-CLNT-11", "CORS 跨域策略配置过宽", "https://api.example.com/", "中危"))
    # 独占端点：本轮没人再报，且没有别的检查项接手 → 唯一可判「已修复」的样本
    base.add(mk("WSTG-ATHN-01", "登录页明文传输口令", "https://sso.example.com/login", "高危"))

    cur = FindingSet(target="示例系统")
    cur.add(mk("WSTG-CONF-07", "HTTP 安全响应头缺失", "https://a.example.com/", "低危"))   # 仍存在
    # WSTG-INFO-02 本轮不再上报，但同端点仍有 WSTG-CONF-07 在报 → 重新归类
    cur.add(mk("WSTG-CONF-04", "敏感文件可公开访问：.env", "https://a.example.com/.env", "中危"))  # 等级下降
    cur.add(mk("WSTG-CLNT-11", "CORS 跨域策略配置过宽", "https://api.example.com/", "中危"))  # 仍存在
    cur.add(mk("WSTG-INPV-05", "SQL 注入", "https://api.example.com/orders", "严重"))       # 新增
    # WSTG-ATHN-01 已修复（移除，且无接手方）

    d = Differ().compare(base, cur)
    print("\n比对结果：")
    for k, v in d.summary().items():
        print(f"  {k}: {v}")

    print("\n" + d.render_markdown()[:1500])

    assert len(d.new) == 1 and d.new[0].item_id == "WSTG-INPV-05"
    assert len(d.fixed) == 1 and d.fixed[0].item_id == "WSTG-ATHN-01", \
        "同端点换检查项上报应记「重新归类」，只有无人接手的才是「已修复」"
    assert len(d.reclassified) == 1 and d.reclassified[0].item_id == "WSTG-INFO-02"
    assert len(d.persisting) == 2
    assert len(d.changed) == 1 and d.changed[0].severity_delta < 0

    # ---- 本轮「没执行」的项不得被记成「已修复」 ----
    d2 = Differ().compare(base, cur, item_states={
        "WSTG-ATHN-01": "未执行",          # 本轮这一项根本没跑
        "WSTG-CONF-07": "通过",
    })
    assert d2.states_loaded
    assert not any(e.item_id == "WSTG-ATHN-01" for e in d2.fixed), \
        "本轮未执行 → 不得记「已修复」（这是把假通过搬到比对层）"
    assert len(d2.unverified) == 1 and d2.unverified[0].item_id == "WSTG-ATHN-01"
    assert d2.summary()["本轮未判定"] == 1 and d2.summary()["已修复"] == 0
    assert "本轮未判定" in d2.render_markdown()
    assert "不得计入「已修复」" in d2.render_markdown()

    # ---- 弱证据 N/A 同样不得被记成「已修复」 ----
    # 弱 N/A 的确切含义是「有限路径探测**没看到**」。若按「N/A」处理，
    # 比对层会把它读成「本轮有结论且没问题」→ 一条历史发现被计成「已修复」，
    # 报告上写着「已修复 1」，实际那一项只是没被看见。这是给客户的假话。
    d3 = Differ().compare(base, cur, item_states={
        "WSTG-ATHN-01": WEAK_NA_STATE,
        "WSTG-CONF-07": "通过",
    })
    assert not any(e.item_id == "WSTG-ATHN-01" for e in d3.fixed), \
        "弱证据 N/A ≠ 确证不具备 → 不得记「已修复」"
    assert len(d3.unverified) == 1 and d3.unverified[0].item_id == "WSTG-ATHN-01", \
        "弱证据 N/A 应落进「本轮未判定」，且要说明成因与「没执行」不同"
    _md3 = d3.render_markdown()
    assert "只做了有限路径探测" in _md3, \
        "弱 N/A 的说明必须写出真实成因（探测过但判据不足），不能写「没有人去看」"
    assert d3.summary()["已修复"] == 0
    # 对照：确证不具备（普通 N/A）仍可支撑「已修复 / 不适用」
    d4 = Differ().compare(base, cur, item_states={"WSTG-ATHN-01": "N/A"})
    assert any(e.item_id == "WSTG-ATHN-01" for e in d4.fixed), \
        "确证不具备（强 N/A）应当支持「已修复 / 不适用」—— 否则这一层永远判不出修复"

    # ---- 两条路径必须产出同一种表示 ----
    # 内存路径（encode_item_states）与归档路径（read_item_states）若不一致，
    # 同一份数据从两条路进来会得到两种结论 —— 那是最难查的一类不一致。
    class _R:
        def __init__(self, iid, state, weak):
            self.item_id, self.state, self.weak_na = iid, state, weak

    _enc = Differ.encode_item_states([_R("A", "N/A", True),
                                      _R("B", "N/A", False),
                                      _R("C", "通过", False)])
    assert _enc == {"A": WEAK_NA_STATE, "B": "N/A", "C": "通过"}, _enc
    import json as _json
    import tempfile as _tmp
    with _tmp.TemporaryDirectory() as _td:
        Path(_td, "检查项结论.json").write_text(_json.dumps(
            {"items": [{"item_id": "A", "state": "N/A", "weak_na": True},
                       {"item_id": "B", "state": "N/A"}]},
            ensure_ascii=False), encoding="utf-8")
        _rd = Differ.read_item_states(Path(_td) / "x.json")
    assert _rd == {"A": WEAK_NA_STATE, "B": "N/A"}, \
        f"归档路径必须产出同一种表示，实得 {_rd} —— 否则两条路会给出两种结论"
    print("✓ 比对层：弱证据 N/A 不得记「已修复」，且内存 / 归档两条路径同表示")
    # 四种「没有结论」都要被挡住
    for st in Differ.NO_CONCLUSION_STATES:
        _r = Differ().compare(base, cur, item_states={"WSTG-ATHN-01": st})
        assert not _r.fixed and len(_r.unverified) == 1, f"{st} 未被挡住"
    # 有结论（通过 / N/A / 不通过）时仍按旧口径判已修复
    for st in ("通过", "N/A", "不通过"):
        _r = Differ().compare(base, cur, item_states={"WSTG-ATHN-01": st})
        assert len(_r.fixed) == 1 and not _r.unverified, f"{st} 不该被改判"
    # 未带结论时如实标注「已修复含未执行风险」
    assert not d.states_loaded and "未取得本轮的检查项结论" in d.render_markdown()

    # ---- latest_pair：空归档目录不得顶替「上一轮」（2026-09-30 真实事故）----
    # 场景就是实测到的那个：内部生产系统 累计 15 轮扫描，中间有一轮扫描被中断
    # （进程随上层会话结束被一并终止），归档根下只留了一个**空目录**。
    # 旧实现把「上一轮」定义成「按名字排序的倒数第二个目录」，空目录顶替了
    # 真正的上一轮 → 返回 None → 通告写「无历史扫描结果可比对（首次扫描）」。
    # 这个函数是「本轮没再看 ≠ 已修复」口径的入口，静默降级后果很大。
    import tempfile as _tp2

    with _tp2.TemporaryDirectory() as _root:
        _rootp = Path(_root)

        def _mk(name: str, with_findings: bool = True) -> Path:
            _d = _rootp / name
            _d.mkdir()
            if with_findings:
                (_d / "T_findings.json").write_text("[]", encoding="utf-8")
            return _d

        _mk("20260930_100000")
        _mk("20260930_110000")
        _mk("20260930_120000")
        _now = _mk("20260930_130000")          # 本轮：报告阶段先落盘，再做比对

        _pr = Differ.latest_pair(_rootp)
        assert _pr is not None, "相邻两轮都有 findings 时必须能配出"
        assert _pr[0].parent.name == "20260930_120000", _pr
        assert _pr[1].parent.name == "20260930_130000", _pr

        _mk("20260930_125000", with_findings=False)   # 被中断那轮留下的空目录
        _pr2 = Differ.latest_pair(_rootp)
        assert _pr2 is not None, (
            "中间夹一个空归档目录（扫描被中断的现场）后不得退化成「首次扫描」"
            "—— 那会让报告写出一句假话，且复扫比对整体失效")
        assert _pr2[0].parent.name == "20260930_120000", _pr2

        # 本轮自己还没有 findings（调用时机不对）→ 宁可 None，
        # 也不能把上一轮当本轮来比（那是自比自，会产出「新增 0」的假比对）
        (_now / "T_findings.json").unlink()
        assert Differ.latest_pair(_rootp) is None, \
            "本轮尚无 findings 时不得拿上一轮当本轮"
        (_now / "T_findings.json").write_text("[]", encoding="utf-8")

        # 真的只有一轮有结果 → 这才是「首次扫描」
        for _p in list(_rootp.iterdir()):
            if _p.name != "20260930_130000":
                for _f in _p.iterdir():
                    _f.unlink()
        assert Differ.latest_pair(_rootp) is None, \
            "只有一轮有结果时报「首次扫描」是对的（不得为了修上面那条而永远不报）"

    print("✓ latest_pair：空归档目录不得顶替上一轮；本轮缺 findings 不得自比自")
    print("✓ 比对逻辑自测通过（新增 / 已修复 / 仍存在 / 等级变化 / "
          "重新归类 / 本轮未判定 均正确识别）")
