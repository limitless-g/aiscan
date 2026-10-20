# -*- coding: utf-8 -*-
"""Juice Shop 实测召回率计分器。

对照 bench/juice_ground_truth.yaml（答案表，独立于被测实现，红线 30）
核某次扫描归档的「检查项结论.json」，按红线 31 的三分类输出：
  命中 / 真漏报 / 能力缺口 —— 三分类不许合并。

用法：
  python bench/juice_score.py <归档目录>
  python bench/juice_score.py outputs/JuiceShop基准/20261009_101443
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
GT_PATH = ROOT / "bench" / "juice_ground_truth.yaml"

# 答案表里参与计分的判定（na = 量程之外，不进分母）
SCOPED_VERDICTS = ("auto", "semi", "manual", "gap")


def load_scan_states(archive: Path) -> dict:
    f = archive / "检查项结论.json"
    if not f.exists():
        sys.exit(f"归档里没有 检查项结论.json：{f}")
    data = json.loads(f.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("items", data.get("results", []))
    return {i["item_id"]: i for i in items}


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("用法：python bench/juice_score.py <扫描归档目录>")
    archive = Path(sys.argv[1])
    states = load_scan_states(archive)
    facts = yaml.safe_load(GT_PATH.read_text(encoding="utf-8"))["facts"]

    scoped = [f for f in facts if f["verdict"] in SCOPED_VERDICTS]
    na = [f for f in facts if f["verdict"] == "na"]
    assert len(scoped) + len(na) == len(facts), "verdict 取值越界，答案表被改坏了"

    hits, misses, gaps = [], [], []
    for f in scoped:
        # 命中判据：归口项里任意一项状态为「不通过」（= 检出了问题）
        hit_by = [
            iid for iid in f["acceptable_items"]
            if states.get(iid, {}).get("state") == "不通过"
        ]
        if hit_by:
            hits.append((f, hit_by))
        elif f["verdict"] == "gap":
            gaps.append(f)
        else:
            misses.append((f, f["verdict"]))

    n = len(scoped)
    print("=" * 64)
    print("Juice Shop 实测召回率（对照官方 116 条答案表）")
    print("=" * 64)
    print(f"归档：{archive}")
    print(f"官方挑战总数：{len(facts)}；量程之外(na)：{len(na)}；真分母：{n}")
    print()
    print(f"  命中        {len(hits):3d} / {n}   召回率 {len(hits)/n*100:.1f}%")
    print(f"  真漏报      {len(misses):3d} / {n}")
    print(f"  能力缺口    {len(gaps):3d} / {n}   （清单无此项，红线 14 单列）")
    print()

    by_verdict = {}
    for f, _ in hits:
        by_verdict.setdefault(f["verdict"], [0, 0])[0] += 1
    for f, v in misses:
        by_verdict.setdefault(v, [0, 0])[1] += 1
    for f in scoped:
        if f["verdict"] != "gap":
            by_verdict.setdefault(f["verdict"], [0, 0])
    total_by_verdict = {}
    for f in scoped:
        total_by_verdict[f["verdict"]] = total_by_verdict.get(f["verdict"], 0) + 1
    print("按判定层级拆分（命中/总数）：")
    for v in ("auto", "semi", "manual", "gap"):
        h = by_verdict.get(v, [0, 0])[0]
        t = total_by_verdict.get(v, 0)
        print(f"  {v:7s} {h:3d} / {t}")
    print()

    print("【命中明细】")
    for f, hit_by in hits:
        print(f"  ✓ {f['name'][:40]:40s} [{f['verdict']}] 由 {'/'.join(hit_by)}")
    print()
    print("【真漏报明细】（有检测体但没检出来 —— 改进对象）")
    for f, v in misses:
        items = "/".join(f["acceptable_items"]) or "-"
        states_str = ",".join(
            f"{iid}:{states.get(iid, {}).get('state', '无记录')}"
            for iid in f["acceptable_items"]
        )
        print(f"  ✗ {f['name'][:36]:36s} [{v}] 归口 {items}（{states_str}）")
    print()
    print("【能力缺口】（清单里没有检测体 —— 不是漏报，是还没做）")
    for f in gaps:
        print(f"  ○ {f['name'][:40]:40s} — {f['because'][:50]}")


if __name__ == "__main__":
    main()
