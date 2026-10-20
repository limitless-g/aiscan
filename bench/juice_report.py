#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
juice_report.py —— 把 juice_ground_truth.yaml 变成一张能读的能力账本。

它回答两个问题，并且**只回答这两个**：
    1. Juice Shop 官方 116 条里，有多少落在黑盒 HTTP 扫描器的量程之内？
    2. 量程之内的那些，aiscan 的能力上界到哪、缺口在哪？

它**不产出任何「已命中/已检出」的数字**。召回率只有实跑才能得到
（红线 1：通过只能来自真实执行；红线 30：召回率只能靠带答案的靶场测）。
本脚本输出的是「-static capability mapping-」—— 静态能力映射的上界，
把话说明白：上界 ≥ 实测，中间差的那一截叫「还没证明」。

用法:
  python bench/juice_report.py
  python bench/juice_report.py --md bench/juice_capability.md
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GT = ROOT / "bench" / "juice_ground_truth.yaml"

ORDER = ["auto", "semi", "manual", "gap", "na"]
LABEL = {
    "auto": "能力强上界（黑盒可自动）",
    "semi": "需前置条件（账号/写/渲染/OOB）",
    "manual": "只能人工项",
    "gap": "能力缺口（清单无该项）",
    "na": "量程之外（白盒/OSINT/Web3/DoS/非漏洞）",
}


def _known_items() -> set:
    """163 项清单里的真实 id —— 用来校验 ground truth 里有没有写错 item id。

    写错一个 id 的后果是：这条专题永远匹配不上任何产出，被算成「引擎漏报」。
    这是最隐蔽的一种失真，必须 mechanized checking。
    """
    from checklist.loader import load_checklist
    cl = load_checklist()
    return {it.id for it in cl.items}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--md", default="")
    args = ap.parse_args()

    gt = yaml.safe_load(GT.read_text(encoding="utf-8"))
    facts = gt.get("facts", [])

    # ---- 硬校验①：归口项必须是清单里真实存在的 id ----
    known = _known_items()
    bad_ids = collections.defaultdict(list)
    for f in facts:
        for i in (f.get("acceptable_items") or []):
            if i not in known:
                bad_ids[i].append(f.get("name"))
    if bad_ids:
        print("[X] ground truth 里写了清单中不存在的检查项 id（会被误判成漏报）：")
        for i, names in sorted(bad_ids.items()):
            print(f"    {i}  ← {', '.join(names[:3])}")
        return 3

    cnt = collections.Counter(f["verdict"] for f in facts)
    total = len(facts)
    in_scope = sum(cnt[v] for v in ("auto", "semi", "manual", "gap"))

    # ---- 硬校验②：每个 verdict 都必须有 because，不许有无依据的判定 ----
    no_reason = [f["name"] for f in facts
                 if not (f.get("because") or "").strip()]
    if no_reason:
        print("[X] 以下条目没有写判定依据，不许进答案表：")
        for n in no_reason[:10]:
            print("    -", n)
        return 4

    lines = []
    lines.append("Juice Shop × aiscan 静态能力映射")
    lines.append("=" * 78)
    lines.append(f"官方挑战总数            : {total}  (源 sha256 {gt.get('source_sha256','')[:12]})")
    lines.append(f"黑盒量程之内（分母）    : {in_scope}  ({in_scope/total:.1%})")
    lines.append(f"量程之外（不计分母）    : {cnt['na']}  ({cnt['na']/total:.1%})")
    lines.append("")
    lines.append(f"{'判定':<8}{'数量':>6}{'占总量':>9}   含义")
    lines.append("-" * 78)
    for v in ORDER:
        if cnt[v] == 0:
            continue
        lines.append(f"{v:<8}{cnt[v]:>6}{cnt[v]/total:>8.1%}   {LABEL[v]}")
    lines.append("")

    upper = cnt["auto"]
    lines.append(f"能力上界（auto）        : {upper} / {in_scope} = {upper/in_scope:.1%}"
                 f"   ← 这是天花板，不是命中数")
    lines.append(f"能力缺口（gap）         : {cnt['gap']} / {in_scope} = {cnt['gap']/in_scope:.1%}"
                 f"   ← 清单里没人负责，需显式列出")
    lines.append("")

    # ---- 按类别的分布 ----
    lines.append("按官方类别分布（na 单独列，便于看出哪些类别整体在量程外）")
    lines.append("-" * 78)
    by_cat = collections.defaultdict(collections.Counter)
    for f in facts:
        by_cat[f["category"]][f["verdict"]] += 1
    lines.append(f"{'类别':<30}{'总':>4}{'auto':>6}{'semi':>6}{'man':>5}{'gap':>5}{'na':>5}")
    for cat, c in sorted(by_cat.items(), key=lambda kv: -sum(kv[1].values())):
        lines.append(f"{cat:<30}{sum(c.values()):>4}{c['auto']:>6}{c['semi']:>6}"
                     f"{c['manual']:>5}{c['gap']:>5}{c['na']:>5}")
    lines.append("")

    # ---- 逐条明细 ----
    for v in ORDER:
        group = [f for f in facts if f["verdict"] == v]
        if not group:
            continue
        lines.append(f"【{v}】{LABEL[v]}  —— {len(group)} 条")
        lines.append("-" * 78)
        for f in sorted(group, key=lambda x: (-x["difficulty"], x["name"])):
            items = ",".join(f.get("acceptable_items") or []) or "—无归口—"
            lines.append(f"  · {f['name']}  (难度{f['difficulty']}, {f['category']})")
            lines.append(f"      归口: {items}")
        lines.append("")

    text = "\n".join(lines)
    print(text)

    if args.md:
        p = pathlib.Path(args.md)
        if not p.is_absolute():
            p = ROOT / p
        p.write_text(text, encoding="utf-8")
        print(f"\n[OK] 已写出 {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
