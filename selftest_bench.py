# -*- coding: utf-8 -*-
"""靶场：把「漏报率无从测量」变成每次发版可断言的数字
================================================================================

为什么需要它
--------------------------------------------------------------------------------
在《扫描器能力评级》里，「真实环境的漏报率」一直是填不出来的那一栏。
原因是结构性的：**误报能测，漏报不能自知** ——
被证伪的发现（报了但复现不出来）是可见的，可「压根没报出来的东西」没有任何
信号，它不存在于任何日志里。

行业里的标准解法是靶场：造一个**知道答案**的目标，让扫描器去跑，比对答案。
答案清单（bench/ground_truth.yaml）必须独立于被测实现 —— 照着引擎输出填的
清单只会永远 100%，那测的是「引擎是否等于它自己」。

本脚本做三件事
--------------------------------------------------------------------------------
  1. 跑一遍完整的离线自测扫描（复用 selftest_engine，localhost 假应用，零外网）
  2. 把「实际报出了什么」与「假应用里真实埋了什么」逐条比对
  3. 三类结果分开报，绝不混为一谈：
       命中     —— 有归口项且归口项报了发现
       真漏报   —— 有归口项、归口项跑了、就是没发现（能力缺陷）
       能力缺口 —— 清单里没人负责这件事（不是漏报，是压根没这项检查）
                  这类必须显式列出：把它们算成「没问题」是最危险的做法

用法
    python selftest_bench.py                  # 跑靶场，输出检出率
    python selftest_bench.py --keep-dump      # 保留中间检出结果，便于排查
    python selftest_bench.py --list           # 只列基准清单，不跑扫描

退出码
    0 = 所有 critical 条目均检出
    1 = 有 critical 条目未被检出（能力回退，CI 应拦）
    2 = 靶场自身出错（基准文件缺失 / 条目引用了不存在的检查项）
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

BENCH_FILE = ROOT / "bench" / "ground_truth.yaml"
DUMP_NAME = "_bench_detected.json"


def _load_yaml(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        print("靶场需要 PyYAML 解析基准文件（本环境应已随引擎安装）。")
        raise SystemExit(2)


def _checklist_ids() -> set[str]:
    from checklist.loader import load_checklist

    cl = load_checklist()
    items = cl if isinstance(cl, list) else getattr(cl, "items", [])
    out: set[str] = set()
    for it in items:
        iid = getattr(it, "id", None) or (it.get("id") if isinstance(it, dict) else None)
        if iid:
            out.add(str(iid))
    return out


def _run_scan(dump_path: Path, timeout: int) -> None:
    env = dict(os.environ)
    env["AISCAN_BENCH_DUMP"] = str(dump_path)
    env["AISCAN_SQLMAP"] = "off"          # 靶场离线：不拉外部注入工具
    env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "selftest_engine.py")],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    if proc.returncode != 0:
        print("靶场：离线自测未通过，检出率统计失去意义。自测输出尾部：")
        print("\n".join((proc.stdout or "").splitlines()[-25:]))
        raise SystemExit(2)


def _hit(fact: dict, findings: list[dict]) -> tuple[bool, str]:
    """判断某个埋点是否被检出。

    命中条件 = 归口项 ID 命中 **且** 端点关键词命中（未给关键词则只比 ID）。
    只比 ID 会误命中：同一个检查项可能在别的端点上报了别的问题。
    """
    acc = [str(x) for x in (fact.get("acceptable_items") or [])]
    keys = [str(x).lower() for x in (fact.get("endpoint_any") or [])]
    for f in findings:
        if str(f.get("item_id")) not in acc:
            continue
        if keys:
            hay = (str(f.get("endpoint") or "") + " " + str(f.get("title") or "")).lower()
            if not any(k in hay for k in keys):
                continue
        return True, f"{f.get('item_id')} @ {f.get('endpoint') or '（无端点）'}"
    return False, ""


def main() -> int:
    ap = argparse.ArgumentParser(description="内置靶场：标定扫描器检出率 / 漏报率")
    ap.add_argument("--list", action="store_true", help="只列基准清单，不跑扫描")
    ap.add_argument("--keep-dump", action="store_true", help="保留中间检出结果文件")
    ap.add_argument("--timeout", type=int, default=900, help="离线扫描超时（秒）")
    args = ap.parse_args()

    if not BENCH_FILE.exists():
        print(f"靶场基准文件缺失：{BENCH_FILE}")
        return 2
    bench = _load_yaml(BENCH_FILE)
    facts: list[dict] = list(bench.get("facts") or [])
    if not facts:
        print("靶场基准文件里没有任何条目。")
        return 2

    ids = _checklist_ids()
    bad_ref: list[str] = []
    for f in facts:
        for iid in (f.get("acceptable_items") or []):
            if str(iid) not in ids:
                bad_ref.append(f"{f.get('id')} → {iid}")
    if bad_ref:
        print("靶场基准引用了清单里不存在的检查项（会造成「幽灵缺口」，必须修）：")
        for x in bad_ref:
            print("  -", x)
        return 2

    if args.list:
        print(f"靶场基准（{bench.get('version')}）：共 {len(facts)} 条")
        for f in facts:
            tag = "已记账缺口" if f.get("known_gap") else ("门槛项" if f.get("critical") else "观察项")
            own = "、".join(f.get("acceptable_items") or []) or "（无归口）"
            print(f"  [{tag}] {f.get('id')}: {f.get('planted')}")
            print(f"           归口：{own}")
        return 0

    tmp = Path(tempfile.mkdtemp(prefix="aiscan_bench_"))
    dump = tmp / DUMP_NAME
    print("靶场：正在跑完整离线扫描（本地假应用，零外网流量）...")
    _run_scan(dump, args.timeout)
    data = json.loads(dump.read_text(encoding="utf-8"))
    findings = data.get("findings") or []

    hits, misses, gaps, regressions = [], [], [], []
    for f in facts:
        acc = list(f.get("acceptable_items") or [])
        if not acc:
            gaps.append((f, "清单中无归口检查项 —— 属能力缺口，不是漏报"))
            continue
        ok, where = _hit(f, findings)
        if ok:
            hits.append((f, where))
            continue
        if f.get("known_gap"):
            gaps.append((f, "已记账缺口（未纳入回归门槛）"))
        else:
            misses.append((f, "归口项已执行但未报出该事实"))
            if f.get("critical"):
                regressions.append(f)

    denom = len([f for f in facts if (f.get("acceptable_items") or [])])
    rate = (len(hits) / denom) if denom else 0.0

    print()
    print("=" * 74)
    print(f"靶场结果：{bench.get('range')}")
    print("=" * 74)
    print(f"基准条目        ：{len(facts)} 条"
          f"（计入检出率 {denom} 条；无归口 {len(facts) - denom} 条）")
    print(f"命中            ：{len(hits)} 条")
    print(f"真漏报          ：{len(misses)} 条")
    print(f"能力缺口 / 记账 ：{len(gaps)} 条")
    print(f"检出率（召回）  ：{rate:.1%}   漏报率：{1 - rate:.1%}")
    print()

    if hits:
        print(f"── 命中 {len(hits)} ──")
        for f, where in hits:
            print(f"  ✓ {f.get('id'):<22} {where}")
    if misses:
        print()
        print(f"── 真漏报 {len(misses)}（有归口项却没发现，属能力缺陷，必须收口）──")
        for f, why in misses:
            print(f"  ✗ {f.get('id'):<22} {f.get('planted')}")
            print(f"    复核方式：{f.get('witness')}")
            print(f"    未检出原因待查：{why}")
    if gaps:
        print()
        print(f"── 能力缺口 / 已记账 {len(gaps)}（**不得**读成「没问题」）──")
        for f, why in gaps:
            print(f"  ! {f.get('id'):<22} {f.get('planted')}")
            print(f"    {why}" +
                  (f"；{f.get('gap_note')}" if f.get("gap_note") else ""))

    print()
    if regressions:
        print(f"❌ 靶场未通过：{len(regressions)} 个门槛项未被检出 —— "
              f"{'、'.join(str(f.get('id')) for f in regressions)}")
        return 1
    print(f"✅ 靶场通过：{denom} 个门槛项全部检出，检出率 {rate:.1%}"
          f"（已知缺口 {len(gaps)} 条已记账，未计入门槛）")

    if args.keep_dump:
        print(f"中间检出结果：{dump}")
    else:
        try:
            dump.unlink()
            tmp.rmdir()
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
