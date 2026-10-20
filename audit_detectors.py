# -*- coding: utf-8 -*-
"""检测器强度审计。

回答一个覆盖率校验回答不了的问题：

   全量检查项都「绑定」了执行体，但每个执行体到底发出了多少请求？
    有没有「一次请求都没发、却报通过」的项？

probes 字段由 DetectorContext 逐次累加，是「真的测了」的硬凭据。
本脚本跑一遍离线靶场，把每项的 (状态, 探测数, 证据类型) 打出来，
并把 probes==0 且状态为「通过 / 不通过」的项单列 —— 这类项虽然登记了
检测器，但检测过程可能没有触达目标，是残余假阴性的主要来源。

用法：
    python audit_detectors.py               # 汇总
    python audit_detectors.py --zero        # 只列零探测项
    python audit_detectors.py --json out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import selftest_engine as S  # noqa: E402
from checklist.loader import load_checklist  # noqa: E402
from engine.fingerprint import HttpProbeClient  # noqa: E402
from engine.registry import MODE_AUTO, STATE_FIND, STATE_MANUAL, STATE_NA, STATE_PASS  # noqa: E402
from engine.registry_runner import build_context, build_registry, run_all_items  # noqa: E402

# 静态分析类检测器不自己发请求，它们分析的是已采集的前端产物 / 页面内容。
# 对这类检测器，probes=0 是正常的；判断它们是否"空转"要看数据源是否为空。
STATIC_KINDS = ("前端产物", "静态", "特征分析", "清单", "内容特征",
                "版本与情报", "依赖", "凭据特征", "语法", "代码")


def is_static(evidence_kind: str) -> bool:
    return any(k in (evidence_kind or "") for k in STATIC_KINDS)


def main() -> int:
    ap = argparse.ArgumentParser(description="检测器强度审计")
    ap.add_argument("--zero", action="store_true", help="只列零探测项")
    ap.add_argument("--json", default="", help="把逐项审计结果写入 JSON")
    args = ap.parse_args()

    srv, port = S.start_app()
    target_url = f"http://127.0.0.1:{port}"
    S.patch_network("127.0.0.1")

    checklist = load_checklist()
    app = S.all_applicable(checklist)
    client = HttpProbeClient({"rate": {"timeout_seconds": 5, "requests_per_second": 500}})

    js_result: dict = {}
    try:
        from engine.js_analyzer import JsAnalyzer  # noqa: PLC0415

        jr = JsAnalyzer(client).analyze(target_url)
        js_result = {
            "urls": list(jr.urls),
            "components": list(jr.components),
            "bodies": list(jr.bodies),
            "inline_scripts": list(jr.inline_scripts),
        }
    except Exception as e:  # noqa: BLE001
        print(f"[警告] JS 分析失败：{type(e).__name__}: {e}")

    ctx = build_context(
        target_name="审计目标", domain="127.0.0.1", target_url=target_url,
        profile={"_key": "deep", "risk_level": "deep", "write_verification": "controlled"},
        profile_key="deep", fp_result={"path_probes": {}}, js_result=js_result,
        nuclei_findings=[], accounts=[{"name": "u1"}, {"name": "u2"}], client=client,
    )

    try:
        results, _ = run_all_items(checklist, app, ctx)
    finally:
        srv.shutdown()

    reg = build_registry()
    rows = []
    for r in results:
        spec = reg.get(r.item_id)
        rows.append({
            "item_id": r.item_id,
            "category": r.item_id.split("-")[1] if r.item_id.startswith("WSTG") else "EXT",
            "state": r.state,
            "mode": (spec.mode if spec else ""),
            "probes": r.probes,
            "evidence_kind": (spec.evidence_kind if spec else ""),
            "executable": r.executable,
            "risk": (spec.risk if spec else ""),
            "note": (r.note or "")[:120],
        })

    if args.json:
        Path(args.json).write_text(json.dumps(rows, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print(f"逐项审计已写入 {args.json}")

    auto = [r for r in rows if r["mode"] == MODE_AUTO]
    manual = [r for r in rows if r["mode"] != MODE_AUTO]

    # 依赖的数据源是否为空 —— 静态类检测器在空数据上跑出「通过」，等于没测
    src_empty = not (js_result.get("bodies") or js_result.get("inline_scripts")
                     or js_result.get("urls"))

    # 零探测：登记了自动检测器，但探测数为 0
    zero = [r for r in auto if r["probes"] == 0 and not is_static(r["evidence_kind"])]
    # 零探测却给出实质结论（通过 / 不通过）—— 最危险的一类
    zero_conclusive = [r for r in zero if r["state"] in (STATE_PASS, STATE_FIND)]
    # 静态类检测器：数据源为空却仍给出实质结论
    blind_static = [r for r in auto
                    if is_static(r["evidence_kind"]) and src_empty
                    and r["state"] in (STATE_PASS, STATE_FIND)]

    print()
    print("=" * 74)
    print("检测器强度审计")
    print("=" * 74)
    print(f"检查项总数            ：{len(rows)}")
    print(f"  自动检测器          ：{len(auto)}")
    print(f"  人工执行指引        ：{len(manual)}")
    print()

    state_cnt = Counter(r["state"] for r in rows)
    print("状态分布：")
    for k, v in state_cnt.most_common():
        print(f"  {k:<12} {v:>4}")
    print()

    dynamic = [r for r in auto if not is_static(r["evidence_kind"])]
    static = [r for r in auto if is_static(r["evidence_kind"])]

    print(f"自动检测器探测总数    ：{sum(r['probes'] for r in auto)} 次")
    print(f"  实测类检测器        ：{len(dynamic)}（要求探测数 > 0）")
    print(f"  静态分析类检测器    ：{len(static)}（分析已采集产物，要求数据源非空）")
    if auto:
        vals = sorted(r["probes"] for r in auto)
        print(f"  单检测器 中位数     ：{vals[len(vals) // 2]} 次")
        print(f"  单检测器 最大       ：{vals[-1]} 次")
        print(f"  实测类中已发请求    ：{len(dynamic) - len(zero)} / {len(dynamic)}")
    print()

    if zero:
        # 零探测但已明确报 N/A / 待确认 = 结论诚实，不是缺陷；
        # 零探测却报通过 / 不通过 = 缺陷（没测却下了结论）。
        zero_ok = [r for r in zero if r["state"] not in (STATE_PASS, STATE_FIND)]
        if zero_conclusive:
            print(f"[!] 零探测却仍下结论的实测类检测器 {len(zero_conclusive)} 项：")
            for r in zero_conclusive:
                print(f"    {r['item_id']:<16} {r['state']:<8} 证据={r['evidence_kind']}")
            print()
        if zero_ok:
            print(f"[i] 零探测但已明确报 N/A / 待确认的 {len(zero_ok)} 项"
                  f"（结论诚实，非缺陷）：")
            for r in zero_ok:
                print(f"    {r['item_id']:<16} {r['state']:<8} 证据={r['evidence_kind']}")
            print()
        if not zero_conclusive and not zero_ok:
            print()
    else:
        print("[OK] 所有实测类检测器均发出了至少 1 次请求。")
        print()

    if blind_static:
        print(f"[!] 盲测的静态类检测器 {len(blind_static)} 项"
              f"（数据源为空却仍下结论）：")
        for r in blind_static:
            print(f"    {r['item_id']:<16} {r['state']:<8} 证据={r['evidence_kind']}")
        print()
    else:
        print("[OK] 静态类检测器的数据源非空。")
        print()

    print("证据类型分布（自动检测器）：")
    for k, v in Counter(r["evidence_kind"] or "(未标注)" for r in auto).most_common():
        print(f"  {k:<24} {v:>4}")
    print()

    by_cat: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        by_cat[r["category"]][r["state"]] += 1
    print("按分类的状态分布：")
    for cat, c in sorted(by_cat.items()):
        detail = "  ".join(f"{k}={v}" for k, v in c.most_common())
        print(f"  {cat:<10} {detail}")
    print()

    if args.zero:
        print("零探测检测器 ID：")
        print(" ".join(r["item_id"] for r in zero))
        print()

    print("=" * 74)
    print(f"结论：{len(auto)} 个自动检测器（实测 {len(dynamic)} / 静态 {len(static)}），"
          f"探测 {sum(r['probes'] for r in auto)} 次")
    print(f"      零探测的实测类 {len(zero)} 项（其中 {len(zero_conclusive)} 项仍给出实质结论）；"
          f"盲测的静态类 {len(blind_static)} 项")
    print("=" * 74)

    # 零探测却给结论 / 盲测 = 必须修的缺陷，非零退出以便挂 CI
    return 1 if (zero_conclusive or blind_static) else 0


if __name__ == "__main__":
    import contextlib

    sys.exit(main())
