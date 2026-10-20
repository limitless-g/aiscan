# -*- coding: utf-8 -*-
"""
检测器覆盖率校验
================
这个脚本的存在意义只有一个：**让「漏测」变成一件不可能悄悄发生的事**。

背景：上一版扫描器最大的问题不是检测能力弱，而是报告里出现了 55 项「通过」，
其中 42 项根本没有对应的检测代码 —— 报告看起来一片绿，实际什么都没测。
加了执行状态机之后，「没有检测逻辑」会变成「未执行」，
但还必须有一道机械化的检查，保证清单里的每一项都真的被绑定了执行体。

校验三件事：
  ① 清单里的每一项都有对应的 DetectorSpec（自动或人工）；
  ② 不存在「注册了但清单里没有」的孤儿检测器；
  ③ 每个自动检测器、每个人工项都有可追溯的说明
     （自动项要有 evidence_kind 与 detector_ref，人工项要有 procedure 与 expect）。

用法：
    python validate_coverage.py            # 打印报告
    python validate_coverage.py --strict   # 有缺口时以非零码退出（可挂到 CI）
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from engine.registry import (  # noqa: E402
    DetectorRegistry, MODE_MANUAL, collect_from_modules,
)

DETECTOR_MODULES = [
    "recon", "config", "identity_auth", "authz", "session", "injection",
    "error_crypto", "business", "client", "api", "extras", "extras2",
    "extras3", "extras4",
]


def load_registry() -> DetectorRegistry:
    mods = []
    for name in DETECTOR_MODULES:
        try:
            mods.append(importlib.import_module(f"engine.checks.{name}"))
        except Exception as e:  # noqa: BLE001
            print(f"[错误] 检测器模块 {name} 导入失败：{type(e).__name__}: {e}")
            raise
    reg = DetectorRegistry()
    collect_from_modules(reg, mods)
    return reg


def load_checklist_items() -> list:
    from checklist.loader import load_checklist  # noqa: PLC0415
    return load_checklist()


def main() -> int:
    ap = argparse.ArgumentParser(description="检测器覆盖率校验")
    ap.add_argument("--strict", action="store_true",
                    help="存在缺口时以非零码退出")
    args = ap.parse_args()

    reg = load_registry()
    items = load_checklist_items()
    all_ids = [it.id for it in items]

    covered, missing = reg.coverage(all_ids)
    orphan = sorted(set(reg.specs.keys()) - set(all_ids))

    print("=" * 68)
    print("检测器覆盖率校验")
    print("=" * 68)
    print(f"检查清单条目数        ：{len(all_ids)}")
    print(f"已绑定执行体          ：{len(covered)}")
    print(f"未绑定（缺口）        ：{len(missing)}")
    print(f"孤儿检测器（无对应项）：{len(orphan)}")

    stats = reg.stats()
    print(f"  其中 自动检测器      ：{stats.get('自动检测器', 0)}")
    print(f"       人工执行指引    ：{stats.get('人工执行指引', 0)}")

    problems: list[str] = []

    if missing:
        print("\n【缺口】以下检查项目前没有绑定任何执行体，"
              "在执行时会落到「未执行」：")
        by_cat: dict[str, list[str]] = {}
        id2item = {it.id: it for it in items}
        for mid in missing:
            it = id2item.get(mid)
            cat = f"{it.category} {it.category_name}" if it else "未知分类"
            by_cat.setdefault(cat, []).append(
                f"{mid}  {it.name if it else ''}")
        for cat, rows in by_cat.items():
            print(f"  · {cat}")
            for r in rows:
                print(f"      - {r}")
        problems.append(f"{len(missing)} 项检查未绑定执行体")

    if orphan:
        print("\n【孤儿】以下检测器绑定了清单里不存在的 ID，可能是 ID 写错：")
        for oid in orphan:
            print(f"  - {oid}  ← {reg.specs[oid].detector_ref}")
        problems.append(f"{len(orphan)} 个检测器绑定到不存在的检查项")

    # ---- 说明完整性校验 ----
    thin_auto, thin_manual = [], []
    for item_id in covered:
        spec = reg.specs[item_id]
        if spec.mode == MODE_MANUAL:
            if not spec.procedure or not spec.expect or not spec.why_manual:
                thin_manual.append(item_id)
        else:
            if not spec.evidence_kind:
                thin_auto.append(item_id)

    if thin_auto:
        print("\n【说明缺失·自动项】以下自动检测器没有声明证据类型（evidence_kind），"
              "报告里无法说明「这项结论是怎么得出的」：")
        for i in thin_auto:
            print(f"  - {i}  {reg.specs[i].name}")
        problems.append(f"{len(thin_auto)} 个自动检测器缺少证据类型说明")

    if thin_manual:
        print("\n【说明缺失·人工项】以下人工项没有写全执行步骤 / 判定标准 / 不能自动化的原因：")
        for i in thin_manual:
            print(f"  - {i}  {reg.specs[i].name}")
        problems.append(f"{len(thin_manual)} 个人工项说明不完整")

    # ---- 业务逻辑类人工项必须有自动前置侦察 ----
    #
    # 这一条是专门为「业务逻辑全靠人工」这个盲区加的闸门。
    # 业务逻辑项的判定前提是业务语义，人工执行本身是对的；但如果连
    # 「找接口、找字段、记当前值」这些准备活也一并推给人，就等于把
    # 最枯燥的部分留给了唯一没有工具的人。加了侦察之后人工只剩判断。
    #
    # 所以对 BUSL 分类：每个手动项**要么**挂了 recon，
    # **要么**显式写明 recon_gap（为什么连前置侦察都做不了）。
    # 两者都没有 = 这一项在悄悄退回「全人工」，必须让它在 CI 里报出来。
    #
    # ATHN / SESS / CRYPT 同理（2026-09-21 扩围）：认证、会话、加密这三类的
    # 人工项同样是「找登录入口 / 找改密表单 / 找密文参数」这类活占了大头，
    # 真正只有人能回答的只有最后那一句判断。若不给它们挂侦察，
    # 「人工除了复测之外不用再投入精力」这个目标就落不了地。
    GATED_CATEGORIES = ("BUSL", "ATHN", "SESS", "CRYP")
    id2item = {it.id: it for it in items}
    no_recon: list[str] = []
    warn_recon: list[str] = []
    for item_id in covered:
        spec = reg.specs[item_id]
        if spec.mode != MODE_MANUAL:
            continue
        if spec.recon is not None or spec.recon_gap:
            continue
        it = id2item.get(item_id)
        cat = (getattr(it, "category", "") or "") if it is not None else ""
        if cat in GATED_CATEGORIES:
            no_recon.append(item_id)
        else:
            # 其余分类暂只提示、不拦 CI —— 把它们一次性铺开容易写成凑数的
            # 「侦察」，反而比没有更坏。但必须让它可见，不能静默。
            warn_recon.append(f"{item_id}（{cat or '未分类'}）")

    if no_recon:
        print("\n【认证 / 会话 / 加密·无前置侦察】以下人工项既没有挂自动侦察，"
              "也没有说明为什么做不了 —— 它们会退回「从零开始全人工」：")
        for i in no_recon:
            print(f"  - {i}  {reg.specs[i].name}")
        problems.append(f"{len(no_recon)} 个人工项缺少前置侦察"
                        f"（{'/'.join(GATED_CATEGORIES)} 分类）")

    if warn_recon:
        print("\n【提示·其他分类人工项暂无前置侦察】不致失败，但请排期补齐"
              f"（共 {len(warn_recon)} 项）：")
        for w in warn_recon:
            print(f"  · {w}")

    recon_n = sum(1 for s in reg.specs.values() if s.recon is not None)
    print(f"\n前置侦察覆盖          ：{recon_n} 项已挂自动侦察"
          f"（门控分类：{'/'.join(GATED_CATEGORIES)}）")

    print("\n" + "=" * 68)
    if not problems:
        print("结果：通过。清单全部条目均已绑定执行体，说明字段完整。")
        print("=" * 68)
        return 0

    print("结果：不通过。")
    for p in problems:
        print(f"  ✗ {p}")
    print("=" * 68)
    return 1 if args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
