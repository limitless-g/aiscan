# -*- coding: utf-8 -*-
"""
全局硬约束执行体自测（hard_limits）
==================================

`config/profiles.yaml` 的 `hard_limits` 长期只有「打印 forbidden_always」一个
读取点，`rate_ceiling_rps` / `stop_on` 以及档位里的 `per_host_rps` /
`delay_between_items_ms` 在代码里**零读取点**。这不是「少了一个功能」，
而是**虚假保证**：配置的措辞让操作者以为有兜底，实际扫描器不会照做。

本自测存在的目的就是**把「真有执行体」这件事钉死**：每个字段都要有一条
断言证明它被读到、并且真的改变了行为。只写实现不加这里的断言，
下一个改动完全可能把它悄悄摘掉而没人发现。

覆盖：
  ① `rate.per_host_rps`            → engine/fingerprint.py `_throttle`
  ② `hard_limits.rate_ceiling_rps` → engine/orchestrator.py `_apply_hard_limits`
  ③ `rate.delay_between_items_ms`  → engine/registry_runner.py `_item_gap_seconds`
  ④ `hard_limits.stop_on`          → engine/banguard.py `TargetHealthWatch`
     （并断言其短路措辞与「被边界拦截」**严格区分** —— 措辞互换就是写假话）

用法：
    python selftest_hardlimits.py
退出码 0 = 全部断言通过。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FAILS: list[str] = []
CHECKS = 0


def check(cond: bool, label: str) -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  ✓ {label}")
    else:
        print(f"  ✗ {label}")
        FAILS.append(label)


# ======================================================================
def ring_per_host_rps() -> None:
    print("\n① 单主机限速 per_host_rps（此前零读取点）")
    from engine.fingerprint import HttpProbeClient, _host_of

    check(_host_of("https://a.com/x") == "a.com:443", "https 默认端口补 443")
    check(_host_of("http://a.com/x") == "a.com:80", "http 默认端口补 80")
    check(_host_of("https://A.COM:443/y?z=1") == "a.com:443",
          "大小写/显式端口归一化到同一个键（否则单主机限速被成倍放宽）")
    check(_host_of("") == "", "空 URL 返回空键（不参与单主机通道，避免除零）")

    c = HttpProbeClient({"rate": {"requests_per_second": 100, "per_host_rps": 4}})
    check(c.per_host_rps == 4.0, "字段真的被读进客户端（零读取点已补齐）")
    c._throttle("https://h.test/1")
    t0 = time.time()
    c._throttle("https://h.test/2")
    gap = time.time() - t0
    check(abs(gap - 0.25) < 0.08, f"同主机两次请求间隔 ≈1/4s（实测 {gap:.3f}s）")

    c2 = HttpProbeClient({"rate": {"requests_per_second": 100, "per_host_rps": 4}})
    c2._throttle("https://h1.test/")
    t0 = time.time()
    c2._throttle("https://h2.test/")
    gap2 = time.time() - t0
    check(gap2 < 0.02, f"不同主机之间不受单主机约束（实测 {gap2:.4f}s）")

    # 单主机通道是**叠加**在全局限速之上，不是替代它
    c3 = HttpProbeClient({"rate": {"requests_per_second": 5, "per_host_rps": 0}})
    c3._throttle("https://g.test/")
    t0 = time.time()
    c3._throttle("https://g.test/")
    check(time.time() - t0 > 0.15, "per_host_rps=0 时全局限速照常生效（两者并存）")


# ======================================================================
def ring_rate_ceiling() -> None:
    print("\n② 速率硬上限 rate_ceiling_rps（此前零读取点）")
    from engine.orchestrator import Orchestrator

    o = Orchestrator(profile="deep")
    check(o.rate_ceiling_rps == 200, f"读到硬上限（实得 {o.rate_ceiling_rps}）")
    check(o.profile["rate"]["requests_per_second"] == 100,
          "deep 档 100 rps 未超上限，不该被削")
    check(o._rate_ceiling_clamp == "",
          "未发生收敛时留痕必须为空（否则就是给正常扫描放假告警）")

    o.profile["rate"]["requests_per_second"] = 999
    o.profile["rate"]["per_host_rps"] = 500
    o.profile["nuclei"]["rate_limit"] = 800
    o._rate_ceiling_clamp = ""
    o._apply_hard_limits()
    check(o.profile["rate"]["requests_per_second"] == 200, "全局速率收敛到上限")
    check(o.profile["rate"]["per_host_rps"] == 200, "单主机速率收敛到上限")
    check(o.profile["nuclei"]["rate_limit"] == 200,
          "nuclei 通道同样受约束（否则一条通道合规、另一条绕过硬上限）")
    check("requests_per_second 999→200" in o._rate_ceiling_clamp,
          "收敛留痕含字段与前后值（报告要能说出收敛了什么）")
    check("nuclei.rate_limit" in o._rate_ceiling_clamp, "nuclei 收敛也留痕")


# ======================================================================
def ring_item_gap() -> None:
    print("\n③ 项间强制间隔 delay_between_items_ms（此前零读取点）")
    from engine.registry_runner import _item_gap_seconds

    class _Ctx:
        def __init__(self, ms):
            self.profile = {"rate": {"delay_between_items_ms": ms}}

    check(_item_gap_seconds(_Ctx(200)) == 0.2, "安全档 200ms → 0.2s")
    check(_item_gap_seconds(_Ctx(50)) == 0.05, "标准档 50ms → 0.05s")
    check(_item_gap_seconds(_Ctx(0)) == 0.0, "深度档 0 → 不间隔")
    check(_item_gap_seconds(_Ctx(None)) == 0.0, "字段缺失 → 不间隔（且不崩）")


# ======================================================================
def ring_stop_on() -> None:
    print("\n④ 停止条件 stop_on（此前零读取点）")
    from engine.banguard import HEALTH_5XX_STREAK, TargetHealthWatch
    from engine.registry import DetectorContext
    from engine.registry_runner import build_registry
    from checklist.loader import load_checklist

    reg = build_registry()
    item_by_id = {it.id: it for it in load_checklist()}

    # 先让这些地址成为「已知正常」（本轮至少返回过一次非 5xx）。
    # 故障判据只认**本来正常**的地址开始报错：目录枚举打到不存在的路径
    # 返 500 是预期噪声（2026-10-10 第 15 轮因此整轮作废），不入判据。
    h = TargetHealthWatch()
    for i in range(HEALTH_5XX_STREAK):
        h.note_response(f"https://k.test/p{i}", 200)
    for i in range(HEALTH_5XX_STREAK):
        h.note_response(f"https://k.test/p{i}", 500)
    check(h.terminal, "连续 5xx 触发停手终态")
    # 反证：首次枚举到的路径返 5xx 不得停手（否则每次枚举都会停）
    h0 = TargetHealthWatch()
    for i in range(50):
        h0.note_response(f"https://k.test/guess{i}", 500)
    check(not h0.terminal, "枚举噪声（首次见到的路径 5xx）不得触发停手")
    check(h0.noise_5xx == 50, "枚举噪声必须被如实计数而不是当作故障")

    ctx = DetectorContext(target_name="t", domain="k.test",
                          target_url="https://k.test")
    h.mark_unexecutable(ctx)
    check("target_unhealthy" in ctx._cache, "停手事实写入**独立**通道")
    check("boundary_block" not in ctx._cache,
          "不得写进 boundary_block（两者报告措辞不同，混用即写假话）")

    needs_app = [(sid, sp) for sid, sp in reg.specs.items()
                 if getattr(sp, "needs_app", False)
                 and not getattr(sp, "is_manual", False)]
    check(bool(needs_app), f"注册表里有需要应用的项（{len(needs_app)} 个）")
    if needs_app:
        sid, _sp = needs_app[0]
        res = reg.execute(item_by_id[sid], ctx, applicability_state="适用")
        check(res.state == "未执行", f"{sid} 被短路成「未执行」（实得 {res.state}）")
        check("目标应用正常响应" in res.note,
              "措辞为「需要目标应用正常响应」—— 与「请求未到达应用」区分开")
        check("未到达" not in res.note,
              "**不得**出现「未到达」字样（那是被拦截的措辞，用在这里就是写假话）")
        check("立即停手" in res.note, "说清是主动停手、不做等待重试")
        check("不得据此认为该项通过" in res.note, "禁止把「未执行」读成「通过」")

        # 对照组：被拦截仍应写「未到达应用」，且两者措辞必须不同
        ctx2 = DetectorContext(target_name="t", domain="k.test",
                               target_url="https://k.test")
        ctx2._cache["boundary_block"] = {"reason": "被 WAF 拦了",
                                         "kind": "mid_scan_ban"}
        res2 = reg.execute(item_by_id[sid], ctx2, applicability_state="适用")
        check("未到达应用" in res2.note, "对照组：被拦截仍写「未到达应用」")
        check(res2.note != res.note,
              "两种成因措辞必须不同（否则研发会去查错方向）")

    # 不需要经过应用的项仍应照常执行 —— 否则会丢掉非应用层证据
    # （2026-09-30 就是这么丢掉 OSS 匿名列举那条已确认严重漏洞的）
    not_app = [(sid, sp) for sid, sp in reg.specs.items()
               if not getattr(sp, "needs_app", True)]
    check(bool(not_app), f"注册表里有不经过应用的项（{len(not_app)} 个）")
    if not_app:
        sid2, _sp2 = not_app[0]
        res3 = reg.execute(item_by_id[sid2], ctx, applicability_state="适用")
        check("目标应用正常响应" not in (res3.note or ""),
              f"{sid2}（不经过应用）不被停手短路 —— 否则会丢掉非应用层证据")


# ======================================================================
def main() -> int:
    print("=" * 74)
    print("全局硬约束执行体自测（hard_limits）")
    print("=" * 74)
    ring_per_host_rps()
    ring_rate_ceiling()
    ring_item_gap()
    ring_stop_on()
    print()
    if FAILS:
        print(f"失败 {len(FAILS)}/{CHECKS}：")
        for x in FAILS:
            print(f"  - {x}")
        return 1
    print(f"全部通过（{CHECKS} 项断言）")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
