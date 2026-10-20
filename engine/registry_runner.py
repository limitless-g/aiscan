# -*- coding: utf-8 -*-
"""
逐项检测执行器
==============
把「全量检查项清单」和「已注册的检测器」对接起来，逐项跑出明确结论。

这是整个扫描器的收口环节。核心约束只有一条：

    **任何一项的结论，都必须来自一次真实执行或一次明确的人工指派，
     不允许因为「没有代码」而默认变成「通过」。**

历史上出问题的地方正是这里：报告层用「适用且无发现 = 通过」来算结论，
于是 42 项根本没有检测代码的检查项在报告里显示为绿色通过。
现在结论由 DetectorRegistry 给出，没有绑定执行体就是「未执行」。

另一个职责是把检测器产出的 Finding 汇总、去重后交给定级层，
避免「同一个问题被新旧两套检测器各报一次」。
"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.applicability import ApplicabilityResult  # noqa: E402
from engine.registry import (  # noqa: E402
    DetectorContext, DetectorRegistry, ItemResult, RISK_SAFE, RISK_STANDARD,
    RISK_DEEP, collect_from_modules, STATE_MANUAL,
)
from models import Finding  # noqa: E402

# 检测器模块清单。新增模块必须登记到这里，
# 否则 validate_coverage.py 会报缺口、报告里会出现「未执行」。
DETECTOR_MODULES = [
    "recon",           # WSTG-INFO 信息收集 10 项
    "config",          # WSTG-CONF 配置部署 15 项
    "identity_auth",   # WSTG-IDNT / ATHN 身份与认证 16 项
    "authz",           # WSTG-ATHZ 授权 5 项
    "session",         # WSTG-SESS 会话 11 项
    "injection",       # WSTG-INPV 输入验证 23 项
    "error_crypto",    # WSTG-ERRH / CRYP 5 项
    "business",        # WSTG-BUSL 业务逻辑 10 项
    "client",          # WSTG-CLNT 客户端 15 项
    "api",             # WSTG-APIT / WASM 5 项
    "extras",          # EXT-SC / CL / CD 供应链云容器 CI/CD 22 项
    "extras2",         # EXT-AI AI 应用 8 项
    "extras3",         # EXT-DM 域名与邮件 6 项
    "extras4",         # EXT-DP / RB 数据隐私与滥用防护 10 项
]

# 档位 → 允许的最高风险级别
RISK_LEVEL_BY_PROFILE = {
    "safe": RISK_SAFE,
    "standard": RISK_STANDARD,
    "deep": RISK_DEEP,
}


def build_registry() -> DetectorRegistry:
    """导入全部检测器模块并汇总注册表。"""
    mods = []
    for name in DETECTOR_MODULES:
        mods.append(importlib.import_module(f"engine.checks.{name}"))
    reg = DetectorRegistry()
    collect_from_modules(reg, mods)
    return reg


def normalize_profile(profile: dict[str, Any], key: str) -> dict[str, Any]:
    """补上注册表需要的两个字段。

    risk_level 决定哪些主动检测允许执行；_key 用于报告与日志标注。
    两者都从档位配置派生，避免在代码里散落硬编码。
    """
    p = dict(profile or {})
    p["_key"] = key
    p.setdefault("risk_level", RISK_LEVEL_BY_PROFILE.get(key, RISK_STANDARD))
    return p


def build_context(
    *,
    target_name: str,
    domain: str,
    target_url: str,
    profile: dict[str, Any],
    profile_key: str,
    fp_result: dict[str, Any] | None = None,
    js_result: dict[str, Any] | None = None,
    nuclei_findings: list[Finding] | None = None,
    accounts: list[dict[str, Any]] | None = None,
    client: Any = None,
    ledger_write_authorized: bool = False,
) -> DetectorContext:
    """构造检测上下文（含缓存、限速、留痕）。

    ⚠️ 写权限必须**两把锁同时开**，缺一不可：

      1. **档位允许** —— `profiles.yaml` 的 `write_verification` 不为 none/false；
      2. **台账显式授权** —— `ledger --register --allow-write` 登记过。

    这里曾经只读档位（第 1 把锁），于是 deep 档下**即使台账写着「写验证：不允许」**，
    `allow_write` 仍被判为 True：写方法的 `PermissionError` 门控被越过，
    `requires=["write"]` 的自动检测器（含向 AI 端点 POST 注入探针的
    EXT-AI-02 / EXT-AI-04）会被真的发出请求。

    「登记了却不生效」比没登记更危险 —— 它给出的是**虚假的授权信心**。
    所以默认值刻意取 False：未登记 / 台账查不到 → 一律按未授权处理。
    """
    prof = normalize_profile(profile, profile_key)
    profile_allows_write = bool(prof.get("write_verification")) and \
        prof.get("write_verification") not in (False, "false", "none")
    allow_write = profile_allows_write and bool(ledger_write_authorized)
    return DetectorContext(
        target_name=target_name,
        domain=domain,
        target_url=target_url,
        profile=prof,
        fp_result=fp_result or {},
        js_result=js_result or {},
        nuclei_findings=nuclei_findings or [],
        accounts=accounts or [],
        allow_write=allow_write,
        client=client,
    )


def _guard_tick(guard: Any, ctx: DetectorContext) -> None:
    """检查项之间的边界封禁抽检。

    **为什么插在这里**：逐项检测是探测最密集的阶段（上千次请求），也是最容易
    触发频率封禁的地方。封禁发生在这一阶段却不察觉，后果是把后半段拿到的
    拦截页当成应用页面继续判定 —— 产出一份格式规范、证据齐全、但复测不出来的
    「发现」。这比报告给「无法评估」更坏。

    这里只是**检查项之间**的到点例行抽检。抽检是抽样的，两次之间是盲区；
    盲区由两条互补机制收口：
      · 探测热路径把每个响应顺手喂给守门（`DetectorContext._feed_guard`），
        可疑迹象出现时提前触发真抽检（缩小窗口）；
      · 封禁事件记下窗口，窗口内的结论由 `_invalidate_contaminated` 作废
        （消除假通过）。

    任何异常都不得中断逐项检测：守门是保护措施，不是主流程。

    **终态是持续状态，不是一次性事件**（2026-09-29 内部生产系统 事故）：
    封禁若在逐项检测**之前**就已成立（例如 L2 采集期间转 persistent），
    `tick()` 因终态而恒返回 None —— 原先只在「拿到本次事件」时才写短路标记，
    于是整段逐项检测在无门控状态下跑完。现在两条都做：
      · tick 返回未恢复的事件 → 立即短路（事件驱动）；
      · **每个检查项**都再问一次 `currently_blocked()`（状态驱动）——
        这样无论封禁在何时成立，门控都不会漏掉任何一项。
    """
    if guard is None:
        return
    ev = None
    try:
        ev = guard.tick(int(getattr(ctx, "probe_count", 0) or 0))
    except Exception:  # noqa: BLE001
        ev = None
    try:
        if ev is not None:
            guard.apply_speed(getattr(ctx, "_client", None))
        blocked_now = False
        try:
            blocked_now = bool(guard.currently_blocked())
        except Exception:  # noqa: BLE001
            blocked_now = False
        if (ev is not None and not ev.recovered) or blocked_now:
            # 终态：把事实写进上下文，后续检查项由注册表统一短路成「未执行」，
            # 避免用「没跑到」冒充「没问题」。幂等，可逐项重复调用。
            guard.mark_unexecutable(ctx)
    except Exception:  # noqa: BLE001
        pass


def _invalidate_contaminated(results: list[ItemResult], ranges: dict[str, tuple[int, int]],
                             guard: Any) -> None:
    """把落在封禁窗口内的「通过 / N/A」改判为「待确认」。

    **为什么必须做**：抽检是抽样。目标在两次抽检之间被封的话，窗口内的检查项
    是在拦截页上跑完的，其中判「通过」的那些是**假通过** —— 它和「未执行」
    有本质区别：未执行是「我没说」，假通过是**主动给出的错误结论**，而报告
    看起来完全正常。抽检密度调得再高也只是把窗口变小，消不掉；只有把窗口内的
    结论作废，假通过才真正消失。

    改判范围刻意收紧：
      · 「通过」→「待确认」：这正是本机制要消灭的东西；
      · 「N/A」→「待确认」：「目标没有该功能」也可能只是拦截页造成的假象，
        两者从外部无法区分；
      · 「不通过」**不动状态**，只加核对标注：发现的真伪由复现闸门裁决
        （闸门要求脚本复测通过），不靠这套启发式翻案 —— 那会把真发现判没。
    """
    if guard is None or not results:
        return
    report = getattr(guard, "report", None)
    if report is None or not getattr(report, "events", None):
        return
    try:
        for r in results:
            rng = ranges.get(r.item_id)
            if not rng or not guard.is_contaminated(*rng):
                continue
            if r.state in ("通过", "N/A"):
                prev = r.state
                r.state = "待确认"
                r.note = ((r.note + "；") if r.note else "") + (
                    f"本次执行落在边界封禁窗口内（探测 {rng[0]}–{rng[1]}），"
                    f"原判「{prev}」可能读的是拦截页，**不作数** —— 请复扫确认。")
                report.invalidated_items += 1
            elif r.state == "不通过":
                r.note = ((r.note + "；") if r.note else "") + (
                    "⚠ 该项取证时段落在边界封禁窗口内，发现的真实性以复现脚本的"
                    "复测结果为准（闸门已强制复现，未复现者不进漏洞清单）。")
                report.annotated_items += 1
    except Exception as e:  # noqa: BLE001
        # 作废机制自身的故障不能把整轮结果丢掉 —— 但必须留痕：
        # 它一旦失效，报告里就会出现无法区分的「假通过」。
        report.notes.append(
            f"⚠ 封禁窗口内的结论作废未能完成（{type(e).__name__}: {str(e)[:120]}）："
            "本次可能存在由拦截页得出的「通过」，请对封禁时段附近的项人工复核。")


def _health_tick(health: Any, ctx: DetectorContext) -> None:
    """检查项之间的目标健康度巡检。

    **与 `_guard_tick` 不是一回事**：那个问「对方有没有拦住我们」，
    这个问「我们有没有把对方打挂」。判据吃的是探测热路径顺手喂进来的响应
    （`DetectorContext._feed_guard`），所以这里只做两件事：
    终态时把事实写进上下文、并让后续项短路成「未执行」。

    异常一律吞掉：保护措施不能因为它自己的故障中断扫描。
    """
    if health is None:
        return
    try:
        if health.terminal:
            health.mark_unexecutable(ctx)
    except Exception:  # noqa: BLE001
        pass


def _item_gap_seconds(ctx: DetectorContext) -> float:
    """档位配置的「检查项之间强制间隔」（`rate.delay_between_items_ms`）。

    **此前该字段零读取点** —— yaml 写着 `delay_between_items_ms: 200`，
    实际检查项之间没有任何间隔。这比字段缺失更坏：它给出的是虚假保证。

    为什么需要它：全量检查项里有很多项会在极短时间内连续打同一批路径。
    「每一项内部已经限速」并不等于「项与项之间不会形成突发」——
    rps 限速管的是平均速率，连续几十项的边界处仍会形成密集窗口。
    安全档把它设成 200ms，就是要把这类窗口抹平。

    返回 0 表示不间隔（标准档 50ms、深度档 0）。
    """
    try:
        ms = float(((ctx.profile or {}).get("rate") or {})
                   .get("delay_between_items_ms") or 0)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, ms / 1000.0)


def run_all_items(
    checklist: Any,
    applicability: list[ApplicabilityResult],
    ctx: DetectorContext,
    guard: Any = None,
    progress_fn: Any = None,
    health: Any = None,
) -> tuple[list[ItemResult], list[Finding]]:
    """逐项执行全部检查项。

    返回 (逐项结论, 检测器产出的发现)。
    applicability 为空的项会以「待确认」落入结论，不会被当成通过。

    guard —— 可选的边界封禁守门（engine.banguard.BoundaryGuard），
    会在每个检查项之前做一次节流抽检，并在整轮结束后作废落在封禁窗口内的结论。

    health —— 可选的目标健康度守门（engine.banguard.TargetHealthWatch），
    对应 `hard_limits.stop_on`。触发后后续项短路成「未执行」，
    且其理由措辞与「被拦截」严格区分（请求到了应用 vs 没到）。

    progress_fn —— 可选进度回调 `fn(done, total, label)`。**异常一律吞掉**：
    进度是观测手段，不能因为它自己出错而中断扫描（曾出现过「附属功能抛异常
    把主流程带崩」的教训，这里明确隔离）。
    """
    reg = build_registry()
    app_map = {r.item.id: r for r in applicability}
    _total = len(list(checklist)) if hasattr(checklist, "__len__") else 0
    _gap = _item_gap_seconds(ctx)

    def _tick(done: int, label: str = "") -> None:
        if progress_fn is None:
            return
        try:
            progress_fn(done, _total, label)
        except Exception:  # noqa: BLE001
            pass

    results: list[ItemResult] = []
    findings: list[Finding] = []
    #: 每个检查项的取证时段（探测序号区间）。封禁窗口要跟它相交才能定位到具体项 ——
    #: 只有窗口没有区间就只能整轮作废，那会把窗口外的好结论一起扔掉。
    probe_ranges: dict[str, tuple[int, int]] = {}

    # 把守门挂到探测热路径上：可疑迹象出现时立刻抽检，不等下一个检查项边界。
    if guard is not None and hasattr(ctx, "attach_guard"):
        ctx.attach_guard(guard)
    if health is not None and hasattr(ctx, "attach_health"):
        ctx.attach_health(health)

    for item in checklist:
        p0 = int(getattr(ctx, "probe_count", 0) or 0)
        _guard_tick(guard, ctx)
        _health_tick(health, ctx)
        ap = app_map.get(item.id)
        if ap is None:
            # 适用性缺失属于上游异常，明确报「待确认」而不是放行
            res = reg.execute(
                item, ctx,
                applicability_state="待确认",
                applicability_note="适用性判定缺失，本项未执行，请检查适用性引擎",
                skipped=False,
            )
        else:
            res = reg.execute(
                item, ctx,
                applicability_state=ap.conclusion,
                applicability_note=ap.reason,
                skipped=ap.skipped_by_user,
                skip_reason=ap.skip_reason,
                # 弱证据 N/A 必须一路带到归档：跨轮承接靠它区分
                # 「确证不适用」与「没看到」，后者不得推翻历史发现。
                weak_na=bool(getattr(ap, "weak_na", False)),
            )
        probe_ranges[item.id] = (p0, int(getattr(ctx, "probe_count", 0) or 0))
        results.append(res)
        if res.state == "不通过":
            findings.extend(res.findings)
        _tick(len(results), f"{getattr(item, 'id', '')} "
                            f"{getattr(item, 'name', '')}".strip())
        # 项间强制间隔放在**最后**：这样它正好覆盖「本项做完了、下一项马上要开始」
        # 那个边界，也就是突发最容易出现的位置。
        # 最后一项之后不间隔（扫描收尾，没有下一次突发需要抹平）。
        if _gap > 0 and len(results) < _total:
            time.sleep(_gap)

    # 封禁窗口内的结论作废：放在整轮结束后统一做 —— 窗口是在扫描过程中逐步
    # 成型的，边跑边改判会漏掉「一个窗口横跨多个检查项」的情形。
    _invalidate_contaminated(results, probe_ranges, guard)

    # 采集充分度评分：整份报告里所有 N/A 结论的可信度都取决于它。
    # 采集不充分时，「没渲染出来」会被误写成「目标没有该功能」。
    # 把注册表一并传进去：前端产物抓取失败时，要按注册表声明
    # （requires=["js"]）算出**受影响的检查项清单**，而不是只给一个分数 ——
    # 只给分数读者不知道该怀疑哪几项，等于没说。
    try:
        from engine.checks.base import collection_report  # noqa: PLC0415

        ctx._cache["collection_report"] = collection_report(ctx, registry=reg)
    except Exception as e:  # noqa: BLE001
        ctx._cache["collection_report"] = {
            "score": 0, "level": "未知", "degraded": True,
            "summary": f"采集充分度评估失败：{type(e).__name__}",
            "items": [],
        }

    return results, findings


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """按 (检查项, 标题, 端点, 参数) 去重。

    新旧两套检测器可能有交集，同一问题重复报两次会让报告失去可信度。
    保留字段更完整的那条（证据条数多者优先）。
    """
    best: dict[tuple[str, str, str, str], Finding] = {}
    for f in findings:
        key = (f.item_id, f.title.strip(), f.endpoint.strip(), f.param.strip())
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        score_new = (len(f.evidence), len(f.technical_detail), len(f.reproduction))
        score_old = (len(cur.evidence), len(cur.technical_detail), len(cur.reproduction))
        if score_new > score_old:
            best[key] = f
    return list(best.values())


def merge_with_legacy(
    detector_findings: list[Finding],
    legacy_findings: list[Finding],
) -> list[Finding]:
    """把新检测器的产出与旧链路（nuclei / 内置检测器 / JS 分析）的产出合并去重。"""
    return dedupe_findings(list(detector_findings) + list(legacy_findings))


def summary_rows(results: list[ItemResult]) -> list[dict[str, Any]]:
    """把逐项结论转成可落盘的字典列表。"""
    return [r.to_dict() for r in results]


def manual_items(results: list[ItemResult]) -> list[ItemResult]:
    """筛出待人工执行的项，供报告单独成节。"""
    return [r for r in results if r.state == STATE_MANUAL]


def summarize(results: list[ItemResult]) -> dict[str, Any]:
    """逐项结论汇总（含可信通过率）。"""
    return DetectorRegistry.summarize(results)
