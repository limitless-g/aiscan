# -*- coding: utf-8 -*-
"""
报告层 × 准入闸门 抽烟测试
==========================

目的：证明「报告里写出去的漏洞 = 能复测的漏洞」这条要求在**渲染层**也成立，
而不只是闸门算对了数。

覆盖四类判定（已复现 / 未复现 / 无法判定 / 未验证）+ 弱复现标注，
并断言报告不会出现任何「未验证却写成漏洞」的措辞。

用法：
    python selftest_report_gate.py
退出码 0 = 全部断言通过。
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.applicability import ApplicabilityEngine, ApplicabilityResult  # noqa: E402
from engine.gate import ReportGate  # noqa: E402
from engine import wafbypass as _wb  # noqa: E402  绕过试探的基线对照常量
from checklist.loader import CheckItem  # noqa: E402
from models import Evidence, Finding, FindingSet  # noqa: E402
from report.generator import ReportContext, ReportGenerator  # noqa: E402

OUT = ROOT / "outputs" / "_闸门渲染自测"

FAILS: list[str] = []
CHECKS = 0


def check(cond: bool, label: str) -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  [OK]   {label}")
    else:
        print(f"  [FAIL] {label}")
        FAILS.append(label)


# ------------------------------------------------------------------------------
# 构造六条发现，覆盖全部判定分支
# ------------------------------------------------------------------------------
def mk(item_id: str, title: str, sev: str, strength: str, kind: str,
       script: str = "", endpoint: str = "https://demo.example.com/x") -> Finding:
    f = Finding(item_id=item_id, title=title, target="闸门自测目标",
                endpoint=endpoint, method="GET", severity=sev,
                confidence="High", evidence_level="A" if sev in ("严重", "高危") else "B",
                grading_basis="自测构造", description="自测构造的描述",
                impact="自测构造的影响", remediation="自测构造的修复建议")
    f.extra = {"verify_strength": strength, "repro_kind": kind,
               "grading": {"hazard_type": "自测", "baseline": "中危",
                           "after_evidence_cap": sev, "final_severity": sev,
                           "rationale": ["自测构造"]}}
    f.verify_script = script
    return f


F_REPRO_STRONG = mk("WSTG-INPV-05", "SQL 注入（强复现）", "高危", "strong",
                    "param_replay", "verify_sqli.py")
F_REPRO_MED = mk("WSTG-CONF-02", "目录列举（中复现）", "中危", "medium",
                 "dir_listing", "verify_dirlist.py")
F_REPRO_WEAK = mk("WSTG-INFO-01", "信息泄露（弱复现）", "低危", "weak",
                  "weak_probe", "verify_info.py")
F_REFUTED = mk("WSTG-ATHN-02", "弱口令（判据待复核）", "高危", "strong",
               "param_replay", "verify_weakpwd.py")
F_INCONCL = mk("WSTG-CRYP-03", "明文传输（无法判定）", "中危", "weak",
               "plain_channel", "verify_plain.py")
F_UNVERIFIED = mk("EXT-CL-06", "前端产物发现云凭据特征（无脚本）", "中危", "weak",
                  "content_marker", "")

ALL = [F_REPRO_STRONG, F_REPRO_MED, F_REPRO_WEAK, F_REFUTED, F_INCONCL, F_UNVERIFIED]

# 让「无法判定」那条带上会话要求：报告必须同时说清它**为什么**验不了 ——
# 是缺专用断言，还是缺真实身份。两者处置动作完全不同（补检测器 vs 填凭据）。
F_INCONCL.extra["repro_needs_session"] = True
F_INCONCL.extra["repro_roles"] = ["user_a", "user_b"]

RUNS = [
    SimpleNamespace(script="verify_sqli.py", exit_code=0, duration_ms=120,
                    output="[复现成功] 载荷回显数据库报错特征"),
    SimpleNamespace(script="verify_dirlist.py", exit_code=0, duration_ms=90,
                    output="[复现成功] 目录索引特征命中"),
    SimpleNamespace(script="verify_info.py", exit_code=0, duration_ms=60,
                    output="[弱复现] 端点可达，无该类型专用断言"),
    SimpleNamespace(script="verify_weakpwd.py", exit_code=1, duration_ms=110,
                    output="[未复现] 未命中"),
    SimpleNamespace(script="verify_plain.py", exit_code=2, duration_ms=80,
                    output="[无法判定] 缺断言"),
]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # ---- 1. 闸门判定 ----
    print("\n[1] 闸门判定")
    gate = ReportGate()
    res = gate.evaluate(ALL, runs=RUNS, verify_ran=True, verify_note="自测")
    s = res.stats()
    check(s["发现总数"] == 6, f"发现总数 = 6（实际 {s['发现总数']}）")
    check(s["已复现"] == 3, f"已复现 = 3（实际 {s['已复现']}）")
    check(s["未复现"] == 1, f"未复现 = 1（实际 {s['未复现']}）")
    check(s["无法判定"] == 1, f"无法判定 = 1（实际 {s['无法判定']}）")
    check(s["未验证"] == 1, f"未验证 = 1（实际 {s['未验证']}）")
    check(s["弱复现"] == 1, f"弱复现 = 1（实际 {s['弱复现']}）")

    # 回写字段：确认闸门统一改了 verify_result
    check(F_REPRO_STRONG.verify_result == "confirmed", "已复现 → verify_result=confirmed")
    check(F_REFUTED.verify_result == "refuted", "未复现 → verify_result=refuted")
    check(F_INCONCL.verify_result == "inconclusive", "无法判定 → verify_result=inconclusive")
    check(F_UNVERIFIED.verify_result == "", "未验证 → verify_result 保持空（不被伪造成 confirmed）")

    # ---- 2. 只有已复现的进漏洞清单 ----
    print("\n[2] 漏洞清单口径")
    fs = FindingSet(target="闸门自测目标")
    reportable = {id(f) for f in res.reportable_findings()}
    blocked = []
    for f in ALL:
        if id(f) in reportable:
            f.verify_result = "confirmed"
            fs.add(f)
        else:
            blocked.append(f)
    check(len(fs.findings) == 3, f"漏洞清单 = 3 条（实际 {len(fs.findings)}）")
    check(len(blocked) == 3, f"被拦下 = 3 条（实际 {len(blocked)}）")
    check(all(f.verify_result == "confirmed" for f in fs.findings),
          "清单内每条的 verify_result 均为 confirmed")

    # ---- 3. 渲染报告 ----
    print("\n[3] 报告渲染")
    ctx = ReportContext(
        target_name="闸门自测目标",
        primary_domain="demo.example.com",
        scan_time="2026-09-21 12:00:00",
        gate_result=res,
        blocked_findings=blocked,
        item_results=[],
        collection={"score": 90, "level": "良好", "summary": "自测"},
    )
    app = [ApplicabilityResult(
        item=CheckItem(id="WSTG-INPV-05", name="注入", app="web",
                       detect="自测", verify="自测", level="中危",
                       compliance="自测", category="WSTG", category_name="WSTG"),
        conclusion="适用", reason="自测",
        feature=SimpleNamespace(evidence="自测", state="present", strength="strong"),
    )]
    gen = ReportGenerator(OUT)
    paths = gen.generate(ctx, fs, app)
    tech = paths["technical"].read_text(encoding="utf-8")
    execu = paths["executive"].read_text(encoding="utf-8")

    check("### 2.1 " in tech, "第 2 章有 2.1 条目")
    check("### 2.3 " in tech, "第 2 章有 2.3 条目（3 条漏洞）")
    # 结构铁律：结论前置、过程后置。
    # 读者第一屏必须是「扫了谁 / 发现几条 / 能不能拿到数据权限」，
    # 逐项检测明细排在后面 —— 顺序一旦被改回去，这条断言会立刻失败。
    check(tech.index("## 2. 漏洞详情") < tech.index("## 3. 检测覆盖情况"),
          "漏洞详情（第 2 章）排在检测覆盖情况（第 3 章）之前")
    check(tech.index("### 1.3 ") < tech.index("## 2. "),
          "第 1 章内含漏洞速查（1.3）且位于漏洞详情之前")
    check(tech.index("## 4. 授权与范围声明") > tech.index("## 3. 检测覆盖情况"),
          "授权声明（第 4 章）后置于检测覆盖情况之后")
    # 标题只能出现一次：矩阵自带标题 + 调用处再写一行 = 同一节印两遍。
    check(tech.count("### 1.4 ") <= 1, "1.4 节标题不重复")
    check(tech.count("### 1.3 ") == 1, "1.3 节标题恰好一次")
    check("未进入漏洞清单的发现" in tech, "存在「未进入漏洞清单的发现」披露节")
    check("证伪记录" in tech, "存在证伪记录节")
    check("待人工复现" in tech, "存在待人工复现节")
    check("未验证清单" in tech, "存在未验证清单节")

    # ---- 4. 不得出现的措辞 ----
    print("\n[4] 禁止出现的措辞")
    check("每项均附可独立执行的复现脚本" not in tech,
          "不含旧的「每项均附…复现脚本」笼统表述")
    check("未接入准入闸门数据" not in tech, "不含「未接入闸门」告警（本次已接入）")
    check("共 6 项。每项均附" not in tech, "不含把 6 条全写成漏洞的表述")

    # ---- 4.5 危害类型必须显示中文标签 ----
    # 「危害形态」列是读者判断「能不能拿到数据/权限」的直接依据，
    # 一旦回退成内部键名（path_reachable_no_auth 之类），这一列就失去意义。
    print("\n[4.5] 危害类型标签")
    from rules.grading import HAZARD_BASELINE, HAZARD_LABEL
    _missing = sorted(set(HAZARD_BASELINE) - set(HAZARD_LABEL))
    check(not _missing, f"每个危害类型都有中文标签（缺失 {_missing}）")
    _leak = [k for k in HAZARD_LABEL if f"| {k} |" in tech]
    check(not _leak, f"报告「危害形态」列不出现内部键名（泄漏 {_leak}）")

    # ---- 5. 必须出现的措辞 ----
    print("\n[5] 必须出现的措辞")
    check("退出码 2" in tech, "明确解释「退出码 2 = 无法判定」")
    check("不是「没问题」" in tech, "明确写出无法判定 ≠ 没问题")
    check("弱复现" in tech, "有弱复现标注")
    check("脚本成功 ≠ 该漏洞一定存在" in tech, "弱复现条目有风险声明")
    check("记录不一致" not in tech, "无孤儿发现（blocked 均在闸门记录中）")
    check("结论可信度" in execu and "条复现成功" in execu, "摘要版含结论可信度声明")
    check("都能用随附脚本复测出来" in execu, "摘要版给出可复测承诺")
    # 可复测率是报告可信度最直接的一个数，必须显式出现在摘要里，
    # 不能只给「32 条复现成功」这种绝对数 —— 分母被藏起来就无从判断好坏。
    check("可复测率" in execu, "摘要版给出可复测率")
    # 「无法判定」必须与「未复现」分开陈述：前者是验不了，后者是跑不出来，
    # 两者都不是「没问题」。合并成一个「未通过」会丢掉这个区别。
    check("无法判定" in execu and "不是没问题" in execu,
          "摘要版区分「无法判定」与「未复现」")

    # ---- 6. 未被接入闸门时必须告警 ----
    print("\n[6] 闸门缺失时的降级行为")
    ctx2 = ReportContext(target_name="无闸门目标", primary_domain="x.example.com",
                         gate_result=None, blocked_findings=[])
    p2 = gen.generate(ctx2, fs, app)
    tech2 = p2["technical"].read_text(encoding="utf-8")
    check("未接入准入闸门数据" in tech2, "闸门缺失时报告显著告警")
    check("请勿将本节内容对外发布" in tech2, "闸门缺失时给出发布禁令")
    check("未触达应用" not in tech2, "未拦截的目标不应出现「未触达应用」告警")

    # ---- 7. 被边界防护全量拦截时的报告行为 ----
    # 这是最容易被写错的一种情况：目标压根没扫到，但报告若照常算一版
    # 「无发现 = 低风险」，读者会直接把它当结论用。
    print("\n[7] 被边界防护拦截时的降级")
    from engine.wafgate import BlockVerdict

    bv = BlockVerdict(blocked=True, vendor="阿里云 WAF", status=405,
                      signature="body 命中 /errors\\.aliyun\\.com/", uniform=True,
                      root_hash="977b7f3262b1e24b",
                      evidence="根路径与随机不存在路径返回逐字节相同的内容")
    ctx3 = ReportContext(target_name="被拦目标", primary_domain="blocked.example.com",
                         gate_result=None, blocked_findings=[], boundary=bv)
    p3 = gen.generate(ctx3, fs, app)
    tech3 = p3["technical"].read_text(encoding="utf-8")
    execu3 = p3["executive"].read_text(encoding="utf-8")
    check("本次扫描未触达应用" in tech3, "技术版顶部给出「未触达应用」告警")
    check("本报告对「应用本身」没有结论" in tech3, "技术版明确本报告无应用层结论")
    check("不得作为该系统的安全结论使用" in tech3, "技术版给出使用禁令")
    check("不受边界影响，已照常执行" in tech3 and "不得读成通过" in tech3,
          "技术版给出可执行的下一步：说清哪些通道照常执行、应用层结论本次没有")
    # 红队口径（2026-09-30 安全负责人定稿）：**不得**再出现「请放行扫描来源 IP 后重扫」。
    # 红队与黑客面对同一环境，被拦就是「打不进去」这个实测结论本身；
    # 放行是内部扫描台账的事，不是给被测方的作业。
    check("放行扫描来源" not in tech3,
          "技术版不得出现「放行扫描来源 IP 后复扫」—— 红队没有「被放行」这个逻辑")
    check("不代表目标安全" in tech3 or "不代表应用没有问题" in tech3,
          "技术版必须澄清「应用层没发现 ≠ 安全」——措辞随有无非应用层发现而变："
          "零发现时说「清单为空不代表目标安全」，"
          "有发现时说「这些发现不来自应用层，不代表应用没有问题」")
    # 管理者看的是摘要版，这里绝不能出现「低风险」
    check("无法评估" in execu3, "摘要版总体结论为「无法评估」")
    check("低风险" not in execu3,
          "摘要版不得出现「低风险」（未测到 ≠ 测了没问题）")
    check("未执行" in execu3, "摘要版说明未执行项不是「已检查且无问题」")
    # 这两条是「没发现 = 没问题」谬误的其他出口，必须一并堵住：
    # 技术版曾照常打「总体评级：低风险」，合规章曾把没有关联发现的条款
    # 逐条写成「本次未发现违反项」—— 在未触达应用的情况下都是误导。
    check("总体评级：低风险" not in tech3,
          "技术版不得给出「低风险」评级（未触达应用时无定级依据）")
    check("总体评级：无法评估" in tech3, "技术版评级为「无法评估」")
    check("本次未发现违反项" not in tech3,
          "合规章不得宣称条款「未发现违反项」（缺判定依据）")
    check("不能得出「哪些合规条款没有问题」的结论" in tech3,
          "合规章明确说明不作符合性判断")

    # ---- 8. 扫描中途被边界封禁（B 类拦截）----
    # 与 [7] 是两种不同的失败：那个是「从头到尾没进去」，这个是「进去了被赶出来」。
    # 后者更隐蔽 —— 报告看起来一切正常，但后半段可能建立在拦截页之上，
    # 其中被判「通过」的项尤其危险（拦截页内容单薄，容易被读成「没发现问题」）。
    print("\n[8] 扫描中途被封禁（B 类）的披露")
    from engine.banguard import BanEvent, GuardReport
    from engine.registry import ItemResult

    def _ir(i: int, state: str) -> ItemResult:
        return ItemResult(item_id=f"T-{i:03d}", name=f"测试检查项{i}",
                          category="测试", category_name="测试",
                          state=state, mode="auto")

    # 前半段真跑过（通过、不通过都有），后半段因封禁记「未执行」
    items_b = ([_ir(i, "通过") for i in range(30)]
               + [_ir(i, "不通过") for i in range(100, 106)]
               + [_ir(i, "未执行") for i in range(200, 220)])

    gr_resumed = GuardReport(
        checks=14,
        events=[BanEvent(seq=1, backoff_used=[30.0], outcome="resumed",
                         evidence="状态码由基线 HTTP 200 变为 405，"
                                  "且与随机不存在路径返回同一张页面",
                         waited_s=30.0, speed_after=0.5)],
        total_waited_s=30.0, speed_factor=0.5)
    ctx4 = ReportContext(target_name="中途被封目标", primary_domain="ban.example.com",
                         item_results=items_b, detector_summary={},
                         gate_result=None, blocked_findings=[],
                         boundary_guard=gr_resumed)
    p4 = gen.generate(ctx4, fs, app)
    tech4 = p4["technical"].read_text(encoding="utf-8")
    execu4 = p4["executive"].read_text(encoding="utf-8")
    check("本次扫描中途被边界防护封禁" in tech4, "技术版披露封禁发生次数")
    check("结论可能建立在拦截页之上" in tech4,
          "技术版提示封禁附近检查项的结论需复核")
    check("不受边界影响，已在封禁期间照常执行" in tech4,
          "技术版给出取得无污染结论的下一步：说清哪条通道在拦截期间仍然有效")
    check("放行扫描来源" not in tech4,
          "技术版不得出现「放行扫描来源 IP 后复扫」—— 红队没有「被放行」这个逻辑")
    check("中途被边界防护封禁" in execu4, "摘要版同样披露封禁（管理者也要看到）")
    check("50%" in tech4, "技术版披露恢复后的降速比例")
    import json as _json
    pay4 = _json.loads(p4["data"].read_text(encoding="utf-8"))
    check(pay4.get("boundary_guard", {}).get("occurred") is True,
          "结构化数据落盘封禁记录（便于批量统计被中断的扫描）")
    check(abs(float(pay4.get("boundary_guard", {}).get("speed_factor", 0)) - 0.5) < 1e-6,
          "落盘降速系数")

    # 封禁后**未能恢复**：即使前段确实跑出过 30 个「通过」，
    # 整体评级也必须是「无法评估」—— 后半段没测到，定级依据不完整。
    gr_term = GuardReport(
        checks=9,
        events=[BanEvent(seq=1, backoff_used=[30.0, 60.0, 120.0, 300.0],
                         outcome="persistent",
                         evidence="退避序列耗尽仍未恢复",
                         waited_s=510.0, speed_after=1.0)],
        total_waited_s=510.0, speed_factor=1.0, terminal=True,
        terminal_reason="退避序列耗尽仍未恢复访问 —— 这不是短时频率封禁，"
                        "而是策略级拦截，等待无意义。剩余检查项无法在"
                        "「未触达应用」的状态下继续，一律按「未执行」记录，"
                        "不得据此认为通过。")
    ctx5 = ReportContext(target_name="中途被封未恢复目标",
                         primary_domain="ban2.example.com",
                         item_results=items_b, detector_summary={},
                         gate_result=None, blocked_findings=[],
                         boundary_guard=gr_term)
    p5 = gen.generate(ctx5, fs, app)
    tech5 = p5["technical"].read_text(encoding="utf-8")
    execu5 = p5["executive"].read_text(encoding="utf-8")
    check("总体评级：无法评估" in tech5,
          "中途封禁未恢复时，即使前段有通过项也必须判「无法评估」")
    check("总体评级：低风险" not in tech5,
          "不得因前段无发现就给出「低风险」（定级依据不完整）")
    check("无法评估" in execu5, "摘要版总体结论为「无法评估」")
    check("那不是「通过」" in tech5,
          "技术版明确封禁后的「未执行」不等于通过")
    pay5 = _json.loads(p5["data"].read_text(encoding="utf-8"))
    check(pay5.get("boundary_guard", {}).get("terminal") is True,
          "结构化数据落盘「未恢复」终态")

    # 封禁窗口内的结论必须被作废，且作废动作量要披露 ——
    # 只说「可能被污染」是不够的：读者不知道到底作废了没有、作废了几项，
    # 于是「封禁附近的通过」会被原样采信，假通过就这么留下了。
    gr_win = GuardReport(
        checks=5,
        events=[BanEvent(seq=1, backoff_used=[30.0], outcome="resumed",
                         evidence="退避后恢复", waited_s=30.0, speed_after=0.5,
                         window_start=100, window_end=130,
                         triggered_by="suspicion")],
        total_waited_s=30.0, speed_factor=0.5,
        suspicion_checks=1, invalidated_items=3, annotated_items=1)
    ctx6 = ReportContext(target_name="窗口作废目标", primary_domain="win.example.com",
                         item_results=items_b, detector_summary={},
                         gate_result=None, blocked_findings=[],
                         boundary_guard=gr_win)
    p6 = gen.generate(ctx6, fs, app)
    tech6 = p6["technical"].read_text(encoding="utf-8")
    check("封禁窗口" in tech6,
          "必须披露封禁窗口（否则读者不知道哪一段取证不可信）")
    check("探测 100–130" in tech6, "窗口必须精确到探测序号区间")
    check("3 个检查项" in tech6, "被改判为「待确认」的项数必须披露")
    check("不计入通过数" in tech6, "必须说明这些项不再计入通过数")
    check("1 个「不通过」项" in tech6, "被加标注的「不通过」项数也要披露")
    check("提前触发" in tech6,
          "必须说明有抽检是被可疑迹象提前触发的（这是把盲区压小的手段）")
    pay6 = _json.loads(p6["data"].read_text(encoding="utf-8"))
    _bg6 = pay6.get("boundary_guard", {})
    check(_bg6.get("suspect_windows") == [[100, 130]], "封禁窗口必须落盘")
    check(_bg6.get("invalidated_items") == 3,
          "作废项数必须落盘（批量统计只看 JSON，看不到正文里的说明）")

    # ---- 8-b. 通告的「防护归因」与「触达口径」----
    # 2026-09-29 内部生产系统 事故里通告同时错了两处，都是「证据与口径」的问题：
    #   ① 守门实测命中了 errors.aliyun.com（阿里云特征），通告却写
    #      「厂商特征未确认」—— 厂商名只被拼进了日志文本，没进结构化字段；
    #   ② 通告写「成功触达业务系统」，而那一轮后半段根本没到达应用
    #      （封禁未恢复）—— 对全部门宣告的文书不能有半句假话。
    print("\n[8-b] 通告的防护归因与触达口径")
    gr_vendor = GuardReport(
        checks=7,
        events=[BanEvent(seq=1, backoff_used=[30.0, 60.0], outcome="persistent",
                         evidence="正文命中 阿里云 WAF 拦截页特征"
                                  "（body 命中 /errors\\.aliyun\\.com/ → "
                                  "errors.aliyun.com），且与随机不存在路径"
                                  "返回同一张页面",
                         waited_s=90.0, speed_after=1.0, vendor="阿里云 WAF")],
        total_waited_s=90.0, speed_factor=1.0, terminal=True,
        terminal_reason="退避序列耗尽仍未恢复访问，一律按「未执行」记录，"
                        "不得据此认为通过。")
    ctx7 = ReportContext(target_name="厂商归因目标",
                         primary_domain="vendor.example.com",
                         item_results=items_b, detector_summary={},
                         gate_result=None, blocked_findings=[],
                         boundary=None, boundary_guard=gr_vendor)
    p7 = gen.generate(ctx7, fs, app)
    notice7 = p7["notice"].read_text(encoding="utf-8")
    tech7 = p7["technical"].read_text(encoding="utf-8")
    check("阿里云 WAF" in notice7,
          "通告必须写出实测命中的防护厂商（守门已取到，不得写成「未确认」）")
    check("厂商特征未确认" not in notice7,
          "厂商已由运行期证据确认时，不得再写「厂商特征未确认」")
    check("成功触达业务系统" not in notice7,
          "封禁未恢复时不得声称「成功触达业务系统」—— 后半段没有到达应用")
    # 2026-10-08 安全负责人改版（红线 54）：通告结论段**只留主句**。
    # 旧断言是「必须点明未取得结论的项不代表没有问题」—— 改版后这两行限定语
    # （「其中 M 项本次有结论…另有 N 项没有取得结论」与「未取得结论的项不代表
    # 没有问题」）整段删除，断言随之**反转**。缺口口径改由第二节
    # （防护有效性：拦截程度 + 本来源被封的实测事实）与第三节承接区承担。
    check("不代表没有问题" not in notice7 and "项本次有结论" not in notice7,
          "非零发现时通告结论段只留主句（2026-10-08 安全负责人定稿，红线 54）—— "
          "不得再并列「其中 M 项有结论」与「未取得结论的项不代表没有问题」")
    # 但**零发现**是另一回事：它针对的是「把『压根没测到』包装成『系统没问题』」
    # 这一种失败形态（红线 42③），安全负责人本次未触及该分支，必须保留。
    n_zero = gen._render_notice(
        ReportContext(target_name="零发现目标", primary_domain="zero.example.com",
                      gate_result=None, blocked_findings=[],
                      item_results=items_b, boundary_guard=gr_vendor),
        FindingSet(target="零发现目标"), app)
    check("不等于「没有问题」" in n_zero,
          "零发现时「0 个 ≠ 没有问题」的限定不得删除 —— "
          "一份「严重 0 / 高危 0 / 中危 0」的通告发进大群，等于对整个部门"
          "宣告该系统没问题，而事实可能是压根没测到")
    check("阿里云 WAF" in tech7,
          "技术版同样要写出防护厂商（两版口径必须一致）")
    pay7 = _json.loads(p7["data"].read_text(encoding="utf-8"))
    check(pay7.get("boundary_guard", {}).get("vendor") == "阿里云 WAF",
          "厂商必须落盘（批量统计与复扫比对只读 JSON）")

    # ---- 8-c. 复现行口径：下划线转义（2026-10-08 安全负责人改版）----
    # 通告是「贴进大群、负责人照着做」的文书；命令里一对 `_` 被 Markdown
    # 当成强调吃掉半行，照着做的人看到的就是错的命令。
    print("\n[8-c] 复现行口径（下划线转义）")
    fs_esc = FindingSet(target="转义自测目标")
    fs_esc.add(Finding(
        item_id="EXT-DM-03", title="域名未配置 DMARC 记录", target="转义自测目标",
        endpoint="DNS TXT _dmarc.esc.test", severity="中危",
        confidence="High", evidence_level="B",
        description="自测", impact="攻击者可伪造域名发信",
        reproduction="nslookup -type=TXT _dmarc.esc.test 8.8.8.8",
        verify_script="verify_dmarc.py", verify_result="confirmed"))
    n_esc = gen._render_notice(
        ReportContext(target_name="转义自测目标", primary_domain="esc.test",
                      gate_result=None, blocked_findings=[]),
        fs_esc, app)
    check(r"\_dmarc.esc.test" in n_esc,
          "复现行（纯文本）里的下划线必须加反斜杠转义 —— 一对 `_` 会被 "
          "Markdown 解析成强调，把命令吃掉半行")
    check("`DNS TXT _dmarc.esc.test`" in n_esc,
          "代码段（反引号内）**不得**转义 —— 那里按字面渲染，"
          "加了反斜杠会显示成 \\_")

    # ---- 渲染（SPA）披露 ----
    # 渲染会在本机浏览器里执行目标页面的 JavaScript，并可能连带请求页面里
    # 引用的第三方资源。这属于「工具对我做了什么」，必须在授权与范围一章披露；
    # 而「没渲染成功」则会改变所有 N/A 的读法，也必须在报告里说出来。
    # 三条断言分别钉住：启用要披露副作用、未成功要提示 N/A 读法、关闭时不得乱说。
    print("\n[渲染披露]")
    ctx_r = ReportContext(
        target_name="SPA 目标", primary_domain="spa.example.com",
        gate_result=None, blocked_findings=[], item_results=[],
        render={"plan": {"enabled": True, "reason": "AISCAN_RENDER=auto，档位 deep"},
                "entry": {"ok": True, "state": "已渲染", "text_before": 0,
                          "text_after": 3200, "refilled": True},
                "notes": ["入口页已由浏览器渲染"]},
    )
    tech_r = gen.generate(ctx_r, fs, app)["technical"].read_text(encoding="utf-8")
    check("浏览器渲染" in tech_r, "渲染已启用时，第 4 章披露「浏览器渲染」")
    check("执行目标页面的 JavaScript" in tech_r,
          "渲染披露必须写明「会在浏览器中执行目标页面的 JavaScript」")
    check("第三方资源" in tech_r,
          "渲染披露必须提示「页面引用的第三方资源可能被一并请求」（授权范围问题）")
    check("可见文本 0 → 3200 字" in tech_r, "渲染披露含渲染效果（渲染前后可见文本量）")

    ctx_r2 = ReportContext(
        target_name="SPA 未渲染目标", primary_domain="spa2.example.com",
        gate_result=None, blocked_findings=[], item_results=[],
        render={"plan": {"enabled": False, "reason": "本机未找到 Edge / Chrome"},
                "entry": {"ok": False, "state": "未渲染",
                          "reason": "本机未找到 Edge / Chrome"},
                "notes": ["⚠ 未渲染入口页 → 覆盖度下降"]},
    )
    tech_r2 = gen.generate(ctx_r2, fs, app)["technical"].read_text(encoding="utf-8")
    check("本次没看到" in tech_r2 and "目标不存在" in tech_r2,
          "入口页未渲染时必须提示「N/A 应读作本次没看到，而非目标不存在」")
    check("本机未找到 Edge" in tech_r2,
          "未渲染原因必须写进报告（否则读者无从判断是工具问题还是目标问题）")

    ctx_r3 = ReportContext(target_name="无渲染目标", primary_domain="norender.example.com",
                           gate_result=None, blocked_findings=[], item_results=[],
                           render={})
    tech_r3 = gen.generate(ctx_r3, fs, app)["technical"].read_text(encoding="utf-8")
    check("执行目标页面的 JavaScript" not in tech_r3,
          "未启用渲染时不得出现渲染副作用说明（避免无中生有）")

    # ---- 健康度守门被显式关闭（AISCAN_HEALTH_GUARD=off）的披露 ----
    # 关闭是操作者的主动选择，但读者必须知道「连续 5xx 会停手」这道闸本轮
    # 不在 —— 否则默认它有（没生效却没说，比没配更危险）。仅限靶场基准。
    print("\n[健康度守门关闭披露]")
    ctx_hg = ReportContext(target_name="靶场目标", primary_domain="bench.example.com",
                           gate_result=None, blocked_findings=[], item_results=[],
                           health_guard_off=True)
    tech_hg = gen.generate(ctx_hg, fs, app)["technical"].read_text(encoding="utf-8")
    check("健康度守门本次被**显式关闭**" in tech_hg,
          "AISCAN_HEALTH_GUARD=off 时报告必须具名披露守门被关闭")
    check("生产目标不得使用" in tech_hg,
          "守门关闭披露必须写明「生产目标不得使用」—— 防止逃生门被带进生产")
    ctx_hg2 = ReportContext(target_name="正常目标", primary_domain="normal.example.com",
                            gate_result=None, blocked_findings=[], item_results=[])
    tech_hg2 = gen.generate(ctx_hg2, fs, app)["technical"].read_text(encoding="utf-8")
    check("健康度守门本次被**显式关闭**" not in tech_hg2,
          "未关闭守门时不得出现关闭披露（避免无中生有）")

    # ---- 业务逻辑自动侦察披露 ----
    #
    # 侦察改变了「人工项还欠多少活」这个判断，三种情形读法完全不同，
    # 而且其中一种是**信息会丢**的危险情形：
    #
    #   · 侦察确证了问题 → 该项状态变「不通过」，于是移出「待人工执行清单」。
    #     如果残留人工步骤只写在那份清单里，就会跟着一起消失 ——
    #     读者只看到一条漏洞，不知道这一项其实只被验证了一部分。
    #     所以必须另有一处按项全量列出。
    #   · 侦察没执行 → 必须显式说「没有任何自动化前置覆盖」，
    #     否则读者看到一份写得很细的人工步骤，会默认自动化已经尽力了。
    print("\n[业务逻辑侦察披露]")
    from engine.registry import ItemResult  # noqa: PLC0415

    def _mk_item(**kw) -> ItemResult:
        base = dict(item_id="WSTG-BUSL-01", name="业务逻辑数据验证测试",
                    category="BUSL", category_name="业务逻辑",
                    state="待人工执行", mode="人工",
                    why_manual="「哪个值是业务上不可能的」需要业务知识",
                    procedure="1) 数值边界：0、-1、-0.01\n2) 类型混淆",
                    expect="所有业务字段在服务端做类型 + 范围 + 业务规则三重校验")
        base.update(kw)
        return ItemResult(**base)

    # ① 侦察已执行、有已定位对象、未确证 → 仍是待人工执行
    ctx_b1 = ReportContext(
        target_name="业务系统", primary_domain="biz.example.com",
        gate_result=None, blocked_findings=[], render={},
        item_results=[_mk_item(
            recon_ran=True, recon_probes=12, recon_finding_count=0,
            recon_note="识别到客户端可控业务参数 3 个，涉及 金额类、数量类\n"
                       "差分实验 2 组：确证 0、通过 1、无结论 1",
            recon_lead=["https://biz.example.com/api/order/save [POST] 字段 `amount` "
                        "—— 金额类，表单隐藏字段，当前值 100",
                        "→ 对每个字段依次提交 0 / -1 / 1.5 / 999999999",
                        "以下是**本次未自动触碰**的接口（副作用不可控，按「不做」处理）：",
                        "  · 因「资金 / 支付类」排除：https://biz.example.com/api/pay"]),
    ]
    )
    tech_b1 = gen.generate(ctx_b1, fs, app)["technical"].read_text(encoding="utf-8")
    check("人工项自动前置侦察结论" in tech_b1,
          "业务逻辑侦察结论必须单列成节（否则确证项移出人工清单时残留步骤会丢）")
    check("已定位到的具体对象" in tech_b1,
          "侦察定位到的接口与字段必须写进报告（这是省人工时间的主体产出）")
    check("字段 `amount`" in tech_b1 and "当前值 100" in tech_b1,
          "已定位对象必须具体到字段名与当前值")
    check("侦察**不等于**本项通过" in tech_b1,
          "侦察未确证时必须明确写「不等于本项通过」（否则侦察会被读成绿色结论）")
    check("本次未自动触碰" in tech_b1 and "资金 / 支付类" in tech_b1,
          "被安全过滤排除的接口必须列出并说明原因（不能悄悄消失）")
    # 「执行方式」列：这一列是读者判断「还欠多少人工」的第一眼来源。
    # 只写「人工（人工核查）」会让挂了侦察的项看起来零自动化 —— 而事实上
    # 接口、字段、当前值都已经定位好，人只剩最后一层业务判断。
    check("已挂自动侦察（已执行）" in tech_b1,
          "侦察跑成了，执行方式列必须标出来（否则读者以为整项零自动化）")
    check("执行方式」列带" in tech_b1,
          "必须有一句解释这列的含义，否则「已挂自动侦察」是行话、读者不知道省了什么")

    # ② 侦察确证了问题 → 该项移出人工清单，但结论节里必须仍然能找到它
    ctx_b2 = ReportContext(
        target_name="业务系统", primary_domain="biz.example.com",
        gate_result=None, blocked_findings=[], render={},
        item_results=[_mk_item(
            state="不通过", recon_ran=True, recon_finding_count=1, recon_probes=8,
            recon_note="差分实验 1 组：确证 1 组 —— 把 `amount` 从 100 改为 0.01 后，"
                       "响应中 total 随之变成 0.01",
            recon_lead=["https://biz.example.com/api/order/save [POST] 字段 `amount`"]),
        ]
    )
    tech_b2 = gen.generate(ctx_b2, fs, app)["technical"].read_text(encoding="utf-8")
    check("人工项自动前置侦察结论" in tech_b2,
          "侦察确证后该项状态变「不通过」，结论节仍须单列（状态变化不得让信息消失）")
    check("WSTG-BUSL-01" in tech_b2 and "确证：1 项" in tech_b2,
          "确证的项必须列出条数，并注明已计入发现列表")
    check("残留人工步骤" in tech_b2 or "仍须执行" in tech_b2 or "人工步骤" in tech_b2,
          "确证的项必须保留「还有人工作业没做」的提示（部分覆盖不得写成全部覆盖）")

    # ③ 侦察没跑起来 → 必须显式说「没有任何自动化前置覆盖」
    ctx_b3 = ReportContext(
        target_name="业务系统", primary_domain="biz.example.com",
        gate_result=None, blocked_findings=[], render={},
        item_results=[_mk_item(
            recon_ran=False, recon_finding_count=0,
            recon_note="写差分未执行：未开启受控写验证（需 deep 档 + 台账 --allow-write 授权）"),
        ]
    )
    tech_b3 = gen.generate(ctx_b3, fs, app)["technical"].read_text(encoding="utf-8")
    check("自动侦察：未执行" in tech_b3,
          "侦察未执行必须在人工项正文里显式标注「未执行」")
    check("没有任何自动化前置覆盖" in tech_b3,
          "侦察未执行时必须说明「没有任何自动化前置覆盖」（否则会被误读为已尽力）")
    check("未开启受控写验证" in tech_b3,
          "侦察未执行的原因必须写进报告")
    check("已挂自动侦察（未执行）" in tech_b3,
          "「挂了但没跑成」与「压根没挂」必须分开写：前者补上凭据 / 档位就能跑，"
          "后者从零开始，两者欠的工作量差得远")

    # ④ 完全没有侦察项的扫描 → 不得凭空出现这一节
    ctx_b4 = ReportContext(target_name="无业务目标", primary_domain="plain.example.com",
                           gate_result=None, blocked_findings=[], render={},
                           item_results=[_mk_item(state="N/A")])
    tech_b4 = gen.generate(ctx_b4, fs, app)["technical"].read_text(encoding="utf-8")
    check("人工项自动前置侦察结论" not in tech_b4,
          "没有任何侦察项时不得出现该节（避免无中生有）")
    check("已挂自动侦察" not in tech_b4,
          "没挂侦察的项不得被标成「已挂自动侦察」（这一列不能无中生有）")

    # ⑨ 「待确认」在 3.1 开头与表格里必须是同一个数
    # 真实报告里出现过「开头写待确认 0 项 / 表格写 21 项」—— 同一页两个数打架，
    # 读者只会认为整份报告不可信，进而不再相信漏洞清单。
    # 根因是两处取的是不同阶段的汇总：开头取「适用性判定」（那时还没执行，
    # 待确认恒为 0），表格取「逐项执行结果」（待确认是执行期才出现的状态）。
    ctx_p = ReportContext(
        target_name="待确认目标", primary_domain="pend.example.com",
        gate_result=None, blocked_findings=[], render={},
        item_results=[
            _mk_item(state="待确认"),
            _mk_item(item_id="WSTG-ATHZ-01", name="目录遍历与文件包含",
                     category="ATHZ", category_name="授权", state="待确认"),
        ],
    )
    tech_p = gen.generate(ctx_p, fs, app)["technical"].read_text(encoding="utf-8")
    import re as _re_t  # noqa: E402

    _intro = _re_t.search(r"待确认 (\d+) 项。", tech_p)
    _row = _re_t.search(r"待确认（外部无法判定） \| (\d+) 项", tech_p)
    check(_intro is not None and _row is not None,
          "3.1 的开头句与表格都应给出待确认项数")
    if _intro and _row:
        check(_intro.group(1) == _row.group(1) == "2",
              "「待确认」在开头与表格里必须是同一个数"
              f"（开头 {_intro.group(1)}、表格 {_row.group(1)}）")

    # ---- 攻击链分析披露 ----
    # 这一节最大的风险是**把推理渲染成事实**：候选链由能力关系推导而来，
    # 若和「已达成」用同一种措辞，读者会把纸面推演当成实测战果。
    from engine.attackchain import (
        CAP_ADMIN,
        CAP_CRED,
        CAP_READ,
        AttackChain,
        ChainEdge,
        ChainNode,
    )

    _n_proven = ChainNode(
        node_id="N01", item_id="EXT-CD-03", title="版本控制目录可访问",
        endpoint="https://biz.example.com/.git/",
        provides=[CAP_CRED], evidence_state="已达成",
        basis="版本控制目录泄露（历史中常含凭据）")
    _n_pending = ChainNode(
        node_id="N02", item_id="WSTG-CONF-05", title="管理接口暴露",
        endpoint="https://biz.example.com/admin",
        provides=[CAP_ADMIN], evidence_state="",
        basis="管理接口暴露")
    _chain_done = AttackChain(
        chain_id="READ_DATA-CREDENTIAL-N01", objective="READ_DATA",
        goal=CAP_READ, state="已达成", nodes=[_n_proven],
        note="链尾能力已有实测证据，结论可直接采信。")
    _chain_cand = AttackChain(
        chain_id="TAKE_CONTROL-ADMIN_ACCESS-N01N02", objective="TAKE_CONTROL",
        goal=CAP_ADMIN, state="未能验证", nodes=[_n_proven, _n_pending],
        edges=[ChainEdge(src=CAP_CRED, dst=CAP_ADMIN, capability=CAP_ADMIN,
                         condition="泄露的凭据属于管理角色")],
        missing=["目标能力「管理功能访问」本身尚未被实测证明",
                 "凭据 → 管理功能访问：泄露的凭据属于管理角色"],
        note="这是一条候选链。")

    # ① 已达成链：必须给出实测证据与复测入口
    ctx_c1 = ReportContext(
        target_name="链目标", primary_domain="chain.example.com",
        gate_result=None, blocked_findings=[], render={},
        chains=[_chain_done])
    p_c1 = gen.generate(ctx_c1, fs, app)
    tech_c1 = p_c1["technical"].read_text(encoding="utf-8")
    pay_c1 = _json.loads(p_c1["data"].read_text(encoding="utf-8"))
    check("攻击链分析" in tech_c1, "有攻击链时必须单列成节")
    check("#### 已达成" in tech_c1, "已达成链必须与候选链分开标题")
    check("实测已证" in tech_c1, "已达成链必须标明该环节是实测证明的")
    check("复测" in tech_c1, "攻击链必须给出复测入口（否则与猜测无异）")
    check(len(pay_c1.get("attack_chains", {}).get("proven", [])) == 1,
          "已达成链必须落盘到 proven 桶（便于批量统计真实战果）")

    # ② 只有候选链时：绝不能被渲染成「已达成」
    ctx_c2 = ReportContext(
        target_name="链目标", primary_domain="chain.example.com",
        gate_result=None, blocked_findings=[], render={},
        chains=[_chain_cand])
    p_c2 = gen.generate(ctx_c2, fs, app)
    tech_c2 = p_c2["technical"].read_text(encoding="utf-8")
    pay_c2 = _json.loads(p_c2["data"].read_text(encoding="utf-8"))
    check("#### 已达成" not in tech_c2,
          "候选链不得被渲染成「已达成」小节（这是把推理写成事实）")
    check("候选链" in tech_c2 and "未逐环实测" in tech_c2,
          "候选链必须显式标注「推导所得、未逐环实测」")
    check("不是漏洞结论" in tech_c2,
          "候选链必须明写「不是漏洞结论」，否则会被当成战果")
    check("尚待确认" in tech_c2,
          "候选链必须逐条列出待确认的衔接条件（这是它唯一的行动价值）")
    check(pay_c2.get("attack_chains", {}).get("proven") == [],
          "候选链不得进「已达成」落盘桶")
    check(len(pay_c2.get("attack_chains", {}).get("candidates", [])) == 1,
          "候选链应落在 candidates 桶，与战果分开统计")

    # ③ 无链但有说明 → 说明必须出现（否则读者分不清「组合不出」与「没做」）
    ctx_c3 = ReportContext(
        target_name="链目标", primary_domain="chain.example.com",
        gate_result=None, blocked_findings=[], render={},
        chains=[], chain_notes=["本次未组合出攻击链：现有发现之间没有可衔接的能力关系"])
    tech_c3 = gen.generate(ctx_c3, fs, app)["technical"].read_text(encoding="utf-8")
    check("未组合出攻击链" in tech_c3,
          "无链时必须说明「分析过了、确实组合不出」，不得静默跳过")

    # ④ 既无链也无说明 → 不得凭空出现该节
    ctx_c4 = ReportContext(
        target_name="链目标", primary_domain="chain.example.com",
        gate_result=None, blocked_findings=[], render={},
        chains=[], chain_notes=[])
    tech_c4 = gen.generate(ctx_c4, fs, app)["technical"].read_text(encoding="utf-8")
    # 按**标题行**判定，而不是裸词搜全文：这份报告的首屏「降级自曝」表里会合法地
    # 提到「3.4 攻击链分析」（它正是在声明这一节因缺上下文而塌陷）。裸词搜全文会
    # 把「提到了这一节」误判成「出现了这一节」，而本断言的真实意图是「该节不得
    # 凭空出现」。判定口径必须跟意图对齐，否则以后只会靠改断言来让它变绿。
    _heads_c4 = [ln for ln in tech_c4.splitlines()
                 if ln.lstrip().startswith("#") and "攻击链分析" in ln]
    check(not _heads_c4,
          "既无链也无说明时不得出现该节（避免无中生有）")

    # ---- 会话上下文披露（越权类复现依赖真实身份）----
    # 这一段的判据是「读者会不会误读」：越权类脚本在没填会话时打印的是
    # 「无法判定」（退出码 2）。若报告只说「无法判定」，读者会理解为
    # 「工具能力不足」，而真实原因只是「凭据还没填」——
    # 处置动作完全不同（一个要补检测器，一个只要填一份 JSON）。
    # 所以三处必须同时出现，缺一处就会出现误读：
    #   · 漏洞详情表：这一条的脚本依赖外部凭据；
    #   · 复现总述：无法判定里有一部分只是没填凭据；
    #   · JSON 落盘：批量统计要能区分两类原因。
    check("复现所需身份" in tech,
          "含会话要求的判定组必须单独列出「复现所需身份」列")
    check("aiscan_sessions.json" in tech,
          "报告必须给出会话文件路径（否则读者不知道去哪填）")

    F_SESS = mk("WSTG-ATHZ-02", "疑似水平越权：同角色账号返回完全相同的个人数据",
                "高危", "strong", "cross_role", "verify_athz.py",
                endpoint="https://biz.example.com/api/orders/1002")
    F_SESS.extra["repro_needs_session"] = True
    F_SESS.extra["repro_roles"] = ["user_a", "user_b"]
    F_SESS.verify_result = "confirmed"
    fs_sess = FindingSet(target="会话自测目标")
    fs_sess.add(F_SESS)
    ctx_s = ReportContext(target_name="会话自测目标", primary_domain="biz.example.com",
                          gate_result=None, blocked_findings=[], render={})
    p_s = gen.generate(ctx_s, fs_sess, app)
    tech_s = p_s["technical"].read_text(encoding="utf-8")
    pay_s = _json.loads(p_s["data"].read_text(encoding="utf-8"))

    check("复现所需身份" in tech_s,
          "越权类发现必须标明复现所需身份（否则读者不知脚本依赖凭据）")
    check("user_a" in tech_s and "user_b" in tech_s, "必须列出具体角色名")
    check("无需修改脚本" in tech_s or "无需改动脚本" in tech_s,
          "必须说明凭据由脚本自行读取、不需要改脚本（改了就不能作为交付物外发）")
    check("两个身份" in tech_s, "复现方式必须说明是跨身份比对，不能只写「无凭据直连」")
    check(any(x.get("item_id") == "WSTG-ATHZ-02"
              for x in pay_s.get("repro_sessions", {}).get("needed", [])),
          "需要会话的发现必须落盘到 repro_sessions")
    check("aiscan_sessions.json" in pay_s.get("repro_sessions", {}).get("howto", ""),
          "落盘必须带填写方式（处置动作要能据此自动化）")

    # ---- 外部引擎（nuclei）回填披露 ----
    # 回填解决的是「报告自相矛盾」：第 2 章列着一条附请求/响应原文的实测发现，
    # 第 3 章同一检查项却写「通过」。披露要落在 JSON 上，因为批量统计只看 JSON,
    # 看不到那两栏打架。
    from engine.nuclei_map import BackfillReport  # noqa: PLC0415

    _bf = BackfillReport(source="nuclei", attached=3, items_touched=2,
                         state_changed={"通过": 1, "N/A": 1},
                         skipped_non_vuln=2, unmapped=["WSTG-X-01｜某模板命中"],
                         notes=["以下 1 条 nuclei 发现找不到对应检查项……"])
    ctx_bf = ReportContext(target_name="回填目标", primary_domain="bf.example.com",
                           gate_result=None, blocked_findings=[], render={},
                           external_backfill=_bf)
    p_bf = gen.generate(ctx_bf, fs, app)
    pay_bf = _json.loads(p_bf["data"].read_text(encoding="utf-8"))
    _eb = pay_bf.get("external_backfill", {})
    check(_eb.get("attached") == 3, "回填条数必须落盘（批量统计据此判断回填是否生效）")
    check(_eb.get("state_changed", {}).get("通过") == 1,
          "「通过→不通过」的改判必须落盘（这是回填最重要的动作）")
    check(_eb.get("skipped_non_vuln") == 2,
          "识别类命中被拦下的条数必须落盘（否则无从判断是否误报收紧了结论）")
    check(_eb.get("unmapped") == ["WSTG-X-01｜某模板命中"],
          "未归口的发现必须落盘（否则没人会去补归口表）")
    check(bool(_eb.get("mapping_stats")),
          "归口表规模必须落盘（表被改坏是静默的，只能靠规模下界发现）")

    # ---- 外部引擎（nuclei）执行范围披露 ----
    # 不披露「跑了多大范围 / 跑完了没有」，被预算掐断的那一批会被读成
    # 「扫过了、没问题」。所以既要写进正文（人看得见），也要落进 JSON（机器可核）。
    _nuc_pass = {
        "tags_include": ["cve", "misconfig"], "tags_exclude": ["fuzz"],
        "protocols_exclude": ["file", "code", "javascript", "headless", "whois"],
        "rate_limit": 20, "concurrency": 8, "bulk_size": 20,
        "per_request_timeout": 12, "retries": 1, "max_host_error": 30,
    }
    _nuc_plan = {
        "risk_level": "standard", "budget_seconds": 420,
        "excluded_protocols": ["file", "code", "javascript", "headless", "whois"],
        "notes": ["已排除对 URL 目标结构性不适用的模板类型"],
        "passes": [dict(_nuc_pass, label="高价值（critical/high）",
                        severity=["critical", "high"]),
                   dict(_nuc_pass, label="其余（medium）", severity=["medium"])],
    }
    ctx_nuc = ReportContext(
        target_name="外部引擎自测目标", primary_domain="nuclei.example.com",
        gate_result=None, blocked_findings=[], render={},
        nuclei_run={
            "available": True, "executed": True, "elapsed": 512.0,
            "findings": 3, "template_count": 2,
            "scope_total": 3190, "scope_known": True,
            "partial": True, "budget_exhausted": True, "plan": _nuc_plan,
            "passes": [
                {"pass": 1, "label": "高价值（critical/high）",
                 "severity": ["critical", "high"], "status": "ok",
                 "findings": 3, "templates": 3190, "elapsed": 128.0},
                {"pass": 2, "label": "其余（medium）", "severity": ["medium"],
                 "status": "timeout", "findings": 0, "templates": None,
                 "elapsed": 384.0},
            ],
            "notes": ["第 2 趟执行到预算上限被掐断 —— 已抢救此前写出的结果"],
        })
    p_nuc = gen.generate(ctx_nuc, fs, app)
    tech_nuc = p_nuc["technical"].read_text(encoding="utf-8")
    pay_nuc = _json.loads(p_nuc["data"].read_text(encoding="utf-8"))
    check("3.2.2" in tech_nuc, "必须披露外部引擎执行情况（跑了多大范围、跑完了没有）")
    check("已排除模板类型" in tech_nuc,
          "必须说明排除了哪些模板类型（否则「没有发现」无法解释）")
    check("未跑完" in tech_nuc and "被预算掐断" in tech_nuc,
          "被预算截断必须明说，否则「跑到一半」会被读成「扫过了没问题」")
    check("未执行（预算耗尽）" in tech_nuc or "未执行" in tech_nuc,
          "未执行的趟次必须与「跑了没发现」在报告里分开表述")
    _nj = pay_nuc.get("nuclei", {})
    check(_nj.get("partial") is True and _nj.get("budget_exhausted") is True,
          "截断事实必须落盘（批量统计只看 JSON，看不到正文里的提醒）")
    check(len(_nj.get("passes") or []) == 2, "趟次明细必须落盘")
    check(_nj.get("plan", {}).get("budget_seconds") == 420, "预算必须落盘")
    check("headless" in (_nj.get("plan", {}).get("excluded_protocols") or []),
          "排除的模板类型必须落盘（减量范围要可核对）")
    check("3190 份模板" in tech_nuc,
          "必须给出本次实际纳入的模板份数（这是解读「无发现」最关键的单一数字）")
    check(_nj.get("scope_known") is True and _nj.get("scope_total") == 3190,
          "执行范围必须落盘")
    check("未清点" in tech_nuc or all(
        isinstance(p.get("templates"), int) for p in _nj.get("passes") or []),
        "未清点的趟次不得写成「0 份」（0 = 一份都没有，含义相反）")

    # ---- 凭据缺口一节：必须给出去哪拿，且不得把「没凭据」说成「没问题」 ----
    # 这一节的存在意义：过去「需要令牌但没有」是个静默终点 —— 报告只记
    # 「未执行」，读者不知道该去哪拿、怎么给，那几项就永远补不上。
    print("\n[凭据缺口披露]")
    _ask = {
        "target": "cred.example.com",
        "target_url": "https://cred.example.com",
        "session_file": "C:/Users/<用户名>/...",
        "needs": [{
            "role": "user_a", "label": "普通用户", "why": "当前登录态：未提供凭据；未配置测试账号",
            "blocked": [["WSTG-ATHZ-03", "垂直 / 水平权限提升矩阵测试"],
                        ["WSTG-BUSL-06", "工作流与审批绕过测试"]],
            "entry_url": "https://cred.example.com/login",
            "entry_evidence": "/login 返回 200 且含密码输入框（对照随机路径 404）",
            "entry_source": "path_probe", "configured": False,
            "present": False, "verified": "",
        }, {
            # 第二个身份是**必须**的：越权判定要 ≥2 个身份，报告也要按账号分轮。
            # 只放一个身份的夹具测不到「一轮一个账号」那条警示 ——
            # 而那条警示正是防「第二个账号被写成第一个的凭据」的。
            "role": "admin_a", "label": "高权账号（管理员 / 跨租户）",
            "why": "当前登录态：未提供凭据；未配置测试账号",
            "blocked": [["WSTG-ATHZ-03", "垂直 / 水平权限提升矩阵测试"]],
            "entry_url": "https://cred.example.com/login",
            "entry_evidence": "/login 返回 200 且含密码输入框（对照随机路径 404）",
            "entry_source": "path_probe", "configured": False,
            "present": False, "verified": "",
        }],
        "notes": [],
    }
    ctx_c = ReportContext(target_name="令牌缺口目标", primary_domain="cred.example.com",
                          gate_result=res, blocked_findings=[],
                          item_results=[_ir(1, "未执行")], cred_ask=_ask)
    p_c = gen.generate(ctx_c, fs, app)
    tech_c = p_c["technical"].read_text(encoding="utf-8")
    # 断言打在**章节标题**上，不打在「凭据缺口」这个短语上 ——
    # 目标名里恰好含这几个字时，短语断言会假通过（已经踩过一次）。
    check("凭据缺口：需要登录令牌" in tech_c, "缺凭据时报告单列「凭据缺口」一节")
    check("https://cred.example.com/login" in tech_c,
          "凭据缺口一节必须给出**有证据的**登录入口（否则读者不知道去哪拿）")
    check("没有结论" in tech_c,
          "凭据缺口一节必须说明这些项「没有结论」（不得写成通过或未见异常）")
    check("aiscan.py creds --target cred.example.com" in tech_c,
          "凭据缺口一节必须给出可直接照抄的补齐命令（含 --target）")
    check("不要把令牌贴进对话" in tech_c,
          "凭据缺口一节必须提示令牌不要贴进对话（凭据不得进入第三方日志）")
    check("verify_path" in tech_c,
          "凭据缺口一节必须点明回验需要「登录后才能访问」的页面")
    # 多身份时报告必须**分轮**，并显式禁止把命令连着跑。
    # 报告是留存下来的那一份（终端输出关了就没），照着它执行的人更多，
    # 所以这个坑在报告里比在终端里更危险：剪贴板一次只装得下一个账号的 Cookie，
    # 连着跑会把第二个账号写成第一个账号的凭据 —— 两个身份塌成同一个人，
    # 越权判定退化成「自己和自己比」，结论全失真，而写入本身不会报错。
    check("一个账号一轮" in tech_c,
          "缺凭据且待补身份 ≥2 时，报告必须分轮说明（否则第二个账号会被写成第一个的凭据）")
    check("不要把几条命令连着跑" in tech_c,
          "报告必须显式禁止把几条写入命令连着跑")
    check("第 1 轮" in tech_c and "第 2 轮" in tech_c,
          "待补身份 ≥2 时报告应给出逐轮的标题，而不是一串并列命令")
    check("--verify-path" in tech_c,
          "报告的回验命令必须带上 --verify-path（不填等于没验）")
    # 反向：没有凭据缺口时不得凭空出现这一节（假披露与不披露同样有害）
    ctx_nc = ReportContext(target_name="无缺口目标", primary_domain="nocred.example.com",
                           gate_result=res, blocked_findings=[],
                           item_results=[_ir(1, "未执行")], cred_ask={})
    tech_nc = gen.generate(ctx_nc, fs, app)["technical"].read_text(encoding="utf-8")
    check("凭据缺口：需要登录令牌" not in tech_nc, "没有凭据缺口时不得凭空捏造该节")

    # ---- 黑客视角凭据获取留痕（红队是怎么「进场」的）----
    #
    # 这一节披露的是**主动动作**：工具真的向目标提交了默认口令。三种形态的
    # 读法完全不同，写错任何一条都会误导：
    #   · 命中 → 必须给出取得的身份，并说明该事实本身即一条高危发现；
    #   · 未命中 → 必须写「不等于系统不存在弱口令」。否则一次未命中会被读成
    #     「这个系统的口令没问题」，而本次只试了一小撮公开组合；
    #   · 档位关闭 → 必须写「未执行」并给出原因。让这一节整个消失最危险 ——
    #     读者会把「没做」读成「做了、没问题」。
    # 另有一条硬约束：口令原文绝不能出现。报告本身是会被转发的文书，
    # 把命中口令写进报告等于把泄露源从扫描器搬到了收件箱。
    print("\n[凭据获取留痕披露]")

    _ch_hit = {
        "enabled": True, "reason": "",
        "entry_url": "https://cred.example.com/login", "entry_source": "path_probe",
        "tried": 2, "found_identities": ["admin"], "lockout_hit": False,
        "stopped_reason": "命中默认口令，已停止后续尝试",
        "attempts": [
            {"url": "https://cred.example.com/api/login", "account": "admin",
             "pw_fingerprint": "9f2c1ab7d4e0", "outcome": "认证失败", "status": 200},
            {"url": "https://cred.example.com/api/login", "account": "admin",
             "pw_fingerprint": "3b7d05e19caf", "outcome": "**命中**", "status": 302},
        ],
        "notes": ["尝试总量未超过档位上限"],
    }
    ctx_ch1 = ReportContext(target_name="凭据自测目标",
                            primary_domain="cred.example.com",
                            gate_result=None, blocked_findings=[], item_results=[],
                            credhunt=_ch_hit)
    p_ch1 = gen.generate(ctx_ch1, fs, app)
    tech_ch1 = p_ch1["technical"].read_text(encoding="utf-8")
    pay_ch1 = _json.loads(p_ch1["data"].read_text(encoding="utf-8"))

    check("### 4.1 凭据获取" in tech_ch1,
          "有凭据获取动作时必须单列 4.1 节（这是「主动动作」的披露位）")
    check("https://cred.example.com/login" in tech_ch1,
          "4.1 必须写明实际使用的登录入口（读者据此判断「从哪进去的」）")
    check("实际取得身份" in tech_ch1 and "admin" in tech_ch1,
          "命中时必须给出取得的身份（这是漏洞清单里越权类结论的前提）")
    check("该事实本身即一条高危发现" in tech_ch1,
          "命中默认口令本身就是漏洞，必须在披露里点明（否则它会被当成「测试手段」）")
    check("命中默认口令，已停止后续尝试" in tech_ch1,
          "停止原因必须写进报告（证明命中后没有继续试探）")
    check("口令原文不记录" in tech_ch1,
          "留痕表必须声明只存散列指纹（否则读者会以为报告藏了口令）")
    check("9f2c1ab7d4e0" in tech_ch1,
          "逐次留痕必须给出散列指纹（这是「试过哪几组」的唯一可核对凭据）")
    check(pay_ch1.get("credential_hunt", {}).get("found_identities") == ["admin"],
          "凭据获取结果必须落盘（批量统计只看 JSON，看不到正文表格）")
    check("credential_hunt" in pay_ch1,
          "凭据获取必须落盘到结构化数据")

    # 未命中：措辞是本节的命门 —— 一次未命中绝不能被读成「口令没问题」
    _ch_miss = {
        "enabled": True, "reason": "", "entry_url": "https://m.example.com/login",
        "entry_source": "path_probe", "tried": 6, "found_identities": [],
        "lockout_hit": False, "stopped_reason": "尝试数量达到档位上限",
        "attempts": [{"url": "https://m.example.com/api/login", "account": "admin",
                      "pw_fingerprint": "aaaaaaaaaaaa", "outcome": "认证失败",
                      "status": 200}],
        "notes": [],
    }
    ctx_ch2 = ReportContext(target_name="未命中目标", primary_domain="m.example.com",
                            gate_result=None, blocked_findings=[], item_results=[],
                            credhunt=_ch_miss)
    tech_ch2 = gen.generate(ctx_ch2, fs, app)["technical"].read_text(encoding="utf-8")
    check("不等于" in tech_ch2 and "不存在弱口令" in tech_ch2,
          "未命中时必须写「不等于系统不存在弱口令」—— 否则一次未命中会被"
          "读成「口令没问题」，而本次只试了极小一撮公开组合")
    check("实际取得身份" not in tech_ch2,
          "未命中时不得出现「实际取得身份」（无中生有等同于假战果）")
    check("尝试数量达到档位上限" in tech_ch2,
          "未命中也要给出停止原因（是试够了还是主动放弃，处置动作不同）")

    # 无表单页 → 字段名是假定的：这一行改的是**整节的读法**。
    # 没有它，一次「字段名猜错」会被读成「口令试过了、没问题」——
    # 而实际根本没碰到口令校验那一层。
    _ch_assume = dict(_ch_miss, assumed_fields=True)
    ctx_ch2b = ReportContext(target_name="假定字段名目标",
                            primary_domain="api.example.com",
                            gate_result=None, blocked_findings=[],
                            item_results=[], credhunt=_ch_assume)
    tech_ch2b = gen.generate(ctx_ch2b, fs, app)["technical"].read_text(
        encoding="utf-8")
    check("字段名是假定的" in tech_ch2b,
          "无表单页直接提交时必须披露「字段名是假定的」"
          "（否则字段名猜错会被读成「口令没问题」）")
    check("不能推断该系统不存在弱口令" in tech_ch2b,
          "假定字段名的使用场景必须写明「不能据此推断不存在弱口令」")
    check("只说明没试对口令校验那一层" in tech_ch2b,
          "必须点明「认证失败」在这层假定下只能说明没试对校验那一层")
    # 反向：有表单页（字段名是读出来的）时不得出现这段免责声明
    _ch_form = dict(_ch_miss, assumed_fields=False)
    ctx_ch2c = ReportContext(target_name="表单目标",
                             primary_domain="form.example.com",
                             gate_result=None, blocked_findings=[],
                             item_results=[], credhunt=_ch_form)
    tech_ch2c = gen.generate(ctx_ch2c, fs, app)["technical"].read_text(
        encoding="utf-8")
    check("字段名是假定的" not in tech_ch2c,
          "读出了真实字段名时不得出现「字段名是假定的」（假披露同样有害）")

    # 档位关闭：不得消失，必须明写「未执行」
    ctx_ch3 = ReportContext(
        target_name="安全档目标", primary_domain="safe.example.com",
        gate_result=None, blocked_findings=[], item_results=[],
        credhunt={"enabled": False, "reason": "当前档位不尝试任何口令",
                  "tried": 0, "found_identities": [], "attempts": [], "notes": []})
    tech_ch3 = gen.generate(ctx_ch3, fs, app)["technical"].read_text(encoding="utf-8")
    check("### 4.1 凭据获取" in tech_ch3,
          "档位关闭时 4.1 节也不得消失（消失会被读成「试过了、没问题」）")
    check("未执行" in tech_ch3 and "当前档位不尝试任何口令" in tech_ch3,
          "档位关闭必须写明「未执行」并给出原因")

    # 反向：压根没跑凭据获取（旧路径 / 未接线）时不得捏造这一节
    ctx_ch4 = ReportContext(target_name="无凭据目标",
                            primary_domain="noch.example.com",
                            gate_result=None, blocked_findings=[], item_results=[],
                            credhunt={})
    tech_ch4 = gen.generate(ctx_ch4, fs, app)["technical"].read_text(encoding="utf-8")
    check("### 4.1 凭据获取" not in tech_ch4,
          "未执行凭据获取流程时不得出现 4.1 节（假披露与不披露同样有害）")
    pay_ch4 = _json.loads(gen.generate(ctx_ch4, fs, app)["data"]
                          .read_text(encoding="utf-8"))
    check(pay_ch4.get("credential_hunt", {}).get("ran") is False,
          "未跑凭据获取时必须落盘 ran=False —— 只看 enabled 会把「模块没接线」"
          "读成「档位关闭、符合预期」，一次真实发生的口令尝试就此静默")
    check(pay_ch1.get("credential_hunt", {}).get("ran") is True,
          "跑过凭据获取时必须落盘 ran=True")

    # 复现方式标签：weak_login 是 credhunt 产出的发现专用的复现类型。
    # 它必须显示通俗说明 —— 内部键名出现在复现说明里，读者无法据此行动。
    from report.generator import REPRO_KIND_NOTE  # noqa: PLC0415
    check("weak_login" in REPRO_KIND_NOTE,
          "weak_login 必须有通俗复现说明（默认口令类发现的复现方式）")
    check("默认口令" in REPRO_KIND_NOTE.get("weak_login", ""),
          "weak_login 的说明必须点明「默认口令」（这才是读者能核对的复现入口）")

    F_WL = mk("WSTG-ATHN-02", "存在默认 / 弱口令可登录（账号 admin）", "高危",
              "medium", "weak_login", "verify_wstg_athn_02.py",
              endpoint="https://cred.example.com/login")
    F_WL.extra["repro"] = {"kind": "weak_login",
                           "path": "/login", "method": "POST"}
    F_WL.verify_result = "confirmed"
    fs_wl = FindingSet(target="弱口令自测目标")
    fs_wl.add(F_WL)
    ctx_wl = ReportContext(target_name="弱口令自测目标",
                           primary_domain="cred.example.com",
                           gate_result=None, blocked_findings=[], item_results=[],
                           credhunt=_ch_hit)
    tech_wl = gen.generate(ctx_wl, fs_wl, app)["technical"].read_text(encoding="utf-8")
    check(REPRO_KIND_NOTE["weak_login"] in tech_wl,
          "弱口令发现的复现方式必须渲染成通俗说明，不得回退成内部键名 weak_login")
    check("| weak_login |" not in tech_wl,
          "报告不得泄漏内部键名 weak_login（读者无法据此行动）")

    # ---- 凭据情报（红队自己上网找登录凭据）----
    #
    # 这一节的披露义务来自它的**外部性**：每一次检索都会向第三方暴露
    # 「有人正在关注该目标」。所以检索词必须逐条出现在报告里 ——
    # 只写「做了情报检索」而不写检索了什么，使用方无法核算对外暴露范围，
    # 而这是本项目对使用方的既定承诺。
    # 另一半是**拒绝的透明度**：候选被挡在自动尝试之外时必须逐条说明原因，
    # 静默拒绝会被读成「全都试过了」。
    print("\n[凭据情报披露]")

    _os_hit = {
        "enabled": True, "reason": "",
        "products": [{"name": "Apache Tomcat Manager",
                      "evidence": "路径 /manager/html 返回 HTTP 401；"
                                  "Server 头 含「Apache-Coyote」"}],
        "candidates": [
            {"account": "tomcat", "pw_fingerprint": "aa11bb22cc33",
             "product": "Apache Tomcat Manager", "source": "本地产品默认口令库",
             "strength": "强", "auto_attempt": True, "hold_reason": ""},
            {"account": "svc_deploy", "pw_fingerprint": "dd44ee55ff66",
             "product": "Apache Tomcat Manager", "source": "公开资料检索",
             "strength": "弱", "auto_attempt": False,
             "hold_reason": "口令形态不符合默认 / 弱口令特征（长度或构成更像真实口令）"},
        ],
        "leads": [{"title": "某博客：Tomcat 默认口令汇总",
                   "url": "https://example.org/blog",
                   "snippet": "常见组合 admin/admin",
                   "source": "公开资料检索",
                   "kind": "凭据线索",
                   "why_not_auto": "检索片段中出现疑似可用的凭据，无法判定归属；"
                                    "自动使用可能误伤无关账号"}],
        "queries": ['"Apache Tomcat Manager" default password',
                    '"cred.example.com" default password leaked'],
        "sources": {"产品识别（本地）": "ok", "本地产品默认口令库": "ok",
                    "公开资料检索": "检索失败（网络不可达：DNS 解析失败）"},
        "notes": ["[凭据情报] 本次向公开检索源发出了 2 次查询"],
        "hits_seen": 0,
    }
    ctx_os = ReportContext(target_name="情报自测目标",
                           primary_domain="cred.example.com",
                           gate_result=None, blocked_findings=[], item_results=[],
                           credhunt=_ch_hit, credosint=_os_hit)
    p_os = gen.generate(ctx_os, fs, app)
    tech_os = p_os["technical"].read_text(encoding="utf-8")
    pay_os = _json.loads(p_os["data"].read_text(encoding="utf-8"))

    check("#### 4.1.1 凭据情报" in tech_os,
          "自己上网找凭据是主动外部动作，必须单列小节披露")
    check("### 4.1 凭据获取" in tech_os,
          "加了情报小节后，凭据获取留痕不得被挤掉")
    _q_ok = True
    for _q in _os_hit["queries"]:
        if f"`{_q}`" not in tech_os:
            _q_ok = False
    check(_q_ok,
          "检索词必须逐条披露（否则使用方无法核算对外暴露范围）")
    check("检索失败（网络不可达" in tech_os,
          "检索失败必须具名写进报告 —— 不得含糊成「未发现线索」，"
          "那会把「没检索成」读成「网上没有」")
    check("svc_deploy" in tech_os and "不符合默认 / 弱口令特征" in tech_os,
          "未纳入自动尝试的候选必须逐条给出原因（静默拒绝同样是误导）")
    check("无法判定归属" in tech_os,
          "线索必须写明为何不自动使用 —— 否则会被读成「找到了却没拿来用」")
    check("aa11bb22cc33" in tech_os,
          "候选必须给散列指纹（与尝试表同一套规矩，报告要能外发）")
    check("产品" in tech_os and "Apache-Coyote" in tech_os,
          "识别产品必须附判定证据 —— 没有证据的识别读者无从核对")
    check(pay_os.get("credential_osint", {}).get("queries")
          == _os_hit["queries"],
          "凭据情报（含检索词）必须落盘 —— 批量审计只看 JSON")
    check(pay_os.get("credential_osint", {}).get("ran") is True,
          "跑过凭据情报时必须落盘 ran=True（只看 enabled 会把「模块没接线」"
          "读成「档位关闭、符合预期」）")

    # 反向：没跑凭据情报时不得捏造这一节
    ctx_os_off = ReportContext(target_name="无情报目标",
                               primary_domain="noos.example.com",
                               gate_result=None, blocked_findings=[],
                               item_results=[], credhunt={}, credosint={})
    tech_os_off = gen.generate(ctx_os_off, fs, app)["technical"] \
        .read_text(encoding="utf-8")
    check("4.1.1 凭据情报" not in tech_os_off,
          "未执行凭据情报时不得出现该小节（假披露与不披露同样有害）")
    pay_os_off = _json.loads(gen.generate(ctx_os_off, fs, app)["data"]
                             .read_text(encoding="utf-8"))
    check(pay_os_off.get("credential_osint", {}).get("ran") is False,
          "未跑凭据情报时必须落盘 ran=False")

    # 引擎不可用时也必须说明覆盖范围收缩，而不是静默少一节
    ctx_nn = ReportContext(target_name="无引擎目标", primary_domain="noengine.example.com",
                           gate_result=None, blocked_findings=[], render={},
                           nuclei_run={"available": False, "executed": False,
                                       "reason": "本机未安装 nuclei，本次仅由内置检测器覆盖"})
    p_nn = gen.generate(ctx_nn, fs, app)
    tech_nn = p_nn["technical"].read_text(encoding="utf-8")
    check("未使用 nuclei" in tech_nn,
          "外部引擎不可用时必须说明覆盖范围收缩，不得静默略过")

    # ---- 扫描通告（对外通晒版）----
    # 这份是**直接贴进部门大群**的那一份，读者含被通报系统的负责人、其上级
    # 以及大量无关同事。它出错的代价与另两份不同：技术版写错了研发能看出来，
    # 通告写错了全部门都会照着错的理解走。
    print("\n[N] 扫描通告（对外通晒版）")

    check("notice" in paths and paths["notice"].exists(),
          "generate() 必须产出扫描通告（每扫完一个系统晒的就是这一份）")
    n1 = paths["notice"].read_text(encoding="utf-8")

    check("闸门自测目标" in n1 and "demo.example.com" in n1,
          "通告开头必须写清「扫的是哪个系统、域名是什么」")
    check("从公网外部发起真实攻击测试" in n1,
          "通告必须点明公网外部攻击者视角（否则会被读成内网自查）")
    check("不使用任何内部账号" not in n1,
          "通告不得声明「不使用任何内部账号」—— 提供凭据时红队确实会用"
          "授权测试账号，对外文书里不能有自己都没法验证的绝对声明")
    check("发现严重漏洞" in n1 and "高危漏洞" in n1 and "中危漏洞" in n1,
          "通告必须给出严重 / 高危 / 中危三个计数")
    check("信息泄露" not in n1,
          "低危条目不得出现在通告里（通晒只列严重 / 高危 / 中危）")
    check("本通告只列" not in n1 and "**说明**" not in n1,
          "通告不带文末「说明」段（2026-09-29 定稿：说明内容不要，"
          "「低危未列」的口径由结论段的计数方式自然表达）")
    check("防护有效性" in n1,
          "通告必须给出「防护有效性」的实测结论（红队视角的核心产出）")
    check("未探测到边界拦截特征" in n1,
          "没探到防护时必须如实写「未探测到」—— 2026-09-29 定稿："
          "探测到什么防护写什么防护，没探到也明说")

    # 未触达应用：**不得出漏洞计数**。这是这份报告最危险的失败形态 ——
    # 一份「严重 0 / 高危 0 / 中危 0」的通告发到大群，等于对整个部门宣告
    # 「这个系统没问题」，而事实是压根没测到。
    bv_notice = BlockVerdict(blocked=True, vendor="阿里云 WAF", status=405,
                             signature="body 命中 /errors\\.aliyun\\.com/",
                             uniform=True, root_hash="977b7f3262b1e24b",
                             evidence="根路径与随机不存在路径返回逐字节相同的内容")
    ctx_blk = ReportContext(target_name="通告被拦目标",
                            primary_domain="blocked.example.com",
                            gate_result=None, blocked_findings=[],
                            boundary=bv_notice)
    # 用**空发现集**构造「被拦且无发现」形态：被拦 + 有已复现发现的形态
    # 在下面 n_blk2 单独测 —— 两条路径的口径不同，混用一个夹具会互相打架。
    fs_blk_empty = FindingSet(target="通告被拦目标")
    n_blk = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    check("本次从公网发起真实攻击测试" in n_blk
          and "发现严重漏洞 0 个" in n_blk
          and "不等于「没有问题」" in n_blk,
          "未触达应用时仍须按固定句式给出零计数，**并紧跟「0 个 ≠ 没问题」的限定**"
          "（2026-09-30 安全负责人定稿：靠「不给计数」防误读是反效果 —— "
          "读者连规模都判断不了）")
    check("从公网外部打不进去" in n_blk,
          "被边界拦住时必须明说「从公网外部打不进去」")
    check("探测到的防护" in n_blk and "拦截程度" in n_blk,
          "防护有效性必须按「探到什么写什么 + 到什么程度会拦」的结构写"
          "（2026-09-29 安全负责人定稿）")
    check("挡住 ≠ 里面没问题" in n_blk,
          "通告必须挡住「拦住 = 系统安全」这个误读")
    check("拦住 ≠ 能防住所有攻击者" in n_blk,
          "「防护有效」只能证明对本次来源/手法有效 —— 不写这句，"
          "管理层会读成「防护很到位」，而那是本次数据支持不了的结论")
    check("没有结论" in n_blk,
          "问题清单为空时必须写明「空 = 没有结论，不是没有问题」")
    check("放行" not in n_blk and "重扫" not in n_blk,
          "通告不得出现「放行扫描来源 IP 后重扫」—— 红队与黑客同一视角，"
          "被拦就是「打不进去」这个实测结论本身；放行是内部扫描台账的事，"
          "不进全部门都能看到的文书（2026-09-29 安全负责人定稿）")

    # 被拦但**手里已有实测复现的发现**（OSS / 端口 / DNS —— 不经过 Web 边界
    # 防护通道）：后一次扫描被拦，抹不掉前一次已经复现的事实。
    # 硬写「问题清单为空」等于把真实存在的严重漏洞藏起来 —— 2026-09-29
    # 安全负责人抓出来的真 bug（内部生产系统 18:42 归档 0 发现，18:12 归档 7 条已复现）。
    fs_perim = FindingSet(target="通告被拦目标")
    fs_perim.add(Finding(
        item_id="EXT-OS-01", title="对象存储桶允许匿名列举（被拦场景自测）",
        target="通告被拦目标", endpoint="https://oss.example.com/bucket/",
        method="GET", severity="严重", confidence="High", evidence_level="A",
        description="自测", impact="可直接匿名列举桶内全部对象",
        reproduction="访问 https://oss.example.com/bucket/ 返回对象列表即复现",
        verify_script="verify_oss.py", verify_result="confirmed"))
    n_blk2 = gen.generate(ctx_blk, fs_perim, app)["notice"].read_text(encoding="utf-8")
    check("问题清单为空" not in n_blk2,
          "被拦但已有实测复现的发现时，不得写「问题清单为空」—— "
          "后一次扫描被拦抹不掉已复现的事实")
    check("对象存储桶允许匿名列举" in n_blk2,
          "外围发现必须照列（严重级别更不能丢）")
    check("不经过 Web 边界防护通道" in n_blk2,
          "被拦场景下列发现必须说明为何不受拦截影响，"
          "否则读者会拿「被拦」质疑清单本身")
    # 2026-10-08 安全负责人改版（红线 54）：结论段只留主句，A 类「Web 全部被拦」
    # 这句随之从结论段下移到第三节点明。**要求本身不变**（被拦了不说 = 误导；
    # 说有漏洞却不说 Web 进不去 = 也是误导），只是断言对象从「结论段」换成
    # 「通告整体」—— 换了位置可以，丢了不行。
    check("发现严重漏洞 1 个" in n_blk2
          and "Web 入口被拦截，但下列问题不经过 Web 边界防护通道" in n_blk2,
          "被拦 + 有发现时，通告**整体**必须同时说清「Web 被拦」与「发现漏洞」"
          "两件事，缺一都是误导（改版后由第三节「问题清单」点明）")

    # 绕过试探：探到防护后红队的标准动作是试绕过（2026-09-29 安全负责人定稿）。
    # 通告必须呈现试探结果；有缺口时要点名变形族，全被拦时给正面结论。
    #
    # ⚠ 夹具必须**带基线对照项**（is_baseline=True，结果为 missed）——
    # 这是 2026-09-30 加上的硬约束。早先这三条断言用的是「只有变形、没有
    # 基线」的夹具，而那种夹具恰好就是 内部生产系统 现场的形态：基线不通时
    # 「全部变形被拦」什么也证明不了，通告只能写「无法评估」。用无对照的
    # 夹具去断言「均被拦住」，等于把这条铁律在测试里又违了一次。
    _BASELINE_ROW = {"name": _wb.BASELINE_NAME,
                     "request": "GET https://blocked.example.com（无任何变形）",
                     "outcome": "missed", "status": 200,
                     "why": "HTTP 200，未命中拦截特征", "is_baseline": True}
    ctx_blk.bypass_probes = [
        _BASELINE_ROW,
        {"name": "伪造内网来源（X-Forwarded-For: 127.0.0.1）",
         "request": "GET https://blocked.example.com + X-Forwarded-For: 127.0.0.1",
         "outcome": "blocked", "status": 405, "why": "HTTP 405 与拦截判定同码"},
        {"name": "伪装搜索引擎爬虫 UA（Googlebot）",
         "request": "GET https://blocked.example.com + User-Agent: Googlebot",
         "outcome": "blocked", "status": 405, "why": "HTTP 405 与拦截判定同码"},
        {"name": "路径规范化变形（/./）",
         "request": "GET https://blocked.example.com/./",
         "outcome": "missed", "status": 200, "why": "HTTP 200，未命中拦截特征"},
    ]
    n_blk3 = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    check("绕过尝试" in n_blk3,
          "探到防护后通告必须呈现绕过试探（试没试、结果如何）")
    check("不构成绕过证据" in n_blk3 and "路径规范化变形" in n_blk3,
          "有变形未被拦截特征命中时必须点名，且**不得**写成「疑似存在绕过面」——"
          "该夹具里基线请求同时刻可达应用（HTTP 200），说明边界本就未拦阻"
          "常规请求，没有可绕之物；missed 只说明「该变形未被拦」，"
          "不构成绕过证据（红线：孤立信号不得当正面证据）")
    check("伪造内网来源" in n_blk3,
          "试探覆盖的变形族要可见（读者得知道红队试过什么）")
    ctx_blk.bypass_probes = [
        _BASELINE_ROW,
        {"name": "伪造内网来源（X-Forwarded-For: 127.0.0.1）",
         "request": "GET https://blocked.example.com + X-Forwarded-For: 127.0.0.1",
         "outcome": "blocked", "status": 405, "why": "同码"},
        {"name": "伪装搜索引擎爬虫 UA（Googlebot）",
         "request": "GET https://blocked.example.com + User-Agent: Googlebot",
         "outcome": "blocked", "status": 405, "why": "同码"},
    ]
    n_blk4 = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    check("均被拦住" in n_blk4 and "疑似存在绕过面" not in n_blk4,
          "基线对照成立且变形全被拦时，才给「均被拦住」的正面结论；"
          "对照不成立时这句只能在「无法评估」分支里出现（见下方 _n_bp 断言）")

    # 「一个都没被拦」——最容易写成「绕过面很大」的形态。判据的落脚点不是
    # 变形，而是**同一批里的基线**：无变形请求也是 2xx，就说明此刻边界对这些
    # 请求整体没生效。没有拦可拦的东西时，绕过无从谈起。
    # 2026-09-30 内部生产系统 实测原形：12/12 未被拦，同时基线对照 HTTP 200 ——
    # 通告当时写的却是「其中 12 种未被拦截特征命中 …… 疑似存在绕过面」。
    ctx_blk.bypass_probes = [
        _BASELINE_ROW,
        {"name": "伪造内网来源（X-Forwarded-For: 127.0.0.1）",
         "request": "GET https://blocked.example.com + X-Forwarded-For: 127.0.0.1",
         "outcome": "missed", "status": 200, "why": "HTTP 200，未命中拦截特征"},
        {"name": "伪装搜索引擎爬虫 UA（Googlebot）",
         "request": "GET https://blocked.example.com + User-Agent: Googlebot",
         "outcome": "missed", "status": 200, "why": "HTTP 200，未命中拦截特征"},
    ]
    n_blk5 = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    check("疑似存在绕过面" not in n_blk5 and "不能读成「绕过了防护」" in n_blk5,
          "基线通、变形一个都没被拦时，必须点明「此刻边界整体没生效」，"
          "不得写成「疑似存在绕过面」—— 没有拦可拦的东西时绕过无从谈起")
    ctx_blk.bypass_probes = []

    # 复现步骤的收敛：通告要发大群，里面不该有能直接复制执行的内容。
    fs_notice = FindingSet(target="通告自测目标")
    fs_notice.add(Finding(
        item_id="WSTG-INPV-05", title="SQL 注入（通告自测）",
        target="通告自测目标", endpoint="https://demo.example.com/api/query",
        method="GET", param="id", severity="高危", confidence="High",
        evidence_level="A", description="自测", impact="可直接读取业务数据",
        reproduction=("curl -s 'https://demo.example.com/api/query?id=1%27' | head -20\n"
                      "# 返回数据库报错即为复现成功"),
        verify_script="verify_sqli.py", verify_result="confirmed"))
    fs_notice.add(Finding(
        item_id="WSTG-INFO-01", title="服务器版本信息泄露（低危自测）",
        target="通告自测目标", endpoint="https://demo.example.com/x",
        method="GET", severity="低危", confidence="Low", evidence_level="B",
        description="自测", impact="自测",
        reproduction="curl -s https://demo.example.com/x",
        verify_script="verify_info.py", verify_result="confirmed"))
    ctx_notice = ReportContext(target_name="通告自测目标",
                               primary_domain="notice.example.com",
                               gate_result=None, blocked_findings=[],
                               item_results=[])
    pn_def = gen.generate(ctx_notice, fs_notice, app)
    n_def = pn_def["notice"].read_text(encoding="utf-8")
    n_full = gen.generate(ctx_notice, fs_notice, app,
                          notice_full_repro=True)["notice"].read_text(encoding="utf-8")

    check("curl" not in n_def,
          "默认通告里不得出现可直接执行的命令（否则通告就是可分发的验证手册）")
    check("https://demo.example.com/api/query?id=1%27" in n_def,
          "收敛后必须保留「打哪里」—— 否则被通报方无法自行确认")
    check("返回数据库报错即为复现成功" in n_def,
          "收敛后必须保留「看到什么算复现成功」的判定标准")
    check("服务器版本信息泄露" not in n_def,
          "低危条目不得进入通告（换一份数据再钉一次同一口径）")
    check("curl" in n_full,
          "显式指定 notice_full_repro 时必须原样保留命令（内部技术通道用）")

    # 收敛函数本身的边界形态：reproduction 由各检测器各自拼装、形态不受控，
    # 漏掉一种形态就等于通告里漏出一段可执行内容。
    from report.generator import notice_repro_mask  # noqa: PLC0415
    check(notice_repro_mask("curl -s 'https://a.test/x' | head") == "访问 `https://a.test/x`",
          "行首命令 → 只留地址")
    check("curl" not in notice_repro_mask("`curl -s https://a.test/x | jq .` 即可看到"),
          "被反引号包裹的命令同样要收敛")
    check(notice_repro_mask("请执行 curl -s https://a.test/x 查看")
          == "（请求构造见《技术版报告》对应条目）",
          "预判不到的形态必须整段退掉（宁可少细节，不漏可执行内容）")
    check(notice_repro_mask("1. 打开 https://a.test/x\n2. 改 id 为 2\n3. 即复现")
          == "1. 打开 https://a.test/x\n2. 改 id 为 2\n3. 即复现",
          "不含命令的步骤描述应原样保留（复现路径本身要留给负责人）")
    check(notice_repro_mask("curl -s https://a.test/x", full=True) == "curl -s https://a.test/x",
          "full=True 必须原样返回（开关要真的有效）")

    # 有缺口时：通告只要求**结论段**给出「有结论 / 覆盖」的口径，
    # 不再附带文末说明段逐项点数（2026-09-29 定稿：说明内容不要）。
    # 缺口明细（未执行 / 待人工 / 待确认各多少、怎么补）在技术版第 3 章。
    ctx_gap = ReportContext(
        target_name="通告缺口目标", primary_domain="gap.example.com",
        gate_result=None, blocked_findings=[],
        item_results=[SimpleNamespace(state="通过", executable=True),
                      SimpleNamespace(state="未执行", executable=False),
                      SimpleNamespace(state="待人工执行", executable=False),
                      SimpleNamespace(state="待确认", executable=False)])
    # 这里直接调通告渲染器而不是走 generate()：技术版对 item_results 的字段
    # 要求远多于通告，造一个只为测通告的完整伪结果反而会把断言绑到无关细节上。
    n_gap = gen._render_notice(ctx_gap, fs, app)
    check("覆盖 4 项检查" in n_gap and "完成 4 项检查" not in n_gap,
          "通告不得写「完成 N 项检查」—— 列在清单里不等于逐项都测过了")
    # 2026-10-08 安全负责人改版（红线 54）：这条**反转**了。
    # 旧要求是「有缺口时结论段必须给出有结论的项数」（怕读者把没测到的
    # 默认成干净）；改版后结论段只留主句，该口径改由第二节与承接区承担。
    check("项本次有结论" not in n_gap,
          "非零发现时结论段只留主句，不再给出「其中 M 项本次有结论」"
          "（2026-10-08 安全负责人定稿，红线 54）")
    check("本通告只列" not in n_gap and "放行" not in n_gap,
          "缺口说明与放行诉求都不得回到通告里")

    # 封过但已恢复：防护事实（频次类拦截、拦了几次）照写，
    # 但**过程话术不得出现**（2026-09-29 定稿：不说「取证可能来自拦截页」、
    # 不说「结论不完整」—— 读者要的是结果，不是扫描过程叙事）。
    n_res = gen.generate(ctx4, fs, app)["notice"].read_text(encoding="utf-8")
    check("临时拦截" in n_res,
          "封禁恢复后通告必须披露「曾被临时拦截 N 次」（这是防护的实测事实）")
    check("取证可能来自拦截页" not in n_res and "结论不完整" not in n_res,
          "过程话术不得出现在通告里 —— 探到什么防护、拦到什么程度、"
          "扫出什么漏洞，就写这些")
    # 封禁未恢复：防护事实照写（触发拦截且未恢复），同样不带过程话术
    n_term = gen.generate(ctx5, fs, app)["notice"].read_text(encoding="utf-8")
    check("触发拦截且未恢复" in n_term,
          "封禁未恢复时通告必须写明「拦截且未恢复」（这是防护的实测事实）")
    check("结论不完整" not in n_term and "后段未测到" not in n_term,
          "「结论不完整」「后段未测到」等过程话术不得出现（2026-09-29 定稿）")
    check("退避序列耗尽" not in n_term,
          "通告不得引用技术版的长原因原文（群消息要能读）")
    check("未被拦住的流量照常完成扫描" in n_term,
          "被封后仍要交代「没拦住的流量扫出了什么」—— "
          "否则读者只有拦截叙事、没有扫描结果")

    # wafbypass.probe_bypasses 的单元行为（stub 客户端，零网络）：
    # 探到防护 → 试绕过；结论只有 blocked / missed 两档，missed 措辞保守。
    # （`_wb` 在文件顶部导入 —— 上面的通告侧夹具也要用它的基线常量。）

    class _StubClient:
        """全响应拦截页，唯独 /./ 变形直达应用。"""

        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def fetch(self, url, method="GET", extra_headers=None, **kw):  # noqa: ANN001, ARG002
            self.calls.append((method, url))
            class _R:  # noqa: N801
                status = 405
                body_snippet = ("<html><body>405 错误 errors.aliyun.com"
                                " 请检查请求是否合法</body></html>")
                headers = {"Content-Type": "text/html"}
                cookies: list[str] = []
            if "/./" in url:
                _R.status = 200
                _R.body_snippet = "<html><title>业务首页</title>欢迎访问</html>"
            return _R()

    sc = _StubClient()
    bv_stub = BlockVerdict(blocked=True, vendor="阿里云 WAF", status=405,
                           root_hash="deadbeef")
    probes = _wb.probe_bypasses(sc, "https://b.test/app", bv_stub)
    check(len(sc.calls) <= _wb.MAX_PROBES + 1 and len(probes) == len(sc.calls),
          "试探总量有硬上限（变形 ≤12 + 基线对照 1），且每个请求都有留痕")
    check(probes[0].get("is_baseline") is True,
          "结果首位必须是基线对照项（同一客户端、同一时刻、不带任何变形）")
    check(any(p["outcome"] == "missed" for p in probes)
          and any(p["outcome"] == "blocked" for p in probes),
          "命中拦截特征的变形记 blocked，直达应用的记 missed")
    _sum = _wb.summarize(probes)
    check(_sum["missed_names"] and "路径规范化变形（/./）" in _sum["missed_names"],
          "missed 必须点名到变形族（通告直接引用）")

    class _AllBlockedClient(_StubClient):
        def fetch(self, url, method="GET", extra_headers=None, **kw):  # noqa: ANN001, ARG002
            self.calls.append((method, url))
            class _R:  # noqa: N801
                status = 405
                body_snippet = "<html>errors.aliyun.com 拦截页</html>"
                headers = {"Content-Type": "text/html"}
                cookies: list[str] = []
            return _R()

    probes2 = _wb.probe_bypasses(_AllBlockedClient(), "https://b.test/app", bv_stub)
    check(all(p["outcome"] == "blocked" for p in probes2),
          "全部变形被拦时一律 blocked —— 不得把「没试出来」写成「绕过成功」")
    # 基线对照不通 = 整批结论**不可采信**。这正是 2026-09-30 内部生产系统 的原形：
    # 那时通告写出了「均被拦住 —— 拦截对本来源覆盖完整」，而事实上那一刻
    # **连不带任何变形的请求也被拦** —— 计数区分不出「WAF 识别了该变形」
    # 与「这个来源已经打不进去」。
    _sum2 = _wb.summarize(probes2)
    check(_sum2["usable"] is False and _sum2["baseline_ok"] is False,
          "基线对照不通时必须判「整批不可采信」（usable=False）")
    check(_sum2["tried"] == len(probes2) - 1,
          "基线项不得计入 tried（它不是变形，只是那把尺子）")

    class _BaselineOkClient(_StubClient):
        """基线（无变形）直达应用，只有伪造来源头的变形被拦。"""

        def fetch(self, url, method="GET", extra_headers=None, **kw):  # noqa: ANN001, ARG002
            self.calls.append((method, url))

            class _R:  # noqa: N801
                status = 200
                body_snippet = "<html><title>业务首页</title>欢迎访问</html>"
                headers = {"Content-Type": "text/html"}
                cookies: list[str] = []

            if extra_headers and "X-Forwarded-For" in extra_headers:
                _R.status = 405
                _R.body_snippet = "<html>errors.aliyun.com 拦截页</html>"
            return _R()

    _sum3 = _wb.summarize(
        _wb.probe_bypasses(_BaselineOkClient(), "https://b.test/app", bv_stub))
    check(_sum3["usable"] is True and _sum3["baseline_ok"] is True,
          "基线可通时对照成立，整批结论才可采信")
    check(_sum3["blocked"] >= 1 and _sum3["missed"] >= 1,
          "对照成立时「被拦」与「未被拦」必须能区分（否则等于没测）")
    check(_sum3["nothing_blocked"] is False,
          "有变形被拦时不得置 nothing_blocked —— 那是「此刻边界整体没生效」的标记")
    check(_sum2["nothing_blocked"] is False,
          "对照不成立时不得置 nothing_blocked（那会被读成「没生效」而不是「来源已死」）")

    class _AllPassClient(_StubClient):
        """什么都不拦（基线可通、变形也全通）—— 内部生产系统 2026-09-30 的形态。"""

        def fetch(self, url, method="GET", extra_headers=None, **kw):  # noqa: ANN001, ARG002
            self.calls.append((method, url))

            class _R:  # noqa: N801
                status = 200
                body_snippet = "<html><title>业务首页</title>欢迎访问</html>"
                headers = {"Content-Type": "text/html"}
                cookies: list[str] = []

            return _R()

    _sum4 = _wb.summarize(
        _wb.probe_bypasses(_AllPassClient(), "https://b.test/app", bv_stub))
    check(_sum4["usable"] is True and _sum4["nothing_blocked"] is True
          and _sum4["blocked"] == 0 and _sum4["tried"] >= 1,
          "基线可通且一个变形都没被拦时，必须置 nothing_blocked —— "
          "这种形态读作「此刻边界对这些请求整体没生效」，不是「绕过面很大」")

    # ---- 通告侧：按「对照是否成立」分叉；问题清单不得凭空变空 ----
    _ctx_bp = ReportContext(target_name="绕过对照自测", primary_domain="bp.example.com",
                            item_results=items_b, detector_summary={},
                            gate_result=None, blocked_findings=[],
                            boundary_guard=gr_term, bypass_probes=probes2)
    _n_bp = gen.generate(_ctx_bp, fs, app)["notice"].read_text(encoding="utf-8")
    # 2026-10-08 安全负责人改版：措辞从开头的「本次无法评估拦截覆盖率」
    # 换成句尾的「本次不对覆盖率下结论」—— 断言跟着换词，**要求没变**：
    # 基线对照不成立时不得对绕过有效性下任何结论。
    check("本次不对覆盖率下结论" in _n_bp,
          "基线对照不成立时，通告必须明说「不对覆盖率下结论」"
          "（改版前措辞为「无法评估拦截覆盖率」，2026-10-08 安全负责人改版换词）")
    check("覆盖完整" not in _n_bp and "均被拦住" not in _n_bp,
          "基线对照不成立时**不得**写「均被拦住 / 覆盖完整」——"
          "那是在给防护背书，而手上的证据只是「本来源已经打不进去」")

    _ctx_pu = ReportContext(
        target_name="承接自测", primary_domain="carry.example.com",
        item_results=items_b, detector_summary={},
        gate_result=None, blocked_findings=[], boundary_guard=gr_term,
        prior_unverified=[
            {"title": "对象存储桶允许匿名列举（ListBucket 未关闭）",
             "severity": "严重",
             "endpoint": "https://x-files.oss-cn-hangzhou.aliyuncs.com",
             "item_id": "WSTG-CONF-11"},
            {"title": "域名未配置 DMARC 记录", "severity": "中危",
             "endpoint": "DNS TXT _dmarc.x.example.com", "item_id": "EXT-DM-03"},
        ])
    _n_pu = gen.generate(_ctx_pu, fs, app)["notice"].read_text(encoding="utf-8")
    check("问题清单为空" not in _n_pu,
          "上一轮有未复测发现时，通告**不得**写「问题清单为空」——"
          "那会被读成「已经没问题了」（2026-09-30 安全负责人指出）")
    check("对象存储桶允许匿名列举" in _n_pu and "严重" in _n_pu,
          "未复测发现必须逐条列出（含等级），不能只给一个数字")
    check("不构成修复证据" in _n_pu,
          "承接项必须写明「本轮未再检出 ≠ 已修复」")
    check(_n_pu.index("对象存储桶允许匿名列举") < _n_pu.index("域名未配置 DMARC"),
          "承接清单按严重度降序（严重在前）")

    # 承接项**不得**被算进本轮的漏洞计数 —— 它们本轮的真伪还没确认。
    # 把它们混进「本次发现严重漏洞 N 个」，等于拿上一轮的结论给这一轮充数，
    # 而且读者会以为本轮实测到了（实际上本轮连应用都没碰到）。
    _p_pu2 = gen.generate(_ctx_pu, FindingSet(target="承接自测"), app)
    _n_pu2 = _p_pu2["notice"].read_text(encoding="utf-8")
    _t_pu2 = _p_pu2["technical"].read_text(encoding="utf-8")
    check("发现严重漏洞 1 个" not in _n_pu2 and "未发现严重" not in _n_pu2,
          "承接项不得计入本轮漏洞计数（既不能算成「发现了」，也不能掩盖成「没问题」）")
    check("对象存储桶允许匿名列举" in _t_pu2 and "本轮未能复测" in _t_pu2,
          "技术版问题清单为空时同样要承接 —— 承接不能只做在通告里，"
          "技术版才是被存档、被逐条核对的那份")
    check("问题清单为空" not in _n_pu2 and "有 2 条" in _n_pu2,
          "本轮零发现时，通告的问题清单要写「承接 N 条」而不是「空」——"
          "条数也要对得上（2 条不能写成别的数）")

    # ================================================================
    # 归档覆盖守卫 + 渲染留痕 + 降级自曝
    # ----------------------------------------------------------------
    # 这三条对应 2026-09-30 的一次真实事故：为了改通告里的一句措辞，
    # 直接对已完成的归档目录调了 generate()，结果技术版报告 / 管理层摘要 /
    # 结构化数据被一份「上下文残缺」的渲染静默覆盖 —— 章节成段消失，
    # `需人工复核的 N/A 项` 从 12 项变成 0 项、`检查项` 从全量检查项变成 0 项，
    # 而同一目录里的 run-manifest.json 还写着正确结论。
    # 这里把「闸门是否真的会拦」「拦的信息够不够定位」「降级会不会自曝」
    # 全部钉成断言，避免这条防线以后被顺手改成 no-op。
    with tempfile.TemporaryDirectory() as _td:
        _arc = Path(_td) / "20260930_114038"
        _arc.mkdir(parents=True, exist_ok=True)
        # 伪造一个「已完成的归档」：只要标志文件在，守卫就必须认。
        (_arc / "run-manifest.json").write_text("{}", encoding="utf-8")
        (_arc / "检查项结论.json").write_text("{}", encoding="utf-8")

        _ctx_arc = ReportContext(
            target_name="归档守卫自测", primary_domain="guard.example.com",
            item_results=items_b, detector_summary={},
        )
        _raised = ""
        try:
            ReportGenerator(_arc).generate(_ctx_arc, fs, app)
        except RuntimeError as _e:
            _raised = str(_e)
        check(bool(_raised), "往已完成的扫描归档里渲染**必须**被拦下（默认拒绝覆盖）")
        check("拒绝覆盖" in _raised, "守卫的报错要说清「拒绝覆盖」这件事本身")
        check("allow_archive_overwrite" in _raised,
              "守卫的报错要告诉调用方怎么合法地继续（显式声明），"
              "否则下一个人只会去把断言删掉")
        check("20260930_114038" in _raised,
              "守卫的报错要点名是哪个目录 —— 否则多归档并行时无从定位")

        # 所有者（本轮编排器）显式声明后必须放行，否则正常扫描会被自己拦死。
        _p_arc = ReportGenerator(_arc).generate(
            _ctx_arc, fs, app, allow_archive_overwrite=True)
        check(_p_arc["technical"].exists(),
              "显式声明 allow_archive_overwrite=True 后必须放行"
              "（本轮编排器就是这个目录的所有者）")

        # 普通输出目录（无归档标志）不得被误拦 —— 否则自测/示例报告全崩。
        _plain = Path(_td) / "not_an_archive"
        _p_plain = ReportGenerator(_plain).generate(_ctx_arc, fs, app)
        check(_p_plain["technical"].exists(),
              "没有归档标志的普通输出目录不得被守卫误拦")

        # ---- 渲染留痕 ----
        check("provenance" in _p_plain,
              "每次渲染都要落一份「渲染留痕」，否则残缺渲染事后无从分辨")
        _stamp = json.loads(_p_plain["provenance"].read_text(encoding="utf-8"))
        check(_stamp.get("render_source") == "(未声明)" and
              _stamp.get("is_live_run") is False,
              "外来渲染（未声明来源）必须在留痕里标明 is_live_run=False")
        check(_stamp.get("context_complete") is False and
              _stamp.get("warning"),
              "外来渲染且上下文残缺时，留痕要给出 context_complete=False 与警告语")
        check("gate_result" in _stamp.get("context_empty", []),
              "留痕要逐字段列出「缺了哪些运行期上下文」，不能只给一个布尔值")

        # ---- 降级自曝：残缺上下文渲染出来的报告必须自己声明 ----
        _t_deg = _p_plain["technical"].read_text(encoding="utf-8")
        check("降级渲染" in _t_deg,
              "残缺上下文渲染出的报告必须自曝「降级渲染」——"
              "否则它会和正常报告长得一模一样，只有数字是错的")
        check("检查项结论.json" in _t_deg,
              "降级自曝要指明「以哪个文件为准」，否则读者知道是假的却不知道信谁")

        # ---- 本轮运行的完整上下文**不得**被误标成降级 ----
        _ctx_run = ReportContext(
            target_name="本轮渲染自测", primary_domain="run.example.com",
            item_results=items_b, detector_summary={},
            gate_result=None, blocked_findings=[], render_source="run")
        _p_run = ReportGenerator(Path(_td) / "run_out").generate(_ctx_run, fs, app)
        _t_run = _p_run["technical"].read_text(encoding="utf-8")
        check("降级渲染" not in _t_run,
              "本轮运行的上下文不得被误标成「降级渲染」——真实运行里 credhunt "
              "之类字段合法为空（跑了、没命中），把「空」当「缺」会把正常报告淹没")
        _stamp_run = json.loads(_p_run["provenance"].read_text(encoding="utf-8"))
        check(_stamp_run.get("is_live_run") is True and
              _stamp_run.get("context_complete") is True,
              "本轮渲染的留痕要标 is_live_run=True / context_complete=True")

    # ================================================================
    # A 类拦截叙述必须跟着「短路粒度」一起走
    # ----------------------------------------------------------------
    # 这组断言守的是一类**接线改了、文案没跟上**的错：A 类叙述写于
    # 「被封 ⇒ 完全没有发现」的年代；后来短路改成按证据通道分流
    # （判据不经过应用的项目照常执行），被封轮次开始产出**非应用层发现**。
    # 内部生产系统 2026-09-30 12:10 那轮就是：边界全量拦截，但 SPF / DMARC 照常实测
    # （2 条中危）。此时报告若还说「清单为空 / 问题分布为空」，
    # 就是当着读者的面说假话 —— 而且管理层摘要会把这 2 条真实问题整个吞掉。
    _bnd_blk = SimpleNamespace(blocked=True, vendor="阿里云 WAF", status=405,
                               signature="body 命中 /errors\\.aliyun\\.com/",
                               root_hash="ff00283f7bbbe4dd", notes=[])

    # ① 被拦 + 有非应用层发现 → 不得声称「为空」，且必须把条数写出来
    _fs_b = FindingSet(target="拦截有发现")
    _fs_b.add(mk("EXT-DM-01", "域名未配置 SPF 记录", "中危", "strong",
                 "dns_query", "verify_spf.py",
                 endpoint="DNS TXT blocked.example.com"))
    _fs_b.add(mk("EXT-DM-03", "域名未配置 DMARC 记录", "中危", "strong",
                 "dns_query", "verify_dmarc.py",
                 endpoint="DNS TXT _dmarc.blocked.example.com"))
    _ctx_bnd1 = ReportContext(
        target_name="拦截有发现", primary_domain="blocked.example.com",
        item_results=items_b, detector_summary={}, gate_result=None,
        blocked_findings=[], boundary=_bnd_blk, render_source="run")
    _p_bnd1 = gen.generate(_ctx_bnd1, _fs_b, app)
    _t_bnd1 = _p_bnd1["technical"].read_text(encoding="utf-8")
    _e_bnd1 = _p_bnd1["executive"].read_text(encoding="utf-8")
    check("第 2 章漏洞清单为空" not in _t_bnd1,
          "被拦但有非应用层发现时，技术版**不得**说「第 2 章漏洞清单为空」"
          "—— 下面明明列着发现（2026-09-30 内部生产系统 12:10 轮 2 条中危）")
    check("2 条问题" in _t_bnd1 and "不经过 Web 边界的通道" in _t_bnd1,
          "被拦时技术版顶部要把「有 N 条非应用层发现」讲清楚，"
          "否则读者会把「应用层没结论」读成「什么都没发现」")
    check("问题分布为空" not in _e_bnd1,
          "被拦但有发现时，管理层摘要**不得**说「问题分布为空」"
          "—— 那会把真实问题整个吞掉，而通告里明明有")
    check("域名未配置 SPF 记录" in _e_bnd1 or "2 条问题" in _e_bnd1,
          "管理层摘要必须把非应用层发现交代出来（至少给条数与等级），"
          "否则同一批产出里通告有、摘要没有，读者按哪份都可能是错的")

    # ② 被拦 + 零发现 → 才允许用「为空」的措辞（旧口径仍然正确）
    _ctx_bnd0 = ReportContext(
        target_name="拦截零发现", primary_domain="blocked0.example.com",
        item_results=items_b, detector_summary={}, gate_result=None,
        blocked_findings=[], boundary=_bnd_blk, render_source="run")
    _p_bnd0 = gen.generate(_ctx_bnd0, FindingSet(target="拦截零发现"), app)
    _t_bnd0 = _p_bnd0["technical"].read_text(encoding="utf-8")
    _e_bnd0 = _p_bnd0["executive"].read_text(encoding="utf-8")
    check("第 2 章漏洞清单为空" in _t_bnd0,
          "被拦且确实零发现时，「清单为空」的提醒仍须保留"
          "（这是阻止「未执行」被读成「通过」的关键一句）")
    check("问题分布为空" in _e_bnd0,
          "被拦且零发现时，摘要写「问题分布为空」是正确的")

    # ③ 封禁能持续多久**没有测过**，报告不得替它下结论
    for _tag, _txt in (("技术版", _t_bnd0), ("管理层摘要", _e_bnd0)):
        check("换时间重扫不会改变" not in _txt and "换时间重扫同样如此" not in _txt,
              f"{_tag}不得断言「换时间重扫也不会变」—— 封禁持续时间我们没测过："
              "内部生产系统 同日 11:40 那轮 L1 还拿到了数据、12:10 才全程被拦，"
              "来源状态本身在变（红线 46 第三款：结论用语不得超出实测范围）")

    # ④ **B 类**（扫到一半被封）不能被说成「发现都来自非应用层通道」
    # 这是修上面那条时自己引入的自伤点：A 类才发现必然来自非应用层通道，
    # 而 B 类封禁前那段是够到应用的。一律套用 A 类措辞，会把一条实测到的
    # 应用层漏洞降格成「配置类小问题」—— 反方向的说假话。
    _ctx_bnd2 = ReportContext(
        target_name="中途被封有发现", primary_domain="mid.example.com",
        item_results=items_b, detector_summary={}, gate_result=None,
        blocked_findings=[], boundary=None, render_source="run",
        boundary_guard=gr_term)
    _p_bnd2 = gen.generate(_ctx_bnd2, _fs_b, app)
    _e_bnd2 = _p_bnd2["executive"].read_text(encoding="utf-8")
    check("这些发现**不来自应用层**" not in _e_bnd2 and
          "来自不经过 Web 边界的通道，已实测复现" not in _e_bnd2,
          "B 类（中途被封）**不得**把发现一律说成「来自非应用层通道」——"
          "封禁前那段是够到应用的，那些发现就是应用层发现")
    check("封禁之后的应用层检查未执行" in _e_bnd2 and
          "不构成该系统的完整画像" in _e_bnd2,
          "B 类要说清「发现只覆盖封禁前那段，不构成完整画像」，"
          "而不是给来源通道下结论")
    check("本次实测发现 2 条问题" in _e_bnd2,
          "B 类同样要数出发现条数（摘要不得把它吞掉）")
    check("本来源本次扫到一半被边界封禁" in _e_bnd2 and
          "开扫即被边界拦在门外" not in _e_bnd2,
          "B 类的「下一步」不得写「开扫即被拦在门外」—— A/B 两类的处置不同")
    # A 类仍须保留 A 类措辞（不能为了修 B 类把 A 类改掉）
    check("这些发现**不来自应用层**" in gen.generate(
        _ctx_bnd1, _fs_b, app)["executive"].read_text(encoding="utf-8"),
        "A 类仍须写「这些发现不来自应用层」—— 修 B 类不得把 A 类改坏")

    # ==================================================================
    # 2026-09-30 第二轮：报告只写关键结论（安全负责人定稿）
    #   ① 扫描结论固定句式；② 绕过尝试写成「被拦 → 尝试 → 结果」三段论；
    #   ③ 钉住本轮新增的 DNS 线索接线与绕过试探分流。
    # ==================================================================

    # ① 固定句式：测试方式 + 覆盖范围 + 三级漏洞计数，一句话说完
    check("本次从公网发起真实攻击测试，覆盖" in n_blk
          and "发现严重漏洞 0 个、高危漏洞 0 个、中危漏洞 0 个" in n_blk,
          "扫描结论必须用固定句式（测试方式 ＋ 覆盖项数 ＋ 三级漏洞计数），"
          "零发现时同样出句式并紧跟限定")

    # ② 绕过试探被**跳过**时，必须说清为什么不做 —— 跳过 ≠ 防护有效
    ctx_blk.bypass_probes = []
    ctx_blk.bypass_skip_reason = ("未探到边界拦截行为（厂商特征与「全站返回同一响应」"
                                  "两个口径均未命中），本轮未执行绕过试探")
    n_skip = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    ctx_blk.bypass_skip_reason = ""
    check("本次未执行" in n_skip and "未探到边界拦截行为" in n_skip,
          "绕过试探被跳过时必须写明「本次未执行」+ 原因 —— 否则读者会把"
          "「没试绕过」读成「试过了、防护有效」")
    check("未执行 ≠ 防护有效" in n_skip,
          "跳过绕过试探时要显式否定「未执行 = 防护有效」这个误读")

    # ②-b 「没试绕过」的**两种成因**措辞必须分开（2026-09-30 内部生产系统 实测）
    #     旧实现只有一套话术，其中「本次既没撞上墙，也就没有可绕之物」这句，
    #     在**中途确实被拦过**的轮次里是**假的** —— 通告同一节里会同时出现
    #     「持续请求累计到一定量后触发拦截且未恢复」与「没撞上墙」。
    #     通告要贴进部门大群，自相矛盾会让读者连前面的真话一起不信。
    _saved_guard = ctx_blk.boundary_guard
    ctx_blk.bypass_probes = []
    ctx_blk.bypass_skip_reason = ("未探到边界拦截行为（厂商特征与「全站返回同一响应」"
                                  "两个口径均未命中），本轮未执行绕过试探")
    # 对照 1：全程没拦过（boundary_guard 为空）—— 旧话术成立，必须原样保留
    #        （别把没问题的分支一起改坏：零发现口径同样要能自洽）
    ctx_blk.boundary_guard = None
    n_skip_clean = gen.generate(ctx_blk, fs_blk_empty,
                                app)["notice"].read_text(encoding="utf-8")
    check("既没撞上墙" in n_skip_clean,
          "全程未发生拦截时，「没撞上墙、没有可绕之物」成立且必须保留 ——"
          "这次修的是「被拦过」那种情形，不得把零发现口径一起改坏")
    # 对照 2：中途真的被拦过（gr_term 带 1 次封禁事件）—— 那句就是假话，必须消失
    ctx_blk.boundary_guard = gr_term
    n_skip_blocked = gen.generate(ctx_blk, fs_blk_empty,
                                  app)["notice"].read_text(encoding="utf-8")
    check("既没撞上墙" not in n_skip_blocked,
          "中途确实被拦过的轮次里不得再写「本次既没撞上墙」—— 那是假话，"
          "且与同一节「拦截程度」自相矛盾")
    check("确实被拦截过" in n_skip_blocked,
          "被拦过却跳过绕过试探时，必须显式写明「确实被拦截过」"
          "并说明这是「没试」而非「防护完整」")
    check("未执行 ≠ 防护有效" in n_skip_blocked,
          "两种成因下都必须保留「未执行 ≠ 防护有效」这句显式否定")
    ctx_blk.bypass_skip_reason = ""
    ctx_blk.boundary_guard = _saved_guard

    # ③ 基线被拦 + 变形未被拦 = **绕过候选**。本轮新增的核心能力：
    #    旧实现因 usable=False 把整批一起作废，把最值钱的发现连带丢掉了。
    ctx_blk.bypass_probes = [
        {"name": _wb.BASELINE_NAME,
         "request": "GET https://blocked.example.com（无任何变形）",
         "outcome": "blocked", "status": 405,
         "why": "HTTP 405，命中拦截特征", "is_baseline": True},
        {"name": "X-Original-URL 指向根路径",
         "request": "GET https://blocked.example.com/nonexist + X-Original-URL: /",
         "outcome": "missed", "status": 200, "why": "HTTP 200，未命中拦截特征"},
        {"name": "伪造内网来源（X-Forwarded-For: 127.0.0.1）",
         "request": "GET https://blocked.example.com + X-Forwarded-For: 127.0.0.1",
         "outcome": "blocked", "status": 405, "why": "HTTP 405，命中拦截特征"},
    ]
    n_cand = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    ctx_blk.bypass_probes = []
    check("绕过候选" in n_cand and "X-Original-URL" in n_cand,
          "基线被拦、而某个变形未被拦时必须报出「绕过候选」并点名 —— "
          "这是唯一能说明「边界不是对所有手法都有效」的证据，"
          "旧实现把它连同整批一起作废了")
    check("候选而非结论" in n_cand,
          "绕过候选**不得**写成「绕过成功」：响应也可能是源站错误页或"
          "另一种形态的拦截，须人工复核后才可写成「绕过」")
    check("**没有**自动改用这些变形" in n_cand,
          "必须说明本轮**未**自动改用候选变形继续扫描 —— 伪造来源头这类变形"
          "会改变应用侧行为，据它取得的结论无法复现")

    # ③-2 基线不通、且没有候选（变形也全被拦）→ 覆盖率断言必须作废。
    #     这一形态最容易被误写成「均被拦住 —— 拦截对本来源覆盖完整」，
    #     而那一批里连不带任何变形的请求也同样被拦，计数证明不了任何事。
    ctx_blk.bypass_probes = [
        {"name": _wb.BASELINE_NAME,
         "request": "GET https://blocked.example.com（无任何变形）",
         "outcome": "blocked", "status": 405,
         "why": "HTTP 405，命中拦截特征", "is_baseline": True},
        {"name": "伪造内网来源（X-Forwarded-For: 127.0.0.1）",
         "request": "GET https://blocked.example.com + X-Forwarded-For: 127.0.0.1",
         "outcome": "blocked", "status": 405, "why": "HTTP 405，命中拦截特征"},
    ]
    n_nocand = gen.generate(ctx_blk, fs_blk_empty, app)["notice"].read_text(encoding="utf-8")
    ctx_blk.bypass_probes = []
    check("本次不对覆盖率下结论" in n_nocand and "覆盖完整" not in n_nocand,
          "基线不通且无候选时，覆盖率断言必须明确作废 —— "
          "不得写「均被拦住 / 拦截覆盖完整」，那是没有证据的话")
    # 2026-10-08 安全负责人改版：删掉开头那句「本次无法评估拦截覆盖率」，
    # 改为直接讲事实（试了几种变形 + 基线对照也没过），把「不下结论」
    # 留在句尾。语义一字未变，少的只是前置标签句。
    check("无法评估拦截覆盖率" not in n_nocand,
          "不再以「本次无法评估拦截覆盖率」开头（2026-10-08 安全负责人定稿）—— "
          "「不下结论」由句尾「本次不对覆盖率下结论」承担")
    check("本次红队试了" in n_nocand,
          "绕过措辞改为直接从「本次红队试了 N 种变形」讲起")

    # ④ DNS 线索（CNAME）要在防护有效性一节可见，且必须声明它不是判据
    _bv_hint = BlockVerdict(blocked=False, vendor_hints=["阿里云 WAF/CDN"])
    _ctx_hint = ReportContext(target_name="线索目标", primary_domain="hint.example.com",
                              gate_result=None, blocked_findings=[], boundary=_bv_hint)
    n_hint = gen.generate(_ctx_hint, FindingSet(target="线索目标"),
                          app)["notice"].read_text(encoding="utf-8")
    check("DNS 线索" in n_hint and "阿里云 WAF/CDN" in n_hint,
          "CNAME 线索要在防护有效性一节可见 —— 读者据此知道边缘是谁家、该找谁核对")
    check("不代表发生过拦截" in n_hint,
          "DNS 线索旁必须声明「不代表发生过拦截」—— 同一家的 CDN 与 WAF "
          "共用 CNAME 后缀，把线索读成判据就是孤立信号当正面证据")

    # ⑤ 管理层摘要的第一屏也要有同一句式 —— 领导通常只读摘要，
    #    缺了这句就只能从分布表里自己加总，而「加总」会漏掉前提。
    _e_hint = gen.generate(_ctx_hint, FindingSet(target="线索目标"),
                           app)["executive"].read_text(encoding="utf-8")
    check("本次从公网发起真实攻击测试，覆盖" in _e_hint
          and "发现严重漏洞" in _e_hint,
          "管理层摘要的总体结论下必须有与通告同源的固定句式")

    # ⑥ 目标健康度停手（hard_limits.stop_on）——
    #    **措辞不得与「被边界拦截」互换**：一个是「请求没到应用」，
    #    一个是「请求到了、应用自己在报错」。研发据此决定去查 WAF 还是查服务，
    #    写反了就是把人引向错误方向，比不给结论更坏。
    _hs_stop = ("目标连续 12 次返回 5xx（跨 3 个不同 URL，最近一次 HTTP 503），"
                "疑似被本次扫描压出故障。")
    # 零发现的那一支：定级依据不完整，必须「无法评估」。
    # ⚠ 必须用**空** FindingSet —— 拿带发现的 fs 去跑这一支，
    #   测的是「有发现」分支，两条分支的判据完全不同。
    _fs_hs_empty = FindingSet(target="健康度停手目标")
    _ctx_hs = ReportContext(target_name="健康度停手目标",
                            primary_domain="hs.example.com",
                            item_results=items_b, detector_summary={},
                            gate_result=None, blocked_findings=[],
                            target_health_stop=_hs_stop)
    _p_hs = gen.generate(_ctx_hs, _fs_hs_empty, app)
    _t_hs = _p_hs["technical"].read_text(encoding="utf-8")
    _e_hs = _p_hs["executive"].read_text(encoding="utf-8")
    check("主动提前停止" in _t_hs, "健康度停手要在报告里显著披露（不静默）")
    check("连续 12 次返回 5xx" in _t_hs, "停手理由必须原样带出实测判据")
    check("请求确实到达了应用" in _t_hs,
          "必须写明「请求确实到达了应用」—— 这是与「被拦截」的分界线")
    check("不是被 WAF 拦截" in _t_hs,
          "必须显式否认「被 WAF 拦截」，否则读者会照 B 类拦截去理解")
    check("我方对目标的影响" in _t_hs,
          "必须交代「可能是本次扫描造成的影响」—— 不可逆风险不能含糊成「目标异常」")
    check("那不是「通过」，也不是「被拦截」" in _t_hs,
          "停手后的「未执行」既不是通过也不是被拦截，三者必须分清")
    check("不加等待避免加重故障" in _t_hs or "继续按原速率施压只会加重故障" in _t_hs,
          "要说明「为什么停手而不退避重试」（这不是限流，等待无意义）")
    check("总体评级：无法评估" in _t_hs,
          "停手且零发现时必须判「无法评估」—— 不得写成「低风险」")
    check("无法评估" in _e_hs, "摘要版同样不得给「低风险」")
    check("服务端为什么异常" in _e_hs,
          "摘要要给出正确的排查方向（服务端 ≠ WAF 白名单）")
    # 有发现的那一支：**不能**判「无法评估」——
    # 那会把已经实测出来的严重漏洞一并判没（2026-09-30 OSS 匿名列举事故
    # 的同类错误：一次失败/中断的采集把风险判没了）。
    # 正确做法是保留按等级评出的结论，只标注「覆盖范围只到停手那一刻」。
    _p_hs_f = gen.generate(_ctx_hs, fs, app)
    _t_hs_f = _p_hs_f["technical"].read_text(encoding="utf-8")
    _e_hs_f = _p_hs_f["executive"].read_text(encoding="utf-8")
    check("总体评级：无法评估" not in _t_hs_f,
          "停手但有实测发现时**不得**判「无法评估」—— 那会把已证实的漏洞判没")
    check("只覆盖已执行的检查项" in _t_hs_f,
          "有发现时必须标注「结论只覆盖已执行部分」（否则会被读成完整画像）")
    check("只覆盖停手之前已执行的检查项" in _e_hs_f,
          "摘要版同样要标注覆盖范围受限")

    _pay_hs = _json.loads(_p_hs["data"].read_text(encoding="utf-8"))
    check(_pay_hs.get("target_health_stop") == _hs_stop,
          "停手原因必须落盘（批量统计只看 JSON，看不到正文）")

    # 未触发时不得渲染 —— 每份正常报告都带一段「本次主动停手」就是假告警，
    # 而假告警会让真告警失效（读者学会跳过这一段）。
    _ctx_hs0 = ReportContext(target_name="未停手目标",
                             primary_domain="hs0.example.com",
                             item_results=items_b, detector_summary={},
                             gate_result=None, blocked_findings=[])
    _t_hs0 = gen.generate(_ctx_hs0, fs, app)["technical"].read_text(encoding="utf-8")
    check("主动提前停止" not in _t_hs0,
          "未触发停手时不得渲染停手段落（假告警比不报更坏）")

    # ⑦ 速率被硬上限收敛要在报告里留痕（hard_limits.rate_ceiling_rps）
    _clamp = "档位「深度档」的速率被全局硬上限 200 rps 收敛：requests_per_second 999→200"
    _ctx_cl = ReportContext(target_name="速率收敛目标",
                            primary_domain="cl.example.com",
                            item_results=items_b, detector_summary={},
                            gate_result=None, blocked_findings=[],
                            rate_ceiling_clamp=_clamp)
    _t_cl = gen.generate(_ctx_cl, fs, app)["technical"].read_text(encoding="utf-8")
    check("速率被全局硬上限收敛" in _t_cl,
          "速率被硬上限削过就必须留痕 —— 否则「跑在多少 rps」是个没人知道的事实")
    check("不影响检查项覆盖" in _t_cl,
          "要说清收敛只影响耗时、不影响覆盖（否则读者会以为少扫了东西）")
    _ctx_cl0 = ReportContext(target_name="未收敛目标",
                             primary_domain="cl0.example.com",
                             item_results=items_b, detector_summary={},
                             gate_result=None, blocked_findings=[])
    _t_cl0 = gen.generate(_ctx_cl0, fs, app)["technical"].read_text(encoding="utf-8")
    check("速率被全局硬上限收敛" not in _t_cl0,
          "未收敛时不得渲染收敛段落")

    # ---- 汇总 ----
    print("\n" + "=" * 60)
    if FAILS:
        print(f"失败 {len(FAILS)}/{CHECKS}：")
        for x in FAILS:
            print(f"  - {x}")
        return 1
    print(f"全部通过（{CHECKS} 项断言）")
    print(f"报告产出：{paths['technical']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
