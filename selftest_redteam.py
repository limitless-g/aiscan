"""红队模式端到端自测（覆盖生产路径）。

=====================================================================
为什么必须单独建一个文件
=====================================================================

`selftest_engine.py` 是**手工组装**流程的：它自己调 `run_all_items()`
和 `ReportGenerator()`，**不走 `orchestrator.scan()`**。

后果是：orchestrator 里新增的编排阶段，在自测里永远不会被执行 ——
这个盲区此前已经造成过一次生产事故：`engine/gate.py` 的 `ReportGate`
漏了导入，`selftest` 全绿（因为它自己 import 了），真实扫描却必然在
最后一步崩掉。**自测跑得再绿，也不能证明生产路径能跑通。**

本文件直接调 `orchestrator.scan(mode="redteam")`，指向本地假应用，
把整条生产链路真正走一遍。

=====================================================================
校验的核心不变量
=====================================================================

  ① 红队模式的编排阶段必须真的执行且不失败（不是「跳过」）
  ② 目标结论只能是三态之一，不得出现其它值
  ③ **「未达成」必须附带已尝试的手段** —— 否则与「没测」无法区分
  ④ 未授权的目标不得执行，且不得记为「未达成」
  ⑤ 报告必须真的渲染出「攻击目标达成情况」
  ⑤-b **未执行的成因必须归对档位**：「本档位默认不含该目标」与「台账未授权」
     是两码事 —— 前者换档位、后者补授权，处置完全不同。混成一句话，读者会去
     追一个根本不存在的授权缺口（2026-09-29 真实发生在 内部生产系统 报告上：该域名
     已在台账登记且有人授权，报告却写「该攻击目标未在授权台账登记」，只因
     standard 档 objectives 不含 TAKE_CONTROL）。**归因错误与结论错误同等严重。**
  ⑥ **若结果证明层已实测证明某目标可达，目标结论不得停留在「未能验证」**
     —— 这两层出现矛盾，说明路径编排被短路了（曾经就因为「发现入口」
     这一步没绑执行体而真实发生过）
  ⑦ **默认视角必须是黑客运维**（明确要求：默认黑客运维，除非特殊说明）
     —— 本文件**故意不传 mode**，直接走默认值；同时把三个入口
     （引擎常量 / 命令行默认值 / scan() 签名默认值）一起断言，
     任何一处被改回合规模式，自测立刻失败。
  ⑧ **台账登记必须真的生效**（登记了却不生效比没登记更危险 ——
     它给出的是虚假的授权信心）。覆盖两个真实坑：
     影响级别字段写了没人读、台账查表未归一化导致 miss 而静默放宽授权。
     台账只能**收紧**授权，任何情况都不得放宽。
"""
from __future__ import annotations

import argparse
import inspect
import io
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import selftest_engine as se  # noqa: E402
from engine.nuclei_runner import NucleiRunner  # noqa: E402
from engine.orchestrator import PLANNED_STAGES, Orchestrator  # noqa: E402
from engine.progress import ProgressReporter, read_status  # noqa: E402
from engine.redteam import (  # noqa: E402
    DEFAULT_MODE,
    IMPACT_LABEL,
    INCONCLUSIVE,
    MODE_REDTEAM,
    NOT_PROVEN,
    OBJECTIVES,
    PROVEN,
)

VALID_STATES = {PROVEN, NOT_PROVEN, INCONCLUSIVE}

# 自测必须跑得快，否则没人愿意跑它 —— 没人跑的测试等于没有测试。
# nuclei 对本地假应用跑全量模板要十几分钟（超时上限 900s），
# 而它和红队编排阶段毫无关系（`selftest_engine` 本就直接跳过采集阶段的
# nuclei 调用）。这里显式关掉，避免自测变成「超时测试」。
NucleiRunner.available = property(lambda self: False)  # type: ignore[assignment]

HARD_TIMEOUT_S = 420


def _watchdog(limit: int) -> None:
    """超时兜底：宁可自测失败退出，也不要挂住 CI。"""
    def _kill() -> None:
        print(f"\n✗ 红队端到端自测超时（>{limit}s），强制退出。", flush=True)
        os._exit(1)
    t = threading.Timer(limit, _kill)
    t.daemon = True
    t.start()


def main() -> int:
    problems: list[str] = []
    t_start = time.time()
    _watchdog(HARD_TIMEOUT_S)
    srv, port = se.start_app()
    # 自测用的台账放在**一次性临时目录**，不放工具目录的 outputs/ 下。
    # 两个原因：
    #   ① 隔离 —— 上一次运行留下的台账是真实状态，会污染本次判定
    #      （台账「只追加」的语义意味着旧记录不会被清掉）。
    #   ② 稳定 —— 原先靠 `os.remove(旧文件)` 起干净，这一步在受限环境里
    #      可能被批量删除守卫拦下（进程直接被终止，连问题清单都来不及打）。
    #      用「每次都是新路径」就没有删除这个动作，天然免疫。
    _tmp_root = tempfile.mkdtemp(prefix="aiscan_redteam_")
    tmp_ledger = os.path.join(_tmp_root, "ledger.yaml")
    try:
        se.patch_network("redteam.test", open_port=port)
        orch = Orchestrator(profile="standard", ledger_path=tmp_ledger)
        # 进度器必须真的挂上，否则下面 ①e 验的是「空实现也能过」的假命题。
        # 输出丢进 StringIO：自测不该被几十行进度刷屏，但**落盘那条链必须真跑**
        # —— 这正是本项目「自测必须走生产路径」的纪律。
        orch.progress = ProgressReporter(enabled=True, stream=io.StringIO())

        # ---- 不变量 ⑦：默认视角必须是黑客运维 ----
        # 三个入口必须指向同一个默认值：引擎常量、命令行默认值、scan() 签名。
        # 默认值只在 engine/redteam.py 定义一次，任何一处被改回合规模式，
        # 这里就会红 —— 默认视角悄悄变掉是最难被发现的一类回归。
        if DEFAULT_MODE != MODE_REDTEAM:
            problems.append(
                f"默认扫描模式不是黑客运维：DEFAULT_MODE={DEFAULT_MODE}")
        _sig_dflt = inspect.signature(Orchestrator.scan).parameters["mode"].default
        if _sig_dflt != DEFAULT_MODE:
            problems.append(
                f"scan() 的 mode 默认值与引擎常量不一致："
                f"{_sig_dflt} != {DEFAULT_MODE}")
        try:
            from aiscan import build_parser  # noqa: PLC0415

            _parser = build_parser()
            _scan_p = None
            for _act in _parser._actions:
                if isinstance(_act, argparse._SubParsersAction):
                    _scan_p = _act.choices.get("scan")
            _cli_dflt = None
            if _scan_p is not None:
                for _act in _scan_p._actions:
                    if "--mode" in _act.option_strings:
                        _cli_dflt = _act.default
            if _cli_dflt != DEFAULT_MODE:
                problems.append(
                    f"命令行 --mode 默认值与引擎常量不一致："
                    f"{_cli_dflt} != {DEFAULT_MODE}")
        except Exception as e:  # noqa: BLE001
            problems.append(f"命令行默认值校验失败：{type(e).__name__}: {e}")

        # 故意**不传 mode**：走默认值。默认值若被改回合规模式，
        # 不变量 ① 会立刻发现编排阶段被跳过。
        res = orch.scan(
            domain="redteam.test",
            target_name="红队自测",
            base_url=f"http://127.0.0.1:{port}",
            skip_auth_check=True,
            # 必须打开：下面不变量 ①b/①c 盯的是「前端产物抢采」这条接线，
            # 而 enable_js=False 时它整段都不会执行 —— 断言看着是绿的，
            # 实际上什么都没验（本文件开头那个 ReportGate 漏导入的事故，
            # 教训就是「自测绿 ≠ 生产路径能跑通」）。
            enable_js=True,
        )
        if orch.mode != MODE_REDTEAM:
            problems.append(
                f"未指定模式时未按默认黑客运维执行：orch.mode={orch.mode}")

        # ---- 不变量 ⑧：台账必须真的能收紧授权（登记了就必须生效）----
        # 两个真实存在的坑：
        #   a) `--impact-level` 字段写了却没人读 → 运维以为限到 L1，实际按 L2 跑；
        #   b) 台账查表没归一化 → 域名大小写/协议/端口不同就 miss，
        #      而 miss 的后果是**退回档位默认全量目标**（授权被静默放宽）。
        # 这两条都属于「授权看起来收紧了、实际没有」，报告上完全看不出来。
        try:
            from ledger.auth_ledger import AuthLedger  # noqa: PLC0415

            # 同样落在一次性临时目录里：路径每次都新，不需要先删旧的。
            _tled = os.path.join(_tmp_root, "ledger-tighten.yaml")
            _lg = AuthLedger(_tled)
            # 故意用「带协议 + 大写 + 带端口」的写法登记，考归一化
            _lg.register("HTTPS://Redteam.Test:8443/", authorizer="自测",
                         authorization_ref="SELFTEST",
                         objectives=["READ_DATA"], impact_level="L1")
            _lg.save()  # 注意：register() 只改内存，落盘必须显式 save()
            _o2 = Orchestrator(profile="standard", ledger_path=_tled)
            _dom = "redteam.test"
            _obj2 = _o2._authorized_objectives(_dom)
            _cap2 = _o2._authorized_impact_level(_dom)
            if _obj2 != ["READ_DATA"]:
                problems.append(
                    f"台账未生效（或未归一化）：已登记 objectives=[READ_DATA]，"
                    f"实际授权目标={_obj2}")
            if _cap2 != "L1":
                problems.append(
                    f"台账影响级别未生效：已登记 L1，档位是 L2，"
                    f"实际生效上限={_cap2}（台账只能收紧、不能放宽）")
            # 反向：登记比档位更宽时，必须以档位为准（不得被放宽）
            _lg.register(_dom, authorizer="自测", authorization_ref="SELFTEST",
                         objectives=["READ_DATA", "MODIFY_DATA", "TAKE_CONTROL"],
                         impact_level="L3")
            _lg.save()
            _o3 = Orchestrator(profile="safe", ledger_path=_tled)
            _cap3 = _o3._authorized_impact_level(_dom)
            if _cap3 != "L1":
                problems.append(
                    f"台账把授权放宽了：档位 safe=L1、台账登记 L3，"
                    f"实际生效上限={_cap3}（应取更保守的 L1）")
            _obj3 = _o3._authorized_objectives(_dom)
            if "TAKE_CONTROL" in _obj3:
                problems.append(
                    f"台账把授权目标放宽了：安全档不含 TAKE_CONTROL，"
                    f"实际={_obj3}（取交集，不得放宽）")
        except Exception as e:  # noqa: BLE001
            problems.append(f"台账收紧校验失败：{type(e).__name__}: {e}")

        # 影响级别上限必须真的落到编排阶段（空值 = 阶段没跑）
        if orch._impact_cap != "L2":
            problems.append(
                f"影响级别上限未落到编排阶段：期望 L2（standard 档），"
                f"实际 {orch._impact_cap!r}")

        print("=" * 70)
        print("扫描阶段")
        print("=" * 70)
        for s in res.stages:
            mark = {"ok": "✓", "failed": "✗", "skipped": "·"}.get(s.status, "?")
            print(f"  {mark} {s.name:<30} {s.duration_ms:>7}ms  {s.detail[:60]}")
            if s.error:
                print(f"      ↳ {s.error[:120]}")

        stages = {s.name: s for s in res.stages}

        # ---- 不变量 ①：两个新阶段必须真的执行且不失败 ----
        for name in ("L3.5 结果证明（攻击目标达成性）",
                     "L4.5 攻击目标编排（红队）"):
            st = stages.get(name)
            if st is None:
                problems.append(f"阶段缺失（生产路径未覆盖）：{name}")
            elif st.status == "failed":
                problems.append(f"阶段执行失败：{name} → {st.error}")
            elif st.status != "ok":
                problems.append(f"阶段状态异常：{name} → {st.status}")

        # ---- 不变量 ①b：任何阶段都不许把内部异常静默咽下去 ----
        # 被真实事故逼出来的一条，**别删**：
        # 编排层按关键字传 `spa_endpoints`，而 `frontend.collect()` 的签名里
        # 没有这个参数 —— 前端产物补采**每一次扫描**都在 `except Exception` 里
        # 静默死掉，而症状只是「报告里脚本数还是 0」，与「前端汇聚压根没做」
        # 完全无法区分。单元自测（selftest_frontend）用的是另一套参数，
        # 永远抓不到「调用点与实现签名不一致」—— 只有生产路径能。
        # 所以这里直接盯阶段说明：吞掉的异常必须显形，不能只在日志里烂掉。
        for s in res.stages:
            _d = s.detail or ""
            if "异常（已捕获" in _d or "unexpected keyword argument" in _d:
                problems.append(
                    f"阶段「{s.name}」把内部异常咽下去了 —— 该子步骤等于没做，"
                    f"报告却看不出：{_d[-200:]}")

        # ---- 不变量 ①c：前端产物采集必须**抢在 nuclei 之前** ----
        # 这条修复的价值全在顺序上，所以顺序必须被断言盯住。
        # nuclei 是本轮请求量的绝对大头（实测某目标纳入 5094 份模板、跑满 420s），
        # 也最容易触发边界频率封禁；而前端采集十来个请求就能把页面 + 脚本 +
        # 内联 + 接口清单一次拿全。排在 nuclei 之后 = 把素材押在「封禁不发生」上，
        # 一旦封禁，采集阶段整批作废，17 个依赖前端产物的项集体落「未执行」，
        # 而素材其实一开扫就拿到了。
        _col = stages.get("L2 扫描采集")
        if _col is None:
            problems.append("阶段缺失（生产路径未覆盖）：L2 扫描采集")
        else:
            _d = _col.detail or ""
            _i_fe = _d.find("[前端采集]")
            _i_nuc = _d.find("nuclei")
            if _i_fe < 0:
                problems.append(
                    "前端产物抢采没有留痕 —— 无法确认它跑在了 nuclei 之前"
                    "（顺序错了，封禁一来素材就丢）")
            elif 0 <= _i_nuc < _i_fe:
                problems.append(
                    "前端产物采集排在了 nuclei 之后 —— nuclei 是最易触发边界封禁的"
                    "一步，排在它后面等于把「有没有素材」押在封禁上")

        # ---- 不变量 ①d：阶段序列必须与 PLANNED_STAGES 逐项相等 ----
        # 进度显示的「分母」来自 PLANNED_STAGES。它一旦与实际阶段序列漂移，
        # 前台就会一直显示一个错的总量（例如「阶段 3/16」而实际只有 14 步），
        # 而**进度显示不会报错**——它只会安静地骗人。所以等式必须被断言钉住：
        # 增删阶段而忘了改计划，这里立刻红，而不是让分母悄悄跑偏。
        # 只对**跑完整场**的扫描比对（未授权闸门拦下会提前 return，那时实到
        # 阶段数天然少于计划，用 abort 口径处理，不该在自测里误报）。
        _actual_seq = [s.name for s in res.stages]
        _planned_seq = list(PLANNED_STAGES)
        if _actual_seq != _planned_seq:
            problems.append(
                "阶段序列与 PLANNED_STAGES 不一致 —— 进度显示的阶段总数是错的。\n"
                f"    计划（{len(_planned_seq)}）：{_planned_seq}\n"
                f"    实到（{len(_actual_seq)}）：{_actual_seq}")

        # ---- 不变量 ①e：状态文件必须真的被写出来，且内容对得上 ----
        # 光断言「进度器能写状态文件」是模块级的事（engine/progress.py 自测已验）；
        # 这里要验的是**接线**：编排层有没有把 archive_dir 交给进度器。
        # 接线断掉时不会有任何报错 —— 只是那份「进程还活着吗」的凭据永远不出现，
        # 而读者会以为「没生成就是没这个功能」，于是下次事故照旧抓瞎。
        _prog_path = Path(getattr(res, "archive_dir", "") or ".") / "progress.json"
        _pst = read_status(_prog_path)
        if not _pst:
            problems.append(
                f"进度状态文件没落盘：{_prog_path} —— 编排层没把归档目录交给"
                "进度器（进程被杀时将无从判断死活）")
        else:
            if _pst.get("stage_total") != len(PLANNED_STAGES):
                problems.append(
                    f"状态文件里的阶段总数与 PLANNED_STAGES 不符："
                    f"{_pst.get('stage_total')} != {len(PLANNED_STAGES)}")
            if _pst.get("stage_index") != len(PLANNED_STAGES):
                problems.append(
                    f"状态文件未记录到收尾阶段：stage_index="
                    f"{_pst.get('stage_index')}，应为 {len(PLANNED_STAGES)}")
            if not _pst.get("pid"):
                problems.append("状态文件缺少 pid —— 无法据此判断进程是否还在")

        # ---- 不变量 ①f：B 类（运行期才出现的封禁）必须回头重判绕过试探 ----
        # 分流判据只在 L1 时点评估一次；运行期真的被封之后，那句「无拦可绕」
        # 已被新证据推翻。不回头重判，就会出现「该做的绕过没做，且报告写
        # 『本次既没撞上墙』」—— 内部生产系统 2026-09-30 实测到的自相矛盾。
        # 三态必须分开，任何一个合并都会产生错结论：
        #   · A 类（L1 就判出要探）→ 那一处已探过，不得重复探（省流量、
        #     也避免重复出现在披露里）
        #   · 只有 B 类 → **必须补探**
        #   · 从未被封 → 不得补探（没有拦可绕，白打一批请求）
        try:
            from engine.orchestrator import bypass_late_probe_reason as _blpr  # noqa: PLC0415

            if _blpr(l1_blocked=False, guard_occurred=True,
                     already_probed=False) == "":
                problems.append(
                    "B 类封禁（运行期才出现）没有触发绕过试探补做 —— "
                    "「被拦 → 尝试绕过 → 出结论」这条链会断在 L1 的判断上")
            if _blpr(l1_blocked=False, guard_occurred=True,
                     already_probed=True) != "":
                problems.append(
                    "已探过还要再探一次 —— 会重复发出试探流量并在披露里重复")
            if _blpr(l1_blocked=True, guard_occurred=True,
                     already_probed=False) != "":
                problems.append(
                    "A 类（L1 即判全量接管）不该走补做路径 —— 那一处已经探过")
            if _blpr(l1_blocked=False, guard_occurred=False,
                     already_probed=False) != "":
                problems.append(
                    "从未发生封禁却要补做绕过试探 —— 没有拦可绕，"
                    "「变形未被拦」证明不了任何事，只会白打一批请求")
        except Exception as e:  # noqa: BLE001
            problems.append(f"绕过试探补做判据校验失败：{type(e).__name__}: {e}")

        # ---- 不变量 ②：目标结论只能是三态 ----
        objs = list(orch._objectives)
        if not objs:
            problems.append("红队模式未产出任何攻击目标结论")
        for oc in objs:
            if oc.result not in VALID_STATES:
                problems.append(f"非法目标结论：{oc.objective} → {oc.result}")
            if oc.objective not in OBJECTIVES:
                problems.append(f"未知攻击目标：{oc.objective}")

        # ---- 不变量 ③：「未达成」必须附带已尝试的手段 ----
        for oc in objs:
            if oc.result == NOT_PROVEN and not oc.attempted():
                problems.append(
                    f"「未达成」缺少已尝试手段清单：{oc.label}"
                    "（这会与「没测」无法区分）")

        # ---- 不变量 ④：未授权目标不得执行、不得记「未达成」 ----
        for oc in objs:
            if not oc.authorized:
                if oc.paths:
                    problems.append(f"未授权目标被执行了路径：{oc.label}")
                if oc.result == NOT_PROVEN:
                    problems.append(f"未授权目标被记为「未达成」：{oc.label}")

        # ---- 不变量 ⑤：报告必须渲染出目标达成情况 ----
        tech = None
        for k, v in (res.reports or {}).items():
            if "技术版" in str(v):
                tech = v
        if tech is None:
            problems.append("未生成技术版报告，无法校验渲染")
        else:
            try:
                text = open(tech, encoding="utf-8").read()
            except Exception as e:  # noqa: BLE001
                text = ""
                problems.append(f"报告读取失败：{e}")
            if "攻击目标达成情况" not in text:
                problems.append("技术版报告未渲染「攻击目标达成情况」")
            if "未能验证" not in text and any(
                    o.result == INCONCLUSIVE for o in objs):
                problems.append("存在「未能验证」目标，但报告未体现该结论")

        # ---- 不变量 ⑤-b：未执行的成因必须归对**档位**，不得一律说「未授权」 ----
        # 「本档位默认不含该目标」与「台账未授权」是两码事，处置完全不同：
        # 前者换档位、后者补授权。混成一句话的后果是读者去追一个根本不存在的
        # 授权缺口 —— 2026-09-29 在 内部生产系统 报告上真实暴露：internal-app.example.com
        # 明明已在台账登记（安全负责人授权 2026-09-21），报告却写「该攻击目标未在
        # 授权台账登记」，因为 standard 档的 objectives 不含 TAKE_CONTROL。
        # **归因错误与结论错误同等严重。**
        from engine.redteam import render_matrix as _rmat  # noqa: PLC0415
        from engine.redteam import OBJ_TAKE_CONTROL as _OTC  # noqa: PLC0415
        from engine.redteam import ObjectiveOutcome as _OO  # noqa: PLC0415

        # (a) 纯函数层：矩阵渲染必须按 scope_kind 分派措辞
        _m_prof = _rmat([_OO(objective=_OTC, label="拿到控制权",
                             result=INCONCLUSIVE, authorized=False,
                             scope_kind="profile", reason="r")])
        _m_led = _rmat([_OO(objective=_OTC, label="拿到控制权",
                            result=INCONCLUSIVE, authorized=False,
                            scope_kind="ledger", reason="r")])
        _m_unk = _rmat([_OO(objective=_OTC, label="拿到控制权",
                            result=INCONCLUSIVE, authorized=False,
                            scope_kind="", reason="r")])
        if "档位" not in "".join(_m_prof):
            problems.append("矩阵渲染：档位不含的目标未说明是档位设定")
        if "未授权" in "".join(_m_prof):
            problems.append("矩阵渲染：档位不含的目标被写成了「未授权」")
        if "台账" not in "".join(_m_led):
            problems.append("矩阵渲染：台账未放行的目标未点名台账")
        if "未纳入" not in "".join(_m_unk):
            problems.append("矩阵渲染：无从归因时应只说「未纳入执行范围」")

        # (b) 确定性检查：直接按**本档位配置**造一个必然越界的目标，
        #     不依赖「本次扫描恰好把 TAKE_CONTROL 留在范围外」——那种依赖
        #     一旦台账状态变了，断言就会静默变成空跑。
        from engine.redteam import AttackPlanner as _AP  # noqa: PLC0415
        from engine.redteam import build_paths as _bp  # noqa: PLC0415

        _prof_objs = orch._redteam_profile_objectives()
        if _OTC in _prof_objs:
            problems.append(
                "standard 档的 objectives 竟含 TAKE_CONTROL —— 不变量 ⑤-b 的"
                "前提被打破，请同步更新该检查的构造方式")
        # 越界目标是 TAKE_CONTROL：它在档位默认里没有 → 必须归因「档位」；
        # 因为不在 scope 内，其攻击路径一条都不会执行（ctx 传 None 即可）。
        _oc_tc = [o for o in _AP(
            None,
            scope=[o for o in _prof_objs if o != _OTC],
            profile_objectives=_prof_objs,
            ledger_objectives=[],
            profile_name=orch._profile_label(),
            paths=[p for p in _bp() if p.objective == _OTC],
        ).run() if o.objective == _OTC][0]
        if _oc_tc.authorized:
            problems.append(
                "目标既不在档位默认范围、也不在台账放行范围，不得判为「已授权」")
        if getattr(_oc_tc, "scope_kind", "") != "profile":
            problems.append(
                f"档位默认不含该目标时必须归因 profile，实际 {_oc_tc.scope_kind!r}")
        if "授权台账" in (_oc_tc.reason or ""):
            problems.append(
                "档位默认不含该目标，原因却写成「未在授权台账登记」—— 会把"
                "档位强度问题误导成授权问题：" + _oc_tc.reason)
        if "档位" not in (_oc_tc.reason or ""):
            problems.append("档位默认不含该目标，原因未点名档位：" + _oc_tc.reason)

        # (c) 报告正文：本次扫描里**真的**出现了「档位不含」的目标时，
        #     渲染层（report/generator.py）的措辞也必须一致。
        #     没出现就跳过 —— (b) 已经确定性地覆盖了判定与归因逻辑。
        _prof_ocs = [o for o in objs
                     if not o.authorized and getattr(o, "scope_kind", "") == "profile"]
        if tech is not None and _prof_ocs:
            _sec: list[str] = []
            _inside = False
            for _ln in text.splitlines():
                if "攻击目标达成情况" in _ln:
                    _inside = True
                    continue
                if _inside and _ln.startswith("#"):
                    break
                if _inside:
                    _sec.append(_ln)
            _sec_txt = "\n".join(_sec)
            if "本档位不含" not in _sec_txt:
                problems.append(
                    "报告的攻击目标一节未说明「本档位不含」—— 读者会去追"
                    "一个不存在的授权缺口。节选：" + _sec_txt[:200])
            for _o in _prof_ocs:
                for _ln in _sec:
                    if _o.label in _ln and "未授权" in _ln:
                        problems.append(
                            f"报告把档位不含的目标（{_o.label}）写成了「未授权」：{_ln}")

        # ---- 不变量 ⑥：结果证明层与攻击目标结论不得互相矛盾 ----
        # 曾经真实发生过：证明层已经实测证明了「匿名取回业务数据」，
        # 目标那一栏却写「未能验证」—— 因为「发现入口」那一环没绑执行体，
        # 整条路径在第一环就被短路了。两层结论打架，报告就自相矛盾，
        # 而读者只会看到其中一栏。这条断言就是拦它的。
        from engine import proofs as _pf  # noqa: PLC0415

        for f in (getattr(res.finding_set, "findings", None) or []):
            p = (getattr(f, "extra", None) or {}).get("proof") or {}
            if p.get("state") != PROVEN:
                continue
            iid = str(getattr(f, "item_id", "") or "")
            hit = _pf.find_prover(type("_F", (), {"item_id": iid})())
            if hit is None:
                continue
            obj = hit[0]
            oc = next((o for o in objs if o.objective == obj), None)
            if oc is None:
                problems.append(
                    f"证明层证明了 {iid} 可达，但目标"
                    f"「{OBJECTIVES.get(obj, obj)}」连结论都没有")
            elif oc.result != PROVEN:
                problems.append(
                    f"两层结论互相矛盾：证明层已实测证明 {iid} 可达，"
                    f"目标「{OBJECTIVES.get(obj, obj)}」却判「{oc.result}」"
                    "（路径编排被短路）")

        # ---- 不变量 ⑨：需要令牌时必须**主动索取**，且不得把「缺凭据」写成别的 ----
        # 这一条测的是**接线**，不是算法：`engine.credguide` 自己的自测已经证明
        # 它会算，但真实的失效形态是「路径没接上」—— 扫描发现缺凭据却不问，
        # 于是那几项永远停在「未执行」，谁也不知道该怎么补。
        # 而且这类断线**症状极其合理**（就是「未执行」），读代码看不出来。
        try:
            from pathlib import Path as _P  # noqa: PLC0415

            _ask = dict(getattr(res, "cred_ask", None) or {})
            _needs = list(_ask.get("needs") or [])
            if not _needs:
                problems.append(
                    "本次扫描没有配置任何测试账号，却没生成凭据需求清单 —— "
                    "「缺凭据」又变成了静默终点")
            else:
                if any(n.get("present") for n in _needs):
                    problems.append("凭据需求清单里出现了「已就位」的项（未提供却报已有）")
                # 登录入口**只能来自证据**：要么有探测依据，要么如实说未能确定。
                _n0 = _needs[0]
                if _n0.get("entry_url") and _n0.get("entry_source") not in ("path_probe", "user"):
                    problems.append(
                        f"登录入口来源非证据：{_n0.get('entry_source')!r}")
                if not _n0.get("entry_url") and not _n0.get("entry_evidence"):
                    problems.append("未确定登录入口时也没给出原因（读者无从补）")
            # 需求清单必须落盘：扫描结束后操作者才去登录、才拿到 Cookie，
            # 那时候它得能凭归档找回「缺哪个身份」。
            # 文件名**引用常量**而不是写字面量 —— 写死名字时，改名的另一头
            # （`latest_plan` 的读取）会静默失配，而这里的断言还会继续通过。
            from engine.credguide import NEED_FILE_NAME as _NEED  # noqa: PLC0415

            _archive = _P(getattr(res, "archive_dir", "") or ".")
            _p = _archive / _NEED
            if _needs and not _p.exists():
                problems.append(f"凭据需求单未落盘：{_p}")
            if getattr(orch, "last_cred_plan", None) is None:
                problems.append("编排器未保留凭据需求（CLI 收尾时打不出指引）")
            # 报告里必须单列一节，把「去哪拿 / 怎么给 / 怎么补跑」写清楚 ——
            # 否则终端输出关掉之后，这条路径就没了。
            _tech = ""
            try:
                _tech = (res.reports.get("technical") and
                         _P(res.reports["technical"]).read_text(encoding="utf-8")) or ""
            except Exception:  # noqa: BLE001
                _tech = ""
            if _needs and "凭据缺口：需要登录令牌" not in _tech:
                problems.append("缺凭据时报告未单列「凭据缺口」一节")
            if _needs and "不要把令牌贴进对话" not in _tech:
                problems.append("报告未提示「令牌不要贴进对话」")
            # 反向：不缺凭据时不得凭空出这一节
            if not _needs and "凭据缺口：需要登录令牌" in _tech:
                problems.append("未缺凭据却渲染了「凭据缺口」一节")
        except Exception as e:  # noqa: BLE001
            problems.append(f"凭据索取接线校验失败：{type(e).__name__}: {str(e)[:160]}")

        print()
        print("=" * 70)
        print("攻击目标结论")
        print("=" * 70)
        for oc in objs:
            print(f"  {oc.label:<10} {oc.result:<8} 约束={oc.authorized}")
            for line in oc.attempted()[:3]:
                print(f"      · {line[:100]}")
            for line in oc.evidence_chain()[:3]:
                print(f"      ✓ {line[:100]}")

    finally:
        # 停掉进度器的看门狗线程。它是 daemon，不会拖住进程，但会继续刷新状态
        # 文件的时间戳 —— 让自测产物在结束后保持静止，否则「时间戳还在往前走」
        # 这个判据会被自测自己污染，下次真出事时反而看不出来。
        try:
            _prog = getattr(orch, "progress", None)
            if _prog is not None:
                _prog.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            srv.shutdown()
        except Exception:  # noqa: BLE001
            pass
        # 清理临时目录是**尽力而为**：在某些受限环境里删除动作会被守卫拦下，
        # 此时绝不能因为收尾失败而把一次已经通过的判定改判成失败 ——
        # 留在 %TEMP% 里的几个小文件由操作系统清理，不值得为它翻盘。
        try:
            shutil.rmtree(_tmp_root, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass

    print()
    print("=" * 70)
    if problems:
        print("红队模式端到端自测失败：")
        for x in problems:
            print("  -", x)
        return 1
    print("红队模式端到端自测通过：生产路径（orchestrator.scan）已完整覆盖。")
    print(f"  默认视角：{DEFAULT_MODE}（黑客运维，未显式指定 mode 时生效）")
    print(f"  影响级别上限：L2（{IMPACT_LABEL.get('L2')}）")
    print(f"  耗时：{time.time() - t_start:.1f}s")
    print("  ✓ L3.5 结果证明阶段执行成功")
    print("  ✓ L4.5 攻击目标编排阶段执行成功")
    print("  ✓ 目标结论均为三态之一")
    print("  ✓ 「未达成」均附带已尝试手段")
    print("  ✓ 未授权目标未被执行、未记为「未达成」")
    print("  ✓ 报告已渲染「攻击目标达成情况」")
    print("  ✓ 未执行的成因分清「档位默认不含」与「台账未登记」（不得一律说「未授权」）")
    print("  ✓ 结果证明层与目标结论一致（无「证明已拿到数据、目标却写未能验证」）")
    print("  ✓ 默认视角为黑客运维（引擎常量 / 命令行 / scan 签名三处一致）")
    print("  ✓ 台账登记真的生效（影响级别与目标范围只能收紧、不能放宽）")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
