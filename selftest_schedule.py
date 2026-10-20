# -*- coding: utf-8 -*-
"""周期化调度 + 飞书通知 端到端自测
=====================================
这是唯一一个**跨进程**的自测：它真的去调 `aiscan.py`，走「判定 → 执行 →
记账 → 通知」整条链路。其余自测都在进程内打桩，测不到 CLI 接线与状态文件落盘。

覆盖：
  ① 授权闸门拦下的目标**不得记账**（否则那一周期永远不再扫它），且下一轮仍判到点
  ② 成功执行 → 记账 → 同周期内不再到点（幂等）
  ③ 扫描阶段失败的目标不得记账（失败不能被静默吞掉）
  ④ 摘要口径：nuclei 截断 → partial；比对未带本轮结论 → diff_state_known=False；
     未配置 webhook → 如实报「未发送」；dry-run 不真发

全程**不发起真实扫描**：卡在闸门前的用真实 CLI（在任何网络请求之前就被拦下），
跑得动的用桩替换引擎。

用法：
    python selftest_schedule.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable
sys.path.insert(0, str(ROOT))

problems: list[str] = []

TPL = """\
settings: {{profile: safe, output_root: outputs}}
schedule: {{enabled: true, mode: daily, retention_days: 180}}
targets:
{targets}
"""

TPL_TARGET = """\
  - name: {name}
    primary_domain: {domain}
    base_url: "{base_url}"
{authz}"""

AUTHZ_OK = """\
    authorization:
      authorizer: 安全负责人
      ref: 自测授权
"""


def run_cli(*argv: str, env: dict | None = None) -> subprocess.CompletedProcess:
    e = dict(os.environ)
    e.pop("AISCAN_FEISHU_WEBHOOK", None)
    e.pop("AISCAN_FEISHU_SECRET", None)
    e["PYTHONIOENCODING"] = "utf-8"
    if env:
        e.update(env)
    return subprocess.run(
        [PY, str(ROOT / "aiscan.py"), *argv],
        cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=e, timeout=600)


def run_py(path: Path, e2e_args: list[str] | None = None) -> subprocess.CompletedProcess:
    import json as _json
    e = dict(os.environ)
    e.pop("AISCAN_FEISHU_WEBHOOK", None)
    e.pop("AISCAN_FEISHU_SECRET", None)
    e["PYTHONIOENCODING"] = "utf-8"
    e["E2E_ARGS"] = _json.dumps(e2e_args or [])
    return subprocess.run([PY, str(path)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=str(ROOT),
                          env=e, timeout=600)


# 桩驱动：把 Orchestrator 换成假的，考的是「记账 / 判定 / 摘要」而不是检测器
STUB_SRC = '''\
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(r"__ROOT__")
sys.path.insert(0, str(ROOT))

import engine.orchestrator as O
import models


class _Stage:
    def __init__(self, name, status):
        self.name, self.status = name, status
        self.duration_ms, self.detail, self.error = 1, "", ""


class _StubOrch:
    def __init__(self, *a, **k):
        self._objectives = [SimpleNamespace(label="拿到数据", result="未达成",
                                            reason="桩：未发现可越权取数路径")]
        self._last_diff = None
        self._boundary = None

    def scan(self, **k):
        name = k.get("target_name") or ""
        fs = models.FindingSet(target=name)
        arc = Path("outputs") / name / "20260921_000000"
        arc.mkdir(parents=True, exist_ok=True)
        (arc / "报告.md").write_text("桩报告", encoding="utf-8")
        items = [SimpleNamespace(item_id="WSTG-INFO-01", state="通过"),
                 SimpleNamespace(item_id="WSTG-INFO-02", state="未执行")]
        return SimpleNamespace(
            target_name=name, domain=k.get("domain") or "",
            stages=[_Stage("L1", "ok")], finding_set=fs, item_results=items,
            detector_summary={"档位": "safe", "可复测率": 0.9,
                              "采集充分度": {}},
            detector_notes=[], reports={"technical": arc / "报告.md"},
            archive_dir=arc,
            nuclei_run={"available": True, "executed": True,
                        "partial": True, "status": "timeout"})


O.Orchestrator = _StubOrch
import json
import os
sys.argv = ["aiscan"] + json.loads(os.environ["E2E_ARGS"])
import aiscan
raise SystemExit(aiscan.main())
'''

# 桩驱动 2：让扫描阶段失败，验证「失败不记账」
STUB_FAIL_SRC = '''\
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(r"__ROOT__")
sys.path.insert(0, str(ROOT))

import engine.orchestrator as O
import models


class _Stage:
    def __init__(self, name, status):
        self.name, self.status = name, status
        self.duration_ms, self.detail, self.error = 1, "", ""


class _StubOrch:
    def __init__(self, *a, **k):
        self._objectives, self._last_diff, self._boundary = [], None, None

    def scan(self, **k):
        name = k.get("target_name") or ""
        return SimpleNamespace(
            target_name=name, domain=k.get("domain") or "",
            stages=[_Stage("L3 逐项检测", "failed")],
            finding_set=models.FindingSet(target=name), item_results=[],
            detector_summary={}, detector_notes=[], reports={},
            archive_dir=Path("outputs") / name, nuclei_run={})


O.Orchestrator = _StubOrch
import json
import os
sys.argv = ["aiscan"] + json.loads(os.environ["E2E_ARGS"])
import aiscan
raise SystemExit(aiscan.main())
'''

SUMMARY_SRC = '''\
import sys
import os
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(r"__ROOT__")
sys.path.insert(0, str(ROOT))

from engine.scheduler import summary_from_scan
from engine.notify import FeishuNotifier

res = SimpleNamespace(
    target_name="通知系统", domain="n.example.com",
    item_results=[SimpleNamespace(item_id="WSTG-INFO-01", state="通过")],
    detector_summary={"档位": "standard", "可复测率": 0.8, "采集充分度": {}},
    finding_set=None, reports={}, archive_dir="x")
orch = SimpleNamespace(_objectives=[], _last_diff=None, _boundary=None)
s0 = summary_from_scan(res, orch)
assert s0["partial"] is False, "没有 nuclei 信息时不得瞎判 partial"
assert s0["diff"] is None and s0["diff_state_known"] is None

nuc = SimpleNamespace(nuclei_run={"executed": True, "partial": True,
                                  "budget_exhausted": False, "status": "partial"})
res.nuclei_run = nuc.nuclei_run
s1 = summary_from_scan(res, orch)
assert s1["partial"] is True, "nuclei 被截断必须体现为 partial"

# 比对没带本轮结论 → 要能说出「已修复可能含未执行项」
class _D:
    states_loaded = False
    def summary(self):
        return {"新增": 0, "已修复": 3, "仍存在": 1, "等级变化": 0,
                "本轮未判定": 4}
s2 = summary_from_scan(res, orch, _D())
assert s2["diff_state_known"] is False
assert s2["diff"]["本轮未判定"] == 4
txt = FeishuNotifier(dry_run=True).render_text(s2)
assert "本轮未判定 4" in txt and "未带本轮逐项结论" in txt, txt

n = FeishuNotifier()
assert not n.available
r = n.send(s2)
assert not r.sent and "未配置" in r.skipped_reason, r.skipped_reason
r2 = FeishuNotifier(webhook="https://example.invalid/hook", dry_run=True).send(s2)
assert not r2.sent and r2.dry_run, "试发不得真的发送"
print("STUB-OK")
'''

# ==============================================================================
# ① 真实 CLI：闸门拦下 → 不记账 → 下一轮仍到点
# ==============================================================================
with tempfile.TemporaryDirectory() as _td:
    td = Path(_td)
    tf = td / "targets.yaml"
    # 台账里没有这个域名 → 授权闸门必然拦下（在任何网络请求之前）
    tf.write_text(TPL.format(targets=TPL_TARGET.format(
        name="未登记授权系统", domain="aiscan-e2e-not-in-ledger.example",
        base_url="http://127.0.0.1:1/", authz=AUTHZ_OK)), encoding="utf-8")

    r1 = run_cli("schedule", "--run", "--no-notify", "--targets", str(tf))
    out1 = r1.stdout + r1.stderr
    if r1.returncode != 0:
        problems.append(f"schedule --run 非零退出：{r1.returncode}\n{out1[-1200:]}")
    if "记账 0 个" not in out1:
        problems.append("被闸门拦下的目标不得计入「记账」（否则该周期永久跳过它）\n"
                        + out1[-1200:])
    if "不记为已执行" not in out1:
        problems.append("被拦下的目标必须明说「不记为已执行」")
    if not (td / "outputs" / ".schedule_state.json").exists() and \
            "已登记执行状态" in out1:
        problems.append("既说已登记执行状态，就必须落状态文件")

    r2 = run_cli("schedule", "--targets", str(tf))
    out2 = r2.stdout + r2.stderr
    if "已执行过" in out2:
        problems.append("没跑成的目标不该被记成「已执行过」——那会让它"
                        "在整个周期内被静默跳过")

# ==============================================================================
# ② 桩驱动：成功执行 → 记账 → 同周期不再到点
# ==============================================================================
with tempfile.TemporaryDirectory() as _td:
    td = Path(_td)
    tf = td / "targets.yaml"
    tf.write_text(TPL.format(targets=TPL_TARGET.format(
        name="自测系统", domain="stub.example.com",
        base_url="https://stub.example.com/", authz=AUTHZ_OK)), encoding="utf-8")

    sd = td / "stub.py"
    sd.write_text(STUB_SRC.replace("__ROOT__", str(ROOT)), encoding="utf-8")
    r3 = run_py(sd, ["schedule", "--run", "--no-notify", "--targets", str(tf)])
    out3 = r3.stdout + r3.stderr
    if r3.returncode != 0:
        problems.append(f"桩驱动非零退出 {r3.returncode}\n{out3[-1500:]}")
    if "记账 1 个" not in out3:
        problems.append(f"成功执行的目标必须记账\n{out3[-1200:]}")
    state = td / "outputs" / ".schedule_state.json"
    if not state.exists():
        problems.append("执行后必须落状态文件（否则下轮重复扫）")
    else:
        import json
        ent = (json.loads(state.read_text(encoding="utf-8")).get("targets") or {})
        if int((ent.get("自测系统") or {}).get("run_count", 0)) != 1:
            problems.append(f"执行次数未累计：{ent}")

    r4 = run_cli("schedule", "--targets", str(tf))
    out4 = r4.stdout + r4.stderr
    if "已执行过" not in out4:
        problems.append("同周期内已执行过，再判必须说「已执行过」而不是再到点\n"
                        + out4[-1000:])

# ==============================================================================
# ③ 桩驱动：扫描阶段失败 → 不记账
# ==============================================================================
with tempfile.TemporaryDirectory() as _td:
    td = Path(_td)
    tf = td / "targets.yaml"
    tf.write_text(TPL.format(targets=TPL_TARGET.format(
        name="失败系统", domain="fail.example.com",
        base_url="https://fail.example.com/", authz=AUTHZ_OK)), encoding="utf-8")
    sd = td / "stub_fail.py"
    sd.write_text(STUB_FAIL_SRC.replace("__ROOT__", str(ROOT)), encoding="utf-8")
    r5 = run_py(sd, ["schedule", "--run", "--no-notify", "--targets", str(tf)])
    out5 = r5.stdout + r5.stderr
    if "记账 0 个" not in out5 or "不记为已执行" not in out5:
        problems.append("扫描阶段失败的目标不得记账（否则失败会被静默吞掉，"
                        "该周期不再重试）\n" + out5[-1200:])

# ==============================================================================
# ④ 摘要 / 通知口径
# ==============================================================================
with tempfile.TemporaryDirectory() as _td:
    sp = Path(_td) / "summary.py"
    sp.write_text(SUMMARY_SRC.replace("__ROOT__", str(ROOT)), encoding="utf-8")
    r6 = run_py(sp)
    if r6.returncode != 0 or "STUB-OK" not in r6.stdout:
        problems.append(f"摘要/通知口径断言失败：\n{r6.stdout}\n{r6.stderr[-1500:]}")

if problems:
    print("周期化调度端到端自测不通过：")
    for p in problems:
        print(f"  ✗ {p}")
    raise SystemExit(1)
print("✓ 周期化调度端到端自测通过（闸门/失败都不记账、同周期幂等、"
      "截断体现为 partial、未配置 webhook 如实报未发送、试发不真发）")
