# -*- coding: utf-8 -*-
"""
外部工具定位自测（binlocate）—— 换台电脑还找不找得到工具
==========================================================

**它守的是什么**

这套工具链原先在三处各写死一份 `C:/Users/<用户名>/...` 绝对路径
（`nuclei_runner` / `tools` / `sqlmap_probe`）。本机没问题，但它**是要被拷到
另一台电脑上跑的**：那边只要 Windows 用户名不同，所有写死路径一起落空 →
nuclei / sqlmap 被当成「未安装」→ 检测静默降级，报告上只写一句「未安装」。
**最坏的地方在于这跟「目标真的没问题」长得一模一样**（红线 9：任何「无发现」
都必须先证明被测对象真被处理过；工具压根没跑起来就更不该产出结论）。

**钉住三件事**

  ① **候选优先级**：环境变量 → 当前 Python 环境 → 用户目录 → 包内 tools/ → 历史兜底，
     且顺序稳定、已去重（后面的不得盖掉前面的）。
  ② **换用户名仍能定位**（正向断言 + 反向验证：老实现必须找不到）。
  ③ **等 stdin 的工具不得被误判为不可用**：pip 版 sqlmap 的 `--version` 打完
     版本号会「Press Enter to continue...」，探测不关 stdin 就挂到超时。

用法：
    python selftest_binlocate.py
退出码 0 = 全部断言通过。
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import binlocate  # noqa: E402
from engine import sqlmap_probe  # noqa: E402
from engine.tools import Toolchain  # noqa: E402

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
def ring_priority() -> None:
    print("\n① 候选优先级与稳定性")
    saved = os.environ.pop(binlocate.ENV_KEYS["nuclei"], None)
    try:
        c0 = binlocate.candidates("nuclei")
        check(len(c0) >= 4, f"nuclei 候选不少于 4 条（实际 {len(c0)}）")
        check(any(".workbuddy" in p for p in c0),
              "含「用户目录约定位置」候选（跟随当前用户，不是写死路径）")
        check(any(f"{os.sep}tools{os.sep}" in p for p in c0),
              "含「包内 tools/」候选（分发包可自包含，不依赖系统安装）")
        check(len(c0) == len(dict.fromkeys(c0)),
              "候选已去重（重复项会让「优先级」失去意义）")

        # 历史硬编码路径必须仍在清单里 —— 否则本机行为会悄悄改变
        legacy = (binlocate._LEGACY.get("nuclei") or [""])[0]
        check(bool(legacy) and legacy in c0,
              "历史硬编码路径仍在候选内（本机行为逐字不变，向后兼容）")

        # 环境变量置顶
        os.environ[binlocate.ENV_KEYS["nuclei"]] = r"C:\explicit\nuclei.exe"
        c1 = binlocate.candidates("nuclei")
        check(c1[0] == r"C:\explicit\nuclei.exe",
              "环境变量显式指定的路径排在首位（没有标准安装位置的机器靠它指路）")
        check(c1[1] == c0[0],
              "环境变量只是**插到最前**，原有候选顺序不受影响")
    finally:
        os.environ.pop(binlocate.ENV_KEYS["nuclei"], None)
        if saved is not None:
            os.environ[binlocate.ENV_KEYS["nuclei"]] = saved

    cs = binlocate.candidates("sqlmap")
    prefix_expect = str(Path(sys.prefix) / "Scripts" / "sqlmap.exe")
    check(prefix_expect in cs,
          f"sqlmap 候选含「当前 Python 环境」位置（{prefix_expect}）"
          "—— 换机重建 venv 后零配置命中")


# ======================================================================
def ring_survives_user_change() -> None:
    print("\n② 换台电脑（不同 Windows 用户名）仍能定位 —— 含反向验证")
    with tempfile.TemporaryDirectory() as td:
        fake_home = Path(td) / "Users" / "zhangsan"
        bindir = fake_home / ".workbuddy" / "binaries" / "bin"
        bindir.mkdir(parents=True)
        fake = bindir / "nuclei.exe"
        fake.write_bytes(b"MZ")  # 内容无所谓，只验「找得到」

        cands = binlocate.candidates("nuclei", home=fake_home)
        check(str(fake) in cands,
              "候选里出现了「这台机器（假用户 zhangsan）自己的」工具位置")
        check(str(fake) not in binlocate._LEGACY["nuclei"],
              "命中的路径不在历史硬编码清单里 —— 换机靠的是新候选，不是老路径")

        got = binlocate.locate("nuclei", home=fake_home)
        check(got == str(fake), f"locate 在假用户目录下命中正确文件（{got}）")

        # 反向验证：老实现（只遍历写死路径）在同一情形下必然找不到它。
        # 没有这条，上面那条「找得到」证明不了是「跟随用户目录」起了作用 ——
        # 也可能是本机恰好装了 nuclei 撞上的。
        def old_locate() -> str | None:
            for p in binlocate._LEGACY.get("nuclei", ()):
                if os.path.isfile(p):
                    return p
            return None

        check(old_locate() != str(fake),
              "反向验证：老实现（只认写死路径）在同一个假用户目录下找不到它 "
              "—— 证明这条断言真的在验「跟随用户目录」这件事")

        # 定位失败是一等公民状态（上层据此记「未执行」），不能以异常形式冒出来
        try:
            res = binlocate.locate("definitely-not-a-real-tool")
        except Exception as e:  # noqa: BLE001
            res = f"EXC:{type(e).__name__}"
        check(res is None, f"未知工具返回 None 而不是抛异常（实得 {res!r}）")

        # 非法路径也不得抛异常。`os.path.isfile` 对含 NUL 的路径抛的是
        # **ValueError** 而非 OSError —— 只 catch OSError 会漏掉这一支。
        # （含 NUL 的值连 os.environ 和 Path() 都进不去，所以这条没法用真实
        #   输入触发，只能用源码断言钉住。但漏了它就是「一个配置错误掀翻
        #   整条流水线」，而那种失败方式看起来像引擎崩了，不像配置错了。）
        src = inspect.getsource(binlocate.locate)
        check("except (OSError, ValueError)" in src,
              "非法路径同时接住 ValueError（只 catch OSError 会漏掉 NUL 那一支）")


# ======================================================================
def ring_stdin_guard() -> None:
    print("\n③ 等 stdin 的工具不得被误判为「未安装」")
    # 原理：一个「打完版本号就等输入」的假工具
    t0 = time.time()
    ok = False
    try:
        subprocess.run([sys.executable, "-c", "print('1.0.0'); input()"],
                       capture_output=True, text=True, timeout=8,
                       stdin=subprocess.DEVNULL)
        ok = True
    except subprocess.TimeoutExpired:
        ok = False
    elapsed = time.time() - t0
    check(ok and elapsed < 6,
          f"关掉 stdin 后，等输入的子进程立刻拿到 EOF 并退出（实测 {elapsed:.2f}s，不挂超时）")

    # 源码级防回归：这两处一旦有人顺手删掉，sqlmap 会重新变成「未安装」
    probe_src = inspect.getsource(Toolchain._probe_one)
    check("stdin=subprocess.DEVNULL" in probe_src,
          "工具**版本探测**必须关掉 stdin —— 摘掉它，pip 版 sqlmap 的 "
          "`--version` 会挂到超时，被记成「未安装」")
    smp_src = inspect.getsource(sqlmap_probe)
    check("stdin=subprocess.DEVNULL" in smp_src,
          "sqlmap **真实调用**同样必须关掉 stdin —— 否则注入验证被记成「未能验证」，"
          "而那是假的：工具跑得起来，只是我们没给它一个 EOF")


# ======================================================================
def ring_env_key_no_clash() -> None:
    print("\n④ 路径变量不得与模式开关重名")
    check(binlocate.ENV_KEYS["sqlmap"] != "AISCAN_SQLMAP",
          "AISCAN_SQLMAP 已被 sqlmap_probe 用作**模式开关**（auto/off）——"
          "路径变量必须另起名字，否则「安全档不调用 sqlmap」（红线 27）会失效")
    saved = os.environ.get("AISCAN_SQLMAP")
    try:
        os.environ["AISCAN_SQLMAP"] = "off"
        cands = binlocate.candidates("sqlmap")
        check("off" not in [str(c) for c in cands],
              "把 AISCAN_SQLMAP 设成 off 不会污染路径候选（两个语义互不干扰）")
    finally:
        if saved is None:
            os.environ.pop("AISCAN_SQLMAP", None)
        else:
            os.environ["AISCAN_SQLMAP"] = saved


# ======================================================================
def main() -> int:
    print("=" * 74)
    print("外部工具定位自测（binlocate）")
    print("=" * 74)
    ring_priority()
    ring_survives_user_change()
    ring_stdin_guard()
    ring_env_key_no_clash()
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
