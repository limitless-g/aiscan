# -*- coding: utf-8 -*-
"""外部工具可执行文件的定位
============================

原先三处（`nuclei_runner` / `tools` / `sqlmap_probe`）各自写死一份
`C:\\Users\\<用户名>\\...` 路径。在本机没问题，但这套工具链是要被拷到
**另一台电脑**上跑的 —— 那边只要 Windows 用户名不同（更别说换盘符、
换安装位置），所有写死路径一起落空：工具「消失」→ 检测静默降级，
而报告上只会写一句「未安装」，没人知道其实是**路径没找对**。

这类错误的可怕之处在于它长得跟「目标没这个问题」一模一样（红线 9：
「无发现」必须先证明被测对象真被应用处理了，工具没跑起来就更不该
产出任何结论）。所以把定位收进一个模块，按**从可信到兜底**的顺序找：

  ① **环境变量显式指定**（`AISCAN_NUCLEI_BIN` / `AISCAN_SQLMAP_BIN`）
     —— 没有标准安装位置的机器上，这是唯一可靠的指路方式。
  ② **当前 Python 环境自身的 Scripts/bin 目录**（`sys.prefix`）
     —— sqlmap 是 pip 包，装进哪个 venv 就在哪个 venv 里；
        换台机器重建 venv 后，这一条自动指向新位置，无需任何配置。
  ③ **用户目录下的约定位置**（`Path.home()` 展开）
     —— 如 `~/.workbuddy/binaries/bin/nuclei.exe`；
        用户目录跟着当前用户走，换用户名自动适配。
  ④ **包内附带**（`<包根>/tools/`）
     —— 分发包可以把二进制放在自己目录里，实现自包含。
  ⑤ **历史硬编码路径兜底** —— 本机行为完全不变（向后兼容）。

**找不到就返回 None，绝不抛异常**：定位失败在上层是一等公民状态
（「未执行」而不是「通过」），不能被一个异常打断整条流水线。

⚠️ 环境变量命名**刻意避开 `AISCAN_SQLMAP`**：那个名字已经被
`sqlmap_probe._env_mode()` 用作**模式开关**（`auto` / `off`），
拿它兼作路径会让「安全档不调用 sqlmap」这条约束（红线 27）失效。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

#: 环境变量名 —— 显式指定可执行文件位置。
#: 注意不要与任何**模式开关**重名（见模块 docstring 的说明）。
ENV_KEYS: dict[str, str] = {
    "nuclei": "AISCAN_NUCLEI_BIN",
    "sqlmap": "AISCAN_SQLMAP_BIN",
}

#: 包根目录（本文件在 `<包根>/engine/` 下）
PKG_ROOT: Path = Path(__file__).resolve().parent.parent

#: 历史硬编码路径的**可移植版本**：保留为最末位兜底。
#: 原写法是 `C:/Users/<用户名>/...` 这样写死的字面量 —— 换台电脑（用户名或
#: 盘符不同）就会全部落空：工具「消失」→ 检测静默降级，而报告只写一句
#: 「未安装」，看起来跟「目标没问题」一模一样（红线 9 的坑）。
#: 因此改成从**用户目录推导**：语义完全等价，但跟着当前用户走，拷到任何
#: 机器都能自动适配。
_HOME: Path = Path.home()
_LEGACY: dict[str, tuple[str, ...]] = {
    "nuclei": (str(_HOME / ".workbuddy" / "binaries" / "bin" / "nuclei.exe"),),
    "sqlmap": (
        str(
            _HOME
            / ".workbuddy"
            / "binaries"
            / "python"
            / "envs"
            / "aiscan"
            / "Scripts"
            / "sqlmap.exe"
        ),
    ),
}


def bin_names(binary: str) -> list[str]:
    """按当前平台给出可执行文件名（Windows 优先 `.exe`，再试无后缀）。"""
    if sys.platform.startswith("win"):
        return [f"{binary}.exe", binary]
    return [binary]


def candidates(binary: str, home: Path | None = None) -> list[str]:
    """返回该工具的候选路径，按可信度降序、已去重。

    `home` 是**为自测注入**的（与 `nuclei_runner` 注入 `clock` 是同一手法）：
    不传时取 `Path.home()`，与生产路径完全一致。自测靠它模拟
    「换到另一台电脑、另一个 Windows 用户名」—— 那是本模块存在的理由，
    而它没法在真机上跑。
    """
    out: list[str] = []

    # ① 环境变量显式指定
    env = (os.environ.get(ENV_KEYS.get(binary, "")) or "").strip()
    if env:
        out.append(env)

    home = home or Path.home()
    names = bin_names(binary)

    if binary == "nuclei":
        # ③ 用户目录约定位置（本机 WorkBuddy 生态的落点）
        out += [str(home / ".workbuddy" / "binaries" / "bin" / n) for n in names]
        # ④ 包内附带（分发包自包含）
        out += [str(PKG_ROOT / "tools" / n) for n in names]
    elif binary == "sqlmap":
        # ② 当前 Python 环境（换机重建 venv 后自动指向新位置，零配置）
        prefix = Path(sys.prefix)
        out += [str(prefix / "Scripts" / n) for n in names]
        out += [str(prefix / "bin" / n) for n in names]
        # ③ 用户目录约定位置
        out += [str(home / ".workbuddy" / "binaries" / "python" / "envs"
                    / "aiscan" / "Scripts" / n) for n in names]

    # ⑤ 历史硬编码路径兜底
    out += list(_LEGACY.get(binary, ()))

    # 去重（保序：先出现的可信度更高，不能被后面的覆盖）
    seen: set[str] = set()
    uniq: list[str] = []
    for p in out:
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def locate(binary: str, home: Path | None = None) -> str | None:
    """定位可执行文件；找不到返回 `None`（**不抛异常**）。

    只做「文件存在」判定，不做版本探测 —— 版本与身份校验是
    `engine/tools.py:_probe_one` 的职责（那里要防「同名不同源」的工具，
    如 Python 的 httpx 库 vs ProjectDiscovery 的 httpx 二进制）。

    `home` 同 `candidates`：仅自测注入用。
    """
    for p in candidates(binary, home=home):
        try:
            if os.path.isfile(p):
                return p
        except (OSError, ValueError):
            # 路径非法时继续试下一个候选，不中断定位。
            # 两类异常都要接：`os.path.isfile` 对含 NUL 的路径
            # 抛的是 **ValueError**（`embedded null character`），
            # 只 catch OSError 会让一个配置错误直接掀翻整条流水线。
            continue
    return None
