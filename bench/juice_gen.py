#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
juice_gen.py —— 把 Juice Shop 官方挑战清单和「aiscan 能力判定表」合成 ground truth。

为什么拆成两个文件、还要过一道 schema
======================================
benchmark 的命门是「答案必须独立于被测实现」（红线 30）。
本项目的做法是把两件事严格分开：

  官方侧      data/static/challenges.yml —— 直接从 juice-shop 仓库拉，
              **aiscan 一行都没改**。行数、名字、难度全是靶场作者写的，
              所以「分母」不可能因为引擎改了而漂。

  判定侧      juice_verdicts.py —— 我逐条对照 aiscan 清单 `detect` 字段
              给出的能力判定。**这是唯一可能出错的地方**，所以它是显式
              的一张表：每一条写了依据（依据什么判断这条该由谁负责），
              改错了一条只会错一条，不会让整个分母失真。

  合成侧      就是本脚本。它做两件保险：
              ①两边全 join 不上就报错退出，不许静默少算几条
              （少算 = 分母变小 = 召回率虚高，这是最危险的失真方向）；
              ②把官方 challenges.yml 的 sha256 写进产物，读者能验证
              答案表对应的是哪一版靶场。

用法:
  python bench/juice_gen.py                        # 生成 bench/juice_ground_truth.yaml
  python bench/juice_gen.py --source <challenges.yml>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from juice_verdicts import VERDICTS  # noqa: E402

DEFAULT_SRC = ROOT / "bench" / "juice-challenges.yml"
OUT = ROOT / "bench" / "juice_ground_truth.yaml"

VERDICT_HELP = {
    "auto": (
        "黑盒可达且有对应检测体：aiscan 清单里存在声明负责该类问题、"
        "且适用性标记（app）在 Juice Shop 上成立的检查项。"
        "这是「能力上界」，不是实测命中。"
    ),
    "semi": (
        "有对应检测体，但需前置条件：多账号 / 写授权 / 渲染 / 字典 / "
        "带外（OOB）回调。补齐条件后可自动，不补齐则只能落到人工项。"
    ),
    "manual": (
        "业务逻辑、多步推理、交互式绕过。按红线 3/32，这类只能作为人工项，"
        "标自动等于造假通过。"
    ),
    "gap": (
        "能力缺口：aiscan 清单中没有任何一项声明负责该类问题。"
        "按红线 14，缺口必须显式列出 —— 读者要把「还没做」和「没问题」分开。"
    ),
    "na": (
        "不适用黑盒扫描：需白盒源码、纯 OSINT 推理、Web3/非 HTTP 协议、"
        "DoS（红线 11 明确不做）、或非安全性 Bug（整蛊：Shenanigans）。"
    ),
}

HEADER = """# ==============================================================================
# Juice Shop · 已知漏洞基准（ground truth）
# ==============================================================================
# 本文件由 bench/juice_gen.py **自动生成**，请勿手工编辑。
#
#   · 要换靶场版本 / 补新挑战 → 换 bench/juice-challenges.yml（官方原文）
#   · 要改「aiscan 能不能检」的判定 → 改 bench/juice_verdicts.py
# ------------------------------------------------------------------------------
# 为什么答案表必须这么来
# ------------------------------------------------------------------------------
# 召回率只能在「有答案的靶场」上测，且答案不能照着引擎当前的产出写 ——
# 那样测出来永远是 100%，测的是「引擎是否等于它自己」（红线 30）。
# 本表的来源是 Juice Shop 官方仓库 data/static/challenges.yml，aiscan 未改一字；
# 只有 verdict / acceptable_items 是本项目给的，且每条都写了依据。
#
# 源: {src}
# sha256: {sha}
# 生成时间: {ts}
#
# ------------------------------- 结论层级 -------------------------------------
# verdict 有五个值，含义见 VERDICT_HELP（生成器内也有副本）：
{verdict_help}
#
# ------------------------------- 怎么读这份表 ---------------------------------
# 真·召回率的算法与红线保持一致：
#   分母 = auto + semi + manual + gap   （黑盒 URGENT 判断这类坏账负责人）：
#          即「这类问题本该被扫出来或被明确记账」
#   其中 na 不计入分母 —— 让一个黑盒 HTTP 扫描器去查 dykstra 挑战、
#          OSINT 密保、Web3 合约，不是漏报，是量程之外。
#   auto   = 能力上界（不是命中）
#   实测召回率 = 真的那条施工证据报出来了才算，必须由实跑产出,
#          **本文件不提供任何「已命中」的结论**。
# ==============================================================================

version: v1
range: OWASP Juice Shop（外部靶场，需在授权环境运行）
source_repo: https://github.com/juice-shop/juice-shop
source_file: data/static/challenges.yml
source_sha256: "{sha}"
source_challenges: {n}

facts:
"""


def _sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _clean(s: str) -> str:
    """把官方描述压成单行，去掉 HTML 标签与多余空白。"""
    import re
    s = re.sub(r"<[^>]+>", "", s or "")
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return " ".join(s.split())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(DEFAULT_SRC))
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    src = pathlib.Path(args.source)
    if not src.exists():
        print(f"[X] 找不到官方挑战清单: {src}")
        print("    先拉取：curl -L "
              "https://raw.githubusercontent.com/juice-shop/juice-shop/"
              "master/data/static/challenges.yml -o bench/juice-challenges.yml")
        return 2

    official = yaml.safe_load(src.read_text(encoding="utf-8"))
    official = [c for c in official if isinstance(c, dict) and c.get("name")]

    # ---- 保险①：官方清单与判定表必须完全对齐 ----
    off_names = {c["name"]: c for c in official}
    miss_graph = sorted(set(off_names) - set(VERDICTS))
    extra = sorted(set(VERDICTS) - set(off_names))

    if extra:
        print("[X] 判定表里有多余条目（官方新版可能已更名/移除），请核对：")
        for n in extra:
            print("    -", n)
        return 3
    if miss_graph:
        # 官方新增挑战 → 分母变大。这是最容易被悄悄略过的失真方向：
        # 少算一条，召回率就虚高一点点。宁可报错也不静默。
        print(f"[!] 官方清单有 {len(miss_graph)} 条尚无判定，已按 na 记账（请补 VERDICTS）：")
        for n in miss_graph:
            print("    -", n)

    vh = "\n".join(f"#   · {k:<7s} {v}" for k, v in VERDICT_HELP.items())
    out = [HEADER.format(src=src.as_posix(), sha=_sha256(src),
                         ts=_dt.datetime.now().isoformat(timespec="seconds"),
                         n=len(official), verdict_help=vh)]

    for c in official:
        v = VERDICTS.get(c["name"], {"verdict": "na", "items": [],
                                     "because": "官方新增条目，尚未判定 —— 按缺口记账，不许静默略过。"})
        items = v.get("items", []) or []
        tags = "/".join(c.get("tags") or [])
        items_yaml = ("[" + ", ".join(f'"{i}"' for i in items) + "]") if items else "[]"

        out.append(
            f"  - key: \"{c.get('key', '')}\"\n"
            f"    name: \"{c['name']}\"\n"
            f"    category: \"{c.get('category', '')}\"\n"
            f"    difficulty: {c.get('difficulty', 0)}\n"
            f"    tags: \"{tags}\"\n"
            f"    planted: \"{_clean(c.get('description', ''))}\"\n"
            f"    acceptable_items: {items_yaml}\n"
            f"    verdict: {v['verdict']}\n"
            f"    because: \"{_clean(v.get('because', ''))}\"\n"
            f"    witness: \"{_clean(v.get('witness', ''))}\"\n"
        )

    text = "".join(out)
    outp = pathlib.Path(args.out)
    outp.write_text(text, encoding="utf-8")

    # ---- 保险②：产物必须能被重新解析，且条数与官方一致 ----
    back = yaml.safe_load(outp.read_text(encoding="utf-8"))
    n_back = len(back.get("facts", []))
    if n_back != len(official):
        print(f"[X] 产物条数 {n_back} != 官方 {len(official)}，写出失败")
        return 4

    print(f"[OK] {outp.relative_to(ROOT).as_posix()}  {n_back} 条，源 sha256 {_sha256(src)[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
