# -*- coding: utf-8 -*-
"""打包分发 —— 把工具链打成「拷过去就能装」的一个包
==================================================

**它解决什么问题**

这套工具链原先只在本机跑得起来：Python 环境建在固定路径、nuclei / sqlmap
的位置写死在代码里。要挪到另一台电脑，不能只拷 `.py` 文件 —— 必须把
**代码 + 依赖清单 + 一键部署脚本**整包带走，在那边跑一次 `install.ps1`
把环境重建出来。这个脚本负责打包，`install.ps1` 负责在目标机重建。

**打包原则**

  · **不打包产物**：`outputs/`（扫描归档，几百 MB，且含真实漏洞证据）、
    `_logs/`、`__pycache__/`、`dist/` 一律排除。
  · **不打包本机状态**：`.venv/`、`.schedule_state.json`。
  · **默认不打包授权台账**：`ledger/auth-ledger.yaml` 是**合规闸门**，
    不是普通配置。带过去意味着「另一台电脑上的扫描不会逐个问你要授权」；
    不带过去则那台机器上每个目标都要重新登记（更安全，但更麻烦）。
    这个取舍交给人决定，所以做成 `--with-ledger` 开关，默认关闭。
  · **不带凭据**：凭据库落在用户目录（`~/.aiscan/sessions/`），本来就不在
    项目里；这里再显式排除一遍，防止有人把它拷进来。

用法：
    python make_dist.py                  # 生成 dist/aiscan-<日期>-<序号>.zip
    python make_dist.py --with-ledger    # 连授权台账一起打包
    python make_dist.py --list           # 只列出会打包哪些文件，不生成
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"

#: 整目录排除
EXCLUDE_DIRS = {
    "outputs",          # 扫描归档：体积大、含真实漏洞证据、与代码无关
    "_logs",
    "__pycache__",
    ".venv", "venv",    # 本机隔离环境（install.ps1 的产物）
    ".git", ".pytest_cache", "node_modules",
    "dist",
    "sessions", "creds",  # 凭据类目录（正常落在用户目录，这里兜底）
}

#: 后缀排除
EXCLUDE_SUFFIX = {".pyc", ".pyo", ".pyd", ".log", ".bak", ".tmp", ".db"}

#: 文件名排除
EXCLUDE_NAMES = {".schedule_state.json", ".DS_Store", "Thumbs.db"}

#: 授权台账（合规闸门，默认不带）
LEDGER_DIR = Path("ledger")
LEDGER_MAIN = LEDGER_DIR / "auth-ledger.yaml"

DIST_NOTE = """# aiscan 分发包 —— 装之前先读这一页

这是一份**只含代码**的分发包（不含扫描产物、不含其他电脑的授权台账）。

## 怎么装

1. 把这整个目录拷到目标电脑上（U 盘 / 共享盘 / 网盘都行，路径别带空格也行）。
2. 双击 `install.cmd`；
   或在 PowerShell 里执行：
   ```
   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
   ```
3. 看最后的 `DIAGNOSIS SUMMARY`：每步是成功、跳过还是失败，一眼看清。

**装了什么**：脚本会在本目录内建一个隔离环境 `.venv\\`，按 `requirements.txt`
装依赖。不写系统 PATH、不改注册表、不碰系统 Python —— 不想要了直接删 `.venv\\`。

**没装 Python？** 不用装。只要这台电脑装了 WorkBuddy，脚本会自动用它自带的
Python；否则会去找系统里的 Python。

## 装完怎么用

```
.venv\\Scripts\\python.exe aiscan.py checklist          # 看全量检查项清单
.venv\\Scripts\\python.exe aiscan.py tools              # 看本机工具链可用性
.venv\\Scripts\\python.exe aiscan.py ledger --register 目标域名 --name 名称 --authorizer 审批人 --ref 依据
.venv\\Scripts\\python.exe aiscan.py scan --target 目标域名 --name 名称 --profile standard
```

**没有登记授权就扫描，会被引擎拒绝**。这是合规闸门，不是故障 ——
授权台账（`ledger/auth-ledger.yaml`）记录每个目标的授权依据。

## 缺工具会怎样

nuclei / sqlmap / nmap 都是**可选**的：缺失时自动走内置降级方案，
报告里会明确标注「该项由内置检测器覆盖，未使用 nuclei 模板」。
不会因为少一个工具就给你一份看着正常、实际没测的报告。

## 出处

本包由 `make_dist.py` 生成；同一份代码在三处副本间保持一致
（`sync_copies.py` 负责同步与校验）。
"""


def collect(with_ledger: bool) -> list[Path]:
    """按排除规则收集要打包的文件（相对 ROOT 的路径）。"""
    picked: list[Path] = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS for part in rel.parts[:-1]):
            continue
        if p.name in EXCLUDE_NAMES or p.name.startswith("_tmp_"):
            continue
        if p.suffix.lower() in EXCLUDE_SUFFIX:
            continue
        if p.name.startswith(".") and p.name != ".gitignore":
            continue
        if rel.parent == LEDGER_DIR and rel.name.startswith(LEDGER_MAIN.name):
            # 授权台账本体 + 历史快照：--with-ledger 也只带本体，
            # 快照（auth-ledger.yaml.bak-<日期>，后缀非 .bak 逃过排除规则）
            # 一律不带——目标机不应继承本机的授权决策历史。
            # 注意 ledger/*.py 是代码，不受此规则影响。
            if not (with_ledger and rel == LEDGER_MAIN):
                continue
        picked.append(rel)
    return picked


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description="打包 aiscan 分发包")
    ap.add_argument("--with-ledger", action="store_true",
                    help="连授权台账一起打包（默认不带：这是合规闸门，不是普通配置）")
    ap.add_argument("--list", action="store_true", help="只列出文件，不生成压缩包")
    ap.add_argument("--out", default="", help="输出目录（默认 aiscan/dist/）")
    args = ap.parse_args()

    files = collect(args.with_ledger)

    if args.list:
        print(f"会打包 {len(files)} 个文件：")
        for rel in files:
            print(f"  {rel}")
        print()
        print(f"授权台账：{'已包含' if args.with_ledger else '未包含（默认）'}")
        return 0

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    outdir = Path(args.out) if args.out else DIST
    outdir.mkdir(parents=True, exist_ok=True)
    tag = "with-ledger" if args.with_ledger else "code-only"
    zpath = outdir / f"aiscan-{stamp}-{tag}.zip"

    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in files:
            z.write(ROOT / rel, arcname=str(Path("aiscan") / rel))
        z.writestr("aiscan/分发说明.md", DIST_NOTE)

    size_kb = zpath.stat().st_size / 1024
    print(f"已生成：{zpath}")
    print(f"  文件数：{len(files) + 1}（含分发说明.md）")
    print(f"  体积：{size_kb:.1f} KB")
    print(f"  校验：sha256:{sha256_of(zpath)}")
    print(f"  台账：{'已包含（扫描前不会逐目标再要授权）' if args.with_ledger else '未包含（目标机上需逐个登记授权）'}")
    print()
    print("目标机上：解压 → 双击 install.cmd（或跑 install.ps1）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
