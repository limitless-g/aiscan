# -*- coding: utf-8 -*-
"""
一次性迁移：把清单 YAML 的顶层结构规范化。
--------------------------------------------------
问题：原文件顶层混用了 mapping（meta / applicability / severity_model）
      和 sequence（- category: ...），这不是合法 YAML，只有正则解析器能读。
处理：把三个顶层 mapping 转为 sequence 的首个元素（加 "- " 并整体缩进），
      使顶层统一为列表。迁移后 yaml.safe_load 可直接读取。
"""
import re
import shutil
import sys
from pathlib import Path

FILES = ["checklist-wstg.yaml", "checklist-extras.yaml"]
HEADER_KEYS = ("meta", "applicability", "severity_model")


def migrate(path: Path) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    i = 0
    changed = False

    while i < len(lines):
        line = lines[i]
        m = re.match(r"^([A-Za-z_]+):\s*$", line)
        if m and m.group(1) in HEADER_KEYS:
            # 收集该顶层块的后续缩进行
            block = [line]
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if nxt.strip() == "" or nxt.startswith((" ", "\t")):
                    block.append(nxt)
                    i += 1
                else:
                    break
            # 去掉尾部空行（留到后面统一处理）
            while block and block[-1].strip() == "":
                block.pop()
            # 首行加 "- "，其余行缩进两格
            out.append("- " + block[0])
            for bl in block[1:]:
                out.append(("  " + bl) if bl.strip() else "")
            out.append("")
            changed = True
            continue
        out.append(line)
        i += 1

    if changed:
        backup = path.with_suffix(path.suffix + ".bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return changed


def main() -> None:
    base = Path(__file__).resolve().parent
    for name in FILES:
        p = base / name
        if not p.exists():
            print(f"跳过（不存在）：{name}")
            continue
        done = migrate(p)
        print(f"{'已规范化' if done else '无需改动'}：{name}")

    # 迁移后立即用标准 YAML 解析验证
    try:
        import yaml
    except ImportError:
        sys.exit("缺少 pyyaml，无法验证")
    for name in FILES:
        p = base / name
        if not p.exists():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        n_cat = sum(1 for b in data if isinstance(b, dict) and "category" in b)
        n_item = sum(
            len(b.get("items", []))
            for b in data
            if isinstance(b, dict) and "category" in b
        )
        print(f"  YAML 解析通过：{name} → 顶层元素 {len(data)} 个，分类 {n_cat}，检查项 {n_item}")


if __name__ == "__main__":
    main()
