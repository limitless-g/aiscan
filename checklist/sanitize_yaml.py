# -*- coding: utf-8 -*-
"""
YAML 值安全化：给以 YAML 特殊字符开头的裸标量加引号。
--------------------------------------------------
背景：清单里存在 `detect: *.aliyuncs.com / *.myqcloud.com ...` 这类值，
      以 * 开头会被 YAML 解析器当作别名引用（AliasToken），直接解析失败。
处理：扫描所有 `key: value` 形式的行，若 value 未加引号且以危险起始字符
      （* & ! % @ ` > | { [ ）开头，则整体加双引号并转义内部双引号。
      同时把值内的裸 `#` 前空格情况保持原样（YAML 视为注释，不处理）。
"""
import re
import shutil
import sys
from pathlib import Path

FILES = ["checklist-wstg.yaml", "checklist-extras.yaml"]
# 这些字符出现在标量开头时，YAML 会赋予其结构含义
RISKY_START = set("*&!%@`>|{[")
KV_RE = re.compile(r"^(\s*(?:-\s+)?[A-Za-z_][A-Za-z0-9_]*:\s+)(.+?)\s*$")


def fix_line(line: str) -> tuple[str, bool]:
    stripped = line.lstrip()
    if stripped.startswith("#") or stripped.startswith("- #"):
        return line, False  # 整行注释，不动
    m = KV_RE.match(line)
    if not m:
        return line, False
    prefix, value = m.group(1), m.group(2)
    if not value:
        return line, False
    # 已加引号则跳过
    if value[0] in ("'", '"'):
        return line, False

    need_quote = False
    # 规则 1：以 YAML 结构字符开头，会被当成别名 / 锚点 / 标签 / 流式集合
    if value[0] in RISKY_START:
        need_quote = True
    # 规则 2：值内含 "冒号+空格"，YAML 会误判为嵌套 mapping
    if ": " in value or value.endswith(":"):
        need_quote = True
    # 规则 3：值内出现 " #"，会被当成行内注释截断
    if " #" in value:
        need_quote = True

    if need_quote:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'{prefix}"{escaped}"', True
    return line, False


def process(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    out, n = [], 0
    for ln in lines:
        new, changed = fix_line(ln)
        out.append(new)
        n += 1 if changed else 0
    if n:
        backup = path.with_suffix(path.suffix + ".pre-quote")
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return n


def main() -> None:
    base = Path(__file__).resolve().parent
    total = 0
    for name in FILES:
        p = base / name
        if p.exists():
            c = process(p)
            total += c
            print(f"{name}: 修复 {c} 处危险起始值")
    print(f"合计修复 {total} 处")

    try:
        import yaml
    except ImportError:
        sys.exit("缺少 pyyaml")
    ok = True
    for name in FILES:
        p = base / name
        if not p.exists():
            continue
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  ✗ {name} 仍无法解析：{type(e).__name__}: {str(e).splitlines()[0]}")
            continue
        n_item = sum(
            len(b.get("items", []))
            for b in data
            if isinstance(b, dict) and "category" in b
        )
        n_cat = sum(1 for b in data if isinstance(b, dict) and "category" in b)
        print(f"  ✓ {name} 解析通过 → 顶层 {len(data)} 元素，分类 {n_cat}，检查项 {n_item}")
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
