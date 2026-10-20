# -*- coding: utf-8 -*-
"""检查项总表结构校验：项数统计 + 字段完整性 + 引用合法性"""
import re
import sys
from pathlib import Path

REQUIRED = {"name", "app", "detect", "verify", "level", "compliance"}
FILES = ["checklist-wstg.yaml", "checklist-extras.yaml"]
APP_ENUM = {
    "always", "has_login", "has_account", "has_admin", "has_api", "has_graphql",
    "has_input", "has_upload", "has_download", "has_payment", "has_oauth",
    "has_session", "has_client", "has_websocket", "has_component", "has_storage",
    "has_cloud", "has_cicd", "has_ai",
}


def parse(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    cats, items, cur, cat = [], [], None, None
    for i, line in enumerate(lines):
        m = re.match(r"^- category:\s*(\S+)", line)
        if m:
            cat = m.group(1)
            cats.append(cat)
            continue
        m = re.match(r"^\s*-\s*id:\s*(\S+)", line)
        if m:
            if cur:
                items.append(cur)
            cur = {"id": m.group(1), "cat": cat, "fields": set(), "line": i + 1}
            continue
        if cur:
            m = re.match(r"^\s{6}([A-Za-z_]+):", line)
            if m:
                cur["fields"].add(m.group(1))
    if cur:
        items.append(cur)
    return cats, items


def main():
    total = 0
    problems = []
    for f in FILES:
        if not Path(f).exists():
            problems.append(f"文件不存在: {f}")
            continue
        cats, items = parse(f)
        print(f"\n=== {f} ===")
        print(f"分类 {len(cats)} 个: {', '.join(cats)}")
        print(f"检查项 {len(items)} 项")
        total += len(items)

        seen = set()
        for it in items:
            if it["id"] in seen:
                problems.append(f"  [{f}] ID 重复: {it['id']}")
            seen.add(it["id"])
            miss = REQUIRED - it["fields"]
            if miss:
                problems.append(f"  [{f}] {it['id']} (line {it['line']}) 缺字段: {sorted(miss)}")
            if it["cat"] is None:
                problems.append(f"  [{f}] {it['id']} 不在任何 category 下")

        # 适用条件取值合法性
        raw = Path(f).read_text(encoding="utf-8")
        for app in re.findall(r"^\s{6}app:\s*(\S+)", raw, re.M):
            if app not in APP_ENUM:
                problems.append(f"  [{f}] 非法 app 取值: {app}")

    print(f"\n{'=' * 46}")
    print(f"合计检查项: {total}")
    if problems:
        print(f"发现 {len(problems)} 个问题:")
        for p in problems:
            print(p)
        sys.exit(1)
    print("结构校验通过：字段完整、ID 唯一、适用条件取值合法")


if __name__ == "__main__":
    main()
