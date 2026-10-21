#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aiscan 控制台入口
================
零依赖的本机 Web 控制台：项目 / 账号 / 扫描进度 / 产出统计。

用法：
    python aiscan_web.py                 # 默认 http://127.0.0.1:8080
    python aiscan_web.py --port 9000
    python aiscan_web.py --host 0.0.0.0  # 仅当你清楚风险（会暴露到局域网/公网）

安全：
    · 默认只绑定 127.0.0.1 —— 控制台是运维壳，不应暴露。
    · 账号口令只存本机 web/data/secrets/<id>.json（权限 0600），不进账号配置。
    · 创建项目时自动调用 aiscan.py ledger --register 满足扫描器合规闸门。
"""
from __future__ import annotations

import argparse

from web import server


def main():
    ap = argparse.ArgumentParser(description="aiscan 本机控制台（零依赖）")
    ap.add_argument("--host", default="127.0.0.1", help="绑定地址（默认 127.0.0.1，仅本机）")
    ap.add_argument("--port", type=int, default=8080, help="端口（默认 8080）")
    args = ap.parse_args()
    server.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
