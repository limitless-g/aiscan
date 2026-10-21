#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web 控制台离线自测（不真正跑扫描，不依赖外部服务）
=================================================
验证：
  ① 存储层：项目 CRUD、账号保存、口令安全存储与隔离（口令不进项目 JSON）
  ② 运行器：accounts.yaml 生成正确（口令走环境变量、配置无明文）、进度解析
  ③ 服务路由：起一个临时 HTTP 服务，验证项目增删查与静态首页
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from web import storage, runner, server  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def test_storage(tmp):
    print("[1] 存储层")
    storage.PROJECTS_DIR = tmp / "projects"
    storage.SECRETS_DIR = tmp / "secrets"
    # 项目 CRUD
    p = storage.create_project({"name": "示例系统", "target": "example.com", "authorizer": "张三", "auth_ref": "M1"})
    check("创建项目", p["id"] and p["name"] == "示例系统")
    got = storage.get_project(p["id"])
    check("读取项目", got and got["target"] == "example.com")
    storage.update_project(p["id"], {"profile": "deep"})
    check("更新项目", storage.get_project(p["id"])["profile"] == "deep")
    # 账号 + 口令隔离
    storage.set_accounts(p["id"], [{"name": "admin", "role": "admin", "username": "a@e.com", "login_url": "/login", "method": "POST"}])
    storage.set_account_secret(p["id"], "admin", "S3cr3t!")
    proj = storage.project_view(p["id"])
    acct = proj["accounts"][0]
    check("账号已保存", acct["name"] == "admin" and acct["username"] == "a@e.com")
    check("口令不进项目 JSON", "S3cr3t!" not in json.dumps(proj))
    check("口令已存安全存储", storage.get_account_secret(p["id"], "admin") == "S3cr3t!")
    # 删除清理
    storage.delete_project(p["id"])
    check("删除项目", storage.get_project(p["id"]) is None and not (storage.SECRETS_DIR / f"{p['id']}.json").exists())


def test_runner(tmp):
    print("[2] 运行器")
    storage.PROJECTS_DIR = tmp / "projects"
    storage.SECRETS_DIR = tmp / "secrets"
    pid = storage.create_project({"name": "T", "target": "t.com", "profile": "standard", "mode": "manual"})["id"]
    storage.set_accounts(pid, [{"name": "u1", "role": "customer", "username": "u1@e.com", "login_url": "/login", "method": "POST"}])
    storage.set_account_secret(pid, "u1", "pw123")
    proj = storage.get_project(pid)
    y, env_block = runner.build_accounts_yaml(pid, proj, tmp / "run")
    check("生成 accounts.yaml", y is not None and y.exists())
    text = y.read_text(encoding="utf-8")
    check("配置不落明文口令", "pw123" not in text and "u1@e.com" not in text)
    check("引用环境变量", "JS_U1_EMAIL" in text and "JS_U1_PASS" in text)
    # 进度解析
    m = runner._STAGE_RE.search("阶段 3/16 正在检测")
    check("解析阶段进度", m and int(m.group(1)) == 3 and int(m.group(2)) == 16)
    # findings 多形态解析
    f1 = runner._extract_findings({"findings": [{"severity": "高危"}]})
    f2 = runner._extract_findings([{"severity": "中危"}])
    f3 = runner._extract_findings({"items": [{"severity": "低危"}]})
    check("解析 findings 形态1", len(f1) == 1 and f1[0]["severity"] == "高危")
    check("解析 findings 形态2(列表)", len(f2) == 1)
    check("解析 findings 形态3(key=items)", len(f3) == 1 and f3[0]["severity"] == "低危")
    storage.delete_project(pid)


def test_server(tmp):
    print("[3] 服务路由")
    storage.PROJECTS_DIR = tmp / "projects"
    storage.SECRETS_DIR = tmp / "secrets"
    srv = server.make_server("127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        # 静态首页
        with urllib.request.urlopen(base + "/") as r:
            html = r.read().decode("utf-8")
        check("首页可访问", "<title>aiscan 控制台" in html)
        # 静态资源 served 内容 == 磁盘文件（防 _serve_static 路径拼接 bug 兜底成 index.html）
        for rel in ("static/styles.css", "static/app.js"):
            with urllib.request.urlopen(base + "/" + rel) as r:
                served = r.read()
            disk = (ROOT / "web" / rel).read_bytes()
            check(f"静态资源 {rel} 与磁盘一致",
                  hashlib.md5(served).hexdigest() == hashlib.md5(disk).hexdigest())
        # 创建项目 via API
        req = urllib.request.Request(base + "/api/projects", data=json.dumps(
            {"name": "API测试", "target": "api.test", "authorizer": "李四", "auth_ref": "M2"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as r:
            pj = json.loads(r.read())
        check("API 创建项目", pj.get("id") and pj["name"] == "API测试")
        pid = pj["id"]
        with urllib.request.urlopen(base + f"/api/projects/{pid}") as r:
            got = json.loads(r.read())
        check("API 读取项目", got["target"] == "api.test")
        # 删除
        req = urllib.request.Request(base + f"/api/projects/{pid}", method="DELETE")
        with urllib.request.urlopen(req) as r:
            dj = json.loads(r.read())
        check("API 删除项目", dj.get("deleted") is True)
    except Exception as e:
        check("服务路由", False, str(e))
    finally:
        srv.shutdown()


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        test_storage(tmp)
        test_runner(tmp)
        test_server(tmp)
    print(f"\n结果：通过 {PASS} / 失败 {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
