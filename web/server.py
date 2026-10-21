#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 控制台 —— HTTP 服务（零依赖，仅标准库）
============================================
基于 ThreadingHTTPServer + BaseHTTPRequestHandler 的极简路由：
  · 静态资源（web/static/）
  · REST 风格 API（项目 / 账号 / 扫描 / 任务进度 / 产出统计）
  · SSE 实时进度流

默认只绑定 127.0.0.1 —— 控制台是本机运维壳，不应暴露到公网。
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from . import storage, runner

WEB_DIR = Path(__file__).resolve().parent
STATIC_DIR = WEB_DIR / "static"
REPO_ROOT = WEB_DIR.parent

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class _Handler(BaseHTTPRequestHandler):
    # 安静日志
    def log_message(self, *args, **kwargs):  # noqa: D401
        pass

    # ---- 工具 ----
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, obj: Any):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def _serve_static(self, path: str):
        rel = path.lstrip("/")
        if rel in ("", "static", "static/"):
            fp = STATIC_DIR / "index.html"
        else:
            # rel 已含 "static/..."，基于 WEB_DIR 解析，避免重复拼接 static
            fp = (WEB_DIR / rel).resolve()
        if not str(fp).startswith(str(STATIC_DIR.resolve())):
            self._send(403, b"forbidden")
            return
        if fp.is_dir():
            fp = fp / "index.html"
        if not fp.exists():
            # SPA 兜底：未知路径回 index.html
            fp = STATIC_DIR / "index.html"
        ctype = _MIME.get(fp.suffix.lower(), "application/octet-stream")
        self._send(200, fp.read_bytes(), ctype)

    # ---- 路由 ----
    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path
        if path == "/" or path.startswith("/static/"):
            self._serve_static(path)
            return
        if path == "/api/projects":
            self._send_json(200, storage.list_projects())
            return
        if path.startswith("/api/projects/"):
            self._route_project_get(path)
            return
        if path.startswith("/api/tasks/"):
            self._route_task_get(path)
            return
        if path == "/api/checklist":
            self._api_checklist()
            return
        if path.startswith("/api/report"):
            self._api_report(p)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        p = urlparse(self.path)
        path = p.path
        if path == "/api/projects":
            self._api_create_project()
            return
        if path.startswith("/api/projects/") and path.endswith("/scan"):
            self._api_scan(path)
            return
        if path.startswith("/api/projects/") and path.endswith("/ledger"):
            self._api_register_ledger(path)
            return
        self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        p = urlparse(self.path)
        path = p.path
        if path.startswith("/api/projects/") and path.endswith("/accounts"):
            self._api_set_accounts(path)
            return
        if path.startswith("/api/projects/"):
            self._api_update_project(path)
            return
        self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        p = urlparse(self.path)
        path = p.path
        if path.startswith("/api/projects/"):
            self._api_delete_project(path)
            return
        self._send_json(404, {"error": "not found"})

    # ---- 业务 ----
    def _route_project_get(self, path: str):
        # /api/projects/<id> 或 /api/projects/<id>/outputs
        parts = [x for x in path.split("/") if x]
        pid = parts[2]
        if len(parts) >= 4 and parts[3] == "outputs":
            self._send_json(200, {
                "outputs": runner.list_outputs(REPO_ROOT, storage.get_project(pid)["name"] if storage.get_project(pid) else pid),
                "task_stats": self._latest_stats(pid),
            })
            return
        if len(parts) >= 4 and parts[3] == "accounts":
            self._send_json(200, {"accounts": storage.get_accounts(pid)})
            return
        proj = storage.project_view(pid)
        if proj is None:
            self._send_json(404, {"error": "project not found"})
            return
        self._send_json(200, proj)

    def _latest_stats(self, pid: str) -> Dict[str, Any]:
        # 内存任务里找该项目最近一次完成的统计
        best = {}
        for t in runner.TASKS.values():
            if t.pid == pid and t.status == "done" and t.stats:
                best = t.stats
        return best

    def _api_create_project(self):
        payload = self._read_json()
        proj = storage.create_project(payload)
        # 尝试自动登记授权台账（满足扫描器合规闸门）
        self._register_ledger_for(proj)
        self._send_json(201, proj)

    def _api_update_project(self, path: str):
        pid = path.split("/")[3]
        proj = storage.update_project(pid, self._read_json())
        if proj is None:
            self._send_json(404, {"error": "project not found"})
            return
        self._send_json(200, proj)

    def _api_delete_project(self, path: str):
        pid = path.split("/")[3]
        ok = storage.delete_project(pid)
        self._send_json(200, {"deleted": ok})

    def _api_set_accounts(self, path: str):
        pid = path.split("/")[3]
        data = self._read_json()
        accts = data.get("accounts", [])
        # 口令走安全存储，不进账号配置
        for a in accts:
            pw = a.get("password")
            if pw:
                storage.set_account_secret(pid, a["name"], pw)
        proj = storage.set_accounts(pid, accts)
        if proj is None:
            self._send_json(404, {"error": "project not found"})
            return
        self._send_json(200, storage.project_view(pid))

    def _api_scan(self, path: str):
        pid = path.split("/")[3]
        tid = runner.launch_scan(pid, REPO_ROOT)
        if tid is None:
            self._send_json(404, {"error": "project not found"})
            return
        self._send_json(202, {"task_id": tid})

    def _api_register_ledger(self, path: str):
        pid = path.split("/")[3]
        proj = storage.get_project(pid)
        if proj is None:
            self._send_json(404, {"error": "project not found"})
            return
        self._send_json(200, self._register_ledger_for(proj))

    def _register_ledger_for(self, proj: Dict[str, Any]) -> Dict[str, Any]:
        target = proj.get("target", "")
        if not target:
            return {"ok": False, "reason": "no target"}
        cmd = [sys.executable, "aiscan.py", "ledger", "--register", target,
               "--name", proj.get("name", target)]
        if proj.get("authorizer"):
            cmd += ["--authorizer", proj["authorizer"]]
        if proj.get("auth_ref"):
            cmd += ["--ref", proj["auth_ref"]]
        try:
            r = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=60)
            return {"ok": r.returncode == 0, "returncode": r.returncode,
                    "stdout": (r.stdout or "")[-500:], "stderr": (r.stderr or "")[:300]}
        except Exception as e:
            return {"ok": False, "reason": str(e)}

    def _route_task_get(self, path: str):
        parts = [x for x in path.split("/") if x]
        # /api/tasks/<id> 或 /api/tasks/<id>/stream
        tid = parts[2]
        task = runner.get_task(tid)
        if task is None:
            self._send_json(404, {"error": "task not found"})
            return
        if len(parts) >= 4 and parts[3] == "stream":
            self._sse(task)
            return
        self._send_json(200, task.snapshot())

    def _sse(self, task: runner.Task):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        deadline = time.time() + 3600  # 最长 1 小时
        grace = 0
        try:
            while time.time() < deadline:
                snap = task.snapshot()
                payload = json.dumps(snap, ensure_ascii=False)
                self.wfile.write(f"event: update\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                # 结束后多推几帧再关连接
                if task.status in ("done", "error"):
                    grace += 1
                    if grace >= 3:
                        break
                time.sleep(1.5)
                if int(time.time()) % 15 == 0:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _api_checklist(self):
        try:
            r = subprocess.run([sys.executable, "aiscan.py", "checklist"],
                               cwd=str(REPO_ROOT), capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=120)
            self._send_json(200, {"ok": r.returncode == 0,
                                  "text": (r.stdout or "")[:4000]})
        except Exception as e:
            self._send_json(200, {"ok": False, "error": str(e)})

    def _api_report(self, parsed):
        qs = parse_qs(parsed.query)
        name = qs.get("name", [""])[0]
        d = qs.get("d", [""])[0]
        f = qs.get("f", [""])[0]
        if not (name and d and f):
            self._send_json(400, {"error": "missing params"})
            return
        fp = (REPO_ROOT / "outputs" / name / d / f).resolve()
        # 严格限制：只能读 outputs 下的文件
        if not str(fp).startswith(str((REPO_ROOT / "outputs").resolve())):
            self._send(403, b"forbidden")
            return
        if not fp.exists():
            self._send_json(404, {"error": "not found"})
            return
        ctype = "text/markdown; charset=utf-8" if f.endswith(".md") else "text/plain; charset=utf-8"
        self._send(200, fp.read_bytes(), ctype)


def make_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), _Handler)
    return srv


def run(host: str = "127.0.0.1", port: int = 8080):
    srv = make_server(host, port)
    url = f"http://{host}:{port}/"
    print(f"aiscan-web 已启动：{url}  （仅本机可访问，Ctrl+C 退出）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    run()
