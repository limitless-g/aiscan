#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 控制台 —— 扫描运行器（零依赖，仅标准库）
============================================
职责：
  · 为一次扫描生成临时 accounts.yaml（口令**只走环境变量**，配置里不落明文）
  · 通过 subprocess 调 aiscan.py scan，捕获 stdout/stderr
  · 解析「阶段 k/total」进度，向任务对象推送日志流
  · 扫描结束后解析 outputs/<名称>/<时间戳>/<名称>_findings.json 做统计
  · 维护内存中的任务表，供 SSE 实时进度推送

注意：任务表是内存态——控制台重启后历史任务会丢失，但项目与产出文件（在
outputs/ 里）是落盘的，刷新后重新读取即可。这符合「控制台只是壳，扫描器
本身是事实来源」的设计。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import storage

WEB_DIR = Path(__file__).resolve().parent

# 阶段进度解析：匹配 "阶段 3/16" 或 "阶段 3"
_STAGE_RE = re.compile(r"阶段\s*(\d+)(?:/(\d+))?")
_SEV_ORDER = ["严重", "高危", "中危", "低危", "信息"]

# ---------------------------------------------------------------------------
# 任务表（内存态）
# ---------------------------------------------------------------------------
class Task:
    def __init__(self, tid: str, pid: str, project_name: str):
        self.id = tid
        self.pid = pid
        self.project_name = project_name
        self.status = "running"          # running | done | error
        self.stage = 0
        self.stage_total = 0
        self.started_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.finished_at: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.log: deque = deque(maxlen=2000)
        self.stats: Dict[str, Any] = {}
        self.archive_dir: Optional[str] = None
        self._subscribers: List[deque] = []

    def push(self, line: str) -> None:
        self.log.append(line)
        for sub in self._subscribers:
            sub.append(line)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pid": self.pid,
            "project_name": self.project_name,
            "status": self.status,
            "stage": self.stage,
            "stage_total": self.stage_total,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "stats": self.stats,
            "archive_dir": self.archive_dir,
            "log_tail": list(self.log)[-200:],
        }


TASKS: Dict[str, Task] = {}
_TASKS_LOCK = threading.Lock()


def get_task(tid: str) -> Optional[Task]:
    return TASKS.get(tid)


def subscribe(tid: str) -> Optional[deque]:
    t = TASKS.get(tid)
    if t is None:
        return None
    q: deque = deque()
    t._subscribers.append(q)
    return q


# ---------------------------------------------------------------------------
# accounts.yaml 生成（口令只走环境变量）
# ---------------------------------------------------------------------------
def _env_name(name: str) -> str:
    up = re.sub(r"[^A-Za-z0-9]", "_", name.upper())
    return up.strip("_") or "ACCT"


def build_accounts_yaml(pid: str, project: Dict[str, Any], tmp_dir: Path) -> Optional[Path]:
    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    accounts = project.get("accounts", [])
    secrets = storage._load_secrets(pid)
    if not accounts:
        return None
    lines = ["# 由 aiscan-web 自动生成（临时文件），口令只走环境变量，不落明文",
             "accounts:"]
    env_block: List[str] = []
    for a in accounts:
        name = a["name"]
        up = _env_name(name)
        email_env = f"JS_{up}_EMAIL"
        pass_env = f"JS_{up}_PASS"
        lines.append(f"  - name: {name}")
        lines.append(f"    role: {a.get('role', 'customer')}")
        if a.get("tenant"):
            lines.append(f"    tenant: {a['tenant']}")
        lines.append("    authorized: true")
        lines.append("    login:")
        lines.append(f"      url: {a.get('login_url', '/login')}")
        lines.append(f"      method: {a.get('method', 'POST')}")
        lines.append(f"      username_field: {a.get('username_field', 'username')}")
        lines.append(f"      username_env: {email_env}")
        lines.append(f"      password_env: {pass_env}")
        lines.append("      no_form_discover: true")
        env_block.append(f"{email_env}={a.get('username', '')}")
        pw = (secrets.get(name) or {}).get("password", "")
        env_block.append(f"{pass_env}={pw}")
    tmp = tmp_dir / "accounts.scan.yaml"
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # 明文口令只在本函数作用域内随 env_block 返回给调用方注入 subprocess，
    # 绝不落盘为文件（扫描结束后 env_block 即被回收）。
    return tmp, env_block


# ---------------------------------------------------------------------------
# 启动扫描
# ---------------------------------------------------------------------------
def launch_scan(pid: str, repo_root: Path) -> Optional[str]:
    project = storage.get_project(pid)
    if project is None:
        return None
    name = project["name"]
    tid = f"t{time.strftime('%Y%m%d%H%M%S')}{storage._new_id()[:4]}"
    task = Task(tid, pid, name)
    with _TASKS_LOCK:
        TASKS[tid] = task

    tmp_dir = repo_root / "web" / "data" / "runs" / tid
    tmp_dir.mkdir(parents=True, exist_ok=True)
    acct_result = build_accounts_yaml(pid, project, tmp_dir)
    acct_yaml = acct_result[0] if acct_result else None
    env_block = acct_result[1] if acct_result else []
    env = dict(os_environ())
    if project.get("health_guard_off"):
        env["AISCAN_HEALTH_GUARD"] = "off"
    for line in env_block:
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v

    cmd = [sys.executable, "aiscan.py", "scan",
           "--target", project["target"],
           "--name", name,
           "--profile", project["profile"],
           "--mode", project["mode"]]
    if project.get("url"):
        cmd += ["--url", project["url"]]
    if acct_yaml:
        cmd += ["--accounts", str(acct_yaml)]
    if project.get("allow_write"):
        cmd += ["--allow-write"]

    task.push(f"$ {' '.join(cmd)}")
    task.push(f"[启动] 项目={name} 目标={project['target']} 档位={project['profile']}")

    threading.Thread(
        target=_run, args=(task, repo_root, cmd, env, name), daemon=True
    ).start()
    return tid


def os_environ() -> Dict[str, str]:
    return dict(os.environ)


# ---------------------------------------------------------------------------
# 子进程读取
# ---------------------------------------------------------------------------
def _run(task: Task, repo_root: Path, cmd: List[str], env: Dict[str, str], name: str) -> None:
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(repo_root), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
    except Exception as e:
        task.push(f"[错误] 无法启动扫描：{e}")
        task.status = "error"
        task.finished_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        return

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        task.push(line)
        m = _STAGE_RE.search(line)
        if m:
            task.stage = int(m.group(1))
            if m.group(2):
                task.stage_total = int(m.group(2))
    proc.stdout.close()
    rc = proc.wait()
    task.exit_code = rc
    task.finished_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    task.status = "done" if rc == 0 else "error"

    # 解析产物
    stats, archive = parse_outputs(repo_root, name)
    task.stats = stats
    task.archive_dir = archive
    task.push(f"[完成] 退出码={rc} 严重={stats.get('严重',0)} 高危={stats.get('高危',0)} "
              f"中危={stats.get('中危',0)} 低危={stats.get('低危',0)} 信息={stats.get('信息',0)}")


def parse_outputs(repo_root: Path, name: str):
    """在 outputs/<name>/ 下找最新归档，解析 findings.json 统计。"""
    base = repo_root / "outputs" / name
    stats = {s: 0 for s in _SEV_ORDER}
    stats["total"] = 0
    archive = None
    if not base.exists():
        return stats, archive
    dirs = sorted([d for d in base.iterdir() if d.is_dir()],
                  key=lambda d: d.name, reverse=True)
    for d in dirs:
        fj = d / f"{name}_findings.json"
        if fj.exists():
            archive = str(d)
            try:
                data = json.loads(fj.read_text(encoding="utf-8"))
            except Exception:
                continue
            findings = _extract_findings(data)
            for f in findings:
                sev = str(f.get("severity", "信息") or "信息")
                if sev not in stats:
                    stats[sev] = 0
                stats[sev] += 1
                stats["total"] += 1
            break
    return stats, archive


def _extract_findings(data: Any) -> List[Dict[str, Any]]:
    """兼容多种 findings.json 形态。"""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "items", "results"):
            v = data.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        # 退路：任意值为「含 severity 的 dict 列表」
        for v in data.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                if any("severity" in x for x in v):
                    return v
    return []


# ---------------------------------------------------------------------------
# 产出列表（供前端展示报告入口）
# ---------------------------------------------------------------------------
def list_outputs(repo_root: Path, name: str) -> List[Dict[str, str]]:
    base = repo_root / "outputs" / name
    out = []
    if not base.exists():
        return out
    for d in sorted(base.iterdir(), key=lambda x: x.name, reverse=True):
        if not d.is_dir():
            continue
        reports = [p.name for p in d.glob(f"{name}_*.md")]
        fj = d / f"{name}_findings.json"
        out.append({
            "dir": d.name,
            "time": d.name,
            "reports": reports,
            "has_findings": fj.exists(),
            "path": str(d),
        })
    return out
