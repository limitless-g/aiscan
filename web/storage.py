#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 控制台 —— 本地存储层（零依赖，仅标准库）
============================================
职责：
  · 项目（project）的增删改查，JSON 落盘到 web/data/projects/<id>.json
  · 账号配置（accounts）随项目保存，但**明文口令绝不进这里**
  · 凭据（口令）单独存到 web/data/secrets/<id>.json，权限 0600，
    与账号配置分离 —— 与扫描器红线 29（凭据只走环境变量 / 安全存储）对齐

设计要点：
  · 全部本地：控制台只绑定 127.0.0.1，数据不出本机。
  · 凭据隔离：即便项目 JSON 被误提交/拷贝，也拿不到任何口令。
"""
from __future__ import annotations

import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
WEB_DIR = Path(__file__).resolve().parent
DATA_DIR = WEB_DIR / "data"
PROJECTS_DIR = DATA_DIR / "projects"
SECRETS_DIR = DATA_DIR / "secrets"

PROFILES = ("safe", "standard", "deep")
MODES = ("manual", "auto")  # 与 aiscan.py SCAN_MODES 保持一致（subset）


def _ensure_dirs() -> None:
    for d in (PROJECTS_DIR, SECRETS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# 项目 CRUD
# ---------------------------------------------------------------------------
def list_projects() -> List[Dict[str, Any]]:
    _ensure_dirs()
    out = []
    for p in sorted(PROJECTS_DIR.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            continue
    out.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    return out


def get_project(pid: str) -> Optional[Dict[str, Any]]:
    f = PROJECTS_DIR / f"{pid}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def create_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_dirs()
    pid = _new_id()
    now = _now()
    proj = {
        "id": pid,
        "name": str(payload.get("name", "未命名项目")).strip() or "未命名项目",
        "target": str(payload.get("target", "")).strip(),
        "url": str(payload.get("url", "")).strip(),
        "profile": payload.get("profile", "standard"),
        "mode": payload.get("mode", "manual"),
        "objectives": str(payload.get("objectives", "")).strip(),
        "authorizer": str(payload.get("authorizer", "")).strip(),
        "auth_ref": str(payload.get("auth_ref", "")).strip(),
        "impact_level": str(payload.get("impact_level", "L2")).strip(),
        "allow_write": bool(payload.get("allow_write", False)),
        "health_guard_off": bool(payload.get("health_guard_off", False)),
        "accounts": [],
        "created_at": now,
        "updated_at": now,
    }
    if proj["profile"] not in PROFILES:
        proj["profile"] = "standard"
    if proj["mode"] not in MODES:
        proj["mode"] = "manual"
    (PROJECTS_DIR / f"{pid}.json").write_text(
        json.dumps(proj, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return proj


def update_project(pid: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    proj = get_project(pid)
    if proj is None:
        return None
    # 只更新允许改的字段
    for k in ("name", "target", "url", "profile", "mode", "objectives",
              "authorizer", "auth_ref", "impact_level", "allow_write",
              "health_guard_off"):
        if k in payload:
            v = payload[k]
            if k in ("allow_write", "health_guard_off"):
                v = bool(v)
            elif isinstance(v, str):
                v = v.strip()
            proj[k] = v
    if proj["profile"] not in PROFILES:
        proj["profile"] = "standard"
    if proj["mode"] not in MODES:
        proj["mode"] = "manual"
    proj["updated_at"] = _now()
    (PROJECTS_DIR / f"{pid}.json").write_text(
        json.dumps(proj, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return proj


def delete_project(pid: str) -> bool:
    f = PROJECTS_DIR / f"{pid}.json"
    sf = SECRETS_DIR / f"{pid}.json"
    ok = False
    if f.exists():
        f.unlink()
        ok = True
    if sf.exists():
        sf.unlink()
    return ok


# ---------------------------------------------------------------------------
# 账号配置（不含明文口令）
# ---------------------------------------------------------------------------
def get_accounts(pid: str) -> List[Dict[str, Any]]:
    proj = get_project(pid)
    if proj is None:
        return []
    return proj.get("accounts", [])


def set_accounts(pid: str, accounts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    proj = get_project(pid)
    if proj is None:
        return None
    cleaned = []
    for a in accounts:
        if not isinstance(a, dict):
            continue
        name = str(a.get("name", "")).strip()
        if not name:
            continue
        cleaned.append({
            "name": name,
            "role": str(a.get("role", "customer")).strip(),
            "tenant": str(a.get("tenant", "")).strip(),
            "username": str(a.get("username", "")).strip(),
            "username_field": str(a.get("username_field", "username")).strip(),
            "login_url": str(a.get("login_url", "/login")).strip(),
            "method": str(a.get("method", "POST")).strip().upper(),
        })
    proj["accounts"] = cleaned
    proj["updated_at"] = _now()
    (PROJECTS_DIR / f"{pid}.json").write_text(
        json.dumps(proj, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return proj


# ---------------------------------------------------------------------------
# 凭据安全存储（明文口令，0600）
# ---------------------------------------------------------------------------
def _secret_file(pid: str) -> Path:
    return SECRETS_DIR / f"{pid}.json"


def _load_secrets(pid: str) -> Dict[str, Any]:
    f = _secret_file(pid)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_secrets(pid: str, data: Dict[str, Any]) -> None:
    _ensure_dirs()
    f = _secret_file(pid)
    f.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    # 仅本人可读写
    try:
        os.chmod(f, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def set_account_secret(pid: str, account_name: str, password: str) -> None:
    """保存某账号的明文口令到安全存储（0600）。"""
    data = _load_secrets(pid)
    data[account_name] = {"password": password}
    _save_secrets(pid, data)


def get_account_secret(pid: str, account_name: str) -> Optional[str]:
    data = _load_secrets(pid)
    return (data.get(account_name) or {}).get("password")


def delete_account_secret(pid: str, account_name: str) -> None:
    data = _load_secrets(pid)
    if account_name in data:
        del data[account_name]
        _save_secrets(pid, data)


def has_any_secret(pid: str) -> bool:
    return bool(_load_secrets(pid))


# ---------------------------------------------------------------------------
# 便捷：项目 + 账号 + 凭据合并视图（供前端展示，口令打码）
# ---------------------------------------------------------------------------
def project_view(pid: str) -> Optional[Dict[str, Any]]:
    proj = get_project(pid)
    if proj is None:
        return None
    view = dict(proj)
    accts = []
    for a in proj.get("accounts", []):
        a = dict(a)
        a["has_secret"] = (a["name"] in _load_secrets(pid))
        accts.append(a)
    view["accounts"] = accts
    return view
