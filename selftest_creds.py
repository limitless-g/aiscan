#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
凭据索取闭环的**跨进程**自测
============================
跑真实的 `aiscan.py creds` 命令行，配一台本地假应用，验证整条闭环：

    探测出入口 → 给指引 → 写进本机凭据库 → 回验真的登进去了 → 不泄露原文

为什么必须是跨进程：这条链路的最后一环是「扫描期真能用上」。
只测 `engine.credguide` 的函数，测到的是「模块自己能算对」；
而真实的失效形态是**接线断了** —— 指引打出来了，命令写进文件了，
可扫描时没人去读那个文件，于是账号永远「没有可用会话」，
原因还显示得完全合理。那种断线只有跑一遍真命令才看得见。

红线：
  · 全程用临时凭据目录（AISCAN_CRED_DIR），不碰真实凭据库；
  · 假应用只监听 127.0.0.1 的随机端口，不外网；
  · 断言「凭据原文不出现在任何输出里」—— 这是通道纪律的底线。
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

PROBLEMS: list[str] = []
CHECKS = 0

# 自测用的假凭据：形状像真的，但显然是测试值。
# 它必须出现在「写入」环节、且**不得**出现在任何输出里。
FAKE_SESS = "SELFTEST-SESSION-VALUE-8F3A"
FAKE_TOKEN = "SELFTEST-TOKEN-2C7B"

_PUBLIC_HTML = ("<html><head><title>首页</title></head><body>"
                "<h1>欢迎</h1><p>本页对游客公开，无需登录即可访问。</p>"
                "</body></html>")
_LOGIN_HTML = ("<html><head><title>登录</title></head><body><form method='post' "
               "action='/api/login'><input name='username'>"
               "<input type='password' name='password'>"
               "<button>登录</button></form></body></html>")


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:  # 静音
        pass

    def _send(self, code: int, ctype: str, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    @staticmethod
    def _path_of(req_path: str) -> str:
        # 代理环境下 requests 可能发**绝对形式**请求行
        # （POST http://host/path HTTP/1.1）。直接拿 self.path 前缀匹配
        # 会 404 —— 且只发生在复用连接的第二个请求起，单独 POST 又正常，
        # 是个「时有时无」的假象。统一用 urlsplit 取路径。
        return urllib.parse.urlsplit(req_path).path or "/"

    def do_GET(self) -> None:  # noqa: N802
        path = self._path_of(self.path)
        if path == "/api/whoami":
            # 会话回验专用：只认**值正确**的会话 Cookie。
            # 只判「有没有这个键」是不够的 —— 那样随便编一个值也算登录成功。
            ck = self.headers.get("Cookie") or ""
            if f"aiscan_sess={FAKE_SESS}" in ck:
                self._send(200, "application/json", '{"ok":true}')
            else:
                self._send(401, "application/json", '{"ok":false}')
            return
        if path == "/login":
            self._send(200, "text/html; charset=utf-8", _LOGIN_HTML)
            return
        if path == "/":
            # 首页对游客也 200 —— 这正是「拿首页回验没有区分力」的场景，
            # 自测要据此断言登录态只能判「未验证」。
            self._send(200, "text/html; charset=utf-8", _PUBLIC_HTML)
            return
        self._send(404, "text/html", "<html><body>404</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        path = self._path_of(self.path)
        if path == "/api/login":
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            fields = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            # 与凭据库自测账号一致的测试值：形状像真的，但显然是测试值。
            if (fields.get("username") == "SELFTEST-USER"
                    and fields.get("password") == "SELFTEST-PASS"):
                raw = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"aiscan_sess={FAKE_SESS}; Path=/")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            else:
                self._send(401, "application/json", '{"ok":false}')
            return
        self._send(404, "text/html", "<html><body>404</body></html>")


def _start_app() -> tuple[socketserver.TCPServer, int]:
    # 必须用**多线程**服务：HTTP/1.1 默认 keep-alive，单线程服务会把
    # 「上一个连接还没关」变成「下一个请求永远连不上」—— 表现是整个自测挂死，
    # 而挂死在 CI 上只会被读成「超时/环境问题」，没人会怀疑到服务模型上。
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, int(srv.server_address[1])


def _check(cond: bool, label: str, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  [OK]   {label}")
    else:
        PROBLEMS.append(label)
        print(f"  [FAIL] {label}" + (f"　（{detail}）" if detail else ""))


def _run(args: list[str], env: dict[str, str], stdin: str = "") -> tuple[int, str]:
    p = subprocess.run([PY, str(ROOT / "aiscan.py"), *args],
                       cwd=str(ROOT), env=env, input=stdin,
                       capture_output=True, encoding="utf-8", errors="replace",
                       timeout=180)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="aiscan_cred_e2e_"))
    cred_dir = tmp / "creds"
    cred_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["AISCAN_CRED_DIR"] = str(cred_dir)
    env["PYTHONIOENCODING"] = "utf-8"
    srv, port = _start_app()
    base = f"http://127.0.0.1:{port}"
    target = "credselftest.example"

    try:
        # ---- 1. 索取指引 ----
        print("\n[1] 索取指引（尚未提供任何凭据）")
        rc, out = _run(["creds", "--target", target, "--login-url", f"{base}/login"], env)
        _check(rc == 0, "creds 默认动作以 0 退出", f"rc={rc}")
        _check("需要你提供登录令牌" in out, "给出索取提示")
        _check(f"{base}/login" in out, "登录入口用的是**传入的证据**，不是编的")
        _check("待提供" in out and "已就位" not in out, "如实显示「待提供」")
        _check("不要把令牌贴进对话" in out,
               "明确警告不要把令牌贴进对话（凭据通道不走对话）")
        _check(f"--target {target} --set" in out,
               "打印的写入命令自带 --target（否则照抄会报错）")

        # ---- 2. 生成骨架：占位不得被当成凭据 ----
        print("\n[2] 生成骨架（占位 ≠ 凭据）")
        rc, out = _run(["creds", "--target", target, "--init"], env)
        sf = cred_dir / f"{target}.json"
        _check(rc == 0 and sf.exists(), "骨架文件已生成", f"rc={rc} {sf}")
        rc, out = _run(["creds", "--target", target], env)
        _check("待提供" in out, "骨架里的占位文字不得被当成凭据")

        # ---- 3. 写入凭据：不得回显原文 ----
        print("\n[3] 写入凭据（通道纪律）")
        payload = json.dumps({
            "cookies": f"aiscan_sess={FAKE_SESS}; tz=Asia/Shanghai",
            "headers": {"Authorization": f"Bearer {FAKE_TOKEN}"},
        }, ensure_ascii=False)
        rc, out = _run(["creds", "--target", target, "--set", "user_a", "--stdin"],
                       env, stdin=payload)
        _check(rc == 0, "写入成功", f"rc={rc}")
        _check("已写入角色" in out and "指纹" in out, "写入后只报摘要与指纹")
        _check(FAKE_SESS not in out and FAKE_TOKEN not in out,
               "**凭据原文不出现在输出里**")
        _check(sf.exists() and FAKE_SESS in sf.read_text(encoding="utf-8"),
               "凭据确实落到了本机凭据库（不是假成功）")

        # ---- 4. 状态：显示已就位，但仍是脱敏的 ----
        print("\n[4] 状态查询")
        rc, out = _run(["creds", "--target", target], env)
        _check("已就位" in out, "状态显示已就位")
        _check(FAKE_SESS not in out and FAKE_TOKEN not in out,
               "状态查询同样不回显凭据原文")

        # ---- 5. 回验：真的能登进去 ----
        print("\n[5] 回验（拿到正确页面才算登录成立）")
        rc, out = _run(["creds", "--target", target, "--verify", "--skip-auth",
                        "--base-url", base, "--verify-path", "/api/whoami"], env)
        _check(rc == 0, "回验以 0 退出", f"rc={rc}")
        _check("已登录" in out, "凭据正确时回验判「已登录」", out[-200:])
        _check(FAKE_SESS not in out and FAKE_TOKEN not in out, "回验输出不回显凭据")
        # 骨架建了 2 个角色，只填了 1 个 —— 计数必须如实是 1，不能把
        # 「库里有这个角色名」当成「这个角色已经能登录」。
        _check("已确认登录态：1 /" in out, "回验给出已确认登录态计数（1 / 2）", out[-160:])

        # ---- 6. 回验的对照实验：公开页不得当登录证据 ----
        # 这是本次修复的核心：判据若是「带 Cookie 访问没被弹回」，而根路径
        # 对游客也 200，那么任何 Cookie（包括失效的）都会被判「已登录」。
        print("\n[6] 回验的对照实验（公开页没有区分力）")
        rc, out = _run(["creds", "--target", target, "--verify", "--skip-auth",
                        "--base-url", base], env)
        _check("未验证" in out, "拿公开首页回验时必须判「未验证」，不能判「已登录」",
               out[-260:])
        _check("已登录" not in out, "公开页对照下不得出现「已登录」")
        _check("verify_path" in out, "要指出补法是指定 verify_path")

        # ---- 7. 错误的凭据必须判「登录失败」，不得含糊 ----
        print("\n[7] 错误凭据的处理")
        bad = json.dumps({"cookies": "aiscan_sess=WRONG-VALUE"})
        rc, _ = _run(["creds", "--target", target, "--set", "user_a", "--stdin"],
                     env, stdin=bad)
        rc, out = _run(["creds", "--target", target, "--verify", "--skip-auth",
                        "--base-url", base, "--verify-path", "/api/whoami"], env)
        _check("登录失败" in out, "无效凭据回验判「登录失败」", out[-200:])

        # ---- 8. 清除：回到「待提供」，不是静默保留 ----
        print("\n[8] 清除")
        rc, out = _run(["creds", "--target", target, "--clear", "user_a"], env)
        _check(rc == 0 and "已清除" in out, "清除有明确回执", f"rc={rc} {out[-120:]}")
        rc, out = _run(["creds", "--target", target], env)
        _check("待提供" in out, "清除后如实回到「待提供」")

        # ---- 9. 授权闸门：回验不得成为绕过台账的发包后门 ----
        print("\n[9] 授权闸门")
        rc, out = _run(["creds", "--target", target, "--verify", "--base-url", base], env)
        _check(rc != 0 and "授权闸门拦截" in out,
               "未登记目标回验被授权闸门拦住（回验会向目标发包）", out[-200:])

        # ---- 10. 账号+密码 → 自动登录（不预置 accounts.yaml 的路线）----
        print("\n[10] 账号密码自动登录")
        _up_dir = Path(tempfile.mkdtemp(prefix="aiscan_cred_up_"))
        try:
            _up_sf = _up_dir / f"{target}.json"  # 与 CLI 写入路径一致
            _env2 = dict(os.environ)
            _env2["AISCAN_CRED_DIR"] = str(_up_dir)
            _env2["PYTHONIOENCODING"] = "utf-8"
            for role in ("user_a", "admin_a"):
                payload = json.dumps({"username": "SELFTEST-USER",
                                      "password": "SELFTEST-PASS"})
                rc, out = _run(["creds", "--target", target,
                                "--set", role, "--stdin"], _env2, payload)
                _check(rc == 0 and "已写入" in out,
                       f"账密 JSON 写入 {role} 成功", f"rc={rc} {out[-160:]}")
            from engine.sessionpool import build_pool
            # CLI 的 creds --set 写到 session_file_for(target)（AISCAN_CRED_DIR 下），
            # 这里直接指到同一个文件 —— 路径对不上就会「写了却读不到」。
            _real_sf = _up_dir / f"{target}.json"
            pool = build_pool(
                [{"name": "user_a", "role": "user", "authorized": True},
                 {"name": "admin_a", "role": "admin", "authorized": True}],
                target_url=base, profile_key="standard",
                verify_path="/api/whoami",
                cred_file=_real_sf, login_url=f"{base}/login")
            by_name = {a["name"]: a for a in pool.accounts}
            _check(len(pool.accounts) == 2, "凭据库账密转出 2 个身份",
                   str([a["name"] for a in pool.accounts]))
            ua = by_name.get("user_a")
            _check(bool(ua) and ua.get("login_state") == "已登录",
                   "账密自动登录后判「已登录」",
                   str((ua or {}).get("login_state")) + " " + str((ua or {}).get("login_note")))
            _check(bool(ua) and f"aiscan_sess={FAKE_SESS}" in ";".join(
                f"{k}={v}" for k, v in (ua.get("cookies") or {}).items()),
                "自动登录拿到的会话 Cookie 真实有效（假应用只认正确值）")
            _check(bool(ua) and ua.get("source") == "auto_login"
                   and ua.get("supplied_by") == "cred_file",
                   "身份来源如实标注为凭据库自动登录",
                   str((ua or {}).get("source")))
            # 错误密码 → 登录失败，不是「未提供凭据」
            _bad_sf = _up_dir / "bad.json"
            from engine import credguide as _cg2
            _cg2.write_role(_bad_sf, "user_a", {}, {},
                            username="SELFTEST-USER", password="WRONG",
                            login_url=f"{base}/login")
            pool_bad = build_pool(
                [{"name": "user_a", "role": "user", "authorized": True}],
                target_url=base, profile_key="standard",
                verify_path="/api/whoami", cred_file=_bad_sf,
                login_url=f"{base}/login")
            ba = (pool_bad.accounts or [{}])[0]
            _check(ba.get("login_state") == "登录失败",
                   "错误密码如实判「登录失败」", str(ba.get("login_state")))
        finally:
            shutil.rmtree(_up_dir, ignore_errors=True)

        # ---- 11. 等待循环：凭据在等待期间写入 → 自动恢复 ----
        print("\n[11] 凭据等待循环")
        import time as _time
        from engine.orchestrator import wait_for_credentials
        from engine import credguide as _cg3
        _wt_dir = Path(tempfile.mkdtemp(prefix="aiscan_cred_wait_"))
        try:
            _wt_sf = _wt_dir / "wait.json"

            def _plan() -> Any:
                return _cg3.build_plan(
                    target="wait.example", target_url="https://wait.example",
                    accounts=[], path_probes={}, session_file=_wt_sf)

            def _fill_later() -> None:
                _time.sleep(1.5)
                _cg3.write_role(_wt_sf, "user_a", {"sid": "wait-ok-1"}, {})
                _cg3.write_role(_wt_sf, "admin_a", {"sid": "wait-ok-2"}, {})

            _th = threading.Thread(target=_fill_later, daemon=True)
            _th.start()
            _t0 = _time.time()
            ok_wait, plan_end = wait_for_credentials(_plan, timeout_s=15,
                                                     poll_s=0.3)
            _dt = _time.time() - _t0
            _th.join(timeout=5)
            _check(ok_wait and not plan_end.pending,
                   "凭据到位后等待循环立即恢复（不必等满超时）", f"耗时 {_dt:.1f}s")
            _check(_dt < 10, "恢复是自动的、且远快于超时上限", f"{_dt:.1f}s")
            # 超时路径：**全新空凭据库**始终等不到 → 按上限返回 False 而不是死等
            _empty_sf = _wt_dir / "empty.json"

            def _plan_empty() -> Any:
                return _cg3.build_plan(
                    target="wait.example", target_url="https://wait.example",
                    accounts=[], path_probes={}, session_file=_empty_sf)

            _t0 = _time.time()
            ok2, _ = wait_for_credentials(_plan_empty, timeout_s=2, poll_s=0.3)
            _check(not ok2 and 1.5 <= _time.time() - _t0 <= 6,
                   "超时路径按上限返回 False（不悬挂）", f"{_time.time() - _t0:.1f}s")
        finally:
            shutil.rmtree(_wt_dir, ignore_errors=True)

    finally:
        srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    if PROBLEMS:
        print(f"失败 {len(PROBLEMS)}/{CHECKS}：")
        for x in PROBLEMS:
            print(f"  - {x}")
        return 1
    print(f"凭据闭环自测通过（{CHECKS} 项断言）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
