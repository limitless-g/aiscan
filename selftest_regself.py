#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
红队自取注册（engine/regself.py）自测
====================================
配两种本地假目标（JSON API 型 / HTML 表单型），验证「开放注册自建测试
身份」整条链路。钉住的都是**真实踩过的坑**：

  ① **环境代理信任坑**（2026-10-09 实测）：沙箱 HTTP_PROXY 在 keep-alive
     复用连接上会把第二个请求（POST 注册）错误路由到站点根 → 返回 SPA
     首页 200 →「注册成功」「登录未下发令牌」两层假象同源。regself 的
     Session 必须 trust_env=False，匿名对照探针必须用全新会话。
  ② **令牌截断坑**：JWT 动辄 700+ 字符，正文截到 400 会切掉闭合引号 →
     真登录被误判「未下发令牌」。假服务器的令牌刻意造 800 字符。
  ③ **token-in-body 型登录的合成判据**：凭据库「账号+密码」合成自动
     登录时，若不带 login_username_field / login_success_*，会话池按
     「username 字段 + Cookie 判据」合成，号是好的也会被误拒收。
  ④ 门控两把锁（deep 档 + 台账写授权）+ AISCAN_REGSELF=off 一票否决。
  ⑤ 失败必须具名（能力缺口），不得静默。
  ⑥ 口令零泄漏：notes / 结果对象 / 会话池记录里都不出现口令原文。

红线（反向对照必须带牙齿）：
  · 注册被拒 → 不得换路硬试（爆破形状），必须具名退场；
  · 幂等：凭据库已有 regself_ 身份时不得重复注册（季度扫描不刷号）。
"""

from __future__ import annotations

import http.server
import json
import os
import re
import socketserver
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import regself                               # noqa: E402
from engine import credguide as CG                       # noqa: E402
from engine.sessionpool import build_pool                # noqa: E402

PROBLEMS: list[str] = []
CHECKS = 0


def check(ok: bool, what: str, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if ok:
        print(f"  ✓ {what}")
    else:
        PROBLEMS.append(f"{what}" + (f"（{detail}）" if detail else ""))
        print(f"  ✗ {what}" + (f" —— {detail}" if detail else ""))


# ==============================================================================
# 假目标 A：JSON API 型（Juice Shop 形态，含安全问题与 800 字符长令牌）
# ==============================================================================

class ApiHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    users: dict[str, str] = {}

    def log_message(self, *a):  # noqa: N802
        pass

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/api/SecurityQuestions":
            self._json(200, {"status": "success", "data": [
                {"id": 1, "question": "Your eldest siblings middle name?"}]})
        elif self.path == "/api/Users":
            # 端点存在但要登录 —— GET 401 是「存在」信号，不是「没有」
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/rest/basket/1":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and len(auth) > 50:
                self._json(200, {"products": []})
            else:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):  # noqa: N802
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""
        try:
            payload = json.loads(raw) if raw.startswith("{") else {
                k: urllib.parse.unquote_plus(v) for k, v in (
                    p.split("=", 1) for p in raw.split("&") if "=" in p)}
        except Exception:  # noqa: BLE001
            payload = {}
        if self.path == "/api/Users":
            email = str(payload.get("email") or "")
            pw = str(payload.get("password") or "")
            if email and pw and "@" in email:
                ApiHandler.users[email] = pw
                # 令牌刻意 800 字符：钉「截断把闭合引号切掉」的坑
                self._json(201, {"status": "success", "data": {"token": "T" * 800}})
            else:
                self._json(400, {"error": "Request body malformed"})
        elif self.path == "/rest/user/login":
            email = str(payload.get("email") or "")
            pw = str(payload.get("password") or "")
            if ApiHandler.users.get(email) == pw:
                # 令牌刻意 800 字符
                self._json(200, {"authentication": {"token": "K" * 800}})
            else:
                self.send_response(401)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", "27")
                self.end_headers()
                self.wfile.write(b"Invalid email or password.")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


# ==============================================================================
# 假目标 B：HTML 表单型（CSRF 隐藏域 + confirm 口令框 + Cookie 会话）
# ==============================================================================

_FORM_REG = """<html><body>
<form action="/do-register" method="post">
<input type="hidden" name="csrf_token" value="csrf-abc123">
<input type="text" name="email" >
<input type="password" name="password">
<input type="password" name="password2">
<input type="text" name="username">
<input type="checkbox" name="agree-terms">
<button type="submit">Sign up</button>
</form></body></html>"""

_FORM_LOGIN = """<html><body>
<form action="/auth" method="post">
<input type="hidden" name="csrf_token" value="csrf-xyz789">
<input type="text" name="mail">
<input type="password" name="pass">
<button type="submit">Log in</button>
</form></body></html>"""


class FormHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    users: dict[str, str] = {}
    sessions: set[str] = set()

    def log_message(self, *a):  # noqa: N802
        pass

    def _html(self, code: int, body: str, headers: list[tuple[str, str]] = ()) -> None:
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):  # noqa: N802
        if self.path == "/register":
            self._html(200, _FORM_REG)
        elif self.path == "/login":
            self._html(200, _FORM_LOGIN)
        elif self.path == "/member":
            ck = (self.headers.get("Cookie") or "")
            if "session=" in ck and ck.split("session=")[1].split(";")[0] in FormHandler.sessions:
                self._html(200, "<html><body>member</body></html>")
            else:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):  # noqa: N802
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""
        fields = {k: urllib.parse.unquote_plus(v) for k, v in (
            p.split("=", 1) for p in raw.split("&") if "=" in p)}
        if self.path == "/do-register":
            # CSRF 没带回 → 403（钉「隐藏域原样带回」的行为）
            if fields.get("csrf_token") != "csrf-abc123":
                self._html(403, "<html>csrf missing</html>")
                return
            email, pw = fields.get("email", ""), fields.get("password", "")
            if email and pw and fields.get("password2") == pw:
                FormHandler.users[email] = pw
                self._html(302, "", [("Location", "/login")])
            else:
                self._html(400, "<html>bad form</html>")
        elif self.path == "/auth":
            email, pw = fields.get("mail", ""), fields.get("pass", "")
            if FormHandler.users.get(email) == pw:
                sid = "S" + "e" * 20
                FormHandler.sessions.add(sid)
                self._html(302, "", [("Set-Cookie", f"session={sid}; Path=/"),
                                     ("Location", "/member")])
            else:
                self._html(401, "<html>bad credentials</html>")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


def _serve(handler) -> tuple[socketserver.TCPServer, str]:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def main() -> int:
    tmpdir = Path(tempfile.mkdtemp())

    # 运行标记须与 run_all_tests.py 第 29 环的 ran_mark 一致（对真实 stdout）。
    print("[1] 门控与两型登录：两把锁 + 环境开关")
    _saved = os.environ.get("AISCAN_REGSELF")
    try:
        os.environ["AISCAN_REGSELF"] = "off"
        r = regself.gate_reason("deep", True)
        check(bool(r) and "AISCAN_REGSELF" in r,
             "off 开关一票否决（具名）", r)
        os.environ.pop("AISCAN_REGSELF", None)
        r2 = regself.gate_reason("standard", True)
        check("standard" in r2 and "deep" in r2, "standard 档拒绝（具名）", r2)
        r3 = regself.gate_reason("deep", False)
        check("台账" in r3 and "allow-write" in r3,
             "无台账写授权拒绝（具名）", r3)
        check(regself.gate_reason("deep", True) == "",
             "两把锁全开 → 放行（返回空串）")
    finally:
        if _saved is None:
            os.environ.pop("AISCAN_REGSELF", None)
        else:
            os.environ["AISCAN_REGSELF"] = _saved

    # ------------------------------------------------------------------
    print("[2] JSON API 路：注册 → 登录回验 → 入库 → 会话池端到端")
    srv_a, url_a = _serve(ApiHandler)
    cred_a = tmpdir / "api-creds.json"
    notes_a: list[str] = []
    try:
        res, notes = regself.run(
            target_url=url_a, domain="127.0.0.1", cred_file=cred_a,
            js_endpoints=["/api/Users"], login_url_hint="/rest/user/login",
            want=2)
        check(len(res) == 2 and all(r.ok for r in res),
             "2 个身份全部建立",
             "; ".join(r.reason for r in res if not r.ok))
        notes_a = list(notes)
        res_a = list(res)
        r1 = res[0]
        check(r1.login_field == "email", "登录字段名识别为 email", r1.login_field)
        check(r1.verify_path == "/rest/basket/1",
             "verify_path 由匿名对照实验找到（401 vs 200）", r1.verify_path)
        check(not r1.cookie_login, "API 路判定为令牌型登录")
        check(any("已建立" in n for n in notes), "报告 note 有「已建立」留痕")
        check(any("受控写纪律" in n for n in notes),
             "受控写放行留痕（deep + 台账写授权）")

        rec = CG._role_record("regself_1", cred_a)
        check(rec.get("login_username_field") == "email",
             "凭据库记录带 login_username_field（否则合成登录用错字段名）")
        check(rec.get("login_success_body") == "token",
             "凭据库记录带 token 判据（否则 token-in-body 被误拒收）")
        check(rec.get("verify_path") == "/rest/basket/1",
             "凭据库记录带 verify_path")

        recs = CG.store_account_records(cred_a)
        pool = build_pool(recs, target_url=url_a, profile_key="deep",
                          domain="127.0.0.1", cred_file=cred_a)
        logged = [a for a in pool.accounts if a.get("login_state") == "已登录"]
        check(len(logged) == 2,
             "会话池端到端：2 个身份自动登录 + 回验通过",
             "; ".join(f"{a['name']}:{a.get('login_state')}" for a in pool.accounts))
        check(pool.authenticated_pairs() >= 2,
             "已确认登录态 ≥2（越权判定门槛）")

        # 幂等：二次 run 不再注册
        res2, notes2 = regself.run(target_url=url_a, domain="127.0.0.1",
                                   cred_file=cred_a, want=2)
        n_before = len(ApiHandler.users)
        check(all("不重复注册" in n for n in notes2) and not res2,
             "幂等：已有身份时跳过注册（季度扫描不刷号）",
             "; ".join(notes2))
        res3, _ = regself.run(target_url=url_a, domain="127.0.0.1",
                              cred_file=cred_a, want=2)
        check(len(ApiHandler.users) == n_before,
             "幂等（二重确认）：假目标用户表未再增长")
    finally:
        srv_a.shutdown()

    # ------------------------------------------------------------------
    print("[3] HTML 表单路：CSRF 隐藏域 + confirm 口令框 + Cookie 登录")
    srv_b, url_b = _serve(FormHandler)
    cred_b = tmpdir / "form-creds.json"
    notes_b: list[str] = []
    try:
        res, notes = regself.run(
            target_url=url_b, domain="127.0.0.1", cred_file=cred_b,
            js_endpoints=["/member"], want=2)
        notes_b = list(notes)
        check(len(res) == 2 and all(r.ok for r in res),
             "表单路 2 个身份全部建立",
             "; ".join(r.reason for r in res if not r.ok) or "; ".join(notes))
        rb = res[0]
        check(rb.cookie_login, "表单路判定为 Cookie 型登录")
        check(rb.verify_path == "/member",
             "Cookie 型也能找到有区分力的回验页（匿名会话对照）", rb.verify_path)
        check(rb.login_field in ("mail", "username"),
             "登录字段名取自表单真实 input 名", rb.login_field)
        # CSRF 是否真被带回了：FormHandler 对缺 csrf 的 POST 一律 403，
        # 能注册成功即证明隐藏域被带回。
        check(len(FormHandler.users) >= 2,
             "CSRF 隐藏域被原样带回（缺 csrf 的 POST 一律 403）")
        rec = CG._role_record("regself_1", cred_b)
        check(not rec.get("login_success_body"),
             "Cookie 型登录不带 token 判据（交给默认 Cookie 判据）")
        recs = CG.store_account_records(cred_b)
        pool = build_pool(recs, target_url=url_b, profile_key="deep",
                          domain="127.0.0.1", cred_file=cred_b)
        logged = [a for a in pool.accounts if a.get("login_state") == "已登录"]
        check(len(logged) == 2,
             "会话池端到端（Cookie 型）：自动登录 + 回验通过",
             "; ".join(f"{a['name']}:{a.get('login_state')}/{a.get('login_note','')[:40]}"
                       for a in pool.accounts))
    finally:
        srv_b.shutdown()

    # ------------------------------------------------------------------
    print("[4] 失败必须具名（能力缺口，不静默、不换路硬试）")
    class RejectHandler(ApiHandler):
        def do_POST(self):  # noqa: N802
            self._json(403, {"error": "registration disabled"})

    srv_c, url_c = _serve(RejectHandler)
    cred_c = tmpdir / "rej-creds.json"
    try:
        res, notes = regself.run(target_url=url_c, domain="127.0.0.1",
                                 cred_file=cred_c, want=2)
        check(all(not r.ok for r in res) and res,
             "注册被拒 → 未建立身份")
        check(any("能力缺口" in n for n in notes),
             "失败具名进报告（能力缺口措辞）", "; ".join(notes))
        check(not CG.read_roles(cred_c).get("regself_1"),
             "失败身份不写入凭据库")
    finally:
        srv_c.shutdown()

    # ------------------------------------------------------------------
    print("[5] 口令零泄漏 + 代理纪律")
    # 泄漏面 = notes / 结果对象（凭据库文件里有口令是设计使然，不算泄漏）
    leak_blob = json.dumps([notes_a, notes_b,
                            [r.__dict__ for r in res_a if "res_a" in dir()],
                            [r.__dict__ for r in res]],
                           ensure_ascii=False, default=str) if res else ""
    check(not re.search(r"Rs-[A-Za-z0-9_\-]{12,}", leak_blob),
          "notes / 结果对象里不出现口令原文")
    check("password" not in regself.RegResult.__dataclass_fields__,
          "RegResult 数据类没有 password 字段（口令不进结果对象）")
    src = (ROOT / "engine" / "regself.py").read_text(encoding="utf-8")
    check("trust_env = False" in src,
          "run() 的 Session 必须 trust_env=False（环境代理坑，实测 2026-10-09）")
    check("anon.trust_env = False" in src,
          "匿名对照探针必须用全新会话（不继承登录态 Cookie）")
    check("截断" in src,
          "令牌正文不截断的注释存在（截断坑的留痕）")
    check("refund" in src,
          "404/405 存在性探测有退款机制（预算不被探测烧光）")

    # ------------------------------------------------------------------
    print()
    print(f"自测完成：{CHECKS - len(PROBLEMS)}/{CHECKS} 项通过")
    if PROBLEMS:
        print("失败项：")
        for p in PROBLEMS:
            print(f"  ✗ {p}")
        return 1
    print("★ 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
