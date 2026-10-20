#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度验证四项（自测）
====================
2026-10-10 由 Strix 在 Juice Shop 上的实战结果倒逼出来的四项能力：

  ① WSTG-SESS-10 JWT **伪造回验**（原本只做静态结构分析）
  ② WSTG-INPV-20 批量赋值自动对照（原本纯人工指引）
  ③ WSTG-INPV-02 存储型 XSS 受控写 + 读回（原本纯人工指引）
  ④ WSTG-ATHZ-03 水平越权（两个登录态互读对方对象，原本纯人工指引）

钉住的都是**同类坑**——「配了却没人读 / 存在却取不到 / 没测到却说没事」：

  · 伪造回验必须**三路对照**（匿名被挡 / 真令牌可进 / 伪造令牌同样可进），
    少一路就是「疑似」不是「证明」（红线 1：通过只能来自真实执行）。
  · SPA 兜底页对任意路径都返 200 —— 伪造回验必须比对正文与匿名响应不同，
    否则「被接受」是假的（regself 踩过的第一个坑的同型）。
  · 采不到令牌时**不得**判通过 / N/A（红线 49 弱证据 N/A）。
  · 批量赋值必须对照组 vs 实验组，且判据落在**实验组自己的响应**上（红线 20）。
  · 存储型 XSS 只报「原样输出」这个可复现事实，转义过的不许报（反误报）。
  · 水平越权必须三次对照，且正文里出现**对方的身份特征**才成立（红线 19）。

反向对照（漏洞模式 vs 安全模式）必须带牙齿：安全模式下四项**都不许**报。
"""

from __future__ import annotations

import base64
import http.server
import json
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.registry_runner import build_context  # noqa: E402

PROBLEMS: list[str] = []
CHECKS = 0
GROUPS: dict[str, bool] = {}


def check(ok: bool, what: str, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if ok:
        print(f"  ✓ {what}")
    else:
        PROBLEMS.append(what + (f"（{detail}）" if detail else ""))
        print(f"  ✗ {what}" + (f" —— {detail}" if detail else ""))


def grp(tag: str) -> None:
    GROUPS[tag] = True


# ----------------------------------------------------------------------
# 令牌工具
# ----------------------------------------------------------------------
def _b64e(obj: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def _b64d(part: str) -> dict:
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:  # noqa: BLE001
        return {}


def make_token(user_id: int, email: str, alg: str = "RS256", sig: str = "sig") -> str:
    return f"{_b64e({'alg': alg, 'typ': 'JWT'})}.{_b64e({'data': {'id': user_id, 'email': email, 'role': 'customer'}})}.{sig}"


EMAILS = {1: "alice@example.test", 2: "bob@example.test"}
FEEDBACKS: list[str] = []
#: 新建出来的业务对象（id → 对象）。自测里必须能被 DELETE 清掉 ——
#: 清理不掉就等于在「客户库」里留了一堆测试数据，而自测自己看不出来。
BASKETS: dict[int, dict] = {}


def _authed(handler) -> dict:
    """从 Authorization 头解析身份。安全模式按安全实现校验签名与算法。

    模式挂在 handler **类**上而不是模块全局：两个假应用同时在线，
    用全局开关会让「漏洞实现」那一台也按安全实现应答 —— 自测里所有
    「漏洞实现应当命中」的断言会集体变绿变红都不可信（同根因：状态共享）。
    """
    hdr = handler.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        return {}
    parts = hdr[7:].split(".")
    if len(parts) != 3:
        return {}
    header, payload = _b64d(parts[0]), _b64d(parts[1])
    if not payload:
        return {}
    if handler.SECURE:
        # 安全实现：拒绝 alg=none、拒绝空签名（这正是被 Juice Shop 漏掉的两条）
        if str(header.get("alg", "")).lower() == "none":
            return {}
        if not parts[2]:
            return {}
    return payload.get("data") if isinstance(payload.get("data"), dict) else payload


class Handler(http.server.BaseHTTPRequestHandler):
    #: 每台假应用一个模式（漏洞实现 / 安全实现）。必须挂在类上，见 _authed 的说明。
    SECURE = False

    def log_message(self, *a):  # 静音
        pass

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self) -> None:
        self._json(401, {"error": "unauthorized"})

    # ---- 注册（批量赋值靶子）----
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else "{}"
        try:
            data = json.loads(raw)
        except Exception:  # noqa: BLE001
            data = {}
        if self.path.startswith("/api/Users"):
            # 漏洞实现：把客户端给的角色字段原样落库并回显
            # 安全实现：角色只由服务端决定
            role = data.get("role") if (not self.SECURE and "role" in data) else "customer"
            uid = 100 + len(FEEDBACKS)
            return self._json(201, {"status": "success",
                                    "data": {"id": uid, "email": data.get("email"),
                                             "role": role}})
        # ---- 双账号交叉读靶子：/rest/basket 集合（A 建 → B 读）----
        if self.path.startswith("/rest/basket"):
            me = _authed(self)
            if not me:
                return self._deny()
            nid = 900 + len(BASKETS) + 1
            owner = int(me.get("id") or 0)
            BASKETS[nid] = {"id": nid, "owner": owner,
                            "email": me.get("email", ""), "items": ["milk"]}
            return self._json(201, {"status": "success",
                                    "data": dict(BASKETS[nid])})
        if self.path.startswith("/api/Feedbacks"):
            for k in ("comment", "message", "content", "text", "body",
                      "review", "caption", "description"):
                if k in data:
                    FEEDBACKS.append(str(data[k]))
                    break
            return self._json(201, {"status": "success"})
        return self._json(404, {"error": "not found"})

    def do_DELETE(self):  # noqa: N802
        me = _authed(self)
        if self.path.startswith("/rest/basket/"):
            if not me:
                return self._deny()
            try:
                want = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                return self._json(404, {"error": "bad id"})
            BASKETS.pop(want, None)
            return self._json(200, {"status": "success"})
        return self._json(404, {"error": "not found"})

    def do_GET(self):  # noqa: N802
        me = _authed(self)
        if self.path.startswith("/api/me"):
            if not me:
                return self._deny()
            return self._json(200, {"user": me})
        if self.path.startswith("/api/Users"):
            if not me:
                return self._deny()
            return self._json(200, {"data": [{"id": 1, "email": EMAILS[1]}]})
        if self.path.startswith("/api/Feedbacks"):
            if not me:
                return self._deny()
            items = list(FEEDBACKS)
            if self.SECURE:
                items = [i.replace("<", "&lt;").replace(">", "&gt;") for i in items]
            return self._json(200, {"data": items})
        # ---- 水平越权靶子：/rest/basket/<id> ----
        if self.path.startswith("/rest/basket/"):
            if not me:
                return self._deny()
            try:
                want = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                return self._json(404, {"error": "bad id"})
            mine = int(me.get("id") or 0)
            built = BASKETS.get(want)
            if built is not None:
                if self.SECURE and built.get("owner") != mine:
                    return self._json(403, {"error": "forbidden"})
                return self._json(200, {"data": dict(built)})
            if self.SECURE and want != mine:
                # 安全实现：校验归属
                return self._json(403, {"error": "forbidden"})
            return self._json(200, {"data": {"id": want,
                                             "email": EMAILS.get(want, "other@example.test"),
                                             "items": ["milk", "bread"]}})
        return self._json(404, {"error": "not found"})


class VulnHandler(Handler):
    SECURE = False


class SecureHandler(Handler):
    SECURE = True


def start_server(secure: bool) -> tuple[str, socketserver.TCPServer]:
    FEEDBACKS.clear()
    srv = socketserver.ThreadingTCPServer(
        ("127.0.0.1", 0), SecureHandler if secure else VulnHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv


def make_ctx(url: str, accounts: list[dict], allow_write: bool = True,
             js_bodies: list[str] | None = None):
    from engine.fingerprint import HttpProbeClient  # noqa: PLC0415
    client = HttpProbeClient({"rate": {"timeout_seconds": 5,
                                       "requests_per_second": 500}})
    return build_context(
        target_name="深度验证四项自测",
        domain="127.0.0.1",
        target_url=url,
        profile={"_key": "deep", "risk_level": "deep",
                 "write_verification": "controlled"},
        profile_key="deep",
        fp_result={"path_probes": {}},
        js_result={"urls": [], "bodies": list(js_bodies or [])},
        nuclei_findings=[],
        accounts=accounts,
        client=client,
        ledger_write_authorized=allow_write,
    )


A_TOK = make_token(1, EMAILS[1])
B_TOK = make_token(2, EMAILS[2])


def accounts(tok_a: str = A_TOK, tok_b: str = B_TOK) -> list[dict]:
    from engine.sessionpool import LOGIN_OK  # noqa: PLC0415
    return [
        {"name": "alice", "role": "user", "authorized": True,
         "login_state": LOGIN_OK, "headers": {"Authorization": f"Bearer {tok_a}"},
         "cookies": {}, "verify_path": "/api/me"},
        {"name": "bob", "role": "user", "authorized": True,
         "login_state": LOGIN_OK, "headers": {"Authorization": f"Bearer {tok_b}"},
         "cookies": {}, "verify_path": "/api/me"},
    ]


# ======================================================================
def main() -> int:
    print("=" * 70)
    print("深度验证四项自测（伪造回验 / 批量赋值 / 存储型 XSS / 水平越权）")
    print("=" * 70)

    vul_url, vul_srv = start_server(secure=False)
    sec_url, sec_srv = start_server(secure=True)
    print(f"假应用（漏洞实现）：{vul_url}")
    print(f"假应用（安全实现）：{sec_url}\n")

    # ------------------------------------------------------------------
    print("[1] SESS-10 伪造回验：三路对照（匿名被挡 / 真令牌可进 / 伪造可进）")
    grp("sess10")
    from engine.checks.session import sess10  # noqa: PLC0415

    out = sess10(make_ctx(vul_url, accounts()))
    hit = [f for f in (getattr(out, "findings", None) or [])
           if "伪造" in str(getattr(f, "title", ""))]
    check(bool(hit), "漏洞实现：伪造 alg=none 令牌被接受 → 判不通过",
          str(getattr(out, "note", ""))[:80])
    if hit:
        check(getattr(hit[0], "severity", "") == "严重",
              "漏洞实现：定级为严重", getattr(hit[0], "severity", ""))
    out_sec = sess10(make_ctx(sec_url, accounts()))
    hit_sec = [f for f in (getattr(out_sec, "findings", None) or [])
               if "伪造" in str(getattr(f, "title", ""))]
    check(not hit_sec, "安全实现：伪造令牌被拒 → 不报", str(getattr(out_sec, "note", ""))[:80])
    check("拒绝" in str(getattr(out_sec, "note", "")),
          "安全实现：结论里写明「服务端全部拒绝」（不是静默无发现）",
          str(getattr(out_sec, "note", ""))[:80])

    print("\n[2] SESS-10 反向：采不到令牌不得判通过 / N/A")
    grp("sess10_weak")
    out_no = sess10(make_ctx(vul_url, []))
    check(bool(getattr(out_no, "pending", False))
          and not getattr(out_no, "not_applicable", False),
          "无令牌时判「待确认」（不得是 通过 / N/A）",
          f"pending={getattr(out_no,'pending',None)} na={getattr(out_no,'not_applicable',None)}")
    check("未做伪造回验" in str(getattr(out_no, "note", "")),
          "无令牌时结论写明「未做伪造回验」", str(getattr(out_no, "note", ""))[:80])
    out_ck = sess10(make_ctx(sec_url, [
        {"name": "c", "authorized": True, "login_state": "已登录",
         "headers": {}, "cookies": {"PHPSESSID": "abc123"}, "rejected": ""}]))
    check(bool(getattr(out_ck, "not_applicable", False)),
          "纯 Cookie 会话且无 JWT → 判 N/A（本项确实不适用）",
          f"na={getattr(out_ck,'not_applicable',None)} note={str(getattr(out_ck,'note',''))[:60]}")

    # ------------------------------------------------------------------
    print("\n[3] INPV-20 批量赋值：对照组 vs 带特权字段组")
    grp("inpv20")
    from engine.checks.injection import recon_inpv20  # noqa: PLC0415

    r20 = recon_inpv20(make_ctx(vul_url, accounts()))
    check(getattr(r20, "ran", False), "侦察真的跑了", str(getattr(r20, "error", ""))[:60])
    check(bool(getattr(r20, "findings", None)),
          "漏洞实现：实验组 role=admin 被回显 → 确证", str(getattr(r20, "note", ""))[:80])
    r20s = recon_inpv20(make_ctx(sec_url, accounts()))
    check(not getattr(r20s, "findings", None),
          "安全实现：角色由服务端决定 → 不报", str(getattr(r20s, "note", ""))[:80])
    r20n = recon_inpv20(make_ctx(vul_url, accounts(), allow_write=False))
    check(not getattr(r20n, "ran", True) and "授权" in str(getattr(r20n, "error", "")),
          "台账未授权写 → 不执行且写明原因", str(getattr(r20n, "error", ""))[:60])

    # ------------------------------------------------------------------
    print("\n[4] INPV-02 存储型 XSS：受控提交 + 读回 + 编码比对")
    grp("inpv02")
    from engine.checks.injection import recon_inpv02  # noqa: PLC0415

    r02 = recon_inpv02(make_ctx(vul_url, accounts()))
    check(getattr(r02, "ran", False), "侦察真的跑了", str(getattr(r02, "error", ""))[:60])
    check(bool(getattr(r02, "findings", None)),
          "漏洞实现：读回原样输出 → 确证存储型 XSS", str(getattr(r02, "note", ""))[:80])
    r02s = recon_inpv02(make_ctx(sec_url, accounts()))
    check(not getattr(r02s, "findings", None),
          "安全实现：读回已转义 → 不报", str(getattr(r02s, "note", ""))[:80])
    r02n = recon_inpv02(make_ctx(vul_url, [], allow_write=True))
    check(not getattr(r02n, "ran", True) and "登录态" in str(getattr(r02n, "error", "")),
          "无已确认登录态 → 不执行且写明原因", str(getattr(r02n, "error", ""))[:60])

    # ------------------------------------------------------------------
    print("\n[5] ATHZ-03 水平越权：A 读自己 / B 读自己 / B 读 A")
    grp("athz03")
    from engine import recon_identity as ri  # noqa: PLC0415

    _hp = [0]
    f_v, l_v = ri._horizontal_idor(make_ctx(vul_url, accounts()), accounts(), _hp)
    check(bool(f_v), "漏洞实现：B 读到 A 的购物车（正文含 A 的邮箱）→ 确证",
          "；".join(l_v[:2])[:100])
    _hp2 = [0]
    f_s, l_s = ri._horizontal_idor(make_ctx(sec_url, accounts()), accounts(), _hp2)
    check(not f_s, "安全实现：归属校验生效 → 不报", "；".join(l_s[:2])[:100])
    # 反误报：B 与 A 返回完全相同（SPA 兜底）不得当证据
    orig = ri._ident_fetch
    try:
        def _spa(url, account=None, ctx=None):
            return {"status": 200, "body": "<html>SPA</html>" * 20, "err": "",
                    "denied": False, "bounced": False}
        ri._ident_fetch = _spa
        _hp3 = [0]
        f_spa, l_spa = ri._horizontal_idor(make_ctx(vul_url, accounts()),
                                           accounts(), _hp3)
        check(not f_spa, "反误报：所有请求返回同一兜底页 → 不作判据",
              "；".join(l_spa[:1])[:80])
    finally:
        ri._ident_fetch = orig
    # 反向钉住 2026-10-10 修掉的坑：垂直越权那套「管理端点候选」一个都定位不到时，
    # 函数在垂直分支提前返回，水平越权**整段被吃掉** —— 报告上却写着
    # 「水平越权属人工范畴」（红线 14：未实现的路径不得静默跳过）。
    # 现在两段各自独立：垂直没有基线，水平照样要跑完。
    r3 = ri.recon_athz03(make_ctx(vul_url, accounts()))
    check(bool(getattr(r3, "findings", None)),
          "垂直越权无候选端点时，水平越权仍独立跑完并确证",
          f"ran={getattr(r3,'ran',None)} err={str(getattr(r3,'error',''))[:70]}")

    # ------------------------------------------------------------------
    # [6] ATHZ-04 登录态双账号交叉读：A 建对象 → B 读它 → 匿名读它（对照）
    #
    # 这一组守的是「越权只测匿名分支」这个覆盖面缺口：真实系统的漏洞
    # 恰恰出在「登录了但没校验归属」那一层，而那一层过去全挂人工。
    # 三条判据都必须带牙齿：漏洞实现要确证、安全实现不许报、
    # **匿名对照必须参与判定**（B 与匿名都读得到是「未授权访问」，
    # 不是「归属校验缺失」，混报会让修复方向跑偏 —— 红线 9）。
    print("\n[6] ATHZ-04 登录态双账号交叉读（A 建 → B 读 → 匿名对照）")
    grp("athz04_cross")
    from engine.checks.authz import _recon_cross_object_read  # noqa: PLC0415

    _BODIES = ['var C="/rest/basket";']
    tried_v: list[str] = []
    BASKETS.clear()
    cf_v, cp_v = _recon_cross_object_read(
        make_ctx(vul_url, accounts(), js_bodies=_BODIES), accounts(), tried_v)
    check(bool(cf_v), "漏洞实现：B 读到 A 新建的对象 → 确证归属校验缺失",
          "；".join(tried_v[:3])[:110])
    check(cp_v >= 3, "三条请求都真的发了（A 建 / B 读 / 匿名对照）", f"probes={cp_v}")
    check(not BASKETS, "受控写已清理（新建的对象被删掉了）", f"残留={list(BASKETS)}")

    BASKETS.clear()
    tried_s: list[str] = []
    cf_s, _cp_s = _recon_cross_object_read(
        make_ctx(sec_url, accounts(), js_bodies=_BODIES), accounts(), tried_s)
    check(not cf_s, "安全实现：B 读他人对象被 403 挡住 → 不报",
          "；".join(tried_s[:3])[:110])

    # 只有 1 组账号时**不许**硬报：一个人跟自己比对不出归属
    tried_one: list[str] = []
    cf_one, _cp_one = _recon_cross_object_read(
        make_ctx(vul_url, accounts()[:1], js_bodies=_BODIES),
        accounts()[:1], tried_one)
    check(not cf_one, "只有 1 组登录态时不产出结论（不编造）",
          "；".join(tried_one[:2])[:80])
    # 台账未授权写 → 不执行且写明原因
    tried_nw: list[str] = []
    cf_nw, _cp_nw = _recon_cross_object_read(
        make_ctx(vul_url, accounts(), allow_write=False, js_bodies=_BODIES),
        accounts(), tried_nw)
    check(not cf_nw and any("受控写未放行" in t for t in tried_nw),
          "台账未授权写 → 不执行且写明原因", "；".join(tried_nw[:2])[:80])

    vul_srv.shutdown()
    sec_srv.shutdown()

    print("\n" + "=" * 70)
    ran = [k for k in GROUPS if GROUPS[k]]
    print(f"自测组：{len(ran)} 组（{'、'.join(ran)}）")
    print(f"断言：{CHECKS} 条，失败 {len(PROBLEMS)} 条")
    if PROBLEMS:
        print("\n失败项：")
        for p in PROBLEMS:
            print(f"  · {p}")
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
