# -*- coding: utf-8 -*-
"""黑客视角凭据获取的端到端自测（本地假站，零外网）。

为什么必须有这一环
----------------------------------------------------------------------------
「默认口令可登录」是红队最值钱的一类发现，而它最容易在交付环节**静默消失**：
  ① 复现模板选错（选成 param_replay）→ 没有可注入参数 → 判「未复现」
     → 被准入闸门踢出漏洞清单，报告上只剩一句「未复现」；
  ② 生成的脚本语法错误 / 依赖缺失 → 退出码 2「无法判定」→ 同样进不了清单；
  ③ 命中口令被当成目标特有凭据写进留痕 → 报告本身成了新的泄露源。

本自测用本地假登录站把链路整条打通：hunt（零凭据试出默认口令）
→ grade_findings（产出绑定 WSTG-ATHN-02 的发现）
→ ScriptBuilder（生成可独立执行的复现脚本）
→ 真跑一遍该脚本（断言退出码 0，且留痕中无口令原文）。

另附一条**源码级**不变量：红队模式下不得挂起等待凭据
（`cred_wait_explicit` 门控必须存在于 orchestrator 的等待条件里）——
这条守的是「扫描跑到一半睡 30 分钟」那个真实故障，行为级验证需要起真进程，
成本高于收益，所以用源码断言兜住回归。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

# 自测必须与操作员的 shell 无关：AISCAN_CREDHUNT=off 是给运维用的总开关，
# 如果它恰好留在环境里，这一环会「因为没试所以没命中」而红 —— 那是环境问题
# 冒充代码问题，排查方向会被彻底带偏。显式清掉，让判据只取决于代码本身。
for _k in ("AISCAN_CREDHUNT", "AISCAN_CRED_WAIT", "AISCAN_PROGRESS"):
    os.environ.pop(_k, None)

from engine import credhunt  # noqa: E402
from verify.framework import ScriptBuilder  # noqa: E402
from verify.repro_templates import build_plan  # noqa: E402

STATE = {"posts": 0}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: ANN002
        pass

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/login") or self.path == "/":
            body = ('<html><form action="/api/login" method="post">'
                    '<input name="username"><input type="password" name="pwd">'
                    '</form></html>')
            self._send(200, body, {})
        else:
            self._send(404, "nf", {})

    def do_POST(self):  # noqa: N802
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace")
        from urllib.parse import parse_qs
        q = parse_qs(raw)
        u = (q.get("username") or [""])[0]
        p = (q.get("pwd") or [""])[0]
        STATE["posts"] += 1
        if self.path == "/api/redirect_only":
            # 只回一个**相对路径**跳转、不给任何 Cookie。
            # 这是真实站点最常见的一种成功形态（会话 Cookie 落在跳转目标上，
            # 或者令牌直接带在 URL 里），也是「漏报弱口令」最容易发生的地方：
            # 判据里要比主机名，而相对路径 urlparse 出来的 netloc 是空串。
            if u == "admin" and p == "admin123":
                self._send(302, "", {"Location": "/home"})
            else:
                self._send(302, "", {"Location": "/login?err=1"})
            return
        if u == "admin" and p == "admin123":
            self._send(302, "", {"Location": "/home", "Set-Cookie": "SESSION=x1; Path=/"})
        else:
            self._send(200, "用户名或密码错误", {})

    def _send(self, st, body, extra):
        data = body.encode("utf-8")
        self.send_response(st)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


class _Client:
    def fetch(self, url, **kw):  # noqa: ANN003
        import requests

        class P:
            pass

        pr = P()
        try:
            r = requests.get(url, timeout=5)
            pr.status, pr.body_snippet = r.status_code, r.text[:4000]
        except Exception as e:  # noqa: BLE001
            pr.status, pr.body_snippet, pr.error = 0, "", str(e)
        return pr


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    prof = {"credential_hunt": {"enabled": True, "max_attempts": 6,
                                "min_gap_seconds": 0.01}}
    res = credhunt.hunt(_Client(), base, profile=prof, profile_key="standard",
                        path_probes={})
    assert res.found, "假站上应命中 admin/admin123"
    findings = credhunt.grade_findings(res, "自测目标")
    assert findings, "命中必须产出发现"
    print("① 命中与发现产出：OK")

    plan = build_plan(findings[0], base)
    print(f"② 复现计划 kind = {plan.kind}（期望 weak_login）")
    assert plan.kind == "weak_login", "复现模板类型错了"

    with tempfile.TemporaryDirectory() as td:
        paths = ScriptBuilder(td).generate_all(findings, base)
        assert paths, "应生成至少一份复现脚本"
        script = paths[0]
        body = script.read_text(encoding="utf-8")
        print(f"③ 脚本已生成：{script.name}（{len(body)} 字节），开始独立执行 …")
        print(f"   强度标注 = {findings[0].extra.get('verify_strength')}，"
              f"repro_kind = {findings[0].extra.get('repro_kind')}")
        print("-" * 70)
        p = subprocess.run([sys.executable, str(script), "--target", base],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=180)
        print(p.stdout)
        if p.stderr.strip():
            print("[stderr]", p.stderr[:800])
        print("-" * 70)
        print(f"   退出码 = {p.returncode}（0=已复现，1=未复现，2=无法判定）")

        ok = True
        if p.returncode != 0:
            print("   ✗ 复现脚本未能复现（真实存在的弱口令被判未复现）")
            ok = False
        if "口令原文" not in (p.stdout or "") and "命中账号" not in (p.stdout or ""):
            print("   ✗ 脚本输出未给出可读的复现证据")
            ok = False
        # 说明：脚本正文里**允许**出现字典项（那是一份公开的教科书级默认口令表，
        # 与 nuclei 的 default-login 模板同理）；不允许的是「命中口令被当作
        # 目标特有凭据写进留痕」—— 留痕里只有散列指纹。
        dump = json.dumps(res.to_dict(), ensure_ascii=False)
        for secret in ("admin123", "P@ssw0rd"):
            if secret in dump:
                print(f"   ✗ 扫描留痕中出现口令原文：{secret}")
                ok = False

    # ---- 相对路径跳转也要能判成「疑似成功」 ----
    # 这一条守的是一次真实的漏报：判据里要比较跳转目标的主机名，而站点普遍
    # 回的是相对路径（`Location: /home`），urlparse("/home").netloc 是空串 ——
    # 于是「跳转到登录页之外 = 登录成功」这条分支永远不成立（死代码），
    # 一个真的能登进去的默认口令被判成「认证失败」。
    # 这类漏报的代价最高：命中了却报没命中，报告上只剩一句「未发现弱口令」，
    # 而且**没有任何报错**能提示判据已经失效。
    print("④ 相对路径跳转（Location: /home，无 Cookie）的判定")
    st, hdr, bd, fin, err = credhunt._post_login(
        f"{base}/api/redirect_only", "username", "pwd", "admin", "admin123")
    outcome, note = credhunt._classify(st, hdr, bd, fin, base)
    print(f"   跳转目标解析为 {fin!r} → 判定 {outcome}（{note}）")
    if outcome != "疑似成功":
        print("   ✗ 只回相对路径跳转的成功登录被判成「认证失败」—— "
              "判据依赖主机名比较，相对路径必须先 urljoin 成绝对地址")
        ok = False
    if not str(fin).startswith("http"):
        print("   ✗ 跳转目标未解析成绝对地址（下游判据比不出主机名）")
        ok = False
    # 反向：失败时跳到登录页本身（/login?err=1）不得被判成成功 ——
    # 否则上面那条修复会把「跳回登录页」这种最常见的失败形态误判为命中。
    st2, hdr2, bd2, fin2, _e2 = credhunt._post_login(
        f"{base}/api/redirect_only", "username", "pwd", "admin", "wrong")
    outcome2, _n2 = credhunt._classify(st2, hdr2, bd2, fin2, base)
    print(f"   失败（跳回 /login）→ 判定 {outcome2}")
    if outcome2 == "疑似成功":
        print("   ✗ 跳回登录页被判成「疑似成功」—— 归一化之后必须仍能排除它")
        ok = False
    srv.shutdown()

    # ---- 目标账号形态：邮箱形态必须覆盖 ----
    # 这一条守的是一次真实的漏报：默认口令字典里只有裸用户名（admin/test），
    # 而账号字段是**邮箱**的系统上整片落空（实测 Juice Shop v20：
    # `admin`/`admin123` 打不动，真正能登的是 `admin@juice-sh.op`，
    # 而域名就写在打包产物里）。只试裸名 = 把「账号形态」这一维整个放弃。
    # 同时必须钉住另一头：**不得拿真实用户做口令喷射** —— 候选里
    # 只允许出现通用账号名，不许出现从产物里抓到的真实邮箱。
    print("⑥ 目标账号形态候选（邮箱形态覆盖 + 不喷射真实用户）")
    from engine.checks.base import target_account_candidates

    class _S:
        def __init__(self, bodies, domain="shop.example.org"):
            self.js_result = {"bodies": bodies, "inline_scripts": [], "urls": []}
            self._cache = {}
            self.target_url = "http://" + domain
            self.domain = domain

    bundle = ("var A=`${host}/rest/languages`;"
              "var B='testing@juice-sh.op';"
              "var C='someone@github.com';"
              "var D=`/api/Users/${id}`;")
    cands = target_account_candidates(_S([bundle]), limit=8)
    print("   候选：" + "、".join(cands))
    ok6 = True
    if "admin@juice-sh.op" not in cands:
        print("   ✗ 未从打包产物的邮箱域名推出 admin@juice-sh.op")
        ok6 = False
    if any("github.com" in c for c in cands):
        print("   ✗ 第三方域名被当成目标域名（会拼出一堆不存在的账号）")
        ok6 = False
    if any("testing@juice-sh.op" in c or "someone@" in c for c in cands):
        print("   ✗ 候选里出现产物中的真实邮箱 —— 这是口令喷射，不是默认口令核查")
        ok6 = False
    if "admin@shop.example.org" not in cands:
        print("   ✗ 目标主机名自身的域名未参与拼账号")
        ok6 = False
    if not ok6:
        ok = False

    # ---- 提交地址：相对路径必须被补全，不许静默失败 ----
    # 这是第 23 轮实测出来的**假「未命中」**：登录提交地址来自前端推断的
    # `api_hint`，形如 `/rest/user/login`。requests 拿到相对路径抛
    # MissingSchema，被 except 吞成 `{"status": 0}` ——
    # 12 次默认口令尝试**一次都没发出**，而报告写「尝试 12 组，未命中」。
    # 读者（和被扫方）都会读成「系统没有弱口令」。
    print("⑦ 提交地址相对路径补全（不许把「没发出」当成「口令不对」）")
    from engine.registry import DetectorContext

    _ctx = DetectorContext.__new__(DetectorContext)
    _ctx.target_url = "http://127.0.0.1:3000"
    ok7 = True
    _cases = {
        "/rest/user/login": "http://127.0.0.1:3000/rest/user/login",
        "rest/user/login": "http://127.0.0.1:3000/rest/user/login",
        "http://x.y/login": "http://x.y/login",
        "https://x.y/login": "https://x.y/login",
    }
    for src, want in _cases.items():
        got = _ctx._abs_url(src)
        if got != want:
            print(f"   ✗ {src} → {got}（期望 {want}）")
            ok7 = False
    if not ok7:
        ok = False
    else:
        print("   相对/绝对四种形态均正确归一")

    # ---- 源码级不变量：红队默认不得挂起等凭据 ----
    src = (ROOT / "engine" / "orchestrator.py").read_text(encoding="utf-8")
    ok_src = True
    if "cred_wait_explicit" not in src:
        print("   ✗ orchestrator 缺少 cred_wait_explicit 门控 —— "
              "红队默认会退回「挂起等凭据」")
        ok_src = False
    if re.search(r"if \(_need_p and not boundary_blocked and _wait_s > 0\s*\):",
                 src):
        print("   ✗ 凭据等待条件回到「只要 _wait_s > 0 就等」—— "
              "默认值又会把扫描挂住 30 分钟")
        ok_src = False
    if not ok_src:
        ok = False
    else:
        print("⑤ 红队不挂起等凭据（源码门控）：OK")

    print("\n结论：" + ("全部通过" if ok else "存在问题，需修"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
