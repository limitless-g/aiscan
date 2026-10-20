# -*- coding: utf-8 -*-
"""
WSTG-ERRH 错误处理（2 项）+ WSTG-CRYP 弱加密（4 项）
====================================================
错误处理的关键判断是：**报错本身不是漏洞，但报错内容泄露了什么才是问题。**
只暴露「系统繁忙」不算问题；把堆栈、SQL 语句、文件绝对路径吐出来就是问题。

加密类的可自动化部分是「事实采集」：支持哪些 TLS 版本、用了什么加密套件、
前端是否用了已被攻破的算法。Padding Oracle 必须人工做。
"""

from __future__ import annotations

import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

from engine.checks.base import (
    STACK_TRACE_PATTERNS, code_scan, extract_params, finding_evidence, is_real_hit,
    ok, found, probe_or_none, scan_paths, WEAK_CRYPTO_PATTERNS,
    no_target_outcome,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)
from engine import recon_identity as recon_id

# 触发错误的输入
ERROR_TRIGGERS = [
    ("'", "单引号"),
    ("%00", "空字节"),
    ("[", "未闭合括号"),
    ("{{", "模板起始符"),
    ("-1", "负数值"),
    ("999999999999999999999", "超长数字"),
    ("aiscan_9z8y7x", "随机串"),
]

# 详细报错页特征（不含堆栈，属于「错误处理不当」而非「堆栈泄露」）
VERBOSE_ERROR_MARKERS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"ORA-\d{5}",
    r"Microsoft OLE DB Provider", r"System\.Data\.SqlClient",
    r"org\.springframework\.\w+Exception", r"javax\.servlet\.ServletException",
    r"java\.lang\.\w+Exception", r"at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.java:\d+\)",
    r"Traceback \(most recent call last\)", r"Fatal error:\s+Uncaught",
    r"Warning:\s+\w+\(\)\s+\[function\.", r"Microsoft OLE DB",
    r"in /var/www/", r"in /home/\w+/", r"C:\\\\inetpub", r"C:\\\\wwwroot",
    r"DEBUG\s*=\s*True", r"DisallowedHost at", r"Symfony\\Component",
    r"whoops\\Exception", r"ActionController::", r"Rails\.root",
    r"Stack trace:", r"at Object\.<anonymous>", r"node_modules/",
    # 2026-10-10 补：Node 生态的原生错误形态（此前全是 Java/PHP/Django
    # 包装形态，Node 应用的报错一概不认 —— 第十轮 ERRH-01 判「未发现
    # 详细报错」而目标真实返回 SQLITE_ERROR，正是这个盲区）。
    r"SQLITE_[A-Z_]*ERROR", r"SequelizeDatabaseError",
    r"Sequelize\w*Error", r"PrismaClient\w+Error", r"MongoError",
    r"MongooseError", r"CastError", r"ValidationError.*is not valid",
]


def _probe_error_responses(ctx: DetectorContext, max_params: int = 8):
    """用异常输入触发错误，返回 (命中列表, 探测次数)。"""
    params = extract_params(ctx)
    targets = []
    for p in params[:max_params]:
        if p["url"].startswith("http") and ctx.domain in p["url"]:
            targets.append((p["url"], p["param"]))
    # 再补一个不存在的深层路径，很多框架在这里暴露调试页
    probes = 0
    results = []
    for url, pname in targets:
        parsed = urlparse(url)
        from urllib.parse import parse_qs, urlencode
        qs = parse_qs(parsed.query, keep_blank_values=True)
        try:
            base = ctx.get(url)
            base_body = getattr(base, "body_snippet", "") or ""
        except Exception:  # noqa: BLE001
            continue
        for trig, tname in ERROR_TRIGGERS[:4]:
            qs[pname] = [trig]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
            probes += 1
            try:
                pr = ctx.get(test_url)
            except Exception:  # noqa: BLE001
                continue
            body = getattr(pr, "body_snippet", "") or ""
            st = getattr(pr, "status", 0)
            if not body:
                continue
            results.append((url, pname, tname, test_url, st, body, base_body))

    # ---------- POST JSON 错误触发 ----------
    # 现代应用的报错大多在 **POST body** 的类型混淆上（`{"email":"'"}` 触发
    # SQL 拼接错误、`{"id":{"$ne":null}}` 触发 ORM 类型错误），GET 参数触发
    # 在 API 型目标上经常一无所获 —— 2026-10-10 第十轮实测，ERRH-01 对
    # 32 组 GET 输入报「未发现详细报错」，而目标 POST /rest/user/login
    # 用一个引号就返回带完整堆栈的 500。
    # 纪律：只对「本来就接受用户提交」的认证 / 查询端点做；载荷只有一个
    # 无害引号；走 data_submit 共享预算（上限 4），全部留痕。
    if ctx.risk_allowed(RISK_DEEP):
        post_targets: list[str] = []
        for u in (ctx.js_result.get("urls") or []):
            if not isinstance(u, str) or not u.startswith("http"):
                continue
            ul = u.lower()
            if ctx.domain in u and re.search(
                    r"(login|auth|search|register|feedback|order|reset)",
                    ul) and u not in post_targets:
                post_targets.append(u.split("#")[0])
        for url in post_targets[:2]:
            base_field = "email" if re.search(r"(login|auth|reset|register)",
                                              url, re.I) else "q"
            try:
                r = ctx.data_submit(url, {base_field: "'--"}, method="POST",
                                    as_json=True,
                                    budget_key="errh01_post_trigger",
                                    max_total=4)
            except PermissionError:
                break
            except Exception:  # noqa: BLE001
                continue
            probes += 1
            body = str(r.get("body") or "")
            st = int(r.get("status") or 0)
            if body:
                results.append((url, base_field, "POST 类型混淆",
                                url, st, body, ""))
    return results, probes


# ======================================================================
# WSTG-ERRH-01 错误处理不当
# ======================================================================
@make_auto("WSTG-ERRH-01", name="错误信息泄露检测", tool="异常输入触发",
           risk=RISK_STANDARD, evidence_kind="错误响应实测",
           detector_ref="checks/error_crypto.py:errh01")
def errh01(ctx: DetectorContext):
    results, probes = _probe_error_responses(ctx)
    if not results:
        return no_target_outcome(ctx, "可触发错误响应的入口", probes=2, evidence_kind="无候选参数")

    findings = []
    leaks = []
    for url, pname, tname, test_url, st, body, base_body in results:
        for mk in VERBOSE_ERROR_MARKERS:
            if re.search(mk, body, re.I) and not re.search(mk, base_body, re.I):
                # 区分「堆栈泄露」与「一般详细报错」
                is_trace = any(re.search(tp, body, re.I) for tp in STACK_TRACE_PATTERNS)
                leaks.append((url, pname, tname, st, mk, is_trace, body[:400]))
                break
        if leaks:
            break

    if leaks:
        url, pname, tname, st, mk, is_trace, frag = leaks[0]
        findings.append(make_finding(
            "WSTG-ERRH-01", "服务端返回详细错误信息，暴露内部实现细节",
            ctx.target_name, endpoint=url, method="GET", param=pname,
            severity="中危", confidence="High", evidence_level="A",
            description=("提交异常输入后，服务端返回了包含技术细节的错误信息，"
                         "而不是统一的用户友好提示。这类信息对攻击者是免费的情报。"),
            technical_detail=(f"触发输入类型：{tname}\n"
                              f"响应状态：HTTP {st}\n"
                              f"命中的敏感错误特征：{mk}\n"
                              f"响应片段（已脱敏）：\n{frag}"),
            impact=("报错信息帮助攻击者确认技术栈与版本、推断后端语句结构、"
                    "定位文件路径，从而把「盲目尝试」变成「精确构造」。"
                    "这是注入、文件包含等漏洞的前置放大器。"),
            reproduction=f"curl -s '{url}'  # 将 {pname} 替换为异常输入（如单引号）",
            remediation=("① 生产环境关闭调试模式（Spring：`debug=false`；"
                         "Django：`DEBUG=False`；Node：`NODE_ENV=production`）；"
                         "② 配置统一异常处理，对外只返回错误码与通用文案，"
                         "详细堆栈只写服务端日志；"
                         "③ 关闭不必要的框架默认错误页（如 Spring Whitelabel 页需自定义）。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-209",
            evidence=[finding_evidence("response", frag, f"错误响应（{tname} 触发）")],
            grading_basis="实测返回含技术细节的错误信息，为后续攻击提供情报，定中危",
        ))

    note = (f"对 {len(results)} 组输入触发错误，探测 {probes} 次，"
            f"{'命中详细报错' if findings else '未发现详细报错（错误处理规范）'}")
    return found(note, findings, probes=probes, evidence_kind="错误响应实测")


# ======================================================================
# WSTG-ERRH-02 堆栈跟踪泄露
# ======================================================================
@make_auto("WSTG-ERRH-02", name="堆栈跟踪泄露检测", tool="异常输入触发",
           risk=RISK_STANDARD, evidence_kind="堆栈响应实测",
           detector_ref="checks/error_crypto.py:errh02")
def errh02(ctx: DetectorContext):
    results, probes = _probe_error_responses(ctx)
    traces = []

    # 补充：直接访问不存在的深层路径，观察是否有调试页
    probes += 1
    try:
        pr = ctx.get(urljoin(ctx.target_url, "aiscan-nonexistent-9z8y7x/deep/path"))
        body = getattr(pr, "body_snippet", "") or ""
        if body:
            for pat in STACK_TRACE_PATTERNS:
                if re.search(pat, body, re.I):
                    traces.append((urljoin(ctx.target_url, "aiscan-nonexistent-9z8y7x/deep/path"),
                                   "不存在的路径", getattr(pr, "status", 0), pat, body[:600]))
                    break
    except Exception:  # noqa: BLE001
        pass

    for url, pname, tname, test_url, st, body, base_body in results:
        for pat in STACK_TRACE_PATTERNS:
            if re.search(pat, body, re.I) and not re.search(pat, base_body, re.I):
                traces.append((test_url, f"参数 {pname}（{tname}）", st, pat, body[:600]))
                break
        if traces:
            break

    findings = []
    if traces:
        endpoint, trigger, st, pat, frag = traces[0]
        findings.append(make_finding(
            "WSTG-ERRH-02", "异常响应中泄露完整调用栈",
            ctx.target_name, endpoint=endpoint, method="GET",
            severity="中危", confidence="High", evidence_level="A",
            description=("服务端在出错时把完整的调用栈返回给了浏览器。"
                         "调用栈里包含类名、方法名、文件绝对路径与行号，"
                         "等于把代码结构摊开给攻击者看。"),
            technical_detail=(f"触发方式：{trigger}\n"
                              f"响应状态：HTTP {st}\n"
                              f"命中的堆栈特征：{pat}\n"
                              f"响应片段（已脱敏）：\n{frag}"),
            impact=("调用栈直接暴露：框架与版本（可查已知 CVE）、"
                    "内部包结构与业务类名（可推断功能模块）、"
                    "服务器绝对路径（可辅助文件包含与日志投毒）、"
                    "数据库驱动与连接方式。这些信息能显著缩短攻击者的试错过程。"),
            reproduction=f"curl -s '{endpoint}' | head -50",
            remediation=("① 生产环境关闭调试输出（框架 debug / dev 模式必须关闭）；"
                         "② 自定义全局异常处理器，统一返回错误码 + 通用文案；"
                         "③ 堆栈只写服务端日志（日志本身也要注意不落敏感数据）；"
                         "④ 部署时剔除源码中的调试开关与开发依赖。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-209",
            evidence=[finding_evidence("response", frag, "堆栈响应片段")],
            grading_basis="实测响应含完整调用栈，泄露内部结构，定中危",
        ))

    note = (f"共探测 {probes} 次（参数触发 + 深层路径），"
            f"{'发现堆栈泄露' if findings else '未发现堆栈泄露'}")
    return found(note, findings, probes=probes, evidence_kind="堆栈响应实测")


# ======================================================================
# WSTG-CRYP-01 弱传输层安全
# ======================================================================
@make_auto("WSTG-CRYP-01", name="TLS 版本与加密套件核查", tool="SSL 套件实测",
           risk=RISK_SAFE, evidence_kind="TLS 握手实测",
           detector_ref="checks/error_crypto.py:cryp01",
           # TLS 握手在 HTTP 层之下；边界封禁是 HTTP 层策略，握手照常完成。
           needs_app=False)
def cryp01(ctx: DetectorContext):
    parsed = urlparse(ctx.target_url)
    if parsed.scheme != "https":
        return ok("目标未使用 HTTPS，TLS 检查不适用（该情况已在 CRYP-03 中覆盖）",
                  probes=1, evidence_kind="协议判定")

    host = parsed.hostname or ctx.domain
    port = parsed.port or 443

    results: dict[str, str] = {}
    probes = 0
    for name, ver in (("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                      ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
                      ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
                      ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None))):
        if ver is None:
            continue
        probes += 1
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = ver
            c.maximum_version = ver
            with socket.create_connection((host, port), timeout=8) as sock:
                with c.wrap_socket(sock, server_hostname=host) as ss:
                    results[name] = ss.version() or "已协商"
        except Exception as e:  # noqa: BLE001
            results[name] = f"不支持（{type(e).__name__}）"

    weak = [n for n in ("TLSv1.0", "TLSv1.1") if results.get(n, "").startswith(("TLSv", "已协商"))]
    findings = []
    if weak:
        findings.append(make_finding(
            "WSTG-CRYP-01", f"服务端仍支持已废弃的 TLS 版本（{'、'.join(weak)}）",
            ctx.target_name, endpoint=f"{host}:{port}",
            severity="中危", confidence="High", evidence_level="A",
            description=(f"服务端允许使用 {'、'.join(weak)} 建立连接。"
                         "这些协议版本已被 IETF 废弃，存在已知的降级与解密攻击方式。"),
            technical_detail="各版本握手结果：\n" + "\n".join(
                f"  {k}  →  {v}" for k, v in results.items()),
            impact=("支持旧版本意味着攻击者可强制把连接降级到弱协议，"
                    "配合中间人位置可解密或篡改传输内容。"
                    "在合规审计（等保 / PCI-DSS）中这属于必查项。"),
            reproduction=f"nmap --script ssl-enum-ciphers -p {port} {host}\n"
                         f"# 或：openssl s_client -connect {host}:{port} -tls1",
            remediation=("① 仅允许 TLS 1.2 与 1.3；"
                         "Nginx：`ssl_protocols TLSv1.2 TLSv1.3;`；"
                         "② 加密套件限制为前向保密套件（ECDHE + AES-GCM / ChaCha20）；"
                         "③ 关闭压缩与重协商，启用 OCSP Stapling；"
                         "④ 变更后重新扫描确认旧版本已不可用。"),
            compliance="等保2.0 安全通信网络-通信传输 / PCI-DSS 4.1",
            evidence=[finding_evidence("tls", str(results), "TLS 版本握手结果")],
            grading_basis="实测旧协议版本可用，定中危",
        ))

    tls_info = ctx.tls
    if tls_info.get("not_after"):
        findings.append(make_finding(
            "WSTG-CRYP-01", "证书有效期与信息核查（信息项）",
            ctx.target_name, endpoint=f"{host}:{port}",
            severity="信息", confidence="High", evidence_level="A",
            description="记录当前证书的签发者与到期时间，用于证书到期管控。",
            technical_detail=(f"签发者：{tls_info.get('issuer', {})}\n"
                              f"到期时间：{tls_info.get('not_after', '')}\n"
                              f"当前套件：{tls_info.get('cipher', '')}\n"
                              f"覆盖域名数：{len(tls_info.get('alt_names', []) or [])}"),
            impact="证书过期会导致浏览器告警与业务中断，属运维管控项。",
            reproduction=f"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer",
            remediation="建立证书到期提醒（建议提前 30 天），并统一管理证书续期。",
            compliance="ISO 27001 A.8.24",
            evidence=[finding_evidence("tls", str(tls_info)[:800], "证书信息")],
            grading_basis="信息记录项，不计入风险",
        ))

    note = (f"TLS 版本支持情况：" + "、".join(f"{k}={'是' if v.startswith(('TLSv','已协商')) else '否'}"
                                            for k, v in results.items()))
    return found(note, findings, probes=probes, evidence_kind="TLS 握手实测")


# ======================================================================
# WSTG-CRYP-02 Padding Oracle
# ======================================================================
@make_manual(
    "WSTG-CRYP-02", name="Padding Oracle 测试",
    procedure=("1) 定位所有使用加密数据的位置：URL 参数中的 Base64 串、"
               "Cookie 中的密文、隐藏表单字段、下载链接中的加密 ID；\n"
               "2) 判定是否为 CBC 模式：修改密文最后一个字节并重新提交，"
               "观察是否出现「解密失败 / 填充错误 / MAC 校验失败」类差异化提示；\n"
               "3) 若存在可区分的错误提示（含状态码差异、响应长度差异、耗时差异），"
               "即构成 padding oracle 条件；\n"
               "4) 使用标准工具在**测试环境**验证可解密范围"
               "（不要在生产的敏感数据上做批量解密）；\n"
               "5) 同时检查是否使用了 ECB 模式（相同明文块产生相同密文块，"
               "可通过构造重复内容观察密文是否重复判定）；\n"
               "6) 检查加密实现是否先加密后 MAC（EtM）而非先 MAC 后加密。"),
    expect=("使用 AEAD 模式（AES-GCM / ChaCha20-Poly1305）；"
            "或采用 EtM 结构且 MAC 校验失败时返回统一错误；"
            "解密失败不产生任何可区分的响应差异。"),
    why_manual="需要反复提交被篡改的密文并统计响应差异，属高侵入性操作；批量解密会触碰真实数据。",
    requires=["测试数据"], risk=RISK_DEEP, tool="人工核查",
    recon=recon_id.recon_cryp02,
)
def _cryp02(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-CRYP-03 敏感信息经未加密通道发送
# ======================================================================
@make_auto("WSTG-CRYP-03", name="明文通道与混合内容核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="协议与资源实测",
           detector_ref="checks/error_crypto.py:cryp03")
def cryp03(ctx: DetectorContext):
    findings = []
    probes = 0
    body = ctx.baseline_body
    parsed = urlparse(ctx.target_url)

    # 1) HTTPS 页面引用 HTTP 资源（混合内容）
    mixed = set(re.findall(r'(?:src|href|action)\s*=\s*["\'](http://[^"\']+)["\']', body, re.I))
    mixed = {m for m in mixed if "localhost" not in m and "127.0.0.1" not in m}
    if mixed:
        findings.append(make_finding(
            "WSTG-CRYP-03", f"HTTPS 页面引用 {len(mixed)} 个明文 HTTP 资源",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("页面通过 HTTPS 加载，但其中引用了 http:// 的资源。"
                         "这类资源不受 HTTPS 保护，且会被中间人替换。"),
            technical_detail="混合内容地址：\n" + "\n".join(f"  · {m}" for m in list(mixed)[:15]),
            impact=("若被引用的明文资源是脚本（<script src=\"http://...\">），"
                    "攻击者可在网络层替换该脚本内容，"
                    "从而在 HTTPS 页面中执行任意代码——"
                    "页面本身的 HTTPS 完全无法阻止这一点。"),
            reproduction=f"curl -s {ctx.target_url} | grep -oE '(src|href)=\"http://[^\"]+'",
            remediation=("① 所有资源改用 https:// 或协议相对形式（//）；"
                         "② 启用 CSP 的 `upgrade-insecure-requests` 指令；"
                         "③ 开启 HSTS 并在浏览器中阻止混合内容（默认行为）。"),
            compliance="等保2.0 安全通信网络-通信传输",
            evidence=[finding_evidence("response", "\n".join(list(mixed)[:15]), "混合内容")],
            grading_basis="实测存在混合内容，可被替换为恶意脚本，定中危",
        ))

    # 2) HTTP 入口是否存在（可被降级）
    if parsed.scheme == "https":
        probes += 1
        http_url = ctx.target_url.replace("https://", "http://", 1)
        try:
            pr = ctx.get(http_url)
            if getattr(pr, "status", 0) in (200, 301, 302):
                final = getattr(pr, "final_url", "") or http_url
                if final.lower().startswith("http://") and getattr(pr, "status", 0) == 200:
                    findings.append(make_finding(
                        "WSTG-CRYP-03", "HTTP 入口可直接访问，未强制跳转 HTTPS",
                        ctx.target_name, endpoint=http_url,
                        severity="中危", confidence="High", evidence_level="A",
                        description=("通过 http:// 访问该地址时，服务端直接返回 200，"
                                     "没有跳转到 HTTPS。"),
                        technical_detail=f"HTTP 访问：HTTP {getattr(pr, 'status', 0)} → {final}",
                        impact=("用户输入域名时若被浏览器补全为 http，"
                                "整个会话就在明文通道上进行，"
                                "同网络内的攻击者可直接读取内容与会话凭据。"),
                        reproduction=f"curl -sI {http_url}",
                        remediation="在服务器 / CDN 层配置 301 强制跳转 HTTPS，并下发 HSTS。",
                        compliance="等保2.0 安全通信网络-通信传输",
                        evidence=[finding_evidence("response",
                                                   f"HTTP {getattr(pr, 'status', 0)} → {final}",
                                                   "HTTP 入口")],
                        grading_basis="实测明文入口可用，定中危",
                    ))
        except Exception:  # noqa: BLE001
            pass

    # 3) 表单提交到 HTTP
    from engine.checks.base import find_forms
    for f in find_forms(ctx)[:6]:
        action = f["action"] or ""
        # 只认「页面里原样写成绝对 http:// 地址」的表单。
        # action 是 urljoin 解析后的绝对地址，任何站点解析结果都以 http(s)://
        # 开头 —— 用解析值判断，等于把 http:// 站点上的每个相对表单都误报成
        # 明文提交（复现脚本一扫一个准地复现不出来，正是这条误报暴露的）。
        if not (f.get("action_raw") or "").strip().lower().startswith("http://"):
            continue
        if action.lower().startswith("http://"):
            findings.append(make_finding(
                "WSTG-CRYP-03", "表单提交到明文 HTTP 地址",
                ctx.target_name, endpoint=action, method=f["method"],
                severity="高危" if f["has_password"] else "中危",
                confidence="High", evidence_level="A",
                description=("页面中的表单把数据提交到 http:// 地址，"
                             + ("且该表单含口令字段。" if f["has_password"] else "传输过程不受加密保护。")),
                technical_detail=f"表单页面：{f['page']}\n提交地址：{action}\n是否含口令：{f['has_password']}",
                impact=("提交内容在网络上以明文传输，可被同网络内设备直接读取。"
                        "若含口令，等同于凭据泄露。"),
                reproduction=f"curl -s {f['page']} | grep -iE '<form|action='",
                remediation="表单提交地址改为 HTTPS，并在服务端强制 HTTPS 跳转。",
                compliance="等保2.0 安全通信网络-通信传输 / PIPL 第 51 条",
                evidence=[finding_evidence("response", f["raw"][:600], "明文表单")],
                grading_basis="实测表单指向明文地址，定高危 / 中危",
            ))
            break

    note = (f"混合内容 {len(mixed)} 个；协议：{parsed.scheme}；"
            f"表单明文提交检查完成")
    return found(note, findings, probes=probes + 1, evidence_kind="协议与资源实测")


# ======================================================================
# WSTG-CRYP-04 弱加密原语
# ======================================================================
@make_auto("WSTG-CRYP-04", name="弱加密原语与不安全随机数检测", tool="前端产物静态分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/error_crypto.py:cryp04")
def cryp04(ctx: DetectorContext):
    hits = code_scan(ctx, WEAK_CRYPTO_PATTERNS, scope="both")
    findings = []
    if hits:
        # 分级：明文存密码 / 无 IV 加密 属高危；MD5/SHA1 属低危（需看用途）
        high_risk = [h for h in hits if any(k in h[0] for k in
                                            ("明文存密码", "无 IV", "ECB", "Math.random"))]
        findings.append(make_finding(
            "WSTG-CRYP-04", f"前端使用弱加密原语或不安全随机数（{len(hits)} 类）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危" if high_risk else "低危",
            confidence="Medium", evidence_level="B",
            description=("打包后的前端代码中出现了已被攻破或使用方式不安全的加密算法。"
                         "前端加密无法替代服务端安全，但会给人「已加密」的错觉。"),
            technical_detail="命中的弱原语：\n" + "\n".join(
                f"  · {d}\n    模式：{p}" for d, p in hits),
            impact=("MD5 / SHA-1 可用于口令哈希时会被彩虹表快速还原；"
                    "DES / RC4 / ECB 模式无法提供有效保密性；"
                    "Math.random 生成的令牌可被预测（V8 的 xorshift128+ 在观测若干输出后可推状态），"
                    "若用于会话或验证码即等于没有随机性。"),
            reproduction="在前端产物中检索 md5 / sha1 / des / rc4 / Math.random 等关键字并确认调用上下文。",
            remediation=("① 口令哈希用 bcrypt / scrypt / Argon2（服务端做，前端不做）；"
                         "② 数据加密用 AES-GCM（带随机 IV），不用 ECB；"
                         "③ 安全相关随机数使用 crypto.getRandomValues()（前端）"
                         "或 CSPRNG（服务端）；"
                         "④ 传输安全依赖 TLS，不依赖前端加密。"),
            compliance="等保2.0 安全计算环境-数据保密性 / CWE-327",
            evidence=[finding_evidence("file", str(hits), "弱加密原语命中")],
            grading_basis="静态匹配到弱原语使用，具体用途需结合上下文确认，按 B 级定中危 / 低危",
        ))

    note = (f"扫描前端产物，命中弱加密原语 {len(hits)} 类"
            + (f"：{'、'.join(d for d, _ in hits)}" if hits else "（未命中）"))
    return found(note, findings, probes=1, evidence_kind="前端产物实测")
