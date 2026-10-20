# -*- coding: utf-8 -*-
"""
WSTG-CLNT 客户端（15 项）
========================
前端安全问题的特点是：**看产物就能发现大部分，但验证需要浏览器**。

本模块的处理：
  - 静态分析（DOM sink/source 配对、postMessage、target=_blank、前端存储）
    可以用产物直接判定，属确证；
  - 浏览器行为类（DOM XSS 实际执行、点击劫持实际效果）做静态判定 + 人工验证指引；
  - 响应头类（CORS、点击劫持防护、XSSI）可以直接实测。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urljoin, urlparse

from engine.checks.base import (
    DOM_XSS_SINKS, DOM_XSS_SOURCES, extract_params, find_forms, finding_evidence,
    is_real_hit, ok, found, pending, probe_or_none, scan_paths, code_scan,
    no_target_outcome, sitewide_guard,
)
from engine.registry import (
    RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding, make_manual,
)


# ======================================================================
# WSTG-CLNT-01 基于 DOM 的 XSS
# ======================================================================
@make_auto("WSTG-CLNT-01", name="DOM 型 XSS 静态分析", tool="前端产物 sink/source 配对",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt01")
def clnt01(ctx: DetectorContext):
    blobs = list(ctx.js_result.get("bodies") or []) + list(ctx.js_result.get("inline_scripts") or [])
    text = "\n".join(b for b in blobs if b)
    if not text:
        return ok("未采集到前端脚本，无法做 DOM XSS 静态分析", probes=1, evidence_kind="无 JS 产物")

    sinks = [(p, d) for p, d in DOM_XSS_SINKS if re.search(p, text, re.I)]
    sources = [(p, d) for p, d in DOM_XSS_SOURCES if re.search(p, text, re.I)]
    findings = []

    if sinks and sources:
        # 进一步确认：source 与 sink 是否在同一文件 / 相邻作用域内出现（降低误报）
        risky = []
        for b in blobs[:200]:
            if not b:
                continue
            s_hit = [d for p, d in DOM_XSS_SOURCES if re.search(p, b, re.I)]
            k_hit = [d for p, d in DOM_XSS_SINKS if re.search(p, b, re.I)]
            if s_hit and k_hit:
                risky.append((s_hit[:3], k_hit[:3]))
        if risky:
            findings.append(make_finding(
                "WSTG-CLNT-01", f"DOM 型 XSS 风险：同一产物中同时存在可控输入与危险输出（{len(risky)} 处）",
                ctx.target_name, endpoint=ctx.target_url,
                severity="中危", confidence="Medium", evidence_level="B",
                description=("前端代码里同时出现了「来自地址栏 / 存储的可控数据」"
                             "和「会把内容当 HTML 解析的危险写入点」，"
                             "且两者出现在同一份产物中。这类组合是 DOM 型 XSS 的典型形态。"),
                technical_detail=("命中的危险写入点（sink）：\n"
                                  + "\n".join(f"  · {d}" for _, d in sinks)
                                  + "\n\n命中的可控输入源（source）：\n"
                                  + "\n".join(f"  · {d}" for _, d in sources)
                                  + "\n\n同时出现二者的产物示例：\n"
                                  + "\n".join(f"  sinks={k} sources={s}" for k, s in risky[:5])),
                impact=("攻击者构造带恶意片段的链接（如 #<img src=x onerror=...>），"
                        "受害者打开后脚本在其浏览器中执行。"
                        "由于不经过服务端，服务端 WAF 无法拦截，"
                        "危害与反射型 XSS 相同（读取页面数据、冒用身份）。"),
                reproduction=("在浏览器中打开目标页面，在地址栏 hash 或查询参数中注入 "
                              "<img src=x onerror=alert(1)>，观察是否触发执行。"),
                remediation=("① 危险写入点改用 textContent / innerText 而非 innerHTML；"
                             "② 必须写 HTML 时先做转义（DOMPurify 等成熟库）；"
                             "③ 避免 eval / new Function / document.write 处理外部数据；"
                             "④ 叠加 CSP 禁止内联脚本执行，作为兜底。"),
                compliance="等保2.0 安全计算环境-入侵防范 / CWE-79",
                evidence=[finding_evidence("file", f"sinks={[d for _, d in sinks]}\n"
                                                   f"sources={[d for _, d in sources]}",
                                           "DOM XSS 静态配对")],
                grading_basis="静态配对到 sink/source，实际可执行性需浏览器验证，按 B 级定中危",
            ))
    else:
        findings_none = True

    note = (f"危险写入点 {len(sinks)} 类、可控输入源 {len(sources)} 类"
            + ("；存在相邻组合，已提示" if findings else "；未发现 sink/source 相邻组合"))
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-CLNT-02 JavaScript 执行
# ======================================================================
@make_auto("WSTG-CLNT-02", name="动态脚本执行点检测", tool="前端产物静态分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt02")
def clnt02(ctx: DetectorContext):
    hits = code_scan(ctx, [
        (r"\beval\s*\(", "eval() 动态求值"),
        (r"new\s+Function\s*\(", "new Function() 动态构造函数"),
        (r"document\.write\s*\(", "document.write() 直接写入文档"),
        (r"setTimeout\s*\(\s*[\"']", "setTimeout 传入字符串（隐式 eval）"),
        (r"setInterval\s*\(\s*[\"']", "setInterval 传入字符串（隐式 eval）"),
        (r"\bexecScript\s*\(", "execScript()（IE 遗留）"),
        (r"\.setAttribute\s*\(\s*[\"']on", "通过 setAttribute 绑定事件处理器"),
        (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML 直接插入 HTML"),
        (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
    ])
    findings = []
    if hits:
        findings.append(make_finding(
            "WSTG-CLNT-02", f"前端存在 {len(hits)} 类动态脚本执行点",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="B",
            description=("前端代码使用了会把字符串当代码执行的能力。"
                         "这类接口本身是语言特性，但一旦有外部数据流进去就成为 XSS 的落点。"),
            technical_detail="命中的执行点：\n" + "\n".join(
                f"  · {d}\n    模式：{p}" for p, d in hits),
            impact=("配合可控数据源（地址栏、存储、接口返回）可执行任意脚本；"
                    "即使当前无可控数据，也会在后续功能迭代中成为隐患。"),
            reproduction="在前端产物中检索 eval / Function / document.write 等关键字，确认调用上下文的数据来源。",
            remediation=("① 不使用 eval / new Function；"
                         "② setTimeout / setInterval 只传函数不传字符串；"
                         "③ document.write 替换为 DOM API；"
                         "④ React 避免 dangerouslySetInnerHTML，必须用时先净化。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-95",
            evidence=[finding_evidence("file", str(hits), "动态执行点")],
            grading_basis="静态匹配到危险接口，无明确可控数据流，按 B 级定低危",
        ))
    note = (f"动态脚本执行点 {len(hits)} 类"
            + (f"：{'、'.join(d for _, d in hits)}" if hits else "（未命中）"))
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-CLNT-03 HTML 注入
# ======================================================================
@make_auto("WSTG-CLNT-03", name="HTML 注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="标签反射实测",
           detector_ref="checks/client.py:clnt03")
def clnt03(ctx: DetectorContext):
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点", probes=2, evidence_kind="无候选参数")

    MARK_TAG = "aiscanx9z8y7x"
    probes = 0
    findings = []
    for p in params[:8]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        payload = f"<b>{MARK_TAG}</b>"
        probes += 1
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[pname] = [payload]
        test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
        try:
            pr = ctx.get(test_url)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(pr, "body_snippet", "") or ""
        # HTML 注入的判定：标签结构被保留且不在 script/style 上下文
        if f"<b>{MARK_TAG}</b>" in body:
            findings.append(make_finding(
                "WSTG-CLNT-03", f"HTML 标签可被注入（参数 {pname}）",
                ctx.target_name, endpoint=url, method="GET", param=pname,
                severity="中危", confidence="High", evidence_level="A",
                description=(f"参数 `{pname}` 的值未做 HTML 编码即输出到页面，"
                             "提交的标签被浏览器解析为真实标签。"),
                technical_detail=(f"受影响参数：{pname}\n"
                                  f"注入内容：{payload}\n"
                                  f"响应中出现未编码的标签结构。\n"
                                  f"响应片段：{body[:500]}"),
                impact=("HTML 注入本身可篡改页面结构、伪造界面元素（如伪造登录框骗取口令）。"
                        "若目标浏览器或框架允许，可进一步升级为 XSS。"
                        "与反射型 XSS 的区别在于本次注入的标签不含脚本，故定中危。"),
                reproduction=f"curl -s '{test_url}' | grep -o '<b>{MARK_TAG}</b>'",
                remediation="对所有输出到 HTML 的用户输入做实体编码（&lt; &gt; &quot; &#39;）。",
                compliance="等保2.0 安全计算环境-入侵防范 / CWE-79",
                evidence=[finding_evidence("response", body[:800], "标签注入响应")],
                grading_basis="实测标签被解析，未确认可执行脚本，定中危",
            ))
            break

    note = f"对 {len(params[:8])} 个参数测试 {probes} 次标签反射，命中 {len(findings)} 处"
    return found(note, findings, probes=probes, evidence_kind="标签反射实测")


# 常见重定向接收点（路径 → 该路径上惯用的跳转参数名）。
# 为什么不只靠采集到的参数：SPA 的服务端重定向路由往往**没有任何页面链接指向它**，
# 只在后端存在。挑这几个是因为它们是跨产品的高频命名，不是某家的私有路径。
_COMMON_REDIRECT_ENDPOINTS = (
    ("redirect", ("to", "url", "next", "target")),
    ("login", ("returnUrl", "next")),
)


def _location_of(pr: Any) -> str:
    """取响应里的 Location（大小写不敏感）。"""
    for k, v in (getattr(pr, "headers", {}) or {}).items():
        if str(k).lower() == "location":
            return str(v or "")
    return ""


def _external_seed_urls(ctx: DetectorContext) -> list[str]:
    """页面上已经出现的外部绝对地址 —— 重定向白名单里最可能就躺着它们。

    能被跳转走的外部链接，按定义必然是被白名单放行的那一批，
    拿它们当种子去试前缀滥用，比凭空猜域名靠谱得多。

    2026-10-15 修正：社交 / 外链常写在**前端 JS 包**里（Angular 模板编译进
    bundle），不一定出现在服务端直出的 baseline HTML 或渲染 DOM。Juice Shop
    的 allowlist 成员 `https://github.com/juice-shop/juice-shop` 就只在 main.js
    里，旧实现只扫 baseline + 渲染，种子取不到它，导致前缀滥用分支整段空转、
    CLNT-04 误判「通过」（红线 1 违例）。现改为同时扫 JS 产物，并把上限提到 15。
    """
    js_blobs = list(ctx.js_result.get("bodies") or []) + list(ctx.js_result.get("inline_scripts") or [])
    html = "\n".join([
        ctx.baseline_body or "",
        str((ctx.fp_result or {}).get("_render_html") or "")[:400_000],
    ] + [b for b in js_blobs if b])
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"https?://[A-Za-z0-9._\-~/?=&%#:]{6,200}", html):
        u = m.group(0).rstrip("\"'<>),.;")
        host = urlparse(u).netloc.lower()
        if not host or ctx.domain in host:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= 15:
            break
    return out


# ======================================================================
# WSTG-CLNT-04 客户端 URL 重定向
# ======================================================================
@make_auto("WSTG-CLNT-04", name="客户端开放重定向检测", tool="内置检测器 + 前端分析",
           risk=RISK_STANDARD, evidence_kind="跳转行为实测",
           detector_ref="checks/client.py:clnt04")
def clnt04(ctx: DetectorContext):
    params = [p for p in extract_params(ctx) if p.get("method", "GET") == "GET"]
    KEYWORD = r"(redirect|return|next|url|goto|target|dest|continue|back|forward|jump|to)"
    named = [p for p in params if re.search(KEYWORD, p.get("param", ""), re.I)]
    # 关键词只决定「优先测谁」，不能决定「只测谁」——
    # 重定向参数常叫 r / u / a / ref / from，名字不像就跳过探测，
    # 等于把这一项的风险判给了猜测。
    others = [p for p in params if p not in named]
    degraded = not named and bool(others)
    cands = (named[:6] + others[:4]) if named else others[:6]
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])

    probes = 0
    findings = []

    # 1) 服务端 302 跳转（本来属 ATHN 范畴，但客户端重定向常与之混杂，一并检测）
    from urllib.parse import urlparse, parse_qs, urlencode
    evil = "https://aiscan-probe.invalid/redirect"
    for p in cands:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[pname] = [evil]
        test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
        probes += 1
        try:
            pr = ctx.get(test_url, allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        loc = ""
        for k, v in (getattr(pr, "headers", {}) or {}).items():
            if k.lower() == "location":
                loc = v
        if "aiscan-probe.invalid" in loc:
            findings.append(make_finding(
                "WSTG-CLNT-04", f"开放重定向（参数 {pname}）",
                ctx.target_name, endpoint=url, method="GET", param=pname,
                severity="中危", confidence="High", evidence_level="A",
                description=(f"参数 `{pname}` 的值被直接用作跳转目标，"
                             "服务端把用户导向了任意外部地址。"),
                technical_detail=(f"受影响参数：{pname}\n"
                                  f"提交值：{evil}\n"
                                  f"响应：HTTP {getattr(pr, 'status', 0)} → Location: {loc}"),
                impact=("攻击者可构造一个域名正确、看起来完全可信的链接"
                        "（如 https://官方域名/redirect?url=钓鱼站），"
                        "受害者点击后跳转到钓鱼页面并可能在此输入凭据。"
                        "这在钓鱼邮件中的成功率远高于普通钓鱼链接。"),
                reproduction=f"curl -si '{test_url}' | grep -i '^location:'",
                remediation=("① 跳转目标改用服务端白名单映射（如 code=home → 固定地址）；"
                             "② 必须接受 URL 时，只允许相对路径（拒绝以 http:// // 开头的值）；"
                             "③ 校验时先解码再比对，避免 %2f%2f 等编码绕过。"),
                compliance="等保2.0 安全计算环境-入侵防范 / CWE-601",
                evidence=[finding_evidence("header", f"Location: {loc}", "重定向响应")],
                grading_basis="实测可跳转到任意外部域名，定中危",
            ))
            break

    # 1-bis) 白名单绕过
    # 「直连外部域名被拒」不等于「没有开放重定向」—— 有白名单但白名单写得松
    # 才是真实世界里更常见、也更常被漏掉的那一类。只测一次 `https://evil`
    # 就收工，等于把「能不能跳出去」判给了「有没有白名单」。
    # 手法只改**值的形态**，不改**目标域名**：目标恒为探测域名，
    # 命中即证明值被用作跳转目标且跳出了允许范围（红线 9：目标明确、可对照）。
    bypass_note = ""
    prefix_note = ""
    allowlisted_seed_found = False
    if not findings:
        probe_host = "aiscan-probe.invalid"
        variants = (
            f"//{probe_host}/x",                 # 协议相对
            f"https:/\\{probe_host}/x",           # 单斜杠反斜杠混写
            f"https:\\\\{probe_host}/x",          # 反斜杠代替斜杠
            f"https:%2f%2f{probe_host}/x",       # URL 编码斜杠
            f"////{probe_host}/x",               # 多斜杠
            f"https://{probe_host}%09/x",        # Tab 截断
            f"https://{probe_host}#/x",          # 片段截断
            f"https://{probe_host}/x#.png",      # 片段 + 伪装扩展名
            f"https://{probe_host}/x%00.png",    # 空字节 + 伪装扩展名
            f"https://user@{probe_host}/x",      # userinfo 混淆
        )
        allowlist_seen = False
        for p in cands[:2]:
            url, pname = p["url"], p["param"]
            if not url.startswith("http") or ctx.domain not in url:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for v in variants:
                qs[pname] = [v]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
                probes += 1
                try:
                    pr = ctx.get(test_url, allow_redirects=False)
                except Exception:  # noqa: BLE001
                    continue
                loc = ""
                for k, vv in (getattr(pr, "headers", {}) or {}).items():
                    if k.lower() == "location":
                        loc = vv
                body = getattr(pr, "body_snippet", "") or ""
                if re.search(r"(allowlist|white[-_ ]?list|不允许的跳转|非法的?\s*(跳转|地址)|"
                             r"invalid\s*(redirect|url|target)|not\s+allowed)",
                             loc + " " + body, re.I):
                    allowlist_seen = True
                if probe_host in loc or re.search(r"aiscan-probe\.invalid", body):
                    findings.append(make_finding(
                        "WSTG-CLNT-04", f"开放重定向白名单可被绕过（参数 {pname}）",
                        ctx.target_name, endpoint=url, method="GET", param=pname,
                        severity="中危", confidence="High", evidence_level="A",
                        description=(f"跳转参数 `{pname}` 对直接的外部域名做了限制，"
                                     "但换一种写法即可绕过限制跳到任意外部站点。"
                                     f"生效的绕过形态：`{v}`"),
                        technical_detail=(f"受影响参数：{pname}\n"
                                          f"绕过形态：{v}\n"
                                          f"请求：{test_url}\n"
                                          f"响应：HTTP {getattr(pr, 'status', 0)}"
                                          f" → Location: {loc or '（无，正文跳转）'}"),
                        impact=("攻击者可构造一个域名正确、看起来完全可信的链接，"
                                "受害者点击后被导向钓鱼页面。"
                                "白名单的存在会让使用者误以为「有防护」，"
                                "实际防护已被绕过，风险反而更隐蔽。"),
                        reproduction=f"curl -si '{test_url}' | grep -i '^location:'",
                        remediation=("① 跳转目标用服务端白名单映射（code → 固定地址），"
                                     "不接受客户端传入的完整 URL；"
                                     "② 必须接受 URL 时：先解码、再归一化"
                                     "（展开 %2f、统一反斜杠、去掉 userinfo 与片段），"
                                     "然后取 scheme+host 与白名单**全等比对**，"
                                     "禁止 startsWith / endsWith 这类前缀后缀匹配；"
                                     "③ 对 %00 等截断字符在取 host 前先剥离。"),
                        compliance="等保2.0 安全计算环境-入侵防范 / CWE-601",
                        evidence=[finding_evidence(
                            "header", f"Location: {loc or body[:300]}", "绕过白名单的重定向响应")],
                        grading_basis="实测可绕过跳转白名单到任意外部域名，定中危",
                    ))
                    break
            if findings:
                break
        if not findings and allowlist_seen:
            bypass_note = ("；目标对跳转参数做了白名单校验（响应中出现白名单 / 非法跳转提示），"
                           f"本次 {len(variants)} 种常见绕过形态均未跳出白名单")

    # 1-ter) 白名单前缀滥用
    # 「有白名单」本身不是结论。真实实现里绝大多数是 **startsWith 前缀匹配**：
    # 只要拿到一个被允许的值，把攻击域名接在它后面就能出去 ——
    # 靶场实测：放行 `https://github.com/juice-shop/juice-shop` 的实现，
    # 会连带放行 `https://github.com/juice-shop/juice-shop.evil.test/x`
    # 与 `...@evil.test/x`。这不是猜：白名单成员**就写在页面上**
    # （能被跳转走的外部链接必然是被允许的那些），拿它当种子即可。
    if not findings:
        seeds = _external_seed_urls(ctx)
        if seeds:
            for path, pnames in _COMMON_REDIRECT_ENDPOINTS:
                base_url = urljoin(ctx.target_url, path)
                for pn in pnames:
                    for seed in seeds[:15]:
                        probes += 1
                        try:
                            pr = ctx.get(f"{base_url}?{pn}={quote(seed, safe='')}",
                                         allow_redirects=False)
                        except Exception:  # noqa: BLE001
                            continue
                        loc = _location_of(pr)
                        if getattr(pr, "status", 0) not in (301, 302, 303, 307, 308) or not loc:
                            continue
                        # 种子被放行 —— 说明它就是白名单成员，试前缀滥用
                        allowlisted_seed_found = True
                        for variant in (seed.rstrip("/") + ".aiscan-probe.invalid/x",
                                        seed.rstrip("/") + "@aiscan-probe.invalid/x",
                                        seed.rstrip("/") + "Xaiscan-probe.invalid"):
                            probes += 1
                            try:
                                pr2 = ctx.get(
                                    f"{base_url}?{pn}={quote(variant, safe='')}",
                                    allow_redirects=False)
                            except Exception:  # noqa: BLE001
                                continue
                            loc2 = _location_of(pr2)
                            if "aiscan-probe.invalid" not in loc2:
                                continue
                            findings.append(make_finding(
                                "WSTG-CLNT-04",
                                f"重定向白名单用前缀匹配，可被追加绕过（参数 {pn}）",
                                ctx.target_name, endpoint=base_url, method="GET", param=pn,
                                severity="中危", confidence="High", evidence_level="A",
                                description=(
                                    f"重定向接收点 `{path}` 对跳转目标做了白名单校验，"
                                    "但校验方式是**前缀匹配**：目标值只要以白名单成员开头"
                                    "就被放行，把攻击者域名接在后面即可跳出去。\n"
                                    f"白名单成员（页面上已出现的外链）：{seed}\n"
                                    f"生效的绕过值：`{variant}`"),
                                technical_detail=(
                                    f"接收点：{base_url}?{pn}=\n"
                                    f"白名单成员实测被放行：{seed} → HTTP "
                                    f"{getattr(pr, 'status', 0)} → Location: {loc}\n"
                                    f"前缀追加后仍被放行：{variant} → Location: {loc2}\n"
                                    "（对照：直连外部域名会被拒绝，见本项前段探测）"),
                                impact=("攻击者可构造域名看起来完全可信的钓鱼链接，"
                                        "点击后被导向任意站点。白名单的存在会让使用者"
                                        "误以为「有防护」，实际防护已被绕过，风险更隐蔽。"),
                                reproduction=(
                                    f"curl -si '{base_url}?{pn}={variant}' | grep -i '^location:'"),
                                remediation=("① 跳转目标改用服务端白名单映射（code → 固定地址），"
                                             "不接受客户端传入的完整 URL；"
                                             "② 必须接受 URL 时，先解码与归一化（去 userinfo、"
                                             "统一反斜杠），再取 scheme + host + port 与白名单"
                                             "**全等比对**，禁止 startsWith / endsWith / includes；"
                                             "③ 若必须按前缀放行，前缀必须以分隔符结尾"
                                             "（`https://a.example/`），且不得允许在该段内出现 @ 或 .。"),
                                compliance="等保2.0 安全计算环境-入侵防范 / CWE-601",
                                evidence=[finding_evidence(
                                    "header", f"Location: {loc2}", "前缀滥用后的重定向响应")],
                                grading_basis="实测可借白名单前缀跳到任意外部域名，定中危",
                            ))
                            break
                        if findings:
                            break
                    if findings:
                        break
                if findings:
                    break
            if not findings and seeds:
                prefix_note = ("；已按页面 / 前端产物上出现的外链作白名单种子做过前缀滥用探测"
                               f"（{len(seeds)} 个种子 × {len(_COMMON_REDIRECT_ENDPOINTS)} 个常见端点），未跳出")

    # 2) 前端基于地址栏的跳转
    if not findings and re.search(
            r"(location\s*=\s*(?:getParam|params|search|decodeURIComponent)|"
            r"location\.href\s*=\s*(?:url|redirect|target|next))", blobs, re.I):
        findings.append(make_finding(
            "WSTG-CLNT-04", "前端直接使用地址栏参数作为跳转目标",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Medium", evidence_level="B",
            description="前端代码把地址栏参数直接赋给了 location，未做白名单校验。",
            technical_detail="前端产物中出现 location = <参数变量> 形式的赋值。",
            impact="可用于钓鱼跳转；配合 OAuth 流程可窃取授权码。",
            reproduction="给疑似参数传入外部地址，观察是否发生跳转。",
            remediation="前端跳转同样使用白名单映射，不接受任意外部地址。",
            compliance="CWE-601",
            evidence=[finding_evidence("file", "location = 参数变量", "前端跳转")],
            grading_basis="静态匹配到前端跳转模式，未实证，按 B 级定中危",
        ))

    if not cands and not findings:
        return no_target_outcome(ctx, "重定向 / 跳转类参数",
                                 probes=probes, evidence_kind="跳转行为实测")

    # 若确认目标存在跳转白名单（有外链种子被放行），但本次没跳出前缀绕过，
    # 不能下「通过」——那是「没探到」不是「没有」（红线 1）。归待确认，
    # 让复核者知道这里值得人眼再看一眼。
    if not findings and allowlisted_seed_found:
        note = (f"候选参数 {len(cands)} 个（候选池 {len(params)} 个），"
                f"探测 {probes} 次；目标对跳转参数做了白名单校验"
                f"（{prefix_note or '存在被放行的外链种子'}），"
                "但本次常见前缀绕过形态均未跳出，归待确认")
        return pending(note, probes=probes, evidence_kind="跳转行为实测")

    note = ((f"按参数名关键词未命中，已对全部 {len(cands)} 个参数降级探测；"
             if degraded else "")
            + f"候选参数 {len(cands)} 个（候选池 {len(params)} 个），"
            + f"探测 {probes} 次，命中 {len(findings)} 处"
            + bypass_note + prefix_note)
    return found(note, findings, probes=probes, evidence_kind="跳转行为实测")


# ======================================================================
# WSTG-CLNT-05 CSS 注入
# ======================================================================
@make_auto("WSTG-CLNT-05", name="CSS 注入检测", tool="前端产物静态分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt05")
def clnt05(ctx: DetectorContext):
    hits = code_scan(ctx, [
        (r"\.style\.cssText\s*=", "style.cssText 直接赋值"),
        (r"\.style\.(?:background|backgroundImage)\s*=\s*[^;]*(?:location|param|query|\+)",
         "样式属性由外部输入拼接"),
        (r"\.css\s*\(\s*[\"'](?:background|background-image)", "jQuery .css 设置背景（可由 URL 注入）"),
        (r"<style[^>]*>[^<]*\+", "拼接字符串生成 style 内容"),
        (r"style\s*=\s*[\"'][^\"']*\+", "内联 style 属性拼接变量"),
    ])
    findings = []
    if hits:
        findings.append(make_finding(
            "WSTG-CLNT-05", f"存在 CSS 注入风险点（{len(hits)} 处）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="B",
            description=("前端把变量拼进了样式定义。"
                         "CSS 注入本身危害有限，但可被用于界面伪装与部分数据外带。"),
            technical_detail="命中模式：\n" + "\n".join(f"  · {d}" for _, d in hits),
            impact=("① 界面伪装：覆盖真实按钮/表单，诱导用户在不该输入的地方输入凭据；"
                    "② 条件加载：用 CSS 选择器 + 背景图请求把页面上的敏感内容外带"
                    "（属性选择器逐字符匹配，可提取 CSRF token 等）。"),
            reproduction="给相关参数注入 CSS 片段（如 background-image:url(...)），观察是否生效。",
            remediation="样式不拼接外部输入；必须动态设置样式时使用白名单属性与值，不用 cssText。",
            compliance="CWE-79",
            evidence=[finding_evidence("file", str(hits), "CSS 注入模式")],
            grading_basis="静态匹配，未实证，定低危",
        ))
    note = f"CSS 注入风险点 {len(hits)} 处"
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-CLNT-06 客户端资源操纵
# ======================================================================
@make_auto("WSTG-CLNT-06", name="客户端资源加载操纵检测", tool="前端产物静态分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt06")
def clnt06(ctx: DetectorContext):
    hits = code_scan(ctx, [
        (r"\.src\s*=\s*(?:[^;]*(?:location|param|query|hash|input))",
         "资源地址由地址栏 / 输入拼接"),
        (r"createElement\s*\(\s*[\"']script[\"']\s*\)", "动态创建 script 标签"),
        (r"\.setAttribute\s*\(\s*[\"']src[\"']", "通过 setAttribute 设置资源地址"),
        (r"document\.domain\s*=", "运行时修改 document.domain"),
        (r"window\.name\s*=", "使用 window.name 传递数据"),
        (r"__proto__|prototype\s*\[", "原型链操作（可影响全局对象）"),
    ])
    findings = []
    if hits:
        findings.append(make_finding(
            "WSTG-CLNT-06", f"客户端资源可被外部数据影响（{len(hits)} 处）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Medium", evidence_level="B",
            description="前端根据地址栏或输入动态决定加载哪个资源，未做来源白名单。",
            technical_detail="命中模式：\n" + "\n".join(f"  · {d}" for _, d in hits),
            impact=("① 攻击者可让页面加载其控制的脚本（等同 XSS）；"
                    "② document.domain 放宽后，同一注册域下的任意子域都能互相读取数据"
                    "（若存在可被接管的子域，风险立即升级为数据泄露）。"),
            reproduction="检查相关参数并尝试改为外部地址，观察网络请求是否发往该地址。",
            remediation=("① 资源地址使用白名单或服务端映射；"
                         "② 避免运行时修改 document.domain（改用 postMessage）；"
                         "③ 动态插入脚本时校验来源域名。"),
            compliance="CWE-829",
            evidence=[finding_evidence("file", str(hits), "资源加载模式")],
            grading_basis="静态匹配，未实证，按 B 级定中危",
        ))
    note = f"资源加载风险点 {len(hits)} 处"
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-CLNT-07 跨域资源共享（CORS）
# ======================================================================
@make_auto("WSTG-CLNT-07", name="CORS 配置核查", tool="响应头实测",
           risk=RISK_STANDARD, evidence_kind="CORS 响应实测",
           detector_ref="checks/client.py:clnt07")
def clnt07(ctx: DetectorContext):
    import requests

    findings = []
    rejected: list[str] = []
    probes = 0
    evil = "https://aiscan-probe.invalid"
    endpoints = [ctx.target_url]
    for p in ("api/user", "api/v1/user", "api/me", "api/account", "api/profile"):
        pr = probe_or_none(ctx, p)
        if pr is not None and getattr(pr, "status", 0) in (200, 401, 403):
            endpoints.append(getattr(pr, "final_url", "") or urljoin(ctx.target_url, p))

    for ep in endpoints[:4]:
        probes += 1
        try:
            ctx._client._throttle()
            r = requests.get(ep, timeout=ctx._client.timeout, verify=False,
                             allow_redirects=False,
                             headers={**dict(ctx._client.session.headers),
                                      "Origin": evil})
        except Exception:  # noqa: BLE001
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if not acao:
            continue

        # ---- 证据归属门槛：这个响应是「应用对端点的回答」吗？ ----
        # 2026-09-28 实测教训（internal-app.example.com）：一条 CORS 发现
        # 「反射任意 Origin + 允许携带凭据」进了漏洞清单，但它的证据来自一个
        # **405 响应** —— 事后复跑同一份复现脚本，200 响应上根本没有 ACAO 头，
        # 「已复现」站不住。405 是「该方法不被允许」的通用错误页，
        # 它上面的头可能由边缘节点（WAF / 网关）统一添加，
        # 归不到「这个端点的 CORS 配置」上。5xx 同理。
        #
        # 这与红线一致：**孤立信号不得当正面证据** ——
        # 先把「响应是否真的来自应用」证出来，再谈它是不是配置缺陷。
        if r.status_code == 405 or r.status_code >= 500:
            rejected.append(f"{ep} 返回 {r.status_code}（通用错误页）—— "
                            f"其上虽有 ACAO，但归不到该端点的 CORS 配置，未采信")
            continue
        _modal, _ratio, _n = sitewide_guard(ctx)
        if _modal and _modal == r.status_code and r.status_code != 200:
            rejected.append(f"{ep} 返回 {r.status_code} 且整站同码"
                            f"（占比 {_ratio:.0%} / {_n} 个样本）—— "
                            f"无法区分是应用的 CORS 配置还是边缘节点统一加的头，未采信")
            continue

        if acao == evil or acao == "*":
            critical = (acao == evil and acac.lower() == "true")
            findings.append(make_finding(
                "WSTG-CLNT-07",
                ("CORS 反射任意 Origin 且允许携带凭据（严重）"
                 if critical else f"CORS 允许任意来源（ACAO: {acao}）"),
                ctx.target_name, endpoint=ep, method="GET", param="Origin",
                severity="高危" if critical else "中危",
                confidence="High", evidence_level="A",
                description=(f"服务端把请求中的 Origin 原样回显到 "
                             f"Access-Control-Allow-Origin，"
                             + ("且同时允许携带凭据（Access-Control-Allow-Credentials: true）。"
                                if critical else "但未允许携带凭据。")),
                technical_detail=(f"请求 Origin：{evil}\n"
                                  f"响应状态码：{r.status_code}\n"
                                  f"响应 Access-Control-Allow-Origin：{acao}\n"
                                  f"响应 Access-Control-Allow-Credentials：{acac or '（未设置）'}"),
                impact=("跨域读取：攻击者页面可携带受害者的登录凭据向该接口发起请求，"
                        "并读取响应内容（浏览器不会阻止）。"
                        "结合反射型 Origin，任何网站都能读取用户在此站点的数据，"
                        "等于把接口开放给全网。"),
                reproduction=f"curl -si -H 'Origin: {evil}' '{ep}' | grep -i access-control",
                remediation=("① CORS 白名单限定到具体业务域名，不用通配符、不反射 Origin；"
                             "② 使用 Allow-Credentials 时绝不解禁为任意来源；"
                             "③ 对无需跨域的接口不返回 CORS 头；"
                             "④ 内部管理接口禁止跨域访问。"),
                compliance="等保2.0 安全计算环境-访问控制 / CWE-346",
                evidence=[finding_evidence("header",
                                           f"HTTP {r.status_code}\nACAO: {acao}\nACAC: {acac}",
                                           "CORS 响应头")],
                grading_basis=("实测反射任意 Origin 且允许凭据，可跨域读取数据，定高危"
                               if critical else "实测反射任意 Origin 但不含凭据，定中危"),
            ))
            break

    note = (f"测试 {len(endpoints[:4])} 个端点的 CORS 配置，"
            f"{'命中配置缺陷' if findings else '未发现反射 Origin 或通配符'}")
    if rejected:
        note += f"；{len(rejected)} 个端点的 ACAO 头因无法归属到应用而未采信"
    # 有命中就报命中；没有命中但存在「无法归属」的情况 → 待确认，
    # 绝不当成「未发现缺陷」（那会用一个不可采信的响应把风险判定掉）。
    if not findings and rejected:
        return pending(note + "：" + rejected[0], probes=probes,
                       evidence_kind="CORS 响应实测")
    return found(note, findings, probes=probes, evidence_kind="CORS 响应实测")


# ======================================================================
# WSTG-CLNT-08 跨站 Flash（遗留）
# ======================================================================
@make_auto("WSTG-CLNT-08", name="跨站 Flash 遗留配置核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="策略文件实测",
           detector_ref="checks/client.py:clnt08")
def clnt08(ctx: DetectorContext):
    findings = []
    hits = scan_paths(ctx, ["crossdomain.xml", "clientaccesspolicy.xml",
                            "crossdomain.xml.bak"])
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    has_swf = bool(re.search(r"\.swf|shockwave", blobs, re.I))

    if hits:
        first = list(hits)[0]
        body = getattr(hits[first], "body_snippet", "") or ""
        wildcard = bool(re.search(r'domain\s*=\s*["\']\*["\']', body))
        findings.append(make_finding(
            "WSTG-CLNT-08",
            ("跨站 Flash 策略允许任意域（通配符）" if wildcard else "存在 Flash 跨域策略文件"),
            ctx.target_name, endpoint=getattr(hits[first], "final_url", "")
            or urljoin(ctx.target_url, first),
            severity="中危" if wildcard else "低危",
            confidence="High", evidence_level="A",
            description="站点仍提供 Flash 时代的跨域策略文件。现代浏览器已不支持 Flash，"
                        + ("且其中对任意域放行。" if wildcard else "该文件应被清理。"),
            technical_detail=f"路径：{first}\n内容：\n{body[:600]}",
            impact="在不支持 Flash 的环境中影响有限，但说明资产与配置未清理，"
                   "且通配符策略在残留的旧客户端上仍可被利用读取数据。",
            reproduction=f"curl -s {urljoin(ctx.target_url, first)}",
            remediation="删除该策略文件；建立配置清理机制，定期排查过时组件残留。",
            compliance="ISO 27001 A.8.8",
            evidence=[finding_evidence("response", body[:800], first)],
            grading_basis="策略文件实测存在，现代环境危害有限，定中危 / 低危",
        ))

    note = (f"策略文件命中 {len(hits)} 个；前端是否引用 Flash：{'是' if has_swf else '否'}")
    return found(note, findings, probes=4, evidence_kind="策略文件实测")


# ======================================================================
# WSTG-CLNT-09 点击劫持
# ======================================================================
@make_auto("WSTG-CLNT-09", name="点击劫持防护核查", tool="响应头实测",
           risk=RISK_SAFE, evidence_kind="防护头实测",
           detector_ref="checks/client.py:clnt09")
def clnt09(ctx: DetectorContext):
    findings = []
    xfo = ctx.header("x-frame-options")
    csp = ctx.header("content-security-policy")
    frame_ancestors = ""
    m = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
    if m:
        frame_ancestors = m.group(1).strip()

    protected = False
    if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        protected = True
    if frame_ancestors and frame_ancestors.strip() not in ("'none'", "*"):
        protected = True
    if frame_ancestors.strip() == "*":
        protected = False

    if not protected:
        findings.append(make_finding(
            "WSTG-CLNT-09", "未配置有效的点击劫持防护",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("页面可以被任意网站用 iframe 嵌入。"
                         "攻击者可以把自己的页面叠在目标页面之上，"
                         "让用户在以为点击自己页面的情况下，实际点到了目标系统的按钮。"),
            technical_detail=(f"X-Frame-Options：{xfo or '缺失'}\n"
                              f"CSP frame-ancestors：{frame_ancestors or '缺失'}"),
            impact=("可诱导已登录用户执行敏感操作：确认支付、授权、删除数据、"
                    "修改安全设置。整个过程用户只看到诱饵页面，"
                    "目标页面被设为透明叠在上层。"),
            reproduction=("构造一个包含 <iframe src=\"目标地址\"> 的页面并打开，"
                          "观察目标页面是否正常嵌入显示。"),
            remediation=("响应头二选一（推荐同时配置）：\n"
                         "X-Frame-Options: DENY\n"
                         "Content-Security-Policy: frame-ancestors 'none'\n"
                         "若确需被嵌入，使用 frame-ancestors 白名单指定具体来源。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-1021",
            evidence=[finding_evidence("header", f"XFO={xfo or '缺失'}；frame-ancestors={frame_ancestors or '缺失'}",
                                       "点击劫持防护头")],
            grading_basis="防护头经实测缺失，定中危",
        ))

    note = (f"X-Frame-Options={xfo or '缺失'}；CSP frame-ancestors="
            f"{frame_ancestors or '缺失'}；防护{'已配置' if protected else '缺失'}")
    return found(note, findings, probes=1, evidence_kind="防护头实测")


# ======================================================================
# WSTG-CLNT-10 WebSocket
# ======================================================================
@make_auto("WSTG-CLNT-10", name="WebSocket 安全性核查", tool="前端分析 + 握手实测",
           risk=RISK_STANDARD, evidence_kind="WS 端点与握手实测",
           detector_ref="checks/client.py:clnt10")
def clnt10(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    ws_endpoints = set(re.findall(r"[\"'](wss?://[^\"'\s]+)[\"']", blobs))
    for m in re.finditer(r"[\"'](/[^\"'\s]*(?:ws|socket|websocket|sockjs|stomp)[^\"'\s]*)[\"']",
                         blobs, re.I):
        ws_endpoints.add(m.group(1))

    if not ws_endpoints:
        return no_target_outcome(ctx, "WebSocket 端点", probes=1, evidence_kind="WS 端点探测")

    findings = []
    probes = 0
    endpoints = sorted(ws_endpoints)[:5]
    insecure = [e for e in endpoints if str(e).startswith("ws://")]
    # 通过 HTTP 升级探测判断端点是否可达、是否校验 Origin
    import requests
    for ep in endpoints[:3]:
        url = ep
        if str(ep).startswith("/"):
            url = ctx.target_url.replace("https://", "wss://").replace("http://", "ws://") + str(ep)
        http_url = str(url).replace("wss://", "https://").replace("ws://", "http://")
        probes += 1
        try:
            ctx._client._throttle()
            r = requests.get(http_url, timeout=min(ctx._client.timeout, 10), verify=False,
                             allow_redirects=False,
                             headers={**dict(ctx._client.session.headers),
                                      "Upgrade": "websocket",
                                      "Connection": "Upgrade",
                                      "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                      "Sec-WebSocket-Version": "13",
                                      "Origin": "https://aiscan-probe.invalid"})
            if r.status_code == 101:
                findings.append(make_finding(
                    "WSTG-CLNT-10", "WebSocket 握手未校验 Origin（接受任意来源）",
                    ctx.target_name, endpoint=http_url, method="GET", param="Origin",
                    severity="中危", confidence="High", evidence_level="A",
                    description=("使用任意 Origin 发起 WebSocket 握手时，"
                                 "服务端返回 101（协议切换成功）。"
                                 "说明 WebSocket 连接不校验来源，"
                                 "且不会受同源策略与 CORS 保护。"),
                    technical_detail=(f"握手地址：{http_url}\n"
                                      f"Origin：https://aiscan-probe.invalid\n"
                                      f"响应：HTTP 101 Switching Protocols"),
                    impact=("攻击者页面可直接与目标建立 WebSocket 连接，"
                            "若鉴权仅依赖 Cookie，浏览器会自动携带，"
                            "攻击者即可读取或发送该用户的消息（跨站 WebSocket 劫持）。"),
                    reproduction=(f"curl -si -N -H 'Upgrade: websocket' -H 'Connection: Upgrade' "
                                  f"-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "
                                  f"-H 'Sec-WebSocket-Version: 13' -H 'Origin: https://evil.example' "
                                  f"'{http_url}'"),
                    remediation=("① WebSocket 握手时校验 Origin 白名单，不合法直接拒绝；"
                                 "② 连接鉴权不依赖 Cookie，改用一次性 token；"
                                 "③ 强制使用 wss://；"
                                 "④ 对消息做服务端授权校验（不信任连接已认证即拥有全部权限）。"),
                    compliance="等保2.0 安全计算环境-访问控制 / CWE-1385",
                    evidence=[finding_evidence("response",
                                               f"Origin: {r.headers.get('Origin', '')}\n"
                                               f"HTTP {r.status_code}", "WS 握手响应")],
                    grading_basis="实测任意 Origin 握手成功，定中危",
                ))
                break
        except Exception:  # noqa: BLE001
            continue

    if insecure:
        findings.append(make_finding(
            "WSTG-CLNT-10", f"WebSocket 使用明文 ws:// 协议（{len(insecure)} 个）",
            ctx.target_name, endpoint=str(insecure[0]),
            severity="中危", confidence="High", evidence_level="A",
            description="前端使用 ws:// 建立 WebSocket 连接，通信内容不加密。",
            technical_detail="明文端点：\n" + "\n".join(f"  · {e}" for e in insecure),
            impact="同网络内的攻击者可读取并篡改 WebSocket 通信内容，"
                   "若其中包含业务数据或令牌，等同于数据泄露。",
            reproduction=f"在浏览器网络面板中查看 WebSocket 连接协议。",
            remediation="全部改用 wss://，并在服务端关闭明文 ws 端口。",
            compliance="等保2.0 安全通信网络-通信传输",
            evidence=[finding_evidence("file", str(insecure), "明文 WS 端点")],
            grading_basis="实测前端使用明文协议，定中危",
        ))

    note = (f"识别 WebSocket 端点 {len(ws_endpoints)} 个，握手探测 {probes} 次，"
            f"明文端点 {len(insecure)} 个")
    return found(note, findings, probes=probes, evidence_kind="WS 端点与握手实测")


# ======================================================================
# WSTG-CLNT-11 Web 消息（postMessage）
# ======================================================================
@make_auto("WSTG-CLNT-11", name="postMessage 安全性检测", tool="前端产物静态分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt11")
def clnt11(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + list(ctx.js_result.get("inline_scripts") or []))
    findings = []
    if not blobs:
        return ok("未采集到前端脚本，无法分析 postMessage", probes=1, evidence_kind="无 JS 产物")

    listeners = re.findall(r"addEventListener\s*\(\s*[\"']message[\"']\s*,\s*[^)]*\)", blobs, re.I)
    wildcard_posts = re.findall(r"postMessage\s*\([^)]*,\s*[\"']\*[\"']\s*\)", blobs, re.I)
    has_origin_check = bool(re.search(r"(event\.origin|e\.origin|\.origin\s*===|"
                                      r"\.origin\s*==|origin\s*!==)", blobs, re.I))

    issues = []
    if listeners and not has_origin_check:
        issues.append((f"监听了 {len(listeners)} 处 message 事件，但未发现 origin 校验",
                       "任意网站都能向本页面发送消息并被处理"))
    if wildcard_posts:
        issues.append((f"{len(wildcard_posts)} 处 postMessage 使用通配符目标源（'*'）",
                       "消息可被任意来源读取，若含敏感数据即泄露"))
    if re.search(r"(?:event|e)\.data[^;]{0,80}(innerHTML|eval|document\.write)",
                 blobs, re.I):
        issues.append(("message 数据直接进入危险写入点", "可导致 DOM 型 XSS"))

    if issues:
        findings.append(make_finding(
            "WSTG-CLNT-11", f"postMessage 使用存在 {len(issues)} 处风险",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Medium", evidence_level="B",
            description=("页面使用 postMessage 跨窗口通信，但缺少来源或目标的严格限制。"),
            technical_detail="发现的问题：\n" + "\n".join(f"  · {n}\n    {w}" for n, w in issues),
            impact=("① 未校验 origin → 任意恶意页面可向本页面注入消息，"
                    "若消息内容被用于执行业务动作，等于被远程操控；"
                    "② 通配符目标源 → 敏感消息可被任意窗口读取；"
                    "③ 消息进入危险写入点 → DOM 型 XSS。"),
            reproduction="构造一个指向目标页面的 iframe 并向其 postMessage，观察是否被处理。",
            remediation=("① 接收端严格校验 event.origin 白名单；"
                         "② 发送端指定具体目标源，不使用 '*'；"
                         "③ 消息体做结构与字段校验，不直接写入 DOM。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-345",
            evidence=[finding_evidence("file", str(issues), "postMessage 风险")],
            grading_basis="静态分析确认缺少来源校验，未实证可被利用，按 B 级定中危",
        ))

    note = (f"message 监听 {len(listeners)} 处；通配符发送 {len(wildcard_posts)} 处；"
            f"origin 校验：{'有' if has_origin_check else '未见'}")
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-CLNT-12 浏览器存储
# ======================================================================
@make_auto("WSTG-CLNT-12", name="浏览器存储使用审查", tool="前端产物静态分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt12")
def clnt12(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    findings = []
    if not blobs:
        return ok("未采集到前端产物，无法审查浏览器存储使用", probes=1, evidence_kind="无 JS 产物")

    sensitive = []
    for m in re.finditer(r"(?:localStorage|sessionStorage|indexedDB)\s*"
                         r"(?:\.setItem\s*\(\s*)?[\"']([^\"']+)[\"']", blobs, re.I):
        key = m.group(1)
        if re.search(r"(token|auth|session|jwt|password|pwd|secret|key|user|role|"
                     r"permission|credit|balance|idcard|phone|mobile|email)", key, re.I):
            sensitive.append(key)
    sensitive = sorted(set(sensitive))

    # 检查是否用了 Cookie 存敏感信息的替代方案
    long_term = bool(re.search(r"localStorage", blobs, re.I))
    stores_plain = bool(re.search(r"localStorage\.setItem\s*\(\s*[\"'][^\"']*(?:password|pwd)",
                                  blobs, re.I))

    if sensitive or stores_plain:
        findings.append(make_finding(
            "WSTG-CLNT-12", f"浏览器存储中存在敏感数据（{len(sensitive)} 个键）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="高危" if stores_plain else "中危",
            confidence="High", evidence_level="A",
            description=("前端把认证令牌或个人信息写入了浏览器存储。"
                         "localStorage 中的数据对同源的所有脚本完全可见，"
                         "不受 HttpOnly 保护。"),
            technical_detail=("存储键名：\n" + "\n".join(f"  · {k}" for k in sensitive[:20])
                              + ("\n\n检测到前端直接存储口令的代码。" if stores_plain else "")
                              + f"\n\n使用 localStorage：{'是' if long_term else '否'}"),
            impact=("任何一次 XSS（含第三方组件引入的）都可以一行代码读走这些数据，"
                    "实现长期账号接管；"
                    "存储的个人信息在共用设备上会被后续使用者读取。"),
            reproduction="浏览器控制台执行 localStorage 与 sessionStorage，检查键值内容。",
            remediation=("① 认证令牌改用 HttpOnly + Secure Cookie；"
                         "② 前端不存储口令；"
                         "③ 必须缓存的数据只放非敏感展示字段，并在登出时清除；"
                         "④ 使用 sessionStorage 替代 localStorage 缩短存活时间。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / PIPL 第 51 条",
            evidence=[finding_evidence("file", f"存储键：{sensitive[:20]}", "浏览器存储键名")],
            grading_basis="实测前端写入敏感数据到浏览器存储，定高危 / 中危",
        ))

    note = (f"浏览器存储敏感键 {len(sensitive)} 个"
            + (f"：{', '.join(sensitive[:8])}" if sensitive else ""))
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-CLNT-13 跨站脚本包含（XSSI）
# ======================================================================
@make_auto("WSTG-CLNT-13", name="XSSI 跨站脚本包含检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="回调参数实测",
           detector_ref="checks/client.py:clnt13")
def clnt13(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])

    # 从前端产物里找 JSONP 形态的调用
    jsonp_calls = set(re.findall(r"[\"']([^\"']*[?&](?:callback|cb|jsonp)=[^\"']*)",
                                 blobs, re.I))
    endpoints = [ctx.target_url]
    for p in ("api/user", "api/data", "api/list", "data.json", "api/v1/list"):
        pr = probe_or_none(ctx, p)
        if pr is not None and getattr(pr, "status", 0) == 200:
            endpoints.append(getattr(pr, "final_url", "") or urljoin(ctx.target_url, p))

    from urllib.parse import urlparse, parse_qs, urlencode
    hit = None
    for ep in (list(jsonp_calls)[:3] + endpoints[:4]):
        url = ep if str(ep).startswith("http") else urljoin(ctx.target_url, str(ep).lstrip("/"))
        if ctx.domain not in url:
            continue
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs["callback"] = ["aiscanCallback9z8y7x"]
        test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
        probes += 1
        try:
            pr = ctx.get(test_url)
        except Exception:  # noqa: BLE001
            continue
        body = (getattr(pr, "body_snippet", "") or "").strip()
        if body.startswith("aiscanCallback9z8y7x(") or \
                re.match(r"^[A-Za-z_$][\w$]*\s*\(\s*[\{\[]", body):
            hit = (test_url, getattr(pr, "status", 0), body[:300])
            break

    if hit:
        url, st, frag = hit
        findings.append(make_finding(
            "WSTG-CLNT-13", "存在 JSONP 接口，可被跨站读取数据",
            ctx.target_name, endpoint=url, method="GET", param="callback",
            severity="中危", confidence="High", evidence_level="A",
            description=("该接口把响应包装在回调函数名里返回（JSONP）。"
                         "JSONP 不使用 CORS，浏览器会直接执行返回的脚本，"
                         "因此任何网站都能读取这个接口的数据。"),
            technical_detail=(f"接口：{url}\n响应状态：HTTP {st}\n响应片段：{frag}"),
            impact=("攻击者页面可以通过 <script src> 加载该接口，"
                    "浏览器会自动携带用户 Cookie，"
                    "返回的数据会被传给攻击者定义的回调函数，从而实现跨站读取。"),
            reproduction=f"curl -s '{url}'",
            remediation=("① 废弃 JSONP，改用 CORS（严格白名单）或后端代理；"
                         "② 必须保留时，对 Referer 做白名单校验并加令牌；"
                         "③ 在响应前加 `)]}',` 前缀并禁止 Content-Type 猜测"
                         "（`X-Content-Type-Options: nosniff`）作为缓解。"),
            compliance="等保2.0 安全计算环境-访问控制 / CWE-346",
            evidence=[finding_evidence("response", frag, "JSONP 响应")],
            grading_basis="实测接口支持 JSONP 回调，可被跨站读取，定中危",
        ))

    note = (f"发现前端 JSONP 调用 {len(jsonp_calls)} 个；回调探测 {probes} 次，"
            f"{'确认存在 JSONP' if hit else '未确认 JSONP'}")
    return found(note, findings, probes=probes, evidence_kind="回调参数实测")


# ======================================================================
# WSTG-CLNT-14 反向标签劫持
# ======================================================================
@make_auto("WSTG-CLNT-14", name="反向标签劫持检测", tool="页面与前端产物分析",
           risk=RISK_SAFE, evidence_kind="链接属性实测",
           detector_ref="checks/client.py:clnt14")
def clnt14(ctx: DetectorContext):
    corpus = ctx.baseline_body + "\n" + "\n".join(ctx.js_result.get("bodies") or [])
    findings = []
    if not corpus.strip():
        return ok("无可分析内容", probes=1, evidence_kind="无内容")

    blanks = re.findall(r"<a\b[^>]*target\s*=\s*[\"']_blank[\"'][^>]*>", corpus, re.I)
    risky = []
    for tag in blanks:
        has_noopener = re.search(r"rel\s*=\s*[\"'][^\"']*noopener", tag, re.I)
        has_noreferrer = re.search(r"rel\s*=\s*[\"'][^\"']*noreferrer", tag, re.I)
        if not (has_noopener and has_noreferrer):
            risky.append(tag[:200])

    # 动态创建 target=_blank 的情况
    dyn = re.findall(r"target\s*[:=]\s*[\"']_blank[\"']", corpus, re.I)
    if risky or (dyn and not re.search(r"noopener", corpus, re.I)):
        findings.append(make_finding(
            "WSTG-CLNT-14", f"存在未防护的 target=_blank 链接（{max(len(risky), len(dyn))} 处）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="B",
            description=("页面中的链接在新窗口打开时没有加 rel=\"noopener noreferrer\"。"
                         "新打开的页面可以通过 window.opener 访问并改写原页面地址。"),
            technical_detail=("未防护的链接标签示例：\n"
                              + "\n".join(f"  {t}" for t in risky[:5])
                              + (f"\n\n动态设置 target=_blank 处数：{len(dyn)}" if dyn else "")),
            impact=("若链接指向攻击者控制的站点（用户生成内容中的外链、"
                    "可被篡改的友情链接），该站点可把原页面重定向到钓鱼页，"
                    "由于发生在同一标签页，用户较难察觉。"),
            reproduction="点击相关外链后，在新窗口执行 window.opener.location 观察是否能改写原页面。",
            remediation=("所有 target=\"_blank\" 的链接补上 rel=\"noopener noreferrer\"；"
                         "或使用 JS 打开窗口时显式设置 opener=null。"),
            compliance="CWE-1022",
            evidence=[finding_evidence("response", "\n".join(risky[:5]) or str(dyn), "未防护链接")],
            grading_basis="链接属性缺失经实测确认，危害中等，定低危",
        ))

    note = (f"target=_blank 链接 {len(blanks)} 处，其中未加 noopener/noreferrer "
            f"{len(risky)} 处；动态设置 {len(dyn)} 处")
    return found(note, findings, probes=1, evidence_kind="链接属性实测")


# ======================================================================
# WSTG-CLNT-15 客户端模板注入
# ======================================================================
@make_auto("WSTG-CLNT-15", name="客户端模板注入检测", tool="前端产物静态分析",
           risk=RISK_STANDARD, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/client.py:clnt15")
def clnt15(ctx: DetectorContext):
    blobs = list(ctx.js_result.get("bodies") or []) + list(ctx.js_result.get("inline_scripts") or [])
    text = "\n".join(b for b in blobs if b)
    if not text:
        return ok("未采集到前端脚本，无法分析客户端模板", probes=1, evidence_kind="无 JS 产物")

    hits = []
    frameworks = []
    if re.search(r"(angular|ng-app|ng-controller|\[\[|\{\{)", text, re.I):
        frameworks.append("Angular")
    if re.search(r"(v-html|v-text|createApp|Vue\.)", text, re.I):
        frameworks.append("Vue")
    if re.search(r"(react|jsx|createElement)", text, re.I):
        frameworks.append("React")
    if re.search(r"(template\s*:|compile\s*\(|<%=\s*)", text, re.I):
        frameworks.append("通用模板引擎")

    # 客户端模板 + 可控数据 = 客户端模板注入（CSTI）
    if re.search(r"(compile|template)\s*\([^)]*(?:location|param|query|hash|input|decodeURIComponent)",
                 text, re.I):
        hits.append("模板编译函数接收了地址栏 / 输入来源的数据")
    if re.search(r"\{\{[^}]*\}\}[^;]{0,40}(?:location|param|query)", text, re.I):
        hits.append("模板表达式与地址栏数据出现在同一表达式中")
    if re.search(r"(innerHTML|textContent)\s*=\s*[^;]*(?:compile|render|template)", text, re.I):
        hits.append("模板渲染结果直接写入 DOM")

    findings = []
    if hits:
        findings.append(make_finding(
            "WSTG-CLNT-15", f"客户端模板注入风险（{len(hits)} 处）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Low", evidence_level="C",
            description=("前端把可控数据交给模板引擎编译。"
                         "若模板引擎支持表达式求值（Angular 的 {{}}、"
                         "Vue 的模板编译等），注入表达式可被执行。"),
            technical_detail=(f"识别到的前端框架：{', '.join(frameworks) or '未识别'}\n"
                              "命中模式：\n" + "\n".join(f"  · {h}" for h in hits)),
            impact=("客户端模板注入可在受害者浏览器中执行表达式，"
                    "读取页面数据；多数情况下危害低于 DOM XSS，"
                    "但在 AngularJS 沙箱逃逸后等同于 XSS。"),
            reproduction="向相关参数注入模板表达式（如 {{7*7}} 或 Angular 沙箱逃逸 payload），观察是否被求值。",
            remediation=("① 使用模板引擎的插值语法（自动转义）而非动态编译；"
                         "② Angular 使用 AOT 编译并避免 $compile 处理外部数据；"
                         "③ 升级到不再受沙箱逃逸影响的框架版本。"),
            compliance="CWE-1336",
            evidence=[finding_evidence("file", str(hits), "客户端模板注入模式")],
            grading_basis="仅静态模式匹配，证据级别 C，不作为漏洞定级，列入待确认",
        ))

    note = (f"识别前端框架：{', '.join(frameworks) or '未识别'}；"
            f"命中模板注入模式 {len(hits)} 处")
    return found(note, findings, probes=1, evidence_kind="前端产物静态分析")
