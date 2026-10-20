# -*- coding: utf-8 -*-
"""
WSTG-INFO 信息收集（10 项）
==========================
这一类的产出多数是「信息级」，但它们是后面所有检查的输入：
入口点、参数、框架、架构判定都从这里出去。

判定原则：只有「暴露了本不该暴露的东西」才产出发现。
单纯识别出服务器是 Nginx，不算漏洞。
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from engine.checks import net
from engine.checks.base import (
    ADMIN_PATHS, API_DOC_PATHS, CREDENTIAL_PATTERNS, INTERNAL_ADDR_PATTERNS,
    META_FILES, finding_evidence, code_scan, extract_params, find_forms,
    is_real_hit, ok, found, probe_or_none, pending,
)
from engine.registry import (
    RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
)


# ======================================================================
# WSTG-INFO-01 搜索引擎信息泄露侦察
# ======================================================================
@make_auto("WSTG-INFO-01", name="搜索引擎与抓取协议侦察", tool="DuckDuckGo + robots.txt",
           risk=RISK_SAFE, evidence_kind="公开索引与 robots 规则实测",
           detector_ref="checks/recon.py:info01")
def info01(ctx: DetectorContext):
    findings = []
    probes = 0

    robots = probe_or_none(ctx, "robots.txt")
    probes += 1
    disallow: list[str] = []
    if robots is not None and getattr(robots, "status", 0) == 200:
        body = getattr(robots, "body_snippet", "") or ""
        disallow = [m.group(1).strip() for m in
                    re.finditer(r"(?im)^\s*Disallow\s*:\s*(\S+)", body)]
        sensitive = [d for d in disallow
                     if re.search(r"(admin|manage|internal|backup|config|test|api|debug|"
                                  r"private|secret|db|sql|log|tmp|old|dev|uat|stage)", d, re.I)]
        if sensitive:
            findings.append(make_finding(
                "WSTG-INFO-01",
                f"robots.txt 主动暴露 {len(sensitive)} 个敏感路径",
                ctx.target_name,
                endpoint=urljoin(ctx.target_url, "robots.txt"),
                severity="低危", confidence="High", evidence_level="A",
                description=("站点的 robots.txt 把不希望被搜索引擎收录的路径逐条列出，"
                             "这份清单本身就是一张「这里有什么」的目录，"
                             "攻击者无需扫描即可直接访问这些路径。"),
                technical_detail="robots.txt 中披露的敏感条目：\n"
                                 + "\n".join(f"Disallow: {d}" for d in sensitive[:25]),
                impact=("攻击者可直接获得后台、备份、内部接口的路径清单，"
                        "跳过目录爆破环节。若这些路径未做额外访问控制，"
                        "等于把管理入口的地址公开。"),
                reproduction=f"curl -s {urljoin(ctx.target_url, 'robots.txt')}",
                remediation=("不要在 robots.txt 中列出敏感路径；"
                             "robots.txt 是公开文件，只应用于屏蔽与安全无关的抓取。"
                             "真正需要保护的路径应由服务端鉴权控制，而非依赖不被收录。"),
                compliance="ISO 27001 A.8.9 / 等保2.0 安全计算环境-访问控制",
                evidence=[finding_evidence("response", body[:1500], "robots.txt 内容")],
                grading_basis="路径清单可直接访问，未实证数据获取，定低危",
            ))

    # 公开索引（第三方搜索引擎，验证是否已有敏感页面被收录）
    indexed = 0
    try:
        html = net.http_text(
            "https://html.duckduckgo.com/html/?q=" + f"site:{ctx.domain}",
            timeout=18)
        hits = set(re.findall(r'uddg=([^"&]+)', html))
        indexed = len(hits)
    except Exception:  # noqa: BLE001
        indexed = 0
    probes += 1

    note = (f"robots.txt {'已获取并解析' if robots is not None else '不可达'}，"
            f"披露敏感路径 {len(disallow)} 条；"
            f"第三方索引查询{'返回 ' + str(indexed) + ' 条结果' if indexed else '未取得结果（搜索引擎可能限流）'}")
    return found(note, findings, probes=probes, evidence_kind="robots.txt + 公开索引")


# ======================================================================
# WSTG-INFO-02 Web 服务器指纹识别
# ======================================================================
@make_auto("WSTG-INFO-02", name="Web 服务器指纹与版本披露", tool="响应头 + TCP 横幅",
           risk=RISK_SAFE, evidence_kind="响应头实测",
           detector_ref="checks/recon.py:info02")
def info02(ctx: DetectorContext):
    findings = []
    h = ctx.root_headers
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    aspnet = h.get("x-aspnet-version", "") or h.get("x-aspnetmvc-version", "")
    gen = h.get("x-generator", "")

    leaked = []
    for label, val in (("Server", server), ("X-Powered-By", powered),
                       ("X-AspNet-Version", aspnet), ("X-Generator", gen)):
        if not val:
            continue
        if re.search(r"\d+\.\d+", val) or re.search(
                r"(nginx|apache|iis|tomcat|jetty|openresty|gunicorn|uwsgi|express|php|"
                r"asp\.net|spring)", val, re.I):
            leaked.append(f"{label}: {val}")

    if leaked:
        findings.append(make_finding(
            "WSTG-INFO-02", f"服务端软件与版本号通过响应头暴露（{len(leaked)} 处）",
            ctx.target_name, endpoint=ctx.target_url, method="GET",
            severity="低危", confidence="High", evidence_level="A",
            description=("服务器在响应头里直接回报了自己是什么软件、什么版本。"
                         "攻击者可以拿着这个版本号去公开漏洞库比对，"
                         "直接筛出该版本已知的漏洞，不需要做任何猜测。"),
            technical_detail="暴露的响应头：\n" + "\n".join(leaked),
            impact=("把「该打哪个漏洞」的答案直接交给攻击者。"
                    "若该版本存在公开 EXP 的漏洞，攻击成本从「需要探测」降到「照着打」。"),
            reproduction=f"curl -sI {ctx.target_url} | grep -iE 'server|powered-by|aspnet|generator'",
            remediation=("在 Web 服务器与反向代理层关闭版本号输出："
                         "Nginx 用 `server_tokens off`；"
                         "Apache 用 `ServerTokens Prod` + `ServerSignature Off`；"
                         "IIS 移除自定义头；"
                         "PHP 关闭 `expose_php`；"
                         "应用框架关闭 X-Powered-By 与 X-AspNet-Version。"),
            compliance="ISO 27001 A.8.8 / 等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("header", "\n".join(leaked), "版本披露响应头")],
            grading_basis="仅泄露版本信息，未实证可利用性，定低危",
        ))

    note = (f"Server={server or '未披露'}；"
            f"版本披露 {len(leaked)} 处"
            + ("；服务器已隐藏版本号" if not leaked else ""))
    return found(note, findings, probes=1, evidence_kind="响应头实测")


# ======================================================================
# WSTG-INFO-03 Web 服务器元文件信息泄露审查
# ======================================================================
@make_auto("WSTG-INFO-03", name="元文件信息泄露审查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="元文件实际内容",
           detector_ref="checks/recon.py:info03")
def info03(ctx: DetectorContext):
    findings = []
    res = ctx.probe_many(META_FILES)
    hits = {p: pr for p, pr in res.items() if is_real_hit(ctx, pr, min_len=10)}

    for path, probe in hits.items():
        body = getattr(probe, "body_snippet", "") or ""
        if path.endswith("security.txt") and re.search(
                r"(mailto:|Contact:|tel:|[a-z0-9._%+-]+@[a-z0-9.-]+)", body, re.I):
            findings.append(make_finding(
                "WSTG-INFO-03", "security.txt 暴露内部联系人与流程信息",
                ctx.target_name, endpoint=getattr(probe, "final_url", "") or path,
                severity="信息", confidence="High", evidence_level="A",
                description=("站点遵守 RFC 9116 提供了 security.txt，其中包含安全联系人与"
                             "漏洞报告流程。这本身是规范做法，但若其中含内部邮箱、"
                             "内部工单系统地址或组织架构信息，会为钓鱼与社工提供素材。"),
                technical_detail=f"路径：{path}\n内容片段：\n{body[:800]}",
                impact="为针对性钓鱼邮件、假冒漏洞报送提供可直接使用的联系人信息与话术素材。",
                reproduction=f"curl -s {urljoin(ctx.target_url, path)}",
                remediation=("security.txt 中只保留对外公开的安全邮箱（建议用角色邮箱如"
                             " security@ 而非个人邮箱），不要写入内部系统链接、"
                             "内部分机号或人员姓名。"),
                compliance="ISO 27001 A.5.34 / PIPL 第 51 条",
                evidence=[finding_evidence("response", body[:1200], path)],
                grading_basis="仅信息暴露，未造成数据或权限损失",
            ))
        if path in ("sitemap.xml", "sitemap_index.xml") and len(body) > 500:
            urls = re.findall(r"<loc>([^<]+)</loc>", body)
            internal = [u for u in urls if re.search(
                r"(admin|internal|test|uat|dev|stage|backup|private|api/)", u, re.I)]
            if internal:
                findings.append(make_finding(
                    "WSTG-INFO-03", f"站点地图暴露 {len(internal)} 个敏感路径",
                    ctx.target_name, endpoint=getattr(probe, "final_url", "") or path,
                    severity="低危", confidence="High", evidence_level="A",
                    description="sitemap.xml 列出了站点认为是「内容」的全部地址，其中混入了管理、测试、备份类路径。",
                    technical_detail="\n".join(internal[:20]),
                    impact="攻击者拿到完整路径清单，省去目录爆破，直接定位高价值入口。",
                    reproduction=f"curl -s {urljoin(ctx.target_url, path)} | grep -oE '<loc>[^<]+'",
                    remediation="站点地图只输出面向公网的内容页；管理、测试、备份路径不进入 sitemap，并由服务端鉴权保护。",
                    compliance="ISO 27001 A.8.9",
                    evidence=[finding_evidence("response", "\n".join(internal[:20]), "sitemap 敏感条目")],
                    grading_basis="路径清单泄露，未实证访问，定低危",
                ))

    note = (f"探测 {len(META_FILES)} 个元文件，命中 {len(hits)} 个"
            + (f"：{', '.join(list(hits)[:6])}" if hits else "（均不存在或为自定义 404 页）"))
    return found(note, findings, probes=len(META_FILES), evidence_kind="元文件实际内容")


# ======================================================================
# WSTG-INFO-04 攻击面识别
# ======================================================================
@make_auto("WSTG-INFO-04", name="攻击面识别（DNS / 端口 / 子域）", tool="公共 DNS + TCP + crt.sh",
           risk=RISK_STANDARD, evidence_kind="DNS 与端口实测",
           detector_ref="checks/recon.py:info04",
           # DNS / TCP / crt.sh 三路取证，都不经被测应用；且它产出的
           # info04_ip / info04_ports 是 EXT-CL-02/09 的前置数据，必须一起放行。
           needs_app=False)
def info04(ctx: DetectorContext):
    # 本项不产出自己的发现（端口定级归 EXT-CL-02），因此没有 findings 列表。
    probes = 0

    recs = {}
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        recs[rt] = net.dns_records(ctx.domain, rt)
        probes += 1

    ip = (recs["A"] or [""])[0]
    if not ip:
        # 裸 IP 目标回退：DNS 永远解析不出 A 记录，但目标自身就是地址。
        # 不回退的后果是**假阴性**——端口扫描被整段跳过，本项最终写
        # 「端口探测 0 个，开放 0 个」并被判「通过」：报告说攻击面识别没问题，
        # 而真实开放的端口（可能含数据库 / 中间件端口）一个都没被看到。
        ip = net.as_ip_literal(ctx.domain)
    open_ports: dict[int, bool] = {}
    signal_ok, signal_why = True, ""
    if ip:
        open_ports = net.scan_ports_cached(ip, getattr(ctx, "profile_key", "standard"))
        probes += len(open_ports)
        # 对照实验：本机到目标的 TCP 连通信号是否可信。
        # 沙箱代理 / 安全客户端会让**每个端口**都表现为开放，
        # 不做这个对照就会写出「公网可达：开放了数据库端口」这种误报。
        signal_ok, signal_why = net.tcp_signal_trustworthy(ip)

    # 必须同时满足「端口在这一类里」**且**「探测结果是开放的」。
    # 只按端口号过滤会把 21 / 3306 / 6379 这些**关闭着**的端口也算进
    # 「公网暴露」，等于凭端口号猜结论 —— 那是纯粹的误报来源。
    dangerous = {p: v for p, v in open_ports.items()
                 if v and p in (21, 23, 445, 3306, 6379, 27017, 9200, 11211,
                                2375, 3389, 5900, 10250, 1521, 1433, 5432, 2181)}
    subs = net.crtsh_subdomains(ctx.domain) if ip else []
    probes += 1

    # 结果先落缓存 —— 后面的 EXT-CL-02 依赖 info04_ip，早退也不能漏掉。
    ctx._cache["info04_ports"] = open_ports
    ctx._cache["info04_subs"] = subs
    ctx._cache["info04_ip"] = ip
    ctx._cache["info04_dns"] = recs
    ctx._cache["info04_signal_ok"] = signal_ok

    # ===== 对照实验未通过 → 端口连通性整体不可采信 =====
    # 这时既不能报「开放了危险端口」（假象），也不能报「没有开放端口」
    # （同样是假象）。两项都判不了，只能如实报待确认。
    if ip and not signal_ok:
        return pending(
            f"{signal_why}因此**本项的端口暴露部分无法判定**："
            f"既不报「存在开放端口」，也不报「无开放端口」。"
            f"DNS 记录与证书透明度枚举本身已完成"
            f"（A {len(recs['A'])}、NS {len(recs['NS'])}、子域 {len(subs)} 个），"
            f"但采集到的端口结论不作为任何风险判定依据。"
            f"请从可信出口网络复测端口暴露。",
            probes=probes, evidence_kind="DNS + 端口（TCP 对照实验未通过）")

    # 可达范围必须先判定再下结论。「端口能连通」只说明从本节点能连上，
    # 解析到私网地址时把它写成「公网暴露」就是拿内网可达冒充公网暴露。
    # 这里仍然要判定：内网地址的端口结论只能标「内网可见（非公网暴露）」。
    scope, _, _scope_why = net.reachability_of(ip)

    # ⚠️ 这里**刻意不产出端口类发现**。
    # 端口暴露的风险定级由 EXT-CL-02「安全组与非预期端口暴露核查」专责上报。
    # 原因：同一份报告里同一个端口（真实目标上 5432 / 9200）曾被
    # INFO-04、EXT-CL-02、EXT-DM-05 各报一次，四个发现标题几乎一样、
    # 指向同一对 IP:端口 —— 读者会把「端口个数」当成「漏洞个数」。
    # 本项保留端口扫描这个动作与结果（见下方 note 与 ctx._cache 缓存，
    # EXT-CL-02 / EXT-CL-03 都从这里取数），只把「给端口定级」这件事
    # 交给唯一出口：职责重叠处只留一个出口。
    #
    # 注意：findings 恒为空 —— 本项不再有自己的端口发现，
    # 因此它的结论是「枚举完成」而非「端口没问题」，
    # note 里必须写明风险定级去哪看，避免「通过」被读成「未见异常」。
    _open_list = sorted(p for p, v in open_ports.items() if v)
    _open_txt = "、".join(str(p) for p in _open_list) if _open_list else "无"
    note = (f"DNS 记录 {sum(len(v) for v in recs.values())} 条（A {len(recs['A'])}、"
            f"MX {len(recs['MX'])}、NS {len(recs['NS'])}、TXT {len(recs['TXT'])}）；"
            f"端口探测 {len(open_ports)} 个，开放 {len(_open_list)} 个（{_open_txt}），"
            f"其中危险端口 {len(dangerous)} 个 —— 风险定级见 EXT-CL-02"
            f"（本项只负责枚举，重复上报会让同一个端口变成多个「漏洞」）；"
            f"证书透明度枚举子域 {len(subs)} 个；可达范围 {scope}；{signal_why}")
    return ok(note, probes=probes, evidence_kind="DNS + 端口 + CT 日志")


# ======================================================================
# WSTG-INFO-05 页面内容信息泄露审查
# ======================================================================
@make_auto("WSTG-INFO-05", name="页面与前端产物信息泄露审查", tool="内置检测器 + JS 分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="页面与 JS 实际内容",
           detector_ref="checks/recon.py:info05")
def info05(ctx: DetectorContext):
    findings = []
    body = ctx.baseline_body
    blobs = [body] + list(ctx.js_result.get("inline_scripts") or []) \
        + list(ctx.js_result.get("bodies") or [])
    text = "\n".join(b for b in blobs if b)

    # 1) HTML 注释中的敏感内容
    comments = re.findall(r"<!--(.*?)-->", body, re.S)
    sensitive_comments = [c.strip()[:200] for c in comments
                          if re.search(r"(todo|fixme|hack|密码|password|账号|内部|测试环境|"
                                       r"debug|临时|todo:|账号[:：]|key[:：])", c, re.I)]
    if sensitive_comments:
        findings.append(make_finding(
            "WSTG-INFO-05", f"页面源码注释暴露 {len(sensitive_comments)} 条内部信息",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="High", evidence_level="A",
            description=("开发过程中留在页面注释里的说明被带到了生产环境。"
                         "这些注释常包含账号提示、内部地址、调试开关、待办事项，"
                         "对攻击者而言是免费的情报。"),
            technical_detail="命中的注释片段：\n" +
                             "\n".join(f"  <!--{c}-->" for c in sensitive_comments[:10]),
            impact="泄露内部系统结构、测试账号线索或未完成的入口，降低攻击者的摸底成本。",
            reproduction=f"curl -s {ctx.target_url} | grep -oE '<!--.*?-->'",
            remediation="构建流程中自动剥离 HTML 注释（前端构建开启 minify 与 removeComments）；代码评审禁止在生产模板写业务说明性注释。",
            compliance="ISO 27001 A.8.9",
            evidence=[finding_evidence("response", "\n".join(sensitive_comments[:10]), "HTML 注释")],
            grading_basis="信息泄露，未直接影响数据与权限，定低危",
        ))

    # 2) 前端产物中的凭据
    cred_hits = code_scan(ctx, CREDENTIAL_PATTERNS, scope="both")
    if cred_hits:
        findings.append(make_finding(
            "WSTG-INFO-05", f"前端产物中发现 {len(cred_hits)} 类疑似凭据",
            ctx.target_name, endpoint=ctx.target_url,
            severity="高危", confidence="Medium", evidence_level="B",
            description=("打包后的前端代码里出现了形如密钥、Token、连接串的字符串。"
                         "前端代码对所有访客可见，写在里面的凭据等于公开。"),
            technical_detail="命中的凭据类型：\n"
                             + "\n".join(f"  · {d}" for d, _ in cred_hits),
            impact=("若命中项为真实可用的云厂商密钥或数据库连接串，"
                    "持有者可直接访问对应资源，可能造成数据泄露或资源盗用。"
                    "需人工确认是否为占位符 / 示例值。"),
            reproduction=("在浏览器开发者工具中打开打包产物，"
                          "搜索 accessKey / secret / token 等关键词，或使用本项检测器输出的文件定位。"),
            remediation=("① 前端绝不放置任何服务端凭据，敏感调用一律经后端代理；"
                         "② 若不慎提交过，立即轮换该密钥；"
                         "③ 接入密钥扫描（pre-commit 钩子 + CI 阶段扫描）防止再次提交。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / ISO 27001 A.8.24",
            evidence=[finding_evidence("file", "\n".join(d for d, _ in cred_hits), "凭据类型命中")],
            grading_basis="静态匹配到凭据特征，未实证其可用性，按 B 级证据定上限中危；"
                          "报告中标为高危待人工确证时上调",
        ))

    # 3) 内网地址与内部域名
    internal = []
    for pat, desc in INTERNAL_ADDR_PATTERNS:
        if re.search(pat, text, re.I):
            internal.append(desc)
    if internal:
        findings.append(make_finding(
            "WSTG-INFO-05", f"前端产物暴露 {len(internal)} 类内部地址信息",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="High", evidence_level="A",
            description="前端代码中出现了内网 IP、内部域名或非生产环境域名，暴露了系统内部拓扑。",
            technical_detail="命中类型：" + "、".join(internal),
            impact="攻击者可据此推断内网结构与非生产环境入口，为横向移动与寻找薄弱环境提供方向。",
            reproduction="在前端产物中检索 10.x / 192.168.x / 172.16-31.x / *.internal 等模式。",
            remediation="前端构建时通过环境变量注入地址，禁止硬编码内网地址；对外发布产物统一使用公网域名。",
            compliance="ISO 27001 A.8.9",
            evidence=[finding_evidence("file", "命中类型：" + "、".join(internal), "内部地址特征")],
            grading_basis="拓扑信息泄露，定低危",
        ))

    note = (f"分析页面与 {len(ctx.js_result.get('bodies') or [])} 份前端产物："
            f"HTML 注释 {len(comments)} 条（敏感 {len(sensitive_comments)}）；"
            f"凭据特征 {len(cred_hits)} 类；内部地址 {len(internal)} 类")
    return found(note, findings, probes=1, evidence_kind="页面与 JS 内容")


# ======================================================================
# WSTG-INFO-06 应用入口点识别
# ======================================================================
@make_auto("WSTG-INFO-06", name="应用入口点识别", tool="内置检测器 + JS 分析",
           risk=RISK_SAFE, evidence_kind="页面链接与表单实测",
           detector_ref="checks/recon.py:info06")
def info06(ctx: DetectorContext):
    findings = []
    body = ctx.baseline_body
    links = set(re.findall(r'href\s*=\s*["\']([^"\']+)["\']', body, re.I))
    forms = find_forms(ctx)
    params = extract_params(ctx)
    endpoints = set()
    for js_url in (ctx.js_result.get("urls") or []):
        if isinstance(js_url, str) and re.search(r"/(api|v\d|rest|graphql|rpc)/", js_url, re.I):
            endpoints.add(js_url)

    # 入口点暴露本身是正常现象，只有「多余的入口」才提示：
    # 例如参数里出现调试 / 内部开关
    debug_params = [p for p in params
                    if re.search(r"(debug|test|admin|internal|preview|mock|dev|flag|trace)",
                                 p.get("param", ""), re.I)]
    if debug_params:
        findings.append(make_finding(
            "WSTG-INFO-06", f"前端暴露 {len(debug_params)} 个调试 / 内部用途参数",
            ctx.target_name,
            endpoint=debug_params[0].get("url", ctx.target_url),
            param=", ".join(sorted({d["param"] for d in debug_params}))[:200],
            severity="中危", confidence="Medium", evidence_level="B",
            description=("前端的请求里出现了 debug / test / mock / preview 这类开关参数。"
                         "这类参数在生产环境往往仍被服务端识别，"
                         "可能开启详细报错、跳过校验或返回未过滤数据。"),
            technical_detail="命中的参数：\n" + "\n".join(
                f"  {d['param']}  ←  {d['url'][:120]}" for d in debug_params[:15]),
            impact=("若服务端响应这些开关，攻击者可通过简单加参数获得调试信息、"
                    "绕过前端限制，或读取未发布的预览数据。"),
            reproduction="对上述 URL 逐个尝试给调试参数赋值（如 debug=1），对比响应差异。",
            remediation="生产构建中移除调试参数；服务端不响应任何用于调试的查询参数（默认忽略而非报错）。",
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("request", "\n".join(d["url"] for d in debug_params[:10]), "调试参数来源")],
            grading_basis="参数存在有技术证据，未实证服务端响应，按 B 级定中危",
        ))

    ctx._cache["info06_params"] = params
    ctx._cache["info06_forms"] = forms
    ctx._cache["info06_api_like"] = sorted(endpoints)[:80]
    note = (f"提取链接 {len(links)} 条、表单 {len(forms)} 个"
            f"（含密码字段 {sum(1 for f in forms if f['has_password'])} 个）、"
            f"带参端点 {len(params)} 个、API 形态地址 {len(endpoints)} 个；"
            f"调试类参数 {len(debug_params)} 个")
    return found(note, findings, probes=len(forms) + 2, evidence_kind="链接 / 表单 / 参数清单")


# ======================================================================
# WSTG-INFO-07 应用执行路径映射
# ======================================================================
@make_auto("WSTG-INFO-07", name="应用执行路径映射", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="路径探测实测",
           detector_ref="checks/recon.py:info07")
def info07(ctx: DetectorContext):
    """把应用实际的路径结构摸出来，供后续检查复用。

    本身是测绘动作，不产出漏洞；只有当探测到「非预期可达」的路径才提示。
    """
    candidates = []
    for p in (ctx.js_result.get("urls") or [])[:200]:
        if not isinstance(p, str):
            continue
        u = urlparse(urljoin(ctx.target_url, p))
        if u.path and u.path != "/" and ctx.domain in (u.netloc or ""):
            candidates.append(u.path.lstrip("/"))
    candidates = sorted(set(candidates))[:120]

    from engine.checks.base import scan_paths
    reachable = scan_paths(ctx, candidates) if candidates else {}

    ctx._cache["info07_paths"] = sorted(reachable)[:120]
    note = (f"从前端产物提取候选路径 {len(candidates)} 条，"
            f"实测可达 {len(reachable)} 条")
    if reachable:
        note += f"；示例：{', '.join('/' + p for p in list(reachable)[:5])}"
    return ok(note, probes=len(candidates), evidence_kind="路径探测结果")


# ======================================================================
# WSTG-INFO-08 Web 应用框架指纹识别
# ======================================================================
@make_auto("WSTG-INFO-08", name="前端框架与库指纹识别", tool="JS 组件分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/recon.py:info08")
def info08(ctx: DetectorContext):
    comps = ctx.js_result.get("components") or []
    note = (f"识别前端组件 {len(comps)} 个"
            + (f"：{', '.join((c.get('name','') + ' ' + str(c.get('version',''))).strip() for c in comps[:12])}"
               if comps else "（未从产物中识别到已知组件）"))
    # 本身不产出漏洞；版本与已知漏洞的比对见 EXT-SC-01
    return ok(note, probes=1, evidence_kind="前端组件清单")


# ======================================================================
# WSTG-INFO-09 Web 应用指纹识别
# ======================================================================
@make_auto("WSTG-INFO-09", name="应用指纹与默认特征识别", tool="响应头 / Cookie / 页面",
           risk=RISK_SAFE, evidence_kind="响应特征实测",
           detector_ref="checks/recon.py:info09")
def info09(ctx: DetectorContext):
    findings = []
    h = ctx.root_headers
    cookies = getattr(ctx.root, "cookies", []) or []
    body = ctx.baseline_body

    signals = []
    body_low = body.lower()
    sig_map = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["sites/default/files", "drupal.js"],
        "Joomla": ["/components/com_", "joomla"],
        "Spring Boot": ["whitelabel error page", "spring"],
        "Apache Shiro": ["rememberme="],
        "ThinkPHP": ["thinkphp", "/index.php?s="],
        "Vue.js": ["data-v-", "__vue__"],
        "React": ["__react", "react-dom"],
        "Next.js": ["__next_data__"],
        "Nuxt.js": ["__nuxt"],
    }
    for name, marks in sig_map.items():
        if any(m in body_low for m in marks):
            signals.append(name)
    if "rememberMe" in "".join(cookies) or "remember-me" in "".join(cookies):
        signals.append("Apache Shiro（rememberMe Cookie）")
    if h.get("x-frame-options") == "SAMEORIGIN" and "jsessionid" in "".join(cookies).lower():
        signals.append("Java Web 应用（JSESSIONID）")
    if "phpsessid" in "".join(cookies).lower():
        signals.append("PHP 应用（PHPSESSID）")
    if "asp.net_sessionid" in "".join(cookies).lower():
        signals.append("ASP.NET 应用")

    # 默认页 / 安装向导残留
    default_markers = ("welcome to nginx", "apache2 ubuntu default page",
                       "iis windows server", "it works!", "欢迎使用",
                       "tomcat", "default web site page")
    if any(mk in body_low for mk in default_markers) and len(body) < 6000:
        findings.append(make_finding(
            "WSTG-INFO-09", "站点首页为服务器默认页或安装向导残留",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("目标返回的是服务器软件自带的默认页（而非业务页面），"
                         "通常意味着站点未完成配置、被废弃，或该端口上跑着未经加固的实例。"),
            technical_detail=f"特征命中：{', '.join(mk for mk in default_markers if mk in body_low)}\n"
                             f"响应长度：{len(body)}",
            impact="这类页面常伴随默认凭据、示例程序、未关闭的管理接口，是横向移动的常见跳板。",
            reproduction=f"curl -s {ctx.target_url} | head -40",
            remediation="下线无用实例；无法下线时改为返回统一的空白页，并关闭示例程序与管理接口。",
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("response", body[:800], "默认页特征")],
            grading_basis="默认页可访问属实证，但尚未取得权限，定中危",
        ))

    ctx._cache["info09_signals"] = signals
    note = (f"识别应用指纹 {len(signals)} 项"
            + (f"：{'、'.join(signals[:8])}" if signals else "（未匹配到已知特征）")
            + f"；Cookie {len(cookies)} 个")
    return found(note, findings, probes=1, evidence_kind="应用指纹特征")


# ======================================================================
# WSTG-INFO-10 应用架构映射
# ======================================================================
@make_auto("WSTG-INFO-10", name="架构与中间层映射", tool="响应头链 + TLS",
           risk=RISK_SAFE, evidence_kind="响应头链实测",
           detector_ref="checks/recon.py:info10")
def info10(ctx: DetectorContext):
    findings = []
    h = ctx.root_headers
    chain = []
    if h.get("cf-ray"):
        chain.append("Cloudflare CDN")
    if h.get("x-cache") or h.get("via"):
        chain.append("缓存层 / CDN（X-Cache / Via）")
    if h.get("ali-swift") or h.get("x-oss-"):
        chain.append("阿里云 OSS")
    if h.get("x-amz-cf-id"):
        chain.append("AWS CloudFront")
    if h.get("x-served-by"):
        chain.append("Fastly")
    if h.get("server") and re.search(r"(nginx|openresty)", h["server"], re.I):
        chain.append("反向代理（Nginx/OpenResty）")
    if h.get("x-application-context"):
        chain.append("Java 应用容器")

    # WAF 识别：用一条无害的注入测试串，观察是否被拦截
    waf = ""
    try:
        probe = ctx.get(ctx.target_url + ("&" if "?" in ctx.target_url else "?")
                        + "aiscan_probe=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        if getattr(probe, "status", 0) in (403, 406, 419, 501):
            waf = f"疑似 WAF 拦截（返回 {probe.status}）"
        elif any(k in {k2.lower() for k2 in (probe.headers or {})}
                 for k in ("x-waf", "x-sucuri-id", "server")):
            srv = (probe.headers or {}).get("Server", "")
            if re.search(r"(cloudflare|safedog|yunsuo|waf|tengine)", srv, re.I):
                waf = f"响应头指示 WAF：{srv}"
    except Exception:  # noqa: BLE001
        waf = ""

    ctx._cache["info10_chain"] = chain
    ctx._cache["info10_waf"] = waf
    note = (f"识别中间层 {len(chain)} 层"
            + (f"：{'、'.join(chain)}" if chain else "（未识别到 CDN / 代理特征，疑似直连源站）")
            + f"；{waf or '未识别到 WAF 特征'}")
    return found(note, findings, probes=2, evidence_kind="响应头链")
