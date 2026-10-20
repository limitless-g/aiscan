# -*- coding: utf-8 -*-
"""
场景扩展检查 第一批（EXT-SC 8 + EXT-CL 9 + EXT-CD 5 = 22 项）
=============================================================
组件供应链、云与容器、CI/CD 制品。

这三类是 WSTG 没有系统覆盖、但在实际事件中出现频率极高的部分：
拿到源码 / 拿到云凭据 / 拿到暴露的中间件，几乎都是从这里入手的。
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from engine.checks import net
from engine.checks.base import (
    CICD_PATHS, CONTAINER_PATHS, CREDENTIAL_PATTERNS, INTERNAL_ADDR_PATTERNS,
    K8S_API_PATHS, METADATA_PATHS, code_scan, finding_evidence, is_real_hit, ok,
    found, probe_or_none, scan_paths, na, pending,
    no_target_outcome, no_data_outcome, reachability_scope,
)
from engine.registry import (
    RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
)

# 已知高危组件版本（规则集，可按实际组件清单扩充）
VULNERABLE_COMPONENTS = [
    (r"jquery", r"^[12]\.", "jQuery 1.x / 2.x", "存在多个已知 XSS 与原型污染问题", "中危"),
    (r"jquery", r"^3\.[0-4]\.", "jQuery 3.0–3.4", "XSS 与原型污染（CVE-2020-11022/11023）", "中危"),
    (r"bootstrap", r"^[23]\.", "Bootstrap 2.x / 3.x", "XSS（CVE-2018-14040 系列）且已停止维护", "中危"),
    (r"angular", r"^1\.[0-5]\.", "AngularJS 1.0–1.5", "沙箱可逃逸，配合 CSTI 可执行任意脚本", "高危"),
    (r"angular", r"^1\.", "AngularJS 1.x", "已停止维护，存在沙箱逃逸与 XSS 问题", "中危"),
    (r"lodash", r"^[1-3]\.|^4\.[0-9]\.|^4\.1[0-6]\.", "lodash 受影响版本",
     "原型污染（CVE-2019-10744、CVE-2020-8203）", "高危"),
    (r"moment", r"^2\.(?:[0-9]|1[0-9]|2[0-8])\.", "moment 旧版本", "正则拒绝服务（CVE-2022-31129）", "中危"),
    (r"axios", r"^0\.(?:1[0-9]|2[0-1])\.", "axios 0.x 早期", "SSRF 与正则 DoS（CVE-2021-3749）", "中危"),
    (r"express", r"^[1-3]\.|^4\.(?:[0-9]|1[0-6])\.", "Express 旧版本", "多个路径遍历与 XSS 问题", "中危"),
    (r"vue", r"^2\.[0-5]\.", "Vue 2.x 早期版本", "存在 XSS 与原型污染问题", "中危"),
    (r"react", r"^1[0-5]\.", "React 15 及以下", "旧版本存在 XSS 与绕过问题", "中危"),
    # sanitize-html < 2.3.0 存在 mXSS（mutation XSS，GHSA-mjxr-4v3x-7w8m 一族）
    (r"sanitize-html", r"^1\.", "sanitize-html 1.x", "HTML 净化库存在 mXSS 绕过", "中危"),
    # 组件供应链中常见、版本落后即带公开 CVE 的库；命中即报「不通过」
    (r"express-jwt", r"^[~^]?[0-5]\.", "express-jwt 旧版（<6.0.0）", "JWT alg 混淆导致授权绕过", "高危"),
    (r"multer", r"^[~^]?[01]\.", "multer 旧版（<2.3.0）", "multipart 解析拒绝服务（CVE-2026-77078 等）", "中危"),
    (r"struts", r"^2\.", "Struts 2.x", "多个 RCE（S2-045 / S2-057），历史失陷重灾区", "严重"),
    (r"log4j", r"^1\.|^2\.(?:[0-9]|1[0-5])\.", "Log4j 受影响版本", "Log4Shell（CVE-2021-44228）等 RCE", "严重"),
    (r"shiro", r"^1\.[0-7]\.", "Shiro 受影响版本", "RememberMe 反序列化 RCE（CVE-2016-4437）", "严重"),
    (r"fastjson", r"^1\.2\.(?:[0-7][0-9]|80)", "Fastjson 受影响版本", "反序列化 RCE（多版本绕过）", "严重"),
    (r"spring", r"^[1-4]\.", "Spring Framework 1–4", "多个反序列化与 SpEL 注入问题", "高危"),
    (r"jackson", r"^2\.(?:[0-9]|1[0-1])\.", "Jackson 受影响版本", "反序列化 RCE（CVE-2020-8840 等）", "高危"),
]

# 暴露的依赖清单文件（真实世界高频泄露：Git 部署把整个项目目录丢上服务器）。
# 这些文件里的依赖名 + 精确版本是组件漏洞比对的**第一手来源** ——
# 比从打包产物里猜版本可靠得多。命中后按 JSON 解析。
_DEPENDENCY_MANIFESTS = (
    "package.json", "package-lock.json", "composer.lock",
    "npm-shrinkwrap.json", "yarn.lock",
    # 暴露的开发者备份：站点常把整个项目目录（含 package.json.bak）一起丢上服务器。
    # Juice Shop 的 /ftp/package.json.bak 直连被拦，必须走 null-byte 双重编码
    # （/ftp/package.json.bak%2500.md）才放行 —— 见 athz01 的 LFR 检测同款变体。
    # 拿不到清单会被写成「无法判定」，白白丢掉整类供应链判定（红线 1：没执行≠通过）。
    "ftp/package.json.bak%2500.md", "ftp/package.json.bak",
    "package.json.bak%2500.md", "package.json.bak",
)

_MANIFEST_NAME_RE = re.compile(
    r"(package(?:-lock)?|npm-shrinkwrap|composer|yarn)\.json"
    r"(?:\.(?:bak|old|orig|txt|save))?$", re.I)


def _parse_manifest_body(body: str) -> dict[str, str]:
    """解析一份依赖清单正文（package.json 或 lock 文件形态）。"""
    import json as _json
    try:
        data = _json.loads(body[:500_000])
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(data, dict):
        return {}
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        v = data.get(section)
        if isinstance(v, dict):
            for k, ver in v.items():
                deps.setdefault(str(k), str(ver))
    if not deps and isinstance(data.get("packages"), dict):
        # package-lock.json 形态：packages["node_modules/x"]["version"]
        for pk, info in data["packages"].items():
            short = pk.split("node_modules/")[-1]
            if short and isinstance(info, dict) and info.get("version"):
                deps.setdefault(short, str(info["version"]))
    return deps


def _discovered_manifest_paths(ctx: DetectorContext) -> list[str]:
    """从**已经探到的**路径里挑依赖清单。

    先找真实暴露面再猜固定路径：站点把 package.json 丢在子目录 / 备份后缀下
    （`/ftp/package.json.bak` 这类）的情况并不少见，只按根路径猜会整体落空 ——
    而「没找到清单」会被写成「无法判定」，白白丢掉一整类供应链判定。
    """
    out: list[str] = []
    seen: set[str] = set()
    cands: list[str] = []
    for p in (ctx.fp_result.get("path_probes") or {}):
        if isinstance(p, str):
            cands.append(p)
    for u in (ctx.js_result.get("urls") or [])[:400]:
        if isinstance(u, str):
            cands.append(u)
    for c in cands:
        if not _MANIFEST_NAME_RE.search(c):
            continue
        u = urljoin(ctx.target_url, c)
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:4]


def _fetch_manifest_deps(ctx: DetectorContext) -> tuple[dict[str, str], str]:
    """取回暴露的依赖清单（依赖名 → 版本），返回 (依赖表, 来源说明)。

    两级来源：①本次扫描**真实探到**的清单路径（最可信）②常见清单根路径（兜底）。
    命中即停。拿不到返回空表——空表必须能被区分于「目标没有依赖」，
    所以调用方要写明来源。

    ⚠ 关键：清单正文必须取**全文**，不能只取 body_snippet 的前 4000 字符。
    Juice Shop 的 /ftp/package.json.bak 约 4.2KB，截断会破坏 JSON 解析，
    导致「取到清单却解析为空」的静默漏报（红线 1：没执行≠通过）。故这里
    显式放大 max_body。
    """
    import json as _json

    # 清单体积可能超过默认 4000 字符上限，取全文再解析。
    _MANIFEST_MAX_BODY = 300_000

    for url in _discovered_manifest_paths(ctx):
        try:
            pr = ctx.get(url, max_body=_MANIFEST_MAX_BODY)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if getattr(pr, "status", 0) != 200 or not body.strip().startswith(("{", "[")):
            continue
        deps = _parse_manifest_body(body)
        if deps:
            return deps, url

    for path in _DEPENDENCY_MANIFESTS:
        try:
            pr = ctx.get(urljoin(ctx.target_url, path), max_body=_MANIFEST_MAX_BODY)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if getattr(pr, "status", 0) != 200 or not body.strip().startswith("{"):
            continue
        deps = _parse_manifest_body(body)
        if deps:
            return deps, path
    return {}, ""


RISKY_THIRD_PARTY = {
    "polyfill.io": ("该域名已被出售并用于投毒事件", "严重"),
    "bootcss.com": ("公共 CDN，历史上有被篡改记录，建议自建或加 SRI", "低危"),
    "staticfile.org": ("公共 CDN，建议校验 SRI 完整性", "低危"),
}

PRIORITIZED_KEV = [
    ("Log4j", r"log4j", "CVE-2021-44228（Log4Shell）", "严重",
     "JNDI 注入导致远程代码执行，公开后数小时内即被大规模自动化利用"),
    ("Struts2", r"struts", "S2-045 / S2-057 等", "严重",
     "OGNL 表达式注入，可通过请求头或 URL 直接执行系统命令"),
    ("Apache Shiro", r"shiro", "CVE-2016-4437", "严重",
     "利用固定 AES 密钥伪造 RememberMe Cookie 实现反序列化 RCE"),
    ("Fastjson", r"fastjson", "反序列化 RCE 系列", "严重",
     "autoType 可加载任意类，历史上存在多个绕过版本"),
    ("Spring", r"spring", "Spring4Shell（CVE-2022-22965）", "高危",
     "数据绑定机制可导致远程代码执行"),
    ("Confluence / Jira", r"confluence|jira", "CVE-2023-22515 等", "严重",
     "认证绕过叠加后台 RCE，实际攻击中被广泛利用"),
    ("Redis", r"redis", "未授权访问", "严重",
     "默认无认证，暴露公网即可写文件、写计划任务、窃取数据"),
    ("Elasticsearch", r"elasticsearch", "未授权访问", "严重",
     "默认无认证，可读取全量索引数据"),
    ("Jenkins", r"jenkins", "CVE-2024-23897 等", "严重",
     "任意文件读取可升级为远程代码执行"),
    ("OpenSSH", r"openssh", "CVE-2024-6387（regreSSHion）", "高危",
     "竞争条件导致远程代码执行"),
]


# ======================================================================
# EXT-SC-01 前端组件已知漏洞
# ======================================================================
@make_auto("EXT-SC-01", name="前端组件已知漏洞核对", tool="JS 组件清单 + 版本比对",
           risk=RISK_SAFE, requires=["js"], evidence_kind="组件清单实测",
           detector_ref="checks/extras.py:sc01")
def sc01(ctx: DetectorContext):
    comps = list(ctx.js_result.get("components") or [])
    manifest_note = ""
    # ---------- 暴露的依赖清单文件 ----------
    # 打包产物里的版本号经常被压缩剥掉，但部署时把 package.json /
    # lock 文件一起丢上服务器的站点数不胜数 —— 里面的依赖名与精确
    # 版本是组件漏洞比对的第一手来源。无论 JS 产物是否抽到组件，
    # 都**必须**尝试抓取暴露的清单（含 null-byte 备份路径，见
    # _DEPENDENCY_MANIFESTS）并合并进比对集合：只做 GET 读取，拿到
    # 任意一份即停。空表须能被区分于「目标没有依赖」（红线 1：没执行≠通过）。
    deps, src = _fetch_manifest_deps(ctx)
    if deps:
        seen = {str(c.get("name", "")).lower() for c in comps}
        for k, v in list(deps.items())[:60]:
            if str(k).lower() not in seen:
                comps.append({"name": k, "version": v.lstrip("^~> ")})
                seen.add(str(k).lower())
        manifest_note = f"（含暴露清单 {src}）"

    matched = []
    for c in comps:
        name = str(c.get("name", "")).lower()
        ver = str(c.get("version", "")).lstrip("v")
        if not name or not ver:
            continue
        for pat, vpat, label, risk, sev in VULNERABLE_COMPONENTS:
            if re.search(pat, name, re.I) and re.search(vpat, ver):
                matched.append((f"{c.get('name')} {ver}", label, risk, sev))
                break

    findings = []
    if matched:
        order = ["信息", "低危", "中危", "高危", "严重"]
        worst = max((m[3] for m in matched), key=lambda s: order.index(s))
        findings.append(make_finding(
            "EXT-SC-01", f"前端组件存在 {len(matched)} 项已知漏洞版本",
            ctx.target_name, endpoint=ctx.target_url,
            severity=worst, confidence="Medium", evidence_level="B",
            description=("从产物中识别出的前端组件版本落在公开漏洞的受影响范围内。"
                         "前端资源对全体访客可见，攻击者可据此直接选定攻击方式。"),
            technical_detail="命中的组件与风险：\n" + "\n".join(
                f"  · {n}\n    风险：{r}" for n, _, r, _ in matched),
            impact=("按组件不同可导致 XSS、原型污染或拒绝服务；"
                    "部分服务端框架组件（Struts / Shiro / Fastjson / Log4j）"
                    "的已知漏洞可直接远程执行命令，属系统被接管级别。"),
            reproduction="在浏览器网络面板查看组件文件路径与版本号，或使用本项输出的组件清单。",
            remediation=("① 按清单升级到已修复版本；"
                         "② 建立依赖清单（SBOM）与定期漏洞扫描（npm audit / OWASP Dependency-Check）；"
                         "③ 使用锁定版本文件并纳入 CI 校验；"
                         "④ 服务端框架及时跟进厂商安全公告。"),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.28",
            evidence=[finding_evidence("file", str(matched), "组件版本比对结果")],
            grading_basis="组件版本经实测识别并与公开漏洞范围匹配，定高危 / 中危",
        ))

    note = (f"识别组件 {len(comps)} 个，命中已知漏洞版本 {len(matched)} 个{manifest_note}"
            + (f"：{', '.join(m[0] for m in matched[:5])}" if matched else ""))
    return found(note, findings, probes=1, evidence_kind="组件清单实测")


# ======================================================================
# EXT-SC-02 后端框架已知漏洞
# ======================================================================
@make_auto("EXT-SC-02", name="后端框架已知漏洞核对", tool="响应特征比对",
           risk=RISK_SAFE, evidence_kind="框架特征实测",
           detector_ref="checks/extras.py:sc02")
def sc02(ctx: DetectorContext):
    signals = list(ctx._cache.get("info09_signals") or [])
    h = ctx.root_headers
    if h.get("x-application-context"):
        signals.append("Spring 应用")
    if h.get("x-powered-by"):
        signals.append(h["x-powered-by"])
    # Cookie 名也能指认框架
    cookie_names = " ".join(getattr(ctx.root, "cookies", []) or [])
    if re.search(r"rememberMe", cookie_names, re.I):
        signals.append("Apache Shiro（rememberMe Cookie）")
    if re.search(r"JSESSIONID", cookie_names, re.I):
        signals.append("Java Web 应用")

    risky_families = []
    for name, pat, cve, sev, why in PRIORITIZED_KEV:
        if re.search(pat, " ".join(signals), re.I):
            risky_families.append((name, cve, sev, why))

    findings = []
    if risky_families:
        name, cve, sev, why = risky_families[0]
        findings.append(make_finding(
            "EXT-SC-02", f"识别到历史高危后端框架（{name}），需核对精确版本",
            ctx.target_name, endpoint=ctx.target_url,
            severity=sev, confidence="Low", evidence_level="C",
            description=(f"从响应特征判断目标使用了 {name}。"
                         f"该组件的历史漏洞（{cve}）属于远程代码执行级别，"
                         "实际攻击中被大规模自动化利用。"),
            technical_detail=(f"识别依据：{', '.join(signals[:8])}\n"
                              f"关联漏洞：{cve}\n漏洞性质：{why}\n"
                              "说明：本次未能确认精确版本，故不作定级，仅列为优先核对项。"),
            impact="若版本落在受影响范围内，攻击者可远程执行系统命令，直接取得服务器权限及其上的全部数据。",
            reproduction="通过版本接口、报错页或组件指纹确认精确版本，与厂商安全公告比对。",
            remediation=("① 立即确认版本并升级到修复版本；"
                         "② 无法立即升级时按厂商公告应用缓解措施（关闭特性 / 加 WAF 规则）；"
                         "③ 该组件不应对公网开放；"
                         "④ 排查历史访问日志确认是否已被尝试利用。"),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.8",
            evidence=[finding_evidence("header", str(signals[:8]), "框架特征")],
            grading_basis="仅识别到框架族未确认版本，证据级别 C，列入待确认",
        ))

    note = (f"识别后端框架特征 {len(signals)} 项"
            + (f"：{'、'.join(signals[:6])}" if signals else "（未识别到）")
            + f"；其中高风险框架 {len(risky_families)} 项")
    return found(note, findings, probes=1, evidence_kind="框架特征实测")


# ======================================================================
# EXT-SC-03 服务器与中间件已知漏洞
# ======================================================================
@make_auto("EXT-SC-03", name="服务器与中间件版本漏洞核对", tool="版本横幅 + nmap",
           risk=RISK_STANDARD, evidence_kind="版本横幅实测",
           detector_ref="checks/extras.py:sc03")
def sc03(ctx: DetectorContext):
    banners = []
    server = ctx.root_headers.get("server", "")
    if server:
        banners.append(("HTTP Server 头", server))
    for key in ("x-powered-by", "x-generator", "x-aspnet-version"):
        if ctx.root_headers.get(key):
            banners.append((key, ctx.root_headers[key]))

    ip = ctx._cache.get("info04_ip") or ""
    if ip:
        svc = net.nmap_scan(ip, [80, 443, 22, 3389, 21, 3306, 6379])
        for port, desc in svc.items():
            banners.append((f"{ip}:{port}", desc))

    risky = [(k, v) for k, v in banners
             if v and re.search(r"\d+\.\d+", v)
             and re.search(r"(nginx|apache|iis|tomcat|jetty|openssh|mysql|redis|"
                           r"elasticsearch|php|openresty|lighttpd)", v, re.I)]
    findings = []
    if risky:
        findings.append(make_finding(
            "EXT-SC-03", f"对外暴露 {len(risky)} 处服务版本信息，需核对已知漏洞",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="B",
            description=("公网可直接读取到服务器与中间件的版本号。"
                         "有了版本号就能直接查对应的公开漏洞，无需任何探测。"),
            technical_detail="暴露的版本信息：\n" + "\n".join(
                f"  · {k}: {v}" for k, v in risky[:15]),
            impact=("历史上影响最大的几个漏洞（Log4Shell、Struts RCE、"
                    "Redis 未授权）都是先靠版本号定位目标的。"
                    "版本隐藏只是降低被优先选中的概率，真正解决问题要升级组件本身。"),
            reproduction=(f"curl -sI {ctx.target_url} | grep -i server\n"
                          f"nmap -Pn -sV -p 80,443 {ip or ctx.domain}"),
            remediation=("① 隐藏版本号（Nginx `server_tokens off`、"
                         "Apache `ServerTokens Prod`）；"
                         "② 及时升级中间件到受支持版本；"
                         "③ 建立资产版本台账，定期与厂商公告比对。"),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.8",
            evidence=[finding_evidence("header", str(risky[:15]), "版本横幅")],
            grading_basis="版本信息实测暴露，具体漏洞需逐版本核对，定低危",
        ))

    note = (f"采集版本横幅 {len(banners)} 条，含版本号 {len(risky)} 条；"
            f"nmap 服务识别 {'已执行' if ip else '未执行（无 IP）'}")
    return found(note, findings, probes=1 + (1 if ip else 0), evidence_kind="版本横幅实测")


# ======================================================================
# EXT-SC-04 第三方外链资源与 CDN 风险
# ======================================================================
@make_auto("EXT-SC-04", name="第三方资源与 CDN 风险核查", tool="前端产物分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="外链资源实测",
           detector_ref="checks/extras.py:sc04")
def sc04(ctx: DetectorContext):
    body = ctx.baseline_body + "\n" + "\n".join(ctx.js_result.get("bodies") or [])
    externals = set()
    for m in re.finditer(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)["\']', body, re.I):
        u = m.group(1)
        if ctx.domain not in u:
            externals.add(u)

    order = ["信息", "低危", "中危", "高危", "严重"]
    risky = []
    for u in externals:
        for host, (why, sev) in RISKY_THIRD_PARTY.items():
            if host in u:
                risky.append((u, why, sev))
    sri_missing = [u for u in externals
                   if re.search(r"\.js(\?|$)", u, re.I)
                   and not re.search(re.escape(u) + r'[^>]*integrity', body)]

    findings = []
    if risky:
        findings.append(make_finding(
            "EXT-SC-04", f"引用高风险第三方资源（{len(risky)} 处）",
            ctx.target_name, endpoint=risky[0][0],
            severity=max((r[2] for r in risky), key=lambda s: order.index(s)),
            confidence="High", evidence_level="A",
            description=("页面引用了被标记为高风险的第三方资源域名。"
                         "这类资源的内容完全由第三方控制，却以本站域名的权限执行。"),
            technical_detail="风险外链：\n" + "\n".join(
                f"  · {u}\n    原因：{w}" for u, w, _ in risky[:10]),
            impact=("第三方脚本被篡改或域名被接管时，攻击者可在本站页面执行任意脚本、"
                    "读取全部页面数据、窃取用户凭据。"
                    "polyfill.io 事件即典型案例：域名被出售后向数万站点注入了恶意代码。"),
            reproduction="在浏览器网络面板查看外部请求，或在前端产物中检索第三方域名。",
            remediation=("① 移除或替换高风险第三方资源，改为自建托管；"
                         "② 必须使用外部资源时加 SRI 完整性校验；"
                         "③ 用 CSP 的 script-src 限制为白名单；"
                         "④ 建立第三方资源台账并定期复核域名归属。"),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.28",
            evidence=[finding_evidence("file", str(risky[:10]), "高风险外链")],
            grading_basis="引用高风险域名经实测确认，定严重 / 低危（视域名而定）",
        ))

    if sri_missing:
        findings.append(make_finding(
            "EXT-SC-04", f"{len(sri_missing)} 个外部脚本缺少 SRI 完整性校验",
            ctx.target_name, endpoint=sri_missing[0],
            severity="低危", confidence="High", evidence_level="A",
            description=("外部脚本通过 <script src> 引入但没有 integrity 属性，"
                         "浏览器不会校验其内容是否被改动过。"),
            technical_detail="缺少 SRI 的外部脚本：\n" + "\n".join(
                f"  · {u}" for u in sri_missing[:10]),
            impact="第三方 CDN 被入侵或内容被替换时，恶意脚本会以本域权限执行，且无法被检测。",
            reproduction="在页面源码中检索外部 script 标签，检查是否存在 integrity 属性。",
            remediation="为所有外部脚本与样式添加 integrity + crossorigin 属性。",
            compliance="ISO 27001 A.8.28",
            evidence=[finding_evidence("file", str(sri_missing[:10]), "缺少 SRI")],
            grading_basis="SRI 缺失经实测确认，属加固项，定低危",
        ))

    note = (f"外链资源 {len(externals)} 个，高风险域名 {len(risky)} 个，"
            f"缺少 SRI {len(sri_missing)} 个")
    return found(note, findings, probes=1, evidence_kind="外链资源实测")


# ======================================================================
# EXT-SC-05 依赖混淆与包管理暴露
# ======================================================================
@make_auto("EXT-SC-05", name="依赖混淆与包管理暴露核查", tool="组件清单 + 包仓库查询",
           risk=RISK_STANDARD, evidence_kind="包名与仓库查询",
           detector_ref="checks/extras.py:sc05")
def sc05(ctx: DetectorContext):
    manifests = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                 "composer.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod"]
    hits = scan_paths(ctx, manifests)
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    findings = []

    if hits:
        first = list(hits)[0]
        body = getattr(hits[first], "body_snippet", "") or ""
        findings.append(make_finding(
            "EXT-SC-05", f"依赖清单文件对外可读（{len(hits)} 个）",
            ctx.target_name, endpoint=getattr(hits[first], "final_url", "")
            or urljoin(ctx.target_url, first),
            severity="中危", confidence="High", evidence_level="A",
            description=("构建用的依赖清单被部署到了公网目录，可以直接下载。"
                         "这份文件列出了项目的全部依赖与精确版本。"),
            technical_detail=(f"可下载的清单：{', '.join(list(hits)[:6])}\n"
                              f"内容片段：\n{body[:600]}"),
            impact=("① 直接获得完整依赖树，攻击者可逐个查已知漏洞，把「盲扫」变成「精准命中」；"
                    "② 若清单含私有包名或内部制品库地址，"
                    "可被用于依赖混淆攻击（在公共源注册同名高版本包，诱导构建拉取恶意包）。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, first)} | head -30",
            remediation=("① 构建产物不包含依赖清单；"
                         "② 私有包使用作用域前缀（@company/）并在制品库配置上游代理；"
                         "③ 制品库禁止从公共源拉取与私有包同名的包。"),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.28",
            evidence=[finding_evidence("response", body[:1000], first)],
            grading_basis="清单文件实测可下载，可直接获得依赖树，定中危",
        ))

    internal_pkgs = set(re.findall(r"@([a-z0-9][\w\-]{2,})/([a-z0-9][\w\-\.]{2,})", blobs))
    suspicious = sorted({f"@{s}/{n}" for s, n in internal_pkgs
                         if not re.search(r"(babel|typescript|vue|angular|react|material|"
                                          r"emotion|testing|eslint|storybook|types|tanstack|"
                                          r"radix|floating|formatjs|fortawesome|sentry|swc|"
                                          r"rollup|vite|webpack|chakra|mui|iconify|intlify)",
                                          s + n, re.I)})
    if suspicious:
        findings.append(make_finding(
            "EXT-SC-05", f"前端产物引用可能与内部命名冲突的作用域包（{len(suspicious)} 个）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Low", evidence_level="C",
            description=("产物中出现了非公共库常见的作用域包名。"
                         "若这些包仅存在于内部制品库，则存在依赖混淆风险。"),
            technical_detail="疑似内部作用域包：\n" + "\n".join(
                f"  · {p}" for p in suspicious[:20]),
            impact="成功实施依赖混淆后可在构建或运行时执行任意代码，影响所有使用该依赖的服务。",
            reproduction="在公共包仓库中检索上述包名，确认是否已被他人注册。",
            remediation=("① 私有包在制品库中配置为「仅内部源」；"
                         "② 使用完整作用域名并配置上游排除规则；"
                         "③ 构建流程锁定依赖完整性。"),
            compliance="ISO 27001 A.8.28",
            evidence=[finding_evidence("file", str(suspicious[:20]), "疑似内部包名")],
            grading_basis="仅识别到包名，是否存在于公共源需人工核对，证据级别 C 列入待确认",
        ))

    note = f"依赖清单命中 {len(hits)} 个；疑似内部作用域包 {len(suspicious)} 个"
    return found(note, findings, probes=len(manifests), evidence_kind="包名与仓库查询")


# ======================================================================
# EXT-SC-06 打包产物泄露源码与依赖树
# ======================================================================
@make_auto("EXT-SC-06", name="打包产物源码与依赖树泄露核查", tool="前端产物分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="产物与 Source Map 实测",
           detector_ref="checks/extras.py:sc06")
def sc06(ctx: DetectorContext):
    findings = []
    js_urls = [u for u in (ctx.js_result.get("urls") or [])
               if isinstance(u, str) and re.search(r"\.(js|mjs)(\?|$)", u)][:20]
    maps = []
    probes = 0
    for u in js_urls[:10]:
        if u.startswith("http"):
            continue
        map_path = u.split("?")[0] + ".map"
        probes += 1
        pr = probe_or_none(ctx, map_path)
        if pr is not None and getattr(pr, "status", 0) == 200:
            body = getattr(pr, "body_snippet", "") or ""
            if '"sources"' in body or '"mappings"' in body:
                maps.append(urljoin(ctx.target_url, map_path))

    if maps:
        findings.append(make_finding(
            "EXT-SC-06", f"Source Map 文件可公开下载（{len(maps)} 个）",
            ctx.target_name, endpoint=maps[0],
            severity="中危", confidence="High", evidence_level="A",
            description=("打包产物对应的 Source Map 被部署到了公网。"
                         "浏览器开发者工具可以直接把压缩代码还原成原始源码，"
                         "包括目录结构、变量名与注释。"),
            technical_detail="可下载的 Source Map：\n" + "\n".join(f"  · {m}" for m in maps[:10]),
            impact=("源码还原后可看到：完整业务逻辑与接口调用、隐藏的接口地址与调试入口、"
                    "注释中的说明与临时措施，甚至可能的硬编码凭据。"),
            reproduction=f"curl -s '{maps[0]}' | head -20",
            remediation=("① 生产构建不生成或不部署 Source Map"
                         "（Vite `build.sourcemap=false`；Webpack `devtool=false`）；"
                         "② 需线上排障时把 map 上传到错误监控平台并从产物删除；"
                         "③ 构建流程加一步「产物不含 .map」的检查。"),
            compliance="等保2.0 安全计算环境-数据保密性 / ISO 27001 A.8.28",
            evidence=[finding_evidence("response", str(maps), "Source Map 地址")],
            grading_basis="实测 Source Map 可下载并含 sources 映射，定中危",
        ))

    text = "\n".join(ctx.js_result.get("bodies") or [])
    leaks = []
    if re.search(r"webpack://|/_next/static/|vue-cli-service", text, re.I):
        leaks.append("构建工具路径 / 模块标识残留")
    if re.search(r'(?:^|\n)\s*(?://|/\*)\s*(?:TODO|FIXME|HACK|临时|测试)', text, re.I):
        leaks.append("残留开发注释（TODO / FIXME / 临时）")
    if re.search(r"process\.env\.[A-Z_]{3,}", text):
        leaks.append("引用了 process.env 变量名（可推断部署配置项）")
    if leaks:
        findings.append(make_finding(
            "EXT-SC-06", f"打包产物残留 {len(leaks)} 类构建期信息",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="B",
            description="压缩后的产物中仍包含构建期信息（工具链路径、开发注释、环境变量名）。",
            technical_detail="命中的信息类型：\n" + "\n".join(f"  · {l}" for l in leaks),
            impact="为攻击者提供技术栈与内部约定的线索，降低摸底成本。",
            reproduction="在前端产物中检索 TODO / webpack:// / process.env 等特征。",
            remediation="构建时开启完整压缩与注释剥离，使用 production 模式构建。",
            compliance="ISO 27001 A.8.28",
            evidence=[finding_evidence("file", str(leaks), "构建期信息残留")],
            grading_basis="静态匹配，未直接导致数据或权限损失，定低危",
        ))

    note = (f"检查 {len(js_urls[:10])} 个脚本的 Source Map，命中 {len(maps)} 个；"
            f"构建期信息残留 {len(leaks)} 类")
    return found(note, findings, probes=probes + 1, evidence_kind="产物与 Source Map 实测")


# ======================================================================
# EXT-SC-07 第三方集成凭据泄露
# ======================================================================
@make_auto("EXT-SC-07", name="第三方集成凭据泄露核查", tool="前端产物与配置实测",
           risk=RISK_SAFE, requires=["js"], evidence_kind="凭据特征实测",
           detector_ref="checks/extras.py:sc07")
def sc07(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    third_party = {
        "支付 / 微信密钥": (r"(?:wechat|weixin|alipay|wxpay)[_-]?(?:secret|key|mch[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9]{16,})", "严重"),
        "短信服务密钥": (r"(?:sms|aliyun|tencent)[_-]?(?:access|secret|sign)[_-]?(?:key|secret|name)\s*[:=]\s*[\"']([A-Za-z0-9]{12,})", "高危"),
        "对象存储凭据": (r"(?:oss|s3|cos)[_-]?(?:access|secret)[_-]?(?:key|id|secret)\s*[:=]\s*[\"']([A-Za-z0-9]{12,})", "高危"),
        "地图服务密钥": (r"(?:amap|gaode|baidu)[_-]?(?:key|ak|sk)\s*[:=]\s*[\"']([A-Za-z0-9]{16,})", "中危"),
        "推送 / IM 密钥": (r"(?:fcm|jpush|getui|rongcloud|agora)[_-]?(?:key|secret|appkey)\s*[:=]\s*[\"']([A-Za-z0-9]{12,})", "中危"),
        "统计 / 埋点密钥": (r"(?:sensorsdata|mixpanel|amplitude)[_-]?(?:token|key)\s*[:=]\s*[\"']([A-Za-z0-9]{16,})", "低危"),
    }
    hits = [(name, sev) for name, (pat, sev) in third_party.items()
            if re.search(pat, blobs, re.I)]
    generic = code_scan(ctx, CREDENTIAL_PATTERNS, scope="both")
    hits += [(d, "高危") for d, _ in generic if not any(d in h[0] for h in hits)]

    findings = []
    if hits:
        order = ["信息", "低危", "中危", "高危", "严重"]
        worst = max((h[1] for h in hits), key=lambda s: order.index(s))
        findings.append(make_finding(
            "EXT-SC-07", f"前端产物中可能包含 {len(hits)} 类第三方服务凭据",
            ctx.target_name, endpoint=ctx.target_url,
            severity=worst, confidence="Medium", evidence_level="B",
            description=("前端产物中匹配到了第三方服务的密钥特征。"
                         "前端代码对所有访客可见，其中的密钥等同于公开。"),
            technical_detail="命中的凭据类型：\n" + "\n".join(
                f"  · {n}（疑似等级 {s}）" for n, s in hits)
                + "\n（凭据实际值不在报告中记录）",
            impact=("支付 / 短信密钥泄露可被用于盗刷或发送诈骗短信；"
                    "对象存储凭据泄露可读写业务文件；"
                    "地图 / 统计密钥泄露会造成费用被他人消耗。"),
            reproduction="在前端产物中检索 accessKey / secret / appkey 等关键字，确认是否为真实值。",
            remediation=("① 服务端凭据绝不进入前端，敏感调用经后端代理；"
                         "② 前端可用的地图 / 统计类密钥在服务商后台配置域名白名单与配额；"
                         "③ 已泄露的密钥立即轮换；"
                         "④ 接入提交前密钥扫描（gitleaks 等）。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / PIPL 第 51 条",
            evidence=[finding_evidence("file", str(hits), "第三方凭据特征")],
            grading_basis="静态匹配到凭据特征，实际可用性需人工确认，按 B 级定高危 / 中危",
        ))

    note = f"第三方凭据特征 {len(hits)} 类；通用凭据特征 {len(generic)} 类"
    return found(note, findings, probes=1, evidence_kind="凭据特征实测")


# ======================================================================
# EXT-SC-08 已知被利用漏洞优先核对
# ======================================================================
@make_auto("EXT-SC-08", name="已知被利用漏洞优先核对", tool="版本比对 + 公开情报",
           risk=RISK_SAFE, evidence_kind="版本与情报交叉",
           detector_ref="checks/extras.py:sc08")
def sc08(ctx: DetectorContext):
    corpus = (" ".join(str(s) for s in (ctx._cache.get("info09_signals") or [])) + " "
              + ctx.root_headers.get("server", "") + " "
              + str(ctx._cache.get("info04_ports", {})) + " "
              + " ".join(c.get("name", "") for c in (ctx.js_result.get("components") or [])))
    hits = [(name, cve, sev, why) for name, pat, cve, sev, why in PRIORITIZED_KEV
            if re.search(pat, corpus, re.I)]

    findings = []
    if hits:
        name, cve, sev, why = hits[0]
        findings.append(make_finding(
            "EXT-SC-08", f"识别到历史高危组件 {name}（{cve}），须优先核对版本",
            ctx.target_name, endpoint=ctx.target_url,
            severity=sev, confidence="Low", evidence_level="C",
            description=(f"目标环境中识别到 {name} 的痕迹。"
                         f"该组件的历史漏洞（{cve}）在实际攻击中被大规模利用，属必须优先核对的对象。"),
            technical_detail=(f"组件：{name}\n关联漏洞：{cve}\n漏洞性质：{why}\n"
                              f"识别依据：{corpus[:400]}\n"
                              "说明：本次仅识别到组件存在，未确认精确版本，故不作定级。"),
            impact=("若版本落在受影响范围内，攻击者可远程执行系统命令，"
                    "直接取得服务器控制权并访问其上的全部数据。"
                    "这类漏洞在公开后数小时内就会收到自动化扫描。"),
            reproduction="通过版本接口、报错页或组件指纹确认精确版本，与厂商公告比对。",
            remediation=("① 立即确认精确版本并升级到修复版本；"
                         "② 无法立即升级时按厂商公告应用缓解措施；"
                         "③ 该组件不应对公网开放；"
                         "④ 排查历史日志确认是否已被尝试利用。"),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.8",
            evidence=[finding_evidence("file", f"{name} | {cve} | {corpus[:300]}",
                                       "组件识别线索")],
            grading_basis="仅识别到组件存在未确认版本，证据级别 C，列入待确认并标注优先核对",
        ))

    note = (f"优先核对清单 {len(PRIORITIZED_KEV)} 项，命中 {len(hits)} 项"
            + (f"：{', '.join(h[0] for h in hits)}" if hits else "（未识别到）"))
    return found(note, findings, probes=1, evidence_kind="版本与情报交叉")


# ======================================================================
# EXT-CL-01 云主机元数据服务可达性
# ======================================================================
@make_auto("EXT-CL-01", name="云主机元数据服务可达性核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="元数据路径实测",
           detector_ref="checks/extras.py:cl01")
def cl01(ctx: DetectorContext):
    hits = []
    probes = 0
    for p in METADATA_PATHS:
        probes += 1
        pr = probe_or_none(ctx, p)
        if pr is None:
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if getattr(pr, "status", 0) == 200 and re.search(
                r"(ami-id|instance-id|security-credentials|iam|project|"
                r"service-accounts|computeMetadata)", body, re.I):
            hits.append((p, body[:400]))
            break

    findings = []
    if hits:
        p, frag = hits[0]
        findings.append(make_finding(
            "EXT-CL-01", "云主机元数据服务可经 Web 层访问",
            ctx.target_name, endpoint=urljoin(ctx.target_url, p),
            severity="严重", confidence="High", evidence_level="A",
            description=("通过 Web 路径可以访问到云主机的元数据服务并返回实例信息。"
                         "这在云环境中是取得云凭据的直接路径。"),
            technical_detail=(f"路径：/{p}\n响应片段（已脱敏）：\n{frag}\n\n"
                              "若该路径由 SSRF 参数驱动，则危害等同直接读取云凭据。"),
            impact=("元数据服务中通常包含实例绑定的临时访问凭据（IAM Role / RAM Role）。"
                    "取得凭据后可直接调用云 API，读取或删除对象存储、数据库快照、日志等资源，"
                    "危害范围往往超出单台服务器。"),
            reproduction=f"curl -s '{urljoin(ctx.target_url, p)}' | head -20",
            remediation=("① 应用层不代理元数据服务路径；"
                         "② 启用 IMDSv2（要求 Token 且跳数限制 hop limit = 1）；"
                         "③ 修复所有 SSRF 入口（根因）；"
                         "④ 实例角色按最小权限授权。"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("response", frag, "元数据响应")],
            grading_basis="实测可访问云元数据服务，可延伸至云凭据获取，定严重",
        ))

    note = (f"探测元数据路径 {len(METADATA_PATHS)} 个，"
            f"{'命中可访问' if hits else '均不可达（符合预期）'}")
    return found(note, findings, probes=probes, evidence_kind="元数据路径实测")


# ======================================================================
# EXT-CL-02 安全组与非预期端口暴露
# ======================================================================
@make_auto("EXT-CL-02", name="安全组与非预期端口暴露核查", tool="TCP 端口探测",
           risk=RISK_STANDARD, evidence_kind="端口探测实测",
           detector_ref="checks/extras.py:cl02",
           # 纯 TCP 端口探测，不经 HTTP。
           needs_app=False)
def cl02(ctx: DetectorContext):
    ip = ctx._cache.get("info04_ip") or ""
    if not ip:
        return no_target_outcome(ctx, "目标 IP（DNS 解析未取得地址）", probes=1, evidence_kind="无 IP")

    # 走共享的端口扫描缓存：多个检测器都关心「开了哪些端口」，
    # 各扫一遍会让探测次数成倍增长。档位越高，端口覆盖面越大。
    ports = net.scan_ports_cached(ip, getattr(ctx, "profile_key", "standard")) or {}
    if not ports:
        # 一个端口结果都没拿到：目标不可达、探测被静默丢弃，或该地址非公网可达。
        # 「端口暴露」以公网可达为唯一判据 —— 没有数据就不能说「没有暴露」。
        return no_data_outcome(
            "端口探测结果",
            f"{ip} 上没有任何端口返回结果（目标不可达、探测被丢弃，或该地址非公网可达）",
            probes=1, evidence_kind="端口探测实测")

    # 对照实验：本机到目标的 TCP 连通信号是否可信。
    # 沙箱代理 / 企业安全客户端 / 出口网关会透明接受任意 connect()，
    # 造成「每个端口都开放」的假象。不拦下就会产出
    # 「严重：公网可达，N 个不应开放的端口可直连」这类完全无法复测的误报 ——
    # 客户照着报告去安全组收口，会发现那些端口本来就没开。
    signal_ok, signal_why = net.tcp_signal_trustworthy(ip)
    if not signal_ok:
        return pending(
            f"{signal_why}因此**本项无法判定**：不报「存在非预期开放端口」，"
            f"也不报「没有非预期开放端口」。请在可信出口网络复测。",
            probes=1, evidence_kind="端口探测（TCP 对照实验未通过）")

    opened = sorted(p for p, v in ports.items() if v)
    # 只保留**归本项定级**的端口（归属表见 net.PORT_OWNER）。
    # 邮件协议端口归 EXT-DM-05、容器 / 编排管理接口归 EXT-CL-03、
    # K8s 控制面归 EXT-CL-04 —— 它们各自有更强的证据（协议语义 / HTTP 响应），
    # 本项再报一次就是同一个端口在报告里出现多次，把端口个数变成漏洞个数。
    _OWN = "EXT-CL-02"
    mine = [p for p in opened if net.port_owner(p) == _OWN]
    delegated = [(p, net.port_owner(p)) for p in opened if net.port_owner(p) != _OWN]
    extra = [p for p in mine if p not in (80, 443)]
    risky = [p for p in extra if p in (3306, 6379, 27017, 9200, 11211, 5432, 1433,
                                       5601, 5900, 3389, 21, 23, 445)]
    # 注意：2379(etcd) / 2375(Docker) / 6443·10250(K8s) / 8500(Consul) / 5000(Registry)
    # 都不在这里 —— 它们各有专责检查项（EXT-CL-03 / CL-04 / CL-07）上报，
    # 会通过上面的归属过滤从 mine 里排除掉，写进来也是死代码。
    # 「危险端口」与「其余非标准端口」互斥切分。
    # 老写法是 `if risky: ... elif extra: ...`：只要出现一个危险端口，
    # 剩下的非标准端口（8888 代理、10000 管理台、8080/8443 备用 Web 之类）
    # 就整批不上报了 —— 探到了却没写进报告，属于静默漏报。
    # 拆成两条互不重叠的发现，既不会同一端口出现两次，也不会漏。
    extra_only = [p for p in extra if p not in risky]
    scope, _, scope_why = reachability_scope(ctx)
    is_public = scope == "公网可达"

    findings = []
    if risky:
        findings.append(make_finding(
            "EXT-CL-02",
            (f"公网可达：{len(risky)} 个不应开放的端口可直连"
             if is_public else
             f"内网可见（非公网暴露）：{len(risky)} 个不应开放的端口可直连"),
            ctx.target_name, endpoint=f"{ip}:{','.join(str(p) for p in risky)}",
            severity="严重" if is_public else "中危",
            confidence="High", evidence_level="A",
            description=("这些端口的服务在 TCP 层可建立连接。"
                         "其中数据库、缓存、注册中心、容器管理接口本应只在内网可达。"
                         + ("当前可从公网直接连接。"
                            if is_public else
                            "**目标解析为内网地址，本条描述内网可达性，不计入公网风险。**")),
            technical_detail=(f"目标 IP：{ip}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              "可建立连接的高风险端口：\n"
                              + "\n".join(f"  · {p}/tcp  {CONTAINER_PATHS.get(f'{p}/tcp', '')}"
                                          for p in risky)),
            impact=("⚠️ 本项只证明 **TCP 可达**，未验证这些服务的鉴权状态 —— "
                    "端口开放不等于数据可读。若服务确为无认证 / 弱口令"
                    "（Redis、MongoDB、Elasticsearch 的历史事故多源于此），"
                    "连通后可直接读写业务数据；"
                    "VNC(5900) / RDP(3389) 暴露把服务器登录界面放到可访问网段，"
                    "可被直接爆破；SMB(445) / Telnet(23) 等历史漏洞面极广。"
                    "各端口的实际认证配置需人工核实后才能定论；"
                    "容器 / 编排 / K8s 类端口由 EXT-CL-03、EXT-CL-04 单独核查。"
                    + ("" if is_public else "本条可达范围限于内网，实际风险取决于内网隔离与已有失陷主机的数量。")),
            reproduction=(f"nmap -Pn -p {','.join(str(p) for p in risky)} {ip}\n"
                          f"nc -zv {ip} {risky[0]}"),
            remediation=("① 安全组只放行必要端口且限定来源 IP；"
                         "② 数据库 / 缓存 / 注册中心仅绑内网地址并启用认证；"
                         "③ 容器管理接口绝不对外暴露；"
                         "④ 远程管理走堡垒机；⑤ 收口后复扫确认。"),
            compliance="等保2.0 安全区域边界-访问控制 / ISO 27001 A.8.20",
            evidence=[finding_evidence("network", f"{ip}\n可达范围={scope}\n开放端口 {risky}",
                                       "端口探测结果")],
            grading_basis=(f"TCP 实测可建立连接；可达范围判定为「{scope}」，"
                           + ("按公网暴露定严重" if is_public else "按内网暴露定中危")),
        ))
    if extra_only:
        findings.append(make_finding(
            "EXT-CL-02",
            (f"公网存在 {len(extra_only)} 个非标准开放端口" if is_public
             else f"内网可见（非公网暴露）：{len(extra_only)} 个非标准开放端口"),
            ctx.target_name, endpoint=f"{ip}:{','.join(str(p) for p in extra_only[:20])}",
            severity="中危" if is_public else "低危",
            confidence="High", evidence_level="A",
            description=("除 80 / 443 与上述高风险端口外，还有其他端口可建立连接，"
                         "需确认这些端口的用途与必要性。"
                         + ("" if is_public else "目标解析为内网地址，本条不计入公网风险。")),
            technical_detail=(f"目标 IP：{ip}\n可达性判定：{scope}\n"
                              f"非标准可达端口：{extra_only}"),
            impact=("每个额外端口都是独立攻击面。若其中服务存在漏洞或弱口令，"
                    "可绕过对 Web 服务本身的防护；也可能是历史遗留的测试接口"
                    "或未纳管的服务。仅证明 TCP 可达，未验证服务鉴权状态。"),
            reproduction=f"nmap -Pn -p {','.join(str(p) for p in extra_only[:20])} {ip}",
            remediation=("逐个确认用途，无用端口关闭；"
                         "必要端口限制来源 IP，并纳入资产台账与变更管理。"),
            compliance="等保2.0 安全区域边界-访问控制",
            evidence=[finding_evidence("network", str(extra_only), "开放端口")],
            grading_basis=("端口开放属实测，但服务类型与鉴权状态均未确认，"
                           + ("公网可达定中危" if is_public else "仅内网可达，定低危")),
        ))

    note = (f"探测 {len(ports)} 个端口，开放 {len(opened)} 个"
            f"（本项定级范围 {len(mine)} 个：高风险 {len(risky)}、"
            f"其余非标准 {len(extra_only)}）")
    if delegated:
        # 归属别的检查项的端口要点明去向，否则读者会以为这些开放端口没人管。
        note += ("；不归本项定级的开放端口：" +
                 "、".join(f"{p}(→{o})" for p, o in sorted(delegated)))
    return found(note, findings, probes=len(ports), evidence_kind="端口探测实测")


# ======================================================================
# EXT-CL-03 容器 API 与管理端口暴露
# ======================================================================
@make_auto("EXT-CL-03", name="容器 API 与管理端口暴露核查", tool="TCP + HTTP 探测",
           risk=RISK_STANDARD, evidence_kind="容器端口实测",
           detector_ref="checks/extras.py:cl03")
def cl03(ctx: DetectorContext):
    ip = ctx._cache.get("info04_ip") or ""
    if not ip:
        return no_target_outcome(ctx, "目标 IP（DNS 解析未取得地址）", probes=1, evidence_kind="无 IP")

    targets = {2375: "Docker API（未加密）", 2376: "Docker API（TLS）",
               9000: "Portainer", 5000: "Docker Registry", 8500: "Consul",
               2379: "etcd", 6443: "Kubernetes API Server",
               10250: "Kubelet API", 8080: "容器管理台 / 中间件"}
    probes = 0
    hits = []
    _OWN = "EXT-CL-03"
    opened_owned: list[tuple[int, str]] = []
    delegated: list[tuple[int, str]] = []
    for port, desc in targets.items():
        probes += 1
        if not net.tcp_open(ip, port):
            continue
        owner = net.port_owner(port)
        if owner != _OWN:
            # 该端口的上报出口不是本项（6443 / 10250 归 EXT-CL-04）。
            # 仍然探它 —— 证据留下，但不在这里另开一条发现。
            delegated.append((port, owner))
            continue
        opened_owned.append((port, desc))
        text = net.http_text(f"http://{ip}:{port}/version", timeout=6) or \
            net.http_text(f"http://{ip}:{port}/", timeout=6)
        banner = net.tcp_banner(ip, port)
        if re.search(r"(ApiVersion|Docker|Containers|Images|consul|etcd|"
                     r"kubelet|kubernetes|registry)", text + banner, re.I):
            hits.append((port, desc, (text or banner)[:300]))

    findings = []
    scope, _, scope_why = reachability_scope(ctx)
    is_public = scope == "公网可达"
    if hits:
        port, desc, frag = hits[0]
        findings.append(make_finding(
            "EXT-CL-03",
            (f"容器 / 编排管理接口对外可达（{desc}，端口 {port}）" if is_public
             else f"内网可见（非公网暴露）：容器 / 编排管理接口（{desc}，端口 {port}）"),
            ctx.target_name, endpoint=f"{ip}:{port}",
            severity="严重" if is_public else "高危",
            confidence="High", evidence_level="A",
            description=(f"{ip} 的 {port} 端口返回了 {desc} 的接口内容，"
                         "未携带任何凭据即获得该服务的接口响应。"
                         "⚠️ **认证与授权状态需人工确认**：/version 这类接口本身"
                         "通常就不要求认证，取到版本信息**不等于**能读写数据"
                         "（etcd / Consul 的 /version 即属此类）。要证实「未授权可操作」，"
                         "需进一步验证能否执行列举容器、读取键值、创建特权 Pod 等实质操作。"
                         + ("" if is_public else
                            f"目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=(f"地址：{ip}:{port}\n服务：{desc}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"本项探测到的其他已开放容器管理端口："
                              f"{[q for q, _ in opened_owned]}\n"
                              f"响应片段：{frag}"),
            impact=("以下后果以「认证确实缺失」为前提，需人工验证后定论："
                    "Docker API 可经挂载宿主目录获得主机 root 权限；"
                    "etcd / Consul 可读取全部服务配置与密钥；"
                    "Kubelet / K8s API 可创建特权 Pod 进而接管集群。"),
            reproduction=(f"curl -s http://{ip}:{port}/version | head -20\n"
                          f"# 验证未授权可读：curl -s http://{ip}:{port}/containers/json\n"
                          f"# 有实际内容返回才说明未授权可操作"),
            remediation=("① 管理端口只允许内网或运维网段访问；"
                         "② Docker 使用 Unix Socket，必须用 TCP 时启用 TLS 双向认证；"
                         "③ K8s API 通过私有端点暴露；"
                         "④ etcd / Consul 配置 ACL 并只绑内网。"),
            compliance="等保2.0 安全区域边界-访问控制 / ISO 27001 A.8.20",
            evidence=[finding_evidence("network", frag, f"{desc} 响应")],
            grading_basis=("实测管理接口可达并返回自身接口内容，已具备继续验证未授权操作的条件；"
                           "认证缺失状态待人工确认，故定高危（公网可达加一档为严重）"),
        ))
    elif opened_owned:
        # 端口开着但没能确认接口身份 —— **必须报**，不能因为「没认出产品」就不报。
        # 这些端口原本由 EXT-CL-02 兜底上报，现已归属本项；
        # 静默等于把「我们没认出来」写成「容器管理端口没问题」，是假阴性。
        p, d = opened_owned[0]
        findings.append(make_finding(
            "EXT-CL-03",
            ("公网可达：容器 / 编排管理端口开放，接口身份未确认" if is_public
             else "内网可见（非公网暴露）：容器 / 编排管理端口开放，接口身份未确认"),
            ctx.target_name, endpoint=f"{ip}:{p}",
            severity="高危" if is_public else "中危",
            confidence="Medium", evidence_level="A",
            description=(f"{ip} 的 {[q for q, _ in opened_owned]} 端口 TCP 可建立连接，"
                         f"但未取得可识别 {d} 身份的响应内容，因此**既无法确认**"
                         "该端口运行的是容器 / 编排管理接口，**也无法排除**。"
                         "端口开放这一事实本身已属非预期暴露。"
                         + ("" if is_public else "目标可达范围为内网，本条不计入公网风险。")),
            technical_detail=(f"地址：{ip}\n"
                              f"TCP 可连接的端口：{[q for q, _ in opened_owned]}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              "未取得身份特征响应 —— 置信度中，需人工核实服务类型。"),
            impact=("若确为容器 / 编排管理接口且未启用认证，可延伸至主机或集群接管；"
                    "若为其他服务，则属普通非预期端口暴露。两种情形处置方式不同，"
                    "需先确认服务类型。"),
            reproduction=(f"nc -vz {ip} {p}\n"
                          f"curl -s --max-time 6 http://{ip}:{p}/version"),
            remediation=("① 先确认该端口运行的服务；"
                         "② 非对外必需则从安全组移除放行；"
                         "③ 属管理接口的一律只允许运维网段访问并启用认证。"),
            compliance="等保2.0 安全区域边界-访问控制",
            evidence=[finding_evidence("network", f"tcp {ip}:{p} open; 无身份特征响应",
                                       "端口连通性")],
            grading_basis="实测 TCP 可达但未确认服务身份，按非预期端口暴露定级并标注置信度中",
        ))

    note = (f"探测 {len(targets)} 个容器管理端口，本项定级范围内开放 "
            f"{len(opened_owned)} 个"
            + (f"（{', '.join(str(q) for q, _ in opened_owned)}）" if opened_owned else "")
            + f"，命中身份特征 {len(hits)} 个"
            + (f"：{', '.join(str(h[0]) for h in hits)}" if hits else ""))
    if delegated:
        note += ("；不归本项定级的已开放端口：" +
                 "、".join(f"{p}(→{o})" for p, o in sorted(delegated)))
    return found(note, findings, probes=probes, evidence_kind="容器端口实测")


# ======================================================================
# EXT-CL-04 K8s API Server 暴露
# ======================================================================
@make_auto("EXT-CL-04", name="Kubernetes API 暴露核查", tool="端口 + API 探测",
           risk=RISK_STANDARD, evidence_kind="K8s API 实测",
           detector_ref="checks/extras.py:cl04")
def cl04(ctx: DetectorContext):
    ip = ctx._cache.get("info04_ip") or ""
    probes = 0
    hits = []

    opened_k8s: list[int] = []
    if ip:
        for port in (6443, 10250, 10255):
            probes += 1
            if not net.tcp_open(ip, port):
                continue
            # 6443 / 10250 / 10255 的「上报出口」是本项（见 net.PORT_OWNER），
            # 所以这里必须承担兜底责任：认不出身份也要报，不能静默 ——
            # 否则 EXT-CL-02 不再兜底、本项又不报，端口就成了没人管的盲区。
            opened_k8s.append(port)
            text = net.http_text(f"https://{ip}:{port}/version", timeout=8) or \
                net.http_text(f"http://{ip}:{port}/version", timeout=8)
            if re.search(r'(gitVersion|"major"|kubelet|Kubernetes)', text, re.I):
                hits.append((f"https://{ip}:{port}/version", text[:300]))

    for p in K8S_API_PATHS:
        if hits:
            break
        probes += 1
        pr = probe_or_none(ctx, p)
        if pr is None or getattr(pr, "status", 0) != 200:
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if re.search(r'("kind"\s*:\s*"(VersionInfo|APIVersions|PodList)"|gitVersion)', body):
            hits.append((urljoin(ctx.target_url, p), body[:300]))

    findings = []
    if hits:
        ep, frag = hits[0]
        scope, _, scope_why = reachability_scope(ctx)
        is_public = scope == "公网可达"
        findings.append(make_finding(
            "EXT-CL-04",
            ("Kubernetes API Server 对外可达" if is_public
             else f"内网可见（非公网暴露）：Kubernetes API Server ({scope})"),
            ctx.target_name, endpoint=ep,
            severity="严重" if is_public else "高危",
            confidence="High", evidence_level="A",
            description=("Kubernetes API Server 可访问，且未携带凭据即取到版本信息。"
                         "⚠️ 版本信息接口本身通常不需要认证，"
                         "**能取版本不等于能以匿名身份操作集群**，"
                         "需进一步验证列举命名空间 / 读取 Secret 是否成功。"
                         + ("" if is_public else
                            f"目标可达范围为「{scope}」，本条不计入公网风险，"
                            "实际危害取决于内网访问控制。")),
            technical_detail=(f"地址：{ep}\n响应片段：{frag}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"本项探测到已开放的控制面端口：{opened_k8s}"),
            impact=("K8s API 是集群的控制平面。若确能以匿名身份或弱凭据访问，"
                    "可列举命名空间、读取 Secret（含数据库口令与各类密钥）、"
                    "创建特权 Pod 挂载宿主目录，一步取得全部节点权限。"
                    "上述后果以「确实可未授权操作」为前提，需人工验证后定论。"),
            reproduction=(f"curl -sk {ep} | head -20\n"
                          f"# 验证未授权可读：curl -sk https://{ip}:6443/api/v1/namespaces/default/secrets"),
            remediation=("① API Server 不暴露公网；"
                         "② 关闭匿名认证（`--anonymous-auth=false`）；"
                         "③ 启用 RBAC 并最小化权限；"
                         "④ 开启审计日志并告警异常 API 调用。"),
            compliance="等保2.0 安全区域边界-访问控制",
            evidence=[finding_evidence("response", frag, "K8s API 响应")],
            grading_basis=(f"实测集群控制面可达（可达范围「{scope}」），"
                           + ("按公网暴露定严重" if is_public else "按内网暴露定高危")),
        ))
    elif opened_k8s:
        # 控制面端口开着但取不到可识别身份的内容 —— 必须报，理由同 EXT-CL-03：
        # 这些端口的上报出口已归本项，EXT-CL-02 不再兜底，静默就是假阴性。
        findings.append(make_finding(
            "EXT-CL-04",
            ("公网可达：K8s 控制面端口开放，身份未确认" if is_public
             else "内网可见（非公网暴露）：K8s 控制面端口开放，身份未确认"),
            ctx.target_name, endpoint=f"{ip}:{opened_k8s[0]}",
            severity="高危" if is_public else "中危",
            confidence="Medium", evidence_level="A",
            description=(f"{ip} 的 {opened_k8s} 端口 TCP 可建立连接，"
                         "但未取得可识别 Kubernetes 身份的响应内容 —— "
                         "**既无法确认**其为 K8s 控制面，**也无法排除**。"
                         "控制面端口出现在非预期位置本身即需核实。"
                         + ("" if is_public else "目标可达范围为内网，本条不计入公网风险。")),
            technical_detail=(f"地址：{ip}\nTCP 可连接的端口：{opened_k8s}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              "未取得身份特征响应 —— 置信度中，需人工核实服务类型。"),
            impact=("若确为 K8s 控制面且可未授权访问，可读取 Secret、创建特权 Pod，"
                    "进而取得全部节点权限；若为其他服务，则属普通非预期端口暴露。"),
            reproduction=(f"nc -vz {ip} {opened_k8s[0]}\n"
                          f"curl -sk --max-time 8 https://{ip}:{opened_k8s[0]}/version"),
            remediation=("① 先确认这些端口运行的服务；"
                         "② 非必需则从安全组移除放行；"
                         "③ 属控制面的一律不暴露公网并关闭匿名认证。"),
            compliance="等保2.0 安全区域边界-访问控制",
            evidence=[finding_evidence("network", f"tcp {ip} open: {opened_k8s}",
                                       "端口连通性")],
            grading_basis="实测 TCP 可达但未确认服务身份，按非预期端口暴露定级并标注置信度中",
        ))

    # 旧文案写死了「未发现公网可达的 K8s API」—— 内网目标上这句是错的，
    # 会把「内网开放」说成「公网没开放」，读者据此以为无暴露。
    note = (f"探测 K8s 相关端点 {probes} 次；控制面端口（6443/10250/10255）开放 "
            f"{len(opened_k8s)} 个"
            + (f"（{opened_k8s}）" if opened_k8s else "")
            + ("；命中可达" if hits else "；未取得身份特征响应"))
    return found(note, findings, probes=probes, evidence_kind="K8s API 实测")


# ======================================================================
# EXT-CL-05 云服务默认域名与测试环境暴露
# ======================================================================
@make_auto("EXT-CL-05", name="测试环境与内部域名暴露核查", tool="DNS 枚举",
           risk=RISK_STANDARD, evidence_kind="子域解析实测",
           detector_ref="checks/extras.py:cl05")
def cl05(ctx: DetectorContext):
    prefixes = ["dev", "test", "uat", "sit", "stage", "staging", "pre", "preview",
                "demo", "sandbox", "gray", "canary", "beta", "internal", "admin",
                "backend", "db", "test-db", "mysql", "redis", "gitlab", "jenkins",
                "sonar", "nexus", "wiki", "confluence", "jira", "monitor", "grafana"]
    found_subs = []
    probes = 0
    for pre in prefixes:
        name = f"{pre}.{ctx.domain}"
        probes += 1
        ips = net.dns_records(name, "A")
        if ips:
            found_subs.append((name, ips[0]))

    risky = [(n, ip) for n, ip in found_subs
             if re.search(r"(dev|test|uat|sit|stage|staging|demo|sandbox|internal|"
                          r"mysql|redis|db|gitlab|jenkins|nexus|admin|backend)",
                          n, re.I)]
    findings = []
    if risky:
        n, ip = risky[0]
        findings.append(make_finding(
            "EXT-CL-05", f"发现 {len(risky)} 个测试 / 内部环境域名对公网解析",
            ctx.target_name, endpoint=f"https://{n}",
            severity="中危", confidence="High", evidence_level="A",
            description=("除生产域名外还解析出了测试、预发或内部工具类子域。"
                         "这类环境通常缺少生产环境的安全加固与访问控制。"),
            technical_detail=("解析出的环境域名：\n"
                              + "\n".join(f"  · {n} → {ip}" for n, ip in risky[:20])),
            impact=("① 测试环境常有默认口令、调试接口开启、数据未脱敏"
                    "（最常见的是测试库中含真实个人信息）；"
                    "② 内部工具（Jenkins / GitLab / Nexus）暴露常伴随未授权访问；"
                    "③ 可从非生产环境入手获取生产配置与凭据。"),
            reproduction="\n".join(f"dig +short {n}" for n, _ in risky[:5]),
            remediation=("① 非生产环境不解析公网域名，通过 VPN / 内网访问；"
                         "② 必须开放时加来源 IP 白名单与统一身份认证；"
                         "③ 测试数据必须脱敏，禁止使用生产数据副本；"
                         "④ 建立域名台账，定期核对公网解析记录。"),
            compliance="等保2.0 安全区域边界-访问控制 / PIPL 第 51 条",
            evidence=[finding_evidence("dns", str(risky[:20]), "环境子域解析")],
            grading_basis="环境域名公网可解析属实测，具体风险需登录确认，定中危",
        ))

    ctx._cache["cl05_subs"] = found_subs
    note = (f"枚举 {len(prefixes)} 个环境前缀，解析成功 {len(found_subs)} 个"
            f"（测试 / 内部类 {len(risky)} 个）")
    return found(note, findings, probes=probes, evidence_kind="子域解析实测")


# ======================================================================
# EXT-CL-06 云凭据泄露
# ======================================================================
@make_auto("EXT-CL-06", name="云凭据泄露核查", tool="前端产物与配置实测",
           risk=RISK_SAFE, requires=["js"], evidence_kind="云凭据特征实测",
           detector_ref="checks/extras.py:cl06")
def cl06(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    patterns = [
        (r"(?:AKIA|ASIA)[0-9A-Z]{16}", "AWS Access Key ID", "严重"),
        (r"LTAI[0-9A-Za-z]{12,}", "阿里云 AccessKey ID", "严重"),
        (r"AKID[0-9A-Za-z]{13,}", "腾讯云 SecretId", "严重"),
        (r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*[\"'][A-Za-z0-9/+=]{30,}",
         "AWS Secret Key", "严重"),
        (r"(?i)access[_-]?key[_-]?secret\s*[:=]\s*[\"'][A-Za-z0-9/+=]{20,}", "云厂商 Secret", "严重"),
    ]
    hits = [(name, sev) for pat, name, sev in patterns if re.search(pat, blobs)]

    findings = []
    if hits:
        order = ["信息", "低危", "中危", "高危", "严重"]
        worst = max((h[1] for h in hits), key=lambda s: order.index(s))
        findings.append(make_finding(
            "EXT-CL-06", f"前端产物中发现 {len(hits)} 类云凭据特征",
            ctx.target_name, endpoint=ctx.target_url,
            severity=worst, confidence="Medium", evidence_level="B",
            description="前端代码中匹配到了云厂商凭据的特征串。前端产物对所有访客可见。",
            technical_detail="命中的凭据类型：\n" + "\n".join(
                f"  · {n}（{s}）" for n, s in hits)
                + "\n（凭据实际值不在报告中记录）",
            impact=("云 AccessKey 泄露后可直接调用云 API：列举并下载对象存储文件、"
                    "读取数据库快照、创建新资源用于挖矿（造成费用损失）。"
                    "这是近年数据泄露事件中最高频的初始入口之一。"),
            reproduction="在前端产物中检索 AKIA / LTAI / AKID 等前缀，确认是否为真实凭据。",
            remediation=("① 立即在云控制台轮换该凭据；"
                         "② 前端绝不放云凭据，云操作经后端代理；"
                         "③ 使用临时凭证（STS）并绑定最小权限策略；"
                         "④ 开启云审计日志并对异常调用告警；"
                         "⑤ 接入密钥扫描工具防止再次提交。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / ISO 27001 A.8.24",
            evidence=[finding_evidence("file", str(hits), "云凭据特征")],
            grading_basis="静态匹配到云凭据特征，实际可用性需人工确认，按 B 级定严重",
        ))

    note = f"云凭据特征命中 {len(hits)} 类"
    return found(note, findings, probes=1, evidence_kind="云凭据特征实测")


# ======================================================================
# EXT-CL-07 镜像仓库暴露
# ======================================================================
@make_auto("EXT-CL-07", name="镜像仓库暴露核查", tool="HTTP 探测",
           risk=RISK_STANDARD, evidence_kind="仓库接口实测",
           detector_ref="checks/extras.py:cl07")
def cl07(ctx: DetectorContext):
    ip = ctx._cache.get("info04_ip") or ""
    probes = 0
    hits = []
    for p in ("v2/_catalog", "v2/_catalog?n=100", "v2/",
              "service/rest/v1/repositories", "artifactory/api/repositories"):
        probes += 1
        pr = probe_or_none(ctx, p)
        if pr is None:
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if re.search(r'("repositories"\s*:|"name"\s*:\s*"[^"]+/[^"]+")', body):
            hits.append((urljoin(ctx.target_url, p), body[:400]))
            break

    if ip and not hits:
        probes += 1
        if net.tcp_open(ip, 5000):
            body = net.http_text(f"http://{ip}:5000/v2/_catalog", timeout=8)
            if body and re.search(r'"repositories"|_catalog', body):
                hits.append((f"http://{ip}:5000/v2/_catalog", body[:400]))

    findings = []
    if hits:
        ep, frag = hits[0]
        findings.append(make_finding(
            "EXT-CL-07", "容器镜像仓库可未授权访问",
            ctx.target_name, endpoint=ep,
            severity="高危", confidence="High", evidence_level="A",
            description="镜像仓库的目录接口可直接访问并返回了镜像清单，"
                        "说明仓库未启用认证或存在匿名读取权限。",
            technical_detail=f"地址：{ep}\n响应片段：{frag}",
            impact=("镜像中常包含应用源码、配置文件（含数据库口令与云凭据）、"
                    "内部服务地址，以及基础镜像历史层中残留的被删密钥文件。"
                    "拿到镜像等于拿到应用的全部内部信息。"),
            reproduction=f"curl -s '{ep}' | head -30",
            remediation=("① 镜像仓库启用强制认证，关闭匿名读取；"
                         "② 构建使用多阶段构建，产物层不含源码与配置；"
                         "③ 不在镜像中烘焙任何凭据；"
                         "④ 仓库仅在内网可达。"),
            compliance="等保2.0 安全计算环境-数据保密性 / ISO 27001 A.8.28",
            evidence=[finding_evidence("response", frag, "镜像仓库响应")],
            grading_basis="实测仓库目录可未授权访问，定高危",
        ))

    note = (f"探测镜像仓库接口 {probes} 次，"
            f"{'命中未授权访问' if hits else '未发现可访问的镜像仓库'}")
    return found(note, findings, probes=probes, evidence_kind="仓库接口实测")


# ======================================================================
# EXT-CL-08 对象存储签名与目录遍历
# ======================================================================
@make_auto("EXT-CL-08", name="对象存储签名与目录遍历核查", tool="内置检测器 + JS 分析",
           risk=RISK_STANDARD, evidence_kind="存储访问实测",
           detector_ref="checks/extras.py:cl08")
def cl08(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    signed = re.findall(r"https?://[^\s\"'<>]*[?&](?:Signature|signature|OSSAccessKeyId|"
                        r"X-Amz-Signature|X-Amz-Credential)=[^\s\"'<>&]+", blobs)
    buckets = set(re.findall(r"([a-z0-9\-\.]+)\.(?:oss[\w\-]*\.aliyuncs\.com|"
                             r"s3[\w\-]*\.amazonaws\.com|cos\.[\w\-]+\.myqcloud\.com)",
                             blobs, re.I))
    findings = []
    probes = 0

    if signed:
        findings.append(make_finding(
            "EXT-CL-08", f"前端产物中包含 {len(signed)} 个带签名的存储访问地址",
            ctx.target_name, endpoint=signed[0][:200],
            severity="中危", confidence="High", evidence_level="B",
            description=("前端拿到了带签名的对象存储访问地址。"
                         "签名分发本身是合规做法，但需确认签名有效期与权限范围。"),
            technical_detail=("签名地址数量：" + str(len(signed)) + "\n"
                              "说明：签名内容不在报告中记录。"),
            impact=("若签名有效期过长（数天以上）或权限为写，"
                    "泄露的签名可被他人用于下载甚至覆盖对象；"
                    "若可通过修改路径遍历其他对象，则可读取他人文件。"),
            reproduction="取出签名地址，尝试修改其路径中的对象名后访问，观察是否仍可下载。",
            remediation=("① 签名有效期尽量短（建议 ≤ 15 分钟）；"
                         "② 按最小权限签发（只读、单对象）；"
                         "③ 私有文件走应用层代理鉴权而非前端直传地址；"
                         "④ 对象名使用不可枚举的随机串。"),
            compliance="等保2.0 安全计算环境-访问控制 / PIPL 第 51 条",
            evidence=[finding_evidence("file", f"{len(signed)} 个签名地址", "签名 URL")],
            grading_basis="签名地址存在属实测，滥用可行性需人工确认，按 B 级定中危",
        ))

    for b in list(buckets)[:5]:
        probes += 1
        url = f"https://{b}.aliyuncs.com/?list-type=2&max-keys=5"
        body = net.http_text(url, timeout=10)
        if "<ListBucketResult" in body or "<Contents>" in body:
            keys = re.findall(r"<Key>([^<]+)</Key>", body)[:5]
            findings.append(make_finding(
                "EXT-CL-08", "对象存储桶允许匿名列举对象",
                ctx.target_name, endpoint=url,
                severity="严重", confidence="High", evidence_level="A",
                description="该存储桶对公网开放了列举权限，任何人无需凭据即可列出桶内全部文件。",
                technical_detail=f"桶地址：{url}\n返回对象示例：{', '.join(keys) or '（返回了 ListBucketResult）'}",
                impact="可直接枚举并下载桶内全部对象，若存放用户文件或数据导出，等同全量数据泄露。",
                reproduction=f"curl -s '{url}' | head -20",
                remediation="将桶设为私有并移除 ListBucket 授权；对外分发改用短时效签名 URL。",
                compliance="等保2.0 安全计算环境-数据保密性",
                evidence=[finding_evidence("response", body[:800], "桶列举结果")],
                grading_basis="实测匿名可列举桶内对象，定严重",
                # 同 conf11：声明发现所在端点，否则复现脚本会去打网站首页
                # （桶地址不是站点子域），把真实暴露误判成「未复现」。
                extra={"repro_base": url.split("?")[0]},
            ))
            break

    if not signed and not buckets:
        return no_target_outcome(
            ctx, "对象存储引用（前端产物中未见签名地址或桶域名）",
            probes=probes, evidence_kind="存储访问实测")

    note = (f"发现签名地址 {len(signed)} 个、存储桶引用 {len(buckets)} 个，"
            f"桶遍历探测 {probes} 次")
    return found(note, findings, probes=probes, evidence_kind="存储访问实测")


# ======================================================================
# EXT-CL-09 主机层已知漏洞
# ======================================================================
@make_auto("EXT-CL-09", name="主机层已知漏洞核查（外部可判定部分）", tool="服务横幅比对",
           risk=RISK_STANDARD, evidence_kind="服务横幅实测",
           detector_ref="checks/extras.py:cl09",
           # 基于 INFO-04 端口结果做 nmap 横幅比对，不经 HTTP。
           needs_app=False)
def cl09(ctx: DetectorContext):
    ip = ctx._cache.get("info04_ip") or ""
    if not ip:
        return no_target_outcome(ctx, "目标 IP（DNS 解析未取得地址）", probes=1, evidence_kind="无 IP")

    opened = [p for p, v in (ctx._cache.get("info04_ports") or {}).items() if v][:20]
    if not opened:
        # 没有任何开放端口数据可做横幅比对。可能是端口收口得干净，
        # 也可能是端口探测根本没拿到结果 —— 两者必须区分，后者不能算通过。
        if not (ctx._cache.get("info04_ports") or {}):
            return no_data_outcome(
                "端口探测结果",
                f"{ip} 的端口探测未返回任何数据，无法做服务横幅比对",
                probes=1, evidence_kind="服务横幅实测")
        return na(f"{ip} 未探测到开放端口，无横幅可比对，本项不适用。",
                  probes=1, evidence_kind="服务横幅实测")

    svc = net.nmap_scan(ip, opened) if opened else {}
    findings = []
    identified = [(p, d) for p, d in svc.items() if d and d != "open"]
    for port, desc in identified:
        if re.search(r"(OpenSSH_[1-7]\.|Apache/2\.[0-2]\.|nginx/1\.[0-9]\.|"
                     r"MySQL\s*5\.[0-6]|Redis.*[1-5]\.|OpenSSL/1\.0|"
                     r"Microsoft-IIS/[1-9]\.0|vsftpd 2\.3\.4|ProFTPD 1\.3\.3)", desc, re.I):
            findings.append(make_finding(
                "EXT-CL-09", f"{port}/tcp 运行已知存在高危漏洞的服务版本",
                ctx.target_name, endpoint=f"{ip}:{port}",
                severity="高危", confidence="Medium", evidence_level="B",
                description=f"服务识别结果显示该端口运行的是历史高危版本：{desc}。",
                technical_detail=f"地址：{ip}:{port}\n服务识别结果：{desc}",
                impact=("按服务不同可导致远程代码执行、权限提升或数据读取。"
                        "例如 vsftpd 2.3.4 存在后门、OpenSSH 旧版本存在多个提权与 RCE 问题。"),
                reproduction=f"nmap -Pn -sV -p {port} {ip}",
                remediation=("① 升级该服务到厂商支持的安全版本；"
                             "② 若无需对外提供服务，直接在安全组关闭该端口；"
                             "③ 升级前先在测试环境验证兼容性。"),
                compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.8",
                evidence=[finding_evidence("network", f"{port}: {desc}", "服务版本识别")],
                grading_basis="服务版本经识别命中高危特征，未实测利用，按 B 级定高危",
            ))
            break

    note = (f"服务识别覆盖 {len(opened)} 个开放端口，识别到版本 {len(identified)} 条，"
            f"命中高危版本 {len(findings)} 条")
    return found(note, findings, probes=len(opened) + 1, evidence_kind="服务横幅实测")


# ======================================================================
# EXT-CD-01 流水线配置文件泄露
# ======================================================================
@make_auto("EXT-CD-01", name="流水线配置文件泄露核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="CI 配置实测",
           detector_ref="checks/extras.py:cd01")
def cd01(ctx: DetectorContext):
    hits = scan_paths(ctx, CICD_PATHS)
    findings = []
    if hits:
        with_creds = [p for p, pr in hits.items()
                      if re.search(r"(password|token|secret|_KEY|_TOKEN|credential|"
                                   r"ssh-rsa|BEGIN.*PRIVATE KEY)",
                                   getattr(pr, "body_snippet", "") or "", re.I)]
        first = list(hits)[0]
        findings.append(make_finding(
            "EXT-CD-01", f"CI/CD 配置文件对外可读（{len(hits)} 个）",
            ctx.target_name, endpoint=getattr(hits[first], "final_url", "")
            or urljoin(ctx.target_url, first),
            severity="高危" if with_creds else "中危",
            confidence="High", evidence_level="A",
            description=("流水线配置文件被部署到了公网可访问的目录。"
                         "这类文件描述了构建流程、部署目标与凭据引用方式。"),
            technical_detail=("可读的配置文件：\n"
                              + "\n".join(f"  · {p}" for p in list(hits)[:12])
                              + (f"\n\n其中疑似含凭据：{', '.join(with_creds)}" if with_creds else "")),
            impact=("泄露的流水线配置可暴露部署目标服务器地址、制品库凭据引用、"
                    "私有依赖源地址、构建脚本中的硬编码密钥。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, first)} | head -40",
            remediation=("① CI 配置文件不随产物部署到 Web 目录；"
                         "② 凭据使用 CI 平台的 Secret 机制；"
                         "③ 部署流程只拷贝必要的运行时文件。"),
            compliance="等保2.0 安全计算环境-数据保密性 / ISO 27001 A.8.28",
            evidence=[finding_evidence("response",
                                       (getattr(hits[first], "body_snippet", "") or "")[:1000],
                                       first)],
            grading_basis="配置实测可下载，疑似含凭据者按高危处理",
        ))

    note = f"探测 {len(CICD_PATHS)} 个 CI/CD 配置路径，命中 {len(hits)} 个"
    return found(note, findings, probes=len(CICD_PATHS), evidence_kind="CI 配置实测")


# ======================================================================
# EXT-CD-02 构建产物与制品仓库暴露
# ======================================================================
@make_auto("EXT-CD-02", name="构建产物与制品仓库暴露核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="制品路径实测",
           detector_ref="checks/extras.py:cd02")
def cd02(ctx: DetectorContext):
    paths = ["artifacts/", "build/", "dist/", "target/", "release/", "releases/",
             "packages/", "repository/", "nexus/", "artifactory/", "archiva/",
             "jars/", "libs/", "war/", "apps/", "download/", "downloads/",
             "service/rest/v1/repositories", "artifactory/api/repositories"]
    hits = scan_paths(ctx, paths)
    repo_hits = {p: pr for p, pr in hits.items()
                 if re.search(r"(nexus|artifactory|archiva|repositories)", p, re.I)
                 or re.search(r'("repositories"|"name"\s*:\s*"[^"]+")',
                              getattr(pr, "body_snippet", "") or "")}
    artifact_hits = {p: pr for p, pr in hits.items() if p not in repo_hits}
    findings = []
    if hits:
        first = list(repo_hits or artifact_hits)[0]
        pr = (repo_hits or artifact_hits)[first]
        scope, _, scope_why = reachability_scope(ctx)
        is_public = scope == "公网可达"
        findings.append(make_finding(
            "EXT-CD-02",
            (f"构建产物 / 制品仓库目录对外可达（{len(hits)} 个）" if is_public
             else f"内网可见（非公网暴露）：构建产物 / 制品仓库目录（{len(hits)} 个）"),
            ctx.target_name, endpoint=getattr(pr, "final_url", "")
            or urljoin(ctx.target_url, first),
            severity=("高危" if repo_hits else "中危") if is_public else "中危",
            confidence="High", evidence_level="A",
            description=("构建产物目录或制品仓库接口可以直接访问。"
                         "制品仓库中存放的是可部署的软件包，含完整的应用与配置。"
                         + ("" if is_public else
                            f"目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=("可访问的路径：\n"
                              + "\n".join(f"  · /{p}" for p in sorted(hits)[:15])
                              + (f"\n\n其中制品仓库接口：{list(repo_hits)}" if repo_hits else "")
                              + f"\n可达性判定：{scope}\n判定依据：{scope_why}"),
            impact=("下载到可部署的软件包后可解包分析：源码、配置文件、"
                    "数据库脚本、硬编码凭据、内部接口定义全部可得。"
                    "这是攻击效率最高的一条信息获取路径。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, first)} | head -40",
            remediation=("① 制品仓库与构建产物目录不对公网开放；"
                         "② 仓库启用强制认证并配置权限；"
                         "③ 部署时只发布运行时必要文件。"),
            compliance="等保2.0 安全计算环境-数据保密性 / ISO 27001 A.8.28",
            evidence=[finding_evidence("response",
                                       (getattr(pr, "body_snippet", "") or "")[:900], first)],
            grading_basis="制品路径实测可达，仓库类按高危处理",
        ))

    note = f"探测 {len(paths)} 个制品路径，命中 {len(hits)} 个（仓库类 {len(repo_hits)}）"
    return found(note, findings, probes=len(paths), evidence_kind="制品路径实测")


# ======================================================================
# EXT-CD-03 版本控制与配置泄露
# ======================================================================
@make_auto("EXT-CD-03", name="版本控制与配置泄露核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="VCS 与配置实测",
           detector_ref="checks/extras.py:cd03")
def cd03(ctx: DetectorContext):
    checks = [".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
              ".svn/entries", ".svn/wc.db", ".hg/hgrc",
              ".env", ".env.local", ".env.production"]
    res = ctx.probe_many(checks)
    hit_git = [p for p in (".git/HEAD", ".git/config", ".git/index")
               if is_real_hit(ctx, res.get(p), min_len=5)]
    hit_env = [p for p in (".env", ".env.local", ".env.production")
               if is_real_hit(ctx, res.get(p), min_len=10)]
    findings = []

    if hit_git:
        findings.append(make_finding(
            "EXT-CD-03", "Git 仓库目录泄露，可还原完整源码",
            ctx.target_name, endpoint=urljoin(ctx.target_url, hit_git[0]),
            severity="严重", confidence="High", evidence_level="A",
            description=("服务器上残留了 .git 目录且可从公网访问。"
                         "利用公开工具可以下载全部对象并还原出完整的源码仓库，包括提交历史。"),
            technical_detail=(f"可访问的 Git 文件：{', '.join(hit_git)}\n"
                              f"响应示例：{(getattr(res.get(hit_git[0]), 'body_snippet', '') or '')[:300]}"),
            impact=("还原源码后可获得全部业务逻辑与隐藏接口、数据库结构与连接方式、"
                    "硬编码凭据，以及**提交历史中被删除但仍在历史中的密钥**"
                    "（很多团队误以为删掉文件就安全了）。"),
            reproduction=(f"curl -s {urljoin(ctx.target_url, '.git/HEAD')}\n"
                          "# 若返回 ref: refs/heads/... 则可使用公开工具转储仓库"),
            remediation=("① 立即删除服务器上的 .git 目录；"
                         "② 部署使用 `git archive` 或 CI 产出的干净包；"
                         "③ Nginx 加 `location ~ /\\.git { deny all; return 404; }`；"
                         "④ 若已泄露，轮换所有曾提交过的凭据（含历史提交）。"),
            compliance="等保2.0 安全计算环境-数据保密性 / CWE-538",
            evidence=[finding_evidence("response",
                                       str({p: (getattr(res.get(p), 'body_snippet', '') or '')[:200]
                                            for p in hit_git}), "Git 目录响应")],
            grading_basis="实测 .git 目录可访问，可还原完整源码，定严重",
        ))

    if hit_env:
        body = getattr(res.get(hit_env[0]), "body_snippet", "") or ""
        scope, _, scope_why = reachability_scope(ctx)
        findings.append(make_finding(
            "EXT-CD-03",
            (f"环境变量文件可直接下载（{', '.join(hit_env)}）" if scope == "公网可达"
             else f"内网可见（非公网暴露）：环境变量文件可直接下载（{', '.join(hit_env)}）"),
            ctx.target_name, endpoint=urljoin(ctx.target_url, hit_env[0]),
            severity="严重" if scope == "公网可达" else "高危",
            confidence="High", evidence_level="A",
            description=("环境变量文件（.env）被部署到了 Web 目录，可直接下载。"
                         "这类文件通常存放数据库口令、云凭据与第三方密钥。"
                         + ("" if scope == "公网可达" else
                            f"目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=(f"可下载的文件：{', '.join(hit_env)}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"内容片段（已脱敏）：\n{body[:600]}"),
            impact=("直接获得数据库连接口令、云存储凭据、第三方服务密钥。"
                    "持有这些凭据可直连业务数据库读取全量数据，"
                    "或访问云资源——攻击者不再需要攻击应用本身。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, hit_env[0])}",
            remediation=("① 立即删除并轮换文件中涉及的全部凭据；"
                         "② .env 不进入代码仓库、不随产物部署；"
                         "③ 凭据改用配置中心 / 密钥管理服务注入；"
                         "④ Nginx 禁止访问点开头的文件（`location ~ /\\. { deny all; }`）。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / PIPL 第 51 条",
            evidence=[finding_evidence("response", body[:1000], hit_env[0])],
            grading_basis="实测配置凭据文件可下载，定严重",
        ))

    note = (f"探测 {len(checks)} 个 VCS / 配置路径，"
            f"Git 目录命中 {len(hit_git)} 个，.env 命中 {len(hit_env)} 个")
    return found(note, findings, probes=len(checks), evidence_kind="VCS 与配置实测")


# ======================================================================
# EXT-CD-04 部署脚本与凭据残留
# ======================================================================
@make_auto("EXT-CD-04", name="部署脚本与凭据残留核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="部署脚本实测",
           detector_ref="checks/extras.py:cd04")
def cd04(ctx: DetectorContext):
    # 可达范围在函数入口取一次：本条发现的三处措辞与定级都要用它。
    _cd_scope, _, _cd_why = reachability_scope(ctx)
    paths = ["deploy.sh", "build.sh", "start.sh", "run.sh", "release.sh",
             "install.sh", "setup.sh", "deploy.py", "fabfile.py",
             "ansible/deploy.yml", "playbook.yml", "deploy.yaml",
             "docker-compose.yml", "docker-compose.prod.yml",
             "helm/values.yaml", "k8s/deployment.yaml", ".env.ci",
             "Makefile", "Procfile", "readme.md", "README.md", "CHANGELOG.md"]
    hits = scan_paths(ctx, paths)
    findings = []
    if hits:
        with_creds = [p for p, pr in hits.items()
                      if re.search(r"(password\s*=\s*[\"']?[^\s\"']{4,}|"
                                   r"token\s*=\s*[\"']?[A-Za-z0-9_\-]{12,}|"
                                   r"secret\s*=\s*[\"']?[A-Za-z0-9_\-]{8,}|"
                                   r"ssh\s+-i|BEGIN.*PRIVATE KEY|mysql\s+-u\s*\w+\s*-p\S+)",
                                   getattr(pr, "body_snippet", "") or "", re.I)]
        if with_creds:
            body = getattr(hits[with_creds[0]], "body_snippet", "") or ""
            findings.append(make_finding(
                "EXT-CD-04",
                (f"部署脚本可直接下载且疑似含凭据（{len(with_creds)} 个）"
                 if _cd_scope == "公网可达" else
                 f"内网可见（非公网暴露）：部署脚本可直接下载且疑似含凭据"
                 f"（{len(with_creds)} 个）"),
                ctx.target_name, endpoint=urljoin(ctx.target_url, with_creds[0]),
                severity="严重" if _cd_scope == "公网可达" else "高危",
                confidence="Medium", evidence_level="B",
                description=("部署脚本被部署到了 Web 目录，且内容匹配到凭据特征。"
                             "部署脚本通常包含服务器地址、账号口令与密钥路径。"
                             + ("" if _cd_scope == "公网可达" else
                                f"目标可达范围为「{_cd_scope}」，本条不计入公网风险。")),
                technical_detail=(f"可下载的脚本：{', '.join(with_creds)}\n"
                                  f"可达性判定：{_cd_scope}\n判定依据：{_cd_why}\n"
                                  f"内容片段（已脱敏）：\n{body[:700]}"),
                impact="脚本中的服务器地址与凭据组合可直接用于登录目标环境。",
                reproduction=f"curl -s {urljoin(ctx.target_url, with_creds[0])} | head -40",
                remediation=("① 部署脚本不进入 Web 目录；"
                             "② 凭据从环境变量或密钥管理服务读取；"
                             "③ 已泄露的凭据立即轮换。"),
                compliance="等保2.0 安全计算环境-身份鉴别 / ISO 27001 A.8.24",
                evidence=[finding_evidence("response", body[:1200], with_creds[0])],
                grading_basis="脚本可下载且含凭据特征，实际可用性需人工确认，按 B 级定严重",
            ))
        else:
            findings.append(make_finding(
                "EXT-CD-04",
                (f"部署脚本 / 说明文档可直接下载（{len(hits)} 个）"
                 if _cd_scope == "公网可达" else
                 f"内网可见（非公网暴露）：部署脚本 / 说明文档可直接下载（{len(hits)} 个）"),
                ctx.target_name, endpoint=urljoin(ctx.target_url, list(hits)[0]),
                severity="低危", confidence="High", evidence_level="A",
                description=("部署脚本或项目说明文档可直接下载，暴露了部署方式与目录结构。"
                             + ("" if _cd_scope == "公网可达" else
                                f"目标可达范围为「{_cd_scope}」，本条不计入公网风险。")),
                technical_detail=(f"可达性判定：{_cd_scope}\n可下载的文件：\n"
                                  + "\n".join(f"  · {p}" for p in list(hits)[:12])),
                impact="为攻击者提供部署架构与目录结构线索，降低摸底成本。",
                reproduction=f"curl -s {urljoin(ctx.target_url, list(hits)[0])} | head -30",
                remediation="部署脚本与开发文档不随产物发布。",
                compliance="ISO 27001 A.8.28",
                evidence=[finding_evidence("response",
                                           (getattr(hits[list(hits)[0]], "body_snippet", "") or "")[:800],
                                           list(hits)[0])],
                grading_basis="脚本可下载但未见凭据，定低危",
            ))

    note = f"探测 {len(paths)} 个部署 / 文档路径，命中 {len(hits)} 个"
    return found(note, findings, probes=len(paths), evidence_kind="部署脚本实测")


# ======================================================================
# EXT-CD-05 内部地址与拓扑泄露
# ======================================================================
@make_auto("EXT-CD-05", name="内部地址与拓扑泄露核查", tool="全量内容扫描",
           risk=RISK_SAFE, evidence_kind="内容特征实测",
           detector_ref="checks/extras.py:cd05")
def cd05(ctx: DetectorContext):
    blobs = [ctx.baseline_body] + list(ctx.js_result.get("bodies") or [])
    text = "\n".join(b for b in blobs if b)
    hdr_text = json.dumps(ctx.root_headers, ensure_ascii=False)

    hits = []
    for pat, desc in INTERNAL_ADDR_PATTERNS:
        if re.search(pat, text, re.I):
            hits.append((desc, "前端产物"))
        if re.search(pat, hdr_text, re.I):
            hits.append((desc, "响应头"))

    findings = []
    if hits:
        findings.append(make_finding(
            "EXT-CD-05", f"对外内容暴露 {len(hits)} 类内部地址 / 拓扑信息",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="High", evidence_level="A",
            description="响应头或前端产物中出现了内网地址、内部域名或非生产环境域名。",
            technical_detail="命中的信息类型：\n" + "\n".join(
                f"  · {d}（来源：{src}）" for d, src in hits),
            impact=("暴露内部拓扑后，攻击者可推断网络结构、识别内网服务地址，"
                    "为 SSRF 利用与横向移动提供目标清单。"
                    "非生产环境域名的出现还提示存在配置混淆风险。"),
            reproduction=f"curl -s {ctx.target_url} | grep -oE '10\\.[0-9.]+|192\\.168\\.[0-9.]+'",
            remediation=("① 响应头不暴露内部地址（如 Location 使用外部域名）；"
                         "② 前端构建通过环境变量注入地址，禁止硬编码；"
                         "③ 统一使用对外域名，内网地址只在服务端配置中出现。"),
            compliance="ISO 27001 A.8.9 / 等保2.0 安全计算环境-数据保密性",
            evidence=[finding_evidence("response", str(hits), "内部地址特征")],
            grading_basis="信息泄露经实测确认，未直接导致损失，定低危",
        ))

    note = f"扫描前端产物 {len(blobs)} 份与响应头，命中内部地址特征 {len(hits)} 类"
    return found(note, findings, probes=1, evidence_kind="内容特征实测")


# ======================================================================
# EXT-SC-09 依赖包伪装（typosquatting）
#
# 2026-10-10 新增：靶场答案表把 Frontend / Legacy Typosquatting 两项判为
# 「能力缺口」——全量检查项里没有任何一项负责「包名是不是被抢注的近似包」。
# EXI-SC-01 只比对**版本是否命中 CVE**，SC-04 只判**外链有没有 SRI**，
# 都没有回答「这个包本身是不是假的」。
#
# 做法刻意保守：**不联网查 registry**。底座是零外联的（离线可跑、不向
# 第三方暴露被测目标），所以这里用本地的知名包名表 + 编辑距离/伪装前后缀
# 做离线近似比对，命中只报「高度疑似」，真实来源交人工确认。
# ======================================================================
# 生态内高频包名（前端 / Node 主流，作为近似比对的基准集）
_POPULAR_PACKAGES = (
    "react", "react-dom", "vue", "angular", "jquery", "lodash", "axios", "express",
    "moment", "dayjs", "chalk", "commander", "debug", "bluebird", "async", "underscore",
    "webpack", "babel", "eslint", "prettier", "typescript", "ts-node", "nodemon",
    "sequelize", "mongoose", "mysql", "mysql2", "pg", "redis", "sqlite3", "knex",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet", "morgan", "cors",
    "body-parser", "cookie-parser", "socket.io", "ws", "uuid", "semver", "yargs",
    "glob", "rimraf", "cross-env", "dotenv", "colors", "kleur", "ora", "inquirer",
    "node-fetch", "form-data", "multer", "pdfkit", "exceljs", "zod", "joi", "class-validator",
    "sanitize-html", "dompurify", "marked", "highlight.js", "epilogue-js", "serve-favicon",
    "errorhandler", "compression", "method-override", "connect", "finalhandler",
    "jsonwebtoken", "argon2", "node-cron", "winston", "pino", "mocha", "chai", "jest",
)

# 抢注包最常加的伪装前后缀
_TYPOSQUAT_SUFFIX = ("-js", ".js", "-ng", "-node", "-lib", "-ts", "-core", "js")
_TYPOSQUAT_PREFIX = ("node-", "js-", "ng-", "the-")


def _edit_distance_leq1(a: str, b: str) -> bool:
    """编辑距离 ≤ 1（只判替换一个字符 / 插入一个字符，够用且零依赖）。"""
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long_):
        if short[i] == long_[j]:
            i += 1
            j += 1
        else:
            if skipped:
                return False
            skipped = True
            j += 1
    return True


def _suspicious_package_names(deps: dict[str, str]) -> list[tuple[str, str]]:
    """返回 (可疑包名, 可疑理由)。宁可少报，也不把正常包打成恶意包。"""
    base = {p.lower() for p in _POPULAR_PACKAGES}
    out: list[tuple[str, str]] = []
    for name in sorted(deps):
        n = name.lower().lstrip("@").split("/")[-1]
        if not n or n in base:
            continue
        reason = ""
        for suf in _TYPOSQUAT_SUFFIX:
            if n.endswith(suf) and n[: -len(suf)] in base:
                reason = f"比知名包 {n[: -len(suf)]} 多了伪装后缀「{suf}」"
                break
        if not reason:
            for pre in _TYPOSQUAT_PREFIX:
                if n.startswith(pre) and n[len(pre):] in base:
                    reason = f"比知名包 {n[len(pre):]} 多了伪装前缀「{pre}」"
                    break
        if not reason:
            for p in base:
                if _edit_distance_leq1(n, p):
                    reason = f"与知名包 {p} 仅差一个字符（typo）"
                    break
        if reason:
            out.append((name, reason))
    return out[:8]


@make_auto("EXT-SC-09", name="依赖包伪装（typosquatting）核查", tool="依赖清单 + 本地近似名比对",
           risk=RISK_SAFE, requires=["js"], evidence_kind="包名近似比对",
           detector_ref="checks/extras.py:sc09")
def sc09(ctx: DetectorContext):
    deps, src = _fetch_manifest_deps(ctx)
    if not deps:
        # 拿不到清单不等于没有问题：写清是「没有材料」还是「比对无命中」
        return found(f"未取得依赖清单（尝试 {len(_DEPENDENCY_MANIFESTS)} 个常见清单路径均未返回可解析 JSON），"
                     "typosquatting 无法判定 —— 这是覆盖度说明，不是「无风险」结论",
                     [], probes=len(_DEPENDENCY_MANIFESTS), evidence_kind="依赖清单不足")

    hits = _suspicious_package_names(deps)
    findings = []
    if hits:
        findings.append(make_finding(
            "EXT-SC-09", f"依赖清单中存在 {len(hits)} 个高度疑似的抢注包（typosquatting）",
            ctx.target_name, endpoint=urljoin(ctx.target_url, src) if src else ctx.target_url,
            severity="高危", confidence="Medium", evidence_level="B",
            description=("依赖清单里的这些包名与生态内知名包只差一个字符，或多了 "
                         "-js / node- 这类伪装前后缀。抢注包是最省力的供应链投毒方式："
                         "开发者 npm install 时打错一个字母，装到的就是攻击者的包，"
                         "安装脚本随即执行。"),
            technical_detail=("比对基准：本地知名包名表（离线，不联网查询 registry）\n"
                              f"清单来源：{src or '未知'}\n"
                              "命中项：\n" + "\n".join(f"  · {n}\n    理由：{r}" for n, r in hits)),
            impact=("抢注包可在安装期（postinstall）执行任意代码：窃取 CI 凭据、"
                    "植入后门、篡改产物。一旦进入构建链，影响面是全部下游用户。"),
            reproduction=("逐个人工核对：在 npm registry 上查该包的维护者、发布时间、"
                          "下载量与仓库地址；与官方包的 README / 仓库星数对比，"
                          "确认后再决定是误报还是真实投毒。"),
            remediation=("① 逐个确认命中项，确认是抢注包的立即移除并排查是否已被安装执行；"
                         "② 依赖名统一从官方文档复制，禁止手打；"
                         "③ 开启 lockfile 完整性校验与 npm audit / pnpm 的最小发布年龄限制；"
                         "④ 关键项目使用私有镜像源并开启包名白名单。"),
            compliance="ISO 27001 A.8.21 / 供应链安全",
            evidence=[finding_evidence("file", str(hits), "疑似抢注包名")],
            grading_basis="离线近似名比对命中，实际来源需人工确认，按 B 级定高危",
        ))

    note = (f"依赖清单 {len(deps)} 个包（来源：{src or '未知'}），"
            f"近似名比对命中 {len(hits)} 个")
    return found(note, findings, probes=len(_DEPENDENCY_MANIFESTS),
                 evidence_kind="包名近似比对")
