# -*- coding: utf-8 -*-
"""
WSTG-CONF 配置与部署管理（15 项）
================================
公网黑盒扫描中，这一类最容易产出「真且可修」的问题：
默认页、备份文件、管理接口、安全头、子域接管、云存储误配。
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from engine.checks import net
from engine.checks.base import (
    ADMIN_PATHS, API_DOC_PATHS, CICD_PATHS, META_FILES, SECURITY_HEADER_RULES,
    SENSITIVE_FILE_PATHS, VCS_PATHS, finding_evidence, is_real_hit, ok, found,
    probe_or_none, scan_paths,
    no_target_outcome, reachability_scope,
    collection_health, na, pending,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
)

# 源码泄露特征
SOURCE_MARKERS = [
    "<?php", "<?=", "import java", "package com.", "def ", "class ",
    "#!/bin/", "SECRET_KEY", "DB_PASSWORD", "connectionString",
    "spring.datasource", "password:", "aws_secret", "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
]
BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", ".copy", ".swp", "~",
                   ".txt", ".zip", ".tar.gz", ".rar", ".1", ".php.bak",
                   ".jsp.bak", ".asp.bak", ".html.bak"]

# 可被接管的第三方托管域名特征
TAKEOVER_FINGERPRINTS = [
    (r"\.s3[\w\-]*\.amazonaws\.com$", "AWS S3", "NoSuchBucket"),
    (r"\.github\.io$", "GitHub Pages", "There isn't a GitHub Pages site here"),
    (r"\.herokuapp\.com$", "Heroku", "No such app"),
    (r"\.azurewebsites\.net$", "Azure App Service", "Error 404 - Web app not found"),
    (r"\.cloudapp\.net$", "Azure CloudApp", ""),
    (r"\.cloudfront\.net$", "AWS CloudFront", "Bad request"),
    (r"\.netlify\.app$", "Netlify", "Not Found - Request ID"),
    (r"\.surge\.sh$", "Surge", "project not found"),
    (r"\.readme\.io$", "ReadMe", "Project doesnt exist"),
    (r"\.zendesk\.com$", "Zendesk", "Help Center Closed"),
    (r"\.freshdesk\.com$", "Freshdesk", ""),
    (r"\.statuspage\.io$", "Statuspage", ""),
    (r"\.ghost\.io$", "Ghost", "Domain error"),
    (r"\.pantheonsite\.io$", "Pantheon", "404 error unknown site"),
    (r"\.wordpress\.com$", "WordPress.com", "doesn’t exist"),
    (r"\.fastly\.net$", "Fastly", "Fastly error: unknown domain"),
    (r"\.trafficmanager\.net$", "Azure Traffic Manager", ""),
    (r"\.aliyuncs\.com$", "阿里云 OSS", "NoSuchBucket"),
]


# ======================================================================
# WSTG-CONF-01 网络基础设施配置
# ======================================================================
@make_auto("WSTG-CONF-01", name="网络基础设施配置核查", tool="公共 DNS + 区域传送尝试",
           risk=RISK_STANDARD, evidence_kind="DNS 实测",
           detector_ref="checks/config.py:conf01")
def conf01(ctx: DetectorContext):
    findings = []
    probes = 0

    nss = net.dns_records(ctx.domain, "NS")
    axfr = net.zone_transfer_attempt(ctx.domain) if nss else []
    probes += len(nss) + 1

    if axfr:
        findings.append(make_finding(
            "WSTG-CONF-01", f"DNS 服务器允许区域传送，泄露 {len(axfr)} 条解析记录",
            ctx.target_name, endpoint=f"AXFR {ctx.domain}",
            severity="高危", confidence="High", evidence_level="A",
            description=("权威 DNS 服务器未限制区域传送（AXFR），任何人在公网都能把"
                         "该域名的全部解析记录一次性拉走。这等于把内网结构图直接交出去。"),
            technical_detail=(f"权威服务器：{', '.join(nss[:5])}\n"
                              f"通过 AXFR 获得的记录数：{len(axfr)}\n"
                              "记录示例：\n" + "\n".join(f"  {n}" for n in axfr[:25])),
            impact=("攻击者可获得全部子域与内部主机名（含未在证书透明度日志出现的内部系统），"
                    "直接定位内网入口，省去所有子域枚举工作。"),
            reproduction=f"dig AXFR {ctx.domain} @{nss[0] if nss else 'ns'}",
            remediation=("在 DNS 服务器上限制区域传送：仅允许从服务器（ACL 指定 IP）发起；"
                         "BIND 使用 `allow-transfer { 从服务器IP; };`；"
                         "云 DNS 默认已关闭，需确认未被误开。"),
            compliance="等保2.0 安全区域边界-访问控制 / ISO 27001 A.8.20",
            evidence=[finding_evidence("dns", "\n".join(axfr[:30]), "AXFR 结果")],
            grading_basis="公网实测可完成区域传送，定高危",
        ))

    note = (f"权威 NS {len(nss)} 台；区域传送{'成功（严重）' if axfr else '被拒绝（符合预期）'}")
    return found(note, findings, probes=probes, evidence_kind="DNS 配置实测")


# ======================================================================
# WSTG-CONF-02 应用平台配置
# ======================================================================
@make_auto("WSTG-CONF-02", name="应用平台配置与示例页核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="页面实测",
           detector_ref="checks/config.py:conf02")
def conf02(ctx: DetectorContext):
    findings = []
    candidates = [
        "examples/", "examples/servlets/", "sample/", "samples/", "demo/",
        "test/", "tests/", "docs/", "documentation/", "apidocs/",
        "manager/status", "host-manager/", "web-console/", "druid/",
        "solr/", "es/", "hawtio/", "nacos/", "eureka/", "zipkin/",
        "turbine/", "hystrix/", "cas/", "sso/", "seeyon/", "ecology/",
    ]
    hits = scan_paths(ctx, candidates)
    scope, _, scope_why = reachability_scope(ctx)
    is_public = scope == "公网可达"

    for path, probe in hits.items():
        final = getattr(probe, "final_url", "") or urljoin(ctx.target_url, path)
        title = getattr(probe, "title", "") or ""
        findings.append(make_finding(
            "WSTG-CONF-02",
            (f"平台自带页面 / 中间件控制台对外可达：/{path}" if is_public
             else f"内网可见（非公网暴露）：平台自带页面 / 中间件控制台 /{path}"),
            ctx.target_name, endpoint=final,
            severity="中危", confidence="High", evidence_level="A",
            description=(f"目标上存在框架或中间件自带的页面（{title or path}），"
                         "这类页面不属于业务功能，通常伴随默认凭据、信息泄露或管理能力。"
                         + ("" if is_public else f"目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=(f"路径：/{path}\n标题：{title}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"状态码：{getattr(probe, 'status', 0)}"),
            impact=("示例程序常含已知漏洞（如示例 Servlet 的任意文件读取）；"
                    "中间件控制台若使用默认凭据，可直接获得服务器管理能力。"
                    "本次仅验证页面可达，未尝试登录。"),
            reproduction=f"curl -sI {final}",
            remediation="生产环境移除示例程序与自带控制台；无法移除的通过访问控制只允许运维网段访问。",
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("response", (getattr(probe, 'body_snippet', '') or '')[:800], path)],
            grading_basis=(f"页面实测可达（可达范围「{scope}」），未获得权限，定中危"),
        ))

    note = (f"探测 {len(candidates)} 个平台自带路径，命中 {len(hits)} 个"
            + (f"：{'、'.join('/' + p for p in list(hits)[:6])}" if hits else ""))
    return found(note, findings, probes=len(candidates), evidence_kind="平台页面实测")


# ======================================================================
# WSTG-CONF-03 敏感信息文件扩展名处理
# ======================================================================
@make_auto("WSTG-CONF-03", name="源码与备份扩展名处理核查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="扩展名变体实测",
           detector_ref="checks/config.py:conf03")
def conf03(ctx: DetectorContext):
    findings = []
    # 拿根路径与已知脚本路径做扩展名变体
    base_paths = [""]
    root_url = urlparse(ctx.target_url)
    if root_url.path and root_url.path != "/":
        base_paths.append(root_url.path.strip("/"))
    for script in ("index.php", "index.jsp", "index.asp", "index.aspx",
                   "app.js", "main.js", "config"):
        base_paths.append(script)

    probes = 0
    for bp in base_paths[:5]:
        variants = []
        if bp:
            for sfx in BACKUP_SUFFIXES:
                variants.append(bp + sfx)
        variants += [bp + ".txt", bp + ".html", bp + "::$DATA", bp + "%00.txt"]
        variants = [v for v in dict.fromkeys(variants) if v][:18]
        if not variants:
            continue
        probes += len(variants)
        res = ctx.probe_many(variants)
        for v, probe in res.items():
            if not is_real_hit(ctx, probe, min_len=20):
                continue
            body = getattr(probe, "body_snippet", "") or ""
            hit = next((mk for mk in SOURCE_MARKERS if mk in body), "")
            if not hit:
                continue
            # 排除「本来就是公开的 JS 文件」
            if v.endswith(".js") or v.endswith(".txt") and "robots" in v:
                continue
            sev = "高危" if re.search(r"(password|secret|key|token|datasource)", body, re.I) else "中危"
            findings.append(make_finding(
                "WSTG-CONF-03", f"服务端返回源码或备份内容：/{v}",
                ctx.target_name, endpoint=getattr(probe, "final_url", "") or urljoin(ctx.target_url, v),
                severity=sev, confidence="High", evidence_level="A",
                description=("请求该地址时，服务器返回的是文件源码 / 备份内容，"
                             "而不是脚本执行结果。这通常源于扩展名解析配置错误或"
                             "编辑器备份文件被留在站点目录里。"),
                technical_detail=(f"命中路径：/{v}\n"
                                  f"内容特征：{hit}\n"
                                  f"响应片段：\n{body[:600]}"),
                impact=("源码可直接读取，意味着数据库口令、加密盐值、内部接口地址、"
                        "业务逻辑全部暴露。攻击者可据此构造精确的注入点与绕过路径。"),
                reproduction=f"curl -s {urljoin(ctx.target_url, v)} | head -30",
                remediation=("① 删除所有 .bak / .old / .swp / ~ 备份文件；"
                             "② Web 服务器禁止对备份与文本扩展名的直接访问；"
                             "③ 部署流程中排除编辑器临时文件与源码目录。"),
                compliance="等保2.0 安全计算环境-数据完整性 / ISO 27001 A.8.28",
                evidence=[finding_evidence("response", body[:1200], f"源码泄露 {v}")],
                grading_basis="实测返回源码内容，可直接获得服务端内部信息，定高危 / 中危",
            ))

    note = f"对 {len(base_paths[:5])} 个基准路径尝试 {probes} 种扩展名 / 备份变体，命中 {len(findings)} 处"
    return found(note, findings, probes=probes, evidence_kind="扩展名变体实测")


# ======================================================================
# 敏感文件语义判定
# ======================================================================
# URL 枚举池会派生大量路径（config.php → config.php.bak 等），它们不在
# 静态字典里。没有语义判定就只能笼统写成「未知文件」，报告就没法解释
# 「为什么这算漏洞、为什么定这个级」。
_BACKUP_SUFFIX_SEV: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\.(zip|tar|tar\.gz|tgz|rar|7z|gz)$", re.I), "压缩备份包", "高危"),
    (re.compile(r"\.(sql|dump|db)$", re.I), "数据库导出文件", "高危"),
    (re.compile(r"\.(bak|bak\d+|old|orig|save|sav|copy|tmp|temp)$", re.I), "源码 / 配置备份", "高危"),
    (re.compile(r"(~|\.swp|\.swo)$", re.I), "编辑器临时文件", "高危"),
    (re.compile(r"\.(log|txt)$", re.I), "日志 / 文本文件", "中危"),
    (re.compile(r"\.(json|xml|ya?ml|ini|conf|properties)$", re.I), "配置数据文件", "中危"),
]

# 文件名里出现这些词，说明内容大概率是凭据 / 源码 / 数据导出。
#
# 这里的两条纪律：
#   ① 词必须落在**分隔符边界**上（开头 / 结尾 / `/` `.` `_` `-` 左右），
#      否则 `/keyword-search` 会因子串 `key` 被当成凭据文件。
#   ② **刻意不收录** admin / auth / db / env / key 这类裸词 ——
#      它们做路由词的频率远高于做敏感文件名的频率，准入判据宁缺勿滥。
_SECRET_NAME = re.compile(
    r"(?i)(?:^|[/_.\-])("
    r"config|conf|settings?|secret|secrets|credential|credentials|"
    r"password|passwd|pwd|token|api[-_]?key|access[-_]?key|secret[-_]?key|"
    r"private[-_]?key|id_rsa|id_dsa|id_ecdsa|"
    r"database|dump|backup|"
    r"\.env|\.pem|\.pfx|\.p12|\.jks|\.keystore|\.sqlite|\.mdb|\.htpasswd"
    r")(?:$|[/_.\-])"
)

# 本来就该给浏览器取的公开文件。它们出现在枚举池里是正常的，
# 报成「敏感文件泄露」属于自己吓自己。
#
# robots.txt / sitemap.xml 这两条特别容易漏：它们不带 .txt/.xml 以外的线索，
# 会被后缀规则兜住（.txt → 「日志 / 文本文件」、.xml → 「配置数据文件」），
# 于是每次扫描都稳定产出两条假发现。robots.txt 的暴露问题由 WSTG-INFO-01
# 负责，不在这里重复报。
_KNOWN_PUBLIC_FILES = {
    "manifest.json", "asset-manifest.json", "site.webmanifest", "browserconfig.xml",
    "favicon.ico", "crossdomain.xml", "ads.txt", "security.txt", "humans.txt",
    "index.html", "index.htm", "404.html", "500.html",
    "robots.txt", "sitemap.xml", "sitemap.txt", "sitemap_index.xml",
    "opensearch.xml", "rss.xml", "feed.xml", "atom.xml", "favicon.png",
    "apple-touch-icon.png", "logo.svg",
}

# 这些后缀本身就说明「这是一个页面」，因此返回 HTML 是正常的
_PAGE_EXT = re.compile(r"\.(php\d?|html?|jsp|asp|aspx|do|action|shtml|cfm)$", re.I)

# 词元本身（不含左右边界），用于「整个文件名主干就是这个词」的严格匹配
_SECRET_TOKEN = re.compile(
    r"(config|conf|settings?|secret|secrets|credential|credentials|"
    r"password|passwd|pwd|token|api[-_]?key|access[-_]?key|secret[-_]?key|"
    r"private[-_]?key|id_rsa|id_dsa|id_ecdsa|database|dump|backup|"
    r"\.env|\.pem|\.pfx|\.p12|\.jks|\.keystore|\.sqlite|\.mdb|\.htpasswd)",
    re.I,
)


def _looks_like_page(key: str) -> bool:
    leaf = key.rstrip("/").rsplit("/", 1)[-1]
    return bool(_PAGE_EXT.search(leaf)) or "." not in leaf


def _secret_by_name(key: str) -> bool:
    """路径名是否带凭据 / 配置语义。

    页面型路径（无扩展名、或 .php / .html）要求**整段文件名主干**就是那个词：
    `config.php` 命中，而 `config-guide`、`settings-page`、`backup-status`
    这类描述性路由名不命中 —— 它们是页面标题不是文件名，把它们报成
    「配置文件可下载」是典型的自造误报。
    """
    if _looks_like_page(key):
        leaf = key.rstrip("/").rsplit("/", 1)[-1]
        stem = leaf.rsplit(".", 1)[0] if "." in leaf else leaf
        return bool(_SECRET_TOKEN.fullmatch(stem))
    return bool(_SECRET_NAME.search(key))


def _ctype(probe: Any) -> str:
    if probe is None:
        return ""
    for k, v in (getattr(probe, "headers", {}) or {}).items():
        if str(k).lower() == "content-type":
            return str(v).lower()
    return ""


def _classify_sensitive(path: str, probe: Any = None) -> tuple[str, str] | None:
    """判断一条**真实可达**的路径是否构成「敏感文件」发现。

    返回 ``None`` 表示「这不是敏感文件」—— 这正是本函数存在的意义。

    URL 枚举池会把应用自己的页面与接口也收进来（`/login`、`/api/user`、
    `/admin/`），它们返回 200 完全正常。改动之前这里对任何 200 都兜底成
    「非预期可下载文件（中危）」，于是任何一个能打开的页面都会变成一条
    「敏感文件可从公网直接下载」—— 这种发现脚本能复现、报告也自洽，
    但它根本不是漏洞，评审一眼就会看穿，整份报告的可信度跟着一起没了。

    准入优先级：精确字典 → 版本控制残留 → 后缀语义 → 文件名语义。
    """
    key = path.lstrip("/").split("?", 1)[0].split("#", 1)[0].rstrip("/")
    if not key:
        return None
    leaf = key.rsplit("/", 1)[-1].lower()
    if leaf in _KNOWN_PUBLIC_FILES:
        return None

    # 有响应对象时，做「内容类型 vs 后缀」自洽检查：一个 .json / .bak 却
    # 返回 text/html，说明拿到的是站点的软 404 或 SPA 回退页，不是那个文件。
    html_mismatch = (probe is not None and "text/html" in _ctype(probe)
                     and not _looks_like_page(key))

    if key in SENSITIVE_FILE_PATHS:
        return SENSITIVE_FILE_PATHS[key]
    if key in VCS_PATHS or "/.git/" in f"/{key}/" or key.startswith((".git", ".svn", ".hg")):
        return "版本控制元数据（可还原源码）", "高危"
    if key.startswith(("WEB-INF/", "META-INF/")):
        return "Java Web 应用内部配置", "高危"

    for pat, label, sev in _BACKUP_SUFFIX_SEV:
        if not pat.search(key):
            continue
        if html_mismatch:
            return None
        # 备份包本身高危；若文件名还带凭据 / 配置语义，保持高危
        if _SECRET_NAME.search(key):
            return f"{label}（文件名含配置 / 凭据语义）", "高危"
        return label, sev

    if _secret_by_name(key):
        if html_mismatch:
            return None
        return "疑似配置 / 凭据文件", "高危"

    # 走到这里说明它只是一条普通可访问路径 —— 应用自己的页面或接口，
    # 不是敏感文件发现。宁可不报，也不要把正常页面报成漏洞。
    return None


def _describe_sensitive(path: str, probe: Any = None) -> tuple[str, str] | None:
    """兼容旧调用名，语义同 :func:`_classify_sensitive`。"""
    return _classify_sensitive(path, probe)


# 站上本来就该能下载的静态资源。URL 枚举池会把这些地址也收进来
# （它们确实真实存在），但拿它们当「敏感文件泄露」报出去就是把自己吓自己：
# 一个 JS 打包产物本来就是要给浏览器下的。必须在进入敏感文件审查前剔掉。
_PUBLIC_ASSET = re.compile(
    r"\.(js|mjs|css|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|"
    r"woff2?|ttf|otf|eot|mp4|webm|mp3|wav|ogg)$", re.I)


# 刻意**不**包含 .php / .html / .jsp：它们既可能是正常页面，
# 也可能是 config.php / phpinfo.php 这类敏感文件，只能靠语义逐个判断。


def _is_public_asset(path: str) -> bool:
    return bool(_PUBLIC_ASSET.search(path.split("?", 1)[0]))


# ======================================================================
# WSTG-CONF-04 旧备份与未引用文件审查
# ======================================================================
@make_auto("WSTG-CONF-04", name="敏感文件与备份泄露审查", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="敏感文件实测",
           detector_ref="checks/config.py:conf04")
def conf04(ctx: DetectorContext):
    findings = []
    # 走统一的 URL 枚举池，而不是这张硬编码表。
    # 差别在覆盖面：池子除了字典，还包含 robots.txt 自己声明的路径、
    # sitemap 收录的地址、页面里真实存在的链接、前端产物里调用的接口，
    # 以及由已知文件派生的备份 / 临时文件变体。同时它统一剔除破坏性路径
    # （登出 / 删除 / 取消 / 支付），并记录「试图枚举了什么」供报告陈述。
    from engine.urlpool import build_url_pool  # noqa: PLC0415

    pool = build_url_pool(ctx)
    paths = list(SENSITIVE_FILE_PATHS) + list(VCS_PATHS)
    # 字典里的高价值路径优先试，池子里的其余候选排后。
    # 静态资源（js / css / 图片 / 字体）一律不进敏感文件审查 ——
    # 它们本来就该能从公网下载，报了就是误报。
    extra = [p for p in pool.paths
             if p.lstrip("/") not in SENSITIVE_FILE_PATHS and not _is_public_asset(p)]
    paths += extra
    assets_skipped = len(pool.paths) - len(extra)
    paths = list(dict.fromkeys(paths))

    hits = scan_paths(ctx, paths)

    # 覆盖面留痕：报告要能写清「试了多少地址、来自哪些来源」，
    # 否则「未发现敏感文件」和「基本没试」在读者眼里没有区别。
    ctx.note(f"敏感文件枚举覆盖：{pool.summary()}")
    ctx.note(f"敏感文件审查实际试了 {len(paths)} 个地址"
             f"（其中 {assets_skipped} 个静态资源被排除，不属于敏感文件范畴）")
    # 同时落进缓存，供自测断言与报告渲染取用
    ctx._cache["url_pool_coverage"] = pool.coverage_rows()
    ctx._cache["url_pool_skipped"] = list(pool.skipped)
    ctx._cache["url_pool_notes"] = list(pool.notes)
    ctx._cache["url_pool_summary"] = pool.summary()
    for _n in pool.notes:
        ctx.note(_n)
    if pool.skipped:
        ctx.note(f"敏感文件枚举刻意剔除 {len(pool.skipped)} 个破坏性路径"
                 f"（如 {', '.join(p for p, _ in pool.skipped[:3])}）")

    scope, _, scope_why = reachability_scope(ctx)

    reported = 0
    not_sensitive = 0
    for path, probe in hits.items():
        key = path.lstrip("/")
        verdict = _classify_sensitive(key, probe)
        if verdict is None:
            # 真实可达，但只是应用自己的页面 / 接口，不是敏感文件。
            # 这道准入必须有：URL 枚举池把 /login、/api/user 这类地址也收了
            # 进来，它们返回 200 完全正常，报出去就是自造误报。
            not_sensitive += 1
            continue
        desc, sev = verdict
        body = getattr(probe, "body_snippet", "") or ""
        if reported >= 25:
            break
        reported += 1
        findings.append(make_finding(
            "WSTG-CONF-04",
            (f"敏感文件可直接下载：/{key}（{desc}）" if scope == "公网可达"
             else f"内网可见（非公网暴露）：敏感文件可直接下载 /{key}（{desc}）"),
            ctx.target_name, endpoint=getattr(probe, "final_url", "") or urljoin(ctx.target_url, key),
            severity=sev, confidence="High", evidence_level="A",
            description=(f"该地址返回了{desc}的实际内容。这类文件不应出现在 Web 根目录下，"
                         "更不应能直接下载。"
                         + ("" if scope == "公网可达" else
                            f"注意：目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=(f"路径：/{key}\n用途：{desc}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"响应片段（已截断）：\n{body[:700]}"),
            impact=("凭据类文件可直接获得数据库 / 云资源访问权限；"
                    ".git 目录泄露可用工具还原完整源码；"
                    "配置文件泄露服务器与中间件的连接信息。"
                    "这是「直接拿到数据或权限」的典型路径。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, key)} | head -40",
            remediation=("① 立即删除 Web 根目录下的配置文件、备份文件与版本控制目录；"
                         "② Nginx 增加 `location ~ /\\.(git|svn|env) { deny all; }`；"
                         "③ 构建产物中排除 .git 与配置文件；"
                         "④ 若已泄露，轮换其中涉及的全部凭据。"),
            compliance="等保2.0 安全计算环境-数据保密性 / ISO 27001 A.8.24",
            evidence=[finding_evidence("response", body[:1500], key)],
            grading_basis=(f"实测可直接下载敏感文件内容；可达范围判定为「{scope}」，"
                           "按文件用途定高危 / 中危"),
        ))
    if reported >= 25:
        ctx.note(f"敏感文件命中 {reported} 处，报告仅列出前 25 处（完整清单见产出目录）")
    if not_sensitive:
        ctx.note(f"{not_sensitive} 个地址真实可达但经语义判定不属于敏感文件"
                 f"（应用自身的页面 / 接口），未计入发现")

    # 目录列表
    dir_list = []
    for d in ("", "static/", "assets/", "uploads/", "files/", "images/",
              "backup/", "backups/", "data/", "logs/", "tmp/", "temp/"):
        pr = ctx.get(ctx.target_url) if not d else probe_or_none(ctx, d)
        if pr is None or getattr(pr, "status", 0) != 200:
            continue
        body = (getattr(pr, "body_snippet", "") or "").lower()
        if ("<title>index of" in body or "directory listing for" in body
                or "<h1>index of" in body or '"parent directory"' in body):
            dir_list.append(d or "/")
    if dir_list:
        findings.append(make_finding(
            "WSTG-CONF-04", f"目录列表功能开启（{len(dir_list)} 个目录）",
            ctx.target_name, endpoint=urljoin(ctx.target_url, dir_list[0]),
            severity="中危", confidence="High", evidence_level="A",
            description=("服务器直接把目录下的文件名清单列在页面上，任何人访问该路径都能看到里面有什么、"
                         "以及每个文件的大小和修改时间。"),
            technical_detail="开启目录列表的路径：\n" + "\n".join(f"  /{d}" for d in dir_list),
            impact=("目录清单让攻击者可以逐个翻找，快速定位备份包、日志、上传文件、"
                    "临时导出的数据表等敏感内容；很多数据泄露事件就是从某个忘了关的目录列表开始的。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, dir_list[0])} | head -40",
            remediation=("关闭目录自动索引：Nginx `autoindex off;`；"
                         "Apache `Options -Indexes`；IIS 关闭「目录浏览」；"
                         "云存储桶关闭 ListBucket 权限。"),
            compliance="等保2.0 安全计算环境-访问控制",
            evidence=[finding_evidence("response", "\n".join(dir_list), "目录列表命中")],
            grading_basis="实测可枚举目录内容，为数据发现提供直接路径，定中危",
        ))

    note = (f"探测 {len(paths)} 个敏感 / 版本控制路径，真实可达 {len(hits)} 个，"
            f"经语义准入判定为敏感文件的 {len(findings) - (1 if dir_list else 0)} 个"
            f"（{not_sensitive} 个为应用自身可达页面，未计入）；"
            f"目录列表 {len(dir_list)} 处")
    return found(note, findings, probes=len(paths) + 12, evidence_kind="文件与目录实测")


# ======================================================================
# WSTG-CONF-05 基础设施与应用管理接口枚举
# ======================================================================
# 纯认证入口。它们在 ADMIN_PATHS 里只是为了「探一探」，但一个登录页可访问
# 本身不是管理接口暴露 —— 不加这道排除，站点上每个 /login 都会被报成
# 「管理 / 运维接口对公网开放」，这是纯自造的误报。
_PLAIN_AUTH_PATH = re.compile(
    r"(?i)^(?:user/|auth/|passport/|account/|sso/|member/)?"
    r"(?:login|signin|sign-in|logon|signup|register|logout)/?$"
)

# 路径本身就带管理 / 运维语义
_ADMIN_PATH_HINT = re.compile(
    r"(?i)(admin|manage|manager|console|dashboard|backend|actuator|controlpanel|"
    r"wp-admin|ops|grafana|kibana|prometheus|zabbix|jenkins|gitlab|cms|system)"
)


@make_auto("WSTG-CONF-05", name="管理接口与运维端点枚举", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="管理端点实测",
           detector_ref="checks/config.py:conf05")
def conf05(ctx: DetectorContext):
    findings = []
    names = sorted(set(ADMIN_PATHS))
    hits = scan_paths(ctx, names)

    # 只保留看起来是真实管理界面的（有管理类标题、运维端点特征、或管理语义路径 + 口令表单）
    admin_like = {}
    for path, probe in hits.items():
        key = path.lstrip("/").rstrip("/")
        if _PLAIN_AUTH_PATH.match(key):
            # 纯登录 / 注册入口不算「管理接口暴露」。一个登录页能打开是正常的，
            # 那是认证类检查项（ATHN / SESS）的范围。ADMIN_PATHS 里收录它们
            # 只是为了「探一探」，不代表命中即可上报。
            continue
        body = (getattr(probe, "body_snippet", "") or "").lower()
        title = (getattr(probe, "title", "") or "").lower()
        signal = ""
        if re.search(r"(admin|manage|管理|后台|控制台|console|dashboard)", title):
            signal = f"页面标题「{getattr(probe, 'title', '')}」"
        elif re.search(r"(swagger|api-docs|openapi|actuator)", body):
            signal = "含接口文档 / 运维端点特征"
        elif _ADMIN_PATH_HINT.search(key) and "password" in body and "form" in body:
            # 必须「路径带管理语义」**且**「有口令表单」两个条件同时成立。
            # 只凭后者会把站点上任何一个登录页都报成管理接口。
            signal = "管理语义路径且含口令输入表单"
        if signal:
            admin_like[path] = (probe, signal)

    scope, _, scope_why = reachability_scope(ctx)
    is_public = scope == "公网可达"

    for path, (probe, signal) in admin_like.items():
        final = getattr(probe, "final_url", "") or urljoin(ctx.target_url, path)
        findings.append(make_finding(
            "WSTG-CONF-05",
            (f"管理 / 运维接口对外可达：/{path}" if is_public
             else f"内网可见（非公网暴露）：管理 / 运维接口 /{path}"),
            ctx.target_name, endpoint=final,
            severity="中危", confidence="High", evidence_level="B",
            description=(f"该路径可以直接打开一个管理类界面（判定依据：{signal}），"
                         "且访问到该界面本身不需要登录。"
                         + ("" if is_public else
                            f"注意：目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=(f"路径：/{path}\n判定依据：{signal}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"状态码：{getattr(probe, 'status', 0)}"),
            impact=("管理入口对外可达会被持续扫描与爆破；若存在默认凭据、弱口令或"
                    "历史漏洞，可直接获得管理权限。这属于攻击面收窄的优先项。"
                    + ("" if is_public else "本条可达范围限于内网。")),
            reproduction=f"curl -sI {final}",
            remediation=("① 管理后台不应直接暴露，改为内网访问或经 VPN / 堡垒机；"
                         "② 必须保留外部访问时启用 MFA、IP 白名单与登录频控；"
                         "③ 登录页不反馈账号是否存在。"),
            compliance="等保2.0 安全区域边界-访问控制 / ISO 27001 A.8.20",
            evidence=[finding_evidence("response", (getattr(probe, 'body_snippet', '') or '')[:800], path)],
            grading_basis=(f"管理界面实测可达（可达范围「{scope}」），"
                           "未取得权限，按 B 级证据定中危"),
        ))

    # 接口文档
    doc_hits = scan_paths(ctx, API_DOC_PATHS)
    if doc_hits:
        first = list(doc_hits)[0]
        findings.append(make_finding(
            "WSTG-CONF-05",
            (f"接口文档 / 调试页面对外开放（{len(doc_hits)} 处）" if is_public
             else f"内网可见（非公网暴露）：接口文档 / 调试页面（{len(doc_hits)} 处）"),
            ctx.target_name, endpoint=getattr(doc_hits[first], "final_url", "")
            or urljoin(ctx.target_url, first),
            severity="中危", confidence="High", evidence_level="A",
            description=("Swagger / OpenAPI / GraphiQL 这类接口文档对外可达，"
                         "等于把系统全部接口、参数名、数据结构主动公开。"
                         + ("" if is_public else f"目标可达范围为「{scope}」，不计入公网风险。")),
            technical_detail=(f"命中路径：\n" + "\n".join(f"  /{p}" for p in sorted(doc_hits)[:15])
                              + f"\n可达性判定：{scope}"),
            impact=("攻击者直接从文档获得完整接口清单与参数定义，无需任何探测即可"
                    "构造针对性请求，并可在 GraphiQL 上直接执行查询。"
                    "这是接口类漏洞（越权、批量赋值、注入）最高效的起点。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, first)} | head -40",
            remediation=("生产环境关闭接口文档（Springdoc 设 `springdoc.api-docs.enabled=false`）；"
                         "必须保留时通过鉴权与 IP 白名单限制访问，并关闭 GraphiQL 调试界面。"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("response", "\n".join(sorted(doc_hits)[:15]), "接口文档路径")],
            grading_basis="文档实测可访问，接口面完全暴露，定中危",
        ))

    note = (f"探测管理类路径 {len(names)} 个（命中界面 {len(admin_like)} 个）；"
            f"接口文档 {len(API_DOC_PATHS)} 个（命中 {len(doc_hits)} 个）")
    return found(note, findings, probes=len(names) + len(API_DOC_PATHS), evidence_kind="管理端点实测")


# ======================================================================
# WSTG-CONF-06 HTTP 方法测试
# ======================================================================
@make_auto("WSTG-CONF-06", name="HTTP 方法暴露测试", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="HTTP 方法实测",
           detector_ref="checks/config.py:conf06")
def conf06(ctx: DetectorContext):
    findings = []
    probes = 0

    opt = ctx.raw_request("OPTIONS", ctx.target_url)
    probes += 1
    allow = ""
    for k, v in (opt.get("headers") or {}).items():
        if k.lower() == "allow":
            allow = v
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]

    risky = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "PROPFIND")]
    if risky:
        findings.append(make_finding(
            "WSTG-CONF-06", f"服务端声明允许非常用 HTTP 方法：{', '.join(risky)}",
            ctx.target_name, endpoint=ctx.target_url, method="OPTIONS",
            severity="低危", confidence="Medium", evidence_level="A",
            description=("服务器在 OPTIONS 响应里声明支持这些方法。"
                         "PUT / DELETE 若未被鉴权保护，可直接修改或删除服务器上的资源。"),
            technical_detail=f"Allow: {allow}",
            impact=("若这些方法在真实路由上生效且缺少鉴权，可覆盖静态文件或删除资源，"
                    "造成内容篡改或拒绝服务。本次仅读取声明，未实际执行写操作。"),
            reproduction=f"curl -s -X OPTIONS -i {ctx.target_url} | grep -i '^allow:'",
            remediation=("在 Web 服务器 / 反向代理层只放行业务需要的 GET / POST / HEAD；"
                         "明确拒绝 PUT / DELETE / TRACE；"
                         "TRACE 关闭：Apache `TraceEnable off`。"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("header", f"Allow: {allow}", "OPTIONS 响应")],
            grading_basis="仅确认方法被声明支持（B 级证据），未实证写操作生效，定低危",
        ))

    trace = ctx.raw_request("TRACE", ctx.target_url)
    probes += 1
    if trace.get("status", 0) == 200 and "TRACE" in (trace.get("body") or "").upper():
        findings.append(make_finding(
            "WSTG-CONF-06", "TRACE 方法可用（可被用于跨站追踪）",
            ctx.target_name, endpoint=ctx.target_url, method="TRACE",
            severity="低危", confidence="High", evidence_level="A",
            description="服务器响应 TRACE 请求并回显请求内容。配合浏览器历史记录漏洞可形成跨站追踪攻击。",
            technical_detail=f"TRACE 响应状态：{trace.get('status')}\n响应片段：{(trace.get('body') or '')[:300]}",
            impact="在存在其他浏览器漏洞的前提下，可能被用于读取带凭据的请求内容；单独利用价值有限。",
            reproduction=f"curl -s -X TRACE -i {ctx.target_url} | head -20",
            remediation="在 Web 服务器层关闭 TRACE 方法。",
            compliance="ISO 27001 A.8.20",
            evidence=[finding_evidence("response", (trace.get("body") or "")[:600], "TRACE 回显")],
            grading_basis="实测 TRACE 可用，危害有限，定低危",
        ))

    note = (f"OPTIONS 返回 Allow={allow or '（无）'}；"
            f"TRACE {'可用' if trace.get('status', 0) == 200 else '不可用 / 被拒绝'}")
    return found(note, findings, probes=probes, evidence_kind="HTTP 方法实测")


# ======================================================================
# WSTG-CONF-07 HTTP 严格传输安全（HSTS）
# ======================================================================
@make_auto("WSTG-CONF-07", name="HSTS 配置核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="响应头实测",
           detector_ref="checks/config.py:conf07")
def conf07(ctx: DetectorContext):
    findings = []
    hsts = ctx.header("strict-transport-security")
    is_https = ctx.target_url.lower().startswith("https")
    if not is_https:
        return ok("目标为 HTTP 站点，HSTS 不适用（HSTS 只能由 HTTPS 响应下发）", probes=1,
                  evidence_kind="协议判定")

    if not hsts:
        findings.append(make_finding(
            "WSTG-CONF-07", "未配置 HSTS，HTTPS 未被强制",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("站点支持 HTTPS，但没有下发 HSTS 头。"
                         "这意味着浏览器第一次访问若走 HTTP，会被中间人降级到明文，"
                         "之后即使站点支持 HTTPS 也无法阻止。"),
            technical_detail=f"响应头 Strict-Transport-Security：缺失\n响应头实测：{dict(list(ctx.root_headers.items())[:10])}",
            impact=("在用户首次访问或证书异常时，流量可被降级为明文，"
                    "登录凭据与会话 Cookie 可能被局域网内攻击者截获。"),
            reproduction=f"curl -sI {ctx.target_url} | grep -i strict-transport-security",
            remediation=("在 HTTPS 站点的响应中加入：\n"
                         "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                         "先从小 max-age（如 300）灰度，确认全站 HTTPS 可用后再提升到一年并加 preload。"),
            compliance="等保2.0 安全通信网络-通信传输 / PCI-DSS 4.1",
            evidence=[finding_evidence("header", "缺失 Strict-Transport-Security", "响应头")],
            grading_basis="配置缺失属确证，影响传输安全，定中危",
        ))
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        issues = []
        if age < 15552000:
            issues.append(f"max-age 偏短（{age} 秒，建议 ≥ 15552000）")
        if "includesubdomains" not in hsts.lower():
            issues.append("未包含 includeSubDomains")
        if issues:
            findings.append(make_finding(
                "WSTG-CONF-07", f"HSTS 配置不完整：{'；'.join(issues)}",
                ctx.target_name, endpoint=ctx.target_url,
                severity="低危", confidence="High", evidence_level="A",
                description="HSTS 已启用，但参数配置不到位，保护效果打了折扣。",
                technical_detail=f"Strict-Transport-Security: {hsts}\n问题：{'；'.join(issues)}",
                impact="短 max-age 会在过期后留下降级窗口；未覆盖子域时子域仍可被降级。",
                reproduction=f"curl -sI {ctx.target_url} | grep -i strict-transport-security",
                remediation="按 `max-age=31536000; includeSubDomains` 配置，确认子域全量 HTTPS 后再考虑 preload。",
                compliance="PCI-DSS 4.1",
                evidence=[finding_evidence("header", hsts, "HSTS 头")],
                grading_basis="配置不完整，定低危",
            ))
    return found(f"Strict-Transport-Security: {hsts or '缺失'}", findings, probes=1,
                 evidence_kind="响应头实测")


# ======================================================================
# WSTG-CONF-08 RIA 跨域策略
# ======================================================================
@make_auto("WSTG-CONF-08", name="跨域策略文件核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="策略文件实测",
           detector_ref="checks/config.py:conf08")
def conf08(ctx: DetectorContext):
    findings = []
    hits = scan_paths(ctx, ["crossdomain.xml", "clientaccesspolicy.xml"])
    for path, probe in hits.items():
        body = getattr(probe, "body_snippet", "") or ""
        if re.search(r'domain\s*=\s*["\']\*["\']', body) or "allow-access-from" in body.lower():
            wildcard = bool(re.search(r'domain\s*=\s*["\']\*["\']', body))
            findings.append(make_finding(
                "WSTG-CONF-08",
                ("跨域策略允许任意域访问（通配符）" if wildcard else "存在跨域策略文件"),
                ctx.target_name, endpoint=getattr(probe, "final_url", "") or urljoin(ctx.target_url, path),
                severity="中危" if wildcard else "低危",
                confidence="High", evidence_level="A",
                description=("站点提供了 Flash / Silverlight 时代的跨域策略文件，"
                             + ("且对任意来源放行（domain=\"*\"）。" if wildcard
                                else "虽已过时但仍生效。")),
                technical_detail=f"路径：{path}\n内容：\n{body[:600]}",
                impact=("通配符跨域策略允许任意站点的 Flash 内容读取本域受保护资源，"
                        "在仍支持 Flash 的客户端上可被用于读取用户数据。"
                        "策略文件过时本身也说明资产梳理不清。"),
                reproduction=f"curl -s {urljoin(ctx.target_url, path)}",
                remediation="评估后删除该文件（现代浏览器已不支持 Flash）；确需保留时把 domain 限定到具体来源域名。",
                compliance="ISO 27001 A.8.9",
                evidence=[finding_evidence("response", body[:800], path)],
                grading_basis="策略文件实测可读，通配符放行属配置缺陷，定中危 / 低危",
            ))
    note = f"跨域策略文件命中 {len(hits)} 个" + (f"：{', '.join(hits)}" if hits else "（均不存在）")
    return found(note, findings, probes=2, evidence_kind="策略文件实测")


# ======================================================================
# WSTG-CONF-09 文件权限
# ======================================================================
@make_auto("WSTG-CONF-09", name="文件与目录权限核查（外部可判定部分）",
           tool="内置检测器", risk=RISK_STANDARD, evidence_kind="路径可达性实测",
           detector_ref="checks/config.py:conf09")
def conf09(ctx: DetectorContext):
    findings = []
    # 外部视角可判定的「权限过宽」表现为：能读到不该读的目录内容
    dirs = ["uploads/", "upload/", "files/", "data/", "backup/", "backups/",
            "logs/", "tmp/", "temp/", "static/", "assets/", ".well-known/"]
    readable = {}
    for d in dirs:
        pr = probe_or_none(ctx, d)
        if pr is None or getattr(pr, "status", 0) != 200:
            continue
        body = getattr(pr, "body_snippet", "") or ""
        low = body.lower()
        if ("index of" in low or "parent directory" in low):
            readable[d] = "目录列表已开启"
        elif re.search(r"\.(sql|zip|tar|gz|bak|log|env|xlsx|csv)\b", body, re.I):
            readable[d] = "正文中直接列出敏感文件"
    if readable:
        findings.append(make_finding(
            "WSTG-CONF-09", f"{len(readable)} 个目录对外可读且暴露文件清单",
            ctx.target_name, endpoint=urljoin(ctx.target_url, list(readable)[0]),
            severity="中危", confidence="High", evidence_level="A",
            description="这些目录不需要任何凭据即可访问，并且页面上直接列出了目录内的文件名。",
            technical_detail="\n".join(f"  /{d} → {why}" for d, why in readable.items()),
            impact=("可枚举文件名意味着攻击者能定位上传目录、备份目录、日志目录中的具体文件，"
                    "进而尝试直接下载，是数据泄露的常见起点。"),
            reproduction=f"curl -s {urljoin(ctx.target_url, list(readable)[0])} | head -30",
            remediation=("① 关闭目录列表（Nginx `autoindex off`）；"
                         "② 上传目录禁止脚本执行（`location ~* /uploads/.*\\.(php|jsp)$ { deny all; }`）；"
                         "③ 备份、日志目录移出 Web 根路径。"),
            compliance="等保2.0 安全计算环境-访问控制",
            evidence=[finding_evidence("response", "\n".join(f"/{d} → {w}" for d, w in readable.items()),
                                       "可读目录")],
            grading_basis="实测目录可读并列名，为数据获取提供路径，定中危",
        ))
    note = f"探测 {len(dirs)} 个常见目录，其中 {len(readable)} 个对外可读并暴露文件清单"
    return found(note, findings, probes=len(dirs), evidence_kind="目录可达性实测")


# ======================================================================
# WSTG-CONF-10 子域接管
# ======================================================================
@make_auto("WSTG-CONF-10", name="子域接管风险检测", tool="crt.sh + 公共 DNS + HTTP",
           risk=RISK_STANDARD, evidence_kind="CNAME 与托管方响应实测",
           detector_ref="checks/config.py:conf10")
def conf10(ctx: DetectorContext):
    findings = []
    subs = ctx._cache.get("info04_subs") or net.crtsh_subdomains(ctx.domain)
    if not subs:
        subs = [ctx.domain]
    probes = 0
    checked = 0
    for sub in subs[:60]:
        cnames = net.dns_records(sub, "CNAME")
        probes += 1
        if not cnames:
            continue
        target = cnames[0].rstrip(".").lower()
        for pat, provider, marker in TAKEOVER_FINGERPRINTS:
            if not re.search(pat, target):
                continue
            checked += 1
            body = net.http_text(f"http://{sub}/", timeout=12)
            probes += 1
            dangling = bool(marker) and marker.lower() in body.lower()
            if not body or dangling:
                findings.append(make_finding(
                    "WSTG-CONF-10", f"子域疑似可被接管：{sub} → {target}（{provider}）",
                    ctx.target_name, endpoint=f"http://{sub}/",
                    severity="高危", confidence="High" if dangling else "Medium",
                    evidence_level="A" if dangling else "B",
                    description=(f"该子域的 CNAME 指向第三方托管服务 {provider}，"
                                 f"但该托管侧的资源已不存在（{marker or '无法访问'}）。"
                                 "任何人在托管平台上注册同名资源，即可接管这个子域。"),
                    technical_detail=(f"子域：{sub}\nCNAME：{target}\n托管方：{provider}\n"
                                      + (f"托管方响应特征命中：{marker}\n" if dangling else "托管方返回空响应\n")
                                      + f"响应片段：{body[:300]}"),
                    impact=("接管子域后可发布任意内容，用于钓鱼（地址看起来属于贵公司域名）、"
                            "通过该子域绕过 CORS 信任读取主域数据、"
                            "或利用子域 Cookie 作用域扩大攻击范围。"),
                    reproduction=(f"dig CNAME {sub}\n"
                                  f"curl -sI http://{sub}/ \n"
                                  f"# 在 {provider} 上查询是否存在同名资源"),
                    remediation=("① 删除指向已释放第三方资源的 DNS 记录；"
                                 "② 云资源下线前先摘除 DNS 记录；"
                                 "③ 建立子域台账，定期核对 CNAME 指向的资源是否仍由本公司持有。"),
                    compliance="等保2.0 安全区域边界-访问控制 / ISO 27001 A.8.20",
                    evidence=[finding_evidence("dns", f"{sub} CNAME {target}\n托管方响应：{body[:400]}",
                                               "子域接管线索")],
                    grading_basis=("托管方返回资源不存在特征，实测可接管，定高危"
                                   if dangling else "CNAME 指向第三方服务但未取得资源不存在的确证，按 B 级定上限中危"),
                ))
            break

    note = (f"枚举子域 {len(subs[:60])} 个，其中 CNAME 指向第三方托管 {checked} 个，"
            f"疑似可接管 {len(findings)} 个")
    return found(note, findings, probes=probes, evidence_kind="CNAME + 托管方响应")


# ======================================================================
# WSTG-CONF-11 云存储配置
# ======================================================================
@make_auto("WSTG-CONF-11", name="云存储桶配置核查", tool="内置检测器 + JS 分析",
           risk=RISK_STANDARD, evidence_kind="存储桶实测",
           detector_ref="checks/config.py:conf11",
           # 判据落在桶端点上（直连 *.oss-cn-*.aliyuncs.com），不经被测应用域名。
           needs_app=False)
def conf11(ctx: DetectorContext):
    findings = []
    js_bodies = list(ctx.js_result.get("bodies") or [])
    blobs = "\n".join(js_bodies + [ctx.baseline_body])
    _bucket_re = re.compile(
        r"https?://([a-z0-9.\-]+)\.(oss-[a-z0-9\-]+\.aliyuncs\.com"
        r"|s3[\w\-]*\.amazonaws\.com|cos\.[a-z0-9\-]+\.myqcloud\.com)", re.I)

    #: **从产物里真实提取到的**桶地址 —— 目标自己写在页面/JS 里的，可信。
    #: 与下面「按命名规则猜的候选」性质完全不同：后者只是常见命名，多半全不命中。
    from_assets: set[str] = {m.group(0) for m in _bucket_re.finditer(blobs)}
    buckets: set[str] = set(from_assets)

    # 推测常见桶名
    base = ctx.domain.split(".")[0]
    for suffix in ("static", "assets", "img", "images", "upload", "uploads",
                   "backup", "data", "test", "dev", "cdn", "files", "media"):
        buckets.add(f"https://{base}-{suffix}.oss-cn-hangzhou.aliyuncs.com")

    probes = 0
    listed = []
    for url in list(buckets)[:20]:
        probes += 1
        body = net.http_text(url + "?list-type=2&max-keys=5", timeout=12)
        if not body:
            body = net.http_text(url, timeout=12)
        if "<ListBucketResult" in body or "<Contents>" in body or "ListBucketResult" in body:
            keys = re.findall(r"<Key>([^<]+)</Key>", body)[:5]
            listed.append((url, keys))
            findings.append(make_finding(
                "WSTG-CONF-11", "对象存储桶允许匿名列举（ListBucket 未关闭）",
                ctx.target_name, endpoint=url,
                severity="严重", confidence="High", evidence_level="A",
                description=("该对象存储桶对公网开放了「列举对象」权限。"
                             "任何人不需要任何凭据，就能把桶内所有文件的名称列出来，"
                             "并通常可以直接下载。"),
                technical_detail=(f"桶地址：{url}\n"
                                  f"返回对象示例：{', '.join(keys) if keys else '（返回了 ListBucketResult）'}"),
                impact=("可直接枚举并下载桶内全部对象。若桶中存放用户上传文件、导出报表、"
                        "备份数据，等同于业务数据整体泄露。"
                        "这类问题在公开案例中造成的数据量往往是百万级。"),
                reproduction=f"curl -s '{url}?list-type=2&max-keys=5' | head -20",
                remediation=("① 立即将桶权限设为私有（阿里云 OSS：关闭「公共读」并移除 ListBucket 授权）；"
                             "② 对外访问改用带签名的临时 URL（STS + 签名 URL）；"
                             "③ 开启桶的访问日志与异常访问告警；"
                             "④ 复核桶内是否已有敏感数据被下载。"),
                compliance="等保2.0 安全计算环境-数据保密性 / PIPL 第 51 条",
                evidence=[finding_evidence("response", body[:1200], f"桶列举 {url}")],
                grading_basis="实测匿名可列举桶内对象，属数据可直接获取，定严重",
                # 显式声明「这条发现就发生在桶地址上」：桶不是站点的子域，
                # 不声明的话复现脚本会回落去打网站首页 —— 网站对任意路径都返回
                # 同一张 HTML，脚本据此判「自定义错误页」，把真实暴露记成「未复现」。
                extra={"repro_base": url},
            ))
        elif re.search(r"<Code>\s*NoSuchBucket", body, re.I):
            continue
        else:
            # 尝试匿名上传探测（只发一个不落地的预检请求，不真正写入）
            head = net.http_text(url, timeout=10,
                                 extra_headers={"X-Aiscan-Probe": "readonly"})
            if re.search(r"(AccessDenied|InvalidAccessKeyId)", head, re.I):
                continue

    # ---- 素材充分性闸门（2026-09-30 修）----
    # 「0 命中」有两种完全不同的含义，**不能都算通过**：
    #   · 产物里提取到了桶地址、逐个探测均未开放 → 这是**证据**，可以判通过；
    #   · 产物里**一个桶地址都没提取到**（JS 没采到 / 页面里没写），本次探测的
    #     只是「按常见命名猜的候选」→ 这是**证据不足**。
    #
    # 为什么严重：真实桶名通常写在产物里 —— 内部生产系统那个 `内部生产系统-files`
    # 正是从产物中提取到的。素材一旦缺失，真实桶名就一起消失了，
    # 此时「探测 N 个猜测候选、0 命中」被读成「没有开放桶」，
    # 就是用一次失败的采集把**严重级**风险判掉（假阴性里最坏的一种）。
    #
    # 这里不把整项挂 `requires=["js"]`：本项 `needs_app=False`，桶探测不经应用，
    # 即使 JS 没采到，`baseline_body` 仍可能含桶地址，整项判「未执行」会浪费
    # 这个能力。闸门放在检测器内部，粒度更准。
    if not findings and not from_assets:
        _h = collection_health(ctx)
        if _h.get("degraded"):
            return pending(
                f"未能从页面产物中提取到任何对象存储桶地址，本次只探测了按常见命名"
                f"构造的 {len(buckets)} 个候选（均未命中）；且采集通道不完整"
                f"（{_h.get('detail')}）—— 无法区分「目标未使用对象存储」与"
                "「桶地址写在未采集到的产物里」，请人工确认后补测",
                probes=probes, evidence_kind="存储桶匿名访问实测")
        return na(
            f"页面与 {len(js_bodies)} 份前端产物中均未出现对象存储桶地址，"
            f"另按常见命名探测 {probes} 个候选均未命中 —— "
            "匿名可达表面未发现开放的对象存储桶。",
            probes=probes, evidence_kind="存储桶匿名访问实测")

    note = (f"从产物中提取 {len(from_assets)} 个桶地址、按命名规则构造 "
            f"{len(buckets) - len(from_assets)} 个候选，实际探测 {probes} 次；"
            f"可匿名列举 {len(listed)} 个")
    return found(note, findings, probes=probes, evidence_kind="存储桶匿名访问实测")


# ======================================================================
# WSTG-CONF-12 内容安全策略（CSP）
# ======================================================================
@make_auto("WSTG-CONF-12", name="CSP 配置核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="响应头实测",
           detector_ref="checks/config.py:conf12")
def conf12(ctx: DetectorContext):
    findings = []
    csp = ctx.header("content-security-policy")
    csp_ro = ctx.header("content-security-policy-report-only")
    if not csp and not csp_ro:
        findings.append(make_finding(
            "WSTG-CONF-12", "未配置内容安全策略（CSP）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="High", evidence_level="A",
            description=("站点没有下发 CSP 头。CSP 是浏览器层面的最后一道防线："
                         "即使页面存在 XSS 漏洞，CSP 也能阻止恶意脚本执行、阻止数据被外发。"),
            technical_detail="响应头 Content-Security-Policy：缺失\n"
                             "Content-Security-Policy-Report-Only：缺失",
            impact=("缺失 CSP 时，一旦存在 XSS，攻击脚本可任意执行、任意外发数据。"
                    "存在 CSP 时同类攻击往往被浏览器直接拦下。"
                    "这是纵深防御中成本最低、收益最直接的一层。"),
            reproduction=f"curl -sI {ctx.target_url} | grep -i content-security-policy",
            remediation=("先以 Report-Only 模式上线观察：\n"
                         "Content-Security-Policy-Report-Only: default-src 'self'; "
                         "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\n"
                         "收集报告、消除内联脚本后切换为强制执行。避免使用 unsafe-inline / unsafe-eval。"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("header", "缺失 Content-Security-Policy", "响应头")],
            grading_basis="防护能力缺失，属确证配置问题，定中危",
        ))
    else:
        value = csp or csp_ro
        weak = []
        if "unsafe-inline" in value:
            weak.append("script-src 含 'unsafe-inline'（内联脚本可执行，XSS 防护基本失效）")
        if "unsafe-eval" in value:
            weak.append("script-src 含 'unsafe-eval'")
        if re.search(r"(default-src|script-src)[^;]*\*", value):
            weak.append("源列表使用通配符 *")
        if "data:" in value and "script-src" in value:
            weak.append("script-src 允许 data: 协议")
        if weak:
            findings.append(make_finding(
                "WSTG-CONF-12", f"CSP 已配置但存在 {len(weak)} 处削弱项",
                ctx.target_name, endpoint=ctx.target_url,
                severity="低危", confidence="High", evidence_level="A",
                description="站点启用了 CSP，但策略中包含会大幅削弱防护效果的关键字，实际拦截能力有限。",
                technical_detail=f"策略：{value}\n问题：\n" + "\n".join(f"  · {w}" for w in weak),
                impact="unsafe-inline 等关键字使浏览器仍会执行页面内联脚本，XSS 的防护几乎失效，",
                reproduction=f"curl -sI {ctx.target_url} | grep -i content-security-policy",
                remediation=("移除 unsafe-inline / unsafe-eval，改用 nonce 或 hash 方式放行必要脚本；"
                             "源列表收敛到具体域名，不使用通配符。"),
                compliance="等保2.0 安全计算环境-入侵防范",
                evidence=[finding_evidence("header", value, "CSP 策略")],
                grading_basis="CSP 存在但防护被削弱，定低危",
            ))
    return found(f"CSP：{csp or csp_ro or '缺失'}", findings, probes=1, evidence_kind="响应头实测")


# ======================================================================
# WSTG-CONF-13 路径混淆
# ======================================================================
@make_auto("WSTG-CONF-13", name="路径混淆绕过检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="路径变体对比实测",
           detector_ref="checks/config.py:conf13")
def conf13(ctx: DetectorContext):
    findings = []
    # 找一个当前被拒绝的受控路径作为对照
    denied = []
    for path, probe in (ctx.fp_result.get("path_probes") or {}).items():
        if isinstance(probe, dict) and probe.get("status") in (401, 403):
            denied.append(path)
    if not denied:
        for cand in ("admin", "manage", "console", "actuator/env", "server-status"):
            pr = probe_or_none(ctx, cand)
            if pr is not None and getattr(pr, "status", 0) in (401, 403):
                denied.append(cand)
                break

    if not denied:
        return no_target_outcome(ctx, "返回 401/403 的受控路径", probes=3, evidence_kind="无对照路径")

    base_path = denied[0].strip("/")
    base_pr = probe_or_none(ctx, base_path)
    base_status = getattr(base_pr, "status", 0) if base_pr else 0

    variants = [
        f"/{base_path}/", f"//{base_path}", f"/{base_path}/.", f"/{base_path}//",
        f"/./{base_path}", f"/{base_path}%20", f"/{base_path}.", f"/{base_path}%2f",
        f"/{base_path};x=y", f"/{base_path}..;/", f"/{base_path}/..;/",
        f"/{base_path.upper()}", f"/{base_path}%2e", f"/{base_path}?", f"/{base_path}#",
        f"/{base_path}%00", f"/{base_path}/.json", f"/{base_path}%09",
    ]
    probes = len(variants)
    res = ctx.probe_many(variants)
    bypassed = []
    for v, probe in res.items():
        st = getattr(probe, "status", 0)
        if st == 200 and is_real_hit(ctx, probe, min_len=20):
            bypassed.append((v, st, (getattr(probe, "title", "") or "")[:60]))

    if bypassed:
        findings.append(make_finding(
            "WSTG-CONF-13", f"路径混淆可绕过访问控制（{len(bypassed)} 个变体）",
            ctx.target_name, endpoint=urljoin(ctx.target_url, bypassed[0][0]),
            severity="高危", confidence="High", evidence_level="A",
            description=(f"直接访问 /{base_path} 被服务端拒绝（HTTP {base_status}），"
                         "但加上路径修饰符后却能正常打开。"
                         "说明访问控制是按「路径字符串」匹配的，而不是按归一化后的真实资源匹配。"),
            technical_detail=("基准路径：/{p} → HTTP {s}\n可绕过的变体：\n".format(p=base_path, s=base_status)
                              + "\n".join(f"  {v}  → HTTP {st}  {t}" for v, st, t in bypassed)),
            impact=("这等于绕过了对管理入口、内部接口的访问限制，可直接到达本应被拦截的页面。"
                    "若该路径对应管理功能，攻击者无需凭据即可进入。"),
            reproduction=(f"curl -sI {urljoin(ctx.target_url, base_path)}   # 预期被拒绝\n"
                          f"curl -sI {urljoin(ctx.target_url, bypassed[0][0])}  # 实际可访问"),
            remediation=("① 访问控制在服务端框架层做，不要用 Nginx location 的字符串前缀匹配；"
                         "② 入口做路径归一化后再鉴权（先解码、去多余分隔符、消解 ../ 与 ;）；"
                         "③ 对同一资源的多种表示统一路由到同一鉴权入口。"),
            compliance="等保2.0 安全计算环境-访问控制 / CWE-647",
            evidence=[finding_evidence("response",
                                       "\n".join(f"{v} → {st}" for v, st, _ in bypassed),
                                       "绕过变体")],
            grading_basis="实测绕过访问控制并可达受控资源，定高危",
        ))

    note = (f"以 /{base_path}（HTTP {base_status}）为基准，测试 {len(variants)} 个混淆变体，"
            f"绕过成功 {len(bypassed)} 个")
    return found(note, findings, probes=probes, evidence_kind="路径变体对比")


# ======================================================================
# WSTG-CONF-14 其他 HTTP 安全头配置错误
# ======================================================================
@make_auto("WSTG-CONF-14", name="其他安全响应头核查", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="响应头实测",
           detector_ref="checks/config.py:conf14")
def conf14(ctx: DetectorContext):
    findings = []
    missing = {}
    for name, (expected, desc, sev) in SECURITY_HEADER_RULES.items():
        if name in ("strict-transport-security", "content-security-policy"):
            continue  # 由 CONF-07 / CONF-12 专项检查
        val = ctx.header(name)
        if not val:
            missing[name] = (desc, sev)
        elif expected and expected not in val.lower():
            missing[name] = (f"{desc}（值不合规：{val[:60]}）", sev)

    if missing:
        worst = "中危" if any(s == "中危" for _, s in missing.values()) else "低危"
        findings.append(make_finding(
            "WSTG-CONF-14", f"缺失 {len(missing)} 项安全响应头",
            ctx.target_name, endpoint=ctx.target_url,
            severity=worst, confidence="High", evidence_level="A",
            description=("浏览器依赖这些响应头来决定如何安全地处理页面内容。"
                         "缺失时浏览器会采用宽松的默认行为，把一些本来可防住的问题放过去。"),
            technical_detail="缺失 / 不合规的响应头：\n"
                             + "\n".join(f"  · {n}  —— {d}" for n, (d, _) in missing.items()),
            impact=("X-Frame-Options 缺失 → 页面可被嵌入 iframe 做点击劫持；"
                    "X-Content-Type-Options 缺失 → 浏览器可能按内容猜测类型，把上传文件当脚本执行；"
                    "Referrer-Policy 缺失 → 页面地址可能随外链泄露给第三方。"),
            reproduction=f"curl -sI {ctx.target_url}",
            remediation=("统一在反向代理层下发：\n"
                         "  X-Content-Type-Options: nosniff\n"
                         "  X-Frame-Options: DENY（或 CSP frame-ancestors 'none'）\n"
                         "  Referrer-Policy: strict-origin-when-cross-origin\n"
                         "  Permissions-Policy: geolocation=(), microphone=(), camera=()\n"
                         "  Cross-Origin-Opener-Policy: same-origin"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("header",
                                       "\n".join(f"{n}: 缺失" for n in missing), "缺失响应头")],
            grading_basis="防护头缺失，属确证配置问题，定中危 / 低危",
        ))

    present = [n for n in SECURITY_HEADER_RULES if ctx.header(n)]
    note = (f"核查 {len(SECURITY_HEADER_RULES) - 2} 项安全头，"
            f"已配置 {len(present)} 项，缺失 / 不合规 {len(missing)} 项")
    return found(note, findings, probes=1, evidence_kind="响应头实测")


# ======================================================================
# WSTG-CONF-15 功能开关安全绕过
# ======================================================================
@make_auto("WSTG-CONF-15", name="功能开关绕过检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="开关参数对比实测",
           detector_ref="checks/config.py:conf15")
def conf15(ctx: DetectorContext):
    findings = []
    params = ctx._cache.get("info06_params") or []
    candidates = [p for p in params if p.get("url", "").startswith("http")][:6]
    if not candidates:
        return no_target_outcome(ctx, "可用于特性开关对比的带参接口", probes=2, evidence_kind="无候选接口")

    switches = [("debug", "1"), ("test", "true"), ("preview", "1"),
                ("internal", "1"), ("beta", "1"), ("admin", "true"),
                ("mock", "1"), ("flag", "all")]
    probes = 0
    hits = []
    for cand in candidates[:3]:
        base = ctx.get(cand["url"])
        base_len = len(getattr(base, "body_snippet", "") or "")
        base_status = getattr(base, "status", 0)
        for k, v in switches:
            url = cand["url"] + ("&" if "?" in cand["url"] else "?") + f"{k}={v}"
            probes += 1
            probe = ctx.get(url)
            st = getattr(probe, "status", 0)
            body = getattr(probe, "body_snippet", "") or ""
            if st == 200 and base_status != 200:
                hits.append((url, f"状态码由 {base_status} 变为 200", len(body)))
            elif st == 200 and abs(len(body) - base_len) > max(200, base_len * 0.25):
                hits.append((url, f"响应长度由 {base_len} 变为 {len(body)}", len(body)))

    # ---- 隐藏 / 额外语言包探测（匿名即可，零副作用）----
    # Juice Shop 等会把彩蛋语言包（如 Klingon tlh_AA）打包进前端、却不在语言
    # 选择器里暴露；任何人都能匿名读取 /assets/i18n/<code>.json。
    # 判据：对一组「明显非标准」的 locale 代码发 GET，命中 200 且响应体是 JSON
    # （而非 Angular 路由兜底返回的 index.html，后者以 < 开头）即证明存在
    # 未公开暴露的翻译包 —— 属于信息暴露，且暴露了「应用打包了本不该给匿名用户的资源」。
    _SUSPICIOUS_LOCALES = (
        "tlh_AA", "tlh", "qps-ploc", "qq", "zz", "en_GB-x-psaccent",
        "zh_HANT", "dummy", "xx", "pseudo",
    )
    lang_hits = []
    for code in _SUSPICIOUS_LOCALES:
        lurl = urljoin(ctx.target_url, f"/assets/i18n/{code}.json")
        probes += 1
        try:
            lpr = ctx.get(lurl)
        except Exception:  # noqa: BLE001
            continue
        lbody = (getattr(lpr, "body_snippet", "") or "").strip()
        if getattr(lpr, "status", 0) != 200 or not lbody.startswith("{"):
            # 200 但返回 <!DOCTYPE ...>（Angular 兜底）或 404 都不算命中
            continue
        lang_hits.append((code, lurl, len(lbody)))

    if lang_hits:
        findings.append(make_finding(
            "WSTG-CONF-15", f"暴露未公开的语言包资源（{len(lang_hits)} 个）",
            ctx.target_name, endpoint=lang_hits[0][1], method="GET",
            param="locale 代码",
            severity="低危", confidence="High", evidence_level="A",
            description=("应用把一组非标准的 locale 翻译包打包进了前端，"
                         "且匿名即可直接读取（如 Klingon 等彩蛋语言包），"
                         "但这些语言并不在正常的语言选择器里出现。"
                         "这说明前端打包了本不该向匿名用户暴露的资源，"
                         "也属于一类信息暴露面的失配。"),
            technical_detail=("命中的非标准 locale 代码与地址：\n"
                             + "\n".join(f"  · {c}  →  {u}（HTTP 200，JSON）"
                                         for c, u, _ in lang_hits[:8])),
            impact=("单看语言包本身危害有限，但它揭示的是「前端资源暴露面管理缺失」："
                    "任何被打包进前端的敏感资源（内部配置、调试入口、未启用功能的文案）"
                    "都可能以同样方式被匿名枚举。"),
            reproduction="\n".join(f"curl -s '{u}' | head -c 200"
                                   for _, u, _ in lang_hits[:3]),
            remediation=("仅打包正式启用的语言资源；不启用但仍随包发布的语言包应在构建期剔除；"
                        "或将前端静态资源收口到需鉴权的路径。"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence(
                "response_body",
                f"GET {lang_hits[0][1]} → HTTP 200，响应体以 {{ 开头（JSON 翻译包）",
                "暴露的语言包资源")],
            grading_basis="匿名实测可读取未公开翻译包，定低危",
        ))

    if hits:
        findings.append(make_finding(
            "WSTG-CONF-15", f"功能开关参数影响服务端行为（{len(hits)} 处）",
            ctx.target_name, endpoint=hits[0][0], param=", ".join(sorted({k for k, _ in switches})),
            severity="中危", confidence="Medium", evidence_level="B",
            description=("给请求加上开关类参数后，服务端的响应发生了明显变化，"
                         "说明这些参数在生产环境仍然生效。"),
            technical_detail="命中的参数组合：\n"
                             + "\n".join(f"  {u}\n    → {w}" for u, w, _ in hits[:8]),
            impact=("开关参数生效意味着可能关闭校验、开启调试输出、"
                    "或访问未发布功能。若存在关闭鉴权或打开详细报错的开关，"
                    "危害会直接升级。"),
            reproduction="\n".join(f"curl -s '{u}'" for u, _, _ in hits[:3]),
            remediation="生产构建中移除功能开关参数，或由服务端配置中心统一控制，不响应来自客户端的开关。",
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("request", "\n".join(u for u, _, _ in hits[:8]), "生效的开关参数")],
            grading_basis="响应差异属实测，但未确认具体放开了什么，按 B 级证据定中危",
        ))

    note = f"对 {len(candidates[:3])} 个接口测试 {probes} 组开关参数，命中 {len(hits)} 处行为变化"
    return found(note, findings, probes=probes, evidence_kind="开关参数对比")
