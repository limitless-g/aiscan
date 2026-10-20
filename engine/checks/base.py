# -*- coding: utf-8 -*-
"""
检测器共用基建
==============
全量检查项里有大量重复的探测动作（读响应头、探路径、看正文特征）。
这里把共性抽象出来，各分类模块只写「判定逻辑」，不重复造请求。

设计约束：
  - 所有探测都经过 DetectorContext，天然带缓存与限速；
  - 所有路径字典集中在此，便于按行业增删；
  - 判定「命中」必须排除自定义 404 页与 SPA 回退页，否则误报会淹没报告。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from engine.registry import DetectorContext, DetectorOutcome

# ======================================================================
# 路径字典
# ======================================================================
# 元文件（WSTG-INFO-03）
META_FILES = [
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "humans.txt",
    "security.txt", ".well-known/security.txt", "manifest.json",
    "crossdomain.xml", "clientaccesspolicy.xml", "ads.txt",
]

# 敏感与备份文件（WSTG-CONF-03 / CONF-04）
SENSITIVE_FILE_PATHS = {
    ".env": ("环境变量文件", "高危"),
    ".env.local": ("环境变量文件", "高危"),
    ".env.production": ("环境变量文件", "高危"),
    ".git/config": ("Git 配置", "高危"),
    ".git/HEAD": ("Git 仓库指针", "高危"),
    ".svn/entries": ("SVN 元数据", "中危"),
    ".hg/hgrc": ("Mercurial 配置", "中危"),
    ".DS_Store": ("macOS 目录索引", "低危"),
    ".htaccess": ("Apache 配置", "中危"),
    "web.config": ("IIS 配置", "中危"),
    "WEB-INF/web.xml": ("Java Web 配置", "高危"),
    "config.php.bak": ("PHP 配置备份", "高危"),
    "config.php~": ("PHP 配置临时文件", "高危"),
    "application.yml": ("Spring 配置", "高危"),
    "application.properties": ("Spring 配置", "高危"),
    "bootstrap.yml": ("Spring Cloud 配置", "高危"),
    "database.yml": ("数据库配置", "高危"),
    "settings.py": ("Django 配置", "高危"),
    "id_rsa": ("SSH 私钥", "高危"),
    "id_dsa": ("SSH 私钥", "高危"),
    ".ssh/id_rsa": ("SSH 私钥", "高危"),
    "backup.zip": ("备份包", "高危"),
    "backup.tar.gz": ("备份包", "高危"),
    "backup.sql": ("数据库备份", "高危"),
    "www.zip": ("站点备份", "高危"),
    "wwwroot.zip": ("站点备份", "高危"),
    "web.zip": ("站点备份", "高危"),
    "site.zip": ("站点备份", "高危"),
    "db.sql": ("数据库备份", "高危"),
    "dump.sql": ("数据库备份", "高危"),
    "test.sql": ("数据库备份", "高危"),
    "index.php.bak": ("源码备份", "高危"),
    "index.jsp.bak": ("源码备份", "高危"),
    "package.json": ("前端依赖清单", "低危"),
    "yarn.lock": ("依赖锁定文件", "低危"),
    "composer.json": ("PHP 依赖清单", "低危"),
    "Dockerfile": ("容器构建文件", "中危"),
    "docker-compose.yml": ("容器编排文件", "中危"),
    ".dockerignore": ("容器忽略清单", "低危"),
    "phpinfo.php": ("PHP 探针页", "中危"),
    "info.php": ("PHP 探针页", "中危"),
    "test.php": ("测试页", "中危"),
    "server-status": ("Apache 状态页", "中危"),
    "server-info": ("Apache 信息页", "中危"),
    "actuator": ("Spring Actuator", "高危"),
    "actuator/env": ("Spring 环境变量端点", "高危"),
    "actuator/health": ("Spring 健康端点", "低危"),
    "actuator/heapdump": ("Spring 堆转储", "高危"),
    "actuator/mappings": ("Spring 路由映射", "中危"),
    "metrics": ("指标端点", "中危"),
    "debug/pprof": ("Go pprof 调试端点", "高危"),
    "console": ("管理控制台", "中危"),
    "elmah.axd": ("ASP.NET 错误日志", "中危"),
    "trace.axd": ("ASP.NET 追踪日志", "中危"),
    "login.action": ("遗留登录入口", "低危"),
    "jmx-console": ("JBoss 控制台", "高危"),
    "manager/html": ("Tomcat 管理台", "高危"),
    "host-manager/html": ("Tomcat 虚拟主机管理", "高危"),
    "wp-config.php.bak": ("WordPress 配置备份", "高危"),
    "wp-login.php": ("WordPress 登录入口", "低危"),
    "xmlrpc.php": ("WordPress XML-RPC", "中危"),
}

# 管理后台与运维接口（WSTG-CONF-05）
ADMIN_PATHS = [
    "admin", "admin/", "admin/login", "administrator", "manage", "manager",
    "console", "dashboard", "backend", "cms", "system", "root", "controlpanel",
    "wp-admin", "user/login", "login", "signin", "sign-in", "auth/login",
    "passport/login", "account/login", "sso/login", "portal", "ops", "monitor",
    "grafana", "kibana", "prometheus", "zabbix", "jenkins", "gitlab",
]

# API 文档与接口清单（WSTG-APIT-01）
API_DOC_PATHS = [
    "swagger-ui.html", "swagger-ui/", "swagger/index.html", "swagger.json",
    "swagger.yaml", "v2/api-docs", "v3/api-docs", "api-docs", "openapi.json",
    "openapi.yaml", "docs", "api/docs", "redoc", "graphiql", "graphql/console",
    ".well-known/openapi.json", "api/swagger.json", "api/v1/swagger.json",
]

# 版本控制与 CI/CD 残留（EXT-CD-01 / EXT-CD-03）
VCS_PATHS = [
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".svn/entries", ".svn/wc.db", ".hg/hgrc", ".bzr/README",
]
CICD_PATHS = [
    ".gitlab-ci.yml", ".github/workflows/main.yml", ".github/workflows/ci.yml",
    ".circleci/config.yml", "Jenkinsfile", "azure-pipelines.yml",
    ".travis.yml", "bitbucket-pipelines.yml", "drone.yml", "buildspec.yml",
    ".gitlab-ci.yaml", "deploy.sh", "build.sh", "Makefile", "docker-compose.yml",
    "docker-compose.prod.yml", "k8s/deployment.yaml", "helm/values.yaml",
    ".env.ci", "sonar-project.properties", "Dockerfile",
]

# 云与容器暴露面（EXT-CL-*）
CONTAINER_PATHS = {
    "2375/tcp": "Docker API（未加密）",
    "2376/tcp": "Docker API（TLS）",
    "6443/tcp": "Kubernetes API Server",
    "10250/tcp": "Kubelet API",
    "10255/tcp": "Kubelet 只读端点",
    "8080/tcp": "容器管理台 / 中间件",
    "9000/tcp": "Portainer / 中间件",
    "5000/tcp": "Docker Registry",
    "8500/tcp": "Consul",
    "2379/tcp": "etcd 客户端",
    "4243/tcp": "Docker Remote API（旧版）",
}
K8S_API_PATHS = ["api", "apis", "version", "healthz", "metrics", "api/v1/namespaces", "openapi/v2"]
METADATA_PATHS = [
    "latest/meta-data/", "latest/meta-data/iam/security-credentials/",
    "latest/user-data", "metadata/v1/", "computeMetadata/v1/",
    "latest/api/token",
]

# AI / LLM 端点（EXT-AI-01）
AI_PATHS = [
    "v1/chat/completions", "v1/completions", "v1/models", "v1/embeddings",
    "api/chat", "api/generate", "api/chat/completions", "chat/completions",
    "api/v1/chat/completions", "ollama/api/generate", "api/tags",
    "v1beta/models", "api/ai/chat", "ai/chat", "chat", "llm/chat",
    "v1/messages", "api/v1/messages",
    # 业务客服 / 对话机器人形态（REST 直挂 rest/ 前缀，action+query 载荷）。
    # 2026-10-10 第十轮实测：Juice Shop 的 chatbot 在 rest/chatbot/respond，
    # 不在候选清单里 → EXT-AI-01/02/04/05 四项集体「待确认」。
    "rest/chatbot/respond", "rest/chatbot/status", "rest/bot/response",
    "rest/chat/response", "api/bot/respond",
    # 2026-10-14 第 29 轮实测（Juice Shop v20.2.0）：chatbot 路由改到
    # POST /rest/chat（Vercel AI SDK 形态，载荷 {"messages":[…]}，
    # 旧路径 rest/chatbot/respond 已 404「Unexpected path」）。
    # 该路由是 POST-only：GET 只拿到兜底错误页，与不存在路径无法区分，
    # 靠空载荷 POST 探针确认（见 extras2.py LLM_ERROR_SIGNATURES）。
    "rest/chat", "rest/chat/stream",
]

# 数据与调试泄露（EXT-DP / WSTG-ERRH）
DEBUG_PATHS = [
    "debug", "debug/", "actuator/loggers", "actuator/configprops",
    "actuator/httptrace", "actuator/threaddump", "logs", "log", "error.log",
    "app.log", "debug.log", "logs/app.log", "logs/error.log", "trace",
    "phpinfo.php", "test", "test/", "demo", "sample", "example",
    "api/debug", "api/test", "internal", "internal/", ".well-known/",
]

# 邮件与门户服务端口（EXT-DM-05）
MAIL_PORTS = {25: "SMTP", 465: "SMTPS", 587: "SMTP 提交", 110: "POP3",
              143: "IMAP", 993: "IMAPS", 995: "POP3S", 8443: "备用 HTTPS",
              8080: "备用 HTTP", 21: "FTP", 3306: "MySQL", 6379: "Redis",
              27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached"}

# 供应链 CDN 与第三方资源（EXT-SC-04）
THIRD_PARTY_HOSTS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "code.jquery.com",
    "ajax.googleapis.com", "cdn.bootcdn.net", "lib.baomitu.com", "cdn.staticfile.org",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com", "use.fontawesome.com",
    "kit.fontawesome.com", "cdn.tailwindcss.com", "polyfill.io", "cdn.polyfill.io",
]

# 弱加密原语（WSTG-CRYP-04）
WEAK_CRYPTO_PATTERNS = [
    (r"\bmd5\s*\(", "MD5 哈希"),
    (r"\bsha1\s*\(", "SHA-1 哈希"),
    (r"\bdes\b|\b3des\b|tripledes", "DES / 3DES 对称加密"),
    (r"\brc4\b|\barcfour\b", "RC4 流加密"),
    (r"createCipher\s*\(|createDecipher\s*\(", "Node.js 无 IV 的 createCipher"),
    (r"Math\.random\s*\(", "Math.random 生成安全相关值"),
    (r"\becb\b|\bCipher\.getInstance\(\s*[\"']AES/ECB", "ECB 模式"),
    (r"btoa\s*\(\s*password|localStorage\.setItem\(\s*[\"']password", "前端明文存密码"),
]

# DOM XSS 源与汇（WSTG-CLNT-01）
# 统一为 (正则, 中文说明) 二元组 —— 消费方按元组解包，说明会直接写进报告。
DOM_XSS_SINKS = [
    (r"\.innerHTML\s*=", "innerHTML 赋值"),
    (r"\.outerHTML\s*=", "outerHTML 赋值"),
    (r"document\.write\s*\(", "document.write 写入"),
    (r"\beval\s*\(", "eval 执行"),
    (r"new\s+Function\s*\(", "new Function 构造"),
    (r"setTimeout\s*\(\s*[\"']", "setTimeout 字符串执行"),
    (r"setInterval\s*\(\s*[\"']", "setInterval 字符串执行"),
    (r"location\s*=\s*[^=]", "location 直接赋值"),
    (r"location\.href\s*=", "location.href 赋值"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML 插入"),
    (r"\.srcdoc\s*=", "iframe srcdoc 赋值"),
    (r"\$\s*\(\s*[\"']<", "jQuery 以 HTML 字符串构造元素"),
    (r"v-html\s*=", "Vue v-html 渲染"),
    (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
]
DOM_XSS_SOURCES = [
    (r"location\.hash", "地址栏 hash"),
    (r"location\.search", "地址栏查询串"),
    (r"location\.href", "地址栏完整地址"),
    (r"document\.URL", "document.URL"),
    (r"document\.referrer", "document.referrer"),
    (r"window\.name", "window.name"),
    (r"document\.cookie", "document.cookie"),
    (r"localStorage\.getItem", "localStorage 读取"),
    (r"sessionStorage\.getItem", "sessionStorage 读取"),
    (r"postMessage", "postMessage 消息"),
    (r"URLSearchParams", "URLSearchParams 解析"),
    (r"\.getParameter\s*\(", "getParameter 取参"),
]

# 与「点击劫持 / 安全响应头」相关的头（WSTG-CONF-12 / CONF-14 / CLNT-09）
SECURITY_HEADER_RULES = {
    "x-content-type-options": ("nosniff", "MIME 嗅探防护", "低危"),
    "x-frame-options": (None, "点击劫持防护", "中危"),
    "referrer-policy": (None, "Referer 泄露控制", "低危"),
    "permissions-policy": (None, "浏览器特性权限控制", "低危"),
    "cross-origin-opener-policy": (None, "跨源窗口隔离", "低危"),
    "cross-origin-resource-policy": (None, "跨源资源读取控制", "低危"),
    "strict-transport-security": (None, "HTTPS 强制（HSTS）", "中危"),
    "content-security-policy": (None, "内容安全策略", "中危"),
}

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.java:\d+\)",
    r"System\.NullReferenceException",
    r"Warning:\s+\w+\(\)\s+\[function\.",
    r"Fatal error:\s+Uncaught",
    r"Stack trace:\s*\n\s*#\d",
    r"org\.springframework\.[a-zA-Z.]+Exception",
    r"com\.mysql\.jdbc\.exceptions",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"SQLite3::",
    r"django\.core\.exceptions",
    r"ActionController::",
    r"whoops\\Exception",
    r"in /var/www/|in /home/\w+/|at C:\\\\(inetpub|wwwroot)",
]

PII_PATTERNS = {
    "手机号": r"(?<!\d)1[3-9]\d{9}(?!\d)",
    "身份证号": r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
    "银行卡号": r"(?<!\d)\d{16,19}(?!\d)",
    "邮箱地址": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
}

# 文档 / 示例里的假数据，避免把教程内容当泄露
PLACEHOLDER_VALUES = {
    "13800138000", "13900139000", "13000000000", "18888888888", "12345678901",
    "110101199001011234", "110101199003070000", "test@example.com",
    "admin@example.com", "user@example.com", "example@example.com",
    "6222020000000000000", "4111111111111111", "310101199001011234",
}

# 判「这是不是占位示例」时只看**命中值所在的字段片段**，不按固定字符窗口。
# 用固定窗口两头都错过：开大（曾用 ±60）时紧凑 JSON 里一个 `example.org`
# 会把同一响应里的身份证号、银行卡号一起误过滤 —— 漏报个人信息类型；
# 开小（±16）又会漏掉紧跟在值后面的 `placeholder` 字样 —— 同样漏判。
PII_SKIP_WORDS = ("example", "placeholder", "示例", "占位",
                  "xxxx", "your_", "your-", "dummy")
_TOKEN_SEPS = set("{[,;|\n\"'")


def _token_around(text: str, start: int, end: int, cap: int = 48) -> str:
    """取命中值所在的字段片段：向左右扩到结构分隔符为止（最多各 cap 字符）。"""
    l = start
    while l > 0 and (start - l) < cap and text[l - 1] not in _TOKEN_SEPS:
        l -= 1
    r = end
    while r < len(text) and (r - end) < cap and text[r] not in _TOKEN_SEPS:
        r += 1
    return text[l:r].lower()


def pii_hit_values(text: str, *, limit: int = 12) -> list[tuple[str, str]]:
    """在文本里找 PII 特征，返回 [(类型, 原始值)]。占位值与重复一律过滤。

    ⚠️ 这个函数是**检测器与红队证明器共用的唯一判据**。
    两边各写一份必然会漂移，而漂移的后果是「检测器说响应里有手机号、
    证明器却判未达成」这类**与证据自相矛盾的结论**。所以过滤规则只有这一份：
    占位值表 + 全同数字排除 + 同值去重 + 字段片段内的占位词判定。
    """
    out: list[tuple[str, str]] = []
    if not text:
        return out
    seen: set[str] = set()
    for label, pat in PII_PATTERNS.items():
        for m in re.finditer(pat, text):
            val = m.group(0)
            if val in PLACEHOLDER_VALUES:
                continue
            if len(set(val)) <= 3:               # 11111111111 这类不算
                continue
            # 同一串数字若已被更具体的规则命中，不再换个类型重复计数。
            # （18 位身份证号同时满足「银行卡号」的 16–19 位数字判据。）
            if val in seen:
                continue
            if any(k in _token_around(text, m.start(), m.end())
                   for k in PII_SKIP_WORDS):
                continue
            seen.add(val)
            out.append((label, val))
            if len(out) >= limit:
                return out
    return out

CREDENTIAL_PATTERNS = [
    (r"(?:AKIA|ASIA)[0-9A-Z]{16}", "AWS Access Key"),
    (r"LTAI[0-9A-Za-z]{12,}", "阿里云 AccessKey ID"),
    (r"(?i)(?:secret|access)[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{16,}", "云厂商 Secret"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub Token"),
    (r"sk_live_[A-Za-z0-9]{16,}", "Stripe 密钥"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack Token"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT"),
    (r"(?i)app[_-]?secret\s*[:=]\s*[\"'][A-Za-z0-9]{16,}", "应用密钥"),
    (r"(?i)(?:mysql|postgres|mongodb)://[^\s\"'<>]{8,}", "数据库连接串"),
    (r"(?i)(?:redis|amqp)://[^\s\"'<>]{8,}", "中间件连接串"),
    (r"(?i)private[_-]?key\s*[:=]\s*[\"']?-----BEGIN", "私钥"),
]

INTERNAL_ADDR_PATTERNS = [
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "10/8 内网地址"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "192.168/16 内网地址"),
    (r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "172.16/12 内网地址"),
    (r"\b127\.0\.0\.1\b", "本机回环地址"),
    (r"[\w\-]+\.(?:internal|local|corp|intra|lan)\b", "内部域名"),
    (r"(?i)\b(?:dev|test|uat|stage|staging|pre|sandbox|gray|canary)\b[\w\-]*\.", "非生产环境域名"),
]

SCAN_UA_TAG = "AIScan/1.0 (Authorized Security Assessment)"


# ======================================================================
# 通用助手
# ======================================================================
def is_real_hit(ctx: DetectorContext, probe: Any, *, min_len: int = 15) -> bool:
    """判断一次 200 响应是否为真实内容命中（排除自定义 404 与 SPA 回退）。"""
    if probe is None:
        return False
    status = getattr(probe, "status", 0)
    if status != 200 or getattr(probe, "error", ""):
        return False
    body = getattr(probe, "body_snippet", "") or ""
    return ctx.content_matches("", body) and len(body.strip()) >= min_len


def probe_or_none(ctx: DetectorContext, path: str) -> Any:
    try:
        p = ctx.probe_path(path)
        return p if getattr(p, "reachable", False) else None
    except Exception:  # noqa: BLE001
        return None


def scan_paths(ctx: DetectorContext, paths: list[str]) -> dict[str, Any]:
    """批量探测并过滤成「真实命中」。"""
    res = ctx.probe_many(paths)
    return {p: pr for p, pr in res.items() if is_real_hit(ctx, pr)}


def sitewide_guard(ctx: DetectorContext) -> tuple[int, float, int]:
    """目标是否「对任意路径返回同一个响应」。

    返回 (众数状态码, 占比, 样本数)；未命中整站同一响应时状态码为 0。

    为什么检测器都要问一句：很多判定把「路径返回 405 / 403 / 401」当作
    「该路径存在」的证据。目标若整站同码（边缘防护、反代配错、全站
    return 405），这些推断会同时全部成立 —— 一整套「接口存在」的结论
    都是假的。判定前先问一句，就能把这一类误报整体拦掉。

    结论按 ctx 缓存，整份扫描只算一次。
    """
    cached = ctx._cache.get("_sitewide_status")
    if cached is None:
        from engine.wafgate import sitewide_uniform_status  # noqa: PLC0415

        cached = sitewide_uniform_status(ctx.fp_result.get("path_probes") or {})
        ctx._cache["_sitewide_status"] = cached
    return cached                                                   # type: ignore[return-value]


# ======================================================================
# 可达性判定（全扫描唯一入口）
# ======================================================================
# 端口类发现散落在 INFO-04 / EXT-CL-02 / EXT-DM-05 等多个检测器里。
# 如果每个检测器各自判断「算不算公网暴露」，会出现两个问题：
#   ① 同一份报告里措辞不一致（有的写「公网暴露」，有的写「对外可达」）；
#   ② 目标解析到私网地址时，每个检测器都在独立地犯同一个错。
# 所以这里收敛成一个入口 —— 判定结果缓存在 ctx 上，全扫描只做一次结论。
def reachability_scope(ctx: DetectorContext) -> tuple[str, str, str]:
    """返回（可达范围标签, 建议定级修正, 判定依据说明）。

    标签只有 ``公网可达`` / ``内网可见（非公网暴露）`` 两种，直接用于标题。
    """
    cached = getattr(ctx, "_reach_scope", None)
    if cached is not None:
        return cached
    from engine.checks import net  # noqa: PLC0415

    ip = ctx._cache.get("info04_ip") or ""
    if not ip:
        try:
            ip = (net.dns_records(ctx.domain, "A") or [""])[0]
        except Exception:  # noqa: BLE001
            ip = ""
        if ip:
            ctx._cache["info04_ip"] = ip
    if not ip:
        # 目标是**裸 IP** 的回退分支。内网系统最常见的形态就是直接给一个
        # `10.x / 172.x / 192.168.x` 地址 —— 这时 DNS 侧永远解析不出 A 记录
        # （`dns_records` 对 IP 字符串会抛异常并被吞掉，返回空列表），
        # 而「解析地址」其实就是目标本身。
        #
        # 不做这个回退的后果：可达范围会被写成「未取得解析地址」，读者读出来是
        # 「没解析出来（技术故障）」，而不是「这是私网地址、公网根本不可达」——
        # 公网基线红线要求的内网标注就此丢失，而它恰恰是内网扫描里最重要的一行。
        #
        # 判定逻辑统一放在 net.as_ip_literal()，与 INFO-04 的端口扫描回退
        # 共用同一份实现 —— 同一个根因只留一个实现，避免一处修了一处没修。
        ip = net.as_ip_literal(ctx.domain)
        if ip:
            ctx._cache["info04_ip"] = ip
    out = net.reachability_of(ip)
    ctx._reach_scope = out
    return out


def is_public_scope(ctx: DetectorContext) -> bool:
    """目标是否确实位于公网可达范围（唯一判据，别处不要另做判断）。"""
    return reachability_scope(ctx)[0] == "公网可达"


def finding_evidence(kind: str, content: str, note: str = "") -> Any:
    from models import Evidence
    h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:16]
    return Evidence(kind=kind, content=content[:3000], note=note,
                    masked=False, raw_hash=h)


def extract_params(ctx: DetectorContext) -> list[dict[str, str]]:
    """提取「有参数的端点」，供注入 / SSRF / 重定向类检查使用。

    必须覆盖全部五类来源 —— 只认 JS 产物里的 URL 会漏掉大量真实入口，
    而漏掉的每一个参数都会变成一条安静的「通过」：

      1. JS 产物中的地址（带查询串）
      2. 资产测绘阶段实际探到的带参地址
      3. 页面 <a href> 链接里的查询参数
      4. 表单字段（GET 表单并入查询串，POST 表单标注 method=POST）
      5. 目标根地址自身的查询参数

    返回项形如 {"url", "param", "source", "method", "in"}。
    `in` 为 `query` 或 `body`，**决定载荷怎么送出去** —— 见下面第 6 类来源。
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def push(raw: str, source: str, method: str = "GET", where: str = "query") -> None:
        if not isinstance(raw, str) or "?" not in raw:
            return
        u = urljoin(ctx.target_url, raw)
        if not u.startswith(("http://", "https://")) or ctx.domain not in u:
            return
        qs = parse_qs(urlparse(u).query, keep_blank_values=True)
        if not qs:
            return
        for k in qs:
            key = f"{method} {u} {k}"
            if key in seen:
                continue
            seen.add(key)
            out.append({"url": u, "param": k, "source": source,
                        "method": method, "in": where})

    def push_direct(u: str, param: str, source: str, method: str,
                    where: str) -> None:
        if not u.startswith(("http://", "https://")) or ctx.domain not in u:
            return
        key = f"{method} {u} {param}"
        if key in seen:
            return
        seen.add(key)
        out.append({"url": u, "param": param, "source": source,
                    "method": method, "in": where})

    # 1) JS 产物
    for url in (ctx.js_result.get("urls") or [])[:400]:
        push(url if isinstance(url, str) else "", "js")

    # 2) 资产测绘探到的带参地址
    for _path, probe in (ctx.fp_result.get("path_probes") or {}).items():
        if isinstance(probe, dict):
            push(probe.get("final_url") or probe.get("url") or "", "path_probe")

    # 3) 页面链接里的查询参数
    for href in re.findall(r'<a[^>]+href\s*=\s*["\']([^"\']+)["\']',
                           ctx.baseline_body or "", re.I)[:200]:
        push(href, "link")

    # 4) 表单字段 —— 许多系统只用表单接口，没有可抓的 JS 调用
    for f in find_forms(ctx)[:20]:
        action = f.get("action") or ctx.target_url
        method = (f.get("method") or "GET").upper()
        inputs = [i for i in (f.get("inputs") or [])
                  if i and i.lower() not in ("submit", "button", "reset")]
        if not inputs:
            continue
        if method == "GET":
            push(f"{action}?{'&'.join(f'{i}=1' for i in inputs)}", "form", "GET")
        else:
            base = urljoin(ctx.target_url, action)
            if not base.startswith(("http://", "https://")) or ctx.domain not in base:
                continue
            for i in inputs:
                key = f"POST {base} {i}"
                if key in seen:
                    continue
                seen.add(key)
                out.append({"url": base, "param": i, "source": "form", "method": "POST"})

    # 5) 目标根地址自身的查询参数
    push(ctx.target_url, "root")

    # 6) 接口文档（OpenAPI / Swagger）声明的参数 —— **含请求体字段**
    #
    # 这一类是 2026-10-12 补的，补的是一个结构性盲区：
    # 前五类来源全是「URL 上看得见的查询串」，而现代业务系统的注入点
    # 大部分藏在 **JSON 请求体**里 —— Juice Shop 的 SSRF 在
    # `PUT /api/Users/:id` 的 `imageUrl` 字段、存储型 XSS 在
    # `POST /api/Feedbacks` 的 `comment` 字段，两者在 URL 上
    # **一个字符都看不见**。只测查询串 = 对这一整片注入面结构性失明。
    #
    # ⚠ 载荷通道必须跟着 `in` 走：body 类参数塞进查询串会被服务端
    # 当成未知参数忽略（或返回 400），测出来「无反射」是**假阴性** ——
    # 不是没漏洞，是载荷根本没被处理。注入器按 `in` 分流见
    # `engine/checks/injection.py:_inject()`。
    for t in spec_param_targets(ctx):
        push_direct(t["url"], t["param"], t["source"], t["method"], t["in"])

    return out[:80]


# ======================================================================
# 接口文档声明的参数（注入面第 6 类来源）
# ======================================================================

def _spec_field(spec: Any, name: str, default: Any = None) -> Any:
    """同时支持对象与 dict —— 归档回放走 dict，只用 getattr 会静默取空（红线 68）。"""
    if isinstance(spec, dict):
        return spec.get(name, default)
    return getattr(spec, name, default)


#: 探测上下文里「登录态已回验通过」的标记值。**必须与 sessionpool.LOGIN_OK 同源** ——
#: 这里刻意不 import sessionpool（那个模块承载登录动作，与检测层解耦），
#: 代价是常量可能漂移，所以 `_selftest_base()` 里有一条断言盯住它。
_LOGGED_IN_STATE = "已登录"


def pick_logged_in_account(ctx: DetectorContext) -> dict[str, Any] | None:
    """从上下文里挑一个**已回验通过**的登录身份（没有则返回 None）。

    ⚠ 为什么受控写必须显式带上它：

      `WSTG-INPV-02`（存储型 XSS）会 POST `/api/Feedbacks` 这类
      「必须先登录才有意义」的接口。匿名请求连业务对象都够不着，
      服务端一律 500 —— 6 次写预算全部打空，note 里写着
      `api/Feedbacks[POST]→500`，结论却落「待人工执行」。

      **那 6 次请求是真实发出去的**（副作用照常产生），
      而报告上看不出它们其实一次都没被应用真正处理过 ——
      读者只会读到「试了，没试出来」。

      带着登录态发，同样的请求才会真的走到业务逻辑里，
      差分出来的差异才有意义。拿不到已验证身份时返回 None，
      调用方必须如实记「未验证」，不得当成「测过没问题」。
    """
    for a in (getattr(ctx, "accounts", None) or []):
        if not isinstance(a, dict):
            continue
        if a.get("rejected"):
            continue
        if str(a.get("login_state") or "") == _LOGGED_IN_STATE:
            return a
    return None


#: 通用账号名。与「目标自己暴露的邮箱域名」组合成候选账号。
#: 刻意只放通用名 —— 这些名字在绝大多数系统里要么不存在、要么是测试残留，
#: 命中即说明对方没改默认口令；不放任何真实人名/业务账号。
_GENERIC_ACCOUNT_NAMES: tuple[str, ...] = (
    "admin", "administrator", "test", "root", "guest", "user", "sysadmin",
)

#: 一眼就不是「目标自己的邮箱域名」—— 第三方库 / CDN / 开源项目地址。
#: 拿这些去拼账号只会得到一堆不存在的地址，白吃登录预算。
_VENDOR_EMAIL_DOMAINS: tuple[str, ...] = (
    "example.com", "example.org", "domain.com", "email.com", "test.com",
    "github.com", "gitlab.com", "npmjs.com", "angular.io", "vuejs.org",
    "react.dev", "w3.org", "sentry.io", "schema.org", "mozilla.org",
    "google.com", "microsoft.com", "apache.org", "jquery.com", "spring.io",
    "localhost", "localhost.localdomain",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9\-]{1,63}"
                       r"(?:\.[A-Za-z0-9\-]{1,63})+)")


def target_account_candidates(ctx: DetectorContext, *, limit: int = 8) -> list[str]:
    """从目标自己暴露的信息里构造**账号候选**（邮箱形态优先）。

    为什么必须有这一路：默认口令字典里的账号是 `admin` / `test` 这类
    **裸用户名**，而大量系统的账号字段是**邮箱**。实测 Juice Shop v20：
    `admin` / `admin123` 打不动，真正能登的是 `admin@juice-sh.op`；
    而这个域名就写在打包产物里（`testing@juice-sh.op`）。
    只试裸用户名，等于把「账号形态」这一维整个放弃。

    域名来源两个：① 前端产物里出现的邮箱域名（目标自己的）；
    ② 目标主机名去掉 www（真实站点最常见的形态）。
    账号名只用通用名 —— 与字典里的裸名同一风险级别，
    不做针对真实用户的口令喷射（那是账号锁定风险，见红线 37）。
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(v: str) -> None:
        v = str(v or "").strip().lower()
        if not v or v in seen:
            return
        seen.add(v)
        out.append(v)

    # ① 目标主机名（去 www）
    host = ""
    try:
        host = str(ctx.domain or "").strip().lower()
    except Exception:  # noqa: BLE001
        host = ""
    if host.startswith("www."):
        host = host[4:]
    domains: list[str] = []
    if host and "." in host and host not in _VENDOR_EMAIL_DOMAINS:
        domains.append(host)

    # ② 前端产物里的邮箱域名
    blobs: list[str] = []
    try:
        js = ctx.js_result or {}
        for b in (js.get("bodies") or [])[:40]:
            if isinstance(b, str):
                blobs.append(b)
        for b in (js.get("inline_scripts") or [])[:20]:
            if isinstance(b, str):
                blobs.append(b)
    except Exception:  # noqa: BLE001
        blobs = []
    found_domains: list[str] = []
    for blob in blobs:
        for m in _EMAIL_RE.finditer(blob):
            d = (m.group(1) or "").lower()
            if not d or "." not in d:
                continue
            if any(d == v or d.endswith("." + v) for v in _VENDOR_EMAIL_DOMAINS):
                continue
            if d not in found_domains:
                found_domains.append(d)
        if len(found_domains) >= 4:
            break

    for d in domains + [x for x in found_domains if x not in domains][:3]:
        for n in _GENERIC_ACCOUNT_NAMES[:5]:
            _add(f"{n}@{d}")
        if len(out) >= limit:
            break
    return out[:limit]


def spec_param_targets(ctx: DetectorContext, *, limit: int = 40) -> list[dict[str, str]]:
    """把接口文档里声明的参数转成统一的注入目标。

    返回项形如 {"url", "param", "source", "method", "in"}：
      · `in="query"` —— 文档里 `in: query` 的参数，载荷进查询串；
      · `in="body"`  —— 文档里 requestBody / in:body 的字段，载荷进 JSON 体。

    文档是目标**自己声明**的接口契约，比任何路径字典与正则提取都准；
    拿不到时返回空列表（调用方按「无此类来源」处理，不影响其它来源）。
    """
    out: list[dict[str, str]] = []
    res = None
    try:
        res = ctx._cache.get("openapi_spec")
    except Exception:  # noqa: BLE001
        res = None
    if res is None:
        try:
            from engine import openapi as _oa  # noqa: PLC0415
            res = _oa.discover(ctx)
        except Exception:  # noqa: BLE001
            return out
    if not (_spec_field(res, "found") and _spec_field(res, "parsed")):
        return out

    base = ctx.target_url.rstrip("/")
    eps = _spec_field(res, "endpoints") or []
    for e in eps:
        # `full_path` 已拼上 base path（如 /b2b/v2/orders）—— 注入必须打在它上面
        url = _spec_field(e, "full_path") or _spec_field(e, "url_path") or ""
        method = str(_spec_field(e, "method") or "GET").upper()
        full = url if str(url).startswith("http") else (base + "/" + str(url).lstrip("/"))
        for p in (_spec_field(e, "params") or []):
            out.append({"url": full, "param": str(p), "source": "接口文档",
                        "method": method if method != "GET" else "GET",
                        "in": "query"})
        for p in (_spec_field(e, "body_params") or []):
            out.append({"url": full, "param": str(p), "source": "接口文档",
                        "method": method, "in": "body"})
        if len(out) >= limit:
            break
    return out[:limit]


def js_api_paths(ctx: DetectorContext, *, limit: int = 60) -> list[str]:
    """从前端打包产物里提取的后端接口路径（绝对地址）。

    为什么必须有这一路：接口文档可能是**假的**（实测 Juice Shop v20 的
    `/api-docs` 挂的是一份只有一个 `/b2b/v2/orders` 的 B2B 规范，与真实
    接口面零重合）。打包产物里的接口字面量是前端真的会去请求的地址，
    这一路的召回与文档互补，而不是重复。

    结果缓存在 `ctx._cache["js_api_paths"]` —— 提取一次给所有检查项用，
    避免每个检查项都去扫一遍几 MB 的脚本正文。
    """
    cached = None
    try:
        cached = ctx._cache.get("js_api_paths")
    except Exception:  # noqa: BLE001
        cached = None
    if cached is not None:
        return list(cached)[:limit]
    blobs: list[str] = []
    try:
        js = ctx.js_result or {}
        for b in (js.get("bodies") or [])[:40]:
            if isinstance(b, str):
                blobs.append(b)
        for b in (js.get("inline_scripts") or [])[:20]:
            if isinstance(b, str):
                blobs.append(b)
    except Exception:  # noqa: BLE001
        blobs = []
    try:
        from engine.spa import discover_api_paths  # noqa: PLC0415
        paths = discover_api_paths(blobs, limit=limit)
    except Exception:  # noqa: BLE001
        paths = []
    base = str(ctx.target_url or "").rstrip("/")
    full = [base + "/" + p.lstrip("/") for p in paths if p.startswith("/")]
    try:
        ctx._cache["js_api_paths"] = full
    except Exception:  # noqa: BLE001
        pass
    return full[:limit]


def extract_object_refs(ctx: DetectorContext) -> list[dict[str, str]]:
    """提取 RESTful 风格的对象标识（/orders/123、/user/<uuid>），供越权检查使用。

    参数化接口之外，路径里的对象标识是 IDOR 的主要入口，而它**不会出现在查询串里** ——
    只看 ?key=value 会整体漏掉这一类对象，越权检查就永远「无适用对象」。
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    cands: list[tuple[str, str]] = []
    cands += [(u, "js") for u in (ctx.js_result.get("urls") or [])[:400]
              if isinstance(u, str)]
    cands += [(p, "path_probe") for p in (ctx.fp_result.get("path_probes") or {})]
    cands += [(h, "link") for h in re.findall(
        r'<a[^>]+href\s*=\s*["\']([^"\']+)["\']', ctx.baseline_body or "", re.I)[:200]]

    pats = (
        (re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=[/?#]|$)", re.I), "uuid"),
        (re.compile(r"/([0-9a-f]{16,32})(?=[/?#]|$)", re.I), "hash"),
        (re.compile(r"/(\d{1,12})(?=[/?#]|$)"), "id"),
    )
    for raw, source in cands:
        u = urljoin(ctx.target_url, raw)
        if not u.startswith(("http://", "https://")) or ctx.domain not in u:
            continue
        path = urlparse(u).path
        for pat, kind in pats:
            m = pat.search(path)
            if not m:
                continue
            key = f"{kind}:{u}"
            if key in seen:
                break
            seen.add(key)
            out.append({"url": u, "ref": m.group(1), "kind": kind,
                        "path": path, "source": source})
            break
    return out[:40]


def collection_health(ctx: DetectorContext) -> dict[str, Any]:
    """评估采集通道是否完整。

    这是「目标没有该功能」与「我们没采到」之间唯一的分辨依据。
    没有它，一次失败的采集就能把风险判成 N/A。
    """
    reasons: list[str] = []
    body = ctx.baseline_body or ""
    if not body.strip():
        reasons.append("根路径正文为空（目标不可达或被拦截）")

    urls = ctx.js_result.get("urls") or []
    bodies = ctx.js_result.get("bodies") or []
    inline = ctx.js_result.get("inline_scripts") or []
    if re.search(r"<script", body, re.I) and not (bodies or inline):
        reasons.append("页面含 script 标签但未取到任何脚本内容")
    if not urls and not bodies and not inline:
        reasons.append("未从任何前端产物中提取到接口地址")

    return {
        "degraded": bool(reasons),
        "detail": "；".join(reasons) if reasons else (
            f"根路径可读，提取到接口地址 {len(urls)} 条、"
            f"脚本 {len(bodies) + len(inline)} 份"),
    }


def find_forms(ctx: DetectorContext) -> list[dict[str, Any]]:
    """从根路径与常见入口页里提取表单，供注入 / 认证类检查使用。"""
    forms: list[dict[str, Any]] = []
    pages = [ctx.target_url]
    for extra in ("login", "signin", "register", "search"):
        pr = probe_or_none(ctx, extra)
        if pr is not None and getattr(pr, "status", 0) == 200:
            forms_page = getattr(pr, "final_url", "") or urljoin(ctx.target_url, extra)
            if forms_page not in pages:
                pages.append(forms_page)

    for page in pages[:6]:
        body = (getattr(ctx.get(page), "body_snippet", "") or "")
        if "<form" not in body.lower():
            continue
        forms.extend(_parse_form_blocks(
            body, page, source="direct"))

    # ---------- SPA 渲染 DOM ----------
    # 直连 HTML 在前端渲染应用上是同一张骨架页 —— 表单只存在于
    # **渲染后的 DOM** 里。指纹阶段已经渲染过（fp_result["_render_html"]），
    # 这份数据必须回流给表单发现，否则检测器「看得见 has_login 特征、
    # 却找不到表单」，一族认证 / 业务项集体误判「未发现登录表单」。
    # 2026-10-10 实测：Juice Shop 上 has_login=present 而 find_forms 为空，
    # ATHN-02 因此判 N/A。这个脱节本身就是一个静默漏报源（红线 62）。
    rendered = str((ctx.fp_result or {}).get("_render_html") or "")
    if rendered and "<form" in rendered.lower():
        seen_pages = {f["page"] for f in forms}
        for f in _parse_form_blocks(rendered, ctx.target_url, source="rendered"):
            # 渲染 DOM 里同源表单可能重复出现（轮询重渲染），按
            # 字段签名去重；直连页面里已经出现的表单优先级更高
            # （直连的 action 是服务端真实地址，提交更可靠）。
            sig = (tuple(sorted(f["inputs"])), f["has_password"])
            if any((tuple(sorted(x["inputs"])), x["has_password"]) == sig
                   for x in forms):
                continue
            if f["page"] in seen_pages and not f["inputs"]:
                continue
            forms.append(f)

    # SPA 表单的 action 常为空或指向当前路由（提交由前端 JS 拦截），
    # 直接 POST 到页面地址毫无意义。按表单语义（字段组合 + 页面路由）
    # 从 JS 端点里找真实提交 API，交给调用方决定用不用。
    for f in forms:
        if f["source"] == "rendered" and (
                not f["action_raw"] or f["action"] == ctx.target_url):
            f["api_hint"] = _spa_api_for_form(ctx, f)
    return forms


def _spa_api_for_form(ctx: DetectorContext, form: dict[str, Any]) -> str:
    """为渲染态表单推断真实提交 API。

    判据（按序，命中即返回）：
      1. 表单所在页面的 hash 路由（`page` 附近文本或 form 前的锚点）
         含 login/register 等语义词 → 在 JS 端点里找同名路径；
      2. 字段组合语义：含 password+email/user → 认证类端点；
      3. JS 端点路径里同时出现表单里两个及以上字段名。

    找不到就返回空串 —— 调用方必须把「表单可见但提交目标未知」
    当作「字段识别失败」处理，而不是对着页面根地址硬提交。
    """
    urls = [u for u in (ctx.js_result.get("urls") or []) if isinstance(u, str)]
    if not urls:
        return ""
    inputs = " ".join(form["inputs"]).lower()
    want = ""
    raw = (form.get("raw") or "").lower()
    blob = raw + " " + inputs
    if re.search(r"(login|signin|sign-in|登录)", blob):
        want = "login"
    elif re.search(r"(register|signup|sign-up|注册)", blob):
        want = "register"
    if want:
        for u in urls:
            if want in u.lower():
                return u
    if form["has_password"] and ("password" in inputs):
        for u in urls:
            ul = u.lower()
            if re.search(r"(login|auth|session|user/(login|register))", ul):
                return u
    hits = [u for u in urls
            if sum(1 for i in form["inputs"]
                   if i and i.lower() in u.lower()) >= 2]
    return hits[0] if hits else ""


def _parse_form_blocks(body: str, page: str, *,
                       source: str) -> list[dict[str, Any]]:
    """从一段 HTML 里解析全部 <form>。find_forms 的公共实现。"""
    out: list[dict[str, Any]] = []
    for m in re.finditer(r"<form[^>]*>.*?</form>", body, re.I | re.S):
        block = m.group(0)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', block, re.I)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', block, re.I)
        inputs = re.findall(
            r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*', block, re.I)
        # 渲染 DOM 里大量输入框由 JS 动态挂载，name 属性可能缺失，
        # type 属性仍在 —— 把「有 type 没 name」的输入也收进来，
        # 否则密码框（type=password 但 name 在 JS 状态里）会漏。
        for tm in re.finditer(
                r'<input(?![^>]*\bname\s*=)[^>]*\btype\s*=\s*["\']([^"\']+)["\']',
                block, re.I):
            inputs.append(f"[type:{tm.group(1)}]")
        types = re.findall(r'<input[^>]*type\s*=\s*["\']([^"\']+)["\']', block, re.I)
        out.append({
            "page": page,
            # action：解析后的绝对地址，供需要真实提交地址的检查使用
            "action": urljoin(page, (action.group(1) if action else "") or ""),
            # action_raw：页面里**原样写的**值。判断「表单是否显式指向
            # 明文地址」必须用这个 —— 相对地址（action="/login"）经
            # urljoin 解析后必然以 http:// 或 https:// 开头，拿解析值
            # 去判断会让 http:// 站点上的每个表单都被误报成明文提交。
            "action_raw": (action.group(1) if action else ""),
            "method": (method.group(1).upper() if method else "GET"),
            "inputs": inputs,
            "has_password": any(t.lower() == "password" for t in types),
            "raw": block[:1200],
            "source": source,
        })
    return out


def has_login(ctx: DetectorContext) -> bool:
    for f in find_forms(ctx):
        if f["has_password"]:
            return True
    state = (ctx.fp_result.get("features") or {}).get("has_login", {})
    return state.get("state") == "present"


def code_scan(ctx: DetectorContext, patterns: list[tuple[str, str]],
              *, scope: str = "js") -> list[tuple[str, str]]:
    """在已抓取的前端产物里做模式匹配，返回 (命中说明, 原始模式)。"""
    hits: list[tuple[str, str]] = []
    blobs: list[str] = []
    if scope in ("js", "both"):
        blobs += list(ctx.js_result.get("inline_scripts") or [])
        blobs += list(ctx.js_result.get("bodies") or [])
    if scope in ("html", "both"):
        blobs.append(ctx.baseline_body)
    text = "\n".join(b for b in blobs if b)
    if not text:
        return hits
    for pat, desc in patterns:
        try:
            if re.search(pat, text, re.I):
                hits.append((desc, pat))
        except re.error:
            continue
    return hits


def ok(note: str, *, probes: int = 0, evidence_kind: str = "") -> DetectorOutcome:
    return DetectorOutcome(ok=True, findings=[], note=note,
                           probes=probes, evidence_kind=evidence_kind)


def found(note: str, findings: list[Any], *, probes: int = 0,
          evidence_kind: str = "") -> DetectorOutcome:
    return DetectorOutcome(ok=True, findings=findings, note=note,
                           probes=probes, evidence_kind=evidence_kind)


def fail(note: str) -> DetectorOutcome:
    return DetectorOutcome(ok=False, error=note)


def pending(note: str, *, probes: int = 0, evidence_kind: str = "") -> DetectorOutcome:
    """检测已完整执行，但从外部确实无法得出结论。

    典型场景：DKIM 使用非标准 selector、需要内部配置才能确认的策略。
    这种情况必须报「待确认」——既不能判通过（没证据），
    也不该判未执行（检测其实跑了）。
    """
    return DetectorOutcome(ok=True, findings=[], note=note, probes=probes,
                           evidence_kind=evidence_kind, pending=True)


def na(note: str, *, probes: int = 0, evidence_kind: str = "") -> DetectorOutcome:
    """该项对当前目标不适用 —— 已确认目标不具备对应功能。

    与 ok() 的区别至关重要：ok() 是「测了，没问题」，na() 是「没有可测对象」。
    把两者混为一谈，报告里的「通过」数量会被系统性高估：
    看起来测了很多，实际上一批项连对象都没有。
    """
    return DetectorOutcome(ok=True, findings=[], note=note, probes=probes,
                           evidence_kind=evidence_kind, not_applicable=True)


def no_target_outcome(ctx: DetectorContext, subject: str, *, probes: int = 0,
                      evidence_kind: str = "") -> DetectorOutcome:
    """「找不到可测对象」的统一判定。

    找不到对象有两种完全不同的原因，不能都算通过：
      - 采集通道正常，目标确实没有这类入口 → N/A（写明依据）
      - 采集通道本身不完整（页面没抓到 / 脚本没抓到）→ 待确认

    后者若判成 N/A，就等于用一次失败的采集把风险判定掉了。
    """
    health = collection_health(ctx)
    if health["degraded"]:
        return pending(
            f"未取得「{subject}」的可测对象，且采集通道不完整"
            f"（{health['detail']}）—— 无法区分「目标没有该功能」与"
            "「本工具没采集到」，请人工确认后补测",
            probes=probes, evidence_kind=evidence_kind)
    return na(f"匿名可达表面未发现「{subject}」，该项对当前目标不适用"
              f"（{health['detail']}）。",
              probes=probes, evidence_kind=evidence_kind)


def no_data_outcome(subject: str, why: str, *, probes: int = 0,
                    evidence_kind: str = "") -> DetectorOutcome:
    """前置数据缺失，导致本项根本无法判定 → 待确认。

    典型场景：端口探测一个结果都没拿到（目标不可达 / 探测被静默丢弃 /
    该地址非公网可达）。这类情况必须报「待确认」——
    没有数据不等于没有问题，把它写成「通过」就是漏报。
    """
    return pending(f"未取得{subject}，无法判定：{why}。"
                   "缺少数据不等于没有风险，请人工确认后补测。",
                   probes=probes, evidence_kind=evidence_kind)


def artifact_coverage(ctx: DetectorContext, registry: Any = None) -> dict[str, Any]:
    """前端产物采集完整度 + 受影响检查项 —— 「覆盖度下降」的量化。

    为什么必须单列这一块
    ----------------------------------------------------------------------
    前端产物（HTML / JS bundle / 内联脚本）是**一大批检查项的唯一数据来源**：
    组件版本、源码泄露、凭据特征、接口面、参数名、postMessage、客户端存储……
    这些项在产物抓不到时会**照常跑完并报「通过」**—— 因为它们拿到的是一份
    空数据，而空数据上当然什么问题都没有。

    这正是本项目反复打击的那类失真：不是「审了没问题」，是**「没有材料可审」**。
    只给一个「充分度 45/100」还不够 —— 读者不知道该怀疑哪几项，等于没说。
    所以这里同时给出**受影响检查项清单**（按注册表声明 `requires=["js"]` 取，
    不手写清单，避免与注册表漂移）。

    三种情形必须分开，处置动作完全不同：
      · 页面未引用外部脚本（`scripts_found == 0`）→ 不算抓取失败。
        服务端渲染的站点本就如此，此时**不能报覆盖度下降**，否则每份报告都在报警。
      · 引用了 N 份、一份都没抓到（`fetched == 0`）→ **采集失败**。
        常见原因：出口被拦、需要登录、UA 被拒、产物走了独立 CDN。
      · 抓到 k 份（0 < k < N）→ 部分下降。未抓到的那几份里有什么，完全未知。
    """
    js = getattr(ctx, "js_result", None) or {}
    referenced = list(js.get("scripts_found") or [])
    bodies = list(js.get("bodies") or [])
    inline = list(js.get("inline_scripts") or [])
    urls = list(js.get("urls") or [])
    n_ref = len(referenced)
    n_fetched = int(js.get("scripts_fetched") or len(bodies))
    n_failed = max(0, n_ref - n_fetched)
    errors = list(js.get("errors") or [])

    affected: list[str] = []
    if registry is not None and getattr(registry, "specs", None):
        affected = sorted(i for i, s in registry.specs.items()
                          if "js" in (getattr(s, "requires", None) or []))

    notes: list[str] = []
    if n_ref and n_fetched == 0:
        loss = "full"
        label = "前端产物全部抓取失败"
        notes.append(
            f"页面引用了 {n_ref} 份外部脚本，**一份都没有取回**"
            + (f"（最近一次错误：{errors[-1][:120]}）" if errors else "")
            + f" —— 依赖前端产物的 {len(affected)} 个检查项本次**没有任何材料可判**。")
    elif n_ref and n_failed:
        loss = "partial"
        label = f"前端产物部分抓取失败（{n_failed}/{n_ref} 份未取回）"
        notes.append(
            f"页面引用的 {n_ref} 份外部脚本中有 {n_failed} 份未取回 —— "
            f"这些产物里可能存在的组件版本、硬编码凭据、接口地址、Source Map "
            f"本次**完全未知**；依赖前端产物的 {len(affected)} 个检查项的结论"
            f"应按「部分覆盖」理解。")
    elif n_ref == 0 and not inline and not urls:
        loss = "none"
        label = "页面未引用外部脚本，且无内联脚本与接口线索"
        notes.append(
            "本次未取得任何前端素材（页面既未引用外部脚本，也无内联脚本）——"
            f"依赖前端产物的 {len(affected)} 个检查项只能基于服务端响应判定，"
            "若目标实际是单页应用，这些项应按「未覆盖」理解。")
    else:
        loss = "none"
        label = "前端产物采集完整"

    # 产物抓到了，但一条接口地址都没提取出来：接口面未知。
    # 这不改 loss 档（可能确实是纯静态页面），但必须说出来 ——
    # 依赖接口地址的检测项（接口发现、参数提取、越权面）覆盖范围受限。
    if loss == "none" and (n_fetched or inline) and not urls:
        notes.append("前端素材已取得，但未从中提取到任何接口地址 —— "
                     "接口面未知，依赖接口地址的检测项覆盖范围受限。")

    return {
        "referenced": n_ref,
        "fetched": n_fetched,
        "failed": n_failed,
        "inline_scripts": len(inline),
        "endpoints_extracted": len(urls),
        "errors": errors[-3:],
        "loss": loss,
        "loss_label": label,
        "degraded": loss in ("full", "partial"),
        "affected_items": affected,
        "affected_count": len(affected),
        "notes": notes,
        "summary": label + (f"；受影响检查项 {len(affected)} 项" if notes else ""),
    }


def collection_report(ctx: DetectorContext,
                      registry: Any = None) -> dict[str, Any]:
    """采集充分度评分（0-100）。

    为什么必须有这个指标：
    本引擎把「找不到可测对象」判为 N/A 而不是「通过」—— 这挡住了
    「没测却报通过」。但如果采集本身不充分，N/A 会变成新的掩盖手段：
    「SPA 没渲染出来」被写成「目标没有该功能」。

    所以每次扫描都必须给出采集充分度；低于阈值时，
    报告中所有 N/A 结论都要标注为低置信、需人工复核。
    """
    body = ctx.baseline_body or ""
    urls = ctx.js_result.get("urls") or []
    bodies = ctx.js_result.get("bodies") or []
    inline = ctx.js_result.get("inline_scripts") or []
    forms = find_forms(ctx)
    n_scripts = len(bodies) + len(inline)

    items: list[dict[str, Any]] = []
    score = 0

    def add(cond: bool, points: int, label: str, detail: str) -> None:
        nonlocal score
        if cond:
            score += points
        items.append({"项": label, "得分": points if cond else 0,
                      "满分": points, "说明": detail})

    add(len(body) >= 200, 20, "根页面可取", f"正文 {len(body)} 字符")
    add(len(body) >= 2000, 10, "首页内容充实", f"正文 {len(body)} 字符")
    add(n_scripts >= 1, 15, "脚本产物可获取", f"{n_scripts} 份")
    add(n_scripts >= 3, 10, "脚本采集较全", f"{n_scripts} 份")
    add(len(urls) >= 1, 15, "接口地址可提取", f"{len(urls)} 条")
    add(len(urls) >= 5, 10, "接口面较完整", f"{len(urls)} 条")
    add(len(forms) >= 1, 10, "表单入口可识别", f"{len(forms)} 个")
    add(bool(ctx.root_headers), 10, "响应头可读",
        f"{len(ctx.root_headers or {})} 个响应头")

    # ---- 入口页渲染（SPA）----
    # 为什么单列一项而不是并进「根页面可取」：
    # 骨架页的正文常常超过 2000 字符（全是 <script> 与打包产物引用），
    # 按长度打分会给满分 —— 但那具骨架里没有一个链接、没有一个表单、
    # 没有一个业务关键词。长度在这里是**误导性指标**。
    _rend = (getattr(ctx, "fp_result", {}) or {}).get("render") or {}
    _re = _rend.get("entry") or {}
    _skeleton = bool(_re.get("skeleton_before"))
    if _re.get("ok"):
        add(bool(_re.get("refilled")), 10, "入口页已完成渲染",
            f"可见文本 {_re.get('text_before', 0)} → {_re.get('text_after', 0)} 字")
    else:
        add(False, 10, "入口页已完成渲染",
            f"未渲染（{_re.get('reason') or '渲染未执行'}）")

    # 骨架页 + 未渲染 = 结构性采集缺口。
    # 这种情况下的 N/A 不是「目标没有该功能」，而是「我们没看到页面」，
    # 必须把充分度压到「不足」，让报告里所有 N/A 都被标注为低置信。
    render_gap = _skeleton and not _re.get("ok")
    notes: list[str] = []
    if render_gap:
        notes.append("入口页是 JavaScript 骨架页且本次未成功渲染 —— "
                     "链接、表单、页面文案、接口地址四类采集全部受限，"
                     "本报告的 N/A 结论应读作「本次未看到」，不应读作「不存在」")

    level = "充分" if score >= 70 else ("一般" if score >= 40 else "不足")
    if render_gap:
        score = min(score, 39)
        level = "不足"

    # ---- 前端产物采集失败 → 覆盖度下降 ----
    # 这是与「骨架页未渲染」并列的第二种结构性缺口：页面能取、产物取不回。
    # 它比渲染失败更隐蔽 —— 根页面正文很长、响应头齐全、表单也有，
    # 充分度看起来还不低，但一大类检查项其实是**在空数据上跑完的**。
    art = artifact_coverage(ctx, registry)
    if art["loss"] == "full":
        score = min(score, 39)
        level = "不足"
    elif art["loss"] == "partial":
        score = min(score, 59)
        level = "不足" if level == "不足" else "一般"
    notes.extend(art["notes"])

    artwork_note = ""
    if art["loss"] in ("full", "partial"):
        artwork_note = ("；⚠ " + art["loss_label"])
    return {
        "score": score,
        "level": level,
        "items": items,
        "degraded": score < 70,
        "spa_render_gap": render_gap,
        "artifact": art,
        "artifact_loss": art["loss"],
        "artifact_affected_items": art["affected_items"],
        "notes": notes,
        "summary": (f"采集充分度 {score}/100（{level}）："
                    f"正文 {len(body)} 字符、脚本 {n_scripts} 份、"
                    f"接口 {len(urls)} 条、表单 {len(forms)} 个"
                    + ("；⚠ SPA 骨架页未渲染" if render_gap else "")
                    + artwork_note),
    }
