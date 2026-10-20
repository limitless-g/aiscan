# -*- coding: utf-8 -*-
"""nuclei 结果 → 检查项归口与回填
================================================================================

要解决的两个问题
--------------------------------------------------------------------------------

**问题一：归口太粗，WSTG 检查项永远收不到 nuclei 的结论。**

原来的归口只有 6 条分支（CVE / 接管 / 泄露 / TLS / 默认口令 / 其他），
于是绝大多数模板都落到同一个兜底项（服务器与中间件已知漏洞）。
一个 SQL 注入模板、一个 SSRF 模板、一个 Swagger 暴露模板，
在清单上被归成同一项 —— 那一项的结论因此既说不清是什么问题，
也让真正对应的检查项（WSTG-INPV-05 / INPV-19 / APIT-01）永远是「通过」。

**问题二：nuclei 的发现不回填检查项，报告会自相矛盾。**

检查项状态是**由该项自己的检测器**决定的：检测器没报问题 → 「通过」。
nuclei 的发现挂在同一个 item_id 上，却不参与状态判定。于是同一份报告里：

    第 2 章：`WSTG-CONF-04` 有一条 nuclei 实测命中，附请求 / 响应原文
    第 3 章：`WSTG-CONF-04` …… 通过

研发按第 3 章看，就会把一个真实的、已经拿到证据的问题关掉。
这不是「漏报」——漏报是没测出来；这是**同一份报告里两个栏目互相打脸**，
而读者只会信更干净的那个（「通过」）。

================================================================================
回填的三条硬约束
================================================================================

1. **方向只能是收紧。** 回填只可能把状态改成「不通过」，**永远不可能**把任何
   状态改成「通过」。这条是死规则：一旦回填能产出「通过」，它就变成了一条
   绕过检测的新路径，比不做回填更危险。

2. **覆盖旧状态必须说明。** 原状态写进 note。特别是原本判 N/A 的项
   —— N/A 断言的是「目标不具备该功能」，这与「实测命中」直接冲突，
   必须把冲突摆出来让人复核适用性，而不是静默改判。

3. **归口不确定要说出来。** 模板 tag 没登记、或 CVE 分不清受影响层时，
   归口结论标为「依据不足」，note 里写明需人工确认。
   猜一个归口比不归口更糟：它会把一条真实发现记到错误的检查项上，
   而正确的检查项仍然是「通过」。

未登记 tag 会被记进 `unmapped_tags()` 的统计，便于持续补表 ——
这是这套映射唯一的迭代入口。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ==============================================================================
# 归口结果
# ==============================================================================
@dataclass
class ItemMapping:
    """一个 nuclei 模板到检查项的归口结论。"""

    item_id: str
    basis: str                     # 人类可读的归口依据
    confident: bool = True         # False = 依据不足，需人工确认归口
    matched_tag: str = ""          # 命中的 tag（空 = 靠模板 ID 前缀判断）
    fallback: bool = False         # 走了兜底分支

    def to_dict(self) -> dict[str, Any]:
        return {"item_id": self.item_id, "basis": self.basis,
                "confident": self.confident, "matched_tag": self.matched_tag,
                "fallback": self.fallback}


# ==============================================================================
# 归口表：顺序敏感，先具体后笼统，第一条命中即返回
# ==============================================================================
# 每项：(tag 集合, 检查项 ID, 归口依据)
# tag 一律小写；nuclei 的 tag 本身大小写不统一，调用方负责归一化。
_RULES: tuple[tuple[frozenset, str, str], ...] = (
    # ---- 注入家族：一项一 tag，避免互相吞并 ----
    (frozenset({"sqli", "sql-injection", "sql"}), "WSTG-INPV-05", "SQL 注入"),
    (frozenset({"stored-xss", "persistent-xss", "stored"}), "WSTG-INPV-02", "存储型 XSS"),
    (frozenset({"dom-xss", "dom"}), "WSTG-CLNT-01", "基于 DOM 的 XSS"),
    (frozenset({"xss", "cross-site-scripting", "reflected-xss", "reflected"}),
     "WSTG-INPV-01", "反射型 XSS"),
    (frozenset({"ldap", "ldap-injection"}), "WSTG-INPV-06", "LDAP 注入"),
    (frozenset({"xxe", "xml-injection", "xml-external-entity"}), "WSTG-INPV-07", "XML 注入 / XXE"),
    (frozenset({"ssi", "ssi-injection"}), "WSTG-INPV-08", "SSI 注入"),
    (frozenset({"xpath", "xpath-injection"}), "WSTG-INPV-09", "XPath 注入"),
    (frozenset({"imap", "smtp-injection", "mail-injection"}), "WSTG-INPV-10", "IMAP / SMTP 注入"),
    (frozenset({"code-injection", "eval"}), "WSTG-INPV-11", "代码注入"),
    (frozenset({"rce", "command-injection", "cmdi", "command"}), "WSTG-INPV-12", "命令注入 / RCE"),
    (frozenset({"format-string"}), "WSTG-INPV-13", "格式字符串注入"),
    (frozenset({"crlf", "response-splitting", "header-injection", "http-splitting"}),
     "WSTG-INPV-15", "HTTP 响应拆分（CRLF 注入）"),
    (frozenset({"request-smuggling", "smuggling", "http-smuggling"}),
     "WSTG-INPV-16", "HTTP 请求走私"),
    (frozenset({"host-header", "host-header-injection", "vhost"}), "WSTG-INPV-17", "Host 头注入"),
    (frozenset({"ssti", "template-injection", "server-side-template"}), "WSTG-INPV-18", "SSTI"),
    (frozenset({"ssrf"}), "WSTG-INPV-19", "SSRF"),
    (frozenset({"mass-assignment"}), "WSTG-INPV-20", "批量赋值"),
    (frozenset({"csv-injection", "formula-injection"}), "WSTG-INPV-21", "CSV 注入"),
    (frozenset({"prototype-pollution"}), "WSTG-INPV-22", "原型污染"),
    (frozenset({"deserialization", "deserialize", "java-deserialization", "unsafe-deserialization"}),
     "WSTG-INPV-23", "不安全反序列化"),
    # 文件类：目录遍历 / 文件包含 / 任意文件读取 都在 ATHZ-01 之下
    (frozenset({"lfi", "rfi", "local-file-inclusion", "remote-file-inclusion",
                "file-inclusion", "path-traversal", "traversal",
                "arbitrary-file-read", "file-read", "lfd"}), "WSTG-ATHZ-01",
     "目录遍历与文件包含"),

    # ---- 认证 / 授权 / 会话 ----
    (frozenset({"default-login", "default-logins", "default-credentials",
                "default-password", "weak-login"}), "WSTG-ATHN-02", "默认凭据"),
    (frozenset({"auth-bypass", "authbypass", "authentication-bypass",
                "bypass-auth", "unauth-bypass"}), "WSTG-ATHN-04", "绕过认证方案"),
    (frozenset({"jwt", "json-web-token"}), "WSTG-SESS-10", "JWT 弱点"),
    (frozenset({"oauth", "oidc"}), "WSTG-ATHZ-05", "OAuth 弱点"),
    (frozenset({"csrf"}), "WSTG-SESS-05", "CSRF"),
    (frozenset({"session-fixation"}), "WSTG-SESS-03", "会话固定"),
    (frozenset({"idor", "insecure-direct-object"}), "WSTG-ATHZ-04", "IDOR"),
    (frozenset({"bola"}), "WSTG-APIT-02", "API 对象级授权缺陷（BOLA）"),
    (frozenset({"bfla"}), "WSTG-APIT-04", "API 功能级授权缺陷（BFLA）"),
    (frozenset({"unauthorized", "unauth", "authz-bypass", "privilege-escalation",
                "privesc"}), "WSTG-ATHZ-02", "绕过授权方案 / 权限提升"),
    (frozenset({"account-enumeration", "user-enumeration"}), "WSTG-IDNT-04", "账号枚举"),
    (frozenset({"mfa", "2fa", "otp"}), "WSTG-ATHN-11", "多因素认证"),

    # ---- 客户端 ----
    (frozenset({"cors", "cross-origin"}), "WSTG-CLNT-07", "跨域资源共享（CORS）"),
    (frozenset({"open-redirect", "redirect"}), "WSTG-CLNT-04", "客户端 URL 重定向"),
    (frozenset({"clickjacking", "iframe"}), "WSTG-CLNT-09", "点击劫持"),
    (frozenset({"websocket", "ws"}), "WSTG-CLNT-10", "WebSocket"),
    (frozenset({"postmessage", "web-messaging"}), "WSTG-CLNT-11", "Web 消息（postMessage）"),
    (frozenset({"html-injection"}), "WSTG-CLNT-03", "HTML 注入"),
    (frozenset({"css-injection"}), "WSTG-CLNT-05", "CSS 注入"),
    (frozenset({"xssi", "cross-site-script-inclusion"}), "WSTG-CLNT-13", "XSSI"),

    # ---- 配置 / 暴露面 ----
    (frozenset({"hsts"}), "WSTG-CONF-07", "HSTS"),
    (frozenset({"csp", "content-security-policy"}), "WSTG-CONF-12", "内容安全策略（CSP）"),
    (frozenset({"headers", "security-headers", "http-headers"}), "WSTG-CONF-14",
     "HTTP 安全头配置错误"),
    (frozenset({"takeover", "takeovers", "subdomain-takeover"}), "WSTG-CONF-10", "子域接管"),
    (frozenset({"git", "svn", "hg", "mercurial", "gitlab-exposure"}),
     "EXT-CD-03", "版本控制与配置泄露"),
    (frozenset({"jenkins", "teamcity", "bamboo", "nexus", "artifactory", "harbor",
                "sonarqube", "sonar", "minio"}), "EXT-CD-02", "构建产物与制品仓库暴露"),
    (frozenset({"pipeline", "ci", "cd", "devops"}), "EXT-CD-01", "流水线配置文件泄露"),
    (frozenset({"metadata", "imds", "169-254"}), "EXT-CL-01", "云主机元数据服务可达性"),
    (frozenset({"s3", "oss", "bucket", "blob", "object-storage"}),
     "EXT-CL-08", "对象存储签名与目录遍历"),
    (frozenset({"kubernetes", "k8s", "kubelet", "etcd", "helm"}),
     "EXT-CL-04", "K8s API Server 暴露"),
    (frozenset({"docker", "docker-api", "container", "containerd", "podman"}),
     "EXT-CL-03", "容器 API 与管理端口暴露"),
    (frozenset({"aws", "azure", "gcp", "aliyun", "tencent", "huawei", "cloud",
                "cloud-credential", "aksk"}), "EXT-CL-06", "云凭据泄露"),
    (frozenset({"prometheus", "grafana", "kibana", "zabbix", "nagios", "cacti",
                "jupyter", "hadoop", "spark", "flink", "elasticsearch", "rabbitmq",
                "zookeeper", "consul", "nacos", "eureka"}), "EXT-CL-02",
     "安全组与非预期端口暴露（管理/中间件端口对外）"),
    (frozenset({"actuator", "springboot", "spring-boot", "env", "heapdump",
                "jolokia", "swagger", "openapi", "api-docs", "adminer",
                "phpmyadmin", "panel", "panels", "admin", "console", "debug",
                "debug-page", "dashboard", "phpinfo"}), "WSTG-CONF-05",
     "基础设施与应用管理接口枚举"),
    (frozenset({"graphql"}), "WSTG-APIT-99", "GraphQL 测试"),
    (frozenset({"api", "rest", "apikey"}), "WSTG-APIT-01", "API 侦察"),
    (frozenset({"backup", "bak", "old-files", "unreferenced", "dump"}),
     "WSTG-CONF-04", "旧备份与未引用文件审查"),
    (frozenset({"sourcemap", "source-map", "source-disclosure", "js-source"}),
     "EXT-SC-06", "打包产物泄露源码与依赖树"),
    (frozenset({"credential", "credentials", "apikey-leak", "token-leak",
                "secret", "secrets"}), "EXT-SC-07", "第三方集成凭据泄露"),
    (frozenset({"misconfig", "misconfiguration", "config", "exposure",
                "exposures", "disclosure", "leak", "exposed"}), "WSTG-CONF-02",
     "应用平台配置 / 敏感信息暴露"),
    (frozenset({"stacktrace", "stack-trace", "error-page", "verbose-error"}),
     "WSTG-ERRH-02", "堆栈跟踪泄露"),
    (frozenset({"log", "logs", "log-file", "debug-log"}), "EXT-DP-02",
     "日志与调试接口泄露 PII"),
    (frozenset({"file-upload", "upload", "unrestricted-upload",
                "arbitrary-file-upload"}), "WSTG-BUSL-09", "恶意文件上传"),
    (frozenset({"ratelimit", "rate-limit", "bruteforce", "brute-force"}),
     "EXT-RB-01", "接口速率限制缺失"),
    (frozenset({"dos", "resource-exhaustion", "redos", "zipper"}),
     "EXT-RB-02", "资源耗尽面（静态评估）"),
    (frozenset({"kev", "exploited-in-wild", "actively-exploited"}),
     "EXT-SC-08", "已知被利用漏洞优先核对"),
    (frozenset({"ssl", "tls", "cert", "certificate", "weak-cipher",
                "weak-ssl", "tlscipher", "self-signed"}), "WSTG-CRYP-01",
     "弱传输层安全"),
    (frozenset({"crypto", "weak-crypto", "cipher"}), "WSTG-CRYP-04", "弱加密原语"),
    (frozenset({"dns", "spf"}), "EXT-DM-01", "SPF 记录配置"),
    (frozenset({"dkim"}), "EXT-DM-02", "DKIM 配置"),
    (frozenset({"dmarc"}), "EXT-DM-03", "DMARC 策略"),
    (frozenset({"mx", "mail", "smtp", "imap-port", "pop3", "starttls"}),
     "EXT-DM-05", "邮件服务端口暴露实测"),
    (frozenset({"ftp", "sftp", "ssh", "telnet", "rdp", "vnc", "smb", "nfs",
                "rsync", "ldap-port", "redis", "mongodb", "mssql", "mysql",
                "postgres", "postgresql", "memcached", "couchdb", "neo4j",
                "cassandra", "influxdb", "open-port", "network"}), "EXT-CL-02",
     "安全组与非预期端口暴露"),
    (frozenset({"llm", "ai", "openai", "ollama", "langchain", "chatgpt"}),
     "EXT-AI-01", "LLM 端点未授权访问"),
    (frozenset({"prompt-injection"}), "EXT-AI-02", "提示词注入（直接）"),
    (frozenset({"system-prompt", "prompt-leak"}), "EXT-AI-04", "系统提示词与上下文泄露"),
)

# 产品 tag → 已知漏洞归口。CVE 模板必须靠这层区分「受影响的是哪一层」，
# 否则所有 CVE 都会挤到同一项里，报告上完全看不出到底谁有漏洞。
_PRODUCT_GROUP: dict[str, str] = {}
for _tags, _item in (
    # 前端 / JS 生态
    (("jquery", "bootstrap", "angular", "angularjs", "react", "vue", "vuejs",
      "node", "nodejs", "npm", "express", "nextjs", "nuxt", "webpack",
      "momentjs", "lodash", "axios", "dompurify", "handlebars", "knockout"), "EXT-SC-01"),
    # 后端框架 / CMS
    (("spring", "springboot", "spring-boot", "spring-cloud", "struts", "struts2",
      "shiro", "fastjson", "log4j", "log4j2", "jackson", "xstream", "weblogic",
      "jboss", "wildfly", "django", "flask", "rails", "ruby-on-rails", "laravel",
      "symfony", "cakephp", "yii", "thinkphp", "codeigniter", "wordpress",
      "joomla", "drupal", "magento", "typo3", "prestashop", "confluence",
      "jira", "bitbucket", "vbulletin", "phpbb", "discuz", "shopware"), "EXT-SC-02"),
    # 服务器 / 中间件 / 数据库 / 运行环境
    (("apache", "httpd", "nginx", "iis", "tomcat", "jetty", "undertow",
      "lighttpd", "caddy", "openssl", "php", "aspnet", "asp-net", "exchange",
      "sharepoint", "citrix", "fortinet", "fortigate", "pulse", "vmware",
      "vcenter", "esxi", "coldfusion", "oracle", "mssql", "mysql", "postgres",
      "postgresql", "mongodb", "redis", "memcached", "clickhouse", "couchdb",
      "elasticsearch", "kafka", "zookeeper", "activemq", "rabbitmq",
      "solarwinds", "printer", "router", "firewall", "vpn", "citrix-adc"), "EXT-SC-03"),
):
    for _t in _tags:
        _PRODUCT_GROUP[_t] = _item

# 兜底归口：模板 tag 全未登记时使用
FALLBACK_ITEM = "EXT-SC-03"
FALLBACK_BASIS = ("模板 tag 未登记于归口表，暂归入「服务器与中间件已知漏洞」"
                  "（依据不足，请人工确认归口）")

# 一份「这是漏洞类模板」的最小判据：nuclei 里还有大量纯识别模板
# （tech-detect / waf-detect / dns-* / ssl-*），它们命中的是「目标用了什么」，
# 不是「目标有什么问题」。把它们当发现回填，会让检查项无端变成「不通过」
# —— 那是与漏报相反的另一种失真，而且会迅速把报告的可信度烧光
# （研发看到一堆「不通过」去查，发现全是识别信息，从此整份报告都不信）。
_NON_VULN_TAGS = frozenset({
    "tech", "tech-detect", "technologies", "waf", "waf-detect", "detect",
    "info", "informational", "discovery", "enumeration", "dns-record",
    "ssl-detect", "certificate", "cname", "favicon", "whois",
    "geolocation", "osint", "cdn", "cloud-detect", "fingerprint",
    "http-methods", "options", "robots", "security-headers",
})
# 严重度只到 info / unknown 且没有任何漏洞类 tag 时，一律不回填。
# nuclei 的 info 级结果绝大多数是「识别到了什么」，不是「发现了问题」。
NON_VULN_SEVERITIES = frozenset({"info", "unknown"})

_CVE_RE = re.compile(r"^cve-\d{4}-\d{4,}", re.I)


def _tags_of(info: dict[str, Any]) -> list[str]:
    raw = (info or {}).get("tags") or []
    if isinstance(raw, str):
        raw = re.split(r"[,\s]+", raw)
    out: list[str] = []
    for t in raw:
        t = str(t or "").strip().lower()
        if t and t not in out:
            out.append(t)
    return out


def unknown_tags() -> frozenset:
    """归口表里出现过的全部 tag（供自测核对，避免表项拼写错误）。"""
    s: set[str] = set()
    for tags, _, _ in _RULES:
        s |= set(tags)
    return frozenset(s)


# 「漏洞类 tag」的集合：归口表里登记过的一切 tag。
# 它同时是「这个模板是不是在说一个漏洞」的判据（见 is_vulnerability_template）。
# 放在函数定义之后赋值 —— 归口表就在上面，这里是它的派生量，
# 不做成手写清单，是为了避免「归口表加了一项、判据忘了加」的漂移。
_VULN_CLASS_TAGS = unknown_tags()


def mapping_stats() -> dict[str, int]:
    """归口表规模统计（写进报告用，便于判断归口是否退化）。"""
    items = {item for _, item, _ in _RULES}
    return {"规则数": len(_RULES), "覆盖 tag 数": len(unknown_tags()),
            "覆盖检查项数": len(items), "产品 tag 数": len(_PRODUCT_GROUP)}


def map_template(template_id: str, info: dict[str, Any]) -> ItemMapping:
    """把一个 nuclei 模板归口到检查项。

    顺序：产品/技术栈 tag 最具体 →
          是 CVE 但分不清受影响层 → 兜底（标记依据不足）
          普通 tag 表 → 兜底（标记依据不足）
    """
    tid = str(template_id or "").strip()
    tags = _tags_of(info)
    tagset = set(tags)

    # ① CVE 类：先按产品 tag 定「哪一层」，定不出来才算依据不足
    if "cve" in tagset or "cves" in tagset or _CVE_RE.match(tid):
        for t in tags:
            if t in _PRODUCT_GROUP:
                return ItemMapping(_PRODUCT_GROUP[t],
                                   f"CVE 模板 + 产品 tag「{t}」→ "
                                   f"{_PRODUCT_GROUP[t]}", matched_tag=t)
        return ItemMapping(FALLBACK_ITEM,
                           "CVE 模板但无法从 tag 判断受影响层（前端/后端/中间件）—— "
                           "归口依据不足，请人工确认",
                           confident=False, fallback=True)
    if "kev" in tagset:
        return ItemMapping("EXT-SC-08", "已列入已知被利用漏洞（KEV）",
                           matched_tag="kev")

    # ② 普通 tag 表：先具体后笼统
    for rule_tags, item, basis in _RULES:
        hit = tagset & rule_tags
        if hit:
            tag = sorted(hit)[0]
            return ItemMapping(item, f"tag「{tag}」→ {basis}", matched_tag=tag)

    # ③ 产品 tag（非 CVE，如某组件的配置缺陷）
    for t in tags:
        if t in _PRODUCT_GROUP:
            return ItemMapping(_PRODUCT_GROUP[t],
                               f"产品 tag「{t}」→ {_PRODUCT_GROUP[t]}", matched_tag=t)

    return ItemMapping(FALLBACK_ITEM, FALLBACK_BASIS,
                       confident=False, fallback=True)


def is_vulnerability_template(info: dict[str, Any], severity: str = "") -> tuple[bool, str]:
    """判断这个模板的命中是否代表「一个漏洞」。返回 (是, 理由)。

    判据只有两条，按强度从高到低：

      ① 模板带**明确的漏洞类 tag**（归口表里登记过的那些）、或带 cve / kev
         → 是漏洞。这类 tag 是模板作者自己写的语义，比严重度可靠。
      ② 否则看**严重度**：高于 info / unknown → 采信模板作者的定级，是漏洞。

    两者都不满足（严重度 info、tag 全是识别类）→ 不回填。
    典型被拦下的是 tech-detect / waf-detect / dns-* ——
    它们能回答「目标装了什么」，回答不了「目标有什么问题」。
    """
    tags = set(_tags_of(info))
    sev = str(severity or "").strip().lower()

    if tags & _VULN_CLASS_TAGS or tags & {"cve", "cves", "kev"}:
        return True, ""
    if sev not in NON_VULN_SEVERITIES:
        return True, ""

    shown = ", ".join(sorted(tags)) or "（无 tag）"
    return False, (f"严重度 {sev or '未标注'} 且无漏洞类 tag（识别类结果：{shown}）"
                   "—— 命中「目标用了什么」不等于「目标有问题」")


# ==============================================================================
# 回填
# ==============================================================================
@dataclass
class BackfillReport:
    """回填结果的完整留痕。报告与自测都用它。"""

    source: str = "nuclei"
    attached: int = 0                     # 新挂上的**发现条数**（一个检查项可有多条）
    items_touched: int = 0                # 被挂上发现的**检查项数**（去重后）
    state_changed: dict[str, int] = field(default_factory=dict)   # 旧状态 → 条数
    already: int = 0                      # 同一发现对象被重复传入，去重跳过
    skipped_non_vuln: int = 0             # 识别类结果，不回填
    unmapped: list[str] = field(default_factory=list)   # 找不到对应检查项的发现
    non_vuln_reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.attached and not self.unmapped and not self.skipped_non_vuln:
            return f"{self.source} 结果回填：无需回填（本次无发现或全部已归口）"
        parts = [f"{self.source} 结果回填：{self.attached} 条实测发现挂到 "
                 f"{self.items_touched} 个检查项上"]
        if self.state_changed:
            det = "、".join(f"{k}→不通过 {v} 条"
                            for k, v in sorted(self.state_changed.items()))
            parts.append(f"状态收紧：{det}")
        if self.already:
            parts.append(f"重复传入去重 {self.already} 条")
        if self.skipped_non_vuln:
            parts.append(f"识别类结果未回填 {self.skipped_non_vuln} 条"
                         "（命中「目标用了什么」不等于「目标有问题」）")
        if self.unmapped:
            parts.append(f"⚠ {len(self.unmapped)} 条找不到对应检查项，"
                         "未计入任何结论（见回填报告明细）")
        return "；".join(parts)


def backfill_external_findings(item_results: list[Any], findings: list[Any],
                               source: str = "nuclei") -> BackfillReport:
    """把外部引擎的发现回填到检查项结论上。

    三条约束见模块文档：方向只能收紧、覆盖旧状态必须说明、归口不确定要说出来。

    参数
        item_results  ItemResult 列表（会被就地修改）
        findings      Finding 列表，只处理 source_tool == source 的条目
    返回
        BackfillReport
    """
    from engine.registry import STATE_FIND, STATE_NA, STATE_PASS

    rep = BackfillReport(source=source)
    index: dict[str, Any] = {}
    for r in item_results:
        index.setdefault(getattr(r, "item_id", ""), r)
    touched: set[str] = set()

    for f in findings or []:
        if str(getattr(f, "source_tool", "") or "") != source:
            continue
        extra = getattr(f, "extra", None) or {}
        info = {"tags": extra.get("tags") or []}
        # 识别类结果不回填：命中「目标用了什么」不等于「目标有问题」
        sev = str(getattr(f, "severity", "") or "")
        ok, why = is_vulnerability_template(info, sev)
        if not ok:
            rep.skipped_non_vuln += 1
            if why not in rep.non_vuln_reasons:
                rep.non_vuln_reasons.append(why)
            continue

        item_id = str(getattr(f, "item_id", "") or "")
        base = index.get(item_id)
        if base is None:
            rep.unmapped.append(f"{item_id}｜{getattr(f, 'title', '')}"
                                f"（{extra.get('template_id', '')}）")
            continue

        if any(id(x) == id(f) for x in (getattr(base, "findings", None) or [])):
            rep.already += 1
            continue

        prev = str(getattr(base, "state", "") or "")
        # 方向只能是收紧：这里只可能变成「不通过」，永远不可能变成「通过」。
        if prev == STATE_PASS:
            base.state = STATE_FIND
            note = (f"⚠ 该检查项原有检测器未报问题，但 {source} 实测命中；"
                    "按「有实测发现即为不通过」回填（原状态：通过）。")
        elif prev == STATE_NA:
            base.state = STATE_FIND
            note = (f"⚠ 该检查项原判「N/A」（目标不具备该功能），"
                    f"但 {source} 实测命中 —— **适用性判定与实测结果冲突**，"
                    "请人工复核适用性结论（原状态：N/A）。")
        elif prev == STATE_FIND:
            note = f"{source} 另有一处实测命中，已并入本项。"
        else:
            base.state = STATE_FIND
            note = (f"⚠ 该检查项原本是「{prev}」（本项自动化未得出结论），"
                    f"但 {source} 实测命中 —— 有实测证据即按不通过记录，"
                    f"且本项自动化部分仍属「{prev}」，两者不互相抵消。")
        rep.state_changed[prev] = rep.state_changed.get(prev, 0) + 1

        base.findings = list(getattr(base, "findings", None) or []) + [f]
        base.finding_titles = list(getattr(base, "finding_titles", None) or []) \
            + [getattr(f, "title", "")]
        base.finding_ids = list(getattr(base, "finding_ids", None) or []) + [item_id]
        base.note = ((getattr(base, "note", "") or "") + "\n\n" + note).strip()
        rep.attached += 1
        if item_id not in touched:
            touched.add(item_id)
            rep.items_touched += 1

    if rep.unmapped:
        rep.notes.append(
            f"以下 {len(rep.unmapped)} 条 {source} 发现找不到对应检查项，"
            "未计入任何检查项结论 —— 需补归口表，否则这些发现在清单上无处体现：")
        rep.notes.extend(f"  · {x}" for x in rep.unmapped[:20])
    if rep.skipped_non_vuln:
        rep.notes.append(
            f"{rep.skipped_non_vuln} 条 {source} 命中被判定为「识别类结果」未回填："
            + "；".join(rep.non_vuln_reasons[:3]))
    return rep


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> None:
    ok = 0

    # 1) 归口表本身必须健全：item_id 都形如 XXX-YY-ZZ，basis 非空
    bad = []
    for tags, item, basis in _RULES:
        if not re.match(r"^[A-Z]+-[A-Z]+-[0-9A-Z]+$", item):
            bad.append(f"{item}（tag {sorted(tags)[:2]}）")
        if not basis.strip():
            bad.append(f"{item} 缺归口依据")
    assert not bad, f"归口表存在非法项：{bad}"
    ok += 1

    # 2) 一个 tag 只能属于一条规则 —— 否则命中顺序决定归口，行为不可预测
    seen: dict[str, str] = {}
    dup = []
    for tags, item, _ in _RULES:
        for t in tags:
            if t in seen:
                dup.append(f"{t}: {seen[t]} vs {item}")
            seen[t] = item
    assert not dup, f"归口表存在重复 tag（顺序敏感，行为不可预测）：{dup}"
    ok += 1

    # 3) 注入家族必须一项一 tag —— 早期「xss 一锅端」把存储型/反射型/DOM 型
    #    全归到反射型，报告上三处全是同一个检查项
    assert map_template("x", {"tags": ["sqli"]}).item_id == "WSTG-INPV-05"
    assert map_template("x", {"tags": ["ssrf"]}).item_id == "WSTG-INPV-19"
    assert map_template("x", {"tags": ["xss"]}).item_id == "WSTG-INPV-01"
    assert map_template("x", {"tags": ["stored-xss"]}).item_id == "WSTG-INPV-02"
    assert map_template("x", {"tags": ["dom-xss"]}).item_id == "WSTG-CLNT-01"
    assert map_template("x", {"tags": ["lfi"]}).item_id == "WSTG-ATHZ-01"
    assert map_template("x", {"tags": ["rce"]}).item_id == "WSTG-INPV-12"
    assert map_template("x", {"tags": ["ssti"]}).item_id == "WSTG-INPV-18"
    assert map_template("x", {"tags": ["swagger"]}).item_id == "WSTG-CONF-05"
    assert map_template("x", {"tags": ["git"]}).item_id == "EXT-CD-03"
    ok += 1
    # 关键回归：归口必须落到**不同的**检查项，否则回填会把多个问题挤成一项
    ids = {map_template("x", {"tags": [t]}).item_id
           for t in ("sqli", "ssrf", "xss", "rce", "lfi", "ssti")}
    assert len(ids) == 6, f"注入类归口未能区分开：{ids}"
    ok += 1

    # 4) CVE：按产品 tag 分层，分不清才算依据不足
    m = map_template("CVE-2021-44228", {"tags": ["cve", "log4j", "rce"]})
    assert m.item_id == "EXT-SC-02" and m.confident, f"log4j 应归后端框架：{m}"
    m = map_template("CVE-2023-44487", {"tags": ["cve", "nginx"]})
    assert m.item_id == "EXT-SC-03" and m.confident, f"nginx 应归服务器中间件：{m}"
    m = map_template("CVE-2024-0001", {"tags": ["cve"]})
    assert not m.confident, "分不清受影响层的 CVE 必须标记依据不足，不得静默猜一个"
    assert m.item_id == FALLBACK_ITEM
    ok += 1

    # 5) 未登记 tag → 兜底且标记依据不足（不得伪装成确定结论）
    m = map_template("some-template", {"tags": ["completely-unknown-tag"]})
    assert m.item_id == FALLBACK_ITEM and not m.confident and m.fallback
    ok += 1

    # 6) 识别类结果不得回填 —— 否则检查项会无端变成「不通过」
    yes, _ = is_vulnerability_template({"tags": ["tech-detect", "nginx"]}, "info")
    assert yes is False, "tech-detect 命中不是漏洞"
    yes, _ = is_vulnerability_template({"tags": ["waf-detect"]}, "info")
    assert yes is False, "waf-detect 命中不是漏洞"
    yes, _ = is_vulnerability_template({"tags": ["sqli"]}, "high")
    assert yes is True, "sqli 命中必须回填"
    yes, _ = is_vulnerability_template({"tags": ["exposure"]}, "medium")
    assert yes is True, "medium 级泄露必须回填"
    ok += 1

    # 7) 回填方向只能是收紧
    from engine.registry import (STATE_FIND, STATE_MANUAL, STATE_NA,
                                 STATE_NOTRUN, STATE_PASS, ItemResult)

    def _it(item_id, state):
        return ItemResult(item_id=item_id, name=item_id, category="WSTG",
                          category_name="WSTG", state=state, mode="自动")

    class _F:
        def __init__(self, item_id, sev="高危", tool="nuclei", tags=("sqli",)):
            self.item_id = item_id
            self.title = f"{item_id} 命中"
            self.severity = sev
            self.source_tool = tool
            self.extra = {"template_id": "t", "tags": list(tags)}

    results = [
        _it("WSTG-INPV-05", STATE_PASS),      # 通过 → 必须收紧
        _it("WSTG-CONF-02", STATE_NA),        # N/A → 必须标出适用性冲突
        _it("WSTG-CONF-05", STATE_NOTRUN),    # 未执行 → 有实测证据即不通过
        _it("WSTG-ATHN-02", STATE_MANUAL),    # 待人工 → 同上
    ]
    # 注意：故意**不**给 WSTG-CRLF-99 建检查项 —— 用它验证
    # 「归口到的检查项不在清单里」必须被报出来，而不是静默丢掉。
    finds = [
        _F("WSTG-INPV-05"), _F("WSTG-INPV-05"),        # 同一检查项的两条不同发现
        _F("WSTG-CONF-02", tags=("misconfig",)),
        _F("WSTG-CONF-05", tags=("actuator",)),
        _F("WSTG-ATHN-02", tags=("default-login",)),
        _F("WSTG-CRLF-99", tags=("nodis",)),
        _F("WSTG-INPV-05", sev="info", tags=("sqli", "tech-detect")),  # 有漏洞类 tag
        _F("WSTG-CONF-02", sev="info", tags=("tech-detect", "nginx")),  # 识别类，跳过
    ]
    rep = backfill_external_findings(results, finds)
    assert results[0].state == STATE_FIND, "通过项必须被收紧为不通过"
    assert results[1].state == STATE_FIND and "适用性" in results[1].note, \
        "N/A 项必须改判并把适用性冲突写进说明"
    assert "原状态：通过" in results[0].note, "覆盖旧状态必须留痕"
    assert rep.attached == 6, f"应挂上 6 条发现，实际 {rep.attached}"
    assert rep.items_touched == 4, f"应涉及 4 个检查项，实际 {rep.items_touched}"
    assert len(results[0].findings) == 3, \
        f"同一检查项的多条发现必须全部保留（实际 {len(results[0].findings)}）"
    assert rep.already == 0, "不同发现对象不该被去重"
    assert rep.skipped_non_vuln == 1, f"识别类结果应跳过，实际 {rep.skipped_non_vuln}"
    assert len(rep.unmapped) == 1, "找不到归口的发现必须报出来，不得静默丢弃"
    assert "找不到对应检查项" in "".join(rep.notes)
    ok += 1

    # 7b) 同一个发现对象被传入两次（merge 环节可能造成），必须去重
    rr = [_it("WSTG-INPV-05", STATE_PASS)]
    _once = _F("WSTG-INPV-05")
    rep2 = backfill_external_findings(rr, [_once, _once])
    assert rep2.attached == 1 and rep2.already == 1, \
        f"同一对象重复传入应去重，实际 attached={rep2.attached} already={rep2.already}"
    assert len(rr[0].findings) == 1
    ok += 1

    # 8) 绝不能把任何状态改成「通过」—— 一旦能，回填就成了绕过检测的新路径，
    #    比不做回填更危险。逐状态验证：有发现时一律收紧为「不通过」。
    for st in (STATE_PASS, STATE_NA, STATE_NOTRUN, STATE_MANUAL, STATE_FIND):
        rr = [_it("WSTG-INPV-05", st)]
        backfill_external_findings(rr, [_F("WSTG-INPV-05")])
        assert rr[0].state == STATE_FIND, \
            f"有实测发现时状态应为「不通过」（原状态 {st}），实际 {rr[0].state}"
    # 无发现时回填必须完全不动状态（尤其不能把「通过」变成别的，也不能把
    # 「未执行」悄悄变成「通过」）
    rr = [_it("WSTG-INPV-05", STATE_MANUAL), _it("WSTG-CONF-02", STATE_NA),
          _it("WSTG-CONF-05", STATE_NOTRUN), _it("WSTG-ATHN-02", STATE_PASS)]
    backfill_external_findings(rr, [])
    assert [x.state for x in rr] == [STATE_MANUAL, STATE_NA,
                                     STATE_NOTRUN, STATE_PASS], \
        "没有任何发现时回填必须完全不动状态"
    ok += 1

    # 9) 只处理指定来源：别的来源的发现不得被 nuclei 回填吞掉
    rr = [_it("WSTG-INPV-05", STATE_PASS)]
    backfill_external_findings(rr, [_F("WSTG-INPV-05", tool="builtin")])
    assert rr[0].state == STATE_PASS, "非本来源的发现不得被回填处理"
    ok += 1

    print(f"nuclei 归口与回填自测：{ok} 组断言通过；"
          f"归口表覆盖 {mapping_stats()['覆盖 tag 数']} 个 tag、"
          f"{mapping_stats()['覆盖检查项数']} 个检查项")


if __name__ == "__main__":  # pragma: no cover
    import sys
    from pathlib import Path

    _ROOT = Path(__file__).resolve().parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    print("nuclei 归口与回填自测")
    print("=" * 70)
    _selftest()
