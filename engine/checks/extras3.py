# -*- coding: utf-8 -*-
"""
场景扩展检查 第三批：域名与邮件（EXT-DM 6 项）
==============================================
这一批解决的是「网站本身没问题，但公司域名能被拿去发钓鱼邮件」的问题。

SPF / DKIM / DMARC 三项是邮件安全的底座：缺了它们，
任何人用你的域名给客户发邮件，收件方的邮件网关都不会拦 ——
这在实际事件里比网站漏洞更常见，危害也更直接（直接骗客户打款）。

全部走公共递归 DNS 查询，不依赖本机解析，符合「以公网环境为基线」的要求。
"""

from __future__ import annotations

import json
import re

from engine.checks import net
from engine.checks.base import (  # noqa: I001
    finding_evidence,
    found,
    na,
    ok,
    pending,
    reachability_scope,
)
from engine.registry import RISK_SAFE, DetectorContext, make_auto, make_finding

try:  # 子域接管指纹复用自身已定义的一套，避免两处维护
    from engine.checks.config import TAKEOVER_FINGERPRINTS
except Exception:  # noqa: BLE001
    TAKEOVER_FINGERPRINTS = {}

def _no_domain(ctx: DetectorContext, item_name: str,
               evidence_kind: str = "DNS 记录实测"):
    """「域名与邮件」类检查的适用性前置判断；目标没有域名时返回 N/A 结论。

    ⚠️ 为什么必须有这道判断：对**裸 IP 目标**（内网系统最常见的形态），
    DNS 查询必然返回空。不做判断的后果是空结果被读成
    「该域名未配置 SPF / DMARC」，产出**从公网位置根本无法复现**的误报 ——
    IP 地址不存在 SPF / DKIM / DMARC 这类概念，报告却写着
    `nslookup -type=TXT 10.x.x.x`，运维照着敲只会一脸茫然。

    更隐蔽的一半是反方向：EXT-DM-04 会把「查不到 MX」读成
    「该域名不接收邮件，符合预期」从而判**通过** —— 一个没有任何执行意义的通过。

    返回 None 表示适用，可以继续执行。
    """
    if net.as_ip_literal(ctx.domain):
        return na(
            f"目标 {ctx.domain} 是 IP 地址，没有域名 —— {item_name} "
            f"属于「域名与邮件」类检查，在语义上不适用",
            evidence_kind=evidence_kind)
    return None


# 常见 DKIM selector。覆盖面直接决定这一项的假阴性率：selector 是发信方
# 自己起的名字，猜不到就只能报「未发现」（假阴性）。所以这里按服务商把
# **默认 selector** 尽量收全：Google Workspace / M365 / 腾讯企邮 / 阿里云邮 /
# 网易 / 新浪 / 搜狐 / Amazon SES / SendGrid / Mailgun / Mailjet /
# Postmark / SparkPost / Zoho / HubSpot 等。
DKIM_SELECTORS = [
    # 通用 / 自建
    "default", "dkim", "mail", "smtp", "mta", "email", "key", "keys",
    "dkim1", "dkim2", "s1", "s2", "s3", "k1", "k2", "k3", "mx", "host",
    "domainkey", "mailer", "mailout", "send", "sender", "sig", "sign", "corp",
    # Google Workspace / Gmail
    "google", "goog", "gmail",
    # Microsoft 365 / Exchange / Outlook
    "selector1", "selector2", "selector3", "s1024", "s2048", "ms",
    "microsoft", "exchange", "outlook", "office365",
    # 腾讯企邮 / QQ 邮箱
    "tencent", "qq", "exmail", "qqmail", "tencentmail",
    # 阿里云邮 / 阿里云邮件推送
    "aliyun", "alimail", "dm", "directmail", "qcloud", "aliyunmail",
    # 网易 / 新浪 / 搜狐
    "netease", "163", "126", "sina", "sohu", "yeah",
    # Amazon SES / SendGrid / Mailgun / Mailjet / Postmark / SparkPost
    "amazonses", "ses", "sendgrid", "smtpapi", "mailgun", "mg", "mailjet",
    "postmark", "pm", "sparkpost", "scph", "mandrill", "mandrillapp",
    # Zoho / HubSpot / 其他 SaaS 发信
    "zoho", "zmail", "hubspot", "hs1", "hs2", "salesforce", "marketo",
    "mailchimp", "cm", "klaviyo", "intercom", "freshdesk", "sendlane",
    "mailerlite", "activecampaign", "constantcontact",
    # 常见日期型 / 运维随手起的 selector
    "20230601", "20240101", "20250101", "20260101",
]

# 域名停放 / 待售页特征（域名被抢注或托管商挂起的典型信号）
PARKING_MARKERS = [
    "this domain is for sale", "buy this domain", "domain for sale",
    "域名出售", "此域名出售", "该域名正在出售", "域名停放", "domain parking",
    "sedoparking", "parkingcrew", "bodis.com", "afternic",
    "the domain name is registered", "网站建设中",
]

# 高价值子域前缀（出现在 CT 日志里 = 攻击面暴露）
HIGH_VALUE_PREFIXES = [
    "jenkins", "gitlab", "git", "gitea", "gogs", "ci", "cd", "sonar",
    "harbor", "registry", "nexus", "artifactory", "nacos", "apollo",
    "eureka", "consul", "zookeeper", "kibana", "grafana", "zabbix",
    "prometheus", "vpn", "ssl-vpn", "bastion", "jump", "jumpserver",
    "phpmyadmin", "adminer", "redis", "mysql", "mongo", "es", "kafka",
    "k8s", "kube", "dashboard", "console", "manage", "manager", "admin",
    "oa", "erp", "crm", "hr", "sso", "auth", "ldap", "smtp", "imap",
    "pop", "mail", "exchange", "owa", "phpinfo", "test", "dev", "uat",
    "stage", "staging", "pre", "demo", "sandbox", "gray", "canary",
    "swagger", "api-doc", "apidoc", "docs", "internal", "intranet",
]
LOW_VALUE_PREFIXES = ["www", "api", "static", "cdn", "img", "image", "file",
                      "assets", "media", "m", "h5", "app", "download"]


def _txt_records(ctx: DetectorContext, name: str) -> list[str]:
    vals = net.dns_records(name, "TXT")
    if not vals:
        # dnspython 不可用时退回 socket 通道，避免静默返回空导致假阴性
        vals = ctx._extract_dns_txt(name)
    return [v.strip().strip('"').strip() for v in vals if v and v.strip()]


# ======================================================================
# EXT-DM-01 SPF 记录配置
# ======================================================================
@make_auto("EXT-DM-01", name="SPF 记录配置核查", tool="公共递归 DNS TXT 查询",
           risk=RISK_SAFE, evidence_kind="DNS 记录实测",
           detector_ref="checks/extras3.py:dm01",
           # 公共递归 DNS TXT 查询。
           needs_app=False)
def dm01(ctx: DetectorContext):
    _skip = _no_domain(ctx, "SPF 记录配置")
    if _skip is not None:
        return _skip
    txts = _txt_records(ctx, ctx.domain)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    findings = []

    if len(spf) > 1:
        findings.append(make_finding(
            "EXT-DM-01", f"存在 {len(spf)} 条 SPF 记录，收件方将判定为 PermError",
            ctx.target_name, endpoint=f"DNS TXT {ctx.domain}",
            severity="中危", confidence="High", evidence_level="A",
            description=("同一个域名下发布了多条 SPF 记录。按 RFC 7208，"
                         "收件方遇到多条 SPF 会直接判定为 PermError 并忽略全部记录，"
                         "等于 SPF 完全失效。"),
            technical_detail="实际查询到的 SPF 记录：\n" + "\n".join(
                f"  · {s[:200]}" for s in spf),
            impact=("SPF 失效后，攻击者可以用你的域名任意伪造发件人，"
                    "配合钓鱼邮件时收件方无法通过 SPF 校验识别。"),
            reproduction=f"nslookup -type=TXT {ctx.domain} 8.8.8.8",
            remediation=("① 只保留一条 SPF 记录，把多条的机制合并进同一条；"
                         "② 合并时注意 DNS 查询次数不超过 10 次；"
                         "③ 修改后 48 小时内复查多条记录是否已收敛。"),
            compliance="ISO 27001 A.8.23 / 邮件安全基线 SPF 唯一性",
            evidence=[finding_evidence("dns", "\n".join(spf), "SPF 记录")],
            grading_basis="实测确认多条 SPF，SPF 功能完全失效，定中危",
        ))
    elif not spf:
        findings.append(make_finding(
            "EXT-DM-01", "域名未配置 SPF 记录",
            ctx.target_name, endpoint=f"DNS TXT {ctx.domain}",
            severity="中危", confidence="High", evidence_level="A",
            description=("域名下没有 v=spf1 开头的 TXT 记录。"
                         "任何人都可以用该域名伪造发件人发送邮件。"),
            technical_detail="查询到的 TXT 记录：\n" + (
                "\n".join(f"  · {t[:160]}" for t in txts) or "  （无 TXT 记录）"),
            impact=("攻击者可直接以公司名义向客户、合作伙伴发送邮件。"
                    "实测中大量「供应商改收款账户」诈骗邮件正是靠这个前提成功的。"),
            reproduction=f"nslookup -type=TXT {ctx.domain} 8.8.8.8   # 无 v=spf1 返回",
            remediation=("① 由邮件服务商或网关获取标准 SPF 记录并发布；"
                         "② 只授权实际使用的投递渠道（企业邮箱、营销平台、"
                         "告警系统各自的出口 IP）；"
                         "③ 结尾用 -all（严格）或 ~all（观察期）。"),
            compliance="ISO 27001 A.8.23 / 等保2.0 安全计算环境-数据完整性",
            evidence=[finding_evidence("dns", "\n".join(txts) or "(无 TXT)",
                                       "TXT 记录查询结果")],
            grading_basis="实测确认无 SPF，域名可被任意伪造发件，定中危",
        ))
    else:
        rec = spf[0]
        low = rec.lower()
        if re.search(r"\+\s*all", low):
            findings.append(make_finding(
                "EXT-DM-01", "SPF 记录使用 +all，等于放弃校验",
                ctx.target_name, endpoint=f"DNS TXT {ctx.domain}",
                severity="高危", confidence="High", evidence_level="A",
                description="SPF 记录中包含 +all，明确声明「所有发件服务器都合法」。",
                technical_detail=f"记录内容：\n  {rec[:300]}",
                impact="SPF 形同虚设，任何 IP 都能冒充该域名发信并被判定为合法。",
                reproduction=f"nslookup -type=TXT {ctx.domain} 8.8.8.8   # 含 +all",
                remediation="把 +all 改为 -all（或其前置机制收敛后使用 ~all）。",
                compliance="邮件安全基线 / SPF 机制合法性",
                evidence=[finding_evidence("dns", rec, "SPF 记录")],
                grading_basis="实测确认 SPF 含 +all，校验完全失效，定高危",
            ))
        elif re.search(r"\?\s*all", low):
            findings.append(make_finding(
                "EXT-DM-01", "SPF 使用 ?all（中立），起不到拦截作用",
                ctx.target_name, endpoint=f"DNS TXT {ctx.domain}",
                severity="低危", confidence="High", evidence_level="A",
                description=("SPF 结尾为 ?all（中立），表示既不确定也不否认，"
                             "收件方无法据此拦截伪造邮件。"),
                technical_detail=f"记录内容：\n  {rec[:300]}",
                impact="伪造邮件的投递成功率会明显高于使用 -all 的情况。",
                reproduction=f"nslookup -type=TXT {ctx.domain} 8.8.8.8",
                remediation="观察期结束后改为 ~all，稳定后改为 -all。",
                compliance="邮件安全基线 / SPF 机制合法性",
                evidence=[finding_evidence("dns", rec, "SPF 记录")],
                grading_basis="SPF 存在但机制弱，未直接造成伪造成功，定低危",
            ))
        else:
            lookups = len(re.findall(
                r"\b(?:include|a|mx|ptr|exists|redirect)\b", low))
            if lookups > 10:
                findings.append(make_finding(
                    "EXT-DM-01", f"SPF 查询次数约 {lookups} 次，超出 10 次上限",
                    ctx.target_name, endpoint=f"DNS TXT {ctx.domain}",
                    severity="低危", confidence="Medium", evidence_level="A",
                    description=("SPF 中触发 DNS 查询的机制（include / a / mx 等）"
                                 "超过 10 个，收件方会返回 PermError 导致 SPF 失效。"),
                    technical_detail=(f"记录内容：\n  {rec[:300]}\n"
                                      f"统计到的查询类机制约 {lookups} 个"),
                    impact="SPF 会被判定为永久错误而忽略，等同于未配置。",
                    reproduction=f"nslookup -type=TXT {ctx.domain} 8.8.8.8",
                    remediation="合并 include（很多平台可提供合并后的记录），或改用 SPF 扁平化服务。",
                    compliance="RFC 7208 限制 / 邮件安全基线",
                    evidence=[finding_evidence("dns", rec, "SPF 记录")],
                    grading_basis="查询次数超限将导致 SPF 失效，但需邮件侧实测确认，定低危",
                ))

    note = (f"查询 {ctx.domain} 的 TXT 记录 {len(txts)} 条，"
            f"SPF 记录 {len(spf)} 条"
            + (f"：{spf[0][:120]}" if spf else "（未配置）"))
    if findings:
        return found(note, findings, probes=1, evidence_kind="DNS 记录实测")
    return ok(note + "（结尾机制为 -all，配置有效）", probes=1,
              evidence_kind="DNS 记录实测")


# ======================================================================
# EXT-DM-02 DKIM 配置
# ======================================================================
@make_auto("EXT-DM-02", name="DKIM 公钥记录探测", tool="公共递归 DNS TXT 查询",
           risk=RISK_SAFE, evidence_kind="DNS 记录实测",
           detector_ref="checks/extras3.py:dm02")
def dm02(ctx: DetectorContext):
    _skip = _no_domain(ctx, "DKIM 公钥记录探测")
    if _skip is not None:
        return _skip
    found_selectors: list[tuple[str, str]] = []
    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{ctx.domain}"
        for rec in _txt_records(ctx, name):
            if re.search(r"v=DKIM1|(?:^|;)\s*p=", rec, re.I):
                found_selectors.append((sel, rec))

    if not found_selectors:
        return pending(
            f"已探测 {len(DKIM_SELECTORS)} 个常见 DKIM selector，"
            f"均未查询到公钥记录。DKIM 可能使用了非标准 selector，"
            f"从外部无法确认，本项需人工复核（在邮件安全网关 / 邮局后台"
            f"查看「DKIM 签名」配置与 selector 名称）。",
            probes=len(DKIM_SELECTORS), evidence_kind="DNS 记录实测")

    findings = []
    weak = [(s, r) for s, r in found_selectors
            if not re.search(r"p=[A-Za-z0-9+/=]{80,}", r)]
    if weak:
        findings.append(make_finding(
            "EXT-DM-02", "DKIM 公钥长度偏短，存在被爆破风险",
            ctx.target_name, endpoint=f"DNS TXT <selector>._domainkey.{ctx.domain}",
            severity="低危", confidence="Medium", evidence_level="A",
            description="发现 DKIM 公钥记录，但 p= 部分长度明显短于 1024 位公钥的预期长度。",
            technical_detail="\n".join(
                f"  · selector={s}\n    {r[:240]}" for s, r in weak),
            impact="短密钥（如 512 位）可被离线因子分解，攻击者拿到私钥后即可伪造合法签名。",
            reproduction=f"nslookup -type=TXT {weak[0][0]}._domainkey.{ctx.domain} 8.8.8.8",
            remediation="重新生成 2048 位 DKIM 密钥并轮换 selector，旧记录保留一段时间后再下线。",
            compliance="ISO 27001 A.8.24 / 邮件安全基线 DKIM 密钥强度",
            evidence=[finding_evidence("dns", weak[0][1], "DKIM 公钥记录")],
            grading_basis="密钥强度不足但未被攻破，定低危",
        ))

    note = ("已确认 DKIM 公钥记录，selector：" +
            "、".join(s for s, _ in found_selectors))
    if findings:
        return found(note, findings, probes=len(DKIM_SELECTORS),
                     evidence_kind="DNS 记录实测")
    return ok(note, probes=len(DKIM_SELECTORS), evidence_kind="DNS 记录实测")


# ======================================================================
# EXT-DM-03 DMARC 策略
# ======================================================================
@make_auto("EXT-DM-03", name="DMARC 策略核查", tool="公共递归 DNS TXT 查询",
           risk=RISK_SAFE, evidence_kind="DNS 记录实测",
           detector_ref="checks/extras3.py:dm03",
           # 公共递归 DNS TXT 查询（_dmarc 子域）。
           needs_app=False)
def dm03(ctx: DetectorContext):
    _skip = _no_domain(ctx, "DMARC 策略核查")
    if _skip is not None:
        return _skip
    name = f"_dmarc.{ctx.domain}"
    txts = _txt_records(ctx, name)
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]

    if not dmarc:
        f = make_finding(
            "EXT-DM-03", "域名未配置 DMARC 记录",
            ctx.target_name, endpoint=f"DNS TXT {name}",
            severity="中危", confidence="High", evidence_level="A",
            description=("_dmarc 子域下没有 v=DMARC1 记录。"
                         "即使配置了 SPF 与 DKIM，收件方也没有依据对"
                         "校验失败的邮件执行拦截或隔离。"),
            technical_detail=f"查询 {name} 的 TXT 记录：" + (
                "\n" + "\n".join(f"  · {t[:160]}" for t in txts)
                if txts else "  （无记录）"),
            impact=("攻击者伪造贵司域名的邮件送达率显著提升；"
                    "同时你无法收到任何伪造行为的聚合报告，"
                    "等于对「有人正在冒充我们」这件事完全无感知。"),
            reproduction=f"nslookup -type=TXT _dmarc.{ctx.domain} 8.8.8.8",
            remediation=("① 发布 v=DMARC1; p=none; rua=mailto:<收报邮箱> 先进入观察期；"
                         "② 依据报告清理所有合法发信渠道；"
                         "③ 逐步把 p 提升到 quarantine、reject。"),
            compliance="ISO 27001 A.8.23 / 等保2.0 安全计算环境-数据完整性",
            evidence=[finding_evidence("dns", "\n".join(txts) or "(无 TXT)",
                                       "DMARC 查询结果")],
            grading_basis="实测确认无 DMARC，伪造邮件无拦截依据，定中危",
        )
        return found(f"查询 {name}：未配置 DMARC", [f], probes=1,
                     evidence_kind="DNS 记录实测")

    rec = dmarc[0]
    m_policy = re.search(r"\bp\s*=\s*(\w+)", rec, re.I)
    policy = m_policy.group(1).lower() if m_policy else ""
    findings = []
    if policy in ("", "none"):
        findings.append(make_finding(
            "EXT-DM-03", f"DMARC 策略为 p={policy or '未指定'}，仅监控不拦截",
            ctx.target_name, endpoint=f"DNS TXT {name}",
            severity="低危", confidence="High", evidence_level="A",
            description=("DMARC 记录存在，但策略为 none（或未指定 p），"
                         "收件方不会对校验失败的邮件做任何处置。"),
            technical_detail=f"记录内容：\n  {rec[:300]}",
            impact=("能从聚合报告中看到伪造行为，但伪造邮件依然会正常投递，"
                    "对收件人没有保护效果。"),
            reproduction=f"nslookup -type=TXT _dmarc.{ctx.domain} 8.8.8.8",
            remediation="观察期结束后把 p 提升为 quarantine，稳定后再提升为 reject。",
            compliance="邮件安全基线 / DMARC 策略强度",
            evidence=[finding_evidence("dns", rec, "DMARC 记录")],
            grading_basis="策略存在但不拦截，风险低于完全缺失，定低危",
        ))
    if "rua=" not in rec.lower():
        findings.append(make_finding(
            "EXT-DM-03", "DMARC 未配置 rua 报告地址",
            ctx.target_name, endpoint=f"DNS TXT {name}",
            severity="低危", confidence="High", evidence_level="A",
            description="DMARC 记录中缺少 rua= 聚合报告地址，收不到伪造行为报告。",
            technical_detail=f"记录内容：\n  {rec[:300]}",
            impact="无法发现有哪些第三方正在以贵司名义发信，策略调整失去数据依据。",
            reproduction=f"nslookup -type=TXT _dmarc.{ctx.domain} 8.8.8.8",
            remediation="在 DMARC 记录中补充 rua=mailto:<专用收报邮箱>。",
            compliance="邮件安全基线 / DMARC 可观测性",
            evidence=[finding_evidence("dns", rec, "DMARC 记录")],
            grading_basis="缺少可观测性影响后续治理，非直接可利用，定低危",
        ))

    note = f"DMARC 记录：{rec[:200]}（策略 p={policy or '未指定'}）"
    if findings:
        return found(note, findings, probes=1, evidence_kind="DNS 记录实测")
    return ok(note + "（策略为拦截级，配置有效）", probes=1,
              evidence_kind="DNS 记录实测")


# ======================================================================
# EXT-DM-04 域名劫持与仿冒面
# ======================================================================
@make_auto("EXT-DM-04", name="域名劫持与停放页检查", tool="DNS + HTTP 实测",
           risk=RISK_SAFE, evidence_kind="DNS 与页面实测",
           detector_ref="checks/extras3.py:dm04")
def dm04(ctx: DetectorContext):
    _skip = _no_domain(ctx, "域名劫持与停放页检查", evidence_kind="DNS 与页面实测")
    if _skip is not None:
        return _skip
    import socket
    import uuid

    findings = []
    notes = []

    # ---- ① 通配符 DNS：随便编个子域也能解析 ----
    nonce = f"aiscan-{uuid.uuid4().hex[:10]}.{ctx.domain}"
    wildcard_ips = net.dns_records(nonce, "A")
    if wildcard_ips:
        notes.append(f"存在通配符 DNS 解析（{nonce} → {','.join(wildcard_ips[:3])}）")
        f = make_finding(
            "EXT-DM-04", "域名配置了通配符 DNS 解析",
            ctx.target_name, endpoint=f"DNS A {nonce}",
            severity="低危", confidence="High", evidence_level="A",
            description=("任意编造的子域名都能解析到 IP，说明存在 *.domain 通配记录。"),
            technical_detail=f"随机子域 {nonce} 解析结果：{', '.join(wildcard_ips[:5])}",
            impact=("① 子域接管类漏洞会被掩盖（无法通过 NXDOMAIN 判断子域是否存在）；"
                    "② 容易被用来搭建高度可信的钓鱼站点（任意子域都指向你的 IP）；"
                    "③ 证书签发校验若依赖 DNS 会更易被绕过。"),
            reproduction=f"nslookup {nonce} 8.8.8.8   # 返回了 IP 即为通配符",
            remediation="去掉 *.domain 通配记录，改为按需逐个显式添加子域。",
            compliance="ISO 27001 A.8.20 / 网络安全管理",
            evidence=[finding_evidence("dns", f"{nonce} → {wildcard_ips}", "通配符解析")],
            grading_basis="通配解析放大钓鱼与接管面，未直接可利用，定低危",
        )
        findings.append(f)

    # ---- ② 域名停放 / 待售页 ----
    for scheme in ("https", "http"):
        url = f"{scheme}://{ctx.domain}/"
        body = net.http_text(url, timeout=15)
        if not body:
            continue
        low = body.lower()
        hit = next((m for m in PARKING_MARKERS if m in low), "")
        if hit:
            findings.append(make_finding(
                "EXT-DM-04", "域名指向停放 / 待售页面",
                ctx.target_name, endpoint=url,
                severity="高危", confidence="High", evidence_level="A",
                description=("域名的对外页面是域名停放商或「域名出售」页面，"
                             "而不是业务系统页面，疑似域名已过期被抢注。"),
                technical_detail=(f"页面特征命中：{hit}\n"
                                  f"页面片段：{body[:300]}"),
                impact=("域名若已被他人控制，攻击者可完全接管品牌身份："
                        "搭建仿冒登录页、拦截邮件、以该域名签发证书。"
                        "这是品牌资产级别的损失，不是普通漏洞。"),
                reproduction=f"curl -s '{url}' | head -c 500   # 观察停放页特征",
                remediation=("① 立即核实域名注册状态与到期时间；"
                             "② 若已过期，走争议解决（UDRP）或赎回流程；"
                             "③ 全部品牌域名开启自动续费与到期提醒。"),
                compliance="ISO 27001 A.5.23 / 品牌资产保护",
                evidence=[finding_evidence("response", body[:2000], "停放页特征")],
                grading_basis="实测确认对外页面为停放页，域名可能已失控，定高危",
            ))
            notes.append("命中域名停放页特征")
            break

    # ---- ③ 悬空 CNAME（托管商未认领）----
    dangling = []
    for sub in ("www", "cdn", "static", "files", "img", "assets", "blog",
                "docs", "help", "support", "status", "download", "m", "app"):
        name = f"{sub}.{ctx.domain}"
        cnames = net.dns_records(name, "CNAME")
        if not cnames:
            continue
        target = cnames[0].rstrip(".").lower()
        if any(re.search(pat, target) for pat, _, _ in (TAKEOVER_FINGERPRINTS or [])):
            try:
                socket.gethostbyname(target)
            except Exception:  # noqa: BLE001
                dangling.append(f"{name} → {target}（CNAME 目标已无法解析）")

    if dangling:
        findings.append(make_finding(
            "EXT-DM-04", f"{len(dangling)} 个子域存在悬空 CNAME",
            ctx.target_name, endpoint=f"DNS CNAME {ctx.domain}",
            severity="高危", confidence="Medium", evidence_level="A",
            description=("子域配置了指向第三方托管平台的 CNAME，"
                         "但该托管资源已无法解析，存在被子域接管的可能。"),
            technical_detail="悬空 CNAME 清单：\n" + "\n".join(f"  · {d}" for d in dangling),
            impact=("攻击者在对应托管平台注册同名资源后，即可完全控制该子域，"
                    "可用来托管钓鱼页、签发合法证书、读写该子域下的 Cookie。"),
            reproduction=(f"for s in www cdn static; do dig +short CNAME $s.{ctx.domain}; done\n"
                          "# 对返回的第三方域名再执行 dig，NXDOMAIN 即为悬空"),
            remediation=("① 对不再使用的子域，立即删除其 CNAME 记录（先删记录再释放资源）；"
                         "② 建立子域台账，下线流程里必须包含 DNS 记录清理；"
                         "③ 定期巡检所有指向第三方平台的 CNAME 是否仍然有效。"),
            compliance="ISO 27001 A.8.20 / 等保2.0 访问控制",
            evidence=[finding_evidence("dns", "\n".join(dangling), "悬空 CNAME")],
            grading_basis="实测确认 CNAME 目标失效，接管需第三方平台侧确认，定高危并标注置信度中",
        ))

    # ---- ④ MX 与发信能力 ----
    mx = net.dns_records(ctx.domain, "MX")
    notes.append(f"MX 记录 {len(mx)} 条" +
                 (f"（{'、'.join(x[:60] for x in mx[:3])}）" if mx else "（无，该域名不接收邮件）"))

    note = ("；".join(notes) or "已完成域名劫持面检查")
    if findings:
        return found(note, findings, probes=6, evidence_kind="DNS 与页面实测")
    return ok(note + "；未发现通配解析、停放页或悬空 CNAME", probes=6,
              evidence_kind="DNS 与页面实测")


# ======================================================================
# EXT-DM-05 邮件服务端口暴露
# ======================================================================
@make_auto("EXT-DM-05", name="邮件服务端口暴露实测", tool="TCP 连通性探测",
           risk=RISK_SAFE, evidence_kind="端口连通性实测",
           detector_ref="checks/extras3.py:dm05",
           # 纯 TCP 连通性探测。
           needs_app=False)
def dm05(ctx: DetectorContext):
    import socket

    host = ctx.domain
    try:
        host = socket.gethostbyname(ctx.domain)
    except Exception:  # noqa: BLE001
        return pending(f"域名 {ctx.domain} 无法解析出 A 记录，端口探测未执行",
                       evidence_kind="端口连通性实测")

    # 对照实验：本机到目标的 TCP 连通信号是否可信（与 INFO-04 / EXT-CL-02 同源）。
    # 沙箱代理 / 企业安全客户端 / 出口网关会**透明接受任意 connect()**，
    # 于是「每个端口都开放」。不做这个对照就会写出「公网可达端口 25/110/143」
    # 这类无法复测的发现 —— 2026-09-29 内部生产系统 实测：三个邮件端口与三个
    # 必然关闭的对照端口（49999/54321/65001）同时报「开放」，
    # 说明连接根本没出去，整条发现是假象。
    signal_ok, signal_why = net.tcp_signal_trustworthy(host)
    if not signal_ok:
        return pending(
            f"{signal_why}因此**本项无法判定**：不报邮件端口暴露，"
            f"也不报「邮件端口未暴露」。请在可信出口网络复测。",
            evidence_kind="端口连通性实测（TCP 对照实验未通过）")

    weak_mail = {25: "SMTP", 110: "POP3", 143: "IMAP"}
    secure_mail = {465: "SMTPS", 587: "SMTP 提交", 993: "IMAPS", 995: "POP3S"}
    db_ports = {3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                11211: "Memcached", 5432: "PostgreSQL", 1433: "SQL Server",
                2181: "ZooKeeper", 2375: "Docker API", 6443: "K8s API"}
    other = {21: "FTP", 23: "Telnet", 445: "SMB", 5900: "VNC", 3389: "RDP",
             9000: "常见管理端口", 8080: "备用 HTTP", 8443: "备用 HTTPS"}

    ports = list(weak_mail) + list(secure_mail) + list(db_ports) + list(other)
    # 先吃共享缓存（按档位扫过的全量端口），再补扫本项特有但缓存里没有的端口。
    # 只扫自己这张小表的话，缓存里额外的开放端口就白扫了 —— 覆盖面等于浪费。
    res = dict(net.scan_ports_cached(host, getattr(ctx, "profile_key", "standard")))
    missing = [p for p in ports if p not in res]
    if missing:
        res.update(net.scan_ports(host, missing))
    ports = sorted(res)
    ctx.probe_count += len(ports)
    open_ports = sorted(p for p, is_open in res.items() if is_open)

    findings = []
    sev_map = {}
    # 本项只对「邮件协议端口」产出发现 —— 归属表里登记给 EXT-DM-05 的那 7 个。
    # 数据库 / 中间件 / 容器 / 远程管理端口的定级由 EXT-CL-02 / CL-03 / CL-04
    # 专责上报：同一个端口被多个项各报一次，报告里会多出几条标题雷同、
    # 指向同一对 IP:端口 的发现，读者会把「端口个数」读成「漏洞个数」。
    # 本项仍然扫这些端口（执行证据留在下面的 note 里），只是不再重复定级。
    _OWN = "EXT-DM-05"
    delegated: list[tuple[int, str]] = []
    for p in open_ports:
        _owner = net.port_owner(p)
        if _owner != _OWN:
            delegated.append((p, _owner))
            continue
        if p in weak_mail:
            sev_map[p] = ("中危", weak_mail[p],
                          "明文邮件协议对外可达。账号密码以明文或弱加密传输，"
                          "且暴露了账号枚举与暴力破解面。")
        elif p in secure_mail:
            sev_map[p] = ("低危", secure_mail[p],
                          "加密邮件协议对外可达。属正常业务配置，"
                          "但需确认已启用暴力破解防护。")
        else:
            # 防御性兜底：归属表将来若把某个邮件端口登记给本项、而上面两个
            # 字典没有收录它，这里必须给出结论而不是抛异常。
            # （历史上正是因为直接索引 `secure_mail[p]`，一个 KeyError: 22
            #  把整条检查打成「未执行」—— 端口事实明明已经采到了。）
            sev_map[p] = ("低危", f"邮件相关端口 {p}",
                          "该端口归属于本项（邮件服务面），但未收录进明文 / 加密"
                          "邮件协议清单，需人工确认其协议与是否必需对外暴露。")

    scope, _, scope_why = reachability_scope(ctx)
    is_public = scope == "公网可达"
    _DOWN = {"严重": "中危", "中危": "低危", "低危": "低危"}

    for p, (sev, svc, why) in sorted(sev_map.items()):
        if sev == "低危":
            continue
        # 可达范围不成立时按内网暴露重新定级：一个只在内网可达的 Redis
        # 与一个公网可达的 Redis，危害差一个数量级，定级不能一样。
        if not is_public:
            sev = _DOWN.get(sev, sev)
            why += "（目标解析为内网地址，本条描述内网可达性，不计入公网风险。）"
        banner = net.tcp_banner(host, p)
        findings.append(make_finding(
            "EXT-DM-05",
            (f"公网可达端口 {p}（{svc}）" if is_public
             else f"内网可见（非公网暴露）：端口 {p}（{svc}）"),
            ctx.target_name, endpoint=f"{host}:{p}",
            severity=sev, confidence="High", evidence_level="A",
            description=why,
            technical_detail=(f"TCP 三次握手成功：{host}:{p}\n"
                              f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                              f"服务横幅：{banner or '（未返回横幅）'}"),
            impact=("按该服务性质不同，可导致数据被直接读取、账号被爆破、"
                    "或成为进入内网的跳板。"
                    + ("" if is_public else "本条可达范围限于内网。")),
            reproduction=f"nc -vz {host} {p}   # 连接成功即为开放",
            remediation=(f"① 确认 {svc} 是否为对外业务必需；"
                         "② 非必需则从安全组 / 防火墙移除该端口的对外放行，"
                         "改为仅内网或跳板机可达；"
                         "③ 必需时限制来源 IP 范围并启用强认证与失败锁定。"),
            compliance="等保2.0 安全区域边界-访问控制 / ISO 27001 A.8.20",
            evidence=[finding_evidence("network", f"tcp {host}:{p} open; banner={banner[:120]}",
                                       "端口连通性")],
            grading_basis=(f"实测 TCP 可建立连接；可达范围判定为「{scope}」，"
                           f"按服务性质与可达范围定{sev}"),
        ))

    note = (f"对 {host} 探测 {len(ports)} 个端口，开放 {len(open_ports)} 个"
            + (f"：{'、'.join(str(p) for p in open_ports)}" if open_ports else "")
            + "。判定基于本机 TCP 连通性实测，若目标侧有来源 IP 白名单可能造成偏差，"
              "建议用公网测绘平台（Shodan / FOFA）交叉复核。")
    if delegated:
        # 扫到了但不归本项定级 —— 明确写出去向，别让读者以为这些端口没人管。
        note += ("其中 " + "、".join(f"{p}(→{o})" for p, o in sorted(delegated))
                 + " 不属本项定级范围，已在对应检查项上报。")
    if findings:
        return found(note, findings, probes=len(ports), evidence_kind="端口连通性实测")
    return ok(note + "；本项范围内（邮件协议端口）未发现不应暴露的端口",
              probes=len(ports), evidence_kind="端口连通性实测")


# ======================================================================
# EXT-DM-06 证书透明度日志暴露
# ======================================================================
@make_auto("EXT-DM-06", name="证书透明度日志子域枚举",
           tool="CT 日志多源（crt.sh / Cert Spotter / HackerTarget / 公共 DNS）",
           risk=RISK_SAFE, evidence_kind="公开日志枚举",
           detector_ref="checks/extras3.py:dm06",
           # 证书透明度公开日志枚举（crt.sh 等），外部 API。
           needs_app=False)
def dm06(ctx: DetectorContext):
    _skip = _no_domain(ctx, "证书透明度日志子域枚举", evidence_kind="公开日志枚举")
    if _skip is not None:
        return _skip
    res = net.ct_subdomains(ctx.domain)
    ctx.probe_count += 1
    subs = [s for s in (res.get("subs") or []) if s != ctx.domain]
    sources: dict[str, str] = res.get("sources") or {}
    reachable = int(res.get("reachable") or 0)
    src_line = "；".join(f"{k}：{v}" for k, v in sources.items())

    # 「取不到子域」背后有两种含义相反的原因，必须分开写：
    #   · 源全部不可用 → 是我们的采集通道有问题，结论是「未能确认」；
    #   · 多源都通但确实没有签发记录 → 这才是关于目标的事实。
    # 混成一句「可能有也可能没有」，读的人只能靠猜。
    if not reachable:
        return pending(
            f"证书透明度 / 公开情报源**全部不可用**，未能获取 {ctx.domain} 的"
            f"子域列表 —— 这是采集通道的问题，不是关于目标的结论。"
            f"各源状态：{src_line}。本项需人工用其他公开源复核",
            probes=1, evidence_kind="公开日志枚举（源不可用）")
    if not subs:
        return pending(
            f"{reachable} 个公开源可达且均未返回 {ctx.domain} 的子域签发记录"
            f"（已排除主域自身）。注意这**不等于**「没有暴露子域」——"
            f"CT 日志只覆盖公共信任链证书，内网自签、纯泛域名证书或不走 HTTPS 的"
            f"内部系统不会出现在这里。各源状态：{src_line}",
            probes=1, evidence_kind="公开日志枚举（无记录）")

    interesting, high = [], []
    for s in subs:
        prefix = s.split(".")[0].lower()
        if prefix in LOW_VALUE_PREFIXES:
            continue
        if prefix in HIGH_VALUE_PREFIXES:
            high.append(s)
        elif re.match(r"^(?:[\w\-]*(?:test|dev|uat|stage|pre|demo|sandbox|internal|"
                      r"bak|old|temp|tmp|new|beta|alpha)[\w\-]*)$", prefix):
            interesting.append(s)

    findings = []
    if high or interesting:
        listed = high + interesting
        sev = "中危" if high else "低危"
        findings.append(make_finding(
            "EXT-DM-06", f"证书透明度日志暴露 {len(listed)} 个高价值子域",
            # 本发现描述的是「目标域的子域可以从公开日志枚举出来」，主体是
            # 目标域本身。端点写成 https://crt.sh/ 会让人误以为发现了 crt.sh
            # 的问题，也会让复现脚本跑去请求站外地址。
            ctx.target_name, endpoint=ctx.domain,
            severity=sev, confidence="High", evidence_level="A",
            description=("公开的证书透明度日志中可以枚举出管理后台、CI/CD、"
                         "监控、测试环境等子域。这些本应只在内网可达的系统，"
                         "其子域名对任何人有迹可循。"),
            technical_detail=(f"域名下共枚举到 {len(subs)} 个子域，其中高价值 "
                              f"{len(high)} 个、疑似非生产环境 {len(interesting)} 个：\n"
                              + "\n".join(f"  · {s}" for s in listed[:40])),
            impact=("① 攻击者无需扫描即可获得精准攻击目标清单；"
                    "② 管理后台 / CI / 监控类系统一旦弱口令，直接导致失陷；"
                    "③ 测试环境防护通常弱于生产，是典型的横向突破口。"),
            reproduction=(f"curl -s 'https://crt.sh/?q=%25.{ctx.domain}&output=json' \\\n"
                          "  | grep -oE '\"name_value\":\"[^\"]+' | sort -u\n"
                          f"curl -s 'https://api.certspotter.com/v1/issuances"
                          f"?domain={ctx.domain}&include_subdomains=true&expand=dns_names'"),
            remediation=("① 内部系统使用独立域名（如内网专用域）或独立泛域名证书，"
                         "避免内部系统名进入公用证书透明度日志；"
                         "② 确需公网访问的管理类系统，加 IP 白名单或 SSO + MFA；"
                         "③ 建立子域台账并定期比对 CT 日志新增记录。"),
            compliance="ISO 27001 A.8.9 / 等保2.0 安全区域边界",
            evidence=[finding_evidence("dns", "\n".join(listed[:60]), "CT 日志子域枚举")],
            grading_basis="实测枚举到高价值子域清单，为信息暴露与攻击面扩大，定" + sev,
        ))

    note = (f"从 {reachable} 个公开源枚举 {ctx.domain} 的子域 {len(subs)} 个"
            f"（已排除主域自身；各源状态：{src_line}）")
    if findings:
        return found(note + f"，其中高价值 {len(high)} 个", findings, probes=1,
                     evidence_kind="公开日志枚举")
    return ok(note + "，未发现高价值或非生产环境子域暴露"
              "（注意：CT 日志只覆盖公共信任链证书，结论不覆盖内网自签与"
              "纯泛域名场景）", probes=1, evidence_kind="公开日志枚举")
