# -*- coding: utf-8 -*-
"""
场景扩展检查 第四批：数据与隐私（EXT-DP 5 项）+ 稳健性与滥用防护（EXT-RB 5 项）
==============================================================================
这一批对应国内合规最关心的两块：
  · 数据与隐私：PIPL / GB/T 35273 的落地检查点，重点是「谁的数据能被谁看到」；
  · 滥用防护：不是被黑，而是被「正常功能用歪」——短信轰炸、优惠券刷取、
    接口刷量。这类问题在漏洞平台上是独立品类，在 WSTG 里没有位置。

自动化边界：
  · 能从响应内容判断的（PII 明文、调试接口、缓存头）→ 自动；
  · 必须真的发短信 / 邮箱才能验证的（轰炸面）→ 只做暴露面静态识别，
    报告里明确写「未实际发送任何消息」，绝不为了证明漏洞给真人发短信；
  · 业务规则类的（导出范围、锁定机制）→ 人工。
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from engine.checks.base import (
    DEBUG_PATHS, STACK_TRACE_PATTERNS,
    extract_params, find_forms, finding_evidence, found, is_real_hit, ok,
    pending, pii_hit_values, scan_paths, sitewide_guard, no_target_outcome,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)
from engine import recon_identity as recon_id

# 注：PII 的判据（PII_PATTERNS / 占位值表 / 过滤规则）统一放在
# engine/checks/base.py 的 `pii_hit_values()`，由本模块的检测器与红队结果证明器
# **共用同一份**。两边各写一份必然漂移，而漂移的后果是「检测器说响应里有手机号、
# 证明器却判未达成」这类与证据自相矛盾的结论。

# 含用户数据的路径特征
USER_DATA_HINTS = [
    "user", "account", "profile", "member", "customer", "order", "bill",
    "invoice", "address", "contact", "passport", "employee", "staff",
    "me", "self", "my", "info", "detail", "personal",
]

# 敏感操作特征（用于人机校验与轰炸面判断）
SENSITIVE_OP_HINTS = [
    "register", "signup", "sign-up", "login", "signin", "sign-in",
    "reset", "forget", "forgot", "password", "sms", "sendcode", "send-code",
    "verify", "captcha", "code", "invite", "coupon", "voucher", "redeem",
    "pay", "payment", "recharge", "withdraw", "refund", "order", "comment",
    "feedback", "subscribe", "bind", "unbind", "transfer", "submit",
]

# 人机校验 / 风控信号
HUMAN_VERIFY_SIGNALS = [
    r"recaptcha", r"hcaptcha", r"turnstile", r"geetest", r"captcha",
    r"nc_scale", r"slider", r"滑块", r"验证码", r"图形验证",
    r"yidun", r"dingxiang", r"cloudflare", r"challenges\.cloudflare",
    r"risk[_\-]?control", r"风控",
]

# 短信 / 邮件收发接口的参数字段特征
BOMB_PARAM_HINTS = [
    "mobile", "phone", "tel", "telephone", "mobilephone", "cellphone",
    "email", "mail", "mailbox", "sms", "msg", "captcha", "verifycode",
]


# ======================================================================
# 公共助手
# ======================================================================
def _mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}{'*' * max(2, len(v) - 4)}{v[-2:]}"


def _pii_hits(text: str, *, limit: int = 12) -> list[tuple[str, str]]:
    """在文本里找敏感数据特征，返回 (类型, 脱敏样本)。

    过滤规则（占位值 / 重复 / 字段片段内的占位词）全部在
    `engine.checks.base.pii_hit_values` 里，**与红队证明器共用同一份** ——
    两边各写一份必然漂移，而漂移的后果是「检测器说响应里有手机号、
    证明器却判未达成」这类与证据自相矛盾的结论。
    """
    return [(label, _mask(val)) for label, val in pii_hit_values(text, limit=limit)]


def _api_like_paths(ctx: DetectorContext, limit: int = 12) -> list[str]:
    """找出看起来是「返回用户数据」的接口地址。"""
    urls: list[str] = []
    seen: set[str] = set()
    for u in (ctx.js_result.get("urls") or [])[:400]:
        if not isinstance(u, str):
            continue
        full = urljoin(ctx.target_url, u)
        if ctx.domain not in full or full in seen:
            continue
        low = full.lower()
        if not any(h in low for h in USER_DATA_HINTS):
            continue
        seen.add(full)
        urls.append(full)
        if len(urls) >= limit:
            break
    if not urls:
        for cand in ("api/user", "api/me", "api/profile", "api/account",
                     "user/info", "api/v1/user", "api/user/info"):
            probe = ctx.probe_path(cand)
            if probe is not None and getattr(probe, "status", 0) in (200, 401, 403):
                urls.append(urljoin(ctx.target_url.rstrip("/") + "/", cand))
    return urls


def _burst(url: str, n: int = 8) -> list[dict[str, object]]:
    """连续 n 次相同请求，用于实测速率限制（必须绕开缓存）。"""
    import requests

    out: list[dict[str, object]] = []
    headers = {"User-Agent": "AIScan/1.0 (Authorized Security Assessment)"}
    for _ in range(n):
        t0 = time.time()
        try:
            r = requests.get(url, timeout=8, verify=False, allow_redirects=False,
                             headers=headers)
            out.append({
                "status": r.status_code,
                "elapsed_ms": int((time.time() - t0) * 1000),
                "rl_headers": {k: v for k, v in r.headers.items()
                               if "ratelimit" in k.lower() or "rate-limit" in k.lower()
                               or k.lower() == "retry-after"},
            })
        except Exception as e:  # noqa: BLE001
            out.append({"status": 0, "elapsed_ms": int((time.time() - t0) * 1000),
                        "rl_headers": {}, "error": f"{type(e).__name__}"})
    return out


# ======================================================================
# EXT-DP-01 响应中明文暴露敏感数据
# ======================================================================
@make_auto("EXT-DP-01", name="响应内容敏感数据扫描", tool="全量内容特征扫描",
           risk=RISK_SAFE, evidence_kind="响应内容实测",
           detector_ref="checks/extras4.py:dp01")
def dp01(ctx: DetectorContext):
    blobs = [("根路径 HTML", ctx.baseline_body)]
    for i, b in enumerate((ctx.js_result.get("bodies") or [])[:40]):
        blobs.append((f"前端产物 #{i + 1}", b or ""))
    for i, b in enumerate((ctx.js_result.get("inline_scripts") or [])[:40]):
        blobs.append((f"内联脚本 #{i + 1}", b or ""))

    # 接口响应必须一起扫 —— 敏感数据绝大多数出现在这里，而不是页面 HTML 里。
    # 只扫页面会得出「未发现敏感数据」的假结论（自测正是靠这一点暴露的）。
    api_urls = _api_like_paths(ctx, limit=8)
    for url in api_urls:
        try:
            probe = ctx.get(url)
        except Exception:  # noqa: BLE001
            continue
        if probe is None or getattr(probe, "status", 0) not in (200, 401, 403):
            continue
        body = getattr(probe, "body_snippet", "") or ""
        if body:
            blobs.append((f"接口 {url}", body))

    hits: list[tuple[str, str, str]] = []
    for src, text in blobs:
        for label, sample in _pii_hits(text):
            hits.append((src, label, sample))

    if not hits:
        total = sum(len(t) for _, t in blobs)
        return ok(f"扫描 {len(blobs)} 份对外内容（含 {len(api_urls)} 个接口响应，"
                  f"共约 {total} 字符），未发现明文敏感数据特征",
                  probes=1 + len(api_urls), evidence_kind="响应内容实测")

    by_type: dict[str, int] = {}
    for _, label, _ in hits:
        by_type[label] = by_type.get(label, 0) + 1
    types = "、".join(f"{k}×{v}" for k, v in by_type.items())

    # 端点必须取「**第一个命中所在的地址**」，不能写死根路径。
    # 命中可能来自根 HTML / 前端产物 / 接口响应三种来源；若统一声明成根路径，
    # 后续复核（结果证明层重取、复现脚本）就会打在一个根本没有敏感数据的页面上，
    # 得出「未能复现」的假结论 —— 而数据其实就摆在那个接口响应里。
    # 接口响应优先：敏感数据绝大多数出现在这里，而不是页面 HTML 里。
    _api_hit = next((s for s, _, _ in hits if s.startswith("接口 ")), "")
    ep = _api_hit[len("接口 "):].strip() if _api_hit else ctx.target_url

    f = make_finding(
        "EXT-DP-01", f"对外内容中明文暴露敏感数据（{types}）",
        ctx.target_name, endpoint=ep,
        severity="中危", confidence="Medium", evidence_level="A",
        description=("在无需登录即可获取的页面或前端产物中，"
                     "发现了手机号 / 身份证号 / 银行卡号 / 邮箱等敏感数据特征。"),
        technical_detail=("命中清单（已脱敏）：\n" + "\n".join(
            f"  · [{src}] {label} → {sample}" for src, label, sample in hits[:15])),
        impact=("① 个人信息在未授权状态下即可被批量采集，违反个人信息最小必要与"
                "去标识化要求；"
                "② 若为真实用户数据，属个人信息泄露事件，需按法规评估上报与告知义务；"
                "③ 手机号与身份证号的组合可直接用于撞库与精准诈骗。"),
        reproduction=(f"curl -s '{ep}' | grep -oE '1[3-9][0-9]{{9}}' | head\n"
                      "# 在前端产物中同样检索（view-source 或直接下载 JS）"),
        remediation=("① 接口默认只返回业务必需字段，员工 / 客户敏感字段按角色脱敏"
                     "（手机号中间四位、身份证保留前 6 后 4）；"
                     "② 前端渲染所需数据由后端脱敏后下发，禁止把完整字段塞进页面"
                     "再由前端截断；"
                     "③ 建立响应字段白名单，新增字段默认不下发。"),
        compliance="PIPL 第 51 条 / GB/T 35273 6.3 / 等保2.0 数据保密性",
        evidence=[finding_evidence("response",
                                   "\n".join(f"{s}|{l}|{v}" for s, l, v in hits[:20]),
                                   "敏感数据特征命中（已脱敏）")],
        grading_basis="实测确认未授权可见的敏感数据，但需人工确认是否属真实用户数据，定中危",
    )
    return found(f"扫描 {len(blobs)} 份对外内容"
                 f"（含 {len(api_urls)} 个接口响应），"
                 f"命中敏感数据特征 {len(hits)} 处（{types}）",
                 [f], probes=1 + len(api_urls), evidence_kind="响应内容实测")


# ======================================================================
# EXT-DP-02 日志与调试接口泄露 PII
# ======================================================================
@make_auto("EXT-DP-02", name="调试 / 日志接口泄露检查", tool="路径探测 + 内容特征扫描",
           risk=RISK_STANDARD, evidence_kind="接口实测响应",
           detector_ref="checks/extras4.py:dp02")
def dp02(ctx: DetectorContext):
    hits = scan_paths(ctx, DEBUG_PATHS)
    if not hits:
        return ok(f"探测 {len(DEBUG_PATHS)} 个调试 / 日志类路径，"
                  f"未发现可匿名访问的调试接口", probes=len(DEBUG_PATHS),
                  evidence_kind="接口实测响应")

    findings = []
    for path, probe in hits.items():
        body = (getattr(probe, "body_snippet", "") or "")
        url = urljoin(ctx.target_url.rstrip("/") + "/", path.lstrip("/"))

        pii = _pii_hits(body)
        traces = [p for p in STACK_TRACE_PATTERNS if re.search(p, body, re.I)]
        # 只有确实含敏感内容或堆栈才报，否则只是「路径存在」
        if not pii and not traces:
            continue

        sev = "高危" if (pii and traces) else ("中危" if pii else "低危")
        findings.append(make_finding(
            "EXT-DP-02", f"调试 / 日志接口可匿名访问并泄露信息：/{path}",
            ctx.target_name, endpoint=url, method="GET",
            severity=sev, confidence="High", evidence_level="A",
            description=("该路径无需身份凭证即可访问，"
                         "返回内容中包含" +
                         ("真实敏感数据特征与运行堆栈" if (pii and traces)
                          else ("真实敏感数据特征" if pii else "运行堆栈信息")) + "。"),
            technical_detail=(f"HTTP {getattr(probe, 'status', 0)}\n"
                              + ("敏感数据命中：\n" + "\n".join(
                                  f"    · {l} → {v}" for l, v in pii) + "\n"
                                 if pii else "")
                              + ("堆栈特征命中：\n" + "\n".join(
                                  f"    · {t[:100]}" for t in traces[:5])
                                 if traces else "")
                              + f"\n响应片段：\n    {body[:400]}"),
            impact=("① 调试接口通常暴露配置、环境变量、内部调用链，"
                    "是进入内网的地图；"
                    "② 若返回真实用户数据，直接构成个人信息泄露；"
                    "③ 堆栈信息会暴露框架版本与代码路径，便于精准利用已知漏洞。"),
            reproduction=f"curl -s '{url}' | head -c 800",
            remediation=("① 生产环境关闭所有调试与日志接口（actuator 只暴露 health、"
                         "并置于内网）；"
                         "② 日志文件、*.log 路径从 Web 根目录移出，"
                         "由日志平台统一采集；"
                         "③ 反向代理层对 debug / log / actuator 等前缀直接返回 404。"),
            compliance="等保2.0 安全计算环境-入侵防范 / PIPL 第 51 条",
            evidence=[finding_evidence("response", body[:1500], "调试接口响应")],
            grading_basis=f"实测确认匿名可达且含敏感信息，按内容定{sev}",
        ))

    note = (f"探测 {len(DEBUG_PATHS)} 个调试 / 日志类路径，"
            f"可匿名访问 {len(hits)} 个，其中含敏感信息 {len(findings)} 个")
    if findings:
        return found(note, findings, probes=len(DEBUG_PATHS), evidence_kind="接口实测响应")
    return ok(note + "（可达路径均为静态说明页，未含敏感内容）",
              probes=len(DEBUG_PATHS), evidence_kind="接口实测响应")


# ======================================================================
# EXT-DP-03 导出功能数据范围越界 —— 人工
# ======================================================================
SPEC_DP03 = make_manual(
    "EXT-DP-03",
    name="数据导出范围越界人工核查",
    procedure=(
        "1) 用测试账号（尽量低权限）登录，找到所有「导出 / 下载」入口："
        "   列表页导出、报表下载、批量导出、打印 PDF。\n"
        "2) 用一个明显属于他人的筛选条件做导出："
        "   比如 A 部门账号导出 B 部门数据、A 客户导出 B 客户的订单。\n"
        "3) 导出后检查文件内容：行数是否超出该账号在页面上能看到的范围，"
        "   是否包含页面上被脱敏的字段（完整手机号、身份证、银行账号）。\n"
        "4) 抓取导出请求，单独重放：改动筛选参数（如 deptId、customerId、"
        "   startDate/endDate 拉到三年），看服务端是否校验数据归属与时间范围。\n"
        "5) 检查导出行数上限：把 pageSize/limit 改成 100000 重放一次。"
    ),
    expect=("导出内容超出该账号页面可见范围，或包含未脱敏敏感字段，"
            "或改造筛选参数即可拉取全量数据 → 不通过；"
            "导出严格按当前账号数据权限过滤且字段已脱敏 → 通过。"),
    why_manual=("导出越界本质是服务端数据权限是否落到查询条件上的问题，"
                "必须用两个不同权限的账号实际比对导出内容才能确认，"
                "外部扫描无从判断哪条记录属于谁。"),
    risk=RISK_STANDARD,
    requires=["accounts"],
    # 「匿名即可拿到导出产物」这一半可由响应类型（Content-Type）自动确证；
    # 「导出内容是否超出该账号可见范围」仍需人工。
    recon=recon_id.recon_dp03,
)


# ======================================================================
# EXT-DP-04 含用户数据的响应被缓存
# ======================================================================
@make_auto("EXT-DP-04", name="用户数据响应缓存策略核查", tool="响应头实测",
           risk=RISK_SAFE, evidence_kind="响应头实测",
           detector_ref="checks/extras4.py:dp04")
def dp04(ctx: DetectorContext):
    targets = _api_like_paths(ctx)
    if not targets:
        return pending("未能从已采集内容中定位到返回用户数据的接口路径"
                       "（需登录后才能看到这类接口），本项需人工在登录态下核查",
                       probes=1, evidence_kind="响应头实测")

    bad: list[dict[str, str]] = []
    checked = 0
    for url in targets[:8]:
        probe = ctx.get(url)
        if probe is None:
            continue
        status = getattr(probe, "status", 0)
        if status not in (200, 401, 403):
            continue
        checked += 1
        hdrs = {k.lower(): v for k, v in (getattr(probe, "headers", {}) or {}).items()}
        cc = hdrs.get("cache-control", "")
        pragma = hdrs.get("pragma", "")
        expires = hdrs.get("expires", "")
        low = cc.lower()
        if not cc and not pragma and not expires:
            bad.append({"url": url, "issue": "无任何缓存控制头",
                        "cache_control": "(缺失)"})
        elif "public" in low or ("max-age=" in low
                                 and not re.search(r"max-age=0(?:\D|$)", low)):
            bad.append({"url": url, "issue": "允许公共 / 长期缓存",
                        "cache_control": cc})

    if not bad:
        return ok(f"检查 {checked} 个用户数据接口的缓存响应头，"
                  f"均设置了禁止缓存的策略", probes=checked, evidence_kind="响应头实测")

    f = make_finding(
        "EXT-DP-04", f"{len(bad)} 个用户数据接口缺少禁止缓存策略",
        ctx.target_name, endpoint=bad[0]["url"], method="GET",
        severity="中危", confidence="Medium", evidence_level="A",
        description=("返回用户相关数据的接口未设置 Cache-Control: no-store，"
                     "或声明为 public / 长 max-age，响应可能被浏览器或中间缓存留存。"),
        technical_detail="\n".join(
            f"  · {b['url']}\n    问题：{b['issue']}    Cache-Control: {b['cache_control']}"
            for b in bad),
        impact=("① 在共用终端（前台、门店、公共电脑）上，"
                "后一位使用者可通过浏览器缓存读取到上一位用户的个人数据；"
                "② 中间代理若缓存了带 Cookie 的响应，可能造成跨用户数据串号；"
                "③ 属于个人信息在存储环节的保护缺失。"),
        reproduction=(f"curl -sI '{bad[0]['url']}' | grep -iE 'cache-control|pragma|expires'\n"
                      "# 无 no-store / 显示 public 即为不通过"),
        remediation=("① 所有返回个人数据的接口统一加 "
                     "Cache-Control: no-store, private, max-age=0；"
                     "② 由网关统一注入，避免逐个接口遗漏；"
                     "③ 前端退出登录时清理本地缓存与内存中的用户数据。"),
        compliance="PIPL 第 51 条 / GB/T 35273 6.3 / 等保2.0 数据保密性",
        evidence=[finding_evidence("headers", json.dumps(bad, ensure_ascii=False),
                                   "缓存响应头实测")],
        grading_basis="实测确认缓存策略缺失，可导致本地数据残留，定中危",
    )
    return found(f"检查 {checked} 个用户数据接口，{len(bad)} 个缺少禁止缓存策略",
                 [f], probes=checked, evidence_kind="响应头实测")


# ======================================================================
# EXT-DP-05 移动端 / 小程序接口暴露面
# ======================================================================
@make_auto("EXT-DP-05", name="移动端 / 小程序接口暴露面探测",
           tool="路径探测 + 前端产物分析", risk=RISK_STANDARD,
           evidence_kind="接口实测响应",
           detector_ref="checks/extras4.py:dp05")
def dp05(ctx: DetectorContext):
    mobile_prefixes = [
        "app/", "api/app/", "mobile/", "api/mobile/", "miniapp/", "mini/",
        "wx/", "wechat/", "weixin/", "h5/", "api/h5/", "api/wx/",
        "app/api/", "api/v2/app/", "api/v3/app/", "gateway/app/",
        "api/client/", "client/api/", "appapi/",
    ]
    hits = scan_paths(ctx, mobile_prefixes)

    # 同时从前端产物里找显式的移动端域名或路径
    declared: list[str] = []
    for u in (ctx.js_result.get("urls") or [])[:400]:
        if not isinstance(u, str):
            continue
        if re.search(r"(?:^|/)(?:app|mobile|miniapp|wx|wechat|weixin)/", u, re.I):
            full = urljoin(ctx.target_url, u)
            if ctx.domain in full and full not in declared:
                declared.append(full)
        if len(declared) >= 10:
            break

    if not hits and not declared:
        return ok(f"探测 {len(mobile_prefixes)} 个移动端 / 小程序常见接口前缀，"
                  f"并在 {len(ctx.js_result.get('urls') or [])} 条前端地址中检索，"
                  f"未发现移动端接口暴露", probes=len(mobile_prefixes),
                  evidence_kind="接口实测响应")

    detail = []
    for p in hits:
        detail.append(f"  · {urljoin(ctx.target_url.rstrip('/') + '/', p.lstrip('/'))}")
    for d in declared:
        detail.append(f"  · {d}（来自前端产物）")

    f = make_finding(
        "EXT-DP-05", f"发现 {len(detail)} 处移动端 / 小程序接口暴露",
        ctx.target_name, endpoint=ctx.target_url,
        severity="中危", confidence="Medium", evidence_level="B",
        description=("存在可匿名访问的移动端 / 小程序接口路径，"
                     "这类接口通常为适配 App 而简化了鉴权与风控。"),
        technical_detail="命中清单：\n" + "\n".join(detail[:20]),
        impact=("① 移动端接口常与 Web 端共用后端，但风控规则往往只在 Web 侧配置，"
                "可被用来绕过前端限制；"
                "② 小程序类接口的 AppSecret / 签名逻辑若在客户端，可被逆向复现；"
                "③ 接口暴露面扩大，鉴权设计不一致时容易出现越权。"),
        reproduction=(f"curl -s -o /dev/null -w '%{{http_code}}\\n' "
                      f"'{urljoin(ctx.target_url.rstrip('/') + '/', list(hits.keys())[0].lstrip('/')) if hits else declared[0]}'"),
        remediation=("① 移动端接口与 Web 端接口采用同一套鉴权与数据权限校验，"
                     "不因「客户端是自己人」而放宽；"
                     "② 涉及金额、个人信息的移动端接口必须做签名校验，"
                     "签名密钥只放服务端；"
                     "③ 接口路径做统一前缀收敛并纳入网关统一鉴权。"),
        compliance="等保2.0 安全区域边界-访问控制 / OWASP API5 功能级授权失效",
        evidence=[finding_evidence("response", json.dumps(detail[:20], ensure_ascii=False),
                                   "移动端接口命中")],
        grading_basis="实测确认接口可达，具体越权危害需登录后验证，定中危并标注证据等级 B",
    )
    return found(f"发现移动端 / 小程序接口暴露 {len(detail)} 处", [f],
                 probes=len(mobile_prefixes), evidence_kind="接口实测响应")


# ======================================================================
# EXT-RB-01 接口速率限制缺失
# ======================================================================
@make_auto("EXT-RB-01", name="接口速率限制实测", tool="连续请求实测",
           risk=RISK_STANDARD, evidence_kind="限流行为实测",
           detector_ref="checks/extras4.py:rb01")
def rb01(ctx: DetectorContext):
    candidates: list[str] = []
    for path, probe in (ctx.fp_result.get("path_probes") or {}).items():
        if not isinstance(probe, dict):
            continue
        if probe.get("status") == 200:
            url = probe.get("final_url") or probe.get("url") or ""
            if url and ctx.domain in url and url not in candidates:
                candidates.append(url)
    if not candidates:
        candidates = [ctx.target_url]

    # 优先挑带参数的接口（更能代表真实业务接口），否则用首页
    candidates.sort(key=lambda u: 0 if "?" in u or "/api/" in u else 1)

    # 候选预检：限流实测必须建立在一个「原本就能成功」的地址上。
    # 只按特征挑候选会挑错 —— 例如只接受 POST 的 /api/graphql，用 GET 永远 405，
    # 那一轮 burst 全部非 2xx，整项白跑并落到「无有效基线」的待确认里，
    # 看起来像「目标测不出来」，实际是候选挑错了。
    url = ""
    precheck: list[str] = []
    for cand in candidates[:6]:
        first = _burst(cand, n=1)
        ctx.probe_count += len(first)
        st = first[0]["status"] if first else 0
        precheck.append(f"{cand} → HTTP {st}")
        if st == 200:
            url = cand
            break
    if not url:
        return pending(
            "候选地址逐个预检均未返回 2xx，无法建立「应用已正常处理该请求」的基线 ——"
            "既不能判「未实施限流」，也不能判「已实施限流」。"
            "预检结果：" + "；".join(precheck),
            probes=len(precheck), evidence_kind="限流行为实测（无有效基线）")

    runs = _burst(url, n=8)
    ctx.probe_count += len(runs)
    statuses = [r["status"] for r in runs]
    has_429 = 429 in statuses
    rl_headers = [r["rl_headers"] for r in runs if r["rl_headers"]]
    blocked = any(s in (403, 503) for s in statuses[1:])   # 后续请求被拦

    # 前提校验：限流只能在「应用确实处理了这些请求」的前提下判断。
    # 若 8 次全部拿到同一个非成功状态码（WAF / 反向代理对全站返回 405、
    # 403 等），请求根本没到应用 —— 这时既不能判「已限流」也不能判
    # 「未限流」。实测出过事故：全站 405 的目标被判成
    # 「接口未实施速率限制」并定中危，而这条发现无法复测。
    sitewide_status, sitewide_ratio, sitewide_n = sitewide_guard(ctx)
    if len(set(statuses)) == 1 and statuses[0] not in (200, 201, 202, 204):
        extra = ""
        if sitewide_status:
            extra = (f"另：目标对任意路径返回 HTTP {sitewide_status}"
                     f"（已探测 {sitewide_n} 个路径中 {sitewide_ratio:.0%} 同码），"
                     f"疑似边缘阻断，请求可能未触达应用。")
        return pending(
            f"连续 8 次请求 {url} 的状态码全部为 HTTP {statuses[0]}，"
            f"不构成「应用已处理该请求」的证据（405 = 方法不允许、"
            f"403/503 = 被拒或不可用），既不能据此判「已实施限流」，"
            f"也不能判「未实施限流」。{extra}"
            f"请在一个真正可达的业务路径上复测。",
            probes=len(runs), evidence_kind="限流行为实测（无有效基线）")

    if has_429 or rl_headers or blocked:
        return ok(f"实测连续 8 次请求 {url} 已触发限流保护"
                  f"（状态码序列：{statuses}）", probes=len(runs),
                  evidence_kind="限流行为实测")

    f = make_finding(
        "EXT-RB-01", "接口未实施速率限制",
        ctx.target_name, endpoint=url, method="GET",
        severity="中危", confidence="High", evidence_level="A",
        description=("对同一接口连续发出 8 次请求，全部被正常处理，"
                     "未出现 429 / 503，也没有任何 RateLimit 响应头，"
                     "说明该接口未做请求频率限制。"),
        technical_detail=(f"实测对象：{url}\n"
                          f"连续 8 次状态码：{statuses}\n"
                          f"各次耗时(ms)：{[r['elapsed_ms'] for r in runs]}"),
        impact=("① 可被脚本高频抓取，批量爬走页面上的公开或半公开数据；"
                "② 对登录、短信、下单类接口即构成暴力破解与资源滥用的前提；"
                "③ 单机高频请求即可挤占服务资源，造成可用性下降。"),
        reproduction=(f"for i in $(seq 1 8); do curl -s -o /dev/null -w '%{{http_code}} ' "
                      f"'{url}'; done; echo\n# 实测状态码序列：{statuses}（无 429）"),
        remediation=("① 按 IP + 账号双维度做令牌桶限流（普通接口 10~20 QPS，"
                     "登录 / 短信类接口按分钟级严格限制）；"
                     "② 返回标准 429 并带 Retry-After；"
                     "③ 网关层统一实施，避免各服务各写一套遗漏。"),
        compliance="等保2.0 安全计算环境-资源控制 / OWASP API4 资源无限制",
        evidence=[finding_evidence("response", json.dumps(runs, ensure_ascii=False),
                                   "连续请求实测结果")],
        grading_basis=(f"实测确认无限流（基线 HTTP {statuses[0]} 为应用正常响应，"
                       f"非边缘拦截码），构成暴力破解与资源滥用前提，定中危"),
    )
    return found(f"实测连续 8 次请求 {url} 均未被限流", [f], probes=len(runs),
                 evidence_kind="限流行为实测")


# ======================================================================
# EXT-RB-02 资源耗尽面（静态评估）
# ======================================================================
@make_auto("EXT-RB-02", name="资源耗尽面静态评估", tool="前端产物与接口参数静态分析",
           risk=RISK_SAFE, evidence_kind="静态特征分析",
           detector_ref="checks/extras4.py:rb02")
def rb02(ctx: DetectorContext):
    findings = []
    notes = []

    # ---- ① 分页 / 批量接口是否带无上限的分页参数 ----
    unbounded: list[str] = []
    params = extract_params(ctx)
    paging_keys = {"limit", "size", "pagesize", "page_size", "per_page", "perpage",
                   "rows", "count", "num", "length", "top", "offset"}
    for item in params:
        if str(item.get("param", "")).lower() in paging_keys:
            unbounded.append(f"{item['url']}  (参数 {item['param']})")
        if len(unbounded) >= 10:
            break
    if unbounded:
        notes.append(f"发现 {len(unbounded)} 处带分页参数接口")
        findings.append(make_finding(
            "EXT-RB-02", f"发现 {len(unbounded)} 处无上限分页参数接口",
            ctx.target_name, endpoint=unbounded[0].split("  ")[0],
            severity="低危", confidence="Low", evidence_level="B",
            description=("接口从前端产物中提取到 limit / size / pageSize 一类分页参数。"
                         "若服务端未对上限做硬性约束，可通过传入超大值一次性拉取全量数据，"
                         "造成数据库压力与数据批量外泄。"),
            technical_detail=("含分页参数的接口：\n" + "\n".join(
                f"  · {u}" for u in unbounded) +
                "\n\n说明：本项为静态识别，未实际发送超大分页请求（避免对生产库造成压力）。"
                "是否可被利用需在测试环境验证。"),
            impact=("① 单次请求即可拉取全量数据，绕过前端分页限制；"
                    "② 超大结果集会造成数据库慢查询与内存占用，影响可用性；"
                    "③ 常与越权组合，成为批量拖库的入口。"),
            reproduction=("# 测试环境验证（勿在生产执行）\n"
                          f"curl -s '{unbounded[0].split('  ')[0].replace('limit=', 'limit=1000000&x=')}'"),
            remediation=("① 服务端硬编码分页上限（如最大 200 条），超出直接拒绝；"
                         "② 大数据量导出走异步任务，不通过实时接口；"
                         "③ 对分页参数做类型与范围校验。"),
            compliance="OWASP API4 资源无限制 / 等保2.0 资源控制",
            evidence=[finding_evidence("static", "\n".join(unbounded), "分页参数识别")],
            grading_basis="静态识别到风险面，未实测可利用，定低危并标注置信度低",
        ))

    # ---- ② 首页 / 主要响应体量 ----
    body_len = len(ctx.baseline_body)
    if body_len > 800_000:
        notes.append(f"首页响应体量偏大（{body_len // 1024} KB）")
        findings.append(make_finding(
            "EXT-RB-02", f"首页响应体量偏大（{body_len // 1024} KB）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="低危", confidence="Medium", evidence_level="A",
            description=("单个页面响应体超过 800 KB，且未做分页或按需加载。"),
            technical_detail=f"首页 HTML 实际长度：{body_len} 字节",
            impact="并发访问时会显著放大带宽与内存消耗，是低成本的拒绝服务放大点。",
            reproduction=f"curl -s -o /dev/null -w '%{{size_download}}\\n' '{ctx.target_url}'",
            remediation="首页数据按需加载，列表分页返回，开启 gzip / br 压缩。",
            compliance="等保2.0 资源控制",
            evidence=[finding_evidence("response", f"body_length={body_len}", "响应体量")],
            grading_basis="实测响应体量偏大，构成资源消耗放大点，定低危",
        ))

    if findings:
        return found("；".join(notes) + "（静态评估，未对生产环境施加压力）",
                     findings, probes=1, evidence_kind="静态特征分析")
    return ok("静态评估未发现明显的资源耗尽放大面"
              "（无无上限分页参数、响应体量正常）", probes=1,
              evidence_kind="静态特征分析")


# ======================================================================
# EXT-RB-03 敏感操作缺少人机校验
# ======================================================================
@make_auto("EXT-RB-03", name="敏感操作人机校验核查", tool="页面与脚本特征分析",
           risk=RISK_SAFE, evidence_kind="前端与接口特征分析",
           detector_ref="checks/extras4.py:rb03")
def rb03(ctx: DetectorContext):
    blobs = [ctx.baseline_body] + list(ctx.js_result.get("bodies") or [])[:40]
    text = "\n".join(b for b in blobs if b)
    verify_hits = [p for p in HUMAN_VERIFY_SIGNALS if re.search(p, text, re.I)]

    # 找出敏感操作入口
    forms = find_forms(ctx)
    sensitive_forms = []
    for fm in forms:
        hay = (fm.get("action", "") + " " + " ".join(fm.get("inputs", []))).lower()
        if any(h in hay for h in SENSITIVE_OP_HINTS):
            sensitive_forms.append(fm)
    urls = [u for u in (ctx.js_result.get("urls") or [])[:400] if isinstance(u, str)]
    sensitive_urls = [u for u in urls if any(h in u.lower() for h in SENSITIVE_OP_HINTS)][:15]

    if not sensitive_forms and not sensitive_urls:
        return ok("未在对外内容中识别到注册 / 登录 / 找回密码 / 下单类敏感操作入口，"
                  "本项无可测对象（若系统存在需登录后访问的敏感操作，请人工核查）",
                  probes=1, evidence_kind="前端与接口特征分析")

    if verify_hits:
        return ok(f"识别到敏感操作入口 {len(sensitive_forms) + len(sensitive_urls)} 处，"
                  f"页面 / 脚本中存在人机校验组件痕迹"
                  f"（{'、'.join(verify_hits[:5])}）", probes=1,
                  evidence_kind="前端与接口特征分析")

    f = make_finding(
        "EXT-RB-03", "敏感操作入口未发现人机校验",
        ctx.target_name,
        endpoint=sensitive_forms[0]["page"] if sensitive_forms else ctx.target_url,
        severity="中危", confidence="Medium", evidence_level="B",
        description=("识别到注册 / 登录 / 找回密码 / 短信验证码一类敏感操作入口，"
                     "但在页面与前端脚本中均未发现验证码、滑块、人机校验组件的痕迹。"),
        technical_detail=("识别到的敏感操作入口：\n"
                          + "\n".join(f"  · 表单：{fm['page']} → {fm['action']}"
                                      for fm in sensitive_forms[:8])
                          + "\n".join(f"  · 接口：{u}" for u in sensitive_urls[:8])),
        impact=("① 无验证码的注册 / 登录接口可被脚本批量撞库；"
                "② 短信验证码接口无校验时可被用来刷短信（直接产生费用）；"
                "③ 找回密码流程无校验时可被批量枚举账号有效性。"),
        reproduction=("打开登录 / 注册页，检查是否存在验证码或滑块；"
                      "或用 curl 连续提交表单，观察是否出现验证码拦截"),
        remediation=("① 登录、注册、找回密码、短信验证码四类接口必须接入人机校验；"
                     "② 校验放在服务端完成，前端只为交互提示；"
                     "③ 叠加设备指纹与行为风控，对异常来源直接挑战。"),
        compliance="等保2.0 安全计算环境-身份鉴别 / OWASP API4",
        evidence=[finding_evidence("static",
                                   json.dumps({"forms": [f["page"] for f in sensitive_forms][:8],
                                               "urls": sensitive_urls},
                                              ensure_ascii=False),
                                   "敏感操作入口识别")],
        grading_basis="静态识别到敏感操作入口且未发现校验组件，需登录后实测确认，定中危并标注证据等级 B",
    )
    return found(f"识别到敏感操作入口 {len(sensitive_forms) + len(sensitive_urls)} 处，"
                 f"未发现人机校验痕迹", [f], probes=1,
                 evidence_kind="前端与接口特征分析")


# ======================================================================
# EXT-RB-04 短信与邮件轰炸面
# ======================================================================
@make_auto("EXT-RB-04", name="短信 / 邮件发送接口暴露面识别",
           tool="前端产物与表单参数分析", risk=RISK_SAFE,
           evidence_kind="静态参数识别",
           detector_ref="checks/extras4.py:rb04")
def rb04(ctx: DetectorContext):
    findings: list[str] = []
    params = extract_params(ctx)
    for item in params:
        if str(item.get("param", "")).lower() in BOMB_PARAM_HINTS:
            findings.append(f"接口 {item['url']}  (参数 {item['param']}，来源 {item['source']})")

    for fm in find_forms(ctx):
        hay = (fm.get("action", "") + " " + " ".join(fm.get("inputs", []))).lower()
        if any(h in hay for h in BOMB_PARAM_HINTS):
            findings.append(f"表单 {fm['action']}  (字段 {', '.join(fm.get('inputs', [])[:6])})")

    send_like = [u for u in (ctx.js_result.get("urls") or [])[:400]
                 if isinstance(u, str)
                 and re.search(r"(?:send|sms|email|mail|code|captcha|verify)", u, re.I)]
    for u in send_like[:10]:
        findings.append(f"疑似发送类接口 {u}")

    findings = list(dict.fromkeys(findings))
    if not findings:
        return ok("未在对外内容中识别到短信 / 邮件发送相关接口与参数", probes=1,
                  evidence_kind="静态参数识别")

    f = make_finding(
        "EXT-RB-04", f"识别到 {len(findings)} 处短信 / 邮件发送相关接口与参数",
        ctx.target_name, endpoint=ctx.target_url,
        severity="中危", confidence="Low", evidence_level="B",
        description=("公开可达的接口中存在 mobile / phone / email / sms / code 一类参数，"
                     "或存在发送类接口路径。若服务端未对发送频率、"
                     "接收方与请求来源做绑定，可被用来对任意号码发起短信 / 邮件轰炸。"),
        technical_detail=("命中清单：\n" + "\n".join(f"  · {x}" for x in findings[:20]) +
                          "\n\n重要说明：**本次检测未实际发送任何短信或邮件**。"
                          "本项为暴露面静态识别，是否可被滥用需在获得明确授权后"
                          "用测试号码验证。"),
        impact=("① 可对任意手机号批量发送验证码短信，直接产生短信费用，"
                "并可能因投诉导致短信通道被停用；"
                "② 可用来骚扰特定对象或对竞品客户群发骚扰信息；"
                "③ 骚扰行为以贵司名义发出，属于品牌与合规双重风险。"),
        reproduction=("1) 抓取一次正常的「获取验证码」请求；\n"
                      "2) 仅替换手机号字段，观察是否仍能成功（需授权 + 测试号码）；\n"
                      "3) 连续请求 10 次，观察是否出现频率限制。"),
        remediation=("① 发送接口必须做到「手机号 + 图形验证码 + 单号码每分钟 1 条 + "
                     "单 IP 每小时 N 条」四重约束；"
                     "② 验证码 5 分钟失效、同号码同场景每日上限；"
                     "③ 短信通道侧配置异常发送量告警与自动熔断。"),
        compliance="等保2.0 安全计算环境-资源控制 / 反电信网络诈骗法第 21 条",
        evidence=[finding_evidence("static", "\n".join(findings[:30]), "发送类接口识别")],
        grading_basis="静态识别到发送面，未实际验证滥用可行性，定中危并标注置信度低",
    )
    return found(f"识别到短信 / 邮件发送相关接口与参数 {len(findings)} 处"
                 f"（未实际发送任何消息）", [f], probes=1, evidence_kind="静态参数识别")


# ======================================================================
# EXT-RB-05 锁定机制可被反向利用 —— 人工
# ======================================================================
SPEC_RB05 = make_manual(
    "EXT-RB-05",
    name="账号锁定机制反向滥用人工核查",
    procedure=(
        "1) 用测试账号在登录页连续输错密码，记录：第几次被锁、锁多久、"
        "   是否提示「已锁定」还是「密码错误」。\n"
        "2) 关键判断：锁定是「按账号」还是「按账号 + 来源 IP」。"
        "   若仅按账号锁定 —— 攻击者只需知道用户名，就能故意输错密码"
        "   把真实用户锁在门外（拒绝服务）。\n"
        "3) 验证方式：换一台机器 / 换一个来源 IP，用同一个被锁账号再试 —— "
        "   如果仍然被锁且提示必须等待，说明存在该风险。\n"
        "4) 检查是否存在解锁自助通道（邮件 / 短信重置），"
        "   以及锁定期间管理员是否有解锁入口。\n"
        "5) 顺便确认锁定是否按账号维度枚举泄露："
        "   输错不存在的账号 vs 存在的账号，返回提示是否不同（账号枚举）。"
    ),
    expect=("仅按账号锁定、且无自助解锁通道 → 不通过（可被用来锁定真实用户）；"
            "按账号 + 来源 IP 组合锁定，或锁定时间很短且有自助解锁 → 通过。"),
    why_manual=("锁定机制必须真实触发才能观察，而自动化触发会把测试账号"
                "（甚至误操作命中真实账号）锁死，副作用不可控，"
                "因此不在自动检测范围内。"),
    risk=RISK_DEEP,
)


# ======================================================================
# EXT-DP-06 图片元数据地理位置泄露
#
# 2026-10-10 新增：靶场答案表把 Meta Geo Stalking 判为「能力缺口」——
#全量检查项扫的全是 HTML / JS / 接口响应，从来没有一项去看**对外发布的图片文件
# 本身**。而照片的 EXIF 里可能直接带着拍摄地的 GPS 坐标。
#
# 三条硬约束：
#   ① 零外部依赖（不调 exiftool），本地解析 JPEG APP1/EXIF；
#   ② **只报「存在坐标及精度」，不输出真实经纬度** —— 坐标属于个人信息，
#      扫描器不该在报告里复制一份（与 EXT-AI-05「不导出真实 PII」同一口径）；
#   ③ 只下载对外可访问的图片，不遍历、不大批量抓取（上限 6 张）。
# ======================================================================
def _jpeg_exif_gps(data: bytes) -> dict[str, int] | None:
    """解析 JPEG 的 EXIF，只看 GPS IFD 是否存在及其精度。

    返回 {"lat_digits": n, "lon_digits": n, "has_time": 0/1}；
    没有 GPS 返回 None。**不返回坐标值。**
    """
    if len(data) < 12 or data[:2] != b"\xff\xd8":
        return None
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7 or marker == 0xD9:
            i += 2
            continue
        if marker in (0xDA, 0xD9):
            break
        seglen = int.from_bytes(data[i + 2:i + 4], "big")
        if seglen < 2:
            break
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return _tiff_gps(data[i + 10:i + 2 + seglen])
        i += 2 + seglen
    return None


def _tiff_gps(blob: bytes) -> dict[str, int] | None:
    if len(blob) < 8:
        return None
    bo = "<" if blob[:2] == b"II" else (">" if blob[:2] == b"MM" else None)
    if bo is None:
        return None
    try:
        if0 = int.from_bytes(blob[4:8], "little" if bo == "<" else "big")
        gps_off = None
        for e in _ifd_entries(blob, bo, if0):
            if e[0] == 0x8825:          # GPSInfo IFD
                gps_off = e[1]
                break
        if gps_off is None:
            return None
        tags: dict[int, tuple[int, int]] = {}
        for tag, val_off in _ifd_entries(blob, bo, gps_off):
            tags[tag] = (val_off, 0)
        lat = tags.get(2)
        lon = tags.get(4)
        if lat is None or lon is None:
            return None
        return {
            "lat_digits": _rational_digits(blob, bo, lat[0]),
            "lon_digits": _rational_digits(blob, bo, lon[0]),
            "has_time": 0,
        }
    except Exception:  # noqa: BLE001
        return None


def _ifd_entries(blob: bytes, bo: str, off: int):
    """遍历一个 IFD，产出 (tag, value_or_offset)。越界即停。"""
    if off + 2 > len(blob):
        return
    n = int.from_bytes(blob[off:off + 2], "little" if bo == "<" else "big")
    for k in range(min(n, 256)):
        base = off + 2 + k * 12
        if base + 12 > len(blob):
            return
        tag = int.from_bytes(blob[base:base + 2], "little" if bo == "<" else "big")
        val = int.from_bytes(blob[base + 8:base + 12], "little" if bo == "<" else "big")
        yield tag, val


def _rational_digits(blob: bytes, bo: str, off: int) -> int:
    """读第一个有理数的分母位数 —— 用它表示精度，不读数值本身。"""
    try:
        den = int.from_bytes(blob[off + 4:off + 8], "little" if bo == "<" else "big")
    except Exception:  # noqa: BLE001
        return 0
    if den <= 0:
        return 0
    return len(str(den)) - 1


def _image_urls(ctx: DetectorContext) -> list[str]:
    html = "\n".join([
        ctx.baseline_body or "",
        str((ctx.fp_result or {}).get("_render_html") or "")[:400_000],
    ])
    out: list[str] = []
    seen: set[str] = set()
    for pat in (r'<img[^>]+src\s*=\s*["\']([^"\']+)["\']',
                r'<source[^>]+srcset\s*=\s*["\']([^"\']+)["\']',
                r'url\(\s*["\']?([^"\')]+\.(?:jpe?g|png))["\']?\s*\)'):
        for m in re.finditer(pat, html, re.I):
            raw = m.group(1).split(",")[0].strip().split(" ")[0]
            if not raw or raw.startswith("data:"):
                continue
            u = urljoin(ctx.target_url, raw)
            if not u.startswith(("http://", "https://")):
                continue
            if not re.search(r"\.(jpe?g)(?:[?#]|$)", u, re.I):
                continue
            if u not in seen:
                seen.add(u)
                out.append(u)
    # ③ 接口响应里的图片清单。
    #
    #    前后端分离的系统，图片几乎不在 HTML 里 —— 它们在**接口响应**里。
    #    只扫 HTML 的结果是：站点上确实挂着一批用户上传的照片，而我们一张都没看到，
    #    note 写「检查 6 张，未发现」，读者会以为**看过了**。
    #    （第 21 轮实测：靶场带 GPS 的照片只在 `/rest/memories` 的响应里出现，
    #    入口页一个 `<img>` 都没有。）
    #    代价是每个候选接口一次 GET，所以只挑「名字像相册 / 上传」的那几个，
    #    一个都不像时退一步取前几个接口 —— 不盲扫全部。
    try:
        from engine.checks.base import js_api_paths as _js_api  # noqa: PLC0415
        all_api = _js_api(ctx)
    except Exception:  # noqa: BLE001
        all_api = []
    _albumish = re.compile(
        r"(upload|memory|memories|photo|album|gallery|image|media|attachment|file)",
        re.I)
    picked = [u for u in all_api if _albumish.search(u)][:6] or list(all_api)[:6]
    for api_u in picked:
        try:
            pr = ctx.get(api_u)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if not body or len(body) > 400_000:
            continue
        for m in re.finditer(r"""["']([^"'\s]{4,300}?\.(?:jpe?g))["']""",
                             body, re.I):
            raw = m.group(1).strip()
            if raw.startswith("data:"):
                continue
            u = urljoin(ctx.target_url, raw)
            if re.search(r"\.(jpe?g)(?:[?#]|$)", u, re.I) and u not in seen:
                seen.add(u)
                out.append(u)

    #  candidates 排序：用户上传目录优先 —— 那里才有 EXIF；
    #  站点自己的 UI 切图基本都被构建流程剥过一遍，查它多半是白跑。
    out.sort(key=lambda x: (0 if re.search(r"(upload|user|avatar|photo|album)", x, re.I) else 1,))
    return out


@make_auto("EXT-DP-06", name="图片元数据地理位置泄露核查", tool="图片下载 + 本地 EXIF 解析",
           risk=RISK_SAFE, evidence_kind="EXIF 实测",
           detector_ref="checks/extras4.py:dp06")
def dp06(ctx: DetectorContext):
    urls = _image_urls(ctx)[:6]
    if not urls:
        # 零探测不许判「通过」（红线 1）。没素材有两种成因，处置完全不同：
        # 采集通道不完整 → 待确认；确实没有 JPEG 对外发布 → N/A。
        # 统一走 no_target_outcome，不在这里自造第三种结论。
        return no_target_outcome(ctx, "对外发布的 JPEG 图片资源",
                                 probes=0, evidence_kind="EXIF 实测")

    hits: list[tuple[str, dict[str, int]]] = []
    probes = 0
    for u in urls:
        try:
            if hasattr(ctx._client, "_throttle"):
                ctx._client._throttle()
            r = requests.get(u, timeout=getattr(ctx._client, "timeout", 10),
                             verify=False,
                             headers=dict(getattr(ctx._client, "session").headers))
        except Exception:  # noqa: BLE001
            continue
        probes += 1
        if getattr(r, "status_code", 0) != 200:
            continue
        data = getattr(r, "content", b"") or b""
        if len(data) > 4_000_000:
            data = data[:4_000_000]
        g = _jpeg_exif_gps(data)
        if g:
            hits.append((u, g))

    findings = []
    if hits:
        worst = max(h["lat_digits"] for _, h in hits)
        findings.append(make_finding(
            "EXT-DP-06", f"{len(hits)} 张对外发布的图片残留 EXIF 地理位置",
            ctx.target_name, endpoint=hits[0][0],
            severity="中危", confidence="High", evidence_level="A",
            description=("站点对外提供的 JPEG 图片中保留了拍摄时的 EXIF 元数据，"
                         "其中包含 GPS 坐标。任何下载该图片的人都能还原拍摄地点。"
                         "为避免二次泄露，本报告**不记录真实经纬度**，只记录存在性与精度。"),
            technical_detail=("命中图片：\n" + "\n".join(
                f"  · {u}\n    坐标精度约 {h['lat_digits']} 位小数（纬/经各 3 个有理数）"
                for u, h in hits)
                + f"\n最高精度：约 {worst} 位小数"
                + "\n（坐标值未导出；复现时请在本地用 exiftool 自行查看）"),
            impact=("员工在办公地、仓库、门店或住所拍摄并上传的手机照片，"
                    "会把这些地点直接暴露给外部；"
                    "若图片中是特定人物，可进一步还原其行踪与常去场所，"
                    "构成对个人的跟踪风险，也泄露了公司内部场所位置。"),
            reproduction=(f"curl -s '{hits[0][0]}' -o a.jpg && exiftool a.jpg | grep -i gps\n"
                          "（或用任意在线 EXIF 查看器上传该图片）"),
            remediation=("① 上传/发布链路统一剥离 EXIF（服务端处理，不能只靠前端）；"
                         "② 图片走 CDN 时可开启自动元数据剥离；"
                         "③ 移动端拍摄上传默认关闭位置写入；"
                         "④ 已发布的存量图片批量清洗一次。"),
            compliance="PIPL 第 6 条 / GB/T 35273 个人信息安全规范",
            evidence=[finding_evidence("file", str([u for u, _ in hits]), "含 GPS 的图片地址")],
            grading_basis="本地解析确证 EXIF 中存在 GPS IFD，按 A 级定中危",
        ))

    note = (f"下载并检查 {probes} 张图片（候选 {len(urls)} 张），"
            f"{'其中 ' + str(len(hits)) + ' 张含 GPS 坐标' if hits else '未发现 GPS 坐标'}")
    return found(note, findings, probes=probes, evidence_kind="EXIF 实测")
