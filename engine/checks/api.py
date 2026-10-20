# -*- coding: utf-8 -*-
"""
WSTG-APIT API 测试（5 项）+ WSTG-WASM WebAssembly（1 项）
========================================================
前后端分离的系统，真正的攻击面几乎全在 API 上。这一类里有三件事必须做对：

  ① API 清单要先摸全——文档泄露、前端产物里的路径、版本枚举；
  ② 对象级授权（BOLA）与功能级授权（BFLA）必须多账号交叉验证，不能靠扫描；
  ③ 过度数据暴露（返回了不该返回的字段）可以在匿名视角下判定，
     而且这类问题非常常见，且直接等同个人信息泄露。
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from engine.checks.base import (
    API_DOC_PATHS, PII_PATTERNS, extract_params, finding_evidence, is_real_hit, ok,
    found, js_api_paths, probe_or_none, scan_paths, sitewide_guard,
    no_target_outcome, reachability_scope,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)


def _api_endpoints(ctx: DetectorContext) -> list[str]:
    """汇总所有已知的 API 形态端点。"""
    eps: set[str] = set()
    for u in (ctx.js_result.get("urls") or [])[:400]:
        if isinstance(u, str) and re.search(r"/(api|v\d|rest|graphql|rpc|services)/", u, re.I):
            full = urljoin(ctx.target_url, u)
            if ctx.domain in full:
                eps.add(full)
    for p, pr in (ctx.fp_result.get("path_probes") or {}).items():
        if isinstance(pr, dict) and pr.get("status") in (200, 401, 403) \
                and re.search(r"(api|v\d|graphql|rest)", p, re.I):
            eps.add(pr.get("final_url") or urljoin(ctx.target_url, p))
    for e in (ctx._cache.get("info06_api_like") or []):
        eps.add(e if str(e).startswith("http") else urljoin(ctx.target_url, str(e).lstrip("/")))
    # 接口文档声明的只读接口 —— 目标自己写清楚的接口清单，比正则提取可靠。
    for e in (ctx._cache.get("spec_api_like") or []):
        eps.add(e if str(e).startswith("http") else urljoin(ctx.target_url, str(e).lstrip("/")))
    # 前端打包产物里的接口字面量 —— 文档可能是假的（或干脆没有），
    # 但打包产物里出现的路径是前端真的会去请求的地址。这一路与文档互补。
    for e in js_api_paths(ctx):
        eps.add(e if str(e).startswith("http") else urljoin(ctx.target_url, str(e).lstrip("/")))
    return sorted({e for e in eps if isinstance(e, str) and e.startswith("http")})


def ensure_spec(ctx: DetectorContext) -> Any:
    """发现并解析目标上的接口文档（幂等，结果缓存在 ctx 里）。

    ⚠ 这个函数存在的唯一理由，是修一个「存在却没人调用」的洞：

      `engine/openapi.py` 写了完整的发现 + 解析逻辑，但 2026-10-12 之前
      **全代码库没有任何一处调用 `discover()`** —— `apit01` 只读
      `cached_result(ctx)`，而没有谁往缓存里写过，于是它恒为 None。

      后果是报告上写着「接口文档可达」这条中危发现，而文档里的接口与
      参数一条都没进枚举池：目标把全部接口、参数名、必填项写在文档里
      递过来，我们却只记了一句「文档能开」。接口类检查（越权 / 注入 /
      参数遍历）的起点是接口清单，这一环空着，覆盖率就永远差一截。

    副作用：最多发 `MAX_SPEC_PROBES` 个 GET 请求（默认 5）。
    任何异常都不许冒出去 —— 接口文档是**锦上添花**，不是主流程。
    """
    cached = None
    try:
        cached = ctx._cache.get("openapi_spec")
    except Exception:  # noqa: BLE001
        cached = None
    if cached is not None:
        return cached
    try:
        from engine import openapi as _oa  # noqa: PLC0415
        return _oa.discover(ctx)
    except Exception as e:  # noqa: BLE001
        # 解析失败也必须落一条缓存，否则每个检查项都会重试一遍探测。
        try:
            # `_done` 是给 `discover()` 的免重探针标记 —— 少了它，
            # 每个检查项都会重跑一遍文档探测（都是 404 等待）。
            ctx._cache["openapi_spec"] = {
                "_done": True,
                "found": False, "parsed": False, "url": "",
                "reason": f"接口文档探测异常：{type(e).__name__}: {str(e)[:120]}",
                "probes": 0, "truncated": False, "notes": [],
            }
        except Exception:  # noqa: BLE001
            pass
        return None


def _absorb_spec(ctx: DetectorContext) -> Any:
    """把已解析的接口清单并进「API 形态端点」缓存，供越权 / 注入类检查使用。

    只读接口进 URL 枚举池；**带请求体的写接口不进**（红线：只读），
    它们另外登记在 `spec_write_targets` 里，供受控写检查按需取用。
    """
    res = ensure_spec(ctx)
    if res is None:
        return None
    found = bool(getattr(res, "found", False)) or bool(
        res.get("found") if isinstance(res, dict) else False)
    parsed = bool(getattr(res, "parsed", False)) or bool(
        res.get("parsed") if isinstance(res, dict) else False)
    if not (found and parsed):
        return res

    read_paths = getattr(res, "read_paths", None)
    if read_paths is None and isinstance(res, dict):
        read_paths = res.get("read_paths") or []
    base = ctx.target_url.rstrip("/")
    eps = ctx._cache.get("spec_api_like") or []
    for p in read_paths or []:
        u = p if str(p).startswith("http") else (base + "/" + str(p).lstrip("/"))
        if u not in eps:
            eps.append(u)
    ctx._cache["spec_api_like"] = eps

    # 写接口登记：url / method / 字段名 / 必填 / 样例
    eps_w = getattr(res, "write_endpoints", None)
    if eps_w is None and isinstance(res, dict):
        eps_w = res.get("write_endpoints") or []
    wr = ctx._cache.get("spec_write_targets") or []
    for e in eps_w or []:
        url = e.url_path if hasattr(e, "url_path") else str(e.get("url_path", ""))
        method = e.method if hasattr(e, "method") else str(e.get("method", "POST"))
        names = list(e.body_params) if hasattr(e, "body_params") else list(e.get("body_params") or [])
        req = list(e.body_required) if hasattr(e, "body_required") else list(e.get("body_required") or [])
        ex = dict(e.body_example) if hasattr(e, "body_example") else dict(e.get("body_example") or {})
        if not names:
            continue
        full = url if str(url).startswith("http") else (base + "/" + str(url).lstrip("/"))
        wr.append({"url": full, "method": method, "fields": names,
                   "required": req, "example": ex})
    ctx._cache["spec_write_targets"] = wr
    return res


# ======================================================================
# WSTG-APIT-01 API 侦察
# ======================================================================
@make_auto("WSTG-APIT-01", name="API 侦察与文档暴露核查", tool="内置检测器 + JS 分析",
           risk=RISK_STANDARD, evidence_kind="接口清单与文档实测",
           detector_ref="checks/api.py:apit01")
def apit01(ctx: DetectorContext):
    findings = []
    probes = 0

    # 1) 接口文档
    doc_hits = scan_paths(ctx, API_DOC_PATHS)
    probes += len(API_DOC_PATHS)
    ctx._cache["apit_doc_hits"] = list(doc_hits)

    # 2) 接口文档解析 —— 真正去发现并解析，并把接口并进枚举面
    try:
        _absorb_spec(ctx)
    except Exception as e:  # noqa: BLE001
        ctx.note(f"[接口文档] 解析异常（已捕获，未中断）："
                 f"{type(e).__name__}: {str(e)[:120]}")
    try:
        from engine import openapi as _oa  # noqa: PLC0415
        _sp = _oa.cached_result(ctx)
        if _sp is not None:
            probes += int(getattr(_sp, "probes", 0) or 0)
    except Exception:  # noqa: BLE001
        pass

    # 3) 前端产物里的接口清单
    eps = _api_endpoints(ctx)
    ctx._cache["apit_endpoints"] = eps

    # 3) 接口版本枚举
    versions = []
    for v in ("v1", "v2", "v3", "internal", "beta", "test", "dev"):
        for base in ("api", "service"):
            pr = probe_or_none(ctx, f"{base}/{v}")
            probes += 1
            if pr is not None and getattr(pr, "status", 0) in (200, 401, 403):
                versions.append(f"/{base}/{v}")

    if doc_hits:
        detail = ", ".join(f"/{p}" for p in sorted(doc_hits)[:10])
        scope, _, scope_why = reachability_scope(ctx)
        # 把「文档里到底有什么」写进技术细节：只写「文档可访问」的话，
        # 这份发现的分量全靠读者想象；而文档的接口数 / 参数名数是**实测数字**，
        # 也是后续接口类检查（越权、注入、参数遍历）真正的输入。
        spec_line = ""
        try:
            from engine import openapi as _oa  # noqa: PLC0415
            _sp = _oa.cached_result(ctx)
            if _sp is not None and _sp.parsed:
                spec_line = ("\n" + _sp.summary()
                             + f"\n其中参数名：{'、'.join(_sp.param_names[:20])}"
                             + ("（已截断）" if len(_sp.param_names) > 20 else "")
                             + f"\n已按文档把 {len(_sp.read_paths)} 个只读接口并入 URL 枚举池")
            elif _sp is not None:
                # 文档可达但没解开 —— 这是**覆盖度缺口**，不是「文档里没有接口」。
                spec_line = f"\n{_sp.summary()}"
        except Exception:  # noqa: BLE001
            spec_line = ""
        findings.append(make_finding(
            "WSTG-APIT-01",
            (f"接口文档对外可达（{len(doc_hits)} 处）" if scope == "公网可达"
             else f"内网可见（非公网暴露）：接口文档（{len(doc_hits)} 处）"),
            ctx.target_name,
            endpoint=getattr(doc_hits[list(doc_hits)[0]], "final_url", "")
            or urljoin(ctx.target_url, list(doc_hits)[0]),
            severity="中危", confidence="High", evidence_level="A",
            description=("Swagger / OpenAPI 文档可以直接打开，"
                         "里面列出了系统的全部接口、参数名、数据类型与必填项。"
                         + ("" if scope == "公网可达" else
                            f"目标可达范围为「{scope}」，本条不计入公网风险。")),
            technical_detail=f"可访问的文档地址：\n{detail}\n\n"
                             f"从前端产物提取到的接口地址 {len(eps)} 个。\n"
                             f"可达性判定：{scope}\n判定依据：{scope_why}{spec_line}",
            impact=("攻击者不需要做任何接口探测，直接按文档构造请求即可。"
                    "这是接口类漏洞（越权、批量赋值、注入、参数遍历）最高效的起点，"
                    "也是很多数据泄露事件的第一个跳板。"),
            reproduction=f"浏览器直接访问 {urljoin(ctx.target_url, list(doc_hits)[0])}",
            remediation=("① 生产环境关闭接口文档（Springdoc 设 "
                         "`springdoc.api-docs.enabled=false`、`springdoc.swagger-ui.enabled=false`）；"
                         "② 确需保留时加鉴权 + IP 白名单；"
                         "③ 接口文档按环境隔离，不随生产包发布。"),
            compliance="等保2.0 安全计算环境-入侵防范",
            evidence=[finding_evidence("response", detail, "接口文档地址")],
            grading_basis="文档实测可直接访问，接口面完全暴露，定中危",
        ))

    if versions:
        findings.append(make_finding(
            "WSTG-APIT-01", f"接口版本与内部前缀暴露（{len(versions)} 个）",
            ctx.target_name, endpoint=urljoin(ctx.target_url, versions[0]),
            severity="低危", confidence="High", evidence_level="A",
            description=("发现多个接口版本前缀，其中可能包含已废弃版本（历史版本常缺少后续安全修复）"
                         "或非公开的内部接口前缀。"),
            technical_detail="可达的接口前缀：\n" + "\n".join(f"  · {v}" for v in versions),
            impact=("旧版本接口往往缺失后续的鉴权修复，是越权与信息泄露的高发位置；"
                    "internal / beta / test 这类前缀通常意味着未做完备安全测试的接口。"),
            reproduction="\n".join(f"curl -sI {urljoin(ctx.target_url, v)}" for v in versions[:5]),
            remediation="下线已废弃的接口版本；内部接口不发布到公网入口；建立接口版本退役流程。",
            compliance="ISO 27001 A.8.20",
            evidence=[finding_evidence("response", str(versions), "接口前缀")],
            grading_basis="前缀可达属实测，具体风险需逐接口确认，定低危",
        ))

    # 打包产物那一路要**单独报数**：接口文档可能是假的（与真实接口面零重合），
    # 只报总数的话，「文档解析成功但一条真接口都没有」这种脱节看不出来。
    try:
        _js_n = len(js_api_paths(ctx))
    except Exception:  # noqa: BLE001
        _js_n = 0
    note = (f"接口文档命中 {len(doc_hits)} 个；前端产物提取接口 {len(eps)} 个"
            f"（其中打包产物字面量 {_js_n} 个）；"
            f"版本 / 内部前缀可达 {len(versions)} 个")
    return found(note, findings, probes=probes, evidence_kind="接口清单与文档实测")


# ======================================================================
# WSTG-APIT-02 API 对象级授权缺陷（BOLA）
# ======================================================================
@make_auto("WSTG-APIT-02", name="API 对象级授权检测（匿名分支 + 矩阵待人工）",
           tool="内置检测器", risk=RISK_STANDARD, evidence_kind="对象访问实测",
           detector_ref="checks/api.py:apit02")
def apit02(ctx: DetectorContext):
    findings = []
    probes = 0
    eps = ctx._cache.get("apit_endpoints") or _api_endpoints(ctx)
    object_eps = [e for e in eps if re.search(r"/\d+([/?]|$)|[?&](?:id|uid|userId|no)=[^&]+",
                                              e, re.I)][:12]

    # 匿名分支：直接请求带对象标识的接口，看是否无凭据返回数据
    anon_readable = []
    for ep in object_eps:
        probes += 1
        try:
            pr = ctx.get(ep)
        except Exception:  # noqa: BLE001
            continue
        if getattr(pr, "status", 0) != 200:
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if not body or len(body) < 30:
            continue
        if "application/json" in str(getattr(pr, "headers", {})).lower() or body.strip().startswith(("{", "[")):
            # 判断是否像业务对象
            if re.search(r"[\{\[]\s*\"", body) and re.search(
                    r'"(id|userId|orderId|name|mobile|phone|email|amount|status)"', body, re.I):
                anon_readable.append((ep, body[:300]))

    if anon_readable:
        ep, frag = anon_readable[0]
        findings.append(make_finding(
            "WSTG-APIT-02", f"API 对象接口无需凭据即可读取数据（{len(anon_readable)} 个）",
            ctx.target_name, endpoint=ep, method="GET",
            severity="高危", confidence="High", evidence_level="A",
            description=("该接口返回了完整的业务对象数据，且不需要任何登录凭据。"
                         "接口直接以对象标识作为参数，没有任何归属校验。"),
            technical_detail=(f"接口：{ep}\n响应片段（已脱敏）：\n{frag}\n\n"
                              "本轮为匿名视角。登录态下的水平越权（用 A 的账号读 B 的数据）"
                              "需按下方人工指引用 2 组账号交叉验证。"),
            impact=("匿名即可读取业务对象数据，通常意味着任何登录用户都能读取他人数据。"
                    "在真实事件中这类接口常被脚本批量遍历，"
                    "造成全量用户数据泄露（个人信息、订单、地址、金额）。"),
            reproduction=f"curl -s '{ep}' | head -20",
            remediation=("① 每个对象读取接口都校验「当前登录用户 == 资源所有者」；"
                         "② 校验逻辑集中在统一组件，避免逐个接口手写遗漏；"
                         "③ 对象标识用 UUID 只能提高遍历成本，不能替代归属校验；"
                         "④ 对枚举行为做频控与告警。"),
            compliance="等保2.0 安全计算环境-访问控制 / OWASP API1:2023",
            evidence=[finding_evidence("response", frag, "匿名可读对象接口")],
            grading_basis="实测匿名可读取业务对象数据，定高危",
        ))

    note = (f"API 对象类接口 {len(object_eps)} 个，匿名探测 {probes} 次，"
            f"{'确认无凭据可读' if findings else '未发现匿名可读'}"
            f"（登录态 BOLA 矩阵需 2 组账号人工验证）")
    return found(note, findings, probes=probes, evidence_kind="对象访问实测")


# ======================================================================
# WSTG-APIT-03 过度数据暴露
# ======================================================================
@make_auto("WSTG-APIT-03", name="API 响应过度数据暴露检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="响应字段实测",
           detector_ref="checks/api.py:apit03")
def apit03(ctx: DetectorContext):
    findings = []
    probes = 0
    eps = ctx._cache.get("apit_endpoints") or _api_endpoints(ctx)
    sample_eps = [e for e in eps if not re.search(r"/(login|logout|register|captcha)", e, re.I)][:10]
    if not sample_eps:
        sample_eps = [ctx.target_url]

    # 敏感字段名（接口不该返回的内部 / 个人字段）
    sensitive_fields = re.compile(
        r'"(password|passwd|pwd|passwordHash|salt|secret|token|accessToken|refreshToken|'
        r'apiKey|privateKey|idCard|idcard|idNumber|bankCard|bankAccount|mobile|phone|'
        r'email|address|birthday|realName|internalRemark|auditRemark|createBy|updateBy|'
        r'tenantId|orgId|deptId|isAdmin|roleId|permissionList|deleteFlag|version)"',
        re.I)

    exposed = []
    for ep in sample_eps:
        probes += 1
        try:
            pr = ctx.get(ep)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if not body or len(body) < 40:
            continue
        if not (body.strip().startswith(("{", "[")) or "application/json" in
                str(getattr(pr, "headers", {})).lower()):
            continue
        fields = sorted(set(m.group(1) for m in sensitive_fields.finditer(body)))
        # PII 实际值
        pii = [name for name, pat in PII_PATTERNS.items() if re.search(pat, body)]
        if fields or pii:
            exposed.append((ep, fields, pii, body[:400]))

    if exposed:
        ep, fields, pii, frag = exposed[0]
        has_pii = bool(pii)
        findings.append(make_finding(
            "WSTG-APIT-03", f"接口返回了超出必要的字段"
                            + (f"（含 {len(pii)} 类个人信息）" if has_pii else ""),
            ctx.target_name, endpoint=ep, method="GET",
            severity="高危" if has_pii else "中危",
            confidence="High", evidence_level="A",
            description=("接口响应中包含了前端展示并不需要、但具有敏感性的字段。"
                         "常见的成因是后端直接把数据库实体（Entity）序列化后返回，"
                         "而不是使用专门的响应对象（DTO）。"),
            technical_detail=(f"接口：{ep}\n"
                              f"返回的敏感字段名：{', '.join(fields[:20]) or '（无字段名命中）'}\n"
                              f"响应中出现的个人信息类型：{', '.join(pii) or '（无）'}\n"
                              f"响应片段（已脱敏）：\n{frag}"),
            impact=("① 个人信息泄露：手机号、身份证、银行卡、地址等直接暴露，"
                    "构成《个人信息保护法》意义上的个人信息泄露事件；"
                    "② 凭据泄露：passwordHash / salt 泄露后可离线爆破口令；"
                    "token 泄露可直接冒用身份；"
                    "③ 内部结构泄露：tenantId / deptId / deleteFlag / isAdmin "
                    "为越权与批量赋值提供字段线索。"),
            reproduction=f"curl -s '{ep}' | head -40",
            remediation=("① 使用专门的响应对象（DTO / VO），显式声明要返回的字段；"
                         "② 禁止直接序列化数据库实体返回前端；"
                         "③ 敏感字段统一脱敏（手机号中间四位、身份证仅留后四位）；"
                         "④ 口令哈希、盐值、令牌绝不进入任何接口响应；"
                         "⑤ 在序列化层配置全局排除规则（如 Jackson @JsonIgnore 白名单）。"),
            compliance="PIPL 第 51 条 / 等保2.0 安全计算环境-数据保密性",
            evidence=[finding_evidence("response", frag, "过度暴露的响应字段")],
            grading_basis=("实测响应含个人信息实际值，构成个人信息泄露，定高危"
                           if has_pii else "实测响应含敏感字段名，实际值需进一步确认，定中危"),
        ))

    note = (f"检测 {len(sample_eps)} 个接口的响应字段，"
            f"其中 {len(exposed)} 个存在过度暴露"
            + (f"；含个人信息实际值 {sum(1 for _, _, p, _ in exposed if p)} 个" if exposed else ""))
    return found(note, findings, probes=probes, evidence_kind="响应字段实测")


# ======================================================================
# WSTG-APIT-04 API 功能级授权缺陷（BFLA）
# ======================================================================
@make_auto("WSTG-APIT-04", name="API 功能级授权检测（匿名分支 + 矩阵待人工）",
           tool="内置检测器", risk=RISK_STANDARD, evidence_kind="功能接口实测",
           detector_ref="checks/api.py:apit04")
def apit04(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])

    # 从前端产物里挖管理类接口
    admin_eps: set[str] = set()
    for m in re.finditer(r"[\"']((?:https?://[^\"']*|/)[^\"']*"
                         r"(?:admin|manage|internal|system|config|export|delete|audit)"
                         r"[^\"']*)[\"']", blobs, re.I):
        u = m.group(1)
        if re.search(r"\.(js|css|png|jpg|svg|woff)", u, re.I):
            continue
        admin_eps.add(u if u.startswith("http") else urljoin(ctx.target_url, u.lstrip("/")))
    for p in ("api/admin/users", "api/admin/config", "api/system/info",
              "api/admin/export", "admin/api/users", "api/internal/tasks"):
        pr = probe_or_none(ctx, p)
        probes += 1
        if pr is not None and getattr(pr, "status", 0) in (200, 401, 403):
            admin_eps.add(getattr(pr, "final_url", "") or urljoin(ctx.target_url, p))

    anon = []
    for ep in sorted(admin_eps)[:14]:
        if ctx.domain not in ep or not ep.startswith("http"):
            continue
        probes += 1
        try:
            pr = ctx.get(ep)
        except Exception:  # noqa: BLE001
            continue
        if getattr(pr, "status", 0) == 200 and is_real_hit(ctx, pr, min_len=40):
            body = getattr(pr, "body_snippet", "") or ""
            if re.search(r'[\{\[]\s*"|<\w+>', body) and re.search(
                    r"(user|role|config|list|total|data|admin)", body, re.I):
                anon.append((ep, body[:300]))

    if anon:
        ep, frag = anon[0]
        findings.append(make_finding(
            "WSTG-APIT-04", f"管理类 API 无需凭据即可访问（{len(anon)} 个）",
            ctx.target_name, endpoint=ep, method="GET",
            severity="严重", confidence="High", evidence_level="A",
            description=("该接口从路径看属于管理 / 系统功能，但不需要任何凭据就返回了数据。"
                         "功能级授权（按角色限制可调用的接口）没有生效。"),
            technical_detail=(f"接口：{ep}\n响应片段（已脱敏）：\n{frag}\n\n"
                              "本轮为匿名视角；普通用户账号调用管理接口的情况需人工按矩阵验证。"),
            impact=("可读取管理端数据（用户清单、系统配置、审计日志），"
                    "若同时存在写接口，则可直接修改配置、创建高权限账号。"
                    "这类漏洞的危害等同系统被接管，通常直接影响全量数据。"),
            reproduction=f"curl -s '{ep}' | head -30",
            remediation=("① 每个接口声明所需角色 / 权限，在统一拦截器中强制校验；"
                         "② 权限校验按「接口 + 角色」白名单，默认拒绝；"
                         "③ 管理类接口与业务接口分域名 / 分网关部署，"
                         "管理网关不暴露公网；"
                         "④ 前端隐藏菜单不作为授权手段。"),
            compliance="等保2.0 安全计算环境-访问控制 / OWASP API5:2023",
            evidence=[finding_evidence("response", frag, "匿名可达的管理接口")],
            grading_basis="实测匿名可达管理功能接口并返回数据，定严重",
        ))

    note = (f"从前端产物识别管理类接口 {len(admin_eps)} 个，匿名探测 {probes} 次，"
            f"{'确认无凭据可达' if findings else '未发现匿名可达的管理接口'}"
            f"（普通用户越权调用需人工矩阵验证）")
    return found(note, findings, probes=probes, evidence_kind="功能接口实测")


# ======================================================================
# WSTG-APIT-99 GraphQL 测试
# ======================================================================
@make_auto("WSTG-APIT-99", name="GraphQL 安全性测试", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="GraphQL 内省实测",
           detector_ref="checks/api.py:apit99")
def apit99(ctx: DetectorContext):
    import requests

    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    candidates = set()
    for m in re.finditer(r"[\"']((?:https?://[^\"']*|/)[^\"']*graphql[^\"']*)[\"']", blobs, re.I):
        candidates.add(m.group(1))
    # 整站同码时，405 / 400 这类状态码不构成「端点存在」的证据：
    # 边缘防护对全站返回 405 会让每个候选路径都被误判成 GraphQL 端点。
    _modal, _ratio, _n = sitewide_guard(ctx)
    for p in ("graphql", "api/graphql", "v1/graphql", "graph", "query"):
        pr = probe_or_none(ctx, p)
        if pr is None:
            continue
        _st = getattr(pr, "status", 0)
        if _modal and _st == _modal:
            continue
        if _st in (200, 400, 405):
            candidates.add(urljoin(ctx.target_url, p))

    if not candidates:
        return no_target_outcome(ctx, "GraphQL 端点", probes=6, evidence_kind="GraphQL 端点探测")

    endpoints = sorted(candidates)[:5]
    introspection = {"query": "query{__schema{types{name kind fields{name type{name kind}}}}}"}
    probes = 0
    findings = []
    for ep in endpoints:
        url = ep if str(ep).startswith("http") else urljoin(ctx.target_url, str(ep).lstrip("/"))
        if ctx.domain not in url:
            continue
        probes += 1
        try:
            ctx._client._throttle()
            r = requests.post(url, json=introspection, timeout=ctx._client.timeout,
                              verify=False, allow_redirects=False,
                              headers={**dict(ctx._client.session.headers),
                                       "Content-Type": "application/json"})
            body = r.text or ""
        except Exception:  # noqa: BLE001
            continue
        if "__schema" in body and '"types"' in body:
            types = set(re.findall(r'"name"\s*:\s*"([A-Za-z_]\w*)"', body))
            sensitive_types = sorted(t for t in types
                                     if re.search(r"(User|Admin|Role|Permission|Token|"
                                                  r"Credential|Secret|Account|Payment|Order)",
                                                  t, re.I))
            scope, _, scope_why = reachability_scope(ctx)
            findings.append(make_finding(
                "WSTG-APIT-99",
                ("GraphQL 内省（Introspection）对外开放" if scope == "公网可达"
                 else f"内网可见（非公网暴露）：GraphQL 内省（Introspection）"),
                ctx.target_name, endpoint=url, method="POST",
                severity="中危", confidence="High", evidence_level="A",
                description=("GraphQL 的内省查询处于开启状态，"
                             "任何人不经认证就能拉取完整的类型系统定义，"
                             "包括所有查询、变更、字段与参数类型。"
                             + ("" if scope == "公网可达" else
                                f"目标可达范围为「{scope}」，本条不计入公网风险。")),
                technical_detail=(f"端点：{url}\n"
                                  f"内省响应类型数：{len(types)}\n"
                                  f"其中敏感类型：{', '.join(sensitive_types[:20]) or '（未识别）'}\n"
                                  f"可达性判定：{scope}\n判定依据：{scope_why}"),
                impact=("内省等于把整个数据模型与接口契约公开："
                        "攻击者可据此枚举全部查询与变更操作，"
                        "定位未做鉴权的字段、找出可越权读取的关联关系，"
                        "并直接构造针对性的查询。"
                        "敏感类型名（如 User / Admin / Token）会直接标出高价值目标。"),
                reproduction=(f"curl -s -X POST '{url}' -H 'Content-Type: application/json' "
                              f"-d '{json.dumps(introspection)}' | head -40"),
                remediation=("① 生产环境关闭内省（Apollo Server 设 "
                             "`introspection: false`；GraphQL Java 设 "
                             "`graphql.servlet.enable-introspection=false`）；"
                             "② 查询深度与复杂度限制（防 DoS）；"
                             "③ 每个字段级做鉴权，不依赖「不公开就安全」；"
                             "④ 禁用批量查询别名（防绕过频控）。"),
                compliance="等保2.0 安全计算环境-入侵防范 / OWASP API9:2023",
                evidence=[finding_evidence("response",
                                           f"类型数 {len(types)}；敏感类型 {sensitive_types[:20]}",
                                           "内省响应")],
                grading_basis="实测内省开放，完整接口契约暴露，定中危",
            ))
            break

    note = (f"探测 GraphQL 端点 {len(endpoints)} 个，发起内省 {probes} 次，"
            f"{'确认内省开放' if findings else '未发现开放的内省接口'}")
    return found(note, findings, probes=probes, evidence_kind="GraphQL 内省实测")


# ======================================================================
# WSTG-WASM-00 WebAssembly 测试
# ======================================================================
@make_auto("WSTG-WASM-00", name="WebAssembly 产物安全审查", tool="前端产物分析",
           risk=RISK_SAFE, requires=["js"], evidence_kind="WASM 产物实测",
           detector_ref="checks/api.py:wasm00")
def wasm00(ctx: DetectorContext):
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    wasm_urls = set(re.findall(r"[\"']([^\"']+\.wasm)[\"']", blobs))
    if not wasm_urls:
        return no_target_outcome(ctx, "WebAssembly 产物", probes=1, evidence_kind="WASM 探测")

    findings = []
    probes = 0
    for w in list(wasm_urls)[:3]:
        url = w if w.startswith("http") else urljoin(ctx.target_url, w.lstrip("/"))
        probes += 1
        try:
            pr = ctx.get(url)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(pr, "body_snippet", "") or ""
        if getattr(pr, "status", 0) == 200 and b"\x00asm" in body.encode("utf-8", "ignore"):
            findings.append(make_finding(
                "WSTG-WASM-00", "存在 WebAssembly 产物，需纳入安全评审范围",
                ctx.target_name, endpoint=url,
                severity="信息", confidence="Medium", evidence_level="B",
                description=("站点加载了 WebAssembly 模块。WASM 中的逻辑可被完整逆向，"
                             "且不局限于 JavaScript 的安全模型。"),
                technical_detail=f"WASM 地址：{url}\n引用位置：前端产物",
                impact=("若 WASM 中实现了加密、鉴权或授权逻辑，"
                        "其算法与硬编码密钥可被逆向提取；"
                        "WASM 模块也可能包含内存安全问题，"
                        "成为绕过前端校验的入口。"),
                reproduction=f"下载 {url}，用 wasm2wat 反编译后审查导入导出与字符串常量。",
                remediation=("① 不在 WASM 中放置密钥或安全关键判断；"
                         "② WASM 模块同样纳入代码审计与依赖清单；"
                         "③ 开启 Source Map 时注意不要随产物发布调试信息。"),
                compliance="ISO 27001 A.8.28",
                evidence=[finding_evidence("file", f"WASM 产物 {url}", "WASM 文件")],
                grading_basis="仅记录存在性，WSTG 该基线尚未正式发布，不计入风险",
            ))

    note = f"发现 WebAssembly 产物 {len(wasm_urls)} 个，实测可下载 {len(findings)} 个"
    return found(note, findings, probes=probes, evidence_kind="WASM 产物实测")
