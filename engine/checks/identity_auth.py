# -*- coding: utf-8 -*-
"""
WSTG-IDNT 身份管理（5 项）+ WSTG-ATHN 身份认证（11 项）
======================================================
这一类的分界线很清楚：

  - 能在**匿名视角**下判定的事实（表单属性、Cookie 属性、缓存头、
    认证绕过技巧、枚举差异）→ 自动检测器
  - 必须**真实登录**或**故意触发锁定**才能判定（锁定机制、密码重置逻辑、
    多因素强度、弱口令）→ 人工执行指引

把后面这类硬塞进自动化，只能得到假结论，所以本模块对它们一律标注
「待人工执行」并给出可照做的步骤。
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin, urlparse

from engine.checks.base import (
    finding_evidence, find_forms, is_real_hit, ok, found, pending,
    probe_or_none, scan_paths,
    no_target_outcome, target_account_candidates, _spa_api_for_form,
)
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)
from engine import recon_identity as recon_id

# 默认凭据候选（保持极短，避免锁定真实账号；命中即为高危）
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "admin123"),
    ("test", "test"), ("root", "root"), ("guest", "guest"),
]

# 认证绕过常用技巧
BYPASS_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Host", "localhost"),
]


# ======================================================================
# WSTG-IDNT-01 角色定义
# ======================================================================
@make_manual(
    "WSTG-IDNT-01", name="角色与权限模型审查",
    procedure=("1) 向业务方索取角色清单（如：游客 / 普通用户 / 运营 / 管理员 / 超管）"
               "及每个角色的权限矩阵文档；\n"
               "2) 核对系统实际存在的角色：从前端路由表、菜单配置、接口返回的权限字段中"
               "反推实际角色枚举；\n"
               "3) 逐个比对「文档声明的角色」与「代码 / 配置里的角色」，找出未登记的角色"
               "（常见于历史遗留的测试角色、内部运维角色）；\n"
               "4) 检查是否存在硬编码的超管角色名（如 superadmin / root），"
               "这类角色若可被动创建，即权限体系失效。"),
    expect="不存在未登记角色；每个角色的权限边界有明确来源；无硬编码超管角色。",
    why_manual="角色模型的正确性依赖业务定义，匿名扫描只能看到接口返回的权限字段，无法判断该字段是否符合设计。",
    requires=["业务上下文"], risk=RISK_STANDARD, tool="人工核查",
)
def _idnt01(ctx: DetectorContext):  # pragma: no cover - 占位，不参与自动执行
    return ok("")


# ======================================================================
# WSTG-IDNT-02 用户注册流程
# ======================================================================
# API 式注册端点候选（ curated，不做任意路径探测）。
# 2026-10-14 第 29 轮实测：Juice Shop 的注册是纯 API（POST /api/Users），
# 前端是 SPA、没有任何 HTML 表单 —— 旧逻辑「没有注册表单就判通过」
# 把 Empty User Registration（空值可建号，201）和 Repetitive
# Registration（passwordRepeat 不校验）两个真实漏洞整类漏掉。
# REST 框架的注册端点高度集中在这几条路径上，值得实名探测。
REG_API_PATHS = [
    "api/Users", "api/users", "api/register", "api/auth/register",
    "api/signup", "rest/user/register", "rest/user/signup",
    "rest/auth/register", "api/v1/register", "api/v1/users",
]


def _registration_api_candidates(ctx: DetectorContext) -> list[str]:
    """收集 API 式注册端点候选（URL 形式，已去重）。

    两个来源，都不构成「端点存在」的证据，只是候选：
      ① 前端产物里出现过的地址（js_result.urls，含 /api/Users 这类）；
      ② REG_API_PATHS  curated 清单。
    真正判「是不是注册端点」的是后面的空值提交实测：
    返回建号成功（201）或校验错误里点名 email/password，都算确证；
    404 / 405 / 无信息响应 → 不是，丢弃。
    """
    cands: list[str] = []
    for u in (ctx.js_result.get("urls") or [])[:600]:
        if isinstance(u, str) and re.search(
                r"(register|signup|sign-up|/api/users?\b|/rest/user\b)", u, re.I):
            cands.append(urljoin(ctx.target_url, u))
    for p in REG_API_PATHS:
        cands.append(urljoin(ctx.target_url.rstrip("/") + "/", p))
    seen: set[str] = set()
    out: list[str] = []
    for u in cands:
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


@make_auto("WSTG-IDNT-02", name="注册流程安全审查", tool="表单与前端校验分析",
           risk=RISK_SAFE, evidence_kind="注册表单实测",
           detector_ref="checks/identity_auth.py:idnt02")
def idnt02(ctx: DetectorContext):
    findings = []
    forms = find_forms(ctx)
    reg_forms = [f for f in forms if re.search(
        r"(register|signup|sign-up|注册|invite|join)", f["action"] + f["page"], re.I)]
    if not reg_forms:
        # 退化：找含 email + password 但非登录的表单
        reg_forms = [f for f in forms if f["has_password"] and any(
            re.search(r"(email|mail|phone|mobile)", i, re.I) for i in f["inputs"])]

    api_targets: list[str] = []
    if not reg_forms:
        # 没有 HTML 注册表单 ≠ 没有注册能力。SPA 后端的注册是纯 API
        # （Juice Shop：POST /api/Users，2026-10-14 第 29 轮实测）——
        # 旧逻辑在这里直接判「未发现注册表单 → 通过」，把 Empty User
        # Registration（空值可建号）与 Repetitive Registration
        # （passwordRepeat 不校验）两个真实漏洞整类漏掉。
        # 取 API 候选端点，交给下面的服务端实测判生死。
        api_targets = _registration_api_candidates(ctx)
        if not api_targets:
            return ok("未发现注册入口：HTML 注册表单与 API 式注册端点"
                      "（前端产物 + 常见路径清单）均未探测到"
                      "（可能为邀请制，或入口在独立域名 / 登录页内）",
                      probes=ctx.probe_count or 1, evidence_kind="表单探测")

    issues = []
    for f in reg_forms[:2]:
        raw = f["raw"]
        # 仅前端校验（无 required 之外的约束，或强度校验写在 JS 里）
        has_required = "required" in raw.lower()
        if not has_required:
            issues.append("注册表单未设置必填约束（required）")
        # 密码强度提示写在 placeholder / pattern 里而非服务端
        if re.search(r"pattern\s*=", raw, re.I) is None and re.search(r"password", raw, re.I):
            issues.append("密码字段无 pattern 约束（强度校验可能只在服务端或完全缺失）")
        # 是否暴露「该手机号 / 邮箱已注册」的即时校验接口
        for m in re.finditer(r"(?:url|action)\s*[:=]\s*[\"']([^\"']*check[^\"']*)[\"']", raw, re.I):
            issues.append(f"表单引用即时校验接口：{m.group(1)}")

    # ---------- 服务端必填校验实测（空值注册）----------
    # 只看表单属性判不出「服务端到底有没有校验」 —— 前端 required 是装饰，
    # 删掉只需一步。真正的判据是**绕过前端直接对注册接口提交空值**，
    # 看服务端是不是照样把号建出来。这一步与 regself 同属「开放注册自建」
    # （红线 17①），走同一道门：deep 档 + 台账显式授权受控写；
    # 门没开就如实写「未执行」，绝不退化成「没测出来所以没问题」。
    empty_note = ""
    repeat_note = ""
    empty_hit = False
    repeat_hit = False
    gate_note = ""
    if ctx.risk_allowed(RISK_DEEP):
        targets: list[str] = []
        if reg_forms:
            f0 = reg_forms[0]
            act = (f0.get("action") or "").strip()
            if act and urlparse(urljoin(ctx.target_url, act)).path.strip("/"):
                targets.append(urljoin(ctx.target_url, act))
            hinted = _spa_api_for_form(ctx, f0)
            if hinted:
                targets.append(urljoin(ctx.target_url, hinted))
        for u in (ctx.js_result.get("urls") or [])[:400]:
            if isinstance(u, str) and re.search(
                    r"(register|signup|/api/Users|/rest/user\b)", u, re.I):
                targets.append(urljoin(ctx.target_url, u))
        targets.extend(api_targets)
        seen_t: set[str] = set()
        targets = [t for t in targets
                   if t.startswith(("http://", "https://"))
                   and ctx.domain in t
                   and not (t in seen_t or seen_t.add(t))][:3]
        if not targets:
            empty_note = "；空值注册未执行：未取得注册接口地址（表单 action 与前端产物均无）"
        for tgt in targets:
            for payload in ({"email": "", "password": ""},
                            {"email": " ", "password": " "}):
                try:
                    r = ctx.data_submit(tgt, dict(payload), method="POST", as_json=True,
                                        budget_key="idnt02_empty_reg", max_total=4)
                except PermissionError as e:  # noqa: BLE001
                    empty_note = f"；空值注册未执行：{e}"
                    break
                status = int(r.get("status") or 0)
                body = str(r.get("body") or "")
                created = status in (200, 201) and bool(re.search(
                    r'"\s*(id|token|authentication)\s*"\s*:', body, re.I))
                if created:
                    empty_hit = True
                    findings.append(make_finding(
                        "WSTG-IDNT-02", "注册接口未做必填校验（空值可建号）",
                        ctx.target_name, endpoint=tgt, method="POST",
                        param="email / password",
                        severity="中危", confidence="High", evidence_level="A",
                        description=("绕过前端直接向注册接口提交**空的邮箱与口令**，"
                                     "服务端仍然返回建号成功，说明必填与格式校验"
                                     "完全依赖前端、服务端没有重复校验。"),
                        technical_detail=(f"注册接口：{tgt}\n"
                                          f"提交内容：{payload}\n"
                                          f"响应状态：HTTP {status}\n"
                                          f"响应片段（已截断）：\n{body[:600]}"),
                        impact=("可被批量创建空账号，占用用户表与存储、污染数据统计，"
                                "并可作为后续垃圾内容 / 撞库的落脚点；"
                                "空账号还可能绕过「以邮箱为唯一标识」的下游逻辑。"),
                        reproduction=(f"curl -s -X POST '{tgt}' -H 'Content-Type: application/json' "
                                      f"-d '{json.dumps(payload)}'"),
                        remediation=("① 服务端强制校验必填、格式与口令强度，"
                                     "前端校验只作体验优化；"
                                     "② 注册接口加频控与人机校验；"
                                     "③ 对已建空账号清理并回填校验。"),
                        compliance="等保2.0 安全计算环境-访问控制 / CWE-20",
                        evidence=[finding_evidence("response", body[:1200], "空值注册响应")],
                        grading_basis="实测空值提交返回建号成功，服务端校验缺失可确证，定中危",
                    ))
                    break
            if findings:
                break
        # ② passwordRepeat 不一致仍建号（Repetitive Registration：
        #    服务端不校验「两次输入的口令是否一致」，前端校验可被整类绕过）。
        #    targets 为空时 tgt 未定义，必须守卫 —— 否则空候选目标会
        #    在这里抛 NameError 把整项检测打成「未执行」。
        if targets and not repeat_hit and not empty_note.startswith("；空值注册未执行"):
            import secrets as _secrets

            _email = (f"aiscan-idnt02-{_secrets.token_hex(4)}"
                      f"@{ctx.domain or 'localhost'}")
            _pw = "Rs-" + _secrets.token_urlsafe(12)
            for payload in (
                {"email": _email, "password": _pw, "passwordRepeat": ""},
                {"email": _email, "password": _pw,
                 "passwordRepeat": _pw + "-mismatch"},
            ):
                try:
                    r = ctx.data_submit(tgt, dict(payload), method="POST",
                                        as_json=True,
                                        budget_key="idnt02_empty_reg",
                                        max_total=4)
                except PermissionError as e:  # noqa: BLE001
                    repeat_note = f"；passwordRepeat 测试未执行：{e}"
                    break
                status = int(r.get("status") or 0)
                body = str(r.get("body") or "")
                if status in (200, 201) and bool(re.search(
                        r'"\s*(id|token|authentication)\s*"\s*:', body, re.I)):
                    repeat_hit = True
                    findings.append(make_finding(
                        "WSTG-IDNT-02",
                        "注册不校验重复口令（passwordRepeat 可被绕过）",
                        ctx.target_name, endpoint=tgt, method="POST",
                        param="passwordRepeat",
                        severity="中危", confidence="High", evidence_level="A",
                        description=("向注册接口提交**重复口令为空 / 与口令不一致**"
                                     "的请求，服务端仍然建号成功，说明「两次口令"
                                     "一致」的校验只存在于前端。"),
                        technical_detail=(f"注册接口：{tgt}\n"
                                          f"提交内容：{payload}\n"
                                          f"响应状态：HTTP {status}\n"
                                          f"响应片段（已截断）：\n{body[:600]}"),
                        impact=("① 用户输错口令也能注册成功，后续登录用的却是"
                                "第一次输入的值，造成「我明明设的是这个」的"
                                "账号事故与客服纠纷；"
                                "② 前端校验可被整体绕过（改包 / 直调 API），"
                                "服务端不重复校验等于没有校验。"),
                        reproduction=(f"curl -s -X POST '{tgt}' -H 'Content-Type: application/json' "
                                      f"-d '{json.dumps(payload)}'\n"
                                      "# 返回 201 且含用户 id —— 两次口令不一致也建号"),
                        remediation=("① 服务端校验 password 与 passwordRepeat 一致；"
                                     "② 注册接口加频控与人机校验；"
                                     "③ 前端校验仅作体验，不作安全边界。"),
                        compliance="等保2.0 安全计算环境-访问控制 / CWE-20",
                        evidence=[finding_evidence("response", body[:1200],
                                                   "passwordRepeat 不一致注册响应")],
                        grading_basis="实测两次口令不一致仍返回建号成功，服务端校验缺失可确证，定中危",
                    ))
                    break
        if not repeat_note and not repeat_hit:
            repeat_note = "；passwordRepeat 不一致实测被服务端拒绝（校验生效）"
        if not empty_note and not empty_hit:
            empty_note = "；空值注册实测未通过（服务端拒绝了空值）"
    else:
        # 档位不够（非 deep）时服务端实测不跑。**不能判通过** ——
        # 表单层没看出问题 ≠ 服务端校验生效，那一步根本没测
        # （红线 1：通过只能来自真实执行）。
        gate_note = ("；服务端校验实测未执行：需要 deep 档且台账显式授权受控写"
                     "（两把锁，红线 24）—— 表单层无问题不代表服务端校验生效")

    ctx._cache["idnt02_forms"] = reg_forms
    if reg_forms:
        _entry = f"发现注册类表单 {len(reg_forms)} 个"
    elif api_targets:
        _entry = (f"未发现 HTML 注册表单（SPA 后端），转测 API 式注册端点 "
                  f"{len(api_targets)} 个候选")
    else:
        _entry = "未发现注册入口"
    note = (f"{_entry}；表单层问题 {len(issues)} 处"
            + empty_note + repeat_note + gate_note)
    if issues:
        findings.append(make_finding(
            "WSTG-IDNT-02", "注册流程存在表单层校验缺陷",
            ctx.target_name, endpoint=reg_forms[0]["page"],
            param=", ".join(reg_forms[0]["inputs"])[:200],
            severity="低危", confidence="Medium", evidence_level="B",
            description=("注册表单把校验责任放在前端：缺少必填约束或强度约束，"
                         "服务端是否重复校验无法从外部确证。"),
            technical_detail="表单地址：{}\n输入字段：{}\n问题：\n{}".format(
                reg_forms[0]["action"] or reg_forms[0]["page"],
                ", ".join(reg_forms[0]["inputs"]),
                "\n".join(f"  · {i}" for i in issues)),
            impact=("前端校验可被直接绕过（改包或禁用 JS）。若服务端未重复校验，"
                    "可注册异常账号（超长用户名、非法手机号），"
                    "或用于批量注册以消耗资源、发送垃圾内容。"),
            reproduction=f"curl -s {reg_forms[0]['page']} | grep -A30 -i '<form'",
            remediation="所有校验在服务端强制执行；前端校验仅作为体验优化，不作为安全边界；"
                        "注册接口接入频控与人机校验。",
            compliance="等保2.0 安全计算环境-访问控制 / ISO 27001 A.8.5",
            evidence=[finding_evidence("response", reg_forms[0]["raw"][:1200], "注册表单")],
            grading_basis="表单层缺陷可确证，服务端校验缺失未实证，按 B 级定低危",
        ))
    if findings:
        return found(note, findings, probes=ctx.probe_count or 1,
                     evidence_kind="注册表单实测")
    if gate_note:
        # 有注册入口、服务端实测却没跑（档位 / 台账门没开）——
        # 待确认，绝不写成通过（红线 1）。
        return pending(note, probes=ctx.probe_count or 1,
                       evidence_kind="注册表单实测")
    return found(note, findings, probes=ctx.probe_count or 1,
                 evidence_kind="注册表单实测")


# ======================================================================
# WSTG-IDNT-03 账号开通流程
# ======================================================================
@make_manual(
    "WSTG-IDNT-03", name="账号开通 / 审批流程审查",
    procedure=("1) 梳理账号创建的全部入口：自助注册、管理员创建、批量导入、"
               "SSO 首次登录自动开通、第三方（企业微信 / 飞书）同步；\n"
               "2) 对每个入口确认：是否需要审批、审批人如何确定、"
               "是否校验申请人身份（工号 / 部门 / 上级）；\n"
               "3) 重点检查「SSO 首次登录自动建号」：默认角色是什么？"
               "若默认角色权限过宽（如默认给到可访问他人数据），等于绕过审批；\n"
               "4) 检查离职 / 转岗流程：账号是否在离职当日停用，"
               "转岗后旧权限是否回收（这是最常见的越权来源）；\n"
               "5) 检查是否存在无人认领的历史账号（可通过最后登录时间筛查）。"),
    expect="所有账号创建入口都有身份校验与审批；离职停用 SLA 明确；无长期未登录的活跃账号。",
    why_manual="流程正确性依赖组织制度，技术探测看不到审批链路与人员状态。",
    requires=["业务上下文", "组织制度"], risk=RISK_STANDARD, tool="人工核查",
)
def _idnt03(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-IDNT-04 账号枚举与可猜测用户名
# ======================================================================
@make_auto("WSTG-IDNT-04", name="账号枚举检测", tool="即时校验接口对比",
           risk=RISK_STANDARD, evidence_kind="接口响应差异实测",
           detector_ref="checks/identity_auth.py:idnt04")
def idnt04(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])

    # 找前端调用的「可用性校验」类接口
    cands: set[str] = set()
    for m in re.finditer(
            r"[\"']([^\"']*(?:check|exists|available|verify|validate|unique)[^\"']*)"
            r"[\"']", blobs, re.I):
        u = m.group(1)
        if re.search(r"(user|account|phone|mobile|email|mail|name)", u, re.I):
            cands.add(u)
    for m in re.finditer(r"[\"'](/[^\"']*(?:user|account|member)[^\"']*)[\"']", blobs, re.I):
        cands.add(m.group(1))

    tested = []
    for cand in list(cands)[:8]:
        url = cand if cand.startswith("http") else urljoin(ctx.target_url, cand.lstrip("/"))
        if ctx.domain not in url:
            continue
        for param in ("username", "account", "phone", "mobile", "email"):
            probes += 1
            try:
                p1 = ctx.get(f"{url}{'&' if '?' in url else '?'}{param}=admin")
                p2 = ctx.get(f"{url}{'&' if '?' in url else '?'}{param}="
                             f"aiscan_no_such_user_9z8y7x")
            except Exception:  # noqa: BLE001
                continue
            b1 = (getattr(p1, "body_snippet", "") or "")[:2000]
            b2 = (getattr(p2, "body_snippet", "") or "")[:2000]
            s1, s2 = getattr(p1, "status", 0), getattr(p2, "status", 0)
            if not b1 or not b2:
                continue
            differ = (s1 != s2) or (abs(len(b1) - len(b2)) > 20 and b1 != b2)
            if differ and re.search(r"(exist|已注册|已占用|不可用|occupied|taken|重复)", b1 + b2, re.I):
                tested.append((f"{url}?{param}=", s1, s2, b1[:200], b2[:200]))
                break
        if tested:
            break

    if tested:
        ep, s1, s2, r1, r2 = tested[0]
        findings.append(make_finding(
            "WSTG-IDNT-04", "存在账号枚举接口，可批量探测有效账号",
            ctx.target_name, endpoint=ep, param="username / phone / email",
            severity="中危", confidence="High", evidence_level="A",
            description=("注册或找回密码页面调用的「可用性校验」接口，"
                         "对已存在的账号与不存在的账号返回不同结果。"
                         "攻击者可以据此批量判断哪些手机号 / 邮箱已在本站注册。"),
            technical_detail=(f"接口：{ep}\n"
                              f"查询已存在账号 → HTTP {s1}\n  响应：{r1}\n"
                              f"查询不存在账号 → HTTP {s2}\n  响应：{r2}"),
            impact=("① 批量导出已注册用户清单（手机号 / 邮箱），构成个人信息泄露；"
                    "② 为撞库与定向钓鱼筛出真实账号；"
                    "③ 结合弱口令可对已知账号做精准爆破。"),
            reproduction=f"curl -s '{ep}admin'\ncurl -s '{ep}aiscan_no_such_user_9z8y7x'",
            remediation=("可用性校验接口必须接入频控与图形验证码；"
                         "对任意查询统一返回相同文案（如「若该账号可用将收到提示」），"
                         "不区分存在与否；同时对同一来源做行为限速与告警。"),
            compliance="PIPL 第 51 条 / 等保2.0 安全计算环境-访问控制",
            evidence=[finding_evidence("response", f"存在：{r1}\n\n不存在：{r2}", "枚举接口响应差异")],
            grading_basis="实测响应差异可区分账号存在性，可用于批量收集用户标识，定中危",
        ))

    note = (f"扫描前端产物发现的校验类接口 {len(cands)} 个，"
            f"实测 {len(tested)} 个存在账号枚举差异")
    return found(note, findings, probes=probes, evidence_kind="接口响应差异")


# ======================================================================
# WSTG-IDNT-05 用户名策略弱或未强制
# ======================================================================
@make_auto("WSTG-IDNT-05", name="用户名策略核查", tool="表单与前端约束分析",
           risk=RISK_SAFE, evidence_kind="表单约束实测",
           detector_ref="checks/identity_auth.py:idnt05")
def idnt05(ctx: DetectorContext):
    findings = []
    forms = ctx._cache.get("idnt02_forms") or find_forms(ctx)
    if not forms:
        return ok("未发现注册 / 账号创建表单，无法核查用户名策略", probes=2,
                  evidence_kind="表单探测")

    weak = []
    for f in forms[:2]:
        raw = f["raw"]
        for name in f["inputs"]:
            if not re.search(r"(user|account|name|login|email|phone)", name, re.I):
                continue
            # 找到该字段的标签定义
            m = re.search(rf'<input[^>]*name\s*=\s*["\']{re.escape(name)}["\'][^>]*>',
                          raw, re.I)
            tag = m.group(0) if m else ""
            if "pattern" not in tag.lower() and "minlength" not in tag.lower():
                weak.append(name)
    if weak:
        findings.append(make_finding(
            "WSTG-IDNT-05", f"用户名 / 账号字段无格式约束（{len(weak)} 个字段）",
            ctx.target_name, endpoint=forms[0]["page"],
            param=", ".join(weak),
            severity="低危", confidence="Medium", evidence_level="B",
            description=("账号类输入框没有长度或格式限制。若服务端同样不限制，"
                         "可注册超长、含特殊字符或与其他系统同名冲突的账号。"),
            technical_detail="无约束字段：\n" + "\n".join(f"  · {w}" for w in weak),
            impact=("① 超长用户名可撑大存储、破坏页面展示（存储型问题的前置条件）；"
                    "② 允许与运维账号同名（如 admin、system），为社工与钓鱼创造条件；"
                    "③ 若用户名参与 SQL / 缓存键拼接，可能引出二次问题。"),
            reproduction=f"curl -s {forms[0]['page']} | grep -iE '<input[^>]*name=\"(user|account|name)'",
            remediation=("服务端强制用户名格式：长度 4–32、仅允许字母数字与有限符号、"
                         "大小写归一化、禁止保留字（admin / root / system 等）。"),
            compliance="等保2.0 安全计算环境-身份鉴别",
            evidence=[finding_evidence("response", forms[0]["raw"][:900], "账号字段定义")],
            grading_basis="前端约束缺失可确证，服务端约束未实证，按 B 级定低危",
        ))
    return found(f"核查 {len(forms)} 个表单的账号字段，发现 {len(weak)} 个无格式约束",
                 findings, probes=2, evidence_kind="表单约束")


# ======================================================================
# WSTG-ATHN-01 凭据经加密通道传输
# ======================================================================
@make_auto("WSTG-ATHN-01", name="凭据传输通道加密核查", tool="表单与协议实测",
           risk=RISK_SAFE, requires=[], evidence_kind="登录通道实测",
           detector_ref="checks/identity_auth.py:athn01")
def athn01(ctx: DetectorContext):
    findings = []
    forms = find_forms(ctx)
    login = [f for f in forms if f["has_password"]]
    if not login:
        return no_target_outcome(ctx, "含口令字段的表单", probes=ctx.probe_count or 1, evidence_kind="表单探测")

    for f in login[:3]:
        action = f["action"] or f["page"]
        insecure = action.lower().startswith("http://")
        page_insecure = f["page"].lower().startswith("http://")

        # HTTP 是否可直接访问（用于判定是否存在明文入口）
        http_url = None
        if not insecure and not page_insecure:
            http_url = action.replace("https://", "http://", 1)
        if insecure or page_insecure:
            findings.append(make_finding(
                "WSTG-ATHN-01", "登录凭据经明文 HTTP 传输",
                ctx.target_name, endpoint=action, method="POST",
                severity="高危", confidence="High", evidence_level="A",
                description=("登录表单提交到 http:// 地址，账号与口令在网络上以明文传输。"
                             "同一网络内的任何设备都可以直接看到这些凭据。"),
                technical_detail=f"表单页面：{f['page']}\n提交地址：{action}",
                impact=("攻击者在同一 WiFi / 局域网内可直接嗅探到全部登录凭据，"
                        "也可通过 ARP 欺骗强制降级。凭据泄露即账号失陷，"
                        "若该账号有数据权限，等同于数据泄露。"),
                reproduction=f"curl -s {f['page']} | grep -iE '<form|action='",
                remediation=("登录页与提交地址全部改走 HTTPS，并在服务器与 CDN 层"
                             "配置 HTTP 301 强制跳转；为域配置 HSTS。"),
                compliance="等保2.0 安全通信网络-通信传输 / PIPL 第 51 条",
                evidence=[finding_evidence("response", f["raw"][:900], "登录表单")],
                grading_basis="实测凭据走明文通道，定高危",
            ))
        elif http_url:
            pr = None
            try:
                pr = ctx.get(http_url)
            except Exception:  # noqa: BLE001
                pr = None
            if pr is not None and getattr(pr, "status", 0) in (200, 301, 302) \
                    and (getattr(pr, "final_url", "") or "").lower().startswith("http://"):
                findings.append(make_finding(
                    "WSTG-ATHN-01", "登录入口可通过明文 HTTP 访问且未强制跳转",
                    ctx.target_name, endpoint=http_url, method="POST",
                    severity="中危", confidence="High", evidence_level="A",
                    description=("登录页虽然使用 HTTPS，但通过 http:// 也能打开，"
                                 "且没有被强制跳转到 HTTPS。"
                                 "用户在地址栏输入域名时，若浏览器补全为 http，"
                                 "凭据就会走明文。"),
                    technical_detail=(f"HTTPS 入口：{action}\n"
                                      f"HTTP 访问结果：HTTP {getattr(pr, 'status', 0)} → "
                                      f"{getattr(pr, 'final_url', '')}"),
                    impact=("配合网络层降级或用户直接输入 http 地址，凭据可被截获。"
                            "页面本身若含登录表单，则直接在明文通道下提交。"),
                    reproduction=f"curl -sI {http_url}",
                    remediation="在服务器与 CDN 层配置 301 强制跳转 HTTPS，并下发 HSTS。",
                    compliance="等保2.0 安全通信网络-通信传输",
                    evidence=[finding_evidence("response",
                                               f"HTTP {getattr(pr, 'status', 0)} → {getattr(pr, 'final_url', '')}",
                                               "HTTP 访问结果")],
                    grading_basis="实测明文入口可达，未直接在明文通道提交凭据，定中危",
                ))

    note = f"发现含口令表单 {len(login)} 个，逐项核查提交地址与 HTTP 可达性"
    return found(note, findings, probes=len(forms) + len(login) + 1,
                 evidence_kind="登录通道实测")


# ======================================================================
# WSTG-ATHN-02 默认凭据
# ======================================================================
@make_auto("WSTG-ATHN-02", name="默认凭据探测（受限）", tool="表单提交（deep 档）",
           risk=RISK_DEEP, evidence_kind="登录提交实测",
           detector_ref="checks/identity_auth.py:athn02")
def athn02(ctx: DetectorContext):
    forms = find_forms(ctx)
    login = [f for f in forms if f["has_password"]]
    if not login:
        return no_target_outcome(ctx, "登录表单", probes=1, evidence_kind="表单探测")

    f = login[0]
    action = f["action"] or f["page"]
    # SPA 渲染态表单：action 常指向页面根地址（提交由前端 JS 拦截），
    # 真实提交目标是前端调用的认证 API。优先用 find_forms 推断出的
    # api_hint；拿到 API 端点后改走 JSON 提交 —— 认证接口几乎全是
    # application/json，表单编码只会得到 415 / 参数为空。
    as_json = False
    api_hint = f.get("api_hint") or ""
    if f.get("source") == "rendered" and api_hint:
        action = api_hint
        as_json = True
    user_field = next((i for i in f["inputs"]
                       if re.search(r"(user|account|login|name|phone|mobile|email)", i, re.I)), "")
    pass_field = next((i for i in f["inputs"]
                       if re.search(r"(pass|pwd|secret)", i, re.I)), "")
    if not (user_field and pass_field):
        return ok("登录表单字段名未能确定，跳过默认凭据尝试（避免误提交）",
                  probes=1, evidence_kind="字段识别失败")

    # 候选账号扩展：把「通用账号名 × 目标自己暴露的邮箱域名」并进来。
    # 只试裸用户名（admin/test）会在**账号字段是邮箱**的系统上整片落空 ——
    # 实测 Juice Shop v20：`admin`/`admin123` 打不动，
    # 真正能登的是 `admin@juice-sh.op`，而域名就写在打包产物里。
    # 总量仍受 credhunt 的 12 次硬上限约束（字典 6 + 目标形态最多 6）。
    creds = list(DEFAULT_CREDS)
    try:
        extra: list[tuple[str, str]] = []
        for acc in target_account_candidates(ctx, limit=4):
            for pw in ("admin", "123456", "admin123"):
                extra.append((acc, pw))
                if len(extra) >= 6:
                    break
            if len(extra) >= 6:
                break
        creds = creds + extra
    except Exception:  # noqa: BLE001
        pass

    findings = []
    hits = []
    # 「请求根本没发出去 / 没拿到响应」的次数。
    # 必须单独数：第 23 轮实测 12 次尝试全部打在相对路径上，requests 抛
    # MissingSchema 被吞成 status 0 —— 一次都没发出，报告却写「尝试 12 组，未命中」。
    # 没有这个计数，「目标不接受这组口令」和「我们压根没问过目标」
    # 在报告上长得一模一样，而后者是纯假的「未命中」。
    noresp = 0
    # JSON API 提交（SPA）与表单编码提交（传统）走不同通道：
    # 前者走 data_submit 的共享预算，后者保持 form_submit 的单次上限。
    # JSON API 的「登录成功」判定也不同：令牌在 JSON 响应体里，
    # 不在 Set-Cookie 里 —— 只看响应头会把真登录判成失败。
    if as_json:
        for u, p in creds:
            data = {user_field: u, pass_field: p}
            try:
                r = ctx.data_submit(action, data, method="POST", as_json=True,
                                    budget_key="athn02_default_creds",
                                    max_total=len(creds), purpose="credential")
            except PermissionError as e:
                return ok(f"未执行：{e}", probes=0, evidence_kind="档位限制")
            body = r.get("body", "") or ""
            status = int(r.get("status") or 0)
            if status == 0:
                noresp += 1
            token_in_body = bool(re.search(
                r'"(token|authentication)\s*"|eyJ[A-Za-z0-9_\-]{8,}\.',
                body, re.I))
            fail_marker = bool(re.search(
                r"(密码错误|账号或密码|登录失败|invalid|incorrect|"
                r"用户名或密码|认证失败|Invalid email)", body, re.I))
            if status in (200, 201) and token_in_body and not fail_marker:
                hits.append((u, p, status, action))
    else:
        for u, p in creds:
            data = {user_field: u, pass_field: p}
            try:
                r = ctx.form_submit(action, data, max_attempts=len(creds))
            except PermissionError as e:
                return ok(f"未执行：{e}", probes=0, evidence_kind="档位限制")
            body = r.get("body", "")
            status = r.get("status", 0)
            # 判定成功的信号：跳转到非登录页 / 出现会话 Cookie / **响应体里带了令牌**。
            # 第三条是补的：现在很多登录接口是 SPA 的 JSON API，成功时根本不发
            # Set-Cookie，令牌在响应体里。只看响应头的话，一次**真的登进去了**的
            # 尝试会被判成失败 —— 实测 Juice Shop v20：`admin@juice-sh.op / admin123`
            # 返回 200 + `{"authentication":{"token":"eyJ…"}}`，而响应头无 Set-Cookie。
            # 「登录 200 ≠ 登录成功」的护栏不能反过来变成漏报源（红线 29）。
            body = str(r.get("body") or "")
            if int(r.get("status") or 0) == 0:
                noresp += 1
            token_in_body = bool(re.search(
                r'"(token|authentication|access_token|id_token)\s*"\s*:|'
                r"eyJ[A-Za-z0-9_\-]{8,}\.", body, re.I))
            fail_marker = re.search(r"(密码错误|账号或密码|登录失败|invalid|incorrect|"
                                    r"用户名或密码|认证失败)", body or "", re.I)
            if (not fail_marker and token_in_body) or \
                    (set_cookie and sessionish and not fail_marker) or \
                    (status in (301, 302) and "login" not in (r.get("final_url") or "").lower()):
                hits.append((u, p, status, r.get("final_url", "")))

    if hits:
        u, p, st, final = hits[0]
        findings.append(make_finding(
            "WSTG-ATHN-02", f"存在默认 / 弱口令可登录（账号 {u}）",
            ctx.target_name, endpoint=action, method="POST",
            param=f"{user_field} / {pass_field}",
            severity="高危", confidence="High", evidence_level="A",
            description=(f"使用常见的默认账号口令组合（{u} / 弱口令）即可登录成功，"
                         "说明系统未强制修改默认口令，也未做口令强度校验。"),
            technical_detail=(f"登录地址：{action}\n"
                              f"使用账号：{u}\n"
                              f"响应状态：{st}，最终地址：{final}\n"
                              f"已下发会话凭据：是\n"
                              f"（口令本身不在报告中记录）"),
            impact=("攻击者可用默认口令直接登录，获得该账号的全部权限。"
                    "若该账号为管理类账号，等于系统被接管；"
                    "即使是普通账号，也可读取该账号可见的业务数据。"),
            reproduction=(f"在 {action} 提交 {user_field}={u} 与常见弱口令，"
                          "观察是否跳转至登录后的页面并下发会话 Cookie。"),
            remediation=("① 首次登录强制修改初始口令；"
                         "② 口令策略：长度 ≥ 12、禁止常见弱口令字典、禁止与账号相同；"
                         "③ 登录接口接入频控与失败告警；"
                         "④ 管理类账号强制启用 MFA。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / ISO 27001 A.8.5",
            evidence=[finding_evidence("response",
                                       f"提交账号 {u} → HTTP {st} → {final}（口令已省略）",
                                       "登录尝试结果")],
            grading_basis="实测凭默认口令获得有效会话，定高危",
        ))

    note = (f"对 {action} 尝试 {len(creds)} 组默认口令"
            f"（通用名 {len(DEFAULT_CREDS)} 组 + 目标账号形态 "
            f"{len(creds) - len(DEFAULT_CREDS)} 组；单次、不重试，避免锁定账号），"
            f"{'命中弱口令' if hits else '未命中'}"
            # 试过的**账号**要落在报告里 —— 「未命中」三个字解释不了
            # 「候选本身就选错了」和「系统没有弱口令」这两种完全不同的成
            # 因。账号名不是秘密（秘密是口令，从不落盘），写清楚才能复核。
            + (f"；试过账号：{'、'.join(sorted({u for u, _ in creds})[:8])}"
               + ("…" if len({u for u, _ in creds}) > 8 else ""))
            + (f"；⚠ 其中 {noresp} 次**未取得响应**（请求未真正发出或被拒），"
               f"不能当作「口令不对」" if noresp else ""))
    return found(note, findings, probes=len(creds), evidence_kind="登录提交实测")


# ======================================================================
# WSTG-ATHN-03 锁定机制薄弱
# ======================================================================
@make_manual(
    "WSTG-ATHN-03", name="登录锁定机制测试",
    procedure=("⚠️ 必须在**测试账号**上做，且先与业务方确认该账号可被锁定。\n"
               "1) 用测试账号连续输入错误口令，记录第几次开始出现限制提示；\n"
               "2) 观察限制方式：是否锁定账号（永久 / 临时 / 递增延时）、"
               "是否只限 IP、是否有锁定提示；\n"
               "3) 恢复验证：等待锁定窗口后确认能正常登录；\n"
               "4) 反向验证：对**不存在的账号**同样连续失败，"
               "观察是否有相同的锁定行为（若无，则可通过响应差异枚举账号）；\n"
               "5) 绕过验证：更换 IP / 清 Cookie / 变更 User-Agent 后重试，"
               "判断锁定是否可被轻易绕过。"),
    expect="存在账号级锁定或指数退避；锁定状态不因更换 IP / 清 Cookie 而失效；"
           "锁定提示不泄露账号是否存在。",
    why_manual="必须真实触发失败登录才能判定，自动化反复尝试会把生产账号锁死，风险由人工控制更合适。",
    requires=["测试账号"], risk=RISK_DEEP, tool="人工核查",
    recon=recon_id.recon_athn03,
)
def _athn03(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-ATHN-04 绕过认证方案
# ======================================================================
@make_auto("WSTG-ATHN-04", name="认证绕过技巧检测", tool="内置检测器",
           risk=RISK_STANDARD, evidence_kind="绕过实测",
           detector_ref="checks/identity_auth.py:athn04")
def athn04(ctx: DetectorContext):
    findings = []
    # 找受控路径作对照
    protected = []
    for path, probe in (ctx.fp_result.get("path_probes") or {}).items():
        if isinstance(probe, dict) and probe.get("status") in (401, 403):
            protected.append(path)
    if not protected:
        for cand in ("admin", "manage", "console", "dashboard", "api/user", "actuator/env"):
            pr = probe_or_none(ctx, cand)
            if pr is not None and getattr(pr, "status", 0) in (401, 403):
                protected.append(cand)
                break
    if not protected:
        return ok("未发现返回 401/403 的受控路径，无法验证认证绕过（目标未见访问控制拦截）",
                  probes=3, evidence_kind="无对照路径")

    base = protected[0].strip("/")
    url = urljoin(ctx.target_url, base)
    base_pr = ctx.get(url)
    base_status = getattr(base_pr, "status", 0)

    probes = 0
    hits = []
    for hname, hval in BYPASS_HEADERS:
        probes += 1
        import requests
        try:
            ctx._client._throttle()
            r = requests.get(url, headers={**dict(ctx._client.session.headers),
                                           hname: hval},
                             timeout=ctx._client.timeout, verify=False,
                             allow_redirects=False)
            if r.status_code == 200 and len(r.text or "") > 200:
                hits.append((hname, hval, r.status_code, (r.text or "")[:200]))
        except Exception:  # noqa: BLE001
            continue

    if hits:
        hname, hval, st, frag = hits[0]
        findings.append(make_finding(
            "WSTG-ATHN-04", f"认证可被请求头绕过（{hname}: {hval}）",
            ctx.target_name, endpoint=url, method="GET", param=hname,
            severity="高危", confidence="High", evidence_level="A",
            description=(f"直接访问 /{base} 返回 HTTP {base_status}（被拦截），"
                         f"但加上请求头 `{hname}: {hval}` 后返回 200 并输出正常内容。"
                         "说明访问控制信任了客户端可伪造的请求头。"),
            technical_detail=(f"基准请求：GET {url} → HTTP {base_status}\n"
                              f"绕过请求：GET {url}\n"
                              f"           {hname}: {hval}\n"
                              f"→ HTTP {st}\n"
                              f"响应片段：{frag}"),
            impact=("请求头（X-Forwarded-For / X-Original-URL 等）由客户端完全可控，"
                    "攻击者可以据此伪装为内网来源或直接指定内部路径，"
                    "绕过管理后台、内部接口的访问限制，无需任何凭据。"),
            reproduction=f"curl -s -H '{hname}: {hval}' {url} | head -20",
            remediation=("① 访问控制不要依赖可伪造的请求头；"
                         "② 若架构上必须信任代理头，则在边缘代理层强制覆盖（重写）"
                         "这些头，并在应用层只接受来自可信代理的连接；"
                         "③ 内网来源判定改用网络层身份（mTLS / 源 IP 白名单）。"),
            compliance="等保2.0 安全计算环境-访问控制 / CWE-290",
            evidence=[finding_evidence("request", f"{hname}: {hval}\n→ HTTP {st}\n{frag}",
                                       "绕过请求与响应")],
            grading_basis="实测绕过访问控制可达受控资源，定高危",
        ))

    note = (f"以 /{base}（HTTP {base_status}）为对照，测试 {len(BYPASS_HEADERS)} 种请求头伪造，"
            f"绕过成功 {len(hits)} 种")
    return found(note, findings, probes=probes, evidence_kind="请求头伪造实测")


# ======================================================================
# WSTG-ATHN-05 易受攻击的记住密码功能
# ======================================================================
@make_auto("WSTG-ATHN-05", name="记住密码功能核查", tool="Cookie 与前端分析",
           risk=RISK_SAFE, evidence_kind="Cookie 与前端实测",
           detector_ref="checks/identity_auth.py:athn05")
def athn05(ctx: DetectorContext):
    findings = []
    raw_cookies = ctx.root_headers.get("set-cookie", "")
    all_cookies = " ".join(getattr(ctx.root, "cookies", []) or [])
    remember = re.search(r"([\w\-]*(?:remember|persist|autologin|auto_login|keep)[\w\-]*)=([^;\s]+)",
                         raw_cookies + " " + all_cookies, re.I)
    if not remember:
        # 前端 localStorage 存储「记住我」
        blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
        if re.search(r"(rememberMe|remember_me|autoLogin)", blobs, re.I):
            findings.append(make_finding(
                "WSTG-ATHN-05", "前端实现「记住我」功能（凭据 / 令牌存于浏览器）",
                ctx.target_name, endpoint=ctx.target_url,
                severity="中危", confidence="Medium", evidence_level="B",
                description=("「记住我」由前端实现，令牌保存在浏览器可访问的位置。"
                             "若存于 localStorage，任何 XSS 都能直接读取并长期接管账号。"),
                technical_detail="前端产物中出现 rememberMe / autoLogin 相关标识。",
                impact="配合 XSS 可长期窃取账号（记住我令牌有效期通常以周计）；"
                       "本地持久化令牌泄露后无需口令即可登录。",
                reproduction="在浏览器开发者工具 → Application → Local Storage / Cookies 中查看 rememberMe 相关项。",
                remediation=("记住我令牌由服务端下发 HttpOnly + Secure + SameSite=Strict 的 Cookie；"
                             "不在 localStorage 保存任何认证令牌；"
                             "令牌需可服务端吊销，并在口令变更时立即失效。"),
                compliance="等保2.0 安全计算环境-身份鉴别",
                evidence=[finding_evidence("file", "前端出现 rememberMe 标识", "前端产物")],
                grading_basis="前端实现有技术证据，未实证令牌泄露，按 B 级定中危",
            ))
        else:
            return ok("未发现「记住我」相关 Cookie 或前端标识", probes=1,
                      evidence_kind="Cookie 与前端")
    else:
        name = remember.group(1)
        # 检查该 Cookie 的属性
        seg = raw_cookies
        flags = {
            "HttpOnly": bool(re.search(rf"{re.escape(name)}=[^;]*;.*?httponly", seg, re.I | re.S)),
            "Secure": bool(re.search(rf"{re.escape(name)}=[^;]*;.*?secure", seg, re.I | re.S)),
            "SameSite": bool(re.search(rf"{re.escape(name)}=[^;]*;.*?samesite", seg, re.I | re.S)),
        }
        token_len = len(remember.group(2))
        if not all(flags.values()) or token_len < 24:
            findings.append(make_finding(
                "WSTG-ATHN-05", "「记住我」凭据 Cookie 属性缺失或强度不足",
                ctx.target_name, endpoint=ctx.target_url, param=name,
                severity="中危", confidence="High", evidence_level="A",
                description=(f"持久化登录 Cookie `{name}` 的属性不完整"
                             "（缺少 HttpOnly / Secure / SameSite 之一），"
                             "或令牌长度偏短、随机性不足。"),
                technical_detail=(f"Cookie 名：{name}\n属性：{flags}\n"
                                  f"令牌长度：{token_len} 字符（建议 ≥ 32 且为强随机）"),
                impact=("缺少 HttpOnly → 任意 XSS 可直接读取该令牌并长期接管账号；"
                        "缺少 Secure → 明文通道下可被截获；"
                        "缺少 SameSite → 可被跨站请求携带。"),
                reproduction=f"curl -sI {ctx.target_url} | grep -i set-cookie",
                remediation=("持久化令牌 Cookie 统一设置 "
                             "HttpOnly; Secure; SameSite=Strict; Path=/；"
                             "令牌使用 CSPRNG 生成 ≥ 32 字节；"
                             "支持服务端吊销并在口令变更时全量失效。"),
                compliance="等保2.0 安全计算环境-身份鉴别",
                evidence=[finding_evidence("header", f"{name}=<已省略>；属性 {flags}；长度 {token_len}",
                                           "记住我 Cookie 属性")],
                grading_basis="Cookie 属性经实测确认缺失，定中危",
            ))

    note = f"记住我相关凭据：{remember.group(1) if remember else '未发现'}"
    return found(note, findings, probes=1, evidence_kind="Cookie 与前端实测")


# ======================================================================
# WSTG-ATHN-06 浏览器缓存弱点
# ======================================================================
@make_auto("WSTG-ATHN-06", name="敏感页面缓存策略核查", tool="响应头实测",
           risk=RISK_SAFE, evidence_kind="缓存头实测",
           detector_ref="checks/identity_auth.py:athn06")
def athn06(ctx: DetectorContext):
    findings = []
    sensitive_pages = [ctx.target_url]
    for p in ("login", "user", "account", "profile", "dashboard", "admin"):
        pr = probe_or_none(ctx, p)
        if pr is not None and getattr(pr, "status", 0) == 200:
            sensitive_pages.append(getattr(pr, "final_url", "") or urljoin(ctx.target_url, p))

    bad = []
    for page in sensitive_pages[:8]:
        try:
            pr = ctx.get(page)
        except Exception:  # noqa: BLE001
            continue
        if getattr(pr, "status", 0) != 200:
            continue
        hdr = {k.lower(): v for k, v in (getattr(pr, "headers", {}) or {}).items()}
        cc = hdr.get("cache-control", "")
        pragma = hdr.get("pragma", "")
        formish = bool(re.search(r"(password|登录|login)", 
                                 (getattr(pr, "body_snippet", "") or ""), re.I))
        if not formish:
            continue
        if ("no-store" not in cc and "no-cache" not in cc and "private" not in cc):
            bad.append((page, cc or "（未设置 Cache-Control）", pragma or "（无 Pragma）"))

    if bad:
        findings.append(make_finding(
            "WSTG-ATHN-06", f"含凭据输入的页面未禁用缓存（{len(bad)} 个页面）",
            ctx.target_name, endpoint=bad[0][0],
            severity="低危", confidence="High", evidence_level="A",
            description=("登录页等含敏感输入的页面没有设置禁止缓存的响应头，"
                         "浏览器或中间代理可能把页面内容缓存下来。"),
            technical_detail="\n".join(f"  {p}\n    Cache-Control: {c}\n    Pragma: {pg}"
                                       for p, c, pg in bad),
            impact=("在共用终端（如公用电脑、共享终端机）上，"
                    "后退或历史记录可能还原已登录页面内容；"
                    "共享代理缓存可能把含凭据的页面提供给他人。"),
            reproduction=f"curl -sI {bad[0][0]} | grep -iE 'cache-control|pragma'",
            remediation=("认证相关页面统一返回：\n"
                         "Cache-Control: no-store, no-cache, must-revalidate, private\n"
                         "Pragma: no-cache\nExpires: 0"),
            compliance="等保2.0 安全计算环境-剩余信息保护 / ISO 27001 A.8.11",
            evidence=[finding_evidence("header", str(bad[:5]), "缓存响应头")],
            grading_basis="缓存策略缺失经实测确认，危害受限，定低危",
        ))
    note = f"核查 {len(sensitive_pages[:8])} 个敏感页面的缓存策略，其中 {len(bad)} 个未禁用缓存"
    return found(note, findings, probes=len(sensitive_pages[:8]), evidence_kind="缓存头实测")


# ======================================================================
# WSTG-ATHN-07 弱认证方法
# ======================================================================
@make_auto("WSTG-ATHN-07", name="弱认证方式检测", tool="内置检测器",
           risk=RISK_SAFE, evidence_kind="认证方式实测",
           detector_ref="checks/identity_auth.py:athn07")
def athn07(ctx: DetectorContext):
    findings = []
    probes = 0
    h = ctx.root_headers

    # HTTP Basic / Digest
    if h.get("www-authenticate"):
        scheme = h["www-authenticate"].split()[0]
        # 直接请求受控路径看是否触发 Basic
        for p in ("admin", "manage", "console"):
            pr = probe_or_none(ctx, p)
            probes += 1
            wa = {k.lower(): v for k, v in (getattr(pr, "headers", {}) or {}).items()}.get("www-authenticate", "")
            if wa and re.match(r"(basic|digest)", wa, re.I):
                weakness = ("Basic 认证每次请求都携带可逆的 Base64 凭据，"
                            "一旦通道被降级或日志记录请求头，凭据即泄露。")
                findings.append(make_finding(
                    "WSTG-ATHN-07", f"使用 HTTP {wa.split()[0]} 基础认证",
                    ctx.target_name, endpoint=urljoin(ctx.target_url, p),
                    severity="中危", confidence="High", evidence_level="A",
                    description=weakness,
                    technical_detail=f"路径 /{p} 返回：WWW-Authenticate: {wa}",
                    impact=("凭据以可逆编码随每个请求发送，且无法有效登出；"
                            "在 HTTP 通道或含请求头的日志中会直接暴露。"),
                    reproduction=f"curl -sI {urljoin(ctx.target_url, p)} | grep -i www-authenticate",
                    remediation="改用基于会话或 Token 的应用层认证；无法改动时至少强制 HTTPS 并限制访问来源。",
                    compliance="等保2.0 安全计算环境-身份鉴别",
                    evidence=[finding_evidence("header", f"WWW-Authenticate: {wa}", "认证挑战")],
                    grading_basis="实测确认使用基础认证，凭据可逆传输，定中危",
                ))
                break

    # URL 中携带凭据
    for item in (ctx._cache.get("info06_params") or []):
        if re.search(r"(password|passwd|pwd|token|secret|apikey|api_key)",
                     item.get("param", ""), re.I):
            findings.append(make_finding(
                "WSTG-ATHN-07", "URL 参数中携带凭据 / 令牌",
                ctx.target_name, endpoint=item.get("url", ""), method="GET",
                param=item.get("param", ""),
                severity="中危", confidence="High", evidence_level="A",
                description="认证类凭据被放在 URL 查询参数里传递。",
                technical_detail=f"URL：{item.get('url', '')}\n参数：{item.get('param', '')}",
                impact=("URL 会被完整记录到浏览器历史、服务端访问日志、反向代理日志、"
                        "CDN 日志以及 Referer 头中。凭据一旦进入这些位置，"
                        "等于在多个系统里留下了长期可读的副本。"),
                reproduction=f"curl -s '{item.get('url', '')}'",
                remediation="凭据一律通过请求头或请求体传递，不使用 URL 参数；历史遗留接口需改造并轮换已泄露的令牌。",
                compliance="等保2.0 安全计算环境-身份鉴别 / CWE-598",
                evidence=[finding_evidence("request", item.get("url", "")[:500], "含凭据的 URL")],
                grading_basis="实测确认凭据出现在 URL 中，定中危",
            ))
            break

    note = (f"认证方式核查：WWW-Authenticate={h.get('www-authenticate', '无')}；"
            f"URL 凭据参数 {sum(1 for i in (ctx._cache.get('info06_params') or []) if re.search(r'(password|token|secret)', i.get('param',''), re.I))} 个")
    return found(note, findings, probes=probes + 1, evidence_kind="认证方式实测")


# ======================================================================
# WSTG-ATHN-08 弱安全问题答案
# ======================================================================
@make_manual(
    "WSTG-ATHN-08", name="密保问题安全性测试",
    procedure=("1) 走一遍「忘记密码 → 密保问题」流程，记录问题清单；\n"
               "2) 逐条判断问题答案是否可被公开信息获得（生日、姓名、学校、"
               "车牌、母亲姓名、宠物名——这类答案在社交媒体上通常都能查到）；\n"
               "3) 是否有答案数量上限（如错误 5 次即锁定）；"
               "答案是否区分大小写 / 是否做归一化（'北京' 与 '北京市'）；\n"
               "4) 密保问题是否可被用户跳过；是否可作为唯一的账号找回方式；\n"
               "5) 若密保问题可绕过登录直接重置口令，则危害等同于账号接管。"),
    expect="不使用可公开推断的密保问题；错误尝试有次数限制；密保不作为唯一的找回方式；"
           "与短信 / 邮箱等第二因素组合使用。",
    why_manual="答案的可猜测性依赖对特定人员公开信息的判断，需要人工结合社工视角评估。",
    requires=["业务上下文"], risk=RISK_STANDARD, tool="人工核查",
    recon=recon_id.recon_athn08,
)
def _athn08(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-ATHN-09 弱密码修改与重置功能
# ======================================================================
@make_manual(
    "WSTG-ATHN-09", name="密码修改与重置流程测试",
    procedure=("⚠️ 全程使用测试账号。\n"
               "1) 修改口令时是否要求输入原口令？（不要求 = 会话被劫持即可改口令锁死账号）\n"
               "2) 重置流程：重置链接是否含可预测令牌？令牌是否一次性、有有效期（应 ≤ 15 分钟）？"
               "是否与账号绑定（换账号用同一令牌是否生效）？\n"
               "3) 重置后：旧会话是否失效？旧令牌是否全部失效？\n"
               "4) 新口令强度：是否校验弱口令、是否禁止与旧口令相同、是否禁止历史口令复用；\n"
               "5) 重置接口是否有频控：能否用脚本对同一手机号 / 邮箱反复触发重置（短信轰炸）；\n"
               "6) Host 头注入：修改重置请求的 Host，观察重置链接是否指向攻击者域名。"),
    expect="改口令需验证原口令；重置令牌一次性、短时效、与账号强绑定；"
           "重置后旧会话全部失效；重置接口有频控且不响应被篡改的 Host。",
    why_manual="必须真实走完重置流程并观察令牌生命周期，涉及真实邮件 / 短信发送与账号状态变更。",
    requires=["测试账号"], risk=RISK_DEEP, tool="人工核查",
    recon=recon_id.recon_athn09,
)
def _athn09(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-ATHN-10 替代通道中更弱的认证
# ======================================================================
@make_auto("WSTG-ATHN-10", name="替代认证通道识别", tool="内置检测器 + JS 分析",
           risk=RISK_STANDARD, evidence_kind="替代通道探测",
           detector_ref="checks/identity_auth.py:athn10")
def athn10(ctx: DetectorContext):
    findings = []
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    channels = {}
    patterns = {
        "短信验证码登录": r"(sms|smsCode|captcha|verifyCode|mobile_code|短信验证码)",
        "扫码登录": r"(qrcode|qr_login|scanLogin|扫码登录)",
        "第三方登录": r"(oauth|wechat|weixin|dingtalk|feishu|lark|weibo|qq_login)",
        "API 密钥": r"(api[_-]?key|x-api-key|access[_-]?key|app[_-]?secret)",
        "记住我令牌": r"(remember[_-]?me|auto[_-]?login|persist[_-]?token)",
    }
    for name, pat in patterns.items():
        if re.search(pat, blobs, re.I):
            channels[name] = pat

    # 探测独立的移动端 / 小程序接口前缀
    mobile_prefixes = ["api/app/", "app/", "mobile/", "api/mobile/", "h5/",
                       "api/v1/app/", "miniapp/", "api/wx/"]
    hit_prefix = []
    for pre in mobile_prefixes:
        pr = probe_or_none(ctx, pre)
        if pr is not None and getattr(pr, "status", 0) in (200, 401, 403):
            hit_prefix.append(pre)

    if len(channels) >= 3:
        findings.append(make_finding(
            "WSTG-ATHN-10", f"存在 {len(channels)} 种替代认证通道，需逐一核查强度一致性",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Medium", evidence_level="B",
            description=("系统提供了多种登录方式：" + "、".join(channels) +
                         "。多通道本身是合理的，但每个通道的强度往往不一致——"
                         "攻击者只会走最弱的那一条。"),
            technical_detail=("识别到的通道：\n" + "\n".join(f"  · {c}" for c in channels)
                              + ("\n\n疑似独立移动端接口前缀：\n"
                                 + "\n".join(f"  · /{p}" for p in hit_prefix) if hit_prefix else "")),
            impact=("常见薄弱点：短信验证码可被撞（4–6 位数字、无频控）、"
                    "扫码登录的 ticket 可枚举、"
                    "第三方登录的回调未校验 state。"
                    "任意一条被绕过，口令强度形同虚设。"),
            reproduction="参照本报告「替代通道」清单，逐个执行对应的验证步骤。",
            remediation=("① 所有通道统一接入同一套频控、锁定与告警策略；"
                         "② 短信验证码 ≥ 6 位、5 分钟有效、单号单日限次、错误 5 次作废；"
                         "③ 扫码登录 ticket 使用强随机且一次性；"
                         "④ 第三方登录严格校验 state 与回调域名白名单。"),
            compliance="等保2.0 安全计算环境-身份鉴别",
            evidence=[finding_evidence("file", "识别到通道：" + "、".join(channels), "前端产物")],
            grading_basis="多通道存在属实测，各通道强度未逐一验证，按 B 级定中危",
        ))

    note = (f"识别替代认证通道 {len(channels)} 种"
            + (f"：{'、'.join(channels)}" if channels else "")
            + f"；疑似移动端接口前缀 {len(hit_prefix)} 个")
    return found(note, findings, probes=len(mobile_prefixes) + 1, evidence_kind="替代通道识别")


# ======================================================================
# WSTG-ATHN-11 多因素认证（MFA）
# ======================================================================
@make_auto("WSTG-ATHN-11", name="多因素认证覆盖核查", tool="内置检测器 + JS 分析",
           risk=RISK_SAFE, evidence_kind="MFA 特征实测",
           detector_ref="checks/identity_auth.py:athn11")
def athn11(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    mfa_signals = []
    for pat, desc in (
        (r"(mfa|2fa|two[_-]?factor|otp|totp|authenticator|双重验证|两步验证|二次验证)", "前端出现 MFA 相关标识"),
        (r"(google.?authenticator|authy|微软验证器|totp)", "提及 TOTP 类验证器"),
        (r"(verify[_-]?code|security[_-]?code|动态码|验证码)", "存在验证码校验流程"),
    ):
        if re.search(pat, blobs, re.I):
            mfa_signals.append(desc)

    mfa_paths = ["mfa", "2fa", "otp", "verify", "security/2fa", "user/mfa",
                 "account/security", "settings/security"]
    hits = scan_paths(ctx, mfa_paths)
    probes += len(mfa_paths)

    login_protected = "未执行"
    if not mfa_signals and not hits:
        findings.append(make_finding(
            "WSTG-ATHN-11", "未发现多因素认证机制",
            ctx.target_name, endpoint=ctx.target_url,
            severity="中危", confidence="Medium", evidence_level="B",
            description=("从公网可获取的页面与前端产物中，没有发现任何二次验证机制的痕迹。"
                         "若系统确实只依赖单一口令，则口令一旦泄露（撞库、钓鱼、复用）即账号失守。"),
            technical_detail=("检查范围：登录页表单字段、前端产物关键字、"
                              f"常见 MFA 路径（{len(mfa_paths)} 个，命中 {len(hits)} 个）。\n"
                              "说明：MFA 配置入口位于登录后页面，公网匿名视角无法完全排除其存在；"
                              "登录后的实际配置需人工确认。"),
            impact=("单因素认证下，任何一次口令泄露（员工复用口令、钓鱼、第三方泄露撞库）"
                    "都会直接导致账号被接管。管理类账号尤其危险，"
                    "一旦接管即可触达大量业务数据。"),
            reproduction=("检查登录页是否存在验证码 / 动态口令字段；"
                          "使用测试账号登录后检查账户安全设置页是否存在二次验证开关。"),
            remediation=("① 管理类、运维类、有数据导出权限的账号强制启用 MFA；"
                         "② 优先使用 TOTP 或硬件密钥，短信验证码作为退路；"
                         "③ MFA 覆盖范围需定期审计，防止新增高权限账号绕过。"),
            compliance="等保2.0 安全计算环境-身份鉴别 / ISO 27001 A.8.5",
            evidence=[finding_evidence("file", "未发现 MFA 标识；常见 MFA 路径均不可达", "MFA 特征")],
            grading_basis="匿名视角未发现 MFA 痕迹，登录后配置需人工确认，按 B 级定中危",
        ))

    note = (f"MFA 特征 {len(mfa_signals)} 项，MFA 路径命中 {len(hits)} 个"
            + (f"；特征：{'、'.join(mfa_signals)}" if mfa_signals else "（未发现 MFA 痕迹）"))

    # ---- 测试靶场模式（deep + 台账 --allow-write）：2FA 链主动验证 ----
    # 「部署了 2FA」不等于「2FA 拦得住」：密钥经注入泄露后可被完整复用。
    # 公网目标不带 --allow-write 时 business_active 整段不执行，行为不变。
    try:
        from engine import business_active as _ba  # noqa: PLC0415
        act = _ba.probe_2fa_secret_leak(ctx)
        if act.findings:
            findings.extend(act.findings)
            note += f"；{act.note}"
        elif act.ran and act.note:
            note += f"；{act.note}"
    except Exception as e:  # noqa: BLE001
        note += f"；2FA 链主动验证未执行（{type(e).__name__}）"

    return found(note, findings, probes=probes, evidence_kind="MFA 特征实测")
