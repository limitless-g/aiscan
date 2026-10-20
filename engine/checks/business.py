# -*- coding: utf-8 -*-
"""
WSTG-BUSL 业务逻辑（10 项）
===========================
这一类是整个报告里最值钱、也最不可能靠扫描器拿到的部分。

它们共同的判定前提是**理解业务语义**：知道优惠券应该只能用一次、
退款金额不应该超过实付、审批需要按顺序走。工具的输入是 HTTP 报文，
报文本身看不出来「这个数量字段业务上不可能为负」。

因此本模块的处理方式是：
  - 唯一能完全自动化的部分（是否部署了防滥用措施）写成检测器；
  - 其余登记为「待人工执行」，但**不等于把活全推给人** ——
    每一项都挂了 engine.business 的自动前置侦察（recon）。

侦察层负责把枯燥且可自动化的准备工作做掉：定位接口、定位字段、
记录当前值、判类别、做只读差分、把能自动证的部分证掉。
人工只回答一个只有人能回答的问题：**这个业务结果对不对**。

侦察结果在报告里的读法分三种，绝不能混（见 DetectorRegistry._apply_recon）：
  ① 侦察确证了问题   → 该项「不通过」，证据入发现列表，残留人工部分照样写清；
  ② 侦察跑了没确证   → 仍是「待人工执行」，附「已定位对象清单」；
  ③ 侦察没跑起来     → 仍是「待人工执行」，**显式写出「侦察未执行 + 原因」**。

第 ③ 种最容易被糊过去。读者看到一份写得很细的人工步骤，
会默认自动化已经把能做的都做了 —— 所以「没做」必须写出来。

把这些项伪装成自动化「通过」，就是在制造虚假的安全感 —— 这正是本次改造
要根除的行为。
"""

from __future__ import annotations

import re

import engine.business as business
from engine.checks.base import finding_evidence, find_forms, ok, found, probe_or_none
from engine.registry import (
    RISK_DEEP, RISK_SAFE, RISK_STANDARD, DetectorContext, make_auto, make_finding,
    make_manual,
)


# ======================================================================
# WSTG-BUSL-01 业务逻辑数据验证
# ======================================================================
@make_manual(
    "WSTG-BUSL-01", name="业务逻辑数据验证测试",
    procedure=("对每个涉及金额、数量、时间、状态的可写字段，逐项测试边界与非法值：\n"
               "1) 数值边界：0、-1、-0.01、小数（1.5 个商品）、超大值（999999999）、"
               "科学计数（1e10）、精度溢出（0.1+0.2）；\n"
               "2) 类型混淆：数字字段传字符串（\"1\"、\"1abc\"）、传数组、传对象、传 null；\n"
               "3) 金额字段：提交负金额、把单价改成 0.01、把总价与单价不一致地提交，"
               "观察服务端是重新计算还是采信客户端值；\n"
               "4) 数量字段：库存 1 件时下单 100 件、并发提交同一库存；\n"
               "5) 时间字段：提交过去 / 未来的时间（如预约时间、生效时间）；\n"
               "6) 每个用例都要检查：请求是否被接受、数据是否真的落库、"
               "业务状态是否进入非法组合。"),
    expect=("所有业务字段在服务端做类型 + 范围 + 业务规则三重校验；"
            "金额一律服务端重算，不采信客户端提交的总价；"
            "非法值返回明确错误而非静默接受。"),
    why_manual="「哪个值是业务上不可能的」需要业务知识，工具的输入只有报文，无法判断语义合法性。",
    requires=["测试账号", "write", "业务上下文"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl01,
)
def _busl01(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-02 请求可伪造性
# ======================================================================
@make_manual(
    "WSTG-BUSL-02", name="请求可伪造性测试",
    procedure=("1) 抓取一个完整的业务请求，逐字段判断「服务端能不能自己算出来」；\n"
               "2) 把服务端本可推导的字段改为非法值并提交：\n"
               "   - 价格 / 折扣 / 运费 / 总金额 → 改为 0 或负值\n"
               "   - 用户 ID / 租户 ID → 改为他人 ID\n"
               "   - 时间戳 / 序列号 / 签名 → 删除该字段或改为任意值\n"
               "   - 状态字段（status/state）→ 直接提交为终态（如「已支付」「已通过」）\n"
               "3) 观察服务端是重新计算并覆盖，还是原样采纳；\n"
               "4) 特别检查隐藏字段（Hidden Fields）：表单里的隐藏字段是用户完全可改的，"
               "任何依赖隐藏字段的安全判断都不成立；\n"
               "5) 检查是否存在客户端签名（如 MD5(timestamp+key)）——"
               "若密钥在前端，签名等于没有。"),
    expect=("服务端独立重算所有关键字段；"
            "状态流转只能通过服务端定义的合法动作触发，不能由提交请求直接设置；"
            "所有校验所需信息从会话中取，不从请求体取。"),
    why_manual="需要判断「这个字段该不该由客户端决定」，这依赖对业务流程的理解。",
    requires=["测试账号", "write"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl02,
)
def _busl02(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-03 完整性校验
# ======================================================================
@make_manual(
    "WSTG-BUSL-03", name="数据完整性校验测试",
    procedure=("1) 找出所有「凭标识访问」的场景：订单号、工单号、报销单号、"
               "下载链接、分享链接、回调地址；\n"
               "2) 对每个标识判断：是纯数字连续、是简单编码（Base64）、"
               "还是带签名的不可伪造标识；\n"
               "3) 尝试篡改：\n"
               "   - 数字标识 ±1 遍历，确认能否命中他人对象；\n"
               "   - Base64 标识解码后修改再编码，确认服务端是否校验；\n"
               "   - 删除签名参数 / 改为任意值，确认是否仍被接受；\n"
               "4) 检查多步骤流程中，后一步是否重新校验前一步的状态"
               "（而不是信任客户端传来的「已完成」标记）；\n"
               "5) 检查幂等性：重复提交同一请求（同一订单号 / 同一唯一键）"
               "是否会产生重复业务（重复扣款、重复发货）。"),
    expect=("敏感对象标识使用不可枚举且带服务端校验的形式；"
            "每一步业务动作都重新校验前置状态；关键写操作具备幂等保护。"),
    why_manual="完整性校验的正确性依赖业务流程设计，需人工设计篡改用例并观察业务结果。",
    requires=["测试账号", "write"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl03,
)
def _busl03(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-04 流程时序
# ======================================================================
@make_manual(
    "WSTG-BUSL-04", name="业务流程时序与跳步测试",
    procedure=("1) 画出核心业务的完整流程（如：下单 → 支付 → 发货 → 收货 → 完成；"
               "或：申请 → 初审 → 复审 → 通过）；\n"
               "2) 对每一步抓取请求，然后尝试：\n"
               "   - 直接调用最后一步（跳过中间所有步骤）；\n"
               "   - 乱序调用（先发货后支付）；\n"
               "   - 重复调用某一步（重复领取、重复提交审批）；\n"
               "   - 回退调用（已完成的单再退回上一步）；\n"
               "3) 重点检查「并发」场景：两个请求同时发起时，"
               "是否都能通过前置校验（如两笔并发提现、两次并发领券）；\n"
               "4) 检查超时与过期：长时间未支付、超时的申请单，"
               "过期后能否继续推进流程；\n"
               "5) 记录每个越序请求的实际业务后果。"),
    expect=("服务端为每个状态流转定义合法的前置状态，"
            "非法时序一律拒绝；并发场景使用锁或乐观锁保证一致性；"
            "过期状态有明确处理。"),
    why_manual="必须理解流程的合法顺序，并真实推进业务状态，属写操作。",
    requires=["测试账号", "write", "业务上下文"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl04,
)
def _busl04(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-05 功能使用次数限制
# ======================================================================
@make_manual(
    "WSTG-BUSL-05", name="功能使用次数限制测试",
    procedure=("1) 列出所有「有限次」的功能：领券（每人 N 张）、"
               "抽奖（每日 N 次）、试用（每账号 1 次）、"
               "短信验证码（每号每日 N 条）、评分（每单 1 次）、点赞；\n"
               "2) 对每个功能确认限制维度：按账号 / 按 IP / 按设备 / 按手机号 / 无限制；\n"
               "3) 尝试绕过：\n"
               "   - 并发提交 N+1 个请求（看是否突破计数）；\n"
               "   - 换设备指纹 / 清 Cookie / 换 IP 后重试；\n"
               "   - 多账号领取同一资源（是否做了去重）；\n"
               "4) 检查计数是否存在服务端（而非仅前端按钮置灰）；\n"
               "5) 记录突破后的实际可获得量（是 1 次还是无限次）。"),
    expect="配额在服务端按不可伪造的维度计数，并使用原子操作（Redis INCR / 数据库唯一约束）"
           "防止并发突破；关键资源做多账号去重。",
    why_manual="需要真实消耗配额以验证限制是否生效，且边界值测试需要反复提交。",
    requires=["测试账号", "write"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl05,
)
def _busl05(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-06 工作流绕过
# ======================================================================
@make_manual(
    "WSTG-BUSL-06", name="工作流与审批绕过测试",
    procedure=("1) 梳理所有带审批 / 审核环节的流程（报销、采购、权限申请、"
               "内容发布、退款审核）；\n"
               "2) 尝试绕过审批：\n"
               "   - 直接调用「审批通过」的接口，伪造审批人身份；\n"
               "   - 提交时把状态字段直接设为「已通过」；\n"
               "   - 找到跳过审批的隐藏接口（如 /submit?autoApprove=true）；\n"
               "   - 自己申请、自己审批（缺少申请人 ≠ 审批人的校验）；\n"
               "3) 检查审批人职责分离：同一个人能否同时具备申请与审批权限；\n"
               "4) 检查代理审批：被代理人的权限边界是否被继承放大；\n"
               "5) 检查审批记录的不可否认性：审批日志能否被申请人删除或修改。"),
    expect="审批动作由服务端按角色与流程定义校验；申请人不能审批自己的申请；"
           "审批日志只追加不可修改；状态不能由请求体直接设置。",
    why_manual="必须理解审批规则并模拟不同角色操作，属多账号写操作。",
    requires=["accounts", "write", "业务上下文"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl06,
)
def _busl06(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-07 应用滥用的防御
# ======================================================================
@make_auto("WSTG-BUSL-07", name="防滥用措施部署核查", tool="内置检测器 + JS 分析",
           risk=RISK_SAFE, evidence_kind="防护措施实测",
           detector_ref="checks/business.py:busl07")
def busl07(ctx: DetectorContext):
    findings = []
    probes = 0
    blobs = "\n".join(list(ctx.js_result.get("bodies") or []) + [ctx.baseline_body])
    forms = find_forms(ctx)

    signals = {}
    probes += 1
    # 1) 人机校验
    if re.search(r"(recaptcha|hcaptcha|geetest|turnstile|slide-verify|slider|captcha|"
                 r"图形验证码|行为验证)", blobs, re.I):
        signals["人机校验"] = "已在页面中发现验证码组件"
    # 2) 频控响应头
    hdrs = ctx.root_headers
    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit",
              "retry-after", "x-rate-limit"):
        if h in hdrs:
            signals["速率限制响应头"] = f"{h}: {hdrs[h]}"
    # 3) 前端频控逻辑
    if re.search(r"(countdown|cooldown|倒计时|剩余次数|限流|tooManyRequests|429)", blobs, re.I):
        signals["前端频控提示"] = "前端存在倒计时 / 次数限制逻辑"
    # 4) 设备指纹 / 风控 SDK
    if re.search(r"(fingerprint|deviceId|device_id|riskControl|风控|sensor|_sdk)", blobs, re.I):
        signals["设备指纹 / 风控"] = "前端集成设备标识或风控 SDK"
    # 5) 滑动验证 / 短信频控
    sms_forms = [f for f in forms if any(re.search(r"(phone|mobile)", i, re.I)
                                         for i in f["inputs"])]
    if sms_forms:
        if re.search(r"(sms|verifyCode|sendCode|验证码)", blobs, re.I):
            signals["短信验证流程"] = "存在短信验证码发送逻辑"

    # 关键暴露面（登录、注册、找回密码、短信发送）是否有任何防护
    exposed_forms = []
    for f in forms:
        blob = f["action"] + " " + " ".join(f["inputs"])
        if re.search(r"(login|register|signup|forgot|reset|sms|sendcode|comment|feedback)",
                     blob, re.I):
            exposed_forms.append(f["action"] or f["page"])

    if not signals and exposed_forms:
        findings.append(make_finding(
            "WSTG-BUSL-07", f"关键匿名接口未见防滥用措施（{len(exposed_forms)} 个入口）",
            ctx.target_name, endpoint=exposed_forms[0],
            severity="中危", confidence="Medium", evidence_level="B",
            description=("在登录、注册、找回密码、短信发送这类匿名可访问的入口上，"
                         "没有发现验证码、速率限制响应头或前端频控逻辑。"
                         "这类入口是自动化滥用的首选目标。"),
            technical_detail=("检查的入口：\n"
                              + "\n".join(f"  · {u}" for u in exposed_forms[:10])
                              + "\n\n未发现的防护信号：人机校验、速率限制响应头、"
                                "设备指纹 / 风控 SDK、前端频控逻辑。"),
            impact=("可被自动化脚本批量利用：撞库（用泄露口令库尝试登录）、"
                    "批量注册（消耗短信费用、制造垃圾账号）、"
                    "短信轰炸（对他人手机号反复触发验证码）、"
                    "爬取业务数据（无频控的查询接口）。"),
            reproduction="对上述接口连续发起 20 次请求，观察是否出现 429 或延迟递增。",
            remediation=("① 匿名接口按 IP + 手机号 + 设备指纹多维限流；"
                         "② 登录失败递增延时、5 次锁定时段；"
                         "③ 短信发送单号单日限次 + 图形验证码前置；"
                         "④ 注册接入行为验证（滑块 / 无感验证）；"
                         "⑤ 返回 429 并带 Retry-After。"),
            compliance="等保2.0 安全计算环境-入侵防范 / CWE-770",
            evidence=[finding_evidence("file", str(exposed_forms[:10]), "关键入口清单")],
            grading_basis="未见防护措施属实测排除，实际限流可能存在于网关层，按 B 级定中危",
        ))

    note = (f"发现防护信号 {len(signals)} 项"
            + (f"：{'、'.join(signals)}" if signals else "（未发现任何防滥用措施）")
            + f"；关键匿名入口 {len(exposed_forms)} 个")
    ctx._cache["busl07_signals"] = signals

    # ---- 测试靶场模式（deep + 台账 --allow-write）：主动验证防自动化是否真有效 ----
    # 只读信号只能证明「部署了验证码」，证明不了「验证码拦不住自动化」。
    # 公网目标不带 --allow-write 时 business_active 整段不执行，行为不变。
    try:
        from engine import business_active as _ba  # noqa: PLC0415
        act = _ba.probe_captcha_automation(ctx)
        if act.findings:
            findings.extend(act.findings)
            note += f"；{act.note}"
        elif act.ran and act.note:
            note += f"；{act.note}"
    except Exception as e:  # noqa: BLE001
        note += f"；防自动化主动验证未执行（{type(e).__name__}）"

    return found(note, findings, probes=probes, evidence_kind="防护措施实测")


# ======================================================================
# WSTG-BUSL-08 意外文件类型上传
# ======================================================================
@make_manual(
    "WSTG-BUSL-08", name="非预期文件类型上传测试",
    procedure=("⚠️ 仅在测试环境执行，验证后删除所有测试文件。\n"
               "1) 记录每个上传点的白名单声明（前端 accept 属性、提示文案）；\n"
               "2) 逐个上传未声明的类型，每个只验证一种，观察响应：\n"
               "   - 图片点上传 .txt / .html / .svg / .pdf / .zip\n"
               "   - 文档点上传 .exe / .js / .html / .svg\n"
               "   - 头像点上传 .svg（可内嵌脚本，常用于存储型 XSS）\n"
               "3) 关注「上传成功但无提示」的情况——说明服务端未做类型校验；\n"
               "4) 检查上传后文件的访问路径与 Content-Type 响应头：\n"
               "   若 Content-Type 按文件真实类型返回（如 .html → text/html），"
               "则该文件可在浏览器中渲染，构成 XSS 风险；\n"
               "5) 检查文件是否被重命名、是否保留原扩展名、是否放在独立域名下。"),
    expect=("服务端按白名单校验扩展名 + 真实文件头（magic number）；"
            "上传文件重命名为随机名且不带原扩展名；"
            "存放于独立域名或已禁止脚本解析的目录；下载时强制 Content-Disposition: attachment。"),
    why_manual="必须真实上传文件并访问观察渲染行为，属写操作。",
    requires=["write"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl08,
)
def _busl08(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-09 恶意文件上传
# ======================================================================
@make_manual(
    "WSTG-BUSL-09", name="恶意文件上传与孵化链测试",
    procedure=("⚠️ 仅在测试环境执行，全程不得使用真实的恶意样本。\n"
               "1) 定位所有上传点，确认校验维度：扩展名黑名单还是白名单、"
               "是否校验 MIME、是否校验文件头、是否校验文件内容；\n"
               "2) 按由弱到强的顺序逐项验证（每步只测一个点）：\n"
               "   a. 双扩展名：shell.php.jpg、shell.jpg.php\n"
               "   b. 大小写与变体：shell.PHP、shell.pHp、shell.php5、shell.phtml、shell.jspx\n"
               "   c. 特殊后缀：shell.php.、shell.php::DATA、shell.php%00.jpg\n"
               "   d. 内容类型伪造：把 .php 的 Content-Type 改为 image/jpeg\n"
               "   e. 文件头伪造：GIF89a 开头 + 后续脚本内容\n"
               "   f. 文件名路径穿越：../../shell.php\n"
               "   g. 压缩包穿越：zip 内文件名为 ../../shell.php\n"
               "3) 每种方式上传后，访问返回的文件地址，观察是否被服务端解析执行；\n"
               "4) 检查是否可覆盖已有文件（上传文件名与已有资源同名）；\n"
               "5) 验证完成后删除所有上传文件并留痕。"),
    expect=("上传校验为服务端白名单 + 真实内容检测；上传目录不可执行脚本；"
            "文件名服务端生成；上传与展示使用不同域名。"),
    why_manual="验证需要真实上传并访问执行，属高侵入写操作，必须在受控环境进行。",
    requires=["write", "测试环境"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl09,
)
def _busl09(ctx: DetectorContext):  # pragma: no cover
    return ok("")


# ======================================================================
# WSTG-BUSL-10 支付功能
# ======================================================================
@make_manual(
    "WSTG-BUSL-10", name="支付与资金流程测试",
    procedure=("⚠️ 必须在测试环境或测试商户号上进行，严禁在生产订单上操作。\n"
               "1) 金额篡改：提交订单时修改 total / amount / price 字段，"
               "确认服务端是否重算（正确做法：以服务端商品价格重算）；\n"
               "2) 数量与单价组合：数量改为 0、负数、小数，观察总价计算；\n"
               "3) 优惠与积分：\n"
               "   - 优惠券重复使用（同一券号多次提交）；\n"
               "   - 券叠加超出限制；\n"
               "   - 积分抵扣为负数（反而增加余额）；\n"
               "   - 折扣率 > 100%；\n"
               "4) 支付回调：\n"
               "   - 回调是否校验签名（篡改回调内容看是否被接受）；\n"
               "   - 回调是否可重放（重复发送同一回调是否重复入账）；\n"
               "   - 回调金额与订单金额是否比对；\n"
               "   - 回调来源是否限制（能否从公网伪造回调）；\n"
               "5) 退款：退款金额能否超过实付、能否对同一订单重复退款、"
               "退款是否需要原支付渠道；\n"
               "6) 支付状态：能否通过改状态字段把未支付订单置为已支付。"),
    expect=("金额一律服务端重算；优惠与积分有幂等与上限校验；"
            "支付回调验签 + 校验金额 + 幂等去重 + 来源限制；"
            "退款金额不超过实付且需原路退回。"),
    why_manual="涉及真实资金流，任何自动化尝试都可能造成实际资金损失，必须人工在测试环境逐项验证。",
    requires=["测试环境", "测试账号", "write"], risk=RISK_DEEP, tool="人工核查",
    recon=business.recon_busl10,
)
def _busl10(ctx: DetectorContext):  # pragma: no cover
    return ok("")
