# -*- coding: utf-8 -*-
"""
L5 报告生成器
=============
职责：产出三份固定结构的报告。

  - 技术版（technical）：完整七章，含复现脚本与证据，供研发修复使用
  - 摘要版（executive）：一页纸，面向管理层，去除技术细节与敏感信息
  - 扫描通告（notice）：固定格式，直接可贴进部门大群通晒。
    只列「已实测复现」的严重 / 高危 / 中危问题，低危不列。
    每扫完一个系统，这份就是发群的那一份。

固定七章（规格第 6 章）：
  1. 执行摘要
  2. 授权与范围声明
  3.全量检查项结论表（逐项：通过 / 不通过 / N/A + 原因）
  4. 漏洞详情（每项含复现脚本、实测记录、影响说明、定级依据）
  5. 扫描器盲区专项（业务逻辑与权限矩阵）
  6. 合规对照
  7. 附录

硬性要求：漏洞详情章不出现无复现的条目。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.applicability import (  # noqa: E402
    CONCLUSION_APPLICABLE,
    CONCLUSION_PASS_NA,
    CONCLUSION_PENDING,
    ApplicabilityResult,
    ApplicabilityEngine,
)
# 扫描模式常量：默认值（黑客运维视角）只定义在 engine/redteam.py 一处。
from engine.redteam import (  # noqa: E402
    DEFAULT_MODE, MODE_LABEL, MODE_REDTEAM,
)
from models import Finding, FindingSet, SEVERITY_ORDER  # noqa: E402
from verify.mask import Masker  # noqa: E402

try:  # 危害类型中文标签（与定级引擎同一份定义，避免两处漂移）
    from rules.grading import hazard_label  # noqa: E402
except Exception:  # noqa: BLE001
    def hazard_label(key: str) -> str:  # type: ignore[misc]
        """降级兜底：宁可显示内部键名，也不编造中文。"""
        return key or "—"

try:  # 复现强度文案（与 verify 层保持同一份定义，避免两处漂移）
    from verify.repro_templates import STRENGTH_LABEL, STRENGTH_WEAK  # noqa: E402
except Exception:  # noqa: BLE001
    STRENGTH_LABEL = {
        "strong": "强（含特征断言与对照实验）",
        "medium": "中（状态码 / 协议层断言）",
        "weak": "弱（仅可达性，需人工核对）",
    }
    STRENGTH_WEAK = "weak"

# 复现方式 → 通俗说明。报告里不允许出现读者看不懂的模板代号。
REPRO_KIND_NOTE = {
    "content_marker": "重跑检测规则 + 对照组排除误报",
    "param_replay": "基线请求与载荷请求对比",
    "weak_login": "重放受控默认口令字典（与检测阶段同一份）",
    "anon_access": "无凭据直连 + 响应特征断言",
    "cross_role": "两个身份分别请求同一地址 + 响应逐字节比对（含对照实验）",
    "path_reach": "路径可达性判定（含对照路径）",
    "dir_listing": "目录列举特征匹配",
    "header_state": "响应头状态断言",
    "cors_reflect": "跨域响应头回显验证",
    "port_open": "端口连通性探测",
    "method_accept": "非预期 HTTP 方法接受判定",
    "tls_state": "TLS 协议 / 证书状态断言",
    "component_version": "组件版本指纹比对",
    "dns_record": "DNS 记录独立查询",
    "rate_limit": "有界并发压力 + 频控特征判定",
    "plain_channel": "明文传输通道判定",
    "weak_probe": "可达性探测（**不含该类型的专用断言**）",
}

# 结论状态的含义（第 3 章表头解释用）
STATE_MEANING = {
    "通过": "检测器完整执行，未发现问题",
    "不通过": "检测器完整执行，发现问题（详见第 2 章）",
    "未执行": "适用，但无检测逻辑 / 检测器失败 / 前置条件不足 —— **不代表安全**",
    "待人工执行": "必须人工判断，已给出操作步骤（见本章清单）—— **不代表安全**",
    "N/A": "目标不具备该特征，已逐项说明原因",
    "待确认": "适用性无法从外部判定，需人工确认",
    "已跳过": "用户显式跳过",
}

# 未执行原因归类 → 补齐方式
NOTRUN_FIX = {
    "缺少检测逻辑": "这是引擎覆盖缺口，请反馈补写检测器后复扫",
    "档位限制": "使用更高档位（深度档）重新扫描，或明确接受不测",
    "前置条件不足": "补齐前置条件（测试账号 / 受控写授权）后复扫",
    "检测器执行失败": "查看附录错误明细，修复后复扫",
    "适用性判定缺失": "检查适用性引擎配置，修复后复扫",
    "其他": "逐项人工确认",
}


def _mapping_stats() -> dict[str, int]:
    """nuclei 归口表规模（落盘用，便于发现归口退化）。

    归口退化是静默的：表被改坏之后，所有模板都会走兜底项，
    报告上只表现为「某几项忽然不通过」或「某几项永远通过」，没人会注意。
    """
    try:
        from engine.nuclei_map import mapping_stats  # noqa: PLC0415
        return mapping_stats()
    except Exception:  # noqa: BLE001
        return {}


def _render_recon(L: list[str], r: Any) -> None:
    """在人工项正文前渲染自动侦察结论。

    三种情形必须让读者一眼分清，因为它们对「还欠多少工作」的含义完全不同：

      · 侦察已执行且有结论 → 先给结论与已定位对象，人工直接进入判断环节；
      · 侦察已执行但无确证 → 明说「这不等于本项通过」；
      · 侦察未执行         → 明说「没有任何自动化前置覆盖」。
    """
    if not (getattr(r, "recon_ran", False) or getattr(r, "recon_note", "")):
        return
    if not getattr(r, "recon_ran", False):
        L.append("  **自动侦察：未执行** ⚠")
        L.append("")
        for line in (getattr(r, "recon_note", "") or "").split("\n"):
            if line.strip():
                L.append(f"  {line}")
        L.append("")
        L.append("  ⚠ 本项的人工步骤**没有任何自动化前置覆盖**，需从零开始执行。")
        L.append("")
        return

    L.append("  **自动侦察结论（已执行）**")
    L.append("")
    for line in (getattr(r, "recon_note", "") or "").split("\n"):
        if line.strip():
            L.append(f"  {line}")
    L.append("")
    lead = list(getattr(r, "recon_lead", []) or [])
    if lead:
        L.append("  已定位到的具体对象（按此逐条执行，不必自己找接口和字段）：")
        L.append("")
        for x in lead:
            L.append(f"  - {x}")
        L.append("")
    if getattr(r, "recon_finding_count", 0):
        L.append(f"  ⚠ 侦察已确证 {r.recon_finding_count} 项问题，已计入发现列表。")
        L.append("")
    L.append("  ⚠ 侦察**不等于**本项通过：它覆盖的是可自动证的部分，"
             "业务语义的正确性仍由下面的步骤判定。")
    L.append("")


# ======================================================================
# 扫描通告（对外通晒版）的复现步骤收敛
# ======================================================================
# 这份报告是给部门大群看的，不是给研发看的技术文档。两者的读者不同，
# 「复现步骤」的合适形态也不同：
#
#   技术版报告 → 研发照着 curl 命令自己跑一遍，越精确越好
#   通晒通告   → 负责人要知道「哪个地址、什么现象算确认」，但不需要
#                一条能被任何人群里复制就对着生产系统执行的命令
#
# 群里有外包、代运维、历史遗留账号 —— 一份原样带 curl / sqlmap 的通告，
# 等于安全团队自己把可执行的验证手册分发给所有能看到群消息的人。
# 所以这里做的事是：**保留「打哪里」（URL），收敛「怎么打」（命令构造）**。
_NOTICE_FENCE = re.compile(r"```[A-Za-z0-9_+.\-]*\n.*?```", re.S)
#: 命令行首出现（实测 reproduction 的主要形态）
_NOTICE_CMD_HEAD = re.compile(
    r"^[ \t]*(?:curl|wget|nmap|nc|ncat|netcat|openssl|sqlmap|nikto|"
    r"python3?|perl|ruby|http|httpie|ffuf|gobuster|dirsearch)\b[^\n]*$",
    re.I | re.M,
)
#: 被反引号包裹的命令（Markdown 行内代码里塞命令）
_NOTICE_CMD_TICK = re.compile(
    r"`[^`\n]*(?:curl|wget|nmap|nc|ncat|netcat|openssl|sqlmap|nikto|"
    r"python3?|perl|ruby|http|httpie|ffuf|gobuster|dirsearch)\b[^`\n]*`",
    re.I,
)
#: 兜底探针：**任何位置**出现命令词。前两条只覆盖已知形态，
#: reproduction 是各检测器自己拼的字符串，形态不受控 ——
#: 漏掉一种形态就等于通告里漏出一段可执行内容。
#: 命中兜底时整段替换：宁可少给细节，也不能让通告变成可执行手册。
#:
#: 故意**不收** nslookup / dig / host：它们是公开递归查询，任何人都能查，
#: 收敛它没有安全收益，却会让「域名没配 SPF」这类条目的复现变得不可操作。
#: 收敛的对象是「能对着目标系统跑出东西的命令」，不是所有命令行。
_NOTICE_CMD_PROBE = re.compile(
    r"\b(?:curl|wget|nmap|ncat|netcat|openssl|sqlmap|nikto|"
    r"ffuf|gobuster|dirsearch|httpie)\b",
    re.I,
)
_NOTICE_URL = re.compile(r"https?://[^\s'\"<>|)\\]+")
_NOTICE_CMD_MASK = "（请求构造见《技术版报告》对应条目）"


def notice_repro_mask(text: str, *, full: bool = False) -> str:
    """把复现步骤改写成「可公开通晒」的形态。

    `full=True` 时原样返回 —— 那是给内部技术通道用的，由调用方显式选择，
    不能是默认值。默认收敛的代价是命令细节少了，但 URL 与判定标准都在，
    负责人照样能自行确认问题是否真实存在。
    """
    if full or not text:
        return text or ""

    def _one(m: re.Match[str]) -> str:
        line = m.group(0)
        urls = _NOTICE_URL.findall(line)
        if not urls:
            return _NOTICE_CMD_MASK
        # 一条命令里有多个地址时全部保留（通常是被测的同一组端点），
        # 但只留地址本身：管道、参数构造、payload 一律不进通告。
        head = "、".join(f"`{u}`" for u in urls[:5])
        more = "（等）" if len(urls) > 5 else ""
        return f"访问 {head}{more}"

    t = _NOTICE_FENCE.sub(_NOTICE_CMD_MASK, text)
    t = _NOTICE_CMD_TICK.sub(_one, t)
    t = _NOTICE_CMD_HEAD.sub(_one, t)
    # 兜底：还有命令词没被上面两条收掉 → 说明是没预判到的形态，整段退掉
    if _NOTICE_CMD_PROBE.search(t):
        return _NOTICE_CMD_MASK
    return t


#: Markdown 代码段（反引号内的内容按字面渲染，**不**转义）。
_MD_CODE_SPAN = re.compile(r"`[^`\n]*`")


def md_escape_plain_underscores(text: str) -> str:
    """给**反引号之外**的下划线加反斜杠转义。

    为什么需要：通告里的复现命令是各检测器自己拼出来的字符串，形态不受控。
    Markdown 正文中一对 `_` 会被解析成强调，把中间的内容吃掉半行 ——
    `nslookup -type=TXT _dmarc.a.com _dmarc.b.com` 这类两条查询并排的写法
    就会渲染成斜体，负责人照着做时看到的是错的命令。

    **代码段（反引号内）不转义**：那里按字面渲染，加了反而会显示成 `\\_`。
    位置行本来就是 `` `DNS TXT _dmarc.<域名>` `` 这种形态，因此只有
    复现行（纯文本）需要处理。

    2026-10-08 安全负责人改版通告时手工做的正是这件事（`_dmarc` → `\\_dmarc`），
    这里把它固化成渲染器的默认行为，不再依赖人手补。
    """
    if not text or "_" not in text:
        return text
    out: list[str] = []
    last = 0
    for m in _MD_CODE_SPAN.finditer(text):
        out.append(text[last:m.start()].replace("_", r"\_"))
        out.append(m.group(0))          # 代码段原样保留
        last = m.end()
    out.append(text[last:].replace("_", r"\_"))
    return "".join(out)


def summarize_bypass(probes: list[dict[str, Any]],
                     skip_reason: str = "",
                     interception_occurred: bool = False) -> dict[str, Any]:
    """绕过试探结果的通告侧适配。

    单独包一层而不是直接 import：report 层要在**没有引擎包**的环境下
    也能渲染旧归档（缺数据就退化为「没试过」，不得编造）。

    `skip_reason` 非空表示**本轮根本没做**绕过试探（未探到拦截行为）。
    此时 `tried == 0`，必须把原因一路带到报告 —— 否则读者会把「没试绕过」
    读成「试过了、防护有效」，这是比「测了没问题」更隐蔽的假结论。

    `interception_occurred`（2026-09-30 新增）：本轮**是否真的被拦过**。
    「没试绕过」有两种成因，措辞必须分开 —— 混在一起就会写出假话：
      · 全程没拦过 → 「本次既没撞上墙，没有可绕之物」（成立）
      · **中途被拦过、但试探是在被判之前跳过的** → 上面那句就**是假的**，
        报告会一边写「触发拦截且未恢复」一边写「没撞上墙」（内部生产系统 实测，
        同一节自相矛盾，通告要贴进部门大群）。
    """
    try:
        from engine.wafbypass import summarize as _s  # noqa: PLC0415
        out = dict(_s(probes))
    except Exception:  # noqa: BLE001
        # 缺数据时以「不可采信」返回。宁可写成「没测 / 测了不算」，
        # 也不能让缺数据的旧归档渲染出「拦截对本来源覆盖完整」这类覆盖率结论。
        out = {"tried": 0, "blocked": 0, "missed": 0, "missed_names": [],
               "baseline_status": 0, "baseline_ok": False, "usable": False,
               "baseline_blocked": False, "nothing_blocked": False,
               "bypass_candidates": [], "bypass_candidates_note": ""}
    out["skip_reason"] = str(skip_reason or "")
    out["interception_occurred"] = bool(interception_occurred)
    return out


@dataclass
class ReportContext:
    """生成报告所需的全部上下文。"""

    target_name: str
    primary_domain: str
    scan_time: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    profile_name: str = "标准档"
    features: dict[str, Any] = field(default_factory=dict)      # 特征判定结果
    dns: dict[str, Any] = field(default_factory=dict)
    root_probe: dict[str, Any] = field(default_factory=dict)
    authorization: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    fallbacks: list[str] = field(default_factory=list)
    checklist_meta: dict[str, Any] = field(default_factory=dict)
    authz_findings: list[Finding] = field(default_factory=list)  # 盲区专项
    verify_runs: list[dict[str, Any]] = field(default_factory=list)
    business_notes: list[str] = field(default_factory=list)      # 业务逻辑人工验证记录
    pending: list[Finding] = field(default_factory=list)
    # ---- 逐项执行状态（第 3 章的唯一数据源）----
    # 这些字段来自 engine.registry 的逐项执行结果。报告必须依据它出结论，
    # 不能再用「适用且无发现 = 通过」这种推理 —— 那正是假阴性的来源。
    item_results: list[Any] = field(default_factory=list)
    detector_summary: dict[str, Any] = field(default_factory=dict)
    detector_notes: list[str] = field(default_factory=list)
    # 外部引擎（nuclei）结果回填检查项的留痕。
    # 它决定「第 3 章的状态」与「第 2 章的发现」是否自相矛盾，必须可机器读取。
    external_backfill: Any = None
    submissions: list[dict[str, Any]] = field(default_factory=list)
    # 采集充分度：判定所有 N/A 结论可信度的依据
    collection: dict[str, Any] = field(default_factory=dict)
    # ---- 外部引擎（nuclei）本轮的执行情况 ----
    # nuclei 是唯一自行发请求的一步，不受本工程节流器约束。它的**执行范围与
    # 是否被预算截断**直接决定「没有发现」该怎么读：跑完了没发现，和跑到一半
    # 被掐断，是两件完全不同的事。不披露等于把后者当前者。
    nuclei_run: dict[str, Any] = field(default_factory=dict)
    # ---- 凭据缺口（登录态没到位时的补齐路径）----
    # 「需要令牌但拿不到」过去是个静默终点：报告里只说「未执行」，
    # 读者不知道该去哪拿、怎么给，于是那几项永远补不上。
    # 这一节把「去哪拿（有证据的登录入口）→ 怎么给（写进本机凭据库）→
    # 怎么验（回验登录态）→ 怎么补跑」写成可照做的路径。
    # **它不改变任何检查项的状态**：凭据未到位时那些项仍是「未执行」。
    cred_ask: dict[str, Any] = field(default_factory=dict)
    # 入口页渲染情况（P3）：渲染是**有副作用**的动作（会在浏览器里执行目标页 JS），
    # 必须像受控写一样披露；它同时决定了「N/A 是真不适用还是没看到」。
    render: dict[str, Any] = field(default_factory=dict)
    # ---- 发现准入闸门（第 2 章的唯一数据源）----
    # fs 里只含「已复现」的发现。其余按复现结果分类，在该章末尾单列披露。
    # 这是「报告里的每条漏洞都能复测」的机制保证。
    gate_result: Any = None
    blocked_findings: list[Any] = field(default_factory=list)
    # ---- 枚举与探测覆盖范围（第 6 章附录的唯一数据源）----
    # 「没发现问题」只有在说清「试过什么」之后才有意义。
    coverage: dict[str, Any] = field(default_factory=dict)
    # ---- 边界防护判定（被 WAF 全量拦截时，本报告的结论范围会被收缩）----
    # 这是最高优先级的披露项：如果目标在边缘就被接管，整份报告对「应用本身」
    # 没有任何结论。不显眼地写出来，读者会把「未执行」看成「没问题」。
    boundary: Any = None
    # ---- 运行期边界封禁记录（B 类拦截：开扫正常、扫到一半被拉黑）----
    # 与 boundary 是两件事：那个是「从头到尾没进去」，这个是「进去了被赶出来」。
    # 后者更隐蔽 —— 报告看起来一切正常，但后半段的结论可能建立在拦截页上。
    boundary_guard: Any = None
    # 边界防护绕过试探结果（engine.wafbypass 的产出，dict 列表）。
    # 探到防护后红队试没试绕过、试了哪些变形、结果如何 —— 通告「防护有效性」
    # 一节直接引用，技术版存档备查。
    bypass_probes: list[dict[str, Any]] = field(default_factory=list)
    # 绕过试探被**跳过**时的具名原因（空串 = 执行了）。
    # 跳过不是「没做」——必须在报告里说清为什么不做，否则读者会把
    # 「没试绕过」读成「试过了、防护有效」。2026-09-30 起：未探到拦截行为时
    # 不再无条件烧那十来发流量（流量本身就是按请求量的频次封禁触发器）。
    bypass_skip_reason: str = ""
    # ---- 目标健康度守门触发时的停手原因（`hard_limits.stop_on`，空串 = 未触发）----
    # **必须与 boundary_guard 分开披露，措辞不得互换**：
    #   · boundary_guard    → 「请求没到达应用」（拿到的是拦截页）
    #   · target_health_stop → 「请求**到了**应用，应用自己在返 5xx / 耗时暴增」
    # 复用同一段措辞就是在报告里写下与事实相反的话 —— 比不给结论更坏，
    # 因为研发会据此去查错的方向（查 WAF 白名单 vs 查服务为什么崩）。
    target_health_stop: str = ""
    # ---- 健康度守门被 AISCAN_HEALTH_GUARD=off 显式关闭（一次性靶场基准专用）----
    # 关闭是操作者的主动选择，不是故障；但必须写进报告 —— 否则读者会以为
    # 「连续 5xx 会停手」这道闸本轮仍在，而它实际不在（登记了却不生效的反面：
    # 没生效却没说）。仅限靶场：靶场的 5xx 是应用的正常应答形态。
    health_guard_off: bool = False
    # ---- 档位速率被全局硬上限收敛时的留痕（空串 = 没被收敛）----
    # `hard_limits.rate_ceiling_rps` 此前零读取点。收敛本身无害（只是更慢），
    # 但「你以为跑在 100 rps、实际被削到 200 上限以外的值」必须能被说出来。
    rate_ceiling_clamp: str = ""
    # ---- 此前扫描「已上报、本轮没有结论」的发现（承接用）----
    # 每一项：{title, severity, endpoint, item_id, from_run}。用途只有一个：
    # 本轮「问题清单」不能因为本轮没去复看就变成空的 —— 那会让读者把
    # 「没看」读成「没问题」。**必须回溯多轮**，不能只看上一轮：上一轮可能
    # 整场被边界拦住、0 条发现，那次「0 条」是「没看到」不是「没有了」；
    # 只看上一轮，此前真正报出来的严重漏洞会在后一次无效扫描里凭空消失
    # （2026-09-30 安全负责人指出：上一轮报过严重漏洞，本轮通告却写
    # 「问题清单为空」—— 归档里，报出问题那轮与「0 条」那轮中间还隔了一轮）。
    # 这些条目**不得**计入本轮的「已修复」，也不得当作本轮的真发现 ——
    # 只如实标注「此前扫描上报过、本轮未复测，真伪需复测确认」。
    prior_unverified: list[dict[str, Any]] = field(default_factory=list)
    # ---- 红队模式的攻击目标结论（黑客运维视角下非空）----
    # 这是红队模式下**最核心**的结论：不是「有哪些漏洞」，而是
    # 「攻击目标是否达成」。三态（已达成 / 未达成 / 未能验证）必须分开渲染。
    objectives: list[Any] = field(default_factory=list)
    # 扫描模式：默认黑客运维视角（默认值定义见 engine/redteam.py）
    mode: str = DEFAULT_MODE
    # 本次实际生效的影响级别上限（档位与台账取更保守的一个）。
    # 必须披露：读者要能判断某目标的「未能验证」是打不穿，还是本次授权不够。
    impact_cap: str = ""
    # ---- 攻击链组合结果（发现 → 目标的因果链）----
    # 单点发现回答「这里有个洞」，攻击链回答「这些洞连起来能打到哪」。
    # ⚠️ 候选链是**推理**，必须在报告里与实测结论严格区分开 ——
    # 写成「已达成」的那几条其链尾能力必须是单点实测证明过的。
    chains: list[Any] = field(default_factory=list)
    # 攻击链分析的「未产链」说明（例如：本次没有任何发现经过实测证明，
    # 因此不产出纯推理链）。必须披露 —— 读者要能区分
    # 「分析过了、确实组合不出链」与「这一节被跳过了」。
    chain_notes: list[str] = field(default_factory=list)
    # ---- 链补证结果（engine.chainclose.ClosureReport）----
    # 候选链上的「待确认」如果只列清单不去打，红队就停在半路上。
    # 补证派发的每次实测、升级了哪条链、哪些能力没有自动验证体，
    # 都必须进报告 —— 尤其「能力缺口」：静默跳过与「测了没问题」长得一样。
    chain_closure: Any = None
    # ---- 黑客视角的凭据获取留痕（engine.credhunt 的 HuntResult.to_dict）----
    # 红队零凭据入场，「找登录入口 + 受控默认口令尝试」是主动动作，
    # 必须与受控写同样逐次披露：试了哪些账号、几次、结果如何、为什么停。
    # 口令原文不记录（只有散列指纹），所以这张表可以安全地进报告。
    credhunt: dict[str, Any] = field(default_factory=dict)
    # ---- 凭据情报留痕（engine.credosint 的 OsintResult.to_dict）----
    # 红队自己上网找登录凭据的**主动外部动作**：识别产品 → 查产品默认口令 →
    # 检索公开资料。必须披露的是「发了几次检索、检索词是什么」——
    # 主动外部检索会向第三方暴露「有人正在关注该目标」这一事实，
    # 使用方有权知道这件事发生过。
    credosint: dict[str, Any] = field(default_factory=dict)

    # ---- 渲染来源 ----
    # `"run"` = 这份上下文来自**本轮运行的内存**（编排器自己产出的）。
    # 其余取值（含默认空串）= 外来渲染：可能是重渲染历史归档、可能是自测夹具、
    # 可能是别人手工拼的上下文。
    #
    # 为什么要显式区分：真实运行里 `credhunt` / `credosint` / `bypass_probes`
    # 这些字段**合法地**可能为空（功能跑了但没命中、或有副作用动作按档位关闭）。
    # 光看「字段是否为空」分不出「本轮确实什么都没有」和「这份上下文压根没带」——
    # 前者是结论，后者是缺数据。混为一谈会让真实报告被误标成「降级」，
    # 也会让真正的降级报告藏在噪声里。
    render_source: str = ""


# 归档目录的标志文件：出现任意一个，说明这个目录是**某一轮真实运行**的产出。
ARCHIVE_MARKERS: tuple[str, ...] = ("run-manifest.json", "检查项结论.json")

# 渲染一份**完整**报告所依赖的运行期上下文。这些字段不像 findings / 检查项状态
# 那样能从归档文件反推 —— 它们只存在于跑那一轮时的内存里。
# 缺了它们，报告不会报错，只会**静默地**整段塌陷或给出错数字：
#   gate_result     → 第 2 章准入结论、闸门统计
#   objectives      → 3.3 攻击目标已尝试的手段、1.4 攻击目标达成情况
#   chains          → 3.4 攻击链分析
#   collection      → 3.2 采集充分度
#   nuclei_run      → 3.2.2 外部引擎执行情况
#   credhunt/credosint → 3.26 凭据缺口、4.1 凭据获取与凭据情报
#   boundary/bypass/boundary_guard → 通告「防护有效性」一节
# ⚠ `target_health_stop` / `rate_ceiling_clamp` **不在此列**：它们在正常情况下
#   合法为空（没停手 / 没被封顶），而本清单的空值判定会把空字段标成
#   「降级渲染」。加进去 = 每份正常报告都背上一条假告警 —— 比不报更坏。
RENDER_CRITICAL_FIELDS: tuple[str, ...] = (
    "gate_result", "objectives", "chains", "collection", "nuclei_run",
    "credhunt", "credosint", "boundary", "boundary_guard", "bypass_probes",
    "blocked_findings", "item_results", "coverage", "detector_notes",
    "submissions", "external_backfill", "render",
)


class ReportGenerator:
    """固定七章报告生成器。"""

    def __init__(self, out_dir: Path | str):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    # ==================================================================
    def _refuse_blind_archive_overwrite(self, ctx: ReportContext,
                                        allow: bool) -> None:
        """拦掉「往已完成的扫描归档里盲目覆盖」这一动作。

        为什么需要一道硬闸：归档是那一轮真实运行留下的**唯一凭据**。
        2026-09-30 出过一次事故 —— 为了改扫描通告里的一句措辞，直接对已完成的
        归档目录调了 `generate()`。结果是：技术版报告、管理层摘要、结构化数据
        被一份**上下文残缺**的渲染覆盖，章节成段消失（`需人工复核的 N/A 项`
        从 12 项变成 0 项、`检查项` 从全量检查项变成 0 项、`攻击目标` 从 3 个
        变成「未产出任何结论」），而同一目录里的 `run-manifest.json` 还写着
        正确结论 —— 两份文件互相矛盾，谁也不知道该信哪个。

        这类损坏的危险之处在于**它长得像正常文件**：名字对、格式对、体积也
        像那么回事，只有逐字比对才发现数字是错的。所以不能靠「小心一点」，
        必须有闸。

        `allow=True` 只应该由「正在产出自己这一轮归档」的编排器传 ——
        它是这个目录的**所有者**。想重渲染历史归档，请渲染到另一个目录再比对，
        不要就地覆盖：残缺上下文渲染出来的东西不是那一轮的产出。
        """
        if allow:
            return
        hit = [m for m in ARCHIVE_MARKERS if (self.out_dir / m).exists()]
        if not hit:
            return
        raise RuntimeError(
            f"拒绝覆盖已完成的扫描归档：{self.out_dir}\n"
            f"  该目录含 {('、'.join(hit))}，属于某一轮真实运行的产出。\n"
            f"  就地覆盖会**静默改写**那一轮的交付物；若本次渲染缺少运行期上下文"
            f"（{('、'.join(RENDER_CRITICAL_FIELDS[:6]))} 等），报告会成段塌陷"
            f"而外观完全正常，事后无从分辨。\n"
            f"  确认这就是本轮自己的归档 → 显式传 allow_archive_overwrite=True；\n"
            f"  要重渲染历史归档 → 渲染到另一个目录，比对后再人工决定是否采纳。"
        )

    # ==================================================================
    def _write_render_provenance(self, ctx: ReportContext,
                                 written: dict[str, Path]) -> Path:
        """落一份「本次渲染拿到了哪些运行期上下文」的留痕。

        坏报告和好报告的差别**不在外观**，而在「哪个字段是空的」。把填充情况
        落盘，事后任何人（包括批量统计）都能一眼看出某份报告是不是残缺上下文
        渲染出来的 —— 不需要靠人去猜「这数字怎么这么小」。
        """
        filled: list[str] = []
        empty: list[str] = []
        for name in RENDER_CRITICAL_FIELDS:
            val = getattr(ctx, name, None)
            (filled if val else empty).append(name)
        _src = str(getattr(ctx, "render_source", "") or "")
        _is_run = _src == "run"
        # `context_complete` 的判据是「这份上下文来自本轮运行」，不是「字段都非空」——
        # 真实运行里若干字段合法为空，用「非空」当判据会把正常报告标成降级。
        _complete = _is_run or not empty
        stamp = {
            "rendered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": ctx.target_name,
            "domain": ctx.primary_domain,
            "scan_time": ctx.scan_time,
            "out_dir": str(self.out_dir),
            "render_source": _src or "(未声明)",
            "is_live_run": _is_run,
            "context_filled": filled,
            "context_empty": empty,
            "context_complete": _complete,
            "warning": ("" if _complete else
                        "降级渲染：缺运行期上下文，相关章节会塌陷或给出错误数字"),
            "files": {k: Path(v).name for k, v in written.items()},
            "note": (
                "is_live_run=false ⇒ 这不是本工具的实时扫描产出，而是外来渲染"
                "（重渲染历史归档 / 自测夹具 / 手工拼的上下文）。此时 context_empty"
                " 里的字段代表「这份上下文没带」，相关章节会塌陷 —— "
                "该产出**不得**当作那一轮的完整交付物。"
            ),
        }
        p = self.out_dir / f"{ctx.target_name}_渲染留痕.json"
        p.write_text(json.dumps(stamp, ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return p

    # ==================================================================
    def generate(self, ctx: ReportContext, fs: FindingSet,
                 applicability: list[ApplicabilityResult],
                 *, notice_full_repro: bool = False,
                 allow_archive_overwrite: bool = False) -> dict[str, Path]:
        """生成技术版、管理层摘要与扫描通告三份报告。

        `notice_full_repro=True` 时，扫描通告保留完整复现命令。
        **默认 False（收敛）** —— 通告是给部门大群看的，一份带可直接执行
        命令的通告等于把验证手册分发给所有能看到群消息的人。要完整版
        请显式指定，别把默认值改掉。

        `allow_archive_overwrite=True` 只由本轮编排器传（它是归档的所有者）。
        默认 False 时，往带 `run-manifest.json` 的目录里写会直接抛错 ——
        见 `_refuse_blind_archive_overwrite` 里记的那次事故。
        """
        self._refuse_blind_archive_overwrite(ctx, allow_archive_overwrite)
        tech = self._render_technical(ctx, fs, applicability)
        execu = self._render_executive(ctx, fs, applicability)
        notice = self._render_notice(ctx, fs, applicability,
                                     full_repro=notice_full_repro)

        p_tech = self.out_dir / f"{ctx.target_name}_技术版报告.md"
        p_exec = self.out_dir / f"{ctx.target_name}_管理层摘要.md"
        p_notice = self.out_dir / f"{ctx.target_name}_扫描通告.md"
        p_tech.write_text(tech, encoding="utf-8")
        p_exec.write_text(execu, encoding="utf-8")
        p_notice.write_text(notice, encoding="utf-8")

        # 同时落一份结构化数据，供复扫 diff 使用
        p_json = self.out_dir / f"{ctx.target_name}_findings.json"
        payload = fs.to_dict()
        payload["applicability"] = [r.to_dict() for r in applicability]
        payload["context"] = {
            "target": ctx.target_name, "domain": ctx.primary_domain,
            "scan_time": ctx.scan_time, "profile": ctx.profile_name,
        }
        # 采集充分度必须落盘：它决定「整份报告的 N/A 能不能当结论用」。
        # 尤其前端产物抓取失败时的覆盖度下降 —— 那一整类检查项的「通过」
        # 是在空数据上得出的，批量统计不看这个字段就会把它们当真的通过。
        payload["collection"] = dict(ctx.collection or {})
        # 外部引擎的执行范围与截断事实必须落盘：批量统计/复扫比对要能分辨
        # 「跑完了没发现」与「跑到一半被预算掐断」——前者是结论，后者不是。
        payload["nuclei"] = dict(ctx.nuclei_run or {})
        # 闸门判定全量落盘：findings 里只有「已复现」的，其余在这里可追溯。
        # 不落盘的话，「哪些被拦下、为什么被拦下」就只存在于当次内存里，
        # 复扫比对与事后复盘都无从下手。
        if ctx.gate_result is not None:
            payload["gate"] = {
                "verify_ran": getattr(ctx.gate_result, "verify_ran", False),
                "verify_note": getattr(ctx.gate_result, "verify_note", ""),
                "stats": ctx.gate_result.stats(),
                "decisions": [d.to_dict() for d in ctx.gate_result.decisions],
            }
        else:
            payload["gate"] = {"verify_ran": False,
                               "verify_note": "未接入准入闸门",
                               "stats": {}, "decisions": []}
        payload["blocked_findings"] = [f.to_dict() for f in ctx.blocked_findings]
        # 外部引擎结果回填的留痕：它是「第 3 章状态」与「第 2 章发现」是否
        # 一致的可核对凭据。不回填时报告会自相矛盾（同一项既列发现又写「通过」），
        # 而批量统计只看 JSON，看不到那两栏打架。
        _bf = ctx.external_backfill
        payload["external_backfill"] = ({
            "source": getattr(_bf, "source", ""),
            "attached": getattr(_bf, "attached", 0),
            "items_touched": getattr(_bf, "items_touched", 0),
            "state_changed": dict(getattr(_bf, "state_changed", {}) or {}),
            "already": getattr(_bf, "already", 0),
            "skipped_non_vuln": getattr(_bf, "skipped_non_vuln", 0),
            "unmapped": list(getattr(_bf, "unmapped", []) or []),
            "notes": list(getattr(_bf, "notes", []) or []),
            "mapping_stats": _mapping_stats(),
        } if _bf is not None else {"source": "", "attached": 0,
                                   "skipped_non_vuln": 0, "unmapped": []})
        # 复现会话要求落盘：越权类脚本在没填会话时给出的是「无法判定」，
        # 而下游批量统计只会看到退出码 2。不把「需要身份」这件事落盘，
        # 统计侧就永远分不清「工具能力不足」与「凭据没填」——
        # 前者要补检测器，后者只要填一份 JSON，处置动作完全不同。
        payload["repro_sessions"] = {
            "needed": [
                {"item_id": f.item_id, "title": f.title,
                 "roles": list((f.extra or {}).get("repro_roles") or [])}
                for f in list(fs.findings) + list(ctx.blocked_findings or [])
                if (f.extra or {}).get("repro_needs_session")
            ],
            "howto": ("在复现脚本同目录的 aiscan_sessions.json 中填入各账号 Cookie / Token"
                      "后重跑；脚本自行读取，无需改动脚本。"
                      "也可用环境变量 AISCAN_COOKIE_<角色> / AISCAN_AUTH_<角色>。"),
        }
        # 红队模式的攻击目标结论落盘：首屏结论必须可机器读取，
        # 便于批量统计「有多少目标是真被打穿的」。
        payload["mode"] = ctx.mode
        payload["impact_cap"] = ctx.impact_cap
        payload["objectives"] = [o.to_dict() for o in (ctx.objectives or [])
                                 if hasattr(o, "to_dict")]
        # 攻击链落盘：与 objectives 同理，「已达成」的链与「候选」链必须可区分，
        # 否则批量统计会把推理链当成实测战果计数。
        payload["attack_chains"] = {
            "proven": [c.to_dict() for c in (ctx.chains or [])
                       if hasattr(c, "to_dict") and c.state == "已达成"],
            "candidates": [c.to_dict() for c in (ctx.chains or [])
                           if hasattr(c, "to_dict") and c.state != "已达成"],
            "inferred": [c.to_dict() for c in (ctx.chains or [])
                         if hasattr(c, "to_dict") and c.state != "已达成"
                         and not getattr(c, "testable", True)],
            "notes": list(ctx.chain_notes or []),
            # 链补证：派发了哪些实测、升级了哪条链、哪些能力没验证体。
            # 「能力缺口」必须可机器读取 —— 否则批量统计会把「没测」当成「没问题」。
            "closure": (ctx.chain_closure.to_dict()
                        if ctx.chain_closure is not None
                        and hasattr(ctx.chain_closure, "to_dict") else None),
        }
        # 边界防护判定落盘：它决定整份报告的结论范围，必须可机器读取，
        # 便于批量统计「有多少目标压根没扫到」。
        payload["boundary"] = (ctx.boundary.to_dict()
                               if ctx.boundary is not None and
                               hasattr(ctx.boundary, "to_dict") else {"blocked": False})
        # 运行期封禁记录同样落盘：它是判断「后半段结论是否可信」的唯一凭据，
        # 批量统计时能一眼看出哪些目标是「完整扫完的」、哪些是「被打断的」。
        payload["boundary_guard"] = (ctx.boundary_guard.to_dict()
                                     if ctx.boundary_guard is not None and
                                     hasattr(ctx.boundary_guard, "to_dict")
                                     else {"occurred": False})
        # 绕过试探结果落盘：通告「防护有效性」一节的凭据，复扫比对时
        # 能看出「这轮防护缺口比上轮多 / 少」。
        payload["bypass_probes"] = list(ctx.bypass_probes or [])
        # 目标健康度停手与速率收敛落盘：批量统计时能一眼区分「被 WAF 拦住」
        # 与「目标自身异常导致停手」—— 两者的处置动作完全不同。
        payload["target_health_stop"] = str(ctx.target_health_stop or "")
        payload["rate_ceiling_clamp"] = str(ctx.rate_ceiling_clamp or "")
        # 守门被显式关闭同样落盘：批量统计时「这轮没有停手保护」必须能被
        # 机器读到，不能只藏在正文措辞里。
        payload["health_guard_off"] = bool(getattr(ctx, "health_guard_off", False))
        # 凭据获取留痕落盘：这是「本次是否主动向目标提交过口令」的唯一机器可读
        # 凭据 —— 批量统计与事后审计都据此核对，正文里的留痕表会被阅读者忽略，
        # 而「工具到底有没有试过口令」是必须能一眼查证的事实。
        # **口令原文不在其中**（HuntResult.to_dict 只给散列指纹），
        # 所以这份 JSON 可以随报告一起归档、转发。
        # ran 字段是必需的：只用 enabled 无法区分「跑过但没命中」与「压根没跑」——
        # 后者（模块未接线 / 抛异常）会被读成「档位关闭、符合预期」，
        # 于是一次真实的「口令尝试发生了但没人知道」就这么静默过去了。
        _chj = ctx.credhunt or {}
        payload["credential_hunt"] = ({**_chj, "ran": True} if _chj else {
            "ran": False, "enabled": False, "reason": "未执行凭据获取流程",
            "tried": 0, "found_identities": [], "attempts": [], "notes": []})
        # 凭据情报同样落盘，且**检索词一并落盘**：批量审计只看 JSON，
        # 而「向外部检索源发过什么查询」是本项目的一条披露义务 ——
        # 只落盘「做了情报检索」而不落检索词，等于披露了一半。
        _osj = ctx.credosint or {}
        payload["credential_osint"] = ({**_osj, "ran": True} if _osj else {
            "ran": False, "enabled": False, "reason": "未执行凭据情报流程",
            "products": [], "candidates": [], "leads": [], "queries": [],
            "sources": {}, "notes": []})
        p_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        written = {"technical": p_tech, "notice": p_notice,
                   "executive": p_exec, "data": p_json}
        # 渲染留痕必须**最后**写：它是判断上面四份产出完整性的凭据，
        # 自己得能反映「这四份是在什么上下文下渲染出来的」。
        written["provenance"] = self._write_render_provenance(ctx, written)
        return written

    @staticmethod
    # ==================================================================
    # 红队模式：攻击目标达成情况
    # ==================================================================
    @staticmethod
    def _objective_matrix(ctx: ReportContext, brief: bool = False,
                          with_matrix: bool = True,
                          heading: str = "### 攻击目标达成情况") -> list[str]:
        """渲染「攻击目标达成情况」—— 红队模式的首屏结论。

        三条渲染铁律：
          1. 三态必须分开表述，**不得把「未能验证」写成「未达成」**；
          2. 「未达成」必须列出已尝试的手段 —— 否则与「没测」无法区分；
          3. 「已达成」必须给出证据链，让读者能自行判断可信度。

        brief=True 时只给「结论矩阵 + 影响级别上限 + 三态声明 + 指向明细的索引」，
        供第 1 章结论前置使用。「已尝试的手段」明细留在第 3 章 ——
        明细**不会消失**，只是换了位置，否则首屏会被过程细节挤满。
        """
        from engine.redteam import (
            IMPACT_LABEL, INCONCLUSIVE, NOT_PROVEN, PROVEN,
        )

        m = Masker("internal")
        L: list[str] = [heading, ""]
        # 结论矩阵只在第 1 章出现；第 3 章只要明细，同一张表不印两遍。
        if with_matrix:
            L.append("| 攻击目标 | 结论 | 说明 |")
            L.append("|---|---|---|")
            for oc in ctx.objectives:
                if not getattr(oc, "authorized", True):
                    # 未执行的成因必须说清（redteam 铁律 2b）：「档位默认不含」与
                    # 「台账未授权」是两码事。一律写「未授权」会把档位强度问题
                    # 误导成授权问题 —— 读者会去查一个根本不存在的授权缺口。
                    mark = "未能验证"
                    _kind = getattr(oc, "scope_kind", "")
                    if _kind == "profile":
                        note = ("**本档位不含该目标，未执行** —— 属**档位强度设定**，"
                                "**与目标是否获得授权无关**；换更高档位（deep 档含全部"
                                "三个目标）后重扫。")
                    elif _kind == "ledger":
                        note = ("**该攻击目标未在授权台账登记，未执行** —— "
                                "需在授权台账扩展该目标的授权范围后重扫。")
                    else:
                        note = ("**未纳入本次执行范围，未执行** —— 本次无法判断是"
                                "档位设定还是授权范围所致。")
                else:
                    mark = {PROVEN: "**已达成**", NOT_PROVEN: "未达成",
                            INCONCLUSIVE: "未能验证"}.get(oc.result, oc.result)
                    # 「已达成」的来源必须标明：打出来的（独立攻击路径实测）
                    # 与组合出来的（攻击链分析回填）可信度判断依据不同。
                    if oc.result == PROVEN and getattr(oc, "chain_note", ""):
                        mark = "**已达成**（组合证明）"
                    note = m.mask(str(getattr(oc, "reason", "") or ""))
                L.append(f"| {oc.label} | {mark} | {note} |")
            L.append("")
        if ctx.impact_cap and with_matrix:
            # 影响级别上限必须披露，否则读者无法判断某目标的「未能验证」
            # 究竟是「打不穿」还是「本次授权不够深」。这两者的处置完全不同。
            L.append(f"> 本次影响级别上限：**{ctx.impact_cap}**"
                     f"（{IMPACT_LABEL.get(ctx.impact_cap, '')}）。"
                     f"超过该级别的验证手法本次不会执行。")
            L.append("")

        # 简版：首屏只回答「打穿了没有」，不铺开过程。
        if brief:
            if any(oc.result == INCONCLUSIVE for oc in ctx.objectives):
                L.append("> **「未能验证」不等于「未达成」。**"
                         "它表示条件不足以下结论（缺授权 / 缺账号 / 手法未覆盖），"
                         "既不说明目标安全，也不说明目标有问题。")
                L.append("")
            L.append("> 各目标「已尝试的手段」与「已达成的证据链」明细见第 3 章。")
            L.append("")
            return L

        for oc in ctx.objectives:
            if oc.result != PROVEN:
                continue
            L.append(f"**{oc.label} —— 已达成的证据链**")
            L.append("")
            for line in oc.evidence_chain():
                L.append(f"- {m.mask(str(line))}")
            L.append("")

        for oc in ctx.objectives:
            if oc.result == PROVEN:
                continue
            att = oc.attempted()
            if not att:
                L.append(f"**{oc.label} —— 本次未执行任何尝试**（无可列手段）")
                L.append("")
                continue
            L.append(f"**{oc.label} —— 已尝试的手段**")
            L.append("")
            for line in att:
                L.append(f"- {m.mask(str(line))}")
            L.append("")

        if any(oc.result == INCONCLUSIVE for oc in ctx.objectives):
            L.append("> **「未能验证」不等于「未达成」。**"
                     "它表示条件不足以下结论（缺授权 / 缺账号 / 手法未覆盖），"
                     "既不说明目标安全，也不说明目标有问题。")
            L.append("")
        return L

    # ==================================================================
    # 攻击链分析（发现 → 攻击目标）
    # ==================================================================
    @staticmethod
    def _attack_chains(ctx: ReportContext,
                       heading: str = "### 攻击链分析（发现 → 攻击目标）"
                       ) -> list[str]:
        """渲染「攻击链分析」—— 把单点发现串成通往攻击目标的因果链。

        措辞必须让读者一眼分清两件事：

            已达成（实测） —— 链尾能力已被**单点实测证明**，结论可直接采信；
            候选链（推理） —— 由能力关系**推导**得出，未逐环实测，
                              用途是「指明下一枪该往哪打」，不是「已经打进去了」。

        **把候选链渲染成既成事实，就是本项目一路在根除的那类假结论。**
        所以两档分开标题、分开措辞，且候选链必须逐条列出待确认条件。
        """
        chains = list(getattr(ctx, "chains", None) or [])
        notes = list(getattr(ctx, "chain_notes", None) or [])
        closure = getattr(ctx, "chain_closure", None)
        if not chains and not notes:
            return []

        from engine.attackchain import PROVEN as _CPROVEN

        m = Masker("internal")
        L: list[str] = [heading, ""]
        L.append("单点发现回答「这里有个洞」，本节回答「这些洞连起来能打到哪」。"
                 "链上每一环都标了证据状态：**只有链尾能力被实测证明过的链"
                 "才判「已达成」**，其余是候选链。")
        L.append("")

        proven = [c for c in chains if c.state == _CPROVEN]
        cand = [c for c in chains if c.state != _CPROVEN]
        # 候选链再分两档：到目标只差一环（已派发补证实测）与缺两环以上
        # （纸面推演）。混在一起报，读者会把「推出来的」当成「打出来的」。
        testable = [c for c in cand if getattr(c, "testable", True)]
        inferred = [c for c in cand if not getattr(c, "testable", True)]

        if proven:
            L.append(f"#### 已达成（{len(proven)} 条）")
            L.append("")
            for i, c in enumerate(proven, 1):
                L.append(f"**{i}. {c.objective_label}** —— {m.mask(c.narrative())}")
                L.append("")
                for n in c.nodes:
                    mark = "✅ 实测已证" if n.proven else "待确认"
                    L.append(f"- `{n.item_id}` {m.mask(n.title)} "
                             f"（{m.mask(n.endpoint) or '无端点'}）"
                             f"→ 提供 {n.caps_label()}，{mark}")
                L.append(f"- 复测：{m.mask(c.repro_hint())}")
                L.append("")

        if testable:
            L.append(f"#### 候选链（{len(testable)} 条，"
                     "**推导所得、尚未逐环实测**；这几条到目标只差一环）")
            L.append("")
            L.append("> **候选链不是漏洞结论。** 它由「已有发现能提供什么能力」与"
                     "「目标需要什么条件」之间的因果关系推导而来，**未逐环实测**。"
                     "这几条到目标只差一环，本次已**派发受控实测**去补证，"
                     "结论见本节末尾「链补证结果」。"
                     "补证成功的会升入上面的「已达成」，未成功的仍在候选档。")
            L.append("")
            for i, c in enumerate(testable, 1):
                L.append(f"**{i}. {c.objective_label}** —— {m.mask(c.narrative())}")
                L.append("")
                for n in c.nodes:
                    mark = "✅ 实测已证" if n.proven else "⚠ 未经实测"
                    L.append(f"- 环节 `{n.item_id}` {m.mask(n.title)} "
                             f"（{m.mask(n.endpoint) or '无端点'}）"
                             f"→ 提供 {n.caps_label()}，{mark}")
                if c.missing:
                    L.append("- **尚待确认**：")
                    for miss in c.missing[:6]:
                        L.append(f"  - {m.mask(str(miss))}")
                L.append(f"- 复测顺序：{m.mask(c.repro_hint())}")
                L.append("")

        if inferred:
            L.append(f"#### 纸面推演链（{len(inferred)} 条，**缺环 ≥2，不作为行动依据**）")
            L.append("")
            L.append("> 这几条到目标还差两环以上，中间每个条件都是未经确认的假设。"
                     "本次**不派发实测** —— 给它们发请求只是把猜测再跑一遍。"
                     "列出它们只说明「存在这个方向」，不等于「这条路走得通」；"
                     "要定论需先把中间环节逐个实测。")
            L.append("")
            for i, c in enumerate(inferred, 1):
                L.append(f"**{i}. {c.objective_label}**（缺 "
                         f"{getattr(c, 'gap_hops', 0)} 环）—— "
                         f"{m.mask(c.narrative())}")
                L.append("")
                for miss in (c.missing or [])[:4]:
                    L.append(f"- {m.mask(str(miss))}")
                L.append("")

        if cand:
            L.append("> 候选链的价值在于**排序**：先确认链尾那一环，"
                     "若链尾不成立，整条链直接排除，无需逐环验证。")
            L.append("")

        # ---- 链补证结果：派发了什么、升级了什么、哪些能力没验证体 ----
        if closure is not None:
            res = list(getattr(closure, "results", None) or [])
            up = list(getattr(closure, "upgraded", None) or [])
            gaps = list(getattr(closure, "gaps", None) or [])
            cnotes = list(getattr(closure, "notes", None) or [])
            L.append("#### 链补证结果（派发的受控实测）")
            L.append("")
            if not res:
                L.append("本轮没有派发补证实测（没有「只差一环」的候选链，"
                         "或各环均已实测证明）。")
                L.append("")
            else:
                L.append(f"共派发 {len(res)} 次能力补证实测，"
                         + (f"其中 {len(up)} 条链由候选升为**已达成**。"
                            if up else "未产生新的「已达成」链。"))
                L.append("")
                L.append("| 环节 | 补证的能力 | 结论 | 依据 |")
                L.append("|---|---|---|---|")
                for r in res[:12]:
                    L.append(f"| `{r.get('item_id', '')}` | {r.get('cap_label', '')} "
                             f"| {r.get('state', '')} "
                             f"| {m.mask(str(r.get('detail') or r.get('gap_reason') or ''))[:160]} |")
                L.append("")
            if gaps:
                L.append(f"**能力缺口（{len(gaps)} 项，本次没有自动验证体或未获授权）：**")
                L.append("")
                for g in gaps[:10]:
                    L.append(f"- {m.mask(str(g))}")
                L.append("")
                L.append("> 「能力缺口」是**没测**，不是「打不穿」—— "
                         "两者在报告上必须分开写。")
                L.append("")
            # 共同缺口：好几条链常卡在同一个东西上（通常是没拿到身份）。
            # 逐条列「待确认」看不出这个共性，读者会以为要分别验证 N 件事，
            # 实际先解决这一件，其余链条才有讨论价值。
            common = list(getattr(closure, "common_gaps", None) or [])
            if common:
                L.append("**下一步该先解决什么（未达成链的共同缺口）：**")
                L.append("")
                L.append("| 缺口 | 影响的链 | 去哪拿 / 怎么办 |")
                L.append("|---|---|---|")
                for g in common[:5]:
                    L.append(f"| {g.get('cap_label', '')} "
                             f"| {g.get('chains', 0)} 条 "
                             f"| {m.mask(str(g.get('action') or ''))[:180]} |")
                L.append("")
                L.append("> 先解决表里第一项：它卡住的链最多，"
                         "解决之后其余链条才有讨论价值。")
                L.append("")
            for n in cnotes:
                L.append(f"> {m.mask(str(n))}")
                L.append("")

        for n in notes:
            L.append(f"> {m.mask(str(n))}")
            L.append("")
        return L

    @staticmethod
    def _boundary_alert(ctx: ReportContext, finding_count: int = 0) -> list[str]:
        """边界防护全量拦截时的顶部告警。未拦截时返回空列表。

        这一段是「用一句话说清报告能不能用」。它必须放在第一屏，因为
        「未执行」与「通过」在读者眼里极易混淆，而两者结论完全相反。

        `finding_count` 必须传**本轮实际发现数**：这段告警写于
        「被封 ⇒ 完全没有发现」的年代；后来短路粒度改成按证据通道分流
        （判据不经过应用的项目照常执行），被封轮次开始产出**非应用层发现**
        （内部生产系统 12:10 那轮就有 2 条中危：SPF / DMARC）。文案不跟着改，
        报告就会当面说假话 —— 「第 2 章漏洞清单为空」而下面明明列着 2 条。
        """
        b = ctx.boundary
        if b is None or not getattr(b, "blocked", False):
            return []
        L: list[str] = []
        L.append("> ## ⛔ 本次扫描未触达应用 —— 本报告对「应用本身」没有结论")
        L.append("> ")
        L.append(f"> 目标被 **{b.vendor or '边界防护组件'}** 在边缘全量接管："
                 f"HTTP 状态码 `{b.status}`，正文命中拦截页特征"
                 f"（{b.signature}），且**随机不存在的路径返回同一张拦截页**"
                 f"（剔除每次请求都变化的 traceid / 时间戳后比对，"
                 f"内容哈希 `{b.root_hash}`）。")
        L.append("> ")
        L.append("> 也就是说，请求根本没有到达业务系统。由此：")
        L.append("> ")
        L.append("> 1. 第 3 章绝大多数自动项的状态是 **「未执行」，不是「通过」**"
                 " —— 没有测到应用，不等于测了没问题；")
        if finding_count:
            # A 类拦截下应用层项全部短路，所以这些发现只可能来自
            # 「判据不经过被测应用」的通道（DNS / 端口 / 证书透明度 / 对象存储端点等）。
            L.append(f"> 2. 第 2 章列出的 {finding_count} 条问题**全部来自"
                     f"不经过 Web 边界的通道**（DNS / 端口 / 证书透明度 / "
                     f"对象存储端点等）；**应用层本次一无所知** —— "
                     f"这不代表应用没有问题；")
        else:
            L.append("> 2. 第 2 章漏洞清单为空 **不代表目标安全**，"
                     "只代表本次没拿到任何可复现的应用层发现；")
        L.append("> 3. **本报告不得作为该系统的安全结论使用。**")
        L.append("> ")
        # 只写实测到的事实。**不要**写「换时间重扫不会改变」——
        # 我们并没有测封禁能持续多久：内部生产系统 同日 11:40 那轮 L1 还拿到了数据、
        # 12:10 那轮才全程被拦，说明来源状态本身在变。断言「再扫也没用」
        # 超出了手上的证据（红线 46 第三款）。
        L.append("> **本来源本次被边界防护整体拦在门外**：退避重试实测未恢复。"
                 "封禁能持续多久本次**没有测到**（既可能是策略级长期拦截，"
                 "也可能是窗口型）—— 本次没有取得应用层的可信结论。")
        L.append("> ")
        L.append("> 判据**不经过被测应用**的检查项（DNS / 端口 / TLS 握手 / "
                 "证书透明度 / 对象存储端点等）不受边界影响，已照常执行，"
                 "结论见第 3 章；需要触达应用的项一律记「未执行」，"
                 "**不得读成通过**。")
        L.append("")
        for n in (getattr(b, "notes", []) or []):
            L.append(f"> ℹ️ {n}")
        if getattr(b, "notes", None):
            L.append("")
        return L

    @staticmethod
    def _render_degradation_alert(ctx: ReportContext) -> list[str]:
        """渲染降级自曝：上下文残缺时，报告正文里必须自己说出来。

        对应项目红线「降级必须能被说出名字」。一份用残缺上下文渲染出来的报告，
        外观与正常报告完全没有区别 —— 章节名都在、表格都整齐，只有数字是错的
        （`需人工复核的 N/A 项` 会显示 0 项、`检查项` 会显示 0 项）。靠人肉
        核对是拦不住的，只能让它自己声明。

        缺字段 → 对应章节会塌陷，这里把「少了什么、哪一章会受影响」直接写进
        第一屏，读者不必自己去猜某个 0 是真 0 还是没数据。

        **只在 `ctx.render_source != "run"` 时才可能触发**：本轮运行的内存上下文
        里，`credhunt` 之类字段为空是**合法结论**（跑了、没命中），不是缺数据。
        详见 `ReportContext.render_source` 的注释。
        """
        if getattr(ctx, "render_source", "") == "run":
            return []
        # 字段 → 它会喂哪一章。这份映射是给人看的，必须写清后果。
        consequences = {
            "gate_result": "第 2 章准入结论与闸门统计",
            "objectives": "1.4 攻击目标达成情况、3.3 攻击目标已尝试的手段",
            "chains": "3.4 攻击链分析",
            "collection": "3.2 采集充分度",
            "nuclei_run": "3.2.2 外部引擎执行情况",
            "credhunt": "3.26 凭据缺口、4.1 凭据获取",
            "credosint": "4.1 凭据情报",
            "boundary": "通告「防护有效性」一节",
            "boundary_guard": "运行期封禁披露",
            "bypass_probes": "通告「绕过尝试」一节",
            "blocked_findings": "未进入漏洞清单的发现",
            "item_results": "第 3 章逐项结论表、未执行/N/A/待人工清单",
            "coverage": "6.4 枚举与探测覆盖范围",
            "detector_notes": "3.1 本次检测的执行落实情况",
            "submissions": "受控写披露",
            "external_backfill": "外部引擎结果回填留痕",
            "render": "前端渲染留痕",
        }
        empty = [f for f in RENDER_CRITICAL_FIELDS
                 if not getattr(ctx, f, None)]
        if not empty:
            return []
        L: list[str] = []
        L.append("> ## ⚠️ 本报告为**降级渲染**，请勿据其判断覆盖情况")
        L.append("> ")
        L.append("> 本次渲染**缺少运行期上下文**，下列章节因此会塌陷或给出"
                 "**错误的数字**（例如 `需人工复核的 N/A 项` 显示 0 项、"
                 "`检查项总数` 显示 0 项）。**这不是那一轮真实运行的完整交付物。**")
        L.append("> ")
        L.append("> | 缺失字段 | 受影响的章节 |")
        L.append("> | --- | --- |")
        for f in empty:
            L.append(f"> | `{f}` | {consequences.get(f, '—')} |")
        L.append("> ")
        L.append("> 请以同一归档目录下的 `检查项结论.json` / `run-manifest.json` "
                 "为准（那两份是那一轮直接落盘的凭据），或重跑一次扫描。")
        L.append("")
        return L

    @staticmethod
    def _guard_alert(ctx: ReportContext) -> list[str]:
        """运行期边界封禁（B 类拦截）的披露。未发生封禁时返回空列表。

        与 `_boundary_alert` 的区别：那个讲的是「从头到尾就没进去」，
        这个讲的是「进去了，扫到一半被赶出来」。**后者更隐蔽** ——
        报告看起来一切正常，但后半段的结论可能建立在拦截页之上，
        其中被判「通过」的项尤其危险：拦截页上什么也测不出来，
        很容易被读成「没发现问题」。
        """
        g = ctx.boundary_guard
        if g is None or not getattr(g, "occurred", False):
            return []
        evs = list(getattr(g, "events", []) or [])
        term = bool(getattr(g, "terminal", False))
        waited = float(getattr(g, "total_waited_s", 0) or 0)
        speed = float(getattr(g, "speed_factor", 1.0) or 1.0)

        L: list[str] = []
        L.append(f"> ## ⚠️ 本次扫描中途被边界防护封禁 {len(evs)} 次")
        L.append("> ")
        L.append(f"> 目标在扫描过程中触发了边界防护（累计退避等待 {waited:.0f} 秒）。"
                 "这与「一开扫就被全量拦截」性质不同：**扫描前段是正常触达应用的，"
                 "后段则可能拿到的是拦截页**，两者混在同一份报告里。")
        L.append("> ")
        # 防护「是哪一家」必须写出来 —— 这是运行期实测命中的结构化证据
        # （BanEvent.vendor），不是推测。2026-09-29 内部生产系统：证据命中了阿里云，
        # 报告却写「厂商特征未确认」，因为厂商名当时只进了日志文本。
        _gv = str(getattr(g, "vendor", "") or "")
        if not _gv and ctx.boundary is not None:
            _gv = str(getattr(ctx.boundary, "vendor", "") or "")
        if _gv:
            L.append(f"> **实测命中的边界防护**：**{_gv}**"
                     f"（拦截页特征命中，非推测）。")
            L.append("> ")
        L.append("> | 次序 | 退避所用（秒） | 结果 |")
        L.append("> | --- | --- | --- |")
        _outcome_cn = {
            "resumed": "已恢复，降速续扫",
            "persistent": "退避耗尽未恢复 → 判定为策略级拦截",
            "budget_exhausted": "等待超预算 → 放弃恢复",
            "rounds_exceeded": "反复被封超上限 → 停止",
        }
        for e in evs:
            used = "、".join(f"{x:.0f}" for x in (getattr(e, "backoff_used", []) or [])) or "—"
            oc = _outcome_cn.get(str(getattr(e, "outcome", "")), str(getattr(e, "outcome", "")))
            L.append(f"> | 第 {getattr(e, 'seq', '?')} 次 | {used} | {oc} |")
        L.append("> ")
        if term:
            L.append("> **封禁后未能恢复**，因此封禁之后的检查项全部按 **「未执行」**"
                     "记录 —— 那不是「通过」。**本报告的整体评级为「无法评估」。**")
        else:
            L.append(f"> 已恢复访问，并将扫描速率降至原速的 **{speed:.0%}** 继续扫完。"
                     "但请特别注意：")
            L.append("> ")
            L.append("> **封禁时点附近执行的检查项，其结论可能建立在拦截页之上。**"
                     "应把它们视为「需要复核」，而不是直接采信 ——"
                     "尤其是那些判为「**通过**」的项：拦截页本身内容单薄，"
                     "很容易被误读成「没发现问题」。")
        L.append("> ")
        # ---- 已做的处置：把窗口内的结论作废 ----
        # 只说「可能被污染」是不够的：读者不知道到底作废了没有、作废了几项。
        # 不说清这两件事，「封禁时点附近的通过」就会原样被采信。
        _inv_n = int(getattr(g, "invalidated_items", 0) or 0)
        _ann_n = int(getattr(g, "annotated_items", 0) or 0)
        _sus_n = int(getattr(g, "suspicion_checks", 0) or 0)
        _wins = g.suspect_ranges() if hasattr(g, "suspect_ranges") else []
        L.append("> **本次已做的处置（消除假通过）**")
        L.append("> ")
        if _wins:
            _w = "、".join(f"探测 {a}–{b}" for a, b in _wins)
            L.append(f"> - 封禁窗口：{_w}。窗口内的取证**无法区分**「应用响应」"
                     "与「拦截页」—— 抽检是抽样，两次抽检之间就是盲区。")
        if _sus_n:
            L.append(f"> - 其中 **{_sus_n} 次抽检由可疑迹象提前触发**"
                     "（同一张非基线拦截页在不同路径上重复出现），"
                     "而不是等到点才抽 —— 这是把盲区压小的手段。")
        if _inv_n:
            L.append(f"> - **{_inv_n} 个检查项**的取证落在封禁窗口内，"
                     "原判「通过 / N/A」已改判为「**待确认**」，"
                     "**不计入通过数**。")
        else:
            L.append("> - 未发现落在封禁窗口内的「通过 / N/A」结论。")
        if _ann_n:
            L.append(f"> - 另有 **{_ann_n} 个「不通过」项**的取证落在窗口内，已加核对标注。"
                     "发现的真伪以复现脚本的复测结果为准（未复现者不进漏洞清单），"
                     "不因这套机制直接翻案 —— 那会把真发现判没。")
        L.append("> ")
        L.append("> 判据**不经过被测应用**的检查项（DNS / 端口 / TLS 握手 / "
                 "证书透明度 / 对象存储端点等）不受边界影响，已在封禁期间照常执行，"
                 "结论见第 3 章；需要触达应用的项一律记「未执行」，不得读成通过。")
        L.append("")
        return L

    @staticmethod
    def _health_alert(ctx: ReportContext) -> list[str]:
        """目标健康度停手（`hard_limits.stop_on`）与速率收敛的披露。

        **为什么必须单独一节、不能并进 `_guard_alert`**：两者在讲完全不同的事，
        措辞互换就是写假话。

        | | 边界守门 | 健康度守门 |
        |---|---|---|
        | 请求到没到应用 | **没到**（拿到的是拦截页） | **到了**，是应用自己在报错 |
        | 研发该去查什么 | WAF 白名单 / 防护策略 | 服务为什么崩 |
        | 谁的问题 | 对方的防护策略 | **我们这次扫描可能造成的** |

        最后一行是必须写出来的：如果确实是本次扫描把目标压出 5xx，
        那这是**我们的影响**，报告有义务说明，而不是含糊成「目标异常」。
        """
        L: list[str] = []
        stop = str(ctx.target_health_stop or "").strip()
        if bool(getattr(ctx, "health_guard_off", False)):
            L.append("> ## ⚠️ 目标健康度守门本次被**显式关闭**")
            L.append("> ")
            L.append("> 操作者通过 `AISCAN_HEALTH_GUARD=off` 关闭了 "
                     "`hard_limits.stop_on` 的健康度守门：本次扫描**不会**因目标"
                     "连续 5xx / 响应时间突增而主动停手。")
            L.append("> ")
            L.append("> 该开关仅限一次性靶场基准 —— 靶场对畸形探针返 5xx 是应用的"
                     "正常应答形态，守门会把整轮扫描拦腰截断。"
                     "**生产目标不得使用**：用它扫生产等于拆掉了"
                     "「不把对方打挂」的最后一道闸。")
            L.append("> ")
        if stop:
            L.append("> ## ⚠️ 本次扫描**主动提前停止**：目标健康度异常")
            L.append("> ")
            L.append(f"> {stop}")
            L.append("> ")
            L.append("> **这与「被边界防护拦截」是两件不同的事**，不要混读："
                     "**不是被 WAF 拦截** —— 边界拦截是「请求没到达应用」，"
                     "而这次是**请求确实到达了应用、"
                     "应用自己在返错或响应时间暴增**。因此：")
            L.append("> ")
            L.append("> - 排查方向是**服务端为什么异常**，不是 WAF 白名单；")
            L.append("> - 若这是本次扫描造成的，则属于**我方对目标的影响**，"
                     "应同步告知系统负责人；")
            L.append("> - 停止之后的检查项全部按 **「未执行」** 记录 ——"
                     "**那不是「通过」，也不是「被拦截」**，本次没有取得它们的结论。")
            L.append("> ")
            L.append("> 停手而不等待重试是刻意的：这不是限流（限流等下就恢复），"
                     "而是服务可能已经异常 —— 继续按原速率施压只会加重故障，"
                     "且后果不可逆。")
            L.append("")
        clamp = str(ctx.rate_ceiling_clamp or "").strip()
        if clamp:
            L.append(f"> ℹ️ **速率被全局硬上限收敛**：{clamp}。"
                     "该上限来自 `config/profiles.yaml` 的 `hard_limits.rate_ceiling_rps`，"
                     "任何档位都不得突破。收敛只影响扫描耗时，不影响检查项覆盖。")
            L.append("")
        return L

    # ==================================================================
    # 技术版
    # ==================================================================
    def _render_technical(self, ctx: ReportContext, fs: FindingSet,
                          app: list[ApplicabilityResult]) -> str:
        m = Masker("internal")
        L: list[str] = []
        # ---- 章节暂存区：技术版报告按「结论前置、过程后置」组织 ----
        # 读者第一屏要看到的是「扫了谁、发现几条、有没有能直接拿走数据/权限的、
        # 每条怎么复现」；逐项结论表、覆盖缺口、授权声明、合规对照一律后置。
        # 用暂存列表而不是直接输出，是为了保持各章代码块原地不动、
        # 只在末尾按新顺序拼装 —— 搬代码块比重排拼接顺序更容易出错。
        MAIN: list[str] = L      # 主列表别名：中途 L 会被重绑定到各暂存区，末尾靠它拼装
        SECT3: list[str] = []    # 第 3 章 检测覆盖情况（过程）
        SECT4: list[str] = []    # 第 4 章 授权与范围声明
        TAIL: list[str] = []     # 第 5 / 6 章 合规对照 + 附录
        sec3_idx = 3             # 第 3 章已手工占用 3.1 / 3.2 / 3.3（执行落实、采集充分度、目标明细）
        counts = fs.counts()
        ap_summary = ApplicabilityEngine.summary(app)
        confirmed = [f for f in fs.findings if f.verify_result == "confirmed"]
        unconfirmed = [f for f in fs.findings if f.verify_result != "confirmed"]

        # ---- 标题 ----
        L.append(f"# {ctx.target_name} 安全评估报告（技术版）")
        L.append("")
        L.append(f"| 项目 | 内容 |")
        L.append("| --- | --- |")
        L.append(f"| 目标系统 | {ctx.target_name} |")
        L.append(f"| 主域名 | {ctx.primary_domain} |")
        L.append(f"| 扫描时间 | {ctx.scan_time} |")
        L.append(f"| 扫描档位 | {ctx.profile_name} |")
        L.append(f"| 检查项总数 | {ap_summary['合计']} |")
        L.append(f"| 扫描视角 | 公网视角 |")
        L.append(f"| 判定视角 | {MODE_LABEL.get(ctx.mode, ctx.mode)} |")
        L.append(f"| 报告生成时间 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |")
        L.append("")

        # ---- 边界防护告警：置于全篇最前 ----
        # 目标在边缘就被接管时，必须让读者在第一屏看到「本报告对应用本身没有
        # 结论」。默认不写，读者会把「未执行」读成「没问题」。
        L.extend(self._boundary_alert(ctx, len(fs.findings)))
        L.extend(self._guard_alert(ctx))
        L.extend(self._health_alert(ctx))
        L.extend(self._render_degradation_alert(ctx))

        # ---- 第 1 章：结论前置 ----
        # 第一屏回答三个问题：扫了谁、发现多少条、有没有能直接拿走数据 / 权限的。
        # 过程性内容（执行落实、逐项结论、覆盖缺口）后置到第 3 章。
        L.append("## 1. 扫描对象与漏洞总览")
        L.append("")
        L.append("### 1.1 扫描对象")
        L.append("")
        L.append(f"- 目标系统：**{ctx.target_name}**（`{ctx.primary_domain}`）")
        L.append(f"- 扫描时间：{ctx.scan_time}　|　扫描档位：{ctx.profile_name}")
        L.append(f"- 检查项：{ap_summary['合计']} 项　|　"
                 f"判定视角：{MODE_LABEL.get(ctx.mode, ctx.mode)}")
        L.append("- 暴露判据：**公网可达**（不以本机 / 内网网络状态为准）")
        L.append("")

        # 非黑客运维模式下必须**显式说明没做目标结论** ——
        # 否则读者会把「报告里根本没有攻击目标那一栏」读成「这些目标都没问题」，
        # 这正是本项目最忌讳的一类静默结论（没测被读成没问题）。
        if ctx.mode != MODE_REDTEAM:
            L.append(f"> ⚠️ 本次为**{MODE_LABEL.get(ctx.mode, ctx.mode)}**，"
                     f"**未执行攻击目标编排** —— 因此本报告不包含"
                     f"「攻击目标是否达成」的结论。"
                     f"需要该结论请以默认模式（黑客运维）重扫。")
            L.append("")

        # 「攻击目标达成情况」整体移到 1.4（结论区）输出 ——
        # 首屏先给数量分布与漏洞速查，读者拿到清单之后再看「打穿了没有」。
        # 注意：黑客运维下目标结论为空必须显式说出来（见 1.4），
        # 那是「编排阶段可能漏跑」的哨兵，不能因为搬位置就丢掉。
        # 「执行落实情况 / 采集充分度」搬到了第 3 章（暂存区 SECT3）——
        # 这两段回答「本次检测做到什么程度」，属过程性内容，
        # 放在第 1 章会把「发现了几条漏洞」这块结论挤出第一屏。
        col = ctx.collection or {}
        L.append("### 1.2 漏洞数量分布")
        L.append("")
        L.append("**结论分布**")
        L.append("")
        L.append("| 等级 | 数量 | 说明 |")
        L.append("| --- | --- | --- |")
        desc = {
            "严重": "可获取系统控制权或全量数据", "高危": "可获取有效业务数据 / 越权 / 篡改生效",
            "中危": "路径可达有技术证据，未实证危害", "低危": "仅攻击面暴露",
            "信息": "配置优化建议",
        }
        for s in reversed(SEVERITY_ORDER):
            if counts.get(s, 0) > 0 or s in ("严重", "高危", "中危", "低危"):
                L.append(f"| {s} | {counts.get(s, 0)} | {desc.get(s, '')} |")
        L.append(f"| **合计** | **{counts['合计']}** | 另有 {counts.get('待确认', 0)} 项证据不足，列入待确认 |")
        L.append("")

        # 总体评级
        # 评级的前提是「真的测过了」。一件事都没测到却写「低风险」，
        # 等于用一次失败的采集把风险判没了 —— 这是本工具最不能犯的错误，
        # 也是「无发现 = 低风险」这条默认逻辑最大的坑。
        _bblocked_t = (ctx.boundary is not None
                       and bool(getattr(ctx.boundary, "blocked", False)))
        _gterm_t = bool(ctx.boundary_guard is not None
                        and getattr(ctx.boundary_guard, "terminal", False))
        _hstop_t = bool(str(ctx.target_health_stop or "").strip())
        _ir_t = self._item_summary(ctx.item_results) if ctx.item_results else {}
        _tested = _ir_t.get("通过", 0) + _ir_t.get("不通过", 0)
        if _bblocked_t:
            rating = "无法评估"
            rating_note = ("本次请求在目标边界即被拦截，未触达业务系统，"
                           "没有取得任何可用于风险判断的数据。"
                           "本报告不对该系统作安全性判断。")
        elif _hstop_t and counts.get("合计", 0) == 0:
            # 健康度停手 + 零发现：**不能**写成「低风险」。
            # 「没有发现」在这里的确切含义是「前半程没检出、后半程没执行」，
            # 把它读成「没问题」正是本工具最不能犯的错误。
            rating = "无法评估"
            rating_note = ("本次扫描因**目标健康度异常提前停止**"
                           "（见「防护有效性」一节），已执行的检查项未产出发现，"
                           "但后续检查项**未执行** ——"
                           "「没有发现」不等于「没有问题」。本次不作安全性判断。")
        elif _gterm_t:
            rating = "无法评估"
            rating_note = ("本次扫描中途被边界防护封禁且退避未能恢复，"
                           "封禁之后的检查项未触达应用（按「未执行」记录），"
                           "缺少完整的定级依据，不作风险判断。")
        elif ctx.item_results and _tested == 0:
            rating = "无法评估"
            rating_note = ("本次没有任何检查项真正执行完成（通过 0、不通过 0），"
                           "缺少定级依据，不作风险判断。")
        elif counts.get("严重", 0) > 0:
            rating = "高风险"
            rating_note = "存在可直接获取系统控制权或全量数据的漏洞，建议立即处置。"
        elif counts.get("高危", 0) > 0:
            rating = "中高风险"
            rating_note = "存在可获取有效业务数据或越权操作的漏洞，建议本轮迭代内修复。"
        elif counts.get("中危", 0) > 0:
            rating = "中等风险"
            rating_note = "存在技术证据充分但未实证危害的问题，建议纳入计划修复。"
        else:
            rating = "低风险"
            rating_note = "未发现可直接造成数据或权限损失的问题。"
        if _hstop_t and counts.get("合计", 0) > 0:
            # 有发现时**不改成"无法评估"**：那会把已经实测出来的严重漏洞一并判没
            # （2026-09-30 OSS 匿名列举事故的同类错误）。改为标注覆盖范围。
            rating_note += (" ⚠ 但本次扫描因**目标健康度异常提前停止**，"
                            "上述结论**只覆盖已执行的检查项**；"
                            "停止之后的检查项未执行，见第 3 章。")
        L.append(f"**总体评级：{rating}** —— {rating_note}")
        L.append("")

        # ---- 1.3 漏洞清单速查：哪些可能拿到数据 / 权限 ----
        # 这是全篇最该被看见的一节。判据分两档，**绝不混写**：
        #   「已达成」= 结果证明层实测拿到（有证据链，见第 2 章）；
        #   「未达成 / 未能验证」= 试过没拿到 / 条件不足。后两者都不是「安全」。
        L.append("### 1.3 漏洞清单速查：哪些可能拿到数据 / 权限")
        L.append("")
        _proved_list = [
            f for f in fs.findings
            if str(((f.extra or {}).get("proof") or {}).get("state") or "") == "已达成"
        ]
        if not fs.findings:
            L.append("本轮**没有漏洞进入清单**。"
                     "这**不等于目标安全** —— 准确含义是「本轮检测未产生通过复现验证的发现」。"
                     "未执行 / 待人工执行的检查项见第 3 章。")
            L.append("")
        else:
            if _proved_list:
                L.append(f"**结论：本轮有 {len(_proved_list)} 条漏洞被实测证明拿到了数据 / 权限**"
                         "（证据链见本节下方及第 2 章）。")
            else:
                L.append("**结论：本轮没有任何一条漏洞被实测证明能拿到业务数据或系统权限。**"
                         "下表列出的是**具备该危害形态**的漏洞 —— "
                         "能否真拿到取决于其实际配置（例如服务是否开启鉴权），"
                         "请按第 2 章的复现操作自行确认。")
            L.append("")
            L.append("| 等级 | 漏洞 | 位置 | 危害形态 | 实测验证 |")
            L.append("| --- | --- | --- | --- | --- |")
            for f in fs.sorted_findings():
                _gd = (f.extra or {}).get("grading") or {}
                _hz = hazard_label(str(_gd.get("hazard_type") or ""))
                _pfst = str(((f.extra or {}).get("proof") or {}).get("state") or "未验证")
                L.append(f"| {f.severity} | {m.mask(f.title)} | "
                         f"`{m.mask(f.endpoint) or '—'}` | "
                         f"{_hz} | {_pfst} |")
            L.append("")
            L.append("> **「实测验证」列的含义**：`已达成` = 本轮实测拿到了东西；"
                     "`未达成` = 试过但没拿到；`未能验证` = 条件不足以下结论"
                     "（缺授权 / 缺账号 / 无对应手法），**既不等于安全，也不等于有问题**。"
                     "复现脚本位于本次扫描产出目录 `verify/` 下。")
            _sess_needed = [f for f in fs.findings
                            if (f.extra or {}).get("repro_needs_session")]
            if _sess_needed:
                L.append(">")
                L.append(f"> ⚠ **其中 {len(_sess_needed)} 条的复现脚本需要真实账号身份**"
                         "（越权类问题以匿名请求必然撞上登录页 / 401，"
                         "匿名复现的结果一律是「无法判定」而非「未复现」）。"
                         "请在 `verify/` 目录下的 `aiscan_sessions.json` 里填入各账号凭据后重跑；"
                         "脚本自行读取，**凭据不进脚本、也无需修改脚本任何一行**。")
            L.append("")

        # 「准入与实测情况」搬到 1.5（本报告可信度）输出 ——
        # 它回答的是「这份报告能不能信」，属于结论区尾部的可信度声明。
        gs = ctx.gate_result.stats() if ctx.gate_result is not None else {}

        # ---- 实测达成的攻击目标（结果证明层产出） ----
        # 与「漏洞清单」的关键区别：这里说的是「已经拿到了什么」，
        # 不是「可能存在什么」。黑客观角下前者才有意义。
        _proved = [
            f for f in fs.findings
            if str(((f.extra or {}).get("proof") or {}).get("state") or "") == "已达成"
        ]
        if _proved:
            L.append("**实测达成的攻击目标**（结论来自结果证明层，非证据推断）")
            L.append("")
            L.append("> 以下不是「存在某个漏洞」，而是**已实测证明拿到了什么**。"
                     "每条均附独立复现脚本，可自行复测。")
            L.append("")
            for f in _proved[:10]:
                pf = (f.extra or {}).get("proof") or {}
                L.append(f"- **[{f.severity}] {f.title}**")
                L.append(f"  - 实测结果：{m.mask(str(pf.get('detail') or '')) or '（详见第 2 章）'}")
                if f.endpoint:
                    L.append(f"  - 位置：`{f.endpoint}`")
            L.append("")

        # ---- 1.4 攻击目标达成情况（红队视角的实测结论）----
        # 标题由矩阵自带（含 1.4 编号），此处不再另写一行 —— 否则会印两遍。
        if ctx.objectives:
            L.extend(self._objective_matrix(ctx, brief=True,
                                            heading="### 1.4 攻击目标达成情况"))
            L.append("")
        elif ctx.mode == MODE_REDTEAM:
            # 无目标结论时也要占住 1.4 的位置，并且必须显式说明为什么是空的。
            L.append("### 1.4 攻击目标达成情况")
            L.append("")
            # 黑客运维视角下目标结论为空 —— 这不是「目标都没问题」，
            # 而是「编排阶段没产出结论」。必须显式说出来。
            # 这一条同时是**阶段静默未执行的哨兵**：只要编排阶段漏跑，
            # 报告就会自己喊出来，不会安静地少一栏。
            L.append("> ⚠️ 本次为**黑客运维视角**，但**未产出任何攻击目标结论** —— "
                     "编排阶段可能未执行或未产出。这**不代表**攻击目标不可达成，"
                     "仅表示本次对其没有结论。")
            L.append("")

        # ---- 1.5 本报告可信度 ----
        L.append("### 1.5 本报告可信度")
        L.append("")
        if gs:
            L.append("**准入与实测情况（决定本报告能信到什么程度，请重点看）**")
            L.append("")
            L.append("本轮检测共产生 **{tot} 条原始发现**，全部送入独立复现脚本验证：".format(tot=gs["发现总数"]))
            L.append("")
            L.append("| 复现结果 | 数量 | 处理方式 |")
            L.append("| --- | --- | --- |")
            L.append(f"| 已复现（脚本退出码 0） | {gs['已复现']} | **写入漏洞清单** |")
            L.append(f"| 未复现（脚本退出码 1） | {gs['未复现']} | 不进清单，见 2.x 证伪记录 |")
            L.append(f"| 无法判定（脚本退出码 2） | {gs['无法判定']} | 不进清单，见 2.x 待人工复现 |")
            L.append(f"| 未验证（未生成 / 未执行脚本） | {gs['未验证']} | 不进清单，见 2.x 未验证清单 |")
            L.append("")
            L.append(f"> **本报告漏洞清单中的 {gs['已复现']} 条，每一条都附有可独立执行的复现脚本，"
                     f"照着执行必然得到与「实测记录」一致的结果。**"
                     f"清单之外的发现不会以「漏洞」名义出现 —— "
                     f"报告宁可少写，也不写复测不出来的条目。")
            L.append("")
            if not gs.get("验证环节已执行"):
                L.append("> ⚠ **本次复现验证环节未成功执行**（或执行失败）。"
                         "清单中若仍有条目，其可复测性**未经脚本验证**，请勿据此对外发布。")
                L.append("")
            if gs.get("弱复现"):
                L.append(f"> 已复现的 {gs['已复现']} 条中，**{gs['弱复现']} 条为弱复现**"
                         f"（仅能确认端点可达，不含该漏洞类型的专用断言），"
                         f"已在第 2 章逐条标注「弱」，请优先人工核对。")
                L.append("")
        else:
            L.append(f"**实测验证情况**：{len(fs.findings)} 项发现中，"
                     f"{len(confirmed)} 项已通过独立脚本实测确认，"
                     f"{len(unconfirmed)} 项为技术证据推断（未执行主动验证，"
                     f"按其证据级别设有定级上限）。")
            L.append("")
        # 采集充分度：结果区只放一句结论，完整说明在第 3 章 ——
        # 它直接决定「N/A / 未发现」该怎么读，不能只留在报告末尾。
        if col.get("summary"):
            if col.get("degraded"):
                L.append(f"> ⚠️ **采集充分度 {col.get('score', 0)}/100"
                         f"（{col.get('level', '未知')}）** —— "
                         f"本次采集链路不完整，报告中所有 **N/A** 结论都应读作「**本次未发现**」，"
                         f"而不是「目标确实不具备该功能」。详见第 3 章。")
            else:
                L.append(f"> 采集充分度 {col.get('score', 0)}/100"
                         f"（{col.get('level', '未知')}），N/A 结论有实际依据。")
            L.append("")
            # 采集缺口的具体原因要单独点出来。只说「充分度低」，
            # 读者无从判断是「网站响应快但内容少」还是「页面根本没渲染出来」，
            # 而这两种情况对「那些 N/A 该怎么读」的含义完全不同。
            for _n in (col.get("notes") or []):
                L.append(f"> ⚠️ {_n}")
                L.append("")

        # ---- 第 4 章：授权与范围声明（后置）----
        # 用变量重绑定把整章写入暂存区，块内代码不必逐行改 append 目标。
        L = SECT4
        L.append("## 4. 授权与范围声明")
        L.append("")
        auth = ctx.authorization or {}
        L.append("| 项目 | 内容 |")
        L.append("| --- | --- |")
        L.append(f"| 授权状态 | {'已授权' if auth.get('authorized') else '未登记（需补充）'} |")
        L.append(f"| 授权人 | {auth.get('authorizer', '未登记')} |")
        L.append(f"| 授权日期 | {auth.get('authorization_date', '未登记')} |")
        L.append(f"| 授权依据 | {auth.get('authorization_ref', '未登记')} |")
        L.append(f"| 允许受控写验证 | {'是' if auth.get('allow_write_test') else '否（全程只读）'} |")
        L.append(f"| 扫描时间窗口 | {ctx.scan_time} 起 |")
        L.append(f"| 扫描范围 | {ctx.primary_domain} |")
        L.append(f"| 扫描视角 | 公网视角（不以本机 / 内网网络状态为判据） |")
        # 渲染是**有副作用**的动作，与受控写同等对待，必须在授权与范围这一章披露：
        # 它会在本机浏览器里执行目标页面的 JavaScript，页面引用的第三方资源
        # （统计脚本 / CDN / 字体）会被一并请求。这是授权范围内常见的问题：
        # 「允许你扫我的站」不等于「允许你的工具去请求我页面上挂的第三方」。
        _r = ctx.render or {}
        if _r:
            _p = _r.get("plan") or {}
            _e = _r.get("entry") or {}
            _rdesc = ("已启用（会在本机浏览器中执行目标页面的 JavaScript）"
                      if _p.get("enabled") else
                      f"未启用 —— {_p.get('reason') or '未执行'}")
            L.append(f"| 浏览器渲染 | {_rdesc} |")
            if _p.get("enabled"):
                L.append(f"| 渲染结果 | {_e.get('state') or '未执行'}"
                         + (f"（可见文本 {_e.get('text_before', 0)} → "
                            f"{_e.get('text_after', 0)} 字）" if _e.get("ok") else "") + " |")
                L.append("| 渲染副作用 | 不携带任何业务凭据；使用一次性浏览器配置目录；"
                         "页面中引用的第三方资源可能被一并请求 |")
        L.append("")
        L.append("**DNS 交叉验证**：")
        dns = ctx.dns or {}
        if dns.get("per_resolver"):
            L.append("")
            L.append("| 解析来源 | 结果 |")
            L.append("| --- | --- |")
            for k, v in dns["per_resolver"].items():
                L.append(f"| {k} | {', '.join(v)} |")
            L.append(f"| 一致性 | {'一致' if dns.get('consistent') else '**不一致（疑似分地域解析 / CDN 调度）**'} |")
        else:
            L.append(f"- 解析结果：{', '.join(dns.get('ips', [])) or '（未取得）'}")
        L.append("")
        L.append("> 说明：本次扫描以公网可达性为唯一暴露判据。本机网络是否可达目标，"
                 "不作为判断依据（避免内网可达导致误判为公网暴露）。")
        L.append("")

        # ---- 凭据获取留痕（红队入场方式）----
        # 红队扫描不依赖业务方提供账号：零凭据入场，自己找登录入口、
        # 自己识别产品并查它的默认口令、自己去公开渠道找线索。
        # **这些都是主动动作**（会在目标侧留下失败登录记录，外部检索还会
        # 向第三方暴露「有人正在关注该目标」），必须像受控写一样逐次披露。
        # 口令原文不记录，只留散列指纹 —— 所以这一节能安全地进报告。
        _ch4 = ctx.credhunt or {}
        _os4 = ctx.credosint or {}
        if _ch4 or _os4:
            L.append("### 4.1 凭据获取与凭据情报（本次是如何「进场」的）")
            L.append("")
            L.append("> 本节回答一个只能由本节回答的问题：**本次是怎么拿到（或"
                     "没拿到）一个登录身份的**。红队的入场方式与合规审计不同 ——"
                     "不向业务方索取测试账号，而是零凭据自行尝试："
                     "找登录入口、识别产品后查它的出厂默认口令、再到公开渠道找线索。"
                     "有账号做越权测试是**另一类工作**，其结论不在本节。")
            L.append("")

            # ---------------- 4.1.1 凭据情报（自己上网找） ----------------
            if _os4:
                L.append("#### 4.1.1 凭据情报（自己上网找）")
                L.append("")
                if not _os4.get("enabled"):
                    L.append(f"- 未执行：{_os4.get('reason') or '本档位未启用'}")
                    L.append("")
                else:
                    _prods = _os4.get("products") or []
                    if _prods:
                        L.append("- **识别到的产品**。默认口令与产品是绑定的 ——"
                                 "认错产品就等于拿 A 的口令去打 B 的登录框，"
                                 "所以证据必须逐条列出：")
                        L.append("")
                        L.append("| 产品 | 判定证据 |")
                        L.append("| --- | --- |")
                        for p in _prods:
                            L.append(f"| {p.get('name', '')} | "
                                     f"{m.mask(str(p.get('evidence', '')))} |")
                        L.append("")
                    else:
                        L.append("- 未从现有指纹证据中识别出已知产品 —— "
                                 "因此**没有产出任何自动尝试候选**。"
                                 "拿一份通用字典对着陌生登录框硬试属于爆破，"
                                 "与「找默认凭据」是两件不同的事（授权解释与"
                                 "副作用都不同），不做")
                        L.append("")
                    _qs = _os4.get("queries") or []
                    L.append(f"- 外部检索：**{len(_qs)} 次**"
                             + ("（检索词逐条列出，便于使用方核算披露范围）"
                                if _qs else "（本次未发出任何检索）"))
                    for i, q in enumerate(_qs, 1):
                        L.append(f"  {i}. `{m.mask(str(q))}`")
                    L.append("")
                    if _qs:
                        L.append("> 主动外部检索会向第三方暴露「有人正在关注该目标」"
                                 "这一事实，故检索词全量披露；检索过程中"
                                 "**不携带任何凭据**。如需完全避免外部查询，"
                                 "可用 `--no-credosint` 关闭。")
                        L.append("")
                    _srcs = _os4.get("sources") or {}
                    if _srcs:
                        L.append("| 情报来源 | 状态 |")
                        L.append("| --- | --- |")
                        for _k, _v in _srcs.items():
                            L.append(f"| {_k} | "
                                     f"{'正常' if _v == 'ok' else m.mask(str(_v))} |")
                        L.append("")
                    _cands = _os4.get("candidates") or []
                    _auto = [c for c in _cands if c.get("auto_attempt")]
                    _held = [c for c in _cands if not c.get("auto_attempt")]
                    L.append(f"- 候选口令 **{len(_cands)} 组**："
                             f"进入受控尝试 {len(_auto)} 组，转人工 {len(_held)} 组")
                    if _cands:
                        L.append("")
                        L.append("| 账号 | 口令指纹 | 产品 | 来源 | 强度 | 处置 |")
                        L.append("| --- | --- | --- | --- | --- | --- |")
                        for c in _cands:
                            L.append(
                                f"| {c.get('account', '')} | "
                                f"`{c.get('pw_fingerprint', '')}` | "
                                f"{c.get('product', '')} | {c.get('source', '')} | "
                                f"{c.get('strength', '')} | "
                                f"{'已纳入受控尝试' if c.get('auto_attempt') else '转人工'} |")
                        L.append("")
                        L.append("> 候选口令取自公开资料与厂商文档（原则上是公开信息），"
                                 "此处仍只给散列指纹：报告一旦把「哪次尝试用了哪一组」"
                                 "固化下来，它本身就成了可复用的攻击清单。"
                                 "规则与凭据获取的尝试表一致。")
                        L.append("")
                    if _held:
                        L.append("**未纳入自动尝试的候选（逐条说明原因）**：")
                        L.append("")
                        for c in _held:
                            L.append(f"- `{c.get('account', '')}`："
                                     f"{m.mask(str(c.get('hold_reason', '')))}")
                        L.append("")
                    _leads = _os4.get("leads") or []
                    if _leads:
                        L.append(f"**线索 {len(_leads)} 条**（仅列出，不自动使用）：")
                        L.append("")
                        L.append("| 类型 | 标题 | 来源 | 为何不自动使用 |")
                        L.append("| --- | --- | --- | --- |")
                        for x in _leads:
                            L.append(f"| {x.get('kind', '')} | "
                                     f"{m.mask(str(x.get('title', '')))} | "
                                     f"{m.mask(str(x.get('source', '')))} | "
                                     f"{m.mask(str(x.get('why_not_auto', '')))} |")
                        L.append("")
                        for x in _leads:
                            if x.get("url"):
                                L.append(f"- {m.mask(str(x.get('title', '')))}："
                                         f"{m.mask(str(x.get('url', '')))}")
                        L.append("")
                    for _n in (_os4.get("notes") or []):
                        L.append(f"- {_n}")
                    L.append("")

            # ---------------- 4.1.2 凭据获取（实际提交了什么） ----------------
            if _ch4:
                L.append("#### 4.1.2 凭据获取（实际提交了什么）")
                L.append("")
                if not _ch4.get("enabled"):
                    L.append(f"- 未执行：{_ch4.get('reason') or '本档位未启用'}")
                    L.append("")
                else:
                    L.append(f"- 登录入口：`{_ch4.get('entry_url') or '（未定位到）'}`"
                             f"（来源：{_ch4.get('entry_source') or '—'}）")
                    _psc = _ch4.get("pair_source_counts") or {}
                    _psc_txt = ("；".join(f"{k} {v} 组" for k, v in _psc.items())
                                if _psc else "通用默认口令字典（构成未记录）")
                    L.append(f"- 口令尝试：{_ch4.get('tried', 0)} 组"
                             f"（来源构成：{_psc_txt}）。这是**受控尝试**，"
                             "不是爆破：总次数与单账号次数双重封顶，命中风控即停")
                    _found = _ch4.get("found_identities") or []
                    if _found:
                        L.append(f"- **实际取得身份**：{'、'.join(_found)} —— "
                                 "已用于认证 / 越权类检查；该事实本身即一条高危发现")
                    elif _ch4.get("lockout_hit"):
                        L.append("- 结果：**命中风控 / 锁定信号后立即停止**，"
                                 "相关项记「待确认」（继续尝试的副作用不可逆）")
                    else:
                        L.append("- 结果：未命中 —— 注意这**不等于**系统不存在弱口令，"
                                 "本次只用了受限的口令集合（产品默认值 + 通用弱口令）")
                    if _ch4.get("stopped_reason"):
                        L.append(f"- 停止原因：{_ch4['stopped_reason']}")
                    if _ch4.get("assumed_fields"):
                        # 这一行改的是**整节的读法**，所以必须放在结果之后、
                        # 明细表之前 —— 放在表后面，读者已经先入为主地读完了
                        # 「N 组未命中」，再补一句「其实字段名是猜的」已经晚了。
                        L.append("- ⚠ **本次提交的字段名是假定的**：登录入口没有表单页"
                                 "（POST-only 接口 / SPA 外壳），无法读出真实字段名，"
                                 "按最常见约定假定了 `username` / `password`。"
                                 "若服务端用的是别的字段名，上面这些「认证失败」"
                                 "**只说明没试对口令校验那一层**，"
                                 "不能推断该系统不存在弱口令。")
                    _atts = _ch4.get("attempts") or []
                    if _atts:
                        L.append("")
                        L.append("| # | 提交地址 | 账号 | 口令指纹 | 来源 | 结果 | HTTP |")
                        L.append("| --- | --- | --- | --- | --- | --- | --- |")
                        for i, a in enumerate(_atts, 1):
                            L.append(f"| {i} | `{m.mask(str(a.get('url', '')))}` | "
                                     f"{a.get('account', '')} | "
                                     f"`{a.get('pw_fingerprint', '')}` | "
                                     f"{a.get('source', '')} | "
                                     f"{a.get('outcome', '')} | {a.get('status', '')} |")
                        L.append("")
                        L.append("> 口令原文不记录（仅存散列指纹，可凭账号 + 已知口令"
                                 "复算比对，不可还原）。复现脚本内嵌的只有"
                                 "**公开的**默认口令字典与产品出厂默认值"
                                 "（与 nuclei 的 default-login 模板同理），"
                                 "不含目标特有的任何凭据。")
                for _n in (_ch4.get("notes") or []):
                    L.append(f"- {_n}")
                L.append("")

        L = SECT3   # 恢复指向：以下内容进入第 3 章（检测覆盖情况）暂存区

        # ---- 第 3 章：检测覆盖情况（过程，后置）----
        # 本章回答「都检测了哪些、每项结论是什么、哪些没检测」。
        # 章内编号：3.1 / 3.2 手工占用（执行落实、采集充分度），
        # 逐项结论表从 3.3 起由 sec3_idx 续编。
        L.append("## 3. 检测覆盖情况（本章回答「检测了什么、结论是什么」）")
        L.append("")
        L.append(f"本章逐项列出全部 {ap_summary['合计']} 项检查结论。"
                 "**不适用项亦逐项说明原因**，确保每次扫描的检查范围一致、可比对。")
        L.append("")
        L.append("> **结论是怎么来的**：每一项的结论由「逐项执行状态机」产出。"
                 "只有**检测器完整执行完毕且未发现问题**，才记为「通过」；"
                 "没有绑定检测逻辑、检测器执行失败、或前置条件不足的项，"
                 "一律记为「未执行」。**不存在「没测出问题所以算通过」的情况。**")
        L.append("")

        # ---- 3.1 执行落实情况（自第 1 章后置而来）----
        L.append("### 3.1 本次检测的执行落实情况")
        L.append("")
        ir1 = self._item_summary(ctx.item_results) if ctx.item_results else {}
        # 「待确认」在两个汇总里语义不同，必须分开取数 —— 这里取错过一次：
        #   · ap_summary 来自**适用性判定阶段**，那时还没执行，待确认恒为 0；
        #   · ir1 来自**逐项执行结果**，待确认是执行期才出现的状态（外部判不出来）。
        # 原先这句取的是前者，于是报告开头写「待确认 0 项」，而紧接着的表格里
        # 明明列着 21 项 —— 同一页两个数打架，读者只会认为整份报告不可信。
        _pend_intro = (ir1.get("待确认", 0) if ctx.item_results
                       else ap_summary[CONCLUSION_PENDING])
        L.append(f"本次针对 **{ctx.target_name}**（{ctx.primary_domain}）执行了 "
                 f"{ap_summary['合计']} 项安全检查，其中适用 "
                 f"{ap_summary[CONCLUSION_APPLICABLE]} 项、"
                 f"不适用 {ap_summary[CONCLUSION_PASS_NA]} 项、"
                 f"待确认 {_pend_intro} 项。")
        L.append("")
        if ctx.item_results:
            L.append("**执行落实情况**（这一行请重点看）")
            L.append("")
            L.append("| 项目 | 数量 |")
            L.append("| --- | --- |")
            L.append(f"| 本次真的执行了的检查 | {ir1.get('自动执行', 0)} 项 |")
            L.append(f"| 　├ 通过 | {ir1.get('通过', 0)} 项 |")
            L.append(f"| 　└ 不通过 | {ir1.get('不通过', 0)} 项 |")
            L.append(f"| 待人工执行 | {ir1.get('待人工执行', 0)} 项 |")
            L.append(f"| 未执行（无结论，**不代表安全**） | {ir1.get('未执行', 0)} 项 |")
            L.append(f"| N/A（目标不适用，**不等于通过**） | {ir1.get('N/A', 0)} 项 |")
            L.append(f"| 待确认（外部无法判定） | {ir1.get('待确认', 0)} 项 |")
            L.append("")
            L.append(f"> 报告不把「未测」包装成「通过」。可信通过率为 "
                     f"**{ctx.detector_summary.get('通过率', 0):.1%}**"
                     f"（通过数 / 实际执行数）。")
            L.append("")

        # ---- 3.2 采集充分度（自第 1 章后置而来）----
        L.append("### 3.2 采集充分度")
        L.append("")
        if col.get("summary"):
            L.append(f"采集充分度：**{col.get('score', 0)}/100"
                     f"（{col.get('level', '未知')}）**")
            L.append("")
            L.append(f"{col['summary']}")
            L.append("")
            if col.get("degraded"):
                L.append("> ⚠️ **采集充分度不足以支撑全量判定。**报告中所有 **N/A** "
                         "结论都应理解为「**本次未发现**」，而不是「目标确实不具备该功能」——"
                         "采集链路不完整时，两者从外部无法区分。请人工确认后再据以决策。")
            else:
                L.append("> 采集充分度良好，N/A 结论有实际依据。")
            L.append("")

            # ---- 前端产物采集失败的覆盖度下降披露 ----
            # 这是与「骨架页未渲染」并列的第二种结构性缺口，而且更隐蔽：
            # 根页面正文很长、响应头齐全、表单也有，充分度看起来不低，
            # 但依赖前端产物的那一整类检查项其实是在**空数据上跑完的**。
            # 必须点名说清是哪些项 —— 只给一个分数读者不知道该怀疑哪几项。
            art = col.get("artifact") or {}
            if art.get("loss") in ("full", "partial"):
                _aff = list(col.get("artifact_affected_items") or [])
                L.append(f"#### 3.2.1 覆盖度下降：{art.get('loss_label', '前端产物未完整采集')}")
                L.append("")
                L.append(f"- 页面引用外部脚本：**{art.get('referenced', 0)} 份**；"
                         f"实际取回：**{art.get('fetched', 0)} 份**；"
                         f"未取回：**{art.get('failed', 0)} 份**")
                L.append(f"- 内联脚本：{art.get('inline_scripts', 0)} 段；"
                         f"提取到的接口地址：{art.get('endpoints_extracted', 0)} 条")
                if art.get("errors"):
                    L.append(f"- 最近的抓取错误：`{'`、`'.join(str(x)[:100] for x in art['errors'])}`")
                L.append("")
                for _n in art.get("notes") or []:
                    L.append(f"> {_n}")
                    L.append("")
                if _aff:
                    L.append(f"**受影响的检查项（{len(_aff)} 项）**"
                             "—— 这些项的结论基于**不完整的前端素材**，"
                             "其中的「通过」不得当作「已确认没问题」：")
                    L.append("")
                    L.append("`" + "`、`".join(_aff) + "`")
                    L.append("")
                    L.append("> 补齐方式：换出口网络 / 补 UA 与 Referer / "
                             "若产物在独立 CDN 则改用该地址重采 / 登录后重采，"
                             "然后复扫。")
                    L.append("")

        # ---- 3.2.2 外部引擎（nuclei）执行情况 ----
        # nuclei 是全流程里唯一自行发请求的一步，不受本工程节流器约束。
        # 它必须披露两件事：**跑了多大范围**、**跑完了没有**。
        # 少了前者，「没有发现」无法解释（连什么模板跑过都不知道）；
        # 少了后者，被预算掐断的那一批会被读成「扫过了、没问题」。
        nuc = ctx.nuclei_run or {}
        if nuc:
            L.append("#### 3.2.2 外部引擎（nuclei）执行情况")
            L.append("")
            if not nuc.get("available"):
                L.append(f"- 本次**未使用 nuclei**：{nuc.get('reason') or '工具不可用'}")
                L.append("- 该引擎覆盖的约 77 个检查项本批结论只来自内置检测器，"
                         "与「模板库全量跑过」不等价。")
                L.append("")
            else:
                L.append(f"- 执行：{'已执行' if nuc.get('executed') else '未执行'}"
                         f"（耗时 {nuc.get('elapsed', 0)}s，"
                         f"产出 {nuc.get('findings', 0)} 条，"
                         f"命中模板 {nuc.get('template_count', 0)} 份）")
                if nuc.get("scope_known"):
                    L.append(f"- 执行范围：本次实际纳入 **{nuc.get('scope_total', 0)} 份模板**"
                             "（按档位的严重度与标签筛选后的真实份数，不是模板库总量）")
                else:
                    L.append("- 执行范围：**模板份数未清点**"
                             "（清点失败不影响扫描，但「无发现」的分量无法量化）")
                if not nuc.get("executed") and nuc.get("reason"):
                    L.append(f"- 未执行原因：{nuc.get('reason')}")
                if nuc.get("discarded"):
                    L.append(f"- ⚠️ **本批结果已整体丢弃**：{nuc.get('discard_reason')}"
                             "（结果不可信时宁可不用 —— 留下会变成一份复测不出来的报告）")
                _pl = nuc.get("plan") or {}
                if _pl:
                    _sev = " / ".join(",".join(p.get("severity") or []) for p in _pl.get("passes") or [])
                    L.append(f"- 分层：{len(_pl.get('passes') or [])} 趟"
                             f"（{_sev or '未分层'}），"
                             f"总预算 {int(_pl.get('budget_seconds') or 0)}s")
                    _inc = (_pl.get("passes") or [{}])[0].get("tags_include") or []
                    if _inc:
                        L.append(f"- 模板筛选：仅含标签 `{'`、`'.join(_inc)}`")
                    _exc = _pl.get("excluded_protocols") or []
                    if _exc:
                        L.append(f"- 已排除模板类型：`{'`、`'.join(_exc)}`"
                                 "（需要本地文件 / 本地代码运行时 / 浏览器 / 注册域名，"
                                 "对 URL 目标发不出有效请求，属结构性不适用）")
                    _rate = (_pl.get("passes") or [{}])[0].get("rate_limit")
                    if _rate:
                        L.append(f"- 限速：{_rate} 请求/秒（不超过档位声明的速率）")
                L.append("")
                if nuc.get("budget_exhausted") or nuc.get("partial"):
                    L.append("> ⚠️ **本次外部引擎未跑完。**"
                             "下面的趟次明细里标 `timeout` 的是被预算掐断、"
                             "标 `skipped` 的是根本没跑。"
                             "这两类所覆盖的模板**本次没有结论** —— "
                             "不要把「没有发现」读成「模板库确认没问题」。")
                    L.append("")
                    L.append("> 若需要外部引擎覆盖完整：提高档位限速（nuclei 的速率被"
                             "档位声明的请求速率夹住）或调大配置项 "
                             "`nuclei.budget_seconds`，然后复扫。")
                    L.append("")
                _passes = nuc.get("passes") or []
                if _passes:
                    L.append("| 趟次 | 严重度 | 状态 | 纳入模板 | 产出 | 耗时 |")
                    L.append("| --- | --- | --- | --- | --- | --- |")
                    _st_map = {"ok": "跑完", "timeout": "被预算掐断（已抢救部分产出）",
                               "skipped": "未执行（预算耗尽）"}
                    for _p in _passes:
                        _st = _st_map.get(str(_p.get("status")), str(_p.get("status")))
                        _tpl = _p.get("templates")
                        _tpl_s = f"{_tpl} 份" if isinstance(_tpl, int) else "未清点"
                        L.append(f"| 第 {_p.get('pass')} 趟 | {','.join(_p.get('severity') or [])} "
                                 f"| {_st} | {_tpl_s} | {_p.get('findings', 0)} 条 "
                                 f"| {_p.get('elapsed', 0)}s |")
                    L.append("")
                for _n in nuc.get("notes") or []:
                    L.append(f"> {_n}")
                    L.append("")

        # ---- 3.3 攻击目标已尝试的手段（明细）----
        # 第 1 章只给「打穿了没有」的结论；这里回答「为打穿它试过什么」——
        # 两者缺一不可：没有明细，「未达成」与「根本没测」就区分不开。
        if ctx.objectives:
            L.extend(self._objective_matrix(
                ctx, brief=False, with_matrix=False,
                heading="### 3.3 攻击目标已尝试的手段（逐条明细）"))
            L.append("")

        # ---- 3.x 攻击链分析（发现 → 攻击目标）----
        # 「为打穿它试过什么」之后还必须回答「还有什么组合没试」。
        # 候选链是**推理**产物，措辞必须与实测结论分清（见 _attack_chains）。
        if ctx.chains or ctx.chain_notes:
            sec3_idx += 1
            L.extend(self._attack_chains(
                ctx, heading=f"### 3.{sec3_idx} 攻击链分析（发现 → 攻击目标）"))
            L.append("")

        if not ctx.item_results:
            L.append("> ⚠️ 本次运行未采集到逐项执行记录（逐项检测阶段未完成）。"
                     "因此本章**无法给出任何一项的通过结论**，请修复后重新扫描。")
            L.append("")
            L.append("| 结论 | 数量 |")
            L.append("| --- | --- |")
            L.append(f"| 未执行（无逐项执行记录） | {ap_summary['合计']} |")
            L.append(f"| **合计** | **{ap_summary['合计']}** |")
            L.append("")
        else:
            ir_summary = self._item_summary(ctx.item_results)
            L.append("| 结论 | 数量 | 含义 |")
            L.append("| --- | --- | --- |")
            for state, meaning in STATE_MEANING.items():
                if state in ("通过", "不通过", "未执行", "待人工执行", "N/A", "待确认"):
                    L.append(f"| {state} | {ir_summary.get(state, 0)} | {meaning} |")
            if ir_summary.get("已跳过", 0):
                L.append(f"| 已跳过 | {ir_summary['已跳过']} | 用户显式跳过 |")
            L.append(f"| **合计** | **{ir_summary.get('合计', 0)}** | 与清单条目数一致 |")
            L.append("")
            L.append(f"**可信通过率：{ctx.detector_summary.get('通过率', 0):.1%}**"
                     f"（= 通过数 {ir_summary.get('通过', 0)} / 实际执行数 "
                     f"{ir_summary.get('自动执行', 0)}）。"
                     "分母是「真的跑了的项」，不是「清单总项数」—— "
                     "这样才能看出检测能力的真实水平。")
            L.append("")
            col = ctx.collection or {}
            if ir_summary.get("N/A", 0):
                if col.get("degraded"):
                    L.append(f"> ⚠️ 本次有 **{ir_summary.get('N/A', 0)} 项判为 N/A**，"
                             f"而采集充分度仅 {col.get('score', 0)}/100"
                             f"（{col.get('level', '未知')}）。"
                             "采集不完整时，「目标没有该功能」与「本次没采集到」"
                             "从外部无法区分，**这些 N/A 应按「本次未发现」理解，"
                             "需人工复核**，不能直接当作「不适用」。")
                else:
                    L.append(f"> 本次 {ir_summary.get('N/A', 0)} 项 N/A 的判定依据："
                             f"采集充分度 {col.get('score', 0)}/100"
                             f"（{col.get('level', '未知')}），"
                             "判定基于实际读取到的内容，可信。")
                L.append("")
            if ir_summary.get("未执行", 0) or ir_summary.get("待人工执行", 0):
                L.append(f"> 注意：本次有 **{ir_summary.get('未执行', 0)} 项未执行**、"
                         f"**{ir_summary.get('待人工执行', 0)} 项待人工执行**。"
                         "这些项**不代表安全**，只是本次没有结论。"
                         "请务必查看本章末尾的清单并补齐。")
                L.append("")
            if ctx.detector_notes:
                L.append("**本次执行统计**")
                L.append("")
                for n in ctx.detector_notes:
                    L.append(f"- {n}")
                L.append("")

            # 表头解释：不写这句，「执行方式」列里的「已挂自动侦察」就成了行话，
            # 读者不知道它到底省掉了多少人工。
            if any(getattr(r, "recon_ran", False) or getattr(r, "recon_note", "")
                   for r in ctx.item_results):
                L.append("> 「执行方式」列带 **｜ 已挂自动侦察（已执行）** 的人工项，"
                         "扫描器已自动完成接口 / 字段定位，人工只剩最后一层业务判断；"
                         "带 **（未执行）** 的说明侦察因缺凭据或档位不足没跑成 —— "
                         "补上条件即可自动完成，不必从零开始。")
                L.append("")

            by_cat: dict[str, list[Any]] = {}
            for r in ctx.item_results:
                by_cat.setdefault(r.category, []).append(r)

            # 编号从 3.3 起（3.1 / 3.2 已被执行落实与采集充分度占用）
            for cat, results in by_cat.items():
                sec3_idx += 1
                cname = results[0].category_name
                L.append(f"### 3.{sec3_idx} {cat} — {cname}（{len(results)} 项）")
                L.append("")
                L.append("| 检查项 | 名称 | 执行方式 | 结论 | 等级 / 原因 | 证据类型 |")
                L.append("| --- | --- | --- | --- | --- | --- |")
                for r in results:
                    concl = r.state
                    detail = self._result_detail(r)
                    mode = f"{r.mode}" + (f"（{r.tool}）" if r.tool else "")
                    # 「执行方式」这一列必须把自动侦察也写出来。
                    # 只写「人工（人工核查）」会让读者以为整项零自动化 —— 而事实上
                    # ATHN-03/08/09、ATHZ-03、SESS-11、CRYP-02、EXT-DP-03 这几项
                    # 扫描器已经把接口和字段都定位好了，人只剩最后那步判断。
                    # 「挂了但没跑成」与「压根没挂」也要分开写：前者补上条件（凭据 /
                    # 档位）就能跑，后者从零开始，欠的工作量差得远。
                    if getattr(r, "recon_ran", False):
                        mode += " ｜ 已挂自动侦察（已执行）"
                    elif getattr(r, "recon_note", ""):
                        mode += " ｜ 已挂自动侦察（未执行）"
                    L.append(f"| {r.item_id} | {r.name} | {mode} | {concl} | "
                             f"{detail} | {r.evidence_kind or '—'} |")
                L.append("")

            # ---- 未执行清单 ----
            notrun = [r for r in ctx.item_results if r.state == "未执行"]
            sec3_idx += 1
            L.append(f"### 3.{sec3_idx} 未执行清单（{len(notrun)} 项）")
            L.append("")
            if not notrun:
                L.append("无。本次所有适用项均已实际执行。")
                L.append("")
            else:
                L.append("以下项**本次没有得出任何结论**。未执行 ≠ 通过，"
                         "请按「补齐方式」逐项落实，或明确接受该覆盖缺口。")
                L.append("")
                L.append("| 检查项 | 名称 | 检测器 | 未执行原因 |")
                L.append("| --- | --- | --- | --- |")
                for r in notrun:
                    L.append(f"| {r.item_id} | {r.name} | {r.detector or '（未绑定）'} | "
                             f"{r.note or '—'} |")
                L.append("")

                by_reason: dict[str, list[str]] = {}
                for r in notrun:
                    key = self._notrun_bucket(r.note)
                    by_reason.setdefault(key, []).append(r.item_id)
                L.append("**按原因归类（便于一次性补齐）**")
                L.append("")
                L.append("| 未执行原因 | 涉及项数 | 补齐方式 |")
                L.append("| --- | --- | --- |")
                for reason, ids in sorted(by_reason.items(), key=lambda x: -len(x[1])):
                    L.append(f"| {reason} | {len(ids)} | {NOTRUN_FIX.get(reason, '按上表逐项确认')} |")
                L.append("")

            # ---- 凭据缺口（需要登录令牌的检查怎么补）----
            # 只在确实缺凭据时出现。它不是「通过」的替代品 ——
            # 涉及的项在上一节里仍然是「未执行 / 待人工执行」。
            _ask = getattr(ctx, "cred_ask", None) or {}
            _needs = [n for n in (_ask.get("needs") or []) if not n.get("present")]
            if _needs:
                sec3_idx += 1
                L.append(f"### 3.{sec3_idx} 凭据缺口：需要登录令牌的检查（{len(_needs)} 个身份待补）")
                L.append("")
                L.append("下列检查项依赖**已登录身份**才能判定。本次没有可用的登录态，"
                         "因此它们**没有结论** —— 不是通过，也不是未见异常。"
                         "按下面的步骤补上凭据后重扫，这些项会自动开始执行。")
                L.append("")
                L.append("| 身份 | 当前登录态 | 为什么需要它 |")
                L.append("| --- | --- | --- |")
                for n in _needs:
                    L.append(f"| {n.get('role') or '—'} | {n.get('verified') or '未提供'} | "
                             f"{(n.get('why') or '—')[:80]} |")
                L.append("")
                _n0 = _needs[0]
                if _n0.get("entry_url"):
                    _src = "你提供" if _n0.get("entry_source") == "user" else "探测所得"
                    L.append(f"**登录入口**：{_n0['entry_url']}（依据：{_n0.get('entry_evidence') or ''}；{_src}）")
                else:
                    L.append("**登录入口**：未能从探测结果中确定。")
                    L.append(f"　原因：{_n0.get('entry_evidence') or '无'}")
                    L.append("　→ 可先跑一次标准档扫描（登录页会被记录为证据），"
                             "或直接告知：`--login-url https://域名/登录路径`")
                L.append("")
                _blk = _n0.get("blocked") or []
                if _blk:
                    L.append(f"**受影响的检查项**（{len(_blk)} 项）")
                    L.append("")
                    for iid, name in _blk[:12]:
                        L.append(f"- {iid} {name}")
                    if len(_blk) > 12:
                        L.append(f"- …（其余 {len(_blk) - 12} 项略，见上一节清单）")
                    L.append("")
                _dom = ctx.primary_domain or "<域名>"
                _rounds = [n for n in _needs if not n.get("present")]
                L.append("**补齐步骤**")
                L.append("")
                if len(_rounds) >= 2:
                    # 剪贴板一次只装得下一个账号。把几条命令排成一列让人从上往下跑，
                    # 第二个账号会被写成第一个账号的凭据 —— 两个身份塌成同一个人，
                    # 越权判定退化成「自己和自己比」，报告里的水平越权结论全部失真，
                    # 而写入本身**不会报错**。所以按账号分轮，强制「复制 → 立即执行」。
                    L.append("⚠ **一个账号一轮。** 剪贴板一次只装得下一个账号的 Cookie："
                             "先复制该账号的 Cookie，再**立刻**执行紧跟其后的那条命令。")
                    L.append("　　**不要把几条命令连着跑** —— 否则第二个账号会被写成"
                             "第一个账号的凭据，两个身份变成同一个人，越权判定就没有"
                             "意义了（而且这个过程不会报错）。")
                    L.append("")
                for i, n in enumerate(_rounds, 1):
                    _head = (f"**第 {i} 轮：{n.get('role')}"
                             f"（{n.get('label') or '测试身份'}）**" if len(_rounds) >= 2
                             else "**执行步骤**")
                    L.append(_head)
                    L.append("")
                    L.append(f"1. 用 {n.get('role')} 在浏览器登录"
                             f"{' ' + _n0['entry_url'] if _n0.get('entry_url') else '目标系统'}"
                             "（用你自己的账号，不要用他人账号）")
                    L.append("2. F12 → Application（应用）→ Storage → Cookies → 复制该域名的 "
                             "Cookie 值；若令牌在请求头里，改用 Network → 右键请求 → Copy as cURL")
                    L.append("3. 回到终端执行（凭据取自剪贴板，不进命令历史）：")
                    L.append(f"   `python aiscan.py creds --target {_dom} "
                             f"--set {n.get('role')} --from-clipboard`")
                    if len(_rounds) >= 2:
                        L.append("4. **看到「已写入」回执后**，再开始下一个账号那一轮")
                    L.append("")
                L.append("**收尾**")
                L.append("")
                L.append(f"- 回验登录态是否真的成立（会向目标发请求，目标须已在台账登记）："
                         f"`python aiscan.py creds --target {_dom} --verify "
                         f"--verify-path <登录后可见的页面>`")
                L.append(f"- 重扫，上述项会自动开始执行："
                         f"`python aiscan.py scan --target {_dom}`")
                L.append("")
                L.append("**两条容易踩空的前提**")
                L.append("")
                L.append("- **回验要指定「登录后才能访问」的页面**（账号配置里的 `verify_path`）。"
                         "只拿站点首页回验是无效的 —— 首页对游客也返回 200，"
                         "那种情况下登录态只能判「未验证」，身份类检查仍然跑不起来。")
                L.append("- **越权类判定需要 ≥2 个不同身份的已确认登录态**。"
                         "只补一个账号时，"
                         "「读到自己数据」与「读到他人数据」无法区分，该类结论仍只能判「未能验证」。")
                L.append("")
                L.append("⛔ **不要把令牌贴进对话、工单或聊天。** 会话令牌等同于账号权限，"
                         "贴出去就进了对方系统的日志，而且**收不回来**（会话可以吊销，"
                         "已扩散的副本不行）。上面的写入命令是把凭据直接写进本机凭据文件，"
                         "工具自己读，全程不经手第三方。")
                L.append("")

            # ---- 待人工执行清单 ----
            manual = [r for r in ctx.item_results if r.state == "待人工执行"]
            sec3_idx += 1
            L.append(f"### 3.{sec3_idx} 待人工执行清单（{len(manual)} 项）")
            L.append("")
            if not manual:
                L.append("无。")
                L.append("")
            else:
                L.append("以下项**任何自动化扫描器都判不了**（需要业务语义、"
                         "多账号比对或真实副作用），已给出可照做的操作步骤。")
                L.append("")
                L.append("其中带「自动侦察结论」的项，扫描器已经把准备工作做完："
                         "接口、字段、当前值、可自动证的差分实验都附在下面，"
                         "人工只需按清单逐条执行并**判断业务结果对不对**。"
                         "侦察未执行的项会明确标出，它的人工步骤没有任何自动化覆盖。"
                         "这些项在落实前**不代表安全**。")
                L.append("")
                for i, r in enumerate(manual, 1):
                    L.append(f"**3.{sec3_idx}.{i} [{r.item_id}] {r.name}**")
                    L.append("")
                    L.append(f"- 为什么必须人工：{r.why_manual or '需业务语义判断'}")
                    if r.requires:
                        req_txt = "、".join(
                            {"accounts": "至少 2 组测试账号",
                             "write": "书面授权允许受控写",
                             "js": "前端产物采集",
                             "nuclei": "nuclei 模板结果"}.get(x, x)
                            for x in r.requires)
                        L.append(f"- 前置条件：{req_txt}")
                    L.append(f"- 风险档位：{r.risk}")
                    L.append("")
                    _render_recon(L, r)
                    L.append("  操作步骤：")
                    L.append("")
                    for line in (r.procedure or "（未填写步骤）").split("\n"):
                        L.append(f"  {line}" if line.strip() else "")
                    L.append("")
                    L.append(f"  判定标准：{r.expect or '—'}")
                    L.append("")

            # ---- 人工项自动前置侦察结论（按项列出，与状态无关）----
            #
            # 为什么单独成节、而不是只写在上面的人工清单里：
            # 侦察一旦**确证**了问题，该项状态会变成「不通过」并移出人工清单。
            # 如果只挂在人工清单上，那条已确证的发现会同时带走
            # 「本项还剩下哪些人工步骤没做」这个信息 —— 读者只看到一条漏洞，
            # 不知道这一项其实只被验证了一部分。所以这里按项全量列出。
            #
            # 标题刻意不写「业务逻辑」：挂了侦察的还有认证 / 会话 / 加密三类
            # （ATHN / SESS / CRYP）。标题写死分类，读者会以为那些项没做侦察。
            recon_items = [r for r in ctx.item_results if r.recon_ran or r.recon_note]
            if recon_items:
                sec3_idx += 1
                ran = [r for r in recon_items if r.recon_ran]
                _cats: list[str] = []
                for _r in recon_items:
                    _c = _r.item_id.split("-")[1] if "-" in _r.item_id else ""
                    if _c and _c not in _cats:
                        _cats.append(_c)
                L.append(f"### 3.{sec3_idx} 人工项自动前置侦察结论"
                         f"（{len(recon_items)} 项：{'/'.join(_cats)}）")
                L.append("")
                L.append(
                    "这些检查项仍是人工项 —— 最后那句判断只能由人做"
                    "（业务上应该如何、锁定阈值是否合理、并发策略选哪一种）。"
                    "但「找接口、找字段、记当前值、盘点现有防护、做只读差分」"
                    "这些准备工作已经自动化，"
                    f"本节是侦察的实际产出。本次 {len(ran)}/{len(recon_items)} 项侦察已执行。")
                L.append("")
                L.append("侦察结果分三类，读法完全不同：")
                L.append("")
                L.append("| 侦察结果 | 含义 | 该项能否视为已覆盖 |")
                L.append("|---------|------|------------------|")
                L.append("| 确证问题 | 差分实验拿到可复测证据，已计入发现列表 | "
                         "否 —— 仅本项中可自动证的部分，残留人工步骤仍须执行 |")
                L.append("| 已定位但未确证 | 对象都找齐了，但业务结果对不对只有人能判断 | "
                         "否 —— 但人工不必再找接口和字段 |")
                L.append("| 侦察未执行 | 档位不足 / 无登录态 / 无采集输入 | "
                         "否 —— 且**没有任何自动化前置覆盖**，需从零开始 |")
                L.append("")
                for r in recon_items:
                    mark = "✅ 已执行" if r.recon_ran else "⚠ 未执行"
                    L.append(f"**{r.item_id} {r.name}** —— {mark}")
                    L.append("")
                    if r.recon_finding_count:
                        L.append(f"- 侦察确证：{r.recon_finding_count} 项问题"
                                 "（已计入发现列表，本项状态为「不通过」；"
                                 "残留人工步骤见 3." + str(sec3_idx - 1) + " 节或该发现的复现说明）")
                    else:
                        L.append("- 侦察确证：0 项（**不等于本项通过** —— "
                                 "侦察覆盖的是可自动证的部分，业务语义未验证）")
                    if r.recon_probes:
                        L.append(f"- 侦察请求数：{r.recon_probes}")
                    for line in (r.recon_note or "").split("\n"):
                        if line.strip():
                            L.append(f"  {line}")
                    if r.recon_lead:
                        L.append("- 已定位到的具体对象：")
                        for lead_line in r.recon_lead:
                            L.append(f"  - {lead_line}")
                    L.append("")

            # ---- 弱判定 N/A 复核清单 ----
            weak = [r for r in app if r.weak_na]
            sec3_idx += 1
            L.append(f"### 3.{sec3_idx} 需人工复核的 N/A 项（{len(weak)} 项）")
            L.append("")
            if not weak:
                L.append("无。本次所有 N/A 判定均基于确证性证据。")
                L.append("")
            else:
                L.append(
                    "以下项判定为「不适用」，依据是**有限入口探测未命中**。"
                    "这类判定无法排除目标存在非标准路径入口的可能（例如登录入口不叫 `/login` 而叫 `/passport/sign-in`）。"
                    "**若复核发现目标实际具备该功能，请告知，我们将补做对应检查** —— "
                    "这是防止真实风险被「不适用」掩盖的关键一环。"
                )
                L.append("")
                L.append("| 检查项 | 名称 | 依据特征 | 判定依据 |")
                L.append("| --- | --- | --- | --- |")
                for r in weak:
                    L.append(f"| {r.item.id} | {r.item.name} | {r.item.app} | {self._short(r.feature.evidence, 70)} |")
                L.append("")
                by_feat: dict[str, list[str]] = {}
                for r in weak:
                    by_feat.setdefault(r.item.app, []).append(r.item.id)
                L.append("**按特征聚合的复核清单**（只需确认下列特征是否存在，即可一次性判定全部关联项）：")
                L.append("")
                L.append("| 待确认特征 | 涉及检查项数 | 若存在的后果 |")
                L.append("| --- | --- | --- |")
                for feat, ids in sorted(by_feat.items(), key=lambda x: -len(x[1])):
                    L.append(f"| {feat} | {len(ids)} | 需补做这 {len(ids)} 项检查 |")
                L.append("")

        # ---- 第 2 章：漏洞详情与复现步骤（结论区，前移）----
        L = MAIN   # 恢复指向：漏洞详情紧接第 1 章结论之后
        L.append("## 2. 漏洞详情与复现步骤")
        L.append("")
        if not fs.findings:
            L.append("本次扫描未发现可确证的漏洞。")
            L.append("")
            L.append("> 说明：这不等于「目标安全」。真实含义是「本轮检测未产生通过复现验证的发现」。"
                     "第 3 章的「未执行 / 待人工执行 / 待确认」项，以及 2.x 节的未复现、无法判定条目，"
                     "都仍是未知区域。")
            L.append("")
            if ctx.prior_unverified:
                # 「本轮清单为空」**不等于**「历史的问题没了」。此前扫描报过的
                # 东西如果本轮只是没去复看，本章若就此停笔，读者会把这份报告
                # 当成「漏洞已清零」的证据（2026-09-30 安全负责人指出）。
                L.append("**但本章不空：此前扫描上报过、本轮未能复测的问题如下。**")
                L.append("")
                self._render_carryover(
                    ctx, L, lead="**此前扫描上报过、本轮未能复测的问题有 ",
                    show_source=True)
                L.append("")
        else:
            L.append(f"本节列出 **{len(fs.findings)} 项漏洞**。"
                     "**每一项都经过独立复现脚本实测通过** —— "
                     "按「复现操作」执行一次，必须得到与「实测记录」一致的结果。")
            L.append("")
            L.append("> **准入口径**：检测器发现 → 生成独立复现脚本 → 执行脚本 → "
                     "只有脚本复现成功（退出码 0）的发现才进入本节。"
                     "复现失败、无法判定、未生成脚本的发现一律不进漏洞清单，"
                     "但会在本节末尾「2.%d 未进入漏洞清单的发现」中逐条如实披露，不做静默丢弃。"
                     % (len(fs.findings) + 1))
            L.append("")
            L.append(f"> **口径区别**：第 3 章按**检查项**统计（一项检查可能产生多条发现），"
                     f"本章按**发现**统计，因此两处数字不必相等。")
            L.append("")
            if ctx.prior_unverified:
                # 本章有发现 ≠ 上一轮的问题都被复看过了。上轮报过、本轮对应
                # 检查项没跑（未执行 / 待人工 / 待确认 / 已跳过）的那些，
                # 必须在这里点名，否则读者只看到「本轮 N 项」就以为账已结清。
                L.append("> ⚠ **另有此前扫描上报过、本轮未能复测的问题 "
                         f"{len(ctx.prior_unverified)} 条**（本章下文不含它们，"
                         "也不得视作已修复）：")
                L.append(">")
                _pu_sorted = sorted(
                    ctx.prior_unverified,
                    key=lambda x: (SEVERITY_ORDER.index(x["severity"])
                                   if (x.get("severity") or "") in SEVERITY_ORDER
                                   else -1),
                    reverse=True)
                for _e in _pu_sorted:
                    L.append(f"> - 【{_e.get('severity') or '—'}】"
                             f"{_e.get('title') or '—'}"
                             + (f"　`{_e.get('endpoint')}`" if _e.get("endpoint")
                                else ""))
                L.append(">")
                L.append("> 逐条状态与补齐方式见随附《复扫比对报告》的"
                         "「本轮未判定（不是修复）」一节。")
                L.append("")

        if ctx.gate_result is not None:
            L.append(ctx.gate_result.summary_markdown())
            L.append("")
        else:
            L.append("> ⚠ **本次运行未接入准入闸门数据**，本节条目未经复现准入判定。"
                     "在补齐此环节前，请勿将本节内容对外发布。")
            L.append("")

        for i, f in enumerate(fs.sorted_findings(), 1):
            L.append(f"### 2.{i} [{f.severity}] {f.title}")
            L.append("")
            strength = (f.extra or {}).get("verify_strength", "") or ""
            repro_kind = (f.extra or {}).get("repro_kind", "") or ""
            L.append("| 项目 | 内容 |")
            L.append("| --- | --- |")
            L.append(f"| 检查项 | {f.item_id} |")
            L.append(f"| 受影响端点 | `{m.mask(f.endpoint)}` |")
            L.append(f"| HTTP 方法 | {f.method or '—'} |")
            L.append(f"| 受影响参数 | {f.param or '—'} |")
            L.append(f"| 定级 | **{f.severity}** |")
            L.append(f"| 置信度 | {f.confidence} |")
            L.append(f"| 证据级别 | {f.evidence_level}（{'确证可达' if f.evidence_level == 'A' else '路由存在' if f.evidence_level == 'B' else '无法确证'}） |")
            L.append(f"| 复现结论 | **已复现**（独立脚本执行，退出码 0） |")
            L.append(f"| 复现强度 | {STRENGTH_LABEL.get(strength, '未标注')} |")
            L.append(f"| 复现方式 | {REPRO_KIND_NOTE.get(repro_kind, repro_kind or '未标注')} |")
            sess_roles = list((f.extra or {}).get("repro_roles") or [])
            if (f.extra or {}).get("repro_needs_session") or sess_roles:
                # 越权类复现必须以真实身份请求。这一点必须印在报告上：
                # 否则读者只看到「已复现」三个字，无从知道复现脚本依赖外部会话，
                # 更不知道脚本在没填会话时给出的是「无法判定」而不是「未复现」。
                L.append(
                    "| 复现所需身份 | 需 2 个不同账号："
                    + "、".join(f"`{r}`" for r in (sess_roles or ["见脚本"]))
                    + "（脚本自行从会话文件 / 环境变量读取，**无需修改脚本**） |")
            L.append(f"| 发现来源 | {f.source_tool or '内置检测器'} |")
            L.append("")

            if strength == STRENGTH_WEAK:
                L.append("> ⚠ **本条为弱复现。**复现脚本只能确认该端点可达，"
                         "**不含本漏洞类型的专用断言**（即脚本成功 ≠ 该漏洞一定存在）。"
                         "本条的技术结论来自检测阶段的证据，脚本作用仅为「端点仍可访问」的佐证。"
                         "请以人工核对为准。")
                L.append("")

            L.append("**通俗描述**")
            L.append("")
            L.append(m.mask(f.description) or "（无）")
            L.append("")

            if f.technical_detail:
                L.append("**技术细节**")
                L.append("")
                L.append("```")
                L.append(m.mask(f.technical_detail))
                L.append("```")
                L.append("")

            L.append("**影响说明**")
            L.append("")
            L.append(m.mask(f.impact) or "（无）")
            L.append("")

            # 结果证明层结论：把「存在型」结论推进到「达成型」。
            # 「未能验证」必须与「未达成」分开表述 —— 前者是没测出结论，
            # 后者是试过且失败，混为一谈会让人误以为系统安全。
            _pf = (f.extra or {}).get("proof") or {}
            if _pf:
                _st = str(_pf.get("state") or "")
                L.append("**实测验证结果（结果证明层）**")
                L.append("")
                if _st == "已达成":
                    L.append(f"- 结论：**{_st}** —— "
                             f"{m.mask(str(_pf.get('detail') or ''))}")
                else:
                    L.append(f"- 结论：**{_st}** —— "
                             f"{m.mask(str(_pf.get('reason') or ''))}")
                    if _st == "未能验证":
                        L.append("- 说明：「未能验证」表示**条件不足以下结论**，"
                                 "既不等于该问题不存在，也不等于系统安全。")
                for ev in (_pf.get("evidence") or [])[:3]:
                    L.append(f"  - 证据：{m.mask(str(ev))}")
                L.append("")

            L.append("**复现操作**")
            L.append("")
            if f.verify_script:
                L.append(f"复现脚本：`{Path(f.verify_script).name}`")
                L.append("")
            L.append("```")
            L.append(m.mask(f.reproduction) or "（见复现脚本）")
            L.append("```")
            L.append("")
            if f.verify_output:
                L.append("**实测记录（脱敏）**")
                L.append("")
                L.append("```")
                L.append(m.mask(f.verify_output)[:3000])
                L.append("```")
                L.append("")

            L.append("**定级依据**")
            L.append("")
            grading = (f.extra or {}).get("grading")
            if grading:
                L.append("```")
                lines = [
                    f"危害类型：{hazard_label(str(grading.get('hazard_type', '')))}",
                    f"名义基线：{grading.get('baseline', '')}",
                    f"证据上限修正后：{grading.get('after_evidence_cap', '')}",
                ]
                if grading.get("downgrades"):
                    lines.append("降级因子：" + "、".join(grading["downgrades"]))
                if grading.get("upgrades"):
                    lines.append("升级因子：" + "、".join(grading["upgrades"]))
                lines.append(f"最终定级：{grading.get('final_severity', f.severity)}")
                lines.append("推导过程：")
                lines += [f"  {j}. {r}" for j, r in enumerate(grading.get("rationale", []), 1)]
                L.append("\n".join(lines))
                L.append("```")
            else:
                L.append(m.mask(f.grading_basis) or "（无）")
            L.append("")

            if f.evidence:
                L.append("**原始证据（已脱敏）**")
                L.append("")
                for ev in f.evidence[:5]:
                    L.append(f"- `{ev.kind}`：{ev.note}"
                             + (f"（原始内容指纹 `{ev.raw_hash}`）" if ev.raw_hash else ""))
                    L.append("")
                    L.append("```")
                    L.append(m.mask(ev.content)[:1500])
                    L.append("```")
                    L.append("")

            L.append("**修复建议**")
            L.append("")
            L.append(m.mask(f.remediation) or "（无）")
            L.append("")
            if f.compliance:
                L.append(f"**合规映射**：{f.compliance}")
                L.append("")
            L.append("---")
            L.append("")

        # ---- 2.x 未进入漏洞清单的发现（披露，不隐藏）----
        self._render_gate_disclosures(L, ctx, m, len(fs.findings) + 1, sec_prefix="2")

        # ---- 第 3 章续：扫描器能力缺口与盲区（归入覆盖情况）----
        L = SECT3
        L.append("---")
        L.append("")
        sec3_idx += 1
        L.append(f"### 3.{sec3_idx} 扫描器能力缺口与盲区（自动化扫不出的部分）")
        L.append("")
        L.append("> 本节内容**任何自动化扫描器都扫不出**，需人工理解业务语义或多账号交叉比对。"
                 "把它归入「检测覆盖情况」，是为了让读者一眼看清："
                 "**自动化检测的边界在哪里、边界之外还剩什么没看。**")
        L.append("")
        L.append(f"#### 3.{sec3_idx}.1 权限矩阵验证")
        L.append("")
        if ctx.authz_findings:
            for i, f in enumerate(ctx.authz_findings, 1):
                L.append(f"**3.{sec3_idx}.1.{i} [{f.severity}] {f.title}**")
                L.append("")
                L.append(f"- 端点：`{m.mask(f.endpoint)}`")
                L.append(f"- 证据级别：{f.evidence_level} / 置信度：{f.confidence}")
                L.append(f"- 描述：{m.mask(f.description)}")
                L.append(f"- 影响：{m.mask(f.impact)}")
                L.append(f"- 定级依据：{m.mask(f.grading_basis)}")
                L.append(f"- 修复建议：{m.mask(f.remediation)}")
                L.append("")
        else:
            L.append("- 未配置多测试账号，本次仅执行了「无凭据访问」检查。")
            L.append("- **建议**：提供 2 个同角色测试账号 + 2 个不同租户账号，"
                     "以完成完整的水平 / 垂直 / 跨租户越权矩阵验证。")
            L.append("")

        L.append(f"#### 3.{sec3_idx}.2 业务逻辑人工验证")
        L.append("")
        L.append("以下场景需结合业务语义人工验证，自动化工具无法覆盖：")
        L.append("")
        checklist = [
            "**优惠券 / 权益叠加**：是否存在可重复领取、叠加使用、回滚后仍生效的路径",
            "**退款与金额篡改**：提交订单后可修改金额 / 数量，或退款金额可超出实付",
            "**库存与超卖**：并发下单是否绕过库存校验，是否存在超卖",
            "**流程跳步**：能否跳过必要步骤（如跳过支付直接确认收货、跳过审批直接发布）",
            "**状态机越界**：能否把订单 / 审批单置为非法状态组合（如已取消又已发货）",
            "**频次与配额**：短信、优惠、抽奖是否有有效频控，能否被脚本批量刷取",
            "**价格与折扣**：单价、折扣率、运费是否可被客户端参数影响",
            "**数据导出**：导出功能是否限制范围（能否导出全量而非本人数据）",
        ]
        for c in checklist:
            L.append(f"- [ ] {c}")
        L.append("")
        if ctx.business_notes:
            L.append("**人工验证记录**：")
            L.append("")
            for n in ctx.business_notes:
                L.append(f"- {n}")
            L.append("")

        # ---- 第 5 章：合规对照（后置）----
        L = TAIL
        L.append("## 5. 合规对照")
        L.append("")
        L.append("本章把已发现问题映射到合规条款，可直接用于举证与整改台账。")
        L.append("")
        comp: dict[str, list[Finding]] = {}
        for f in fs.findings:
            key = self._compliance_key(f)
            comp.setdefault(key, []).append(f)
        L.append("| 合规条款 | 关联问题 | 问题数 | 最高等级 |")
        L.append("| --- | --- | --- | --- |")
        for clause, items in sorted(comp.items()):
            worst = max(items, key=lambda x: SEVERITY_ORDER.index(x.severity) if x.severity in SEVERITY_ORDER else -1)
            L.append(f"| {clause} | {'；'.join(i.title for i in items[:3])}{' 等' if len(items) > 3 else ''} | {len(items)} | {worst.severity} |")
        L.append("")
        # 「未发现问题的合规维度」
        # 不能简单用「该条款没有关联发现」来宣称「未发现违反项」—— 那是同一个
        # 「没发现 = 没问题」的谬误换了个粒度。要求两条：
        #   ① 本次确有检查项真正执行完成；
        #   ② 该条款至少被一个**执行过**的检查项覆盖。
        # 两条都不满足时，只能明确说「本次未取得判定依据」。
        _ir_c = self._item_summary(ctx.item_results) if ctx.item_results else {}
        _bblocked_c = (ctx.boundary is not None
                       and bool(getattr(ctx.boundary, "blocked", False)))
        _tested_c = _ir_c.get("通过", 0) + _ir_c.get("不通过", 0)
        L.append("**未发现问题的合规维度**")
        L.append("")
        if _bblocked_c or (ctx.item_results and _tested_c == 0):
            L.append("> ⚠️ 本次**没有任何检查项真正执行完成**"
                     + ("（请求在目标边界即被拦截，未触达应用）" if _bblocked_c else "")
                     + "，因此**不能得出「哪些合规条款没有问题」的结论**。"
                     "合规符合性判断须待有效扫描后重新出具，"
                     "本章不得用于举证或整改台账。")
            L.append("")
        else:
            all_clauses = {"等保2.0 安全计算环境-访问控制", "等保2.0 安全计算环境-入侵防范",
                           "等保2.0 剩余信息保护", "ISO 27001 A.8.3", "ISO 27001 A.8.8",
                           "ISO 27001 A.8.9", "ISO 27001 A.8.24", "PIPL 第 51 条"}
            # 只认「被已执行检查项覆盖过」的条款
            covered: set[str] = set()
            for r in (ctx.item_results or []):
                if getattr(r, "state", "") in ("通过", "不通过"):
                    for part in re.split(r"[/、,；;]", getattr(r, "compliance", "") or ""):
                        if part.strip():
                            covered.add(part.strip())
            silent = sorted((all_clauses - set(comp)) & covered)
            unknown = sorted(all_clauses - set(comp) - covered)
            for c in silent:
                L.append(f"- {c}：本次检查该项通过，未发现违反项")
            if unknown:
                L.append("")
                L.append(f"以下条款本次**未取得判定依据**（无检查项覆盖或相关项未执行），"
                         f"不作符合性判断：{'、'.join(unknown)}")
            L.append("")

        # ---- 第 6 章：附录（后置）----
        L.append("## 6. 附录")
        L.append("")
        L.append("### 6.1 扫描参数")
        L.append("")
        L.append("| 参数 | 值 |")
        L.append("| --- | --- |")
        L.append(f"| 扫描档位 | {ctx.profile_name} |")
        L.append(f"| 视角 | 公网 |")
        L.append(f"| 检查项基线 | {ctx.checklist_meta.get('baseline', 'OWASP WSTG')} |")
        L.append(f"| 检查项数量 | {ctx.checklist_meta.get('total_items', ap_summary['合计'])} |")
        L.append(f"| 扫描开始 | {ctx.scan_time} |")
        L.append("")

        L.append("### 6.2 工具与版本")
        L.append("")
        L.append("| 工具 | 可用性 | 版本 / 状态 | 用途 |")
        L.append("| --- | --- | --- | --- |")
        for t in ctx.tools:
            avail = "可用" if t.get("available") else "不可用"
            ver = t.get("version") or t.get("error") or "—"
            L.append(f"| {t.get('name')} | {avail} | {self._short(str(ver), 60)} | {t.get('purpose', '')} |")
        L.append("")
        if ctx.fallbacks:
            L.append("**降级说明**（工具缺失导致的覆盖度变化，如实标注）：")
            L.append("")
            for n in ctx.fallbacks:
                L.append(f"- {n}")
            L.append("")

        L.append("### 6.3 证据清单")
        L.append("")
        L.append(f"- 发现总数：{len(fs.findings)}")
        L.append(f"- 待确认项：{len(fs.pending)}（证据级别 C，未进入漏洞清单）")
        ev_total = sum(len(f.evidence) for f in fs.findings)
        L.append(f"- 证据条目：{ev_total} 条（全部经脱敏处理，附原始内容指纹）")
        if ctx.item_results:
            ir7 = self._item_summary(ctx.item_results)
            L.append(f"- 逐项执行记录：{ir7.get('合计', 0)} 项，"
                     f"其中实际执行 {ir7.get('自动执行', 0)} 项"
                     f"（明细见同目录 `检查项结论.json`）")
        L.append("")

        if ctx.submissions:
            L.append("**主动提交动作披露**（受控写验证做了什么都写在这里，"
                     "不做「悄悄试一下」）")
            L.append("")
            L.append("| # | 目标地址 | 提交字段 | 返回状态 | 动作类型 |")
            L.append("| --- | --- | --- | --- | --- |")
            for i, s in enumerate(ctx.submissions, 1):
                L.append(f"| {i} | `{m.mask(str(s.get('url', '')))}` | "
                         f"{', '.join(s.get('fields', []) or [])} | "
                         f"{s.get('status', '')} | {s.get('kind', '')} |")
            L.append("")

        # 渲染是**有副作用**的动作，必须与受控写同等对待地披露：
        # 完整披露在**第 4 章授权与范围声明**（那是读者判断「这个工具对我做了什么」
        # 的地方）；这里只留一句指路，不重复整张表。
        if ctx.render:
            L.append("**浏览器渲染**：本次启用了入口页浏览器渲染，"
                     "副作用与结果见第 4 章「授权与范围声明」。")
            L.append("")

        # 渲染的**副作用披露**在第 4 章（授权与范围声明）已给出；
        # 这里只补一句「它如何影响本章 N/A 的读法」，避免重复。
        _r = ctx.render or {}
        _re = _r.get("entry") or {}
        if _r and not _re.get("ok"):
            L.append("> ⚠ **入口页未成功渲染** —— 现代前端应用（SPA）的首屏是"
                     "JavaScript 骨架页，未渲染时拿不到菜单、表单与页面文案。"
                     "本章中与「页面内容 / 表单 / 链接」相关的 **N/A** 结论，"
                     "应读作「**本次没看到**」，不应读作「**目标不存在**」，"
                     "需人工用浏览器打开页面确认。")
            L.append("")

        if fs.pending:
            L.append("**待确认清单**（需人工确认目标是否存在，确认后再纳入漏洞清单）：")
            L.append("")
            L.append("| 检查项 | 标题 | 端点 | 未确证原因 |")
            L.append("| --- | --- | --- | --- |")
            for f in fs.pending:
                L.append(f"| {f.item_id} | {f.title} | `{m.mask(f.endpoint)}` | {self._short(f.description, 60)} |")
            L.append("")

        L.append("### 6.4 枚举与探测覆盖范围")
        L.append("")
        L.append("「没发现问题」只有在说清「试过什么」之后才有意义。"
                 "本节列出本次实际覆盖的地址来源与端口范围。")
        L.append("")
        cov = self._coverage_rows(ctx)
        if cov["url_rows"]:
            L.append(f"**URL 枚举**（{cov['url_total']} 个地址，{len(cov['url_rows'])} 类来源）")
            L.append("")
            L.append("| 来源 | 数量 | 说明 |")
            L.append("| --- | --- | --- |")
            for src, n, note in cov["url_rows"]:
                L.append(f"| {src} | {n} | {note} |")
            L.append("")
            if cov.get("url_notes"):
                # 这一段是「本次没拿到什么」。它必须挨着来源表出现 ——
                # 光看表只会知道「枚举了 N 个地址」，不会知道其中某个来源
                # 本该有内容却一个都没拿到。
                for _n in cov["url_notes"]:
                    L.append(f"- {_n}")
                L.append("")
            if cov["url_skipped"]:
                L.append(f"**刻意未枚举的地址（{len(cov['url_skipped'])} 个）**")
                L.append("")
                L.append("枚举会大量发起 GET 请求。以下路径一旦被 GET 就可能产生真实副作用"
                         "（登出、删除、取消订单等），因此**从候选清单中主动剔除**，"
                         "不纳入自动探测 —— 这类路径只能人工在受控条件下验证。")
                L.append("")
                for p, why in cov["url_skipped"][:15]:
                    L.append(f"- `{p}` —— {why}")
                if len(cov["url_skipped"]) > 15:
                    L.append(f"- …… 其余 {len(cov['url_skipped']) - 15} 个同因剔除")
                L.append("")
        else:
            L.append("本次未采集到 URL 枚举覆盖记录。")
            L.append("")

        if cov["port_rows"]:
            L.append("**端口探测**")
            L.append("")
            L.append("| 目标 | 扫描档位 | 覆盖端口数 | 实测开放 | 可达范围（实测判定） |")
            L.append("| --- | --- | --- | --- | --- |")
            scope_txt = cov["reach_scope"] or "未判定"
            for host, rec in cov["port_rows"].items():
                opened = rec.get("open") or []
                L.append(f"| {host} | {rec.get('profile', '—')} | {rec.get('scanned', 0)} | "
                         f"{', '.join(str(p) for p in opened) if opened else '无'} | {scope_txt} |")
            L.append("")
            L.append("> 端口暴露以**公网可达**为唯一判据。上表为探测结果记录，"
                     "不代表已从公网逐端口交叉验证；如需确证，请结合公网测绘平台复核。")
            if cov["reach_why"]:
                L.append(f">")
                L.append(f"> 本次可达范围判定依据：{cov['reach_why']}")
            L.append("")

        L.append("### 6.5 脱敏与数据处理说明")
        L.append("")
        L.append("- 扫描过程中采集到的凭据、手机号、身份证、邮箱、银行卡等信息，"
                 "在落盘与报告中均已脱敏（保留前缀便于定位，其余打码）。")
        L.append("- 每处证据附有原始内容的哈希指纹，用于证明证据未被篡改（哈希不可逆）。")
        L.append("- 若需查看未脱敏的完整证据，须按公司数据分级审批流程申请，"
                 "并全程留痕。")
        L.append("")

        L.append("### 6.6 免责声明")
        L.append("")
        L.append("- 本报告基于扫描时间点的目标状态，**不能等同于目标在任一时点均无漏洞**。")
        if ctx.item_results:
            ir9 = self._item_summary(ctx.item_results)
            L.append(f"- 本次有 {ir9.get('未执行', 0)} 项未执行、"
                     f"{ir9.get('待人工执行', 0)} 项待人工执行。"
                     "这些项**没有结论，不能视为安全**，清单与补齐方式见第 3 章。")
        L.append(f"- 本次共 {len(unconfirmed)} 项发现为技术证据推断（未执行主动验证），"
                 "已按其证据级别设有定级上限，结论可能偏保守。")
        L.append("- 业务逻辑漏洞与权限矩阵错配（第 3 章）需持续人工验证，"
                 "自动化扫描不能替代。")
        L.append("- 未实测复现的问题，建议在测试环境按复现脚本确认后再定稿修复方案。")
        L.append("")

        # ---- 按「结论前置、过程后置」拼装 ----
        # 1 扫描对象与漏洞总览 → 2 漏洞详情与复现步骤 → 3 检测覆盖情况
        # → 4 授权与范围声明 → 5 合规对照 → 6 附录
        L = MAIN
        L.extend(SECT3)
        L.extend(SECT4)
        L.extend(TAIL)
        return "\n".join(L)

    # ==================================================================
    # x.x 未进入漏洞清单的发现（披露，不隐藏；章号由调用方 sec_prefix 指定）
    # ==================================================================
    def _render_gate_disclosures(self, L: list[str], ctx: ReportContext,
                                 m: Masker, sec_no: int,
                                 sec_prefix: str = "4") -> None:
        """渲染「没过闸门、因此没进漏洞清单的发现」。

        设计原则：闸门是**分类器，不是垃圾桶**。没通过复现的发现仍然全部列出，
        只是不以「漏洞」名义出现、不计入漏洞数量。若静默丢弃，检测器的误报
        会因为无人看见而长期存在 —— 那等于用「不写」掩盖准确性问题。
        """
        gate = ctx.gate_result
        if gate is None:
            return

        groups = [
            (gate.refuted, f"{sec_prefix}.{sec_no}.1 证伪记录：脚本执行但未复现",
             "检测器报了，但用同一判据独立复现失败。",
             "可能原因有三：**① 检测器误报**（判据过宽，或只看了表面特征）；"
             "**② 问题已被修复**（距上次扫描目标已变化）；"
             "**③ 判据不一致**（检测器与复现脚本的判定标准不同）。"
             "①② 属正常收敛，**③ 是工具缺陷，请反馈**。"),
            (gate.inconclusive, f"{sec_prefix}.{sec_no}.2 待人工复现：脚本无法判定",
             "脚本能跑通，但不足以判定该问题是否存在。",
             "⚠ **退出码 2 的含义是「无法判定」，不是「没问题」。**"
             "两种常见原因："
             "**① 该漏洞类型尚无专用断言**，脚本只能确认端点可达；"
             "**② 本项复现需要真实身份** —— 越权类问题以匿名请求必然撞上登录页 / 401，"
             "脚本会明确报出「无法判定」并给出填写说明，"
             "请在复现脚本同目录的 `aiscan_sessions.json` 里填好账号凭据后重跑"
             "（凭据不进脚本，也无需改动脚本任何一行）。"
             "两种情况都请人工按 `verify/` 下对应脚本的提示复核。"),
            (gate.unverified, f"{sec_prefix}.{sec_no}.3 未验证清单：未生成或未执行复现脚本",
             "无脚本可执行，因此**完全无法判断能否复测**。",
             "这类发现的可信度最低 —— 既没证实也没证伪。"
             "常见原因：该检查项尚无复现模板、脚本生成阶段异常、或复现环节整体未执行。"),
        ]

        if not any(g[0] for g in groups) and not ctx.blocked_findings:
            L.append(f"### {sec_prefix}.{sec_no} 未进入漏洞清单的发现")
            L.append("")
            L.append("无。本轮所有发现都通过了复现准入，没有需要披露的落选条目。")
            L.append("")
            return

        L.append(f"### {sec_prefix}.{sec_no} 未进入漏洞清单的发现")
        L.append("")
        L.append("本节列出**全部未通过复现准入的发现**。它们不进上面的漏洞清单，"
                 "也不计入任何漏洞数量，但**一律如实披露** —— "
                 "否则检测器的误报会长期无人察觉，「报告里的都是真的」就成了一句空话。")
        L.append("")

        for decisions, title, lead, why in groups:
            if not decisions:
                continue
            L.append("---")
            L.append("")
            L.append(f"#### {title}")
            L.append("")
            L.append(f"共 {len(decisions)} 条。{lead}")
            L.append("")
            L.append(why)
            L.append("")
            # 本组里只要有一条需要会话，就加一列把「需要哪些身份」标出来 ——
            # 否则读者看到「无法判定」会以为是工具能力不足，而不是「凭据没填」。
            any_sess = any((d.finding.extra or {}).get("repro_needs_session")
                           for d in decisions)
            if any_sess:
                L.append("| 检查项 | 名称 | 严重度 | 端点 | 复现方式 | 复现所需身份 | 判定说明 |")
                L.append("| --- | --- | --- | --- | --- | --- | --- |")
            else:
                L.append("| 检查项 | 名称 | 严重度 | 端点 | 复现方式 | 判定说明 |")
                L.append("| --- | --- | --- | --- | --- | --- |")
            for d in decisions:
                f = d.finding
                kind = (f.extra or {}).get("repro_kind", "") or ""
                roles = list((f.extra or {}).get("repro_roles") or [])
                sess_cell = ("、".join(f"`{r}`" for r in roles)
                             if (f.extra or {}).get("repro_needs_session") else "—")
                L.append(
                    f"| {d.item_id} | {self._short(d.title, 46)} | {f.severity} | "
                    f"`{m.mask(f.endpoint) or '—'}` | "
                    f"{REPRO_KIND_NOTE.get(kind, kind or '—')} | "
                    + (f"{sess_cell} | " if any_sess else "")
                    + f"{self._short(d.reason, 60)} |"
                )
            L.append("")

            scripted = [d for d in decisions if d.script]
            if scripted:
                L.append("**可自行执行复核**（脚本位于本次扫描产出目录的 `verify/` 下）：")
                L.append("")
                for d in scripted[:20]:
                    code = f"，退出码 {d.exit_code}" if d.exit_code is not None else "，未执行"
                    kd = REPRO_KIND_NOTE.get((d.finding.extra or {}).get("repro_kind", ""), "见脚本")
                    L.append(f"- `{Path(d.script).name}` —— {d.item_id}"
                             f"（复现方式：{kd}{code}）")
                if len(scripted) > 20:
                    L.append(f"- …… 其余 {len(scripted) - 20} 份脚本见产出目录 `verify/`")
                L.append("")
            else:
                L.append("> 本节无脚本可执行，因此**只能人工复核**。")
                L.append("")

        # 兜底：被拦下但闸门无记录的发现 —— 属链路记录丢失的工具缺陷
        known = {id(d.finding) for d in gate.decisions}
        orphans = [f for f in ctx.blocked_findings if id(f) not in known]
        if orphans:
            L.append("---")
            L.append("")
            L.append(f"#### {sec_prefix}.{sec_no}.4 记录不一致（{len(orphans)} 条，工具缺陷）")
            L.append("")
            L.append("以下发现被拦在漏洞清单外，但闸门判定中没有对应记录。"
                     "说明**准入链路存在记录丢失**，请反馈修复。")
            L.append("")
            for f in orphans:
                L.append(f"- {f.item_id} [{f.severity}] {f.title} —— `{m.mask(f.endpoint) or '—'}`")
            L.append("")

    # ==================================================================
    # 管理层摘要版
    # ==================================================================
    def _render_executive(self, ctx: ReportContext, fs: FindingSet,
                          app: list[ApplicabilityResult]) -> str:
        m = Masker("external")   # 对外版本额外抹除内网地址
        counts = fs.counts()
        ap_summary = ApplicabilityEngine.summary(app)

        L: list[str] = []
        L.append(f"# {ctx.target_name} 安全评估摘要")
        L.append("")
        L.append(f"**评估对象**：{ctx.target_name}（{ctx.primary_domain}）  ")
        L.append(f"**评估时间**：{ctx.scan_time}  ")
        L.append(f"**检查范围**：{ap_summary['合计']} 项安全检查，覆盖 OWASP WSTG 国际通行基线")
        L.append(f"**判定视角**：{MODE_LABEL.get(ctx.mode, ctx.mode)}")
        L.append("")

        # 被边界防护拦截时，风险评级**没有依据**。默认那套「无发现 = 低风险」
        # 在这里是彻底的误导：「低风险」意味着「测过了，没问题」，
        # 而实际情况是「根本没测到」。
        _bblocked = ctx.boundary is not None and bool(getattr(ctx.boundary, "blocked", False))
        _gterm = bool(ctx.boundary_guard is not None
                      and getattr(ctx.boundary_guard, "terminal", False))
        # 目标健康度停手（`hard_limits.stop_on`）。**必须与上面两者分开措辞**：
        # 边界拦截是「请求没到达应用」，健康度停手是「请求到了、应用自己在返错」。
        _hstop = bool(str(ctx.target_health_stop or "").strip())
        _hstop_only = _hstop and not _bblocked and not _gterm
        L.extend(self._boundary_alert(ctx, len(fs.findings)))
        L.extend(self._guard_alert(ctx))
        L.extend(self._health_alert(ctx))
        L.extend(self._render_degradation_alert(ctx))

        # 红队模式：目标达成情况是对外沟通的核心 ——
        # 「有没有被打穿、被打穿到什么程度」比「有多少个中危」更值得先说。
        if ctx.objectives:
            L.append("## 攻击目标达成情况")
            L.append("")
            L.append("| 攻击目标 | 结论 |")
            L.append("|---|---|")
            for oc in ctx.objectives:
                # 括注必须区分「档位不含」与「未授权」（redteam 铁律 2b）——
                # 一个字的差别，读者会去追一个不存在的授权缺口。
                mk = str(oc.result)
                if not getattr(oc, "authorized", True):
                    mk += {"profile": "（本档位不含，未执行）",
                           "ledger": "（未授权，未执行）"}.get(
                               getattr(oc, "scope_kind", ""),
                               "（未纳入执行范围，未执行）")
                L.append(f"| {oc.label} | {mk} |")
            L.append("")
            if any(str(oc.result) == "未能验证" for oc in ctx.objectives):
                L.append("> 「未能验证」表示条件不足以下结论，"
                         "**不代表这些攻击目标打不穿**。")
                L.append("")
        elif ctx.mode == MODE_REDTEAM:
            # 黑客运维视角却没结论 —— 必须说出来，不能空着（同技术版哨兵）
            L.append("## 攻击目标达成情况")
            L.append("")
            L.append("> ⚠️ 本次为**黑客运维视角**，但**未产出任何攻击目标结论**。"
                     "这**不代表**攻击目标不可达成，仅表示本次对其没有结论。")
            L.append("")
        else:
            # 没做目标结论时必须显式说出来 —— 空着不写，读者会读成「都没问题」
            L.append("## 攻击目标达成情况")
            L.append("")
            L.append(f"> ⚠️ 本次为**{MODE_LABEL.get(ctx.mode, ctx.mode)}**，"
                     f"**未执行攻击目标编排** —— 本摘要不包含"
                     f"「攻击目标是否达成」的结论。"
                     f"需要该结论请以默认模式（黑客运维）重扫。")
            L.append("")

        # ⚠ 条件不能写成 `(A or B or C) and 无发现`：A/B 两类拦截即使有发现
        # （非应用层通道产出）也必须判「无法评估」+ 把发现数出来。
        # 健康度停手则相反：**有发现时不能判「无法评估」** —— 那会把已实测到的
        # 严重漏洞一并判没（2026-09-30 OSS 匿名列举事故的同类错误）。
        if _bblocked or _gterm or (_hstop and counts.get("合计", 0) == 0):
            L.append("## 总体结论：无法评估")
            L.append("")
            # 「发现了什么」必须**数出来**再写。这一段曾经写死成
            # 「没有取得任何可用于风险判断的数据」+「问题分布为空」，而短路粒度
            # 改成按证据通道分流后，被封轮次照样产出非应用层发现
            # （内部生产系统 12:10 那轮 2 条中危 SPF / DMARC）—— 于是管理层摘要把 2 条
            # 真实问题吞掉了：同一批产出里通告有、技术版有、摘要没有。
            _sev_order = [s for s in reversed(SEVERITY_ORDER) if counts.get(s)]
            _sev_brief = "、".join(f"{s} {counts[s]} 条" for s in _sev_order)
            if _bblocked:
                L.append("本次请求在目标边界即被拦截，未触达业务系统，"
                         "**没有取得任何可用于判断应用层风险的数据**。"
                         "本摘要不对该系统的**应用层**安全状况作任何判断 —— "
                         "既不认为它安全，也不认为它有问题。")
            elif _hstop_only:
                L.append(f"本次扫描**主动提前停止**：{ctx.target_health_stop}")
                L.append("")
                L.append("停手原因是**目标在扫描期间出现异常**（连续返回 5xx / "
                         "响应时间暴增）。注意**这不是被 WAF 拦截** —— "
                         "请求确实到达了应用，是应用自己在返错；"
                         "排查方向应是**服务端为什么异常**，而不是防护白名单。"
                         "若这一异常由本次扫描造成，属**我方对目标的影响**，"
                         "应同步告知系统负责人。停止之后的检查项按「未执行」记录，"
                         "**缺少完整的定级依据**，本摘要不作安全性判断。")
            else:
                L.append("本次扫描**中途被边界防护封禁，且退避未能恢复** —— "
                         "封禁之后的检查项未触达应用。扫描只覆盖了前段，"
                         "**缺少完整的应用层定级依据**，"
                         "本摘要不对该系统的**应用层**安全状况作任何判断。")
            L.append("")
            # 发现的「来源通道」必须按拦截类型区分，**不能一律说「不经过 Web 边界」**：
            #   · A 类（开扫即被拦）：应用层项全部短路，发现只可能来自非应用层通道；
            #   · B 类（扫到一半被封）：**封禁前那段是够到应用的**，那里的发现就是
            #     应用层发现。把 B 类发现也说成「非应用层」，是反方向的说假话 ——
            #     等于把一条实测到的应用层漏洞降格成「配置类小问题」。
            _pure_a = _bblocked and not _gterm and not _hstop
            if _sev_brief:
                if _pure_a:
                    L.append(f"但**判据不经过 Web 边界的通道照常执行并已实测复现**："
                             f"本次实测发现 {counts['合计']} 条问题（{_sev_brief}），"
                             f"逐条见随附《扫描通告》第三节。")
                    L.append("")
                    L.append("> 这些发现**不来自应用层**。应用层本次一无所知 —— "
                             "**不代表应用没有问题**。")
                else:
                    L.append(f"本次实测发现 {counts['合计']} 条问题（{_sev_brief}），"
                             f"逐条见随附《扫描通告》第三节。"
                             f"**封禁之后的应用层检查未执行** —— 这些发现只覆盖"
                             f"扫描前段够到应用的那段时间，**不构成该系统的完整画像**。")
                L.append("")
            # 只写实测到的事实：**不要**写「换时间重扫不会改变 / 同样如此」——
            # 封禁能持续多久我们没测过。2026-09-30 内部生产系统 同日实测：
            # 11:40 L1 拿到数据、12:10 全程被拦、12:2x 又自行恢复 ——
            # 来源状态本身在变，断言「再扫也没用」超出证据（红线 46 第三款）。
            L.append("**下一步**：" + (
                "本次扫描已主动停手，未继续施压（**不做等待重试** ——"
                "这不是限流，等待无意义；服务异常时继续打只会加重故障）。"
                "建议先确认该目标在扫描时段是否确有异常，再安排复扫。"
                "判据不经过被测应用的检查项（DNS / 端口 / TLS / 证书透明度 / "
                "对象存储等）已照常执行，结论见《技术版报告》第 3 章；"
                "停止之后的应用层风险结论本次没有取得。"
                if _hstop_only else
                ("本来源本次开扫即被边界拦在门外" if _pure_a
                 else "本来源本次扫到一半被边界封禁、退避未恢复") +
                "（退避重试未恢复；**封禁能持续多久本次没有测到**）。"
                "判据不经过被测应用的检查项（DNS / 端口 / TLS / 证书透明度 / "
                "对象存储等）已照常执行，结论见《技术版报告》第 3 章；"
                + ("应用层的风险结论本次没有取得。" if _pure_a
                   else "封禁之后的应用层风险结论本次没有取得。")))
            L.append("")
            L.append("## 问题分布")
            L.append("")
            if _sev_brief:
                # A 类才能说「来自非应用层通道」；B 类是混合来源，只标「已实测复现」。
                _note_a = {
                    "严重": "来自不经过 Web 边界的通道，已实测复现",
                    "高危": "来自不经过 Web 边界的通道，已实测复现",
                    "中危": "来自不经过 Web 边界的通道，已实测复现",
                    "低危": "来自不经过 Web 边界的通道",
                    "信息": "加固建议",
                }
                _note_b = {
                    "严重": "已实测复现（含封禁前时段）",
                    "高危": "已实测复现（含封禁前时段）",
                    "中危": "已实测复现（含封禁前时段）",
                    "低危": "已实测复现（含封禁前时段）",
                    "信息": "加固建议",
                }
                _note = _note_a if _pure_a else _note_b
                L.append("| 等级 | 数量 | 说明 |")
                L.append("| --- | --- | --- |")
                for s in _sev_order:
                    L.append(f"| {s} | {counts[s]} | {_note.get(s, '—')} |")
                L.append(f"| **合计** | **{counts['合计']}** | " +
                         ("应用层 0 条（本次未触达） |" if _pure_a
                          else "封禁后的应用层未覆盖 |"))
            else:
                L.append("本次未取得应用层数据，问题分布为空。")
            L.append("")
            ir_b = self._item_summary(ctx.item_results) if ctx.item_results else {}
            if ir_b:
                L.append("## 检查项执行情况（说明本摘要为何没有结论）")
                L.append("")
                L.append("| 执行状态 | 项数 |")
                L.append("| --- | --- |")
                for k in ("通过", "不通过", "未执行", "待人工执行",
                          "N/A", "待确认", "已跳过"):
                    if ir_b.get(k):
                        L.append(f"| {k} | {ir_b[k]} |")
                L.append("")
                L.append("> 「未执行」= 本项需要触达应用才能判断，而本次请求被拦截，"
                         "**不是「已检查且无问题」**。")
                L.append("")
            return "\n".join(L)

        if counts.get("严重", 0) > 0:
            rating, action = "高风险", "建议立即安排处置，优先处理严重与高危项。"
        elif counts.get("高危", 0) > 0:
            rating, action = "中高风险", "建议在下一轮迭代内完成高危项修复。"
        elif counts.get("中危", 0) > 0:
            rating, action = "中等风险", "建议纳入版本计划，按优先级逐步修复。"
        else:
            rating, action = "低风险", "当前未发现直接影响数据或权限的问题，保持定期复检。"

        L.append(f"## 总体结论：{rating}")
        L.append("")
        L.append(action)
        if _hstop:
            # 有发现时保留按等级评出的结论（那才是实测结果），
            # 但要标明**覆盖范围只到停手那一刻** —— 不说这句，
            # 读者会把「已扫部分没问题」当成「整个系统没问题」。
            L.append("")
            L.append(f"⚠ 但本次扫描因**目标健康度异常提前停止**"
                     f"（{ctx.target_health_stop}），"
                     f"上述结论**只覆盖停手之前已执行的检查项**；"
                     f"停止之后的检查项**未执行**，见《技术版报告》第 3 章。")
        L.append("")
        # 固定句式（与通告同源）：摘要第一屏必须有可直接引用的核心数字 ——
        # 领导通常只读到这里，缺了这句就只能从下面的分布表里自己加总，
        # 而「加总」很容易漏掉「本轮有多少项压根没测」这个前提。
        L.append(f"本次从公网发起真实攻击测试，覆盖 {ap_summary['合计']} 项检查，"
                 f"**发现严重漏洞 {counts.get('严重', 0)} 个、"
                 f"高危漏洞 {counts.get('高危', 0)} 个、"
                 f"中危漏洞 {counts.get('中危', 0)} 个**。")
        L.append("")

        L.append("## 问题分布")
        L.append("")
        L.append("| 等级 | 数量 | 含义 |")
        L.append("| --- | --- | --- |")
        meaning = {
            "严重": "可直接获得系统控制权或全量数据",
            "高危": "可获取有效业务数据、越权操作或篡改数据",
            "中危": "存在技术证据但未实际造成危害，或影响限于本人",
            "低危": "仅暴露攻击面，尚未造成实际损失",
            "信息": "加固建议",
        }
        for s in reversed(SEVERITY_ORDER):
            L.append(f"| {s} | {counts.get(s, 0)} | {meaning[s]} |")
        L.append(f"| **合计** | **{counts['合计']}** | — |")
        L.append("")

        # 结论可信度声明：清单里的每一条都经脚本复现
        gs = ctx.gate_result.stats() if ctx.gate_result is not None else {}
        if gs:
            L.append("## 结论可信度")
            L.append("")
            L.append(f"本次共产生 {gs['发现总数']} 条原始发现，全部经独立复现脚本验证：")
            L.append(f"**{gs['已复现']} 条复现成功**（写入本报告问题清单），"
                     f"{gs['未复现'] + gs['无法判定'] + gs['未验证']} 条未能确认"
                     f"（不计入问题数，但在技术版报告第 2 章逐条披露）。")
            L.append("")
            # 可复测率是报告可信度最直接的一个数，必须显式给出，不能只给绝对数
            L.append(f"**可复测率 {gs['可复测率']:.1%}**"
                     f"（{gs['已复现']} ÷ {gs['发现总数']}）。"
                     + ("低于 80%，建议先看技术版报告的披露清单再使用本报告结论。"
                        if gs["可复测率"] < 0.8 else ""))
            L.append("")
            L.append("> 即：**本报告问题清单中的每一条，都能用随附脚本复测出来。**"
                     "复测不出来的条目，不会被写成「漏洞」。")
            L.append("")
            # 区分「证伪」与「无法判定」——前者是「跑不出来」，后者是「验不了」，
            # 两者都不是「没问题」。
            if gs["无法判定"] or gs["未验证"]:
                L.append(f"> 其中「未能确认」的构成："
                         + f"未复现 {gs['未复现']} 条（跑了脚本但没复现出来）；"
                         + f"**无法判定 {gs['无法判定']} 条（验不了，不是没问题）**；"
                         + f"未验证 {gs['未验证']} 条（脚本未执行）。")
                L.append("")

        L.append("## 需要关注的问题")
        L.append("")
        top = fs.sorted_findings()
        if not top:
            L.append("本次评估未发现需要业务侧关注的安全问题。")
        else:
            for i, f in enumerate(top[:5], 1):
                weak_mark = "（弱复现，建议人工核对）" if (
                    (f.extra or {}).get("verify_strength") == STRENGTH_WEAK) else ""
                L.append(f"**{i}. [{f.severity}] {f.title}**{weak_mark}")
                L.append("")
                L.append(f"   {m.mask(f.impact or f.description)}")
                L.append("")
        L.append("")

        L.append("## 我们做了什么")
        L.append("")
        if ctx.item_results:
            irE = self._item_summary(ctx.item_results)
            L.append(f"- 对目标执行了 {irE.get('合计', 0)} 项检查，"
                     f"其中**实际跑通 {irE.get('自动执行', 0)} 项**，"
                     f"{irE.get('待人工执行', 0)} 项需人工配合完成，"
                     f"{irE.get('未执行', 0)} 项本次未执行"
                     f"（未执行与待人工项均已在技术版第 3 章逐项列出，"
                     f"**这些项没有结论，不能当作安全**）")
            L.append(f"- {ap_summary[CONCLUSION_PASS_NA]} 项经判定不适用，"
                     f"技术版报告已逐项说明不适用的原因")
        else:
            L.append(f"- 对目标执行了 {ap_summary['合计']} 项检查，"
                     f"{ap_summary[CONCLUSION_PASS_NA]} 项经判定不适用"
                     f"（技术版报告已逐项说明原因）")
        confirmed = sum(1 for f in fs.findings if f.verify_result == "confirmed")
        if gs:
            L.append(f"- 列出的每一条问题都用独立脚本复跑验证过，"
                     f"**确认不是误报、且可复测**（{confirmed} 项已实测复现）")
            if gs.get("弱复现"):
                L.append(f"- 其中 {gs['弱复现']} 条为**弱复现**（脚本只能确认端点可达，"
                         f"不含该类型的专用断言），已在技术版报告中标注，建议优先人工核对")
            L.append(f"- 另有 {gs['未复现'] + gs['无法判定'] + gs['未验证']} 条发现"
                     f"**未能通过复现验证，没有计入问题数**，"
                     f"已在技术版报告第 2 章逐条披露（不做静默丢弃）")
        else:
            L.append(f"- 每一条问题都用独立脚本实际验证过，确认不是误报"
                     f"（{confirmed} 项已实测复现）")
        L.append("- 重点核查了「谁能看到谁的数据」这类工具查不出的问题")
        L.append("")

        L.append("## 下一步建议")
        L.append("")
        if counts.get("严重", 0) > 0 or counts.get("高危", 0) > 0:
            L.append("1. **立即**：安排资源修复严重与高危问题，修复方案见技术版报告")
        else:
            L.append("1. **按计划**：将中危问题纳入版本排期")
        L.append("2. **本轮内**：完成剩余中危项的修复与回归验证")
        L.append("3. **持续**：提供 2 组业务测试账号，以便我们完成越权相关检查"
                 "（这类问题工具无法发现，只能靠多账号交叉比对）")
        L.append("4. **持续**：建立定期复检机制，修复完成后重新扫描比对")
        L.append("")

        L.append("---")
        L.append("")
        L.append("*本摘要为管理层版，完整技术细节、复现步骤与修复方案见《技术版报告》。*")
        L.append("")
        return "\n".join(L)

    # ==================================================================
    # 「此前扫描上报过、本轮没有结论」的承接块
    # ==================================================================
    def _render_carryover(self, ctx: ReportContext, L: list[str],
                          *, lead: str, show_source: bool = False) -> None:
        """把上轮发现里「本轮没有结论」的那些**逐条**承接出去。

        为什么必须有这块：报告的问题清单是管理层唯一会读的那份。上一轮报过
        严重漏洞、这一轮因为边界拦截（或该项未执行）没去复看，清单若写「空」
        或者只字不提，读者只会读成「已经修好了」——**「本轮未再检出」不是
        修复证据**，本轮这些项的状态是「未执行 / 待人工执行 / 待确认 / 已跳过」
        之一，也就是没人去看（2026-09-30 安全负责人指出：上一轮报过严重漏洞，
        本轮却写「问题清单为空」）。

        为什么必须**逐条带等级**列：只给一个数字（「有 2 条未复测」）读者
        无从判断该不该现在排资源。「严重」两个字出现，这条才会被排进待办。

        为什么三条分支都要接：只要本轮任意一条发现进了清单，通告就会走
        「有发现」那条分支，承接块如果只挂在「本轮零发现」上，上轮的问题
        就会**在有发现的那次静默消失** —— 这比清单为空更隐蔽。
        """
        pu = sorted(
            ctx.prior_unverified,
            key=lambda x: (SEVERITY_ORDER.index(x["severity"])
                           if (x.get("severity") or "") in SEVERITY_ORDER
                           else -1),
            reverse=True)
        if not pu:
            return
        top = pu[0].get("severity") or "—"
        L.append(f"{lead}{len(pu)} 条（最高等级：{top}）"
                 f"—— 本次既未确认、也未推翻它们。**")
        L.append("")
        L.append("> 「本轮未再检出」**不构成修复证据**：这些项本轮的状态是"
                 "「未执行 / 待人工执行 / 待确认 / 已跳过」之一，"
                 "也就是**没有人去看**。")
        L.append("")
        for i, e in enumerate(pu, 1):
            ep = f"　`{e.get('endpoint')}`" if e.get("endpoint") else ""
            # 技术版要点名「出自哪一轮归档」—— 承接项是要被逐条核对的，
            # 读者得能自己翻回那一轮的报告去对。通告（发大群）不印这个：
            # 归档目录名对群里的读者是噪声。
            src = (f"　（出自 `{e.get('from_run')}` 归档）"
                   if show_source and e.get("from_run") else "")
            L.append(f"{i}. 【{e.get('severity') or '—'}】"
                     f"{e.get('title') or '—'}{ep}{src}")
        L.append("")
        L.append("> 逐条状态与补齐方式见随附《复扫比对报告》的"
                 "「本轮未判定（不是修复）」一节。")

    # ==================================================================
    def _render_notice(self, ctx: ReportContext, fs: FindingSet,
                       app: list[ApplicabilityResult],
                       *, full_repro: bool = False) -> str:
        """扫描通告（对外通晒版）—— 固定格式，直接可贴进部门大群。

        与另两份报告的根本差别：**它会被直接贴进大群**，读者不只是被通报
        系统的负责人，还有其上级和大量与该系统无关的同事。由此定四条规矩：

        1. **低危与信息类不列。** 通晒要回答的是「该谁修、修什么」，
           不是交台账。
        2. **复现步骤收敛掉可直接执行的命令**（见 `notice_repro_mask`）。
        3. **触达不了应用时不出漏洞统计。** 一份「严重 0 / 高危 0 / 中危 0」
           的通告发到群里，等于对整个部门宣告「这个系统没问题」——
           而事实是「压根没测到」。这是这份报告最危险的失败形态：
           它把一次无效扫描包装成了安全结论。触达不了时，
           通告要说的恰恰相反：**边界把外部攻击者挡住了，这是防护有效**，
           但应用自身有没有问题，本次没有结论。
        4. **与攻击者同一视角，不夹带运营诉求。** 红队从公网打过去，
           黑客面对什么环境，红队就面对什么环境 —— 被边界拦截就是
           「打不进去」这个实测结论本身，通告里**不出现**「请放行
           扫描来源 IP 后重扫」这类话：那是给内部扫描台账的备注，
           不是给全部门的结论。缺失项的处理口径写在技术版里，
           不占通告篇幅（2026-09-29 安全负责人定稿）。
        """
        m = Masker("external")
        counts = fs.counts()
        ir = self._item_summary(ctx.item_results) if ctx.item_results else {}
        tot = int(ir.get("合计", 0) or 0)
        blocked = ctx.boundary is not None and bool(getattr(ctx.boundary, "blocked", False))
        g = ctx.boundary_guard
        # 用 `occurred`（发生过封禁）而不是只看 `terminal`（未恢复）：
        # 封过又恢复的场景，通告原先说成「本次流量未被拦截」—— 这是错的。
        # 封禁窗口内的取证可能来自拦截页，那段时间的「通过」不能直接当结论，
        # 必须在通告里说出来，否则被通报方会以为这段是干净的。
        goccur = bool(g is not None and getattr(g, "occurred", False))
        gterm = bool(g is not None and getattr(g, "terminal", False))
        n_ban = len(getattr(g, "events", []) or []) if g is not None else 0
        # 「没有结论」的四类：未执行 / 待人工 / 待确认 / 已跳过。
        # 结论段与文末说明都要用，在这里算一次。
        # 「待确认」必须算进来 —— 它的含义是「外部确实判不出来」，
        # 同样不是「没问题」；漏算等于在通告里把一部分没结论的项
        # 悄悄算成了通过。
        _gap_parts = [(k, int(ir.get(k, 0) or 0))
                      for k in ("未执行", "待人工执行", "待确认", "已跳过")]
        _gap = sum(n for _, n in _gap_parts)

        # 只有「已实测复现」的发现才进通告，且只列严重 / 高危 / 中危。
        listed = [f for f in fs.sorted_findings()
                  if f.severity in ("严重", "高危", "中危")]

        L: list[str] = []
        L.append(f"# 【安全扫描通告】{ctx.target_name}")
        L.append("")
        L.append(f"**扫描系统**：{ctx.target_name}  ")
        L.append(f"**域名**：{ctx.primary_domain}  ")
        L.append(f"**扫描时间**：{ctx.scan_time}  ")
        # 只声明「公网位置 / 不借助内网通道」—— 这一条永远成立。
        # **不要**写「不使用任何内部账号」：提供凭据时红队确实会用授权测试账号，
        # 那句话在那种情况下就是假的。通告是要发到大群的对外文书，
        # 里面不能有自己都没法验证的绝对声明。
        L.append("**扫描方式**：从公网外部发起真实攻击测试"
                 "（不借助内网通道与内部网络位置）  ")
        L.append(f"**扫描视角**：{MODE_LABEL.get(ctx.mode, ctx.mode)}")
        L.append("")
        L.append("---")
        L.append("")

        # ---- 一、结论 ---------------------------------------------------
        L.append("## 一、扫描结论")
        L.append("")
        # 固定句式（2026-09-30 安全负责人定稿）：**只写关键结论** ——
        # 「测试方式 + 覆盖范围 + 三级漏洞计数」一句话说完。
        # 过程叙事（谁拦的、拦在哪一跳、退避几次）一律下移到第二节：
        # 通告是发到大群的，结论段每多一句，读者对核心数字的记忆就少一分。
        #
        # 但「精简」不等于「去掉限定」：零发现时若不紧跟限定，「0 个」会被
        # 读成「这个系统很安全」—— 那是本次数据支持不了的结论。
        # 所以主句固定、限定紧随其后，且尽可能短。
        _sev = counts.get("严重", 0)
        _high = counts.get("高危", 0)
        _mid = counts.get("中危", 0)
        L.append(f"本次从公网发起真实攻击测试，覆盖 {tot} 项检查，"
                 f"**发现严重漏洞 {_sev} 个、高危漏洞 {_high} 个、"
                 f"中危漏洞 {_mid} 个**。")
        L.append("")

        # 触达口径：**只在真有缺口时出现**，且必须区分 A 类（全程未触达）
        # 与 B 类（前段触达、中途被封）。把 B 类封禁前的应用层发现说成
        # 「非应用层」，是反方向的说假话 —— 2026-09-30 自查发现并修。
        if blocked:
            _reach_note = ("**Web 入口全部请求在边界即被拦截，应用层未能触达**"
                           " —— 从公网外部打不进去")
        elif gterm:
            _reach_note = "扫描中途触发边界封禁且未恢复，**后半段未能触达应用**"
        else:
            _reach_note = ""

        # ---- 2026-10-08 安全负责人改版：结论段只留主句（红线 54）----
        # 原先紧跟主句的**两行限定语**整段删除：
        #   ① 「其中 M 项本次有结论，上述数字对应这一部分；…另有 N 项本次
        #      没有取得结论（未执行 / 待人工 / 待确认）」
        #   ② 「未取得结论的项不代表没有问题 —— 它们本次没有结论…」
        # **这是有意为之，不是漏写。** 通告的读者面已从「被通报系统的负责人」
        # 扩到「全部门」：结论段每多一句，核心数字被记住的概率就少一分。
        # 缺口口径改由两处承担，**信息并没有丢**：
        #   · 第二节「防护有效性」—— 拦截程度 + 本来源被封的实测事实；
        #   · 第三节「问题清单」—— 承接区（此前报过、本轮未复测的逐条）。
        # 改版依据：`_diff_notice_template.py` 对归档做逐字节比对，
        # 差异恰好就是上面两行（外加绕过措辞与下划线转义）。
        # **不要以「这看起来像漏写」为由把它们加回来。**
        #
        # 唯一的例外是**零发现分支**（下方 `if not (_sev or _high or _mid)`）：
        # 那是红线 42③ 的另一半，针对的是**另一种**失败形态 —— 把「压根没测到」
        # 包装成「这个系统没问题」（「严重 0 / 高危 0 / 中危 0」发进大群）。
        # 安全负责人本次改的是**非零发现**时的措辞，未触及该分支，保留。
        if not (_sev or _high or _mid):
            # 零发现是这份通告最容易被读成「系统很安全」的形态，必须紧跟读法
            # 限定；即便没有缺口，也要说清「未发现」只描述本次实测范围。
            _why = ([_reach_note] if _reach_note else [])
            _why.append(f"{_gap} 项本次**没有取得结论**" if _gap
                        else "**「未发现」只描述本次实测范围**")
            L.append("> **「0 个」在这里不等于「没有问题」**："
                     + "；".join(_why) + "。")
        if ctx.prior_unverified:
            # 承接项**不得**计入上面的三级漏洞计数 —— 它们是「此前报过、
            # 本轮没复测」，与本轮实测发现是两类东西。必须紧跟在结论句后，
            # 否则大群读者只记住「发现了 X 个」，上一轮那条严重漏洞就没了。
            L.append(f"> 另有**此前扫描上报过、本轮未能复测**的问题 "
                     f"{len(ctx.prior_unverified)} 条 —— "
                     f"本次既未确认、也未推翻，见第三节问题清单。")
        # 本小节收尾：与下一节之间**恰好一个空行**。
        # 主句后面已经压了一行空行；两行限定语被删掉（红线 54）之后它就是
        # 本小节的最后一行，此时再无脑补一行会多出一个空行 ——
        # 逐字节比对安全负责人的模板时，差异恰好就停在这一行上。
        if L and L[-1] != "":
            L.append("")

        # ---- 二、防护有效性（先回答「防护是真的有效吗」）-----------------
        # 这一节是红队视角的核心产出，按安全负责人定稿的结构写：
        #   探测到什么防护写什么防护（WAF？防火墙？拿证据说话）→
        #   到什么程度会拦截 → 绕过试探结果 → 没拦住的流量扫出了什么。
        L.append("## 二、防护有效性（公网实测）")
        L.append("")

        # 探测到的防护（L1 边界判定 + 运行期封禁记录合并描述）
        _bp_desc = ""
        if blocked:
            _p = []
            if getattr(ctx.boundary, "vendor", ""):
                _p.append(str(ctx.boundary.vendor))
            if getattr(ctx.boundary, "status", 0):
                _p.append(f"统一返回 HTTP {ctx.boundary.status}")
            if getattr(ctx.boundary, "uniform", False):
                _p.append("随机不存在的路径与首页返回同一张拦截页")
            _bp_desc = "、".join(_p) if _p else "全部探测路径被统一接管"
            L.append(f"- **探测到的防护**：{_bp_desc}。")
        elif goccur:
            # 运行期频次类拦截：厂商特征优先取运行期守门**实测命中**的证据
            # （结构化字段，不解析日志文本），L1 的判定作为兜底。
            # 两者都没有才写「厂商特征未确认」—— 不编造是底线，
            # 但证据明明在手上却没接过来（2026-09-29 内部生产系统）是接线缺口，不是诚实。
            _v = str(getattr(ctx.boundary, "vendor", "") or "") if ctx.boundary is not None else ""
            if not _v and g is not None:
                _v = str(getattr(g, "vendor", "") or "")
            _who = _v if _v else "边界防护（厂商特征未确认）"
            L.append(f"- **探测到的防护**：{_who}，**基于请求频次的拦截**。")
        else:
            L.append("- **探测到的防护**：未探测到边界拦截特征 —— "
                     "请求直达应用。")

        # DNS 线索（CNAME → 边缘服务商）：**只作披露**，不是拦截判据。
        # 它回答「流量去了谁家的边缘」，读者据此知道该找谁核对策略。
        # 不能反过来读成「有 WAF」—— 同家的 CDN 与 WAF 共用 CNAME 后缀，
        # 源站直连型 WAF 更是完全不体现在 CNAME 上（红线：孤立信号不得当正面证据）。
        _hints = list(getattr(ctx.boundary, "vendor_hints", None) or [])
        if _hints:
            L.append(f"- **DNS 线索**：CNAME 指向 {'、'.join(_hints)} 边缘节点。"
                     f"**这只是线索，不代表发生过拦截** —— 同一家的 CDN 与 WAF "
                     f"共用 CNAME 后缀，是否拦截由响应特征判定。")

        # 拦截时机 / 程度
        if blocked:
            if listed:
                L.append("- **拦截程度**：**Web 入口的全部请求被接管**，"
                         "应用层未能触达；不经过 Web 边界的检查"
                         "（DNS 记录、端口可达性、对象存储等）不受影响。")
            else:
                L.append("- **拦截程度**：**开扫第一个请求即被接管**，"
                         "扫描全程未到达应用。")
        elif goccur:
            if gterm:
                L.append(f"- **拦截程度**：开扫时请求可达应用，"
                         f"**持续请求累计到一定量后触发拦截且未恢复**"
                         f"（本次被封 {n_ban} 次）—— 说明边界对该来源"
                         f"**存在基于请求量的拦截策略**，但**没能拦住前段流量**。")
            else:
                L.append(f"- **拦截程度**：高频探测时**被临时拦截 {n_ban} 次**，"
                         f"间隔后自动恢复 —— 只拦高频，不拦常态访问。")

        # 绕过尝试 —— **红队三段论**：先有拦截，才谈得上绕过。
        # 结论结构固定为「① 前提：探到什么拦截 → ② 尝试：N 种变形 + 基线对照
        # → ③ 结果：能否绕过」。没有①就没有③ —— 没撞上墙时「变形未被拦」
        # 证明不了任何事，只能写「本次未执行」。
        #
        # 2026-09-30 两处修正：
        #   · 过去只看 `blocked` 计数，在「本来源已被整体封禁」时写出
        #     「均被拦住 —— 拦截对本来源覆盖完整」；而那一批试探里连
        #     **不带任何变形的请求**也同样被拦，计数根本区分不出
        #     「WAF 识别了这个变形」与「来源已死」。
        #   · 「基线不通」时不再把整批一起作废：**基线被拦、变形未被拦**
        #     恰恰是绕过候选（`bypass_candidates`）—— 最值钱的发现，
        #     早先被 `usable=False` 连带丢掉了。
        _bp = summarize_bypass(ctx.bypass_probes or [],
                               getattr(ctx, "bypass_skip_reason", "") or "",
                               interception_occurred=bool(goccur))
        _cands = _bp.get("bypass_candidates") or []
        if _bp.get("skip_reason") and not _bp["tried"]:
            # ③-0 未执行：没探到拦截行为 → 本次没做，且必须说清为什么不做。
            #
            # **「没试绕过」有两种成因，措辞必须分开**（2026-09-30 内部生产系统 实测）：
            # 旧实现只有一套话术，其中那句「本次既没撞上墙，也就没有可绕之物」
            # 在**中途确实被拦过**的轮次里是**假的** —— 报告同一节里会同时出现
            # 「触发拦截且未恢复」与「没撞上墙」，读者连前面的真话一起不信。
            L.append(f"- **绕过尝试**：**本次未执行** —— "
                     f"{_bp['skip_reason']}。")
            L.append("")
            if _bp.get("interception_occurred"):
                L.append("> **未执行 ≠ 防护有效。** 而且本轮**确实被拦截过**"
                         "（见上「拦截程度」）—— 所以这里的「没试绕过」尤其要说清："
                         "它既不是「防护有效」，也不是「绕不过去」，就是**没试**。"
                         "跳过发生在拦截被观测到**之前**，跳过时的判断"
                         "（「未探到拦截行为」）已被后来的事实推翻。"
                         "**不得据此断言防护完整。**")
            else:
                L.append("> 未执行 ≠ 防护有效。绕过的前提是**有拦截行为** —— "
                         "先撞上墙，才谈得上翻墙；本次既没撞上墙，也就没有可绕之物。"
                         "这**也不代表**目标没有其他形态的防护：本次只在"
                         "「拦截页厂商特征」与「全站返回同一响应」两个口径上做了检测。")
        elif _bp["tried"]:
            if _cands:
                # ③-1 最值钱的形态：有别的东西在拦（基线被拦死），
                #      而这个变形穿了过去 —— 绕过候选。
                #      措辞停在「候选」：响应也可能是源站错误页，需人工复核。
                _cn = "、".join(str(c.get("name", "")) for c in _cands[:4])
                L.append(f"- **绕过尝试**：**发现 {len(_cands)} 个绕过候选**。"
                         f"前提 —— 同一时刻**不带任何变形的基线请求已被拦截**"
                         f"（HTTP {_bp['baseline_status']}）；红队据此用 "
                         f"{_bp['tried']} 种变形试探，"
                         f"其中 **{len(_cands)} 种未命中任何拦截特征**"
                         f"（{_cn}）—— 它们**可能**穿过了边界。")
                L.append("")
                L.append("> **这是候选而非结论。** 未命中拦截特征同样可能是"
                         "源站错误页、或另一种形态的拦截，须人工复核后才可写成"
                         "「绕过」。本轮**没有**自动改用这些变形继续扫描 —— "
                         "伪造来源头这类变形会改变应用侧行为，"
                         "据它取得的结论无法复现（红线：孤立信号不得当正面证据）。"
                         "复现命令见《技术版报告》。")
            elif not _bp.get("usable"):
                # ③-2 基线不成立且无候选 → 覆盖率不可评估（候选已在上面单独报过）
                #
                # 2026-10-08 安全负责人改版：**不再用「本次无法评估拦截覆盖率」开头**
                # （旧措辞见红线 53），改为直接讲事实、把「不下结论」留在句尾。
                # 语义一字未变 —— 末尾仍是「**本次不对覆盖率下结论。**」，
                # 少的只是开头那句前置标签。断言随之改成在这句上把关。
                L.append(f"- **绕过尝试**：本次红队试了 {_bp['tried']} 种变形，"
                         f"但同一时刻的"
                         f"**基线对照请求也没通过**（HTTP {_bp['baseline_status']}）"
                         f"—— 本来源已被整体封禁，连不带任何变形的普通请求同样被拦，"
                         f"所以「变形被拦」区分不出「边界识别了该变形」与"
                         f"「这个来源已经打不进去了」。**本次不对覆盖率下结论。**")
            elif _bp.get("nothing_blocked"):
                # 一个变形都没被拦，恰恰是最容易被写成「绕过面很大」的形态。
                # 但同一批里的基线（**不带任何变形**）也是 2xx —— 说明此刻
                # 边界对本批请求整体没有生效。没有拦可拦的东西，绕过无从谈起。
                # 2026-09-30 内部生产系统 实测原形：12/12 未被拦，同时基线 HTTP 200。
                L.append(f"- **绕过尝试**：红队用 {_bp['tried']} 种变形试探绕过"
                         f"（伪造内网来源、爬虫 UA、路径变形等），"
                         f"**没有一种被拦截**；但同一时刻**不带任何变形的基线"
                         f"请求同样直达应用**（HTTP {_bp['baseline_status']}）——"
                         f"也就是说，**此刻边界对本批请求整体没有生效**。"
                         f"因此本次结果只能说明「这些变形没有被拦」，"
                         f"**不能读成「绕过了防护」**：没有拦可拦的东西时，"
                         f"绕过无从谈起。本批只覆盖根路径及其变形，"
                         f"**其他路径是否被拦不在本结论范围内**。")
            elif _bp["missed"]:
                # 基线通、部分变形被拦、部分未拦：**未被拦者不构成绕过**
                # （基线本来也没被拦，没有可绕之物）。有价值的是「哪些被拦」。
                _names = "、".join(_bp["missed_names"][:4])
                _more = "等" if len(_bp["missed_names"]) > 4 else ""
                L.append(f"- **绕过尝试**：红队用 {_bp['tried']} 种变形试探绕过"
                         f"（伪造内网来源、爬虫 UA、路径变形等）："
                         f"**{_bp['blocked']} 种被拦、{_bp['missed']} 种未被拦**"
                         f"（{_names}{_more}）。基线对照请求可正常访问"
                         f"（HTTP {_bp['baseline_status']}），说明边界"
                         f"**并未拦阻本来源的常规请求**；未被拦的那些"
                         f"因此**不构成绕过证据** —— 没有可绕之物，"
                         f"它们只是普通请求的变体。"
                         f"**结论：未发现可绕过的手法** —— "
                         f"边界对其中 {_bp['blocked']} 类特征有识别规则，"
                         f"明细见《技术版报告》。")
            else:
                L.append(f"- **绕过尝试**：红队用 {_bp['tried']} 种变形试探绕过"
                         f"（伪造内网来源、爬虫 UA、路径变形等），"
                         f"**均被拦住**（基线对照成立：同刻无变形请求可正常访问）。"
                         f"**结论：未发现可绕过的手法** —— "
                         f"就本次试过的这些手法而言，拦截有效。")
        else:
            # tried == 0 且无 skip_reason：试探未执行或执行异常，如实说没测
            L.append("- **绕过尝试**：**本次未取得结果**"
                     "（试探未执行或执行异常），不对绕过有效性下结论。")

        # 落点：没拦住的流量扫出了什么
        _hit = counts.get("严重", 0) + counts.get("高危", 0) + counts.get("中危", 0)
        if blocked and not listed:
            L.append("- **未取得应用层数据**：请求没有到达应用，"
                     "应用自身的防护能力本次无法评价。")
            L.append("")
            L.append("> **挡住 ≠ 里面没问题。**本次没有发现漏洞，"
                     "是因为**请求没有触达应用**，"
                     "而不是因为这个系统经得起打。")
            L.append("> ")
            # 「拦住」只能证明「对本次来源、本次手法有效」。不写这句，
            # 管理层会把它读成「我们的防护很到位」—— 那是本次数据支持不了的结论。
            L.append("> 同理，**拦住 ≠ 能防住所有攻击者** —— "
                     "本次只验证了「本次来源 + 本次手法」被挡住；"
                     "换来源、换手法是否仍能挡住，本次没有结论。")
        elif blocked:
            pass  # 结论已在「拦截程度」里说清，清单见第三节
        elif listed:
            L.append(f"- **未被拦住的流量照常完成扫描**："
                     f"**{_hit} 处未能守住**（即下列问题）。")
        elif ctx.prior_unverified:
            # 同第一节：零发现但有承接项时，这句也得加「新的」限定 ——
            # 否则第二节又一次替整个系统背书「没发现 = 干净」。
            L.append(f"- **未被拦住的流量照常完成扫描**："
                     f"覆盖 {tot} 项检查，**本轮未发现新的严重、高危、中危漏洞**；"
                     f"此前扫描上报过、本轮未能复测的 "
                     f"{len(ctx.prior_unverified)} 条见第三节。")
        else:
            L.append(f"- **未被拦住的流量照常完成扫描**："
                     f"覆盖 {tot} 项检查，未发现严重、高危、中危漏洞。")
        L.append("")

        # ---- 三、问题清单 -----------------------------------------------
        L.append("## 三、问题清单")
        L.append("")
        if listed:
            if blocked:
                # 被拦但仍有已复现发现：先说清这些结论为什么不受拦截影响，
                # 否则读者会拿第一节的「被拦」来质疑清单本身。
                L.append("**Web 入口被拦截，但下列问题不经过 Web 边界防护通道**"
                         "（DNS 记录、端口可达性、对象存储等），"
                         "**均为已实测复现**：")
                L.append("")
            else:
                L.append("没拦住的流量扫出了以下漏洞（均经独立复现脚本实测确认）：")
                L.append("")
            for i, f in enumerate(listed, 1):
                L.append(f"### {i}. 【{f.severity}】{f.title}")
                L.append("")
                loc = f.endpoint or "—"
                if f.method:
                    loc = f"{f.method} {loc}"
                L.append(f"- **位置**：`{loc}`")
                if f.param:
                    L.append(f"- **参数**：`{f.param}`")
                _imp = (f.impact or f.description or "").strip()
                L.append(f"- **影响**：{m.mask(_imp) if _imp else '—'}")
                _rep = notice_repro_mask(m.mask(f.reproduction or ""),
                                         full=full_repro)
                # 反引号外的下划线加转义（`_dmarc` → `\_dmarc`）：
                # 2026-10-08 安全负责人改版通告时手工做的这一步，固化成默认行为。
                _rep = md_escape_plain_underscores(_rep).strip()
                L.append(f"- **复现**：{_rep if _rep else '—'}")
                L.append("")
            # 本轮有发现，但上轮「没有结论」的项同样要交代 —— 这块不能只挂在
            # 「本轮零发现」上：只要有任意一条发现进清单，上轮的问题就会
            # 在有发现的那次静默消失（比「清单为空」更隐蔽）。
            if ctx.prior_unverified:
                self._render_carryover(
                    ctx, L, lead="**另有此前扫描上报过、本轮未能复测的问题 ")
        elif blocked or gterm:
            # 本轮无新发现。但「本轮没测到」≠「没问题」：上一轮报过的问题
            # 如果本轮只是**没去复看**，写「清单为空」会被读成「已经修好了」
            # （2026-09-30 安全负责人指出：上一轮报过严重漏洞，本轮却写空）。
            if ctx.prior_unverified:
                self._render_carryover(
                    ctx, L, lead="**本轮没有新发现；但此前扫描上报过、"
                                 "本轮未能复测的问题有 ")
            else:
                L.append("**本次未取得应用层数据，问题清单为空。**")
                L.append("")
                L.append("> 这里写「空」的含义是**没有结论**，"
                         "不是「没有问题」。详见第二节。")
        else:
            L.append("本次未发现严重、高危、中危漏洞。")
            L.append("")
            if ctx.prior_unverified:
                # 本轮跑完了没新发现，但上轮有几条对应检查项没跑（待人工 /
                # 待确认 / 已跳过）→ 那几条既不能说修好了，也不能吞掉。
                self._render_carryover(
                    ctx, L, lead="**但此前扫描上报过、本轮未能复测的问题有 ")
            else:
                L.append("> 「未发现」指本次检查的范围内没有测出问题。")
        L.append("")
        return "\n".join(L)

    # ==================================================================
    # 辅助
    # ==================================================================
    @staticmethod
    def _coverage_rows(ctx: ReportContext) -> dict[str, Any]:
        """归一化「枚举与端口覆盖」数据，缺失字段一律降级为空，不抛异常。"""
        cov = ctx.coverage or {}
        url_rows = [tuple(r) for r in (cov.get("url_pool") or []) if len(r) == 3]
        return {
            "url_rows": url_rows,
            "url_total": sum(n for _, n, _ in url_rows),
            "url_skipped": [tuple(x) for x in (cov.get("url_skipped") or []) if len(x) == 2],
            # 覆盖度说明（不是「剔除」，是「本次没拿到什么」）。
            # 典型：接口文档找到了但解析失败 —— 这决定了读者怎么读
            # 「本次没有枚举到文档里的接口」这句话。
            "url_notes": [str(x) for x in (cov.get("url_notes") or []) if str(x).strip()],
            "port_rows": cov.get("ports") or {},
            # 可达范围（公网可达 / 内网可见）。端口类结论的定级完全取决于它，
            # 所以必须和端口清单并排展示，不能只写在正文里。
            "reach_scope": cov.get("reach_scope", ""),
            "reach_why": cov.get("reach_why", ""),
        }

    @staticmethod
    def _short(text: str, limit: int = 90) -> str:
        if not text:
            return ""
        t = str(text).replace("\n", " ").replace("|", "／").strip()
        return t[:limit] + ("…" if len(t) > limit else "")

    @staticmethod
    def _risk_index(fs: FindingSet) -> dict[str, list[Finding]]:
        idx: dict[str, list[Finding]] = {}
        for f in fs.findings:
            idx.setdefault(f.item_id, []).append(f)
        return idx

    # ---- 逐项执行结果的统计与渲染 ----
    @staticmethod
    def _item_summary(results: list[Any]) -> dict[str, int]:
        """按逐项执行结果统计各状态数量。"""
        out: dict[str, int] = {s: 0 for s in STATE_MEANING}
        for r in results:
            out[r.state] = out.get(r.state, 0) + 1
        out["合计"] = len(results)
        out["自动执行"] = sum(1 for r in results if getattr(r, "executable", False))
        return out

    @staticmethod
    def _result_detail(r: Any) -> str:
        """单行的「等级 / 原因」列。"""
        if r.state == "不通过":
            titles = list(getattr(r, "finding_titles", []) or [])
            if titles:
                return f"**{len(titles)} 项发现**：" + "；".join(t[:40] for t in titles[:2])
            return "发现问题（详见第 2 章）"
        if r.state == "通过":
            return "未发现问题"
        note = (r.note or "").replace("\n", " ").replace("|", "／")
        if not note:
            return "—"
        return note[:120] + ("…" if len(note) > 120 else "")

    @staticmethod
    def _notrun_bucket(note: str) -> str:
        """把未执行原因归到固定几个桶里，便于统计与补齐。"""
        n = note or ""
        if "没有绑定检测逻辑" in n:
            return "缺少检测逻辑"
        if "风险档" in n:
            return "档位限制"
        if "档位" in n:
            return "档位限制"
        if "前置条件不足" in n:
            return "前置条件不足"
        if "执行失败" in n or "异常" in n:
            return "检测器执行失败"
        if "适用性判定缺失" in n:
            return "适用性判定缺失"
        return "其他"

    def _pass_count(self, app: list[ApplicabilityResult], fs: FindingSet) -> int:
        """【已弃用】旧的「适用且无发现 = 通过」计数。

        保留仅为兼容历史调用，**不得再用于生成报告结论** ——
        它会把「没有检测代码」误算成「通过」，这正是本次改造要根治的问题。
        """
        risk = self._risk_index(fs)
        n = 0
        for r in app:
            if r.conclusion == CONCLUSION_APPLICABLE and not r.skipped_by_user:
                if r.item.id not in risk:
                    n += 1
        return n

    @staticmethod
    def _compliance_key(f: Finding) -> str:
        c = f.compliance or ""
        if not c:
            return "未映射"
        return c.split("/")[0].strip()


if __name__ == "__main__":
    print("报告生成器自测")
    print("=" * 70)

    from checklist.loader import load_checklist
    from engine.applicability import build_example_features
    from engine.tools import Toolchain
    from engine.nuclei_runner import BuiltinDetector
    from engine.fingerprint import Fingerprinter
    from rules.grading import GradingEngine

    cl = load_checklist()
    tf = build_example_features("示例会员系统")
    app = ApplicabilityEngine().evaluate(cl, tf)

    fp = Fingerprinter({"rate": {"requests_per_second": 5, "timeout_seconds": 10}})
    findings = BuiltinDetector().run("https://example.com", fp.client)
    for f in findings:
        f.target = "示例会员系统"
        f.verify_result = "confirmed"

    GradingEngine().grade_all(findings)

    fs = FindingSet(target="示例会员系统")
    for f in findings:
        fs.add(f)

    tc = Toolchain()
    tc.probe_all()

    ctx = ReportContext(
        target_name="示例会员系统",
        primary_domain="example.com",
        features={k: v.state for k, v in tf.features.items()},
        dns={"ips": ["104.20.23.154"], "consistent": True, "per_resolver": {"223.5.5.5/A": ["104.20.23.154"]}},
        root_probe={"status": 200, "server": "cloudflare"},
        authorization={"authorized": True, "authorizer": "示例授权人", "authorization_date": "2026-09-20",
                       "authorization_ref": "自测用例"},
        tools=tc.report_rows(),
        fallbacks=tc.fallback_notes(),
        checklist_meta=cl.meta,
    )

    out = Path(ROOT) / "outputs" / "_selftest" / "report"
    paths = ReportGenerator(out).generate(ctx, fs, app)
    print(f"\n生成报告：")
    for k, v in paths.items():
        print(f"  {k:<10} {v.name}  ({v.stat().st_size} 字节)")
