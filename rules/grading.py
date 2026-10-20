# -*- coding: utf-8 -*-
"""
L4 定级引擎
===========
职责：按「实测危害」而非 CVSS 分值给发现定级，并输出完整可审计的推导链。

定级逻辑（规格第 5 章）：
  1. 查「漏洞类型 → 实测危害基线」得到基础等级
  2. 按证据分级设上限（A 可至严重；B 上限中危；C 不进清单）
  3. 应用降级因子（每命中一项降一级）
  4. 应用升级因子（每命中一项升一级）
  5. 未实测确认的，最高只能中危
  6. 输出最终等级 + 每一步的理由

为什么不用 CVSS 直接定级：
  CVSS 衡量的是「漏洞技术严重程度」，本工程要回答的是「实际能拿到什么」。
  一个 CVSS 9.8 的漏洞如果实测只返回空数据，就不该定严重 —— 否则研发会认为
  报告在虚报，进而整份报告都不被信任。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Finding, SEVERITY_ORDER, severity_rank  # noqa: E402


def _shift(level: str, delta: int) -> str:
    """按档位平移等级，边界截断。"""
    idx = severity_rank(level)
    if idx < 0:
        return level
    return SEVERITY_ORDER[max(0, min(len(SEVERITY_ORDER) - 1, idx + delta))]


# ==============================================================================
# 漏洞类型 → 实测危害基线
# ==============================================================================
# 说明：这里给的是「在证据级别 A（已确证）前提下」的名义等级。
# 实际等级还要经过证据上限、降级因子、升级因子的修正。
# 判据写成「实测到 X 才算 Y 级」，而不是「这类漏洞就是 Y 级」。
HAZARD_BASELINE: dict[str, dict[str, str]] = {
    # ---- 直接拿到控制权 / 全量数据 ----
    "rce": {"A": "严重", "note": "实测可执行命令"},
    "sqli_dump": {"A": "严重", "note": "实测拖出库表数据"},
    "deserialization": {"A": "严重", "note": "实测反序列化执行"},
    "auth_bypass_admin": {"A": "严重", "note": "实测绕过认证进入管理后台且可操作"},
    "unauth_admin_panel": {"A": "严重", "note": "管理后台无鉴权且可实际操作"},
    "tenant_isolation_missing": {"A": "严重", "note": "实测跨租户读取他人数据"},
    "hardcoded_cloud_key": {"A": "严重", "note": "前端实测存在云访问密钥且可用"},
    "backup_download": {"A": "严重", "note": "实测可下载含全量数据的备份"},
    "db_backup_exposed": {"A": "严重", "note": "实测可下载数据库备份"},
    "actuator_env": {"A": "严重", "note": "实测 Actuator env 返回配置与环境变量"},

    # ---- 拿到有效业务数据 / 越权 / 篡改生效 ----
    "idor": {"A": "高危", "note": "实测读到他人业务数据"},
    "bola": {"A": "高危", "note": "实测越权访问他人对象"},
    "write_effective": {"A": "高危", "note": "实测写操作生效并落地"},
    "info_disclosure_data": {"A": "高危", "note": "实测响应含真实业务数据"},
    "unauth_api_data": {"A": "高危", "note": "实测无鉴权接口返回业务数据"},
    "file_download_data": {"A": "高危", "note": "实测下载到含真实数据的文件"},
    "cors_credentials": {"A": "高危", "note": "实测通配来源 + 允许凭据，可跨域读认证响应"},
    "debug_log": {"A": "高危", "note": "实测日志可访问且含 SQL / 路径 / 堆栈"},
    "git_exposed": {"A": "高危", "note": "实测 .git 可访问，可还原源码"},
    "svn_exposed": {"A": "高危", "note": "实测 .svn 可访问"},
    "env_exposed": {"A": "高危", "note": "实测 .env 可访问"},
    "weak_credential": {"A": "高危", "note": "实测弱口令可登录"},
    "upload_executable": {"A": "严重", "note": "实测上传可执行文件并触发"},

    # ---- 技术证据充分但未实证危害 ----
    "path_reachable_no_auth": {"B": "中危",
                               "note": "路由可达（鉴权状态未在本项验证），未取得数据"},
    "swagger_exposed": {"B": "中危", "note": "接口文档暴露"},
    "dir_listing": {"A": "中危", "note": "目录可浏览"},
    "http_dangerous_method": {"B": "中危", "note": "声明支持危险方法，未实际验证"},
    "sourcemap_exposed": {"A": "中危", "note": "源码映射可下载"},
    "cors_wildcard": {"B": "中危", "note": "通配来源但未允许凭据"},
    "default_login_page": {"B": "中危", "note": "默认管理入口暴露"},
    "websocket_no_origin_check": {"B": "中危", "note": "WebSocket 未校验 Origin"},

    # ---- 仅攻击面暴露 ----
    "missing_headers": {"A": "低危", "note": "安全响应头缺失，纵深防御不足"},
    "version_disclosure": {"A": "低危", "note": "组件版本泄露"},
    "component_version_extracted": {"A": "低危", "note": "前端组件版本可提取"},
    "internal_ip_leak": {"A": "低危", "note": "内网地址泄露"},
    "cookie_flag_missing": {"A": "低危", "note": "Cookie 缺少 HttpOnly/Secure"},
    "tls_weak_cipher": {"A": "低危", "note": "TLS 弱套件"},
    "port_open": {"A": "低危", "note": "端口开放"},
    "autocomplete_enabled": {"A": "低危", "note": "敏感表单未禁用自动填充"},
    "sri_missing": {"A": "低危", "note": "外链资源缺少 SRI"},
    "debug_flag_enabled": {"A": "信息", "note": "生产残留调试开关"},

    # ---- 优化建议 ----
    "config_hardening": {"A": "信息", "note": "配置加固建议"},
    "permissions_policy_missing": {"A": "信息", "note": "未声明 Permissions-Policy"},
}

# 检查项 ID → 危害类型（用于自动选基线）
ITEM_HAZARD_MAP: dict[str, str] = {
    "WSTG-CONF-04": "info_disclosure_data",
    "WSTG-CONF-06": "http_dangerous_method",
    "WSTG-CONF-07": "missing_headers",
    "WSTG-INFO-02": "version_disclosure",
    "WSTG-CLNT-11": "cors_wildcard",
    "WSTG-ATHZ-02": "idor",
    "WSTG-ATHN-02": "weak_credential",
    "WSTG-INPV-05": "sqli_dump",
    "WSTG-CRYP-01": "tls_weak_cipher",
    "EXT-SC-01": "component_version_extracted",
    "EXT-SC-07": "sourcemap_exposed",
    "EXT-DP-01": "internal_ip_leak",
}

# ==============================================================================
# 因子识别规则
# ==============================================================================
# 每个因子：(名称, 匹配函数)
DOWNGRADE_RULES: list[tuple[str, Any]] = [
    ("需已认证身份", lambda f: _any_kw(f, ["需登录", "需认证", "authenticated", "登录后", "带凭据", "已登录"])),
    ("需特定角色", lambda f: _any_kw(f, ["管理员角色", "需 admin", "特定角色", "高权限角色", "需 vip"])),
    ("需用户交互", lambda f: _any_kw(f, ["需点击", "诱导", "钓鱼", "社工", "需用户"] )),
    ("需罕见环境", lambda f: _any_kw(f, ["特定浏览器", "旧版本浏览器", "罕见配置", "需特定插件"])),
    ("版本区间无法确认", lambda f: _any_kw(f, ["版本区间", "未能确认版本", "无法确认可达", "疑似版本"])),
    ("单一账号影响", lambda f: _any_kw(f, ["仅影响本身份", "仅本人", "仅自身账号", "影响限于自己"])),
]

UPGRADE_RULES: list[tuple[str, Any]] = [
    ("无需认证", lambda f: _any_kw(f, ["无需认证", "未认证可获得", "匿名可", "未登录", "无凭据"])),
    ("可跨用户跨租户影响", lambda f: _any_kw(f, ["跨租户", "跨用户", "他人数据", "其他用户", "全量数据"])),
    ("可批量利用", lambda f: _any_kw(f, ["批量", "遍历", "全量拉取", "可枚举", "任意 ID"])),
    ("触及生产数据", lambda f: _any_kw(f, ["生产数据", "真实业务数据", "真实用户数据"])),
]


def _any_kw(f: Finding, keywords: list[str]) -> bool:
    """在发现的可解释文本中搜索关键词。"""
    blob = " ".join([
        f.title or "", f.description or "", f.impact or "",
        f.grading_basis or "", f.technical_detail or "", f.verify_result or "",
    ]).lower()
    return any(k.lower() in blob for k in keywords)


# ==============================================================================
# 危害类型 → 中文标签（报告可读性）
# ==============================================================================
# 报告里的「危害形态」列必须写人话。把 hazard_type 的内部键名
# （如 path_reachable_no_auth）直接印给读者，等于把机器标识当结论交付 ——
# 读者既看不懂「能不能拿到数据」，也无法据以决策。
# 新增 HAZARD_BASELINE 键时必须同步补这里，
# 否则自测的「标签完整性」断言会失败（防止两处失配）。
HAZARD_LABEL: dict[str, str] = {
    # ---- 可拿控制权 ----
    "rce": "可执行任意命令（取控制权）",
    "deserialization": "反序列化执行（取控制权）",
    "auth_bypass_admin": "认证绕过进入管理后台（取控制权）",
    "unauth_admin_panel": "管理后台未授权访问（取控制权）",
    "weak_credential": "弱口令（取控制权）",
    "upload_executable": "可上传可执行文件（取控制权）",
    # ---- 可取数据 ----
    "sqli_dump": "可拖取数据库数据（取数据）",
    "tenant_isolation_missing": "跨租户读取他人数据（取数据）",
    "hardcoded_cloud_key": "云密钥硬编码前端（取权限）",
    "backup_download": "可下载数据备份（取数据）",
    "db_backup_exposed": "数据库备份泄露（取数据）",
    "actuator_env": "Actuator 配置与环境变量泄露（取数据）",
    "idor": "越权访问他人对象（取/改数据）",
    "bola": "对象级越权（取数据）",
    "write_effective": "写入生效（可改数据）",
    "info_disclosure_data": "敏感信息泄露（取数据）",
    "unauth_api_data": "未授权接口取回业务数据（取数据）",
    "file_download_data": "文件可下载取回数据（取数据）",
    "cors_credentials": "CORS 携带凭据（取数据）",
    "debug_log": "调试日志暴露（取数据）",
    "git_exposed": ".git 目录泄露（可取源码与配置）",
    "svn_exposed": ".svn 目录泄露（可取源码）",
    "env_exposed": ".env 文件泄露（可取凭据）",
    # ---- 攻击面暴露 / 待验证 ----
    "path_reachable_no_auth": "路径可达，鉴权状态未验证",
    "swagger_exposed": "接口文档暴露（为其它攻击提供入口）",
    "dir_listing": "目录列举",
    "http_dangerous_method": "危险 HTTP 方法未禁用",
    "sourcemap_exposed": "Source Map 暴露（可还原源码）",
    "cors_wildcard": "CORS 通配任意来源",
    "default_login_page": "默认登录页未改",
    "websocket_no_origin_check": "WebSocket 未校验来源",
    "version_disclosure": "版本信息泄露",
    "internal_ip_leak": "内网 IP 泄露",
    "port_open": "端口对外开放",
    # ---- 配置加固 ----
    "missing_headers": "安全响应头缺失",
    "component_version_extracted": "组件版本已提取（待比对已知漏洞）",
    "cookie_flag_missing": "Cookie 安全标志缺失",
    "tls_weak_cipher": "TLS 弱加密套件",
    "autocomplete_enabled": "表单自动完成未关闭",
    "sri_missing": "外部脚本 SRI 缺失",
    "debug_flag_enabled": "调试标志未关闭",
    "config_hardening": "配置加固项",
    "permissions_policy_missing": "Permissions-Policy 缺失",
}


def hazard_label(key: str) -> str:
    """危害类型键名 → 中文标签。

    未登记的键**如实回显键名**，不猜、不美化 —— 猜错比不翻译更危险，
    读者会据此判断「能不能拿到数据」。
    """
    k = (key or "").strip()
    if not k:
        return "—"
    return HAZARD_LABEL.get(k, k)


# ==============================================================================
# 定级决策
# ==============================================================================
@dataclass
class GradingDecision:
    """一次定级的完整推导记录（可审计）。"""

    finding_title: str
    hazard_type: str = ""
    baseline: str = ""
    after_evidence_cap: str = ""
    final_severity: str = ""
    downgrades: list[str] = field(default_factory=list)
    upgrades: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    excluded: bool = False        # True 表示证据不足，不入漏洞清单
    exclude_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "hazard_type": self.hazard_type,
            "baseline": self.baseline,
            "after_evidence_cap": self.after_evidence_cap,
            "final_severity": self.final_severity,
            "downgrades": self.downgrades,
            "upgrades": self.upgrades,
            "rationale": self.rationale,
            "excluded": self.excluded,
            "exclude_reason": self.exclude_reason,
        }

    def render(self) -> str:
        """渲染成报告里「定级依据」段落。"""
        lines = [
            f"危害类型：{hazard_label(self.hazard_type)}",
            f"名义基线：{self.baseline or '（未定义）'}",
            f"证据上限修正后：{self.after_evidence_cap or '（不适用）'}",
        ]
        if self.downgrades:
            lines.append("降级因子：" + "、".join(self.downgrades))
        if self.upgrades:
            lines.append("升级因子：" + "、".join(self.upgrades))
        lines.append(f"最终定级：{self.final_severity}")
        if self.rationale:
            lines.append("推导过程：")
            lines.extend(f"  {i}. {r}" for i, r in enumerate(self.rationale, 1))
        return "\n".join(lines)


class GradingEngine:
    """按实测危害定级。"""

    def __init__(self, baseline: dict[str, dict[str, str]] | None = None,
                 item_map: dict[str, str] | None = None):
        self.baseline = baseline or HAZARD_BASELINE
        self.item_map = item_map or ITEM_HAZARD_MAP

    # ------------------------------------------------------------------
    def grade(self, f: Finding) -> GradingDecision:
        d = GradingDecision(finding_title=f.title)

        # --- 步骤 0：证据不足直接排除 ---
        if f.evidence_level == "C":
            d.excluded = True
            d.exclude_reason = (
                "证据级别 C（无法确证目标存在），按规格第 5 章不进入漏洞清单，"
                "列入「待确认」章节"
            )
            d.final_severity = ""
            d.rationale.append(d.exclude_reason)
            return d

        # --- 步骤 1：定位危害类型与基线 ---
        hazard = self._pick_hazard(f)
        d.hazard_type = hazard
        base_entry = self.baseline.get(hazard, {})
        raw_baseline = base_entry.get("A", f.severity or "中危")
        d.baseline = f"{hazard_label(hazard)} → {raw_baseline}"
        d.rationale.append(f"按危害类型「{hazard_label(hazard)}」取名义基线 {raw_baseline}（{base_entry.get('note', '')}）")

        # 若发现自报等级高于基线，以发现自报为准（说明有更具体的实测依据）
        current = f.severity if severity_rank(f.severity) > severity_rank(raw_baseline) else raw_baseline
        if current != raw_baseline:
            d.rationale.append(f"发现自带分级 {f.severity} 高于基线，采用 {current}")

        # --- 步骤 2：证据分级设上限 ---
        cap = f.max_allowed_severity
        if cap and severity_rank(current) > severity_rank(cap):
            d.rationale.append(
                f"证据级别 {f.evidence_level} 将定级上限压至 {cap}（原 {current}）"
            )
            current = cap
        d.after_evidence_cap = current
        if not cap:
            d.rationale.append(f"证据级别 {f.evidence_level} 未设上限")
        else:
            d.rationale.append(f"证据级别 {f.evidence_level} 上限为 {cap}")

        # --- 步骤 3：实测确认状态 ---
        if f.verify_result != "confirmed":
            if severity_rank(current) > severity_rank("中危"):
                d.rationale.append(
                    f"未取得实测确认（验证结论：{f.verify_result or '未执行'}），"
                    "按规则最高定中危"
                )
                current = "中危"
            else:
                d.rationale.append(f"未取得实测确认，当前等级 {current} 低于中危，不再下压")

        # --- 步骤 4：降级 / 升级因子 ---
        for name, pred in DOWNGRADE_RULES:
            try:
                if pred(f):
                    d.downgrades.append(name)
            except Exception:  # noqa: BLE001
                continue
        for name, pred in UPGRADE_RULES:
            try:
                if pred(f):
                    d.upgrades.append(name)
            except Exception:  # noqa: BLE001
                continue

        delta = len(d.upgrades) - len(d.downgrades)
        if delta != 0:
            new = _shift(current, delta)
            d.rationale.append(
                f"因子修正：{len(d.upgrades)} 项升级 / {len(d.downgrades)} 项降级，"
                f"净变化 {delta:+d} 级，{current} → {new}"
            )
            current = new
        else:
            d.rationale.append("无降级 / 升级因子命中，等级不变")

        # --- 步骤 5：安全阀 —— 因子修正不得把「仅攻击面暴露」抬成高危 ---
        if hazard in ("missing_headers", "version_disclosure", "component_version_extracted",
                      "port_open", "sri_missing", "debug_flag_enabled",
                      "permissions_policy_missing", "internal_ip_leak"):
            if severity_rank(current) > severity_rank("低危"):
                d.rationale.append(
                    f"安全阀：危害类型「{hazard}」属纯攻击面暴露，不因因子抬升超过低危"
                )
                current = "低危"

        # --- 步骤 6：证据级别 B 的硬上限复核 ---
        if f.evidence_level == "B" and severity_rank(current) > severity_rank("中危"):
            d.rationale.append("复核：证据级别 B 上限中危")
            current = "中危"

        d.final_severity = current
        d.rationale.append(f"最终定级：{current}")
        return d

    # ------------------------------------------------------------------
    def _pick_hazard(self, f: Finding) -> str:
        """推断发现对应的危害类型。"""
        # 1) 显式声明优先
        declared = f.extra.get("hazard_type") if f.extra else None
        if declared and declared in self.baseline:
            return declared

        # 2) 按检查项映射
        if f.item_id in self.item_map:
            mapped = self.item_map[f.item_id]
            # 但同一检查项下轻重差别很大，按标题再细分
            refined = self._refine_by_title(f, mapped)
            return refined

        # 3) 按标题关键词兜底
        return self._refine_by_title(f, "path_reachable_no_auth")

    @staticmethod
    def _refine_by_title(f: Finding, default: str) -> str:
        t = (f.title or "").lower()
        pairs = [
            (["git"], "git_exposed"),
            (["svn"], "svn_exposed"),
            (["env", "环境变量"], "env_exposed"),
            (["备份", "backup"], "backup_download"),
            (["actuator"], "actuator_env"),
            (["日志", "log"], "debug_log"),
            (["source map", "sourcemap", "源码映射"], "sourcemap_exposed"),
            (["目录列表", "dir"], "dir_listing"),
            (["敏感文件", "可公开访问"], "info_disclosure_data"),
            (["安全响应头", "响应头缺失"], "missing_headers"),
            (["版本"], "version_disclosure"),
            (["组件"], "component_version_extracted"),
            (["跨域", "cors"], "cors_credentials" if "凭据" in (f.description or "") else "cors_wildcard"),
            (["越权", "未授权", "缺鉴权", "缺少鉴权"], "unauth_api_data"),
            (["敏感信息"], "hardcoded_cloud_key" if "云" in (f.severity or "") else "internal_ip_leak"),
            (["危险方法"], "http_dangerous_method"),
        ]
        for keys, hazard in pairs:
            if any(k in t for k in keys):
                return hazard
        return default

    # ------------------------------------------------------------------
    def grade_all(self, findings: list[Finding]) -> list[tuple[Finding, GradingDecision]]:
        """批量定级，并把结果写回 Finding。"""
        out = []
        for f in findings:
            d = self.grade(f)
            if d.excluded:
                f.status = "pending"
            else:
                f.severity = d.final_severity
            f.extra = f.extra or {}
            f.extra["grading"] = d.to_dict()
            out.append((f, d))
        return out


if __name__ == "__main__":
    print("定级引擎自测")
    print("=" * 70)

    eng = GradingEngine()

    cases = [
        Finding(
            item_id="WSTG-INPV-05", target="订单系统", title="SQL 注入（订单查询接口）",
            severity="高危", evidence_level="A", verify_result="confirmed",
            description="订单查询接口的 orderId 参数存在注入，实测可拖出 user 表全部记录，无需认证",
            impact="攻击者可读取全量生产数据", grading_basis="实测返回数据库错误回显与表数据",
        ),
        Finding(
            item_id="WSTG-CONF-07", target="门户站点", title="HTTP 安全响应头缺失",
            severity="中危", evidence_level="A", verify_result="confirmed",
            description="缺少 CSP / HSTS 等安全头", impact="非直接数据泄露",
        ),
        Finding(
            item_id="WSTG-ATHZ-02", target="会员中心", title="疑似水平越权：同角色账号返回完全相同的个人数据",
            severity="高危", evidence_level="B", verify_result="inconclusive",
            description="采样推断，需人工确认", impact="若确认则可读取他人数据",
        ),
        Finding(
            item_id="EXT-SC-01", target="门户站点", title="前端组件版本可提取（4 个组件）",
            severity="低危", evidence_level="A", verify_result="confirmed",
            description="版本命中不等于可利用", impact="降低攻击者成本",
            extra={"hazard_type": "component_version_extracted"},
        ),
        Finding(
            item_id="WSTG-CONF-04", target="门户站点", title="疑似存在备份文件",
            severity="高危", evidence_level="C", verify_result="inconclusive",
            description="404 且对照响应一致", impact="未确证",
        ),
    ]

    for f in cases:
        d = eng.grade(f)
        print(f"\n{'─' * 70}")
        print(f"发现：{f.title}")
        print(f"  自报 {f.severity} / 证据 {f.evidence_level} / 验证 {f.verify_result or '未执行'}")
        if d.excluded:
            print(f"  → 排除：{d.exclude_reason}")
        else:
            print(f"  → 最终定级：{d.final_severity}")
            for r in d.rationale:
                print(f"     · {r}")
