# -*- coding: utf-8 -*-
"""
复现模板映射表 ——全量检查项 → 复现模板类型
===============================================

为什么要有这张表
----------------
复现方式由「检查项本身」决定，是确定性事实，不该从发现的自然语言描述里猜。
上一版按关键词推断，结果「前端产物中发现云凭据特征」被匹配成「目录列举」——
因为它的影响描述里写着「列举并下载对象存储文件」，而词表里有「列举」。
一句解释性文字就污染了判断。

所以这里把全量检查项的复现方式显式声明。映射规则：
    content_marker    断言「当时实测到的内容特征」仍存在（含对照实验）
    path_reach        路径可未授权访问 + 语义特征 + 对照 404
    dir_listing       目录索引特征断言
    header_state      响应头仍缺失 / 仍存在
    cors_reflect      带 Origin 请求，断言 ACAO 反射
    param_replay      重放载荷，断言响应特征差异
    anon_access       不带凭据请求，断言仍返回业务数据
    cross_role        带两个身份请求同一地址，断言响应逐字节相同（越权类）
    port_open         TCP 连通 + banner 断言
    method_accept     目标方法未被拒绝（仅声明层）
    tls_state         指定协议版本仍可握手
    component_version 响应中仍暴露该版本标识
    dns_record        查询并断言 DNS 记录状态（SPF/DKIM/DMARC）
    rate_limit        并发探测，断言是否出现限流
    weak_login        重放受控默认口令字典，断言仍能登入（默认凭据类）
    weak_probe        兜底：仅可达性，**报告必须披露为弱复现**

维护约定：新增检查项时必须在此登记；未登记项自动回落 weak_probe 并在报告中标注。
"""

from __future__ import annotations

# ------------------------------------------------------------------------------
# WSTG 标准检查项（117 项）
# ------------------------------------------------------------------------------
WSTG_KINDS: dict[str, str] = {
    # ---- INFO：信息收集，多数是「对外暴露了某内容」→ 内容特征断言 ----
    "WSTG-INFO-01": "path_reach",        # robots.txt / sitemap 泄露路径
    "WSTG-INFO-02": "header_state",      # Server / X-Powered-By 版本泄露
    "WSTG-INFO-03": "path_reach",        # 元文件（favicon/robots/sitemap 等）
    # 该项产出的发现是「这些端口从公网可直接连通」，属于可以用 TCP 三次握手
    # 独立复测的结论 —— 走 weak_probe（HTTP 可达性）等于换了判据，
    # 必然把一个已被证实的端口暴露判成「无法判定」。
    "WSTG-INFO-04": "port_open",
    "WSTG-INFO-05": "content_marker",    # 页面内容泄露（凭据/内部地址/注释）
    "WSTG-INFO-06": "weak_probe",        # 入口点清单，结论需人工核对
    "WSTG-INFO-07": "path_reach",        # 执行路径映射
    "WSTG-INFO-08": "component_version",  # 框架指纹
    "WSTG-INFO-09": "component_version",  # 应用指纹
    "WSTG-INFO-10": "weak_probe",        # 架构 / WAF 映射

    # ---- CONF：配置缺陷 ----
    "WSTG-CONF-01": "weak_probe",        # 网络基础设施（外部无法整体判定）
    "WSTG-CONF-02": "path_reach",        # 平台样例页 / 默认页
    "WSTG-CONF-03": "path_reach",        # 扩展名变体源码泄露
    "WSTG-CONF-04": "path_reach",        # 旧备份与未引用文件
    "WSTG-CONF-05": "path_reach",        # 管理接口 / 接口文档
    "WSTG-CONF-06": "method_accept",     # HTTP 方法
    "WSTG-CONF-07": "header_state",      # HSTS
    "WSTG-CONF-08": "path_reach",        # crossdomain.xml / clientaccesspolicy.xml
    "WSTG-CONF-09": "dir_listing",       # 目录权限 / 目录列举
    "WSTG-CONF-10": "weak_probe",        # 子域接管（需人工确认 CNAME 归属）
    "WSTG-CONF-11": "path_reach",        # 云存储配置
    "WSTG-CONF-12": "header_state",      # CSP
    "WSTG-CONF-13": "method_accept",     # 路径混淆 / 大小写与方法绕过
    "WSTG-CONF-14": "header_state",      # 其他安全头
    "WSTG-CONF-15": "param_replay",      # 功能开关绕过

    # ---- IDNT：身份与账号，全部属账号体系行为，外部无法自证 ----
    "WSTG-IDNT-01": "weak_probe",
    "WSTG-IDNT-02": "weak_probe",
    "WSTG-IDNT-03": "weak_probe",
    "WSTG-IDNT-04": "weak_probe",
    "WSTG-IDNT-05": "weak_probe",

    # ---- ATHN：认证 ----
    "WSTG-ATHN-01": "plain_channel",     # 凭据经明文通道：判据是站点是否提供 http 入口
    "WSTG-ATHN-02": "weak_login",        # 默认凭据（受控提交；复现 = 重放受控字典）
    "WSTG-ATHN-03": "weak_probe",
    "WSTG-ATHN-04": "anon_access",       # 认证绕过
    "WSTG-ATHN-05": "header_state",      # 记住我 Cookie
    "WSTG-ATHN-06": "header_state",      # 缓存头缺失
    "WSTG-ATHN-07": "weak_probe",
    "WSTG-ATHN-08": "weak_probe",
    "WSTG-ATHN-09": "weak_probe",
    "WSTG-ATHN-10": "weak_probe",
    "WSTG-ATHN-11": "weak_probe",

    # ---- ATHZ：授权 ----
    "WSTG-ATHZ-01": "param_replay",      # 目录遍历 / 文件包含
    "WSTG-ATHZ-02": "anon_access",       # 绕过授权
    "WSTG-ATHZ-03": "anon_access",       # 权限提升
    "WSTG-ATHZ-04": "anon_access",       # IDOR
    "WSTG-ATHZ-05": "param_replay",      # OAuth 参数

    # ---- SESS：会话 ----
    "WSTG-SESS-01": "header_state",      # 会话管理方案（凭据下发方式）
    "WSTG-SESS-02": "header_state",      # Cookie 属性
    "WSTG-SESS-03": "weak_probe",        # 会话固定（需登录态）
    "WSTG-SESS-04": "content_marker",    # 会话变量暴露
    "WSTG-SESS-05": "weak_probe",        # CSRF（token 存在性可判，有效性需人工）
    "WSTG-SESS-06": "anon_access",       # 登出后会话仍有效
    "WSTG-SESS-07": "weak_probe",        # 会话超时（需长时间观察）
    "WSTG-SESS-08": "weak_probe",
    "WSTG-SESS-09": "weak_probe",
    "WSTG-SESS-10": "content_marker",    # JWT 声明与算法
    "WSTG-SESS-11": "weak_probe",

    # ---- INPV：注入类，统一走参数重放 ----
    "WSTG-INPV-01": "param_replay",
    "WSTG-INPV-02": "weak_probe",        # 存储型 XSS 需人工触发回显
    "WSTG-INPV-03": "method_accept",
    "WSTG-INPV-04": "param_replay",
    "WSTG-INPV-05": "param_replay",
    "WSTG-INPV-06": "param_replay",
    "WSTG-INPV-07": "param_replay",
    "WSTG-INPV-08": "param_replay",
    "WSTG-INPV-09": "param_replay",
    "WSTG-INPV-10": "param_replay",
    "WSTG-INPV-11": "param_replay",
    "WSTG-INPV-12": "param_replay",
    "WSTG-INPV-13": "param_replay",
    "WSTG-INPV-14": "weak_probe",
    "WSTG-INPV-15": "param_replay",
    "WSTG-INPV-16": "weak_probe",        # 请求走私属时序现象，需专用环境
    "WSTG-INPV-17": "param_replay",
    "WSTG-INPV-18": "param_replay",
    "WSTG-INPV-19": "param_replay",
    "WSTG-INPV-20": "weak_probe",
    "WSTG-INPV-21": "weak_probe",
    "WSTG-INPV-22": "param_replay",
    "WSTG-INPV-23": "weak_probe",

    # ---- ERRH：错误处理 ----
    "WSTG-ERRH-01": "content_marker",
    "WSTG-ERRH-02": "content_marker",

    # ---- CRYP：加密 ----
    "WSTG-CRYP-01": "tls_state",
    "WSTG-CRYP-02": "weak_probe",        # Padding Oracle 需专用判据
    "WSTG-CRYP-03": "content_marker",
    "WSTG-CRYP-04": "content_marker",

    # ---- BUSL：业务逻辑，全部需人工 ----
    "WSTG-BUSL-01": "weak_probe",
    "WSTG-BUSL-02": "weak_probe",
    "WSTG-BUSL-03": "weak_probe",
    "WSTG-BUSL-04": "weak_probe",
    "WSTG-BUSL-05": "weak_probe",
    "WSTG-BUSL-06": "weak_probe",
    "WSTG-BUSL-07": "weak_probe",
    "WSTG-BUSL-08": "weak_probe",
    "WSTG-BUSL-09": "weak_probe",
    "WSTG-BUSL-10": "weak_probe",

    # ---- CLNT：客户端 ----
    "WSTG-CLNT-01": "content_marker",    # DOM XSS 的汇点/源配对
    "WSTG-CLNT-02": "content_marker",    # 动态脚本执行
    "WSTG-CLNT-03": "param_replay",      # HTML 注入
    "WSTG-CLNT-04": "param_replay",      # 客户端重定向
    "WSTG-CLNT-05": "param_replay",      # CSS 注入
    "WSTG-CLNT-06": "content_marker",    # 资源操纵
    "WSTG-CLNT-07": "cors_reflect",
    "WSTG-CLNT-08": "path_reach",        # Flash 跨域策略
    "WSTG-CLNT-09": "header_state",      # 点击劫持（XFO / CSP frame-ancestors）
    "WSTG-CLNT-10": "content_marker",    # WebSocket
    "WSTG-CLNT-11": "content_marker",    # postMessage
    "WSTG-CLNT-12": "content_marker",    # 浏览器存储
    "WSTG-CLNT-13": "content_marker",    # XSSI
    "WSTG-CLNT-14": "content_marker",    # 反向标签劫持
    "WSTG-CLNT-15": "content_marker",    # 客户端模板注入

    # ---- APIT：API ----
    "WSTG-APIT-01": "path_reach",        # API 文档 / 版本暴露
    "WSTG-APIT-02": "anon_access",       # BOLA
    "WSTG-APIT-03": "anon_access",       # 过度数据暴露
    "WSTG-APIT-04": "anon_access",       # BFLA
    "WSTG-APIT-99": "path_reach",        # GraphQL 端点
    "WSTG-WASM-00": "path_reach",        # WASM 产物
}

# ------------------------------------------------------------------------------
# 场景扩展检查项（46 项）
# ------------------------------------------------------------------------------
EXT_KINDS: dict[str, str] = {
    # ---- SC：组件与供应链 ----
    "EXT-SC-01": "component_version",
    "EXT-SC-02": "component_version",
    "EXT-SC-03": "component_version",
    "EXT-SC-04": "content_marker",       # 第三方外链 / 无 SRI
    "EXT-SC-05": "path_reach",           # 依赖清单暴露
    "EXT-SC-06": "path_reach",           # Source Map / 构建产物
    "EXT-SC-07": "content_marker",       # 第三方集成凭据
    "EXT-SC-08": "component_version",    # KEV 优先核对

    # ---- CL：云与容器 ----
    "EXT-CL-01": "anon_access",          # 云元数据服务可达
    "EXT-CL-02": "port_open",
    "EXT-CL-03": "port_open",
    "EXT-CL-04": "anon_access",          # K8s API
    "EXT-CL-05": "weak_probe",           # 云默认域名（需人工确认归属）
    "EXT-CL-06": "content_marker",       # 云凭据泄露
    "EXT-CL-07": "path_reach",           # 镜像仓库
    "EXT-CL-08": "path_reach",           # 对象存储
    "EXT-CL-09": "port_open",            # 主机层 banner

    # ---- CD：CI/CD 与制品 ----
    "EXT-CD-01": "path_reach",
    "EXT-CD-02": "path_reach",
    "EXT-CD-03": "path_reach",
    "EXT-CD-04": "path_reach",
    "EXT-CD-05": "content_marker",

    # ---- AI：AI/LLM 应用 ----
    "EXT-AI-01": "anon_access",
    "EXT-AI-02": "param_replay",
    "EXT-AI-03": "weak_probe",           # 间接注入需投毒 RAG 语料
    "EXT-AI-04": "content_marker",
    "EXT-AI-05": "content_marker",
    "EXT-AI-06": "rate_limit",
    "EXT-AI-07": "weak_probe",
    "EXT-AI-08": "weak_probe",

    # ---- DM：域名与邮件 ----
    "EXT-DM-01": "dns_record",           # SPF（查询名确定：<domain> TXT）
    "EXT-DM-02": "weak_probe",           # DKIM：selector 未知，查不到 ≠ 未配置，不可自动判定
    "EXT-DM-03": "dns_record",           # DMARC（查询名确定：_dmarc.<domain>）
    "EXT-DM-04": "weak_probe",           # 域名劫持 / 仿冒面
    "EXT-DM-05": "port_open",            # 邮件端口暴露
    # 证书透明度子域暴露。证据源就是公开 CT 日志，所以用专用模板重新查
    # 同一个公开源并核对子域清单 —— 走 weak_probe（按 base + path 请求目标）
    # 等于换了判据，永远只能得到「无法判定」。
    "EXT-DM-06": "ct_subdomains",

    # ---- DP：数据与隐私 ----
    "EXT-DP-01": "content_marker",
    "EXT-DP-02": "path_reach",
    "EXT-DP-03": "weak_probe",
    "EXT-DP-04": "header_state",         # 响应被缓存
    "EXT-DP-05": "weak_probe",

    # ---- RB：稳健性与滥用防护 ----
    "EXT-RB-01": "rate_limit",
    "EXT-RB-02": "weak_probe",
    "EXT-RB-03": "weak_probe",
    # 短信/邮件轰炸面是**清单式**发现（「识别到 N 处相关接口」），
    # 不是「实测该接口未限流」。用 rate_limit 去复现等于换了判据，
    # 必然得出错误的否定结论。正确做法是用规则重扫页面与前端产物。
    "EXT-RB-04": "content_marker",
    "EXT-RB-05": "weak_probe",
}

KIND_MAP: dict[str, str] = {**WSTG_KINDS, **EXT_KINDS}


def kind_for(item_id: str) -> str:
    """取某检查项的复现模板类型。未登记项返回空串，由调用方回落并标注。"""
    return KIND_MAP.get(item_id or "", "")


def coverage() -> tuple[list[str], list[str]]:
    """返回 (已登记, 未登记) 的 item_id 列表，供覆盖率校验使用。"""
    try:
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from checklist.loader import load_checklist
        all_ids = [it.id for it in load_checklist()]
    except Exception:  # noqa: BLE001
        return sorted(KIND_MAP), []
    covered = [i for i in all_ids if i in KIND_MAP]
    missing = [i for i in all_ids if i not in KIND_MAP]
    return covered, missing


if __name__ == "__main__":
    cov, miss = coverage()
    print(f"复现模板映射：已登记 {len(cov)}，未登记 {len(miss)}")
    if miss:
        print("未登记项（将回落弱复现并在报告标注）：")
        for m in miss:
            print("   ", m)
    from collections import Counter
    print("\n模板分布：")
    for k, v in Counter(KIND_MAP.values()).most_common():
        print(f"   {k:<20} {v:>3}")
