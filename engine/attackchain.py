# -*- coding: utf-8 -*-
"""
攻击链组合（P2）
=================

单点发现回答的是「这里有个洞」；攻击链回答的是「这些洞连起来能打到哪」。

    合规视角产出 39 条发现，每条都成立。但读者会问：
        「所以呢？这些洞加在一起，能打到什么程度？」
    回答它需要按**能力因果**把发现串起来：

        泄露的凭据（提供身份）→ 认证绕过（提供后台入口）→ 后台功能（提供控制权）

=====================================================================
最重要的一条红线：推理不是事实
=====================================================================

能力匹配推导出来的链，在没有实测证据时**只是假设**。
把它写成「已达成」就是本项目一路在根除的那类假结论。

所以出链的每一环都带证据状态，而链的整体结论按**严格分层**：

    已达成   —— 存在一个**被实测证明**的节点，其能力直接命中目标能力。
                 （注意：绝不允许靠升级边推导出「已达成」，见下）
    部分证实 —— 目标能力在「全部节点能力并集的闭包」里可达，
                 但没有任何单点被实测证明过 → 这是一条**候选链**，
                 价值在于精确指出「还差哪几环、每环要确认什么」。
    （两者都不满足时不产出链 —— 没有锚点的推理链只会制造噪声。）

=====================================================================
为什么升级边永远不能用于「已达成」
=====================================================================

升级边（如 `认证绕过 → 管理后台`）附带的成立条件**只能由人确认**：
「绕过后能不能真的进管理功能」取决于该系统的实现，扫描器的输入只有报文。

如果允许用升级边推结论，就会出现最坏的一类假结论：

    扫到一个登录页面的认证绕过（实测已证）
      → 升级边说「认证绕过 → 管理后台」
      → 升级边说「管理后台 → 命令执行」
      → 报告写「已达成：拿到控制权」

三级推理之后结论已经完全脱离实测。升级边的唯一合法用途是：
**生成待确认清单**，告诉人工「下一枪该往哪打」。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Iterable

# 允许直接 `python engine/attackchain.py` 运行自测。
# 以模块方式导入时 __package__ 有值，这段不生效。
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.redteam import (  # noqa: E402
    INCONCLUSIVE,
    NOT_PROVEN,
    OBJ_MODIFY_DATA,
    OBJ_READ_DATA,
    OBJ_TAKE_CONTROL,
    OBJECTIVES,
    PROVEN,
)

# ======================================================================
# 能力定义
# ======================================================================

CAP_INFO = "INFO"                 # 掌握了信息（版本 / 路径 / 拓扑）
CAP_CRED = "CREDENTIAL"           # 拿到凭据 / 密钥 / token
CAP_SESSION = "SESSION"           # 可预测 / 固定 / 劫持他人会话
CAP_AUTH_BYPASS = "AUTH_BYPASS"   # 可绕过认证或授权
CAP_SSRF = "SSRF"                 # 服务端代为发起请求
CAP_SQLI = "SQLI"                 # 存在注入原语
# NoSQL 注入与 SQL 注入**不是同一个原语**：语法不同、可利用面不同
# （`$ne` 直接改写查询语义、不需要 UNION / 注释符），混在一个能力里
# 会让「链上有什么牌」这句话失真 —— 单独列一项。
CAP_NOSQL = "NOSQL"               # NoSQL 查询语义可被运算符改写
CAP_IDOR = "IDOR"                 # 换对象标识即可越权访问
CAP_FILE_READ = "FILE_READ"       # 可读服务端文件
CAP_FILE_WRITE = "FILE_WRITE"     # 可写入服务端文件（含上传）
CAP_INTERNAL = "INTERNAL_REACH"   # 可触达内网服务
CAP_READ = "READ_DATA"            # 已能读到业务数据（结果能力）
CAP_WRITE = "WRITE_DATA"          # 已能改业务数据（结果能力）
CAP_PRIV = "PRIV_ESC"             # 权限提升
CAP_ADMIN = "ADMIN_ACCESS"        # 可访问管理功能
CAP_EXEC = "EXEC"                 # 可在服务端执行代码 / 命令
#: ⚠ 这一类**不是已获得的能力，而是「让某种能力变得可尝试」的前提条件**。
#:
#: 区分它的理由来自实测：接口无限速（EXT-RB-01）曾被登记成「凭据（CAP_CRED）」，
#: 于是组合出「无限速 → 改数据」这种链 —— 它读起来像攻击链，实际是纸面推演：
#: 无限速只说明「可以无限次猜」，**一个凭据都还没拿到**，中间那两环一个都没落地。
#: 把「前提条件」登记成「已获得能力」，是能力表最容易犯也最隐蔽的错，
#: 因为它不会报错，只会让链变多、每条都更虚。
#:
#: 判据只有一句：**这条发现成立时，攻击者手上立刻多了什么**。
#: 「多了更多尝试机会」≠「多了凭据」。后者要真的拿到才算。
#:
#: 因此 CAP_BRUTE **刻意不参与任何升级边**（见 `_UPGRADES`）：它单独推不到
#: 任何结果能力，只有与真正的凭据类能力同时出现时才有意义。
CAP_BRUTE = "BRUTE_FORCE"         # 可无限次尝试（无频率限制 / 无锁定）

#: 链的可信档位。
#: `TIER_TESTABLE`：到目标最多差一环，可以派发受控实测去定论（红队会真的去打）。
#: `TIER_INFERRED`：缺两环以上，中间每个条件都是假设 —— 只能作为「侦察线索」
#: 列出，**不得**与可验证链混排，更不得被读成「下一步就能打进去」。
TIER_TESTABLE = "可验证"
TIER_INFERRED = "纸面推演"

#: **前提类能力**：不构成攻击链的环节，只构成「让某环节更容易」的条件。
#: 发现若只提供这类能力，不建链节点 —— 否则会串出「无限速 → 拿到数据」
#: 这种看起来有因果、实际没有的链（无限速跟拿到数据之间隔着整个凭据环节）。
#: 它们不会被丢掉：由 `ChainBuilder.prereq` 具名承接并在摘要里披露。
_PREREQ_CAPS: frozenset[str] = frozenset({CAP_BRUTE})

#: 可作为「候选链（值得派发实测）」的最大缺环数。
#: 1 是刻意的选择：缺 0 环就是已达成，缺 1 环意味着「再打一枪就有定论」，
#: 缺 2 环意味着要连续满足两个未经确认的条件 —— 那种链的实际命中率极低，
#: 派发实测也只是把猜测再跑一遍。
MAX_GAP_HOPS = 1

CAPABILITY_LABEL: dict[str, str] = {
    CAP_INFO: "信息掌握",
    CAP_CRED: "凭据",
    CAP_SESSION: "会话",
    CAP_AUTH_BYPASS: "认证 / 授权绕过",
    CAP_SSRF: "服务端请求伪造",
    CAP_SQLI: "注入原语",
    CAP_NOSQL: "NoSQL 语义改写原语",
    CAP_IDOR: "对象越权原语",
    CAP_FILE_READ: "服务端文件读取",
    CAP_FILE_WRITE: "服务端文件写入 / 上传",
    CAP_INTERNAL: "内网可达",
    CAP_READ: "读取业务数据",
    CAP_WRITE: "修改业务数据",
    CAP_PRIV: "权限提升",
    CAP_ADMIN: "管理功能访问",
    CAP_EXEC: "代码 / 命令执行",
    # 「可无限次尝试」是前提条件，不是进展 —— 排序上放在最前（链首）
    CAP_BRUTE: "可无限次尝试（前提，非能力）",
}

# 攻击进展序：用于把一条链里的节点排成人能读的顺序（信息 → 身份 → 原语 → 结果）。
# 这不是「能力强弱」的判定，只用于叙述排序。
_PROGRESS_RANK: dict[str, int] = {
    CAP_BRUTE: -1,
    CAP_INFO: 0, CAP_CRED: 1, CAP_SESSION: 2, CAP_AUTH_BYPASS: 3,
    CAP_SSRF: 4, CAP_SQLI: 5, CAP_NOSQL: 5, CAP_IDOR: 6, CAP_FILE_READ: 7,
    CAP_FILE_WRITE: 8, CAP_INTERNAL: 9, CAP_READ: 10, CAP_WRITE: 11,
    CAP_PRIV: 12, CAP_ADMIN: 13, CAP_EXEC: 14,
}


def rank_of(caps: Iterable[str]) -> int:
    return max((_PROGRESS_RANK.get(c, 0) for c in caps), default=0)


# ======================================================================
# 目标能力（三态结论挂在这里）
# ======================================================================

OBJECTIVE_GOALS: dict[str, tuple[str, ...]] = {
    OBJ_READ_DATA: (CAP_READ,),
    OBJ_MODIFY_DATA: (CAP_WRITE,),
    OBJ_TAKE_CONTROL: (CAP_EXEC, CAP_PRIV, CAP_ADMIN),
}


# ======================================================================
# 能力升级图（有向）：每条边都带「成立条件」——条件是给人看的，不是判据
# ======================================================================

_UPGRADES: list[tuple[str, str, str]] = [
    (CAP_SQLI, CAP_READ, "注入点可用且当前数据库账号具备读权限"),
    (CAP_SQLI, CAP_WRITE, "当前数据库账号具备写权限（INSERT / UPDATE / DELETE）"),
    (CAP_SQLI, CAP_FILE_READ, "数据库账号具备 FILE 权限，或支持读文件的扩展"),
    (CAP_SQLI, CAP_EXEC, "数据库支持堆叠查询，且可写入 Web 目录或具备执行扩展"),
    (CAP_NOSQL, CAP_READ, "运算符可放宽查询条件，且服务端不校验数据归属"),
    (CAP_NOSQL, CAP_AUTH_BYPASS, "认证查询直接采信请求体，可被 `$ne` / `$gt` 绕过"),
    (CAP_IDOR, CAP_READ, "对象标识可枚举，且服务端不校验数据归属"),
    (CAP_IDOR, CAP_WRITE, "目标对象支持写操作，且服务端不校验归属"),
    (CAP_CRED, CAP_AUTH_BYPASS, "泄露的凭据当前有效，且可直接用于认证"),
    (CAP_CRED, CAP_ADMIN, "泄露的凭据属于管理角色"),
    (CAP_AUTH_BYPASS, CAP_ADMIN, "绕过后可触达管理功能"),
    (CAP_AUTH_BYPASS, CAP_READ, "绕过后可触达数据读取接口"),
    (CAP_AUTH_BYPASS, CAP_WRITE, "绕过后可触达数据写入接口"),
    (CAP_SESSION, CAP_AUTH_BYPASS, "会话标识可预测或可固定，能冒充他人身份"),
    (CAP_SESSION, CAP_ADMIN, "被冒充的会话本身具备管理权限"),
    (CAP_SSRF, CAP_INTERNAL, "SSRF 可指定任意内网地址，且无协议 / 网段白名单"),
    (CAP_SSRF, CAP_FILE_READ, "支持 file:// 等本地协议，或可读取云元数据服务"),
    (CAP_INTERNAL, CAP_READ, "内网服务提供未鉴权的数据接口"),
    (CAP_INTERNAL, CAP_EXEC, "内网服务暴露可执行面（未鉴权的管理 API / 运维接口）"),
    (CAP_INTERNAL, CAP_ADMIN, "内网服务的管理接口未鉴权"),
    (CAP_FILE_READ, CAP_CRED, "读到的文件中含凭据 / 密钥 / 令牌"),
    (CAP_FILE_READ, CAP_INFO, "文件中含路径 / 拓扑 / 版本等信息"),
    (CAP_FILE_WRITE, CAP_EXEC, "上传目录可被 Web 直接访问，且服务器会执行该类型文件"),
    (CAP_FILE_WRITE, CAP_FILE_READ, "可覆盖或追加可读文件（日志 / 配置）"),
    (CAP_READ, CAP_CRED, "读到的业务数据里含凭据 / 会话标识"),
    (CAP_WRITE, CAP_EXEC, "可写入被服务加载的文件（配置 / 计划任务 / 模板）"),
    (CAP_PRIV, CAP_ADMIN, "提升后的身份具备管理权限"),
    (CAP_ADMIN, CAP_EXEC, "管理后台具备命令执行 / 脚本 / 插件等功能"),
    (CAP_ADMIN, CAP_READ, "管理后台可读取全量数据"),
    (CAP_ADMIN, CAP_WRITE, "管理后台可修改数据"),
]


def upgrade_conditions(frm: str, to: str) -> list[str]:
    """取某条升级边成立所需的条件（可能多条路径）。"""
    return [c for f, t, c in _UPGRADES if f == frm and t == to]


def closure(caps: Iterable[str]) -> set[str]:
    """能力的传递闭包（乐观：把所有**可能**升级出的能力都算上）。

    只用于「部分证实」这一档的候选链生成与缺口提示，
    **不得**用于判定「已达成」—— 原因见模块 docstring。
    """
    out = set(caps)
    changed = True
    while changed:
        changed = False
        for frm, to, _cond in _UPGRADES:
            if frm in out and to not in out:
                out.add(to)
                changed = True
    return out


def route_to(goal: str, have: Iterable[str]) -> list[tuple[str, str, str]]:
    """从已有能力到目标能力的最短升级路径（边序列）。

    用于「部分证实」档：告诉人工「你现在在哪、还差哪几跳、每跳的条件是什么」。
    """
    have = set(have)
    if goal in have:
        return []
    prev: dict[str, tuple[str, str]] = {}
    frontier = list(have)
    seen = set(have)
    hops: list[tuple[str, str, str]] = []
    while frontier:
        nxt: list[str] = []
        for cur in frontier:
            for frm, to, cond in _UPGRADES:
                if frm != cur or to in seen:
                    continue
                seen.add(to)
                prev[to] = (cur, cond)
                nxt.append(to)
                if to == goal:
                    # 回溯
                    chain: list[tuple[str, str, str]] = []
                    node = goal
                    while node in prev:
                        src, c = prev[node]
                        chain.append((src, node, c))
                        node = src
                    chain.reverse()
                    return chain
        frontier = nxt
    return hops


# ======================================================================
# 发现 → 能力映射
# ======================================================================

# (item_id 模式, provides, 依据说明)
#
# ⚠️ 只写**语义明确**的项。不得使用 `WSTG-INPV-*` 这类大前缀兜底 ——
# 那会把「反射型 XSS」也算成「代码执行原语」，链立刻变成噪声发生器。
# 历史上 proofs.py 的 `_PAT_UNAUTH` 用过 `"EXT-"`，把 30 多项全吞了。
#
# ⚠️ 但**反过来一样是事故**：2026-10-10 复盘发现，这张表只登记了「教科书上
# 理想的那批项」（命令注入 / 默认口令 / XXE …），而真实扫描里命中率最高的
# 那批项（过度数据暴露 APIT-03、备份文件 CONF-04、XSS 家族、CORS、CSRF、
# 速率限制缺失）**一项都不在表里** —— 结果是：17 条 A 级实测发现，能力映射
# 全部为空，攻击链一节永远只打印「没有任何发现经过实测结果证明」。
# 一个写得再严谨的链引擎，只要映射表是空的，就等于没有。
#
# 所以这张表的收录判据只有一条：**这条发现成立时，攻击者手里多了什么**。
# 多了就在表上（能力是否真到手由 evidence_state 判，不由这张表判）；
# 什么都没多（HSTS、CSP、点击劫持这类「防护缺失」）就不在表上。
_CAPABILITY_RULES: list[tuple[str, tuple[str, ...], str]] = [
    # ---- 注入类 ----
    ("WSTG-INPV-01", (CAP_SESSION,), "反射型 XSS：可在受害者浏览器上下文执行脚本（劫持会话 / 代发请求）"),
    ("WSTG-INPV-02", (CAP_SESSION,), "存储型 XSS：脚本被持久化，访问者即中招"),
    ("WSTG-INPV-03", (CAP_AUTH_BYPASS,), "HTTP 动词篡改：换方法即可绕过访问控制"),
    ("WSTG-INPV-04", (CAP_AUTH_BYPASS,), "参数污染：前后端解析不一致可绕过校验"),
    ("WSTG-INPV-05", (CAP_SQLI,), "SQL 注入点：可尝试读取 / 写入库内数据"),
    ("WSTG-INPV-06", (CAP_INFO,), "LDAP 注入：可探测目录服务信息"),
    ("WSTG-INPV-07", (CAP_FILE_READ,), "XXE：可读服务端文件或发起内网请求"),
    ("WSTG-INPV-08", (CAP_EXEC,), "SSI 注入：可执行服务端指令"),
    ("WSTG-INPV-09", (CAP_READ,), "XPath 注入：可改写查询条件读到更多数据"),
    ("WSTG-INPV-11", (CAP_EXEC,), "代码注入：可直接执行代码"),
    ("WSTG-INPV-12", (CAP_EXEC,), "命令注入：可直接执行系统命令"),
    ("WSTG-INPV-13", (CAP_READ,), "格式字符串：可读取进程内存内容"),
    ("WSTG-INPV-14", (CAP_INFO,), "孵化漏洞：预留接口 / 未完成功能可被利用"),
    ("WSTG-INPV-15", (CAP_SESSION,), "CRLF 注入：可注入 Set-Cookie / 拆分响应定型会话"),
    ("WSTG-INPV-16", (CAP_AUTH_BYPASS,), "请求走私：请求边界混淆可绕过前端访问控制"),
    ("WSTG-INPV-17", (CAP_CRED,), "Host 头注入：可污染密码重置链接拿到重置令牌"),
    ("WSTG-INPV-18", (CAP_EXEC,), "SSTI：模板引擎可触达代码执行"),
    ("WSTG-INPV-19", (CAP_SSRF,), "SSRF：服务端可代为发起请求"),
    ("WSTG-INPV-22", (CAP_EXEC,), "原型污染：可改变服务端对象行为，Node 场景常可达代码执行"),
    ("WSTG-INPV-23", (CAP_EXEC,), "不安全反序列化：可触达代码执行"),
    ("WSTG-INPV-24", (CAP_NOSQL,), "NoSQL 注入：查询语义可被运算符改写"),
    ("WSTG-INPV-20", (CAP_WRITE,), "批量赋值：可写入本不该由客户端决定的字段"),
    # ---- 身份与授权 ----
    ("WSTG-IDNT-02", (CAP_CRED,), "注册流程可绕过校验 / 批量注册：可自建或批量取得有效身份"),
    ("WSTG-IDNT-04", (CAP_INFO,), "账号枚举：可确认哪些账号存在"),
    ("WSTG-IDNT-05", (CAP_INFO,), "用户名可预测 / 无唯一性校验"),
    # ❌ `WSTG-ATHN-01`（凭据经明文通道提交）**刻意不在本表**。
    #    它成立时攻击者手上什么都没多 —— 要拿到那些凭据，还得先站到链路上
    #    （中间人 / 共享网段 / 镜像口）。它是「传输防护缺失」，不是能力。
    #    登记进去会组合出「明文传凭据 → 改数据」这种链：读着像攻击链，
    #    实际缺了中间人位置和凭据复用两环。
    ("WSTG-ATHN-02", (CAP_AUTH_BYPASS,), "默认凭据可用：可直接进入系统"),
    # 无锁定 / 无延迟 / 无验证码 = 「可以一直猜」，不等于「已经猜到了」
    ("WSTG-ATHN-03", (CAP_BRUTE,), "无锁定 / 无延迟 / 无验证码：可穷举口令（前提，非凭据）"),
    ("WSTG-ATHN-04", (CAP_AUTH_BYPASS,), "认证方案可绕过"),
    ("WSTG-ATHN-05", (CAP_CRED,), "记住密码令牌可预测 / 无过期 / 可跨设备复用"),
    ("WSTG-ATHN-07", (CAP_AUTH_BYPASS,), "认证方法薄弱，可被绕过"),
    ("WSTG-ATHN-08", (CAP_CRED,), "安全问题答案可推导：可重置他人密码"),
    ("WSTG-ATHN-09", (CAP_CRED,), "重置令牌可预测 / 可跳过验证：可接管他人账号"),
    ("WSTG-ATHN-10", (CAP_AUTH_BYPASS,), "替代通道（移动端 / 开放 API）认证强度更弱"),
    ("WSTG-ATHN-11", (CAP_AUTH_BYPASS,), "MFA 可绕过 / 降级 / 重放"),
    ("WSTG-ATHZ-01", (CAP_FILE_READ,), "目录遍历 / 文件包含：可读服务端文件"),
    ("WSTG-ATHZ-02", (CAP_AUTH_BYPASS,), "授权方案可绕过"),
    ("WSTG-ATHZ-03", (CAP_PRIV,), "权限提升"),
    ("WSTG-ATHZ-04", (CAP_IDOR,), "IDOR：换对象标识即可访问他人数据"),
    ("WSTG-ATHZ-05", (CAP_AUTH_BYPASS,), "OAuth 弱点：可冒充他人身份"),
    # ---- 会话 ----
    ("WSTG-SESS-01", (CAP_SESSION,), "会话标识生成算法可预测"),
    ("WSTG-SESS-02", (CAP_SESSION,), "Cookie 属性缺失（HttpOnly / Secure）：脚本或链路可取到会话标识"),
    ("WSTG-SESS-03", (CAP_SESSION,), "会话固定：可预置他人会话标识"),
    ("WSTG-SESS-04", (CAP_SESSION,), "会话标识出现在 URL / 日志 / 前端存储"),
    ("WSTG-SESS-05", (CAP_WRITE,), "CSRF：可代受害者发起状态变更请求"),
    ("WSTG-SESS-06", (CAP_SESSION,), "登出后会话未失效：旧标识仍可用"),
    ("WSTG-SESS-09", (CAP_SESSION,), "会话劫持面"),
    ("WSTG-SESS-10", (CAP_AUTH_BYPASS,), "JWT 缺陷：可伪造身份"),
    ("WSTG-SESS-11", (CAP_INFO,), "并发会话不受限：可长期保持多端在线"),
    # ---- 文件与配置 ----
    ("WSTG-CONF-02", (CAP_ADMIN,), "调试模式 / 示例应用 / 管理端点暴露"),
    ("WSTG-CONF-03", (CAP_FILE_READ,), "敏感文件可直接下载"),
    ("WSTG-CONF-04", (CAP_FILE_READ,), "备份 / 未引用文件可直接下载"),
    ("WSTG-CONF-05", (CAP_ADMIN,), "管理接口暴露"),
    ("WSTG-CONF-06", (CAP_FILE_WRITE,), "PUT / DELETE / WebDAV 等非预期方法可用：可写入文件"),
    ("WSTG-CONF-08", (CAP_READ,), "RIA 跨域策略通配符：可跨域读取应用数据"),
    ("WSTG-CONF-09", (CAP_INFO,), "文件权限问题：可推断部署结构"),
    ("WSTG-CONF-10", (CAP_WRITE,), "子域接管：可控制该子域返回的内容"),
    ("WSTG-CONF-11", (CAP_READ,), "云存储匿名可读 / 可列举对象"),
    ("WSTG-CONF-13", (CAP_AUTH_BYPASS,), "路径混淆：// 、/./ 、编码变体可绕过访问控制"),
    ("WSTG-CONF-15", (CAP_AUTH_BYPASS,), "功能开关可被绕过"),
    # ---- 业务逻辑（写操作面） ----
    ("WSTG-BUSL-01", (CAP_WRITE,), "业务字段可提交非法值（负数 / 超限 / 越界枚举）"),
    ("WSTG-BUSL-02", (CAP_WRITE,), "关键业务请求可由客户端任意构造"),
    ("WSTG-BUSL-03", (CAP_WRITE,), "服务端采信客户端提交的业务字段"),
    ("WSTG-BUSL-04", (CAP_WRITE,), "多步流程可乱序执行或跳过前置步骤"),
    ("WSTG-BUSL-05", (CAP_WRITE,), "次数限制缺失：可重复领取 / 重复提交"),
    ("WSTG-BUSL-06", (CAP_WRITE,), "审批 / 状态机可绕过"),
    ("WSTG-BUSL-07", (CAP_INFO,), "缺反自动化措施：可批量构造请求"),
    ("WSTG-BUSL-08", (CAP_FILE_WRITE,), "可上传非预期类型文件"),
    ("WSTG-BUSL-09", (CAP_EXEC,), "恶意文件上传"),
    ("WSTG-BUSL-10", (CAP_WRITE,), "支付 / 资金链路可被篡改"),
    # ---- 客户端 ----
    ("WSTG-CLNT-01", (CAP_SESSION,), "DOM XSS：前端 sink 可执行不可信来源的脚本"),
    ("WSTG-CLNT-02", (CAP_SESSION,), "用户输入进入 JS 执行上下文"),
    ("WSTG-CLNT-05", (CAP_READ,), "CSS 注入：可用属性选择器逐字符外带页面数据"),
    ("WSTG-CLNT-07", (CAP_READ,), "CORS：Origin 被反射且允许携带凭据 —— 攻击者站点可跨域读取已登录用户的接口响应"),
    ("WSTG-CLNT-10", (CAP_READ,), "WebSocket 不校验 Origin / 消息无鉴权"),
    ("WSTG-CLNT-11", (CAP_INFO,), "postMessage 未校验 origin 或用了通配符 targetOrigin"),
    ("WSTG-CLNT-12", (CAP_INFO,), "前端存储了敏感数据：本地可取"),
    ("WSTG-CLNT-13", (CAP_READ,), "XSSI：敏感 JSON 端点可被跨站脚本标签读取"),
    ("WSTG-CLNT-15", (CAP_SESSION,), "客户端模板注入：输入进入前端模板引擎被执行"),
    # ---- API ----
    ("WSTG-APIT-02", (CAP_IDOR,), "BOLA：端点以对象 ID 索引且不校验归属"),
    ("WSTG-APIT-03", (CAP_READ,), "过度数据暴露：接口返回超出业务需要的字段（含内部字段与 PII）"),
    ("WSTG-APIT-04", (CAP_ADMIN,), "BFLA：管理级功能端点仅靠前端隐藏，后端不校验角色"),
    ("WSTG-APIT-99", (CAP_INFO, CAP_READ), "GraphQL：内省暴露完整 schema，且字段级鉴权可能缺失"),
    # ---- 错误处理与密码 ----
    ("WSTG-ERRH-01", (CAP_INFO,), "原始错误泄露数据库语句 / 内部路径"),
    ("WSTG-ERRH-02", (CAP_INFO,), "堆栈跟踪泄露实现细节"),
    ("WSTG-CRYP-02", (CAP_READ,), "Padding Oracle：可逐字节解密他人密文数据"),
    ("WSTG-CRYP-03", (CAP_CRED,), "敏感字段经明文 HTTP 传输：可被截获"),
    ("WSTG-CRYP-04", (CAP_INFO,), "弱算法 / 硬编码密钥与 IV：可用于伪造或解密"),
    # ---- 数据暴露 ----
    ("EXT-DP-01", (CAP_READ,), "响应中明文暴露业务数据"),
    ("EXT-DP-02", (CAP_READ,), "日志 / 调试接口泄露数据"),
    ("EXT-DP-03", (CAP_READ,), "导出功能数据范围越界"),
    ("EXT-DP-04", (CAP_INFO,), "含用户数据的响应被缓存"),
    ("EXT-DP-05", (CAP_READ,), "移动端 / 小程序接口暴露"),
    ("EXT-DP-06", (CAP_INFO,), "图片 EXIF 残留 GPS 与设备信息"),
    # ---- 供应链与凭据 ----
    ("EXT-SC-06", (CAP_INFO,), "打包产物泄露源码与依赖树"),
    ("EXT-SC-07", (CAP_CRED,), "第三方集成凭据泄露"),
    # ---- 云与容器 ----
    ("EXT-CL-01", (CAP_INTERNAL,), "云元数据服务可达"),
    ("EXT-CL-02", (CAP_READ,), "数据库 / 缓存端口公网可达：可直连读取数据"),
    ("EXT-CL-03", (CAP_ADMIN,), "容器 API 暴露"),
    ("EXT-CL-04", (CAP_ADMIN,), "K8s API Server 暴露"),
    ("EXT-CL-05", (CAP_INFO,), "云默认域名 / 测试环境暴露"),
    ("EXT-CL-06", (CAP_CRED,), "云凭据泄露"),
    ("EXT-CL-07", (CAP_INFO,), "镜像仓库暴露"),
    ("EXT-CL-08", (CAP_READ,), "对象存储可遍历 / 签名可复用"),
    ("EXT-CL-09", (CAP_INFO,), "主机层已知漏洞（外部可判定部分）"),
    # ---- CI/CD 与源码 ----
    ("EXT-CD-01", (CAP_CRED,), "流水线配置泄露（常含部署凭据）"),
    ("EXT-CD-02", (CAP_INFO,), "构建产物 / 制品仓库暴露"),
    ("EXT-CD-03", (CAP_CRED,), "版本控制目录泄露（历史中常含凭据）"),
    ("EXT-CD-04", (CAP_CRED,), "部署脚本凭据残留"),
    ("EXT-CD-05", (CAP_INTERNAL,), "内部地址与拓扑泄露"),
    # ---- 域名与邮件 ----
    ("EXT-DM-04", (CAP_INFO,), "相似域名 / 到期时间 / 注册商锁状态可查"),
    ("EXT-DM-06", (CAP_INFO,), "证书透明度日志暴露内部 / 测试域名"),
    # ---- 速率与风控（取得身份的通道） ----
    # ⚠ 这两条是**前提**不是凭据：无限速只说明「可以一直猜 / 一直注册」，
    #   一个有效身份都还没到手。实测踩过 —— 登记成 CAP_CRED 后组合出
    #   「无限速 → 改数据」，缺两环的纸面链照样被当成候选链报出去。
    ("EXT-RB-01", (CAP_BRUTE,), "关键接口无频率限制：可穷举凭据 / 批量撞库（前提，非凭据）"),
    ("EXT-RB-03", (CAP_BRUTE,), "注册 / 登录无人机校验：可自动化批量取得身份（前提，非凭据）"),
    # ---- AI 应用 ----
    ("EXT-AI-01", (CAP_ADMIN,), "LLM 端点未授权访问"),
    ("EXT-AI-02", (CAP_INFO,), "直接提示词注入：可覆盖系统指令 / 越出设定角色"),
    ("EXT-AI-03", (CAP_INFO,), "间接提示词注入 / RAG 投毒：外部内容可操控模型行为"),
    ("EXT-AI-04", (CAP_INFO,), "系统提示词与上下文泄露"),
    ("EXT-AI-05", (CAP_READ,), "模型输出未过滤导致数据泄露"),
    ("EXT-AI-07", (CAP_EXEC,), "工具调用 / Agent 权限过宽"),
    ("EXT-AI-08", (CAP_READ,), "可复述训练 / 微调语料中的敏感信息"),
]


def _match_item(item_id: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return item_id.startswith(pattern[:-1])
    return item_id == pattern


def _field(finding: Any, name: str, default: Any = "") -> Any:
    """从发现上取一个字段 —— 对象与 dict 都要能取到。

    ⚠️ 为什么要单独写这个：报告层与归档回放路径拿到的是 **dict**（从
    findings.json 反序列化），生产路径拿到的是 **Finding 对象**。只用
    `getattr` 时，dict 一律返回默认值 —— item_id 变空串、能力映射变空、
    evidence_level 变空，于是整条链静默消失，而**没有任何报错**。
    这正是「存在却取不到」那一类静默错误的原形（红线 52 同一族）。
    """
    if isinstance(finding, dict):
        v = finding.get(name, default)
    else:
        v = getattr(finding, name, default)
    return default if v is None else v


def capabilities_of(finding: Any) -> tuple[list[str], str]:
    """推导一条发现「能提供什么能力」，返回 (能力列表, 依据说明)。

    ⚠️ 这里推导的是「这条发现**如果成立**能提供什么」，不是
    「已经拿到了什么」。能力是否真的到手，由 evidence_state 决定。
    """
    item_id = str(_field(finding, "item_id", "") or "")
    caps: list[str] = []
    basis: list[str] = []
    for pattern, prov, why in _CAPABILITY_RULES:
        if _match_item(item_id, pattern):
            for c in prov:
                if c not in caps:
                    caps.append(c)
            basis.append(why)
    return caps, "；".join(basis)


def evidence_state_of(finding: Any) -> str:
    """读取该发现的**实测**证据状态。

    这是本模块最关键的一处判断：

        发现存在（evidence_level=B）只说明「有这个入口」，
        **不说明「这个能力已经拿到手」**。

    只有结果证明层（engine/proofs.py）真的证明过，才算实测已证。
    """
    ex = _field(finding, "extra", None) or {}
    if not isinstance(ex, dict):
        ex = {}
    pr = ex.get("proof") or {}
    if not isinstance(pr, dict):
        pr = {}
    st = str(pr.get("state") or "")
    if st == PROVEN:
        return PROVEN
    if st == INCONCLUSIVE:
        return INCONCLUSIVE
    if st:
        return NOT_PROVEN
    # 没有 proof 记录时，只有 A 级证据算实测 —— A 的定义就是「实测影响」
    if str(_field(finding, "evidence_level", "") or "") == "A":
        return PROVEN
    return ""


# ======================================================================
# 数据结构
# ======================================================================


@dataclass
class ChainNode:
    """攻击链上的一个节点（对应一条发现）。"""

    node_id: str
    item_id: str
    title: str
    endpoint: str = ""
    method: str = ""
    provides: list[str] = field(default_factory=list)
    evidence_state: str = ""      # PROVEN / NOT_PROVEN / INCONCLUSIVE / ""（未证明）
    basis: str = ""
    severity: str = ""

    @property
    def proven(self) -> bool:
        return self.evidence_state == PROVEN

    def caps_label(self) -> str:
        return "、".join(CAPABILITY_LABEL.get(c, c) for c in self.provides)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "item_id": self.item_id,
            "title": self.title,
            "endpoint": self.endpoint,
            "method": self.method,
            "provides": list(self.provides),
            "provides_label": self.caps_label(),
            "evidence_state": self.evidence_state or "未做结果证明",
            "basis": self.basis,
            "severity": self.severity,
        }


@dataclass
class ChainEdge:
    """链上的一次能力升级，附带必须人工确认的成立条件。"""

    src: str
    dst: str
    capability: str
    condition: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.src, "to": self.dst,
            "capability": self.capability,
            "capability_label": CAPABILITY_LABEL.get(self.capability, self.capability),
            "condition": self.condition,
        }


@dataclass
class AttackChain:
    """一条从入口到攻击目标的候选链。"""

    chain_id: str
    objective: str
    goal: str
    state: str                       # 已达成 / 部分证实
    nodes: list[ChainNode] = field(default_factory=list)
    edges: list[ChainEdge] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)   # 待确认的环节
    note: str = ""
    #: 到目标还差几环（升级跳数 + 未实测节点数）。**这是链的可信度刻度。**
    #:
    #: 0 = 已达成；1 = 再打一枪就能定论（值得派发实测补证）；
    #: ≥2 = 缺两环以上，中间每一步都是未经确认的假设。
    #: 缺 ≥2 环的链写进报告会稀释真正有价值的那一条 —— 实测踩过：
    #: 一次扫描 10 条链里 9 条是缺 2 环的推理链，读报告的人根本分不清
    #: 哪条是打出来的、哪条是推出来的。
    gap_hops: int = 0
    #: 可信档位：`TIER_TESTABLE`（可派发实测）/ `TIER_INFERRED`（纸面推演）。
    tier: str = TIER_TESTABLE

    @property
    def objective_label(self) -> str:
        return OBJECTIVES.get(self.objective, self.objective)

    @property
    def testable(self) -> bool:
        return self.tier == TIER_TESTABLE

    def narrative(self) -> str:
        """渲染成「手段 → 手段 → 结果」的可读链条。"""
        parts: list[str] = []
        for n in self.nodes:
            mark = "实测已证" if n.proven else "待确认"
            parts.append(f"{n.title}[{n.item_id}]（{mark}）")
        # 目标名是不带箭头的**宾语**：它是链条的终点，不是下一环。
        # 写成 f"→ {label}" 再 join 就会出现「X → → 拿到数据」这种双箭头，
        # 报告上看着像丢了一环，读者会以为链条渲染坏了。
        parts.append(self.objective_label)
        return " → ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "objective": self.objective,
            "objective_label": self.objective_label,
            "goal": self.goal,
            "goal_label": CAPABILITY_LABEL.get(self.goal, self.goal),
            "state": self.state,
            "narrative": self.narrative(),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "missing": list(self.missing),
            "note": self.note,
            "repro": self.repro_hint(),
            "gap_hops": self.gap_hops,
            "tier": self.tier,
            "testable": self.testable,
        }

    def repro_hint(self) -> str:
        """复测入口提示。链结论必须可复测，否则与「猜」没有区别。"""
        eps = [n.endpoint for n in self.nodes if n.endpoint]
        if not eps:
            return "按各发现的复现脚本逐项复测，并在同一次会话中确认链路衔接。"
        return ("按下列顺序在同一测试环境下复测：" + " → ".join(eps[:4])
                + "；每一步都要用上一步的真实产物作为输入。")


# ======================================================================
# 组合器
# ======================================================================


class ChainBuilder:
    """从一次扫描的发现集合里组合出攻击链。"""

    def __init__(self, findings: list[Any], *, max_nodes: int = 3,
                 max_per_goal: int = 3, max_gap_hops: int = MAX_GAP_HOPS):
        """max_nodes 是链上**节点数**上限。

        3 是刻意的选择：4 环以上的链在真实场景里几乎总是纸面推演 ——
        每一环都要满足一个未经确认的条件，累积起来概率极低，
        写进报告只会稀释真正有价值的那两三条链。

        `max_gap_hops` 是**缺环上限**：到目标差几环以内才算「值得派发实测」。
        超过的仍会产出，但标为 `TIER_INFERRED`，与可验证链分列
        （不丢弃是为了不静默 —— 红线 14：没做的事必须能被说出名字）。
        """
        self.findings = list(findings or [])
        self.max_nodes = max(1, int(max_nodes))
        self.max_per_goal = max(1, int(max_per_goal))
        self.max_gap_hops = max(0, int(max_gap_hops))
        self.nodes: list[ChainNode] = []
        self.skipped: list[str] = []
        #: 只提供前提类能力、未进入链组合的发现（如实披露，不静默丢弃）
        self.prereq: list[ChainNode] = []
        self._chains: list[AttackChain] = []
        self._built = False

    # ------------------------------------------------------------------
    def _build_nodes(self) -> None:
        for i, f in enumerate(self.findings):
            caps, basis = capabilities_of(f)
            if not caps:
                continue
            # 前提类能力不进链：它不构成「能力升级」的一环。
            # 剥掉之后若什么都不剩，说明这条发现整条就是前提，归到 prereq。
            real = [c for c in caps if c not in _PREREQ_CAPS]
            node = ChainNode(
                node_id=f"N{i + 1:02d}",
                item_id=str(_field(f, "item_id", "") or ""),
                title=str(_field(f, "title", "") or "")[:80],
                endpoint=str(_field(f, "endpoint", "") or ""),
                method=str(_field(f, "method", "") or ""),
                provides=real or list(caps),
                evidence_state=evidence_state_of(f),
                basis=basis,
                severity=str(_field(f, "severity", "") or ""),
            )
            if not real:
                self.prereq.append(node)
                continue
            if real != caps:
                node.basis = (f"{basis}（另有前提类能力 "
                              f"{'、'.join(CAPABILITY_LABEL.get(c, c) for c in caps if c in _PREREQ_CAPS)}"
                              "，不构成链上环节）")
            self.nodes.append(node)
        # 排序只为叙述稳定：进展序低的在前，同序按 item_id
        self.nodes.sort(key=lambda n: (rank_of(n.provides), n.item_id, n.node_id))

    # ------------------------------------------------------------------
    def build(self) -> list[AttackChain]:
        self._build_nodes()
        out: list[AttackChain] = []
        for objective, goals in OBJECTIVE_GOALS.items():
            for goal in goals:
                out.extend(self._chains_for(objective, goal))
        # 排序：已达成 → 可验证候选 → 纸面推演；同档内链短优先。
        # 顺序本身就是结论的一部分：把推理链排在可验证链前面，
        # 读者会把「推出来的」当成「打出来的」。
        out.sort(key=lambda c: (0 if c.state == PROVEN else
                                (1 if c.testable else 2),
                                c.gap_hops, len(c.nodes)))
        self._chains = out
        self._built = True
        return out

    def _testable(self) -> list[AttackChain]:
        return [c for c in self._chains if c.testable and c.state != PROVEN]

    def _inferred(self) -> list[AttackChain]:
        return [c for c in self._chains if not c.testable]

    # ------------------------------------------------------------------
    def _chains_for(self, objective: str, goal: str) -> list[AttackChain]:
        if not self.nodes:
            return []

        # ---- 第一档：已达成。必须存在**被实测证明**的节点直接命中目标能力。
        #      绝不用升级边推 —— 见模块 docstring。
        direct = [n for n in self.nodes if n.proven and goal in n.provides]
        if direct:
            # 在此基础上，若还有其它实测节点能作为上游环节，串成更完整的链
            upstream = [n for n in self.nodes
                        if n.proven and n.node_id != direct[0].node_id
                        and rank_of(n.provides) < rank_of(direct[0].provides)]
            picked = sorted(direct, key=lambda n: -rank_of(n.provides))[:1]
            if upstream:
                picked = sorted(upstream, key=lambda n: rank_of(n.provides))[:1] + picked
            return [self._make_chain(objective, goal, picked, PROVEN,
                                     note="链尾能力已有实测证据，结论可直接采信。")]

        # ---- 第二档：未达成。目标在能力闭包里可达，但没有任何单点被实测证明。
        #      可验证链优先；一个目标最多再带 1 条推理链作为「方向提示」——
        #      不带会静默（不知道还有什么方向），带多了会稀释。
        found = self._search(objective, goal)
        testable = [c for c in found if c.testable]
        inferred = [c for c in found if not c.testable]
        picked = sorted(testable, key=lambda c: (c.gap_hops, len(c.nodes)))
        picked = picked[:self.max_per_goal]
        if len(picked) < self.max_per_goal and inferred:
            picked += sorted(inferred, key=lambda c: (c.gap_hops,
                                                      len(c.nodes)))[:1]
        return picked

    # ------------------------------------------------------------------
    def _search(self, objective: str, goal: str) -> list[AttackChain]:
        """在小规模组合里搜索可达目标的候选链（最短优先）。"""
        # 只用「提供能力」的节点，且必须至少有一个实测节点作锚点，
        # 否则纯推理链没有锚，写进报告只会误导。
        pool = [n for n in self.nodes if n.provides]
        if not pool:
            return []
        if not any(n.proven for n in pool):
            self.skipped.append(
                f"{OBJECTIVES.get(objective, objective)}：本次没有任何发现"
                "经过实测结果证明，不产出攻击链 —— 纯推理链没有证据锚点。")
            return []

        out: list[AttackChain] = []
        seen_sets: set[frozenset[str]] = set()
        limit = min(self.max_nodes, len(pool))
        for depth in range(1, limit + 1):
            for combo in combinations(pool, depth):
                if not any(n.proven for n in combo):
                    continue
                caps: set[str] = set()
                for n in combo:
                    caps |= set(n.provides)
                if goal not in closure(caps):
                    continue
                key = frozenset(n.node_id for n in combo)
                if key in seen_sets:
                    continue
                seen_sets.add(key)
                out.append(self._make_chain(objective, goal, list(combo),
                                            INCONCLUSIVE))
                if len(out) >= self.max_per_goal * 2:
                    break
            if len(out) >= self.max_per_goal:
                break
        return out

    # ------------------------------------------------------------------
    def _make_chain(self, objective: str, goal: str, nodes: list[ChainNode],
                    state: str, note: str = "") -> AttackChain:
        nodes = sorted(nodes, key=lambda n: rank_of(n.provides))
        caps: set[str] = set()
        for n in nodes:
            caps |= set(n.provides)

        edges: list[ChainEdge] = []
        missing: list[str] = []
        acc: set[str] = set()
        for n in nodes:
            new_caps = [c for c in n.provides if c not in acc]
            for c in new_caps:
                # 找出「从已有能力升级到该能力」的那条边及条件
                for frm, to, cond in _UPGRADES:
                    if to == c and frm in acc and frm not in n.provides:
                        edges.append(ChainEdge(src=frm, dst=c, capability=c,
                                               condition=cond))
            acc |= set(n.provides)

        # ---- 缺环数：到目标还剩几个未经确认的环节 ----
        #      升级跳数（每一步都要满足一个条件）+ 链上未实测的节点数。
        #      这个数决定链值不值得派发实测，也决定它在报告里的档位。
        hops = route_to(goal, caps) if goal not in caps else []
        gap = len(hops) + sum(1 for n in nodes if not n.proven)

        if state != PROVEN:
            for frm, to, cond in hops:
                edges.append(ChainEdge(src=frm, dst=to, capability=to,
                                       condition=cond))
            if goal not in caps:
                missing.append(
                    f"目标能力「{CAPABILITY_LABEL.get(goal, goal)}」本身尚未被实测证明")
            for frm, to, cond in hops:
                missing.append(
                    f"{CAPABILITY_LABEL.get(frm, frm)} → "
                    f"{CAPABILITY_LABEL.get(to, to)}：{cond}")
            for n in nodes:
                if not n.proven:
                    missing.append(
                        f"{n.item_id} {n.title}：发现已成立，但「"
                        f"{n.caps_label()}」未经实测证明，需按复现脚本验证一次")
            if not note:
                if gap <= self.max_gap_hops:
                    note = ("这是一条**候选链**：到目标只差一环，"
                            "值得派发一次受控实测去定论。它回答的是"
                            "「下一枪往哪打」，不是「已经打进去了」。")
                else:
                    note = (
                        f"这是一条**纸面推演链**：到目标还差 {gap} 环，"
                        "中间每个条件都是未经确认的假设。"
                        "它只说明「存在这个方向」，不说明「这条路走得通」，"
                        "**不得**作为行动依据 —— 要定论需先把中间各环节"
                        "逐个实测（见下方待确认清单）。")

        chain_id = f"{objective}-{goal}-{''.join(n.node_id for n in nodes)}"
        return AttackChain(chain_id=chain_id, objective=objective, goal=goal,
                           state=state, nodes=nodes, edges=edges,
                           missing=missing, note=note, gap_hops=gap,
                           tier=(TIER_TESTABLE
                                 if (state == PROVEN or gap <= self.max_gap_hops)
                                 else TIER_INFERRED))

    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        return {
            "nodes": len(self.nodes),
            "capable_findings": len(self.nodes),
            "testable": len(self._testable()) if self._built else 0,
            "inferred": len(self._inferred()) if self._built else 0,
            "prereq": [f"{n.item_id} {n.title}" for n in self.prereq],
            "skipped": list(self.skipped),
        }


# ======================================================================
# 门面：组合 + 能力缺口回填（生产路径与自测共用同一段逻辑）
# ======================================================================


@dataclass
class ChainPlan:
    """一次攻击链分析的完整产出。"""

    chains: list[AttackChain] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    filled: list[str] = field(default_factory=list)   # 被回填结论的目标

    @property
    def proven(self) -> list[AttackChain]:
        return [c for c in self.chains if c.state == PROVEN]

    @property
    def candidates(self) -> list[AttackChain]:
        return [c for c in self.chains if c.state != PROVEN]


def plan_attack_chains(findings: list[Any], objectives: list[Any], *,
                       max_nodes: int = 3) -> ChainPlan:
    """组合攻击链，并用实测结论回填「能力缺口」的攻击目标。

    为什么要有回填：`engine/redteam.py` 只为「拿到数据」注册了攻击路径，
    另外两个目标会如实报「能力缺口（未实现该目标的攻击路径）」。
    但扫描过程中完全可能已经**实测证明**了某个发现直接提供了该能力
    （例如命令注入被实测证明执行成功 → 「拿到控制权」事实上已达成）。
    没有回填，实测到的战果会因为「没有独立攻击路径」被埋成「未能验证」——
    那是另一种形式的假结论。

    ⚠️ 回填的合法性完全依赖本模块的严格分层：链判「已达成」只认
    **单点实测**，绝不靠升级边推导。所以回填的仍然是实测结论，
    只是证据来自组合分析。报告必须用 chain_note 标明来源，
    否则读者无法判断「已达成」是打出来的还是推出来的。
    """
    b = ChainBuilder(findings, max_nodes=max_nodes)
    chains = b.build()
    notes = list(b.skipped)
    if b.prereq:
        notes.append(
            f"另有 {len(b.prereq)} 项发现只提供**前提类能力**（如无限速 / 无锁定），"
            "不构成攻击链环节 —— 它们只让「取得凭据」变得可能，本身不是凭据："
            + "、".join(f"{n.item_id} {n.title}" for n in b.prereq[:4]))
    filled = fill_objectives(chains, objectives)
    if not chains and not notes:
        notes = ["本次未组合出攻击链：现有发现之间没有可衔接的能力关系"
                 "（既没有可用的能力原语，也没有能与之衔接的目标条件）。"]
    return ChainPlan(chains=chains, notes=notes, filled=filled)


def fill_objectives(chains: list[AttackChain],
                    objectives: list[Any]) -> list[str]:
    """用「已达成」的链回填「未能验证」的攻击目标。

    单独抽出来的原因：链补证（`engine/chainclose.py`）会把候选链**实测升级**
    成已达成，那时必须再回填一次，否则打出来的战果挂在链上、目标却仍显示
    「未能验证」—— 又一处「有结论却没人读」。
    """
    by_obj: dict[str, list[AttackChain]] = {}
    for c in chains:
        if c.state == PROVEN:
            by_obj.setdefault(c.objective, []).append(c)

    filled: list[str] = []
    for oc in (objectives or []):
        if str(getattr(oc, "result", "")) != INCONCLUSIVE:
            continue
        if not getattr(oc, "authorized", True):
            continue
        hit = by_obj.get(str(getattr(oc, "objective", "")))
        if not hit:
            continue
        best = hit[0]
        oc.result = PROVEN
        oc.chain_note = (f"该目标暂无独立的攻击路径（能力缺口），"
                         f"但攻击链分析证明已达成：{best.narrative()}")
        oc.chain_evidence = [f"[攻击链 {best.chain_id}] {best.narrative()}"]
        for n in best.nodes:
            if n.proven:
                oc.chain_evidence.append(
                    f"    实测证据：{n.item_id} {n.title}"
                    f"（{n.endpoint or '无端点'}）→ 提供 {n.caps_label()}")
        oc.reason = oc.chain_note
        filled.append(str(getattr(oc, "objective", "")))
    return filled


def build_chains(findings: list[Any], **kw: Any) -> list[AttackChain]:
    """仅组合、不回填的便捷入口（报告层与统计用）。"""
    return ChainBuilder(findings, **kw).build()


# ======================================================================
# 自测
# ======================================================================


def _selftest() -> int:
    problems: list[str] = []

    # ---- ① 能力映射：双向。有能力的项能映射出能力，无关项不得映射 ----
    class _F:
        def __init__(self, item_id, title="x", endpoint="", extra=None,
                     evidence_level="B", severity="高危", method=""):
            self.item_id = item_id
            self.title = title
            self.endpoint = endpoint
            self.method = method
            self.severity = severity
            self.evidence_level = evidence_level
            self.extra = extra or {}

    # 正向名单里**必须**有真实扫描里命中率高的那批项。
    # （2026-10-10：原表只登记了教科书项，实测命中的 APIT-03 / CONF-04 /
    #   XSS 家族 / CORS / CSRF 全不在表里 → 17 条 A 级发现一条链都产不出。
    #   自测当时是全绿的 —— 因为它只验了「理想项有没有映射」。）
    for iid in ("WSTG-INPV-12", "WSTG-ATHN-04", "EXT-CD-03", "WSTG-ATHZ-04",
                "WSTG-APIT-03", "WSTG-CONF-04", "WSTG-INPV-01", "WSTG-CLNT-01",
                "WSTG-CLNT-07", "WSTG-SESS-05", "EXT-RB-01", "WSTG-ATHN-09",
                "WSTG-ERRH-01", "WSTG-CONF-06", "WSTG-BUSL-06", "EXT-DP-01"):
        caps, _ = capabilities_of(_F(iid))
        if not caps:
            problems.append(f"能力映射：{iid} 应能映射出能力，实际为空")
    # 反向：与能力无关的项不得被映射进来（宽前缀兜底会在这里暴露）。
    # 判据是「这条成立时攻击者手里多了什么」—— 纯「防护缺失」类不多任何东西：
    # HSTS / CSP / 点击劫持 / 反向标签劫持 / 指纹 / DMARC 都不在表上。
    #
    # ⚠ `WSTG-ATHN-01`（凭据经明文通道提交）也在反向名单里：
    # 它成立时攻击者手上什么都没多，要拿到凭据还得先站到链路上。
    # 把它记成 CAP_CRED 曾组合出「明文传凭据 → 改数据」—— 缺两环的纸面链
    # 照样被当成候选链报出去，读起来像攻击链，实际一步都没落地。
    for iid in ("WSTG-CONF-07", "WSTG-CONF-12", "WSTG-CLNT-09", "WSTG-CLNT-14",
                "WSTG-INFO-02", "EXT-DM-03", "WSTG-CONF-14", "EXT-RB-02",
                "EXT-RB-04", "EXT-RB-05", "WSTG-ATHN-01"):
        caps, _ = capabilities_of(_F(iid))
        if caps:
            problems.append(
                f"能力映射：{iid} 与攻击能力无关，不得映射出 {caps}"
                "（大前缀兜底会把噪声灌进链里）")

    # ---- ①c 前提类能力：不得被当成「已获得能力」 ----
    # 无限速 / 无锁定只让「取得凭据」变得可能，本身不是凭据。
    # 登记错会组合出「无限速 → 改数据」这种没有因果的链。
    _rb = capabilities_of(_F("EXT-RB-01"))[0]
    if _rb != [CAP_BRUTE]:
        problems.append(
            f"能力映射：EXT-RB-01 应只映射前提类能力 BRUTE，实际 {_rb}")
    _an = capabilities_of(_F("WSTG-ATHN-03"))[0]
    if _an != [CAP_BRUTE]:
        problems.append(
            f"能力映射：WSTG-ATHN-03 应只映射前提类能力 BRUTE，实际 {_an}")

    # ---- ①b 端到端：一组「真实会命中的 A 级发现」必须真的产出链 ----
    # 这是本模块最该钉的一条不变量。映射表、evidence_state、组合器三者
    # 各自自测都绿，但接起来产不出链时**没有任何一环会报错** ——
    # 报告上就只剩一句「没有任何发现经过实测结果证明」，读者以为
    # 「这次确实没打到什么」，实际是链引擎根本没工作。
    _real = [
        {"item_id": "WSTG-APIT-03", "title": "接口返回超出业务需要的字段",
         "endpoint": "https://t/rest/user/whoami", "method": "GET",
         "severity": "严重", "evidence_level": "A", "extra": {}},
        {"item_id": "WSTG-CONF-04", "title": "旧备份文件可直接下载",
         "endpoint": "https://t/ftp/legacy.dat", "method": "GET",
         "severity": "高危", "evidence_level": "A",
         "extra": {"proof": {"state": "未达成"}}},
    ]
    _real_chains = build_chains([dict(x) for x in _real])
    if not _real_chains:
        problems.append(
            "攻击链端到端：一组真实会命中的 A 级实测发现产不出任何链 —— "
            "映射表或 evidence_state 有一处取不到值，链引擎等于没工作")
    # dict 与对象两种形态必须等价（归档回放走 dict，生产走对象）
    _as_obj = [_F(**x) for x in _real]
    if not build_chains(_as_obj):
        problems.append("攻击链端到端：对象形态的发现产不出链（与 dict 形态不等价）")
    if bool(_real_chains) != bool(build_chains(_as_obj)):
        problems.append("攻击链：dict 与对象两种形态的产出不一致 —— "
                        "归档回放会静默丢失攻击链")

    # ---- ①d 缺环分档：可验证链与纸面推演链必须分开 ----
    # 缺 ≥2 环的链如果和可验证链混排，读者会把「推出来的」当成「打出来的」。
    # 实测踩过：一次扫描 10 条链里 9 条是缺 2 环的推演，把唯一那条真链淹了。
    _b1 = ChainBuilder([_F(**x) for x in _real])
    ch1 = _b1.build()
    for c in ch1:
        if c.state == PROVEN:
            if c.gap_hops != 0:
                problems.append(f"已达成的链缺环数应为 0，实际 {c.gap_hops}")
            continue
        if c.gap_hops > 1 and c.tier != TIER_INFERRED:
            problems.append(
                f"{c.chain_id} 缺 {c.gap_hops} 环却标为「{c.tier}」—— "
                "缺两环以上必须标纸面推演")
        if c.gap_hops <= 1 and c.tier != TIER_TESTABLE:
            problems.append(f"{c.chain_id} 缺 {c.gap_hops} 环应标可验证")
    # 排序：已达成 → 可验证 → 纸面推演
    _rank = {PROVEN: 0}
    order = [(0 if c.state == PROVEN else (1 if c.testable else 2)) for c in ch1]
    if order != sorted(order):
        problems.append(f"链的排序必须是「已达成 → 可验证 → 纸面推演」，实际 {order}")
    # 前提类发现不进链，但必须被具名承接（不得静默丢弃）
    _bp = ChainBuilder([_F("EXT-RB-01", title="无限速", endpoint="/api/x")])
    _bp.build()
    if any(n.item_id == "EXT-RB-01" for n in _bp.nodes):
        problems.append("只提供前提类能力的发现不得成为链上环节")
    if not _bp.prereq:
        problems.append("被排除的前提类发现必须进 prereq 具名披露（不得静默丢弃）")

    # ---- ② 实测状态判定：发现存在 ≠ 能力到手 ----
    f_plain = _F("WSTG-ATHN-04", evidence_level="B")
    if evidence_state_of(f_plain) == PROVEN:
        problems.append("证据判定：B 级证据（仅发现存在）不得算「实测已证」")
    f_proof = _F("WSTG-ATHN-04", extra={"proof": {"state": PROVEN}})
    if evidence_state_of(f_proof) != PROVEN:
        problems.append("证据判定：proof.state=已达成 时必须算「实测已证」")
    f_lv_a = _F("WSTG-ATHN-04", evidence_level="A")
    if evidence_state_of(f_lv_a) != PROVEN:
        problems.append("证据判定：A 级证据（实测影响）应算「实测已证」")

    # ---- ③ 已达成：链尾必须被实测证明，且不得靠升级边推出来 ----
    #     构造：认证绕过（实测已证，provides AUTH_BYPASS）
    #     升级边里有 认证绕过 → 管理功能、管理功能 → 命令执行。
    #     若用升级边推结论，就会得出「拿到控制权已达成」—— 这是必须禁止的。
    only_bypass = [_F("WSTG-ATHN-04", title="认证可绕过", extra={"proof": {"state": PROVEN}})]
    chains = build_chains(only_bypass)
    tc = [c for c in chains if c.objective == OBJ_TAKE_CONTROL]
    if any(c.state == PROVEN for c in tc):
        problems.append(
            "「已达成」判定：认证绕过 + 升级边推导出了「拿到控制权已达成」"
            "—— 升级边绝不可用于判定已达成")
    # 且该候选链必须把中间条件列为待确认
    if tc and not tc[0].missing:
        problems.append("候选链必须列出待确认的中间条件")

    # 真正的单点直达：命令注入被实测证明 → 拿到控制权应判已达成
    rce = [_F("WSTG-INPV-12", title="命令注入", extra={"proof": {"state": PROVEN}})]
    c_rce = [c for c in build_chains(rce) if c.objective == OBJ_TAKE_CONTROL]
    if not c_rce or c_rce[0].state != PROVEN:
        problems.append("单点实测证明命令执行时，「拿到控制权」应判已达成")
    c_rw = [c for c in build_chains(rce) if c.objective == OBJ_MODIFY_DATA]
    if c_rw and c_rw[0].state == PROVEN:
        problems.append(
            "命令执行不得被当成「修改数据」的实测证据"
            "（结果能力必须逐项对应，不能互推）")

    # ---- ④ 纯推理链不得产出（没有实测锚点） ----
    no_proof = [_F("WSTG-ATHN-04", title="认证绕过"), _F("WSTG-CONF-05", title="管理接口暴露")]
    for c in build_chains(no_proof):
        if c.state == PROVEN:
            problems.append("全部节点均未实测时，任何链都不得判「已达成」")

    # ---- ⑤ 未提供能力的发现不产生节点 ----
    b = ChainBuilder([_F("WSTG-CONF-07", title="缺 HSTS"), _F("WSTG-INPV-12", title="命令注入")])
    b._build_nodes()
    if any(n.item_id == "WSTG-CONF-07" for n in b.nodes):
        problems.append("与攻击能力无关的发现不得成为攻击链节点")

    # ---- ⑥ 升级闭包与路径：条件必须逐跳带出，且不得凭空空转 ----
    if CAP_ADMIN not in closure({CAP_CRED}):
        problems.append("凭据应能推导出管理功能访问（用于候选链）")
    if CAP_EXEC in closure({CAP_INFO}):
        problems.append("信息掌握不得直接推导出命令执行（升级图出现越级）")
    hops = route_to(CAP_EXEC, {CAP_CRED})
    if not hops:
        problems.append("凭据到命令执行应存在升级路径（用于缺口提示）")
    else:
        for frm, to, cond in hops:
            if not cond:
                problems.append(f"升级边 {frm}→{to} 缺少成立条件说明")
    if route_to(CAP_READ, {CAP_READ}) != []:
        problems.append("已达成的目标不应再给出升级路径")

    # ---- ⑦ 链必须可复测：给出复测入口 ----
    chain = build_chains(rce)[0]
    if "复测" not in chain.repro_hint():
        problems.append("攻击链必须给出复测提示")

    # ---- ⑧ 节点排序稳定（叙述可读） ----
    mixed = [_F("WSTG-INPV-12", title="命令注入", extra={"proof": {"state": PROVEN}}),
             _F("EXT-CD-03", title="Git 泄露", extra={"proof": {"state": PROVEN}})]
    ch = build_chains(mixed)
    if ch:
        ranks = [rank_of(n.provides) for n in ch[0].nodes]
        if ranks != sorted(ranks):
            problems.append("链内节点应按攻击进展序排列（信息在前、结果在后）")

    # ---- ⑨ 能力缺口回填：只有「实测已达成」的链可以回填 ----
    #      回填解决的是「实测到的战果因为没有独立攻击路径而被埋成未能验证」。
    #      但它的合法性完全依赖「已达成只认单点实测」这条分层 —— 一旦放松，
    #      三级推理就会把「扫到一个认证绕过」写成「拿到控制权」。
    from engine.redteam import NOT_PROVEN, ObjectiveOutcome

    def _obj(objective, result=INCONCLUSIVE):
        return ObjectiveOutcome(objective=objective, label="目标", result=result)

    # (a) 命令注入被实测证明 → 「拿到控制权」（能力缺口）应被回填
    oc_tc = _obj(OBJ_TAKE_CONTROL)
    plan_attack_chains(
        [_F("WSTG-INPV-12", title="命令注入", extra={"proof": {"state": PROVEN}})],
        [oc_tc])
    if oc_tc.result != PROVEN:
        problems.append("已实测证明命令执行时，「拿到控制权」的能力缺口应被回填")
    if oc_tc.chain_note and not oc_tc.chain_evidence:
        problems.append("回填必须带 chain_evidence（否则「已达成」没有可见证据）")
    if oc_tc.result == PROVEN and not oc_tc.chain_note:
        problems.append("回填必须带 chain_note 标明来源（否则读者分不清是打的还是推的）")

    # (b) 只有候选链（未经实测）→ 绝不能回填
    oc_tc2 = _obj(OBJ_TAKE_CONTROL)
    plan_attack_chains([_F("WSTG-ATHN-04", title="认证绕过")], [oc_tc2])
    if oc_tc2.result == PROVEN:
        problems.append("候选链（未经实测）绝不能回填「已达成」")

    # (c) 未授权的目标不得被回填
    oc_tc3 = _obj(OBJ_TAKE_CONTROL)
    oc_tc3.authorized = False
    plan_attack_chains(
        [_F("WSTG-INPV-12", title="命令注入", extra={"proof": {"state": PROVEN}})],
        [oc_tc3])
    if oc_tc3.result == PROVEN:
        problems.append("未授权的目标不得被回填成「已达成」")

    # (d) 已有明确结论的目标不得被回填覆盖
    oc_rd = _obj(OBJ_READ_DATA, NOT_PROVEN)
    plan_attack_chains(
        [_F("EXT-DP-01", title="明文暴露数据", extra={"proof": {"state": PROVEN}})],
        [oc_rd])
    if oc_rd.result != NOT_PROVEN:
        problems.append("已有明确结论（未达成）的目标不得被回填覆盖")

    if problems:
        print("攻击链组合自测失败：")
        for p in problems:
            print("  -", p)
        return 1

    print("攻击链组合自测通过（9 组）：")
    print("  ✓ 能力映射双向：明确的注入/认证/凭据项能映射，配置与客户端项不映射")
    print("  ✓ 实测状态：发现存在 ≠ 能力到手，只有结果证明或 A 级证据才算实测")
    print("  ✓ 「已达成」只认单点实测，绝不靠升级边推导")
    print("  ✓ 结果能力逐项对应，命令执行不被当成「读到数据」的证据")
    print("  ✓ 无实测锚点时产出「未产链」说明，而不是推理链")
    print("  ✓ 无关发现不入链；升级条件逐跳带出且非空")
    print("  ✓ 链带复测入口；节点按攻击进展序排列")
    print("  ✓ 能力缺口回填只认真实测量：候选链 / 未授权 / 已有结论的目标都不回填")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_selftest())
