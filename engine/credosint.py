# -*- coding: utf-8 -*-
"""红队视角的凭据情报（credential OSINT）。

为什么需要它
================================================================================
`engine/credhunt.py` 已经解决了「自己动手试」：找登录入口 + 试一份**固定的**
教科书级默认口令（9 组）。它诚实地把第三条路留成了空白：

    | ③ 从外部泄露信息找线索 | 只出线索与检索指引，**不自动联网检索**（交人工） |

那个空格在红队视角下是个真实的缺口。真实攻击者面对一个陌生系统，
第一件事不是从 9 组通用口令开始撞，而是先**认出这是什么系统**，
然后去查**这个系统的默认口令是什么** —— 因为厂商文档、安装手册、
镜像的 docker-compose、教程博客里都写着。这件事的命中率远高于通用字典，
代价却更低（往往只需 1～3 次尝试）。本模块补的就是这条路。

三条路（与 credhunt 的三行表一一对应）
================================================================================

| 黑客的路 | 本模块的做法 | 依赖 |
|---|---|---|
| 这是什么系统 | 从指纹证据识别产品（服务器头 / Cookie 名 / 路径命中 / 页面标记） | 本地，零网络 |
| 它的默认口令是什么 | ① 本地产品默认口令知识库 ② 联网检索厂商资料 | ② 需出网 |
| 有没有人已经泄露过 | 检索目标自身的公开线索；产出**线索**，不自动尝试 | 需出网 |

与 credhunt 的分工：本模块**只产出候选与线索，不自己发登录请求**。
所有实际的口令提交仍走 credhunt 那一个受控循环，因此 credhunt 的三条硬约束
（双重次数上限 / 命中风控即停 / 口令原文不落盘）天然覆盖到这里产出的每一组候选。
这是刻意的：把「想试什么」与「怎么试」分开，安全边界就只需要守一处。

不可回退的红线（每条都有自测钉住）
================================================================================
1. **不许瞎撞**：只有**识别出产品**才产出候选口令。识别不出产品时，
   本模块产出零个自动尝试候选 —— 拿一份字典对着陌生表单硬试是爆破，
   不是「找默认凭据」，两者的授权解释和副作用完全不同。
2. **候选必须准入**：账号名须属通用运维账号集合，口令须是弱口令形态。
   形如 `svc_deploy: Xq7#mK2pLz9v` 这种（长度 / 形态不符）**一律不进自动尝试**，
   只作为线索列出 —— 检索到别人的真实凭据就去自动使用，
   会误伤无关账号，且超出「默认口令探测」的授权边界。
3. **检索词不得含凭据**：发给搜索引擎的查询串里绝不能出现任何口令。
   把凭据拼进 URL 等于亲手把它交给第三方日志。
4. **外部检索必须披露**：发了几次检索、检索词是什么，逐条写进报告。
   主动查询会向第三方暴露「有人正在关注该目标」这一事实，
   项目使用方有权知道这件事发生过（`AISCAN_CREDOSINT=off` 可关闭）。
5. **降级必须具名**：检索不可用（DNS / TLS / 超时 / 限流 / 结果页解析不到条目）
   各有各的措辞，且**不得**因此判「没有线索」—— 「没检索到」和
   「检索没做成」是两件事，后者必须原样说出来。
6. **安全档零外部请求**：安全档不做任何对外检索与产品推断。
7. **命中限流即停**：检索源上机器人校验后立即停止后续查询，并如实说明
   「这次没检索成」。继续打只会延长校验期，而**把它写成「没有线索」
   是最坏的一类假结论** —— 读者会据此认为公开渠道已经查干净了。
   实测：连打数次后检索源会持续返回校验页（UA 无关，见下方 UA 注释），
   所以联网这一路是**尽力而为**，本地产品库才是可靠的那条腿。

三条状态互斥（与项目其他模块同一套语义）
================================================================================
    未检索   —— 档位关闭 / 显式关闭 / 目标非公网 / 未识别出可检索的对象
    检索未成 —— 发了请求但没拿到可用结果（限流 / 网络失败 / 对端改版，各自具名）
    已检索   —— 拿到了结果；结果本身可以是「无线索」，那是有效结论

绝不把「检索未成」写成「无线索」。
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "CredCandidate", "Lead", "OsintResult", "SearchHit",
    "detect_products", "product_defaults", "is_weak_pair",
    "osint", "MAX_QUERIES",
]

# ==============================================================================
# 常量
# ==============================================================================
#: 检索 UA —— 与项目其他出网模块一致，让对端在日志里能识别这是一次扫描行为。
#: 刻意**不伪装成浏览器**：伪装只会让对端更难判断我们的意图。
#:
#: 2026-09-29 做过一次对照实验，结论值得记下来：检索源对**连续查询**会返回
#: HTTP 202 + `anomaly` / `challenge` 的机器人校验页。当时怀疑是 UA 里的
#: 「aiscan…」后缀触发的，于是同一 IP、同一时刻只换 UA 对打三枪 ——
#: 自报身份 UA 和普通浏览器 UA **结果完全一样，都被校验**。
#: 所以这不是 UA 特征，是**查询频率 / IP 级限流**。改 UA 解决不了，
#: 该做的是控制频率（见 MIN_QUERY_GAP）并在被限流时如实说出来。
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 "
      "(aiscan-credential-osint; authorized-security-assessment)")

#: 单次外部请求超时。取值偏保守：这是扫描的**辅助**路径，
#: 不能让一次网络抖动把整场扫描拖住。
NET_TIMEOUT = 10.0

#: 一次运行最多发出多少次检索。上限不是性能考虑，是**披露成本**：
#: 每一次检索都向第三方暴露一次「有人在查这个目标」。
#: 检索词全部记进报告，次数越多，披露段落越接近噪声。
#: 取 3 还有一个实测原因：这个量级的检索源对短时间内的连续查询会直接上校验。
MAX_QUERIES = 3

#: 两次检索之间的强制间隔（秒）。**必须有** —— 实测连打 4 枪时，
#: 第 2、3 枪就出现了机器人校验（HTTP 202 + `anomaly` / `challenge`），
#: 结果是「检索跑了但什么都没拿到」。加间隔是反频控的自约束，
#: 与 credhunt 的 `MIN_GAP_SECONDS` 同一思路：宁可慢一点，也别把自己打成被封。
MIN_QUERY_GAP = 4.0

#: 最多保留多少条线索进报告（超出部分只在计数里体现，避免报告被刷屏）。
MAX_LEADS = 10

#: 自动尝试候选上限。与 credhunt 的次数硬上限共同生效：
#: 这里限「产出多少」，那里限「实际发多少请求」。
MAX_CANDIDATES = 6

#: 口令形态判定的长度闸门。默认口令几乎都很短；
#: 超过这个长度基本可以确定是「某人的真实口令」而不是「厂商默认值」。
WEAK_PASSWORD_MAX_LEN = 16

#: 通用运维 / 产品默认账号。只有落在这个集合里的账号名，
#: 才有资格进入自动尝试。
WEAK_ACCOUNTS: frozenset[str] = frozenset({
    "admin", "administrator", "root", "test", "guest", "demo", "manager",
    "tomcat", "both", "role1", "nacos", "sentinel", "apollo", "jenkins",
    "minioadmin", "elastic", "airflow", "hue", "sonar", "pma", "weblogic",
    "nsroot", "nagiosadmin", "cacti", "admin123", "postgres", "sa",
    "mysql", "oracle", "redis", "cassandra", "rabbitmq", "zabbix",
    "dolphinscheduler", "superset", "rancher", "artifactory", "nexus",
    "opensearch", "kibana", "grafana", "chronograf", "sysadmin",
})

#: 「空口令 / 无口令」的写法集合。空口令是很多管理台的出厂状态。
EMPTY_PASSWORD_TOKENS: frozenset[str] = frozenset({
    "", "(empty)", "empty", "none", "null", "blank", "无", "空", "空口令",
    "no password", "<empty>",
})


def _norm_account(a: str) -> str:
    return str(a or "").strip().strip("`'\"").lower()


def _is_empty_password(p: str) -> bool:
    return str(p or "").strip().lower() in EMPTY_PASSWORD_TOKENS


# ==============================================================================
# 数据结构
# ==============================================================================
@dataclass
class SearchHit:
    """一条检索结果。只保留**元信息**，不抓取目标页面正文。"""

    title: str
    url: str
    snippet: str
    query: str

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "url": self.url,
                "snippet": self.snippet, "query": self.query}


@dataclass
class CredCandidate:
    """一条候选口令。"""

    account: str
    password: str
    product: str
    source: str            # 本地产品默认口令库 / 公开资料检索
    evidence: str          # 为什么认为它适用（具体到哪条证据）
    strength: str          # 强（厂商公开文档级）/ 弱（检索摘要）
    auto_attempt: bool = False
    hold_reason: str = ""  # 不进自动尝试时的原因（必须非空，否则不许留空）

    def key(self) -> tuple[str, str]:
        return (_norm_account(self.account), str(self.password))

    def to_dict(self) -> dict[str, Any]:
        # 注意：**口令原文不进 to_dict**。
        # 候选口令来自公开资料，原则上不是秘密；但一旦落进报告 JSON，
        # 它与「某次尝试用的是哪个口令」之间的对应关系就被固定下来了，
        # 而报告是要外发的。所以只给指纹，与 credhunt 的尝试表同一套规矩。
        return {"account": self.account,
                "pw_fingerprint": _pw_fingerprint(self.account, self.password),
                "product": self.product, "source": self.source,
                "evidence": self.evidence, "strength": self.strength,
                "auto_attempt": self.auto_attempt,
                "hold_reason": self.hold_reason}


@dataclass
class Lead:
    """一条线索。**不自动尝试**，只交人工判断。"""

    title: str
    url: str
    snippet: str
    source: str
    kind: str              # 凭据线索 / 暴露面线索 / 管理台暴露
    why_not_auto: str

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "url": self.url, "snippet": self.snippet,
                "source": self.source, "kind": self.kind,
                "why_not_auto": self.why_not_auto}


def _pw_fingerprint(account: str, password: str) -> str:
    """与 credhunt 同一算法的短指纹：可复算比对，不可反推。"""
    import hashlib

    h = hashlib.sha256(f"{account}\x00{password}".encode("utf-8")).hexdigest()
    return h[:12]


@dataclass
class OsintResult:
    """一次凭据情报的完整结果。"""

    enabled: bool = False
    reason: str = ""
    #: [(产品名, 判定证据), ...]
    products: list[tuple[str, str]] = field(default_factory=list)
    candidates: list[CredCandidate] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    #: 实际发出的检索词（披露用，必须可复算）
    queries: list[str] = field(default_factory=list)
    #: 来源名 -> 状态。状态要么是 "ok"，要么是具名降级原因
    sources: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    #: 检索到的结果条数（不代表有线索，只代表拿到了页面）
    hits_seen: int = 0

    def auto_pairs(self) -> list[tuple[str, str]]:
        """可进入受控尝试的候选，按「我们想先试哪个」排序。

        排序理由：**先试产品专属的、强证据的**。通用字典（credhunt 那 9 组）
        排在最后，因为它的信息量最低 —— 识别出是 Nacos 之后还先去试
        admin/admin，是在浪费本就极少的尝试配额。
        """
        picked = [c for c in self.candidates if c.auto_attempt]
        order = {"强": 0, "弱": 1}
        picked.sort(key=lambda c: (order.get(c.strength, 2), c.product))
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for c in picked:
            k = c.key()
            if k in seen:
                continue
            seen.add(k)
            out.append((c.account, c.password))
        return out[:MAX_CANDIDATES]

    def pair_sources(self) -> dict[tuple[str, str], str]:
        """候选 -> 来源，供 credhunt 把来源写进每一条尝试留痕。"""
        return {c.key(): f"{c.source}·{c.product}" for c in self.candidates}

    def online_status(self) -> str:
        """联网部分的总体状态：ok / 未检索 / 具名失败。"""
        keys = [k for k in self.sources if "检索" in k]
        if not keys:
            return "未检索"
        if all(self.sources[k] == "ok" for k in keys):
            return "ok"
        bad = [f"{k}：{self.sources[k]}" for k in keys if self.sources[k] != "ok"]
        return "；".join(bad)

    def summary_lines(self) -> list[str]:
        L: list[str] = []
        if not self.enabled:
            L.append(f"[凭据情报] 未执行：{self.reason or '本档位未启用'}")
            return L
        if self.products:
            names = "、".join(p for p, _ in self.products[:5])
            L.append(f"[凭据情报] 识别到产品：{names}"
                     f"（依据见报告 4.1 节）")
        else:
            L.append("[凭据情报] 未从指纹证据中识别出已知产品 —— "
                     "不产出任何自动尝试候选（拿通用字典硬试等于爆破，不做）")
        n_auto = len(self.auto_pairs())
        n_hold = len(self.candidates) - n_auto
        L.append(f"[凭据情报] 候选口令 {len(self.candidates)} 组"
                 f"（自动尝试 {n_auto} 组，转人工线索 {n_hold} 组）")
        if self.queries:
            L.append(f"[凭据情报] 已发出 {len(self.queries)} 次外部检索"
                     f"（检索词见报告；每次检索都会向第三方暴露"
                     "「有人在查该目标」，因此全量披露）")
        st = self.online_status()
        if st not in ("ok", "未检索"):
            L.append(f"[凭据情报] 联网检索未完成：{st}")
        if self.leads:
            L.append(f"[凭据情报] 另有 {len(self.leads)} 条线索需人工判断"
                     "（不自动使用，原因见报告 4.1 节）")
        return L

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "reason": self.reason,
            "products": [{"name": n, "evidence": e} for n, e in self.products],
            "candidates": [c.to_dict() for c in self.candidates],
            "leads": [x.to_dict() for x in self.leads],
            "queries": list(self.queries),
            "sources": dict(self.sources),
            "notes": list(self.notes),
            "hits_seen": self.hits_seen,
        }


# ==============================================================================
# 产品识别（本地，零网络）
# ==============================================================================
#: 产品知识表。每条：
#:   name    产品名（进报告）
#:   paths   指纹阶段已探过的路径前缀 —— 命中即可作为强证据
#:   server  服务器 / 响应头特征（正则）
#:   body    页面标题 / 正文 / 组件标记（正则）
#:   creds   该产品的公开默认口令；空元组表示「无固定默认口令」
#:   no_creds_reason  creds 为空时必填：为什么没有固定默认口令（进报告）
#:   console 该产品自己的管理台路径（用于把「暴露面」写成可复现的线索）
#:
#: 收录原则：只收**厂商公开文档或广泛公开资料里写过默认口令**的产品。
#: 拿不准的一律不放 creds —— 少一条候选只是少一次尝试，
#: 错一条候选会变成对无关账号的一次失败登录。
_PRODUCTS: tuple[dict[str, Any], ...] = (
    {
        "name": "Apache Tomcat Manager",
        "paths": ("/manager/html", "/manager/status", "/host-manager/html"),
        "server": (r"Apache-Coyote", r"Tomcat"),
        "body": (r"Tomcat Manager", r"Tomcat Web Application Manager",
                 r"/manager/html"),
        "creds": (("tomcat", "tomcat"), ("admin", "admin"),
                  ("tomcat", "s3cret"), ("role1", "role1"), ("both", "both")),
        "console": "/manager/html",
    },
    {
        "name": "Jenkins",
        "paths": ("/jenkins", "/jenkins/login", "/login?from="),
        "server": (),
        "body": (r"Jenkins", r"jenkins"),
        "creds": (),
        "no_creds_reason": "Jenkins 没有固定默认口令：首次启动会在数据目录生成"
                           "初始管理员口令文件（initialAdminPassword），"
                           "只有能读到该文件才拿得到 —— 属主机侧访问，不在本次范围",
        "console": "/jenkins",
    },
    {
        "name": "Grafana",
        "paths": ("/grafana", "/grafana/login", "/login"),
        "server": (),
        "body": (r"Grafana",),
        "creds": (("admin", "admin"), ("admin", "grafana")),
        "console": "/login",
    },
    {
        "name": "Kibana",
        "paths": ("/app/kibana", "/kibana", "/app/monitoring"),
        "server": (),
        "body": (r"Kibana",),
        "creds": (("elastic", "changeme"), ("kibana", "changeme")),
        "console": "/login",
    },
    {
        "name": "Elasticsearch",
        "paths": ("/_cat/indices", "/_cluster/health", "/_nodes"),
        "server": (),
        "body": (r"elasticsearch", r"\"cluster_name\""),
        "creds": (("elastic", "changeme"), ("elastic", ""), ("kibana", "changeme")),
        "console": "/_security/_authenticate",
    },
    {
        "name": "RabbitMQ Management",
        "paths": ("/rabbitmq", "/api/overview", "/#/login"),
        "server": (),
        "body": (r"RabbitMQ Management", r"RabbitMQ"),
        "creds": (("guest", "guest"),),
        "console": "/#/login",
    },
    {
        "name": "Zabbix",
        "paths": ("/zabbix", "/zabbix/index.php"),
        "server": (),
        "body": (r"Zabbix",),
        "creds": (("Admin", "zabbix"), ("admin", "zabbix")),
        "console": "/index.php",
    },
    {
        "name": "phpMyAdmin",
        "paths": ("/phpmyadmin", "/pma", "/phpMyAdmin"),
        "server": (),
        "body": (r"phpMyAdmin",),
        "creds": (("root", ""), ("root", "root"), ("pma", ""), ("admin", "")),
        "console": "/index.php",
    },
    {
        "name": "WordPress",
        "paths": ("/wp-admin", "/wp-login.php", "/wp-json"),
        "server": (),
        "body": (r"WordPress", r"wp-content", r"wp-includes"),
        "creds": (("admin", "admin"), ("admin", "password")),
        "console": "/wp-login.php",
    },
    {
        "name": "Joomla",
        "paths": ("/administrator", "/administrator/index.php"),
        "server": (),
        "body": (r"Joomla",),
        "creds": (("admin", "admin"),),
        "console": "/administrator/",
    },
    {
        "name": "Drupal",
        "paths": ("/user/login", "/user", "/core/install.php"),
        "server": (),
        "body": (r"Drupal",),
        "creds": (("admin", "admin"),),
        "console": "/user/login",
    },
    {
        "name": "Alibaba Nacos",
        "paths": ("/nacos", "/nacos/index.html", "/nacos/v1/auth"),
        "server": (),
        "body": (r"Nacos", r"nacos"),
        "creds": (("nacos", "nacos"),),
        "console": "/index.html",
    },
    {
        "name": "Alibaba Druid Monitor",
        "paths": ("/druid/index.html", "/druid/websession.html", "/druid/sql.html"),
        "server": (),
        "body": (r"Druid Stat", r"Druid"),
        "creds": (),
        "no_creds_reason": "Druid 监控台默认**完全无鉴权**（不存在口令这一层）—— "
                           "它不是「弱口令」问题而是「未授权访问」问题，"
                           "应作为暴露面单独处置，不适用口令尝试",
        "console": "/druid/index.html",
    },
    {
        "name": "Alibaba Sentinel Dashboard",
        "paths": ("/sentinel", "/sentinel/#/login", "/#/login"),
        "server": (),
        "body": (r"Sentinel",),
        "creds": (("sentinel", "sentinel"),),
        "console": "/#/login",
    },
    {
        "name": "XXL-JOB",
        "paths": ("/xxl-job-admin", "/xxl-job-admin/toLogin"),
        "server": (),
        "body": (r"XXL-JOB", r"xxl-job"),
        "creds": (("admin", "123456"),),
        "console": "/toLogin",
    },
    {
        "name": "Apache Airflow",
        "paths": ("/airflow", "/home", "/login/"),
        "server": (),
        "body": (r"Airflow",),
        "creds": (("airflow", "airflow"), ("admin", "admin")),
        "console": "/login/",
    },
    {
        "name": "Apache Zeppelin",
        "paths": ("/zeppelin", "/zeppelin/#/login", "/api/login"),
        "server": (),
        "body": (r"Zeppelin",),
        "creds": (("admin", "admin"), ("zeppelin", "zeppelin")),
        "console": "/#/login",
    },
    {
        "name": "Apache DolphinScheduler",
        "paths": ("/dolphinscheduler", "/dolphinscheduler/ui", "/dolphinscheduler/login"),
        "server": (),
        "body": (r"DolphinScheduler",),
        "creds": (("admin", "dolphinscheduler123"),),
        "console": "/login",
    },
    {
        "name": "Cloudera Hue",
        "paths": ("/hue", "/hue/accounts/login"),
        "server": (),
        "body": (r"Hue",),
        "creds": (("admin", "admin"), ("hue", "hue")),
        "console": "/accounts/login",
    },
    {
        "name": "SonarQube",
        "paths": ("/sonar", "/about", "/sessions/new", "/api/system/status"),
        "server": (),
        "body": (r"SonarQube",),
        "creds": (("admin", "admin"),),
        "console": "/sessions/new",
    },
    {
        "name": "Harbor",
        "paths": ("/harbor", "/harbor/projects", "/c/login"),
        "server": (),
        "body": (r"Harbor",),
        "creds": (("admin", "Harbor12345"), ("admin", "Harbor12345!")),
        "console": "/c/login",
    },
    {
        "name": "MinIO Console",
        "paths": ("/minio", "/minio/login", "/api/v1/login"),
        "server": (),
        "body": (r"MinIO", r"minio"),
        "creds": (("minioadmin", "minioadmin"),),
        "console": "/login",
    },
    {
        "name": "Portainer",
        "paths": ("/portainer", "/api/status", "/#!/init/admin"),
        "server": (),
        "body": (r"Portainer",),
        "creds": (),
        "no_creds_reason": "Portainer 首次访问走初始化流程，由使用者**现场设置**"
                           "管理员口令，不存在出厂默认口令",
        "console": "/#!/init/admin",
    },
    {
        "name": "Spring Boot Actuator",
        "paths": ("/actuator", "/actuator/env", "/actuator/health",
                  "/actuator/beans", "/env", "/health"),
        "server": (),
        "body": (r"\"_links\"", r"actuator"),
        "creds": (),
        "no_creds_reason": "Actuator 端点默认**不做鉴权**（Spring Boot 2.x 默认只暴露 "
                           "health/info，误配后暴露 env / heapdump）—— "
                           "属未授权访问与信息泄露，不是口令问题",
        "console": "/actuator",
    },
    {
        "name": "Apache APISIX Dashboard",
        "paths": ("/apisix", "/apisix/dashboard", "/apisix/admin"),
        "server": (),
        "body": (r"APISIX",),
        "creds": (("admin", "admin"),),
        "console": "/user/login",
    },
    {
        "name": "Ctrip Apollo 配置中心",
        "paths": ("/apollo", "/apollo/config.html", "/apollo/"),
        "server": (),
        "body": (r"Apollo",),
        "creds": (("apollo", "admin"),),
        "console": "/",
    },
    {
        "name": "Sonatype Nexus Repository",
        "paths": ("/nexus", "/service/rest/v1/status", "/nexus/#admin"),
        "server": (),
        "body": (r"Nexus Repository", r"Nexus"),
        "creds": (("admin", "admin123"),),
        "console": "/#admin",
    },
    {
        "name": "JFrog Artifactory",
        "paths": ("/artifactory", "/ui/", "/artifactory/webapp/"),
        "server": (),
        "body": (r"Artifactory",),
        "creds": (("admin", "password"),),
        "console": "/ui/",
    },
    {
        "name": "Prometheus",
        "paths": ("/graph", "/targets", "/api/v1/status/config"),
        "server": (),
        "body": (r"Prometheus",),
        "creds": (),
        "no_creds_reason": "Prometheus 自身不带鉴权 —— 暴露即为未授权访问；"
                           "若前置了反向代理，其口令属于代理配置，不由本产品决定",
        "console": "/graph",
    },
    {
        "name": "HashiCorp Consul",
        "paths": ("/ui/", "/v1/agent/self", "/v1/catalog/services"),
        "server": (),
        "body": (r"Consul",),
        "creds": (),
        "no_creds_reason": "Consul 默认无鉴权（ACL 需显式开启）—— 属未授权访问问题",
        "console": "/ui/",
    },
    {
        "name": "etcd",
        "paths": ("/v2/keys", "/version", "/v3/kv/range"),
        "server": (),
        "body": (r"\"etcdserver\"", r"etcd"),
        "creds": (),
        "no_creds_reason": "etcd 默认无鉴权 —— 暴露即等于配置与密钥全量泄露，"
                           "属未授权访问问题，不适用口令尝试",
        "console": "/version",
    },
    {
        "name": "Apache CouchDB",
        "paths": ("/_utils", "/_all_dbs", "/_up"),
        "server": (r"CouchDB",),
        "body": (r"CouchDB", r"\"couchdb\""),
        "creds": (("admin", "password"), ("admin", "")),
        "console": "/_utils",
    },
    {
        "name": "InfluxDB",
        "paths": ("/chronograf", "/ping", "/query"),
        "server": (),
        "body": (r"InfluxDB", r"Chronograf"),
        "creds": (("admin", "admin"),),
        "console": "/",
    },
    {
        "name": "mongo-express",
        "paths": ("/mongo-express", "/db/"),
        "server": (),
        "body": (r"mongo-express",),
        "creds": (("admin", "pass"), ("admin", "admin")),
        "console": "/",
    },
    {
        "name": "Apache Superset",
        "paths": ("/superset", "/superset/welcome", "/login/"),
        "server": (),
        "body": (r"Superset",),
        "creds": (("admin", "admin"),),
        "console": "/login/",
    },
    {
        "name": "Rancher",
        "paths": ("/rancher", "/dashboard", "/v3-public/localProviders"),
        "server": (),
        "body": (r"Rancher",),
        "creds": (("admin", "admin"),),
        "console": "/login",
    },
    {
        "name": "GitLab",
        "paths": ("/users/sign_in", "/-/health", "/explore"),
        "server": (),
        "body": (r"GitLab",),
        "creds": (("root", "5iveL!fe"),),
        "console": "/users/sign_in",
    },
    {
        "name": "Oracle WebLogic",
        "paths": ("/console", "/console/login/LoginForm.jsp", "/wls-wsat"),
        "server": (r"WebLogic",),
        "body": (r"WebLogic", r"Oracle WebLogic"),
        "creds": (("weblogic", "welcome1"), ("weblogic", "weblogic")),
        "console": "/console",
    },
    {
        "name": "JBoss / WildFly",
        "paths": ("/jmx-console", "/web-console", "/admin-console"),
        "server": (r"JBoss", r"WildFly"),
        "body": (r"JBoss", r"WildFly"),
        "creds": (("admin", "admin"),),
        "console": "/jmx-console",
    },
    {
        "name": "Nagios",
        "paths": ("/nagios", "/nagios/cgi-bin/status.cgi"),
        "server": (),
        "body": (r"Nagios",),
        "creds": (("nagiosadmin", "nagiosadmin"),),
        "console": "/",
    },
    {
        "name": "Cacti",
        "paths": ("/cacti", "/cacti/index.php"),
        "server": (),
        "body": (r"Cacti",),
        "creds": (("admin", "admin"),),
        "console": "/index.php",
    },
    {
        "name": "F5 BIG-IP",
        "paths": ("/tmui", "/tmui/login.jsp", "/mgmt/shared/authn/login"),
        "server": (r"BIG-IP",),
        "body": (r"BIG-IP", r"F5 Networks"),
        "creds": (("admin", "admin"),),
        "console": "/tmui/login.jsp",
    },
    {
        "name": "Citrix NetScaler",
        "paths": ("/vpn/index.html", "/nitro/v1/config", "/nf/auth/doAuthentication.do"),
        "server": (r"NetScaler",),
        "body": (r"NetScaler",),
        "creds": (("nsroot", "nsroot"),),
        "console": "/vpn/index.html",
    },
)

#: 产品名 -> 定义，便于查表
_PRODUCT_INDEX: dict[str, dict[str, Any]] = {p["name"]: p for p in _PRODUCTS}

#: **不具区分度的路径**。命中它们**不构成**任何产品的证据，只作补充。
#:
#: 这一条来自本模块第一次自测的失败，值得写下来：`/login` 返回 200 曾把
#: Grafana、Airflow、Superset 三个产品**同时**「识别」出来 —— 而 `/login`
#: 是个登录框就有。这正是本项目反复吃过的亏：**孤立信号不得当正面证据**。
#: 判据必须是产品**特有**的东西（`/manager/html`、`/nacos/`、`Apache-Coyote` 头、
#: 页面里的产品标记），而不是任何系统都有的通用路径。
#: 用通用路径识别产品的后果很具体：会拿 Grafana 的默认口令去打一个
#: 压根不是 Grafana 的登录框，几次失败登录留在对方日志里，还平白消耗
#: 本就极少的尝试配额。
_GENERIC_PATHS: frozenset[str] = frozenset({
    "/", "/login", "/signin", "/sign_in", "/user/login", "/home", "/about",
    "/index.php", "/api/login", "/#/login", "/admin", "/console",
    "/dashboard", "/explore", "/login?from=",
})


def _is_discriminating_path(path: str) -> bool:
    """该路径是否足以用来识别产品。"""
    p = str(path or "").strip().lower().rstrip("/") or "/"
    return p not in _GENERIC_PATHS


#: 厂商标识前缀。检索匹配时要剥掉 —— 产品全名常带厂商
#: （"Apache Tomcat Manager"），而公开资料里普遍只写产品名（"Tomcat Manager"），
#: 拿全名去做匹配会一条都匹配不上，表现为「检索跑过了但没有候选」。
_VENDOR_PREFIXES: tuple[str, ...] = (
    "Apache ", "Alibaba ", "HashiCorp ", "Oracle ", "Ctrip ", "JFrog ",
    "Sonatype ", "Cloudera ", "Spring Boot ",
)


def _name_keyword(name: str) -> str:
    """产品的区分性关键词：剥掉厂商前缀后的首个词。

    "Apache Tomcat Manager" -> "Tomcat"；"Alibaba Nacos" -> "Nacos"；
    "Spring Boot Actuator" -> "Actuator"。
    """
    n = str(name or "")
    for p in _VENDOR_PREFIXES:
        if n.startswith(p):
            n = n[len(p):]
            break
    parts = n.split()
    return parts[0] if parts else n


def product_defaults(product: str) -> tuple[tuple[str, str], ...]:
    """取某产品的公开默认口令。未知产品返回空元组（不猜）。"""
    p = _PRODUCT_INDEX.get(product)
    if not p:
        return ()
    return tuple(p.get("creds") or ())


def product_console(product: str) -> str:
    p = _PRODUCT_INDEX.get(product) or {}
    return str(p.get("console") or "")


def product_no_creds_reason(product: str) -> str:
    p = _PRODUCT_INDEX.get(product) or {}
    return str(p.get("no_creds_reason") or "")


# ==============================================================================
# 从指纹证据识别产品
# ==============================================================================
def _probe_paths(path_probes: dict[str, Any]) -> list[tuple[str, int]]:
    """把指纹的 path_probes 折成 [(路径, 状态码), ...]，只保留「确实响应了」的。

    判据与 fingerprint / credguide 侧一致：可达且状态码落在
    (200, 301, 302, 401, 403, 405) —— 401/403 同样是**有价值的证据**：
    它说明「这个路径存在，只是要认证」，恰恰是产品管理台最典型的形态。
    """
    out: list[tuple[str, int]] = []
    for path, info in (path_probes or {}).items():
        if isinstance(info, dict):
            reachable = info.get("reachable")
            status = int(info.get("status") or 0)
        else:
            reachable = getattr(info, "reachable", None)
            status = int(getattr(info, "status", 0) or 0)
        if reachable is False:
            continue
        if status in (200, 301, 302, 401, 403, 405):
            out.append((str(path), status))
    return out


def _text_blobs(evidence: dict[str, Any]) -> list[tuple[str, str]]:
    """收集可用来做内容匹配的文本。返回 [(来源标签, 文本), ...]。"""
    blobs: list[tuple[str, str]] = []
    rp = evidence.get("root_probe") or {}
    if isinstance(rp, dict):
        if rp.get("title"):
            blobs.append(("首页标题", str(rp["title"])))
        if rp.get("body_snippet"):
            blobs.append(("首页正文", str(rp["body_snippet"])))
        if rp.get("server"):
            blobs.append(("Server 头", str(rp["server"])))
    elif rp:
        for label, attr in (("首页标题", "title"), ("首页正文", "body_snippet"),
                            ("Server 头", "server")):
            v = getattr(rp, attr, "")
            if v:
                blobs.append((label, str(v)))
    for p, info in (evidence.get("path_probes") or {}).items():
        title = ""
        snippet = ""
        if isinstance(info, dict):
            title = str(info.get("title") or "")
            snippet = str(info.get("body_snippet") or "")
        else:
            title = str(getattr(info, "title", "") or "")
            snippet = str(getattr(info, "body_snippet", "") or "")
        if title:
            blobs.append((f"路径 {p} 标题", title))
        if snippet:
            blobs.append((f"路径 {p} 正文", snippet))
    return blobs


def _cookie_names(evidence: dict[str, Any]) -> list[str]:
    rp = evidence.get("root_probe") or {}
    if isinstance(rp, dict):
        return [str(c) for c in (rp.get("cookies") or [])]
    return [str(c) for c in (getattr(rp, "cookies", None) or [])]


def detect_products(evidence: dict[str, Any]) -> list[tuple[str, str]]:
    """从指纹证据里认出产品。返回 [(产品名, 证据原文), ...]。

    **证据原文必须具体**（哪个路径返回了多少、哪个头里写了什么）——
    报告里这一列是读者判断「这个结论可不可信」的唯一依据，
    写「疑似 Spring 系」这种话等于没写。
    """
    probes = _probe_paths(evidence.get("path_probes") or {})
    blobs = _text_blobs(evidence)
    cookies = _cookie_names(evidence)
    found: list[tuple[str, str]] = []

    for spec in _PRODUCTS:
        # 强证据（足以单独识别产品）与弱证据（只能补强）分开收集。
        # 弱证据**不参与识别判定** —— 见 _GENERIC_PATHS 的说明。
        strong: list[str] = []
        weak: list[str] = []
        kw = _name_keyword(str(spec["name"]))
        # ① 路径命中：产品特有的路径判据最强（那条路径本身就是该产品的）
        for want in spec.get("paths") or ():
            for p, st in probes:
                if p == want or p.rstrip("/") == want.rstrip("/") or p.startswith(want):
                    item = f"路径 {p} 返回 HTTP {st}"
                    (strong if _is_discriminating_path(p) else weak).append(item)
                    break
        # ② 服务器 / 响应头特征（产品特有的横幅，强证据）
        for pat in spec.get("server") or ():
            for label, text in blobs:
                if label == "Server 头" and re.search(pat, text, re.I):
                    strong.append(f"{label} 含「{pat}」")
                    break
        # ③ 页面标题 / 正文里的产品标记（强证据）
        for pat in spec.get("body") or ():
            for label, text in blobs:
                if label == "Server 头":
                    continue
                if re.search(pat, text, re.I):
                    strong.append(f"{label} 含「{pat}」")
                    break
        # ④ Cookie 名（如 grafana_session / _gitlab_session 是产品特有的；
        #    JSESSIONID / PHPSESSID 只说明技术栈，不构成产品证据）
        for ck in cookies:
            if re.search(re.escape(kw), ck, re.I):
                strong.append(f"Cookie 名 {ck} 含产品名")
                break
        if not strong:
            continue
        # 去重且保序，最多 3 条，避免报告被证据淹没
        uniq: list[str] = []
        for e in strong + weak:
            if e not in uniq:
                uniq.append(e)
        found.append((str(spec["name"]), "；".join(uniq[:3])))
    return found


# ==============================================================================
# 候选准入：什么能自动试，什么只能交人工
# ==============================================================================
def is_weak_pair(account: str, password: str) -> bool:
    """判定一组「账号 + 口令」是否属于**默认/弱口令形态**。

    这个函数是自动尝试的守门人。它的存在理由很具体：
    检索回来的文本里可能混着别人的真实凭据（运维博客里打码不全的示例、
    泄露文件片段）。把那些直接拿去登录，会误伤无关账号，
    也超出了「默认口令探测」这个授权解释。

    所以规则刻意保守 —— 只放行「一眼就是厂商默认值」的形态：
      · 空口令（很多管理台的出厂状态）
      · 口令 == 账号名（admin/admin）
      · 纯数字且不超过 8 位
      · 账号名 + 少量数字（admin123 / tomcat12345）
      · 落在公开弱口令集合里
    且总长度不超过 WEAK_PASSWORD_MAX_LEN。
    """
    acct = _norm_account(account)
    if not acct or acct not in WEAK_ACCOUNTS:
        return False
    if _is_empty_password(password):
        return True
    pw = str(password or "").strip()
    if not pw or len(pw) > WEAK_PASSWORD_MAX_LEN:
        return False
    low = pw.lower()
    if low == acct:
        return True
    if low in WEAK_PASSWORDS:
        return True
    if re.fullmatch(r"\d{1,8}", pw):
        return True
    if re.fullmatch(re.escape(acct) + r"[!_\-]?\d{1,5}", low):
        return True
    if re.fullmatch(r"[a-z]{2,10}[!_\-]?\d{1,5}", low) and len(pw) <= 12:
        return True
    return False


#: 公开弱口令集合。**只收广泛公开、出现在多份「最常见口令」榜单里的那些**。
#: 刻意保持小：每多一条，生产系统的失败登录日志就多一条。
WEAK_PASSWORDS: frozenset[str] = frozenset({
    "password", "passw0rd", "p@ssw0rd", "123456", "1234567", "12345678",
    "123456789", "12345", "1234", "111111", "000000", "abc123", "qwerty",
    "letmein", "welcome", "changeme", "change_me", "secret", "default",
    "test", "test123", "guest", "root", "toor", "admin", "manager",
    "administrator", "tomcat", "s3cret", "role1", "both", "nacos",
    "sentinel", "apollo", "zabbix", "dolphinscheduler123", "harbor12345",
    "minioadmin", "5ivel!fe", "5iveL!fe", "weblogic", "welcome1",
    "nsroot", "nagiosadmin", "admin123", "admin12345", "pfsense",
    "changeme123", "password123", "p@ssword",
})


def _admit(account: str, password: str, product: str, source: str,
           evidence: str, strength: str) -> CredCandidate:
    """构造候选，并决定它能否进入自动尝试；不能则必须写明原因。"""
    ok = is_weak_pair(account, password)
    reason = ""
    if not ok:
        acct = _norm_account(account)
        if acct not in WEAK_ACCOUNTS:
            reason = (f"账号 `{account}` 不在通用运维账号集合内 —— "
                      "可能是某人的个人 / 服务账号，自动尝试会误伤该账号，"
                      "交人工确认归属后再决定")
        else:
            reason = ("口令形态不符合默认 / 弱口令特征（长度或构成更像真实口令）—— "
                      "检索到的这类凭据可能是第三方的真实凭据，"
                      "自动使用会误伤无关账号，且超出「默认口令探测」的授权解释")
    return CredCandidate(account=account, password=password, product=product,
                         source=source, evidence=evidence, strength=strength,
                         auto_attempt=ok, hold_reason=reason)


# ==============================================================================
# 联网检索（DuckDuckGo HTML 端点，无鉴权）
# ==============================================================================
#: 检索端点。选型依据是**实测**：本机环境下 DuckDuckGo HTML 端点返回
#: 可解析的结果条目（10 条链接 + 10 条摘要）；DDG Lite 与 Bing 的标记
#: 对不上（HTTP 200 但取不到条目）；Google 返回 JS 外壳；
#: GitHub 代码搜索 API 需要鉴权（401）。
#: 记下来是为了下次「优化」的人不必重跑一遍探测 ——
#: 也要清楚：**这是随时会变的外部依赖**，所以解析失败必须具名降级。
_SEARCH_URL = "https://html.duckduckgo.com/html/?q={q}"
_RE_RESULT_LINK = re.compile(
    r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_RE_RESULT_SNIPPET = re.compile(
    r'class="result__snippet"[^>]*>(.*?)</a>', re.I | re.S)
_RE_TAG = re.compile(r"<[^>]+>")


def _strip_html(s: str) -> str:
    return html.unescape(_RE_TAG.sub("", s or "")).strip()


def _unwrap_ddg(href: str) -> str:
    """解开 DDG 的跳转包装：`//duckduckgo.com/l/?uddg=<urlencoded>&rut=...`。

    不解开的话，报告里给出的线索 URL 会是一串跳转链接 ——
    读者复制到浏览器里能用，但**没法一眼看出指向哪个域名**，
    而「这条线索到底来自哪里」正是判断其可信度的关键信息。
    """
    h = html.unescape(href or "").strip()
    if h.startswith("//"):
        h = "https:" + h
    if "duckduckgo.com/l/" in h:
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(h).query)
            if qs.get("uddg"):
                return urllib.parse.unquote(qs["uddg"][0])
        except Exception:  # noqa: BLE001
            return h
    return h


def _default_fetcher(url: str, timeout: float = NET_TIMEOUT) -> Any:
    """默认真实网络取回。**只做 GET，不发任何带凭据的请求。**

    返回 `(状态码, 正文)` —— 状态码是必需的：检索源被限流时返回的是
    HTTP 202 而不是错误码，只看正文长度根本分不出来。
    """
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return int(getattr(r, "status", 200) or 200), r.read().decode("utf-8", "replace")


def _norm_fetch(out: Any) -> tuple[int, str]:
    """归一化 fetcher 的返回：允许返回正文，也允许返回 (状态码, 正文)。"""
    if isinstance(out, tuple) and len(out) == 2:
        return int(out[0] or 0), str(out[1] or "")
    return 200, str(out or "")


#: 检索源的限流 / 机器人校验标记。
#: ⚠ **不要加 "robot"**：正常结果页里也含这个词（实测），
#: 加了会把成功页误判成限流 —— 那会把一次好的检索结果整批丢掉。
#: 这些标记只在**解析不到任何结果条目**时才参与判定，
#: 所以正常页面上偶然出现这些词也不会造成误判。
_LIMIT_MARKERS: tuple[str, ...] = (
    "anomaly", "challenge", "captcha", "unusual traffic", "rate limit",
    "not a bot", "are you a robot",
)


def search(query: str, fetcher: Callable[[str], Any] | None = None
           ) -> tuple[list[SearchHit], str]:
    """执行一次检索。返回 (结果列表, 状态)。

    状态约定（**四种状态必须互斥**，后三种不许互相冒充）：
      "ok"                 —— 拿到了结果页，且解析出条目
      "被限流（...）"        —— 检索源上了机器人校验。**这不等于「没有线索」**，
                              且调用方应停止后续检索（继续打只会更糟）
      "结果页无条目（...）"  —— 拿到了正常页面但解析不出条目（多为对端改版）
      "检索失败（...）"      —— 请求本身没成功
    """
    fetcher = fetcher or _default_fetcher
    url = _SEARCH_URL.format(q=urllib.parse.quote(query))
    try:
        status_code, body = _norm_fetch(fetcher(url))
    except urllib.error.HTTPError as e:
        return [], f"检索失败（HTTP {e.code}）"
    except urllib.error.URLError as e:
        return [], f"检索失败（网络不可达：{str(e.reason)[:60]}）"
    except Exception as e:  # noqa: BLE001
        return [], f"检索失败（{type(e).__name__}）"
    if not body:
        return [], "检索失败（响应为空）"

    links = _RE_RESULT_LINK.findall(body)
    snips = [_strip_html(s) for s in _RE_RESULT_SNIPPET.findall(body)]
    hits: list[SearchHit] = []
    for i, (href, title_html) in enumerate(links):
        hits.append(SearchHit(
            title=_strip_html(title_html)[:160],
            url=_unwrap_ddg(href)[:300],
            snippet=(snips[i] if i < len(snips) else "")[:400],
            query=query))
    if hits:
        return hits, "ok"

    # 解析不到条目时，才去区分「被限流」与「对端改版」。
    markers = [mk for mk in _LIMIT_MARKERS if mk in body.lower()]
    if status_code in (202, 429) or markers:
        _detail = f"HTTP {status_code}"
        if markers:
            _detail += f"；页面含 " + "、".join(f"`{mk}`" for mk in markers[:2])
        return [], f"被限流（检索源上了机器人校验：{_detail}）"
    return [], "结果页无条目（对端页面结构变化，解析规则需更新）"


def _queries_for(products: list[tuple[str, str]], domain: str,
                 want_leads: bool) -> list[str]:
    """编排检索词。**任何情况下都不把凭据拼进查询串。**

    用关键词而不是带引号的完整产品名：实测 `"Apache Tomcat Manager" default
    password` 这种精确短语查询在检索源上返回 0 条（太严），
    而 `Tomcat default password` 能正常返回结果。
    检索词越窄，越容易什么都查不到 —— 而「查不到」会被误读成「没有默认口令」。
    """
    qs: list[str] = []
    for name, _ev in products:
        if len(qs) >= MAX_QUERIES - 1:
            break
        # 用**产品关键词**而不是完整证据：证据里可能带目标特有的路径，
        # 那会把「目标是谁」一并带进检索词，扩大对外暴露面。
        qs.append(f"{_name_keyword(name)} default password")
    if want_leads and len(qs) < MAX_QUERIES:
        qs.append(f"{domain} default password leaked")
    return qs[:MAX_QUERIES]


#: 私有 / 回环 / 保留地址段。命中即认为「不是公网域名」。
_RE_IPV4_PRIVATE = re.compile(
    r"^(?:0|10|127)\.|^169\.254\.|^192\.168\.|"
    r"^172\.(?:1[6-9]|2\d|3[01])\.")


def _looks_non_public(domain: str) -> str:
    """目标是不是「公开检索源上查不到意义」的地址。返回原因，空串表示是公网。

    加这道判断不是为了省一次请求，而是因为**对回环地址做公开检索本身就是
    一件没有意义的事**：`"127.0.0.1" default password leaked` 只会捞回一堆
    无关噪声，还平白向第三方暴露一次查询。附带的好处是：引擎自测
    （目标就是 127.0.0.1）因此天然保持离线，不需要额外的环境变量开关 ——
    少一个开关就少一处「忘了设」的隐患。
    """
    d = str(domain or "").strip().lower()
    if not d:
        return "未提供域名"
    if d in ("localhost", "::1") or d.endswith((".local", ".localhost",
                                                ".internal", ".lan")):
        return f"目标是本机 / 内网名称（{d}）"
    if _RE_IPV4_PRIVATE.match(d):
        return f"目标是私有 / 回环地址（{d}）"
    return ""


#: 从摘要里抽「账号 / 口令」的形态。刻意收得很紧：
#: 只认「显式的分隔符 + 两侧都是短 token」这种写法，
#: 避免把正常英文句子里的两个词误配成一组凭据。
_RE_PAIR = re.compile(
    r"(?:^|[\s（(\[【])([A-Za-z][A-Za-z0-9_.\-]{1,20})\s*[/:：]\s*"
    r"([A-Za-z0-9!@#$%^&*_.\-]{0,20})(?=$|[\s，。、）)\]】,;])")

#: 句末标点。抽出来的口令必须剥掉它们 ——
#: 这不是洁癖，是本模块第一次自测抓到的真问题：摘要写
#: "…are tomcat / tomcat and admin/admin123." 时，正则会把句号并进口令，
#: 得到 `admin123.`，接着被弱口令准入拦掉，**表现为「检索到了但没有候选」**。
#: 而凭据在检索摘要里最常出现在句末，所以这是一个会静默丢候选的假阴性 ——
#: 危险的正是方向：读者会以为「网上没找到」，实际是解析把结果吃掉了。
_TRAILING_PUNCT = ".,;:!?。，、；：)】]}）〕"


def extract_pairs(text: str) -> list[tuple[str, str]]:
    """从检索摘要里抽候选「账号/口令」。只返回通过弱口令准入的那些。

    注意：**这里只做抽取，不做使用**。抽取结果仍要过 `is_weak_pair`，
    再由 `_admit` 决定是进自动尝试还是转人工。
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _RE_PAIR.finditer(text or ""):
        acct = m.group(1).strip(_TRAILING_PUNCT + " ")
        raw = m.group(2)
        # 先试原文，再试剥掉句末标点的版本 —— 口令真的以标点结尾是极少数，
        # 但「句号被并进来」是常态，两种都判一次，能过就行。
        for pwd in (raw, raw.rstrip(_TRAILING_PUNCT)):
            if not is_weak_pair(acct, pwd):
                continue
            k = (_norm_account(acct), pwd)
            if k in seen:
                break
            seen.add(k)
            out.append((acct, pwd))
            break
    return out


# ==============================================================================
# 主入口
# ==============================================================================
def osint(
    target_url: str,
    domain: str = "",
    evidence: dict[str, Any] | None = None,
    profile_key: str = "standard",
    enabled: bool = True,
    allow_online: bool = True,
    fetcher: Callable[[str], Any] | None = None,
    query_gap: float | None = None,
) -> OsintResult:
    """执行一次凭据情报。

    `evidence` 是指纹阶段的产物（root_probe / path_probes），
    本模块只读它，不再对目标发任何请求 ——
    「识别产品」复用已有证据，是零额外请求成本的。

    `query_gap` 只为自测开放（自测不该真的睡 4 秒）；生产一律用 MIN_QUERY_GAP。
    """
    res = OsintResult()
    evidence = evidence or {}

    if os.environ.get("AISCAN_CREDOSINT", "").strip().lower() in ("off", "0", "false"):
        res.reason = "已由 AISCAN_CREDOSINT=off 显式关闭"
        return res
    if not enabled:
        res.reason = "本次未启用凭据情报"
        return res
    if profile_key == "safe":
        # 安全档的档位定义是「最低干扰」，而外部检索会向第三方暴露目标信息。
        # 口径与 credhunt 一致：安全档不做，且必须说明为什么。
        res.reason = ("当前为安全档：凭据情报需要向外部检索源发出与目标相关的查询，"
                      "会向第三方暴露「有人正在关注该目标」这一事实，"
                      "与「最低干扰」的档位定义冲突，故未执行")
        return res

    res.enabled = True

    # ---------- ① 产品识别（本地，零网络） ----------
    res.products = detect_products(evidence)
    res.sources["产品识别（本地）"] = ("ok" if res.products
                                      else "未从现有证据中识别出已知产品")

    # ---------- ② 本地产品默认口令库（主力） ----------
    local_n = 0
    for name, ev in res.products:
        creds = product_defaults(name)
        if not creds:
            why = product_no_creds_reason(name)
            if why:
                res.leads.append(Lead(
                    title=f"{name}：无固定默认口令",
                    url="", snippet=why, source="产品知识库",
                    kind="说明",
                    why_not_auto="该产品不存在可尝试的出厂口令，"
                                 "任何口令猜测都会变成对真实账号的失败登录"))
            continue
        for acct, pwd in creds:
            res.candidates.append(_admit(
                acct, pwd, name, "本地产品默认口令库",
                f"{ev}；该口令为 {name} 的公开出厂默认值", "强"))
            local_n += 1
    res.sources["本地产品默认口令库"] = ("ok" if local_n
                                        else "无适用条目（未识别出产品，"
                                             "或识别到的产品没有固定默认口令）")

    # ---------- ③ 联网检索（可选，逐条披露） ----------
    if not allow_online:
        res.sources["公开资料检索"] = "未执行（本次已关闭联网检索）"
    elif _looks_non_public(domain):
        # 「未执行」而不是「失败」：我们主动决定不做，且理由成立。
        res.sources["公开资料检索"] = (
            f"未执行（{_looks_non_public(domain)}，公开检索源上查不到有意义的结果）")
    else:
        want_leads = bool(domain)
        queries = _queries_for(res.products, domain, want_leads)
        if not queries:
            res.sources["公开资料检索"] = ("未执行（没有可检索的对象："
                                          "未识别出产品且缺少目标域名）")
        else:
            ok_n = 0
            fail: list[str] = []
            limited = ""
            _gap = MIN_QUERY_GAP if query_gap is None else max(0.0, float(query_gap))
            for i, q in enumerate(queries):
                if i and _gap:
                    # 反频控自约束：两次检索之间强制间隔。没有它时实测第 2、3 枪
                    # 就被判机器人校验，整段检索等于白跑。
                    time.sleep(_gap)
                hits, status = search(q, fetcher=fetcher)
                res.queries.append(q)
                res.hits_seen += len(hits)
                if status != "ok":
                    fail.append(status)
                    if status.startswith("被限流"):
                        # **命中限流即停**：继续打只会让校验期更长，
                        # 与 credhunt「命中风控即停」同一条纪律。
                        limited = status
                        break
                    continue
                ok_n += 1
                res.leads.extend(_leads_from_hits(hits, domain))
                for c in _candidates_from_hits(hits, res.products):
                    res.candidates.append(c)
            if limited:
                _left = len(queries) - len(res.queries)
                res.sources["公开资料检索"] = (
                    f"{limited}；已停止后续检索"
                    + (f"（还有 {_left} 条检索词未执行）" if _left > 0 else ""))
                res.notes.append(
                    "[凭据情报] 检索源上了机器人校验，已立即停止后续检索。"
                    "**这不等于「网上没有线索」** —— 是这次没检索成；"
                    "需要完整线索时请间隔一段时间重跑，"
                    "或直接人工用浏览器检索（本节已给出检索词）")
            elif fail and ok_n == 0:
                res.sources["公开资料检索"] = "；".join(sorted(set(fail)))
            elif fail:
                res.sources["公开资料检索"] = (
                    f"部分完成（{ok_n}/{len(res.queries)} 次成功；"
                    f"失败：{'；'.join(sorted(set(fail)))}）")
            else:
                res.sources["公开资料检索"] = "ok"

    # ---------- 去重（同一组候选可能来自多个产品 / 多条摘要） ----------
    uniq: dict[tuple[str, str], CredCandidate] = {}
    for c in res.candidates:
        k = c.key()
        if k not in uniq:
            uniq[k] = c
        elif not uniq[k].auto_attempt and c.auto_attempt:
            uniq[k] = c
    res.candidates = list(uniq.values())

    # 线索去重 + 截断
    seen_lead: set[str] = set()
    dedup: list[Lead] = []
    for x in res.leads:
        key = f"{x.kind}|{x.url or x.title}"
        if key in seen_lead:
            continue
        seen_lead.add(key)
        dedup.append(x)
    if len(dedup) > MAX_LEADS:
        res.notes.append(f"[凭据情报] 线索共 {len(dedup)} 条，"
                         f"报告只列前 {MAX_LEADS} 条（其余同源，未逐条展开）")
        dedup = dedup[:MAX_LEADS]
    res.leads = dedup

    # ---------- 披露与免责 ----------
    if res.queries:
        res.notes.append(
            f"[凭据情报] **本次向公开检索源发出了 {len(res.queries)} 次查询**"
            "（检索词逐条列在本节）—— 主动外部检索会向第三方暴露"
            "「有人正在关注该目标」这一事实，属本项目既定的披露义务。"
            "如需完全避免，可加 `--no-credosint` 或以 `AISCAN_CREDOSINT=off` 运行")
    if any(c.hold_reason for c in res.candidates):
        res.notes.append(
            "[凭据情报] 部分候选**未进入自动尝试**（逐条注明原因）："
            "检索到的凭据可能是第三方的真实凭据，自动使用会误伤无关账号，"
            "也会超出「默认口令探测」的授权解释 —— 这类交人工判断归属")
    if not res.products:
        res.notes.append(
            "[凭据情报] 未识别出产品，因此**没有产出任何自动尝试候选**："
            "拿一份通用字典对着陌生登录框硬试属于爆破，"
            "与「找默认凭据」是两件不同的事，不做")
    return res


def _leads_from_hits(hits: list[SearchHit], domain: str) -> list[Lead]:
    """把检索结果整理成线索。

    **刻意不自动尝试**检索到的任何具体凭据（能自动试的那些已由
    `_candidates_from_hits` 单独挑走并过了准入）。这里留下的是
    「需要人去判断」的部分：包含真实口令形态的片段、疑似泄露文件、
    以及目标相关的暴露面线索。
    """
    out: list[Lead] = []
    low_domain = (domain or "").lower()
    for h in hits:
        blob = f"{h.title} {h.snippet}".lower()
        pairs = extract_pairs(f"{h.title} {h.snippet}")
        if pairs:
            kind = "凭据线索"
            why = ("检索片段中出现疑似可用的凭据 —— 无法判定它是否属于目标，"
                   "也无法判定是否仍有效；自动使用可能误伤无关账号，交人工确认")
        elif low_domain and low_domain in blob:
            kind = "目标相关线索"
            why = ("与目标域名相关，但未识别出可自动尝试的默认口令形态 —— "
                   "需人工打开原文判断")
        elif any(k in blob for k in ("password", "credential", "passwd",
                                     "默认口令", "默认密码", "泄露", "leak")):
            kind = "凭据线索"
            why = "检索结果与凭据话题相关，需人工判断是否与本目标有关"
        else:
            continue
        out.append(Lead(title=h.title[:160], url=h.url, snippet=h.snippet[:300],
                        source=f"公开资料检索（{h.query}）", kind=kind,
                        why_not_auto=why))
    return out


def _candidates_from_hits(hits: list[SearchHit],
                          products: list[tuple[str, str]]
                          ) -> list[CredCandidate]:
    """从检索结果里挑出**可以自动尝试**的候选。

    只有同时满足两条才挑走：
      · 摘要里抽出了「账号 / 口令」对，且过了弱口令准入；
      · 该摘要与某个已识别产品的**区分性关键词**同现
        （否则无法确认这是**这个产品**的默认口令）。
    其余一律留给 `_leads_from_hits` 作为线索。
    """
    out: list[CredCandidate] = []
    for h in hits:
        blob = f"{h.title} {h.snippet}"
        matched = [n for n, _e in products
                   if re.search(re.escape(_name_keyword(n)), blob, re.I)]
        if not matched:
            continue
        for acct, pwd in extract_pairs(blob):
            out.append(_admit(
                acct, pwd, matched[0], "公开资料检索",
                f"检索「{h.query}」的摘要中同时出现产品名与这组凭据"
                f"（来源：{h.url[:120]}）", "弱"))
    return out


# ==============================================================================
# 自测
# ==============================================================================
# 自测分组清单。**必须与 _selftest() 里的 grp() 调用点一一对应** ——
# 这里声明、那里执行，末尾核对两者是否一致。
#
# 为什么要有这份清单：在此之前，通过时打的是 `通过（20 组断言）`,
# 而「20」是写死的字符串。也就是说，就算有人把中间若干组整段删掉、
# 或者插了一句提前 return，自测照样会宣布「通过（20 组断言）」,
# 数字一个字都不变。这正是本项目最不肯接受的失败形态：**自测自己说自己通过了**。
# 现在数字是数出来的，少跑一组就报错，且报的是「哪一组没跑」。
_SELFTEST_GROUPS: tuple[str, ...] = (
    "①", "①-b", "①-c", "②", "③", "④", "⑤", "⑤-b", "⑥", "⑦", "⑧",
    "⑨", "⑩", "⑪", "⑫", "⑬", "⑭", "⑮", "⑯", "⑰", "⑱", "⑲", "⑳",
)


def _selftest() -> int:
    """离线自测。**全部用假 fetcher，不发一次真实网络请求。**"""
    problems: list[str] = []
    ran: list[str] = []

    def eq(got: Any, want: Any, label: str) -> None:
        if got != want:
            problems.append(f"{label}：期望 {want!r}，实际 {got!r}")

    def grp(tag: str) -> None:
        """进入某一组时登记 + 打一行进度。"""
        if tag not in _SELFTEST_GROUPS:
            problems.append(f"自测分组 {tag} 未在 _SELFTEST_GROUPS 里声明 —— 清单要同步")
        ran.append(tag)
        print(f"  [{len(ran):2d}/{len(_SELFTEST_GROUPS)}] 第 {tag} 组")

    # ---------------- 公共夹具 ----------------
    _ev_tomcat = {
        "root_probe": {"status": 200, "server": "Apache-Coyote/1.1",
                       "title": "Apache Tomcat", "cookies": ["JSESSIONID"],
                       "body_snippet": "Tomcat Web Application Manager"},
        "path_probes": {
            "/manager/html": {"reachable": True, "status": 401},
            "/manager/status": {"reachable": True, "status": 401},
            "/login": {"reachable": True, "status": 200},
        },
    }
    _ddg_html = """
<html><body>
<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ftomcat.apache.org%2Fdoc%2Fmanager-howto.html&rut=ab">Apache Tomcat Manager default credentials</a>
<a class="result__snippet" href="x">The default credentials for Tomcat Manager are <b>tomcat / tomcat</b> and admin/admin123.</a>
<a class="result__a" href="https://example.org/blog">某运维博客：Tomcat 默认口令汇总</a>
<a class="result__snippet" href="x">常见组合 admin/admin、tomcat/s3cret，生产环境请务必修改。</a>
</body></html>
"""

    def _fake_ok(_url: str) -> str:
        return _ddg_html

    def _fake_boom(_url: str) -> str:
        raise OSError("模拟：DNS 解析失败")

    def _fake_noparse(_url: str) -> str:
        return "<html><body>请启用 JavaScript 后重试</body></html>"

    # ① 产品识别：路径 + Server 头 + 正文三路证据都要留下可读的原文
    grp("①")
    prods = detect_products(_ev_tomcat)
    names = [n for n, _ in prods]
    if "Apache Tomcat Manager" not in names:
        problems.append(f"未识别出 Tomcat，实际识别到 {names}")
    else:
        ev = dict(prods)["Apache Tomcat Manager"]
        if "HTTP 401" not in ev:
            problems.append(f"产品证据未包含路径状态码原文：{ev!r}")
        if "Apache-Coyote" not in ev:
            problems.append(f"产品证据未包含 Server 头原文：{ev!r}")
        if not ev:
            problems.append("产品证据为空 —— 没有证据的识别等于猜测")

    # ①-b 无证据时不得凭空识别出产品
    grp("①-b")
    if detect_products({}) != []:
        problems.append("空证据下识别出了产品 —— 识别必须基于证据")

    # ①-c **通用路径不得识别出产品**。这一条是第一次自测抓出来的真问题：
    #      `/login` 返回 200 曾同时「识别」出 Grafana / Airflow / Superset。
    grp("①-c")
    _ev_generic = {"root_probe": {"status": 200, "server": "nginx",
                                  "title": "登录", "body_snippet": "请登录"},
                   "path_probes": {"/login": {"reachable": True, "status": 200},
                                   "/admin": {"reachable": True, "status": 200}}}
    _pg = [n for n, _e in detect_products(_ev_generic)]
    if _pg:
        problems.append(f"通用路径（/login、/admin）识别出了产品：{_pg} —— "
                        "孤立信号不得当正面证据")
    if not _is_discriminating_path("/manager/html"):
        problems.append("/manager/html 被判为不具区分度（它是产品特有路径）")
    if _is_discriminating_path("/login"):
        problems.append("/login 被判为具区分度 —— 它会误导产品识别")

    # ② 本地库候选：来源可追溯、强度为强、直接可自动尝试
    grp("②")
    r2 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
               profile_key="standard", allow_online=False)
    if not r2.enabled:
        problems.append(f"标准档 + 允许联网时凭据情报应启用，实际：{r2.reason!r}")
    pairs2 = r2.auto_pairs()
    if ("tomcat", "tomcat") not in pairs2:
        problems.append(f"本地库未产出 tomcat/tomcat，实际候选 {pairs2}")
    _tomcat_cand = [c for c in r2.candidates if c.key() == ("tomcat", "tomcat")]
    if not _tomcat_cand:
        problems.append("tomcat/tomcat 候选缺失")
    else:
        c = _tomcat_cand[0]
        eq(c.source, "本地产品默认口令库", "候选来源标注")
        eq(c.strength, "强", "本地库候选强度")
        if not c.evidence:
            problems.append("候选缺少适用证据 —— 报告里读者无从判断可信度")
        if not c.auto_attempt:
            problems.append("本地库的默认口令应当可直接进入受控尝试")

    # ③ 口令原文不得进 to_dict（报告要外发）
    grp("③")
    _d = _tomcat_cand[0].to_dict() if _tomcat_cand else {}
    if "password" in _d:
        problems.append("候选凭据的 to_dict 里出现了口令原文 —— 报告外发会带走它")
    if not _d.get("pw_fingerprint"):
        problems.append("候选凭据缺少散列指纹（无法复算比对）")

    # ④ 弱口令准入：形态像真实口令的一律转人工，且原因必须写清楚
    grp("④")
    if is_weak_pair("svc_deploy", "Xq7#mK2pLz9vYw"):
        problems.append("服务账号 + 强口令被判为可自动尝试")
    if is_weak_pair("admin", "Xq7#mK2pLz9vYw"):
        problems.append("admin 配强口令被判为可自动尝试（长度/形态均不符合）")
    for acct, pwd in (("admin", "admin"), ("root", ""), ("tomcat", "tomcat"),
                      ("admin", "123456"), ("Admin", "zabbix")):
        if not is_weak_pair(acct, pwd):
            problems.append(f"教科书级默认口令未通过准入：{acct}/{pwd}")
    _hold = _admit("admin", "Xq7#mK2pLz9vYw", "X", "公开资料检索", "e", "弱")
    if _hold.auto_attempt:
        problems.append("形态像真实口令的候选被放进了自动尝试")
    if not _hold.hold_reason:
        problems.append("候选被拦下但未写明原因（静默拦截）")
    _hold2 = _admit("somebody", "x", "X", "公开资料检索", "e", "弱")
    if _hold2.auto_attempt or not _hold2.hold_reason:
        problems.append("非通用账号名的候选处置不正确")

    # ⑤ 检索解析：DDG 跳转包装要解开，摘要要取到（否则线索里的 URL 读不出域名）
    grp("⑤")
    hits, st = search("q", fetcher=_fake_ok)
    eq(st, "ok", "假结果页的检索状态")
    if len(hits) < 2:
        problems.append(f"结果条目解析不足：{len(hits)} 条")
    if hits and "tomcat.apache.org" not in hits[0].url:
        problems.append(f"DDG 跳转包装未解开：{hits[0].url!r}")
    if hits and "结果" not in hits[0].title and "Manager" not in hits[0].title:
        problems.append(f"标题解析异常：{hits[0].title!r}")
    if not any(h.snippet for h in hits):
        problems.append("摘要未解析出来（线索判断依赖摘要）")

    # ⑤-b 句末标点不得被并进口令。第一次自测就是因为这个丢了候选：
    #      "…and admin/admin123." 被抽成 `admin123.`，随后被准入拦掉，
    #      表现为「检索到了却没有候选」—— 一个会静默丢结果的假阴性。
    grp("⑤-b")
    _tail = extract_pairs("defaults are tomcat / tomcat and admin/admin123.")
    if ("admin", "admin123") not in _tail:
        problems.append(f"句末标点被并进口令，候选被静默丢弃：{_tail}")
    if ("tomcat", "tomcat") not in _tail:
        problems.append(f"句中的默认口令未抽出：{_tail}")
    if any(p.endswith(".") for _a, p in _tail):
        problems.append(f"抽出的口令仍带句末标点：{_tail}")

    # ⑥ 三种失败状态必须互斥：网络失败 ≠ 页面无条目 ≠ 检索成功
    grp("⑥")
    _h6, st6 = search("q", fetcher=_fake_boom)
    if not st6.startswith("检索失败"):
        problems.append(f"网络失败未归入「检索失败」：{st6!r}")
    _h7, st7 = search("q", fetcher=_fake_noparse)
    if _h7 or "无条目" not in st7:
        problems.append(f"页面无条目未如实归类：{st7!r}")
    if st6 == st7:
        problems.append("「检索失败」与「结果页无条目」被混为一谈")
    if st7.startswith("检索失败"):
        problems.append("「结果页无条目」被误判为「检索失败」")

    # ⑦ 联网失败时：本地库候选仍要产出，且降级原因必须具名
    grp("⑦")
    r7 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
               profile_key="standard", fetcher=_fake_boom, query_gap=0.0)
    if not r7.auto_pairs():
        problems.append("联网失败导致本地库候选也丢了 —— 两条路必须独立")
    if r7.sources.get("公开资料检索") == "ok":
        problems.append("联网失败却把检索状态写成 ok（假成功）")
    if "检索失败" not in (r7.sources.get("公开资料检索") or ""):
        problems.append(f"降级原因未具名：{r7.sources.get('公开资料检索')!r}")
    if not r7.queries:
        problems.append("发过的检索词未记录（披露义务无法履行）")

    # ⑧ 检索词披露 + **绝不含凭据**
    grp("⑧")
    r8 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
               profile_key="standard", fetcher=_fake_ok, query_gap=0.0)
    if len(r8.queries) != len(set(r8.queries)):
        problems.append("检索词重复计数")
    if not r8.queries:
        problems.append("未记录检索词")
    # 每个检索词都必须指向「某个已识别产品」或「目标域名」，
    # 否则说明检索词是凭空生成的（也可能是把证据原文整段塞进了查询串，
    # 那会把目标独有的路径一并泄露给第三方）。
    _anchors = [_name_keyword(n) for n, _e in r8.products] + ["t.example"]
    for q in r8.queries:
        if not any(a.lower() in q.lower() for a in _anchors):
            problems.append(f"检索词既不指向已识别产品也不指向目标：{q!r}")
        if re.search(r"\s/\s|admin123|s3cret|password\d", q, re.I):
            problems.append(f"检索词里疑似混入了凭据：{q!r} —— 绝不能把凭据发给第三方")
    if len(r8.queries) > MAX_QUERIES:
        problems.append(f"检索次数超过披露上限：{len(r8.queries)}")

    # ⑨ 检索到的候选：通过准入的进自动尝试，通不过的必须留在线索里
    grp("⑨")
    r9 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
               profile_key="standard", fetcher=_fake_ok, query_gap=0.0)
    _srcs = {c.source for c in r9.candidates}
    if "公开资料检索" not in _srcs:
        problems.append("联网检索未产出任何候选（摘要里明明有 tomcat/tomcat）")
    for c in r9.candidates:
        if c.auto_attempt and not is_weak_pair(c.account, c.password):
            problems.append(f"放行了不该自动尝试的候选：{c.account}")
        if not c.auto_attempt and not c.hold_reason:
            problems.append(f"候选被拦但无原因：{c.account}")
    if not r9.leads:
        problems.append("检索到内容却没有任何线索产出")

    # ⑩ 线索一律不自动尝试
    grp("⑩")
    for x in r9.leads:
        if not x.why_not_auto:
            problems.append(f"线索 {x.title[:40]!r} 未写明为何不自动尝试")
    if any(x.url and x.url.startswith("//") for x in r9.leads):
        problems.append("线索 URL 仍是未解开的跳转包装")

    # ⑪ 无产品可识别时：零自动尝试候选（不许瞎撞）
    grp("⑪")
    _ev_bare = {"root_probe": {"status": 200, "server": "nginx",
                               "title": "欢迎", "body_snippet": "hello"},
                "path_probes": {"/login": {"reachable": True, "status": 200}}}
    r11 = osint("http://t/", domain="t.example", evidence=_ev_bare,
                profile_key="standard", fetcher=_fake_ok, query_gap=0.0)
    if r11.auto_pairs():
        problems.append(f"未识别出产品却产出了自动尝试候选：{r11.auto_pairs()}")
    if r11.products:
        problems.append(f"空手证据下识别出了产品：{r11.products}")
    _gone = r11.sources.get("本地产品默认口令库") or ""
    if "无适用条目" not in _gone:
        problems.append(f"本地库无条目时未说明原因：{_gone!r}")

    # ⑫ 安全档：零外部请求
    grp("⑫")
    _calls: list[str] = []

    def _spy(url: str) -> str:
        _calls.append(url)
        return _ddg_html

    r12 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
                profile_key="safe", fetcher=_spy)
    if r12.enabled:
        problems.append("安全档不应启用凭据情报")
    if _calls:
        problems.append(f"安全档发出了 {len(_calls)} 次外部请求（应为 0）")
    if not r12.reason:
        problems.append("安全档未执行但没给理由")

    # ⑬ 显式关闭
    grp("⑬")
    _prev = os.environ.get("AISCAN_CREDOSINT")
    os.environ["AISCAN_CREDOSINT"] = "off"
    try:
        r13 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
                    profile_key="deep", fetcher=_spy)
        if r13.enabled or "AISCAN_CREDOSINT" not in (r13.reason or ""):
            problems.append(f"显式关闭未生效或理由不清：{r13.reason!r}")
    finally:
        if _prev is None:
            os.environ.pop("AISCAN_CREDOSINT", None)
        else:
            os.environ["AISCAN_CREDOSINT"] = _prev

    # ⑭ 关闭联网：本地库照常工作，且状态要写「未执行」而不是「失败」
    grp("⑭")
    r14 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
                profile_key="standard", allow_online=False)
    if not r14.auto_pairs():
        problems.append("关闭联网后本地库候选也丢了")
    if "未执行" not in (r14.sources.get("公开资料检索") or ""):
        problems.append(f"关闭联网的状态描述不对：{r14.sources.get('公开资料检索')!r}")
    if r14.queries:
        problems.append("关闭联网却记录了检索词")

    # ⑮ 无固定默认口令的产品 → 说明性线索，而不是硬凑一组口令
    grp("⑮")
    _ev_druid = {
        "root_probe": {"status": 200, "server": "nginx", "title": "Druid Stat",
                       "body_snippet": "Druid Stat Index"},
        "path_probes": {"/druid/index.html": {"reachable": True, "status": 200}},
    }
    r15 = osint("http://t/", domain="t.example", evidence=_ev_druid,
                profile_key="standard", allow_online=False)
    if r15.auto_pairs():
        problems.append(f"Druid 无鉴权场景却产出了口令候选：{r15.auto_pairs()}")
    if not any("无鉴权" in (x.snippet or "") for x in r15.leads):
        problems.append("无固定口令的产品未产出解释性线索")

    # ⑯ to_dict 可序列化（报告要落盘）
    grp("⑯")
    try:
        json.dumps(r9.to_dict(), ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        problems.append(f"to_dict 不可 JSON 序列化：{type(e).__name__}")

    # ⑰ summary_lines 不得出现口令原文
    grp("⑰")
    for line in r9.summary_lines():
        for _c in r9.candidates:
            if _c.password and len(_c.password) >= 4 and _c.password in line:
                problems.append(f"摘要行里出现口令原文：{line[:60]!r}")

    # ⑱ 非公网目标不做外部检索。这既是正确性（对回环地址做公开检索没有意义），
    #     也让引擎自测（目标就是 127.0.0.1）天然保持离线 ——
    #     少一个「记得设环境变量」的隐患。
    grp("⑱")
    _calls18: list[str] = []

    def _spy18(url: str) -> str:
        _calls18.append(url)
        return _ddg_html

    for _bad in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.1.5", "svc.local"):
        if not _looks_non_public(_bad):
            problems.append(f"{_bad!r} 未被识别为非公网地址")
    if _looks_non_public("internal-app.example.com"):
        problems.append("公网域名被误判为非公网（会导致真目标不做检索）")
    r18 = osint(f"http://127.0.0.1/", domain="127.0.0.1", evidence=_ev_tomcat,
                profile_key="standard", fetcher=_spy18)
    if _calls18:
        problems.append(f"对回环地址发出了 {len(_calls18)} 次外部检索（应为 0）")
    _st18 = r18.sources.get("公开资料检索") or ""
    if "未执行" not in _st18:
        problems.append(f"非公网目标应记「未执行」，实际：{_st18!r}")
    if "失败" in _st18:
        problems.append("非公网目标被写成了「检索失败」—— 那是两件不同的事")
    if not r18.auto_pairs():
        problems.append("非公网目标仍应产出本地库候选（识别产品不依赖网络）")

    # ⑲ 检索源限流：必须**认清**（不能混成「没有线索」）且**立即停止后续检索**。
    #     这一条来自真实联调：连打 4 枪时第 2、3 枪就返回 HTTP 202 +
    #     `anomaly` / `challenge`，页面里没有结果条目。老实现会把它归成
    #     「结果页无条目」——读者于是读到「网上没找到」，实际是「没检索成」。
    grp("⑲")
    def _fake_limited(_url: str) -> Any:
        return 202, "<html><body>anomaly detected — please complete the challenge</body></html>"

    _h19, _st19 = search("q", fetcher=_fake_limited)
    if not _st19.startswith("被限流"):
        problems.append(f"限流页未被识别为限流：{_st19!r}")
    if "无条目" in _st19:
        problems.append("限流被归成了「结果页无条目」—— 那是「没检索成」被写成「没有线索」")
    # `robot` 不得作为限流标记：正常结果页里也含这个词（实测），
    # 会反过来把成功页判成限流，整批结果被丢掉。
    if "robot" in _LIMIT_MARKERS:
        problems.append("`robot` 被当作限流标记 —— 正常结果页也含该词，会误杀")
    _spy19: list[str] = []

    def _spy19f(url: str) -> Any:
        _spy19.append(url)
        return _fake_limited(url)

    r19 = osint("http://t/", domain="t.example", evidence=_ev_tomcat,
                profile_key="standard", fetcher=_spy19f, query_gap=0.0)
    if len(_spy19) != 1:
        problems.append(f"命中限流后仍继续检索（共发出 {len(_spy19)} 次；应为 1 次）")
    if "已停止后续检索" not in (r19.sources.get("公开资料检索") or ""):
        problems.append(f"限流后未说明已停止：{r19.sources.get('公开资料检索')!r}")
    if not any("不等于" in x and "网上没有线索" in x for x in r19.notes):
        problems.append("限流时必须写明「这不等于网上没有线索」（否则会被读成检索结论）")
    if not r19.auto_pairs():
        problems.append("限流不应影响本地库候选的产出")

    # ⑳ 反频控间隔必须存在且足够大。实测把间隔去掉后连续检索必被校验，
    #     表现为「检索跑了但什么都没拿到」—— 一个看起来像「没有线索」的假结论。
    grp("⑳")
    if MIN_QUERY_GAP < 3.0:
        problems.append(f"检索间隔过小（{MIN_QUERY_GAP}s）—— 会被检索源判为机器人")
    if MAX_QUERIES > 4:
        problems.append(f"检索次数上限过大（{MAX_QUERIES}）—— 披露成本与限流风险都上升")

    # 末尾核对：清单里声明过的组，是不是每一组都真的跑过了。
    # 少跑一组就报错（且点名是哪一组），不允许「静默少跑」。
    missing = [g for g in _SELFTEST_GROUPS if g not in ran]
    if missing:
        problems.append(f"自测分组未执行：{'、'.join(missing)} —— 少跑的分组不得当通过")

    if problems:
        print("凭据情报自测：失败")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print(f"凭据情报自测：通过（{len(ran)} 组断言，全部执行）")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_selftest())
