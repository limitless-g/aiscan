# -*- coding: utf-8 -*-
"""
网络层探测助手
==============
端口探测、证书透明度日志、公共 DNS、外部服务的原始 HTTP 请求。

说明：这些探测不走 DetectorContext 的缓存（它们不针对目标站点，
而是针对 DNS、crt.sh、nmap 等），单独放在这里便于统一控制超时与并发度。
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

UA = {"User-Agent": "AIScan/1.0 (Authorized Security Assessment)"}
PUBLIC_RESOLVERS = ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"]


# ======================================================================
# 公网可达性判定
# ======================================================================
# 为什么单独做这一层：端口能连通 ≠ 公网暴露。扫描器跑在哪儿是随机的
# （开发机、办公网、云主机），一次 TCP 握手只证明「从我这个位置能连上」。
# 如果目标解析出的是 10.x / 192.168.x 这类私网地址，或者本机就在同一内网，
# 那么写「公网暴露」是把内网可达性冒充成公网暴露 —— 这是最典型的一类
# 假结论，客户按报告去加安全组会发现根本改不动，报告的可信度就此崩塌。
#
# 判定拆成两步，两步都要在报告里写清楚：
#   ① 地址本身是否公网可路由（私网 / 回环 / 保留段一律排除）
#   ② 连通性只声明为「从扫描节点实测」，并注明未做第三方测绘交叉验证
def as_ip_literal(host: str) -> str:
    """目标本身就是 IP 字面量时返回它（已去方括号），否则返回空串。

    为什么必须有这个回退：**裸 IP 目标（内网系统最常见的形态）走 DNS
    永远解析不出 A 记录**，但它的「解析地址」就是目标自身。不回退的后果
    不是少一条信息，而是一连串**假阴性**：

      - 端口扫描整段被跳过 → 报告写「端口探测 0 个，开放 0 个」→
        `WSTG-INFO-04 攻击面识别` 据此判**「通过」**；
      - 而同一份报告的端口覆盖一节里，实测开放的端口一个不少。

    一个「通过」背后没有任何执行支撑，正是本工具最不能犯的错。
    """
    cand = (host or "").strip().strip("[]")
    if not cand:
        return ""
    try:
        ipaddress.ip_address(cand)
        return cand
    except ValueError:
        return ""


def is_public_ip(ip: str) -> bool:
    """该地址是否为公网可路由地址（排除私网 / 回环 / 保留 / 链路本地段）。"""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip.strip().split("%", 1)[0])
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_multicast or a.is_unspecified)


def reachability_of(ip: str, *, node_public: bool | None = None
                    ) -> tuple[str, str, str]:
    """返回（可达性标签, 建议定级修正, 判定依据说明）。

    标签只有两种取值，报告里直接用，不要自己另造措辞：
      - ``公网可达``         目标解析到公网地址，且从本节点实测可连通
      - ``内网可见（非公网暴露）``  解析结果是私网 / 保留地址，或本节点位于内网
    """
    if not ip:
        return ("未取得解析地址", "", "DNS 未返回 A / AAAA 记录，无法判定可达范围。")
    if not is_public_ip(ip):
        return (
            "内网可见（非公网暴露）",
            "调低",
            f"目标解析地址 {ip} 属于私网 / 回环 / 保留网段，"
            "从任何公网位置都不可路由。本节描述的是内网可达性，"
            "不构成公网暴露，也不应计入公网风险统计。",
        )
    extra = ""
    if node_public:
        extra = "；扫描节点位于公网，连通性具备参考价值，但仍建议以公网测绘平台复核。"
    else:
        extra = ("；扫描节点可能位于内网或存在 NAT，"
                 "建议以公网测绘平台（Shodan / FOFA 等）复核后再对外表述为公网暴露。")
    return ("公网可达", "", f"目标解析地址 {ip} 为公网可路由地址，TCP 握手由其本节点实测{extra}")

# ======================================================================
# 端口分级
# ======================================================================
# 一份平铺的端口表有两个问题：一是档位无法表达「这次到底覆盖了多少」，
# 二是多个检测器各自调 scan_ports 会重复扫同一批端口（自测里 614 次探测中
# 有不小一部分是这么浪费掉的）。
# 分级的目的不是「扫得更多」，而是让「覆盖了哪些端口」变成报告里能陈述的事实。
PORT_TIERS: dict[str, list[int]] = {
    # 安全档：只碰最常见的 Web 与远程管理端口
    "safe": [80, 443, 22, 8080, 8443],
    # 标准档：在常见对外服务端口上做一轮覆盖面检查
    "standard": [
        21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636,
        993, 995, 1433, 1521, 2049, 2181, 2375, 2376, 2379, 3000, 3306,
        3389, 4444, 5000, 5432, 5601, 5672, 5900, 6379, 6443, 7001, 8000,
        8009, 8080, 8081, 8443, 8500, 8888, 9000, 9001, 9090, 9200, 9300,
        9418, 10250, 10255, 11211, 15672, 27017, 50000,
    ],
    # 深度档：数据库 / 中间件 / 容器编排 / 大数据 / 常见面板与备份服务
    "deep": [
        21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 139, 143, 161, 389, 443,
        445, 465, 500, 512, 513, 514, 515, 548, 554, 587, 623, 631, 636,
        873, 902, 993, 995, 1025, 1080, 1099, 1158, 1433, 1521, 1527, 1701,
        1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
        2222, 2375, 2376, 2379, 2424, 2480, 3000, 3128, 3260, 3306, 3389,
        3478, 4000, 4040, 4369, 4443, 4444, 4505, 4506, 5000, 5001, 5003,
        5005, 5038, 5044, 5222, 5269, 5280, 5432, 5433, 5555, 5601, 5671,
        5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6380, 6443,
        6444, 7001, 7002, 7070, 7199, 7443, 7474, 7687, 7777, 8000, 8001,
        8008, 8009, 8010, 8042, 8069, 8080, 8081, 8082, 8083, 8086, 8088,
        8090, 8091, 8123, 8161, 8180, 8200, 8300, 8443, 8444, 8500, 8529,
        8530, 8531, 8600, 8686, 8834, 8888, 8899, 8983, 9000, 9001, 9002,
        9021, 9042, 9060, 9080, 9090, 9091, 9092, 9100, 9160, 9200, 9300,
        9418, 9443, 9500, 9600, 9800, 9999, 10000, 10250, 10255, 10256,
        11211, 15672, 16379, 18080, 20000, 25565, 27017, 27018, 28017,
        50000, 50070, 50075, 50090, 61616,
    ],
}

# 服务语义：报告中把「开了什么端口」翻译成「可能是什么服务」才有意义
PORT_SERVICE: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "rpcbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 512: "rexec", 513: "rlogin", 514: "rsh",
    548: "AFP", 554: "RTSP", 587: "SMTP(提交)", 623: "IPMI", 631: "CUPS",
    636: "LDAPS", 873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1099: "Java RMI", 1433: "MSSQL", 1521: "Oracle",
    1883: "MQTT", 2049: "NFS", 2082: "cPanel", 2181: "ZooKeeper",
    2222: "SSH(备用)", 2375: "Docker API(明文)", 2376: "Docker API(TLS)",
    2379: "etcd", 3000: "Node/Web", 3260: "iSCSI", 3306: "MySQL",
    3389: "RDP", 4000: "Web", 4369: "Erlang EPMD", 4444: "Web/Metasploit",
    5432: "PostgreSQL", 5555: "ADB", 5601: "Kibana", 5672: "RabbitMQ",
    5900: "VNC", 5984: "CouchDB", 5985: "WinRM(HTTP)", 5986: "WinRM(HTTPS)",
    6379: "Redis", 6443: "K8s API", 7001: "WebLogic", 7443: "Web", 7474: "Neo4j",
    7687: "Neo4j(Bolt)", 8000: "Web", 8009: "AJP", 8069: "Odoo",
    8080: "HTTP(alt)", 8081: "HTTP(alt)", 8086: "InfluxDB", 8161: "ActiveMQ",
    8200: "Vault", 8443: "HTTPS(alt)", 8500: "Consul", 8529: "ArangoDB",
    8888: "Web/Jupyter", 8983: "Solr", 9000: "Web/FastCGI", 9001: "Web",
    9042: "Cassandra", 9090: "Web/Cockpit", 9092: "Kafka", 9100: "打印服务",
    9200: "Elasticsearch", 9300: "ES 集群", 9418: "Git", 9443: "HTTPS(alt)",
    10000: "Webmin", 10250: "Kubelet", 10255: "Kubelet(只读)",
    11211: "Memcached", 15672: "RabbitMQ 管理", 27017: "MongoDB",
    50000: "SAP", 50070: "HDFS NameNode", 61616: "ActiveMQ",
}

# 一旦暴露即可直接拿数据 / 拿权限的端口（报告据此定级，而不是按端口号定级）
CRITICAL_SERVICES = {"Redis", "MongoDB", "Elasticsearch", "Memcached",
                     "Docker API(明文)", "etcd", "K8s API", "Kubelet",
                     "HDFS NameNode", "CouchDB", "Neo4j", "Vault", "Consul",
                     "ZooKeeper", "Cassandra", "SMB", "NFS", "IPMI", "rsync"}

# 本次扫描的端口覆盖记录：报告要如实写出「扫了哪些档、多少个端口」
_PORT_SCAN_LOG: dict[str, dict[str, Any]] = {}


def ports_for_profile(profile_key: str) -> list[int]:
    """按档位取端口集。未知档位按 standard 处理（宁可多扫，不可漏报）。"""
    key = (profile_key or "standard").lower()
    return list(PORT_TIERS.get(key, PORT_TIERS["standard"]))


# 兼容旧引用：默认端口集 = 标准档
COMMON_PORTS = PORT_TIERS["standard"]


# ----------------------------------------------------------------------
# 端口归属表：一个端口只能有一个「上报出口」
# ----------------------------------------------------------------------
# 为什么需要这张表：同一份报告里，同一个端口会被多个检查项各报一次。
# 真实目标上 5432 / 9200 曾被 WSTG-INFO-04（攻击面识别）、EXT-CL-02
# （非预期端口暴露）、EXT-DM-05（邮件与门户端口）三个项各报一次，四条发现
# 标题几乎一样、指向同一对 IP:端口。读者会把「端口个数」当成「漏洞个数」，
# 报告看起来漏洞很多，实际只有一处需要收口。
#
# 所以这里显式规定归属：**只有 owner 对应的检查项**可以就这个端口产出发现，
# 其他检查项最多在 note 里提及（保留「扫过」这个执行证据，不重复计数）。
# 归属原则：谁给的证据更强 / 谁的业务范围就是这类服务，谁当 owner。
#   · 邮件协议（25/110/143/465/587/993/995）→ EXT-DM-05（本项就是为邮件暴露而设）
#   · 容器 / 编排管理接口 → EXT-CL-03（有 HTTP 响应证据，强于单纯 TCP 可达）
#   · K8s 控制面 → EXT-CL-04（有 /version 与 API 路径证据）
#   · 其余一切非 80/443 端口 → EXT-CL-02（通用出口，兜底不让任何端口没人管）
PORT_OWNER: dict[int, str] = {
    25: "EXT-DM-05", 110: "EXT-DM-05", 143: "EXT-DM-05",
    465: "EXT-DM-05", 587: "EXT-DM-05", 993: "EXT-DM-05", 995: "EXT-DM-05",
    2375: "EXT-CL-03", 2376: "EXT-CL-03", 2379: "EXT-CL-03", 9000: "EXT-CL-03",
    5000: "EXT-CL-03", 8500: "EXT-CL-03", 15672: "EXT-CL-03",
    6443: "EXT-CL-04", 10250: "EXT-CL-04", 10255: "EXT-CL-04",
}
DEFAULT_PORT_OWNER = "EXT-CL-02"


def port_owner(port: int) -> str:
    """该端口唯一的「上报出口」检查项 ID。

    未登记的端口一律归 EXT-CL-02 —— 兜底必须是显式的，
    否则「排除掉别人的端口」会顺手把没人管的端口也一起排掉，
    变成探测到了却不上报的假阴性。
    """
    return PORT_OWNER.get(int(port), DEFAULT_PORT_OWNER)


def tcp_open(host: str, port: int, timeout: float = 2.5) -> bool:
    """TCP 连通性探测。只做三次握手，不发应用层数据。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


# ----------------------------------------------------------------------
# TCP 连通信号的「对照实验」
# ----------------------------------------------------------------------
# 上面那一层排除了「目标地址本身是私网」，但还有一类更隐蔽的假象：
# **本机到目标的 TCP 连接被中间设备透明接管**。
# 沙箱代理、企业安全客户端、出口 NAT 网关都可能对任意 connect() 直接
# 返回成功而不真正建连 —— 结果是**每个端口都「开放」**。
#
# 实测踩过这个坑：某目标 IP 的 49999 / 54321 / 65001 三个高位端口
# 全部报「可连接」，而**同网段的无关 IP** 也全开，说明并不是目标开了端口，
# 而是本机发出的连接根本没出去。当时扫描器据此写出了
# 「严重：公网可达，10 个不应开放的端口可直连」—— 整条发现是误报。
#
# 判据因此必须带对照：在**正常主机上必然关闭**的端口上做同样的探测，
# 若它们也报「可连接」，则本机对该目标的端口连通性整体不可采信。
_TCP_SANITY_PORTS: tuple[int, ...] = (49999, 54321, 65001)

# 每台主机的对照结论缓存 {host: {...}}，避免每个检测器重复探测。
TCP_SIGNAL_LOG: dict[str, dict[str, Any]] = {}


def tcp_signal_trustworthy(host: str, timeout: float = 2.5) -> tuple[bool, str]:
    """判定「本机到该主机的 TCP 连通信号」是否可信。

    做法：探测若干个在正常主机上**必然关闭**的高位端口。只要其中任意一个
    报告「可连接」，这些连接就没有到达目标主机本身，而是被中间设备接管了，
    此后所有端口结论一律不可采信。

    返回 (是否可信, 依据文本)。结论按 host 缓存。
    """
    if host in TCP_SIGNAL_LOG:
        rec = TCP_SIGNAL_LOG[host]
        return bool(rec["trustworthy"]), str(rec["evidence"])

    falsely_open = [p for p in _TCP_SANITY_PORTS if tcp_open(host, p, timeout=timeout)]
    if falsely_open:
        ok = False
        evidence = (
            f"对照端口实验：在正常主机上必然关闭的端口 "
            f"{'、'.join(str(p) for p in falsely_open)} 报「可建立 TCP 连接」。"
            f"说明本机到 {host} 的连接被中间设备（沙箱代理 / 安全客户端 / "
            f"出口网关）透明接管，并未真正到达目标主机 —— "
            f"本次端口连通性结论整体不可采信。")
    else:
        ok = True
        evidence = (
            f"对照端口实验：{'、'.join(str(p) for p in _TCP_SANITY_PORTS)} "
            f"均不可连接（符合这些端口不监听的预期），"
            f"本机到 {host} 的 TCP 连通信号可信。")
    TCP_SIGNAL_LOG[host] = {
        "trustworthy": ok, "evidence": evidence, "open": falsely_open,
        "sanity_ports": list(_TCP_SANITY_PORTS), "checked": True,
    }
    return ok, evidence


def tcp_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """尝试读取服务欢迎横幅（仅对主动问候类服务有效）。"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                return data.decode("utf-8", "replace").strip()[:200]
            except Exception:  # noqa: BLE001
                return ""
    except Exception:  # noqa: BLE001
        return ""


def service_of(port: int) -> str:
    return PORT_SERVICE.get(port, "未知服务")


#: 端口探测的**档位声明值**（本机侧还会再被资源预算封一次，取更小者）。
#: 与 HTTP 路径探测分开设：端口探测是纯 TCP 连接、不产生 HTTP 语义，
#: 单次开销小得多，可以比 HTTP 并发略高一点。
_PORT_WORKERS_DECLARED = 24


def scan_ports(host: str, ports: list[int] | None = None,
               workers: int | None = None) -> dict[int, bool]:
    """并发 TCP 端口探测。

    `workers=None` 时取本机资源预算的并发上限（见 `engine/resources.py`）——
    端口探测是纯 socket 连接，**不开线程池就会把 174 个端口串行扫一遍**，
    但开太大同样会把本机连接表与 CPU 打满。默认交给预算模块统一决策。
    """
    ports = ports or PORT_TIERS["standard"]
    if workers is None:
        try:
            from engine import resources as _res  # noqa: PLC0415
            workers = _res.cap_workers(_PORT_WORKERS_DECLARED)
        except Exception:  # noqa: BLE001
            workers = _PORT_WORKERS_DECLARED
    out: dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as ex:
        futs = {ex.submit(tcp_open, host, p): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                out[p] = fut.result()
            except Exception:  # noqa: BLE001
                out[p] = False
    return out


def scan_ports_cached(host: str, profile_key: str = "standard",
                      workers: int | None = None) -> dict[int, bool]:
    """按 (主机, 档位) 缓存的端口扫描。

    多个检测器都关心「目标开了哪些端口」，各扫一遍会让探测次数成倍增长、
    也会给目标造成不必要的连接压力。这里做一次全扫描共享，
    同时把「本次覆盖了哪些端口」记进 _PORT_SCAN_LOG —— 报告必须能说清覆盖范围，
    否则「未发现开放端口」和「没扫」在读者眼里没有区别。
    """
    key = host
    cached = _PORT_SCAN_LOG.get(key)
    ports = ports_for_profile(profile_key)
    if cached and cached.get("profile") == (profile_key or "standard"):
        return cached["result"]                                   # type: ignore[return-value]

    result = scan_ports(host, ports, workers=workers)
    # 对照实验必须先做，并把结论随端口结果一起留痕：报告要能解释
    # 「这些开放端口为什么可信 / 为什么不可信」，否则下一次又会有人
    # 直接把 TCP 连通当成公网暴露。
    signal_ok, signal_why = tcp_signal_trustworthy(host)
    _PORT_SCAN_LOG[key] = {
        "host": host,
        "profile": profile_key or "standard",
        "scanned": len(ports),
        "open": sorted(p for p, ok in result.items() if ok),
        "signal_trustworthy": signal_ok,
        "signal_evidence": signal_why,
        "result": result,
    }
    return result


def port_scan_log() -> dict[str, dict[str, Any]]:
    """本次运行的端口扫描覆盖记录（不含 result 大对象）。"""
    return {k: {kk: vv for kk, vv in v.items() if kk != "result"}
            for k, v in _PORT_SCAN_LOG.items()}


def nmap_available() -> str:
    return shutil.which("nmap") or ""


def nmap_scan(host: str, ports: list[int] | None = None, timeout: int = 180) -> dict[int, str]:
    """用 nmap 做服务识别（可用时优先，结果比裸 TCP 探测信息量更大）。"""
    exe = nmap_available()
    if not exe:
        return {}
    port_arg = ",".join(str(p) for p in (ports or COMMON_PORTS))
    cmd = [exe, "-Pn", "-sV", "--version-light", "-T3",
           "--host-timeout", "150s", "-p", port_arg, "-oX", "-", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
        out: dict[int, str] = {}
        for m in re.finditer(
            r'<port protocol="tcp" portid="(\d+)".*?<state state="open".*?'
            r'(?:<service name="([^"]*)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?)?',
            proc.stdout or "", re.S):
            p = int(m.group(1))
            parts = [x for x in (m.group(2), m.group(3), m.group(4)) if x]
            out[p] = " ".join(parts) or "open"
        return out
    except Exception:  # noqa: BLE001
        return {}


def http_json(url: str, timeout: int = 25) -> Any:
    """对一个外部服务发 GET 并解析 JSON（用于 crt.sh 等）。"""
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return None


def http_text(url: str, timeout: int = 20, data: bytes | None = None,
              extra_headers: dict[str, str] | None = None) -> str:
    """对外部服务发 GET / POST，返回正文（用于搜索引擎与厂商接口）。"""
    try:
        h = dict(UA)
        h.update(extra_headers or {})
        req = urllib.request.Request(url, headers=h, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()[:200_000].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def crtsh_subdomains(domain: str, timeout: int = 35) -> list[str]:
    """单源（crt.sh）枚举。保留这个名字是为了兼容既有调用点。"""
    return ct_subdomains(domain, timeout=timeout)["subs"]


def ct_subdomains(domain: str, timeout: int = 20) -> dict[str, Any]:
    """证书透明度 / 公开情报多源枚举子域。

    为什么必须多源
    --------------
    只有一个 crt.sh 时，「取不到子域」这一个现象背后有**两种完全不同的
    原因**，而它们对报告的含义相反：

      · crt.sh 这个站本身不可达 / 限流 → 我们的采集通道有问题，
        结论应当是「未能确认」，而不是「目标没有暴露子域」；
      · 所有源都通、但确实没有签发记录 → 这才是关于目标的事实。

    单源实现把两者混成同一句「可能有也可能没有」，读的人只能靠猜。
    这里把所有源的可用性一并返回，让上层能分开写。

    四个源都是公开、无需凭据的 HTTPS 接口，且都只做 GET。
    """
    subs: set[str] = set()
    #: 源名 -> 「命中 N 条」或「不可达」
    sources: dict[str, str] = {}
    d = (domain or "").strip().lower()
    if not d:
        return {"subs": [], "sources": {}, "reachable": 0}

    def _keep(name: str) -> None:
        n = (name or "").strip().lstrip("*.").lower()
        if n.endswith(d) and " " not in n and n:
            subs.add(n)

    # ---- 1) crt.sh（JSON）----
    try:
        data = http_json(f"https://crt.sh/?q=%25.{d}&output=json", timeout=timeout)
        got = 0
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                for name in str(row.get("name_value", "")).split("\n"):
                    before = len(subs)
                    _keep(name)
                    got += len(subs) - before
        sources["crt.sh"] = f"命中 {got} 条" if isinstance(data, list) else "无有效响应"
    except Exception:  # noqa: BLE001
        sources["crt.sh"] = "不可达"

    # ---- 2) Cert Spotter（JSON，独立于 crt.sh 的 CT 聚合）----
    # crt.sh 单点故障的互补源：两者都挂的概率远低于任一单挂。
    try:
        data = http_json(
            "https://api.certspotter.com/v1/issuances"
            f"?domain={d}&include_subdomains=true&expand=dns_names",
            timeout=timeout)
        got = 0
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                for name in (row.get("dns_names") or []):
                    before = len(subs)
                    _keep(str(name))
                    got += len(subs) - before
        sources["certspotter"] = f"命中 {got} 条" if isinstance(data, list) else "无有效响应"
    except Exception:  # noqa: BLE001
        sources["certspotter"] = "不可达"

    # ---- 3) HackerTarget hostsearch（纯文本 CSV）----
    try:
        txt = http_text(
            f"https://api.hackertarget.com/hostsearch/?q={d}", timeout=timeout)
        got = 0
        if txt and "API count exceeded" not in txt and "<html" not in txt[:200].lower():
            for line in txt.splitlines():
                if "," in line:
                    before = len(subs)
                    _keep(line.split(",", 1)[0])
                    got += len(subs) - before
            sources["hackertarget"] = f"命中 {got} 条"
        else:
            sources["hackertarget"] = "无有效响应 / 配额耗尽"
    except Exception:  # noqa: BLE001
        sources["hackertarget"] = "不可达"

    # ---- 4) 域名自身的 DNS 记录（兜底：至少确认主域存在）----
    try:
        if dns_records(d, "A") or dns_records(d, "CNAME"):
            subs.add(d)
            sources["公共 DNS（主域）"] = "存在"
        else:
            sources["公共 DNS（主域）"] = "无 A/CNAME 记录"
    except Exception:  # noqa: BLE001
        sources["公共 DNS（主域）"] = "查询失败"

    reachable = sum(1 for v in sources.values()
                    if v not in ("不可达", "查询失败"))
    return {"subs": sorted(subs)[:300], "sources": sources, "reachable": reachable}


def dns_records(name: str, rtype: str) -> list[str]:
    """走公共递归查询指定记录类型，多解析器交叉。"""
    out: set[str] = set()
    try:
        import dns.resolver  # type: ignore
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = PUBLIC_RESOLVERS
        r.lifetime = 6
        for ans in r.resolve(name, rtype):
            out.add(str(ans).strip('"'))
    except Exception:  # noqa: BLE001
        pass
    return sorted(out)


def zone_transfer_attempt(domain: str) -> list[str]:
    """尝试对权威 NS 做区域传送（AXFR）。成功的服务器等于把内网结构直接送出。"""
    names: list[str] = []
    try:
        import dns.query  # type: ignore
        import dns.zone  # type: ignore
        nss = dns_records(domain, "NS")
        for ns in nss[:4]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=8, lifetime=12))
                names += [f"{n}.{domain}".rstrip(".") for n in z.nodes.keys()]
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return sorted(set(names))[:500]
