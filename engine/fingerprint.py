# -*- coding: utf-8 -*-
"""
L1 资产测绘与目标特征识别
=========================
职责：对目标做被动 + 轻量主动探测，产出一份 TargetFeatures，驱动后续的
      适用性判定（N/A 生成）与检查项选型。

硬约束（规格第 7 章）：
  - 一律公网视角。DNS 走公共递归并交叉验证，排除 split-horizon。
  - 不以本机网络可达性推断目标真实暴露。
  - 探测本身要轻：默认只发 GET / HEAD，不做破坏性请求。
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

ROOT = Path(__file__).resolve().parent.parent
import sys  # noqa: E402

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.applicability import TargetFeatures  # noqa: E402
# 「整站同一响应」守卫与拦截页归一化都在 wafgate 里，它只依赖标准库，
# 不会与 fingerprint 形成循环导入。
from engine.wafgate import (  # noqa: E402
    SITEWIDE_DOMINANCE,
    SITEWIDE_MIN_SAMPLES,
    SITEWIDE_STATUSES,
    detect_block_page,
    representative_probe,
    sitewide_uniform_body,
    sitewide_uniform_status,
    status_mix,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PUBLIC_RESOLVERS = ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"]

# 安全测试标识 UA —— 让目标方在日志里能识别这是授权扫描
SCAN_UA = "AIScan/1.0 (Authorized Security Assessment)"

DEFAULT_HEADERS = {
    "User-Agent": SCAN_UA,
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

# 探测阶段允许的方法：全部为只读语义，不含任何副作用
# OPTIONS 虽非 GET/HEAD，但仅返回 Allow 等元信息，用于判断危险方法是否被声明
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _host_of(url: str) -> str:
    """从 URL 取「主机:端口」作为单主机限速的键。

    必须是**归一化**的键：同一个主机可能以 `https://a.com` / `https://a.com:443`
    / `https://A.COM/` 三种写法出现，不做归一化就会各占一个 slot，
    单主机限速形同失效（三条通道各自宽松，合起来还是三倍速率）。
    端口按 scheme 补默认值，统一小写。
    """
    u = (url or "").strip()
    if not u:
        return ""
    try:
        p = urlparse(u)
    except Exception:  # noqa: BLE001
        return ""
    host = (p.hostname or "").lower()
    if not host:
        return ""
    port = p.port
    if port is None:
        port = 443 if (p.scheme or "").lower() == "https" else 80
    return f"{host}:{port}"

# 常规探测只留前 4000 字符：绝大多数判据（状态码 / 标题 / 特征串 / 哈希）
# 都在这个长度内，留全文只会让内存与证据体积失控。
BODY_SNIPPET_CHARS = 4000

# 静态前端产物（JS / CSS）是例外：压缩后的产物动辄几百 KB 到数 MB，
# 组件 banner、sourceMappingURL、接口地址、动态 chunk 引用全都散布在
# 正文各处，只留前 4000 字符等于什么都没读到 ——
# 「抓到了脚本」与「从脚本里读出了东西」是两件事，前者不产生任何结论。
# 实测依据（缺陷 D5）：Juice Shop main.js 1.2MB，关键注入端点
# /rest/products/search 出现在 70% 处（offset 846857），600KB 上限会把它
# 整段切掉且无任何痕迹 —— 截断必须可见（body_truncated），上限取 2.5MB
# （覆盖现实 SPA 主包的常见体量；超限仍截断，但一定留痕）。
ASSET_BODY_MAX_CHARS = 2_500_000


# ==============================================================================
# DNS：公共递归交叉解析
# ==============================================================================
@dataclass
class DnsResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    consistent: bool = True
    per_resolver: dict[str, list[str]] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "ips": self.ips,
            "cnames": self.cnames,
            "consistent": self.consistent,
            "per_resolver": self.per_resolver,
            "error": self.error,
        }


class PublicDnsResolver:
    """用指定公共 DNS 服务器解析，交叉比对结果。"""

    def __init__(self, resolvers: list[str] | None = None, timeout: float = 6.0):
        self.resolvers = resolvers or PUBLIC_RESOLVERS
        self.timeout = timeout

    def resolve(self, domain: str) -> DnsResult:
        res = DnsResult(domain=domain)
        try:
            import dns.resolver
        except ImportError:
            res.error = "缺少 dnspython，退回系统解析（无法交叉验证）"
            try:
                res.ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
            except Exception as e:  # noqa: BLE001
                res.error = f"系统解析失败：{type(e).__name__}"
            return res

        for rtype in ("A", "CNAME"):
            for svr in self.resolvers:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [svr]
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                try:
                    ans = resolver.resolve(domain, rtype)
                    vals = sorted(str(r.target if rtype == "CNAME" else r) for r in ans)
                except Exception:  # noqa: BLE001
                    vals = []
                if vals:
                    res.per_resolver[f"{svr}/{rtype}"] = vals
                    if rtype == "A":
                        res.ips = sorted(set(res.ips) | set(vals))
                    else:
                        res.cnames = sorted(set(res.cnames) | set(vals))

        # 交叉验证：不同解析器对 A 记录是否一致
        a_sets = [
            set(v) for k, v in res.per_resolver.items() if k.endswith("/A") and v
        ]
        if len(a_sets) > 1:
            res.consistent = len(set.union(*a_sets)) == len(set.intersection(*a_sets))
        return res


# ==============================================================================
# HTTP 基础探测
# ==============================================================================

def disable_ambient_proxy() -> list[str]:
    """禁止扫描流量走环境里配置的代理。**必须在任何 HTTP 客户端创建前调用。**

    为什么这不是小事 —— requests 默认 `trust_env=True`，会读取
    `HTTP_PROXY` / `HTTPS_PROXY`。只要运行环境里存在代理（CI 沙箱、公司
    上网代理、抓包工具、终端安全软件），**全部扫描流量都会经过它**，后果有四条：

      ① **响应可被改写** → 所有基于内容的结论不再可信；
      ② 代理转发常使用**绝对形式请求行**（`GET http://host/path HTTP/1.1`），
         一部分服务端（含 Python `http.server`）会把整串当路径，直接 404 ——
         现象是「所有路径都打不开」，极易被误判成「目标没有该功能」；
      ③ 目标侧看到的来源 IP 变成代理的，与「公网基线」判定直接冲突；
      ④ 把目标流量送进一个未经授权的第三方，本身就越界。

    返回被清理掉的变量名，便于在报告/日志里留痕。
    """
    removed: list[str] = []
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
              "ALL_PROXY", "all_proxy"):
        if os.environ.pop(k, None) is not None:
            removed.append(k)
    # NO_PROXY 是「让 urllib/requests 主动绕过代理」的开关。
    # 模块级 requests.get/post 会自建 Session 且 trust_env=True，
    # 只有这一条能覆盖到它们。
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"
    return removed


# 导入即生效：本模块是 HTTP 能力的入口，所有客户端都由它派生。
PROXY_ENV_REMOVED = disable_ambient_proxy()


@dataclass
class HttpProbe:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    body_snippet: str = ""
    server: str = ""
    cookies: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0
    error: str = ""
    final_url: str = ""
    # 正文是否被 max_body 截断。「截了却没说」会让下游把「后半段没有」
    # 读成「目标上没有」（缺陷 D5：截断点之后的接口地址整批静默丢失）。
    body_truncated: bool = False

    @property
    def reachable(self) -> bool:
        return self.status > 0 and not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "server": self.server,
            "title": self.title,
            "cookies": self.cookies,
            "redirect_chain": self.redirect_chain,
            "tls": self.tls,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "headers": self.headers,
            # 正文片段要带上：边界防护判定需要用**一批已探测路径**的正文
            # 做一致性对照（整站是否返回同一张页面）。不带正文就只能靠
            # 一次额外的根路径重取，那一枪打飞整个边界结论就翻了。
            # 截断到 1200 字符足够做特征匹配与哈希比对，不至于把 JSON 撑大。
            "body_snippet": (self.body_snippet or "")[:1200],
            "body_truncated": self.body_truncated,
        }


class HttpProbeClient:
    """受限 HTTP 客户端：限速、超时、不发写请求。"""

    def __init__(self, profile: dict[str, Any] | None = None):
        self.profile = profile or {}
        rate = self.profile.get("rate", {})
        self.timeout = rate.get("timeout_seconds", 12)
        self.rps = rate.get("requests_per_second", 20)
        #: 单主机速率上限。**此前这个字段在代码里没有任何读取点** ——
        #: 档位写着 `per_host_rps: 3`，实际完全没生效（典型的「配了却没人读」，
        #: 它比字段缺失更坏：给的是虚假保证）。2026-09-30 补齐。
        #:
        #: 语义与全局限速**并存**，不是二选一：全局管「整场总压力」，
        #: 单主机管「别把某一个主机打急」。两者各自独立预约 slot，
        #: 一次请求要同时等到两个通道放行才发出。
        #:
        #: 为什么需要它：目标站常见「同一域名下挂多个后端 / 多子域」，
        #: 全局 20 rps 平摊到 5 个主机可能很轻，但全部压在同一个主机上
        #: （目录枚举、路径探测天然集中在主站）就会触发该主机自己的频控。
        self.per_host_rps = float(rate.get("per_host_rps", 0) or 0)
        self.verify_tls = False  # 扫描场景下允许自签证书，但要记录证书信息
        self._last = 0.0
        #: 下一个允许发出的**时刻**（slot 预约模型）。
        #: 与旧实现的区别见 `_throttle`：旧实现记「上次几点发的」，多线程下
        #: 每个线程都读到同一个旧值、同时判定「间隔够了」，瞬时速率被并发数
        #: 放大；预约模型下每个线程领走一个独立 slot，**总速率恒等于 rps**。
        self._next_slot = 0.0
        #: 每个主机各自的「下一个允许发出的时刻」。键是主机名（含端口）。
        self._host_slots: dict[str, float] = {}
        #: 保护 slot 预约的锁。并发路径（`_fetch_stateless`）与串行路径
        #: （`fetch`）共用同一条限速通道，必须互斥。
        self._throttle_lock = threading.Lock()
        self.session = requests.Session()
        # 双保险：即使环境变量在运行期被重新注入，这个 Session 也不读它。
        self.session.trust_env = False
        self.session.headers.update(DEFAULT_HEADERS)

    def _throttle(self, url: str = "") -> None:
        """限速。**线程安全，并发与串行走同一条通道、共用同一个锁。**

        `url` 用于识别主机（单主机通道按主机分别预约 slot）。
        传空字符串时只走全局通道 —— 调用方应当尽量传 URL。

        用「预约下一个 slot」而不是「距上次过了多久」：后者在并发下会被击穿 ——
        8 个线程同时读到同一个旧 `_last`、同时判定「间隔够了」，于是一起发出去，
        瞬时速率变成 8×rps。预约模型下每个线程领走独立 slot，
        **总速率恒等于 `self.rps`，与并发度无关**。

        这一点直接关系到封禁：目标（阿里云 WAF）是按请求量触发拦截的 ——
        本项目实测过一次「停流量十几分钟自行恢复」的窗口型封禁，而指纹阶段
        一批几十个路径正是流量最密集的那一段。

        2026-09-30 修：`_fetch_stateless`（并发路径）此前**完全不调用本函数**。
        后果是双重的：档位的 `requests_per_second` 对这段无效；
        更严重的是 `banguard.apply_speed()` 只改 `self.rps`，**退避恢复后的降速
        对这一整段也无效** —— 一个静默失效的降级（红线：降级必须能被说出名字）。
        `fetch_asset` 的注释写着「与 fetch() 走同一条限速通道…不会绕过退避」，
        而真正绕过的正是这条并发通道。

        2026-09-30 补：`per_host_rps` 接进来。此前该字段在代码里**零读取点**，
        档位写 `per_host_rps: 3` 却从未生效 —— 属于「配了却没人读」，
        比字段缺失更坏，因为它给出的是虚假保证。现在两条通道各自独立预约：
        全局限总压力、单主机限「别把某个主机打急」。
        """
        if self.rps <= 0 and self.per_host_rps <= 0:
            return
        host = _host_of(url)
        gap = (1.0 / self.rps) if self.rps > 0 else 0.0
        host_gap = (1.0 / self.per_host_rps) if (self.per_host_rps > 0 and host) else 0.0
        with self._throttle_lock:
            now = time.time()
            if gap > 0:
                slot = max(now, self._next_slot)
                self._next_slot = slot + gap
                self._last = slot
            else:
                slot = now
            wait = slot - now
            if host_gap > 0:
                hslot = max(now, self._host_slots.get(host, 0.0))
                self._host_slots[host] = hslot + host_gap
                # 取两者**更晚**的那个：单主机通道比全局更紧时以单主机为准。
                # 全局 slot 已经按 gap 递推过了，所以「等得更久」不会让全局超速。
                wait = max(wait, hslot - now)
        # sleep 必须在锁外 —— 放进锁里会让并发线程排队，并发度退化成 1，
        # probe_many 的意义就没了（那是为了不把目标打挂才限的并发）。
        if wait > 0:
            time.sleep(wait)

    def fetch(
        self,
        url: str,
        method: str = "GET",
        allow_redirects: bool = True,
        timeout: float | None = None,
        max_body: int = BODY_SNIPPET_CHARS,
        extra_headers: dict[str, str] | None = None,
    ) -> HttpProbe:
        method = method.upper()
        if method not in SAFE_METHODS:
            raise ValueError(f"探测阶段只允许 {SAFE_METHODS}，收到 {method}")

        probe = HttpProbe(url=url)
        self._throttle(url)
        t0 = time.time()
        try:
            resp = self.session.request(
                method,
                url,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_tls,
                stream=False,
                # 逐请求合并，不改 Session 全局头 —— 绕过试探（wafbypass）
                # 需要对单个请求换 UA / 伪造来源头，但扫描其余部分必须
                # 保持一致的指纹。
                headers=dict(extra_headers) if extra_headers else None,
            )
            probe.elapsed_ms = int((time.time() - t0) * 1000)
            probe.status = resp.status_code
            probe.final_url = resp.url
            probe.headers = {k: v for k, v in resp.headers.items()}
            probe.server = resp.headers.get("Server", "")
            probe.cookies = list(resp.cookies.keys())
            probe.redirect_chain = [h.url for h in resp.history] + [resp.url]
            # 用显式解码，而非库默认（目标是 text/* 且未声明 charset 时，
            # 库默认会把 UTF-8 中文解成乱码，导致中文特征判据集体失效）
            body = self.decode_body(resp)
            probe.body_truncated = len(body) > max(0, int(max_body))
            probe.body_snippet = body[:max(0, int(max_body))]
            probe.title = self._extract_title(body)
            if url.lower().startswith("https"):
                probe.tls = self.inspect_tls(url)
        except requests.exceptions.SSLError as e:
            probe.error = f"TLS 错误：{str(e)[:160]}"
        except requests.exceptions.Timeout:
            probe.error = "请求超时"
        except requests.exceptions.ConnectionError as e:
            probe.error = f"连接失败：{str(e)[:160]}"
        except Exception as e:  # noqa: BLE001
            probe.error = f"{type(e).__name__}: {str(e)[:160]}"
        return probe

    def fetch_asset(self, url: str, max_bytes: int = ASSET_BODY_MAX_CHARS) -> HttpProbe:
        """取静态前端产物正文（保留全文，而非前 4000 字符）。

        与 `fetch()` 走同一条限速通道 —— 封禁守卫调整的是 `self.rps`，
        这里照样吃节流，不会绕过退避。仍然只发 GET。

        仅用于 JS / CSS 这类**公开静态资源**：它们不含用户数据，
        体积大、判据分散在正文各处，截断就等于没读。
        """
        return self.fetch(url, max_body=min(int(max_bytes), ASSET_BODY_MAX_CHARS))

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

    @staticmethod
    def decode_body(resp: Any) -> str:
        """按响应体真实编码解码，而不是无条件用库的默认。

        为什么必须显式做这件事
        ------------------------------------------------------------------
        HTTP 对 `text/*` 类型的默认编码是 ISO-8859-1。目标只要**没在
        Content-Type 里声明 charset**（大量内网系统、老系统、静态文件都如此），
        `resp.text` 就会把 UTF-8 字节按 Latin-1 解出来：中文标题「管理后台」
        变成 `ç®¡çå°`。

        后果不是「显示难看」，而是**判定集体失效**：所有靠中文关键词的判据
        （页面标题含「管理 / 后台 / 控制台」、报错页含「错误 / 异常」、
        敏感提示含「密码 / 身份证」……）在乱码文本上永远匹配不到。
        这类漏报没有任何报错信号 —— 检测器跑了、也没崩，只是永远不命中。

        解码顺序（先严后宽）：
          ① 目标自己声明了 charset → 尊重目标声明（它最清楚自己是什么编码）
          ② 未声明 → 先试 UTF-8（现代系统的绝对主流）
          ③ 再试 GB18030（覆盖 GBK / GB2312，中文老系统的常见编码）
          ④ 都不行 → 退回库默认，并保留 errors="replace" 不抛异常

        注意：这里**只解码、不截断**。曾经这里藏着截到 20 万字符的第二层
        截断（缺陷 D5 的第二坑）：`fetch_asset` 配了 2.5MB 上限，但正文
        在进入它之前就被 decode_body 切成 200KB —— 配置没人读、截断
        无痕迹、main.js 70% 处的注入端点整段丢失。截断的职责统一收口
        到 `fetch(max_body)`（它会置 body_truncated 留痕）。
        """
        declared = ""
        try:
            declared = (resp.headers.get("Content-Type") or "").lower()
        except Exception:  # noqa: BLE001
            pass
        raw = getattr(resp, "content", None)
        if raw is not None and "charset" not in declared:
            for enc in ("utf-8", "gb18030"):
                try:
                    text = raw.decode(enc)
                    # UTF-8 解码成功不代表解对了（GBK 字节也可能恰好是合法 UTF-8），
                    # 但乱码特征里最常见的替换字符足以排除大半误判。
                    if "\ufffd" not in text:
                        return text
                except (UnicodeDecodeError, LookupError):
                    continue
        try:
            return resp.text or ""
        except Exception:  # noqa: BLE001
            return ""

    def inspect_tls(self, url: str) -> dict[str, Any]:
        """读取证书与 TLS 版本信息（不校验证书链，仅采集事实）。"""
        info: dict[str, Any] = {}
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port or 443
        if not host:
            return info
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info["protocol"] = ssock.version()
                    cert = ssock.getpeercert()
                    info["cipher"] = (ssock.cipher() or [None])[0]
                    if cert:
                        info["subject"] = dict(x[0] for x in cert.get("subject", []))
                        info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                        info["not_after"] = cert.get("notAfter", "")
                        info["alt_names"] = cert.get("subjectAltName", [])
        except Exception as e:  # noqa: BLE001
            info["error"] = f"{type(e).__name__}: {str(e)[:120]}"
        return info

    def probe_path(self, base: str, path: str) -> HttpProbe:
        return self.fetch(urljoin(base.rstrip("/") + "/", path.lstrip("/")))

    def probe_many(self, base: str, paths: list[str]) -> dict[str, HttpProbe]:
        """并发探测多个路径。

        串行探测 57 个路径在限速 5rps 下要 12 秒以上，而目标通常有几百个路径 ——
        必须并发。并发度受档位的 concurrency 约束，避免把目标打挂。

        注意：requests.Session 不是线程安全的，并发分支中改用无状态 requests.get，
        并由信号量控制并发度。
        """
        out: dict[str, HttpProbe] = {}
        if not paths:
            return out

        workers = min(
            int(self.profile.get("rate", {}).get("concurrency", 8) or 8),
            len(paths),
            16,
        )
        # 本机侧再封一次。档位的 concurrency 管的是「别把目标打挂」，
        # 这里管的是「别把这台电脑的 CPU 吃满」—— 两个约束方向不同，取更小者。
        try:
            from engine import resources as _res  # noqa: PLC0415
            workers = max(1, min(workers, _res.budget().worker_cap))
        except Exception:  # noqa: BLE001
            pass
        if workers <= 1:
            for p in paths:
                out[p] = self.probe_path(base, p)
            return out

        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        sem = threading.Semaphore(workers)

        def _one(path: str) -> tuple[str, HttpProbe]:
            with sem:
                return path, self._fetch_stateless(
                    urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                )

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_one, p) for p in paths]
            for fut in as_completed(futures):
                try:
                    path, probe = fut.result()
                    out[path] = probe
                except Exception as e:  # noqa: BLE001
                    out[f"__error_{len(out)}"] = HttpProbe(
                        url=base, error=f"{type(e).__name__}: {str(e)[:100]}"
                    )
        return out

    def _fetch_stateless(self, url: str, method: str = "GET") -> HttpProbe:
        """无状态请求（线程安全），用于并发探测。

        ⚠ **必须走 `_throttle()`**：本函数是并发通道，它一样在打被测目标。
        少了这一步，档位限速与封禁退避后的降速都管不到这一段
        （2026-09-30 修，见 `_throttle` 的说明）。
        与 `fetch()` 同样只允许安全方法 —— 并发不是放宽方法约束的理由。
        """
        method = method.upper()
        if method not in SAFE_METHODS:
            raise ValueError(f"探测阶段只允许 {SAFE_METHODS}，收到 {method}")
        probe = HttpProbe(url=url)
        self._throttle(url)
        t0 = time.time()
        try:
            resp = requests.request(
                method, url,
                headers=DEFAULT_HEADERS,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_tls,
            )
            probe.elapsed_ms = int((time.time() - t0) * 1000)
            probe.status = resp.status_code
            probe.final_url = resp.url
            probe.headers = {k: v for k, v in resp.headers.items()}
            probe.server = resp.headers.get("Server", "")
            probe.cookies = list(resp.cookies.keys())
            # 用显式解码，而非库默认（目标是 text/* 且未声明 charset 时，
            # 库默认会把 UTF-8 中文解成乱码，导致中文特征判据集体失效）
            body = self.decode_body(resp)
            probe.body_snippet = body[:4000]
            probe.title = self._extract_title(body)
        except requests.exceptions.SSLError as e:
            probe.error = f"TLS 错误：{str(e)[:120]}"
        except requests.exceptions.Timeout:
            probe.error = "请求超时"
        except requests.exceptions.ConnectionError as e:
            probe.error = f"连接失败：{str(e)[:120]}"
        except Exception as e:  # noqa: BLE001
            probe.error = f"{type(e).__name__}: {str(e)[:120]}"
        return probe


# ==============================================================================
# 特征推导规则
# ==============================================================================
def path_hit_usable(status: int, modal: int, n: int) -> bool:
    """这条「路径命中」能不能当「该功能存在」的证据？

    判据（与检测器侧的 `checks.base.sitewide_guard` 同源，不另立一套）：

      · 整站同码（`modal` 非 0）→ **一律不可用**：状态码说明不了任何路径的存在性；
      · 对照样本不足（`n < SITEWIDE_MIN_SAMPLES`）且状态码属拦截类
        （401/403/405/406/429/451/503）→ **不可用**。做不了对照就不采信 ——
        这是本函数存在的唯一理由（见下方 FEATURE_PATHS 处的事故记录）；
      · 其余 → 可用。2xx/3xx 不依赖对照：「页面真的被送达了」本身就是事实。

    抽成纯函数是为了能被自测钉死：这段逻辑原先散在循环里，
    「样本不足时静默采信」这个回退没有任何测试覆盖，就一直没人发现。
    """
    if modal:
        return False
    if n < SITEWIDE_MIN_SAMPLES and int(status) in SITEWIDE_STATUSES:
        return False
    return True


# 每个规则：特征名 -> 判定用路径清单（命中即视为具备该特征）
FEATURE_PATHS: dict[str, list[str]] = {
    "has_login": ["login", "signin", "auth/login", "user/login", "account/login", "sso/login"],
    "has_account": ["register", "signup", "user/register", "forgot-password", "reset-password"],
    "has_admin": ["admin", "manage", "administrator", "console", "dashboard", "admin/login"],
    "has_api": ["api", "api/v1", "api/v2", "v1", "v2", "rest"],
    "has_upload": ["upload", "api/upload", "file/upload", "attachment/upload"],
    "has_download": ["download", "export", "api/export", "file/download"],
    "has_payment": ["pay", "payment", "order/checkout", "cart", "trade"],
    "has_oauth": ["oauth", "oauth2", "oidc", "connect/authorize", "api/oauth"],
    "has_graphql": ["graphql", "api/graphql", "gql"],
    "has_storage": ["oss", "static", "assets", "cdn"],
    "has_websocket": ["ws", "socket.io", "websocket"],
}

# 响应头 / 内容特征
# 注意：has_cloud 只认云服务商特有头，has_cdn 认 CDN 特有头。
# 二者语义不同（Cloudflare 是 CDN，阿里云 OSS 是云存储），不可混用。
HEADER_FEATURES = {
    "has_session": ["set-cookie", "x-auth-token", "authorization"],
    "has_cloud": ["x-amz-", "x-oss-", "x-obs-", "x-cos-", "ali-swift", "x-ecs-"],
    "has_cdn": ["cf-ray", "x-cache", "x-served-by", "ali-swift", "x-amz-cf-id", "x-cdn", "x-fastly"],
}

# Server 头 / 内容中命中的组件特征
COMPONENT_SIGNATURES = [
    "nginx", "apache", "iis", "tomcat", "jetty", "openresty",
    "vue", "react", "angular", "jquery", "bootstrap", "axios", "lodash",
    "spring", "django", "flask", "express", "laravel", "thinkphp", "struts",
    "shiro", "fastjson", "log4j", "php", "asp.net", "jsp",
]

# 页面内容里出现这些关键词，说明存在用户可控输入入口
INPUT_SIGNATURES = ["<form", "<input", "search", "query=", "?id=", "?page="]

# <script> / <style> / <noscript> 的整块内容（含标签）
_SCRIPT_BLOCK_RE = re.compile(r"(?is)<(script|style|noscript)\b[^>]*>.*?</\1>")


def _spa_route_links(html: str) -> list[str]:
    """从渲染 DOM 里提取 SPA hash 路由（去重、交互语义优先排序）。

    为什么必须多路由渲染：入口页只是 SPA 的第一张路由 —— 登录、注册、
    个人资料这些页面的表单**只有渲染对应路由后才存在**。只渲染入口页，
    find_forms 在 SPA 上永远空手，「看得见 has_login 特征、找不到登录
    表单」的脱节就是这么来的（红线 62，2026-10-10 Juice Shop 实测）。
    """
    routes: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"#/([A-Za-z0-9_\-/]{1,40})", html or ""):
        r = m.group(1).strip("/")
        if r and r not in seen:
            seen.add(r)
            routes.append(r)
    prio = ("login", "signin", "register", "signup", "search", "profile",
            "contact", "complaint", "basket", "cart", "chatbot", "admin",
            "forgot", "address", "saved")
    routes.sort(key=lambda r: 0 if any(p in r.lower() for p in prio) else 1)
    return routes


def visible_html(html: str) -> str:
    """剥掉 `<script>` / `<style>` / `<noscript>` 的**内容**，保留其余标签与文本。

    为什么必须这么做：现代前端把「要渲染成什么」写成字符串
    （`innerHTML`、模板字符串、`dangerouslySetInnerHTML`），于是
    `<form`、`<a href=`、`管理后台` 这些片段会以**字面文本**出现在内联脚本或
    打包产物里。若直接对原始 HTML 做子串匹配，一个纯骨架页也会「命中」表单与链接。

    这类「碰巧对」的判定比判错更危险：结论看着是对的，依据却是脚本里的字符串，
    它会把**真正的漏报**掩盖掉 —— 检测器以为自己看到了表单，于是不再报
    「没看到页面」，而适用性也已按「有表单」扩展开，后面所有结论都建在沙子上。

    注意：这里只用于「页面上是否真的存在某个元素」这类判据。
    「是否存在某段前端代码」类判据（组件指纹 / 前端脚本引用）仍应看原始正文。
    """
    if not html:
        return ""
    out = _SCRIPT_BLOCK_RE.sub(" ", html)
    # 畸形页面里 <script> 可能没闭合：从它开始到结尾一并丢掉，
    # 否则脚本里的字面量仍会被当成页面内容。
    return re.sub(r"(?is)<(script|style|noscript)\b.*$", " ", out)

# AI / LLM 特征
AI_SIGNATURES = [
    "openai", "chat/completions", "gpt-", "claude", "llm", "/v1/chat",
    "dashscope", "qianfan", "hunyuan", "embedding", "ragflow", "ollama",
]

# CI/CD 与制品特征
CICD_SIGNATURES = [
    ".git/config", ".gitlab-ci.yml", ".github/workflows", "jenkins",
    "nexus", "artifactory", "swagger", "openapi.json", "api-docs",
]


class FeatureDeriver:
    """把探测结果翻译成 TargetFeatures。"""

    def __init__(self) -> None:
        self.derived_evidence: dict[str, str] = {}

    def derive(
        self,
        target_name: str,
        base_url: str,
        root: HttpProbe,
        path_probes: dict[str, HttpProbe],
        dns: DnsResult | None = None,
        preset: dict[str, Any] | None = None,
        rendered_html: str = "",
    ) -> TargetFeatures:
        tf = TargetFeatures(target=target_name)
        self.derived_evidence = {}

        if preset:
            for k, v in preset.items():
                if isinstance(v, bool):
                    tf.set(k, "present" if v else "absent", "目标清单中预置", "override")
                elif isinstance(v, dict):
                    tf.set(k, v.get("state", "unknown"), v.get("evidence", ""), "override")

        combined_headers = " ".join(f"{k}:{v}" for k, v in root.headers.items()).lower()
        body_all = " ".join(p.body_snippet for p in path_probes.values()).lower()
        body_all += " " + root.body_snippet.lower()

        # 两种「可见正文」版本，用途不同，不能混：
        #   · body_visible     = **直连** HTML 剥掉脚本内容后的版本
        #     （curl 一下就能复现；「页面上真的存在某元素」类判据用它）
        #   · body_visible_all = 上面再加上**渲染后** DOM 的可见版本
        #     （需要开浏览器才能复现；判「这个元素到底存不存在」用它）
        # 两者的差集就是「只有渲染后才看得到」——这正是 P3 要区分的东西，
        # 报告里必须能说清某个结论是 curl 可验还是要开浏览器。
        body_visible = (" ".join(visible_html(p.body_snippet or "")
                                 for p in path_probes.values())
                        + " " + visible_html(root.body_snippet or "")).lower()
        if rendered_html:
            body_all += " " + rendered_html[:300_000].lower()
        body_visible_all = body_visible
        if rendered_html:
            body_visible_all += " " + visible_html(rendered_html)[:300_000].lower()

        # --- 路径命中类特征 ---
        # 先做「整站同一响应」守卫：目标若对任意路径返回同一个状态码，
        # 那么「路径返回 405 / 403 / 401」就不再是「该路径存在」的证据。
        # 实测踩过：某站点全站 405（边缘防护），/login、/admin、/api、
        # /graphql 因此全部被判定为「存在」，15 项特征凭空变成「具备」，
        # 适用性从「几乎不适用」被抬到 124 项 —— 后续全部检测都跑在
        # 拦截页上，产出的「漏洞」一条也复测不出来。
        _modal, _ratio, _n = sitewide_uniform_status(path_probes)
        # 状态码分布的**事实**（不做门控）：判据未达标时 `_ratio` 是 0.0，
        # 而披露文案要说的是「众数占比 55%」这种真话，不能写成 0%。
        _mix_status, _mix_ratio, _mix_n = status_mix(path_probes)
        # 第二个口径：**正文**。
        # 状态码口径在「边缘对同一批请求返回混合状态码」时会静默失效 ——
        # 限速、挑战、部分放行、多节点行为不一致，都会把众数占比压到阈值以下，
        # 于是 405/403/401 又被当成「路径存在」的证据。那时唯一的线索是
        # **页面正文归一化后仍然相同**。2026-09-29 实测踩到这个洞：同一目标
        # 同一代码，一次状态码探测是混的，适用性就从 67 项跳到 124 项，
        # 而且一条提示都没打。
        _bh, _b_ratio, _b_n = sitewide_uniform_body(path_probes)
        _body_uniform = bool(_bh)
        # 正文同码**本身不足以**判「边缘拦截」：SPA 兜底路由把任意路径都渲染成
        # 首页，也是整站同一张页，那是应用自己的行为。必须再叠加拦截页厂商特征
        # 才算数 —— 否则修好一个静默失效，会换来一片静默误杀。
        _block_like, _vendor, _why = False, "", ""
        if _body_uniform:
            _rep = representative_probe(path_probes, _bh)
            if _rep is not None:
                _block_like, _vendor, _why = detect_block_page(
                    int(getattr(_rep, "status", 0) or 0),
                    getattr(_rep, "headers", None),
                    getattr(_rep, "body_snippet", "") or "",
                    getattr(_rep, "cookies", None),
                )
        sitewide_hit = bool(_modal) or (_body_uniform and _block_like)
        # 守卫「失败时朝危险方向倒」是这类判据最典型的坑：样本不足（n < 5）时
        # `sitewide_uniform_status` 返回「非同码」，于是 405/403/401 又被当成
        # 「路径存在」的证据 —— 守卫看着在，其实失效了，而且**静默**。
        # 实测踩过：同一目标同一代码，一次探测样本不足就翻成这样 ——
        # 适用性从 67 项抬到 124 项，has_login / has_admin / has_api 全部「具备」，
        # 后续检测全跑在拦截页上，产出的「漏洞」一条也复测不出来。
        # 结论：**做不了对照 ≠ 可以采信**，样本不足时必须失败关闭。
        _no_contrast = _n < SITEWIDE_MIN_SAMPLES

        def _guard_why() -> str:
            """把「为什么判整站同一响应」写成一句可复现的话。

            结论必须能被复述、被复测，因此依据也要说清是**哪个口径**命中 ——
            状态码口径与正文口径的复现方式不同（后者要剔除易变标识再比对）。
            所有对外文案一律走本函数，**不得**在各分支里硬写 `HTTP {_modal}`、
            `{_ratio:.0%}` —— 正文口径命中时 `_modal` 恒为 0，会渲染成
            「HTTP 0」「占比 0%」这种自相矛盾的话。
            """
            if _modal:
                return (f"已探测的 {_n} 个路径中有 {_ratio:.0%} 返回 "
                        f"HTTP {_modal}")
            return (f"已探测的 {_b_n} 个路径中有 {_b_ratio:.0%} 返回**归一化后"
                    f"完全相同**的页面（正文哈希 `{_bh}`），且该页面命中边界"
                    f"防护拦截页特征（{_why or _vendor}）；注意这批探测的"
                    f"**状态码并不统一**（众数只占 {_mix_ratio:.0%}，"
                    f"最高频者 HTTP {_mix_status}）")

        for feat, paths in FEATURE_PATHS.items():
            if feat in tf.features and tf.features[feat].source == "override":
                continue
            hits = [
                (p, path_probes[p])
                for p in paths
                if p in path_probes
                and path_probes[p].reachable
                and path_probes[p].status in (200, 301, 302, 401, 403, 405)
            ]
            # 没有对照依据时，拦截类状态码（401/403/405/406/429/451/503）一律不作数：
            # 它既可能是「路径在，只是要鉴权 / 只收 POST」，也可能是「边缘统一拦」。
            # 2xx/3xx 仍可采信 —— 「页面真的被送达了」不依赖对照实验。
            _usable = [
                (p, pr) for p, pr in hits
                if path_hit_usable(pr.status, _modal, _n)
            ]
            if hits and sitewide_hit:
                # 整站同一响应 → 状态码不构成路径存在的证据，只能留 unknown。
                # 依据文案统一由 _guard_why() 生成：命中可能是状态码口径，
                # 也可能是正文口径，分支里无从得知，硬写状态码会写错。
                tf.set(
                    feat, "unknown",
                    f"探测到相关路径返回 HTTP {hits[0][1].status}，但{_guard_why()}"
                    " —— 目标疑似对任意路径返回同一张页面，"
                    "无法据此判断该功能是否存在",
                    "path_probe", strength="weak",
                )
            elif _usable:
                p, pr = _usable[0]
                ev = f"探测到 /{p} 返回 {pr.status}" + (f"（标题：{pr.title}）" if pr.title else "")
                tf.set(feat, "present", ev, "path_probe")
            elif hits:
                # 有命中，但全部落在「无对照 + 拦截类状态码」上 → 不得判 present。
                p, pr = hits[0]
                tf.set(
                    feat, "unknown",
                    f"探测到 /{p} 返回 HTTP {pr.status}，但本次路径探测只采到 "
                    f"{_n} 个有效样本（做「整站同码」对照需 ≥{SITEWIDE_MIN_SAMPLES} 个），"
                    "**无法区分「该路径存在」与「边缘防护统一响应」** —— "
                    "缺少对照的证据不予采信，记为「未知」",
                    "path_probe", strength="weak",
                )
            else:
                # 只有确实探测过且全部未命中，才能判 absent；否则留 unknown
                probed = [p for p in paths if p in path_probes]
                if probed and sitewide_hit:
                    tf.set(
                        feat, "unknown",
                        f"已探测 {len(probed)} 个相关路径，但{_guard_why()}"
                        " —— 无法区分「路径不存在」与「被边界防护统一接管」",
                        "path_probe", strength="weak",
                    )
                elif probed:
                    tf.set(
                        feat,
                        "absent",
                        f"已探测 {len(probed)} 个相关路径（{'、'.join(probed[:3])} 等），均未命中",
                        "path_probe",
                    )
                else:
                    tf.set(feat, "unknown", "未执行该特征的路径探测", "path_probe")

        if sitewide_hit:
            tf.notes.append(
                f"整站同一响应：{_guard_why()}。"
                "路径存在性类特征一律记为「未知」，不作为适用性扩大或缩小的依据。")
        elif _body_uniform:
            # 反向误杀也要防。SPA 兜底路由把任意路径都交给前端路由，返回的
            # 骨架页**整站同一份**，正文哈希同样「全站相同」—— 但它不是拦截。
            # 若把这种情况也判成「整站被接管」，适用性会直接归零：用一把大锤
            # 砸死全部结论，比漏判更难被发现（报告看起来只是「没什么可测的」）。
            # 所以这里**只披露、不改判定**：2xx/3xx 的「页面确实被送达」仍旧成立。
            #
            # 但披露的措辞不能替读者选边。没有厂商特征时，我们**分不清**
            # 「应用兜底路由」与「自研 / 未收录标识的边界防护」—— 那是两种
            # 处置完全相反的情况。所以只并列事实 + 要求人工复核，不下方向判断。
            # （`_body_uniform` 为真时必有 n ≥ SITEWIDE_MIN_SAMPLES，
            #   因此与下面 `_no_contrast` 分支天然互斥，不会漏掉或重复披露。）
            tf.notes.append(
                f"⚠ 已探测的 {_b_n} 个路径中有 {_b_ratio:.0%} 返回**归一化后完全"
                f"相同**的页面（正文哈希 `{_bh}`），但**未命中任何已知边界防护"
                "厂商**特征。两种可能本次**无法区分**：①应用自身的兜底路由"
                "（SPA 把任意路径都交给前端路由）或统一跳转；②自研 / 未收录"
                "厂商标识的边界防护在统一接管。本次不据此判「整站被接管」"
                "（2xx/3xx 仍算页面送达，路径存在性照常判定）；"
                "但若实为防护页，则相关结论与后续检测全建在它上面，须人工复核。")
        elif _no_contrast:
            # 守卫没生效这件事**必须说出来**。不说，读者会把「适用 67 项」
            # 与「适用 124 项」当成目标变了，而其实是判据这次没跑起来。
            tf.notes.append(
                f"⚠ 「整站同码」对照未能生效：本次路径探测只采到 {_n} 个有效样本"
                f"（需 ≥{SITEWIDE_MIN_SAMPLES} 个），**不足以判断目标是否对任意路径"
                "返回同一响应**。为避免把「边缘防护的统一响应」当成「该路径存在」，"
                "本次**不采信**拦截类状态码（401 / 403 / 405 等）作为路径存在的证据，"
                "相关特征一律记为「未知」—— 适用性据此收敛，不因缺少对照而放大。"
                "这些特征本次**没有取得真实结论**（缺少路径存在性的独立证据）。")

        # --- 响应头类特征 ---
        for feat, markers in HEADER_FEATURES.items():
            if feat in tf.features and tf.features[feat].source == "override":
                continue
            if feat == "has_session":
                # 2026-10-10 修正：这里曾经只看根响应的 Set-Cookie，于是 SPA + JWT
                # 型应用（令牌存 localStorage、登录后才下发，根响应既无 Cookie
                # 也无令牌）被一律判成「不具备会话」，SESS-10 等 11 个会话类检查项
                # 整族变 N/A——Juice Shop 基准里 SESS-10 的 N/A 就是这么来的。
                # 「这次没看见」与「目标没有」是两件事（红线 49 弱证据 N/A）：
                # 现在把证据面铺开，铺开了仍没有才判 absent，采不充分判 unknown。
                sess_ev = ""
                if root.cookies:
                    sess_ev = f"响应 Set-Cookie：{', '.join(root.cookies[:3])}"
                else:
                    hdr_hit = next(
                        (m for m in markers
                         if m in combined_headers), None)
                    if hdr_hit:
                        sess_ev = f"响应头命中会话特征「{hdr_hit}」"
                if not sess_ev:
                    # JWT 形态串（eyJ…）出现在页面或前端产物里，是「用令牌做会话」
                    # 的直接证据 —— 它就是会话，只是不在 Cookie 里。
                    if re.search(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.",
                                 body_all or ""):
                        sess_ev = "页面 / 前端产物中出现 JWT 形态令牌（令牌式会话）"
                if not sess_ev:
                    # 有登录入口 → 几乎必然有会话，但这里没有**直接**证据，
                    # 记 unknown（待确认）而不是 absent：判 absent 会把整族检查项
                    # 一次性关掉，代价太大，且这个代价在报告上表现为「不适用」。
                    _lf = tf.features.get("has_login")
                    login_present = bool(getattr(_lf, "present", False))
                    if login_present:
                        tf.set(feat, "unknown",
                               "探测到登录入口，但未在匿名响应中直接观测到 Cookie / 令牌"
                               "（令牌式会话通常登录后下发）—— 需要登录态才能确认",
                               "header")
                    else:
                        tf.set(feat, "absent",
                               "根路径响应未下发会话 Cookie，且未观测到令牌或登录入口",
                               "header")
                else:
                    tf.set(feat, "present", sess_ev, "header")
            else:
                hit = next((m for m in markers if m in combined_headers), None)
                if hit:
                    tf.set(feat, "present", f"响应头命中特征「{hit}」", "header")
                else:
                    label = "云服务商" if feat == "has_cloud" else "CDN"
                    tf.set(feat, "absent", f"响应头未命中{label}特征", "header")

        # --- 组件与前端类特征 ---
        sig_hit = [c for c in COMPONENT_SIGNATURES if c in combined_headers or c in body_all]
        if sig_hit:
            tf.set("has_component", "present", f"命中组件特征：{', '.join(sig_hit[:6])}", "content")
        else:
            tf.set("has_component", "absent", "未在响应头与页面内容中识别到第三方组件特征", "content")

        if re.search(r"<script|\.js[\"']|__webpack|/assets/|chunk", body_all):
            tf.set("has_client", "present", "页面含前端脚本 / 打包产物引用", "content")
        else:
            tf.set("has_client", "absent", "未发现前端脚本引用，疑似纯服务端渲染或非 HTML 响应", "content")

        # 输入入口的判据走 visible_html：必须页面上**真的存在** <form> / <input>，
        # 写在脚本字符串里的不算（见 visible_html 的说明 —— 那类「碰巧命中」
        # 会把真正的漏报掩盖掉）。
        inp_hit = [s for s in INPUT_SIGNATURES if s in body_visible_all]
        if inp_hit:
            # 输入入口是 SPA 最典型的「只有渲染后才出现」的特征：
            # 骨架页里没有 <form> / <input>，渲染后才有。
            # 这个区别必须写进证据 —— 它决定了复测方式（是否需要开浏览器），
            # 也决定了读者能否判断这个结论有多硬。
            only_rendered = (bool(rendered_html)
                             and not any(s in body_visible for s in inp_hit))
            ev = f"页面含输入入口特征（{', '.join(inp_hit[:3])}）"
            if only_rendered:
                ev += "；这些入口只存在于**浏览器渲染后**的 DOM 中，直连 HTTP 响应里没有" \
                      "（SPA 形态），复测需在浏览器中打开页面"
            tf.set("has_input", "present", ev, "rendered" if only_rendered else "content")
        else:
            # 判「无」时要说清是「直连与渲染后都没有」，还是「没渲染所以不知道」。
            # 后者是覆盖度问题，不是关于目标的结论。
            _why = ("未在响应中发现表单或查询参数入口"
                    if rendered_html else
                    "未在直连响应中发现表单或查询参数入口"
                    "（本次未渲染入口页，SPA 的表单只存在于渲染后的 DOM 中，"
                    "故此项可能是「没看到」而非「不存在」）")
            tf.set("has_input", "absent", _why, "content")

        # --- AI / CI-CD / 云 ---
        ai_hit = [s for s in AI_SIGNATURES if s in body_all]
        tf.set(
            "has_ai",
            "present" if ai_hit else "absent",
            f"命中 AI 接口特征：{', '.join(ai_hit[:4])}" if ai_hit else "未发现 AI / LLM 接口特征",
            "content",
        )

        cicd_hit = [
            s for s in CICD_SIGNATURES
            if s in body_all
            or any(s in (p.body_snippet.lower()) for p in path_probes.values())
        ]
        tf.set(
            "has_cicd",
            "present" if cicd_hit else "absent",
            f"命中构建 / 制品特征：{', '.join(cicd_hit[:4])}" if cicd_hit else "未发现公网可达的构建产物或流水线配置",
            "content",
        )

        # --- 整站同一响应时，内容类特征同样不可信 ---
        # 上面这些内容特征读的都是根路径正文。目标若对任意路径返回同一张
        # （并非应用的）页面，正文里出现的 <script>、组件指纹、AI 关键词
        # 全部来自那张页面 —— 据此判「具备」等于拿着拦截页给应用画像。
        if sitewide_hit and body_all.strip():
            for _f, _why in (
                ("has_component", "组件特征"), ("has_client", "前端脚本引用"),
                ("has_input", "输入入口"), ("has_ai", "AI 接口特征"),
                ("has_cicd", "构建制品特征"),
            ):
                tf.set(_f, "unknown",
                       f"整站同一响应（{_guard_why()}），正文并非应用页面，"
                       f"无法据此判断{_why}",
                       "content", strength="weak")

        if rendered_html:
            tf.notes.append(
                "入口页已由本机浏览器渲染，渲染后的 DOM 并入内容类特征判定"
                "（渲染过程会在浏览器中执行目标页面的 JavaScript）。"
                "凡「依赖渲染才能看到」的结论，复测时需在浏览器里打开对应页面 —— "
                "curl 直连看不到同样的结果。")

        if root.tls and not root.tls.get("error"):
            tf.set(
                "tls_info",
                "present",
                f"TLS {root.tls.get('protocol', '?')} / {root.tls.get('cipher', '?')}",
                "tls",
            )

        # --- 资产测绘结果（供报告第一章使用）---
        if dns:
            tf.set(
                "resolved_ips",
                "present" if dns.ips else "unknown",
                f"公共递归解析：{', '.join(dns.ips) if dns.ips else '无 A 记录'}"
                + ("" if dns.consistent else "（多解析器结果不一致，疑似分地域解析）"),
                "dns",
            )

        # 未探明的特征统一标 unknown，交人工确认（不擅自判 N/A）
        declared_extra = ["has_cloud", "has_storage"]
        for feat in declared_extra:
            if feat not in tf.features:
                tf.set(feat, "unknown", "需人工确认", "manual")

        return tf


# ==============================================================================
# 编排入口
# ==============================================================================
class Fingerprinter:
    def __init__(self, profile: dict[str, Any] | None = None, resolvers: list[str] | None = None):
        self.client = HttpProbeClient(profile)
        self.resolver = PublicDnsResolver(resolvers)
        self.deriver = FeatureDeriver()

    def assess(
        self,
        target_name: str,
        domain: str,
        base_url: str | None = None,
        preset: dict[str, Any] | None = None,
        profile_key: str = "standard",
        render_runner: Any = None,
    ) -> dict[str, Any]:
        url = base_url or f"https://{domain}"
        dns = self.resolver.resolve(domain)

        root = self.client.fetch(url)
        if not root.reachable and url.startswith("https://"):
            # HTTPS 不通时试 HTTP，记录降级
            alt = self.client.fetch(f"http://{domain}")
            if alt.reachable:
                alt.error = f"HTTPS 不可达（{root.error}），退回 HTTP 探测"
                root = alt

        all_paths = sorted({p for paths in FEATURE_PATHS.values() for p in paths})
        probes = self.client.probe_many(root.final_url or url, all_paths)

        # ---- SPA 渲染（P3）----
        # 放在这里而不是更后面，是因为它的产出要参与**特征派生**：
        # 骨架页里没有表单、没有链接、没有文案，如果先按直连 HTML 判完
        # `has_input=无` 再去渲染，适用性已经收窄，晚了。
        render_report: Any = None
        rendered_html = ""
        # 渲染成功的路由清单要落进 fp_result：INPV-01 的 hash 路由参数验证
        # 必须以「本次真的渲染过哪些路由」为准，而不是在 DOM 里正则捞一遍
        # （捞不到就等于没候选，验证环节静默变成 0 项 —— 见红线 62）。
        rendered_routes: list[str] = []
        try:
            from engine.render import RenderReport, plan_for, render_entry  # noqa: PLC0415

            _plan = plan_for(profile_key)
            entry = render_entry(
                root.final_url or url, profile_key=profile_key,
                status=root.status,
                content_type=(root.headers or {}).get("Content-Type", "")
                             or (root.headers or {}).get("content-type", ""),
                before_html=root.body_snippet or "",
                runner=render_runner, plan=_plan,
            )
            render_report = RenderReport(plan=_plan, entry=entry)
            render_report.notes.append(entry.summary_line())
            if entry.ok:
                rendered_html = entry.html
                # ---- 多路由渲染（红线 62）----
                # 入口页渲染成功后，从 DOM 里提取 hash 路由，逐个渲染合并。
                # 预算按档位：deep 8 个、standard 4 个、safe 0（渲染有副作用）。
                # 每个失败的路由单独留痕，绝不静默 —— 少渲染一个路由就是
                # 一族检查项的覆盖度下降，必须能被说出名字。
                _budget = {"deep": 8, "standard": 4}.get(profile_key, 0)
                if _budget:
                    _base = (root.final_url or url).split("#")[0].rstrip("/")
                    _merged: list[str] = []
                    _ok_routes: list[str] = []
                    _fail_routes: list[str] = []
                    for _r in _spa_route_links(rendered_html)[:_budget]:
                        try:
                            _e2 = render_entry(
                                f"{_base}/#{_r}", profile_key=profile_key,
                                status=200, content_type="text/html",
                                before_html=root.body_snippet or "",
                                runner=render_runner, plan=_plan)
                        except Exception as e2:  # noqa: BLE001
                            _fail_routes.append(f"{_r}（{type(e2).__name__}）")
                            continue
                        if _e2.ok and _e2.html:
                            _merged.append(_e2.html)
                            _ok_routes.append(_r)
                            rendered_routes.append(_r)
                        else:
                            _fail_routes.append(f"{_r}（{_e2.state}）")
                    if _ok_routes:
                        rendered_html = rendered_html + (
                            "\n<!-- aiscan route boundary -->\n"
                            + "\n".join(_merged))
                        render_report.notes.append(
                            f"多路由渲染：额外渲染 {len(_ok_routes)} 个路由成功"
                            f"（{'、'.join('/' + r for r in _ok_routes[:6])}"
                            f"{'…' if len(_ok_routes) > 6 else ''}）"
                            + (f"；失败 {len(_fail_routes)} 个："
                               f"{'、'.join(_fail_routes[:4])}" if _fail_routes else ""))
                    elif _fail_routes:
                        render_report.notes.append(
                            f"多路由渲染：{len(_fail_routes)} 个路由全部渲染失败"
                            f"（{'、'.join(_fail_routes[:4])}）—— SPA 子页面"
                            "表单与参数覆盖度下降，须人工用浏览器确认")
            elif entry.state == "未渲染":
                # 「没渲染」不是关于目标的结论，是关于本次扫描覆盖度的说明。
                # 必须显式登记，否则报告里那些 N/A 会被读成「不存在」。
                render_report.notes.append(
                    "⚠ 未渲染入口页 → 本次对 SPA 类判定的覆盖度下降："
                    "链接、表单、页面文案类特征可能整体判「无」，"
                    "而这未必是目标真实情况，需人工用浏览器确认。")
        except Exception as e:  # noqa: BLE001
            render_report = None
            _render_err = f"{type(e).__name__}: {str(e)[:160]}"

        tf = self.deriver.derive(target_name, url, root, probes, dns, preset,
                                 rendered_html=rendered_html)
        if render_report is not None and getattr(render_report, "notes", None):
            tf.notes.extend(render_report.notes)
        elif render_report is None:
            tf.notes.append(f"渲染阶段未能执行：{_render_err} —— "
                            "SPA 类特征判定可能不完整（这是覆盖度说明，不是对目标的结论）")

        return {
            "target": target_name,
            "domain": domain,
            "dns": dns.to_dict(),
            "root_probe": root.to_dict(),
            "path_probes": {k: v.to_dict() for k, v in probes.items()},
            "features": {
                k: {"state": f.state, "evidence": f.evidence, "source": f.source}
                for k, f in tf.features.items()
            },
            "render": render_report.to_dict() if render_report else {
                "plan": {}, "entry": None, "extra": [],
                "notes": ["渲染阶段未能执行（详见扫描日志）"],
            },
            # 渲染后的正文单独存放：URL 枚举要用它抽链接，
            # 报告要用它区分「直连可见」与「渲染可见」。
            "_render_html": rendered_html,
            # 本次实际渲染成功的 SPA 路由（多路由渲染产出，可能为空）
            "_render_routes": rendered_routes,
            "_features_obj": tf,
        }


if __name__ == "__main__":
    # 链路自测：用 example.com（IANA 保留的示例域名，公开可访问，无业务数据）
    fp = Fingerprinter({"rate": {"requests_per_second": 5, "timeout_seconds": 10}})
    out = fp.assess("example.com", "example.com", "https://example.com")
    print(f"目标：{out['target']}")
    print(f"DNS 解析：{out['dns']['ips']}  一致性={out['dns']['consistent']}")
    rp = out["root_probe"]
    print(f"根路径：HTTP {rp['status']}  Server={rp['server']}  Title={rp['title']!r}  {rp['elapsed_ms']}ms")
    if rp.get("error"):
        print(f"  错误：{rp['error']}")
    print(f"\n特征判定（{len(out['features'])} 项）：")
    for k, v in sorted(out["features"].items()):
        mark = {"present": "有", "absent": "无", "unknown": "?"}.get(v["state"], "?")
        print(f"  [{mark}] {k:<16} {v['evidence'][:70]}")
