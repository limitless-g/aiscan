# -*- coding: utf-8 -*-
"""
检查项执行注册表
================
这个模块解决一个具体问题：**报告里的「通过」必须代表「真的测过」。**

改造前的逻辑是「适用 且 没产出发现 → 通过」。这条链路有个致命缺陷：
如果一个检查项根本没有检测代码，它同样不会产出发现，于是被标成「通过」。
实跑报告里 55 项「通过」中有 42 项属于这种情况 —— 不是「测了没问题」，
而是「压根没测」，却被包装成已验通过，研发会据此关掉整改任务。

本模块建立的规则：

  1. 每个检查项必须显式绑定一个执行体：自动检测器（auto）或人工执行指引（manual）。
     绑定缺失时状态是「未执行」，**永远不会是「通过」**。
  2. 检测器抛异常 / 前置条件不满足时，状态同样是「未执行」，并记录原因。
  3. 只有检测器**完整跑完且未产出发现**，状态才是「通过」。
  4. 必须人工判断的项（业务逻辑、多账号越权），状态是「待人工执行」，
     并附可照做的操作步骤 —— 它不进「通过」统计，也不掩盖问题。

状态取值（互斥）：
    通过 / 不通过 / 未执行 / 待人工执行 / N/A / 待确认 / 已跳过
"""

from __future__ import annotations

import re
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Finding  # noqa: E402

# 已确认登录态的字段值。唯一事实来源是 sessionpool.LOGIN_OK（「已登录」），
# import 解析不到时退空串（只意味着该补丁不生效，不影响其它判定路径）。
# 2026-10-10 踩坑：这里曾硬编码 "authenticated"，与 LOGIN_OK 的真实值
# 「已登录」对不上，凭据就位判据永远 False —— 配了却没人读得到的又一个变体。
try:  # noqa: SIM105
    from engine.sessionpool import LOGIN_OK as _LOGIN_OK  # noqa: E402
except Exception:  # noqa: BLE001
    _LOGIN_OK = ""

# ======================================================================
# 执行状态
# ======================================================================
STATE_PASS = "通过"          # 检测器跑完，未发现问题
STATE_FIND = "不通过"        # 检测器跑完，产出了问题
STATE_NOTRUN = "未执行"      # 适用，但没有可用检测器 / 检测器失败 / 前置条件不足
STATE_MANUAL = "待人工执行"  # 必须人判，已提供操作指引
STATE_NA = "N/A"             # 目标不具备该特征，逐项说明原因
STATE_PENDING = "待确认"     # 适用性无法判定
STATE_SKIP = "已跳过"        # 用户显式跳过

ALL_STATES = (STATE_PASS, STATE_FIND, STATE_NOTRUN, STATE_MANUAL,
              STATE_NA, STATE_PENDING, STATE_SKIP)

# 执行方式
MODE_AUTO = "自动"
MODE_MANUAL = "人工"

# 风险档位：检测该动作对目标的影响程度
RISK_SAFE = "safe"        # 纯被动读取，任何档位都可执行
RISK_STANDARD = "standard"  # 常规主动探测，standard 及以上可执行
RISK_DEEP = "deep"        # 有副作用或易触发风控，仅 deep 档执行
RISK_ORDER = {RISK_SAFE: 0, RISK_STANDARD: 1, RISK_DEEP: 2}

#: 喂给边界守门的响应正文长度上限。
#:
#: 守门只做「归一化哈希 + 同页比较」，不需要全文；截断让这条**热路径**
#: （每次探测都要走）的开销与响应体大小解耦，避免大响应拖慢整个检测阶段。
GUARD_BODY_LIMIT = 4000


@dataclass
class DetectorOutcome:
    """一个检测器的执行结果。"""

    ok: bool = True                  # 检测器自身是否正常跑完
    findings: list[Finding] = field(default_factory=list)
    note: str = ""                   # 执行说明（会写进报告）
    error: str = ""                  # 执行失败原因
    probes: int = 0                  # 实际发出的请求数，用于证明「真的测了」
    evidence_kind: str = ""          # 证据类型描述，如「响应头实测」
    pending: bool = False            # 检测已执行，但外部无法得出结论 → 待确认
    not_applicable: bool = False     # 已确认目标不具备该功能 → N/A（≠ 通过）

    @property
    def found(self) -> bool:
        return bool(self.findings)


@dataclass
class ReconOutcome:
    """人工项的「自动前置侦察」结果。

    与 DetectorOutcome 的关键区别：**侦察不产出该项的最终结论。**

    业务逻辑类检查项之所以是人工项，是因为「业务上应该怎样」需要业务知识，
    这一点不会因为写了检测代码就改变。但如果因此就让整项停在「请人工从零开始测」，
    等于把最枯燥的活（找接口、找字段、记当前值、构造报文）全推给人。
    侦察层负责把这些做掉，人工只回答一个只有人能回答的问题：**这个业务结果对不对**。

    因此字段语义刻意与 DetectorOutcome 不同：
      · findings  已确证的问题（证据齐全，计入发现列表，会造成该项「不通过」）
      · lead      已定位到的具体对象（接口 / 参数 / 当前值），供人工照着执行
      · note      侦察做了什么、覆盖了什么、**没覆盖什么**
      · ran       侦察是否真的执行了。False = 档位不足 / 前置缺失 / 环境关闭，
                  绝不等于「侦察过且没问题」。
    """

    ran: bool = True
    findings: list[Finding] = field(default_factory=list)
    lead: list[str] = field(default_factory=list)
    note: str = ""
    probes: int = 0
    error: str = ""

    @property
    def proved(self) -> bool:
        return bool(self.findings)


@dataclass
class DetectorSpec:
    """一个检查项的执行体登记信息。"""

    item_id: str
    mode: str                        # MODE_AUTO / MODE_MANUAL
    run: Callable[["DetectorContext"], DetectorOutcome] | None = None
    name: str = ""                   # 检测器名称，写进报告「发现来源」
    tool: str = ""                   # 依赖的工具 / 模块
    risk: str = RISK_SAFE
    requires: list[str] = field(default_factory=list)  # accounts / write / js / nuclei ...
    evidence_kind: str = ""          # 预期证据类型
    procedure: str = ""              # 人工执行步骤（manual 模式必填）
    expect: str = ""                 # 人工执行的判定标准
    why_manual: str = ""             # 为什么不能自动化
    detector_ref: str = ""           # 检测逻辑对应的代码位置（可追溯）
    #: 该项要不要拿到**被测应用的 HTTP 响应**才能出结论。
    #:
    #: True（默认）：判据建立在应用响应之上（响应头 / 页面正文 / 接口返回 / 前端产物）。
    #:   扫描中途被边界封禁时，这类项必须短路成「未执行」—— 照跑只会把拦截页
    #:   当应用，产出复测不出来的结论（2026-09-29 内部生产系统 事故）。
    #: False：判据走**非应用通道**（DNS / TCP / TLS 握手 / crt.sh / 云端点直连）。
    #:   这类项**不受边界封禁影响**，封禁期间照常执行 —— 一刀切短路会把它们
    #:   一并打成「未执行」，等于用「没去看」丢掉了本来拿得到的真实结论
    #:   （2026-09-30 实测：OSS 匿名列举这条已确认的严重漏洞因此消失，通告
    #:   的「问题清单」变成空的，读者会读成「没问题」）。
    #:
    #: 声明 False 必须有据可依：其检测函数不得读取应用响应（见
    #: `selftest_engine.py` 的「不依赖应用的检测器不得读取应用响应」不变量）。
    needs_app: bool = True
    # 人工项的自动前置侦察（engine.business）。None = 没有可自动化的前置部分，
    # 此时 recon_gap 必须写清原因，否则 validate_coverage 对业务逻辑类会报问题。
    recon: Callable[["DetectorContext"], ReconOutcome] | None = None
    recon_gap: str = ""              # 为什么该项连前置侦察都做不了

    @property
    def is_manual(self) -> bool:
        return self.mode == MODE_MANUAL

    def __call__(self, fn: Callable[[DetectorContext], DetectorOutcome]):
        """让 DetectorSpec 本身可当装饰器用。

        这样两种写法等价，不会因为写法不同而静默漏登记：
            @make_auto("X", ...)        装饰器写法
            SPEC_X = make_auto("X", ...) 直接调用写法
        """
        self.run = fn
        if not self.detector_ref:
            self.detector_ref = f"{fn.__module__}.{fn.__name__}"
        fn._detector_spec = self  # type: ignore[attr-defined]
        return fn


@dataclass
class ItemResult:
    """一个检查项的完整执行结论。报告第 3 章逐项渲染它。"""
    item_id: str
    name: str
    category: str
    category_name: str
    state: str
    mode: str
    note: str = ""
    detector: str = ""
    tool: str = ""
    risk: str = RISK_SAFE
    requires: list[str] = field(default_factory=list)
    compliance: str = ""
    evidence_kind: str = ""
    probes: int = 0
    duration_ms: int = 0
    finding_titles: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    procedure: str = ""
    expect: str = ""                 # 人工项的判定标准
    why_manual: str = ""
    detector_ref: str = ""
    executable: bool = False         # 该项是否真的被自动执行了
    # ---- 人工项的自动侦察留痕 ----
    # 这三项让「侦察跑了没有、跑出了什么」在报告里可核对。
    # recon_ran=False 时报告必须显示「侦察未执行」，不得让读者以为自动化已经覆盖过。
    recon_note: str = ""
    recon_ran: bool = False
    recon_probes: int = 0
    recon_lead: list[str] = field(default_factory=list)
    recon_finding_count: int = 0
    #: 本项的「N/A」是否基于**弱证据**（有限路径探测推断，而非确证不具备）。
    #: 为什么必须落盘并跨轮传递：弱证据 N/A 的确切含义是「**没看到**」，
    #: 不是「**没有了**」。此前的承接逻辑把 N/A 一律当作「本轮有结论」，
    #: 于是**一次错误的弱 N/A 会把此前已证实的严重漏洞从通告里抹掉**：
    #:   第 N 轮：has_storage present → OSS 匿名列举（严重）被实测证实；
    #:   第 N+1 轮：路径探测没命中 has_storage → 弱证据判 N/A
    #:             → 该严重漏洞既不进本清单、也不被承接 → 凭空消失。
    #: 这与「跨轮资产记忆」要解决的是同一个问题，但修法更窄更准：
    #: 不依赖下一轮「看得见什么」，而是让「没看到」不再能推翻「看到过」。
    #: （2026-09-30 修，见 orchestrator._collect_prior_unverified）
    weak_na: bool = False
    # 运行期字段：本次执行产出的完整 Finding 对象（不落盘，供定级层消费）
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "category": self.category,
            "category_name": self.category_name,
            "state": self.state,
            "mode": self.mode,
            "note": self.note,
            "detector": self.detector,
            "tool": self.tool,
            "risk": self.risk,
            "requires": list(self.requires),
            "compliance": self.compliance,
            "evidence_kind": self.evidence_kind,
            "probes": self.probes,
            "duration_ms": self.duration_ms,
            "finding_titles": list(self.finding_titles),
            "finding_ids": list(self.finding_ids),
            "procedure": self.procedure,
            "expect": self.expect,
            "why_manual": self.why_manual,
            "detector_ref": self.detector_ref,
            "executable": self.executable,
            "recon_note": self.recon_note,
            "recon_ran": self.recon_ran,
            "recon_probes": self.recon_probes,
            "recon_lead": list(self.recon_lead),
            "recon_finding_count": self.recon_finding_count,
            # 必须落盘：跨轮承接要靠它区分「确证不适用」与「没看到」。
            # 不落盘的话，历史轮次的弱点信息就丢了，弱 N/A 又会被当成
            # 「那轮真测过且没问题」，从而清掉更早的真实发现。
            "weak_na": self.weak_na,
        }


# ======================================================================
# 检测上下文：所有检测器共用的探测入口（带缓存，避免重复打目标）
# ======================================================================
class DetectorContext:
    """检测器运行上下文。

    缓存很关键：全量检查项里有一大半都要读根路径响应头，逐个检测器各发一次请求
    会让扫描时长爆炸，也会给目标造成不必要的压力。
    """

    def __init__(
        self,
        target_name: str,
        domain: str,
        target_url: str,
        profile: dict[str, Any] | None = None,
        fp_result: dict[str, Any] | None = None,
        js_result: dict[str, Any] | None = None,
        nuclei_findings: list[Finding] | None = None,
        accounts: list[dict[str, Any]] | None = None,
        allow_write: bool = False,
        client: Any = None,
    ):
        self.target_name = target_name
        self.domain = domain
        self.target_url = target_url.rstrip("/") or f"https://{domain}"
        self.profile = profile or {}
        self.profile_name = self.profile.get("name", "standard")
        self.profile_key = self.profile.get("_key", "standard")
        self.fp_result = fp_result or {}
        self.js_result = js_result or {}
        self.nuclei_findings = nuclei_findings or []
        self.accounts = accounts or []
        self.allow_write = allow_write
        self._client = client

        self._cache: dict[str, Any] = {}
        self.notes: list[str] = []
        self.errors: list[str] = []
        self.probe_count = 0
        self.submissions: list[dict[str, Any]] = []   # 主动提交留痕，报告须披露
        #: 运行期边界封禁守门（由 registry_runner 挂上，见 `attach_guard`）。
        #:
        #: 挂上之后，每一次探测拿到的响应都会**顺手**喂给守门做一次便宜的
        #: 本地判断（只算哈希，不额外发请求）。作用是让封禁被发现的时机
        #: 从「下一次到点抽检」提前到「可疑迹象出现的那一刻」——
        #: 两次抽检之间的盲区里，检查项是在拦截页上跑完的，其中判「通过」的
        #: 那些就是**假通过**：它不是「没测」，而是主动给出的错误结论。
        self._guard: Any = None
        #: 运行期**目标健康度**守门（`hard_limits.stop_on` 的执行体，
        #: engine.banguard.TargetHealthWatch）。与上面那个守门是两件事：
        #:   · `_guard`  ← 「对方拦住我们」（403/429/拦截页）→ 退避降速后继续
        #:   · `_health` ← 「我们可能把对方打挂」（连续 5xx / 响应时间突增）
        #:                → **立即停手**，不可逆风险不做任何等待重试
        #: 两者共用同一条探测热路径喂入，但不共用结论、不共用报告措辞。
        self._health: Any = None

    def attach_guard(self, guard: Any) -> None:
        """挂上运行期边界守门（None 表示不启用）。"""
        self._guard = guard

    def attach_health(self, health: Any) -> None:
        """挂上运行期目标健康度守门（None 表示不启用）。"""
        self._health = health

    def _feed_guard(self, url: str, probe: Any) -> None:
        """把一次探测的响应喂给两个守门。**热路径，必须永不抛异常、永不阻塞。**"""
        try:
            if isinstance(probe, dict):
                st = probe.get("status", 0)
                body = probe.get("body_snippet") or probe.get("body") or ""
                ms = probe.get("elapsed_ms")
            else:
                st = getattr(probe, "status", 0)
                body = (getattr(probe, "body_snippet", "") or
                        getattr(probe, "body", "") or "")
                ms = getattr(probe, "elapsed_ms", None)
        except Exception:  # noqa: BLE001
            return
        h = self._health
        if h is not None:
            # 健康度只吃状态码与耗时，不吃正文 —— 省掉一次哈希计算。
            try:
                if st:
                    h.note_response(url, int(st or 0), ms)
                    if h.terminal:
                        h.mark_unexecutable(self)
                    elif getattr(h, "slowdown_requested", False):
                        # 宽免的代价在这里落地：站还活着 → 继续扫，但压速率。
                        # 标志不落到这里就等于「宽免 = 什么都不做」，保护机制名义生效、
                        # 实际不减速 —— 与「配置写了没人读」是同一类假保证。
                        h.apply_reprieve_slowdown(self._client)
            except Exception:  # noqa: BLE001
                pass
        g = self._guard
        if g is None:
            return
        try:
            if not st:
                return
            ev = g.note_response(url, int(st or 0), str(body)[:GUARD_BODY_LIMIT],
                                 probe_count=self.probe_count)
            if ev is None:
                return
            # 与 registry_runner._guard_tick 的处置保持一致：
            # 降速落到客户端；终态写进上下文，由注册表把后续项短路成「未执行」。
            g.apply_speed(self._client)
            if not ev.recovered:
                g.mark_unexecutable(self)
        except Exception:  # noqa: BLE001
            # 守门是保护措施，不是主流程 —— 它自己的故障绝不能中断检测器。
            pass

    # ------------------------------------------------------------------
    # 包一层请求，保证计数与缓存
    # ------------------------------------------------------------------
    @property
    def client(self) -> Any:
        return self._client

    def _extract_dns_txt(self, name: str) -> list[str]:
        """走公共递归查 TXT 记录（SPF / DMARC 用）。"""
        key = f"txt::{name}"
        if key in self._cache:
            return self._cache[key]
        out: list[str] = []
        try:
            from engine.fingerprint import PublicDnsResolver
            res = PublicDnsResolver()
            q = res.query(name, "TXT") if hasattr(res, "query") else []
            out = q or []
        except Exception:  # noqa: BLE001
            out = []
        if not out:
            out = self._dns_via_socket(name, "TXT")
        self._cache[key] = out
        return out

    @staticmethod
    def _dns_via_socket(name: str, rtype: str) -> list[str]:
        """用 dnspython / socket 兜底查询。"""
        out: list[str] = []
        try:
            import dns.resolver  # type: ignore
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = ["223.5.5.5", "119.29.29.29", "8.8.8.8"]
            r.lifetime = 5
            for ans in r.resolve(name, rtype):
                out.append(str(ans).strip('"'))
        except Exception:  # noqa: BLE001
            pass
        return out

    def dns_query(self, name: str, rtype: str = "A") -> list[str]:
        key = f"dns::{rtype}::{name}"
        if key in self._cache:
            return self._cache[key]
        vals = self._dns_via_socket(name, rtype)
        self._cache[key] = vals
        return vals

    # ------------------------------------------------------------------
    def get(self, url: str, method: str = "GET",
            allow_redirects: bool = True, max_body: int | None = None) -> Any:
        """带缓存的 GET / HEAD / OPTIONS。

        max_body：覆盖默认 4000 字符的 body_snippet 上限，用于依赖清单这类
        体积可能超过 4KB、且需完整 JSON 才能解析的场景（截断会破坏 JSON
        解析，导致「取到清单却解析为空」的静默漏报）。默认 None = 沿用引擎
        默认上限，不影响其它调用方。
        """
        key = f"{method}::{url}::{allow_redirects}::{max_body}"
        if key in self._cache:
            return self._cache[key]
        kwargs: dict[str, Any] = {}
        if max_body is not None:
            kwargs["max_body"] = max_body
        probe = self._client.fetch(
            url, method=method, allow_redirects=allow_redirects, **kwargs)
        self.probe_count += 1
        self._cache[key] = probe
        self._feed_guard(url, probe)
        return probe

    def raw_request(self, method: str, url: str, **kwargs: Any) -> Any:
        """不受 SAFE_METHODS 限制的请求，仅供受限场景使用。

        允许用途：
          - OPTIONS / TRACE：只读语义，用于 HTTP 方法测试
          - PUT / DELETE / PATCH：仅在 deep 档 + 显式开启受控写时放行，
            且调用方必须保证带唯一标记并可回滚
        """
        import requests

        m = method.upper()
        if m in ("OPTIONS", "TRACE", "HEAD", "GET"):
            pass
        elif not self.allow_write:
            raise PermissionError(
                f"{m} 属于写 / 侵入性方法，未开启受控写验证，拒绝执行"
            )
        key = f"RAW::{m}::{url}"
        if key in self._cache:
            return self._cache[key]
        self._client._throttle() if hasattr(self._client, "_throttle") else None
        try:
            r = requests.request(
                m, url, timeout=self._client.timeout,
                allow_redirects=False, verify=False,
                headers=dict(self._client.session.headers), **kwargs,
            )
            out = {
                "status": r.status_code,
                "headers": {k: v for k, v in r.headers.items()},
                "body": (r.text or "")[:8000],
                "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
                "error": "",
            }
        except Exception as e:  # noqa: BLE001
            out = {"status": 0, "headers": {}, "body": "", "elapsed_ms": 0,
                   "error": f"{type(e).__name__}: {str(e)[:120]}"}
        self.probe_count += 1
        self._cache[key] = out
        return out

    def _abs_url(self, url: str) -> str:
        """把相对路径补成绝对地址。

        ⚠ 这不是防御性编程，是**堵一个已经发生过的静默漏报**：
        第 23 轮实测，登录表单的提交地址来自前端推断的 `api_hint`，形如
        `/rest/user/login`（相对路径）。`requests.post("/rest/user/login")`
        抛 MissingSchema，被 except 吞成 `{"status": 0}` ——
        12 次默认口令尝试**一次都没有真正发出**，
        而报告上写的是「尝试 12 组，未命中」，读者只会读成「系统没有弱口令」。

        请求没发出去必须能被**看出来**，所以这一层只做补全长地址，
        不把失败静默化；补完之后仍然失败的话，status 0 会照常出现在留痕里。
        """
        u = str(url or "")
        if not u:
            return u
        if u.startswith(("http://", "https://")):
            return u
        try:
            from urllib.parse import urljoin  # noqa: PLC0415
            return urljoin(str(self.target_url or "").rstrip("/") + "/", u.lstrip("/"))
        except Exception:  # noqa: BLE001
            return u

    def form_submit(self, url: str, data: dict[str, Any], *,
                    max_attempts: int = 6) -> dict[str, Any]:
        """受限表单提交：仅用于登录尝试、账号枚举这类必须发 POST 的检查。

        三重约束，缺一不可：
          ① 档位必须是 deep（生产核心系统默认不会用这一档）；
          ② 单次检查的提交次数上限默认 6 次，且不做重试 ——
             避免把真实账号锁死（锁定类风险由 ATHN-03 人工专项处理）；
          ③ 所有提交内容记入 ctx.submissions，供报告如实披露做过什么。
        """
        if not self.risk_allowed(RISK_DEEP):
            raise PermissionError(
                "表单提交类检查需要 deep 档，当前档位不允许（避免误锁真实账号）"
            )
        if len(self.submissions) >= max_attempts:
            raise PermissionError(f"本项检查的提交次数已达上限 {max_attempts} 次")

        import requests

        url = self._abs_url(url)
        key = f"POST::{url}::{sorted(data.items(), key=lambda x: x[0])}"
        if key in self._cache:
            return self._cache[key]
        if hasattr(self._client, "_throttle"):
            self._client._throttle()
        try:
            r = requests.post(url, data=data, timeout=self._client.timeout,
                              allow_redirects=True, verify=False,
                              headers=dict(self._client.session.headers))
            out = {
                "status": r.status_code,
                "headers": {k: v for k, v in r.headers.items()},
                "body": (r.text or "")[:8000],
                "final_url": r.url,
                "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
                "error": "",
                "sent_fields": sorted(data.keys()),
            }
        except Exception as e:  # noqa: BLE001
            out = {"status": 0, "headers": {}, "body": "", "final_url": url,
                   "elapsed_ms": 0, "error": f"{type(e).__name__}: {str(e)[:120]}",
                   "sent_fields": sorted(data.keys())}
        self.probe_count += 1
        self.submissions.append({"url": url, "fields": sorted(data.keys()),
                                 "status": out["status"], "kind": "表单提交"})
        self._cache[key] = out
        return out

    def data_submit(self, url: str, payload: dict[str, Any], *,
                    method: str = "POST", as_json: bool = False,
                    account: Any = None, budget_key: str = "default",
                    max_total: int = 12, purpose: str = "differential") -> dict[str, Any]:
        """受限的 JSON / 表单数据提交，供业务参数差分实验使用。

        与 form_submit 的四点差异，都是被真实场景逼出来的：

          ① **支持 JSON 体**。业务接口几乎全是 application/json，
             只发 form-encoded 会得到 415 / 参数为空的响应，差分实验直接失效。
          ② **可以带某一组账号的凭据**。业务参数差分必须在登录态下做 ——
             匿名请求连业务对象都拿不到，比出来的差异没有意义。
          ③ **总次数用共享预算**：预算存在 ctx 里按 budget_key 累计，跨检测项共享。
             form_submit 的 max_attempts 是「单次调用」，多个检测项各自调用
             会叠加出远超预期的写请求量。业务逻辑侦察要打的接口最多、
             副作用最不可控，必须有全局闸门。
          ④ **缓存键用 JSON 序列化**：payload 可能是嵌套结构，
             sorted(data.items()) 会直接抛 TypeError。

        与 form_submit 一致的三条硬约束不变：
        deep 档 + 次数上限 + 全部记入 ctx.submissions 供报告披露。

        **第二道门（台账授权）—— 这里统一把守，不再依赖每个调用点手写**
        （过去漏一处就静默越权，正是「登记了却不生效」那一类，见红线 24）。
        按 `purpose` 区分两件事：

          purpose="differential"（默认）—— 业务差分写：创建对象 / 篡改业务参数 /
            提交业务数据。两把锁都要开：deep 档 + 台账 `allow_write` 显式授权。
            没有台账授权就真发请求，等于「选了 deep 档」被当成「被授权写」，
            是虚假的授权信心（registry_runner.py 注释已记过一次事故）。

          purpose="credential" —— 登录 / 注册尝试（红线 17 凭据链）。
            只判 deep 档，不判台账写授权：这类请求是**取得测试身份的前提**，
            不是「写验证」提交业务数据，且已由 `max_total` / form_submit
            的次数上限单独约束。把它也关在台账写授权后面，会静默掐断
            全部登录态覆盖，是更大的召回率损失。
        """
        if not self.risk_allowed(RISK_DEEP):
            raise PermissionError(
                "数据提交类检查需要 deep 档，当前档位不允许（避免对真实业务产生副作用）"
            )
        m = (method or "POST").upper()
        if m not in ("GET", "HEAD", "OPTIONS", "TRACE") and \
                purpose != "credential" and not self.allow_write:
            raise PermissionError(
                "受控写需要两把锁同时开：当前档位允许，但台账未对该目标授权"
                "写验证（补齐方式：ledger --register --allow-write）。见红线 24"
            )
        import json as _json

        url = self._abs_url(url)
        bkey = f"write_budget::{budget_key}"
        used = int(self._cache.get(bkey, 0) or 0)
        if used >= max_total:
            raise PermissionError(
                f"「{budget_key}」写请求预算已用尽（{used}/{max_total} 次），"
                "本次不再提交，避免对目标业务造成累计影响"
            )

        try:
            payload_sig = _json.dumps(payload, sort_keys=True, default=str)[:2000]
        except Exception:  # noqa: BLE001
            payload_sig = repr(sorted((str(k), str(v)) for k, v in payload.items()))
        key = f"DATA::{method}::{url}::{as_json}::{payload_sig}"
        if key in self._cache:
            return self._cache[key]

        import requests

        acc_headers = dict(getattr(account, "headers", {}) or {}) if account is not None else {}
        if isinstance(account, dict):
            acc_headers = dict(account.get("headers") or {})
        acc_cookies = dict(getattr(account, "cookies", {}) or {}) if account is not None else {}
        if isinstance(account, dict):
            acc_cookies = dict(account.get("cookies") or {})

        if hasattr(self._client, "_throttle"):
            self._client._throttle()
        hdrs = {**dict(self._client.session.headers), **acc_headers}
        kwargs: dict[str, Any] = {}
        if as_json:
            hdrs.setdefault("Content-Type", "application/json")
            kwargs["data"] = _json.dumps(payload, default=str).encode("utf-8")
        else:
            kwargs["data"] = {k: ("" if v is None else str(v)) for k, v in payload.items()}
        try:
            r = requests.request(
                method.upper(), url, timeout=self._client.timeout,
                allow_redirects=False, verify=False,
                headers=hdrs, cookies=acc_cookies or None, **kwargs,
            )
            out = {
                "status": r.status_code,
                "headers": {k: v for k, v in r.headers.items()},
                "body": (r.text or "")[:8000],
                "final_url": r.url,
                "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
                "error": "",
                "sent_fields": sorted(str(k) for k in payload.keys()),
            }
        except Exception as e:  # noqa: BLE001
            out = {"status": 0, "headers": {}, "body": "", "final_url": url,
                   "elapsed_ms": 0, "error": f"{type(e).__name__}: {str(e)[:120]}",
                   "sent_fields": sorted(str(k) for k in payload.keys())}

        self.probe_count += 1
        self._cache[bkey] = used + 1
        self.submissions.append({
            "url": url, "method": method.upper(), "fields": out["sent_fields"],
            "status": out["status"], "kind": "业务参数差分",
            "account": (getattr(account, "name", "") or
                        (account.get("name") if isinstance(account, dict) else "") or ""),
        })
        self._cache[key] = out
        return out

    def probe_path(self, path: str, base: str | None = None) -> Any:
        from urllib.parse import urljoin
        b = (base or self.target_url).rstrip("/") + "/"
        url = urljoin(b, path.lstrip("/"))
        return self.get(url)

    def probe_many(self, paths: Iterable[str], base: str | None = None) -> dict[str, Any]:
        """批量路径探测，复用底层并发能力并写入缓存。"""
        from urllib.parse import urljoin
        b = (base or self.target_url).rstrip("/") + "/"
        todo = [p for p in paths
                if f"GET::{urljoin(b, p.lstrip('/'))}::True" not in self._cache]
        if todo:
            res = self._client.probe_many(b, list(todo))
            self.probe_count += len(res)
            for p, probe in res.items():
                u = urljoin(b, p.lstrip("/"))
                self._cache[f"GET::{u}::True"] = probe
                # 批量探测是**最密集**的一条路径（一次几十上百个路径）。
                # 封禁期间它返回的每一条都是拦截页，不逐条喂给守门的话，
                # 只能等下一个检查项边界才发现 —— 那中间的整批结论都不可信。
                self._feed_guard(u, probe)
        out: dict[str, Any] = {}
        for p in paths:
            out[p] = self._cache.get(f"GET::{urljoin(b, p.lstrip('/'))}::True")
        return out

    # ------------------------------------------------------------------
    # 常用派生数据
    # ------------------------------------------------------------------
    @property
    def root(self) -> Any:
        return self.get(self.target_url)

    @property
    def root_headers(self) -> dict[str, str]:
        p = self.root
        return {k.lower(): v for k, v in (getattr(p, "headers", {}) or {}).items()}

    def header(self, name: str) -> str:
        return self.root_headers.get(name.lower(), "")

    @property
    def baseline_body(self) -> str:
        """根路径正文，用于对比判断自定义 404 页。"""
        return getattr(self.root, "body_snippet", "") or ""

    @property
    def tls(self) -> dict[str, Any]:
        return getattr(self.root, "tls", {}) or {}

    def risk_allowed(self, risk: str) -> bool:
        """当前档位是否允许执行该风险级别的检测。"""
        cur = RISK_ORDER.get(self.profile.get("risk_level", RISK_STANDARD), 1)
        return RISK_ORDER.get(risk, 0) <= cur

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    # ------------------------------------------------------------------
    def content_matches(self, path: str, body: str) -> bool:
        """判断 200 响应是否是该路径的真实内容，而不是自定义 404 页。"""
        if not body or len(body.strip()) < 15:
            return False
        base = self.baseline_body
        # 与首页完全一致 → 大概率是 SPA 回退，不算命中
        if base and body.strip()[:400] == base.strip()[:400]:
            return False
        lower = body.lower()
        # 明显的 404 / 错误页特征
        for marker in ("404 not found", "not found</h1>", "页面不存在",
                       "does not exist", "找不到页面", "no such file"):
            if marker in lower:
                return False
        return True


# ======================================================================
# 注册表
# ======================================================================
class DetectorRegistry:
    """检查项 → 执行体 的登记表。"""

    def __init__(self) -> None:
        self.specs: dict[str, DetectorSpec] = {}

    # ------------------------------------------------------------------
    def register(self, spec: DetectorSpec) -> None:
        if spec.item_id in self.specs:
            raise ValueError(f"检查项 {spec.item_id} 重复注册执行体")
        self.specs[spec.item_id] = spec

    def get(self, item_id: str) -> DetectorSpec | None:
        return self.specs.get(item_id)

    def __contains__(self, item_id: str) -> bool:
        return item_id in self.specs

    def __len__(self) -> int:
        return len(self.specs)

    # ------------------------------------------------------------------
    def coverage(self, all_item_ids: Iterable[str]) -> tuple[list[str], list[str]]:
        """返回 (已绑定, 未绑定)。未绑定项在任何报告里只能是「未执行」。"""
        ids = list(all_item_ids)
        covered = [i for i in ids if i in self.specs]
        missing = [i for i in ids if i not in self.specs]
        return covered, missing

    def stats(self) -> dict[str, int]:
        auto = sum(1 for s in self.specs.values() if not s.is_manual)
        manual = sum(1 for s in self.specs.values() if s.is_manual)
        return {"登记总数": len(self.specs), "自动检测器": auto, "人工执行指引": manual}

    # ------------------------------------------------------------------
    def execute(
        self,
        item,
        ctx: DetectorContext,
        *,
        applicability_state: str,
        applicability_note: str = "",
        skipped: bool = False,
        skip_reason: str = "",
        weak_na: bool = False,
    ) -> ItemResult:
        """执行单个检查项，产出结论。这是消除假阴性的唯一入口。

        `weak_na` —— 上游适用性判定的「N/A 是否基于弱证据」。只有它落进
        `ItemResult` 并随 `检查项结论.json` 归档，跨轮承接才能区分
        「**确证不适用**」与「**没看到**」：后者不构成推翻历史发现的证据。
        """
        spec = self.specs.get(item.id)

        base = ItemResult(
            item_id=item.id,
            name=item.name,
            category=item.category,
            category_name=item.category_name,
            state=STATE_NOTRUN,
            mode=MODE_AUTO,
            compliance=item.compliance,
            risk=spec.risk if spec else RISK_SAFE,
            requires=list(spec.requires) if spec else [],
            detector=spec.name if spec else "",
            tool=spec.tool if spec else "",
            evidence_kind=spec.evidence_kind if spec else "",
            procedure=spec.procedure if spec else "",
            expect=spec.expect if spec else "",
            why_manual=spec.why_manual if spec else "",
            detector_ref=spec.detector_ref if spec else "",
            # 只在「N/A」这种结论上才有意义 —— 其它状态下它不参与任何判定，
            # 但一并带上不会有歧义（读的人按 state 门控）。
            weak_na=bool(weak_na),
        )

        # ---- 用户显式跳过 ----
        if skipped:
            base.state = STATE_SKIP
            base.note = skip_reason or "用户要求跳过"
            return base

        # ---- 适用性未通过 ----
        if applicability_state != "适用":
            # 「待确认」+ 已确认登录态 → **照跑**（2026-10-10，红线 62 补丁）。
            # 「无法确认目标是否具备 X 特征」是**匿名视角**有限探测的结论；
            # 会话池里已有回验通过的登录态时，检测器完全有能力用真实凭据
            # 把「有没有」变成「有 / 没有」—— 卡在待确认等于放着一手证据不用。
            # 第十一轮实测：Juice Shop 的 has_session 匿名视角判「无法确认」，
            # SESS-05 / SESS-10（伪造回验、CSRF）整族被关 —— 而它们上一轮
            # 真跑出了严重发现。放行是安全的：检测器拿不到登录态时自然落
            # 「未执行 / 待人工」，绝不会因此产出假「通过」（红线 1 的门全在）。
            _cred_ready = any(
                (a.get("authorized") and not a.get("rejected")
                 and str(a.get("login_state") or "") == _LOGIN_OK)
                for a in (getattr(ctx, "accounts", None) or []))
            if not (applicability_state == "待确认" and _cred_ready):
                base.state = applicability_state
                base.note = applicability_note
                return base
            applicability_note += (
                "；匿名视角的「待确认」不构成跳过理由：已确认登录态就位，"
                "凭真实凭据执行，由检测器给出实证结论")

        # ---- 目标健康度异常：请求到达了应用，但应用正在报错 ----
        # **与上一段必须分开写**（2026-09-30）。两者的措辞不能互换：
        # 边界拦截是「请求未到达应用（拿到的是拦截页）」，
        # 健康度异常是「请求**确实到了**应用，应用自己返回 5xx / 耗时暴增」。
        # 复用同一段措辞就会在报告里写下与事实相反的话 —— 那比不给结论更坏。
        #
        # 同样按 `needs_app` 分流：DNS / crt.sh / 云端点直连这类项不碰应用，
        # 目标应用挂了也不影响它们的结论（且这些项往往是严重漏洞的唯一证据来源）。
        _unhealthy = (getattr(ctx, "_cache", {}) or {}).get("target_unhealthy")
        if _unhealthy and not (spec is not None and not spec.needs_app):
            _uw = _unhealthy.get("reason") or "目标健康度异常，本次主动停手"
            if spec is not None and spec.is_manual:
                base.state = STATE_MANUAL
                base.mode = MODE_MANUAL
                base.note = ((spec.procedure or "") +
                             f"\n\n⚠ 本次扫描因目标健康度异常而中止（{_uw}），"
                             "该人工项需要应用正常响应才能执行，本次未执行。")
                return base
            base.state = STATE_NOTRUN
            base.note = (f"未执行：{_uw}。本项需要目标应用正常响应才能判断，"
                         "扫描已在检测到异常后**立即停手**（不做等待重试，"
                         "避免加重故障），**不得据此认为该项通过**；"
                         "本次没有取得该项结论。")
            return base

        # ---- 边界防护拦截：请求没触达应用 ----
        # 这时若照常执行，检测器看到的不是应用而是拦截页，两种错误都会发生：
        #   ① 把拦截页当应用页面 → 产出真实环境复测不出来的「漏洞」；
        #   ② 采不到东西 → 被 collection_health 之外的分支写成 N/A，
        #      等于用一次失败的采集把风险判没了。
        # 所以**依赖应用响应**的项统一短路成「未执行」，并把拦截事实写进理由。
        #
        # 但短路必须**按依赖分流**：判据走非应用通道的项（DNS / TCP / TLS /
        # crt.sh / 云端点直连，见 DetectorSpec.needs_app）压根不看应用响应，
        # 拦截它们照样能跑。一刀切会把这类项的真实结论一并打成「未执行」——
        # 2026-09-30 实测就是这么丢掉 OSS 匿名列举（已确认的严重漏洞）的，
        # 通告的「问题清单」随之变空，读者读成「没问题」。
        _blk = (getattr(ctx, "_cache", {}) or {}).get("boundary_block")
        if _blk and not (spec is not None and not spec.needs_app):
            _why = _blk.get("reason") or "目标被边界防护拦截，未触达应用"
            if spec is not None and spec.is_manual:
                base.state = STATE_MANUAL
                base.mode = MODE_MANUAL
                base.note = ((spec.procedure or "") +
                             f"\n\n⚠ 本次采集被边界防护拦截（{_why}），"
                             "该人工项需要触达应用才能执行，本次未执行。")
                return base
            base.state = STATE_NOTRUN
            base.note = (f"未执行：{_why}。本项需要触达应用页面或接口才能判断，"
                         "本次请求未到达应用（拿到的是边界拦截页），"
                         "**不得据此认为该项通过**；本次没有取得该项结论。")
            return base

        # ---- 没有绑定执行体：明确报「未执行」，绝不判通过 ----
        if spec is None:
            base.state = STATE_NOTRUN
            base.note = ("该检查项在当前引擎版本中**没有绑定检测逻辑**，"
                         "本次未执行。请勿据此认为该项已通过。")
            return base

        # ---- 人工执行项 ----
        if spec.is_manual:
            base.state = STATE_MANUAL
            base.mode = MODE_MANUAL
            base.note = spec.procedure
            # 自动前置侦察：把「能自动做的部分」做掉，人工只回答只有人能回答的问题。
            #
            # 这里刻意**不改变「人工项」这个分类**：侦察再充分，该项的业务语义
            # 判定权仍在人手上，所以默认状态依然是「待人工执行」。
            # 唯一的例外是侦察**确证**了问题 —— 那时证据已经齐全、可复测，
            # 就按「不通过」计入发现列表，否则等于把已经拿到手的漏洞藏起来。
            if spec.recon is not None:
                self._apply_recon(base, spec, ctx)
            return base

        # ---- 档位限制 ----
        if not ctx.risk_allowed(spec.risk):
            base.state = STATE_NOTRUN
            base.note = (f"该检测属于「{spec.risk}」风险档，"
                         f"当前档位（{ctx.profile.get('name', '标准档')}）未开启。"
                         f"如需执行请使用更高档位。")
            return base

        # ---- 前置条件 ----
        lack = self._missing_requirements(spec, ctx)
        if lack:
            base.state = STATE_NOTRUN
            base.note = f"前置条件不足，未执行：{'、'.join(lack)}"
            return base

        # ---- 真正执行 ----
        t0 = time.time()
        try:
            outcome = spec.run(ctx) if spec.run else DetectorOutcome(ok=False, error="检测器为空")
            base.duration_ms = int((time.time() - t0) * 1000)
            base.probes = outcome.probes
            base.executable = True
            if not outcome.ok:
                base.state = STATE_NOTRUN
                base.note = f"检测器执行失败，未得出结论：{outcome.error or '未知原因'}"
                return base
            # ---- 检测跑了，但外部确实判不出来：报「待确认」，绝不判通过 ----
            if outcome.pending:
                base.state = STATE_PENDING
                base.note = outcome.note
                base.evidence_kind = outcome.evidence_kind
                base.probes = outcome.probes
                return base
            # ---- 已确认目标不具备该功能：报 N/A，而不是「通过」 ----
            # 这是「测了没问题」与「没有可测对象」的分界，混淆会让通过率虚高。
            if outcome.not_applicable and not outcome.findings:
                base.state = STATE_NA
                base.note = outcome.note
                base.evidence_kind = outcome.evidence_kind
                base.probes = outcome.probes
                return base
            for f in outcome.findings:
                f.source_tool = f.source_tool or spec.name
                if not f.item_id:
                    f.item_id = item.id
            if outcome.findings:
                base.state = STATE_FIND
                base.findings = list(outcome.findings)
                base.finding_titles = [f.title for f in outcome.findings]
                base.finding_ids = [f.item_id for f in outcome.findings]
            else:
                base.state = STATE_PASS
            base.note = outcome.note
            return base
        except Exception as e:  # noqa: BLE001
            base.duration_ms = int((time.time() - t0) * 1000)
            base.state = STATE_NOTRUN
            base.note = (f"检测器异常，未得出结论：{type(e).__name__}: {str(e)[:160]}"
                         f"（已捕获，未中断整体扫描）")
            ctx.errors.append(f"{item.id}: {type(e).__name__}: {str(e)[:120]}")
            return base

    @staticmethod
    def _apply_recon(base: ItemResult, spec: DetectorSpec, ctx: DetectorContext) -> None:
        """执行人工项的自动前置侦察，把结果写进该结论。

        三种结果在报告里的读法完全不同，绝不能混：

          ① **侦察确证了问题** → 状态改「不通过」，证据进发现列表。
             这时残留人工部分仍要写清楚：抓到的只是这一项里可自动证的那一块。
          ② **侦察跑了但没确证** → 状态保持「待人工执行」。
             绝不因为「侦察没抓到」而判通过 —— 侦察的覆盖面本来就窄于该项的完整定义。
          ③ **侦察没跑起来**（档位不足 / 无登录态 / 环境变量关闭）→ 状态保持
             「待人工执行」，但必须**显式写出「侦察未执行 + 原因」**。

        第 ③ 种最容易被糊过去：读者看到一份写得很细的人工步骤，
        会默认自动化已经把能做的都做了。把「没做」写出来，才不会制造这种错觉。
        """
        try:
            ro = spec.recon(ctx)  # type: ignore[misc]
        except Exception as e:  # noqa: BLE001
            base.recon_ran = False
            base.recon_note = (f"自动侦察异常，未得出结论：{type(e).__name__}: {str(e)[:160]}"
                               f"（已捕获，未中断整体扫描）")
            base.note = (base.recon_note +
                         "\n\n【人工执行步骤】\n" + spec.procedure +
                         "\n\n⚠ 本次自动侦察异常，本项的人工步骤**没有任何自动化前置覆盖**。")
            ctx.errors.append(f"{base.item_id}: 侦察异常 {type(e).__name__}: {str(e)[:120]}")
            return

        base.recon_ran = bool(ro.ran)
        base.recon_probes = int(ro.probes or 0)
        base.recon_lead = list(ro.lead or [])
        base.recon_note = ro.note or ""
        base.recon_finding_count = len(ro.findings or [])
        base.probes = max(int(base.probes or 0), base.recon_probes)

        parts: list[str] = []
        if ro.ran:
            parts.append("【自动侦察结论】" + (ro.note or "（无说明）"))
            if ro.lead:
                parts.append(
                    "本次侦察已定位到的具体对象 —— 人工只需按此逐条执行，"
                    "不需要自己去找接口和字段：\n" +
                    "\n".join(f"  · {x}" for x in ro.lead))
        else:
            # ⚠ 这里**必须**把 note 一并带出来。
            # `_manual_only(reason, extra=...)` 把补齐方式写在 note 里、原因写在
            # error 里；只渲染 error 的话，「怎么补」这句话会被静默丢掉 ——
            # 报告上剩一句「侦察未执行」，操作者知道缺东西却不知道该给什么。
            # 这类信息丢失不会报错，只会让人多做几轮无效往返。
            _why = ro.error or ro.note or "原因不明"
            _extra = ""
            if ro.note and ro.error and ro.note.strip() not in _why:
                _extra = "\n" + ro.note.strip()
            parts.append(
                "【自动侦察未执行】" + _why + _extra +
                "\n⚠ 本项的人工步骤**没有任何自动化前置覆盖**，需从零开始执行。")

        if ro.findings:
            base.state = STATE_FIND
            base.findings = list(ro.findings)
            base.finding_titles = [f.title for f in ro.findings]
            base.finding_ids = [f.item_id for f in ro.findings]
            for f in base.findings:
                f.source_tool = f.source_tool or f"{spec.name}·自动侦察"
            parts.append(
                f"⚠ 自动侦察已确证 {len(ro.findings)} 项问题，已计入发现列表。"
                "**以下人工步骤仍须执行** —— 侦察只覆盖了本项中可自动证的那一部分。")

        parts.append("【人工执行步骤】\n" + spec.procedure)
        base.note = "\n\n".join(parts)

    @staticmethod
    def _missing_requirements(spec: DetectorSpec, ctx: DetectorContext) -> list[str]:
        lack: list[str] = []
        for req in spec.requires:
            if req == "accounts" and len(ctx.accounts) < 2:
                lack.append("需要至少 2 组测试账号（多账号交叉比对）")
            elif req == "write" and not ctx.allow_write:
                lack.append("需要开启受控写验证（授权书须写明允许写入测试数据）")
            elif req == "js":
                miss = DetectorRegistry._frontend_lack(ctx.js_result)
                if miss:
                    lack.append(miss)
            elif req == "nuclei" and not ctx.nuclei_findings:
                lack.append("需要 nuclei 模板检测结果（工具不可用或无命中）")
        return lack

    #: 前端分析素材的四个来源见 `engine/frontend.py:has_material`。
    #: 过去闸门只看 `ctx.js_result` 整体是否为空，两个方向都会出错：
    #: 素材很全但被采集阶段一次异常清空时集体落「未执行」；
    #: 而一个只有 `spa` 标记、其他字段全空的对象又能混过去，
    #: 让检测器在空数据上跑完并报「通过」—— 那是最坏的一种假阴性。
    #: 判据统一收在 frontend 模块里，避免两处各写一份、慢慢走偏。
    @staticmethod
    def _has_frontend_material(js: Any) -> bool:
        from engine import frontend as _frontend  # noqa: PLC0415
        return _frontend.has_material(js)

    @staticmethod
    def _frontend_lack(js: Any) -> str:
        """返回缺失说明；素材够用时返回空串。

        说明必须**是具体原因**，不能只写一句「未采集到前端产物」——
        实测里这句话掩盖过三种完全不同的情形（目标不可达 / 页面无脚本引用 /
        脚本引用取不到），三者的补齐方式完全不同，写成一团等于没写。
        """
        if DetectorRegistry._has_frontend_material(js):
            return ""
        note = str((js or {}).get("collect_note") or "").strip()
        detail = ""
        if note:
            # 只取覆盖度说明，去掉过长的来源账目
            frag = note.split("；")
            detail = frag[-1] if len(frag) > 1 else note
        return ("需要前端分析素材（脚本正文 / 内联脚本 / 接口地址 / 组件清单），"
                "本次一项都没取到"
                + (f"：{detail[:160]}" if detail else "（目标不可达或未取到任何页面内容）"))

    # ------------------------------------------------------------------
    @staticmethod
    def summarize(results: list[ItemResult]) -> dict[str, int]:
        out: dict[str, int] = {s: 0 for s in ALL_STATES}
        for r in results:
            out[r.state] = out.get(r.state, 0) + 1
        out["合计"] = len(results)
        out["自动执行"] = sum(1 for r in results if r.executable)
        out["未执行"] = out.get(STATE_NOTRUN, 0)
        out["待人工执行"] = out.get(STATE_MANUAL, 0)
        # 可信通过率：通过数 / 自动执行数
        executed = out["自动执行"]
        out["通过率"] = round(out[STATE_PASS] / executed, 3) if executed else 0.0
        return out


# ======================================================================
# 注册装饰器
# ======================================================================
def make_auto(
    item_id: str,
    *,
    name: str,
    tool: str = "内置检测器",
    risk: str = RISK_SAFE,
    requires: list[str] | None = None,
    evidence_kind: str = "",
    detector_ref: str = "",
    needs_app: bool = True,
) -> DetectorSpec:
    """把一个函数注册为自动检测器。

    返回值是 DetectorSpec，既可当装饰器（@make_auto(...)），
    也可直接赋给变量（SPEC_X = make_auto(...)）。

    `needs_app=False` 仅用于判据完全走非应用通道的检测器（DNS / TCP / TLS /
    crt.sh / 云端点直连），详见 `DetectorSpec.needs_app` 的说明。
    """
    return DetectorSpec(
        item_id=item_id,
        mode=MODE_AUTO,
        run=None,
        name=name,
        tool=tool,
        risk=risk,
        requires=list(requires or []),
        evidence_kind=evidence_kind,
        detector_ref=detector_ref,
        needs_app=needs_app,
    )


def make_manual(
    item_id: str,
    *,
    name: str,
    procedure: str,
    expect: str = "",
    why_manual: str = "",
    requires: list[str] | None = None,
    risk: str = RISK_STANDARD,
    tool: str = "人工核查",
    recon: Callable[["DetectorContext"], ReconOutcome] | None = None,
    recon_gap: str = "",
) -> DetectorSpec:
    """把一项登记为人工执行项。procedure 必须写成可照做的步骤。

    recon —— 该项的自动前置侦察（engine.business）。挂了侦察不代表该项变成
    自动项：业务语义的判定权仍在人手上，状态依然是「待人工执行」。
    侦察只是把「找接口、找字段、记当前值、做差分」这些准备活做掉，
    让人工直接进入判断环节。

    确实连前置侦察都做不了的项，用 recon_gap 写明原因 ——
    什么都不写会让这一项悄悄退回「从零开始全人工」，
    validate_coverage 会对业务逻辑类报出这种缺省。

    返回 DetectorSpec，同样支持装饰器写法与直接调用写法。
    """
    return DetectorSpec(
        item_id=item_id,
        mode=MODE_MANUAL,
        run=None,
        name=name,
        tool=tool,
        risk=risk,
        requires=list(requires or []),
        procedure=procedure,
        expect=expect,
        why_manual=why_manual,
        detector_ref="manual",
        recon=recon,
        recon_gap=recon_gap,
    )


def collect_from_modules(registry: DetectorRegistry, modules: list[Any]) -> None:
    """从已导入的模块里收集所有被装饰器绑定的执行体。

    两种写法都要认：
      ① 装饰器写法  @make_auto(...) / @make_manual(...)  → 挂在函数对象上；
      ② 直接调用写法 SPEC_X = make_manual(...)           → 模块级 DetectorSpec 实例。
    只认第一种会让「直接调用写法」的人工项静默漏掉，
    而漏掉的项在报告里会显示成「无检测逻辑」—— 正是要根治的那类问题。
    """
    found_specs: list[DetectorSpec] = []
    for mod in modules:
        for obj in vars(mod).values():
            spec = getattr(obj, "_detector_spec", None)
            if isinstance(spec, DetectorSpec):
                found_specs.append(spec)
            elif isinstance(obj, DetectorSpec):
                found_specs.append(obj)
    registered: set[str] = set()
    for spec in found_specs:
        if spec.item_id in registered:
            continue          # 同一项被两种写法重复登记，保留先出现的
        registered.add(spec.item_id)
        registry.register(spec)


# ======================================================================
# 辅助：构造 Finding 的便捷函数（各检测器共用，保证字段一致）
# ======================================================================
def make_finding(
    item_id: str,
    title: str,
    target: str,
    *,
    endpoint: str = "",
    method: str = "",
    param: str = "",
    severity: str = "中危",
    confidence: str = "Medium",
    evidence_level: str = "B",
    description: str = "",
    technical_detail: str = "",
    impact: str = "",
    reproduction: str = "",
    remediation: str = "",
    compliance: str = "",
    evidence: list[Any] | None = None,
    grading_basis: str = "",
    extra: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        item_id=item_id,
        title=title,
        target=target,
        endpoint=endpoint,
        method=method,
        param=param,
        severity=severity,
        confidence=confidence,
        evidence_level=evidence_level,
        description=description,
        technical_detail=technical_detail,
        impact=impact,
        reproduction=reproduction,
        remediation=remediation,
        compliance=compliance,
        evidence=evidence or [],
        grading_basis=grading_basis,
        extra=dict(extra or {}),
    )
