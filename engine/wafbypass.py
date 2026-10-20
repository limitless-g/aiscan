"""边界防护绕过试探（红队视角，受限、有界）。

探到边界防护之后，红队的标准动作是**试着绕过它** —— 不试就下「防护有效」
的结论，等于只测了「正面硬闯」。本模块用一小撮**无副作用**的请求变形
试探拦截的覆盖面：全部 GET/HEAD，不带任何攻击 payload，总量有硬上限
（默认 12 个请求，吃客户端自身的限速通道）。

结论只有两档，措辞刻意保守：

- **blocked**：拦截特征命中（厂商特征或与已知拦截页同哈希）—— 该变形被拦住
- **missed**：未被拦截特征命中且返回 2xx/3xx —— 只写「未被拦截特征命中」，
  **不写「绕过成功」**：响应也可能是源站错误页或另一层拦截，
  这个判断要人工复核后才成立

变形族（每族都是公开的、任何渗透测试课程都会讲的手法，无完整利用链）：
伪造内网来源头、爬虫 UA、Referer 回环、X-Original-URL、路径规范化变形、
方法降级（HEAD）。

**必须带对照实验（2026-09-30 实测后加的硬约束）**

整批试探之前，先发**一个不带任何变形的基线请求**（同一客户端、同一时刻、
同一限速通道），把结果作为列表的第一项。原因是实测撞上的一个陷阱：

    试探当时只在「已经探到拦截」时才触发，于是 12 个变形**全部**返回同一张
    405 阿里云拦截页；而那时**连不带任何变形的请求也是 405** ——
    「全部被拦住」于是区分不出「WAF 识别了这些变形」与「本来源已经死了，
    发什么都拦」。通告据此写出「拦截对本来源覆盖完整」，是一句没有证据的话。

判据因此收紧：**基线通，变形被拦才算「该变形被拦住」**；
基线不通时整批结论作废（`summarize()` 的 `usable=False`），
通告只能写「本次无法评估绕过有效性」，不得写覆盖率。
这一条与红线「孤立信号不得当正面证据」同源：没有对照的拦截计数不是证据。
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from engine.wafgate import detect_block_page

#: 单轮试探的请求总数硬上限。绕过试探是**定性**动作（有没有明显缺口），
#: 不是穷举 —— 穷举交给专门工具且必须单独授权。
MAX_PROBES = 12

#: 基线对照项的名字。它不是一个「变形」，而是同时刻的**无变形**请求，
#: 用来证明「此刻正常请求能通」—— 没有它，变形全被拦说明不了任何问题。
BASELINE_NAME = "基线对照（无变形，同一客户端同一时刻）"

_UA_GOOGLEBOT = ("Mozilla/5.0 (compatible; Googlebot/2.1; "
                 "+http://www.google.com/bot.html)")
_UA_BAIDU = ("Mozilla/5.0 (compatible; Baiduspider/2.0; "
             "+http://www.baidu.com/search/spider.html)")


@dataclass
class BypassProbe:
    """单个变形试探的结果。"""

    name: str                      # 变形族名（人话，直接进通告）
    request_desc: str              # 请求描述（脱敏后的方法 + URL + 附加头）
    outcome: str = "error"         # blocked / missed / error
    status: int = 0
    why: str = ""
    #: 是否为本轮的基线对照项。它不进「变形被拦」的统计，只用于判定
    #: 整批结果是否可采信。
    is_baseline: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "request": self.request_desc,
            "outcome": self.outcome,
            "status": self.status,
            "why": self.why,
            "is_baseline": self.is_baseline,
        }


def _variants(target_url: str) -> list[tuple[str, str | None, str, str]]:
    """生成变形清单：`(变形名, 附加头或 None, url, method)`。

    数量控制在 `MAX_PROBES` 以内；顺序即优先级（先试最常见的手法）。
    """
    base = target_url.rstrip("/")
    _bust = f"{random.randint(1 << 20, 1 << 29):x}"  # nosec B311 非安全用途
    return [
        ("伪造内网来源（X-Forwarded-For: 127.0.0.1）",
         {"X-Forwarded-For": "127.0.0.1"}, base, "GET"),
        ("伪造内网来源（X-Forwarded-For: 10.0.0.1）",
         {"X-Forwarded-For": "10.0.0.1"}, base, "GET"),
        ("伪装搜索引擎爬虫 UA（Googlebot）",
         {"User-Agent": _UA_GOOGLEBOT}, base, "GET"),
        ("伪装搜索引擎爬虫 UA（Baiduspider）",
         {"User-Agent": _UA_BAIDU}, base, "GET"),
        ("Referer 回环（伪装从本站跳转）",
         {"Referer": target_url}, base, "GET"),
        ("X-Original-URL 指向根路径",
         {"X-Original-URL": "/"}, f"{base}/nonexist-bypass-probe", "GET"),
        ("路径规范化变形（/./）", None, f"{base}/./", "GET"),
        ("路径规范化变形（//）", None, f"{base}//", "GET"),
        ("追加无意义查询参数", None, f"{base}/?_b={_bust}", "GET"),
        ("尾斜杠变形", None, f"{base}/", "GET"),
        ("方法降级（HEAD）", None, target_url, "HEAD"),
        ("宿主名大小写变形", None, _flip_host_case(target_url), "GET"),
    ][: max(1, int(MAX_PROBES))]


def _flip_host_case(url: str) -> str:
    """把宿主段翻一个字符的大小写。域名不区分大小写，边界若按原文匹配就会漏。"""
    parts = urlsplit(url)
    host = parts.netloc
    if not host:
        return url
    for i, ch in enumerate(host):
        if ch.isalpha():
            host = host[:i] + (ch.lower() if ch.isupper() else ch.upper()) + host[i + 1:]
            break
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _classify(client: Any, p: BypassProbe, url: str, method: str,
              extra: dict[str, str] | None,
              v_status: int, v_hash: str) -> None:
    """发一个请求，把结果归到 blocked / missed / error，写回 `p`。

    归类规则与既有实现一致（不改判据，只把它抽出来给基线与变形共用，
    保证两者**用同一把尺子量**——尺子不同，对照就不成立）。
    """
    try:
        r = client.fetch(url, method=method, extra_headers=extra)
    except Exception as e:  # noqa: BLE001
        p.why = f"{type(e).__name__}: {str(e)[:80]}"
        return
    p.status = int(getattr(r, "status", 0) or 0)
    body = str(getattr(r, "body_snippet", "") or "")
    headers = getattr(r, "headers", None)
    cookies = getattr(r, "cookies", None)

    hit, _vendor, why = detect_block_page(p.status, headers, body, cookies)
    same_page = bool(v_hash) and (_snapshot_hash(r) == v_hash)
    if hit or same_page or (v_status and p.status == v_status
                            and v_status not in (0, 200)):
        p.outcome = "blocked"
        p.why = why or (f"HTTP {p.status} 与已知拦截页一致" if same_page
                        else f"HTTP {p.status} 与拦截判定同码")
    elif 200 <= p.status < 400:
        p.outcome = "missed"
        p.why = f"HTTP {p.status}，未命中拦截特征"
    else:
        p.outcome = "error"
        p.why = f"HTTP {p.status}，形态无法归类（不进结论）"


def probe_bypasses(client: Any, target_url: str, verdict: Any, *,
                   max_probes: int = MAX_PROBES) -> list[dict[str, Any]]:
    """对一个目标执行一圈变形试探，**并先做一次基线对照**。

    `verdict` 是 `wafgate.BlockVerdict`（提供 `status` / `root_hash` 等对照基准）；
    可以为 None —— 此时只靠厂商特征判定。
    每个请求都走 `client` 自身的限速通道，不额外控制节奏。

    返回列表**第 0 项固定是基线对照**（`is_baseline=True`）：一次不带任何变形的
    普通请求，用来回答「此刻正常请求能不能通」。基线不通时，后面每个变形的
    `blocked` 都不能读成「WAF 识别了这个变形」—— 它只说明本来源整体已被拦。
    """
    out: list[dict[str, Any]] = []
    v_status = int(getattr(verdict, "status", 0) or 0) if verdict is not None else 0
    v_hash = str(getattr(verdict, "root_hash", "") or "") if verdict is not None else ""

    # ---- ① 基线对照：不带任何变形，同一客户端、同一时刻 ----
    b = BypassProbe(name=BASELINE_NAME,
                    request_desc=f"GET {target_url}（无任何变形）",
                    is_baseline=True)
    _classify(client, b, target_url, "GET", None, v_status, v_hash)
    out.append(b.to_dict())

    # ---- ② 逐个变形 ----
    for name, extra, url, method in _variants(target_url)[:max_probes]:
        head_desc = ("" if not extra
                     else " + " + "、".join(f"{k}: {str(v)[:24]}"
                                            for k, v in extra.items()))
        desc = f"{method} {url}{head_desc}"
        p = BypassProbe(name=name, request_desc=desc)
        _classify(client, p, url, method, extra, v_status, v_hash)
        out.append(p.to_dict())
    return out


def _snapshot_hash(resp: Any) -> str:
    """对响应正文做与 wafgate 同源的归一化哈希。"""
    from engine.wafgate import _body_hash  # noqa: PLC0415  同包内复用私有实现

    return _body_hash(str(getattr(resp, "body_snippet", "") or ""))


def summarize(probes: list[dict[str, Any]]) -> dict[str, Any]:
    """把试探结果压成通告/报告要的字段。

    `usable` 是**基线对照是否成立**：基线项（`is_baseline`）本身不进 `tried`
    统计，它只回答「此刻正常请求能不能通」。基线不通时整批结论作废 ——
    此时 `blocked` 的计数不得读成「WAF 识别了这些变形」，它只说明
    本来源已被整体封禁（2026-09-30 内部生产系统 实测的原形）。

    `bypass_candidates` 是**反方向**的字段，两者必须分开表达：

      · `usable`      管的是「能不能写**覆盖率**」—— 覆盖率断言需要基线通；
      · `candidates`  管的是「有没有**绕过信号**」—— 而绕过信号恰恰需要
        基线**不通**才有意义：有别的东西在拦（基线被拦死了），
        这个变形却穿了过去。

    2026-09-30 修：早先只有 `usable` 一个字段，「基线不通 → 整批作废」把
    「基线不通而某变形通了」这个**最值钱的发现**一起丢掉了。
    """
    baseline = next((p for p in probes if p.get("is_baseline")), None)
    baseline_ok = bool(baseline) and baseline.get("outcome") == "missed"
    #: 基线是否**确认被拦**。「基线 error（连接失败等）」不算 —— 那种情况下
    #: 整批结果都不可信，不能说「有别的东西在拦」。
    baseline_blocked = bool(baseline) and baseline.get("outcome") == "blocked"
    tried = [p for p in probes
             if not p.get("is_baseline")
             and p.get("outcome") in ("blocked", "missed")]
    blocked = [p for p in tried if p["outcome"] == "blocked"]
    missed = [p for p in tried if p["outcome"] == "missed"]

    # 绕过候选：**基线被拦死、而这个变形没被拦** → 它可能穿过了边界。
    # 注意措辞停留在「候选」：响应也可能是源站错误页或另一种形态的拦截，
    # 这个判断必须人工复核后才成立（见模块 docstring 的结论两档）。
    candidates = [p for p in missed] if baseline_blocked else []

    return {
        "tried": len(tried),
        "blocked": len(blocked),
        "missed": len(missed),
        "missed_names": [p.get("name", "") for p in missed],
        "baseline_status": int((baseline or {}).get("status", 0) or 0),
        "baseline_ok": baseline_ok,
        "baseline_blocked": baseline_blocked,
        #: 整批结论是否可采信。False 时不得写「拦截覆盖完整」/
        #: 「均被拦住」这类覆盖率断言，只能写「本次无法评估」。
        "usable": baseline_ok,
        #: **一个变形都没被拦**。这种结果有个专门的读法陷阱：它看起来最像
        #: 「绕过面很大」，实际上多半是「边界此刻对这些请求整体没生效」——
        #: 判据就是同一批里的基线（无变形请求）也照样直达应用。
        #: 没有拦可拦的东西时，绕过无从谈起，**不得**写成「疑似存在绕过面」。
        #: 2026-09-30 内部生产系统 实测就是这个形态：12/12 未被拦，同时基线 HTTP 200。
        "nothing_blocked": bool(tried) and not blocked,
        #: **绕过候选**（见上方 docstring）：基线被拦、变形未被拦。
        #: 只作「候选」—— 不得直接写成「绕过成功」，需人工复核。
        "bypass_candidates": [dict(p) for p in candidates],
        "bypass_candidates_note": (
            f"基线请求（无任何变形）已被拦截（HTTP "
            f"{(baseline or {}).get('status', 0)}），而下列 {len(candidates)} 种"
            f"变形未命中任何拦截特征 —— 它们**可能**穿过了边界。"
            "这是候选而非结论：响应也可能是源站错误页或另一种形态的拦截，"
            "需人工复核后才可写成「绕过」。"
            if candidates else ""
        ),
    }
