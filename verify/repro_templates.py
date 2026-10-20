# -*- coding: utf-8 -*-
"""
L3 复现模板族 —— 按「证据形态」生成可独立执行的复现脚本
=========================================================

设计原则（这是本模块存在的理由）
--------------------------------
旧实现按 item_id 硬编码专用模板，只有 4 个检查项享受专用逻辑，
其余全部落到一个「请求一次、看状态码」的兜底 —— 那不是复现脚本，
是「URL 还能不能打开」的检查。报告里写着「每项均附可独立执行的复现脚本」，
实际上 133 项的脚本内容一模一样且不含任何断言。

本模块改为**按证据形态选择模板**。因为复现的本质只有一个：
    把检测器当时看到的客观事实，用独立方式再验证一次。

于是模板的断言必须来自「当时实测到的那段证据」，而不是泛泛的可达性。
每个模板返回 (脚本体, 预期结果, 复现强度)：

    强度 strong  —— 断言基于具体特征（内容片段 / 语义特征串 / 状态码 / 载荷回显），
                    复现成功即能独立证明该问题存在，且带对照实验排除伪命中。
    强度 medium  —— 断言基于状态码或协议层可观测现象，能证明「端点行为与预期不符」，
                    但不足以单凭它认定危害。
    强度 weak    —— 只有可达性断言。**报告必须显式披露**，
                    不得与 strong 混在一起呈现。

退出码语义（与 framework 一致）：
    0 = 复现成功（问题确认存在） / 1 = 未复现 / 2 = 执行错误
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# 会话上下文：越权类复现脚本需要以真实身份请求（见 verify/sessionctx.py）。
# 两种导入路径都要支持 —— 本模块既作为 `verify.repro_templates` 被引用，
# 也会被单独导入用于离线自测。
try:
    from verify.sessionctx import MAX_ROLES, SESSION_KINDS, roles_of  # noqa: F401
except ImportError:  # noqa: BLE001
    from sessionctx import MAX_ROLES, SESSION_KINDS, roles_of  # type: ignore  # noqa: F401

STRENGTH_STRONG = "strong"
STRENGTH_MEDIUM = "medium"
STRENGTH_WEAK = "weak"

STRENGTH_LABEL = {
    STRENGTH_STRONG: "强（含特征断言与对照实验）",
    STRENGTH_MEDIUM: "中（状态码 / 协议层断言）",
    STRENGTH_WEAK: "弱（仅可达性，需人工核对）",
}


# ------------------------------------------------------------------------------
# 复现计划：从一条 Finding 抽取出的「复现要素」
# ------------------------------------------------------------------------------
@dataclass
class ReproPlan:
    """一条发现的复现要素。由选择器填写，模板据此生成脚本。"""

    kind: str = "weak_probe"
    probe_path: str = ""              # 相对 target 根的路径（含查询串）
    method: str = "GET"
    param: str = ""
    payload: str = ""                 # 重放载荷
    markers: list[str] = field(default_factory=list)   # 断言用特征串
    control_path: str = ""            # 对照组路径（应 404 或行为不同）
    expect_status: int = 200
    sample: str = ""                  # 当时实测到的片段（脱敏后）
    extra: dict[str, Any] = field(default_factory=dict)

    def url_expr(self) -> str:
        """生成脚本中探针 URL 的表达式片段。"""
        if not self.probe_path:
            return 'base = target.rstrip("/")'
        p = self.probe_path
        if p.startswith(("http://", "https://")):
            return f'probe_url = {p!r}'
        return f'probe_url = target.rstrip("/") + {p!r}'


# ------------------------------------------------------------------------------
# 生成脚本共用的内联助手（保证脚本脱离本工程也能跑）
# ------------------------------------------------------------------------------
INLINE_HELPERS = '''
def _fetch(url, timeout, method="GET", data=None, extra_headers=None, follow=False):
    """发一次请求。默认不跟随跳转 —— 跳转本身往往就是待验证的现象。"""
    headers = dict(DEFAULT_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    return requests.request(method, url, headers=headers, data=data,
                            timeout=timeout, verify=False, allow_redirects=follow)


def _probe_control(base, timeout, control_path):
    """对照实验：请求一个必然不存在的路径，用于识别「伪 200 / 自定义错误页」。"""
    url = base.rstrip("/") + "/" + control_path.lstrip("/")
    try:
        r = _fetch(url, timeout)
        return r.status_code, len(r.text or "")
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}"
'''


def _markers_literal(markers: list[str]) -> str:
    return json.dumps(markers[:8], ensure_ascii=False)


def _control_literal(path: str) -> str:
    if path:
        return json.dumps(path, ensure_ascii=False)
    return '"aiscan-control-" + "9f3c1d7e-should-not-exist"'


# ==============================================================================
# 模板 1：响应内容特征复现（凭据泄漏 / 版本号 / PII / 内部地址 / 栈追踪）
# ==============================================================================
def t_content_marker(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：用**同一套检测规则**独立重扫对外产物，看能否再得出同样结论。

    为什么不比对「当时的特征串」
    --------------------------
    证据里存的是检测器的**结论摘要**（如 "sinks=['innerHTML 赋值']"），
    那是 Python repr，不是响应原文 —— 拿它去响应里找，永远找不到。
    所以这里改为把检测规则内嵌进脚本，让它**独立重跑一次检测**：
    规则再次命中，才叫复现成功。

    特征可能出现在根页面、也可能在某个前端产物里，因此遍历全部候选地址。
    """
    rules = plan.extra.get("rules") or {}
    candidates = plan.extra.get("candidates") or [plan.probe_path or "/"]
    body = f'''{INLINE_HELPERS}
import json as _json

# 检测规则：{{类别: [[正则, 说明], ...]}} —— 与扫描时所用规则一致
RULES = _json.loads(r"""{json.dumps(rules, ensure_ascii=False)}""")
# 兜底特征（规则为空时使用）
MARKERS = {_markers_literal(plan.markers)}
CANDIDATES = {json.dumps(candidates[:12], ensure_ascii=False)}
CONTROL_PATH = {_control_literal(plan.control_path)}
# 资源引用正则（json.dumps 输出的就是合法 Python 字符串字面量）
ASSET_RE = {json.dumps(r'<(?:script|link|img|iframe)[^>]+(?:src|href)\s*=\s*["\']([^"\']+)["\']')}


def _discover_assets(base, text):
    """从页面解析脚本 / 样式 / 图片等资源地址。

    不能靠猜文件名：真实产物路径千变万化（/static/app.js、/chunk.7f3a.js 等），
    硬编码候选必然大面积 404。从根页面解析引用才靠谱。
    只收集同源地址，避免复现脚本越出授权范围。
    """
    out = []
    for m in re.finditer(ASSET_RE, text, re.I):
        u = (m.group(1) or "").strip()
        if not u or u.startswith(("data:", "javascript:", "#")):
            continue
        if u.startswith(("http://", "https://")):
            if u.startswith(base):
                out.append(u[len(base):] or "/")
            continue
        if u.startswith("//"):
            continue
        out.append(u if u.startswith("/") else "/" + u.lstrip("./"))
    return list(dict.fromkeys(out))


def _scan(text):
    """用内嵌规则扫一遍文本，返回命中列表 [(类别, 说明, 原文片段)]。"""
    out = []
    for cat, pats in RULES.items():
        for item in pats:
            pat, label = item[0], item[1]
            try:
                m = re.search(pat, text, re.I)
            except re.error:
                continue
            if m:
                s, e = m.span()
                out.append((cat, label, text[max(0, s - 50): e + 80]))
    if not out and MARKERS:
        for mk in MARKERS:
            if mk.lower() in text.lower():
                i = text.lower().find(mk.lower())
                out.append(("marker", mk[:40], text[max(0, i - 50): i + 80]))
    return out


def main(target, timeout):
    base = target.rstrip("/")
    print("[1/4] 请求根页面，动态发现资源引用")
    queue = list(CANDIDATES)
    try:
        root = _fetch(base + "/", timeout)
        if root.status_code < 400:
            assets = _discover_assets(base, root.text or "")
            if assets:
                print(f"  发现资源引用 {{len(assets)}} 个：{{assets[:8]}}")
                queue = assets + [c for c in queue if c not in assets]
    except Exception as e:  # noqa: BLE001
        print(f"  根页面请求失败：{{type(e).__name__}}: {{e}}")

    queue = list(dict.fromkeys(queue))[:40]
    print(f"\\n[2/4] 用扫描时的检测规则扫描 {{len(queue)}} 个候选地址")
    hits = []
    hit_url = ""
    tried = 0
    for cand in queue:
        url = base + cand if cand.startswith("/") else cand
        try:
            r = _fetch(url, timeout)
        except Exception:  # noqa: BLE001
            continue
        if r.status_code >= 400:
            continue
        tried += 1
        found = _scan(r.text or "")
        if found:
            print(f"  ✔ {{cand}} —— 命中 {{len(found)}} 项")
            hits, hit_url = found, url
            break

    if not hits:
        if tried == 0:
            print("[错误] 全部候选地址请求失败或返回错误码，无法完成复现")
            return 2
        if tried < 3:
            # 覆盖面不足时不能下否定结论 —— 检测器当初可能在别的数据源里看到的
            # （例如某个匿名可达的 API 响应），这里扫不到不等于问题不存在。
            print(f"  仅 {{tried}} 个地址可达，覆盖面不足，不足以据以否定该发现。")
            print("  退出码 2「无法判定」—— 不代表问题不存在，请人工核对。")
            return 2
        return result(False, f"重扫 {{tried}} 个可达地址均未命中，"
                             f"问题可能已修复或环境已变化")

    print(f"\\n[3/4] 命中详情：{{hit_url}}")
    for cat, label, snippet in hits[:8]:
        print(f"  · [{{cat}}] {{label}}")
        print(f"      {{mask(snippet)}}")

    print("\\n[3/3] 对照实验（排除「任意页面都命中」的假阳性）")
    cs, clen = _probe_control(base, timeout, CONTROL_PATH)
    show("对照状态码", cs)
    if cs == 200:
        try:
            cr = _fetch(base.rstrip("/") + "/" + CONTROL_PATH.lstrip("/"), timeout)
            if _scan(cr.text or ""):
                return result(False, "对照路径同样命中，该规则在当前目标上不具判定力")
        except Exception:  # noqa: BLE001
            pass

    labels = [h[1] for h in hits]
    return result(True, f"规则重扫命中 {{len(hits)}} 项：{{labels[:5]}}")
'''
    if rules:
        strength = STRENGTH_STRONG
        cat = plan.extra.get("rule_category", "")
        expected = (
            f"1. 用扫描时的检测规则（类别：{cat}）重扫以下候选地址：\n"
            f"   {', '.join(candidates[:5])}\n"
            "2. 规则再次命中，且输出命中处的原文片段（已脱敏）\n"
            "3. 对照路径不命中（排除「任意页面都命中」的假阳性）\n"
            "4. 三项同时满足 → 问题确认存在"
        )
    elif plan.markers:
        strength = STRENGTH_MEDIUM
        expected = (
            f"1. 在候选地址中检索当时记录的特征串\n"
            f"2. 特征：{', '.join(plan.markers[:4])}\n"
            "3. 说明：本次未能匹配到规则集，改用特征串比对，判定力弱于规则重扫"
        )
    else:
        strength = STRENGTH_WEAK
        expected = (
            "⚠ 既无规则集也无可比对特征，脚本只能确认端点可达，"
            "无法判定问题是否仍存在。请按报告中的复现步骤人工核对。"
        )
    return body, expected, strength
    expected = (
        f"1. 对 {plan.probe_path or target_url} 请求后返回非错误状态码\n"
        f"2. 响应中仍含当时实测命中的特征：{', '.join(plan.markers[:4]) or '（内容片段）'}\n"
        f"3. 对照路径不含该特征（排除通用页面误判）\n"
        f"4. 三项同时满足 → 问题确认存在"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 2：路径可达复现（敏感文件 / 配置 / 备份 / 调试端点 / 接口文档）
# ==============================================================================
def t_path_reach(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：路径可未授权访问，且内容属于该文件语义；对照路径行为不同。"""
    body = f'''{INLINE_HELPERS}

# 该路径的语义特征 —— 用于排除「自定义 404 页面返回 200」的假命中
SEMANTIC_MARKERS = {_markers_literal(plan.markers)}
CONTROL_PATH = {_control_literal(plan.control_path)}
EXPECT_STATUS = {plan.expect_status}


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/3] 请求目标路径：{{}}".format(probe_url))
    try:
        r = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("HTTP 状态码", r.status_code)
    show("Content-Type", r.headers.get("Content-Type", ""))
    show("响应长度", len(r.text or ""))

    print("\\n[2/3] 对照实验：请求必然不存在的路径")
    cs, clen = _probe_control(base, timeout, CONTROL_PATH)
    show("对照状态码", cs)
    show("对照长度", clen)

    print("\\n[3/3] 判定")
    if r.status_code != EXPECT_STATUS:
        return result(False, "目标返回 {{}}，期望 {{}}，当前不可复现".format(r.status_code, EXPECT_STATUS))

    text = r.text or ""
    hit = [m for m in SEMANTIC_MARKERS if m.lower() in text.lower()]
    show("语义特征命中", hit)

    # 伪 200 判定：对照组同样 200 且长度接近 → 不是真实的文件暴露
    if cs == 200 and isinstance(clen, int) and len(text) and clen >= len(text) * 0.9:
        return result(False, "不存在的路径同样返回 200 且长度接近，判定为自定义错误页，非真实暴露")

    if not hit:
        return result(False, "状态码正确但响应内容与该路径语义不符，疑为伪 200 页面")

    print("\\n响应片段（已脱敏）：")
    print("    " + mask(text[:400]))
    return result(True, "路径 {{}} 可未授权访问，内容特征命中 {{}}".format(probe_url, hit))
'''
    expected = (
        f"1. 对 {plan.probe_path or target_url} 的请求返回 {plan.expect_status}\n"
        f"2. 响应内容命中该路径类型的语义特征：{', '.join(plan.markers[:4]) or '（见脚本内特征表）'}\n"
        f"3. 对照路径（必然不存在）返回 404 或内容明显不同\n"
        f"4. 三项同时满足 → 问题确认存在"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 3：目录列举复现
# ==============================================================================
def t_dir_listing(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：返回目录索引页而非 403/404，且含可点击的子项链接。"""
    body = f'''{INLINE_HELPERS}

INDEX_MARKERS = ["Index of /", "<title>Index of", "Parent Directory",
                 "Directory listing for", "[To Parent Directory]",
                 "<a href=\\"../\\"", "<a href=\\"/\\">"]
CONTROL_PATH = {_control_literal(plan.control_path)}


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/3] 请求目标目录：{{}}".format(probe_url))
    try:
        r = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("HTTP 状态码", r.status_code)

    if r.status_code != 200:
        return result(False, "目录返回 {{}}，未开启列举".format(r.status_code))

    print("\\n[2/3] 目录索引特征断言")
    text = r.text or ""
    hit = [m for m in INDEX_MARKERS if m.lower() in text.lower()]
    show("索引特征命中", hit)
    if not hit:
        # 再补一条判据：响应里出现指向同级文件的链接
        links = re.findall(LINK_RE, text, re.I)
        show("页面内链接数", len(links))
        if len(links) < 3:
            return result(False, "响应为 200 但不具备目录索引特征，非目录列举")

    print("\\n[3/3] 对照实验")
    cs, _ = _probe_control(base, timeout, CONTROL_PATH)
    show("对照状态码", cs)
    if cs == 200:
        return result(False, "对照路径同样返回 200，无法区分真实索引与自定义页面")

    print("\\n目录列表片段（已脱敏）：")
    print("    " + mask(text[:500]))
    return result(True, "目录 {{}} 开启列举，可枚举文件".format(probe_url))
'''
    expected = (
        f"1. 对 {plan.probe_path or target_url} 请求返回 200\n"
        "2. 响应含目录索引特征（Index of /、Parent Directory 等）或 3 个以上同级链接\n"
        "3. 对照路径返回 404\n"
        "4. 三项同时满足 → 目录列举确认存在"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 4：响应头状态复现（缺失的安全头 / 存在的危险头 / 信息泄露头）
# ==============================================================================
def t_header_state(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：目标响应头仍处于「缺失」或「存在」的待验证状态。"""
    mode = plan.extra.get("mode", "missing")     # missing | present | value
    want = plan.extra.get("value", "")
    body = f'''{INLINE_HELPERS}

HEADER_NAME = {json.dumps(plan.extra.get("header", ""), ensure_ascii=False)}
MODE = {json.dumps(mode)}          # missing=该头应缺失(缺陷) / present=该头存在(缺陷) / value=取值不符
WANT = {json.dumps(want, ensure_ascii=False)}


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/2] 请求目标：{{}}".format(probe_url))
    try:
        r = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("HTTP 状态码", r.status_code)

    print("\\n[2/2] 响应头断言")
    actual = r.headers.get(HEADER_NAME)
    show("待检查响应头", HEADER_NAME)
    show("实际取值", actual if actual is not None else "(不存在)")
    show("全部安全相关响应头", {{k: v for k, v in r.headers.items()
                             if k.lower().startswith(("strict-", "content-security",
                                                      "x-frame", "x-content", "referrer",
                                                      "permissions-", "access-control",
                                                      "server", "x-powered"))}})

    if MODE == "missing":
        if actual is None:
            return result(True, "响应头 {{}} 确实缺失，问题复现".format(HEADER_NAME))
        return result(False, "响应头 {{}} 现已存在（{{}}），问题可能已修复".format(HEADER_NAME, actual))
    if MODE == "present":
        if actual is not None:
            return result(True, "响应头 {{}} 仍存在：{{}}，问题复现".format(HEADER_NAME, mask(actual)))
        return result(False, "响应头 {{}} 现已移除，问题可能已修复".format(HEADER_NAME))
    # value 模式
    if actual is not None and WANT.lower() not in actual.lower():
        return result(True, "响应头 {{}} 取值 {{}} 不含期望值 {{}}，问题复现".format(HEADER_NAME, actual, WANT))
    return result(False, "响应头取值已符合预期：{{}}".format(actual))
'''
    expected = (
        f"1. 请求 {plan.probe_path or target_url} 获取响应头\n"
        f"2. 按模式判定：{mode}\n"
        f"3. 判定结果与本次扫描一致 → 问题复现"
    )
    return body, expected, STRENGTH_STRONG if mode in ("missing", "present") else STRENGTH_MEDIUM


# ==============================================================================
# 模板 5：CORS 反射复现
# ==============================================================================
def t_cors_reflect(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：带自定义 Origin 请求时，ACAO 反射该 Origin 且允许携带凭据。"""
    evil = plan.extra.get("origin", "https://aiscan-cors-probe.invalid")
    body = f'''{INLINE_HELPERS}

EVIL_ORIGIN = {json.dumps(evil)}


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/2] 携带非授权 Origin 请求：{{}}".format(probe_url))
    try:
        r = _fetch(probe_url, timeout, extra_headers={{"Origin": EVIL_ORIGIN}})
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = (r.headers.get("Access-Control-Allow-Credentials", "") or "").lower()
    show("HTTP 状态码", r.status_code)
    show("发送的 Origin", EVIL_ORIGIN)
    show("Access-Control-Allow-Origin", acao)
    show("Access-Control-Allow-Credentials", acac)

    print("\\n[2/2] 判定")
    if acao == "*":
        return result(True, "ACAO 为通配符 *，任意站点均可读取该接口响应，问题复现")
    if acao.strip() == EVIL_ORIGIN:
        if acac == "true":
            return result(True, "ACAO 反射任意 Origin 且允许携带凭据，可跨站读取用户数据，问题复现")
        return result(True, "ACAO 反射任意 Origin（未允许凭据），跨站读取受限但仍属配置缺陷")
    if not acao:
        return result(False, "未返回 Access-Control-Allow-Origin，问题可能已修复")
    return result(False, "ACAO 为 {{}}，未反射非授权 Origin，问题可能已修复".format(acao))
'''
    expected = (
        f"1. 携带 Origin: {evil} 请求 {plan.probe_path or target_url}\n"
        "2. 响应头 ACAO 反射该 Origin（且 ACAC=true 时为高危），或 ACAO 为通配符 *\n"
        "3. 命中任一情况 → 问题确认存在"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 6：参数重放复现（注入 / 反射 / 重定向 / SSRF）
# ==============================================================================
def t_param_replay(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：重放同一载荷后，当时观察到的响应特征再次出现，且基线不含该特征。"""
    method = (plan.method or "GET").upper()
    body = f'''{INLINE_HELPERS}

METHOD = {json.dumps(method)}
PARAM = {json.dumps(plan.param, ensure_ascii=False)}
PAYLOAD = {json.dumps(plan.payload, ensure_ascii=False)}
MARKERS = {_markers_literal(plan.markers)}
BASELINE_MARKERS = {_markers_literal(plan.extra.get("baseline_markers", []))}


def _inject(base, value, timeout):
    """把载荷注入指定参数后请求。base 为目标根地址。"""
    from urllib.parse import urlencode, urlsplit, parse_qsl, urlunsplit
    {plan.url_expr()}
    if METHOD == "GET":
        parts = urlsplit(probe_url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[PARAM] = value
        return _fetch(urlunsplit((parts.scheme, parts.netloc, parts.path,
                                  urlencode(q, doseq=True), parts.fragment)), timeout)
    return _fetch(probe_url, timeout, method=METHOD,
                  data={{PARAM: value}},
                  extra_headers={{"Content-Type": "application/x-www-form-urlencoded"}})


def main(target, timeout):
    base = target.rstrip("/")
    print("[1/3] 基线请求（使用无害值）")
    try:
        b = _inject(base, "aiscan_baseline_value", timeout)
    except Exception as e:
        print("[错误] 基线请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("基线状态码", b.status_code)
    show("基线长度", len(b.text or ""))
    btext = b.text or ""

    print("\\n[2/3] 载荷重放")
    try:
        r = _inject(base, PAYLOAD, timeout)
    except Exception as e:
        print("[错误] 载荷请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("载荷状态码", r.status_code)
    show("载荷长度", len(r.text or ""))
    text = r.text or ""

    print("\\n[3/3] 断言（必须与基线对比，排除「页面本来就含该串」）")
    hit = [m for m in MARKERS if m.lower() in text.lower()]
    base_hit = [m for m in hit if m.lower() in btext.lower()]
    show("载荷响应命中", hit)
    show("基线也命中的（无效特征）", base_hit)
    effective = [m for m in hit if m not in base_hit]

    if effective:
        print("\\n有效命中片段（已脱敏）：")
        for m in effective[:3]:
            i = text.lower().find(m.lower())
            print("    " + mask(text[max(0, i - 80): i + 160]))
        return result(True, "载荷输入后出现基线不具备的特征 {{}}，问题复现".format(effective))

    # 状态码/长度显著变化也算可观测差异，但强度较弱
    if r.status_code != b.status_code:
        return result(True, "载荷使状态码由 {{}} 变为 {{}}，行为存在差异".format(b.status_code, r.status_code))
    if abs(len(text) - len(btext)) > max(200, len(btext) * 0.2):
        return result(True, "载荷使响应长度由 {{}} 变为 {{}}，行为存在差异".format(len(btext), len(text)))

    return result(False, "载荷与基线响应无实质差异，问题可能已修复或需调整载荷")
'''
    expected = (
        f"1. 用无害值请求得到基线响应\n"
        f"2. 把载荷 {plan.payload[:60]!r} 注入参数 {plan.param!r}（{method}）后重放\n"
        f"3. 载荷响应的特征与基线存在差异（基线不具备的特征出现、或状态码/长度显著变化）\n"
        f"4. 差异可稳定复现 → 问题确认存在"
    )
    strength = STRENGTH_STRONG if plan.markers else STRENGTH_MEDIUM
    return body, expected, strength


# ==============================================================================
# 模板 7：无凭据访问复现（IDOR / 越权 / 未授权接口）
# ==============================================================================
def t_anon_access(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：不带任何凭据请求该端点，仍返回业务数据而非登录页/401/403。"""
    body = f'''{INLINE_HELPERS}

# 登录页 / 拒绝访问的识别特征 —— 命中即说明访问其实是被拦住的
DENY_MARKERS = ["<title>登录", "请先登录", "login", "sign in", "unauthorized",
                "forbidden", "access denied", "未授权", "无权限", "认证失败"]
# 说明确实拿到了业务数据的特征（由本次扫描实测得到）
DATA_MARKERS = {_markers_literal(plan.markers)}
DENY_STATUS = (401, 403, 302, 303)


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/2] 不带任何凭据请求：{{}}".format(probe_url))
    print("      （脚本不携带 Cookie / Token，以此验证匿名可达性）")
    try:
        r = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("HTTP 状态码", r.status_code)
    show("Content-Type", r.headers.get("Content-Type", ""))
    show("响应长度", len(r.text or ""))
    show("响应中 Set-Cookie", r.headers.get("Set-Cookie", "(无)"))

    print("\\n[2/2] 判定")
    if r.status_code in DENY_STATUS:
        return result(False, "匿名请求返回 {{}}（被拦截或要求登录），当前不可复现".format(r.status_code))

    text = r.text or ""
    low = text.lower()
    deny_hit = [m for m in DENY_MARKERS if m.lower() in low]
    show("拒绝特征命中", deny_hit)
    if deny_hit and len(text) < 4000:
        return result(False, "响应疑似登录页 / 拒绝页（命中 {{}}），当前不可复现".format(deny_hit))

    hit = [m for m in DATA_MARKERS if m.lower() in low]
    show("业务数据特征命中", hit)
    if DATA_MARKERS and not hit:
        return result(False, "未再出现本次扫描记录的数据特征，可能已加鉴权或数据已变化")

    print("\\n响应片段（已脱敏）：")
    print("    " + mask(text[:600]))
    return result(True, "匿名请求 {{}} 仍可获取业务数据，未授权访问复现".format(probe_url))
'''
    expected = (
        f"1. 不携带任何凭据请求 {plan.probe_path or target_url}\n"
        "2. 响应状态码不是 401/403/302\n"
        "3. 响应体不是登录页 / 拒绝页\n"
        f"4. 响应含本次扫描记录的数据特征（{', '.join(plan.markers[:3]) or '见脚本内特征表'}）\n"
        "5. 四项满足 → 未授权访问确认存在"
    )
    return body, expected, STRENGTH_STRONG if plan.markers else STRENGTH_MEDIUM


# ==============================================================================
# 模板 8：跨身份访问复现（IDOR / BOLA / 水平越权 / 跨租户）
# ==============================================================================
# 为什么不复用模板 7（匿名访问）
# --------------------------------------------------------------------------
# 模板 7 断言的是「**不带凭据**也能拿到业务数据」。它的适用前提是
# 「该接口本来就该要求认证」—— 这条断言对未授权访问成立，对越权不成立。
#
# 越权的证据形态完全不同：它是**带身份的**实测结果 ——
# 「两个不同身份请求同一地址，拿到的是同一份个人数据」。
# 拿匿名请求去复现它，打到的必然是登录页 / 401，脚本于是打印「未复现」。
# 这不是「问题已修复」，而是**「本次没有验证到」被写成了「未复现」**——
# 报告里这两句话的含义正好相反，前者是「我不知道」，后者是「我确认没有」。
# 审阅者看到「复现失败」，会合理推断漏洞已修复，于是把一个真实问题关掉。
#
# 所以本模板的判定逻辑，与检测器当时的判据**逐条对齐**（同一套规则独立重跑）：
#   · 两个身份对同一地址都返回 200
#   · 响应体逐字节相同
#   · 响应含个人数据标识（id / userId / orderId …）
# 三项同时成立，才叫复现成功。
#
# 两个不能省的对照实验
# --------------------------------------------------------------------------
# 对照一（路径不敏感）：请求一个**不应存在**的同类路径。若它也返回 200 且含
#   个人数据标识，说明该站对「资源是否存在」根本不区分（或对所有路径都回同一
#   份内容），此时「读到数据」不能证明任何归属问题 —— 判「无法判定」。
# 对照二（身份真的不同）：两个角色解析出的凭据若完全一致，说明操作者把同一个
#   账号填了两遍。「两个不同身份读到同一份数据」于是退化成「同一个身份读了两次
#   自己的数据」—— 结论看起来成立，实际毫无意义。必须拒判而不是照样输出。
#
# 还有一个语义边界必须说清楚：响应逐字节相同，证明的是
# **服务端未按当前身份过滤数据归属**；那份数据究竟属于谁，
# 需要人工核对响应里的归属人标识才能定最终级别。脚本会把这句话印在结论里。
# ==============================================================================
def t_cross_role(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    # 本模块既可能以 `verify.repro_templates` 导入，也可能被独立导入
    # （`from repro_templates import ...`），两种路径都要能拿到内联片段。
    try:
        from verify.sessionctx import SESSION_INLINE, skeleton  # noqa: PLC0415
    except ImportError:  # noqa: BLE001
        from sessionctx import SESSION_INLINE, skeleton  # type: ignore  # noqa: PLC0415

    roles: list[str] = [str(r) for r in (plan.extra.get("roles") or [])][:2]
    primary = str(plan.extra.get("primary_role") or (roles[0] if roles else ""))
    control = str(plan.extra.get("control_role") or (roles[1] if len(roles) > 1 else ""))

    # 用占位符 + replace 而不是 f-string：本模板正文里有大量 `{}` / `%` 字面量，
    # f-string 下每一处都要转义，漏一处就是语法错误，而语法错误只会在
    # 生成脚本被执行时才暴露 —— 交付物带语法错误属于最差的失败形态。
    body = '''__HELPERS__
SESSION_ROLES = __ROLES__
SESSION_SKELETON = __SKELETON__
__SESSION_INLINE__

# 与检测器同源的判据：响应里必须出现个人数据标识。
# 否则「两个身份读到同一份数据」可能只是一份所有人都该看到的公共配置，
# 那不构成越权 —— 判据一旦放松，每个返回公共字典的接口都会被报成越权。
OWNER_ID_RE = __OWNER_RE__
DENY_STATUS = (401, 403, 302, 303)
DENY_MARKERS = ["<title>登录", "请先登录", "login", "sign in", "unauthorized",
                "forbidden", "access denied", "未授权", "无权限", "认证失败"]
CONTROL_PATH = __CONTROL__

PRIMARY_ROLE = __PRIMARY__
CONTROL_ROLE = __CONTROL_ROLE__


def main(target, timeout):
    base = target.rstrip("/")
    __URL_EXPR__

    # [0/5] 会话自检放在最前：缺凭据时后面每一步的结论都不成立，
    #       不能先跑一遍再在末尾附一句「其实没登录」。
    missing = _sess_missing()
    if missing:
        _session_gap_lines(missing)
        return 2

    p_ctx = _sessions().get(str(PRIMARY_ROLE)) or {}
    c_ctx = _sessions().get(str(CONTROL_ROLE)) or {}
    if (p_ctx.get("cookies") == c_ctx.get("cookies")
            and p_ctx.get("headers") == c_ctx.get("headers")):
        print("[无法判定] 「{}」与「{}」解析出的凭据完全相同 —— 这通常是把同一个"
              .format(PRIMARY_ROLE, CONTROL_ROLE))
        print("           账号填了两遍。两个身份必须是不同账号，否则本次比对"
              "没有意义。")
        return 2

    print("[1/5] 匿名基线：{}".format(probe_url))
    try:
        anon = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{}: {}".format(type(e).__name__, e))
        return 2
    show("匿名状态码", anon.status_code)
    show("匿名响应长度", len(anon.text or ""))
    anon_deny = [m for m in DENY_MARKERS if m.lower() in (anon.text or "").lower()]

    ctrl_url = base + "/" + CONTROL_PATH.lstrip("/")
    print("\\n[2/5] 对照实验一：请求一个不应存在的同类路径")
    print("      {}".format(ctrl_url))
    try:
        ctrl = _fetch(ctrl_url, timeout)
        show("对照状态码", ctrl.status_code)
        show("对照响应长度", len(ctrl.text or ""))
    except Exception as e:
        ctrl = None
        show("对照请求异常", type(e).__name__)

    print("\\n[3/5] 以「{}」身份请求同一地址".format(PRIMARY_ROLE))
    try:
        p = _req_as(probe_url, PRIMARY_ROLE, timeout)
    except Exception as e:
        print("[错误] 请求失败：{}: {}".format(type(e).__name__, e))
        return 2
    show("{} 状态码".format(PRIMARY_ROLE), p.status_code)
    show("{} 响应长度".format(PRIMARY_ROLE), len(p.text or ""))

    print("\\n[4/5] 以「{}」身份请求同一地址（对照身份）".format(CONTROL_ROLE))
    try:
        c = _req_as(probe_url, CONTROL_ROLE, timeout)
    except Exception as e:
        print("[错误] 请求失败：{}: {}".format(type(e).__name__, e))
        return 2
    show("{} 状态码".format(CONTROL_ROLE), c.status_code)
    show("{} 响应长度".format(CONTROL_ROLE), len(c.text or ""))

    print("\\n[5/5] 判定")
    pbody = p.text or ""
    cbody = c.text or ""

    # 匿名就能拿到含个人数据的响应：这是更直接的方向（未授权访问），
    # 属于另一类问题，单独点明，不要混进「越权」这个结论里。
    if anon.status_code == 200 and re.search(OWNER_ID_RE, anon.text or ""):
        print("  提示：不带任何凭据也拿到了含个人数据标识的响应。")
        print("        这是未授权访问（比越权更直接），应单独定级，不在本条范围。")
    else:
        show("匿名被拦迹象", anon_deny or "(匿名未命中拒绝特征)")

    if p.status_code in DENY_STATUS:
        return result(False, "主身份 {} 请求被拒（{}），当前不可复现"
                             .format(PRIMARY_ROLE, p.status_code))
    if p.status_code != 200:
        return result(False, "主身份 {} 请求返回 {}，当前不可复现"
                             .format(PRIMARY_ROLE, p.status_code))
    if not re.search(OWNER_ID_RE, pbody):
        return result(False, "主身份响应中未出现个人数据标识，与当时实测不符，"
                             "本次未复现")

    if c.status_code != 200:
        return result(False, "两个身份响应不同（{} 返回 {}）—— 服务端按身份做了"
                             "区分，本次未复现".format(CONTROL_ROLE, c.status_code))
    if pbody != cbody:
        return result(False, "两个身份拿到的是不同内容（长度 {} vs {}）—— "
                             "服务端已按身份过滤数据，本次未复现"
                             .format(len(pbody), len(cbody)))

    # 对照实验一：不存在的路径也回同一类内容 → 无法区分「越权」与
    # 「该站对任意路径返回同一份内容」，此时不判越权。
    if (ctrl is not None and getattr(ctrl, "status_code", 0) == 200
            and re.search(OWNER_ID_RE, ctrl.text or "")):
        return result(False, "一个不应存在的路径同样返回了含个人数据标识的 200 "
                             "响应，无法区分「越权」与「该站对任意路径返回同一份"
                             "内容」，本次不判越权")

    print("\\n两个不同身份对同一地址返回了**逐字节相同**的响应：")
    show("响应长度", len(pbody))
    print("  响应片段（已脱敏）：")
    print("    " + mask(pbody[:400]))
    print("")
    print("  说明：本条证明的是「服务端未按当前身份过滤数据归属」。")
    print("        那份数据究竟属于哪个主体，须人工核对响应中的归属人标识后")
    print("        再定最终级别 —— 脚本不代替这一步。")
    return result(True, "同一地址（{}）在身份 {} 与 {} 下返回完全相同的响应，"
                        "且响应含个人数据标识 —— 服务端未按当前身份过滤数据归属"
                  .format(probe_url, PRIMARY_ROLE, CONTROL_ROLE))
'''

    reps = {
        "__HELPERS__": INLINE_HELPERS,
        "__SESSION_INLINE__": SESSION_INLINE,
        "__ROLES__": json.dumps(roles, ensure_ascii=False),
        "__SKELETON__": json.dumps(skeleton(roles), ensure_ascii=False),
        "__OWNER_RE__": json.dumps(
            r'"(?:id|userId|user_id|orderId|order_id|accountId|customerId|tenantId|ownerId)"'),
        "__CONTROL__": _control_literal(plan.control_path),
        "__PRIMARY__": repr(primary),
        "__CONTROL_ROLE__": repr(control),
        "__URL_EXPR__": plan.url_expr(),
    }
    for k, v in reps.items():
        body = body.replace(k, v)
    # 占位符漏替换会在生成脚本里留下一段看似注释的垃圾，静默且难查 ——
    # 尤其 `__SKELETON__` 漏替换时，操作者会看到一份填不了的骨架，
    # 而症状是「怎么填都没用」，排查成本很高。
    #
    # 按**已知占位符名**逐个查，不用「任意 __X__」的宽口径：
    # 骨架里本来就含哨兵 `__FILL_ME__`（那是给操作者看的，必须留着），
    # 宽口径会把它当成漏替换，直接让生成失败。
    left = sorted(k for k in reps if k in body)
    if left:
        raise ValueError(f"跨身份模板存在未替换的占位符：{left}")

    expected = (
        f"1. 不提供凭据时**不判「未复现」**，而是明确「无法判定」并给出填写说明\n"
        f"2. 以「{primary}」身份请求 {plan.probe_path or target_url} → 期望 200 且含个人数据标识\n"
        f"3. 以对照身份「{control}」请求同一地址 → 期望同样返回 200\n"
        f"4. 两次响应体逐字节相同 → 服务端未按当前身份过滤数据归属\n"
        f"5. 对照一：不应存在的同类路径不得返回含个人数据标识的 200\n"
        f"6. 对照二：两个角色的凭据必须不同（同一账号填两遍则拒判）\n"
        f"7. 会话从 aiscan_sessions.json / 环境变量读取，无需改动本脚本\n"
        f"8. 三项同时满足 → 越权复现成功；数据归属须人工确认后再定级"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 9：端口连通复现
# ==============================================================================
def _ports_of(f: Any) -> list[int]:
    """抽取一条端口类发现声称暴露的全部端口。

    端口类发现的 endpoint 有几种写法：`1.2.3.4:6379`、`1.2.3.4:445,5900`，
    也有把清单写在技术细节里的（`  · 445/tcp`）。
    **多端口必须逐个复核** —— 只查第一个端口验证不了「这些端口都暴露」；
    而只按端口号取数（不看是否真的开放）正是「凭猜测定结论」的来源。
    """
    ep = (f.endpoint or "").strip()
    detail = f.technical_detail or ""
    ports: list[int] = []

    def _push(tok: str) -> None:
        try:
            p = int(tok)
        except ValueError:
            return
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)

    # 形式一：host:445,5900,6379
    m = re.match(r"^[^\s]*?:([\d,\s]+)$", ep)
    if m:
        for tok in re.findall(r"\d{2,5}", m.group(1)):
            _push(tok)
    # 形式二：技术细节里的 445/tcp 清单（要求 /tcp 后缀，避免把 IP 段误当端口）
    for tok in re.findall(r"(?<![\d.])(\d{2,5})\s*/tcp", detail, re.I):
        _push(tok)
    # 形式三：单个 host:port
    if not ports:
        mm = re.search(r":(\d{2,5})(?![,\d])", ep)
        if mm:
            _push(mm.group(1))
    return ports


# 只有这种形态才可能是真正的服务 banner：单行、纯 ASCII、不带报告标签。
# 把技术细节里的标签行当成 banner 去匹配，
# 会让每一个端口类发现都判「banner 不匹配 → 未复现」，把真问题说成假的。
_BANNER_LIKE = re.compile(r"^[\x20-\x7e]{4,120}$")


def _pick_banner(f: Any) -> str:
    for line in (f.technical_detail or "").splitlines():
        s = line.strip()
        if _BANNER_LIKE.match(s) and not s.isdigit():
            return s
    return ""


def t_port_open(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：声明的端口仍能建立 TCP 三次握手；可选校验 banner。"""
    host = plan.extra.get("host", "")
    ports = list(plan.extra.get("ports") or [])
    if not ports and plan.extra.get("port"):
        ports = [int(plan.extra["port"])]
    port = ports[0] if ports else 0
    banner = plan.extra.get("banner", "")
    body = f'''#!/usr/bin/env python3
# 端口连通性复现。只做 TCP 三次握手，不发应用层数据。
import argparse
import socket
import sys

HOST = {json.dumps(host)}
PORTS = {json.dumps(ports)}
PORT = {port}
BANNER_EXPECT = {json.dumps(banner[:200], ensure_ascii=False)}


def result(ok, message):
    print("\\n" + "=" * 68)
    print(("[复现成功] " if ok else "[未复现] ") + message)
    print("=" * 68)
    return 0 if ok else 1


def show(label, value, limit=400):
    s = str(value)
    if len(s) > limit:
        s = s[:limit] + f"... (共 {{len(str(value))}} 字符)"
    print(f"  {{label}}: {{s}}")


def _probe(host, port, timeout):
    """返回 (是否开放, banner 或错误说明)。只做三次握手 + 可选读欢迎语。"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            b = ""
            try:
                s.settimeout(min(timeout, 3))
                b = s.recv(512).decode("utf-8", "replace")
            except Exception:
                b = ""
            return True, b
    except Exception as e:
        return False, f"{{type(e).__name__}}: {{e}}"


def main(target, timeout):
    host = HOST or target.split("//")[-1].split("/")[0].split(":")[0]
    check = PORTS or [PORT]
    print("口径说明：本脚本只证明「从运行本脚本的节点可以建立 TCP 连接」，")
    print("          不等同于「公网可达」。公网暴露须以公网测绘平台复核后表述。")
    print()
    print(f"[1/2] TCP 连通性探测：{{host}} 上 {{len(check)}} 个端口 {{check}}")
    opened, closed, banners = [], [], {{}}
    for p in check:
        ok, extra = _probe(host, p, timeout)
        if ok:
            opened.append(p)
            if extra:
                banners[p] = extra.strip()[:120]
            print(f"  {{p}}/tcp  开放"
                  + (f"  banner: {{banners[p]}}" if banners.get(p) else ""))
        else:
            closed.append(p)
            print(f"  {{p}}/tcp  不可达（{{extra}}）")

    print("\\n[2/2] 判定")
    show("声称暴露的端口", check)
    show("当前开放的", opened)
    show("当前不可达的", closed)
    if not opened:
        return result(False, "所有声明端口均无法建立连接，问题可能已修复或被防火墙收口")
    if closed:
        return result(False, f"{{len(closed)}} 个声明端口已不可达（{{closed}}）—— "
                             f"暴露面已缩小，但仍有 {{len(opened)}} 个端口开放（{{opened}}），"
                             f"请按实际开放清单更新结论")

    if BANNER_EXPECT:
        hit = [p for p, b in banners.items() if BANNER_EXPECT.lower() in b.lower()]
        show("期望 banner 特征", BANNER_EXPECT)
        if not hit:
            # banner 不匹配**不等于**端口不开放。多数服务不主动问候，
            # 而本发现的主张是「该端口可以建立 TCP 连接」—— 三次握手成功
            # 就已经把这句话证完了。banner 只是旁证，读不到记为旁证缺失，
            # 不能因此把结论降级成「无法判定」。
            print("  注：没有读到匹配的服务 banner（多数服务不主动发送欢迎语）。")
            print("  本发现的主张是「该端口可以建立 TCP 连接」，已由三次握手证实；")
            print("  服务类型系依据端口号推断，如需确证请人工取 banner。")
        else:
            show("banner 命中端口", hit)

    return result(True, f"{{len(opened)}} 个端口 {{opened}} 仍可建立 TCP 连接")


'''
    expected = (
        f"1. 与 {host} 上声明的 {len(ports) or 1} 个端口逐个建立 TCP 连接（三次握手）\n"
        f"2. {'banner 含特征：' + banner[:80] if banner else '连接成功即视为复现'}"
        f"（banner 仅作旁证，读不到不影响结论）\n"
        "3. 全部端口仍开放 → 复现成功；部分不可达 → 暴露面已缩小，按实际清单更新\n"
        "4. 口径说明：本脚本证明的是「从运行节点可建立 TCP 连接」，"
        "不等于「公网可达」；公网暴露须以公网测绘平台复核后表述"
    )
    return body, expected, STRENGTH_STRONG



# ==============================================================================
# 模板 9：HTTP 方法接受复现
# ==============================================================================
def t_method_accept(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：该 HTTP 方法仍被服务端接受（未返回 405/501）。只做声明层验证，不执行写操作。"""
    method = (plan.method or "OPTIONS").upper()
    body = f'''{INLINE_HELPERS}

METHOD = {json.dumps(method)}
# 只做声明层验证：OPTIONS 探测与必要方法的最小请求，不提交任何数据
READONLY_SAFE = METHOD in ("OPTIONS", "HEAD", "TRACE", "GET")


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/3] 基线：GET 请求确认端点可达")
    try:
        g = _fetch(probe_url, timeout)
        show("GET 状态码", g.status_code)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2

    print("\\n[2/3] OPTIONS 探测服务端声明支持的方法")
    allow = ""
    try:
        o = _fetch(probe_url, timeout, method="OPTIONS")
        allow = o.headers.get("Allow", "") or o.headers.get("Access-Control-Allow-Methods", "")
        show("OPTIONS 状态码", o.status_code)
        show("Allow 头", allow or "(未声明)")
    except Exception as e:  # noqa: BLE001
        show("OPTIONS 请求异常", type(e).__name__)

    print("\\n[3/3] 判定：目标方法是否被接受")
    if METHOD == "OPTIONS":
        if allow:
            return result(True, "服务端声明支持方法：{{}}".format(allow))
        return result(False, "服务端未通过 Allow 头声明方法，无法据此判定")

    if not READONLY_SAFE:
        print("  注意：目标方法 {{}} 具有写语义，本脚本不发送写请求。".format(METHOD))
        print("  仅依据 OPTIONS 声明判定，实际可用性需在测试环境另行确认。")

    try:
        r = _fetch(probe_url, timeout, method=METHOD)
        show("{{}} 状态码".format(METHOD), r.status_code)
    except Exception as e:
        return result(False, "目标方法请求失败：{{}}".format(type(e).__name__))

    if r.status_code in (405, 501):
        return result(False, "服务端返回 {{}}，明确不接受该方法，问题可能已修复".format(r.status_code))
    if allow and METHOD in allow.upper():
        return result(True, "服务端声明且实际接受 {{}} 方法".format(METHOD))
    if r.status_code < 500:
        return result(True, "服务端对 {{}} 方法返回 {{}}，未明确拒绝该方法的处理".format(METHOD, r.status_code))
    return result(False, "服务端返回 {{}}，无法确认方法可用性".format(r.status_code))
'''
    expected = (
        f"1. GET 请求确认端点可达\n"
        f"2. OPTIONS 探测 Allow 头声明\n"
        f"3. 目标方法 {method} 未返回 405/501，或在 Allow 头中被声明\n"
        "4. 判定为「服务端未拒绝该方法」→ 问题复现（写方法仅做声明层验证）"
    )
    return body, expected, STRENGTH_MEDIUM


# ==============================================================================
# 模板 10：TLS 配置复现
# ==============================================================================
def t_tls_state(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：目标仍接受指定的 TLS 协议版本（或弱套件）。"""
    want = plan.extra.get("protocol", "TLSv1.0")
    body = f'''#!/usr/bin/env python3
"""TLS 配置复现。仅做握手探测，不传输任何业务数据。"""
import argparse
import socket
import ssl
import sys

WANT = {json.dumps(want)}


def result(ok, message):
    print("\\n" + "=" * 68)
    print(("[复现成功] " if ok else "[未复现] ") + message)
    print("=" * 68)
    return 0 if ok else 1


def show(label, value):
    print(f"  {{label}}: {{value}}")


def _version_const(name):
    return getattr(ssl.TLSVersion, name, None)


def main(target, timeout):
    hostport = target.split("//")[-1].split("/")[0]
    host, _, port = hostport.partition(":")
    port = int(port or 443)
    show("目标", f"{{host}}:{{port}}")
    show("待验证协议", WANT)

    vmap = {{"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1_1", "TLSv1.2": "TLSv1_2", "TLSv1.3": "TLSv1_3"}}
    const = _version_const(vmap.get(WANT, ""))
    if const is None:
        print("  当前 Python 不支持单独构造该协议版本，改用全量握手推断。")

    print("\\n[1/2] 尝试以指定协议版本握手")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if const is not None:
            ctx.minimum_version = const
            ctx.maximum_version = const
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                show("协商结果", ss.version())
                show("加密套件", ss.cipher()[0] if ss.cipher() else "(未知)")
    except ssl.SSLError as e:
        return result(False, f"以 {{WANT}} 握手失败（{{e}}），该协议已被禁用")
    except Exception as e:
        return result(False, f"连接失败：{{type(e).__name__}}: {{e}}")

    print("\\n[2/2] 判定")
    return result(True, f"目标仍接受 {{WANT}} 协议握手，弱协议未禁用")
'''
    expected = (
        f"1. 以 {want} 协议与目标建立 TLS 握手\n"
        "2. 握手成功 → 该协议仍被接受，问题复现\n"
        "3. 握手失败 → 协议已禁用，问题已修复"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 11：组件版本复现
# ==============================================================================
def t_component_version(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：响应中仍暴露该版本号，且版本仍落在受影响范围。"""
    body = f'''{INLINE_HELPERS}

COMPONENT = {json.dumps(plan.extra.get("component", ""), ensure_ascii=False)}
VERSION = {json.dumps(plan.extra.get("version", ""), ensure_ascii=False)}
MARKERS = {_markers_literal(plan.markers)}


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("[1/2] 请求目标：{{}}".format(probe_url))
    try:
        r = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("HTTP 状态码", r.status_code)
    text = r.text or ""
    headers_blob = "\\n".join(f"{{k}}: {{v}}" for k, v in r.headers.items())

    print("\\n[2/2] 版本特征断言")
    show("组件", COMPONENT)
    show("本次扫描识别版本", VERSION)
    hit_body = [m for m in MARKERS if m.lower() in text.lower()]
    hit_head = [m for m in MARKERS if m.lower() in headers_blob.lower()]
    show("响应体中命中", hit_body)
    show("响应头中命中", hit_head)

    if VERSION and VERSION.lower() in (text + headers_blob).lower():
        return result(True, "版本号 {{}} 仍从响应中暴露，可据此定位受影响组件".format(VERSION))
    if hit_body or hit_head:
        return result(True, "组件 {{}} 的特征仍在响应中出现（{{}}）".format(COMPONENT, (hit_body + hit_head)[:3]))
    return result(False, "未再发现该组件版本特征，可能已升级或已隐藏版本信息")
'''
    expected = (
        f"1. 请求 {plan.probe_path or target_url}\n"
        f"2. 响应体或响应头中仍出现组件 {plan.extra.get('component', '')} 的版本标识 {plan.extra.get('version', '')}\n"
        "3. 命令：python verify_xxx.py 观察「版本号仍从响应中暴露」"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 12：可达性兜底（弱）—— 必须显式披露，不得与强断言混同
# ==============================================================================
def t_weak_probe(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """兜底：只验证端点可达并回显关键字段，明确标注「非完整复现」。"""
    body = f'''{INLINE_HELPERS}

# ⚠ 本脚本为可达性兜底复现 —— 它只能证明端点仍然存在，
#   不能独立证明漏洞存在。判定结论必须结合人工核对。
REPRO_STEPS = {json.dumps((f.reproduction or "（无）"), ensure_ascii=False)}
TECH_DETAIL = {json.dumps((f.technical_detail or "（无）")[:1200], ensure_ascii=False)}


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print("⚠ 兜底复现：仅验证端点可达性，不含该问题类型的专用断言。")
    print("  以下复现步骤需人工逐项核对：")
    for i, ln in enumerate(REPRO_STEPS.splitlines(), 1):
        print(f"    {{i}}. {{ln}}")
    print("\\n  技术细节（供核对）：")
    for ln in TECH_DETAIL.splitlines()[:12]:
        print(f"    {{ln}}")
    print()

    print("[1/2] 请求目标端点：{{}}".format(probe_url))
    try:
        r = _fetch(probe_url, timeout)
    except Exception as e:
        print("[错误] 请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("HTTP 状态码", r.status_code)
    show("Content-Type", r.headers.get("Content-Type", ""))
    show("响应长度", len(r.text or ""))
    show("响应片段", mask((r.text or "")[:400]))

    print("\\n[2/2] 判定")
    if r.status_code >= 400:
        # 端点已不可用 —— 这是确凿的「未复现」，不是「无法判定」
        return result(False, f"端点返回 {{r.status_code}}，当前不可复现")
    print("  端点可达。")
    print("  但本类型缺少专用断言模板，脚本**无法自动判定**漏洞是否仍存在。")
    print("  请按上述复现步骤人工核对后定稿结论。")
    print()
    print("  退出码 2 表示「无法判定」，不是「漏洞不存在」——")
    print("  该结论不得被当作「已修复」或「未见异常」解读。")
    return 2
'''
    expected = (
        f"⚠ 本项为弱复现：脚本只确认 {plan.probe_path or target_url} 仍可访问，"
        "不含该问题类型的专用断言。\n"
        "退出码 2 表示「无法自动判定」，**不等于问题不存在**。\n"
        "报告已如实标注为「弱」，请按脚本内列出的复现步骤人工核对。"
    )
    return body, expected, STRENGTH_WEAK


# ==============================================================================
# 模板 12：DNS 记录状态复现（SPF / DKIM / DMARC / 证书透明度）
# ==============================================================================
def t_dns_record(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：目标域名仍缺失该 DNS 记录，或记录取值仍不符合安全要求。"""
    domain = plan.extra.get("domain", "")
    mode = plan.extra.get("mode", "missing")     # missing | value
    want = plan.extra.get("value", "")
    rtype = plan.extra.get("rtype", "TXT")
    rname = plan.extra.get("record_name", "")
    body = f'''#!/usr/bin/env python3
"""DNS 记录状态复现。查询 SPF / DKIM / DMARC 等 TXT 记录，不发送邮件。"""
import argparse
import subprocess
import sys

DOMAIN = {json.dumps(domain, ensure_ascii=False)}
RECORD_NAME = {json.dumps(rname, ensure_ascii=False)}   # 完整查询名，留空则用 DOMAIN
RTYPE = {json.dumps(rtype)}
MODE = {json.dumps(mode)}          # missing=该记录应缺失(缺陷) / value=取值不符
WANT = {json.dumps(want, ensure_ascii=False)}


def result(ok, message):
    print("\\n" + "=" * 68)
    print(("[复现成功] " if ok else "[未复现] ") + message)
    print("=" * 68)
    return 0 if ok else 1


def show(label, value):
    print(f"  {{label}}: {{value}}")


def query(name, rtype):
    """优先用 dnspython，缺失时回退 nslookup。返回记录字符串列表。"""
    try:
        import dns.resolver
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["223.5.5.5", "119.29.29.29", "8.8.8.8"]
        r.lifetime = 8
        out = []
        for ans in r.resolve(name, rtype):
            out.append(ans.to_text().strip('"'))
        return out, ""
    except ImportError:
        pass
    except Exception as e:  # noqa: BLE001
        return [], f"{{type(e).__name__}}: {{e}}"

    try:
        p = subprocess.run(["nslookup", "-type=" + rtype, name],
                           capture_output=True, text=True, timeout=15)
        text = (p.stdout or "") + (p.stderr or "")
        recs = []
        for line in text.splitlines():
            s = line.strip()
            if "text =" in s.lower():
                recs.append(s.split("=", 1)[1].strip().strip('"'))
        if not recs and ("NXDOMAIN" in text or "can't find" in text.lower()):
            return [], ""
        return recs, ("解析无结果" if not recs else "")
    except Exception as e:  # noqa: BLE001
        return [], f"{{type(e).__name__}}: {{e}}"


def main(target, timeout):
    name = RECORD_NAME or DOMAIN or target.split("//")[-1].split("/")[0]
    print(f"[1/2] 查询 {{RTYPE}} 记录：{{name}}")
    recs, err = query(name, RTYPE)
    if err:
        show("查询异常", err)
    print("  解析结果：")
    if not recs:
        print("    (无记录)")
    for r in recs:
        show("记录", r)

    print("\\n[2/2] 判定")
    if MODE == "missing":
        if not recs:
            return result(True, f"{{name}} 仍无 {{RTYPE}} 记录，记录缺失问题复现")
        joined = " ".join(recs).lower()
        if WANT and WANT.lower() not in joined:
            return result(True, f"记录存在但不含 {{WANT}}，配置仍不达标")
        return result(False, f"已配置相关记录：{{recs[:2]}}，问题可能已修复")
    if WANT and not any(WANT.lower() in r.lower() for r in recs):
        return result(True, f"记录取值仍不含 {{WANT}}，问题复现")
    if not recs:
        return result(True, f"记录缺失，问题复现")
    return result(False, "记录取值已符合预期")


'''
    expected = (
        f"1. 查询 {rname or domain} 的 {rtype} 记录\n"
        f"2. 按模式判定：{'记录应仍缺失' if mode == 'missing' else f'取值应不含 {want}'}\n"
        "3. 命令：python verify_xxx.py（无需参数，域名已内嵌）\n"
        "4. 说明：DNS 记录属公网可查事实，复现不受扫描网络环境影响"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 13：速率限制复现（并发探测，只读）
# ==============================================================================
def t_rate_limit(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：连续并发请求未触发任何限流；全部成功即说明缺速率限制。

    注意：本脚本只发只读请求（GET/HEAD），并发数受控（默认 20，上限 40），
    不提交任何业务数据，也不会造成明显负载。
    """
    burst = min(int(plan.extra.get("burst", 20) or 20), 40)
    body = f'''{INLINE_HELPERS}

BURST = {burst}
# 只保留**明确的限流语汇**。
# 绝不能把「验证码」「captcha」算作限流 —— 登录页普遍含这两个词，
# 一旦纳入，任何一个有登录页的目标都会被误判成「已实施限流」。
LIMIT_MARKERS = ["too many requests", "rate limit", "ratelimit", "slow down",
                 "请求过于频繁", "操作太频繁", "访问过于频繁", "请求次数过多",
                 "请稍后再试", "到达上限", "达到上限", "exceeded"]


def _one(args):
    """单次只读请求。

    必须通过参数取 URL：probe_url 是 main() 的局部变量，
    被 ThreadPoolExecutor 提交的函数看不到它
    （曾因此让整个并发段全部抛 NameError，判定却还继续往下走）。
    """
    import time as _t
    url, _i = args
    t0 = _t.time()
    try:
        r = _fetch(url, 10)
        return (r.status_code, len(r.text or ""), int((_t.time() - t0) * 1000),
                "", (r.text or ""))
    except Exception as e:  # noqa: BLE001
        return (None, 0, int((_t.time() - t0) * 1000), type(e).__name__, "")


def main(target, timeout):
    base = target.rstrip("/")
    {plan.url_expr()}
    print(f"[1/3] 基线：单次请求 {{probe_url}}")
    try:
        b = _fetch(probe_url, timeout)
    except Exception as e:
        print(f"[错误] 基线请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("基线状态码", b.status_code)
    show("基线长度", len(b.text or ""))
    base_text = b.text or ""

    print(f"\\n[2/3] 并发发送 {{BURST}} 次只读请求（不提交业务数据）")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(BURST, 10)) as ex:
        # 必须把 URL 作为参数传进去：probe_url 是 main() 的局部变量，
        # 工作线程看不到它（曾因此让并发段整体抛 NameError）。
        res = list(ex.map(_one, [(probe_url, i) for i in range(BURST)]))
    codes = [r[0] for r in res]
    show("状态码分布", sorted(set(codes)))
    show("成功次数", sum(1 for c in codes if c == 200))
    show("429 次数", sum(1 for c in codes if c == 429))
    show("请求异常", sorted({{r[3] for r in res if r[3]}}))

    print("\\n[3/3] 判定")
    if any(c == 429 for c in codes):
        return result(False, "出现 429，服务端已实施速率限制，问题可能已修复")

    # 检查响应体是否出现限流提示
    hits = []
    try:
        last = _fetch(probe_url, timeout)
        lt = (last.text or "").lower()
        hits = [m for m in LIMIT_MARKERS if m.lower() in lt]
    except Exception:  # noqa: BLE001
        pass
    show("响应中的限流提示", hits)
    if hits:
        return result(False, f"响应中出现限流提示 {{hits}}，问题可能已修复")

    ok_n = sum(1 for c in codes if c is not None and c < 500)
    timeout_n = sum(1 for c in codes if c is None)
    if ok_n >= BURST * 0.9:
        return result(True, f"连续 {{BURST}} 次请求全部正常返回且无限流特征，"
                            f"该接口未实施速率限制")
    if timeout_n > BURST * 0.3:
        # 客户端侧大面积超时通常说明目标处理能力有限，而不是实施了限流 ——
        # 把它读成「已有限流」会得到完全相反的结论。
        print(f"  {{timeout_n}}/{{BURST}} 次请求在客户端侧失败（超时 / 连接错误），")
        print("  这更可能是目标处理能力有限，而非实施了限流。")
        print("  退出码 2「无法判定」—— 建议在网络条件更稳定的环境重跑。")
        return 2
    return result(False, f"仅 {{ok_n}}/{{BURST}} 次返回正常且出现限流迹象，"
                         f"无法认定完全未实施限流")


'''
    expected = (
        f"1. 单次请求 {plan.probe_path or '/'} 记录基线状态码与响应\n"
        f"2. 并发发送 {burst} 次只读请求（GET/HEAD，无业务数据提交）\n"
        "3. 全部返回正常、且无 429 / 限流提示 → 未实施速率限制，问题复现\n"
        "4. 出现 429 或限流提示 → 已有防护，问题已修复"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 14：明文通道可用性复现（站点可经 http:// 访问 / 明文入口）
# ==============================================================================
def t_plain_channel(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：把目标地址换成 http:// 后仍能正常访问，说明明文通道可用。

    为什么需要单独的模板
    --------------------
    「凭据经明文传输」这类发现的判据是**站点是否提供明文入口**，
    而不是「页面里有没有 http:// 资源引用」。用后者去复现前者，
    必然判据不匹配 —— 判据一旦错位，复现脚本就会给出错误的否定结论。
    """
    body = f'''{INLINE_HELPERS}

# 该发现类的判据：站点是否接受 http:// 访问
PROBE_PATH = {json.dumps(plan.probe_path or "/", ensure_ascii=False)}


def main(target, timeout):
    print("[1/3] 判定目标当前使用的协议")
    is_plain = target.lower().startswith("http://")
    show("目标地址", target)
    show("当前协议", "http（明文）" if is_plain else "https（加密）")

    if is_plain:
        print("\\n[2/3] 目标本身即以明文 http 提供服务 —— 无需降级即可确认")
        plain_url = target.rstrip("/") + PROBE_PATH
        try:
            r = _fetch(plain_url, timeout)
        except Exception as e:  # noqa: BLE001
            print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
            return 2
        show("HTTP 状态码", r.status_code)
        show("响应长度", len(r.text or ""))
        if r.status_code >= 400:
            return result(False, f"明文地址返回 {{r.status_code}}，当前不可复现")
        print("\\n[3/3] 判定")
        return result(True, "目标以明文 HTTP 提供服务，凭据与数据不经加密通道传输，"
                            "明文传输问题确认存在")

    print("\\n[2/3] 尝试降级到 http:// 访问（只做只读 GET，不提交任何凭据）")
    plain_url = target.replace("https://", "http://", 1).rstrip("/") + PROBE_PATH
    show("降级地址", plain_url)
    try:
        r = _fetch(plain_url, timeout)
    except Exception as e:  # noqa: BLE001
        show("请求异常", type(e).__name__)
        return result(False, "明文地址不可访问，站点已强制加密通道，问题可能已修复")

    show("HTTP 状态码", r.status_code)
    show("响应长度", len(r.text or ""))
    try:
        show("最终地址", r.url)
    except Exception:  # noqa: BLE001
        pass

    print("\\n[3/3] 判定")
    if r.status_code >= 400:
        return result(False, f"明文地址返回 {{r.status_code}}，明文入口不可用")
    # 只认「确实拿到了内容」：跳转到 https 或返回空壳都不算明文入口可用
    if r.text and len(r.text) > 200:
        return result(True, "http:// 地址仍返回有效内容，明文通道可用，"
                            "凭据存在被明文嗅探的风险")
    return result(False, "明文地址返回内容过短或为空，无法确认明文通道可用")


'''
    expected = (
        f"1. 访问 {plan.probe_path or '/'}\n"
        "2. 目标本身是 http:// → 直接确认明文传输\n"
        "3. 目标为 https:// → 尝试降级为 http:// 访问\n"
        "4. 明文地址返回 200 且内容有效 → 明文通道可用，问题复现\n"
        "5. 仅做只读 GET，不提交任何凭据"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板注册表
# ==============================================================================
# ==============================================================================
# 模板：证书透明度日志子域枚举复现
# ==============================================================================
# 本发现的证据源本身就是公开 CT 日志，所以复现脚本必须去查同一个公开源 ——
# 这不算超出授权范围（它不触碰目标主机，只查公开日志），但正因为目标不是
# 目标站点，默认模板（按 base + path 请求）套上去只会得到「无法判定」。
_SUBDOMAIN_LINE = re.compile(
    r"(?m)^\s*[·\-*]\s*([A-Za-z0-9][A-Za-z0-9._\-]*\.[A-Za-z]{2,})\s*$")


def _claimed_subdomains(f: Any, domain: str = "") -> list[str]:
    """从发现里取出被点名的子域清单。

    EXT-DM-06 的 technical_detail 写成「  · sub.example.com」这种列表行；
    从文本里取比新增字段省事，而且历史记录同样能解析。统一按目标域过滤，
    避免把 technical_detail 里顺带提到的第三方域名（如 crt.sh）当成子域。
    """
    out: list[str] = []
    for m in _SUBDOMAIN_LINE.finditer(_detail_text(f)):
        out.append(m.group(1).lower().strip("."))
    if not out:
        for ev in (getattr(f, "evidence", None) or []):
            content = getattr(ev, "content", "") or ""
            out += [x.lower().strip(".") for x in
                    re.findall(r"[A-Za-z0-9][A-Za-z0-9._\-]*\.[A-Za-z]{2,}", content)]
    dom = (domain or "").lower()
    if dom:
        out = [s for s in out if s == dom or s.endswith("." + dom)]
    return list(dict.fromkeys(out))[:60]


def t_ct_subdomains(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：被点名的子域至今仍能从公开 CT 日志枚举出来。"""
    domain = plan.extra.get("domain") or _domain_of(f, target_url)
    domain = re.sub(r":\d+$", "", domain or "")
    subs = list(plan.extra.get("subdomains") or [])
    api = "https://crt.sh/?q=%25." + domain + "&output=json"
    body = f'''#!/usr/bin/env python3
# 证书透明度日志子域枚举复现。
# 说明：本脚本只查询公开 CT 日志，不向目标主机发送任何请求。
import argparse
import json
import sys
import urllib.request

DOMAIN = {json.dumps(domain)}
CLAIMED = {json.dumps(subs, ensure_ascii=False)}
API = {json.dumps(api)}
UA = {{"User-Agent": "AIScan/1.0 (Authorized Security Assessment)"}}


def result(code, message):
    print("\\n" + "=" * 68)
    print({{0: "[复现成功] ", 1: "[未复现] ", 2: "[无法判定] "}}[code] + message)
    print("=" * 68)
    return code


def main(timeout):
    if not DOMAIN:
        return result(2, "未记录目标域名，无法查询 CT 日志")
    print(f"[1/2] 查询公开证书透明度日志：{{API}}")
    try:
        req = urllib.request.Request(API, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except Exception as e:
        return result(2, f"crt.sh 不可达（{{type(e).__name__}}: {{e}}）—— "
                         f"无法判定；请人工用其他公开源复核子域清单")
    try:
        rows = json.loads(raw)
    except Exception:
        return result(2, "crt.sh 返回内容不是 JSON（可能触发限流）—— 无法判定")

    found = set()
    for it in rows:
        for name in str(it.get("name_value", "")).split("\\n"):
            name = name.strip().lower().lstrip("*.").strip(".")
            if name:
                found.add(name)

    print(f"  日志中共取到 {{len(found)}} 个名称")
    if not found:
        # 整个域名在 CT 日志里一条记录都没有 —— 这不是「问题已修复」，而是
        # 「观察不到」（测试域、未签发公信证书、或接口限流返回空）。这两件事
        # 必须分开：判成「未复现」会把观察失败说成漏洞消失。
        return result(2, "该域名在 CT 日志中无任何记录，无法据此核对子域清单"
                         "（可能是内部 / 测试域名，或接口限流）—— 无法判定")
    print("\\n[2/2] 核对被点名的子域")
    if not CLAIMED:
        return result(2, "本发现未记录具体子域清单，无法逐项核对")
    hit = [s for s in CLAIMED if s.lower() in found]
    miss = [s for s in CLAIMED if s.lower() not in found]
    print(f"  仍在日志中：{{len(hit)}} / {{len(CLAIMED)}}")
    for s in hit:
        print(f"    · {{s}}")
    if miss:
        print(f"  已不在日志中：{{len(miss)}}")
        for s in miss:
            print(f"    · {{s}}")
    if hit and not miss:
        return result(0, f"{{len(hit)}} 个被点名子域仍可从公开 CT 日志枚举到")
    if hit:
        return result(1, f"仅 {{len(hit)}}/{{len(CLAIMED)}} 个子域仍在日志中 —— "
                         f"清单已变化，请按实际结果更新结论")
    return result(1, "被点名的子域均已不在 CT 日志中 —— 问题可能已收敛")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="")
    ap.add_argument("--timeout", type=int, default=45)
    a = ap.parse_args()
    sys.exit(main(a.timeout))


'''
    expected = (
        f"1. 查询公开 CT 日志 API（域名 {domain}），只取 name_value 字段\n"
        f"2. 逐项核对被点名的 {len(subs)} 个子域是否仍在日志中\n"
        "3. 全部仍在 → 复现成功；部分 / 全部消失 → 清单已变化，按实际结果更新\n"
        "4. 说明：本脚本只查公开日志、不触碰目标主机；crt.sh 不可达或限流时判「无法判定」"
    )
    return body, expected, STRENGTH_STRONG


# ==============================================================================
# 模板 17：默认 / 弱口令登录复现（WSTG-ATHN-02）
# ==============================================================================
def t_weak_login(plan: ReproPlan, f: Any, target_url: str) -> tuple[str, str, str]:
    """断言：重放**同一份受控字典**，仍能登进系统。

    为什么不把「当时命中的那一组口令」写进脚本
    ------------------------------------------
    报告刻意不记录口令原文（只留散列指纹）。所以复现脚本重放的是与检测阶段
    完全一致的那份固定字典 —— 只要其中仍有一组能拿到会话凭据 / 跳出登录页，
    就说明「默认 / 弱口令可登录」这个问题依然存在。脚本因此可独立执行，
    又不会把口令变成一个新的泄露源。

    为什么不能沿用 param_replay：那条模板要把载荷塞进某个参数、
    再比对响应特征差异；默认口令这个主张里**根本没有可注入的参数**，
    比对出来必然是「未复现」—— 一条真实存在的高危发现会被准入闸门挡在
    漏洞清单之外（这正是 内部生产系统 OSS 那次漏报的同型事故）。
    """
    try:
        from engine.credhunt import DEFAULT_PAIRS as _PAIRS  # noqa: PLC0415
    except ImportError:  # noqa: BLE001
        try:
            from credhunt import DEFAULT_PAIRS as _PAIRS  # type: ignore  # noqa: PLC0415
        except ImportError:  # noqa: BLE001
            _PAIRS = (("admin", "admin"), ("admin", "admin123"),
                      ("test", "test"), ("test", "123456"))
    creds = [[u, p] for u, p in list(_PAIRS)[:12]]
    login_path = plan.probe_path or "/"

    body = f'''{INLINE_HELPERS}
import re
from urllib.parse import urljoin

LOGIN_PATH = {json.dumps(login_path, ensure_ascii=False)}
CREDS = {json.dumps(creds, ensure_ascii=False)}

RE_RISK = re.compile(r"(验证码|captcha|锁定|冻结|尝试次数过多|操作过于频繁|"
                     r"请稍后再试|访问过于频繁|too\\s+many|locked|rate\\s+limit)", re.I)
RE_FAIL = re.compile(r"(密码错误|账号或密码|用户名或密码|登录失败|认证失败|"
                     r"invalid\\s+(password|credential)|incorrect|wrong\\s+password)", re.I)
RE_SESS = re.compile(r"(session|jsessionid|token|ticket|remember|sid|auth)", re.I)
RE_FORM = re.compile(r"(?is)<form\\b.*?</form>")
RE_INPUT = re.compile(r"(?is)<input\\b[^>]*>")
RE_ACTION = re.compile(r"(?is)<form[^>]*\\baction=[\\"']?([^\\"'\\s>]+)")
RE_NAME = re.compile(r"(?is)\\bname=[\\"']?([^\\"'\\s>]+)")
RE_TYPE = re.compile(r"(?is)\\btype=[\\"']?([^\\"'\\s>]+)")
RE_PW = re.compile(r"(?is)type=[\\"']?password")


def _fields(html):
    """从登录页识别 (提交地址, 账号字段, 口令字段)。识别不出返回空。"""
    m = RE_FORM.search(html or "")
    form = m.group(0) if m else (html or "")
    action = RE_ACTION.search(form)
    a = action.group(1) if action else ""
    user = pw = ""
    for inp in RE_INPUT.findall(form):
        t = (RE_TYPE.search(inp).group(1) if RE_TYPE.search(inp) else "").lower()
        n = RE_NAME.search(inp).group(1) if RE_NAME.search(inp) else ""
        if not n:
            continue
        if t == "password" or re.search(r"(pass|pwd)", n, re.I):
            pw = pw or n
        elif re.search(r"(user|account|login|name|phone|mobile|email)", n, re.I):
            user = user or n
    return a, user, pw


def _post(url, data, timeout):
    return _fetch(url, timeout, method="POST", data=data,
                  extra_headers={{"Content-Type": "application/x-www-form-urlencoded"}})


def main(target, timeout):
    base = target.rstrip("/")
    login_url = urljoin(base + "/", LOGIN_PATH.lstrip("/"))

    print("[1/3] 读取登录页，识别表单字段")
    try:
        page = _fetch(login_url, timeout)
    except Exception as e:
        print("[错误] 登录页请求失败：{{}}: {{}}".format(type(e).__name__, e))
        return 2
    show("登录页状态码", page.status_code)
    html = page.text or ""
    action, user_field, pw_field = _fields(html)
    if not (user_field and pw_field):
        print("[无法判定] 未能从登录页识别出账号 / 口令字段名"
              "（可能是验证码 / 短信 / SSO 登录）—— 需人工核对")
        return 2
    submit_url = urljoin(login_url, action) if action else login_url
    print("    提交地址：{{}}".format(mask(submit_url)))
    print("    字段：{{}} / {{}}".format(user_field, pw_field))

    print("\\n[2/3] 重放受控默认口令字典（{{}} 组，与检测阶段一致）".format(len(CREDS)))
    for u, p in CREDS:
        try:
            r = _post(submit_url, {{user_field: u, pw_field: p}}, timeout)
        except Exception as e:
            print("  [跳过] {{}}：{{}}".format(u, type(e).__name__))
            continue
        text = r.text or ""
        if RE_RISK.search(text) or r.status_code == 429:
            print("[无法判定] 服务端出现风控 / 锁定信号（HTTP {{}}）—— "
                  "为避免账号锁定，脚本立即停止；本次**未验证**".format(r.status_code))
            return 2
        set_cookie = r.headers.get("Set-Cookie", "")
        ok = False
        why = ""
        if set_cookie and RE_SESS.search(set_cookie):
            ok, why = True, "服务端下发了会话类 Cookie"
        elif r.status_code in (301, 302, 303, 307):
            loc = r.headers.get("Location", "")
            if loc and not re.search(r"(login|signin|logon|sso|passport)", loc, re.I):
                ok, why = True, "提交后被重定向到登录页之外"
        print("  {{}} -> HTTP {{}}{{}}".format(u, r.status_code,
              ("（认证失败特征）" if RE_FAIL.search(text) else "")))
        if ok:
            print("\\n[3/3] 断言")
            show("命中账号", u)
            show("判定依据", why)
            print("口令原文不在报告中记录（仅散列指纹）。")
            return result(True, "账号 {{}} 用默认 / 弱口令即可登录（{{}}），问题复现".format(u, why))

    print("\\n[3/3] 断言")
    print("字典内 {{}} 组组合均未登录成功。".format(len(CREDS)))
    print("注意：这**不等于**系统不存在弱口令 —— 本次只用了受限的默认口令集；")
    print("      若目标对失败尝试有频控，也可能改变结果。需人工确认后关闭本项。")
    return result(False, "本轮受控字典未复现默认口令（可能是已修复、或字典未覆盖）")


'''
    expected = ("用与检测阶段一致的受控字典重放登录请求 → "
                "任一组默认口令仍能登录成功（下发会话凭据 / 跳出登录页）")
    return body, expected, STRENGTH_MEDIUM


TEMPLATES: dict[str, Any] = {
    "content_marker": t_content_marker,
    "path_reach": t_path_reach,
    "dir_listing": t_dir_listing,
    "header_state": t_header_state,
    "cors_reflect": t_cors_reflect,
    "param_replay": t_param_replay,
    "anon_access": t_anon_access,
    "cross_role": t_cross_role,
    "port_open": t_port_open,
    "method_accept": t_method_accept,
    "tls_state": t_tls_state,
    "component_version": t_component_version,
    "dns_record": t_dns_record,
    "rate_limit": t_rate_limit,
    "plain_channel": t_plain_channel,
    "ct_subdomains": t_ct_subdomains,
    "weak_login": t_weak_login,
    "weak_probe": t_weak_probe,
}


def render_script(kind: str, plan: ReproPlan, f: Any, target_url: str):
    """按模板类型渲染脚本。未知类型回落弱兜底，并如实返回弱强度。"""
    fn = TEMPLATES.get(kind) or t_weak_probe
    return fn(plan, f, target_url)


# ==============================================================================
# 选择器：从一条 Finding 推断「该用哪个模板」
# ==============================================================================
# 敏感文件的语义特征表（用于 path_reach 的断言）
_FILE_MARKERS: dict[str, list[str]] = {
    ".git/config": ["[core]", "repositoryformatversion"],
    ".env": ["DB_", "APP_", "SECRET", "="],
    ".svn/entries": ["dir", "svn"],
    ".ds_store": ["bud1"],
    ".idea/workspace.xml": ["<project", "component"],
    ".vscode/settings.json": ['"editor"', '"files"'],
    "WEB-INF/web.xml": ["<web-app", "servlet"],
    "actuator/env": ["activeProfiles", "systemProperties"],
    "actuator/health": ["status"],
    "actuator/beans": ["beans", "type"],
    "server-status": ["Apache Server Status"],
    "server-info": ["Apache Server Information"],
    "phpinfo.php": ["phpinfo", "PHP Version"],
    "info.php": ["phpinfo", "PHP Version"],
    "swagger-ui.html": ["swagger", "openapi"],
    "swagger/index.html": ["swagger", "openapi"],
    "v2/api-docs": ["paths", "swagger"],
    "v3/api-docs": ["paths", "openapi"],
    "openapi.json": ["openapi", "paths"],
    "api-docs": ["swagger", "paths"],
    "package.json": ['"dependencies"', '"name"'],
    "composer.json": ['"require"'],
    "requirements.txt": ["==", ">="],
    "Gemfile.lock": ["GEM", "specs"],
    "yarn.lock": ["version", "resolved"],
    "Dockerfile": ["FROM", "RUN"],
    "docker-compose.yml": ["services", "image"],
    ".dockerignore": ["Dockerfile"],
    "Jenkinsfile": ["pipeline", "stage"],
    ".gitlab-ci.yml": ["stages", "script"],
    ".travis.yml": ["language", "script"],
    "debug.log": ["ERROR", "Exception", "Traceback"],
    "error.log": ["ERROR", "Exception"],
    "access.log": ["GET", "POST", "HTTP"],
    "backup.sql": ["INSERT INTO", "CREATE TABLE"],
    "dump.sql": ["INSERT INTO", "CREATE TABLE"],
    "database.sql": ["INSERT INTO", "CREATE TABLE"],
    "backup.zip": ["PK"],
    "backup.tar.gz": ["\\x1f\\x8b"],
    ".bash_history": ["cd ", "sudo", "ls "],
    ".ssh/id_rsa": ["PRIVATE KEY"],
    ".aws/credentials": ["aws_access_key_id"],
    ".npmrc": ["registry", "_auth"],
    ".pypirc": ["index-servers", "username"],
    "web.config": ["<configuration", "connectionString"],
    "crossdomain.xml": ["cross-domain-policy"],
    "clientaccesspolicy.xml": ["access-policy"],
}

_DIR_LISTING_HINTS = ("目录列举", "目录浏览", "directory listing", "index of", "列举")

_ANON_HINTS = ("未授权", "匿名", "无凭据", "越权", "idor", "bola", "bfla",
               "未鉴权", "未认证", "任意用户", "越界访问", "未授权访问")

_PORT_HINTS = ("端口", "开放服务", "高危端口", "服务暴露")

_TLS_HINTS = ("tls", "ssl", "协议版本", "加密套件", "弱加密协议")

_METHOD_HINTS = ("http 方法", "危险方法", "方法允许", "verb", "请求方法")

_CORS_HINTS = ("cors", "跨域", "跨源")

_HEADER_HINTS = ("响应头", "安全头", "security header", "hsts", "csp",
                 "x-frame", "x-content-type", "referrer-policy")

_VERSION_HINTS = ("版本", "version", "指纹", "组件", "framework", "中间件", "banner")


def _find_file_markers(path: str) -> list[str]:
    p = path.lower().lstrip("/")
    for key, markers in _FILE_MARKERS.items():
        if p.endswith(key) or key in p:
            return markers
    # 按扩展名给通用特征
    ext_table = {
        ".json": ['"', "{"],
        ".xml": ["<", ">"],
        ".yml": [":", "-"],
        ".yaml": [":", "-"],
        ".sql": ["INSERT", "CREATE", "SELECT"],
        ".log": ["ERROR", "INFO", "WARN", "GET", "POST"],
        ".bak": ["=", "<", "{"],
        ".old": ["=", "<", "{"],
        ".zip": ["PK"],
        ".gz": ["\\x1f\\x8b"],
        ".txt": ["=", ":", "-"],
    }
    for ext, markers in ext_table.items():
        if p.endswith(ext):
            return markers
    return []


def _unescape_layer(text: str) -> str:
    """剥掉证据里多余的一层 JSON 转义。

    证据普遍是 `json.dumps(响应片段)` 的产物，于是响应原文
    `{"object":"list","data":[]}` 在证据里会变成
    `"{\\"object\\":\\"list\\",\\"data\\":[]}"`。
    若直接把这段文本当特征串用，`\\"` 里那个反斜杠会留下来 ——
    特征串就被改成了 `{\\object\\:\\list...`，与真实响应永远匹配不上，
    一个真实存在的问题被判成「未复现」。
    """
    s = (text or "").strip()
    if not s:
        return ""
    for _ in range(2):                      # 最多剥两层，避免把正常内容吃掉
        if not (s.startswith('"') and s.endswith('"') and len(s) >= 2):
            break
        try:
            nxt = json.loads(s)
        except Exception:  # noqa: BLE001
            break
        if not isinstance(nxt, str):
            break
        s = nxt.strip()
    return s


def _iter_evidence_strings(content: str) -> list[str]:
    """把一段证据内容展开成「候选特征串」列表。

    证据可能是：纯文本行；也可能是一层 JSON（dict / list）。
    JSON 的情况下，**真正值得断言的是它的字符串值**（也就是当时的响应片段），
    而不是 JSON 结构本身 —— 拿结构去响应里搜，搜不到东西。
    """
    out: list[str] = []
    s = (content or "").strip()
    if s.startswith(("{", "[")):
        try:
            data = json.loads(s)
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict):
            out.extend(str(v) for v in data.values() if isinstance(v, str))
        elif isinstance(data, list):
            out.extend(str(v) for v in data if isinstance(v, str))
    out.extend(_unescape_layer(ln) for ln in (content or "").splitlines())
    return out


def _extract_markers(f: Any, limit: int = 6) -> list[str]:
    """从证据内容里抽取可用于断言的特征串。

    优先取「短小且具辨识度」的片段 —— 太长会因页面细微变化而误判未复现，
    太短（如单个字母）则毫无判定力。

    **不要在这里剥引号。** 曾经为了「好嵌进生成脚本的字符串」把 `"` 去掉，
    结果是 JSON 转义残留的反斜杠被留在串里，特征串被改坏（见 `_unescape_layer`）。
    引号在生成脚本里由 `_markers_literal()`（`json.dumps`）负责转义，
    在这一层剥引号纯属多余且有害。
    """
    out: list[str] = []
    for ev in (f.evidence or []):
        content = getattr(ev, "content", "") or ""
        kind = getattr(ev, "kind", "") or ""
        if kind in ("request", "dns"):
            continue
        for cand in _iter_evidence_strings(content):
            for line in str(cand).splitlines():
                s = " ".join(line.split())
                if (8 <= len(s) <= 80 and re.search(r"[A-Za-z]", s)
                        and not s.startswith(("http", "<!"))
                        # 丢掉带 `\"` 的候选：这是 JSON 转义残留，不是响应原文。
                        # 断言一个被转义搅过的串，只会把真问题判成未复现。
                        # 只拦这一种形态，纯反斜杠（如 windows 路径）仍保留 ——
                        # 那可能正是要找的证据。
                        and '\\"' not in s):
                    out.append(s)
                    break
        if len(out) >= limit:
            break
    return list(dict.fromkeys(out))[:limit]


def _endpoint_path(f: Any, target_url: str) -> str:
    """把 endpoint 转成相对 target 根的路径（含查询串）。"""
    ep = (f.endpoint or "").strip()
    if not ep:
        return "/"
    m = re.match(r"^https?://[^/]+(/.*)?$", ep)
    if m:
        return m.group(1) or "/"
    if ep.startswith("/"):
        return ep
    if ep.startswith(("http://", "https://")):
        return "/"
    return "/" + ep.lstrip("/")


# ==============================================================================
# 选择器：检查项级确定性映射优先，自然语言推断仅作兜底
# ==============================================================================
def _kind_for(item_id: str) -> str:
    try:
        from verify.kind_map import kind_for as _kf
    except ImportError:  # noqa: BLE001
        try:
            from kind_map import kind_for as _kf  # type: ignore
        except ImportError:  # noqa: BLE001
            return ""
    return _kf(item_id)


def _head_blob(f: Any) -> str:
    """只拼「判定性字段」——标题与检查项 ID。

    绝不拼 description / impact / remediation：那些是解释性文字。
    把它们纳入关键词匹配会让「列举并下载对象存储文件」这类影响描述
    污染类型判断（这正是上一版把「云凭据泄露」误判成「目录列举」的原因）。
    """
    return f"{f.title or ''} {f.item_id or ''}".lower()


def _detail_text(f: Any) -> str:
    return f"{f.title or ''}\n{f.technical_detail or ''}"


# 响应头判定规则：(关键词, 头名, 模式)
_HEADER_RULES: list[tuple[str, str, str]] = [
    ("严格传输安全", "Strict-Transport-Security", "missing"),
    ("hsts", "Strict-Transport-Security", "missing"),
    ("内容安全策略", "Content-Security-Policy", "missing"),
    ("csp", "Content-Security-Policy", "missing"),
    ("点击劫持", "X-Frame-Options", "missing"),
    ("frame-ancestors", "Content-Security-Policy", "missing"),
    ("mime", "X-Content-Type-Options", "missing"),
    ("x-content-type", "X-Content-Type-Options", "missing"),
    ("referrer", "Referrer-Policy", "missing"),
    ("permissions-policy", "Permissions-Policy", "missing"),
    ("cookie 属性", "Set-Cookie", "value"),
    ("remember", "Set-Cookie", "value"),
    ("记住密码", "Set-Cookie", "value"),
    ("记住我", "Set-Cookie", "value"),
    ("缓存", "Cache-Control", "missing"),
    # Server / 指纹类必须排在「安全头」之前，否则会被兜底规则抢走
    ("服务端软件", "Server", "present"),
    ("服务器指纹", "Server", "present"),
    ("版本泄露", "Server", "present"),
    ("版本号", "Server", "present"),
    ("版本", "Server", "present"),
    ("中间件指纹", "X-Powered-By", "present"),
    ("中间件", "X-Powered-By", "present"),
    ("安全头", "X-Content-Type-Options", "missing"),
    ("cors", "Access-Control-Allow-Origin", "present"),
    ("跨域", "Access-Control-Allow-Origin", "present"),
]

# Cookie 属性类的期望值（HTTP 模式为 value 时，缺失该值即为问题）
_COOKIE_WANT = {
    "cookie 属性": "HttpOnly",
    "remember": "HttpOnly",
    "记住密码": "HttpOnly",
    "记住我": "HttpOnly",
}


def _pick_header(f: Any) -> tuple[str, str, str]:
    """从标题里挑出待断言的响应头与模式。返回 (头名, 模式, 期望值)。"""
    blob = _head_blob(f)
    # 标题里直接出现的头名优先（最精确）
    m = re.search(r"(X-[A-Za-z0-9-]{2,40}|Strict-Transport-Security|"
                  r"Content-Security-Policy|Referrer-Policy|Permissions-Policy)",
                  f.title or "")
    if m:
        name = m.group(1)
        mode = "missing" if re.search(r"(缺失|未设置|未启用|缺少)", f.title or "") else "present"
        return name, mode, ""
    for kw, name, mode in _HEADER_RULES:
        if kw in blob:
            return name, mode, _COOKIE_WANT.get(kw, "")
    return "X-Content-Type-Options", "missing", ""


def _pick_tls_protocol(f: Any) -> str:
    text = _detail_text(f)
    m = re.search(r"(TLS\s*v?1\.[0-3]|TLSv1(?:_[0-3])?|SSL\s*v?3)", text, re.I)
    if not m:
        return "TLSv1.0"
    raw = re.sub(r"\s+", "", m.group(1)).replace("TLSv", "TLSv1.").replace("TLS1.", "TLSv1.")
    table = {
        "TLSv1.0": "TLSv1.0", "TLSv1.1": "TLSv1.1", "TLSv1.2": "TLSv1.2",
        "TLSv1.3": "TLSv1.3", "TLSv1_0": "TLSv1.0", "TLSv1_1": "TLSv1.1",
        "TLSv1_2": "TLSv1.2", "TLSv1_3": "TLSv1.3", "SSLv3": "SSLv3",
    }
    return table.get(raw, "TLSv1.0")


def _domain_of(f: Any, target_url: str) -> str:
    m = re.search(r"https?://([^/:]+)", f.endpoint or "")
    if m:
        return m.group(1)
    m = re.search(r"https?://([^/:]+)", target_url or "")
    return m.group(1) if m else ""


def _pick_version(f: Any) -> str:
    m = re.search(r"(\d+\.\d+(?:\.\d+){0,3})", _detail_text(f))
    return m.group(1) if m else ""


def _pick_selector(hint: str, f: Any) -> str:
    """从标题里找可能被提到的参数名 / 载荷片段（用于参数重放）。"""
    m = re.search(r"[`\"'（(]([A-Za-z_][\w\-\[\]{}'\"]{0,40})[`\"'）)]", hint or "")
    return m.group(1) if m else ""


def _infer_kind(f: Any) -> str:
    """推断兜底：仅在检查项映射表未登记时使用。

    只读取标题类字段，不读影响/修复建议等解释性文本。
    """
    blob = _head_blob(f)
    ev_kinds = {getattr(e, "kind", "") for e in (f.evidence or [])}
    path = _endpoint_path(f, "")

    if re.search(r":\d{2,5}\b", f.endpoint or "") and re.search(r"(端口|服务暴露|开放)", blob):
        return "port_open"
    if re.search(r"(tls|ssl|加密套件|协议版本)", blob):
        return "tls_state"
    if re.search(r"(cors|跨域|跨源)", blob):
        return "cors_reflect"
    if "header" in ev_kinds or re.search(r"(响应头|安全头|hsts|csp)", blob):
        return "header_state"
    if re.search(r"(目录列举|目录浏览|directory listing)", blob):
        return "dir_listing"
    if re.search(r"(未授权|匿名|无凭据|越权|idor|bola|bfla|未鉴权)", blob):
        return "anon_access"
    if f.param and re.search(r"(注入|injection|反射|重定向|ssrf|xss|crlf|遍历|traversal)", blob):
        return "param_replay"
    if re.search(r"(http 方法|危险方法|动词)", blob):
        return "method_accept"
    if re.search(r"(版本|指纹|组件|框架)", blob) and re.search(r"\d+\.\d+", _detail_text(f)):
        return "component_version"
    if path != "/" and re.search(r"(暴露|泄露|备份|源码|配置|敏感文件|文档|接口)", blob):
        return "path_reach"
    if (f.evidence or []) and ("response" in ev_kinds or "file" in ev_kinds):
        return "content_marker"
    return "weak_probe"


# 常见前端产物路径 —— 特征常出现在这些文件里，而非根页面
_PROD_ASSET_PATHS = [
    "/app.js", "/main.js", "/index.js", "/bundle.js", "/app.min.js", "/main.min.js",
    "/static/js/main.js", "/static/js/app.js", "/js/app.js", "/js/main.js",
    "/assets/index.js", "/assets/app.js", "/dist/app.js", "/dist/main.js",
    "/common.js", "/vendor.js", "/runtime.js", "/config.js",
]

# 从「命中清单」这类结构化说明文字里抽取候选地址。
# 形态：`· [接口 /api/user?uid=1] 手机号 → 138****8888`
#       `· [接口 http://host/api/user?uid=1] 手机号 → 138****8888`
# 接口路径没有文件扩展名，靠后缀正则抽不出来；而敏感数据恰恰最常出现在
# 接口响应里 —— 漏掉它们，复现脚本就扫不到当初的命中位置，
# 会把一个真实问题误判成「未复现」。
_PATH_IN_LABEL = re.compile(
    r"[\[（(]\s*(?:接口|端点|路径|地址|URL|url)?\s*"
    r"((?:https?://[^\s\]\)，,]{4,160})|/[\w\-./?=&%:@~+]{1,90})")


def _label_paths(text: str, host: str = "", limit: int = 10) -> list[str]:
    """抽取说明文字里的站内候选路径。

    绝对 URL 只在**主机与当前端点一致**时才转成相对路径；
    站外地址一律丢弃 —— 复现脚本不得越出授权范围去请求第三方。
    """
    out: list[str] = []
    for m in _PATH_IN_LABEL.finditer(text or ""):
        raw = m.group(1)
        if raw.startswith("//"):
            continue
        if raw.lower().startswith(("http://", "https://")):
            mm = re.match(r"^https?://([^/]+)(/.*)?$", raw)
            if not mm:
                continue
            if host and mm.group(1).lower() != host.lower():
                continue
            raw = mm.group(2) or "/"
        out.append(raw)
    return list(dict.fromkeys(out))[:limit]


def _content_candidates(f: Any, path: str, limit: int = 14) -> list[str]:
    """列出「内容特征可能出现的候选地址」。

    特征可能来自根页面、内联脚本，也可能来自某个前端打包产物。
    只试根地址会把「特征其实在 app.js 里」误判成「未复现」。

    安全约束：只输出站内相对路径，绝不把发现里出现的站外 URL 放进候选 ——
    复现脚本不得越出授权范围去请求第三方地址。
    """
    cands: list[str] = []
    if path and path != "/":
        cands.append(path)
    cands.append("/")
    # 先放「扫描时真正命中的那个地址」，其次才是前端产物候选。
    # 顺序即优先级：脚本按序探测，命中即停。
    detail = _detail_text(f)
    hm = re.match(r"^https?://([^/]+)", (getattr(f, "endpoint", "") or "").strip())
    cands.extend(_label_paths(detail, host=hm.group(1) if hm else ""))
    for m in re.finditer(r"(?:^|[\s\"'(])([\w\-./]{2,80}\.(?:js|css|json|map|txt|xml))",
                         detail):
        cands.append("/" + m.group(1).lstrip("/"))
    cands.extend(_PROD_ASSET_PATHS)
    return list(dict.fromkeys(cands))[:limit]


# 「缺失式」发现：标题以这些词开头时，说明结论是「没找到某功能」，
# 这类观察无法用「重放访问」复现，必须降级为弱复现并交人工核对。
_MISSING_HINTS = ("未发现", "未能", "无法", "未检测到", "未识别", "不存在")

# 依赖动态交互的复现方式。缺失式发现落到这些类型上时一律降级。
_DYNAMIC_KINDS = {"anon_access", "param_replay", "rate_limit", "port_open",
                  "method_accept", "cors_reflect", "weak_login"}


# ------------------------------------------------------------------------------
# 内容类检测规则：复现脚本内嵌同一套规则，独立重跑检测
# ------------------------------------------------------------------------------
def _base_rules():
    """从检测器基础库取规则常量（保持与扫描时完全一致）。"""
    try:
        from engine.checks.base import (  # noqa: E402
            CREDENTIAL_PATTERNS, DOM_XSS_SINKS, DOM_XSS_SOURCES,
            INTERNAL_ADDR_PATTERNS, PII_PATTERNS, STACK_TRACE_PATTERNS,
            WEAK_CRYPTO_PATTERNS,
        )
    except ImportError:  # noqa: BLE001
        import pathlib as _p
        import sys as _s
        _root = _p.Path(__file__).resolve().parent.parent
        if str(_root) not in _s.path:
            _s.path.insert(0, str(_root))
        from engine.checks.base import (  # type: ignore  # noqa: E402
            CREDENTIAL_PATTERNS, DOM_XSS_SINKS, DOM_XSS_SOURCES,
            INTERNAL_ADDR_PATTERNS, PII_PATTERNS, STACK_TRACE_PATTERNS,
            WEAK_CRYPTO_PATTERNS,
        )
    return {
        "CREDENTIAL_PATTERNS": CREDENTIAL_PATTERNS,
        "DOM_XSS_SINKS": DOM_XSS_SINKS,
        "DOM_XSS_SOURCES": DOM_XSS_SOURCES,
        "INTERNAL_ADDR_PATTERNS": INTERNAL_ADDR_PATTERNS,
        "PII_PATTERNS": PII_PATTERNS,
        "STACK_TRACE_PATTERNS": STACK_TRACE_PATTERNS,
        "WEAK_CRYPTO_PATTERNS": WEAK_CRYPTO_PATTERNS,
    }


def _rule_sets() -> dict[str, list[list[str]]]:
    """规则集：{类别: [[正则, 说明], ...]}，可直接内嵌进复现脚本。"""
    b = _base_rules()
    as_pairs = lambda seq: [[str(p), str(l)] for p, l in seq]  # noqa: E731
    return {
        "credentials": as_pairs(b["CREDENTIAL_PATTERNS"]),
        "pii": [[str(v), str(k)] for k, v in b["PII_PATTERNS"].items()],
        "internal": as_pairs(b["INTERNAL_ADDR_PATTERNS"]),
        "weak_crypto": as_pairs(b["WEAK_CRYPTO_PATTERNS"]),
        "stack_trace": [[str(p), "堆栈 / 异常信息"] for p in b["STACK_TRACE_PATTERNS"]],
        "dom_xss": as_pairs(b["DOM_XSS_SINKS"] + b["DOM_XSS_SOURCES"]),
        "dynamic_script": [
            [r"eval\s*\(", "eval 执行"],
            [r"new\s+Function\s*\(", "Function 构造执行"],
            [r"setTimeout\s*\(\s*[\"']", "setTimeout 字符串执行"],
            [r"setInterval\s*\(\s*[\"']", "setInterval 字符串执行"],
            [r"document\.write\s*\(", "document.write 写入"],
            [r"\.innerHTML\s*=", "innerHTML 赋值"],
            [r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML 写入"],
        ],
        "browser_storage": [
            [r"localStorage\.setItem\s*\(", "localStorage 写入"],
            [r"sessionStorage\.setItem\s*\(", "sessionStorage 写入"],
            [r"document\.cookie\s*=", "document.cookie 写入"],
            [r"indexedDB\.open\s*\(", "IndexedDB 使用"],
        ],
        "mixed_content": [
            [r"""<form[^>]+action\s*=\s*["']http://""", "表单提交到明文 HTTP"],
            [r"""<script[^>]+src\s*=\s*["']http://""", "脚本经明文 HTTP 加载"],
            [r"""<link[^>]+href\s*=\s*["']http://""", "样式经明文 HTTP 加载"],
            [r"""<img[^>]+src\s*=\s*["']http://""", "图片经明文 HTTP 加载"],
        ],
        "source_map": [
            [r"//#\s*sourceMappingURL=", "Source Map 引用"],
            [r"\.map\b", "Source Map 文件引用"],
        ],
        # 「短信 / 邮件发送面」这类**清单式**发现（识别到 N 处相关接口与参数）
        # 只能用规则重扫来复现：当初是靠这些模式匹配出来的，复现就得重跑同一套模式。
        "sms_mail": [
            [r"""(?i)(?:send|get|req(?:uest)?)[_\-]?(?:sms|mail|email|code|msg)""",
             "短信 / 邮件 / 验证码发送接口"],
            [r"""(?i)(?:sms|smscode|sendcode|send_?msg|sendmail|send_?email)""",
             "短信 / 邮件发送标识"],
            [r"""(?i)(?:发送短信|发送邮件|获取验证码|短信验证码)""",
             "短信 / 邮件发送文案"],
        ],
    }


# 类别判定：(关键词, 类别)。顺序即优先级 —— 越具体的判断放越前。
_RULE_CATEGORY_ORDER: list[tuple[str, str]] = [
    ("短信", "sms_mail"),
    ("邮件", "sms_mail"),
    ("轰炸", "sms_mail"),
    ("dom", "dom_xss"),
    ("浏览器存储", "browser_storage"),
    ("localstorage", "browser_storage"),
    ("动态脚本", "dynamic_script"),
    ("敏感数据", "pii"),
    ("个人信息", "pii"),
    ("手机号", "pii"),
    ("身份证", "pii"),
    ("明文", "mixed_content"),
    ("混合内容", "mixed_content"),
    ("凭据", "credentials"),
    ("凭证", "credentials"),
    ("密钥", "credentials"),
    ("令牌", "credentials"),
    ("secret", "credentials"),
    ("accesskey", "credentials"),
    ("内部地址", "internal"),
    ("内网", "internal"),
    ("拓扑", "internal"),
    ("弱加密", "weak_crypto"),
    ("随机数", "weak_crypto"),
    ("哈希", "weak_crypto"),
    ("堆栈", "stack_trace"),
    ("异常信息", "stack_trace"),
    ("错误信息", "stack_trace"),
    ("source map", "source_map"),
    ("sourcemap", "source_map"),
    ("源码", "source_map"),
]


def _pick_rule_category(f: Any) -> str:
    """判断该发现属于哪一类内容特征，用于选规则集。"""
    blob = _head_blob(f)
    for kw, cat in _RULE_CATEGORY_ORDER:
        if kw in blob:
            return cat
    return ""


def _fill_plan(kind: str, f: Any, target_url: str) -> ReproPlan:
    """按模板类型补齐该模板需要的复现要素。"""
    path = _endpoint_path(f, target_url)
    markers = _extract_markers(f)
    domain = _domain_of(f, target_url)
    detail = _detail_text(f)

    plan = ReproPlan(kind=kind, probe_path=path, markers=markers,
                     method=(f.method or "GET").upper(), param=f.param or "")

    if kind == "content_marker":
        # 特征可能出现在根页面，也可能在某个前端产物里 —— 列出全部候选地址
        plan.extra["candidates"] = _content_candidates(f, path)
        # 内嵌检测规则，让复现脚本独立重跑一次检测（而非比对结论摘要）
        cat = _pick_rule_category(f)
        rs = _rule_sets()
        plan.extra["rules"] = {cat: rs[cat]} if cat and cat in rs else {}
        plan.extra["rule_category"] = cat

    elif kind == "path_reach":
        fm = _find_file_markers(path)
        if fm:
            plan.markers = list(dict.fromkeys(fm + markers))
        if not plan.markers:
            plan.markers = ["=", "key", "name"]

    elif kind == "dir_listing":
        plan.expect_status = 200

    elif kind == "header_state":
        name, mode, want = _pick_header(f)
        plan.extra.update({"header": name, "mode": mode, "value": want})

    elif kind == "cors_reflect":
        plan.extra["origin"] = "https://aiscan-cors-probe.invalid"

    elif kind == "weak_login":
        # 默认 / 弱口令：复现 = 重放同一份受控字典（见 t_weak_login）。
        # 这里只需保证探针地址落在「登录入口」上 —— path 已由 endpoint 得出；
        # 若检测器显式声明了入口地址（extra.repro），上面优先分支已处理。
        plan.method = "POST"

    elif kind == "param_replay":
        payload = _pick_selector(detail, f) or "aiscan9f3c1d'\"<>(){}"
        plan.payload = payload
        # 基线特征：取当时命中的特征，用于判断「基线是否本来就有」        plan.extra["baseline_markers"] = []

    elif kind == "anon_access":
        pass    # markers 即业务数据特征

    elif kind == "port_open":
        ep = (f.endpoint or "").strip()
        host = re.sub(r"^https?://", "", ep).split("/")[0].split(":")[0].strip()
        ports = _ports_of(f)
        plan.extra.update({
            "host": host or domain,
            "ports": ports,
            "port": ports[0] if ports else 0,
            # 只取像真 banner 的那一行；把技术细节的说明文字当 banner 匹配，
            # 会让每个端口类发现都判「banner 不匹配 → 未复现」。
            "banner": _pick_banner(f),
        })

    elif kind == "ct_subdomains":
        # 本发现的主张是「这些子域能从公开 CT 日志枚举到」。复现脚本要重新
        # 查一次 crt.sh 并核对清单，而不是请求 crt.sh 首页 —— 所以目标域名
        # 单独传，不能靠 --target（那会让脚本去请求一个非目标主机的地址）。
        plan.extra["domain"] = re.sub(r":\d+$", "", domain or "")
        plan.extra["subdomains"] = _claimed_subdomains(f, plan.extra["domain"])

    elif kind == "method_accept":
        plan.method = (f.method or "").upper() or "OPTIONS"

    elif kind == "tls_state":
        plan.extra["protocol"] = _pick_tls_protocol(f)

    elif kind == "component_version":
        plan.extra.update({"component": (f.title or "")[:60],
                           "version": _pick_version(f)})
        if plan.extra["version"] and plan.extra["version"] not in plan.markers:
            plan.markers.append(plan.extra["version"])

    elif kind == "dns_record":
        if "spf" in _head_blob(f):
            plan.extra.update({"domain": domain, "record_name": domain,
                               "rtype": "TXT", "mode": "missing", "value": "v=spf1"})
        elif "dmarc" in _head_blob(f):
            plan.extra.update({"domain": domain, "record_name": f"_dmarc.{domain}",
                               "rtype": "TXT", "mode": "value", "value": "v=DMARC1"})
        else:
            plan.extra.update({"domain": domain, "record_name": domain,
                               "rtype": "TXT", "mode": "missing", "value": ""})

    elif kind == "rate_limit":
        plan.extra["burst"] = 10

    elif kind == "plain_channel":
        # 「页面里引用了明文地址」与「站点本身提供明文入口」是两回事：
        # 前者要用规则重扫页面内容，后者要用协议降级验证。
        # 判据一旦错位，复现就会对真实问题给出错误的否定结论。
        #
        # 只认「资源引用 / 表单提交」这类页面内特征的说法，例如
        # 「表单提交到明文 HTTP 地址」「脚本经明文 HTTP 加载」；
        # 而「登录凭据经明文 http 传输」「站点提供明文入口」属于通道问题，
        # 走 plain_channel 本体。
        if re.search(r"(混合内容|引用|资源|表单|加载|action)", f.title or ""):
            plan.extra["candidates"] = _content_candidates(f, path)
            cat = "mixed_content"
            rs = _rule_sets()
            plan.kind = "content_marker"
            plan.extra["rules"] = {cat: rs[cat]} if cat in rs else {}
            plan.extra["rule_category"] = cat

    return plan


def build_plan(f: Any, target_url: str) -> ReproPlan:
    """从一条发现推断复现要素。

    优先级：
      1. 检测器显式声明（extra.repro）—— 检测器最清楚自己看到了什么
      2. 检查项级映射表（kind_map）—— 确定性事实，不受措辞影响
      3. 自然语言推断 —— 仅作兜底，且只读标题类字段
    """
    explicit = (f.extra or {}).get("repro")
    if isinstance(explicit, dict) and explicit.get("kind"):
        return ReproPlan(
            kind=explicit["kind"],
            probe_path=explicit.get("path") or _endpoint_path(f, target_url),
            method=(explicit.get("method") or f.method or "GET").upper(),
            param=explicit.get("param") or f.param or "",
            payload=explicit.get("payload", ""),
            markers=explicit.get("markers") or _extract_markers(f),
            control_path=explicit.get("control", ""),
            expect_status=int(explicit.get("status", 200) or 200),
            sample=explicit.get("sample", ""),
            extra=explicit.get("extra", {}) or {},
        )

    kind = _kind_for(f.item_id) or _infer_kind(f)

    # 「缺失式」发现降级：标题说「没发现某功能」时，用重放访问去复现是语义错配 ——
    # 例如「未发现任何登出入口」用匿名访问去验，必然命中登录页并误判为未复现。
    if kind in _DYNAMIC_KINDS and (f.title or "").lstrip().startswith(_MISSING_HINTS):
        kind = "weak_probe"

    plan = _fill_plan(kind, f, target_url)

    # 越权类发现若带多账号上下文，改用「跨身份比对」复现。
    #
    # 判据是**实测事实**：`extra["accounts"]` 里真的有 ≥2 个账号参与了比对。
    # 不去解析自然语言描述里有没有「两个账号」字样 —— 那是猜，而猜错的代价
    # 是给一条匿名就能复现的发现套上一个必然失败的会话要求（操作者白填一遍
    # 凭据，还以为是目标变了），或者反过来把真正的越权发现送去匿名复现。
    #
    # 为什么必须换模板：匿名请求打越权接口，拿回来的必然是登录页 / 401，
    # 脚本会打印「未复现」—— 而准确含义是「本次没有验证到」。
    if plan.kind == "anon_access" and len(roles_of(f)) >= MAX_ROLES:
        roles = roles_of(f)[:MAX_ROLES]
        plan.kind = "cross_role"
        plan.extra["roles"] = roles
        plan.extra["primary_role"] = roles[0]
        plan.extra["control_role"] = roles[1]

    return plan


