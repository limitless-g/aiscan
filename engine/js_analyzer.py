# -*- coding: utf-8 -*-
"""
JS 前端资产分析
===============
职责：从目标页面引用的 JavaScript 产物中提取三类信息，产出 Finding：

  1. 组件与版本  → 比对已知漏洞（EXT-SC-01）
  2. 敏感信息    → 硬编码密钥、内网地址、注释残留（EXT-DP / WSTG-CONF-04）
  3. Source Map  → 源码与依赖树泄露（EXT-SC-07）

设计要点：
  - 不执行任何 JS。只做静态文本提取，避免触发页面逻辑。
  - 版本号必须来自可信位置（打包 banner / 已知全局变量赋值 / 文件名），
    不从任意字符串里猜 —— 误报比漏报更伤报告可信度。
  - 提取到的敏感内容一律脱敏后才进入 Finding。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Evidence, Finding  # noqa: E402
from verify.mask import Masker  # noqa: E402

# ==============================================================================
# 组件版本特征库
# ==============================================================================
# 每条：组件名 -> [(版本提取正则, 匹配说明)]
# 正则必须锚定在组件特有的标识上，避免撞到普通字符串。
COMPONENT_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "jquery": [
        (r"jQuery\s+v?([\d]+\.[\d]+\.[\d]+)", "jQuery 版本声明"),
        (r'jquery[/-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js', "jQuery 文件名版本"),
    ],
    "react": [
        (r'react(?:\.production\.min)?\.js[^"\']*?["\']?\s*', "React 引用"),
        (r'React\s+v?([\d]+\.[\d]+\.[\d]+)', "React 版本声明"),
    ],
    "vue": [
        (r"Vue\.js\s+v?([\d]+\.[\d]+\.[\d]+)", "Vue 版本声明"),
        (r'vue[@/-]([\d]+\.[\d]+\.[\d]+)', "Vue 文件名版本"),
    ],
    "angular": [
        (r'angular[@/-]([\d]+\.[\d]+\.[\d]+)', "Angular 文件名版本"),
        (r"@angular/core@([\d]+\.[\d]+\.[\d]+)", "Angular 包版本"),
    ],
    "bootstrap": [
        (r'Bootstrap\s+v?([\d]+\.[\d]+\.[\d]+)', "Bootstrap 版本声明"),
        (r'bootstrap[@/-]([\d]+\.[\d]+\.[\d]+)', "Bootstrap 文件名版本"),
    ],
    "lodash": [
        (r'lodash[@/-]([\d]+\.[\d]+\.[\d]+)', "Lodash 文件名版本"),
        (r"lodash\s+v?([\d]+\.[\d]+\.[\d]+)", "Lodash 版本声明"),
    ],
    "axios": [
        (r'axios[@/-]([\d]+\.[\d]+\.[\d]+)', "Axios 文件名版本"),
        (r'axios\.VERSION\s*=\s*["\']([\d]+\.[\d]+\.[\d]+)', "Axios VERSION 赋值"),
    ],
    "moment": [(r'moment[@/-]([\d]+\.[\d]+\.[\d]+)', "Moment 文件名版本")],
    "echarts": [(r'echarts[@/-]([\d]+\.[\d]+\.[\d]+)', "ECharts 文件名版本")],
    "elementui": [(r'element-ui[@/-]([\d]+\.[\d]+\.[\d]+)', "Element UI 文件名版本")],
    "nextjs": [(r'/_next/static/([\w.-]+)/', "Next.js 构建标识")],
}

# ==============================================================================
# 敏感信息特征（静态提取，命中即脱敏后入证）
# ==============================================================================
SENSITIVE_PATTERNS: list[tuple[str, str, str, str]] = [
    # (名称, 正则, 建议等级, 说明)
    ("云厂商 AccessKey", r"\b(?:AKIA[0-9A-Z]{12,}|LTAI[0-9A-Za-z]{10,}|AKID[0-9A-Za-z]{10,})\b",
     "严重", "前端产物中硬编码云厂商访问密钥，可被任意访客提取并直接调用云 API"),
    ("私钥文件内容", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     "严重", "前端产物中嵌入私钥，等同于交出对应服务的身份"),
    ("硬编码口令", r"(?i)\b(?:password|passwd|pwd|secret|apikey|api_key|access_token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
     "高危", "前端产物中硬编码口令或密钥，逆向即可获取"),
    ("内网地址", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
     "低危", "前端产物暴露内网网段，为攻击者提供横向移动线索"),
    ("内部域名 / 环境", r"\b[\w.-]+\.(?:internal|local|corp|lan|intra)\b",
     "低危", "前端产物暴露内部域名，泄露架构信息"),
    ("调试开关", r"\bdebug\s*[:=]\s*(?:true|1)\b",
     "信息", "生产环境残留调试开关"),
    ("注释残留 TODO/FIXME 含敏感上下文",
     r"(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX)[^\n]{0,120}(?:password|token|key|auth|admin)",
     "低危", "代码注释泄露实现细节与潜在凭据线索"),
]

# Source Map 引用
SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

# 需要从页面中提取的脚本引用
SCRIPT_SRC_PATTERN = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
LINK_HREF_PATTERN = re.compile(r"""<link[^>]+href\s*=\s*["']([^"']+\.(?:js|css))["']""", re.I)


@dataclass
class ComponentHit:
    name: str
    version: str
    evidence: str
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version,
                "evidence": self.evidence, "source_file": self.source_file}


@dataclass
class JsAnalysisResult:
    target: str
    scripts_found: list[str] = field(default_factory=list)
    scripts_fetched: int = 0
    components: list[ComponentHit] = field(default_factory=list)
    sourcemaps: list[str] = field(default_factory=list)
    sensitive_hits: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # ---- 供检测器复用的原始素材 ----
    # 这三个字段是下游大量检测器的数据来源（接口发现、参数提取、
    # 敏感信息扫描、调试接口定位）。历史上它们没有暴露出来，
    # 导致依赖它们的检测器在空数据上跑完并报「通过」—— 典型的假阴性。
    urls: list[str] = field(default_factory=list)          # 脚本地址 + 产物中提取的接口地址
    bodies: list[str] = field(default_factory=list)        # 抓取到的脚本正文
    inline_scripts: list[str] = field(default_factory=list)  # 页面内联脚本正文

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scripts_found": len(self.scripts_found),
            "scripts_fetched": self.scripts_fetched,
            "components": [c.to_dict() for c in self.components],
            "sourcemaps": self.sourcemaps,
            "sensitive_hit_types": sorted({h.split("：")[0] for h in self.sensitive_hits}),
            "urls_extracted": len(self.urls),
            "bodies_bytes": sum(len(b) for b in self.bodies),
            "findings": [f.title for f in self.findings],
            "errors": self.errors,
        }


class JsAnalyzer:
    """前端产物静态分析器。"""

    def __init__(self, client: Any, max_scripts: int = 30, max_bytes: int = 3_000_000):
        self.client = client
        self.max_scripts = max_scripts
        self.max_bytes = max_bytes
        self.masker = Masker()

    # ------------------------------------------------------------------
    def analyze(self, target_url: str, page_html: str = "") -> JsAnalysisResult:
        res = JsAnalysisResult(target=target_url)

        if not page_html:
            probe = self.client.fetch(target_url)
            if not probe.reachable:
                res.errors.append(f"页面不可达：{probe.error}")
                return res
            page_html = probe.body_snippet

        scripts = self._collect_scripts(target_url, page_html)
        res.scripts_found = scripts

        blob = ""
        inline = self._extract_inline_scripts(page_html)
        # 静态产物必须走 fetch_asset（全文）：client.fetch 默认只留前 4000
        # 字符，压缩后的 SPA 主包动辄上 MB，4000 字符等于没读（缺陷 D5）。
        fetch_asset = getattr(self.client, "fetch_asset", None)
        for src in scripts[: self.max_scripts]:
            try:
                p = fetch_asset(src) if callable(fetch_asset) else self.client.fetch(src)
                if p.reachable and p.status == 200:
                    text = p.body_snippet
                    if getattr(p, "body_truncated", False):
                        res.errors.append(
                            f"{src}: 正文超过保留上限被截断"
                            "（截断点之后的内容未参与分析）")
                    if len(text) >= self.max_bytes:
                        text = text[: self.max_bytes]
                    blob += "\n" + text
                    res.bodies.append(text)
                    res.scripts_fetched += 1
                    self._scan_sourcemap(src, text, res)
            except Exception as e:  # noqa: BLE001
                res.errors.append(f"{src}: {type(e).__name__}")

        # 行内脚本也要扫（很多配置直接写在 index.html 里）
        blob += "\n" + inline
        if inline.strip():
            res.inline_scripts.append(inline)

        # 接口地址提取：下游检测器（接口发现、参数提取、越权面识别）都靠它
        res.urls = self._extract_endpoints(blob, target_url, res.scripts_found)

        res.components = self._extract_components(blob)
        res.sensitive_hits = self._scan_sensitive(blob, target_url)

        res.findings = self._build_findings(target_url, res)
        return res

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_endpoints(blob: str, base: str, scripts: list[str],
                           max_n: int = 400) -> list[str]:
        """从脚本正文里提取接口地址。

        只做静态提取，不构造请求。提取范围：
          · 脚本自身的地址（保证至少有一批可分析的入口）
          · 产物中出现的绝对 URL（同域才保留，跨域属于第三方范围）
          · 产物中出现的以 / 开头的相对路径（接口地址的主要形态）

        模板字符串里的 ${...} 会被替换成占位值，这样带参数的接口
        仍然能被 parse_qs 解析出来，供参数提取使用。
        """
        out: list[str] = []
        seen: set[str] = set()

        def push(u: str) -> None:
            u = u.strip()
            if not u or len(u) > 300 or u in seen:
                return
            if any(c in u for c in (" ", "\n", "\t", "\\", "<", ">", "(", ")")):
                return
            if u.startswith(("javascript:", "data:", "mailto:", "#")):
                return
            seen.add(u)
            out.append(u)

        for s in scripts:
            push(s)

        base_host = ""
        try:
            base_host = urlparse(base).hostname or ""
        except Exception:  # noqa: BLE001
            pass

        # 绝对地址：只保留同域（第三方地址不请求，但记录仍有助于识别外链）
        for m in re.finditer(r"[\"'](https?://[^\"'\s]+)[\"']", blob):
            u = m.group(1)
            if base_host and base_host not in u:
                continue
            push(u)
            if len(out) >= max_n:
                break

        # 相对路径。字符类必须包含 ? & = # —— 否则带查询串的接口地址
        # （/api/user?uid=1 这种最常见的形态）会被整条漏掉，
        # 下游的参数提取拿不到参数，注入类检测器就会空转。
        for m in re.finditer(r"[\"'`]((?:/)[A-Za-z0-9_\-./{}:$~%?&=#+]{1,240})[\"'`]", blob):
            push(re.sub(r"\$\{[^}]*\}", "1", m.group(1)))
            if len(out) >= max_n:
                break

        # 模板字符串里拼接的路径（/api/user/${id}）单独再抓一遍
        for m in re.finditer(r"[\"'`]((?:/)(?:[A-Za-z0-9_\-.]|\$\{[^}]*\}){1,240})[\"'`]"
                             r"(?:\s*\+|\s*`)", blob):
            push(re.sub(r"\$\{[^}]*\}", "1", m.group(1)))
            if len(out) >= max_n:
                break

        # 「变量前缀 + 路径」的模板字符串（`${host}/rest/products/search?q=${e}`）
        # —— 现代前端最常见的写法。上面三条都要求字符串**以 / 开头**，
        # 这种以 ${...} 开头的会整条静默丢失，注入类检测器的候选参数
        # 凭空少一大半（2026-10-09 Juice Shop 基准三轮实测：
        # /rest/products/search?q= 就是这么丢的，3 条 SQLi 挑战全灭）。
        for m in re.finditer(r"[\"'`]\$\{[^}]*\}((?:/)[A-Za-z0-9_\-./{}:$~%?&=#+]{1,240})[\"'`]",
                             blob):
            push(re.sub(r"\$\{[^}]*\}", "1", m.group(1)))
            if len(out) >= max_n:
                break

        return out[:max_n]

    # ------------------------------------------------------------------
    def _collect_scripts(self, base: str, html: str) -> list[str]:
        urls: list[str] = []
        for m in SCRIPT_SRC_PATTERN.finditer(html):
            urls.append(urljoin(base, m.group(1)))
        for m in LINK_HREF_PATTERN.finditer(html):
            u = m.group(1)
            if u.endswith(".js"):
                urls.append(urljoin(base, u))
        # 去重保序，并排除纯第三方 CDN（不在授权范围内，不主动请求）
        seen, out = set(), []
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            if self._is_third_party(base, u):
                continue
            out.append(u)
        return out

    @staticmethod
    def _is_third_party(base: str, url: str) -> bool:
        """判断脚本是否来自第三方域（第三方不属于授权范围，不主动请求）。"""
        try:
            bh = urlparse(base).hostname or ""
            uh = urlparse(url).hostname or ""
        except Exception:  # noqa: BLE001
            return False
        if not uh:
            return False
        # 取主域比较（简化：末两段）
        def root(h: str) -> str:
            parts = h.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else h
        return root(bh) != root(uh)

    @staticmethod
    def _extract_inline_scripts(html: str) -> str:
        out = []
        for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.I | re.S):
            out.append(m.group(1))
        return "\n".join(out)

    # ------------------------------------------------------------------
    def _extract_components(self, blob: str) -> list[ComponentHit]:
        hits: list[ComponentHit] = []
        for name, patterns in COMPONENT_SIGNATURES.items():
            for pat, why in patterns:
                m = re.search(pat, blob, re.I)
                if not m:
                    continue
                groups = [g for g in m.groups() if g]
                version = groups[0] if groups else ""
                if not version or not re.match(r"^[\d]+\.[\d]", version):
                    # 没拿到可信版本号时不产出组件条目，避免误报
                    continue
                hits.append(ComponentHit(name=name, version=version, evidence=why))
                break
        return hits

    def _scan_sensitive(self, blob: str, target_url: str) -> list[str]:
        hits: list[str] = []
        for name, pattern, sev, _why in SENSITIVE_PATTERNS:
            for m in re.finditer(pattern, blob):
                snippet = m.group(0)
                masked = self.masker.mask(snippet)
                # 同类型去重，避免重复记录几十条相同片段
                tag = f"{name}：{masked[:80]}"
                if tag not in hits:
                    hits.append(tag)
        return hits

    def _scan_sourcemap(self, script_url: str, content: str, res: JsAnalysisResult) -> None:
        m = SOURCEMAP_PATTERN.search(content[-2000:])
        if not m:
            return
        sm_url = urljoin(script_url, m.group(1))
        probe = None
        try:
            probe = self.client.fetch(sm_url)
        except Exception:  # noqa: BLE001
            return
        if probe.reachable and probe.status == 200 and len(probe.body_snippet.strip()) > 50:
            res.sourcemaps.append(sm_url)

    # ------------------------------------------------------------------
    def _build_findings(self, target_url: str, res: JsAnalysisResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1) 组件版本（不直接定高危 —— 版本命中 ≠ 可利用，需后续验证危害）
        if res.components:
            rows = "\n".join(
                f"  - {c.name} {c.version}（{c.evidence}）" for c in res.components
            )
            findings.append(Finding(
                item_id="EXT-SC-01",
                title=f"前端组件版本可提取（{len(res.components)} 个组件）",
                target=target_url,
                endpoint=target_url,
                severity="低危",
                confidence="High",
                evidence_level="A",
                grading_basis=(
                    "版本号系从打包产物中静态提取，证据确凿；"
                    "但「版本命中 CVE」不等于「可被利用」，须逐组件确认可达性后才能升级定级"
                ),
                description=(
                    "站点前端产物中可以直接读出所用第三方组件的名称与精确版本。"
                    "这本身不是漏洞，但等于替攻击者完成了信息收集：他们可以跳过指纹探测，"
                    "直接去查这些版本对应的已知漏洞。"
                ),
                technical_detail="提取到的组件：\n" + rows,
                impact=(
                    "不直接造成数据泄露。风险在于：若其中任一组件存在可远程触发的已知漏洞，"
                    "攻击者拿到版本后可直接定位利用方式，大幅降低攻击成本。"
                ),
                reproduction=(
                    f"1. 访问 {target_url}\n"
                    "2. 从页面中提取 <script src> 引用的 JS 文件\n"
                    "3. 在产物文本中检索组件版本特征字符串"
                ),
                remediation=(
                    "1. 用构建工具（webpack/vite）压缩并抹除 banner 与版本常量\n"
                    "2. 升级存在已知漏洞的组件到修复版本\n"
                    "3. 建立前端依赖台账，定期跑 npm audit / OWASP Dependency-Check"
                ),
                compliance="ISO 27001 A.8.8 / 等保2.0 入侵防范",
                evidence=[Evidence(kind="file", content=rows, note="组件提取结果", masked=True,
                                   raw_hash=Masker.fingerprint(rows))],
                source_tool="js_analyzer",
            ))

        # 2) Source Map 泄露
        if res.sourcemaps:
            rows = "\n".join(f"  - {u}" for u in res.sourcemaps[:10])
            findings.append(Finding(
                item_id="EXT-SC-07",
                title=f"Source Map 文件公开可访问（{len(res.sourcemaps)} 个）",
                target=target_url,
                severity="中危",
                confidence="High",
                evidence_level="A",
                grading_basis="实测 sourceMappingURL 可访问且返回有效 map 内容，非伪 200",
                description=(
                    "前端打包生成的 Source Map 仍可公开下载。它包含原始源码、注释、"
                    "以及完整的依赖清单。攻击者据此可直接阅读未压缩的源代码，"
                    "找出前端逻辑缺陷、隐藏接口与内部注释。"
                ),
                technical_detail="可访问的 Source Map：\n" + rows,
                impact=(
                    "泄露源代码结构与全部依赖（含精确版本），为后续漏洞挖掘提供完整地图；"
                    "若源码注释中含内部接口或调试信息，风险进一步提升。"
                ),
                reproduction=f"1. 访问 {target_url}\n2. 提取 JS 文件末尾的 sourceMappingURL\n3. 直接访问该 .map 地址",
                remediation=(
                    "1. 生产构建关闭 sourcemap（vue-cli: productionSourceMap=false；vite: build.sourcemap=false）\n"
                    "2. 若需保留用于排障，须仅上传到内部监控平台，并从产物中移除引用\n"
                    "3. 在 Web 服务器拦截 *.map 的公网访问"
                ),
                compliance="ISO 27001 A.8.8 / 等保2.0 剩余信息保护",
                evidence=[Evidence(kind="file", content=rows, note="可访问的 map 地址", masked=True,
                                   raw_hash=Masker.fingerprint(rows))],
                source_tool="js_analyzer",
            ))

        # 3) 敏感信息
        if res.sensitive_hits:
            # 按类型取最严重等级
            order = {"严重": 4, "高危": 3, "中危": 2, "低危": 1, "信息": 0}
            sev = "低危"
            for hit in res.sensitive_hits:
                name = hit.split("：")[0]
                for n, _p, s, _w in SENSITIVE_PATTERNS:
                    if n == name and order.get(s, 0) > order.get(sev, 0):
                        sev = s
                        break
            rows = "\n".join(f"  - {h}" for h in res.sensitive_hits[:20])
            findings.append(Finding(
                item_id="EXT-DP-01",
                title=f"前端产物中存在敏感信息（{len(res.sensitive_hits)} 处）",
                target=target_url,
                severity=sev,
                confidence="High",
                evidence_level="A",
                grading_basis=(
                    f"实测从产物文本中提取到敏感片段，最高等级类型为 {sev}；"
                    "内容已在证据中脱敏，仅保留类型与前缀"
                ),
                description=(
                    "前端 JavaScript 产物中残留了本不该出现在客户端的敏感信息。"
                    "由于前端资源对任何访客都是公开的，这些内容等同于直接公布。"
                ),
                technical_detail="命中类型与脱敏片段：\n" + rows,
                impact=(
                    "取决于命中类型：若是云访问密钥（严重），持有者可直接调用云 API 读写数据；"
                    "若是内网地址（低危），则为横向移动提供线索。"
                ),
                reproduction=(
                    f"1. 下载 {target_url} 引用的 JS 产物\n"
                    "2. 用文本检索匹配密钥 / 地址 / 口令特征\n"
                    "3. 命中内容即为本发现"
                ),
                remediation=(
                    "1. 立即轮换所有已暴露的密钥（前端暴露过的密钥必须视为已泄露）\n"
                    "2. 移除前端硬编码，改由后端签发短期凭据\n"
                    "3. 生产构建接入密钥扫描（gitleaks / trufflehog）作为发布卡点"
                ),
                compliance="等保2.0 剩余信息保护 / PIPL 第 51 条 / ISO 27001 A.8.24",
                evidence=[Evidence(kind="file", content=rows, note="脱敏后的命中片段", masked=True,
                                   raw_hash=Masker.fingerprint(rows))],
                source_tool="js_analyzer",
            ))

        return findings


if __name__ == "__main__":
    from engine.fingerprint import Fingerprinter

    print("=" * 70)
    print("JS 分析器自测")
    print("=" * 70)

    # ---- 离线自测：用合成样本验证提取逻辑（不发网络请求）----
    print("\n[离线自测] 合成样本提取逻辑验证")
    ja = JsAnalyzer(client=None)
    sample_html = """
    <html><head>
      <script src="/static/js/jquery-3.4.1.min.js"></script>
      <script src="/assets/app.bundle.js"></script>
      <script src="https://cdn.example-thirdparty.com/lib/analytics.js"></script>
      <script>
        window.__CONFIG__ = { apiBase: "https://10.20.30.40/api", debug: true };
        var _token = "placeholder-token-value-for-test";
      </script>
    </head></html>
    """
    sample_js = """
    /*! jQuery v3.6.0 | (c) OpenJS Foundation */
    axios.VERSION = "1.6.2";
    Vue.js v3.2.47 initialized
    lodash@4.17.19
    //# sourceMappingURL=app.bundle.js.map
    // TODO: remove before release - admin bypass password check
    """
    blob = sample_js + "\n" + JsAnalyzer._extract_inline_scripts(sample_html)

    comps = ja._extract_components(blob)
    print(f"\n  组件提取（{len(comps)} 个）：")
    for c in comps:
        print(f"    - {c.name:<12} {c.version:<10} ({c.evidence})")

    sens = ja._scan_sensitive(blob, "https://t.example")
    print(f"\n  敏感信息提取（{len(sens)} 处）：")
    for s in sens:
        print(f"    - {s}")

    scripts = ja._collect_scripts("https://app.example.com/index.html", sample_html)
    print(f"\n  脚本收集（{len(scripts)} 个，已排除第三方域）：")
    for s in scripts:
        print(f"    - {s}")

    sm = SOURCEMAP_PATTERN.search(sample_js[-2000:])
    print(f"\n  Source Map 引用识别：{'命中 → ' + sm.group(1) if sm else '未命中'}")

    assert len(comps) >= 3, f"组件提取数量异常：{len(comps)}"
    assert any("云厂商" in s or "口令" in s or "调试" in s for s in sens), "敏感信息提取异常"
    assert not any("thirdparty" in s for s in scripts), "第三方域未被正确排除"
    assert sm, "Source Map 未识别"
    print("\n  ✓ 离线自测全部通过")

    # ---- 在线链路自测 ----
    print("\n[在线自测] 真实目标探测链路")
    fp = Fingerprinter({"rate": {"requests_per_second": 5, "timeout_seconds": 10}})
    r = JsAnalyzer(fp.client).analyze("https://example.com")
    print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
