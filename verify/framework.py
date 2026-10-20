# -*- coding: utf-8 -*-
"""
L3 验证框架 —— verify_xxx.py 生成器
===================================
职责：为每一条漏洞发现生成一份**可独立执行**的验证脚本。

设计要求（来自规格第 6 章硬性要求）：
  - 脚本脱离本工程也能跑（只依赖 requests，标准库优先）
  - 必须含：断言、预期结果、实测结果、复现步骤
  - 输出必须脱敏（脚本内部自带脱敏函数，不依赖外部模块）
  - 退出码统一：0=漏洞确认存在 / 1=未复现 / 2=执行错误
    → 便于批量执行与接入 CI
  - 脚本只做只读验证，绝不包含写操作（受控写另走 write 子命令且需显式开启）

生成的脚本结构统一，便于人工复核与归档。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Finding  # noqa: E402

try:
    from verify.repro_templates import (  # noqa: E402
        STRENGTH_LABEL, build_plan, render_script,
    )
except ImportError:  # noqa: BLE001
    from repro_templates import (  # type: ignore  # noqa: E402
        STRENGTH_LABEL, build_plan, render_script,
    )

# ==============================================================================
# 所有生成脚本共用的头部（自带脱敏，不依赖本工程）
# ==============================================================================
SCRIPT_HEADER = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
{title}
------------------------------------------------------------------------
检查项      : {item_id}
目标        : {target}
受影响端点  : {endpoint}
定级        : {severity}（证据级别 {evidence_level}）
生成时间    : {generated_at}
生成工具    : aiscan L3 验证框架

用途
    独立复现该漏洞，供修复方自查与回归验证。
    本脚本只做只读检测，不含任何写操作。

用法
    python {filename}
    python {filename} --target https://替换为目标地址

退出码
    0 = 漏洞确认存在（复现成功）
    1 = 未复现（可能已修复，或环境有差异）
    2 = 执行错误（网络不可达、参数错误等）

预期结果
{expected}

实测结果
    运行后由脚本输出，并与预期结果逐项比对。
"""

import argparse
import os
import re
import sys

# ---------------------------------------------------------------------------
# 禁止复现脚本走环境里配置的代理。
#
# requests 默认 trust_env=True，会读取 HTTP_PROXY / HTTPS_PROXY。一旦运行机器上
# 存在代理（企业上网代理、抓包工具、CI 沙箱），复现请求就会经过它，两个后果：
#   · 代理可改写响应 → 复现结果不再代表目标真实状态；
#   · 代理转发常使用绝对形式请求行（GET http://host/path），部分服务端直接 404，
#     表现为「全都复现不出来」，会把真实问题误判成已修复。
# 设置 NO_PROXY=* 让 urllib / requests 主动绕过代理；如需保留代理行为，
# 运行前设置 AISCAN_ALLOW_PROXY=1。
# ---------------------------------------------------------------------------
if not os.environ.get("AISCAN_ALLOW_PROXY"):
    for _k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
               "ALL_PROXY", "all_proxy"):
        os.environ.pop(_k, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[错误] 缺少依赖 requests，请执行：pip install requests")
    sys.exit(2)

SCAN_UA = "AIScan/1.0 (Authorized Security Assessment)"
DEFAULT_HEADERS = {{"User-Agent": SCAN_UA, "Accept": "*/*"}}

# 与本工程一致的脱敏规则（脚本自带，保证独立运行）
_MASK_RULES = [
    (re.compile(r"\\beyJ[A-Za-z0-9_-]{{6,}}\\.[A-Za-z0-9_-]{{6,}}\\.[A-Za-z0-9_-]{{6,}}"), lambda m: m.group(0)[:8] + "***"),
    (re.compile(r"(?i)\\b(api[_-]?key|secret|access[_-]?key(?:[_-]?(?:id|secret))?|password|token)\\s*[:=]\\s*[\\"']?([A-Za-z0-9_\\-+/=.]{{6,}})"), lambda m: m.group(1) + "=" + m.group(2)[:4] + "***"),
    (re.compile(r"(?<!\\d)1[3-9]\\d{{9}}(?!\\d)"), lambda m: m.group(0)[:3] + "****" + m.group(0)[-4:]),
    (re.compile(r"\\b[1-9]\\d{{5}}(?:19|20)\\d{{2}}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{{3}}[\\dXx]\\b"), lambda m: m.group(0)[:6] + "********" + m.group(0)[-4:]),
    (re.compile(r"\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{{2,}}\\b"), lambda m: m.group(0)[:2] + "***@" + m.group(0).split("@")[1]),
]


def mask(text):
    """脱敏：凭据与 PII 一律不落盘、不出现在输出中。"""
    if not text:
        return text
    out = str(text)
    for pattern, repl in _MASK_RULES:
        out = pattern.sub(repl, out)
    return out


def show(label, value, limit=800):
    print(f"  {{label}}: {{mask(str(value))[:limit]}}")


def result(ok, message):
    """统一结果输出与退出码。"""
    if ok:
        print(f"\\n[复现成功] {{message}}")
        print("  结论：该漏洞在当前目标上真实存在。")
        return 0
    print(f"\\n[未复现] {{message}}")
    print("  结论：本次检测未复现该漏洞。可能已修复，也可能环境存在差异，建议人工确认。")
    return 1

'''

SCRIPT_FOOTER = '''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="{title}")
    parser.add_argument("--target", default="{target_url}", help="目标地址（默认使用扫描时的地址）")
    parser.add_argument("--timeout", type=int, default={timeout}, help="请求超时秒数")
    args = parser.parse_args()
    sys.exit(main(args.target.rstrip("/"), args.timeout))
'''


# ==============================================================================
# 各漏洞类型的验证逻辑
# ==============================================================================
class StorageHost:
    """判断一个主机是不是「由目标域名派生出来的云存储桶」。

    为什么需要单独判断：桶名是检测器按目标一级标签推出来的
    （`internal-app.example.com` → `内部生产系统-files`、`内部生产系统-static`……），
    所以它**不是站点的子域**，用「同主机 / 子域」判据必然漏掉它，
    复现脚本就会回落去打网站首页、把真实暴露判成「未复现」。

    为什么只对已知后缀放行：只用「首标签相同」会放进 `内部生产系统.evil.com`
    这种第三方主机。加上云存储域名后缀这一条，误放的范围就被收敛到
    「目标一级标签 + 已知云存储服务」这个很窄的形态上。

    注意这**不会扩大扫描范围**：这些地址本来就已经被检测器探测过
    （发现就是探测结果），这里只是让复现脚本去打同一个地址，
    而不是换成另一个地址去打。真正的第三方情报源（crt.sh 等）
    仍然走「回落扫描目标根」这条老路。
    """

    SUFFIXES = (
        ".oss-cn-hangzhou.aliyuncs.com", ".oss-cn-beijing.aliyuncs.com",
        ".oss-cn-shanghai.aliyuncs.com", ".oss-cn-shenzhen.aliyuncs.com",
        ".oss-cn-guangzhou.aliyuncs.com", ".oss-cn-qingdao.aliyuncs.com",
        ".oss-cn-zhangjiakou.aliyuncs.com", ".oss-cn-hongkong.aliyuncs.com",
        ".oss-accelerate.aliyuncs.com", ".aliyuncs.com",
        ".cos.ap-guangzhou.myqcloud.com", ".cos.ap-shanghai.myqcloud.com",
        ".cos.ap-beijing.myqcloud.com", ".myqcloud.com",
        ".s3.amazonaws.com", ".s3.us-east-1.amazonaws.com",
        ".s3.us-west-2.amazonaws.com", ".amazonaws.com",
        ".bcebos.com", ".jdcloud-oss.com", ".bkt.clouddn.com", ".clouddn.com",
    )

    @classmethod
    def is_derived(cls, host: str, label: str) -> bool:
        """host 是否为 `label` 派生出的云存储桶主机。"""
        h = (host or "").lower().split(":")[0]
        lb = (label or "").lower()
        if not h or not lb:
            return False
        if not any(h.endswith(sfx) for sfx in cls.SUFFIXES):
            return False
        first = h.split(".")[0]
        return first == lb or first.startswith(lb + "-") or first.startswith(lb + "_")


@dataclass
class VerifySpec:
    """一份验证脚本的完整定义。"""

    filename: str
    item_id: str
    title: str
    target: str
    endpoint: str
    severity: str
    evidence_level: str
    expected: str
    target_url: str
    body: str                      # main() 函数体
    timeout: int = 15
    strength: str = ""             # strong / medium / weak —— 复现强度
    repro_kind: str = ""           # 使用的复现模板类型
    session_roles: list[str] = field(default_factory=list)   # 需要哪些身份的会话


def _docstring_safe(text: str) -> str:
    """保证一段文本放进生成脚本的文档字符串里绝对安全。

    两类会出事的字符：
      · `\\` 后面跟非转义字符（如 `\\o`、`\\d`）→ 编译告警
        （`SyntaxWarning: invalid escape sequence`）。交付物带告警很难看，
        更糟的是某些 CI 把告警当失败；
      · `'''` / `\"\"\"` → 提前闭合三引号，脚本直接语法错误。
      · 结尾单独一个 `\\` → 会把结尾三引号转义掉，同样语法错误。

    做法是把反斜杠写成双反斜杠：文档字符串里读起来仍是同一个字符
    （显示为 `\\\\`），但不再有非法转义。三引号序列替换为普通引号。
    """
    if not text:
        return ""
    s = str(text).replace("\r", "")
    s = s.replace("'''", "’").replace('"""', "”")
    s = s.replace("\\", "\\\\")
    return s.rstrip()


class ScriptBuilder:
    """把 Finding 转成可独立执行的 verify 脚本。"""

    def __init__(self, out_dir: Path | str):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        # 会话文件骨架的落盘情况（供调用方在报告 / 控制台里如实披露）
        self.session_template: Path | None = None
        self.session_template_note: str = ""

    # ------------------------------------------------------------------
    def generate(self, finding: Finding, target_url: str) -> Path:
        spec = self._build_spec(finding, target_url)
        content = self._render(spec)
        path = self.out_dir / spec.filename
        path.write_text(content, encoding="utf-8")
        if spec.session_roles:
            self._emit_session_template([spec.session_roles])
        return path

    def generate_all(self, findings: list[Finding], target_url: str) -> list[Path]:
        """为每条发现生成一份复现脚本，返回**全部**脚本路径。

        返回值是列表，不是以标题为键的字典 —— 同一检查项可能产出标题相同的
        多条发现（例如凭据外泄的两个变体、同一条规则命中的两个端点），
        用标题作键会互相覆盖：脚本文件其实都写盘了，但调用方手里的少了几个
        却毫无察觉，少掉的那条会被闸门判成「未验证」。自测里就真实发生过。
        """
        out: list[Path] = []
        used: set[str] = set()
        session_roles: list[str] = []
        for i, f in enumerate(findings, 1):
            spec = self._build_spec(f, target_url)
            # 文件名去重
            base = spec.filename
            if base in used:
                spec.filename = base.replace(".py", f"_{i}.py")
            used.add(spec.filename)
            path = self.out_dir / spec.filename
            path.write_text(self._render(spec), encoding="utf-8")
            out.append(path)
            f.verify_script = str(path.relative_to(ROOT)) if ROOT in path.parents else str(path)
            for r in spec.session_roles:
                if r not in session_roles:
                    session_roles.append(r)
        if session_roles:
            self._emit_session_template([session_roles])
        return out

    def _emit_session_template(self, role_groups: list[list[str]]) -> None:
        """在脚本目录放一份会话文件骨架，供操作者填写。

        为什么由生成器落盘而不是写进脚本注释里让操作者自己建文件：
        越权类发现是**批量**出现的（一次扫描可能几十条），让操作者逐份脚本
        去建文件、抄格式，抄错一处就是一条「无法判定」。骨架先放好，
        操作者只需填空。
        """
        try:
            from verify.sessionctx import write_template  # noqa: PLC0415
        except ImportError:  # noqa: BLE001
            from sessionctx import write_template  # type: ignore  # noqa: PLC0415

        roles: list[str] = []
        for grp in role_groups:
            for r in grp:
                if r not in roles:
                    roles.append(r)
        path, note = write_template(self.out_dir, roles)
        if path is not None:
            self.session_template = path
            self.session_template_note = note

    # ------------------------------------------------------------------
    def _render(self, spec: VerifySpec) -> str:
        expected_full = (
            f"复现强度：{STRENGTH_LABEL.get(spec.strength, spec.strength or '未标注')}\n"
            f"复现方式：{spec.repro_kind or '通用'}\n"
            f"{spec.expected}"
        )
        header = SCRIPT_HEADER.format(
            title=spec.title,
            item_id=spec.item_id,
            target=spec.target,
            endpoint=spec.endpoint,
            severity=spec.severity,
            evidence_level=spec.evidence_level,
            generated_at=datetime.now().isoformat(timespec="seconds"),
            filename=spec.filename,
            # 所有插进文档字符串的内容统一过一遍安全化：
            # 交付物必须零告警编译，见 _docstring_safe 的说明。
            expected=_docstring_safe(expected_full),
        )
        footer = SCRIPT_FOOTER.format(
            title=spec.title,
            target_url=spec.target_url,
            timeout=spec.timeout,
        )
        return header + spec.body + footer

    def _build_spec(self, f: Finding, target_url: str) -> VerifySpec:
        """按「证据形态」生成复现脚本。

        旧实现按 item_id 与 source_tool 硬编码分发，只有 8 种来源享受专用逻辑，
        其余全部落到一个「请求一次看状态码」的兜底 —— 那不是复现脚本。
        现在统一走 repro_templates 的证据驱动模板族：

          1. 检查项级确定性映射（kind_map，全量检查项全登记）
          2. 检测器显式声明（Finding.extra.repro）可覆盖映射
          3. 都未命中才回落弱兜底，并在报告里如实标注为「弱复现」

        同时在 Finding.extra 回写 verify_strength / repro_kind，
        供报告渲染与准入闸门使用。
        """
        plan = build_plan(f, target_url)
        body, expected, strength = render_script(plan.kind, plan, f, target_url)

        f.extra = dict(f.extra or {})
        f.extra["verify_strength"] = strength
        f.extra["repro_kind"] = plan.kind
        f.extra["repro_expected"] = expected
        if plan.extra.get("rule_category"):
            f.extra["rule_category"] = plan.extra["rule_category"]
        if plan.markers:
            f.extra["repro_markers"] = plan.markers[:6]

        # 越权类复现需要会话上下文。这件事必须写进发现里、并进报告 ——
        # 否则报告上只有「已复现 / 未复现」两种字样，而实际上这类脚本
        # 在操作者没填会话时给出的是「无法判定」。读者看不到第三态就会误读。
        roles = [str(r) for r in (plan.extra.get("roles") or [])]
        if roles:
            f.extra["repro_needs_session"] = True
            f.extra["repro_roles"] = roles

        return VerifySpec(
            filename=f"verify_{self._slug(f)}.py",
            item_id=f.item_id,
            title=f.title,
            target=f.target or target_url,
            endpoint=f.endpoint or target_url,
            severity=f.severity,
            evidence_level=f.evidence_level,
            expected=expected,
            target_url=self._repro_base(f, target_url),
            body=body,
            strength=strength,
            repro_kind=plan.kind,
            session_roles=roles,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _repro_base(f: Finding, target_url: str) -> str:
        """复现脚本的默认目标地址：**目标根，不带路径**。

        所有复现模板统一按「base + plan.probe_path」拼探针 URL，因此这里
        绝不能把 f.endpoint 整个塞进去 —— 那会把路径拼两次
        （`/.env` → `/.env/.env`），让所有带路径的发现都「复现失败」，
        而报告上完全看不出是工具自己拼错了地址。

        范围约束（重要）：只有当端点主机**属于扫描目标**时才沿用端点 origin。
        否则一律回落到扫描目标根 —— 有些发现的 endpoint 记的是「证据来源」
        （如 crt.sh 这类第三方情报源），照搬就会让复现脚本跑去请求站外地址，
        越出授权范围。

        三种「属于目标」的判据，按优先级：

          ① **检测器显式声明** `finding.extra["repro_base"]`
             —— 最可靠的一条。检测器自己知道这个地址是怎么来的
             （例如桶名由目标域名派生：`内部生产系统` → `内部生产系统-files.oss-...`），
             不必让这里靠字符串猜。**这条是 2026-09-28 修的漏报根因**：
             当时只认「同主机 / 目标子域」，于是目标自己的 OSS 桶
             （`内部生产系统-files.oss-cn-hangzhou.aliyuncs.com`，不是站点的子域）
             被判为站外，复现脚本回落去打网站首页 —— 网站对任意路径都回同一张
             HTML，脚本据此判「自定义错误页，非真实暴露」，退出码 1。
             结果是一条**实测存在的严重暴露**被复现准入闸门挡在漏洞清单外，
             而报告上只写着「未复现，可能已修复」。这类静默漏报比误报更坏：
             误报有人来质疑，漏报要靠人自己再去翻一遍桶才会发现。
          ② **同主机或目标的子域**（原有的严格判据，保持不变）
          ③ 目标域名派生出的云存储主机 —— 形如 `<目标一级标签>-<后缀>.oss-*.aliyuncs.com`。
             桶名是检测器按目标域名推出来的，属目标自有资产；
             但**只对已知云存储域名后缀放行**，避免 `内部生产系统.evil.com`
             这种「前缀像」的第三方主机被误当目标。
        """
        ep = (f.endpoint or "").strip()
        tgt = (target_url or "").strip().rstrip("/")

        # ① 检测器显式声明（必须自带 scheme，防止相对路径混进来）
        declared = str((f.extra or {}).get("repro_base") or "").strip()
        if declared.startswith("http://") or declared.startswith("https://"):
            return declared.rstrip("/")

        tgt_host = ""
        tm = re.match(r"^https?://([^/]+)", tgt)
        if tm:
            tgt_host = tm.group(1).lower()

        m = re.match(r"^(https?://[^/]+)", ep)
        if m:
            host = m.group(1).split("//", 1)[1].lower()
            # ② 同主机，或为目标的子域（api.example.com ← example.com）
            if not tgt_host or host == tgt_host or host.endswith("." + tgt_host):
                return m.group(1)
            # ③ 目标域派生出的云存储桶
            label = (tgt_host.split(":")[0].split(".")[0] if tgt_host else "")
            if label and StorageHost.is_derived(host, label):
                return m.group(1)
            return tgt or ep
        return tgt or ep

    @staticmethod
    def _slug(f: Finding) -> str:
        raw = f"{f.item_id}_{f.title}"
        raw = re.sub(r"[^\w\u4e00-\u9fff]+", "_", raw)
        raw = re.sub(r"_+", "_", raw).strip("_")
        return raw[:60].lower() if raw else "finding"


# ==============================================================================
# 具体验证逻辑实现
# ==============================================================================
def _verify_sensitive_file(target_url: str, f: Finding) -> tuple[str, str]:
    path = f.endpoint.replace(target_url, "").lstrip("/") or f.endpoint
    body = f'''
# 该敏感文件的语义特征 —— 用于排除「自定义 404 页面返回 200」的假命中
CONTENT_MARKERS = {json.dumps(_markers_for(path), ensure_ascii=False)}
FAKE_PATH = "this-path-should-not-exist-{datetime.now().strftime('%Y%m%d')}"


def main(target, timeout):
    base = target.rstrip("/")
    url = base + "/{path.lstrip('/')}"
    print(f"[1/3] 请求目标文件：{{url}}")
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
        r.raise_for_status() if False else None
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    show("Content-Type", r.headers.get("Content-Type", ""))
    show("响应长度", len(r.text or ""))

    print(f"[2/3] 对照实验：请求一个必然不存在的路径 {{FAKE_PATH}}")
    try:
        fake = requests.get(f"{{base}}/{{FAKE_PATH}}", headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
        show("对照状态码", fake.status_code)
        show("对照长度", len(fake.text or ""))
    except Exception as e:
        fake = None
        show("对照请求异常", f"{{type(e).__name__}}")

    print("[3/3] 判定")
    if r.status_code != 200:
        return result(False, f"目标文件返回 {{r.status_code}}，非可访问状态")

    # 关键：不能只看状态码，要确认内容确实属于该文件
    hit = [m for m in CONTENT_MARKERS if m.lower() in (r.text or "").lower()]
    show("命中特征", hit)
    if not hit:
        return result(False, "状态码为 200，但响应内容与该文件语义不符（疑为伪 200 页面）")

    # 排除伪 200：若对照路径也返回 200 且内容相似，说明是自定义错误页
    if fake is not None and fake.status_code == 200 and len(fake.text or "") >= len(r.text or "") * 0.9:
        return result(False, "存在不存在的路径同样返回 200，判定为自定义错误页，非真实文件泄露")

    body_snip = mask((r.text or "")[:500])
    print("  响应片段（已脱敏）：")
    print(f"    {{body_snip}}")
    return result(True, f"敏感文件 {{url}} 可未授权访问，内容特征命中 {{hit}}")
'''
    expected = (
        f"1. 对 {target_url}/{path.lstrip('/')} 的 GET 请求返回 200\n"
        f"2. 响应内容命中该文件类型的语义特征：{', '.join(_markers_for(path))[:120]}\n"
        f"3. 对照路径（必然不存在）返回 404，或内容明显不同\n"
        f"4. 三项同时满足 → 漏洞确认存在"
    )
    return body, expected


def _markers_for(path: str) -> list[str]:
    table = {
        ".git/config": ["[core]", "repositoryformatversion"],
        ".env": ["=", "APP_", "DB_", "SECRET"],
        ".svn/entries": ["dir", "svn"],
        "backup.sql": ["INSERT INTO", "CREATE TABLE"],
        "backup.zip": ["PK"],
        "phpinfo.php": ["phpinfo", "PHP Version"],
        "swagger-ui.html": ["swagger", "openapi"],
        "swagger/index.html": ["swagger", "openapi"],
        "v2/api-docs": ["paths", "swagger"],
        "actuator/env": ["activeProfiles", "systemProperties"],
        "actuator/health": ["status"],
        "server-status": ["Apache Server Status"],
        "debug.log": ["ERROR", "Exception", "Traceback"],
        "WEB-INF/web.xml": ["<web-app", "servlet"],
        "package.json": ['"dependencies"', '"name"'],
        "composer.json": ['"require"'],
        ".DS_Store": ["bud1"],
    }
    return table.get(path, ["=", "key", "name"])


def _verify_security_headers(target_url: str, f: Finding) -> tuple[str, str]:
    body = f'''
# 基线：这些响应头必须存在（缺失即为缺陷）
REQUIRED_HEADERS = {{
    "Strict-Transport-Security": "中危",
    "Content-Security-Policy": "中危",
    "X-Content-Type-Options": "低危",
    "X-Frame-Options": "低危",
    "Referrer-Policy": "低危",
}}


def main(target, timeout):
    print(f"[1/2] 请求 {{target}} 并读取响应头")
    try:
        r = requests.get(target, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    hdrs = {{k.lower(): v for k, v in r.headers.items()}}
    print("  完整响应头：")
    for k, v in r.headers.items():
        print(f"    {{k}}: {{mask(v)[:120]}}")

    print("\\n[2/2] 逐项比对基线")
    missing = []
    for name, sev in REQUIRED_HEADERS.items():
        if name.lower() in hdrs:
            print(f"  [有] {{name}}: {{mask(hdrs[name.lower()])[:80]}}")
        else:
            print(f"  [缺] {{name}}  （建议等级 {{sev}}）")
            missing.append((name, sev))

    if not missing:
        return result(False, "全部基线安全头均已配置")
    return result(True, f"缺失 {{len(missing)}} 项安全响应头：" + ", ".join(n for n, _ in missing))
'''
    expected = (
        f"1. 对 {target_url} 发起 GET，读取响应头\n"
        "2. 逐项比对基线：Strict-Transport-Security / Content-Security-Policy / "
        "X-Content-Type-Options / X-Frame-Options / Referrer-Policy\n"
        "3. 存在缺失项 → 缺陷确认"
    )
    return body, expected


def _verify_version_leak(target_url: str, f: Finding) -> tuple[str, str]:
    body = f'''
# 版本泄露特征
LEAK_PATTERNS = [
    (r"^Server:.*$", re.I, "Server 头泄露中间件与版本"),
    (r"^X-Powered-By:.*$", re.I, "X-Powered-By 泄露后端技术栈"),
    (r"^X-AspNet-Version:.*$", re.I, "ASP.NET 版本泄露"),
]


def main(target, timeout):
    print(f"[1/2] 请求 {{target}} 采集响应头")
    try:
        r = requests.get(target, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    raw = "\\n".join(f"{{k}}: {{v}}" for k, v in r.headers.items())

    print("\\n[2/2] 匹配版本泄露特征")
    hits = []
    for pattern, flag, why in LEAK_PATTERNS:
        m = re.search(pattern, raw, flag | re.M)
        if m:
            hits.append(why)
            show("命中", m.group(0))
    if not hits:
        return result(False, "未在响应头中发现组件版本信息")
    return result(True, "响应头泄露组件版本：" + "；".join(hits))
'''
    expected = (
        f"1. 对 {target_url} 发起 GET\n"
        "2. 响应头中存在 Server / X-Powered-By / X-AspNet-Version 且含版本号\n"
        "3. 命中 → 版本泄露确认"
    )
    return body, expected


def _verify_dir_listing(target_url: str, f: Finding) -> tuple[str, str]:
    path = f.endpoint.replace(target_url, "").lstrip("/")
    body = f'''
# 目录索引页面的特征标记
LISTING_MARKERS = ["Index of /", "Directory listing for", "[To Parent Directory]"]


def main(target, timeout):
    url = target.rstrip("/") + "/{path.lstrip('/')}"
    print(f"[1/2] 请求目录：{{url}}")
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    show("响应长度", len(r.text or ""))
    print("  响应片段（已脱敏）：")
    print(f"    {{mask((r.text or '')[:300])}}")

    print("\\n[2/2] 判定是否返回目录索引")
    hit = [m for m in LISTING_MARKERS if m.lower() in (r.text or "").lower()]
    show("命中标记", hit)
    if not hit:
        return result(False, "响应未包含目录索引特征，目录浏览可能已关闭")
    return result(True, f"目录 {{url}} 开启了列表浏览，命中标记 {{hit}}")
'''
    expected = (
        f"1. 访问 {target_url}/{path.lstrip('/')}\n"
        "2. 页面返回含「Index of /」或「Directory listing」等目录索引标记\n"
        "3. 命中 → 目录浏览确认开启"
    )
    return body, expected


def _verify_http_methods(target_url: str, f: Finding) -> tuple[str, str]:
    body = f'''
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]


def main(target, timeout):
    print(f"[1/2] 对 {{target}} 发起 OPTIONS 请求（只读，不实际调用写方法）")
    try:
        r = requests.options(target, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    allow = r.headers.get("Allow") or r.headers.get("allow") or ""
    show("Allow", allow)
    if not allow:
        return result(False, "OPTIONS 未返回 Allow 头，无法判定方法支持情况")

    print("\\n[2/2] 检查是否声明了危险方法")
    found = [m for m in DANGEROUS_METHODS if m in allow.upper()]
    show("声明的危险方法", found)
    if not found:
        return result(False, "Allow 头未包含危险方法")
    print("  说明：本脚本只做声明层检测，未实际调用写方法（避免产生副作用）。")
    print("       若需确认是否真正可用，须在测试环境由人工执行并做好回滚准备。")
    return result(True, f"Allow 头声明支持危险方法：{{found}}")
'''
    expected = (
        f"1. 对 {target_url} 发起 OPTIONS 请求\n"
        "2. 响应 Allow 头中包含 PUT / DELETE / TRACE / CONNECT 之一\n"
        "3. 命中 → 危险方法已启用（声明层面）"
    )
    return body, expected


def _verify_cors(target_url: str, f: Finding) -> tuple[str, str]:
    body = f'''
PROBE_ORIGIN = "https://evil-scanner-probe.example"


def main(target, timeout):
    print(f"[1/2] 携带伪造 Origin 请求 {{target}}：{{PROBE_ORIGIN}}")
    hdrs = dict(DEFAULT_HEADERS)
    hdrs["Origin"] = PROBE_ORIGIN
    try:
        r = requests.get(target, headers=hdrs, timeout=timeout, verify=False)
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    show("Access-Control-Allow-Origin", acao)
    show("Access-Control-Allow-Credentials", acac)

    print("\\n[2/2] 判定跨域策略是否过宽")
    if not acao:
        return result(False, "未返回 Access-Control-Allow-Origin，不存在跨域开放")
    if acao.strip() == "*":
        if acac.lower() == "true":
            return result(True, "ACAO 为通配符且允许凭据 —— 任意站点可读取认证后的响应（高危）")
        return result(True, "ACAO 为通配符 —— 任意站点可读取公开响应（中危）")
    if PROBE_ORIGIN in acao:
        return result(True, f"ACAO 直接反射了伪造来源 {{acao}} —— 任意站点可跨域读取响应（高危）")
    print("  回显的来源并非本次伪造来源，进一步测试来源白名单边界：")
    for probe in ["https://evil-scanner-probe.example", "null", "https://sub.target-probe.example"]:
        hdrs2 = dict(DEFAULT_HEADERS); hdrs2["Origin"] = probe
        try:
            r2 = requests.get(target, headers=hdrs2, timeout=timeout, verify=False)
            got = r2.headers.get("Access-Control-Allow-Origin", "")
            print(f"    Origin={{probe}} -> ACAO={{got or '(无)'}}")
            if got and got.strip() != "null" and (probe in got or got.strip() == "*"):
                return result(True, f"来源白名单校验缺失：{{probe}} 被接受")
        except Exception:
            continue
    return result(False, f"ACAO 为 {{acao}}，未发现可绕过的来源校验")
'''
    expected = (
        f"1. 携带伪造 Origin（{PROBE_ORIGIN}）请求 {target_url}\n"
        "2. 响应 Access-Control-Allow-Origin 为 * 或回显该伪造来源\n"
        "3. 若同时 Allow-Credentials: true，则升级为高危\n"
        "4. 命中 → CORS 配置过宽确认"
    )
    return body, expected


def _verify_js(f: Finding, target_url: str) -> tuple[str, str]:
    if "Source Map" in f.title:
        body = f'''
# 从产物中提取的 Source Map 地址（扫描时确认可访问）
SOURCEMAP_URLS = {json.dumps(_extract_urls(f), ensure_ascii=False, indent=4)}


def main(target, timeout):
    if not SOURCEMAP_URLS or SOURCEMAP_URLS == ["__DYNAMIC__"]:
        print("[1/2] 未预置地址，从页面动态提取 sourceMappingURL")
        try:
            page = requests.get(target, headers=DEFAULT_HEADERS, timeout=timeout, verify=False).text
        except Exception as e:
            print(f"[错误] 页面请求失败：{{type(e).__name__}}: {{e}}")
            return 2
        js_urls = re.findall(r'<script[^>]+src=["\\']([^"\\']+)["\\']', page, re.I)
        candidates = []
        for u in js_urls[:20]:
            if not u.startswith("http"):
                u = target.rstrip("/") + "/" + u.lstrip("/")
            try:
                js = requests.get(u, headers=DEFAULT_HEADERS, timeout=timeout, verify=False).text
            except Exception:
                continue
            m = re.search(r"//[#@]\\s*sourceMappingURL=(\\S+)", js[-3000:])
            if m:
                sm = m.group(1)
                if not sm.startswith("http"):
                    sm = u.rsplit("/", 1)[0] + "/" + sm.lstrip("/")
                candidates.append(sm)
    else:
        candidates = SOURCEMAP_URLS

    if not candidates:
        return result(False, "未发现 Source Map 引用")

    print(f"[2/2] 逐个验证 Source Map 是否可公开访问（共 {{len(candidates)}} 个）")
    confirmed = []
    for sm in candidates[:10]:
        try:
            r = requests.get(sm, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
        except Exception as e:
            print(f"  {{sm}} -> 请求异常 {{type(e).__name__}}")
            continue
        ok = r.status_code == 200 and len(r.text or "") > 50 and ('"mappings"' in r.text or '"sources"' in r.text)
        print(f"  {{sm}} -> HTTP {{r.status_code}}, 长度 {{len(r.text or '')}}, 有效map={{ok}}")
        if ok:
            confirmed.append(sm)
    if not confirmed:
        return result(False, "Source Map 引用存在但实际不可访问或内容无效")
    return result(True, f"{{len(confirmed)}} 个 Source Map 可公开下载：{{confirmed[:3]}}")
'''
        expected = (
            "1. 提取 JS 产物末尾的 sourceMappingURL 引用\n"
            "2. 直接访问该 .map 地址\n"
            "3. 返回 200 且内容含 mappings / sources 字段 → 源码泄露确认"
        )
        return body, expected

    # 组件版本 / 敏感信息
    body = f'''
# 扫描时提取到的产物地址（用于重新抓取比对）
PAGE_URL = "{target_url}"
SENSITIVE_PATTERNS = [
    ("云厂商 AccessKey", r"\\b(?:AKIA[0-9A-Z]{{12,}}|LTAI[0-9A-Za-z]{{10,}}|AKID[0-9A-Za-z]{{10,}})\\b", "严重"),
    ("私钥内容", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "严重"),
    ("硬编码口令", r"(?i)\\b(?:password|secret|apikey|api_key|access_token)\\s*[:=]\\s*[\\"'][^\\"']{{8,}}[\\"']", "高危"),
    ("内网地址", r"\\b(?:10\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}|192\\.168\\.\\d{{1,3}}\\.\\d{{1,3}})\\b", "低危"),
]


def main(target, timeout):
    print(f"[1/3] 抓取页面 {{target}}")
    try:
        page = requests.get(target, headers=DEFAULT_HEADERS, timeout=timeout, verify=False).text
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2

    js_urls = re.findall(r'<script[^>]+src=["\\']([^"\\']+)["\\']', page, re.I)
    print(f"[2/3] 抓取 JS 产物（{{len(js_urls)}} 个引用）")
    blob = page
    for u in js_urls[:20]:
        if not u.startswith("http"):
            u = target.rstrip("/") + "/" + u.lstrip("/")
        try:
            blob += "\\n" + requests.get(u, headers=DEFAULT_HEADERS, timeout=timeout, verify=False).text
            print(f"  [ok] {{u}}")
        except Exception as e:
            print(f"  [跳过] {{u}} ({{type(e).__name__}})")

    print("\\n[3/3] 检索敏感信息特征")
    hits = []
    for name, pattern, sev in SENSITIVE_PATTERNS:
        for m in re.finditer(pattern, blob):
            snip = mask(m.group(0))
            hits.append((name, sev, snip))
            print(f"  [命中] {{name}}（{{sev}}）：{{snip}}")
    if not hits:
        return result(False, "未在产物中检索到敏感信息特征")
    return result(True, f"产物中命中 {{len(hits)}} 处敏感信息")
'''
    expected = (
        f"1. 抓取 {target_url} 页面及其引用的 JS 产物\n"
        "2. 在产物文本中检索云密钥 / 私钥 / 硬编码口令 / 内网地址特征\n"
        "3. 命中 → 敏感信息泄露确认（命中项已脱敏输出）"
    )
    return body, expected


def _extract_urls(f: Finding) -> list[str]:
    urls = re.findall(r"https?://[^\s,)]+", f.technical_detail or "")
    return urls[:10] if urls else ["__DYNAMIC__"]


def _verify_authz(f: Finding, target_url: str) -> tuple[str, str]:
    body = f'''
# 需要两个账号的凭据交叉验证。凭据从环境变量读取，不落盘。
#   ANON_OR_LOW_TOKEN  : 低权 / 未认证账号的凭据（可留空表示完全匿名）
#   HIGH_TOKEN         : 对照账号的凭据
import os

LOW_TOKEN = os.environ.get("VERIFY_LOW_TOKEN", "")
HIGH_TOKEN = os.environ.get("VERIFY_HIGH_TOKEN", "")


def probe(url, token, timeout):
    hdrs = dict(DEFAULT_HEADERS)
    if token:
        hdrs["Authorization"] = token if token.lower().startswith("bearer") else f"Bearer {{token}}"
    try:
        r = requests.get(url, headers=hdrs, timeout=timeout, verify=False)
        return {{"status": r.status_code, "len": len(r.text or ""), "body": r.text or ""}}
    except Exception as e:
        return {{"error": f"{{type(e).__name__}}: {{e}}"}}
''' + f'''
def main(target, timeout):
    url = "{f.endpoint or target_url}"
    url = url if url.startswith("http") else target.rstrip("/") + "/" + url.lstrip("/")
    print(f"[1/3] 无凭据请求 {{url}}")
    anon = probe(url, "", timeout)
    if "error" in anon:
        print(f"[错误] {{anon['error']}}")
        return 2
    show("状态码", anon["status"])
    show("响应长度", anon["len"])
    show("响应片段", anon["body"][:300])

    print("\\n[2/3] 带低权凭据请求")
    if LOW_TOKEN:
        low = probe(url, LOW_TOKEN, timeout)
        show("状态码", low.get("status"))
        show("响应长度", low.get("len"))
    else:
        print("  未设置 VERIFY_LOW_TOKEN，跳过（匿名结果已足够判定未授权访问）")
        low = anon

    print("\\n[3/3] 判定")
    if anon["status"] == 200 and anon["len"] > 50:
        ct = "json" if anon["body"].strip()[:1] in "{{[" else "非结构化"
        print(f"  匿名请求返回 200，响应为{{ct}}内容，长度 {{anon['len']}}")
        if ct == "json":
            return result(True, "接口无需认证即可返回结构化数据，判定为未授权访问")
        return result(False, "匿名可访问，但返回内容非结构化数据，需人工确认是否含敏感信息")
    if anon["status"] in (401, 403):
        return result(False, f"匿名请求被拒绝（{{anon['status']}}），鉴权生效")
    return result(False, f"匿名请求状态码 {{anon['status']}}，未确认未授权访问")
'''
    expected = (
        f"1. 不带任何凭据请求 {f.endpoint or target_url}\n"
        "2. 观察是否返回 200 且响应为结构化数据\n"
        "3. 若有账号，再带低权凭据比对（可选，通过环境变量传入）\n"
        "4. 匿名即可读取结构化数据 → 未授权访问确认"
    )
    return body, expected


def _generic_verify(f: Finding, target_url: str) -> tuple[str, str]:
    body = f'''
# 该发现未匹配到专用验证模板，此处做通用可达性与特征复检。
# 复现步骤见下方注释，建议人工按步骤执行。
#
# 原始复现步骤：
{chr(10).join("    #   " + ln for ln in (f.reproduction or "（无）").splitlines())}
#
# 技术细节：
{chr(10).join("    #   " + ln for ln in (f.technical_detail or "（无）").splitlines()[:10])}


def main(target, timeout):
    print(f"[1/2] 请求目标端点：{{target}}")
    try:
        r = requests.get(target, headers=DEFAULT_HEADERS, timeout=timeout, verify=False)
    except Exception as e:
        print(f"[错误] 请求失败：{{type(e).__name__}}: {{e}}")
        return 2
    show("HTTP 状态码", r.status_code)
    show("Content-Type", r.headers.get("Content-Type", ""))
    show("响应长度", len(r.text or ""))
    show("响应片段", (r.text or "")[:400])

    print("\\n[2/2] 通用可达性判定")
    if r.status_code >= 400:
        return result(False, f"端点返回 {{r.status_code}}，当前不可复现")
    print("  端点可达，但该类型缺少专用断言模板，需人工按上述步骤确认。")
    print("  建议：对照复现步骤逐项核对，确认后再定稿结论。")
    return 1
'''
    expected = (
        f"1. 按复现步骤访问 {f.endpoint or target_url}\n"
        "2. 本类型暂无专用断言，需人工核对技术细节\n"
        "3. 端点可达性由脚本自动确认"
    )
    return body, expected


_DISPATCH: dict[str, Any] = {
    "WSTG-CONF-04": _verify_sensitive_file,
    "WSTG-CONF-07": _verify_security_headers,
    "WSTG-INFO-02": _verify_version_leak,
    "WSTG-CLNT-11": _verify_cors,
}


# ==============================================================================
# 批量执行器
# ==============================================================================
@dataclass
class VerifyRun:
    script: str
    exit_code: int
    output: str = ""
    duration_ms: int = 0

    @property
    def confirmed(self) -> bool:
        return self.exit_code == 0

    @property
    def status_text(self) -> str:
        return {0: "已复现", 1: "未复现", 2: "执行错误"}.get(self.exit_code, "未知")


class VerifyRunner:
    """批量执行生成的 verify 脚本，收集结论。"""

    def __init__(self, script_dir: Path | str, python_exe: str | None = None):
        self.script_dir = Path(script_dir)
        self.python_exe = python_exe or sys.executable

    def run_all(self, timeout: int = 120) -> list[VerifyRun]:
        """执行目录下全部 verify_*.py。"""
        return self.run_paths(sorted(self.script_dir.glob("verify_*.py")), timeout)

    def run_paths(self, scripts: list[Path], timeout: int = 120) -> list[VerifyRun]:
        """只执行**指定的**脚本。

        为什么需要这个：产出目录里可能残留上一次运行的脚本（清理操作在
        某些环境下会被安全策略拦下）。直接 glob 会把两轮扫描的结果混在一起，
        闸门统计随之失真 —— 严重时会把上一轮的「已复现」算进本轮。
        只跑本次生成的那批脚本，结果才对应本次扫描。
        """
        import time

        runs: list[VerifyRun] = []
        for script in scripts:
            t0 = time.time()
            runs.append(self._run_one(Path(script), timeout, t0))
        return runs

    def _run_one(self, script: Path, timeout: int, t0: float) -> VerifyRun:
        import subprocess
        import time

        try:
            kw: dict[str, Any] = {}
            if sys.platform.startswith("win"):
                kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            # 复现脚本是独立的 Python 进程，同样要单独降优先级 ——
            # 它们是串行跑的，但每一个都会导入 requests 并发并发请求，
            # 不降的话就是「主进程在让路、子进程在抢 CPU」。
            try:
                from engine import resources as _res  # noqa: PLC0415
                _k = _res.child_kwargs()
                kw["env"] = _k["env"]
                if "creationflags" in _k:
                    kw["creationflags"] = kw.get("creationflags", 0) | _k["creationflags"]
            except Exception:  # noqa: BLE001
                pass
            proc = subprocess.run(
                [self.python_exe, str(script)],
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace", **kw,
            )
            return VerifyRun(
                script=script.name,
                exit_code=proc.returncode,
                output=(proc.stdout or "") + (proc.stderr or ""),
                duration_ms=int((time.time() - t0) * 1000),
            )
        except subprocess.TimeoutExpired:
            return VerifyRun(script.name, 2, f"执行超时（>{timeout}s）",
                             int((time.time() - t0) * 1000))
        except Exception as e:  # noqa: BLE001
            return VerifyRun(script.name, 2, f"{type(e).__name__}: {e}",
                             int((time.time() - t0) * 1000))


if __name__ == "__main__":
    print("验证框架自测")
    print("=" * 70)

    from models import Finding
    from engine.nuclei_runner import BuiltinDetector
    from engine.fingerprint import Fingerprinter

    # 用真实探测结果先生成 Finding，再生成 verify 脚本，最后批量执行
    fp = Fingerprinter({"rate": {"requests_per_second": 5, "timeout_seconds": 10}})
    url = "https://example.com"
    findings = BuiltinDetector().run(url, fp.client)
    print(f"\n源发现：{len(findings)} 条")

    out_dir = ROOT / "outputs" / "_selftest" / "verify"
    builder = ScriptBuilder(out_dir)
    paths = builder.generate_all(findings, url)
    print(f"生成 verify 脚本 {len(paths)} 份：")
    # generate_all 返回的是**列表**（同一标题可能有多条发现，用标题作键会互相
    # 覆盖），所以这里只能按列表迭代 —— 早先这里写的是 paths.items()，
    # 一旦有人直接运行本文件就会 AttributeError。
    for p in paths:
        print(f"  - {p.name}  ({p.stat().st_size} 字节)")
    if builder.session_template is not None:
        print(f"会话文件骨架：{builder.session_template}")
        print(f"  {builder.session_template_note}")

    print("\n批量执行 verify 脚本：")
    runs = VerifyRunner(out_dir).run_all()
    for r in runs:
        print(f"  [{r.status_text}] {r.script}  ({r.duration_ms}ms, 退出码 {r.exit_code})")
    print(f"\n脚本目录：{out_dir}")
