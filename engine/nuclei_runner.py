# -*- coding: utf-8 -*-
"""
L2 扫描引擎 —— nuclei 集成与内置降级检测器
==========================================
职责：执行模板化检测，产出 Finding。

两种运行模式：
  1. 原生模式：本机装了 nuclei，按档位参数调用模板库，解析 jsonl 输出。
  2. 降级模式：nuclei 不可用时，用内置检测器覆盖「无需外部工具即可确证」的
     检查项（安全头、敏感文件、版本泄露、目录列表等）。

降级不改变报告结构 —— 结论照出，但报告附录会如实标注「该项由内置检测器
覆盖，未使用 nuclei 模板」，供读者判断覆盖度。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import binlocate  # noqa: E402
from engine import resources as res_budget  # noqa: E402
from engine.nuclei_budget import NucleiPass, build_plan  # noqa: E402
from models import Evidence, Finding  # noqa: E402
from verify.mask import Masker  # noqa: E402

# ==============================================================================
# nuclei 原生集成
# ==============================================================================

# nuclei 严重度 -> 本工程定级
NUCLEI_SEVERITY_MAP = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "信息",
}


@dataclass
class NucleiRunResult:
    executed: bool = False
    findings: list[Finding] = field(default_factory=list)
    command: str = ""
    raw_output: str = ""
    error: str = ""
    template_count: int = 0
    # --- 执行预算与截断事实（报告要据此披露「这一批结论完不完整」） ---
    commands: list[str] = field(default_factory=list)
    plan: dict[str, Any] = field(default_factory=dict)
    pass_results: list[dict[str, Any]] = field(default_factory=list)
    elapsed: float = 0.0
    budget_exhausted: bool = False
    partial: bool = False
    notes: list[str] = field(default_factory=list)
    #: 本轮实际纳入的模板份数（各趟之和；清点失败时为 0 并由 scope_known 标记）。
    #: 这是解读「nuclei 没有发现」最关键的单一数字：同一个「无发现」，
    #: 是「3190 份模板跑完了」还是「只跑完 1/3 就被掐断」，含义完全不同。
    scope_total: int = 0
    scope_known: bool = False

    def summary(self) -> str:
        """一句话执行摘要（进报告 notes）。截断事实必须出现，不得静默。"""
        if not self.executed:
            return f"nuclei 未执行：{self.error or '未安装'}"
        scope = (f"，纳入模板 {self.scope_total} 份" if self.scope_known
                 else "，纳入模板数未清点")
        tail = f"{scope}，产出 {len(self.findings)} 条，耗时 {self.elapsed:.0f}s"
        if self.budget_exhausted:
            tail += "，⚠ 预算耗尽被截断，本批结论不完整"
        elif self.partial:
            tail += "，⚠ 部分趟未跑完"
        return f"nuclei 执行{'成功' if not self.error else '有提示'}{tail}"


class NucleiRunner:
    """调用本机 nuclei 执行模板化检测。

    执行受 `engine/nuclei_budget.py` 的计划约束：按严重度分层多趟跑、带总预算、
    被预算掐断时**抢救已写出的 jsonl**（已经发生的事实不因「没跑完」而消失）。
    """

    # PATH 之外的已知安装位置：候选与优先级见 `engine/binlocate.py`。
    # 原先是写死的本机路径（`C:/Users/<用户名>/...`），换台电脑就找不到 nuclei。

    def __init__(self, profile: dict[str, Any] | None = None, timeout: int | None = None,
                 clock: Any = None, measure_scope: bool = True,
                 scope_timeout: float = 90.0):
        self.profile = profile or {}
        self.plan = build_plan(self.profile)
        #: 进程总预算。显式传入时以传入值为准（自测/复现用），否则取计划预算。
        self.timeout = float(timeout) if timeout is not None else self.plan.budget_seconds
        #: 可注入时钟。默认 `time.monotonic`；注入是为了让「预算耗尽 → 跳过下一趟」
        #: 这条分支能被确定性验证，而不是靠 sleep 去撞时机（那种测试必然不稳定）。
        self._clock = clock or time.monotonic
        #: 是否在执行前清点模板份数（`-tl`，只加载元数据、不打目标）。
        self.measure_scope = measure_scope
        self.scope_timeout = float(scope_timeout)
        # 定位：PATH → engine/binlocate 的多级候选（环境变量 / 用户目录 /
        # 包内 tools/ / 历史路径兜底）。写死本机路径的做法换台机器即失效。
        self.binary = shutil.which("nuclei") or binlocate.locate("nuclei")
        self.masker = Masker()

    @property
    def available(self) -> bool:
        return bool(self.binary)

    def build_command(self, target_url: str, out_file: Path,
                      extra_args: list[str] | None = None,
                      nuclei_pass: NucleiPass | None = None) -> list[str]:
        """拼命令行。

        参数一律来自计划（`NucleiPass`），不再就地读配置 —— 执行参数只有
        一处来源，才不会出现「报告里写的排除项」和「实际命令行」不一致。
        """
        ps = nuclei_pass or (self.plan.passes[0] if self.plan.passes else NucleiPass(label="默认"))
        cmd = ps.to_args(self.binary or "nuclei", target_url, out_file)
        if extra_args:
            cmd += list(extra_args)
        return cmd

    def count_templates(self, nuclei_pass: NucleiPass) -> int | None:
        """清点这一趟实际纳入的模板份数（`-tl`，只加载元数据、不向目标发请求）。

        返回 None 表示**没能清点**（工具不可用 / 超时 / 输出为空）。这不是
        「0 份」—— 报告必须把「未清点」和「一份都没有」分开，否则一个清点
        失败的扫描会被写成「模板库是空的」。
        """
        if not self.available or not self.measure_scope:
            return None
        cmd = nuclei_pass.to_list_args(self.binary or "nuclei")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.scope_timeout,
                encoding="utf-8", errors="replace",
                # 清点模板同样要低优先级 + GOMAXPROCS 限额：`-tl` 会把
                # 几千份模板全部加载进内存，这一枪的瞬时占用不比执行那趟小。
                **res_budget.child_kwargs(),
            )
            lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
            return len(lines) or None
        except Exception:  # noqa: BLE001
            # 清点是**披露**用的，不是主流程。失败不中断扫描，但必须让
            # 「纳入模板数未知」这个事实传下去（返回 None 而非 0）。
            return None

    def run(self, target_url: str) -> NucleiRunResult:
        res = NucleiRunResult()
        res.plan = self.plan.to_dict()
        res.notes.extend(self.plan.notes)

        if not self.available:
            res.error = "nuclei 未安装，跳过原生模式"
            return res
        if not self.plan.passes:
            res.error = "档位未启用任何 nuclei 严重度，跳过"
            res.notes.append(self.plan.summary())
            return res

        res.executed = True
        t_start = self._clock()
        deadline = t_start + self.timeout

        with tempfile.TemporaryDirectory() as td:
            for idx, ps in enumerate(self.plan.passes, start=1):
                remain = deadline - self._clock()
                if remain <= 1.0:
                    # 上一趟把预算吃完了。后面这趟**没跑**，不是「跑了没发现」——
                    # 报告要能区分这两件事。
                    res.budget_exhausted = True
                    res.partial = True
                    res.notes.append(
                        f"预算耗尽，第 {idx} 趟「{ps.label}」未执行 —— "
                        "该档结论本次无外部引擎覆盖")
                    res.pass_results.append(
                        {"pass": idx, "label": ps.label, "severity": list(ps.severity),
                         "status": "skipped", "findings": 0, "templates": None,
                         "elapsed": 0.0})
                    break

                out_file = Path(td) / f"nuclei_pass{idx}.jsonl"
                cmd = self.build_command(target_url, out_file, nuclei_pass=ps)
                res.commands.append(" ".join(cmd))
                if not res.command:
                    res.command = res.commands[0]

                # 先清点这一趟罩住多大范围。只加载模板元数据、不打目标，
                # 但**确实花时间**，所以要重新取一次剩余预算再决定给多少。
                scope = self.count_templates(ps)
                if scope is not None:
                    res.scope_total += scope
                    res.scope_known = True
                remain = max(1.0, deadline - self._clock())

                t0 = self._clock()
                status = "ok"
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=remain,
                        encoding="utf-8", errors="replace",
                        # 低影响运行：子进程必须**单独**降优先级（父进程的优先级
                        # 不会被继承），并用 GOMAXPROCS / GOMEMLIMIT 给 Go 侧
                        # 划死核数与内存 —— 这是「扫描时电脑不卡」的关键一步。
                        **res_budget.child_kwargs(),
                    )
                    res.raw_output = (proc.stdout or "")[-8000:]
                    if proc.returncode not in (0, 1):   # nuclei 无发现时返回 1
                        status = f"exit={proc.returncode}"
                        res.notes.append(f"第 {idx} 趟「{ps.label}」退出码 {proc.returncode}")
                except subprocess.TimeoutExpired:
                    status = "timeout"
                    res.budget_exhausted = True
                    res.partial = True
                    res.notes.append(
                        f"第 {idx} 趟「{ps.label}」执行到预算上限（{int(self.timeout)}s）被掐断 —— "
                        "已抢救该趟此前写出的结果（未跑到的模板本次没有结论）")
                except Exception as e:  # noqa: BLE001
                    status = "error"
                    res.notes.append(
                        f"第 {idx} 趟「{ps.label}」异常：{type(e).__name__}: {str(e)[:160]}")

                # 抢救：无论正常结束还是被掐断，jsonl 里已经写出的就是既成事实。
                # 原来的写法只在 returncode 正常时才解析，一次超时=整批结果归零。
                got = self.parse_jsonl(out_file) if out_file.exists() else []
                res.findings.extend(got)
                res.pass_results.append({
                    "pass": idx, "label": ps.label, "severity": list(ps.severity),
                    "status": status, "findings": len(got), "templates": scope,
                    "elapsed": round(self._clock() - t0, 1),
                })

                if status == "timeout":
                    break

        res.elapsed = round(self._clock() - t_start, 1)
        res.findings = self._dedupe(res.findings)
        res.template_count = len({f.extra.get("template_id") for f in res.findings})
        return res

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """去重：同一模板命中同一地址只留一条。

        分层多趟跑引入的新风险是同一命中被两次跑到（比如某模板同时带
        critical 与 medium 标签）。重复计数会让报告里的发现数虚高。
        """
        seen: set[tuple[str, str]] = set()
        out: list[Finding] = []
        for f in findings:
            key = (str(f.extra.get("template_id") or ""), str(f.endpoint or ""))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def parse_jsonl(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(self._to_finding(rec))
        return findings

    def _to_finding(self, rec: dict[str, Any]) -> Finding:
        info = rec.get("info", {}) or {}
        sev_raw = (info.get("severity") or "info").lower()
        sev = NUCLEI_SEVERITY_MAP.get(sev_raw, "信息")
        tid = rec.get("template-id") or info.get("name") or "nuclei-unknown"
        matched = rec.get("matched-at") or rec.get("host") or ""

        req = rec.get("request", "")
        resp = rec.get("response", "")
        ev = [
            Evidence(
                kind="request",
                content=self.masker.mask(req[:2000]),
                note="nuclei 请求原文（已脱敏）",
                masked=True,
                raw_hash=Masker.fingerprint(req),
            ),
            Evidence(
                kind="response",
                content=self.masker.mask(resp[:2000]),
                note="nuclei 响应原文（已脱敏）",
                masked=True,
                raw_hash=Masker.fingerprint(resp),
            ),
        ]

        return Finding(
            item_id=self._map_template_to_item(tid, info),
            title=info.get("name") or tid,
            target=rec.get("host", ""),
            endpoint=matched,
            method=(rec.get("type", "") or "").upper(),
            severity=sev,
            confidence="High",
            evidence_level="A",
            grading_basis=f"nuclei 模板 {tid} 实测命中，证据为可复现的请求/响应原文",
            description=info.get("description", "") or f"nuclei 模板 {tid} 检出",
            technical_detail=json.dumps(
                {"template_id": tid, "tags": info.get("tags", []), "reference": info.get("reference", [])},
                ensure_ascii=False, indent=2,
            ),
            impact=info.get("impact", "") or "详见技术细节与证据",
            remediation=info.get("remediation", "") or "按模板建议修复",
            compliance="",
            evidence=ev,
            source_tool="nuclei",
            # 归口依据与 tags 必须一起落进 extra：
            #   · tags    —— 「这条命中是不是一个漏洞」要靠它判（识别类模板不回填）；
            #   · mapping —— 归口是否可信。依据不足时报告要标出来，让人工确认，
            #     而不是把一个猜出来的归口当成确定结论写进清单。
            extra={
                "template_id": tid,
                "tags": list(info.get("tags") or []),
                "mapping": self._map_detail(tid, info),
                "curl_command": self.masker.mask(rec.get("curl-command", "")),
            },
        )

    @staticmethod
    def _map_template_to_item(template_id: str, info: dict[str, Any]) -> str:
        """把 nuclei 模板归口到本工程的检查项 ID。

        归口表在 `engine/nuclei_map.py`（覆盖 299 个 tag / 77 个检查项）。
        此处只做一次委托 —— 映射逻辑放在一个模块里，nuclei 侧与回填侧
        才不会各自维护一份、慢慢漂移成两套结论。
        """
        try:
            from engine.nuclei_map import map_template  # noqa: PLC0415
        except ImportError:  # noqa: BLE001
            from nuclei_map import map_template  # type: ignore  # noqa: PLC0415
        return map_template(template_id, info).item_id

    @staticmethod
    def _map_detail(template_id: str, info: dict[str, Any]) -> dict[str, Any]:
        """归口依据（落进 extra，供报告披露与回填判定）。"""
        try:
            from engine.nuclei_map import map_template  # noqa: PLC0415
        except ImportError:  # noqa: BLE001
            from nuclei_map import map_template  # type: ignore  # noqa: PLC0415
        return map_template(template_id, info).to_dict()


# ==============================================================================
# 内置降级检测器
# ==============================================================================
@dataclass
class DetectRule:
    """一条内置检测规则。"""

    item_id: str
    name: str
    severity: str
    description: str
    impact: str
    remediation: str
    compliance: str
    check: Any  # callable(ctx) -> Finding | None


SECURITY_HEADERS = {
    "Strict-Transport-Security": ("中危", "未启用 HSTS，存在 SSL 剥离攻击风险"),
    "Content-Security-Policy": ("中危", "缺少 CSP，XSS 攻击缺少纵深防御"),
    "X-Content-Type-Options": ("低危", "缺少 nosniff，存在 MIME 嗅探风险"),
    "X-Frame-Options": ("低危", "缺少点击劫持防护（或用 CSP frame-ancestors 替代）"),
    "Referer-Policy": ("低危", "未设置 Referrer-Policy，可能通过 Referer 泄露敏感路径"),
    "Permissions-Policy": ("信息", "未声明 Permissions-Policy，浏览器特性权限未收敛"),
}

# 敏感文件 / 路径清单（判定内容泄露，而非仅路径存在）
SENSITIVE_PATHS = {
    ".git/config": ("严重", "Git 配置泄露，攻击者可进一步还原整个源码仓库"),
    ".env": ("严重", "环境变量文件泄露，通常含数据库口令与密钥"),
    ".svn/entries": ("高危", "SVN 元数据泄露，可还原源码"),
    "backup.zip": ("高危", "备份文件可公开下载，可能含全量数据与源码"),
    "backup.sql": ("严重", "数据库备份可公开下载"),
    "phpinfo.php": ("中危", "phpinfo 暴露服务器配置、路径与模块信息"),
    "swagger-ui.html": ("中危", "接口文档公开暴露，泄露全部接口定义与参数结构"),
    "swagger/index.html": ("中危", "接口文档公开暴露"),
    "v2/api-docs": ("中危", "Springfox 接口文档公开暴露"),
    "actuator/env": ("严重", "Spring Boot Actuator 端点暴露，可能泄露配置与环境变量"),
    "actuator/health": ("低危", "Actuator 健康端点暴露，泄露组件状态"),
    "server-status": ("中危", "Apache server-status 暴露运行状态与客户端请求"),
    "debug.log": ("高危", "调试日志可公开访问，通常含路径、SQL、堆栈"),
    "WEB-INF/web.xml": ("高危", "Java Web 部署描述符泄露"),
    "package.json": ("低危", "前端依赖清单纯文本泄露，便于攻击者定位组件版本"),
    "composer.json": ("低危", "PHP 依赖清单泄露"),
    ".DS_Store": ("低危", "macOS 目录索引文件泄露文件结构"),
}

VERSION_LEAK_PATTERNS = [
    (r"Server:\s*([A-Za-z\-]+)/([\d.]+)", "Server 头"),
    (r"X-Powered-By:\s*([^\r\n]+)", "X-Powered-By 头"),
    (r"X-AspNet-Version:\s*([^\r\n]+)", "X-AspNet-Version 头"),
]

DIRECTORY_LISTING_MARKERS = [
    "Index of /", "Directory listing for", "[To Parent Directory]",
]


class BuiltinDetector:
    """nuclei 缺失时的降级检测器。

    只做「无需外部工具、可确证、零副作用」的检测。每条规则的失败都会被捕获并
    记录为 inconclusive，绝不让单个规则异常中断整轮扫描。
    """

    def __init__(self, profile: dict[str, Any] | None = None):
        self.profile = profile or {}
        self.masker = Masker()
        self.errors: list[str] = []

    # ------------------------------------------------------------------
    def run(self, target_url: str, client: Any) -> list[Finding]:
        """执行全部内置检测。client 需实现 probe_path / fetch。"""
        findings: list[Finding] = []
        checks = [
            self._check_security_headers,
            self._check_sensitive_files,
            self._check_version_leak,
            self._check_directory_listing,
            self._check_http_methods,
            self._check_cors,
        ]
        for fn in checks:
            try:
                res = fn(target_url, client)
                if res:
                    findings.extend(res if isinstance(res, list) else [res])
            except Exception as e:  # noqa: BLE001
                self.errors.append(f"{fn.__name__}: {type(e).__name__}: {str(e)[:120]}")
        return findings

    # ------------------------------------------------------------------
    def _check_security_headers(self, target_url: str, client: Any) -> list[Finding]:
        probe = client.fetch(target_url)
        if not probe.reachable:
            return []
        hdrs = {k.lower(): v for k, v in probe.headers.items()}
        missing = []
        for name, (sev, why) in SECURITY_HEADERS.items():
            if name.lower() not in hdrs:
                missing.append((name, sev, why))
        if not missing:
            return []
        # 缺失安全头归为一条低危发现，逐项列出（避免刷屏，也便于研发统一处理）
        rows = "\n".join(f"  - {n}（建议等级 {s}）：{w}" for n, s, w in missing)
        highest = "中危" if any(s == "中危" for _, s, _ in missing) else "低危"
        return Finding(
            item_id="WSTG-CONF-07",
            title="HTTP 安全响应头缺失",
            target=probe.final_url or target_url,
            endpoint=probe.final_url or target_url,
            method="GET",
            severity=highest,
            confidence="High",
            evidence_level="A",
            grading_basis=(
                f"实测响应头缺失 {len(missing)} 项安全策略头。"
                "属纵深防御缺陷，单独不构成直接入侵，但会放大其他漏洞的影响。"
            ),
            description=(
                "服务器响应中缺少若干安全策略头。这些头本身不阻止攻击，但它们的缺失意味着"
                "浏览器侧少了一层限制：攻击者若能注入内容，浏览器不会帮忙拦。"
            ),
            technical_detail="缺失清单：\n" + rows,
            impact=(
                "非直接数据泄露。影响为：若目标存在 XSS 或中间人条件，缺失的 CSP / HSTS / "
                "nosniff 会使攻击更容易成功。"
            ),
            reproduction=(
                f"1. 对 {probe.final_url or target_url} 发起 GET 请求\n"
                "2. 读取响应头，逐项比对安全头基线清单\n"
                "3. 缺失项即为本发现内容"
            ),
            remediation=(
                "在 Web 服务器或应用层统一注入：\n"
                "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                "  Content-Security-Policy: default-src 'self'（按业务细化）\n"
                "  X-Content-Type-Options: nosniff\n"
                "  X-Frame-Options: DENY（或 CSP frame-ancestors 'none'）\n"
                "  Referrer-Policy: strict-origin-when-cross-origin"
            ),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.9",
            evidence=[Evidence(
                kind="header",
                content=self.masker.mask("\n".join(f"{k}: {v}" for k, v in probe.headers.items())),
                note="实测响应头（已脱敏）", masked=True,
                raw_hash=Masker.fingerprint(str(probe.headers)),
            )],
            source_tool="builtin:headers",
        )

    def _check_sensitive_files(self, target_url: str, client: Any) -> list[Finding]:
        out: list[Finding] = []
        # 批量并发探测，避免逐个路径串行等待
        try:
            probes = client.probe_many(target_url, list(SENSITIVE_PATHS.keys()))
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"敏感文件批量探测失败：{type(e).__name__}: {str(e)[:100]}")
            return out

        for path, (sev, why) in SENSITIVE_PATHS.items():
            p = probes.get(path)
            if p is None:
                continue
            if not p.reachable or p.status != 200:
                continue
            body = p.body_snippet or ""
            # 必须确认是真实内容，而不是自定义 404 页 / 空响应
            if len(body.strip()) < 15:
                continue
            # 排除把 200 空页当命中的情况：内容需与该路径语义相关
            if not self._content_matches(path, body):
                continue
            out.append(Finding(
                item_id="WSTG-CONF-04",
                title=f"敏感文件可公开访问：{path}",
                target=target_url,
                endpoint=p.final_url or f"{target_url.rstrip('/')}/{path}",
                method="GET",
                severity=sev,
                confidence="High",
                evidence_level="A",
                grading_basis=f"实测 GET 返回 200 且响应内容与 {path} 语义匹配，非伪 200 页面",
                description=f"{why}。该文件未做访问控制，任何能访问公网的人都能直接读取。",
                technical_detail=f"路径：{path}\n状态码：{p.status}\n响应长度：{len(body)} 字符",
                impact=why,
                reproduction=(
                    f"1. 浏览器或命令行访问 {p.final_url or target_url.rstrip('/') + '/' + path}\n"
                    f"2. 无需任何身份认证，直接返回 200 与文件内容"
                ),
                remediation=(
                    f"1. 立即在 Web 服务器层面拒绝访问该路径（Nginx: location ~ /\\.(git|svn|env) {{ deny all; }}）\n"
                    f"2. 确认该文件是否已被外部抓取，必要时轮换其中涉及的凭据\n"
                    f"3. 部署前检查流程加入敏感文件扫描，防止再次上线"
                ),
                compliance="等保2.0 安全计算环境-访问控制 / ISO 27001 A.8.3",
                evidence=[Evidence(
                    kind="response",
                    content=self.masker.mask(body[:1200]),
                    note=f"{path} 响应内容（已脱敏）", masked=True,
                    raw_hash=Masker.fingerprint(body),
                )],
                source_tool="builtin:sensitive_files",
            ))
        return out

    @staticmethod
    def _content_matches(path: str, body: str) -> bool:
        """判断响应内容是否真的属于该敏感文件，避免把伪 200 页当命中。"""
        low = body.lower()
        markers = {
            ".git/config": ["[core]", "repositoryformatversion", "[remote"],
            ".env": ["=", "app_", "db_", "secret", "key"],
            ".svn/entries": ["dir", "svn", "12"],
            "backup.zip": ["pk", "zip"],
            "backup.sql": ["insert into", "create table", "-- mysql", "dump"],
            "phpinfo.php": ["php version", "phpinfo", "configuration file"],
            "swagger-ui.html": ["swagger", "openapi", "api-docs"],
            "swagger/index.html": ["swagger", "openapi"],
            "v2/api-docs": ["swagger", "openapi", "paths"],
            "actuator/env": ["propertysources", "activeprofiles", "systemproperties"],
            "actuator/health": ["status", "healthy", "up"],
            "server-status": ["apache server status", "server version", "current time"],
            "debug.log": ["error", "exception", "warning", "traceback", ".php", "sql"],
            "WEB-INF/web.xml": ["<web-app", "servlet", "<display-name"],
            "package.json": ['"name"', '"version"', "dependencies"],
            "composer.json": ['"require"', '"name"', "composer"],
            ".DS_Store": ["bud1", "dsstore", "\x00\x00\x00\x01"],
        }
        keys = markers.get(path)
        if not keys:
            return True
        return any(k.lower() in low for k in keys)

    def _check_version_leak(self, target_url: str, client: Any) -> list[Finding]:
        probe = client.fetch(target_url)
        if not probe.reachable:
            return []
        leaks = []
        raw = "\n".join(f"{k}: {v}" for k, v in probe.headers.items())
        for pattern, label in VERSION_LEAK_PATTERNS:
            m = re.search(pattern, raw, re.I)
            if m:
                leaks.append(f"{label}：{m.group(0).strip()}")
        if not leaks:
            return []
        sev = "低危" if any("X-Powered-By" in x or "AspNet" in x for x in leaks) else "信息"
        return Finding(
            item_id="WSTG-INFO-02",
            title="服务器组件版本信息泄露",
            target=target_url,
            endpoint=probe.final_url or target_url,
            severity=sev,
            confidence="High",
            evidence_level="A",
            grading_basis="实测响应头直接回显组件与版本，无需猜测",
            description="服务器在响应头里主动告知了中间件类型与版本号。攻击者可据此精准匹配已知漏洞，省去指纹探测步骤。",
            technical_detail="命中项：\n  " + "\n  ".join(leaks),
            impact="不直接导致入侵，但显著降低攻击者成本：可跳过探测，直接查对应版本的已知 CVE。",
            reproduction=f"1. 对 {probe.final_url or target_url} 发起 GET\n2. 读取响应头中的 Server / X-Powered-By 字段",
            remediation=(
                "1. Nginx: server_tokens off;\n"
                "2. Apache: ServerTokens Prod / ServerSignature Off\n"
                "3. Tomcat: 在 Connector 上配置 server 属性\n"
                "4. 移除 X-Powered-By（PHP: expose_php = Off）"
            ),
            compliance="等保2.0 安全计算环境-入侵防范 / ISO 27001 A.8.9",
            evidence=[Evidence(kind="header", content=self.masker.mask("\n".join(leaks)),
                               note="命中泄露项", masked=True,
                               raw_hash=Masker.fingerprint(str(leaks)))],
            source_tool="builtin:version_leak",
        )

    def _check_directory_listing(self, target_url: str, client: Any) -> list[Finding] | None:
        # 空串代表根路径（用于识别「整站就是一个目录列表」的情况）
        candidates = ["", "static/", "assets/", "uploads/", "files/", "images/"]
        try:
            probes = client.probe_many(target_url, candidates)
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"目录列表批量探测失败：{type(e).__name__}: {str(e)[:100]}")
            probes = {}
        for path in candidates:
            p = probes.get(path)
            if p is None or not p.reachable or p.status != 200:
                continue
            shown = path or "(根路径)"
            if any(mk.lower() in p.body_snippet.lower() for mk in DIRECTORY_LISTING_MARKERS):
                return Finding(
                    item_id="WSTG-CONF-04",
                    title=f"目录列表功能开启：{shown}",
                    target=target_url,
                    endpoint=p.final_url,
                    severity="中危",
                    confidence="High",
                    evidence_level="A",
                    grading_basis="实测返回目录索引页面，含真实文件条目",
                    description="Web 服务器开启了目录浏览，访问目录时直接列出其中所有文件。攻击者无需任何工具即可摸清站点结构，并发现本不该公开的文件。",
                    technical_detail=f"命中路径：/{path}\n特征：响应含目录索引标记",
                    impact="泄露目录结构与文件名，可能暴露备份、配置、日志等敏感文件路径，为后续攻击提供入口。",
                    reproduction=f"1. 访问 {p.final_url}\n2. 页面直接列出目录内文件清单",
                    remediation=(
                        "Nginx: autoindex off;\n"
                        "Apache: Options -Indexes\n"
                        "IIS: 关闭「目录浏览」功能\n"
                        "并清理该目录下不应公开的文件"
                    ),
                    compliance="等保2.0 安全计算环境-访问控制 / ISO 27001 A.8.3",
                    evidence=[Evidence(kind="response", content=self.masker.mask(p.body_snippet[:1000]),
                                       note="目录索引页面片段（已脱敏）", masked=True,
                                       raw_hash=Masker.fingerprint(p.body_snippet))],
                    source_tool="builtin:dir_listing",
                )
        return None

    def _check_http_methods(self, target_url: str, client: Any) -> Finding | None:
        """探测是否需要关注的危险方法（只读探测，不实际调用写方法）。"""
        probe = client.fetch(target_url, method="OPTIONS")
        if not probe.reachable or probe.status >= 400:
            return None
        allow = probe.headers.get("Allow") or probe.headers.get("allow") or ""
        if not allow:
            return None
        dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m.upper() in allow.upper()]
        if not dangerous:
            return None
        return Finding(
            item_id="WSTG-CONF-06",
            title=f"HTTP 危险方法已启用：{', '.join(dangerous)}",
            target=target_url,
            endpoint=probe.final_url or target_url,
            method="OPTIONS",
            severity="中危",
            confidence="Medium",
            evidence_level="B",
            grading_basis="OPTIONS 响应 Allow 头声明了危险方法；未实际调用验证是否生效（避免写操作）",
            description=f"服务器在 OPTIONS 响应中声明支持 {', '.join(dangerous)} 方法。其中 PUT 可能允许上传文件、DELETE 可能允许删除资源、TRACE 存在跨站追踪风险。",
            technical_detail=f"Allow: {allow}",
            impact="若 PUT/DELETE 实际生效且无鉴权，攻击者可能上传或删除服务器文件。当前为声明层面证据，需人工确认是否真正可用。",
            reproduction=f"1. curl -X OPTIONS {probe.final_url or target_url} -i\n2. 观察 Allow 响应头",
            remediation=(
                "只保留业务必需方法：\n"
                "Nginx: if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }\n"
                "Apache: 用 <LimitExcept GET POST HEAD> Require all denied </LimitExcept>\n"
                "同时关闭 TRACE"
            ),
            compliance="等保2.0 安全计算环境-访问控制 / ISO 27001 A.8.9",
            evidence=[Evidence(kind="header", content=f"Allow: {allow}", note="OPTIONS 响应头",
                               masked=True, raw_hash=Masker.fingerprint(allow))],
            source_tool="builtin:http_methods",
        )

    def _check_cors(self, target_url: str, client: Any) -> Finding | None:
        probe = client.fetch(target_url, allow_redirects=False)
        if not probe.reachable:
            return None
        h = {k.lower(): v for k, v in probe.headers.items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "")
        if not acao:
            return None
        wildcard = acao.strip() == "*"
        reflect = acao.strip().rstrip("/").endswith("*")
        if not (wildcard or reflect):
            return None
        if wildcard and acac.lower() == "true":
            sev, note = "高危", "通配来源同时允许携带凭据，任意站点可读取认证后的响应"
        elif reflect:
            sev, note = "高危", "来源被动态反射，攻击者可构造任意 Origin 读取响应"
        else:
            sev, note = "中危", "通配来源（未允许凭据），可被任意站点读取公开数据"
        return Finding(
            item_id="WSTG-CLNT-11",
            title="CORS 跨域策略配置过宽",
            target=target_url,
            endpoint=probe.final_url or target_url,
            severity=sev,
            confidence="Medium",
            evidence_level="B",
            grading_basis=f"实测响应头 Access-Control-Allow-Origin={acao}，且凭据策略为 {acac or '未声明'}；实际可利用性取决于是否存在需认证的敏感接口",
            description="跨域资源共享策略允许了过宽的来源。任何第三方页面都能代表已登录用户读取本站响应，用户的隐私数据可能被静默窃取。",
            technical_detail=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac or '(未设置)'}",
            impact=note,
            reproduction=(
                f"1. curl -H 'Origin: https://evil.example' {probe.final_url or target_url} -i\n"
                f"2. 观察响应头 Access-Control-Allow-Origin 是否回显该来源或为 *"
            ),
            remediation=(
                "1. 改为显式白名单，禁止使用 *\n"
                "2. 若必须动态反射，须校验 Origin 是否在允许清单内，不得无条件回显\n"
                "3. 仅在对可信来源时才设置 Access-Control-Allow-Credentials: true"
            ),
            compliance="等保2.0 安全计算环境-访问控制 / OWASP API Security API8",
            evidence=[Evidence(kind="header", content=f"ACAO: {acao}\nACAC: {acac}",
                               note="CORS 相关响应头", masked=True,
                               raw_hash=Masker.fingerprint(acao + acac))],
            source_tool="builtin:cors",
        )


if __name__ == "__main__":
    from engine.fingerprint import Fingerprinter

    print("=" * 70)
    print("采集层自测（nuclei 不可用时走内置降级检测器）")
    print("=" * 70)

    nr = NucleiRunner()
    print(f"\nnuclei 可用性：{'可用' if nr.available else '不可用 → 走降级模式'}")

    fp = Fingerprinter({"rate": {"requests_per_second": 5, "timeout_seconds": 10}})
    url = "https://example.com"
    det = BuiltinDetector()
    findings = det.run(url, fp.client)
    print(f"\n内置检测器执行完毕，产生 {len(findings)} 条发现：")
    for f in findings:
        print(f"  [{f.severity}] {f.item_id}  {f.title}  (证据级别 {f.evidence_level}, 工具 {f.source_tool})")
    if det.errors:
        print(f"\n检测器异常（{len(det.errors)} 条，不影响其他规则）：")
        for e in det.errors:
            print(f"  - {e}")
