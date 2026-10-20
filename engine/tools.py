# -*- coding: utf-8 -*-
"""
外部工具适配层
==============
职责：探测本机可用的安全工具，把「工具存在性」与「扫描逻辑」解耦。

设计原则：
  - 工具缺失不导致扫描失败。缺 nuclei 时用内置检测器降级，引擎照常出结论，
    并在报告中如实标注「该项由内置检测器覆盖，未使用 nuclei 模板」。
  - 工具能力显式声明。每个工具登记它负责哪些检查项，供报告附录列出。
  - 版本落盘。附录要求记录工具与版本，便于复现。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from engine import binlocate
except ImportError:  # 以顶层模块方式导入时（sys.path 指向 engine/ 自身）
    import binlocate  # type: ignore[no-redef]


@dataclass
class ToolSpec:
    """一个外部工具的登记信息。"""

    key: str
    name: str
    binary: str
    version_args: list[str]
    covers: list[str]          # 覆盖的检查项 ID 前缀或具体 ID
    purpose: str
    optional: bool = True
    install_hint: str = ""
    fallback: str = ""         # 缺失时的降级方案
    version_pattern: str = ""  # 版本输出必须匹配的正则，用于识别同名不同源的工具
    version_regex: str = ""    # 从版本输出中精确提取版本号的正则（第一个捕获组）
    wrong_tool_hint: str = ""  # 命中同名但非目标工具时的说明


@dataclass
class ToolStatus:
    spec: ToolSpec
    available: bool = False
    path: str = ""
    version: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.spec.key,
            "name": self.spec.name,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "purpose": self.spec.purpose,
            "covers": self.spec.covers,
            "fallback": self.spec.fallback if not self.available else "",
            "error": self.error,
        }


# ------------------------------------------------------------------------------
# 工具登记表
# ------------------------------------------------------------------------------
TOOL_REGISTRY: list[ToolSpec] = [
    ToolSpec(
        key="nuclei",
        name="Nuclei",
        binary="nuclei",
        version_args=["-version"],
        covers=["EXT-SC", "WSTG-CONF", "WSTG-INFO", "EXT-CL"],
        purpose="模板化 CVE / 配置错误 / 信息泄露 / 子域接管检测",
        optional=True,
        install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        fallback="内置指纹比对 + 已知路径探测（覆盖度较低，报告将标注）",
        version_pattern=r"[Nn]uclei",
        version_regex=r"Version:\s*(v?[\d.]+)",
    ),
    ToolSpec(
        key="httpx",
        name="httpx (ProjectDiscovery)",
        binary="httpx",
        version_args=["-version"],
        covers=["WSTG-INFO", "WSTG-CONF"],
        purpose="HTTP 存活探测、状态码、标题、技术指纹",
        optional=True,
        install_hint="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        fallback="内置 requests 探针",
        version_pattern=r"httpx\s+v?\d+\.\d+|projectdiscovery",
        wrong_tool_hint=(
            "检测到的是 Python httpx 客户端 CLI，非 ProjectDiscovery httpx 扫描器，"
            "不具备批量探测能力，按缺失处理"
        ),
    ),
    ToolSpec(
        key="subfinder",
        name="subfinder",
        binary="subfinder",
        version_args=["-version"],
        covers=["WSTG-INFO-01", "WSTG-INFO-04"],
        purpose="子域名枚举",
        optional=True,
        install_hint="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        fallback="证书透明度日志（crt.sh）+ 公共 DNS 查询",
        version_pattern=r"subfinder",
    ),
    ToolSpec(
        key="nmap",
        name="Nmap",
        binary="nmap",
        version_args=["--version"],
        covers=["WSTG-CONF-01", "WSTG-CONF-02"],
        purpose="端口开放探测与服务识别",
        optional=True,
        install_hint="https://nmap.org/download.html",
        fallback="内置 TCP 连接探测（仅常见端口）",
        version_pattern=r"Nmap version",
    ),
    ToolSpec(
        key="sqlmap",
        name="sqlmap",
        binary="sqlmap",
        version_args=["--version"],
        covers=["WSTG-INPV-05"],
        purpose="SQL 注入深度验证（须显式授权后启用）",
        optional=True,
        install_hint="pip install sqlmap",
        fallback="内置报错型注入探针（仅错误回显场景）",
        version_pattern=r"sqlmap|#stable|#pip",
        version_regex=r"([\d.]+#(?:pip|stable))",
    ),
    ToolSpec(
        key="openssl",
        name="OpenSSL",
        binary="openssl",
        version_args=["version"],
        covers=["WSTG-CRYP-01", "WSTG-CRYP-02", "WSTG-CRYP-03"],
        purpose="TLS 配置与证书链检测",
        optional=False,
        install_hint="随 Git for Windows 提供",
        fallback="内置 SSL 套件探测",
        version_pattern=r"OpenSSL",
    ),
    ToolSpec(
        key="curl",
        name="curl",
        binary="curl",
        version_args=["--version"],
        covers=[],
        purpose="原始 HTTP 请求复核（PoC 复现用）",
        optional=False,
        install_hint="Windows 10+ 内置",
        fallback="requests 库",
        version_pattern=r"^curl\s",
    ),
]


class Toolchain:
    """工具链探测与调用封装。"""

    def __init__(self):
        self.status: dict[str, ToolStatus] = {}

    def probe_all(self, verbose: bool = False) -> dict[str, ToolStatus]:
        for spec in TOOL_REGISTRY:
            st = self._probe_one(spec)
            self.status[spec.key] = st
            if verbose:
                mark = "✓" if st.available else "·"
                ver = st.version or ("未安装" if not st.error else st.error)
                print(f"  {mark} {st.spec.name:<12} {ver}")
        return self.status

    @staticmethod
    def _known_path(binary: str) -> str | None:
        """PATH 之外按已知安装位置查找工具。

        候选与优先级统一收在 `engine/binlocate.py`：
        环境变量 → 当前 Python 环境 → 用户目录约定位置 → 包内 tools/ → 历史路径兜底。

        原先这里写死的是本机绝对路径（`C:/Users/<用户名>/...`）——
        本机没问题，但把这套工具链拷到另一台电脑（用户名不同）就会
        一个候选都命中不了：工具被误判成「未安装」→ 检测静默降级，
        而报告上只会写一句「未安装」，看不出其实是**路径没找对**。
        """
        return binlocate.locate(binary)

    def _probe_one(self, spec: ToolSpec) -> ToolStatus:
        st = ToolStatus(spec=spec)
        path = shutil.which(spec.binary) or self._known_path(spec.binary)
        if not path:
            st.error = "未找到可执行文件"
            return st
        try:
            proc = subprocess.run(
                [path] + spec.version_args,
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
                # stdin 必须显式关掉：pip 版 sqlmap 的 `--version` 打印完版本号
                # 会「Press Enter to continue...」等输入。探测进程没有键盘可等
                # → 一直挂到超时 → 工具被误判成「未安装」，
                # 而报告上只会写一句「版本探测失败」，看不出它其实装得好好的
                # （红线 27：工具不可用 ≠ 目标没问题，而这个「不可用」是假的）。
                stdin=subprocess.DEVNULL,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            st.version = self._extract_version(out)
            if spec.version_regex:
                m = re.search(spec.version_regex, out)
                if m:
                    st.version = m.group(1)
        except Exception as e:  # noqa: BLE001
            st.version = ""
            st.error = f"版本探测失败：{type(e).__name__}"
            return st

        # 身份校验：同名不同源的工具会被误认为目标工具（如 Python httpx vs
        # ProjectDiscovery httpx）。版本输出不匹配特征时按缺失处理，并在报告中说明。
        if spec.version_pattern:
            if not re.search(spec.version_pattern, out, re.MULTILINE):
                st.available = False
                st.error = spec.wrong_tool_hint or "可执行文件存在但输出特征不匹配，疑似同名不同源工具"
                st.version = st.version or ""
                return st

        st.available = True
        st.path = path
        return st

    @staticmethod
    def _extract_version(out: str) -> str:
        """从工具输出里提取版本号，尽量取首行有效内容。"""
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            return line[:120]
        return ""

    def has(self, key: str) -> bool:
        st = self.status.get(key)
        return bool(st and st.available)

    def missing_required(self) -> list[ToolStatus]:
        """返回缺失的必需工具（非 optional）。"""
        return [st for st in self.status.values() if not st.available and not st.spec.optional]

    def report_rows(self) -> list[dict[str, Any]]:
        """生成报告附录用的工具清单。"""
        return [st.to_dict() for st in self.status.values()]

    def fallback_notes(self) -> list[str]:
        """生成降级说明，供报告如实标注。"""
        notes = []
        for st in self.status.values():
            if not st.available:
                tag = "必需工具缺失" if not st.spec.optional else "可选工具缺失"
                notes.append(
                    f"{tag}：{st.spec.name} 不可用（{st.error}），"
                    f"相关检查项改用降级方案 —— {st.spec.fallback or '内置实现'}"
                )
        return notes

    def to_json(self) -> str:
        return json.dumps(
            {"tools": self.report_rows(), "fallbacks": self.fallback_notes()},
            ensure_ascii=False,
            indent=2,
        )


def detect_source_root() -> Path:
    """返回本工程根目录，便于其他模块定位清单/配置。"""
    return Path(__file__).resolve().parent.parent


if __name__ == "__main__":
    print("本机安全工具链探测：")
    tc = Toolchain()
    tc.probe_all(verbose=True)
    print()
    miss_req = tc.missing_required()
    if miss_req:
        print("⚠ 必需工具缺失：", ", ".join(s.spec.name for s in miss_req))
    else:
        print("必需工具齐备。")
    fb = tc.fallback_notes()
    if fb:
        print("\n降级说明：")
        for n in fb:
            print(f"  - {n}")
