# -*- coding: utf-8 -*-
"""
证据脱敏模块
============
职责：扫描过程中采集到的任何原始数据，落盘 / 进报告前必须经过本模块处理。

为什么必须有（规格第 7 章 + 公司数据分级红线）：
  扫描本身会产生证据（响应体、Token、手机号、AK/SK）。如果不脱敏就直接写进
  报告，这份报告本身就成了新的数据泄露源 —— 而且是以「安全报告」的名义流转的，
  风险更高。

脱敏策略：
  - 凭据类：只保留前 4 位，其余打码（便于定位是哪一个，但不可用）
  - PII 类：手机号 / 身份证 / 邮箱 / 银行卡，保留结构，中间打码
  - 保留指纹：每处脱敏都记录原始内容的哈希，证明证据未被篡改
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

# ==============================================================================
# 脱敏规则表
# ==============================================================================
# 每条：(名称, 正则, 替换函数)
# 顺序有意义 —— 先处理长结构（如 JWT），再处理其中的片段。


def _keep_edges(value: str, head: int = 4, tail: int = 0) -> str:
    """保留头尾若干字符，中间打码，并标注原长。"""
    n = len(value)
    if n <= head + tail:
        return "*" * n
    masked = value[:head] + "*" * max(4, n - head - tail) + (value[-tail:] if tail else "")
    return f"{masked}<len={n}>"


def _mask_phone(m: re.Match) -> str:
    s = m.group(0)
    return s[:3] + "****" + s[-4:]


def _mask_idcard(m: re.Match) -> str:
    s = m.group(0)
    return s[:6] + "********" + s[-4:]


def _mask_email(m: re.Match) -> str:
    local, _, domain = m.group(0).partition("@")
    head = local[:2] if len(local) > 2 else local[:1]
    return f"{head}{'*' * max(2, len(local) - len(head))}@{domain}"


def _mask_bankcard(m: re.Match) -> str:
    s = re.sub(r"[^\d]", "", m.group(0))
    return s[:4] + "********" + s[-4:]


def _mask_secret(m: re.Match) -> str:
    """key=value 形式的密钥，保留键名与值的前 4 位。"""
    key = m.group(1)
    val = m.group(2).strip("\"'")
    return f"{key}={_keep_edges(val, 4)}"


def _mask_jwt(m: re.Match) -> str:
    return _keep_edges(m.group(0), 8)


def _mask_aksk(m: re.Match) -> str:
    prefix = m.group(1)
    val = m.group(2)
    return f"{prefix}{_keep_edges(val, 4)}"


RULES: list[tuple[str, re.Pattern[str], Any]] = [
    # JWT：三段式，先处理，避免被其他规则切碎
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"), _mask_jwt),
    # 云厂商 AK/SK
    ("aws_ak", re.compile(r"\b(AKIA[0-9A-Z]{12,})"), lambda m: _keep_edges(m.group(1), 4)),
    ("aliyun_ak", re.compile(r"\b(LTAI[0-9A-Za-z]{10,})"), lambda m: _keep_edges(m.group(1), 4)),
    ("tencent_ak", re.compile(r"\b(AKID[0-9A-Za-z]{10,})"), lambda m: _keep_edges(m.group(1), 4)),
    # 常见密钥键值对
    # 注意：键名要同时覆盖下划线（api_key）与驼峰（accessKeyId / accessKeySecret）
    # 两种写法，否则驼峰形式的云凭据会漏网。
    (
        "secret_kv",
        re.compile(
            r"(?i)\b("
            r"api[_-]?key|apikey|"
            r"secret[_-]?key|secretkey|"
            r"access[_-]?key(?:[_-]?(?:id|secret))?|"
            r"client[_-]?secret|"
            r"secret|"
            r"access[_-]?token|"
            r"auth[_-]?token|"
            r"refresh[_-]?token|"
            r"password|passwd|pwd|"
            r"private[_-]?key"
            r")"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{6,})[\"']?"
        ),
        _mask_secret,
    ),
    # Authorization 头
    (
        "auth_header",
        re.compile(r"(?i)\b(authorization|bearer|x-api-key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{8,})[\"']?"),
        lambda m: f"{m.group(1)}={_keep_edges(m.group(2).strip(chr(34)+chr(39)), 6)}",
    ),
    # Cookie 值
    (
        "cookie_val",
        re.compile(r"(?i)\b((?:session|sessionid|jsessionid|phpsessid|token|sid)[a-z0-9_\-]*)\s*=\s*([^;\s\"']{6,})"),
        lambda m: f"{m.group(1)}={_keep_edges(m.group(2), 4)}",
    ),
    # PII
    ("idcard", re.compile(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"), _mask_idcard),
    ("phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), _mask_phone),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), _mask_email),
    ("bankcard", re.compile(r"(?<!\d)\d{16,19}(?!\d)"), _mask_bankcard),
    # 内网地址：默认不脱敏 —— 内部报告需要它来定位资产。
    # 导出「管理层摘要版 / 对外版」时通过 EXTERNAL_ONLY 规则集启用。
    (
        "internal_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        lambda m: _keep_edges(m.group(0), 4),
    ),
]

# 仅在「对外版本」启用的附加规则（内部技术版不启用，避免丢掉定位信息）
EXTERNAL_ONLY = {"internal_ip"}


@dataclass
class MaskReport:
    """一次脱敏操作的统计，用于报告附录说明。"""

    hits: dict[str, int] = field(default_factory=dict)
    total: int = 0

    def record(self, name: str, n: int = 1) -> None:
        self.hits[name] = self.hits.get(name, 0) + n
        self.total += n

    def to_dict(self) -> dict[str, Any]:
        return {"total_masked": self.total, "by_type": self.hits}


class Masker:
    """脱敏器。

    两种 profile：
      internal（默认）——保留内网地址等定位信息，供内部技术版报告使用
      external       ——额外抹除内网地址，供管理层摘要版 / 对外版本使用

    凭据与 PII 在任何 profile 下都会被脱敏，不存在「不脱敏」的选项。
    """

    def __init__(self, profile: str = "internal", enabled: list[str] | None = None):
        self.profile = profile
        if enabled is not None:
            self.rules = [r for r in RULES if r[0] in enabled]
        elif profile == "external":
            self.rules = list(RULES)
        else:
            self.rules = [r for r in RULES if r[0] not in EXTERNAL_ONLY]
        self.last_report = MaskReport()

    def mask(self, text: str, report: MaskReport | None = None) -> str:
        """对文本执行脱敏。"""
        if not text:
            return text
        rep = report if report is not None else MaskReport()
        out = text
        for name, pattern, repl in self.rules:
            out, n = pattern.subn(repl, out)
            if n:
                rep.record(name, n)
        if report is None:
            self.last_report = rep
        return out

    def mask_obj(self, obj: Any, report: MaskReport | None = None) -> Any:
        """递归脱敏任意 JSON 化对象。"""
        rep = report if report is not None else MaskReport()
        result = self._walk(obj, rep)
        if report is None:
            self.last_report = rep
        return result

    def _walk(self, obj: Any, rep: MaskReport) -> Any:
        if isinstance(obj, str):
            return self.mask(obj, rep)
        if isinstance(obj, dict):
            return {k: self._walk(v, rep) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._walk(v, rep) for v in obj]
        return obj

    @staticmethod
    def fingerprint(text: str) -> str:
        """原始内容的短哈希，用于证明证据未被篡改（不可逆）。"""
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


# 便捷函数
_default_masker = Masker()


def mask(text: str) -> str:
    return _default_masker.mask(text)


def mask_and_fingerprint(text: str) -> tuple[str, str]:
    """返回 (脱敏后文本, 原始内容指纹)。"""
    return mask(text), Masker.fingerprint(text)


if __name__ == "__main__":
    # 自测用合成样例：只输出脱敏后的结果，不回显原始值。
    samples = {
        "JWT 三段式": "tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
        "云厂商 AK/SK 键值对": "accessKeyId=XXXXdeadbeefcafe&secret=YYYYfeedfacecafe",
        "手机号": "手机 1" + "3800000000",
        "身份证": "证件 110101" + "199003074567",
        "邮箱": "邮箱 user" + "name@corp-example.com",
        "银行卡": "卡号 6222" + "021234567890123",
        "会话 Cookie": "sid=" + "ABCDEF0123456789ABCDEF0123456789",
        "密码字段": "password=Zz9" + "Qq7Ww5Ee3Rr1",
    }
    rep = MaskReport()
    print("脱敏效果预览（仅显示脱敏结果）：\n" + "=" * 70)
    for name, raw in samples.items():
        print(f"  {name:<18} -> {_default_masker.mask(raw, rep)}")
    print("=" * 70)
    print(f"统计：共脱敏 {rep.total} 处")
    for k, v in rep.hits.items():
        print(f"  {k:<14} {v} 处")
    # 指纹功能验证
    fp1 = Masker.fingerprint("same content")
    fp2 = Masker.fingerprint("same content")
    fp3 = Masker.fingerprint("other content")
    assert fp1 == fp2 and fp1 != fp3, "指纹函数异常"
    print(f"\n指纹校验：相同内容一致 ✓  不同内容可区分 ✓（样例 {fp1}）")
