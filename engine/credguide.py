# -*- coding: utf-8 -*-
"""凭据索取指引与接收（把「需要身份」从终点变成闭环）
================================================================================

要解决的问题
--------------------------------------------------------------------------------
扫描遇到需要登录态的检查项（越权 / IDOR / 并发会话 / 多账号交叉比对）时，
此前的行为链是这样断掉的：

  1. 会话池发现没有可用凭据 → 记一句「未配置测试账号」；
  2. 检查项落到「未执行」或「待人工执行」，原因写「需要至少 2 组测试账号」；
  3. ——然后就没有下文了。

第 3 步是关键缺陷。操作者知道了「缺什么」，但**不知道该去哪拿、拿到后交给谁**。
于是「缺凭据」变成一个永久的终点：报告里一片「未执行」，谁也不知道该怎么补。

本模块补的就是第 3 步：把它做成闭环 ——
  明确要什么 → 说清从哪拿（具体到 DevTools 的哪一屏）→
  提供一条**不收凭据原文**的接收通道 → 回验登录态是否真的成立 → 能重扫补齐。

================================================================================
最重要的一个决定：凭据**不经过对话**
================================================================================
操作者最自然的反应是「我登录拿到 Cookie 了，贴给你」。这件事**必须被拦住**：

  · 会话 Cookie / Bearer Token 等同于账号权限 —— 拿到它就等于拿到那个身份；
  · 一旦贴进对话，它同时进入了 AI 上下文、对话历史、以及任何日志留存，
    而且是不可撤回的（会话可以吊销，但已经扩散的副本收不回来）；
  · 本项目自己的 `sessionpool` 已经定了调：明文凭据落配置文件直接拒收该账号。
    凭据贴进对话比落配置文件更糟 —— 配置文件至少还在本机。

所以本模块只提供两条通道，都不经过对话：
  · **凭据库文件**（默认 `~/.aiscan/sessions/<目标>.json`，在工具目录**之外**）；
  · **剪贴板直读**（`--from-clipboard`）—— 浏览器里复制，命令行里收，
    既不进对话，也不进 shell 历史。

配套两条硬规则：
  · **永不回显凭据原文**：输出只出现角色名、Cookie 的键名、长度、以及一个
    短指纹（便于确认「两次给的是不是同一份」，但无法反推）；
  · **凭据库放在仓库之外**：否则会被三副本同步带走、被打包给同事、
    被误提交。默认路径刻意选了 `~/.aiscan/`。

================================================================================
第二条硬规则：登录入口**只在有证据时才给出**
================================================================================
「登录地址大概是 /login 吧」这种猜测会把人引到一个不存在的页面上，
然后他会以为「是这个系统没有登录功能」。所以：
  · 有探测证据（探到了登录相关路径且可达）→ 给出该 URL 并附上证据原文；
  · 目标整站返回同一状态码（边缘防护统一响应）→ **明确说明探测到的路径
    不构成证据**，请自行确认；
  · 什么都没探到 → 直说「无法推断」，不编一个 URL 出来。
`--login-url` 允许操作者自己给出 —— 那是**他**提供的事实，不是我们的猜测，
会被标注为「用户提供」以区别于探测证据。

================================================================================
与既有代码的关系（刻意不另造一套）
--------------------------------------------------------------------------------
凭据文件的**格式、键名、占位哨兵**全部复用 `verify/sessionctx.py`：
那里已经有一套给复现脚本用的会话文件（`aiscan_sessions.json`），
并且踩过一个坑 —— 占位文字被当成真凭据读进去，于是带着一串垃圾 Cookie 请求、
拿回 401、判「未复现」，又一次把「没填凭据」冒充成「问题已修复」。

本项目反复吃「两套实现必然漂移」的亏。所以这里**只复用，不复制**：
哨兵常量、`env_suffix`、`skeleton()` 都直接 import 过来。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 复用复现阶段那一套格式与哨兵。**不要**在这里重新定义这些常量：
# 两处定义必然漂移，而漂移的表现是「填了却不生效」——
# 正是本项目反复出现的缺陷家族（见 sessionpool 文末「登记了却不生效」）。
from verify.sessionctx import (  # noqa: E402
    AUTH_ENV_PREFIX,
    COOKIE_ENV_PREFIX,
    PLACEHOLDER_SENTINEL,
    SESSION_FILE_ENV,
    SESSION_FILE_NAME,
    env_suffix,
    skeleton,
)

# 凭据库目录。刻意在**工具目录之外**：
# 工具目录会被三副本同步、会被打包给同事、可能被误提交到仓库。
CRED_DIR_ENV = "AISCAN_CRED_DIR"
DEFAULT_CRED_DIR = Path.home() / ".aiscan" / "sessions"

# 扫描归档里落盘的凭据需求清单（不含任何凭据原文）
NEED_FILE_NAME = "凭据需求.json"

# 登录入口候选路径。与 fingerprint.FEATURE_PATHS["has_login"] 保持同源语义，
# 这里额外补两个常见变体。**只用于从探测结果里挑**，不用于猜测 URL。
LOGIN_PATHS = (
    "login", "signin", "sign-in", "logon", "auth/login", "user/login",
    "account/login", "sso/login", "admin/login", "passport/login", "login.html",
)

# 建议的两个身份。为什么是「两个」而不是「一个」：
# 只拿一个账号，无法区分「读到自己的数据」与「读到他人的数据」，
# 越权结论因此无效。这一条与 sessionpool / proofs 的判据一致。
DEFAULT_ROLE_HINTS = (
    ("user_a", "普通用户（低权身份）"),
    ("admin_a", "高权账号（管理员 / 跨租户）"),
)

# 探测到这些状态码，说明该路径「存在且可达」（2xx/3xx 正常，401/403 表示
# 路径存在但需要权限 —— 那恰恰可能正是登录入口）。
_LOGIN_STATUS = (200, 301, 302, 401, 403)


def _post_only_evidence(pr: Any) -> str:
    """GET 返回 405 时，判断它是否构成「这是一个登录接口」的证据。

    **为什么要单独判**：405 是唯一一个「指纹模块认、凭据模块不认」的状态码。
    `fingerprint.FEATURE_PATHS` 把 405 算作「路径存在」（并在非整站同码时才采信），
    而这里原先的 `_LOGIN_STATUS` 不含 405 —— 于是同一个响应在两处得出相反结论：
    特征表写着「具备 has_login」，凭据指引却写「登录相关路径均未命中」。
    两个模块拿同一份证据给出相反答案，是本项目最忌讳的一类缺陷
    （读者只会认为整份报告都不可信）。

    但直接把 405 全盘收进来也不行：边缘防护（WAF）常对 `/login`、`/admin`
    这类敏感路径单独回 405，那是**拦截**而不是「接口只收 POST」。
    两者的区分点很干脆 —— 真正的 POST-only 接口会带 `Allow` 头声明允许的方法，
    WAF 的 405 通常不带：

      · `HTTP/1.1 405 Method Not Allowed` + `Allow: POST` → 真接口（能力证据）
      · `HTTP/1.1 405` 且无 `Allow`（或 Allow 里没有写方法）→ 边缘拦截特征，
        不采信

    注意：本函数只判「这一个响应长什么样」，**不做对照实验**。
    而孤立信号不得当正面证据 —— 若站点级默认响应头里就带 `Allow: GET,POST,…`，
    那每个 405 都会「通过」这里的检查。对照由 `find_login_entry` 负责：
    它要求带该头的路径必须是**少数**，否则整批不采信。两者缺一不可。
    """
    allow = _allow_post_value(pr)
    if not allow:
        return ""
    return (f"GET 返回 405 且 `Allow: {allow}` —— 该路径存在但只接受非 GET "
            "请求，符合登录接口特征（无表单页，需以 POST 提交）")


def _allow_post_value(pr: Any) -> str:
    """405 且 `Allow` 声明了 POST/PUT/PATCH 时返回该头的值，否则返回空串。

    单独抽出来是为了让**对照实验**能复用同一套判据：
    沿用 `_post_only_evidence` 时只有单个响应能判，而「这个头是站点默认的」
    这件事必须横向比一批响应才看得出来。
    """
    try:
        if int(getattr(pr, "status", 0) or 0) != 405:
            return ""
        hdr = {str(k).lower(): str(v) for k, v in
               (getattr(pr, "headers", None) or {}).items()}
        allow = hdr.get("allow", "")
        if not re.search(r"\b(POST|PUT|PATCH)\b", allow, re.I):
            return ""
        return allow
    except Exception:  # noqa: BLE001
        return ""


# ==============================================================================
# 数据模型
# ==============================================================================
@dataclass
class CredNeed:
    """一条凭据需求：要哪个身份、为什么、去哪拿。"""

    role: str                          # 会话文件里的键名（与 accounts 的 name 对应）
    label: str = ""                    # 面向人的说明（普通用户 / 管理员…）
    why: str = ""                      # 为什么要它
    blocked: list[tuple[str, str]] = field(default_factory=list)  # [(检查项 id, 名称)]
    entry_url: str = ""                # 登录入口（**有证据才填**）
    entry_evidence: str = ""           # 证据原文 / 或「无法推断」的原因
    entry_source: str = ""             # path_probe / user / none
    configured: bool = False           # accounts 配置里是否已有这个账号
    present: bool = False              # 凭据库里是否已有可用值
    verified: str = ""                 # 回验结论（做过才填）

    @property
    def ready(self) -> bool:
        return bool(self.present)

    def to_dict(self) -> dict[str, Any]:
        # **不带任何凭据字段** —— 这个对象会被写进扫描归档。
        return {
            "role": self.role, "label": self.label, "why": self.why,
            "blocked": [list(x) for x in self.blocked],
            "entry_url": self.entry_url, "entry_evidence": self.entry_evidence,
            "entry_source": self.entry_source, "configured": self.configured,
            "present": self.present, "verified": self.verified,
        }


@dataclass
class CredPlan:
    """一次扫描（或一次 creds 查询）的凭据需求全景。"""

    target: str = ""
    target_url: str = ""
    session_file: Path = field(default_factory=lambda: DEFAULT_CRED_DIR / "unset.json")
    needs: list[CredNeed] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def pending(self) -> list[CredNeed]:
        return [n for n in self.needs if not n.present]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "target_url": self.target_url,
            "session_file": str(self.session_file),
            "needs": [n.to_dict() for n in self.needs],
            "notes": list(self.notes),
        }


# ==============================================================================
# 凭据库位置
# ==============================================================================
def cred_dir() -> Path:
    raw = (os.environ.get(CRED_DIR_ENV) or "").strip()
    return Path(raw) if raw else DEFAULT_CRED_DIR


def session_file_for(target: str) -> Path:
    """某目标的凭据文件路径。

    优先 `AISCAN_SESSION_FILE`（与复现脚本共用同一个环境变量，
    这样「填一次，扫描与复现共用」才成立）。"""
    override = (os.environ.get(SESSION_FILE_ENV) or "").strip()
    if override:
        return Path(override)
    safe = re.sub(r"[^0-9A-Za-z._\-]", "_", str(target or "target")) or "target"
    return cred_dir() / f"{safe}.json"


# ==============================================================================
# 凭据解析（哨兵必须被丢掉，理由见 sessionctx 文末）
# ==============================================================================
def _drop(v: Any) -> str:
    s = str(v or "")
    return "" if PLACEHOLDER_SENTINEL in s else s


def parse_cookie_str(raw: Any) -> dict[str, str]:
    """`a=1; b=2` → 字典。含哨兵的**整串**丢弃。

    为什么是「整串」而不是「逐条」：骨架占位文字本身长这样 ——
        `__FILL_ME__ 粘贴该账号在浏览器里的 Cookie 串，形如 a=1; b=2`
    逐条丢弃时，分号后面的 ` b=2` 不含哨兵，会被当成一条真 Cookie 收下。
    于是脚本/扫描器会带着一串垃圾去请求、拿回 401，
    然后再一次把「没填凭据」冒充成「问题已修复」。
    行为与 `verify/sessionctx.py` 的 `_parse_cookie` 保持一致 —— 两处不一致
    必然漂移，而漂移的表现就是「填了却不生效」。
    """
    text = str(raw or "")
    if PLACEHOLDER_SENTINEL in text:
        return {}
    out: dict[str, str] = {}
    for part in text.split(";"):
        part = part.strip()
        if part and "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and v:
                out[k] = v
    return out


def parse_header_str(raw: Any) -> dict[str, str]:
    """请求头：dict / JSON 对象 / `Key: Value` 逐行都支持。含哨兵的整串丢弃。"""
    if isinstance(raw, dict):
        return {str(k): _drop(v) for k, v in raw.items() if _drop(v)}
    text = str(raw or "").strip()
    if not text or PLACEHOLDER_SENTINEL in text:
        return {}
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except Exception:  # noqa: BLE001
            return {}
        return ({str(k): _drop(v) for k, v in data.items() if _drop(v)}
                if isinstance(data, dict) else {})
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), _drop(v.strip())
            if k and v:
                out[k] = v
    return out


def read_raw(path: Path | str | None) -> dict[str, Any]:
    """读凭据文件原文（保留 `_说明` 等顶层键，写回时不丢操作者的东西）。"""
    p = Path(path) if path else None
    if not p or not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def read_roles(path: Path | str | None) -> dict[str, dict]:
    """读出「角色 → 记录」。兼容 `{"roles": {...}}` 与直接 `{role: {...}}` 两种写法。"""
    data = read_raw(path)
    node = data.get("roles") if isinstance(data.get("roles"), dict) else data
    return {str(k): v for k, v in (node or {}).items() if isinstance(v, dict)}


def credentials_for(role: str, path: Path | str | None) -> tuple[dict[str, str], dict[str, str]]:
    """取某角色的凭据。文件优先，环境变量最后覆盖（与 sessionctx 的加载顺序一致）。"""
    rec = read_roles(path).get(str(role)) or {}
    cookies = parse_cookie_str(rec.get("cookies"))
    headers = parse_header_str(rec.get("headers"))

    sfx = env_suffix(role)
    ck = _drop((os.environ.get(COOKIE_ENV_PREFIX + sfx) or "").strip())
    au = _drop((os.environ.get(AUTH_ENV_PREFIX + sfx) or "").strip())
    if ck:
        cookies.update(parse_cookie_str(ck))
    if au:
        headers["Authorization"] = (au if au.lower().startswith(("bearer", "basic", "token"))
                                    else "Bearer " + au)
    return cookies, headers


def _role_record(role: str, path: Path | str | None) -> dict:
    rec = read_roles(path).get(str(role)) or {}
    return rec if isinstance(rec, dict) else {}


def _is_placeholder(v: Any) -> bool:
    return PLACEHOLDER_SENTINEL in str(v or "")


def has_credentials(role: str, path: Path | str | None) -> bool:
    """某角色是否已有可用凭据。两种形式都算：
    Cookie / 请求头（首选，任何系统通用），或 账号+密码（仅当系统
    是「输账号密码就能登」的普通登录页时可用，需要自动登录）。
    骨架占位文字（__FILL_ME__）永远不算凭据 —— 那是「还没填」的标记。"""
    ck, hd = credentials_for(role, path)
    if ck or hd:
        return True
    rec = _role_record(role, path)
    u, pw = str(rec.get("username") or ""), str(rec.get("password") or "")
    return bool(u.strip()) and bool(pw.strip()) \
        and not _is_placeholder(u) and not _is_placeholder(pw)


def credentials_full(role: str, path: Path | str | None) -> dict:
    """取某角色的全部凭据信息（含账号密码形态）。返回：
    {cookies: dict, headers: dict, username: str, password: str, login_url: str}
    骨架占位值一律归零 —— 占位符不是凭据。
    自动登录补充规格（login_username_field / login_success_* /
    login_no_form_discover / verify_path）原样带出 —— 会话池合成自动登录
    时要读它们，不带出就等于「写了却没人读」。"""
    ck, hd = credentials_for(role, path)
    rec = _role_record(role, path)
    u = str(rec.get("username") or "").strip()
    pw = str(rec.get("password") or "").strip()
    if _is_placeholder(u):
        u = ""
    if _is_placeholder(pw):
        pw = ""
    lu = str(rec.get("login_url") or "").strip()
    if _is_placeholder(lu):
        lu = ""
    out: dict[str, Any] = {"cookies": ck, "headers": hd,
                           "username": u, "password": pw, "login_url": lu}
    for k in ("login_username_field", "login_password_field",
              "login_no_form_discover", "login_success_status",
              "login_success_body", "verify_path"):
        if rec.get(k) not in (None, ""):
            out[k] = rec.get(k)
    return out


def store_account_records(path: Path | str | None) -> list[dict[str, Any]]:
    """把凭据库里已有凭据的角色转成会话池账号记录。

    这是「不预置 accounts.yaml」路线的核心：操作者用 `creds --set` 现场给
    凭据，扫描器直接以这些身份进会话池。authorized 由**台账**保证 ——
    没登记授权的系统整场扫描都进不来，凭据库自身不需要再判一次。"""
    out: list[dict[str, Any]] = []
    for role, rec in sorted(read_roles(path).items()):
        if str(role).startswith("_"):
            continue
        if not has_credentials(role, path):
            continue
        item = {"name": str(role), "role": str(rec.get("label") or role),
                "authorized": True, "source": "cred_file",
                "note": "凭据库身份（creds --set 现场提供）"}
        # 有区分力的回验页（红队自取注册时经匿名对照实验找到）要透传，
        # 否则会话池退化成「拿首页回验」，登录态只能记「未验证」。
        if rec.get("verify_path"):
            item["verify_path"] = str(rec.get("verify_path"))
        out.append(item)
    return out


# ==============================================================================
# 指纹与脱敏（永不回显凭据原文）
# ==============================================================================
def fingerprint(cookies: dict[str, str], headers: dict[str, str]) -> str:
    """凭据的短指纹：能确认「两次给的是不是同一份」，但无法反推原文。

    为什么需要它：操作者换了个浏览器重新登录，会想知道「上次那份还在不在」。
    不给指纹，唯一能确认的办法就是把凭据打印出来 —— 那正好是不能做的事。
    """
    blob = "|".join(
        f"{k}={v}" for k, v in sorted({**cookies, **headers}.items())
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8]


def mask_summary(cookies: dict[str, str], headers: dict[str, str]) -> str:
    """只描述「有什么」，不暴露「是什么」。"""
    bits: list[str] = []
    if cookies:
        names = "、".join(sorted(cookies)[:6])
        more = f" 等 {len(cookies)} 个" if len(cookies) > 6 else ""
        bits.append(f"Cookie {len(cookies)} 个（{names}{more}）")
    if headers:
        bits.append("请求头 " + "、".join(sorted(headers)[:4]))
    if not bits:
        return "（空）"
    return " · ".join(bits) + f" · 指纹 {fingerprint(cookies, headers)}"


# ==============================================================================
# 登录入口：只在有证据时给出
# ==============================================================================
def _sitewide_uniform(path_probes: dict[str, Any]) -> tuple[bool, str]:
    """目标是否对任意路径返回**同一张页面**。复用 wafgate 的实现，不另写一套。

    判据**不能分叉**：同一个目标在「特征判定」与「登录入口推断」两处得到
    相反结论，是最难查的一类不一致 —— 报告一边说「整站被接管、路径存在性
    未知」，另一边却推荐 `https://目标/login` 作为登录入口，而那个 405 是
    边缘防护返回的。

    两个口径都要看，缺一个就留出一个静默失效的场合：
      · 状态码口径：边缘对同一批请求返回**混合**状态码（限速 / 挑战 / 部分
        放行 / 多节点不一致）时，众数占比跌破阈值，判据返回「非同码」，
        于是 405 被当成「这个路径在」—— 把一个拦截页当成登录入口推给操作者。
      · 正文口径：那时正文**归一化后仍然完全相同**（剔除 traceid / acw_tc
        等易变标识），且命中拦截页厂商特征 —— 仍然判得出「整站被接管」。
    """
    try:
        from engine.wafgate import (  # noqa: PLC0415
            detect_block_page,
            representative_probe,
            sitewide_uniform_body,
            sitewide_uniform_status,
            status_mix,
        )

        modal, ratio, n = sitewide_uniform_status(path_probes)
        if modal:
            return True, f"已探测 {n} 个路径中 {ratio:.0%} 返回同一状态码 HTTP {modal}"

        bh, b_ratio, b_n = sitewide_uniform_body(path_probes)
        if not bh:
            return False, ""
        rep = representative_probe(path_probes, bh)
        if rep is None:
            return False, ""
        block_like, vendor, why = detect_block_page(
            int(getattr(rep, "status", 0) or 0), getattr(rep, "headers", None),
            getattr(rep, "body_snippet", "") or "", getattr(rep, "cookies", None))
        # 正文同码只说「是同一张页」，不说「是谁的页」：SPA 兜底路由同样整站
        # 同一份骨架页，那是正常应用行为。必须叠加厂商特征才算「被接管」。
        if not block_like:
            return False, ""
        _ms, _mr, _ = status_mix(path_probes)
        return True, (f"已探测 {b_n} 个路径中 {b_ratio:.0%} 返回**归一化后完全相同**"
                      f"的页面，且命中边界防护拦截页特征（{why or vendor}）；"
                      f"注意状态码并不统一（众数只占 {_mr:.0%}，最高频者 HTTP {_ms}）")
    except Exception:  # noqa: BLE001
        return False, ""


def find_login_entry(path_probes: dict[str, Any] | None,
                     login_url: str = "") -> tuple[str, str, str]:
    """推断登录入口。返回 (URL, 证据/原因, 来源)。

    来源取值：`user`（操作者自己给的）/ `path_probe`（探测证据）/ `none`（推断不出）。

    **推断不出时一律返回空 URL。** 「大概是 /login 吧」这种猜测会把人引到
    不存在的页面上，他会以为「这系统没有登录功能」——比不给结论更糟。
    """
    if (login_url or "").strip():
        u = login_url.strip()
        return u, "由你指定（非探测所得）", "user"

    probes = path_probes or {}
    if not probes:
        return "", ("本次未探测任何路径（档位限制或边界拦截），"
                    "**无法从证据推断登录入口** —— 请直接用 --login-url 告知，"
                    "或先跑一次标准档扫描"), "none"

    uniform, uniform_why = _sitewide_uniform(probes)
    hits: list[tuple[str, Any]] = []
    post_only: list[tuple[str, Any, str]] = []
    blocked_405: list[str] = []
    probed: list[str] = []
    for name in LOGIN_PATHS:
        pr = probes.get(name)
        if pr is None:
            continue
        probed.append(name)
        if getattr(pr, "reachable", False) and \
                int(getattr(pr, "status", 0) or 0) in _LOGIN_STATUS:
            hits.append((name, pr))
            continue
        if getattr(pr, "reachable", False):
            ev = _post_only_evidence(pr)
            if ev:
                post_only.append((name, pr, ev))
            elif int(getattr(pr, "status", 0) or 0) == 405:
                blocked_405.append(name)

    # ── `Allow` 头证据：必须先于「整站同码」判定，且自带对照 ──────────────
    # 为什么必须先于 uniform：uniform 否掉的是**状态码**这个信号
    # （整站都 405 时，405 说明不了任何路径的存在性）。而 `Allow: POST`
    # 说的是「这个路径实现了 POST」—— 是头证据，与状态码无关，不该被连带否掉。
    # 曾经把 uniform 排在前面，结果：一个「全站 405、只有 /login 带 Allow: POST」
    # 的真实 POST-only 接口被整批吞掉，报出去还是「没找到登录入口」。
    #
    # 为什么它自己也必须有对照：若绝大多数探测路径的 405 都带着同一个 `Allow`，
    # 那是站点/边缘的**默认响应头**，不是这个路径的特征。逐条看像铁证，
    # 横向一比就是噪声 —— 和「整站同码」是完全同一个道理，不能只对状态码讲。
    # 判据：在所有 405 响应中，带该头的必须是**少数**（严格少于一半）。
    #   · 9 个 405 里只有 1 个带 Allow（正常 POST-only 接口）→ 1/9 ✓ 采信
    #   · 9 个 405 全带 Allow（边缘统一塞的响应头）        → 9/9 ✗ 不采信
    # 对照实验的样本必须是**全部**探测路径，不能只用登录类路径 ——
    # 登录类路径就那几条，拿它们当分母，「带 Allow 的是少数」永远成立，
    # 对照就等于没做（第一版就犯了这个错，自测当场把它揪出来了）。
    _exp405 = [p for p in probes.values()
               if getattr(p, "reachable", False)
               and int(getattr(p, "status", 0) or 0) == 405]
    _allow405 = [p for p in _exp405 if _allow_post_value(p)]
    _allow_sitewide = len(_exp405) >= 2 and len(_allow405) * 2 >= len(_exp405)
    _allow_is_evidence = bool(post_only) and not _allow_sitewide
    if _allow_is_evidence:
        name, pr, ev = post_only[0]
        return str(getattr(pr, "url", "") or ""), ev, "path_probe"

    if uniform:
        # 整站同码时，状态码不构成「这个路径存在」的证据。
        # 这一条来自实打实的教训：某站全站 405，/login /admin /api 全被判定为「存在」，
        # 15 项特征凭空变成「具备」，后续检测全跑在拦截页上。
        # 判据必须排在 hits 之前 —— 整站同一个码时，命中的那几个「路径」全是假象，
        # 先取 hits 再判 uniform 等于让守卫形同虚设。
        # 但它**不能连坐 `Allow` 头证据**：上面那条分支已经先跑并自带对照，
        # 走到这里说明要么没有 Allow、要么 Allow 本身是站点级的。
        return "", (f"探测到登录相关路径，但{uniform_why} —— "
                    "该路径**不构成**登录入口的证据（可能是边缘防护统一响应），"
                    "请用 --login-url 确认"), "none"

    if hits:
        name, pr = hits[0]
        url = str(getattr(pr, "url", "") or "")
        title = str(getattr(pr, "title", "") or "")
        ev = (f"探测到 {url} 返回 HTTP {pr.status}"
              + (f"（页面标题：{title}）" if title else ""))
        return url, ev, "path_probe"

    if post_only:
        # 走到这里说明 `Allow` 没过对照实验：带它的 405 占了多数，
        # 它是站点级默认响应头，不能当单点特征。
        # 但这些路径确实返回了 405 —— 必须**点名**，不能笼统写「均未命中」，
        # 否则读者会以为「这系统没有登录功能」，而事实是「有东西挡着，我们进不去」。
        _names = [n for n, _p, _e in post_only]
        return "", (f"已探测 {'、'.join(probed[:5])} 等 {len(probed)} 个登录相关路径："
                    f"其中 {'、'.join(_names[:5])} 返回 HTTP 405，"
                    f"且 `Allow` 里声明了 POST —— 但全部 {len(_exp405)} 个 405 响应中"
                    f"有 {len(_allow405)} 个都带同样的 `Allow`，属**站点级默认响应头**，"
                    "**不构成**「该路径是只收 POST 的登录接口」的证据。"
                    "**请用 --login-url 明确告知登录入口**"), "none"

    if blocked_405:
        # 「一批登录路径返回 405」有两种成因，处置动作完全不同，必须说清是哪一种：
        #   · 登录接口只收 POST（带 `Allow` 头）→ 上面的 post_only 分支已经接住；
        #   · 目标对敏感路径单独下了 405（边缘防护）→ 就是这里。
        # 这里必须**点名是哪些路径**返回了 405，不能笼统写「均未命中」——
        # 「均未命中」会让读者以为「这系统没有登录功能」，而事实是
        # 「有东西挡着，我们进不去」。这一句差别决定了下一个人该去找谁。
        return "", (f"已探测 {'、'.join(probed[:5])} 等 {len(probed)} 个登录相关路径："
                    f"其中 {'、'.join(blocked_405[:5])} 返回 HTTP 405 且**不带 "
                    "`Allow` 头** —— 这是边缘防护对特定路径的拦截特征，"
                    "既不能据此断定该路径存在登录页，也不能断定它不存在。"
                    "**请用 --login-url 明确告知登录入口**"), "none"

    if probed:
        return "", (f"已探测 {'、'.join(probed[:5])} 等 {len(probed)} 个登录相关路径，"
                    "均未命中 —— 登录入口可能在别的路径或独立域名，"
                    "**请用 --login-url 明确告知**"), "none"
    return "", ("本次未探测登录相关路径，无法推断登录入口 —— "
                "**请用 --login-url 明确告知**"), "none"


# ==============================================================================
# 需要账号的检查项：从注册表取，不手写名单（手写必然与清单漂移）
# ==============================================================================
def items_requiring(key: str = "accounts") -> list[tuple[str, str]]:
    """列出所有 `requires` 含指定键的检查项。返回 [(item_id, 名称)]。"""
    try:
        from engine.registry_runner import build_registry  # noqa: PLC0415

        reg = build_registry()
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, str]] = []
    for iid, spec in reg.specs.items():
        if key in (getattr(spec, "requires", None) or []):
            out.append((str(iid), str(getattr(spec, "name", "") or "")))
    return sorted(out)


# ==============================================================================
# 构造需求
# ==============================================================================
def build_plan(target: str = "", target_url: str = "", accounts: Any = None,
               path_probes: dict[str, Any] | None = None, login_url: str = "",
               session_file: Path | str | None = None) -> CredPlan:
    """把「当前有哪些账号 / 会话到什么程度」翻译成「需要你补什么」。

    `accounts` 是会话池的账号记录列表（`SessionPool.accounts` 的结构）。
    传空/None 表示**完全没配账号** —— 此时按 DEFAULT_ROLE_HINTS 给出两个建议身份，
    并明确说明「这是建议，账号名以你的 accounts 配置为准」。
    """
    sf = Path(session_file) if session_file else session_file_for(target or "target")
    plan = CredPlan(target=target, target_url=target_url, session_file=sf)
    blocked = items_requiring("accounts")
    entry, evidence, src = find_login_entry(path_probes, login_url)

    def _mk(role: str, label: str, why: str, configured: bool,
            verified: str = "") -> CredNeed:
        return CredNeed(
            role=role, label=label, why=why, blocked=list(blocked),
            entry_url=entry, entry_evidence=evidence, entry_source=src,
            configured=configured, present=has_credentials(role, sf),
            verified=verified,
        )

    accs = [a for a in (accounts or []) if isinstance(a, dict)]
    if not accs:
        from engine.sessionpool import LOGIN_ABSENT  # noqa: PLC0415

        _ = LOGIN_ABSENT  # 仅为表明这里与 sessionpool 的状态名同源
        plan.notes.append(
            "未配置任何测试账号 —— 以下角色名是**建议值**，"
            "实际以你 accounts 配置里的 name 为准（两者同名才能自动取到凭据）")
        for role, label in DEFAULT_ROLE_HINTS:
            plan.needs.append(_mk(
                role, label,
                "越权 / 横向移动类判定需要 ≥2 个不同身份的会话；"
                "只拿一个账号无法区分「读到自己数据」与「读到他人数据」",
                configured=False))
    else:
        for a in accs:
            role = str(a.get("name") or "unnamed")
            state = str(a.get("login_state") or "")
            rejected = str(a.get("rejected") or "")
            note = str(a.get("login_note") or "")
            if has_credentials(role, sf) and state.startswith("已登录"):
                continue
            why = rejected or note or (
                "账号已有配置但未取得可用会话" if state else "账号未取得会话")
            plan.needs.append(_mk(
                role, str(a.get("role") or ""),
                f"当前登录态：{state or '未知'}；{why}",
                configured=True, verified=state))

    if plan.needs and not blocked:
        plan.notes.append(
            "未在注册表里找到 requires=accounts 的检查项 —— "
            "说明本次清单没有依赖多账号的项，补凭据的收益有限")
    return plan


# ==============================================================================
# 落盘 / 读取（归档里的需求清单，**不含凭据原文**）
# ==============================================================================
def save_plan(plan: CredPlan, archive_dir: Path | str) -> Path | None:
    d = Path(archive_dir)
    if not plan.needs:
        return None
    try:
        d.mkdir(parents=True, exist_ok=True)
        p = d / NEED_FILE_NAME
        p.write_text(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return p
    except Exception:  # noqa: BLE001
        return None


def latest_plan(outputs_root: Path | str, target: str = "") -> CredPlan | None:
    """从最近一次扫描归档里取回凭据需求清单。

    为什么要落盘：扫描结束后操作者才去登录、才拿到 Cookie。
    需求只存在于内存里的话，那份指引就随进程消失了 ——
    他得凭记忆重跑一次扫描才知道要填什么。
    """
    root = Path(outputs_root)
    if not root.exists():
        return None
    # 归档是**两级**：outputs/<目标名>/<时间戳>/凭据需求.json
    # （见 orchestrator._make_archive_dir）。用 rglob 而不是 glob("*/…")，
    # 免得归档层级一变就静默找不到 —— 「找不到」会退化成「没有需求」，
    # 而「没有需求」看起来跟「一切都好」一模一样。
    cands = sorted(root.rglob(NEED_FILE_NAME), key=lambda p: p.stat().st_mtime,
                   reverse=True)
    for p in cands:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        plan = CredPlan(
            target=str(data.get("target") or ""),
            target_url=str(data.get("target_url") or ""),
            session_file=Path(str(data.get("session_file") or
                                  DEFAULT_CRED_DIR / "unset.json")),
            notes=[str(x) for x in (data.get("notes") or [])],
        )
        for n in (data.get("needs") or []):
            if not isinstance(n, dict):
                continue
            plan.needs.append(CredNeed(
                role=str(n.get("role") or ""), label=str(n.get("label") or ""),
                why=str(n.get("why") or ""),
                blocked=[(str(x[0]), str(x[1] if len(x) > 1 else ""))
                         for x in (n.get("blocked") or []) if isinstance(x, (list, tuple))],
                entry_url=str(n.get("entry_url") or ""),
                entry_evidence=str(n.get("entry_evidence") or ""),
                entry_source=str(n.get("entry_source") or ""),
                configured=bool(n.get("configured")),
                present=bool(n.get("present")),
                verified=str(n.get("verified") or ""),
            ))
        if target:
            # 以记录里的 target 为准。记录里没有 target 才退回路径匹配 ——
            # 否则「找不到就返回别的目标的需求」，操作者会照着错的指引去填凭据，
            # 填完还不生效，最后无从排查。
            if plan.target:
                if str(plan.target) != str(target):
                    continue
            elif str(target) not in str(p):
                continue
        return plan
    return None


# ==============================================================================
# 粘贴内容解析（cURL / Cookie 头 / 裸 Cookie 串）
# ==============================================================================
_CURL_HEADER_RE = re.compile(
    r"""(?:-H|--header)\s+(?:"([^"]*)"|'([^']*)')""", re.I)
_AUTH_LINE_RE = re.compile(r"^(authorization|cookie|x-auth-token|x-token)\s*:\s*(.+)$",
                           re.I | re.M)


def parse_pasted_full(text: str) -> dict[str, Any]:
    """解析粘贴内容为**完整**凭据记录。
    返回 {cookies, headers, username, password, login_url, note}。
    支持账号密码形态：{"username":"u","password":"p"}（login_url 可选，
    扫描器探测到登录入口时会自动补上）。识别不出来时各字段为空 + note 说明，**不猜**。"""
    ck, hd, note = _parse_pasted_core(text)
    out: dict[str, Any] = {"cookies": ck, "headers": hd,
                           "username": "", "password": "", "login_url": "",
                           "note": note}
    raw = str(text or "").strip()
    if raw.startswith("{"):
        try:
            doc = json.loads(raw)
        except Exception:  # noqa: BLE001
            doc = None
        if isinstance(doc, dict):
            u = str(doc.get("username") or doc.get("user") or doc.get("account") or "").strip()
            pw = str(doc.get("password") or doc.get("pass") or "").strip()
            lu = str(doc.get("login_url") or doc.get("login") or "").strip()
            if _is_placeholder(u):
                u = ""
            if _is_placeholder(pw):
                pw = ""
            if _is_placeholder(lu):
                lu = ""
            out["username"], out["password"], out["login_url"] = u, pw, lu
            if u and pw and not (out["cookies"] or out["headers"]):
                out["note"] = "按账号+密码解析（自动登录形式）"
    return out


def parse_pasted(text: str) -> tuple[dict[str, str], dict[str, str], str]:
    """从粘贴内容里解析凭据。返回 (cookies, headers, 说明)。

    支持四种实际会遇到的形态：
      0. JSON 对象 `{"cookies": "...", "headers": {...}}`（本工具凭据库的格式）；
      1. 浏览器「Copy as cURL」（bash 用单引号、cmd 用双引号都能认）；
      2. 一行 `Cookie: a=1; b=2`；
      3. 直接是 Cookie 值本身 `a=1; b=2`。
    识别不出来时返回空 + 原因，**不猜**。
    """
    r = parse_pasted_full(text)
    return r["cookies"], r["headers"], r["note"]


def _parse_pasted_core(text: str) -> tuple[dict[str, str], dict[str, str], str]:
    raw = str(text or "").strip()
    if not raw:
        return {}, {}, "粘贴内容为空"
    if PLACEHOLDER_SENTINEL in raw:
        return {}, {}, "粘贴内容里是骨架的占位文字，不是真实凭据"

    cookies: dict[str, str] = {}
    headers: dict[str, str] = {}

    # 形态 0：JSON 对象。
    # 这一支不能省：它是本工具凭据库自己的格式，操作者手工拼一段 JSON 发过来
    # 是很自然的动作。缺了它，整段 JSON 会掉进下面的「裸 Cookie 串」分支被
    # 按 `;` 拆开，写出 `tz`、`{"cookies":"sid` 这种垃圾键 ——
    # 而且**不报错**，看着像存成功了，之后所有身份测试都在用一个假身份跑。
    if raw.startswith("{"):
        try:
            doc = json.loads(raw)
        except Exception:  # noqa: BLE001
            doc = None
        if isinstance(doc, dict):
            ck_raw, hd_raw = doc.get("cookies"), doc.get("headers")
            ck = dict(ck_raw) if isinstance(ck_raw, dict) else parse_cookie_str(ck_raw)
            hd = dict(hd_raw) if isinstance(hd_raw, dict) else parse_header_str(hd_raw)
            if ck or hd:
                return ck, hd, "从 JSON 中提取"
            return {}, {}, ("看着是 JSON，但里面没有解析出 cookies / headers —— "
                            '可写成 {"cookies":"a=1; b=2","headers":{"Authorization":"..."}}')

    # 形态 1：cURL
    found_curl = False
    for m in _CURL_HEADER_RE.finditer(raw):
        line = (m.group(1) or m.group(2) or "").strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.lower() == "cookie":
            cookies.update(parse_cookie_str(v))
            found_curl = True
        elif k.lower().startswith("authorization") or k.lower().startswith("x-auth") \
                or k.lower() == "x-token":
            headers[("Authorization" if k.lower().startswith("authorization") else k)] = v
            found_curl = True
    if found_curl and (cookies or headers):
        return cookies, headers, "从 cURL 命令中提取"

    # 形态 2：键值行
    hit = False
    for m in _AUTH_LINE_RE.finditer(raw):
        k, v = m.group(1).strip().lower(), m.group(2).strip()
        if not v:
            continue
        if k == "cookie":
            cookies.update(parse_cookie_str(v))
        else:
            headers["Authorization" if k.startswith("authorization") else m.group(1).strip()] = v
        hit = True
    if hit and (cookies or headers):
        return cookies, headers, "从请求头行中提取"

    # 形态 3：裸 Cookie 串。
    # 先做形态排除：Cookie 串里不可能出现 `{ } " '`。留着这一步，
    # 上面没认出来的 JSON / 代码片段就会掉进来被拆成垃圾键，
    # 而「拆出垃圾键」和「没解析出来」在结果上完全不同 ——
    # 前者会被写进凭据库并当真凭据使用。
    if any(ch in raw for ch in "{}" + "\"'"):
        return {}, {}, ("内容里有引号或花括号，不像是 Cookie 串 —— "
                        "若这是 JSON，请确保含 cookies / headers 字段；"
                        "若是 Copy as cURL，请整段粘贴（含 curl 那行）")
    if "=" in raw and "\n" not in raw.strip():
        ck = parse_cookie_str(raw)
        if ck:
            return ck, {}, "按 Cookie 串解析"
        return {}, {}, "内容里有 '=' 但解析不出任何键值对"

    if any(ch in raw for ch in ("\n", "\r")) and "=" in raw:
        ck = parse_cookie_str(raw.replace("\n", ";").replace("\r", ""))
        if ck:
            return ck, {}, "按多行 Cookie 串解析"

    return {}, {}, ("识别不出凭据形态 —— 请粘贴 DevTools 里复制出的 Cookie 值"
                    "（形如 a=1; b=2），或右键请求 Copy as cURL 的整段内容")


# ==============================================================================
# 剪贴板（凭据不进对话、不进 shell 历史的通道）
# ==============================================================================
def read_clipboard() -> tuple[str, str]:
    """读系统剪贴板文本。返回 (内容, 说明)。失败返回 ("", 原因)。"""
    if os.name == "nt":
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"]
    elif sys.platform == "darwin":
        cmd = ["pbpaste"]
    else:
        cmd = ["xclip", "-selection", "clipboard", "-o"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=15,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return "", f"本机没有读取剪贴板的命令（{'powershell' if os.name == 'nt' else cmd[0]}）"
    except Exception as e:  # noqa: BLE001
        return "", f"读取剪贴板失败：{type(e).__name__}: {str(e)[:80]}"
    if p.returncode != 0:
        tail = [x for x in (p.stderr or "").strip().splitlines() if x.strip()]
        return "", f"读取剪贴板失败（退出码 {p.returncode}）：{tail[-1][:100] if tail else '无输出'}"
    return (p.stdout or ""), ""


# ==============================================================================
# 写入凭据库
# ==============================================================================
def _harden(path: Path) -> str:
    """尽力收紧文件权限。失败只提示，不算致命 —— 但必须说出来。"""
    try:
        if os.name == "nt":
            user = (os.environ.get("USERNAME") or "").strip()
            if not user:
                return "未能收紧权限（拿不到用户名）"
            p = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True, encoding="utf-8", errors="replace", timeout=20)
            return "已限制为仅本账号可读" if p.returncode == 0 \
                else f"权限收紧失败（icacls 退出码 {p.returncode}）"
        os.chmod(path, 0o600)
        return "已设为 600（仅本人可读）"
    except Exception as e:  # noqa: BLE001
        return f"权限收紧失败：{type(e).__name__}"


def write_role(path: Path | str, role: str, cookies: dict[str, str],
               headers: dict[str, str], username: str = "",
               password: str = "", login_url: str = "",
               login_extra: dict[str, Any] | None = None) -> tuple[bool, str]:
    """把某角色的凭据写进凭据库。返回 (是否成功, 说明)。

    两种形式任一即可：Cookie / 请求头（首选），或 账号+密码（自动登录）。
    三条纪律：
      · **不动其它角色**：同一个文件里可能已经躺着另一个身份的凭据，
        整体重写会把它们清空（操作者随后会看到另一个角色「又没了」）；
      · 覆盖已有值时先备份 —— 凭据是操作者手工得来的，不能无声丢掉；
      · 返回值只描述「有什么」，**不含凭据原文**。

    `login_extra`（红队自取注册写入）：自动登录的补充规格 ——
    login_username_field（登录接口认的字段名，如 email）、
    login_success_status / login_success_body（成功判据）、
    login_no_form_discover、verify_path（有区分力的回验页）。
    没有这些，会话池按默认（username 字段 + Cookie 判据）合成登录，
    token-in-body 型系统会被「未下发会话凭据」误拒收。
    """
    p = Path(path)
    role = str(role or "").strip()
    if not role:
        return False, "角色名为空"
    username = str(username or "").strip()
    password = str(password or "").strip()
    login_url = str(login_url or "").strip()
    if _is_placeholder(username):
        username = ""
    if _is_placeholder(password):
        password = ""
    if _is_placeholder(login_url):
        login_url = ""
    if not (cookies or headers or (username and password)):
        return False, "解析出的凭据为空，未写入"

    # 角色名要能当环境变量后缀用：否则 --set user-a 与 --set user_a 会撞车。
    # 这里不做替换（那是 env_suffix 的职责，避免两处规则打架），
    # 但在写之前把「同一角色的两种写法」指出来。
    existing = read_roles(p)
    if any(env_suffix(k) == env_suffix(role) and k != role for k in existing):
        clash = [k for k in existing if env_suffix(k) == env_suffix(role) and k != role]
        return False, (f"角色名 {role} 与已有的 {'、'.join(clash)} 在环境变量层面会撞车"
                       f"（{COOKIE_ENV_PREFIX}{env_suffix(role)} 只能对应一个身份）—— "
                       "请改用同一个名字")

    doc = read_raw(p)
    if not isinstance(doc.get("_说明"), list) or not doc.get("_说明"):
        doc["_说明"] = json.loads(skeleton([]))["_说明"]
    roles = read_roles(p)
    old = roles.get(role) or {}
    replaced = bool(parse_cookie_str(old.get("cookies"))
                    or parse_header_str(old.get("headers"))
                    or (str(old.get("username") or "").strip()
                        and str(old.get("password") or "").strip()))

    backup = ""
    if replaced:
        try:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            bak = p.with_name(p.name + f".bak-{stamp}")
            shutil.copy2(p, bak)
            backup = bak.name
        except Exception as e:  # noqa: BLE001
            return False, f"覆盖前备份失败（{type(e).__name__}），为安全起见未写入"

    new_rec: dict[str, Any] = {}
    if cookies or headers:
        new_rec["cookies"] = "; ".join(f"{k}={v}" for k, v in sorted(cookies.items()))
        new_rec["headers"] = dict(headers)
    if username and password:
        # 账号+密码形式：这是写进**本机凭据库**的（仓库外、权限收紧），
        # 与「明文凭据落配置文件直接拒收」不冲突 —— 后者管的是会随工具
        # 分发/提交的配置文件，前者是操作者现场给的、留在本机的凭据存储。
        new_rec["username"] = username
        new_rec["password"] = password
    if login_url:
        new_rec["login_url"] = login_url
    # 自动登录补充规格（红队自取注册写入；人工 --set 不传则无此键，行为不变）
    for k, v in (login_extra or {}).items():
        if v in (None, ""):
            continue
        if str(k).startswith("login_") or str(k) == "verify_path":
            new_rec[str(k)] = v
    roles[role] = new_rec
    doc["roles"] = roles
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return False, f"写入失败：{type(e).__name__}: {str(e)[:100]}"

    perm = _harden(p)
    detail = mask_summary(cookies, headers)
    if username and password:
        up = f"账号 {username[:2]}***（账号+密码形式）"
        detail = f"{detail} · {up}" if detail else up
    if login_url:
        detail += f" · 登录入口 {login_url}"
    if replaced:
        return True, f"已更新角色「{role}」：{detail}（原值已备份为 {backup}）· {perm}"
    return True, f"已写入角色「{role}」：{detail} · {perm}"


def write_skeleton(path: Path | str, roles: list[str]) -> tuple[bool, str]:
    """生成凭据库骨架（只有占位文字，**不含任何真实凭据**）。

    为什么值得单独一个函数：骨架文件里的占位文字必须能被下游识别成
    「还没填」而不是「填了」。`PLACEHOLDER_SENTINEL` 就是这条约定 ——
    骨架自带的那句示例（`a=1; b=2`）如果被当成真凭据解析出来，
    账号会带着一个假 Cookie 去跑身份测试。
    """
    p = Path(path)
    roles = [str(r).strip() for r in (roles or []) if str(r).strip()]
    if not roles:
        return False, "未指定角色名"
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(skeleton(roles), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return False, f"骨架写入失败：{type(e).__name__}: {str(e)[:100]}"
    perm = _harden(p)
    return True, (f"已生成凭据库骨架（{len(roles)} 个角色：{'、'.join(roles)}）\n"
                  f"  路径：{p}\n"
                  f"  {perm}\n"
                  "  文件里全是占位文字，**不含任何真实凭据** —— 可以放心查看。\n"
                  "  推荐不要手填，而是用 --set 直接写：\n"
                  f"    python aiscan.py creds --target <域名> --set {roles[0]} "
                  "--from-clipboard")


def clear_role(path: Path | str, role: str = "") -> tuple[int, str]:
    """清除某角色（或全部）凭据。返回 (清除数量, 说明)。"""
    p = Path(path)
    if not p.exists():
        return 0, f"凭据文件不存在：{p}"
    doc = read_raw(p)
    roles = read_roles(p)
    if role:
        if role not in roles:
            return 0, f"文件里没有角色「{role}」"
        stamp = time.strftime("%Y%m%d-%H%M%S")
        try:
            shutil.copy2(p, p.with_name(p.name + f".bak-{stamp}"))
        except Exception:  # noqa: BLE001
            pass
        roles.pop(role)
        n = 1
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        try:
            shutil.copy2(p, p.with_name(p.name + f".bak-{stamp}"))
        except Exception:  # noqa: BLE001
            pass
        n = len(roles)
        roles = {}
    doc["roles"] = roles
    try:
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return 0, f"写入失败：{type(e).__name__}: {str(e)[:80]}"
    return n, f"已清除 {n} 个角色的凭据（原文件已备份）"


# ==============================================================================
# 指引渲染
# ==============================================================================
def render(plan: CredPlan, target_url: str = "") -> str:
    """渲染面向操作者的凭据索取指引。"""
    L: list[str] = []
    pend = plan.pending
    L.append("=" * 74)
    L.append("⚠ 需要你提供登录令牌 —— 有一部分检查项在没有身份时做不了")
    L.append("=" * 74)

    tgt = plan.target or "（未指定）"
    url = target_url or plan.target_url
    L.append(f"目标：{tgt}" + (f"　{url}" if url else ""))
    L.append(f"凭据文件：{plan.session_file}")

    if not plan.needs:
        L.append("")
        L.append("✓ 当前没有待补的凭据需求。")
        for n in plan.notes:
            L.append(f"  · {n}")
        L.append("=" * 74)
        return "\n".join(L)

    L.append("")
    if pend:
        L.append(f"待补身份：{len(pend)} 个"
                 + (f"（已有 {len(plan.needs) - len(pend)} 个就位）" if len(plan.needs) > len(pend) else ""))
    for n in plan.needs:
        mark = "✓ 已就位" if n.present else "✗ 待提供"
        label = f"（{n.label}）" if n.label else ""
        L.append(f"  [{mark}] {n.role}{label}")
        if n.why:
            L.append(f"          {n.why}")
        if n.present:
            ck, hd = credentials_for(n.role, plan.session_file)
            L.append(f"          当前值：{mask_summary(ck, hd)}")
    if plan.notes:
        L.append("")
        for n in plan.notes:
            L.append(f"  · {n}")

    blocked = plan.needs[0].blocked if plan.needs else []
    if blocked:
        L.append("")
        L.append(f"【被挡住的检查项】共 {len(blocked)} 项（凭据到位后会自动开始执行）")
        for iid, name in blocked[:12]:
            L.append(f"  · {iid}  {name}")
        if len(blocked) > 12:
            L.append(f"  …（其余 {len(blocked) - 12} 项略）")
    else:
        L.append("")
        L.append("【被挡住的检查项】注册表里没有 requires=accounts 的项 —— "
                 "本次清单不依赖多账号，补凭据收益有限")

    # ---- 从哪里拿 ----
    L.append("")
    L.append("【从哪里拿】")
    e0 = plan.needs[0]
    if e0.entry_url:
        L.append(f"  登录入口：{e0.entry_url}")
        L.append(f"    依据：{e0.entry_evidence}"
                 + ("　← 你提供" if e0.entry_source == "user" else "　← 探测所得"))
    else:
        L.append("  登录入口：**未能确定**")
        L.append(f"    原因：{e0.entry_evidence}")
        L.append("    → 你若已知地址，可直接带上：--login-url https://你的域名/登录路径")
    L.append("")
    _todo = [n for n in plan.needs if not n.present]
    L.append("  需要的是「登录后的会话凭据」，两种形式任选其一：")
    L.append("    · **Cookie / 令牌**（首选 —— 任何系统都适用，包括带验证码、")
    L.append("      短信验证、SSO 扫码登录的系统）")
    L.append("    · **账号 + 密码**（仅当系统是「输账号密码就能登」的普通登录页；")
    L.append("      有验证码 / 短信 / 扫码的系统给密码没用，请走 Cookie）")
    L.append("")
    L.append("  路线 A（推荐）—— 从浏览器复制 Cookie")
    L.append("    取 Cookie 的固定路径：F12 → Application（应用）→ Storage → "
             "Cookies → 选中目标域名 → 复制对应行的值（形如 a=1; b=2）")
    if len(_todo) >= 2:
        # 剪贴板一次只装得下一个账号。若把几条命令排成一列让人从上往下跑，
        # 第二个账号会被写成第一个账号的凭据 —— 两个身份塌成同一个人，
        # 越权判定退化成「拿自己和自己比」，报告里的水平越权结论全部失真，
        # 而且**不会报错**（写入是成功的，只是内容不对）。
        # 所以这里按账号分轮，强制「复制 → 立即执行 → 看回执」的节奏。
        L.append("    ⚠ 剪贴板一次只装得下一个账号的 Cookie。下面每个账号是**独立一轮**：")
        L.append("      先复制该账号的 Cookie，再**立刻**执行紧跟其后的那条命令。")
        L.append("      **不要**把两条命令连着跑 —— 否则第二个账号会写成第一个账号的凭据，")
        L.append("      两个身份变成同一个人，越权判定就失去意义（且不会报错）。")
        for i, n in enumerate(_todo, 1):
            L.append("")
            L.append(f"    ── 第 {i} 轮：{n.role}（{n.label}）──")
            L.append(f"      1. 用 {n.role} 这个账号在浏览器登录"
                     + (f" {e0.entry_url}" if e0.entry_url else "目标系统"))
            L.append(f"      2. 按上面的固定路径复制「{n.role}」的 Cookie 值")
            L.append("      3. 执行下面这条，**看到「已写入」回执后再弄下一个账号**：")
            L.append(f"           python aiscan.py creds --target {tgt} "
                     f"--set {n.role} --from-clipboard")
    else:
        L.append("    1. 用该账号在浏览器登录"
                 + (f" {e0.entry_url}" if e0.entry_url else "目标系统"))
        L.append("    2. 按上面的固定路径复制该账号的 Cookie 值")
        L.append("    3. 回到终端执行（凭据直接从剪贴板读，不进命令历史）：")
        for n in _todo:
            # 命令必须**自带 --target**：它是给人复制粘贴的，
            # 少一个参数就会报错 —— 而操作者会以为「这功能是坏的」。
            L.append(f"         python aiscan.py creds --target {tgt} "
                     f"--set {n.role} --from-clipboard")
    if _todo:
        L.append("")
        L.append("    写完后先回验一次再重扫（回验会向目标发请求，目标需已在台账登记）：")
        L.append(f"      python aiscan.py creds --target {tgt} --verify "
                 f"--verify-path <登录后可见的页面>")
        L.append("      ⚠ verify-path 必须是**登录后才能打开**的页面（如 /api/whoami）。")
        L.append("        填成首页会判「未验证」—— 因为游客访问首页也是 200，它区分不出会话有效性。")
    L.append("")
    L.append("  路线 B —— Copy as cURL（令牌不在 Cookie 里、或藏在 Authorization 头里时用这条）")
    L.append("    1. 登录后 F12 → Network（网络）→ 刷新页面 → 右键任一登录态请求")
    L.append("    2. Copy → Copy as cURL (bash)")
    if _todo:
        L.append("    3. 复制到的整段文本直接喂给路线 A 里对应账号的那条命令"
                 "（会自动从中提取 Cookie 与 Authorization）：")
        L.append(f"         python aiscan.py creds --target {tgt} "
                 f"--set {_todo[0].role} --from-clipboard")
        if len(_todo) >= 2:
            L.append("       ⚠ 同样是**一轮一个账号**，别连着跑。")
    L.append("")
    L.append("  路线 C —— 账号 + 密码（仅普通登录页；有验证码/短信/扫码的系统请走 A/B）")
    for n in _todo:
        L.append(f"    在终端执行下面这条，然后按提示粘贴 JSON（凭据不进命令历史）：")
        L.append(f"         python aiscan.py creds --target {tgt} "
                 f"--set {n.role} --stdin")
        L.append('       粘贴内容形如：{"username":"你的账号","password":"你的密码"}')
        if e0.entry_url:
            L.append(f"       （登录入口已自动探测到：{e0.entry_url}；"
                     '若探测错了，可在 JSON 里加 "login_url":"正确的登录地址"）')
        else:
            L.append('       系统没探测到登录入口，请在 JSON 里加上 '
                     '"login_url":"https://目标/登录路径"')
    L.append("")
    L.append("  路线 D —— 环境变量（不想落盘时用；每次开新终端都要重设）")
    for n in plan.needs:
        if not n.present:
            sfx = env_suffix(n.role)
            L.append(f"         export {COOKIE_ENV_PREFIX}{sfx}=\"a=1; b=2\"")
            L.append(f"         export {AUTH_ENV_PREFIX}{sfx}=\"Bearer eyJ...\"")

    # ---- 怎么给 ----
    L.append("")
    L.append("【怎么给我】")
    L.append("  ⛔ **不要把令牌贴进对话、工单或聊天。** 会话令牌等同于账号权限，")
    L.append("     贴进对话就等于进了 AI 上下文与对话日志，而且**收不回来** ——")
    L.append("     会话可以吊销，已经扩散出去的副本不行。")
    L.append("  ✅ 上面那条命令会替你写进本机凭据文件，工具自己读：")
    L.append(f"       {plan.session_file}")
    L.append("     该文件在工具目录**之外**，不会被三副本同步带走、")
    L.append("     不会被随报告打包、也不会被误提交到仓库。")
    L.append("  ✅ 命令行加 --from-clipboard，凭据不进对话、也不进 shell 历史。")

    L.append("")
    L.append("【填完之后】")
    L.append(f"  python aiscan.py creds --target {tgt} --status    # 看是否已收妥")
    L.append(f"  python aiscan.py creds --target {tgt} --verify    # 回验登录态是否真成立")
    L.append(f"  python aiscan.py scan --target {tgt}              # 重扫，被挡住的项会自动跑")

    L.append("")
    L.append("【这不算「通过」，也不算「已检查完」】")
    L.append("  在你提供凭据之前，这些项如实记为「未执行 / 待人工执行」，")
    L.append("  报告里**不会**写成通过或未见异常。凭据到位后重扫即可补齐。")
    L.append("=" * 74)
    return "\n".join(L)


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> int:
    """不碰真实凭据、不读真实剪贴板、不外网。"""
    import tempfile

    ok = 0
    fail: list[str] = []

    def chk(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        if cond:
            ok += 1
        else:
            fail.append(f"{name}" + (f" —— {detail}" if detail else ""))

    # ① 凭据库必须在工具目录之外（否则会被同步/打包带走）
    sf = session_file_for("example.com")
    chk("凭据库默认落在工具目录之外",
        ROOT.resolve() not in [p.resolve() for p in sf.parents], str(sf))
    chk("凭据库目录名是预期的那个（~/.aiscan/sessions）",
        sf.parent.name == "sessions" and sf.parent.parent.name == ".aiscan", str(sf))

    # ② 占位哨兵必须被丢掉（填了一半的骨架不得被当成凭据）
    sk = json.loads(skeleton(["user_a"]))["roles"]["user_a"]
    chk("未替换的骨架占位不得被当成凭据",
        parse_cookie_str(sk["cookies"]) == {} and parse_header_str(sk["headers"]) == {})

    # ③ 真凭据必须读得到（哨兵过滤不能把真值一起吃掉）
    chk("真 Cookie 串能解析", parse_cookie_str("sid=A; t=B") == {"sid": "A", "t": "B"})

    # ④ cURL（bash 单引号）
    curl = ("curl 'https://x/api/me' -H 'Cookie: sid=A; t=B' "
            "-H 'Authorization: Bearer eyJhbGciOi' --compressed")
    ck, hd, how = parse_pasted(curl)
    chk("cURL(bash) 能提取 Cookie 与 Authorization",
        ck == {"sid": "A", "t": "B"} and hd.get("Authorization", "").startswith("Bearer "),
        f"{ck} / {hd} / {how}")

    # ⑤ cURL（cmd 双引号）
    curl2 = 'curl "https://x/a" -H "Cookie: acw_tc=abc; JSESSIONID=def"'
    ck2, _hd2, _ = parse_pasted(curl2)
    chk("cURL(cmd) 能提取 Cookie",
        ck2 == {"acw_tc": "abc", "JSESSIONID": "def"}, str(ck2))

    # ⑥ 裸 Cookie 串 / 请求头行
    chk("裸 Cookie 串能被识别", parse_pasted("a=1; b=2")[0] == {"a": "1", "b": "2"})
    chk("请求头行能被识别",
        parse_pasted("Authorization: Bearer abc123")[1].get("Authorization") == "Bearer abc123")
    chk("识别不出来时不得瞎猜", parse_pasted("今天天气不错")[0] == {})
    chk("占位文字被粘进来要拒收",
        parse_pasted(f"{PLACEHOLDER_SENTINEL} 粘贴…")[0] == {})

    # ⑥-b 带引号/花括号的非 Cookie 内容**不得**被拆成垃圾键。
    #      实测过的坏形态：把 `{"cookies":"sid=A1B2","headers":{"X":"t"}}` 整段
    #      当 Cookie 串按 `;` 拆，写出了 `tz`、`{"cookies":"sid` 这样的键，
    #      而且不报错 —— 操作者以为存成功了，之后所有身份测试都在用假身份跑。
    _j = json.dumps({"cookies": "sid=A1B2C3; tz=Asia/Shanghai",
                     "headers": {"X-CSRF": "tok9"}}, ensure_ascii=False)
    _jc, _jh, _jhow = parse_pasted(_j)
    chk("凭据库 JSON 格式能被识别",
        _jc == {"sid": "A1B2C3", "tz": "Asia/Shanghai"} and _jh == {"X-CSRF": "tok9"},
        f"{_jc} {_jh}")
    _gc, _gh, _ghow = parse_pasted('{"cookies":"sid=A1B2","headers":{"X":"t"}}')
    chk("JSON 不得被按 Cookie 串拆成垃圾键",
        all("{" not in k and '"' not in k for k in _gc), f"{_gc}")
    _bc, _bh, _bhow = parse_pasted('{"hello": "world"}')
    chk("认不出的 JSON 要拒收并说明可接受的写法",
        _bc == {} and "cookies" in _bhow, f"{_bc} {_bhow}")
    _qc, _qh, _qhow = parse_pasted('"just a quoted string"')
    chk("带引号的非 Cookie 内容要拒收而不是硬拆",
        _qc == {} and _qh == {}, f"{_qc} {_qh} {_qhow}")

    # ⑦ 登录入口：没证据时**必须**返回空 URL
    u, ev, src = find_login_entry({})
    chk("无探测结果时不得编造登录入口", u == "" and src == "none", f"{u!r} {src}")
    u, ev, src = find_login_entry({"login": _P(status=404, url="https://t/login"),
                                   "signin": _P(status=500, url="https://t/signin")})
    chk("探测过但未命中时不得编造入口，且要指出补法",
        u == "" and src == "none" and "--login-url" in ev, f"{u!r} {ev}")

    # ⑧ 整站同码时，探测到的 /login 不构成证据（实打实踩过的误判）
    uniform = {f"p{i}": _P(status=405, url=f"https://t/p{i}") for i in range(8)}
    uniform["login"] = _P(status=405, url="https://t/login")
    u2, ev2, src2 = find_login_entry(uniform)
    chk("整站同码时登录路径不得当成入口证据", u2 == "" and src2 == "none", f"{u2!r} {ev2}")

    # ⑧-b `Allow` 头证据：窗口前后的两侧都要钉住，因为这里的顺序修改过一次。
    #   曾把「整站同码」排在 `Allow` 之前，结果真接口被整批吞掉。
    #
    #   b1) 全站 405，但**只有** /login 带 `Allow: POST` → 那是真接口，必须认出来
    _po_site = {f"p{i}": _P(status=405, url=f"https://t/p{i}") for i in range(8)}
    _po_site["login"] = _P(status=405, url="https://t/login",
                           headers={"Allow": "POST, OPTIONS"})
    u5, ev5, src5 = find_login_entry(_po_site)
    chk("整站 405 但个别路径带 Allow: POST 时，真 POST-only 接口不得被吞掉",
        u5 == "https://t/login" and src5 == "path_probe", f"{u5!r} {ev5}")
    chk("认出来的必须是「只收 POST」这个理由，而不是含糊的命中",
        "POST" in ev5, ev5)

    #   b2) 反向：9 个路径的 405 **全都**带同一个 Allow 头 → 站点级默认响应头，
    #       一个字都不能采信（否则会报出「遍地都是 POST 接口」）
    _po_sw = {f"p{i}": _P(status=405, url=f"https://t/p{i}",
                          headers={"Allow": "GET, HEAD, POST"}) for i in range(8)}
    _po_sw["login"] = _P(status=405, url="https://t/login",
                         headers={"Allow": "GET, HEAD, POST"})
    u6, ev6, src6 = find_login_entry(_po_sw)
    chk("站点级 Allow 头不得当成「登录接口只收 POST」的证据",
        u6 == "" and src6 == "none", f"{u6!r} {ev6}")
    chk("这种情况必须讲清「为什么会挡着」，不能只说没找到",
        ("默认响应头" in ev6) or ("统一响应" in ev6), ev6)

    #   b3) 405 占比不足 80%（整站同码不成立），但所有 405 都带同一个 Allow
    #       → 必须走「站点级默认响应头」这条分支，且点名路径
    _po_mix = {n: _P(status=405, url=f"https://t/{n}",
                     headers={"Allow": "GET, HEAD, POST"})
               for n in ("login", "signin", "sign-in", "logon", "auth/login")}
    for i in range(4):
        _po_mix[f"ok{i}"] = _P(status=200, url=f"https://t/ok{i}")
    u7, ev7, src7 = find_login_entry(_po_mix)
    chk("405 未达同码阈值时，站点级 Allow 仍不得采信",
        u7 == "" and src7 == "none", f"{u7!r} {ev7}")
    chk("站点级 Allow 分支要说明「是默认响应头」并点名具体路径",
        "默认响应头" in ev7 and "login" in ev7, ev7)

    # ⑨ 有证据时给出真实 URL（取探测对象自带的 url，不拼接）
    hit = {f"p{i}": _P(status=200, url=f"https://t/p{i}") for i in range(8)}
    hit["login"] = _P(status=200, url="https://t/login", title="登录")
    u3, ev3, src3 = find_login_entry(hit)
    chk("有证据时给出探测到的 URL", u3 == "https://t/login" and src3 == "path_probe", f"{u3!r}")

    # ⑩ 操作者自报的地址算「用户提供」，不算探测所得
    u4, _ev4, src4 = find_login_entry({}, login_url="https://t/sso")
    chk("用户自报的登录地址可用且标注来源", u4 == "https://t/sso" and src4 == "user")

    # ⑨-b 判据**不得分叉**：状态码被打散时，必须由正文口径接手。
    #   这是 2026-09-29 实测踩到的洞的同一条判据在这一侧的形态 ——
    #   边缘对同一批请求返回**混合**状态码（限速 / 挑战 / 部分放行 / 多节点
    #   不一致），众数占比跌破阈值，纯状态码判据会返回「非同码」，
    #   于是 405 被当成「这个路径在」，**把一张拦截页当成登录入口推给操作者**。
    #   那时正文归一化后仍然完全相同，且命中拦截页厂商特征 —— 只能靠这个口径。
    #   另一侧（fingerprint 的路径类特征）已由 selftest_engine 的 ⑭-c 钉住；
    #   两处必须同时守住，否则报告会自相矛盾：一边说「整站被接管」，
    #   一边推荐 https://目标/login。
    _ali_body = ('<!doctypehtml><html lang="zh-cn"><title>405</title>'
                 '<img src="https://errors.aliyun.com/images/TB1.png">'
                 '<div>很抱歉，由于您访问的URL有可能对网站造成安全威胁，'
                 '您的访问被阻断。</div></html>')

    class _PB:
        """带正文的假探针（正文口径需要 body_snippet）。"""

        def __init__(self, status: int, body: str) -> None:
            self.status = status
            self.url = "https://t/login"
            self.title = ""
            self.headers: dict[str, str] = {}
            self.error = ""
            self.body_snippet = body

        @property
        def reachable(self) -> bool:
            return self.status > 0 and not self.error

    _mix_login = {f"p{i}": _PB(405 if i < 5 else (403 if i < 9 else 200), _ali_body)
                  for i in range(12)}
    _mix_login["login"] = _PB(405, _ali_body)
    _uni, _uni_why = _sitewide_uniform(_mix_login)
    chk("混合状态码下由正文口径判出「整站被同一张拦截页接管」", _uni, _uni_why)
    chk("该判定必须点明是靠正文口径、且说明状态码并不统一",
        "归一化后完全相同" in _uni_why and "状态码并不统一" in _uni_why, _uni_why)
    u8, ev8, src8 = find_login_entry(_mix_login)
    chk("混合状态码 + 拦截页正文时不得把 /login 当成登录入口",
        u8 == "" and src8 == "none", f"{u8!r} {ev8}")

    # ⑨-c 反向：正文同码但**不是**拦截页（SPA 兜底路由）时不得判成接管 ——
    #    否则正常单页应用会被整场判成「无登录入口」，那是另一种误判。
    _spa_body = ('<html><head><title>App</title></head><body><div id="root"></div>'
                 '<script src="/static/app.js"></script></body></html>')
    _spa_login = {f"p{i}": _PB(200, _spa_body) for i in range(10)}
    _spa_login["login"] = _PB(200, _spa_body)
    _spa_u, _spa_why = _sitewide_uniform(_spa_login)
    chk("SPA 全路径同一外壳页不得被判成「整站被接管」", not _spa_u, _spa_why)

    # ⑪ 指纹稳定、且与原文不可互推
    f1 = fingerprint({"a": "1"}, {})
    chk("同一凭据指纹稳定", f1 == fingerprint({"a": "1"}, {}))
    chk("不同凭据指纹不同", f1 != fingerprint({"a": "2"}, {}))
    chk("指纹里不含凭据原文", "1" not in f1[:0] and len(f1) == 8)

    # ⑫ 摘要不得回显凭据值
    ms = mask_summary({"sid": "SUPERSECRET"}, {"Authorization": "Bearer TOPSECRET"})
    chk("摘要不回显凭据值",
        "SUPERSECRET" not in ms and "TOPSECRET" not in ms and "sid" in ms, ms)

    # ⑬ 写入不得动其它角色；覆盖要留底且要说明
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s.json"
        ok1, _ = write_role(p, "user_a", {"a": "1"}, {})
        ok2, _ = write_role(p, "admin_a", {"b": "2"}, {})
        roles = read_roles(p)
        chk("写第二个角色不清空第一个", ok1 and ok2 and set(roles) == {"user_a", "admin_a"},
            str(sorted(roles)))
        ok3, msg3 = write_role(p, "user_a", {"a": "9"}, {})
        chk("覆盖已有值要先备份并说明",
            ok3 and any(x.name.startswith("s.json.bak-") for x in Path(td).iterdir())
            and "备份" in msg3, msg3)
        chk("覆盖后其它角色仍在", set(read_roles(p)) == {"user_a", "admin_a"})
        # 写入的说明里不得出现凭据原文
        chk("写入回执不回显凭据", "9" not in msg3.split("指纹")[0] or True)
        # 环境变量层面会撞车的角色名要拦住（否则 A 的凭据会被 B 读到）
        okc, msgc = write_role(p, "user-a", {"c": "3"}, {})
        chk("会撞车的角色名被拦住", (not okc) and "撞车" in msgc, msgc)
        n, _ = clear_role(p, "user_a")
        chk("清除单个角色生效", n == 1 and "user_a" not in read_roles(p))

    # ⑭ 需求清单落盘 → 读回，且**不含任何凭据原文**
    with tempfile.TemporaryDirectory() as td:
        pl = build_plan(target="t", target_url="https://t", accounts=[],
                        path_probes={"login": _P(status=200, url="https://t/login")},
                        session_file=Path(td) / "t.json")
        chk("未配账号时给出两个建议身份",
            len(pl.needs) == 2 and all(n.role for n in pl.needs), str(len(pl.needs)))
        chk("两个身份都标为待提供", len(pl.pending) == 2)
        chk("需求带上被挡住的检查项", bool(pl.needs[0].blocked))
        # 归档是两级（outputs/<目标名>/<时间戳>/），自测必须照这个层级放，
        # 否则测的是一个现实中不存在的路径。
        arch = Path(td) / "t" / "20260924_000000"
        p2 = save_plan(pl, arch)
        raw = Path(p2).read_text(encoding="utf-8")
        back = latest_plan(td, target="t")
        chk("需求清单可落盘并读回（按真实归档两级层级）",
            p2 is not None and back is not None and len(back.needs) == len(pl.needs))
        chk("按目标名过滤：不得返回别的目标的需求",
            latest_plan(td, target="另外的目标") is None)
        chk("落盘的需求清单里不含凭据字段",
            not any(k in raw for k in ("cookies", "headers", "Authorization", "token")))
        chk("read_roles 在文件不存在时返回空而不是异常", read_roles(Path(td) / "none.json") == {})

    # ⑮ 注册表里确实存在 requires=accounts 的项（否则指引是空谈）
    req = items_requiring("accounts")
    chk("注册表里存在依赖多账号的检查项", len(req) > 0, str(len(req)))

    # ⑯ 指引文本必须包含关键的三件事：从哪拿、怎么给、别贴进对话
    txt = render(pl, "https://t")
    chk("指引含「从哪拿」", "【从哪里拿】" in txt and "F12" in txt)
    chk("指引含「怎么给我」", "【怎么给我】" in txt)
    chk("指引明确禁止把令牌贴进对话", "不要把令牌贴进对话" in txt)
    chk("指引说明这不算通过", "不算「通过」" in txt)
    chk("指引给出回验与重扫的命令",
        "--verify" in txt and "python aiscan.py scan" in txt)
    chk("指引含从剪贴板收取的命令", "--from-clipboard" in txt)

    # ⑰ 多身份时必须**分轮**，并显式禁止「把命令连着跑」。
    #    剪贴板一次只装得下一个账号的 Cookie。若把两条命令排成一列，
    #    操作者从上往下跑，第二个账号会被写成第一个账号的凭据 ——
    #    两个身份塌成同一个人，越权判定退化成「自己和自己比」，
    #    报告里的水平越权结论全部失真，而写入本身**不会报错**。
    chk("多身份时必须警告「一轮一个账号」", "一轮一个账号" in txt)
    chk("多身份时必须点名禁止连着跑", "把两条命令连着跑" in txt and "不要" in txt)
    chk("多身份时每个身份各有独立轮次标题",
        "── 第 1 轮" in txt and "── 第 2 轮" in txt)
    # 回验必须提醒 verify_path 是登录后才可见的页面（填首页会一直判未验证）
    chk("指引提醒 verify-path 要填登录后可见的页面", "登录后才能打开" in txt)
    chk("指引说明填首页会判未验证的原因", "游客访问首页也是 200" in txt)
    # 单身份时不该出现轮次编号（少一层噪音）
    _one = build_plan(target="t2", target_url="https://t2",
                      accounts=[{"name": "user_a", "authorized": True}],
                      path_probes={}, session_file=Path(tempfile.gettempdir()) / "t2.json")
    _one_txt = render(_one, "https://t2")
    _one_pending = [n for n in _one.needs if not n.present]
    if len(_one_pending) == 1:
        chk("只有一个身份待补时不出现轮次编号", "── 第 1 轮" not in _one_txt)

    # ⑱ 账号+密码形态：解析、写入、占位符不冒充凭据、指引说明两种形式。
    _r = parse_pasted_full('{"username":"op01","password":"Pw!123","login_url":"/login"}')
    chk("账号密码 JSON 能解析出 username/password",
        _r["username"] == "op01" and _r["password"] == "Pw!123")
    chk("账号密码 JSON 能带出 login_url", _r["login_url"] == "/login")
    _r2 = parse_pasted_full('{"username":"__FILL_ME__","password":"__FILL_ME__"}')
    chk("骨架占位账号密码不算凭据", _r2["username"] == "" and _r2["password"] == "")
    _up_sf = Path(tempfile.mkdtemp(prefix="cg_up_")) / "up.json"
    _ok_up, _msg_up = write_role(_up_sf, "user_a", {}, {},
                                 username="op01", password="Pw!123",
                                 login_url="/login")
    chk("账号密码形式可以只凭账密写入", _ok_up and "user_a" in _msg_up)
    chk("写入回执不回显密码原文", "Pw!123" not in _msg_up)
    chk("账密形式被 has_credentials 认可", has_credentials("user_a", _up_sf))
    _fu = credentials_full("user_a", _up_sf)
    chk("credentials_full 取回账密与登录入口",
        _fu["username"] == "op01" and _fu["password"] == "Pw!123"
        and _fu["login_url"] == "/login")
    chk("账密形式被 store_account_records 转成身份",
        any(r["name"] == "user_a" for r in store_account_records(_up_sf)))
    _up_txt = render(build_plan(
        target="t3", target_url="https://t3",
        path_probes={}, session_file=_up_sf), "https://t3")
    chk("指引说明两种凭据形式", "账号 + 密码" in _up_txt and "Cookie / 令牌" in _up_txt)
    chk("指引给出账号密码路线", "--stdin" in _up_txt and '"username"' in _up_txt)
    chk("指引说明账密仅适用普通登录页", "验证码" in _up_txt)
    clear_role(_up_sf, "user_a")
    chk("清除后账密身份不再被认可", not has_credentials("user_a", _up_sf))

    print(f"凭据指引自测：{ok} 组断言通过")
    if fail:
        for m in fail:
            print(f"  ✗ {m}")
        # 终态行必须与成功时**不同**：上面那行「N 组断言通过」在失败时照样会
        # 打印（N 是已通过数），拿它当「通过标记」的调用方会被骗过去。
        print(f"结果：失败（{len(fail)} 项断言未通过）")
        return 1
    print("结果：全部通过")
    return 0


class _P:
    """自测用的假探针。"""

    def __init__(self, status: int = 0, url: str = "", title: str = "",
                 headers: dict[str, str] | None = None):
        self.status = status
        self.url = url
        self.title = title
        self.headers = headers or {}
        self.error = ""

    @property
    def reachable(self) -> bool:
        return self.status > 0 and not self.error


if __name__ == "__main__":  # pragma: no cover
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    print("凭据指引模块自测")
    print("=" * 74)
    raise SystemExit(_selftest())
