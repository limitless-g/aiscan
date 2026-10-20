# -*- coding: utf-8 -*-
"""认证态会话池（P2：让「登录之后的越权取数」从看不见到看得见）
================================================================================

为什么这一层价值最高
--------------------------------------------------------------------------------
「最容易被拿走数据的一类问题」是**登录之后的越权**：A 用户能读 B 用户的订单、
普通角色能调管理接口。它不在任何匿名扫描的视野里 —— 不是「看了没问题」，
是**结构性看不见**。

要看见它，前提只有一个：扫描器得先成为一个合法的登录用户，而且最好是
**两个**不同身份的登录用户（一个不够：只拿一个账号，无法区分「读到他人数据」
与「读到自己数据」，这是证明层已经写明的判据）。

================================================================================
三条硬约束
================================================================================

1. **凭据只从环境变量取，配置文件里不许出现明文口令。**
   `password: hunter2` 这种写法直接拒收该账号，并给出明确理由。
   理由不是洁癖：配置文件会被复制、会被提交、会随报告一起发出去，
   而口令一旦落盘，泄露是静默的、且无法收回。
   允许的写法只有 `password_env: USER_A_PASS`。
   —— 「登记了却不生效」是本项目反复出现的缺陷家族；这里是它的反面：
      **登记了但不安全，就不生效，而且要说出来。**

2. **未验证的会话不得当作「已认证」。**
   登录接口返回 200 不等于登录成功（很多系统对失败也回 200 的 JSON）。
   所以登录后必须**回验**：带着会话访问一个需要认证的路径，
   看是否被弹回登录页。判不出来就标「未验证」——
   绝不能把「以为登上了」当成「以该身份测过了」。这一条直接决定
   越权结论的有效性：用游客身份测出来的「越权」，全是噪声。

3. **自动化不了的登录，交人工递会话，而不是假装支持。**
   验证码 / 短信 OTP / SSO 扫码这三类登录，机器无法稳定完成
   （验证码识别既不可靠也不合规）。对它们的正确做法不是「尝试破解」，
   而是提供 `cookies_env` 通道：人工在浏览器登录一次，把 Cookie 塞进环境变量。
   能自动化就自动化，不能就明确交人工 —— 不装作能行。

4. **凭据的三个合法来源，按「谁实际供上了」如实标注。**（2026-09-24 新增）
   ① 本机凭据库（`~/.aiscan/sessions/<目标>.json`，由 `engine.credguide` 维护）——
      操作者从浏览器复制一次，工具直接读；**不落配置文件、不用环境变量**；
   ② 配置里指定的环境变量（`cookies_env` / `headers_env` / `login.*_env`）；
   ③ 配置里的静态 header / cookie（只允许 `${ENV:}` 引用）。
   谁供上了就标谁（`AccountSpec.supplied_by`）。**不许含糊**：
   过去踩过的坑就是「配置写了 cookies_env，代码里没人读它」——
   账号看起来配好了，实际以游客身份去测越权，产出一批复测不出来的结论。

================================================================================
与既有代码的关系
--------------------------------------------------------------------------------
`engine/authz_matrix.py` 已经能做「多账号响应比对」，缺的只是**怎么拿到会话**。
本模块补的正是这一环：把配置文件里的账号记录变成可用的会话（自动登录或
人工 Cookie），并把「登录到底成没成功」如实标出来。
产出与 `ctx.accounts` 的既有结构兼容（name / role / tenant / headers / cookies /
authorized），避免大范围改动。

================================================================================
踩坑记录（由不变量 ⑳ 抓到的两个真实缺陷，禁止回退）
================================================================================

**坑一：护栏把用户推向它要防的那件事。**
最早的明文检查是「键名里含 password / secret / token 就要求值是 ${ENV:}」。
于是 `password_env: USER_A_PASS` —— 也就是**本模块文档推荐的写法** ——
会因为键名里含 "password"、值又不是 `${ENV:}` 而被判成「明文凭据」拒收。
后果比不做检查更糟：操作者为了让配置通过，会改成直接写明文口令。
修法是把键名分成三档（结构型 / 指针型 / 凭据型），指针型键
（`*_env`、`*_field`）跳过明文检查，但要校验它的值确实是个变量名。
**教训：一个总是拒收合法配置的护栏，最终一定被绕过或关闭 —— 等于没有护栏。**

**坑二：文档承诺了「人工 Cookie 通道」，代码里没人去读那个环境变量。**
`source` 会被标成 `manual_cookie`，`cookies_env` 也写进了配置文件，
但没有任何一行代码去解析它 —— 账号看起来「配好了」，实际以游客身份
去测越权，产出一批看起来合理、复测不出来的越权结论，
失败原因显示为「会话不成立」这种完全无害的话。
这是本项目反复出现的「登记了却不生效」缺陷家族的又一例：
**判断「有没有实现」的唯一标准是「有没有代码去读它」，不是「配置里有没有这一项」。**
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

# 允许的「非明文」凭据写法：值必须是 ${ENV:NAME}
_ENV_REF = re.compile(r"^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$")
# 合法的环境变量名 / 字段名
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# ------------------------------------------------------------------------------
# 键名分类（这一节的教训来自自测不变量 ⑳ 抓到的真实缺陷，见文末「踩坑记录」）
# ------------------------------------------------------------------------------
# 结构型键：值是配置结构（URL / 方法 / 子字典），既不是凭据，
# 也不该按「环境变量名」去校验。
_STRUCT_KEYS = frozenset({
    "url", "method", "success", "fields", "headers", "cookies", "login",
    "submit", "expect", "content_type",
})

# 指针型键：值是**环境变量名**，而不是凭据本身。
# 这类键必须被跳过明文检查 —— 否则 `password_env: USER_A_PASS`
# 这种**模块自己文档推荐**的写法，会因为键名里含 "password" 被判成
# 「明文凭据」而拒收。后果比不做检查更糟：操作者为了让配置通过，
# 会改成直接写明文口令 —— 护栏反而把人推向它要防的那件事。
_ENV_NAME_KEYS = frozenset({
    "username_env", "password_env", "token_env", "apikey_env", "api_key_env",
    "cookies_env", "headers_env", "auth_env",
})

# 疑似承载凭据的键名，分两档匹配：
#   · 子串档：这些词出现在键名任何位置都可疑，且不会误伤友军；
#   · 精确档：这些词必须**恰好等于**键名才可疑 —— 用子串会误伤
#     （"auth" 会命中布尔开关 "authorized"，"session" 会命中 "session_timeout"
#      这类配置项），而误伤的代价在本项目里已经反复出现过：
#      一个总是拒收合法配置的护栏，会被绕过或关闭，等于没有护栏。
_SECRET_SUBSTR = ("password", "passwd", "secret", "token", "apikey",
                  "api_key", "credential", "privatekey", "private_key",
                  "passphrase", "authorization")
_SECRET_EXACT = frozenset({
    "pwd", "auth", "bearer", "key", "sess", "session", "sessionid",
    "jsessionid", "sid", "signature", "setcookie",
})

# 登录态取值（五态，不含糊）
LOGIN_OK = "已登录"
LOGIN_FAIL = "登录失败"
LOGIN_UNVERIFIED = "未验证"
LOGIN_ABSENT = "未配置登录"
# 「未提供凭据」是独立一态，**不能并入「登录失败」**：
#   登录失败 = 真的拿着凭据去登了，被拒；
#   未提供凭据 = 压根没东西可登（环境变量没导出 / 凭据库还是占位骨架 / 档位禁止登录）。
# 两者混用会变成一句假话：报告里写「登录失败」，读的人以为试过了，
# 于是去查密码对不对 —— 而真实原因是没配置。排查方向整个是错的。
LOGIN_NO_CRED = "未提供凭据"
# 「未授权使用」同样单列：账号没被启用是因为授权声明缺失，不是因为登录失败。
LOGIN_NOT_AUTHORIZED = "未授权使用"


@dataclass
class AccountSpec:
    """配置文件里的一条账号记录（已做安全性校验）。"""

    name: str
    role: str = "user"
    tenant: str = ""
    authorized: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    login: dict[str, Any] = field(default_factory=dict)
    verify_path: str = ""           # 回验会话用的「登录后页面」；空 = 站点首页
    source: str = "static"          # static / auto_login / manual_cookie / cred_file
    supplied_by: str = ""           # 凭据实际由谁供上：cred_file / env / static / login
    rejected: str = ""              # 非空 = 该账号被拒收，原因为此
    rejected_kind: str = ""         # 拒收类别：unsafe_config / no_cred / unauthorized
    #                               —— 决定 login_state 怎么写。
    #                               「明文凭据」是配置不安全（真的配了东西）；
    #                               「no_cred」是什么都没配到，两者不能都写「登录失败」。


def _resolve(value: Any) -> str:
    """解析 ${ENV:NAME}；普通字符串原样返回。"""
    m = _ENV_REF.match(str(value or ""))
    if m:
        return os.environ.get(m.group(1), "")
    return str(value or "")


def _norm_key(k: Any) -> str:
    """键名归一化：去掉下划线 / 连字符 / 空格并转小写，用于「精确档」比较。

    这样 `access_key`、`access-key`、`accessKey` 三种写法会归一成同一个键，
    而 `authorized` 不会因为含 "auth" 被误判 —— 它归一后是 `authorized`，
    与精确档里的 `auth` 不相等。
    """
    return re.sub(r"[\s_\-]", "", str(k or "")).lower()


def _is_secret_key(k: Any) -> bool:
    kl = str(k or "").lower()
    if any(s in kl for s in _SECRET_SUBSTR):
        return True
    return _norm_key(k) in _SECRET_EXACT


def _audit_secrets(rec: dict[str, Any], where: str) -> list[str]:
    """检查是否有明文凭据。返回违规描述列表（空 = 通过）。

    只认 `${ENV:NAME}` 这一种写法。空的字面值（None / ""）不算违规 ——
    那是「没填」，不是「写死了」。
    """
    bad: list[str] = []
    for k, v in (rec or {}).items():
        kl = str(k).lower()
        if kl in _STRUCT_KEYS:
            # 值是配置结构（下面会单独递归进去查），
            # 在这里只跳过、不判 —— 否则 `fields: {...}` 会因为
            # 「值不是环境变量名」被误报
            continue
        if kl in _ENV_NAME_KEYS or kl.endswith("_env"):
            # 指针键：值应当是一个环境变量名。
            # 填成别的东西（例如图省事把口令直接写在这）是**写法错误**，
            # 不是「明文凭据」—— 两者修法完全不同，必须分开报。
            if isinstance(v, str) and v and not _ENV_NAME.match(v):
                if "${ENV:" in v:
                    continue          # 已用 ${ENV:...} 引用，合规
                bad.append(f"{where} 的 {k} 应填**环境变量名**（如 USER_A_PASS），"
                           f"当前值不像变量名；若这里写的是口令本身，"
                           f"请改为 password_env: 变量名 或 ${{ENV:变量名}}")
            continue
        if kl.endswith("_field"):
            continue                  # 表单字段名，不是凭据
        if _is_secret_key(k):
            if v not in (None, "") and not _ENV_REF.match(str(v)):
                # 修法建议要贴上下文：headers / cookies 里的键名是**服务端约定的
                # 名字**（Authorization、JSESSIONID…），改成「Authorization_env」
                # 这种指针写法反而无效，只有 ${ENV:} 一种可用写法。
                hint = ("应把值改为 ${ENV:变量名}"
                        if ("headers" in where or "cookies" in where)
                        else f"应改为 {k}_env: 环境变量名，或写成 ${{ENV:变量名}}")
                bad.append(f"{where} 的 {k} 是明文凭据（{hint}）")
    return bad


def _parse_cookie_env(var: str) -> dict[str, str]:
    """把 `cookies_env` 指向的环境变量解析成 Cookie 字典。

    支持浏览器里直接复制出来的形式：`a=1; b=2`。
    这是「自动化不了的登录交人工」那条约束的落地点 —— 人工在浏览器登录一次，
    把 Cookie 串塞进环境变量即可。**凭据始终不落配置文件。**
    """
    raw = os.environ.get(str(var or ""), "").strip()
    if not raw:
        return {}
    out: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _parse_headers_env(var: str) -> dict[str, str]:
    """把 `headers_env` 指向的环境变量解析成请求头字典。

    支持两种形式：JSON 对象，或 `Key: Value` 逐行。"""
    raw = os.environ.get(str(var or ""), "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except Exception:  # noqa: BLE001
            return {}
        return {}
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def load_specs(records: list[dict[str, Any]],
               cred_lookup: Any = None, cred_full_lookup: Any = None,
               fallback_login_url: str = "") -> list[AccountSpec]:
    """把原始账号记录转成受校验的规格。不合规的账号照样返回，但带 rejected 原因。

    为什么不直接丢弃：静默丢弃会让「配置了 2 个账号」变成「实际 1 个账号」，
    而越权判断恰恰依赖账号数量（<2 就无法区分他人数据）。必须让上层看得见。

    `cred_lookup`：`name -> (cookies, headers)` 的回调，用于从本机凭据库取凭据。
    它和 `cookies_env` 一样，是**合法凭据来源之一**，不是「兜底补丁」——
    所以放在这里与其它来源一起解析，而不是事后再覆盖一遍配置的结论。

    `cred_full_lookup`：`name -> 完整凭据记录`（含 username/password/login_url）。
    配置里没给任何凭据时，若凭据库里有「账号+密码」且登录入口可知，
    就现场合成一个自动登录规格 —— 这是「不预置 accounts.yaml」路线的落地：
    操作者 `creds --set user_a --stdin` 给账密，扫描器自己登录。
    明文口令**只在运行期内存里**存在，绝不写回配置文件（审计仍拒绝配置明文）。
    """
    out: list[AccountSpec] = []
    for rec in records or []:
        rec = dict(rec or {})
        name = str(rec.get("name") or "unnamed")
        login = dict(rec.get("login") or {})

        bad = _audit_secrets(rec, f"账号 {name}")
        bad += _audit_secrets(rec.get("headers") or {}, f"账号 {name} 的 headers")
        bad += _audit_secrets(rec.get("cookies") or {}, f"账号 {name} 的 cookies")
        bad += _audit_secrets(login, f"账号 {name} 的 login")
        bad += _audit_secrets(login.get("fields") or {}, f"账号 {name} 的 login.fields")

        source = "static"
        if login:
            source = "auto_login"
        elif rec.get("cookies_env") or rec.get("headers_env"):
            source = "manual_cookie"

        headers = {k: _resolve(v) for k, v in (rec.get("headers") or {}).items()}
        cookies = {k: _resolve(v) for k, v in (rec.get("cookies") or {}).items()}

        # 人工 Cookie 通道必须在**这里**落地，否则就是「登记了却不生效」：
        # 配置里写了 cookies_env、会话池也把 source 标成 manual_cookie，
        # 却没人去读那个环境变量 —— 结果是账号看起来「配好了」，
        # 实际以游客身份去测越权，测出来的全是噪声，且原因显示为
        # 「会话不成立」这种看起来完全合理的话。
        manual_hint: list[str] = []
        no_cred_reason = ""
        if rec.get("cookies_env"):
            got = _parse_cookie_env(rec["cookies_env"])
            if got:
                cookies.update(got)
                source = "manual_cookie"
            else:
                manual_hint.append(f"cookies_env={rec['cookies_env']} 未导出或为空")
        if rec.get("headers_env"):
            got = _parse_headers_env(rec["headers_env"])
            if got:
                headers.update(got)
                source = "manual_cookie"
            else:
                manual_hint.append(f"headers_env={rec['headers_env']} 未导出或为空")

        # 本机凭据库：与上面并列的一个来源。
        # 覆盖顺序上「配置里显式写的不被文件盖掉」，因为配置是针对性更强的意图。
        supplied_by = ""
        if headers or cookies:
            supplied_by = "env" if source == "manual_cookie" else "static"
        if cred_lookup is not None:
            try:
                f_ck, f_hd = cred_lookup(name)
            except Exception:  # noqa: BLE001
                f_ck, f_hd = {}, {}
            if f_ck or f_hd:
                headers = {**f_hd, **headers}
                cookies = {**f_ck, **cookies}
                if not supplied_by:
                    supplied_by = "cred_file"
                    source = "cred_file"
                    manual_hint = []   # 文件里拿到了，就不再报「环境变量没导出」

        # 凭据库「账号+密码」通道：配置没给任何凭据时，凭据库里有账密
        # 且登录入口可知 → 现场合成自动登录。放在审计之后（审计管的是
        # 配置文件里的明文，这里是运行期内存合成，不落盘、不进配置）。
        up_note = ""
        if (not (headers or cookies)) and not login and cred_full_lookup is not None:
            try:
                _full = cred_full_lookup(name) or {}
            except Exception:  # noqa: BLE001
                _full = {}
            _u = str(_full.get("username") or "").strip()
            _p = str(_full.get("password") or "").strip()
            _lu = str(_full.get("login_url") or "").strip() or str(fallback_login_url or "")
            if _u and _p:
                if _lu:
                    # 字段名 / 成功判据来自凭据库里的补充规格
                    # （红队自取注册时记录：登录接口认 email 还是 username、
                    # 成功特征是什么）。没有这些，按「username 字段 + Cookie
                    # 判据」合成 —— token-in-body 型系统（Juice Shop 等）
                    # 会被「未下发会话凭据」误拒收，账号明明是好的。
                    _uf = str(_full.get("login_username_field") or "username")
                    _pf = str(_full.get("login_password_field") or "password")
                    login = {"url": _lu, "method": "POST",
                             "fields": {_uf: _u, _pf: _p}}
                    if _full.get("login_no_form_discover"):
                        login["no_form_discover"] = True
                    _succ: dict[str, Any] = {}
                    if _full.get("login_success_status"):
                        _succ["status"] = _full.get("login_success_status")
                    if _full.get("login_success_body"):
                        _succ["body_contains"] = _full.get("login_success_body")
                    if _succ:
                        login["success"] = _succ
                    source = "auto_login"
                    supplied_by = "cred_file"
                else:
                    up_note = ("凭据库里有「账号+密码」但没确定登录入口 —— "
                               "自动登录无法发起。补法：给该角色写入 login_url"
                               "（creds --set 时 JSON 里带 \"login_url\"），"
                               "或确认扫描器能探测到登录页")

        if source == "manual_cookie" and not (headers or cookies):
            no_cred_reason = ("人工 Cookie 通道未提供有效凭据（"
                              + "；".join(manual_hint or ["cookies_env / headers_env 未配置"])
                              + "）—— 该账号不得用于身份相关测试")
        if up_note and not login and not (headers or cookies) and not no_cred_reason:
            no_cred_reason = up_note

        rejected = "；".join(bad)
        kind = "unsafe_config" if bad else ""
        if not rejected and no_cred_reason:
            # 这里与「配置不安全」分开记：前者是「配了但配错」，后者是「根本没配到」。
            # 描述混在一起，报告里就只能含糊成「登录失败」。
            rejected, kind = no_cred_reason, "no_cred"

        out.append(AccountSpec(
            name=name,
            role=str(rec.get("role") or "user"),
            tenant=str(rec.get("tenant") or ""),
            authorized=bool(rec.get("authorized", False)),
            headers=headers,
            cookies=cookies,
            login=login,
            verify_path=str(rec.get("verify_path") or ""),
            source=source,
            supplied_by=supplied_by,
            rejected=rejected,
            rejected_kind=kind,
        ))
    return out


# ==============================================================================
# 自动登录
# ==============================================================================
def _form_pairs(login: dict[str, Any]) -> dict[str, str]:
    """构造登录表单字段值（凭据来自环境变量）。"""
    pairs: dict[str, str] = {}
    for k, v in (login.get("fields") or {}).items():
        pairs[str(k)] = _resolve(v)
    # 便捷写法：username_env / password_env
    if login.get("username_env"):
        pairs[str(login.get("username_field") or "username")] = \
            os.environ.get(str(login["username_env"]), "")
    if login.get("password_env"):
        pairs[str(login.get("password_field") or "password")] = \
            os.environ.get(str(login["password_env"]), "")
    return pairs


def login_one(spec: AccountSpec, target_url: str, timeout: int = 12) -> AccountSpec:
    """对单个账号执行自动登录，成功则把会话写进 spec.headers / spec.cookies。

    判定「登录成功」必须**回验**，不能只看登录接口的状态码：
    很多系统对失败也返回 200（`{"code":1,"msg":"密码错误"}`）。
    """
    import requests

    login = spec.login or {}
    url = str(login.get("url") or "")
    if not url:
        return spec
    if url.startswith("/"):
        url = target_url.rstrip("/") + url
    method = str(login.get("method") or "POST").upper()
    pairs = _form_pairs(login)
    if not any(pairs.values()):
        spec.rejected = spec.rejected or "登录凭据环境变量为空（未导出或变量名写错）"
        return spec

    sess = requests.Session()
    sess.verify = False
    # 禁信环境代理（与 HttpProbeClient 同一纪律）。生产主链路因 fingerprint
    # 导入即清代理而一直没暴露；但本模块**可被独立使用**（regself 自测、
    # 凭据回验 CLI），此时环境代理若存在（CI 沙箱 / 公司代理 / 抓包工具），
    # keep-alive 复用连接上的第二个请求会被错误路由 —— 表现是「登录响应
    # 未下发任何会话凭据」这种看起来像密码错误的话（2026-10-09 实测）。
    sess.trust_env = False
    # 表单 action 发现：登录入口通常是**页面**（如 /login），而账密真正的
    # 提交地址在页面表单的 action 里（如 /api/login）。直接 POST 给页面
    # 会得到 200/404 却没有会话 —— 表现是「登录响应未下发会话凭据」这种
    # 看起来像密码错误的话。先 GET 一次页面，把 action 提出来再用。
    if method == "POST" and not login.get("no_form_discover"):
        try:
            _page = sess.get(url, timeout=timeout, allow_redirects=True)
            _m = re.search(
                r"<form[^>]*\baction=['\"]([^'\"]+)['\"]",
                _page.text or "", re.I)
            if _m:
                from urllib.parse import urljoin  # noqa: PLC0415

                _act = urljoin(_page.url or url, _m.group(1))
                if _act != url:
                    url = _act
        except Exception:  # noqa: BLE001
            pass  # 发现失败不致命：按原地址提交（显式配置了接口地址的系统不受影响）
    try:
        if method == "POST":
            resp = sess.request(method, url, data=pairs, timeout=timeout,
                                allow_redirects=True,
                                headers=login.get("headers") or {})
        else:
            resp = sess.request(method, url, params=pairs, timeout=timeout,
                                allow_redirects=True,
                                headers=login.get("headers") or {})
    except Exception as e:  # noqa: BLE001
        spec.rejected = f"登录请求失败：{type(e).__name__}: {str(e)[:100]}"
        return spec

    # 成功判据：可由配置显式指定，否则用「拿到会话凭据」这一客观事实
    ok_expr = login.get("success")
    if isinstance(ok_expr, dict):
        want_status = ok_expr.get("status")
        body_has = ok_expr.get("body_contains")
        status_ok = (want_status is None) or (resp.status_code == int(want_status))
        body_ok = (body_has is None) or (str(body_has) in (resp.text or ""))
        if not (status_ok and body_ok):
            spec.rejected = (f"登录判定未通过（status={resp.status_code}，"
                             f"期望 {want_status}；body 特征 "
                             f"{'命中' if body_ok else '未命中'}）")
            return spec
    elif not (sess.cookies or resp.headers.get("Set-Cookie")):
        spec.rejected = ("登录响应未下发任何会话凭据（Cookie / Token），"
                         "可能登录未成功或凭据错误")
        return spec

    spec.cookies = {c.name: c.value for c in sess.cookies} or spec.cookies
    # 有些系统把令牌放在 JSON body 里
    if not spec.cookies:
        for key in ("token", "access_token", "accessToken", "jwt"):
            m = re.search(rf'"{key}"\s*:\s*"([^"]{{10,}})"', resp.text or "")
            if m:
                spec.headers.setdefault("Authorization", f"Bearer {m.group(1)}")
                break
    if not (spec.cookies or spec.headers.get("Authorization")):
        spec.rejected = "登录响应里既没有 Cookie 也没有 Token，无法维持会话"
    return spec


# ==============================================================================
# 会话回验
# ==============================================================================
_LOGIN_URL_RE = re.compile(r"(?i)/(login|signin|sign-in|logon|sso|passport|auth)")
_PW_FORM_RE = re.compile(r"(?i)<input[^>]+type=[\"']?password")
_FORM_RE = re.compile(r"(?i)<form")


def _fetch(url: str, account: dict[str, Any] | None, timeout: int) -> dict[str, Any]:
    """发一次回验请求。`account=None` 表示**对照请求**（不带任何凭据）。"""
    import requests

    kw: dict[str, Any] = {}
    if account:
        kw["headers"] = {**(account.get("headers") or {})}
        kw["cookies"] = {**(account.get("cookies") or {})}
    try:
        # 单发短会话 + 禁信环境代理（与 login_one 同纪律；回验对照请求
        # 也不该被环境代理改写，否则「匿名被拦 / 带凭据通过」的对照本身
        # 就建立在被代理污染的观测上）。
        _s = requests.Session()
        _s.trust_env = False
        r = _s.get(url, timeout=timeout, verify=False, allow_redirects=True, **kw)
    except Exception as e:  # noqa: BLE001
        return {"err": f"{type(e).__name__}: {str(e)[:100]}"}
    body = (r.text or "")[:20000]
    return {
        "err": "", "status": int(getattr(r, "status_code", 0) or 0),
        "final": str(getattr(r, "url", "") or ""), "body": body,
        # Content-Type 是「导出接口匿名可达」这类判定的关键证据：
        # 导出接口与普通页面同样返回 200，区分它们靠的就是响应类型
        # （spreadsheet / csv / pdf …）。不带这一项，调用方只能拿
        # 「状态码 200」下结论，而 200 在两者之间没有区分力。
        "ctype": str(r.headers.get("Content-Type", "") or ""),
        # 被弹回认证页：跳到登录地址，或页面出现登录表单。这两条都是
        # 「服务端认为你不该看这里」的表现。
        "bounced": bool(_LOGIN_URL_RE.search(str(getattr(r, "url", "") or ""))),
        "login_form": bool(_PW_FORM_RE.search(body) and _FORM_RE.search(body)),
        "denied": int(getattr(r, "status_code", 0) or 0) in (401, 403),
    }


def verify_session(account: dict[str, Any], target_url: str,
                   verify_path: str = "", timeout: int = 12) -> tuple[str, str]:
    """回验会话是否真的是「已登录」状态。返回 (状态, 说明)。

    **零凭据守卫（不可删）**：Cookie 与认证头都为空时，返回「未提供凭据」
    并且**一个请求都不发**。
    理由是一次实测出来的误报：「什么凭据都没有的账号」被判成「已登录」，
    `authenticated_pairs()` 记 1 个 —— 两个空账号就能满足「≥2 个已登录态」
    的门槛，扫描器随后以匿名身份去跑越权检测，产出一批复测不出来的「越权」
    结论。没有会话，就没有「会话是否有效」这个问题可谈。

    **对照实验（不可删）**：带凭据的请求「没被弹回」本身**不构成**会话有效的
    证据 —— 一个随手编的假 Cookie，访问站点公开页面同样 200。
    所以这里必须再发一次**不带凭据的对照请求**：
      · 对照被弹回/被拒 → 该页面确实需要登录 → 带凭据通过 = 会话有效（判「已登录」）
      · 对照也放行      → 该路径对「会话是否有效」毫无区分力 → 判「未验证」
    旧写法只有前半段，于是「根路径是公开页」的目标上，任何账号都会被判已登录。
    """
    if not (account.get("cookies") or account.get("headers")):
        return LOGIN_NO_CRED, (
            "该账号没有任何 Cookie 或认证头，没有会话可回验 —— "
            "不判「已登录」（匿名请求访问公开页同样不会被弹回登录页，"
            "只看「有没有被弹回」会把游客误判成已登录）")

    path = verify_path or "/"
    url = target_url.rstrip("/") + (verify_path or "/")
    with_cred = _fetch(url, account, timeout)
    if with_cred["err"]:
        return LOGIN_UNVERIFIED, f"回验请求失败（{with_cred['err'][:80]}），未确认登录态"
    if with_cred["bounced"]:
        return LOGIN_FAIL, (f"带会话访问被重定向到认证页"
                            f"（{with_cred['final'][:80]}），会话无效")
    # 401 / 403 = 服务端明确拒绝该身份。这条判据不能省：
    # 只判「有没有被弹回登录页」时，一个携带了无效 header 的账号会拿到 401，
    # 而 401 既没有重定向也没有表单 → 被误判成「已登录」。
    if with_cred["denied"]:
        return LOGIN_FAIL, (f"回验请求返回 {with_cred['status']}，服务端拒绝该身份，"
                            "会话不成立")

    # —— 对照请求 ——
    anon = _fetch(url, None, timeout)
    if anon["err"]:
        return LOGIN_UNVERIFIED, (
            f"对照请求（不带凭据）失败（{anon['err'][:60]}），"
            f"无法确认 {path} 是否真的需要登录 —— 未确认登录态")
    if (anon["bounced"] or anon["denied"]) and not with_cred["login_form"]:
        return LOGIN_OK, (
            f"带会话访问 {path} 未被弹回，而匿名访问被挡"
            f"（{'重定向到认证页' if anon['bounced'] else '返回 ' + str(anon['status'])}）"
            " —— 会话有效")
    if with_cred["login_form"]:
        return LOGIN_UNVERIFIED, ("回验页面含登录表单特征，无法区分「未登录被弹回」"
                                  "与「该页面本身就有表单」，未确认登录态")
    return LOGIN_UNVERIFIED, (
        f"{path} 匿名访问也能正常打开（{anon['status']}）—— "
        "该路径对「会话是否有效」没有区分力。请在账号配置里指定 verify_path "
        "为一个**需要登录才能访问**的页面（如个人中心 / 订单页），否则登录态只能判「未验证」")


# ==============================================================================
# 门面
# ==============================================================================
@dataclass
class SessionPool:
    accounts: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def by_role(self, role: str) -> dict[str, Any] | None:
        for a in self.accounts:
            if str(a.get("role")) == role:
                return a
        return None

    @property
    def usable(self) -> list[dict[str, Any]]:
        return [a for a in self.accounts if not a.get("rejected")]

    def authenticated_pairs(self) -> int:
        ok = [a for a in self.usable if a.get("login_state") == LOGIN_OK]
        return len(ok)

    def summary_lines(self) -> list[str]:
        return list(self.notes)


def build_pool(records: list[dict[str, Any]], target_url: str,
               profile_key: str = "standard",
               verify_path: str = "", allow_write: bool = False,
               domain: str = "", cred_file: Any = None,
               login_url: str = "") -> SessionPool:
    """构造会话池。

    档位门控：安全档不执行自动登录 —— 登录会在服务端创建会话、写登录日志，
    属于「对目标产生状态变化」的动作，与安全档「最低干扰」的定义冲突。
    人工 Cookie 通道不受此限（凭据由人工在浏览器取得，扫描器只是携带）。

    `domain` / `cred_file`：本机凭据库的位置。给了 domain 就按
    `~/.aiscan/sessions/<域名>.json` 自动定位；也可用 `cred_file` 显式指定。
    **凭据库的存在意义是让操作者不必设环境变量** —— 环境变量在 Windows 上
    要开新终端才生效、且每次重扫都得重设，实际使用中极易被跳过。

    `login_url`：探测到的登录入口（指纹阶段的证据）。凭据库里的「账号+密码」
    没带 login_url 时用它兜底 —— 探测是证据，不是猜测。
    """
    pool = SessionPool()
    lookup = None
    full_lookup = None
    cred_path: Any = cred_file
    if cred_path is None and domain:
        try:
            from engine import credguide  # noqa: PLC0415

            cred_path = credguide.session_file_for(domain)
        except Exception:  # noqa: BLE001
            cred_path = None
    if cred_path is not None:
        try:
            from engine import credguide  # noqa: PLC0415

            def lookup(nm: str) -> tuple[dict[str, str], dict[str, str]]:  # noqa: E306
                return credguide.credentials_for(nm, cred_path)

            def full_lookup(nm: str) -> dict[str, Any]:  # noqa: E306
                f = credguide.credentials_full(nm, cred_path)
                if not str(f.get("login_url") or "") and login_url:
                    f["login_url"] = str(login_url)
                return f
        except Exception:  # noqa: BLE001
            lookup = None
            full_lookup = None
            cred_path = None

    specs = load_specs(records, cred_lookup=lookup,
                       cred_full_lookup=full_lookup,
                       fallback_login_url=str(login_url or ""))
    if cred_path is not None:
        pool.notes.append(f"本机凭据库：{cred_path}")
    if not specs:
        # 这句过去是个**终点**：只说「缺什么」，不说「去哪拿」。
        # 现在必须带上取证指引 —— 否则「缺凭据」会永久停在「未执行」，
        # 谁也不知道该怎么补。
        pool.notes.append(
            "无授权测试账号 —— 越权 / IDOR / 横向 / 并发会话这类检查无法执行，"
            "将记为「未执行」，而不是「通过」。"
            "**注意这类检查属于「持账号的认证态测试」，与红队零凭据入场不是"
            "一回事**：红队那条路（自己找入口、自己识别产品查默认口令、"
            "自己上网找线索）由凭据情报与凭据获取完成，见报告 4.1 节。"
            "若确定要跑认证态测试，把一个**专用测试账号**交给凭据通道："
            f"python aiscan.py creds --target {domain or '<域名>'}")
        return pool

    for spec in specs:
        rec: dict[str, Any] = {
            "name": spec.name, "role": spec.role, "tenant": spec.tenant,
            "authorized": spec.authorized, "headers": dict(spec.headers),
            "cookies": dict(spec.cookies), "source": spec.source,
            "supplied_by": spec.supplied_by,
            "verify_path": spec.verify_path,
            "login_state": LOGIN_ABSENT, "login_note": "",
        }
        # 凭据由文件供上的，必须说出来：操作者的配置里写的是环境变量，
        # 实际生效的却是另一个来源。不说 = 他下次改了环境变量却发现没影响，
        # 排查方向整个是错的。
        if spec.supplied_by == "cred_file":
            pool.notes.append(
                f"账号「{spec.name}」的凭据取自本机凭据库"
                "（配置里指定的环境变量为空 —— 本机凭据库是并列的合法来源）")
        if spec.rejected:
            rec["rejected"] = spec.rejected
            # 「没配到凭据」不能写成「登录失败」—— 那是在报告里说一句没发生过的
            # 事。判据也不一样：前者该去补凭据，后者该去查账号密码。
            rec["login_state"] = (LOGIN_NO_CRED if spec.rejected_kind == "no_cred"
                                  else LOGIN_FAIL)
            pool.accounts.append(rec)
            pool.notes.append(f"账号「{spec.name}」未启用：{spec.rejected}")
            continue
        if not spec.authorized:
            rec["rejected"] = ("该账号未标记 authorized: true —— 未经授权的账号"
                               "不得用于任何身份相关测试")
            rec["login_state"] = LOGIN_NOT_AUTHORIZED
            pool.accounts.append(rec)
            pool.notes.append(f"账号「{spec.name}」未启用：未声明授权（authorized: true）")
            continue

        if spec.source == "auto_login":
            if profile_key == "safe":
                rec["login_state"] = LOGIN_UNVERIFIED
                rec["login_note"] = "安全档不执行自动登录（会在服务端创建会话）"
            else:
                spec = login_one(spec, target_url)
                if spec.rejected:
                    rec["rejected"] = spec.rejected
                    rec["login_state"] = LOGIN_FAIL
                    rec["login_note"] = spec.rejected
                    pool.notes.append(f"账号「{spec.name}」自动登录失败：{spec.rejected}")
                    pool.accounts.append(rec)
                    continue
                rec["headers"] = dict(spec.headers)
                rec["cookies"] = dict(spec.cookies)

        # 回验只对「手上确实有会话凭据」的账号做。
        # 旧写法是「只要不是登录失败就去回验」，于是零凭据账号也发一枪匿名请求，
        # 而匿名访问公开页同样不会被弹回登录页 → 被判「已登录」→
        # 两个空账号就凑够「≥2 个已登录态」，越权检测随后以游客身份开跑。
        # 这一条必须挡在发请求之前。
        has_cred = bool(rec.get("headers") or rec.get("cookies"))
        if not has_cred:
            if rec["login_state"] == LOGIN_UNVERIFIED:
                # 档位有意不登录：保持「未验证」，并说清是档位造成的
                rec["login_note"] = rec.get("login_note") or "档位限制，未尝试登录"
            else:
                rec["login_state"] = LOGIN_NO_CRED
                rec["login_note"] = ("配置里没有可用的会话凭据（Cookie / 认证头为空），"
                                     "未回验")
                pool.notes.append(
                    f"账号「{spec.name}」没有任何会话凭据 —— 该账号不参与身份相关测试；"
                    "凭据可用 `python aiscan.py creds --target "
                    f"{domain or '<域名>'} --set {spec.name}` 写入本机凭据库")
        elif rec["login_state"] != LOGIN_FAIL:
            # 每账号可覆盖回验路径：全局那个是默认值，具体账号最清楚自己的
            # 「登录后页面」是哪个。
            state, why = verify_session(rec, target_url,
                                        spec.verify_path or verify_path)
            rec["login_state"] = state
            rec["login_note"] = why

        pool.accounts.append(rec)

    ok = pool.authenticated_pairs()
    pool.notes.append(
        f"会话池：{len(specs)} 个账号配置，{len(pool.usable)} 个可用，"
        f"{ok} 个已确认登录态"
        + ("（≥2 个已确认登录态才能做「读到他人数据」的判定）" if ok >= 2
           else "（不足 2 个已确认登录态 → 越权类结论只能判「未能验证」）"))
    if ok < 2:
        # 缺凭据不是终点，是**待办**。给出取证指引的确切命令。
        pool.notes.append(
            "获取指引：python aiscan.py creds --target "
            f"{domain or '<域名>'}（会说明从哪取令牌、怎么交给工具）")
    return pool


if __name__ == "__main__":  # pragma: no cover
    print("会话池模块（无独立自测，随 aiscan.py selftest 一起验证）")
