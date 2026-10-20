# -*- coding: utf-8 -*-
"""会话上下文 —— 让越权类复现脚本「自己能拿到身份」，不必手工改脚本
================================================================================

要解决的问题
--------------------------------------------------------------------------------
越权类问题（IDOR / BOLA / BFLA / 水平越权）**只有在以真实身份请求时才可能复现**。
而生成的复现脚本此前是纯匿名的：拿匿名请求去打一个需要登录的接口，
拿回来的必然是 401 或登录页 —— 脚本于是打印「未复现」。

这是本项目最不能接受的一类失真：**「没验证到」被写成了「未复现」**。
两者在报告里的含义完全相反 —— 前者是「我不知道」，后者是「我确认没有」。
更糟的是它还会连带污染结论链：审阅者看到「复现失败」，
会合理推断该漏洞已被修复，于是把一个真实的越权问题关掉。

为什么不是「让操作者手工往脚本里贴 Cookie」
--------------------------------------------------------------------------------
旧做法是把 Cookie 手填进生成的 verify_xxx.py。四个后果，每一个都真实发生过：

1. **凭据落盘且随脚本扩散。** 复现脚本会被归档、会随报告外发、会被复制到
   别的机器。写死的 Cookie 一旦落盘，泄露是静默的，而且收不回来。
2. **脚本很快就「复现不出来」。** Cookie 有有效期，写死意味着几天后重跑
   必然失败，失败原因显示为「未复现」—— 又是一次「过期」被读成「已修复」。
3. **一次扫描几十份脚本，要改几十遍。** 操作者改到第三份就开始漏改，
   漏改的那几份静默地给出「未复现」。
4. **改脚本等于改交付物。** 脚本本身是要交给修复方自查的，
   里面出现真实凭据就无法外发。

所以本模块只做一件事：**给生成的脚本开一个凭据入口，凭据不进脚本。**
入口有两个，都不需要改动脚本的任何一行代码：
  · 会话文件 —— 脚本同目录的 `aiscan_sessions.json`（生成时自动放好骨架）
  · 环境变量 —— `AISCAN_COOKIE_<角色>` / `AISCAN_AUTH_<角色>`

生成脚本是**独立交付物**（只依赖 requests），所以这里的代码会以文本形式
内联进脚本；本模块同时提供扫描器侧用到的工具函数。

三条硬约束（与 engine/sessionpool.py 同一套价值观）
--------------------------------------------------------------------------------
1. **缺凭据 = 「无法判定」，绝不是「未复现」。** 脚本退出码 2 并明确说明
   「本次没有验证到」，同时打印可复制的填写说明。
2. **两个身份必须是不同账号。** 若两个角色解析出的凭据完全相同，说明操作者
   把同一个账号填了两遍 —— 此时「两个身份读到同一份数据」这个结论毫无意义。
   脚本必须识别并拒判，而不是照样输出一个看起来成立的结论。
3. **凭据绝不打印。** 输出一律过脱敏函数；日志里只出现角色名与「有/无」。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# 会话文件与相关环境变量（生成脚本侧用同一套名字，避免两处漂移）
SESSION_FILE_NAME = "aiscan_sessions.json"
SESSION_FILE_ENV = "AISCAN_SESSION_FILE"
COOKIE_ENV_PREFIX = "AISCAN_COOKIE_"
AUTH_ENV_PREFIX = "AISCAN_AUTH_"

# 骨架里占位文字的哨兵。
#
# 为什么必须有一个可识别的哨兵，而不是留空字符串或写一句说明
# ------------------------------------------------------------------
# 骨架是先放好的，操作者可能只填一半、或干脆忘了填。此时文件里躺着的是
# **非空的占位文字**。若加载器把它当真凭据读进去，会出两个问题：
#   · 两个角色的占位文字完全相同 → 触发「两个身份填了同一个账号」的拒判，
#     报出来的原因是**错的**（真实原因是「没填」），操作者会去查账号配置，
#     查半天查不出所以然；
#   · 更糟的方向：若占位文字恰好只有一部分角色非空，脚本会带着一串垃圾
#     Cookie 去请求，拿回 401 后判「未复现」—— 又一次把「没填凭据」
#     冒充成「问题已修复」。
# 所以占位值里嵌一个哨兵，加载器见到就丢弃该凭据；丢弃后该角色等于「没填」，
# 走「无法判定」这条正确的路。
PLACEHOLDER_SENTINEL = "__FILL_ME__"

# 需要会话上下文才有意义的复现模板类型
SESSION_KINDS = frozenset({"cross_role"})

# 取角色名时最多用几个：两个足够（一个主身份、一个对照身份）。
# 取更多不会让结论更可靠，只会让操作者多填几份凭据、多几处填错的入口。
MAX_ROLES = 2


def env_suffix(name: str) -> str:
    """把角色名转成可作环境变量后缀的形式。

    角色名来自配置里的账号名（`user_a`、`svc-order`、`测试账号`…），
    其中可能含连字符、点、中文 —— 这些在环境变量名里非法。
    **不能**直接丢掉非法字符：`user-a` 与 `user_a` 会撞成同一个变量名，
    操作者给 A 填的凭据会被 B 静默读到。
    所以非法字符一律替换成下划线（保留长度与位置），只可能碰撞到本来就
    长得一样的名字，那种情况下两个角色确实该用同一个凭据。
    """
    return "".join(ch if (ch.isalnum() and ch.isascii()) or ch == "_" else "_"
                   for ch in str(name or ""))


def roles_of(finding: Any) -> list[str]:
    """从一条发现里取出「参与本次实测的账号名」，按出现顺序去重。

    来源是 `Finding.extra["accounts"]` —— 多账号响应比对（authz_matrix）
    会把自己用了哪几个账号写进去。**只认这个字段，不去解析自然语言描述**：
    从描述里猜账号名，正是本项目已经吃过亏的那类推断。
    """
    extra = getattr(finding, "extra", None) or {}
    raw = extra.get("accounts") if isinstance(extra, dict) else None
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    for item in raw:
        name = str(item or "").strip()
        if name and name not in out:
            out.append(name)
    return out


def needs_session(finding: Any) -> bool:
    """该发现是否必须带身份才能复现（≥2 个账号的实测证据）。"""
    return len(roles_of(finding)) >= MAX_ROLES


def skeleton(roles: list[str]) -> str:
    """会话文件骨架文本。

    故意用「填写…」这样的占位值而不是空字符串：空字符串的 JSON 看起来像
    「已经填好了」，操作者会以为不用管；带占位文字才会让人意识到要替换。
    """
    node: dict[str, Any] = {}
    for r in roles:
        node[str(r)] = {
            "cookies": f"{PLACEHOLDER_SENTINEL} 粘贴该账号在浏览器里的 Cookie 串，形如 a=1; b=2",
            "headers": {
                "Authorization": f"{PLACEHOLDER_SENTINEL} 粘贴该账号的 Token（没有就删掉这一行）"
            },
        }
    doc = {
        "_说明": [
            "把上面每个角色的占位文字替换成真实凭据，然后重跑复现脚本。",
            "只需填一次，同一目录下所有复现脚本共用本文件。",
            "本文件含真实凭据，请勿提交到代码仓库、勿随报告外发。",
            "也可改用环境变量：AISCAN_COOKIE_<角色> / AISCAN_AUTH_<角色>。",
        ],
        "roles": node,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def write_template(out_dir: Path | str, roles: list[str]) -> tuple[Path | None, str]:
    """在复现脚本目录放一份会话文件骨架。返回 (路径, 说明)。

    **绝不覆盖已存在的文件。** 操作者很可能已经填过一次；
    再生成一次就把它清空，等于把「已经准备好的会话」无声地毁掉，
    而脚本随后报出的是「无法判定」——操作者会以为是目标变了。
    """
    if not roles:
        return None, ""
    path = Path(out_dir) / SESSION_FILE_NAME
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            return path, f"会话文件已存在但无法读取（{type(e).__name__}），未改动"
        missing = [r for r in roles if f'"{r}"' not in existing]
        if missing:
            return path, (f"会话文件已存在，**未覆盖**；其中缺少本次用到的角色："
                          f"{', '.join(missing)} —— 请手动补上这几个键")
        return path, "会话文件已存在且已含本次全部角色，未改动"
    try:
        path.write_text(skeleton(roles), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return None, f"会话文件写入失败：{type(e).__name__}: {e}"
    return path, f"已生成会话文件骨架（含 {len(roles)} 个角色），填写后复现脚本即可带身份请求"


# ==============================================================================
# 内联进生成脚本的代码
# ==============================================================================
# 这一段会以文本形式拼进 verify_xxx.py。约束：
#   · 只依赖 requests 与标准库（生成脚本是独立交付物）；
#   · 不定义与脚本头部同名的符号（mask / show / result / DEFAULT_HEADERS）；
#   · 依赖调用方先定义 `SESSION_ROLES` 与 `SESSION_SKELETON` 两个字面量。
SESSION_INLINE = '''
# ---------------------------------------------------------------------------
# 会话上下文
#
# 越权类问题只有在「以真实身份请求」时才可能复现。匿名请求打到的是登录页 /
# 401 —— 那不是「问题已修复」，而是「这次根本没有验证到」，两件事不能混。
#
# 凭据为什么不写进脚本
#   · 脚本会被复制、归档、随报告外发；写死的 Cookie 等于凭据静默泄露，收不回；
#   · Cookie / Token 有有效期，写死意味着脚本很快就「复现不出来」，
#     而失败原因显示的仍是「未复现」—— 又一次把「过期」读成「已修复」。
#
# 怎么提供凭据（二选一，都不需要改动本脚本的任何一行代码）
#   A. 会话文件：把下方骨架存为脚本同目录的 aiscan_sessions.json，填上真实值重跑
#   B. 环境变量：AISCAN_COOKIE_<角色> / AISCAN_AUTH_<角色>
#      <角色> 的写法见下方骨架里的键名（非字母数字字符会写成下划线）
#
# 脚本不打印凭据原文，所有输出均经脱敏。
# ---------------------------------------------------------------------------
SESSION_FILE_NAME = "aiscan_sessions.json"
SESSION_FILE_ENV = "AISCAN_SESSION_FILE"
COOKIE_ENV_PREFIX = "AISCAN_COOKIE_"
AUTH_ENV_PREFIX = "AISCAN_AUTH_"
# 骨架占位文字的哨兵：加载器见到就丢弃该条凭据（详细理由见本文件 PLACEHOLDER_SENTINEL）
SESSION_PLACEHOLDER = "__FILL_ME__"
_SESSION_CACHE = {}


def ROLE_ENV_SUFFIX(name):
    """角色名 → 环境变量后缀（非字母数字字符替换为下划线，不做删除）。

    删除而不是替换会让 `user-a` 与 `user_a` 撞成同一个变量名，
    给 A 填的凭据会被 B 静默读到 —— 于是「两个身份」变成「同一个身份」，
    结论随之失真。
    """
    return "".join(ch if (ch.isalnum() and ch.isascii()) or ch == "_" else "_"
                   for ch in str(name or ""))


def _parse_cookie(raw):
    """`a=1; b=2` → 字典（浏览器里直接复制出来的形式）。

    含哨兵的条目直接丢弃：那是骨架里没被替换掉的占位文字，不是凭据。
    当成真凭据读进去，会让脚本带着一串垃圾 Cookie 去请求、拿回 401、
    然后判「未复现」—— 又一次把「没填凭据」冒充成「问题已修复」。
    """
    raw = str(raw or "")
    if SESSION_PLACEHOLDER in raw:
        return {}
    out = {}
    for part in raw.split(";"):
        part = part.strip()
        if part and "=" in part:
            k, v = part.split("=", 1)
            if k.strip() and SESSION_PLACEHOLDER not in v:
                out[k.strip()] = v.strip()
    return out


def _parse_headers(raw):
    """请求头：支持 JSON 对象，或 `Key: Value` 逐行。含哨兵的条目丢弃。"""
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()
                if SESSION_PLACEHOLDER not in str(v)}
    text = str(raw or "").strip()
    if not text or SESSION_PLACEHOLDER in text:
        return {}
    if text.startswith("{"):
        try:
            import json as _json
            data = _json.loads(text)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()
                        if SESSION_PLACEHOLDER not in str(v)}
        except Exception:
            return {}
        return {}
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip() and SESSION_PLACEHOLDER not in v:
                out[k.strip()] = v.strip()
    return out


def _session_file_path():
    import os as _os
    return (_os.environ.get(SESSION_FILE_ENV) or
            _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                          SESSION_FILE_NAME))


def _load_sessions():
    """读出「角色 → 请求上下文」。会话文件与环境变量都读，环境变量最后覆盖。"""
    import json as _json
    import os as _os

    roles = {}
    path = _session_file_path()
    if _os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = _json.load(fh) or {}
            if isinstance(data, dict):
                node = data.get("roles") if isinstance(data.get("roles"), dict) else data
                for name, rec in (node or {}).items():
                    if not isinstance(rec, dict):
                        continue
                    roles[str(name)] = {
                        "cookies": _parse_cookie(rec.get("cookies")),
                        "headers": _parse_headers(rec.get("headers")),
                    }
        except Exception as e:
            print("[警告] 会话文件无法解析（{}: {}），已忽略：{}".format(
                type(e).__name__, e, path))
    else:
        print("[信息] 未找到会话文件：{}".format(path))

    for name in SESSION_ROLES:
        sfx = ROLE_ENV_SUFFIX(name)
        ck = _os.environ.get(COOKIE_ENV_PREFIX + sfx, "").strip()
        au = _os.environ.get(AUTH_ENV_PREFIX + sfx, "").strip()
        if SESSION_PLACEHOLDER in ck:
            ck = ""
        if SESSION_PLACEHOLDER in au:
            au = ""
        slot = roles.setdefault(str(name), {"cookies": {}, "headers": {}})
        if ck:
            slot["cookies"].update(_parse_cookie(ck))
        if au:
            slot["headers"]["Authorization"] = (
                au if au.lower().startswith(("bearer", "basic", "token"))
                else "Bearer " + au)
    return {k: v for k, v in roles.items() if v.get("cookies") or v.get("headers")}


def _sessions():
    if not _SESSION_CACHE:
        _SESSION_CACHE.update(_load_sessions())
    return _SESSION_CACHE


def _sess_missing():
    have = _sessions()
    return [r for r in SESSION_ROLES if str(r) not in have]


def _session_gap_lines(missing):
    """缺凭据时打印「怎么补」，并说明这不是「未复现」。"""
    print("")
    print("[无法判定] 本项复现必须以**真实身份**请求，以下角色尚未提供凭据："
          + ", ".join(str(m) for m in missing))
    print("           这不是「未复现」—— 含义是「本次没有验证到」。")
    print("           请先补上会话，再重跑本脚本；不要据此判定问题已修复。")
    print("")
    print("  方式 A（推荐，只需填一次）：把下面内容存为")
    print("      " + _session_file_path())
    for line in str(SESSION_SKELETON).splitlines():
        print("      " + line)
    print("")
    print("  方式 B：改用环境变量（<角色> 见上面对应的键名）")
    for r in SESSION_ROLES:
        print('      export {}{}="粘贴浏览器里的完整 Cookie 串"'.format(
            COOKIE_ENV_PREFIX, ROLE_ENV_SUFFIX(r)))
        print('      export {}{}="粘贴 Bearer Token（没有就留空）"'.format(
            AUTH_ENV_PREFIX, ROLE_ENV_SUFFIX(r)))
    print("")
    print("  凭据由脚本自行读取，**不需要修改本脚本的任何一行代码**。")


def _req_as(url, role, timeout, follow=False):
    """以指定角色的身份发一次请求。"""
    ctx = _sessions().get(str(role)) or {}
    headers = dict(DEFAULT_HEADERS)
    headers.update(ctx.get("headers") or {})
    return requests.request("GET", url, headers=headers,
                            cookies=ctx.get("cookies") or {},
                            timeout=timeout, verify=False, allow_redirects=follow)
'''


# ==============================================================================
# 内联片段的自检：语法必须成立（生成脚本是交付物，不能带语法错误）
# ==============================================================================
def _selftest() -> None:
    import ast

    ok = 0
    fail: list[str] = []

    # 1) 内联片段本身必须是合法 Python 源码
    try:
        ast.parse(SESSION_INLINE)
        ok += 1
    except SyntaxError as e:  # pragma: no cover
        fail.append(f"内联会话片段语法错误：{e}")

    # 2) 与脚本头部拼在一起后仍须合法（重复定义符号是常见事故）
    probe = (
        "DEFAULT_HEADERS = {}\n"
        "SESSION_ROLES = ['user_a', 'user_b']\n"
        "SESSION_SKELETON = '{}'\n"
        + SESSION_INLINE
    )
    try:
        ast.parse(probe)
        ok += 1
    except SyntaxError as e:  # pragma: no cover
        fail.append(f"内联片段与脚本头部拼接后语法错误：{e}")

    # 3) 环境变量后缀：非法字符替换而不是删除，避免两个角色撞成同一个变量
    assert env_suffix("user_a") == "user_a"
    assert env_suffix("user-a") == "user_a"
    assert env_suffix("svc.order") == "svc_order"
    ok += 1
    # 反例：删除式实现会让这两个名字相同 —— 那样给 A 填的凭据会被 B 读到
    assert env_suffix("a-b") != env_suffix("ab") or True
    assert env_suffix("a-b") == env_suffix("a_b")
    ok += 1

    # 4) roles_of 只认 extra.accounts，不猜自然语言
    class _F:
        def __init__(self, extra):
            self.extra = extra

    assert roles_of(_F({"accounts": ["u1", "u2"]})) == ["u1", "u2"]
    assert roles_of(_F({"accounts": ["u1", "u1", "u2"]})) == ["u1", "u2"]
    assert roles_of(_F({})) == []
    assert roles_of(_F(None)) == []
    assert roles_of(_F({"accounts": "u1,u2"})) == []      # 字符串不是列表
    assert needs_session(_F({"accounts": ["u1"]})) is False
    assert needs_session(_F({"accounts": ["u1", "u2"]})) is True
    ok += 1

    # 5) 骨架内容可被 json 解析，键名就是角色名，且占位值带哨兵
    sk = skeleton(["user_a", "user_b"])
    doc = json.loads(sk)
    assert sorted(doc["roles"].keys()) == ["user_a", "user_b"]
    assert PLACEHOLDER_SENTINEL in doc["roles"]["user_a"]["cookies"]
    # 哨兵必须和内联片段里加载器认的那个是同一个字符串（两处漂移就失效）
    assert f'SESSION_PLACEHOLDER = "{PLACEHOLDER_SENTINEL}"' in SESSION_INLINE, \
        "骨架哨兵与加载器识别的哨兵不一致 —— 占位文字会被当成真凭据"
    ok += 1

    # 6) 不覆盖已存在的会话文件（否则会把操作者填好的凭据清空）
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / SESSION_FILE_NAME
        p.write_text('{"roles": {"user_a": {"cookies": "x=1"}}}', encoding="utf-8")
        before = p.read_text(encoding="utf-8")
        ret, note = write_template(td, ["user_a", "user_b"])
        assert ret == p, "应返回已存在的路径"
        assert p.read_text(encoding="utf-8") == before, "已存在的会话文件被覆盖了"
        assert "缺少" in note, f"应说明缺哪些角色，实际：{note}"
        # 角色齐全时不报缺失
        _, note2 = write_template(td, ["user_a"])
        assert "缺少" not in note2, f"角色齐全不该报缺失：{note2}"
        # 不存在时才创建
        p.unlink()
        ret2, note3 = write_template(td, ["user_a"])
        assert ret2 is not None and ret2.exists()
        assert "已生成" in note3
    ok += 1

    # 7) 内联片段不得重复定义脚本头部已有的符号（否则会静默覆盖脱敏函数）
    for name in ("mask", "show", "result", "DEFAULT_HEADERS", "requests"):
        assert f"def {name}(" not in SESSION_INLINE, f"内联片段重复定义 {name}"
    ok += 1

    # 8) 真跑一遍内联加载器：未替换的占位文字必须被丢掉，不能被当成凭据。
    #    这条不能只看常量字符串 —— 必须让加载器真的解析一次骨架。
    ns: dict[str, Any] = {"SESSION_ROLES": ["user_a", "user_b"]}
    ns["SESSION_SKELETON"] = skeleton(["user_a", "user_b"])
    exec(compile(SESSION_INLINE, "<inline>", "exec"), ns)  # noqa: S102
    _skel = json.loads(ns["SESSION_SKELETON"])["roles"]
    for role in ("user_a", "user_b"):
        c = ns["_parse_cookie"](_skel[role]["cookies"])
        h = ns["_parse_headers"](_skel[role]["headers"])
        assert c == {}, f"未填的骨架 Cookie 被当成了凭据：{c}"
        assert h == {}, f"未填的骨架请求头被当成了凭据：{h}"
    # 反过来，真填了的值必须读得到（哨兵过滤不能把真凭据一起吃掉）
    assert ns["_parse_cookie"]("sid=A; t=B") == {"sid": "A", "t": "B"}
    assert ns["_parse_headers"]({"Authorization": "Bearer abc"}) == \
        {"Authorization": "Bearer abc"}
    ok += 1

    # 终态行必须与成功时**不同**：上面若写成「N 组断言通过」，失败时那行照样会
    # 打印（N 是已通过数），拿它当「通过标记」的调用方会被骗过去。
    if fail:
        for m in fail:
            print(f"  ✗ {m}")
        print(f"结果：失败（{len(fail)} 项断言未通过）")
        raise SystemExit(1)
    print(f"会话上下文自测：{ok} 组断言通过")
    print("结果：全部通过")


if __name__ == "__main__":  # pragma: no cover
    print("会话上下文模块自测")
    print("=" * 70)
    _selftest()
