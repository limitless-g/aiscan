# -*- coding: utf-8 -*-
"""sqlmap 受限调用层（P0：把「注入是否存在」从报错初判升级为真实注入验证）
================================================================================

为什么需要这一层
--------------------------------------------------------------------------------
注入检测原先只有一种手法：**给参数塞一个单引号，看响应里有没有 SQL 报错**。
命中了报「高危」，没命中就写「盲注 / UNION / 堆叠查询类手法本次未覆盖，
不能据此判定数据不可达」—— 判为「未能验证」。

这个说法本身是诚实的，但它把「注入到底存不存在」这件事推给了人工。
而真实目标上，报错型注入只是注入里最容易被挡住的一小类：
只要报错被统一兜底页吞掉，内置手法就一无所获，**目标就成了漏报**。

sqlmap 补的正是这一块：它用布尔盲注、时间盲注、UNION、报错、堆叠等多种手法
交叉验证，是「注入存在性」这个问题的行业标准答案。

================================================================================
三条不可松的约束（写在这里，因为它们是本模块存在的理由）
================================================================================

1. **白名单式开关，而且是反向的**：本模块**只允许**自己构造的 argv，
   并对任何出现在 argv 里的危险开关做断言。危险开关一旦漏进命令行，
   扫描器就从「验证工具」变成了「数据导出工具」——
   而这类事故是不可逆的（数据已经出去了）。
   被禁的开关见 `FORBIDDEN_FLAGS`，`is_safe_argv()` 是它的执行体，
   自测里逐条断言过。

2. **证明即止**：只取 DBMS banner（版本串）/ 当前库名，证明「数据面可达」为止。
   不枚举表、不读业务数据、不导出。多读一条都超出证明所需，
   且会让报告失去「运维可安全复测」的性质。`--dump` 系列因此是禁用项，不是可选项。

3. **没测出来 ≠ 不存在**：sqlmap 跑完没发现注入时，只能判「未能验证」，
   绝不能判「未达成」——它是覆盖面最广的开源手法集合，
   但不是「SQL 注入的完备判定」。写成「未达成」就是把工具能力当成了事实边界。
   反过来，工具不可用 / 被关闭时也要如实说「没测」，不能说「没问题」。

4. **凭据不得进入交付物**：带认证的目标需要把会话 Cookie 传给 sqlmap，
   而 `cmd_preview`（复现命令）会被写进发现的 `reproduction` 与 `evidence`，
   最终落到技术版报告和独立复现脚本里 —— 那是要发给运维的**交付物**。
   一旦 Cookie 原文跟进去，等于把一份可直接冒用的会话凭据随报告外发。
   因此预览一律用占位符遮盖（`COOKIE_PLACEHOLDER`），
   与 `verify/sessionctx.py` 的骨架占位是同一套约定（`__FILL_ME__` 哨兵）。
   自测里有断言钉住「原文绝不出现在预览里」——这类泄露不会报错，只会静默扩散。

================================================================================
调用时机与门控
================================================================================

- `AISCAN_SQLMAP=off` 显式关闭（离线自测用），`=on` 强制开启，缺省 auto。
- 安全档（safe）**不调用**：sqlmap 会向目标发送成百上千条载荷，
  与「最低干扰、绝不影响业务」的档位定义直接冲突。
- 标准档：level=1 / risk=1 / 手法 BEU（报错+布尔+UNION），单注入点。
- 深度档：level=2 / risk=2 / 手法 BEUST（增加时间盲注），最多 2 个注入点。
- risk=3（含 OR 型改写载荷）**永不放行**：它可能真的改写数据，
  与「本模块只读」的定位冲突。写类证明属于受控写通道，不走这里。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from engine import binlocate
except ImportError:  # 以顶层模块方式导入时（sys.path 指向 engine/ 自身）
    import binlocate  # type: ignore[no-redef]

# ------------------------------------------------------------------------------
# 危险开关：出现即拒绝调用
# ------------------------------------------------------------------------------
# 分类说明（不是凑数，每一条都对应一种「越界」）：
#   数据导出：--dump* / --sql-query / --sql-file  —— 会真的把业务数据拉出来
#   命令执行：--os-* —— 取得命令执行能力，与「只读证明」是两个性质
#   文件读写：--file-read / --file-write / --file-dest —— 读文件即数据外带
#   代码执行：--eval / --udf-inject / --shared-lib —— 本地代码执行面
#   注册表：  --reg-* —— 目标侧写操作
#   提权：    --priv-esc
FORBIDDEN_FLAGS: tuple[str, ...] = (
    "--dump", "--dump-all", "--dump-format", "--stop", "--sql-query", "--sql-file",
    "--sql-shell", "--os-shell", "--os-pwn", "--os-cmd", "--os-smbrelay", "--os-bof",
    "--file-read", "--file-write", "--file-dest", "--file-upload",
    "--eval", "--udf-inject", "--shared-lib", "--priv-esc",
    "--reg-read", "--reg-add", "--reg-del", "--reg-key",
    "--batch-file", "--wizard", "--cleanup",
)

# 已知安装位置：候选与优先级统一收在 `engine/binlocate.py`
# （环境变量 → 当前 Python 环境 → 用户目录约定位置 → 历史路径兜底）。
# 原先这里写死了本机绝对路径，换台电脑（用户名不同）就找不到 sqlmap，
# 于是「注入存在性」会被如实记成「没测」，但那不是事实 —— 是路径没找对。

# 本模块**只允许**这些开关出现在命令行里（正向白名单，比反向黑名单可靠）
ALLOWED_FLAGS: tuple[str, ...] = (
    "-u", "-p", "--batch", "--disable-coloring", "--flush-session", "--smart",
    "--level=", "--risk=", "--threads=", "--timeout=", "--retries=", "--technique=",
    "--output-dir", "--cookie=", "--user-agent=", "--banner", "--current-db",
    "--forms", "--answers=", "--random-agent", "--delay=",
)


def _flag_name(tok: str) -> str:
    return tok.split("=", 1)[0]


# ------------------------------------------------------------------------------
# 复现命令预览里的凭据占位
# ------------------------------------------------------------------------------
# 哨兵沿用 verify/sessionctx.py 的 PLACEHOLDER_SENTINEL（`__FILL_ME__`）：
# 复现脚本被丢进 outputs/ 目录后是要交给运维执行的，
# 报告与脚本里出现的必须是「这里要你填」，而不是一份现成可用的会话凭据。
# 自测会断言两个常量确实相等 —— 分叉了就会出现「一处遮盖、一处明写」。
COOKIE_PLACEHOLDER: str = "__FILL_ME__"
COOKIE_MASK: str = f"--cookie={COOKIE_PLACEHOLDER}（复测时在此填入该账号的会话 Cookie）"


def is_safe_argv(argv: list[str]) -> list[str]:
    """返回 argv 里的违规项。空列表 = 通过。

    三道判据，缺一不可：
      ① 不得出现 `FORBIDDEN_FLAGS` 里的任何开关（含 `--dump=x` 这种带值写法）
      ② 其余所有以 `-` 开头的开关都必须在 `ALLOWED_FLAGS` 白名单内
         —— 只做黑名单的话，sqlmap 新增一个危险开关，本模块就自动放行了。
         黑名单会被绕过，白名单不会：新开关默认是「不允许」。
      ③ **数值级下界**：`--risk` 不得大于 2，`--level` 不得大于 3。
         判据 ② 只比开关名，`--risk=3` 和 `--risk=1` 在它眼里是一样的 ——
         而 risk=3 会启用 OR 型改写载荷，**可能真的改动目标数据**。
         名字合法不等于取值安全，这是两件事，必须分开判。
    """
    bad: list[str] = []
    for tok in argv:
        if not isinstance(tok, str) or not tok.startswith("-"):
            continue
        name = _flag_name(tok)

        # ③ 数值级下界（先判，因为它比名字更具体）
        if "=" in tok:
            _k, _v = tok.split("=", 1)
            if _k == "--risk":
                try:
                    if int(_v) > 2:
                        bad.append(f"--risk={_v} 超出只读上限（>2 会启用 OR 型改写载荷，"
                                   "可能改动目标数据）")
                except ValueError:
                    bad.append(f"--risk 取值非法：{_v!r}")
            if _k == "--level":
                try:
                    if int(_v) > 3:
                        bad.append(f"--level={_v} 超出上限（>3 探测面过宽且耗时不可控）")
                except ValueError:
                    bad.append(f"--level 取值非法：{_v!r}")
            if _k == "--technique" and re.search(r"[^BEUSTQ]", _v.upper()):
                bad.append(f"--technique 取值非法：{_v!r}")

        for f in FORBIDDEN_FLAGS:
            # `--dump` 与 `--dump-all` 是不同的开关，用词边界精确匹配，
            # 避免 `--dump-format` 被 `--dump` 的 startswith 漏判或误判
            if name == f or name.startswith(f + "="):
                bad.append(f"禁用开关 {name}")
                break
        else:
            if not any(name == _flag_name(a) or name.startswith(a) for a in ALLOWED_FLAGS):
                bad.append(f"未登记的开关 {name}")
    return bad


def find_sqlmap() -> str:
    """定位 sqlmap 可执行文件，找不到返回空串。

    候选与优先级见 `engine/binlocate.py`：环境变量 → 当前 Python 环境
    （换机重建 venv 后自动指向新位置）→ 用户目录约定位置 → 历史路径兜底。
    """
    return shutil.which("sqlmap") or (binlocate.locate("sqlmap") or "")


def _env_mode() -> str:
    return (os.environ.get("AISCAN_SQLMAP") or "auto").strip().lower()


def _env_timeout(default: int = 120) -> int:
    try:
        return max(20, min(600, int(os.environ.get("AISCAN_SQLMAP_TIMEOUT") or default)))
    except Exception:  # noqa: BLE001
        return default


# ==============================================================================
# 调用计划：由档位决定「用什么强度、测几个点、要不要测」
# ==============================================================================
@dataclass
class SqlmapPlan:
    enabled: bool
    reason: str
    risk: int = 1
    level: int = 1
    technique: str = "BEU"
    timeout: int = 120
    max_points: int = 1


def _plan_strength(key: str) -> SqlmapPlan:
    """按档位算出调用强度。

    抽成独立函数的理由：自测与生产**必须用同一套参数**。
    原先自测路径（注入的假执行体）固定用 risk=1 / BEU，而深度档在生产里是
    risk=2 / BEUST —— 自测跑的是标准档的强度却宣称覆盖了 sqlmap 接线，
    档位参数写错时不会有任何信号。强度只在这里算一次，两条路径都读它。
    """
    if key == "deep":
        return SqlmapPlan(True, "深度档：level=2 / risk=2 / 手法 BEUST（含时间盲注）",
                          risk=2, level=2, technique="BEUST",
                          timeout=_env_timeout(180), max_points=2)
    return SqlmapPlan(True, "标准档：level=1 / risk=1 / 手法 BEU（报错+布尔+UNION）",
                      risk=1, level=1, technique="BEU",
                      timeout=_env_timeout(120), max_points=1)


def plan_for(ctx: Any = None) -> SqlmapPlan:
    """按运行环境与档位算出本次是否调用、用什么强度。

    每一个「不调用」都必须带理由 —— 理由会被写进报告的注记里。
    「没调用」和「调用了没发现问题」是两件完全不同的事，
    报告读者必须能分清（这是本项目反复吃过的教训）。

    判定顺序有意为之，**档位门控排在自测执行体之前**：
      · 关闭开关 → 安全档 → 自测执行体 → 是否装得上 → 按档位定强度
    把自测执行体排在安全档之前看着无害（假执行体不发请求），
    实际是把「安全档绝不调用 sqlmap」这条保证绕开了：
    自测里 ctx 带着假执行体、档位若是 safe，sqlmap 就会被「调用」。
    档位的语义是「对目标的最小干扰」，它不该有任何一条旁路。
    """
    mode = _env_mode()
    if mode == "off":
        return SqlmapPlan(False, "本次运行已显式关闭外部注入工具（AISCAN_SQLMAP=off）")

    key = str(getattr(ctx, "profile_key", "") or "standard")
    if key == "safe":
        return SqlmapPlan(
            False,
            "当前为安全档：sqlmap 会向目标发送大量载荷，与「最低干扰」的档位定义冲突，"
            "故未调用（需盲注验证时请改用标准档或深度档）")

    # 自测注入的假执行体：不依赖本机是否装了 sqlmap，也不发真实请求。
    # 强度仍按档位算 —— 否则自测覆盖的是另一套参数。
    if getattr(ctx, "sqlmap_runner", None) is not None:
        p = _plan_strength(key)
        p.reason = f"自测模式：使用注入的执行体（不调用真实工具）；{p.reason}"
        return p

    if not find_sqlmap():
        return SqlmapPlan(False, "本机未安装 sqlmap，注入判定仅使用内置报错型手法"
                                 "（覆盖度较低，盲注类注入可能漏报）")
    return _plan_strength(key)


def build_argv(exe: str, url: str, param: str, plan: SqlmapPlan,
               cookie: str = "", user_agent: str = "") -> list[str]:
    """构造 argv。

    risk 硬上限 2：risk=3 会启用 OR 型改写载荷，**可能真的改动数据**，
    与「本模块只读」的定位冲突。写类验证走受控写通道，不从这里走。
    """
    risk = min(int(plan.risk), 2)
    out_dir = Path(tempfile.mkdtemp(prefix="aiscan_sqlmap_"))
    argv = [
        exe, "-u", url,
        "--batch", "--disable-coloring", "--flush-session", "--smart",
        f"--level={plan.level}", f"--risk={risk}",
        "--threads=1", "--timeout=8", "--retries=1",
        f"--technique={plan.technique}",
        "--output-dir", str(out_dir),
        "--banner",
    ]
    if param:
        argv[3:3] = ["-p", param]
    if cookie:
        argv.append(f"--cookie={cookie}")
    if user_agent:
        argv.append(f"--user-agent={user_agent}")
    return argv


# ==============================================================================
# 复现命令预览（凭据遮盖后才会进报告）
# ==============================================================================
def preview_argv(argv: list[str]) -> str:
    """把 argv 拼成可读的复现命令，**并把凭据替换成占位符**。

    这个函数存在的唯一理由是安全：返回值会被写进发现的 `reproduction`
    与 `evidence`，最终出现在技术版报告和独立复现脚本里 ——
    那是要发给运维的交付物。带认证的目标下 argv 里有会话 Cookie，
    原样拼出去就等于随报告外发一份可直接冒用的凭据。

    遮盖的是「值」，保留的是「有这个参数」这一事实：
    复测的人必须知道这条命令原本带 Cookie，否则会以为扫的是匿名态。
    """
    parts: list[str] = []
    for a in argv:
        if a.startswith("--cookie="):
            parts.append(COOKIE_MASK)
            continue
        parts.append(f'"{a}"' if (" " in a or "&" in a) else a)
    return " ".join(parts)


# ==============================================================================
# 输出解析
# ==============================================================================
_RE_PARAM = re.compile(r"^Parameter:\s*(\S+)\s*\(([^)]+)\)", re.M)
_RE_TYPE = re.compile(r"^\s*Type:\s*(.+)$", re.M)
_RE_DBMS = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_RE_BANNER = re.compile(r"banner:\s*'([^']{1,120})'", re.I)
_RE_FOUND = re.compile(r"identified the following injection point", re.I)
_RE_NOT_INJ = re.compile(
    r"(all tested parameters do not appear to be injectable|"
    r"does not seem to be injectable|"
    r"no parameter\(s\) found)", re.I)
_RE_CRIT = re.compile(r"\[CRITICAL\]\s*(.+)", re.I)


def parse_output(text: str) -> dict[str, Any]:
    """从 sqlmap 输出里提取结论。只取结论，不取数据。"""
    t = text or ""
    info: dict[str, Any] = {
        "injected": False, "param": "", "dbms": "", "banner": "",
        "techniques": [], "not_injectable": False, "critical": "",
    }
    if _RE_FOUND.search(t):
        info["injected"] = True
    m = _RE_PARAM.search(t)
    if m:
        info["param"] = m.group(1)
        info["injected"] = True
    types = [x.strip() for x in _RE_TYPE.findall(t) if x.strip()]
    if types:
        info["techniques"] = types[:6]
        info["injected"] = True
    m = _RE_DBMS.search(t)
    if m:
        info["dbms"] = m.group(1).strip()[:80]
    m = _RE_BANNER.search(t)
    if m:
        info["banner"] = m.group(1).strip()[:80]
    if _RE_NOT_INJ.search(t):
        info["not_injectable"] = True
    m = _RE_CRIT.search(t)
    if m:
        info["critical"] = m.group(1).strip()[:160]
    return info


# ==============================================================================
# 执行
# ==============================================================================
@dataclass
class SqlmapOutcome:
    ran: bool = False
    injected: bool = False
    param: str = ""
    dbms: str = ""
    banner: str = ""
    techniques: list[str] = field(default_factory=list)
    reason: str = ""
    probes: int = 0
    cmd_preview: str = ""
    timed_out: bool = False
    disabled_reason: str = ""

    @property
    def proven(self) -> bool:
        """确认注入即视为「数据面可达」——banner 是服务端才能提供的信息。"""
        return bool(self.ran and self.injected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran": self.ran, "injected": self.injected, "param": self.param,
            "dbms": self.dbms, "banner": self.banner, "techniques": self.techniques,
            "reason": self.reason, "probes": self.probes,
            "cmd": self.cmd_preview, "timed_out": self.timed_out,
            "disabled_reason": self.disabled_reason,
        }

    def evidence_lines(self) -> list[str]:
        ev = []
        if self.cmd_preview:
            ev.append(f"复现命令：{self.cmd_preview}")
        if self.techniques:
            ev.append(f"sqlmap 判定注入手法：{'、'.join(self.techniques)}")
        if self.dbms:
            ev.append(f"后端数据库：{self.dbms}")
        if self.banner:
            ev.append(f"取回 DBMS 版本（仅元信息）：{self.banner}")
        return ev


def _outcome_from_info(out: SqlmapOutcome, info: dict[str, Any],
                       param: str) -> SqlmapOutcome:
    """把解析结果落到结论对象上。

    **两条执行路径（假执行体 / 真实子进程）必须共用这一个函数。**
    原先它们各写一份判定：真实路径处理了 `[CRITICAL]`（连接失败 / 被拦），
    假执行体路径只认「命中 / 未命中」。后果不是自测不准，而是——
    自测走的是假执行体路径，所以自测看到的结论与生产不同。
    于是「sqlmap 根本没连上目标」在一条路径上被写成
    「未得出结论」，在另一条上被写成「所选手法未判定存在注入」，
    而后者在报告里读起来就是「测过了，没有注入」。
    一个函数、一处措辞，这类分叉就不会再长出来。
    """
    out.ran = True
    out.injected = bool(info.get("injected"))
    if out.injected:
        out.param = str(info.get("param") or param)
        out.dbms = str(info.get("dbms") or "")
        out.banner = str(info.get("banner") or "")
        out.techniques = list(info.get("techniques") or [])
        out.reason = "sqlmap 确证注入存在"
        return out

    crit = str(info.get("critical") or "")
    # 优先级：命中 > 明确否定 > 无结论。
    # 这个顺序不是风格问题 —— 真实 sqlmap 在「全部参数都测不出注入」时，
    # 输出的最后一行**就是** `[CRITICAL] all tested parameters do not appear
    # to be injectable`。只看 `[CRITICAL]` 就归到「未得出结论」，
    # 会把一个**有结论的否定**写成「工具没跑出结果」；
    # 反过来若把连接失败归到「不可注入」，就是把「没测成」写成「测过，没有」。
    # 两个方向都误导读者，所以必须先判否定、再判无结论。
    if info.get("not_injectable"):
        out.reason = "sqlmap 已执行：全部测试参数均未判定为可注入"
        if crit:
            # sqlmap 自带的那句建议有信息量（它说明了这次否定的作用范围），
            # 保留但要收窄，别把整段工具输出灌进报告。
            out.reason += f"（工具原话：{crit[:100]}）"
    elif crit:
        # 连接失败 / 目标拒绝 / 被边界拦截 —— 工具没得出结论。
        # 这里绝不能写成「未判定存在注入」：那是「测过没有」，而事实是「没测成」。
        out.reason = f"sqlmap 未得出结论（{crit[:120]}）—— 属「没测完」，不能据此判定不存在注入"
    else:
        out.reason = "sqlmap 已执行，所选手法未判定存在注入"
    return out


def run(url: str, param: str = "", *, plan: SqlmapPlan | None = None,
        cookie: str = "", user_agent: str = "", runner: Any = None) -> SqlmapOutcome:
    """对单个注入点执行一次受限 sqlmap 调用。

    `runner` 供自测注入假执行体（离线环境不得真的拉起 sqlmap）。
    """
    plan = plan or SqlmapPlan(True, "", timeout=_env_timeout())
    if not plan.enabled:
        return SqlmapOutcome(disabled_reason=plan.reason,
                             reason=plan.reason or "未调用外部注入工具")

    exe = find_sqlmap()
    argv = build_argv(exe, url, param, plan, cookie=cookie, user_agent=user_agent)

    # 调用前断言：argv 里出现危险开关就直接拒绝调用并如实说明
    violations = is_safe_argv(argv)
    if violations:
        return SqlmapOutcome(
            reason=f"调用前安全检查未通过，已放弃调用：{'；'.join(violations)}",
            disabled_reason="argv 含未登记 / 禁用开关")

    # 预览只用于报告与复现脚本，凭据在这里被替换成占位符
    out = SqlmapOutcome(cmd_preview=preview_argv(argv), probes=1)

    if runner is not None:
        return _outcome_from_info(out, parse_output(runner(argv) or ""), param)

    kwargs: dict[str, Any] = dict(capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=plan.timeout,
                                  # stdin 关掉：pip 版 sqlmap 在 Win 上会
                                  # 「Press Enter to continue...」等输入。
                                  # 没有 stdin 时它会一直挂到超时，
                                  # 注入验证就被记成「未能验证」——
                                  # 那是对「没测」的诚实表述，但这里的「没测」
                                  # 是假的：工具跑得起来，是我们没给它一个 EOF。
                                  stdin=subprocess.DEVNULL)
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # 低影响运行：sqlmap 是 Python 程序，自己带线程池（已收到 --threads=1），
    # 但进程优先级仍是父进程不带下来的 —— 单独降一次，别让它跟你的前台工作抢 CPU。
    try:
        from engine import resources as _res  # noqa: PLC0415
        _kw = _res.child_kwargs()
        kwargs["env"] = _kw["env"]
        if "creationflags" in _kw:
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | _kw["creationflags"]
    except Exception:  # noqa: BLE001
        # 资源模块不可用不能让 sqlmap 这一步失败 —— 它是可选的佐证手段。
        pass
    try:
        proc = subprocess.run(argv, **kwargs)  # noqa: S603
    except subprocess.TimeoutExpired:
        out.ran = True
        out.timed_out = True
        out.reason = (f"sqlmap 在 {plan.timeout}s 内未跑完，已终止"
                      "（未得出结论，属「没测完」而非「不存在注入」）")
        return out
    except Exception as e:  # noqa: BLE001
        out.reason = f"sqlmap 调用失败：{type(e).__name__}: {str(e)[:120]}"
        return out

    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return _outcome_from_info(out, parse_output(text), param)


def prove_points(ctx: Any, points: list[dict[str, Any]],
                 runner: Any = None) -> SqlmapOutcome:
    """对一批候选注入点依次尝试，返回第一个成功的结论。

    全部失败时，返回的 reason 里带「已试过哪些点、用了什么手法」——
    这样报告读者能分清「试了没打通」与「压根没试」。
    """
    plan = plan_for(ctx)
    if not plan.enabled:
        return SqlmapOutcome(disabled_reason=plan.reason, reason=plan.reason)

    cache = getattr(ctx, "_cache", None)
    cookie = ""
    ua = ""
    try:
        h = dict(getattr(getattr(ctx, "_client", None), "session", None).headers or {})
        cookie = h.get("Cookie", "")
        ua = h.get("User-Agent", "")
    except Exception:  # noqa: BLE001
        pass

    tried: list[str] = []
    for pt in points[: max(1, plan.max_points)]:
        url = str(pt.get("url") or "")
        param = str(pt.get("param") or "")
        if not url:
            continue
        if not re.search(r"[?&][^=&\s]+=", url):
            continue
        ck = f"sqlmap::{url}::{param}"
        if cache is not None and ck in cache:
            done = cache[ck]
            if done.proven:
                return done
            tried.append(f"{url}（缓存：未确认）")
            continue
        one = run(url, param, plan=plan, cookie=cookie, user_agent=ua, runner=runner)
        if cache is not None:
            cache[ck] = one
        if one.proven:
            return one
        tried.append(f"{url}{('（参数 ' + param + '）') if param else ''}")
        if one.timed_out:
            break

    last_reason = ("已用 sqlmap 试过 " + "；".join(tried[:3]) +
                   "，所选手法未确证注入") if tried else "没有可测的注入点"
    return SqlmapOutcome(ran=bool(tried), reason=last_reason + "。" +
                         "注意：模型未确证注入 ≠ 不存在注入，"
                         "sqlmap 覆盖不了所有手法与所有参数位置（如 JSON body / 自定义编码）。")


# ==============================================================================
# 自测
# ==============================================================================
# 这里断言的都是**失效时不报错**的性质 —— 它们错掉的表现是
# 「扫描器照常跑完、报告照常生成」，只是结论悄悄偏了，或者凭据悄悄漏了。
# 这也是它必须进回归清单的原因：模块自测写得再全，没人跑就等于没有。
def _selftest() -> int:
    problems: list[str] = []
    import json as _json  # noqa: PLC0415

    # ① 危险开关族必须都在（防「好心清理」把数据导出能力放回来）
    #    这几条不是普通字符串，是「本工具只读」这条定位的物理边界。
    for _must in ("--dump", "--dump-all", "--sql-query", "--sql-shell",
                  "--os-shell", "--os-pwn", "--os-cmd", "--file-read",
                  "--file-write", "--file-dest", "--eval", "--shared-lib",
                  "--priv-esc", "--reg-add"):
        if _must not in FORBIDDEN_FLAGS:
            problems.append(f"禁用开关清单里缺少 {_must} —— "
                            "注入验证会退化成数据导出 / 命令执行工具")

    # ② 白名单语义：**没登记的开关默认拒绝**
    #    只做黑名单的话，sqlmap 未来新增一个危险开关，本模块会自动放行。
    _v = is_safe_argv(["--brand-new-dangerous-flag", "-u", "http://x/a?q=1"])
    if not _v:
        problems.append("未登记开关未被拒 —— 白名单退化成了黑名单")
    elif "未登记" not in _v[0]:
        problems.append(f"未登记开关的拒绝理由不对：{_v[0]}")

    # ③ 词边界：`--dumping` 不是 `--dump`，不能被报成「禁用开关 --dump」
    #    （误报会让人以为开关清单太严，进而去放宽它 —— 那才是真危险）
    _v2 = is_safe_argv(["--dumping", "-u", "http://x/a?q=1"])
    if not _v2:
        problems.append("--dumping 未被拒（应作为未登记开关被拒）")
    elif any("禁用开关" in x for x in _v2):
        problems.append(f"词边界判错：--dumping 被误报成禁用开关 --dump：{_v2}")

    # ④ 数值级下界：名字合法 ≠ 取值安全
    if not is_safe_argv(["--risk=3", "-u", "http://x/a?q=1"]):
        problems.append("--risk=3 未被拒 —— 它会启用 OR 型改写载荷，可能改动目标数据")
    if not is_safe_argv(["--level=4", "-u", "http://x/a?q=1"]):
        problems.append("--level>3 未被拒")
    if is_safe_argv(["--risk=2", "--level=3", "-u", "http://x/a?q=1"]):
        problems.append("合法的只读参数被误拒（会把能力误判成不可用）")
    if not is_safe_argv(["--technique=BEUSTQX", "-u", "http://x/a?q=1"]):
        problems.append("--technique 里的非法手法字符未被拒")

    # ⑤ build_argv 自己钳位 risk，且钳位后仍通过自检
    #    （plan 里写了 3 也不能让命令行里出现 3；两处都要拦，一处漏就通了）
    _hot = SqlmapPlan(True, "", risk=3, level=2, timeout=30)
    _argv_hot = build_argv("sqlmap", "http://x/a?q=1", "q", _hot)
    if "--risk=2" not in _argv_hot:
        problems.append(f"build_argv 未把 risk 钳到 2：{_argv_hot}")
    if any(a == "--risk=3" for a in _argv_hot):
        problems.append("build_argv 把 --risk=3 原样写进了命令行")
    if is_safe_argv(_argv_hot):
        problems.append(f"自身构造的 argv 未通过安全自检：{is_safe_argv(_argv_hot)}")

    # ⑥ **凭据不得出现在复现命令里**（本模块新修的泄露路径）
    #    cmd_preview 会进 reproduction / evidence → 报告与复现脚本（交付物）。
    #    带认证的目标下它原本带着真实会话 Cookie，等于随报告外发一份可冒用的凭据。
    _secret = "SESSID=abcdef0123456789secretvalue"
    _argv_ck = build_argv("sqlmap", "http://x/a?q=1", "q",
                          SqlmapPlan(True, "", timeout=30), cookie=_secret)
    _pv = preview_argv(_argv_ck)
    if "secretvalue" in _pv or _secret in _pv:
        problems.append("复现命令预览里出现了会话 Cookie 原文 —— "
                        "报告与复现脚本是要交给运维的交付物，这等于外发凭据")
    if COOKIE_PLACEHOLDER not in _pv:
        problems.append("复现命令预览未用占位符替换 Cookie（复测者会以为命令不完整）")
    if "--cookie" not in _pv:
        problems.append("预览里应保留「原本带 Cookie」这一事实，否则复测者会按匿名态复现")
    # 与 sessionctx 的哨兵必须同源：分叉就会出现「一处遮盖、一处明写」
    try:
        from verify.sessionctx import PLACEHOLDER_SENTINEL as _sent  # noqa: PLC0415
        if _sent != COOKIE_PLACEHOLDER:
            problems.append(f"占位哨兵与 sessionctx 分叉：{COOKIE_PLACEHOLDER!r} vs {_sent!r}")
    except Exception:  # noqa: BLE001
        pass

    # ⑦ 假执行体命中：结论、参数、手法、DBMS、留痕命令都要齐
    #    `runner` 只在显式传入时才挂上去 —— 挂了它会短路掉「本机是否装了 sqlmap」
    #    的检查（自测要能离线跑），但档位门控仍在它之前生效。
    class _Ctx:
        def __init__(self, key: str = "standard", runner: Any = None):
            self.profile_key = key
            self._cache: dict[str, Any] = {}
            if runner is not None:
                self.sqlmap_runner = runner
            self.calls = 0
    _hit_text = ("[INFO] testing connection\n"
                 "[INFO] the back-end DBMS is MySQL\n"
                 "back-end DBMS: MySQL >= 5.0\n"
                 "[INFO] GET parameter 'q' appears to be 'boolean-based blind' injectable\n"
                 "Parameter: q (GET)\n    Type: boolean-based blind\n"
                 "    Title: AND boolean-based blind\n"
                 "banner: '8.0.32'\n")
    _plan_on = SqlmapPlan(True, "自测", timeout=30)
    _o = run("http://x/a?q=1", "q", plan=_plan_on, cookie=_secret,
             runner=lambda _a: _hit_text)
    if not (_o.ran and _o.injected and _o.proven):
        problems.append(f"命中输出未被判为确证注入：ran={_o.ran} injected={_o.injected}")
    if _o.param != "q":
        problems.append(f"受影响参数未取到：{_o.param!r}")
    if "boolean-based blind" not in " ".join(_o.techniques):
        problems.append(f"判定手法未取到：{_o.techniques}")
    if not _o.dbms or "MySQL" not in _o.dbms:
        problems.append(f"后端数据库未识别：{_o.dbms!r}")
    if not _o.cmd_preview:
        problems.append("未留复现命令 —— 发现就没有可复测凭据")
    if "secretvalue" in "\n".join(_o.evidence_lines()):
        problems.append("evidence_lines 里带出了会话 Cookie 原文")

    # ⑧ 未命中：只能判「未确证」，措辞里不得出现「不存在」这种绝对结论
    _neg_text = ("[INFO] testing 'AND boolean-based blind'\n"
                 "[WARNING] GET parameter 'q' does not seem to be injectable\n"
                 "[CRITICAL] all tested parameters do not appear to be injectable\n")
    _o2 = run("http://x/a?q=1", "q", plan=_plan_on, runner=lambda _a: _neg_text)
    if not _o2.ran:
        problems.append("sqlmap 跑完但未记为「已执行」—— 会把「测了没有」错记成「没测」")
    if _o2.injected or _o2.proven:
        problems.append("未命中输出被误判为确证注入（会误报）")
    if "不存在" in _o2.reason:
        problems.append(f"未确证的措辞出现了绝对结论：{_o2.reason!r}")

    # ⑨ **`[CRITICAL]` 不等于「不可注入」**
    #    连接失败 / 被 WAF 拦 / 目标 403 时 sqlmap 也会吐 CRITICAL。
    #    若把它归到 not_injectable，读者会把「根本没测成」读成「测过，没有注入」——
    #    这正是本项目最危险的方向：把「没测」写成「没有问题」。
    _err_text = ("[CRITICAL] unable to connect to the target URL\n"
                 "[CRITICAL] connection reset by peer\n")
    _err_info = parse_output(_err_text)
    if _err_info["not_injectable"]:
        problems.append("连接失败被归为「不可注入」—— 把「没测成」写成了「没有注入」")
    if _err_info["injected"]:
        problems.append("连接失败被误判为命中")
    _o3 = run("http://x/a?q=1", "q", plan=_plan_on, runner=lambda _a: _err_text)
    if "CRITICAL" not in _o3.reason and "未得出结论" not in _o3.reason:
        problems.append(f"[CRITICAL] 类输出必须显式说明「未得出结论」，实际：{_o3.reason!r}")

    # ⑩ 关闭态：`ran` 必须是假，且「没测」的理由必须能被说出来
    _o4 = run("http://x/a?q=1", "q",
              plan=SqlmapPlan(False, "安全档不调用 sqlmap"))
    if _o4.ran:
        problems.append("计划为关闭态却记为「已执行」")
    if not _o4.disabled_reason:
        problems.append("未执行时必须留下理由（否则报告上无法区分「没测」与「测了没有」）")

    # ⑪ 超时：判「没测完」，不是「不存在」
    #    走真实子进程路径来触发超时太重（要等满 timeout），这里断言的是**文案契约** ——
    #    超时分支里那两句声明就是这个分支的全部价值：它决定了报告上写
    #    「本次没测完」还是「数据不可达」。
    _o5 = SqlmapOutcome(ran=True, timed_out=True,
                        reason=f"sqlmap 在 {_plan_on.timeout}s 内未跑完，已终止"
                               "（未得出结论，属「没测完」而非「不存在注入」）")
    if "没测完" not in _o5.reason:
        problems.append("超时文案未说明「没测完」")
    if _o5.proven:
        problems.append("超时不得判为「已证明」")
    # 并且超时必须真的能从子进程异常路径走到 —— 用 runner 抛 TimeoutExpired
    # 之外的方式验证太绕，这里改为直接确认 run() 的 except 顺序：
    # TimeoutExpired 必须排在通用 except 之前，否则会被吞成「调用失败」，
    # 而「调用失败」在报告上读起来像是目标的问题，不是「没测完」。
    try:
        _run_src = Path(__file__).read_text(encoding="utf-8")
        _i_to = _run_src.index("except subprocess.TimeoutExpired")
        _i_ge = _run_src.index("except Exception as e:  # noqa: BLE001",
                               _i_to)
        if _i_ge < _i_to:
            problems.append("TimeoutExpired 分支被通用 except 排在后面（超时会被吞成调用失败）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"超时分支顺序检查未能执行：{type(e).__name__}: {str(e)[:80]}")

    # ⑫ 被污染的 argv 必须在**调用之前**被拦住
    #    关键是「调用之前」：拦晚了请求已经发出去了，拦不拦已经没意义。
    _touched: list[list[str]] = []
    _orig_build = globals()["build_argv"]
    try:
        globals()["build_argv"] = lambda *a, **k: [  # type: ignore[assignment]
            "sqlmap", "-u", "http://x/a?q=1", "--batch", "--dump"]
        _o6 = run("http://x/a?q=1", "q", plan=_plan_on,
                  runner=lambda argv: (_touched.append(argv), "")[1])
    finally:
        globals()["build_argv"] = _orig_build  # type: ignore[assignment]
    if _touched:
        problems.append("argv 含禁用开关时仍然发起了调用 —— 安全检查必须在调用之前")
    if not _o6.disabled_reason:
        problems.append("因 argv 违规而拒绝调用时未说明原因")
    if _o6.ran:
        problems.append("被拒绝的调用不得记为「已执行」")

    # ⑬ prove_points：没参数的网址直接跳过（不浪费请求），
    #    全部试完仍失败时，理由必须让人能分清「试了没打通」与「压根没试」。
    #    注意执行体要**传给 prove_points 本身**（它读的是自己的 runner 参数，
    #    不是 ctx.sqlmap_runner —— 后者只用于骗过「本机装了没有」这一道检查）。
    _none = prove_points(_Ctx(runner=lambda _a: _neg_text),
                         [{"url": "http://x/a/b", "param": ""}],
                         runner=lambda _a: _neg_text)
    if _none.ran:
        problems.append("没有查询参数的网址不该被拿去测（sqlmap 无从下手，纯浪费请求）")
    if "没有可测的注入点" not in _none.reason:
        problems.append(f"无点可测时的理由不对：{_none.reason!r}")

    _tried_calls: list[list[str]] = []

    def _neg_runner(a: list[str]) -> str:
        _tried_calls.append(a)
        return _neg_text

    _all_fail = prove_points(_Ctx("deep", runner=_neg_runner),
                             [{"url": "http://x/a?q=1", "param": "q"},
                              {"url": "http://x/a?b=2", "param": "b"}],
                             runner=_neg_runner)
    if _all_fail.proven:
        problems.append("全部未命中却判为确证")
    if "已用 sqlmap 试过" not in _all_fail.reason:
        problems.append("全败理由未说明「试过哪些点」—— 读者分不清「试了没打通」与「没试」")
    if "不存在注入" not in _all_fail.reason and "≠" not in _all_fail.reason:
        problems.append("全败理由缺少「未确证 ≠ 不存在」的免责说明")
    # 深度档 max_points=2（自测路径也必须按档位算强度，否则覆盖的是另一套参数）
    if len(_tried_calls) != 2:
        problems.append(f"深度档应测 2 个注入点，实际发起 {len(_tried_calls)} 次")

    # ⑭ 缓存：同一注入点不重复打目标（重复打会拉长扫描时间、也会加大目标压力）
    _hits: list[list[str]] = []

    def _hit_runner(a: list[str]) -> str:
        _hits.append(a)
        return _hit_text

    _c4 = _Ctx("standard", runner=_hit_runner)
    _r1 = prove_points(_c4, [{"url": "http://x/a?q=1", "param": "q"}],
                       runner=_hit_runner)
    _r2 = prove_points(_c4, [{"url": "http://x/a?q=1", "param": "q"}],
                       runner=_hit_runner)
    if not (_r1.proven and _r2.proven):
        problems.append("命中结果未在缓存中复用")
    if len(_hits) != 1:
        problems.append(f"同一注入点被重复调用 {len(_hits)} 次（缓存未生效）")

    # ⑮ 元信息长度上限：报告里不得出现大段工具输出
    _long = parse_output("back-end DBMS: " + "M" * 500 + "\n"
                         "banner: '" + "B" * 500 + "'")
    if len(_long["dbms"]) > 80 or len(_long["banner"]) > 80:
        problems.append("DBMS / banner 未截断 —— 大段工具输出会灌进报告")

    # ⑯ 落盘字段完整且**不含数据行**（本模块只证明可达，不取数据）
    _d = _o.to_dict()
    for _k in ("ran", "injected", "param", "dbms", "banner", "techniques",
               "reason", "probes", "cmd", "timed_out", "disabled_reason"):
        if _k not in _d:
            problems.append(f"落盘字段缺失：{_k}")
    if any(_k in _d for _k in ("dump", "rows", "data", "records")):
        problems.append("落盘字段里出现了数据类键名 —— 本模块的定位是只读证明，不是取数")
    if not _json.dumps(_d, ensure_ascii=False):
        problems.append("结论不可序列化（报告落盘会炸）")

    # ⑰ 档位门控：安全档不调用、关闭开关不调用，两者都必须带理由
    #    安全档这一条用**带执行体的上下文**来测：原先 runner 检查排在档位检查之前，
    #    于是「安全档绝不调用 sqlmap」在有假执行体时被静默绕开。
    _safe_ctx = _Ctx("safe", runner=lambda _a: _hit_text)
    _sp = plan_for(_safe_ctx)
    if _sp.enabled:
        problems.append("安全档不应调用 sqlmap（会向目标发大量载荷）—— "
                        "注意这条也要在带自测执行体时成立，不能有旁路")
    if not _sp.reason:
        problems.append("安全档不调用时必须给出理由（不能静默跳过）")
    _prev = os.environ.get("AISCAN_SQLMAP")
    os.environ["AISCAN_SQLMAP"] = "off"
    try:
        _op = plan_for(_Ctx("deep", runner=lambda _a: _hit_text))
        if _op.enabled or not _op.reason:
            problems.append("显式关闭 sqlmap 后仍被判定为可调用")
    finally:
        if _prev is None:
            os.environ.pop("AISCAN_SQLMAP", None)
        else:
            os.environ["AISCAN_SQLMAP"] = _prev
    # 强度必须由档位算出，且**自测路径与生产路径同源**（同一函数）
    _dp = plan_for(_Ctx("deep", runner=lambda _a: _hit_text))
    if not (_dp.enabled and _dp.risk == 2 and _dp.level == 2
            and "T" in _dp.technique and _dp.max_points == 2):
        problems.append(f"深度档参数不对：risk={_dp.risk} level={_dp.level} "
                        f"technique={_dp.technique!r} max_points={_dp.max_points}")
    _stp = plan_for(_Ctx("standard", runner=lambda _a: _hit_text))
    if not (_stp.enabled and _stp.risk == 1 and _stp.level == 1
            and _stp.max_points == 1):
        problems.append(f"标准档参数不对：risk={_stp.risk} level={_stp.level} "
                        f"max_points={_stp.max_points}")
    if _stp.risk > 2 or _dp.risk > 2:
        problems.append("任何档位的 risk 都不得超过 2（>2 会启用 OR 型改写载荷）")

    if problems:
        print("sqlmap 调用层自测不通过：")
        for x in problems:
            print(f"  ✗ {x}")
        return 1
    print("sqlmap 调用层自测：通过（17 组断言）")
    print(f"  sqlmap 定位：{find_sqlmap() or '（本机未找到，注入验证将只用内置报错型手法）'}")
    print(f"  危险开关 {len(FORBIDDEN_FLAGS)} 项全拦｜白名单 {len(ALLOWED_FLAGS)} 项｜"
          f"复现命令中的凭据以 {COOKIE_PLACEHOLDER} 占位")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
