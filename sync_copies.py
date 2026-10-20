# -*- coding: utf-8 -*-
"""三副本同步 + 逐副本校验
===========================
项目规矩：本工作区的 aiscan 是**开发副本**，另外两处是**部署副本**
（skill 调用用一份、安全探测项目用一份）。任何改动都必须三处一致，
同步后各自跑一遍 `validate_coverage.py --strict`。

在此之前这条规矩靠人记：改了 3 个文件，同步时漏掉 1 个，
两份部署副本就悄悄与开发副本分叉 —— 而且是**静默**分叉，
下一次有人从部署副本跑扫描，结论就跟开发副本不一致，没人会知道为什么。

所以把它写成脚本：

    python sync_copies.py             # 同步 + 逐副本校验
    python sync_copies.py --check     # 只比对，不写入（CI / 复核用）
    python sync_copies.py --verify-only   # 只校验，不同步
    python sync_copies.py --self-test     # 台账合并 + 方向守卫自测（临时目录）

安全约定：
  · **只增改，不删除** —— 目标副本里多出来的文件一律保留（可能是那边独有的配置）。
  · 排除 outputs/（扫描归档，几百 MB 且与代码无关）、__pycache__、备份后缀。
  · 排除凭据类文件与状态文件（.schedule_state.json），避免把本机状态带过去。
  · **授权台账例外**：它是合规闸门而非本机状态，三处必须内容一致。
    不一致时默认**判失败**（不能让分叉静默），用 --merge-ledger 取并集写回三处。
    合并方向是对称的（dev ≠ 唯一真源），因为任何一份里都可能有另一份没有的真实授权。
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# 开发副本的**绝对路径**，从用户目录推导而非用 __file__ 推出来：
# 本脚本自己也会被同步到两份部署副本里。若用 __file__ 推 DEV，
# 在副本里执行时 DEV 就变成了那份副本，同步方向会整个反过来 ——
# 用部署副本的内容去覆盖开发副本。那是不可逆的破坏，必须从根上堵住。
#
# 同时用 Path.home() 而非写死 `C:/Users/<用户名>/...`：本机用户名属于
# 个人信息，且写死后换台电脑就失效（这是本仓库发布前的净身项之一）。
# 若你的部署副本不在这些位置，直接改下面两行即可。
def _dev_root() -> Path:
    """开发副本根目录。优先读 `AISCAN_DEV`，否则按用户目录推导。"""
    env = os.environ.get("AISCAN_DEV", "").strip()
    return Path(env) if env else Path.home() / "WorkBuddy" / "2026-09-20-15-17-17" / "aiscan"


def _deploy_copies() -> list[Path]:
    """部署副本目录列表。优先读 `AISCAN_COPIES`（分号或逗号分隔）。"""
    env = os.environ.get("AISCAN_COPIES", "").strip()
    if env:
        return [Path(x.strip()) for x in re.split(r"[;,]", env) if x.strip()]
    h = Path.home()
    return [
        h / ".workbuddy" / "skills" / "webscan-skill" / "toolchain" / "aiscan",
        h / "WorkBuddy" / "2026-07-06-19-08-10" / "aiscan",
    ]


#: 副本路径是否被**显式配置**过（用于区分「配了却找不到」和「压根没配」）
COPIES_CONFIGURED: bool = bool(os.environ.get("AISCAN_COPIES", "").strip())

DEV: Path = _dev_root()
COPIES: list[Path] = _deploy_copies()

# 不同步的目录 / 后缀。outputs 是扫描归档（体积大且与代码无关）；
# __pycache__ 是编译缓存；.bak / .pre-quote 是本地备份。
SKIP_DIRS = {"outputs", "__pycache__", ".git", ".pytest_cache", "node_modules",
             "dist",   # make_dist.py 的产物：压缩包不该在副本之间传来传去
             # 部署脚本（install.ps1）在本机建出来的隔离环境。它属于
             # **本机状态**而不是代码：同步过去既没用（里面是全套
             # site-packages，几百 MB），又特别坏 —— venv 里的路径是按
             # 源机器的用户名与目录写死的，拷到副本上就是一堆废路径，
             # 而副本上的人会以为「环境已经配好了」。
             ".venv", "venv"}
SKIP_SUFFIX = (".bak", ".pre-quote", ".pyc", ".log")
SKIP_NAMES = {".schedule_state.json", "授权台账.yaml.bak"}

# 临时文件的**前缀**，与 make_dist.py 保持同一套命名约定。
# 为什么必须在这里也要过滤：本次踩过一次 —— 在开发副本里起了个
# `_tmp_items.txt` 做列表缓存，被同步进了两个副本，然后从开发副本删掉。
# 结果副本上的反向守卫看到「副本有而开发没有」的新文件，判定可能存在副本上的
# 新工作，**拒绝同步并让回归失败**。那个守卫是对的（它防的是非法覆盖），
# 错的是把一个跟代码无关的临时 checksums 当成代码同步了过去。
# 换句话说：少过滤一个前缀，代价是「同步工具假装发现了一个冲突」。
SKIP_PREFIX = ("_tmp_", "_negtest_")

# ---------------------------------------------------------------------------
# 授权台账：三处必须一致，但合并方向是对称的（见 merge_ledger）
# ---------------------------------------------------------------------------
# 为什么台账要单独处理，而不是当成「副本里多出来的文件」保留：
# 台账不是本地配置，是**合规闸门** —— 引擎用它决定「这个目标能不能扫」。
# 三份台账不一致时，同一条命令从不同副本跑会得到不同结论：
#   副本1 登记了 内部生产系统 → 放行；副本2 没登记 → 拒绝执行。
# 这不是「谁的配置更全」，是「同一个资产到底有没有授权」出现了两个答案。
# 而且台账还是审计凭证：scan_count 分散在各自副本里累加，审计链就是断的。
LEDGER_REL = Path("ledger") / "auth-ledger.yaml"
#: `--merge-ledger` 留底用的备份名前缀（后接 -YYYYMMDD-HHMMSS）。
LEDGER_BAK_PREFIX = LEDGER_REL.name + ".bak-"

# 与 ledger/auth_ledger.py 的 save() 保持逐字一致 ——
# 否则合并写回后「文件被本工具改过」一眼可见，审计上看不出是同一套流程产的。
LEDGER_HEADER = (
    "# ==============================================================================\n"
    "# 授权台账\n"
    "# ==============================================================================\n"
    "# 本文件记录每个目标的授权依据，是扫描合法性的凭证。\n"
    "# 规则：同一目标只需首次登记，后续扫描自动放行（零交互）。\n"
    "#       未登记目标将被引擎拒绝，需先补登记。\n"
    "# 注意：本文件只追加、不覆盖历史记录。请勿手工删除已登记条目。\n"
    "# ==============================================================================\n\n"
)

# 字段顺序与 AuthRecord 对齐，保证合并写回的文件与引擎自己写的一模一样。
LEDGER_FIELDS = ("domain", "target_name", "authorizer", "authorization_date",
                 "authorization_ref", "allow_write_test", "objectives",
                 "impact_level", "registered_at", "last_scan_at", "scan_count",
                 "notes")

# 占位 / 自测域名。**只提示，不自动删除**：
# 「只追加不覆盖」是台账作为审计凭证的前提，
# 自动抹掉一条记录 = 篡改审计链。清不清由人决定，工具只负责让它显形。
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "example.edu"}
PLACEHOLDER_SUFFIX = (".invalid", ".test", ".localhost", ".example", ".local")
PLACEHOLDER_HINTS = ("自测", "链路验证", "无人值守", "selftest", "self-test", "占位")


def _wanted(p: Path) -> bool:
    # 台账**不走代码同步这条路**：_sync 是「dev 覆盖副本」的单向语义，
    # 而台账里副本可能有 dev 没有的真实授权 —— 一旦被覆盖就是**丢授权记录**，
    # 而且是静默丢。台账只由 --merge-ledger 以并集方式写回三处。
    if p == LEDGER_REL:
        return False
    # 台账备份（auth-ledger.yaml.bak-<时间戳>）由 --merge-ledger 自动留底，
    # 名字带时间戳后缀，`.endswith(".bak")` 拦不住。它本就只存在于副本侧，
    # 是审计留底而不是「副本里多出来的东西」—— 不排除掉，方向守卫会天天
    # 拿它当分叉证据，把一条正常留底报成需要处置的异常。
    if p.name.startswith(LEDGER_BAK_PREFIX):
        return False
    if any(part in SKIP_DIRS for part in p.parts):
        return False
    if p.name in SKIP_NAMES:
        return False
    if p.name.endswith(SKIP_SUFFIX):
        return False
    if p.name.startswith(SKIP_PREFIX):
        return False
    return True


def _files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if not _wanted(rel):
            continue
        out.append(rel)
    return sorted(out)


def _label(p: Path) -> str:
    """副本短名。两个副本末级目录都叫 aiscan，必须靠上一级区分，
    否则日志里会出现两行一模一样的「... @ aiscan」，无法定位是哪个副本。"""
    try:
        return f"{p.parent.name}/aiscan"
    except Exception:  # noqa: BLE001
        return str(p)


def _md5(p: Path) -> str:
    h = hashlib.md5()
    h.update(p.read_bytes())
    return h.hexdigest()


def _diff(dev: Path, copy: Path) -> tuple[list[Path], list[Path]]:
    """返回（缺失, 内容不同）。"""
    missing, changed = [], []
    for rel in _files(dev):
        t = copy / rel
        if not t.exists():
            missing.append(rel)
            continue
        try:
            if not filecmp.cmp(dev / rel, t, shallow=False):
                changed.append(rel)
        except OSError:
            changed.append(rel)
    return missing, changed


#: 部署副本里允许存在、但不属于开发副本的文件名。
#: 目前**刻意为空** —— 副本里多出文件一律先拦下来问清楚。
#: 「副本里有新模块、开发副本里没有」正是最危险的形态：按固定方向同步
#: 会把它当成无需处理的多余文件留在一旁（甚至在下一次全量同步时被误判为
#: 应删项），而真正的问题是**开发副本落后了**。
EXTRA_ALLOW: set[str] = set()


def _copy_newer_than_dev(dev: Path, copy: Path) -> tuple[list[str], list[str]]:
    """找出「这份副本比开发副本新」的证据。

    返回（比开发副本更新的同名文件, 副本独有、开发副本没有的文件）。

    为什么必须有这道闸门
    --------------------
    本脚本同步方向固定为「DEV → 副本」，且它**自己也会被同步进副本**。
    于是存在一条真实发生过的破坏路径：

      1. 在**部署副本**里直接改代码（临时调试、或换了工作目录没注意）；
      2. 从那份副本里执行 sync_copies.py；
      3. 脚本按固定方向把 DEV 的旧内容写回副本 ——
         **刚改完的东西被无声覆盖，且不可逆。**

    所幸文件系统本身就带着判据：`shutil.copy2` 会保留 mtime，
    所以一次正常同步之后，两侧同名文件的 mtime 是**相等**的。
    一旦副本侧的 mtime 明显更大，就说明那份副本被单独编辑过。

    ⚠ 但**光看 mtime 不够**，必须同时要求内容也不同。
    实测踩过这个坑：打包 / 复制 / 「打开又原样保存」都会刷新时间戳，
    一次整体刷新把 51 个文件的 mtime 一起推到了副本侧 —— 而它们的内容
    与开发副本**逐字节相同**，真正内容不同的那 14 个文件反而 mtime 更小。
    若只看 mtime，守卫会在 51 个毫无问题的文件上误报，于是每次同步都被拦；
    被拦几次之后人的反应是「把守卫关掉」—— 那比没有守卫更糟。
    所以判据收紧成：**内容确实不同 且 副本 mtime 更大**，
    两者同时成立才是「副本里有一份开发副本没有的工作」。

    副本独有文件是同一信号的另一种形态：新增的模块在 DEV 里压根不存在，
    按 md5 比对只会显示成「无此文件」，看起来像无害的杂物。
    """
    newer: list[str] = []
    dev_files = set(_files(dev))
    for rel in _files(copy):
        if rel not in dev_files:
            continue
        try:
            if filecmp.cmp(dev / rel, copy / rel, shallow=False):
                # 内容一模一样 → mtime 更大只是被「摸过」，不构成分叉证据。
                continue
        except OSError:
            continue
        try:
            d_m = (dev / rel).stat().st_mtime
            c_m = (copy / rel).stat().st_mtime
        except OSError:
            continue
        # 1 秒容差：避开文件系统时间戳粒度带来的假阳性
        if c_m > d_m + 1.0:
            newer.append(rel)
    extras = [str(rel) for rel in _files(copy) if rel not in dev_files
              and rel.name not in EXTRA_ALLOW and rel.name not in SKIP_NAMES]
    # 两个返回值统一成 str：混着 Path 与 str 返回，调用方做集合运算或相等判断时
    # 会出现「打印出来一模一样却判不相等」的假失败（Path('a.py') != 'a.py'）。
    return sorted(str(r) for r in newer), sorted(extras)


def _sync(dev: Path, copy: Path) -> tuple[int, int]:
    copy.mkdir(parents=True, exist_ok=True)
    n_new = n_upd = 0
    for rel in _files(dev):
        src, dst = dev / rel, copy / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            shutil.copy2(src, dst)
            n_new += 1
        elif not filecmp.cmp(src, dst, shallow=False):
            shutil.copy2(src, dst)
            n_upd += 1
    return n_new, n_upd


def _verify(copy: Path) -> tuple[bool, str]:
    """在副本里跑覆盖率校验。必须用副本自己的路径，才算真的验证了那一份。"""
    script = copy / "validate_coverage.py"
    if not script.exists():
        return False, "副本里没有 validate_coverage.py"
    try:
        p = subprocess.run([sys.executable, str(script), "--strict"],
                           cwd=str(copy), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {str(e)[:120]}"
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode == 0 and "结果：通过" in out:
        return True, "覆盖率校验通过"
    tail = [x for x in out.strip().splitlines() if x.strip()][-3:]
    return False, f"退出码 {p.returncode}：" + " / ".join(tail)


def _key_hashes(root: Path) -> dict[str, str]:
    """抽查一批「分叉了就会静默出错」的文件。

    纳入标准不是「重要」，而是**分叉后不报错**：
      · engine/credguide.py —— 凭据库读写与需求单生成。分叉会出现
        「一份副本能读到凭据、另一份读不到」，同一条命令结论相反。
      · engine/sessionpool.py —— 会话态判定（含零凭据守卫 / 对照实验）。
        分叉等于一份副本还在把空账号当「已登录」。
      · engine/orchestrator.py —— 扫描主链，含中途索取提示与需求单落盘。
      · engine/authz_matrix.py —— 账号字段定义，须与 sessionpool 消费端对齐。
      · engine/frontend.py —— 前端产物汇聚，同时承载 `has_material()` 这唯一
        一份「素材够不够」判据。分叉会出现一份副本认为素材充足、另一份认为
        没有，同一份 js_result 跑出「已检查」和「未执行」两种结论。
      · engine/fingerprint.py —— fetch / fetch_asset 与正文截断上限。
        分叉会让一份副本只读到脚本前 4000 字符，另一份读全文。
      · engine/credhunt.py —— 黑客视角凭据获取。它的六条红线全写在代码里
        （双重尝试上限 / 命中风控即停 / 口令不落盘只留加盐指纹 / 登录入口
        必须同源 / 成功必经匿名对照实验回验 / 逐次留痕）。分叉的后果是
        **一份副本在试口令，另一份不知道**：报告上「本次未做口令尝试」与
        实际发生的尝试对不上，留痕这一条审计凭据直接失效。
      · engine/credosint.py —— 凭据情报（自己上网找登录凭据）。分叉的后果有两层：
        ① **对外的**：一份副本会向外部检索源发查询、另一份不会，
        而「发了几次检索、检索词是什么」是使用方要求过的披露项；
        ② **对内的**：产品默认口令表是安全边界 —— 三份里只要有一份的
        `_GENERIC_PATHS` / `WEAK_ACCOUNTS` 判据被放宽，同一份授权下
        就会从「按产品试默认值」变成「拿字典怼所有登录框」，
        而后者是爆破，副作用（账号锁定）不可逆。
      · engine/progress.py —— 进度播报。分叉只会让一份副本少打几行，
        但它是「扫描卡住还是正常」的唯一外部信号，且 `_emit` 内建了
        「异常静默降级」——分叉后没有任何报错会提示你看到的是旧行为。
      · engine/redteam.py —— 攻击目标三态判定与「未执行」的**归因**。
        分叉的表现是：同一份台账、同一次扫描，一份副本说某个目标
        「本档位默认不含」、另一份说它「未在授权台账登记」—— 两者处置
        完全不同（换档位 vs 补授权），而报告上**看不出谁对谁错**。
        归因分叉与结论分叉同等严重，且同样不报错。
      · engine/wafgate.py —— 拦截页识别、边界一致性判定，以及
        「整站同一响应」的**两个口径**（状态码 / 归一化正文）。
        它被 fingerprint（路径类特征）、credguide（登录入口推断）、
        checks/base（检测器侧 sitewide_guard）同时依赖，是这三处判据的
        **共同上游**。分叉的表现最阴：三个下游文件的哈希都一致，
        同一目标却在两份副本上得到相反的边界结论 —— 一边判「整站被接管、
        路径存在性未知」，另一边把拦截页当应用扫。
        （正因如此，它必须单独抽查：改它不会改下游任何一个文件的哈希。）
      · verify/sessionctx.py —— 越权类复现脚本的内联片段与凭据解析。
        credguide 从它 import，所以它的分叉**不会**体现在 credguide 的哈希上：
        一份副本生成的复现脚本可能带着语法错误或符号重复，要到交付后才炸。
      · selftest_creds.py / selftest_credhunt.py / selftest_frontend.py /
        selftest_redteam.py —— 上面这些的守门测试。
    真正「编译期就报错」的分叉会被 import 挡住，不必进这份清单。
    """
    keys = ["aiscan.py", "engine/registry.py", "engine/scheduler.py",
            "engine/notify.py", "engine/recon_identity.py",
            "engine/nuclei_runner.py", "engine/banguard.py", "diff/differ.py",
            "report/generator.py", "validate_coverage.py",
            "engine/credguide.py", "engine/sessionpool.py",
            "engine/orchestrator.py", "engine/authz_matrix.py",
            "engine/frontend.py", "engine/fingerprint.py",
            "engine/credhunt.py", "engine/credosint.py",
            "engine/progress.py", "engine/redteam.py",
            "engine/wafgate.py", "verify/sessionctx.py",
            # 资源预算：分叉的后果是「同一份代码在一台机器上把 CPU 吃满、
            # 在另一台机器上很乖」—— 因为它的行为取决于运行环境，
            # 这种差异最难归因，必须保证三处一致。
            "engine/resources.py", "engine/nuclei_budget.py",
            "engine/openapi.py",
            # sqlmap 调用层：分叉的后果与上面几份不同 —— 它是一道**安全边界**。
            # 三份副本里只要有一份的 FORBIDDEN_FLAGS / ALLOWED_FLAGS / 档位强度
            # 被放宽，那一份就会把开关交给 sqlmap：同一批目标、同一份授权台账，
            # 一台机器上只读验证、另一台机器上可能真的导出数据。
            # 这类事故不可逆（数据已经出去了），所以三个常量必须逐字节一致。
            "engine/sqlmap_probe.py",
            "selftest_engine.py", "selftest_report_gate.py",
            "selftest_schedule.py", "selftest_creds.py",
            "selftest_frontend.py", "selftest_credhunt.py",
            "selftest_redteam.py", "run_all_tests.py",
            # 逐项门控（2026-09-30）：注册表里「每个检查项先问一次
            # currently_blocked()」那几行，是 B 类拦截下唯一拦住
            # 假通过的东西。三份里只要有一份漏了这段，同一目标会在
            # 一台机器上判「未执行」、在另一台上把拦截页当应用扫完 ——
            # 而两份报告的格式完全一样，谁也看不出哪份是错的。
            "engine/registry_runner.py",
            # 端口类检测器（2026-09-30）：TCP 对照实验的接入点。
            # 分叉的后果是同一批端口在一份副本里报「公网可达」、
            # 在另一份里报「待确认」—— 这正是当年那条
            # 「严重：10 个端口可直连」误报的形态。
            "engine/checks/extras3.py",
            # 全局硬约束执行体（2026-09-30）：rate_ceiling_rps / per_host_rps /
            # delay_between_items_ms / stop_on 四个字段此前**零读取点**。
            # 这一环本身就是「它们到底有没有被读到」的判据 ——
            # 三份里少一份，那一份的 yaml 就是一份虚假保证。
            "selftest_hardlimits.py"]
    out = {}
    for k in keys:
        f = root / k
        out[k] = _md5(f) if f.exists() else "（缺失）"
    return out


def _read_ledger(root: Path) -> dict[str, dict]:
    """读一份授权台账。读不动 / 不存在一律返回空字典 ——
    调用方靠「份数」和「并集差异」判断，不靠异常。"""
    p = root / LEDGER_REL
    if not p.exists():
        return {}
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, dict] = {}
    for rec in (data.get("authorizations") or []):
        if not isinstance(rec, dict):
            continue
        dom = str(rec.get("domain") or "").strip()
        if dom:
            out[dom] = rec
    return out


def placeholder_reason(domain: str, rec: dict) -> str:
    """这条记录像不像自测 / 占位。返回原因，不像则返回空串。"""
    d = domain.lower()
    if d in PLACEHOLDER_DOMAINS or d.endswith(PLACEHOLDER_SUFFIX):
        return "保留域名（不可能作为真实扫描目标）"
    blob = " ".join(str(rec.get(k) or "") for k in
                    ("authorization_ref", "notes", "target_name"))
    low = blob.lower()
    for h in PLACEHOLDER_HINTS:
        if h.lower() in low:
            return f"依据/备注含「{h}」，疑似自测记录"
    return ""


def merge_ledgers(sources: list[tuple[str, dict[str, dict]]],
                  ) -> tuple[dict[str, dict], list[str]]:
    """并集合并三份台账。返回（合表, 冲突列表）。

    规则（只增不删）：
      · 域名取**并集** —— 任何一份里登记过的，合并后都必须还在。
      · 同域名取「更活跃」的那条做底（先比 scan_count，再比 last_scan_at），
        空字段一律用另一份补全，绝不丢信息。
      · scan_count 取 **max 而不是 sum**：合并必须幂等。写回三处后三份计数相同，
        若用 sum，每合并一次就翻一倍，审计数字反而变成假的。
    """
    merged: dict[str, dict] = {}
    conflicts: list[str] = []
    for label, recs in sources:
        for dom, rec in recs.items():
            if dom not in merged:
                merged[dom] = dict(rec)
                continue
            cur = merged[dom]
            for f in ("authorizer", "authorization_ref", "target_name",
                      "allow_write_test", "impact_level"):
                a, b = cur.get(f), rec.get(f)
                if a not in (None, "", [], False) and b not in (None, "", [], False) and a != b:
                    conflicts.append(f"{dom} · {f}：已有 {a!r}，{label} 为 {b!r}")
            key = lambda r: (int(r.get("scan_count") or 0),  # noqa: E731
                             str(r.get("last_scan_at") or ""))
            base, other = (dict(rec), cur) if key(rec) > key(cur) else (dict(cur), rec)
            for k, v in other.items():  # 空字段补全，绝不丢信息
                if v not in (None, "", [], {}) and base.get(k) in (None, "", [], {}):
                    base[k] = v
            merged[dom] = base
    return merged, conflicts


def _norm_record(domain: str, rec: dict) -> dict:
    """按 AuthRecord 的字段与类型归一，保证写回的文件与引擎自产的一致。"""
    out: dict = {"domain": domain}
    for k in LEDGER_FIELDS:
        if k == "domain":
            continue
        out[k] = rec.get(k, "")
    out["allow_write_test"] = bool(rec.get("allow_write_test", False))
    out["objectives"] = list(rec.get("objectives") or [])
    try:
        out["scan_count"] = int(rec.get("scan_count") or 0)
    except (TypeError, ValueError):
        out["scan_count"] = 0
    return out


def _write_ledger(root: Path, merged: dict[str, dict]) -> Path:
    import yaml

    p = root / LEDGER_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump(
        {"authorizations": [_norm_record(d, r) for d, r in merged.items()]},
        allow_unicode=True, sort_keys=False, default_flow_style=False,
    )
    p.write_text(LEDGER_HEADER + body, encoding="utf-8")
    return p


def _backup_ledger(root: Path, stamp: str) -> Path | None:
    """合并前留底。台账是审计凭证，改它之前必须先能退回去。"""
    src = root / LEDGER_REL
    if not src.exists():
        return None
    dst = src.with_name(src.name + f".bak-{stamp}")
    shutil.copy2(src, dst)
    return dst


def _ledger_selftest() -> int:
    """纯临时目录自测：不碰真实台账。合并语义错一次，三份合规闸门就一起错。"""
    import tempfile

    ok = fail = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  ✓ {name}")
        else:
            fail += 1
            print(f"  ✗ {name}" + (f" —— {detail}" if detail else ""))

    with tempfile.TemporaryDirectory() as td:
        roots = [Path(td) / n for n in ("dev", "c1", "c2")]
        leds = [
            {"a.com": {"domain": "a.com", "authorizer": "安全负责人",
                       "authorization_ref": "工单-1", "scan_count": 2,
                       "last_scan_at": "2026-09-21T10:00:00"},
             "b.com": {"domain": "b.com", "authorizer": "安全负责人",
                       "authorization_ref": "工单-2", "scan_count": 9}},
            {"b.com": {"domain": "b.com", "authorizer": "安全负责人",
                       "authorization_ref": "工单-2", "scan_count": 9,
                       "notes": "内网地址"}},
            {"c.com": {"domain": "c.com", "authorizer": "安全负责人",
                       "authorization_ref": "无人值守链路验证", "scan_count": 1}},
        ]
        sources = list(zip(["dev", "c1", "c2"], leds))
        merged, conflicts = merge_ledgers(sources)

        check("并集：三份里出现过的域名一个都不能少",
              set(merged) == {"a.com", "b.com", "c.com"}, str(sorted(merged)))
        check("同域名取更活跃的那条（scan_count 大者为准）",
              merged["b.com"]["scan_count"] == 9)
        check("空字段被另一份补全，不丢信息",
              merged["b.com"].get("notes") == "内网地址")
        check("授权依据一致时不得报冲突", not conflicts, str(conflicts))
        check("占位域名能被识别（example.com）",
              bool(placeholder_reason("example.com", {})))
        check("自测依据能被识别", bool(placeholder_reason(
            "real.internal", {"authorization_ref": "无人值守链路验证"})))
        check("正常记录不得被误判为占位",
              not placeholder_reason("internal-app.example.com",
                                     {"authorization_ref": "WorkBuddy会话授权 2026-09-21"}))

        # 冲突必须显形，不能被「取其一」盖掉
        _m2, conf2 = merge_ledgers([
            ("dev", {"x.com": {"domain": "x.com", "authorizer": "甲",
                               "authorization_ref": "工单-9", "scan_count": 1}}),
            ("c1", {"x.com": {"domain": "x.com", "authorizer": "乙",
                              "authorization_ref": "工单-9", "scan_count": 5}}),
        ])
        check("同域名授权人不一致时必须报冲突", any("authorizer" in c for c in conf2),
              str(conf2))

        # 幂等：合并 → 写回三处 → 再合并，结果必须逐字相同
        for r in roots:
            _write_ledger(r, merged)
        again, _ = merge_ledgers([(str(r), _read_ledger(r)) for r in roots])
        check("幂等：合并写回后再合并，台账完全不变",
              _norm_records(again) == _norm_records(merged),
              f"{_norm_records(again)} != {_norm_records(merged)}")
        check("scan_count 不因重复合并而膨胀（max 语义）",
              again["b.com"]["scan_count"] == 9)
        check("写回后三份逐字一致",
              len({(r / LEDGER_REL).read_text(encoding="utf-8") for r in roots}) == 1)
        check("写回的文件带标准表头（与引擎自产同形）",
              (roots[0] / LEDGER_REL).read_text(encoding="utf-8").startswith(LEDGER_HEADER[:20]))
        check("无台账的副本也能被合并写回（缺失 ≠ 拒绝）",
              (roots[2] / LEDGER_REL).exists())

    print(f"\n结果：{'通过' if not fail else '失败'}（{ok} 项通过，{fail} 项失败）")
    return 1 if fail else 0


def _guard_selftest() -> int:
    """方向守卫的受控实验（纯临时目录，不碰真实文件）。

    这道守卫是「同步」这条路上唯一的刹车。它误报的代价不是「拦错一次」，
    而是**每次同步都被拦** —— 被拦几次之后人的反应是把守卫关掉，
    那比没有守卫更糟。上面那个 51 个文件批量误报的坑就是这么踩出来的。

    所以它的判据不能只靠当时那一次手工验证，必须有断言永久守着：

      · 内容相同 + 副本 mtime 更新  → 只是被「摸过」，**不得拦**
      · 内容不同 + 副本 mtime 更大  → 真分叉，**必拦**
      · 内容不同 + 开发副本 mtime 更大 → 开发副本领先，**不得拦**（本就该同步过去）
      · 副本独有文件 → 要显形（新增模块在 DEV 里根本不存在，md5 比不出来）
      · 台账及其备份 → 既不算同步内容，也不算「副本独有」
    """
    import os
    import tempfile

    ok = fail = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  ✓ {name}")
        else:
            fail += 1
            print(f"  ✗ {name}" + (f" —— {detail}" if detail else ""))

    def write(p: Path, text: str, mtime: float | None = None) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        if mtime is not None:
            os.utime(p, (mtime, mtime))

    with tempfile.TemporaryDirectory() as td:
        dev = Path(td) / "dev"
        copy = Path(td) / "copy"
        base = time.time() - 1000.0
        off = 500.0  # 远超 1 秒容差

        write(dev / "same.py", "x = 1\n", base)
        write(copy / "same.py", "x = 1\n", base + off)

        write(dev / "real.py", "x = 1\n", base)
        write(copy / "real.py", "x = 2\n", base + off)

        write(dev / "behind.py", "x = 1\n", base + off)
        write(copy / "behind.py", "x = 2\n", base)

        write(copy / "orphan.py", "y = 1\n", base)

        write(copy / LEDGER_REL, "authorizations: []\n", base)
        write(copy / "ledger" / (LEDGER_BAK_PREFIX + "20260924-142920"),
              "authorizations: []\n", base)

        newer, extras = _copy_newer_than_dev(dev, copy)

        check("内容不同 + 副本 mtime 更大 → 必须拦住",
              newer == ["real.py"], str(newer))
        check("内容相同、只是 mtime 被刷新 → 不得误报",
              "same.py" not in newer, str(newer))
        check("内容不同但开发副本领先 → 不得误报（那是正常待同步）",
              "behind.py" not in newer, str(newer))
        check("副本独有文件要被报出来", extras == ["orphan.py"], str(extras))
        check("台账备份不算「副本独有」",
              not any(LEDGER_BAK_PREFIX in e for e in extras), str(extras))
        check("台账本身不进代码同步", not _wanted(LEDGER_REL))
        check("返回值类型一致（全 str，避免 Path('a.py') != 'a.py' 的假失败）",
              all(isinstance(x, str) for x in newer + extras), str(newer + extras))

        # 反向：守卫必须真的会拦 —— 全放行的守卫等于没有守卫
        clean = Path(td) / "clean"
        for name in ("same.py", "real.py", "behind.py"):
            write(clean / name, (dev / name).read_text(encoding="utf-8"),
                  (dev / name).stat().st_mtime)
        n0, e0 = _copy_newer_than_dev(dev, clean)
        check("逐字节一致的副本不得被拦（同步后的正常状态）",
              n0 == [] and e0 == [], f"{n0} / {e0}")

    print(f"\n结果：{'通过' if not fail else '失败'}（{ok} 项通过，{fail} 项失败）")
    return 1 if fail else 0


def _norm_records(merged: dict[str, dict]) -> dict[str, dict]:
    return {d: _norm_record(d, r) for d, r in sorted(merged.items())}


def main() -> int:
    ap = argparse.ArgumentParser(description="aiscan 三副本同步")
    ap.add_argument("--check", action="store_true", help="只比对不写入")
    ap.add_argument("--verify-only", action="store_true", help="只校验不比对")
    ap.add_argument("--merge-ledger", dest="merge_ledger", action="store_true",
                    help="把三处授权台账取并集后写回三处（只增不删，先自动留底）")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="只跑自测（台账合并 + 同步方向守卫，临时目录，不碰真实文件）")
    ap.add_argument("--ledger-self-test", dest="ledger_self_test", action="store_true",
                    help="--self-test 的旧名，保留兼容")
    args = ap.parse_args()

    if args.self_test or args.ledger_self_test:
        rc = 0
        print("台账合并自测（临时目录）")
        print("=" * 74)
        rc |= _ledger_selftest()
        print()
        print("同步方向守卫自测（临时目录）")
        print("=" * 74)
        rc |= _guard_selftest()
        return 1 if rc else 0

    #: 本脚本**只能从开发副本里运行**（同步方向固定为 DEV → 两份部署副本）。
    #: 从任何别的地方跑 —— 部署副本、外部使用者的克隆、CI 沙箱 —— 一律跳过。
    #:
    #: 理由两条，都是踩出来的：
    #:   ① **不可逆破坏**：反向或以副本为起点写入，会用旧内容覆盖新工作；
    #:   ② **信息泄露**：本脚本会读 `ledger/auth-ledger.yaml` 并**打印其中的
    #:      域名清单** —— 那是维护者的真实目标资产台账。外部使用者跑一次，
    #:      屏幕上一行行全出来了（仓库文件里没有，但脚本会把它们读出来）。
    #: 因此对非开发副本环境，明确说明后干净退出，且**不计入失败**。
    here = Path(__file__).resolve().parent
    if here != DEV:
        print("ⓘ sync_copies.py 是维护者专用的「三副本同步」工具，已跳过。")
        print(f"   当前目录：{here}")
        print(f"   开发副本：{DEV}"
              f"{'' if DEV.exists() else '（当前机器上不存在）'}")
        print()
        print("   外部使用者：忽略本文件即可，它不影响扫描功能。")
        print("   维护者：设置 AISCAN_DEV / AISCAN_COPIES 环境变量，")
        print("          或改本文件顶部的 DEV / COPIES 定义指向你的路径。")
        return 0

    dev_n = len(_files(DEV))
    print(f"开发副本：{DEV}（{dev_n} 个文件）")
    for c in COPIES:
        print(f"部署副本：{c}")
    print()

    bad = 0
    for c in COPIES:
        print("=" * 74)
        print(f"▶ {_label(c)}")
        print(f"  {c}")
        print("=" * 74)
        if not c.exists():
            # 「副本不存在」有两种截然不同的含义，得分开对待：
            #   · 显式配置了 AISCAN_COPIES 却找不到 → 真问题，按失败计；
            #   · 没配置（外部使用者的常态）→ 本工具对其无意义，明确说明
            #     后跳过，**不计失败** —— 否则一句「存在不一致，需处理」
            #     会让人以为代码坏了（红线 9：别让「没跑起来」看起来像
            #     「检查不通过」）。
            if COPIES_CONFIGURED:
                print("  ⛔ 目录不存在（已通过 AISCAN_COPIES 配置）：跳过")
                bad += 1
            else:
                print("  ⓘ 未配置：该部署副本在本机不存在，跳过"
                      "（外部使用者可忽略本脚本）")
            continue

        # ---- 方向守卫（必须在任何写入之前）----
        # 唯一能真正防止「用旧内容覆盖新工作」的一步。放在 _sync 之前，
        # 因为一旦写下去就不可逆了 —— 事后再报「同步后仍有差异」，
        # 报的是已经发生的破坏，不是警告。
        newer_files, extra_files = _copy_newer_than_dev(DEV, c)
        if newer_files or extra_files:
            print("  ⛔ 拒绝同步：该副本里有「开发副本没有 / 比开发副本更新」的内容")
            if newer_files:
                print(f"     副本侧更新的文件 {len(newer_files)} 个（副本 mtime 更大＝"
                      "在本副本里改过）：")
                for rel in newer_files[:10]:
                    print(f"       · {rel}")
                if len(newer_files) > 10:
                    print(f"       …（其余 {len(newer_files) - 10} 项略）")
            if extra_files:
                print(f"     副本独有的文件 {len(extra_files)} 个（开发副本里没有）：")
                for rel in extra_files[:10]:
                    print(f"       · {rel}")
                if len(extra_files) > 10:
                    print(f"       …（其余 {len(extra_files) - 10} 项略）")
            print("     继续按固定方向同步会把这份副本的新工作覆盖掉，且不可逆。")
            print("     处理方式：确认哪一份是最新的 ——")
            print(f"       · 若确实是这份副本更新：先把改动搬回开发副本"
                  f"（{DEV}），再运行本脚本；")
            print("       · 若只是无关的临时文件：从该副本删除后重跑。")
            bad += 1
            continue

        if not args.verify_only:
            missing, changed = _diff(DEV, c)
            print(f"  差异：缺失 {len(missing)}，内容不同 {len(changed)}")
            for rel in missing[:10]:
                print(f"    ← 缺失 {rel}")
            for rel in changed[:10]:
                print(f"    ≠ 不同 {rel}")
            if len(missing) + len(changed) > 10:
                print(f"    …（其余 {len(missing) + len(changed) - 10} 项略）")
            if args.check:
                if missing or changed:
                    bad += 1
                continue
            n_new, n_upd = _sync(DEV, c)
            print(f"  已同步：新增 {n_new}，更新 {n_upd}")
            # 同步后必须复核，否则「同步成功」只是自我声明
            m2, c2 = _diff(DEV, c)
            if m2 or c2:
                print(f"  ✗ 同步后仍有差异：缺失 {len(m2)}，不同 {len(c2)}")
                for rel in (m2 + c2)[:8]:
                    print(f"    · {rel}")
                bad += 1
                continue
            print("  ✓ 内容已一致")

        ok, why = _verify(c)
        print(f"  {'✓' if ok else '✗'} 副本自校验：{why}")
        if not ok:
            bad += 1
        print()

    # ------------------------------------------------------------------
    # 授权台账：合规闸门，三处必须一致
    # ------------------------------------------------------------------
    print("=" * 74)
    print("授权台账（合规闸门：三处必须一致）")
    print("=" * 74)
    ledger_roots = [("开发副本", DEV)] + [(f"部署副本 {_label(c)}", c) for c in COPIES]
    ledger_src = [(lab, _read_ledger(p) if p.exists() else {}) for lab, p in ledger_roots]
    n_src = len(ledger_src)

    for lab, recs in ledger_src:
        print(f"  {lab:<34} {len(recs)} 条")

    all_doms = sorted({d for _, r in ledger_src for d in r})
    uneven = [d for d in all_doms
              if sum(1 for _, r in ledger_src if d in r) != n_src]
    merged, conflicts = merge_ledgers(ledger_src)
    ph = [(d, w) for d, w in ((d, placeholder_reason(d, r))
                              for d, r in sorted(merged.items())) if w]
    print()

    if uneven:
        print(f"  ✗ {len(uneven)} 个域名未在三处齐备：")
        for d in uneven[:20]:
            have = [lab for lab, r in ledger_src if d in r]
            print(f"    · {d}　仅见于 {'、'.join(have)}")
    elif all_doms:
        print(f"  ✓ {len(all_doms)} 个域名三处齐备")
    else:
        print("  三处均无记录（首次使用，属正常）。")

    if ph:
        print()
        print(f"  ⚠ 疑似自测/占位记录 {len(ph)} 条 —— **只提示，不自动清理**：")
        print("    台账「只追加不覆盖」是它作为审计凭证的前提，自动抹一条等于篡改审计链。")
        for d, why in ph:
            print(f"    · {d} —— {why}")

    if args.merge_ledger:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        print()
        print(f"  ▶ 合并写回：并集 {len(merged)} 条，只增不删，先留底 .bak-{stamp}")
        for lab, p in ledger_roots:
            if not p.exists():
                print(f"    {lab}：目录不存在，跳过")
                continue
            b = _backup_ledger(p, stamp)
            if b:
                print(f"    留底 {b.name}")
            _write_ledger(p, merged)
            print(f"    写回 → {len(merged)} 条")
        if conflicts:
            print(f"  ⚠ 合并中发现 {len(conflicts)} 处字段冲突"
                  f"（取更活跃的一条为准，请人工复核）：")
            for c in conflicts[:20]:
                print(f"    · {c}")
        # 写回后必须复核 —— 否则「已合并」只是自我声明
        after = [_read_ledger(p) for _, p in ledger_roots if p.exists()]
        if len({str(_norm_records(r)) for r in after}) == 1:
            print(f"  ✓ 合并后三处台账逐字一致（{len(merged)} 条）")
        else:
            print("  ✗ 合并后仍不一致")
            bad += 1
    elif uneven:
        print()
        print("  ✗ 台账三处不一致 —— 同一个目标在不同副本里会得到不同的放行结论，")
        print("    且审计凭证（登记时间/扫描次数）分散在多处，审计链是断的。")
        print("    处理：python sync_copies.py --merge-ledger")
        bad += 1

    print()
    print("=" * 74)
    print("关键文件摘要（三处必须一致）")
    print("=" * 74)
    dev_h = _key_hashes(DEV)
    mismatched = []
    for c in COPIES:
        if not c.exists():
            continue
        ch = _key_hashes(c)
        for k in dev_h:
            if ch.get(k) != dev_h[k]:
                mismatched.append(f"{k} @ {_label(c)}")
    for k, v in dev_h.items():
        print(f"  {v[:12]}  {k}")
    print()
    if mismatched:
        print("✗ 以下关键文件在三处之间不一致：")
        for m in mismatched:
            print(f"    · {m}")
        bad += 1
    else:
        print("✓ 关键文件三处一致")
    print()
    if bad:
        print("结果：存在不一致，需处理。")
        return 1
    # 收尾那句必须与**实际做过的事**对齐：
    # --check 只比对过、没跑副本自校验，写成「各自校验通过」就是把没做的说成通过。
    if args.check:
        print("结果：内容与台账均一致（仅比对，未跑副本自校验）。")
    elif args.verify_only:
        print("结果：各副本自校验通过（未做内容比对）。")
    else:
        print("结果：三副本一致且各自校验通过。")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
