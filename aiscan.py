#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aiscan — AI 驱动安全扫描工具链
==============================
统一命令行入口。

子命令
    scan        对目标执行完整扫描
    checklist   查看检查项清单统计
    tools       探测本机安全工具链
    profiles    查看扫描档位配置
    ledger      管理授权台账
    diff        比对两次扫描结果
    batch       按 targets.yaml 批量扫描（周期化预留）
    schedule    周期化判定 / 执行 / 通知
    creds       索取与接收登录凭据（拿令牌的指引 + 本地凭据库）

示例
    python aiscan.py scan --target example.com --name 示例系统
    python aiscan.py scan --target example.com --url https://example.com --profile deep
    python aiscan.py scan --target example.com --mode compliance   # 只出逐项合规清单

默认扫描模式为 redteam（黑客运维视角）：以「拿数据 / 改数据 / 拿控制权」为判定
终点，穷尽攻击路径。全量检查项逐项检查照旧全跑全报，红队是叠加层而非替代。
    python aiscan.py checklist
    python aiscan.py tools
    python aiscan.py ledger --register example.com --authorizer 张三 --ref "邮件20260920"
    python aiscan.py creds --target example.com          # 告诉我该去哪拿令牌
    python aiscan.py creds --target example.com --set user_a --from-clipboard
    python aiscan.py diff --target 示例系统
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 扫描模式：默认值（黑客运维视角）只定义在 engine/redteam.py 一处，命令行与
# 引擎共用同一个常量 —— 否则某天只改一处，就会出现「命令行说红队、引擎跑合规」。
from engine.redteam import DEFAULT_MODE, SCAN_MODES  # noqa: E402

BANNER = r"""
   _   ___ ___  ___   _   _  _
  /_\ |_ _/ __|/ __| /_\ | \| |
 / _ \ | |\__ \ (__ / _ \| .` |
/_/ \_\___|___/\___/_/ \_\_|\_|
  AI 驱动安全扫描工具链
"""


# ==============================================================================
def _make_progress() -> Any:
    """构造进度输出器（命令行默认开启）。

    默认开启、写 stderr、受 AISCAN_PROGRESS=off 控制 ——
    扫描一次十几分钟，没有进度输出时人无法区分「在跑」与「卡死」。
    """
    try:
        from engine.progress import ProgressReporter

        return ProgressReporter(enabled=True)
    except Exception:  # noqa: BLE001
        return None


def cmd_scan(args: argparse.Namespace) -> int:
    from engine.orchestrator import Orchestrator

    orch = Orchestrator(profile=args.profile)
    orch.progress = _make_progress()
    # 凭据等待：**只在显式要求时才等**（`--cred-wait N` 或 AISCAN_CRED_WAIT=N）。
    # 红队视角下不给「等运维递账号」留默认行为 —— 攻击者不等人，
    # 而无人值守时睡 30 分钟就是空转。试不出来的凭据缺口如实记进报告。
    _cw = getattr(args, "cred_wait", None)
    if _cw is None:
        _env = os.environ.get("AISCAN_CRED_WAIT", "").strip()
        orch.cred_wait_seconds = max(0, int(_env)) if _env.isdigit() else 0
        orch.cred_wait_explicit = bool(_env.isdigit())
    else:
        orch.cred_wait_seconds = max(0, int(_cw))
        orch.cred_wait_explicit = True
    if getattr(args, "no_credhunt", False):
        os.environ["AISCAN_CREDHUNT"] = "off"
    # 凭据情报：`--no-credosint` 完全关闭；`--no-credosint-online` 只关联网部分
    # （保留本地产品默认口令库）。后者是给「不想向任何第三方暴露目标关注关系」
    # 的场合用的 —— 本地库命中率依然很高，因为它靠的是产品识别。
    if getattr(args, "no_credosint", False):
        os.environ["AISCAN_CREDOSINT"] = "off"
        orch._no_credosint = True
    if getattr(args, "no_credosint_online", False):
        orch._no_credosint_online = True
    print(BANNER)

    # 授权提示
    if not args.skip_auth:
        ok, msg = orch.ledger.check(args.target)
        if not ok:
            print("=" * 72)
            print("⛔ 授权闸门拦截")
            print("=" * 72)
            print(msg)
            print()
            print("登记方式（二选一）：")
            print(f"  1. 命令行：python aiscan.py ledger --register {args.target} "
                  f"--authorizer 授权人 --ref 授权依据")
            print(f"  2. 编辑文件：{orch.ledger.path}")
            print()
            print("提示：这是为避免「未授权扫描」这一合规风险设置的闸门。")
            print("      内部自测可用 --skip-auth 跳过（不建议用于真实目标）。")
            return 2

    presets = {}
    if args.features:
        try:
            presets = json.loads(Path(args.features).read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"特征预置文件读取失败：{e}")
            return 2

    # 进度收尾必须显式做：**进程被强杀时这段不会执行**，那种情况靠归档目录里
    # progress.json 的时间戳不再前进来判断（见 engine/progress.py 说明 ⑦）。
    # 但正常结束与异常结束都必须留一行明确终态 —— 否则日志会静静停住，
    # 读者无从区分「跑完了」与「死了」。2026-09-30 真实事故：一次扫描跑完
    # nuclei 后被上层会话一并终止，前台最后一行停在 [5m39s]，没有任何说明。
    # 捕获 BaseException（含 KeyboardInterrupt）：Ctrl+C 也应当留下痕迹。
    _pg = getattr(orch, "progress", None)
    try:
        res = orch.scan(
            domain=args.target,
            target_name=args.name or "",
            base_url=args.url,
            preset_features=presets or None,
            skip_auth_check=args.skip_auth,
            enable_js=not args.no_js,
            enable_authz=args.authz,
            accounts_path=args.accounts,
            mode=getattr(args, "mode", DEFAULT_MODE),
            notice_full_repro=(getattr(args, "notice_repro", "masked") == "full"),
        )
    except BaseException as e:  # noqa: BLE001
        if _pg is not None:
            try:
                _pg.close(aborted=True, reason=f"{type(e).__name__}: {e}")
            except Exception:  # noqa: BLE001
                pass
        raise
    else:
        if _pg is not None:
            try:
                _pg.close()
            except Exception:  # noqa: BLE001
                pass

    print("=" * 72)
    print(f"扫描完成：{res.target_name}（{res.domain}）")
    print("=" * 72)
    for s in res.stages:
        mark = {"ok": "✓", "failed": "✗", "skipped": "·"}.get(s.status, "?")
        print(f"  {mark} {s.name:<22} {s.duration_ms:>7}ms  {s.detail[:70]}")
        if s.error:
            print(f"      ↳ 错误：{s.error.splitlines()[0][:150]}")
    print()
    if res.finding_set:
        c = res.finding_set.counts()
        print(f"发现：严重 {c['严重']} | 高危 {c['高危']} | 中危 {c['中危']} | "
              f"低危 {c['低危']} | 信息 {c['信息']}  （合计 {c['合计']}，待确认 {c['待确认']}）")
    # 红队模式下，「攻击目标达成没有」比漏洞计数更该被先看到
    _objs = getattr(orch, "_objectives", None) or []
    if _objs:
        print()
        print("攻击目标达成情况（红队视角）：")
        for o in _objs:
            why = (o.reason or "").splitlines()[0] if o.reason else ""
            print(f"  [{o.result}] {o.label}" + (f" —— {why}" if why else ""))
        print("  提示：「未能验证」= 没测；「未达成」= 试过打不穿。两者不可混同。")
    print()
    print("产出：")
    for k, v in res.reports.items():
        print(f"  • {k:<10} {v}")
    print(f"\n归档目录：{res.archive_dir}")

    # 需要登录令牌而没有 → 主动给出处置指引。
    # 过去这里只留一句「未配置测试账号」，等于把「拿不到凭据」变成静默终点：
    # 谁也说不清那几项该怎么补，它们就永远停在「未执行」。
    #
    # v11.7：在此之前先交代**自己试过什么**。顺序很重要 —— 一上来就谈
    # 「怎么把账号交给我们」，整份产出就从红队报告变成了需要业务方配合的自查表，
    # 而事实是我们已经零凭据试过入口、产品默认口令，也上网找过了。
    _plan = getattr(orch, "last_cred_plan", None)
    if _plan is not None and _plan.pending:
        print()
        _os = getattr(orch, "credosint", None)
        _ch = getattr(orch, "credhunt", None)
        if _os is not None or _ch is not None:
            _np = len(getattr(_os, "products", None) or []) if _os else 0
            _nq = len(getattr(_os, "queries", None) or []) if _os else 0
            _tried = int(getattr(_ch, "tried", 0) or 0) if _ch else 0
            _got = list(getattr(_ch, "found", None) or []) if _ch else []
            if not _got:
                print(f"零凭据自取结果：识别产品 {_np} 个、提交口令 {_tried} 组、"
                      f"外部检索 {_nq} 次 —— 未取得身份。")
                print("由此空出的认证类项属于**另一类工作**：持账号的认证态测试"
                      "（越权 / IDOR / 横向 / 并发会话）。")
                print("它需要业务方提供一个专用测试账号，与红队零凭据入场是两回事；"
                      "结论在报告中单列，不与红队结论混记。")
                print()
        # 默认**不展开**「怎么把令牌交给我们」的那几条路线（2026-09-30）。
        # 红队扫描的收尾里出现一大段索取凭据的操作指引，整份产出就会被读成
        # 「需要业务方配合的自查表」——姿态错了，而且那些路线此时用不上：
        # 真正要做持账号的认证态测试时，单独调出来即可。
        _pend = len(getattr(_plan, "pending", None) or [])
        print(f"（持账号的认证态测试目前登记 {_pend} 项。交接方式见 "
              f"`python aiscan.py creds --help`；扫描收尾不再展开，"
              f"以免把红队产出读成需要业务方配合的自查表。）")
    return 0


# ==============================================================================
def _cred_plan(target: str, url: str = "", login_url: str = ""):
    """取该目标的凭据需求全景：优先复用最近一次扫描落盘的需求单。

    为什么要复用扫描的产物：登录入口是**探测出来的**（指纹阶段探过的那批路径）。
    脱离扫描重新猜一个登录地址，等于把「有证据」降级成「拍脑袋」——
    而操作者会照着它去登录，指错了地方他还以为自己找错了系统。
    """
    from engine import credguide as cg

    saved = None
    try:
        saved = cg.latest_plan(ROOT / "outputs", target=target)
    except Exception:  # noqa: BLE001
        saved = None
    if saved is not None and saved.needs:
        if login_url and not saved.needs[0].entry_url:
            # 扫描时没能推断出入口，但这次给了 —— 用给的，并标明来源是人。
            saved.needs = [cg.CredNeed(
                role=n.role, label=n.label, why=n.why, blocked=n.blocked,
                entry_url=login_url, entry_evidence="由你直接提供",
                entry_source="user", configured=n.configured,
                present=n.present, verified=n.verified) for n in saved.needs]
        return saved

    return cg.build_plan(target=target, target_url=url,
                         accounts=_accounts_from_config(target),
                         login_url=login_url)


def _accounts_from_config(target: str) -> list[dict]:
    """从 targets.yaml 的 accounts 段取账号名（只取名字，不取凭据）。"""
    tf = ROOT / "targets.yaml"
    if not tf.exists():
        return []
    try:
        import yaml  # noqa: PLC0415

        data = yaml.safe_load(tf.read_text(encoding="utf-8")) or {}
        for rec in (data.get("targets") or []):
            if str(rec.get("domain") or "") == target:
                return [dict(a) for a in (rec.get("accounts") or [])]
        return [dict(a) for a in (data.get("accounts") or [])]
    except Exception:  # noqa: BLE001
        return []


def _creds_set(cg, args: argparse.Namespace, sf: Path) -> int:
    """把凭据写进本机凭据库。**全程不回显凭据原文**。"""
    role = args.set
    if args.file:
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            print(f"读取凭据文件失败：{type(e).__name__}: {e}")
            return 2
        src = f"文件 {args.file}"
    elif args.stdin:
        text = sys.stdin.read()
        src = "标准输入"
    else:
        text, src = cg.read_clipboard()
        if not text.strip():
            print("剪贴板里没读到内容。")
            print("  先在浏览器登录 → F12 → Application → Cookies 复制值，")
            print("  或用 --file / --stdin 指定来源。")
            return 2

    rec_full = cg.parse_pasted_full(text)
    ck, hd = rec_full["cookies"], rec_full["headers"]
    u, pw = rec_full["username"], rec_full["password"]
    lu = str(getattr(args, "login_url", "") or "").strip() or rec_full["login_url"]
    if not ck and not hd and not (u and pw):
        print(f"从{src}里没能解析出凭据（识别为：{rec_full['note']}）。")
        print("  可接受三种形态：")
        print("    1. Cookie 串（a=1; b=2）或 Copy as cURL 的整段命令")
        print('    2. JSON 请求头：{"cookies":"a=1; b=2","headers":{"Authorization":"..."}}')
        print('    3. 账号+密码（仅普通登录页）：{"username":"账号","password":"密码"}')
        return 2

    ok, msg = cg.write_role(sf, role, ck, hd, username=u, password=pw,
                            login_url=lu)
    print(msg)
    if not ok:
        return 2
    print()
    if u and pw:
        print("⚠ 账号+密码形式：扫描器会在下一轮扫描时**自动登录**。")
        print("  这要求登录页是「输账号密码就能登」的普通表单 ——")
        print("  有验证码 / 短信 / 扫码的系统，自动登录会失败，请改给 Cookie（路线 A）。")
        print()
    print("⚠ 回验要能成立，还需要一个「登录后才能访问」的页面。")
    print("  拿站点首页回验是无效的（首页对游客也返回 200），")
    print("  那种情况下登录态只能判「未验证」，认证类检查项仍然跑不起来。")
    print("  补法：在 accounts 配置里给该账号加一行 verify_path: /个人中心路径")
    print()
    print("下一步：")
    print(f"  python aiscan.py creds --target {args.target} --verify")
    return 0


def _creds_verify(cg, args: argparse.Namespace, target: str, base: str) -> int:
    """回验凭据是否真的构成有效会话。

    `base` 是回验请求的**基准地址**（默认 `https://<域名>`），与登录入口
    `--login-url` 是两件事：入口是「去哪登录」，基准是「回验时请求哪台主机」。
    混用会把回验打到登录页上 —— 登录页对游客当然 200，于是「会话有效」这一
    结论会毫无根据地成立。
    """
    from engine.sessionpool import build_pool

    # 回验会**真的向目标发请求**，所以同样必须过授权闸门 ——
    # 否则「creds --verify」就成了绕过台账往任意主机发包的后门。
    if not getattr(args, "skip_auth", False):
        from ledger.auth_ledger import AuthLedger

        ok, msg = AuthLedger().check(target)
        if not ok:
            print("=" * 72)
            print("⛔ 授权闸门拦截（回验会向目标发 2 个请求，同样需要授权）")
            print("=" * 72)
            print(msg)
            return 2

    sf = cg.session_file_for(target)
    roles = [args.set] if args.set else sorted(cg.read_roles(sf).keys())
    if not roles:
        print(f"凭据库里还没有任何角色：{sf}")
        print(f"  先执行：python aiscan.py creds --target {target}")
        return 2

    vp = str(getattr(args, "verify_path", "") or "")
    recs = [{"name": r, "authorized": True, "verify_path": vp} for r in roles]
    pool = build_pool(recs, base, profile_key=args.profile,
                      verify_path=vp, cred_file=sf)

    print("-" * 74)
    print(f"{'角色':<14}{'登录态':<10}说明")
    print("-" * 74)
    for a in pool.accounts:
        note = str(a.get("login_note") or a.get("rejected") or "")
        print(f"{str(a.get('name')):<14}{str(a.get('login_state')):<10}{note[:60]}")
    print("-" * 74)
    got = pool.authenticated_pairs()
    print(f"已确认登录态：{got} / {len(roles)}")
    if got < 2:
        print("提示：越权 / 横向移动类判定需要 ≥2 个**已确认登录态**的不同身份，")
        print("      不足 2 个时这类结论只能判「未能验证」，不会被写成通过。")
    for line in pool.summary_lines():
        print(f"  · {line}")
    return 0


def cmd_creds(args: argparse.Namespace) -> int:
    """索取与接收登录凭据。

    存在的理由：「扫描需要令牌」过去是个**静默的终点** —— 只会记一句
    「未配置测试账号」然后降级成未执行，没人知道该去哪拿、怎么给。
    这里把它变成闭环：探测出的登录入口 → 两条取证路线 → 写进本机凭据库
    → 回验 → 重扫补齐。

    **凭据通道刻意不走对话**：令牌等同于账号权限，贴进对话就进了 AI 上下文
    与对话日志，且收不回来。所以这里只告诉操作者「写到哪个文件」，
    由工具自己读。
    """
    from engine import credguide as cg

    print(BANNER)
    target = (args.target or "").strip()
    if not target:
        print("请用 --target 指定目标域名（与 scan --target 保持一致）：")
        print("  python aiscan.py creds --target <域名>")
        return 2
    sf = cg.session_file_for(target)
    base = (getattr(args, "base_url", "") or "").strip() or f"https://{target}"
    login_url = (args.login_url or "").strip()
    url = login_url or f"https://{target}"

    if args.set:
        return _creds_set(cg, args, sf)

    if args.clear is not None:
        n, msg = cg.clear_role(sf, "" if args.clear == "*" else args.clear)
        print(msg)
        print("（清除后重扫，相关检查项会如实回到「未执行」，不会被记成通过。）")
        return 0 if n else 1

    if args.init:
        roles = [args.set] if args.set else [
            str(a.get("name") or "") for a in _accounts_from_config(target)
            if a.get("name")] or [r for r, _ in cg.DEFAULT_ROLE_HINTS]
        if sf.exists() and not args.force:
            print(f"凭据文件已存在，未覆盖：{sf}")
            print("  要重建骨架请加 --force（会丢弃已填内容）。")
            return 1
        ok, msg = cg.write_skeleton(sf, roles)
        print(msg)
        return 0 if ok else 2

    if args.verify:
        return _creds_verify(cg, args, target, base)

    # 默认：给出索取指引 + 当前状态
    plan = _cred_plan(target, url, login_url)
    print(cg.render(plan, url))
    if args.json:
        try:
            Path(args.json).write_text(
                json.dumps(plan.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8")
            print(f"（需求清单已写入 {args.json}）")
        except Exception as e:  # noqa: BLE001
            print(f"[警告] 需求清单写入失败：{type(e).__name__}: {e}")
    return 0


# ==============================================================================
def cmd_checklist(args: argparse.Namespace) -> int:
    from checklist.loader import load_checklist, load_applicability

    cl = load_checklist()
    apps = load_applicability()
    print(BANNER)
    print(f"检查项总量：{len(cl)} 项")
    print(f"  WSTG 骨架   ：{cl.meta.get('wstg_items')} 项（{cl.meta.get('baseline', '')}）")
    print(f"  场景扩展    ：{cl.meta.get('extras_items')} 项")
    print(f"  适用条件变量：{len(apps)} 个")
    print()
    print(f"{'分类':<12} {'名称':<18} {'项数':>5}")
    print("-" * 40)
    for cat, group in cl.by_category().items():
        print(f"{cat:<12} {group[0].category_name:<18} {len(group):>5}")
    print("-" * 40)
    print(f"{'合计':<12} {'':<18} {len(cl):>5}")

    if args.show:
        item = cl.by_id(args.show)
        if not item:
            print(f"\n未找到检查项：{args.show}")
            return 1
        print(f"\n检查项详情：{item.id}")
        print("-" * 60)
        print(f"名称    ：{item.name}")
        print(f"分类    ：{item.category} — {item.category_name}")
        print(f"适用条件：{item.app}（{apps.get(item.app, '')}）")
        print(f"检测方法：{item.detect}")
        print(f"验证方法：{item.verify}")
        print(f"定级规则：{item.level}")
        print(f"合规映射：{item.compliance}")
    return 0


# ==============================================================================
def cmd_tools(args: argparse.Namespace) -> int:
    from engine.tools import Toolchain

    print(BANNER)
    tc = Toolchain()
    tc.probe_all(verbose=True)
    print()
    fb = tc.fallback_notes()
    if fb:
        print("降级说明：")
        for n in fb:
            print(f"  • {n}")
    else:
        print("全部工具可用，无降级。")
    return 0


# ==============================================================================
def cmd_profiles(args: argparse.Namespace) -> int:
    import yaml

    p = ROOT / "config" / "profiles.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    print(BANNER)
    print(f"默认档位：{data.get('meta', {}).get('default', 'standard')}")
    print()
    for key, prof in (data.get("profiles") or {}).items():
        r = prof.get("rate", {})
        print(f"[{key}] {prof.get('name')}")
        print(f"  {prof.get('description', '').strip()}")
        print(f"  速率 {r.get('requests_per_second')} rps / 并发 {r.get('concurrency')} / "
              f"超时 {r.get('timeout_seconds')}s")
        print(f"  nuclei 严重度：{', '.join(prof.get('nuclei', {}).get('severity_filter', []))}")
        print(f"  允许方法：{', '.join(prof.get('http', {}).get('methods_allowed', []))}")
        print(f"  受控写验证：{prof.get('write_verification')}")
        print()
    hl = data.get("hard_limits", {})
    print("全局硬约束（任何档位不可突破）：")
    for f in hl.get("forbidden_always", []):
        print(f"  ⛔ {f}")
    return 0


# ==============================================================================
def cmd_coverage(args: argparse.Namespace) -> int:
    """校验「清单条目 ↔ 检测器」的绑定覆盖率。

    这条命令的意义：保证清单里的每一项都真的有人负责执行。
    只要出现缺口，扫描报告里那一项就会是「未执行」——
    宁可少说，也不能把没测的项说成通过。
    """
    import subprocess

    print(BANNER)
    cmd = [sys.executable, str(ROOT / "validate_coverage.py")]
    if getattr(args, "strict", False):
        cmd.append("--strict")
    return subprocess.call(cmd)


def cmd_selftest(args: argparse.Namespace) -> int:
    """离线自测：本地起假应用跑完全量检查项，验证状态机不产生假阴性。

    全程不产生外网流量（DNS / crt.sh / 端口扫描均已打桩），可反复运行。
    """
    import subprocess

    print(BANNER)
    cmd = [sys.executable, str(ROOT / "selftest_engine.py")]
    if getattr(args, "verbose", False):
        cmd.append("--verbose")
    if getattr(args, "report", None):
        cmd += ["--report", args.report]
    return subprocess.call(cmd)


def cmd_audit(args: argparse.Namespace) -> int:
    """检测器强度审计：覆盖率之外，检查每个检测器是否真的发出了请求。

    覆盖率只能回答「有没有人负责」，回答不了「负责人有没有干活」。
    这条命令统计每个检测器的实际探测次数，并揪出
    「一次请求都没发、却下了结论」的项 —— 那是残余假阴性的主要来源。
    有缺陷时非零退出，可直接挂到提交前检查或流水线里。
    """
    import subprocess

    print(BANNER)
    cmd = [sys.executable, str(ROOT / "audit_detectors.py")]
    if getattr(args, "json", None):
        cmd += ["--json", args.json]
    return subprocess.call(cmd)


# ==============================================================================
def cmd_ledger(args: argparse.Namespace) -> int:
    from ledger.auth_ledger import AuthLedger

    ledger = AuthLedger()
    print(BANNER)

    if args.register:
        rec = ledger.register(
            args.register,
            target_name=args.name or "",
            authorizer=args.authorizer or "",
            authorization_ref=args.ref or "",
            authorization_date=args.date or "",
            allow_write_test=bool(args.allow_write),
            notes=args.notes or "",
            objectives=([o for o in str(args.objectives).split(",") if o.strip()]
                        if getattr(args, "objectives", None) else None),
            impact_level=getattr(args, "impact_level", "") or "",
        )
        ledger.save()
        print(f"已登记：{rec.domain}")
        print(f"  授权人  ：{rec.authorizer or '⚠ 未填写'}")
        print(f"  授权依据：{rec.authorization_ref or '⚠ 未填写'}")
        print(f"  写验证  ：{'允许' if rec.allow_write_test else '不允许'}")
        print(f"  攻击目标：{rec.objectives or '（按扫描档位默认）'}")
        print(f"  影响级别：{rec.impact_level or '（按扫描档位默认）'}")
        print(f"\n台账文件：{ledger.path}")
        if not rec.is_valid:
            print("\n⚠ 授权人或授权依据未填写，该记录暂不可用（扫描时仍会被拦截）。")
        return 0

    if args.remove:
        d = ledger._norm(args.remove)
        if d in ledger.records:
            del ledger.records[d]
            ledger.save()
            print(f"已移除：{d}")
            return 0
        print(f"未找到记录：{d}")
        return 1

    records = ledger.list_all()
    print(f"授权台账（{len(records)} 条）")
    print(f"文件：{ledger.path}")
    print()
    if not records:
        print("（空）")
        print("\n登记方式：python aiscan.py ledger --register <域名> "
              "--authorizer <授权人> --ref <授权依据>")
        return 0
    print(f"{'域名':<34} {'授权人':<12} {'依据':<24} {'扫描次数':>8}")
    print("-" * 84)
    for r in records:
        mark = "" if r.is_valid else "  ⚠要素不全"
        print(f"{r.domain:<34} {r.authorizer or '-':<12} {r.authorization_ref or '-':<24} "
              f"{r.scan_count:>8}{mark}")
    return 0


# ==============================================================================
def cmd_diff(args: argparse.Namespace) -> int:
    from diff.differ import Differ

    print(BANNER)
    d = Differ()
    if args.baseline and args.current:
        res = d.compare_files(args.baseline, args.current)
    elif args.target:
        # 自动找最近两次
        target_dirs = list((ROOT / "outputs").glob(f"*{args.target}*"))
        if not target_dirs:
            print(f"未找到目标归档目录：outputs/*{args.target}*")
            return 1
        pair = None
        for td in target_dirs:
            pair = Differ.latest_pair(td)
            if pair:
                break
        if not pair:
            print("该目标历史扫描不足两次，无法比对。")
            return 1
        print(f"基线：{pair[0]}")
        print(f"本次：{pair[1]}\n")
        res = d.compare_files(*pair)
    else:
        print("请指定 --target 或同时指定 --baseline / --current")
        return 1

    print(res.render_markdown())
    s = res.summary()
    print(f"\n比对结果：新增 {s['新增']} | 已修复 {s['已修复']} | "
          f"仍存在 {s['仍存在']} | 等级变化 {s['等级变化']}")
    return 0


# ==============================================================================
def _run_targets(targets: list[dict], profile: str, mode: str) -> list[tuple]:
    """逐个扫描目标，返回 [(target, res, orch)]。

    抽出来是为了让「手动批量」与「周期化调度」走**同一条**扫描链路 ——
    两条链路各写一遍的话，某天只改了其中一条，周期性扫描的结论就会跟
    手动跑出来的不一致，而没人会发现。
    """
    from engine.orchestrator import Orchestrator

    out: list[tuple] = []
    for i, t in enumerate(targets):
        name = t.get("name") or t.get("primary_domain", "")
        print("=" * 72)
        print(f"目标：{name}")
        print("=" * 72)
        orch = Orchestrator(profile=profile)
        # 批量 / 调度路径**不等待凭据**：无人值守场景停下来等人会让整批
        # 目标全部超时。缺口照旧如实写进报告，人工补齐后重扫即可。
        orch.cred_wait_seconds = 0
        orch.cred_wait_explicit = False
        # 批量场景也要有进度：整批跑起来可能几十分钟，没有进度就只能盯着黑屏。
        orch.progress = _make_progress()
        print(f"  [目标 {i + 1}/{len(targets)}] {name}", flush=True)
        # 与单目标一致：进度必须在每条终态上都收尾，异常也不许让日志静静停住。
        _pg = getattr(orch, "progress", None)
        try:
            res = orch.scan(
                domain=t.get("primary_domain", ""),
                target_name=name,
                base_url=t.get("base_url"),
                authorization=t.get("authorization"),
                # 批量/调度一律「自动」：有测试身份就跑，没身份这一步本来也只会空转。
                # 传 None 而不是 bool(...)，是为了让「凭据中途到位后补跑」这条
                # 在批量场景下同样生效 —— 定时任务里没人能手动加开关。
                enable_authz=None,
                mode=mode,
            )
        except BaseException as e:  # noqa: BLE001
            if _pg is not None:
                try:
                    _pg.close(aborted=True, reason=f"{type(e).__name__}: {e}")
                except Exception:  # noqa: BLE001
                    pass
            raise
        else:
            if _pg is not None:
                try:
                    _pg.close()
                except Exception:  # noqa: BLE001
                    pass
        out.append((t, res, orch))
        if res.finding_set:
            c = res.finding_set.counts()
            print(f"  发现：严重 {c['严重']} | 高危 {c['高危']} | 中危 {c['中危']} | "
                  f"低危 {c['低危']} | 信息 {c['信息']}")
        # 红队模式的目标结论比漏洞计数更重要 —— 批量场景尤其要看这一行
        for o in (getattr(orch, "_objectives", None) or []):
            why = (o.reason or "").splitlines()[0][:60] if o.reason else ""
            print(f"  [{o.result}] {o.label}{('——' + why) if why else ''}")
        print()
    return out


def _notify_targets(pairs: list[tuple], *, dry_run: bool = False,
                    quiet: bool = False) -> list:
    """把每轮结果编成摘要发飞书。

    没配置 webhook 时**如实说「未发送」**，不得表现为「已通知」。
    """
    from engine.notify import FeishuNotifier, WEBHOOK_ENV
    from engine.scheduler import summary_from_scan

    if quiet:
        print("（--no-notify：本次不发通知）")
        return []
    n = FeishuNotifier(dry_run=dry_run)
    if not n.available:
        print(f"（未配置飞书通知：环境变量 {WEBHOOK_ENV} 未设置 → 本次未发送）")
        return []
    results = []
    for _t, res, orch in pairs:
        summ = summary_from_scan(res, orch, getattr(orch, "_last_diff", None))
        r = n.send(summ)
        results.append(r)
        print(f"  通知（{res.target_name}）：{r.summary()}")
    return results


def cmd_batch(args: argparse.Namespace) -> int:
    """按 targets.yaml 批量扫描（**不管周期**，凡在册目标全扫一遍）。"""
    import yaml

    tf = Path(args.targets) if getattr(args, "targets", None) else (ROOT / "targets.yaml")
    data = yaml.safe_load(tf.read_text(encoding="utf-8")) or {}
    targets = data.get("targets") or []
    settings = data.get("settings") or {}

    print(BANNER)
    if not targets:
        print(f"targets.yaml 中未配置目标。")
        print(f"请编辑 {tf}，在 targets 段按模板添加目标后重试。")
        print(f"\n周期化扫描配置位于该文件的 schedule 段（当前 "
              f"{'已启用' if (data.get('schedule') or {}).get('enabled') else '未启用'}）。")
        return 1

    profile = args.profile or settings.get("profile", "standard")
    mode = getattr(args, "mode", DEFAULT_MODE)
    print(f"批量扫描：{len(targets)} 个目标，档位 {profile}，模式 {mode}")
    print("注意：本命令忽略 schedule 判定，在册目标全部执行；"
          "只想跑到点的目标请用 `schedule --run`。\n")

    pairs = _run_targets(targets, profile, mode)

    print("=" * 72)
    print(f"批量扫描完成，共 {len(pairs)} 个目标")
    for _t, r, _o in pairs:
        c = r.finding_set.counts() if r.finding_set else {}
        print(f"  {r.target_name:<24} 合计 {c.get('合计', 0):>3} 项，"
              f"严重 {c.get('严重', 0)} / 高危 {c.get('高危', 0)}")
    print()
    _notify_targets(pairs, dry_run=getattr(args, "notify_test", False),
                    quiet=getattr(args, "no_notify", False))
    return 0


# ==============================================================================
def cmd_schedule(args: argparse.Namespace) -> int:
    """周期化调度：按 targets.yaml 的 schedule 段判定该谁跑，可选直接执行。

    默认**只看不跑**（打印每个目标到不到点、以及为什么），避免手滑全量扫描。
    """
    from engine.scheduler import Scheduler, STATE_FILE_NAME

    print(BANNER)
    tf = Path(args.targets) if getattr(args, "targets", None) else (ROOT / "targets.yaml")
    sch = Scheduler(tf)

    # 配置错误必须先说 —— 表达式写错 = 永远不执行，而且一声不吭。
    errs = sch.config_errors()
    if errs:
        print("⛔ 调度配置有问题，已停止（不静默不出勤）：")
        for e in errs:
            print(f"  • {e}")
        print(f"\n请修正 {tf} 的 schedule 段后重试。")
        return 2

    mode_desc = f"cron {sch.cron!r}" if sch.cron else f"mode={sch.mode}"
    print(f"调度判定：{mode_desc}　启用={'是' if sch.enabled else '否'}"
          f"　保留期={sch.retention_days or '未设置'}天")
    print(f"状态文件：{sch.state_path}　（文件名 {STATE_FILE_NAME}）")
    print()

    all_due = sch.due()
    if not all_due:
        print(f"{tf} 的 targets 段没有目标。请在模板里添加后重试。")
        return 1

    print(f"{'目标':<24} {'判定':<6} 原因")
    print("-" * 72)
    n_due = 0
    for t, d in all_due:
        name = t.get("name") or t.get("primary_domain", "(未命名)")
        if d.due:
            n_due += 1
        print(f"{name:<24} {'到点' if d.due else '不到点':<6} {d.reason}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"mode": sch.mode, "cron": sch.cron, "enabled": sch.enabled,
             "decisions": [d.to_dict() for _t, d in all_due]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n判定明细已写入：{args.json}")

    stale = sch.stale_archives()
    if stale:
        print(f"\n超过保留期（{sch.retention_days} 天）的历史归档 {len(stale)} 个："
              f"**只清点，不删除**")
        for s in stale:
            print(f"  • {s['path']}（{s['age_days']} 天）")
        print("  如需清理请人工确认后手动删除 —— 自动删会把历史比对基线一起删掉。")

    if not args.run:
        print(f"\n本次为「只看不跑」。到点 {n_due} 个目标；"
              f"要执行请加 `--run`。")
        # 注册命令的三个坑（都会让人「以为配好了，其实没有」）：
        #   ① 不带 /f 时重复注册会报「任务已存在」—— 改了时间再跑一次，
        #      你会以为改成了，实际 Task Scheduler 里还是旧的那条。
        #   ② 注册成功 ≠ 到点会跑：默认只在用户登录时才触发，
        #      无人值守的机器上会「静默不出勤」，正是本模块最想避免的失效形态。
        #   ③ schtasks 认不认这条任务，只有 /query 说了算 —— 必须给出复核命令。
        task_name = "aiscan 周期扫描"
        _win = sys.platform.startswith("win")
        print("\n让本命令自动按期执行（需要本机常开）：")
        if _win:
            print("  Windows —— 注册计划任务（/f = 重复执行即更新，可安全重跑）：")
            print(f"    schtasks /create /tn \"{task_name}\" /sc daily /st 02:00 /f "
                  f"/tr \"\\\"{sys.executable}\\\" \\\"{ROOT / 'aiscan.py'}\\\" schedule --run\"")
            print("    注册后**必须复核**（不复核等于没配）：")
            print(f"      schtasks /query /tn \"{task_name}\" /v /fo LIST")
            print("    ⚠ 上面这条默认只在「用户已登录」时触发。无人值守请去掉该限制：")
            print("      在「任务计划程序」里打开该任务 → 常规 → 选「不管用户是否登录都运行」，")
            print("      或加 /ru SYSTEM（需管理员权限）。")
            print("    停用 / 删除：")
            print(f"      schtasks /change /tn \"{task_name}\" /disable")
            print(f"      schtasks /delete /tn \"{task_name}\" /f")
        else:
            # 只打印与当前平台相符的那条：把 Windows 路径写进 crontab 的提示
            # 是照着抄必然失败的假指令 —— 宁可不显示。
            print("  Linux/macOS —— 写进 crontab：")
            print(f"    {sys.executable} {ROOT / 'aiscan.py'} schedule --run")
        print("    ⚠ 它跑的是**当前这份副本**的 aiscan.py 与 targets.yaml：")
        print(f"      {ROOT / 'aiscan.py'}")
        print("      哪份副本想被调度，就从哪份副本执行本命令；"
              "targets.yaml 的 targets 段为空时，到点也不会扫任何目标。")
        print("  ⚠ 无论哪种方式，都请先 `schedule --run` **手动跑一次**：")
        print("    手动跑不通的任务，挂到计划任务里同样跑不通，而且不再有人看着报错。")
        print("  通知需要环境变量 AISCAN_FEISHU_WEBHOOK（可选 AISCAN_FEISHU_SECRET）；"
              "建议配好后先用 `--notify-test` 试发一次。")
        return 0

    if not sch.enabled:
        # 说清是「没启用」而不是「没有目标」—— 二者运维处理完全不同。
        print("\n⛔ schedule.enabled 为 false，周期化未启用，不执行。"
              "（要现在跑一次请用 `batch`）")
        return 2

    due = [(t, d) for t, d in all_due if d.due]
    if not due:
        print("\n没有到点的目标，本次不执行。")
        print("（这不是失败：cron 未命中 / 本周期已跑过 / 目标缺授权，"
              "逐条原因见上表）")
        return 0

    targets = [t for t, _d in due]
    print(f"\n开始执行 {len(targets)} 个到点目标：")
    print("  " + "、".join((t.get("name") or t.get("primary_domain", ""))
                           for t in targets))
    print()

    settings = sch.settings
    profile = args.profile or settings.get("profile", "standard")
    scan_mode = getattr(args, "mode", DEFAULT_MODE)
    pairs = _run_targets(targets, profile, scan_mode)

    # 只对**真正跑完**的目标记账 —— 扫描抛异常的目标不落「已执行」，
    # 否则这一周期就永远不会再扫它了。
    done_names = []
    ok_pairs = []
    for t, res, orch in pairs:
        name = t.get("name") or t.get("primary_domain", "")
        failed = any(s.status == "failed" for s in (res.stages or []))
        if failed:
            bad = "、".join(s.name for s in res.stages if s.status == "failed")
            print(f"  ⚠ {name} 有阶段失败（{bad}），本周期**不记为已执行**，"
                  f"下轮会重扫")
            continue
        sch.mark_ran(name, note="周期化自动执行")
        done_names.append(name)
        ok_pairs.append((t, res, orch))
    if done_names:
        sch.save_state()
        print(f"\n已登记执行状态（{len(done_names)} 个）："
              + "、".join(done_names))
    print(f"状态文件：{sch.state_path}")

    print("=" * 72)
    print(f"周期化执行完成：到点 {len(targets)} 个，实际执行 {len(pairs)} 个，"
          f"记账 {len(done_names)} 个")
    print()
    _notify_targets(ok_pairs, dry_run=getattr(args, "notify_test", False),
                    quiet=getattr(args, "no_notify", False))
    return 0


# ==============================================================================
def _add_resource_flags(p: argparse.ArgumentParser) -> None:
    """给会跑扫描的子命令挂上资源控制开关。

    为什么默认就是低影响：一次扫描的峰值占用足以让整台机器不可用
    （nuclei 是 Go 程序、默认按全部逻辑核跑；渲染再起一个浏览器）。
    「默认流畅」比「默认最快」重要得多 —— 想快可以显式开全速，
    但没人应该因为忘了加参数而被打断工作。
    """
    g = p.add_mutually_exclusive_group()
    g.add_argument("--full-speed", action="store_true",
                   help="全速运行：不限并发、不给子进程设资源上限、不改进程优先级。"
                        "会占满本机 CPU（这是配置选择，不是故障）")
    g.add_argument("--low-impact", dest="low_impact", action="store_true", default=None,
                   help="强制低影响模式（这是默认值；显式给出用于覆盖环境变量）")
    p.add_argument("--cpu-share", type=float, default=None, metavar="0.1-1.0",
                   help="低影响模式下允许使用的 CPU 份额（默认 0.5，即一半逻辑核）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aiscan",
        description="AI 驱动安全扫描工具链",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # scan
    p = sub.add_parser("scan", help="对目标执行完整扫描")
    p.add_argument("--target", required=True, help="目标域名（如 example.com）")
    p.add_argument("--name", help="目标系统名称（用于报告标题与归档目录）")
    p.add_argument("--url", help="指定入口 URL（默认 https://<域名>）")
    p.add_argument("--profile", default="standard", choices=["safe", "standard", "deep"],
                   help="扫描档位（默认 standard）")
    p.add_argument("--features", help="特征预置 JSON 文件路径")
    p.add_argument("--accounts", help="测试账号配置文件（启用越权矩阵时需要）")
    p.add_argument("--authz", dest="authz", action="store_true", default=None,
                   help="强制启用权限矩阵验证（默认：有测试身份就自动启用，"
                        "含凭据在扫描中途到位后的自动补跑）")
    p.add_argument("--no-authz", dest="authz", action="store_false",
                   help="显式关闭权限矩阵验证")
    p.add_argument("--no-js", action="store_true", help="跳过 JS 产物分析")
    p.add_argument("--mode", default=DEFAULT_MODE, choices=list(SCAN_MODES),
                   help=f"扫描模式（默认 {DEFAULT_MODE}）："
                        f"redteam=黑客运维视角，以「拿数据 / 改数据 / 拿控制权」"
                        f"为判定终点；compliance=只出逐项合规清单")
    p.add_argument("--skip-auth", action="store_true",
                   help="跳过授权闸门（仅限内部自测，勿用于真实目标）")
    p.add_argument("--cred-wait", type=int, default=None,
                   help="缺登录凭据时暂停等待的秒数。**默认不等待**"
                        "（红队视角：攻击者不等人；无人值守时睡 30 分钟等于空转）；"
                        "要现场守着终端等凭据就显式给，如 --cred-wait 1800。"
                        "环境变量 AISCAN_CRED_WAIT 同样视为显式指定")
    p.add_argument("--no-credhunt", action="store_true",
                   help="关闭「黑客视角凭据获取」（默认开启：找登录入口 + "
                        "受控默认口令尝试）。关闭后相关项直接记「待人工执行」")
    p.add_argument("--no-credosint", action="store_true",
                   help="关闭「凭据情报」（默认开启：从指纹识别产品 → 本地产品"
                        "默认口令库 → 必要时联网检索）。这是红队自己找凭据的路子")
    p.add_argument("--no-credosint-online", action="store_true",
                   help="只关掉凭据情报里的**联网检索**部分，保留本地产品默认口令库。"
                        "用于不希望向第三方检索源暴露「有人正在关注该目标」的场合")
    p.add_argument("--notice-repro", choices=["masked", "full"], default="masked",
                   help="扫描通告（对外通晒版）里的复现步骤形态："
                        "masked=收敛掉可直接执行的命令、保留地址与判定标准（默认）；"
                        "full=保留完整复现命令。通告会贴进部门大群，"
                        "默认收敛是为了不让通告变成一份可分发的验证手册")
    _add_resource_flags(p)   # scan：资源开关（低影响默认开）
    p.set_defaults(func=cmd_scan)

    # checklist
    p = sub.add_parser("checklist", help="查看检查项清单统计")
    p.add_argument("--show", help="查看指定检查项的完整定义（如 WSTG-INPV-05）")
    p.set_defaults(func=cmd_checklist)

    # tools
    p = sub.add_parser("tools", help="探测本机安全工具链")
    p.set_defaults(func=cmd_tools)

    # profiles
    p = sub.add_parser("profiles", help="查看扫描档位配置")
    p.set_defaults(func=cmd_profiles)

    # ledger
    p = sub.add_parser("ledger", help="管理授权台账")
    p.add_argument("--register", metavar="域名", help="登记一个目标的授权")
    p.add_argument("--remove", metavar="域名", help="移除一条授权记录")
    p.add_argument("--name", help="目标系统名称")
    p.add_argument("--authorizer", help="授权人")
    p.add_argument("--ref", help="授权依据（邮件编号 / 工单号等）")
    p.add_argument("--date", help="授权日期（YYYY-MM-DD）")
    p.add_argument("--allow-write", action="store_true", help="允许受控写验证")
    p.add_argument("--notes", help="备注")
    p.add_argument("--objectives",
                   help="红队模式允许的攻击目标，逗号分隔："
                        "READ_DATA,MODIFY_DATA,TAKE_CONTROL（不填=按档位默认）")
    p.add_argument("--impact-level", choices=["L1", "L2", "L3"],
                   help="红队模式允许的最大影响级别："
                        "L1 证明可达 / L2 证明影响 / L3 完整利用")
    p.set_defaults(func=cmd_ledger)

    # diff
    p = sub.add_parser("diff", help="比对两次扫描结果")
    p.add_argument("--target", help="目标名称（自动查找最近两次扫描）")
    p.add_argument("--baseline", help="基线结果 JSON 路径")
    p.add_argument("--current", help="本次结果 JSON 路径")
    p.set_defaults(func=cmd_diff)

    # batch
    p = sub.add_parser("batch", help="按 targets.yaml 批量扫描（忽略周期，全扫）")
    p.add_argument("--profile", choices=["safe", "standard", "deep"], help="覆盖档位")
    p.add_argument("--mode", default=DEFAULT_MODE, choices=list(SCAN_MODES),
                   help=f"扫描模式（默认 {DEFAULT_MODE}，同 scan）")
    p.add_argument("--notify-test", dest="notify_test", action="store_true",
                   help="渲染飞书卡片但不真的发送（试发）")
    p.add_argument("--no-notify", dest="no_notify", action="store_true",
                   help="本次不发通知")
    p.add_argument("--targets", metavar="文件",
                   help="使用指定的目标清单（默认 <工具目录>/targets.yaml）")
    _add_resource_flags(p)   # batch：资源开关（低影响默认开）
    p.set_defaults(func=cmd_batch)

    # schedule
    p = sub.add_parser("schedule",
                       help="周期化调度：判定该谁跑（默认只看不跑），--run 执行")
    p.add_argument("--run", action="store_true",
                   help="执行到点的目标（不加则只打印判定与原因）")
    p.add_argument("--json", metavar="文件", help="把逐目标判定写入 JSON")
    p.add_argument("--profile", choices=["safe", "standard", "deep"], help="覆盖档位")
    p.add_argument("--mode", default=DEFAULT_MODE, choices=list(SCAN_MODES),
                   help=f"扫描模式（默认 {DEFAULT_MODE}）")
    p.add_argument("--notify-test", dest="notify_test", action="store_true",
                   help="渲染飞书卡片但不真的发送（试发）")
    p.add_argument("--no-notify", dest="no_notify", action="store_true",
                   help="本次不发通知")
    p.add_argument("--targets", metavar="文件",
                   help="使用指定的目标清单（默认 <工具目录>/targets.yaml）")
    _add_resource_flags(p)   # schedule：资源开关（低影响默认开）
    p.set_defaults(func=cmd_schedule)

    # coverage
    p = sub.add_parser("coverage", help="校验检查项与检测器的绑定覆盖率")
    p.add_argument("--strict", action="store_true", help="有缺口时以非零码退出")
    p.set_defaults(func=cmd_coverage)

    # selftest
    p = sub.add_parser("selftest", help="离线自测：验证「没测」不会被报成「通过」")
    p.add_argument("--verbose", action="store_true", help="打印逐项状态")
    p.add_argument("--report", metavar="目录", help="同时渲染一份报告到指定目录")
    _add_resource_flags(p)   # selftest：资源开关（低影响默认开）
    p.set_defaults(func=cmd_selftest)

    # creds
    p = sub.add_parser("creds",
                       help="索取与接收登录凭据（拿令牌的指引 + 本机凭据库）")
    p.add_argument("--target", help="目标域名（与 scan --target 保持一致）")
    p.add_argument("--login-url", "--url", dest="login_url", metavar="URL",
                   help="登录入口地址（未能自动推断时由你给出）")
    p.add_argument("--base-url", metavar="URL",
                   help="回验请求的基准地址（默认 https://<域名>）")
    p.add_argument("--set", metavar="角色",
                   help="把凭据写入该角色（默认从剪贴板读）")
    p.add_argument("--from-clipboard", action="store_true",
                   help="从剪贴板读取（默认行为，凭据不进命令历史）")
    p.add_argument("--file", metavar="路径", help="从文件读取凭据文本")
    p.add_argument("--stdin", action="store_true", help="从标准输入读取凭据文本")
    p.add_argument("--init", action="store_true",
                   help="生成凭据库骨架（占位，不含真实凭据）")
    p.add_argument("--force", action="store_true", help="配合 --init 覆盖已存在的文件")
    p.add_argument("--clear", nargs="?", const="*", metavar="角色",
                   help="清除凭据（不带角色=清空全部）")
    p.add_argument("--status", action="store_true", help="只看当前状态（默认行为）")
    p.add_argument("--verify", action="store_true",
                   help="回验凭据是否真的构成有效会话（会向目标发 2 个请求）")
    p.add_argument("--verify-path", metavar="路径",
                   help="回验用的「登录后才能访问」的页面，如 /api/whoami")
    p.add_argument("--profile", default="standard",
                   choices=["safe", "standard", "deep"], help="回验时使用的档位")
    p.add_argument("--skip-auth", action="store_true",
                   help="跳过授权闸门（仅限内部自测）")
    p.add_argument("--json", metavar="文件", help="把需求清单写入指定 JSON 文件")
    p.set_defaults(func=cmd_creds)

    # audit
    p = sub.add_parser("audit", help="检测器强度审计：查「没发请求却下结论」的项")
    p.add_argument("--json", help="把逐项审计结果写入指定 JSON 文件")
    p.set_defaults(func=cmd_audit)

    return parser


def _activate_resources(args: argparse.Namespace) -> None:
    """在任何扫描动作之前落实资源预算。**降优先级越早越好。**

    这一步的意义：把「扫描别把电脑拖垮」变成默认行为，而不是一个要记得加的开关。
    姿态（并发上限、子进程配额、优先级）会随 `ResourceBudget.notes` 一路进报告 ——
    静默降速与静默降级同罪，读者必须能看出这次跑在什么姿态下。
    """
    try:
        from engine import resources as res
    except Exception as e:  # noqa: BLE001
        print(f"⚠ 资源预算模块不可用（{type(e).__name__}: {e}），本次不做资源限制")
        return
    full = bool(getattr(args, "full_speed", False))
    forced_low = getattr(args, "low_impact", None)
    # --full-speed 必须穿透到 orchestrator：orchestrator 在阶段 0 会用 profile 重新
    # 算预算（resources.reconfigure 传 low_impact=None），届时只会看环境变量
    # AISCAN_LOW_IMPACT。不在这里落环境变量，--full-speed 就只改了全局 _BUDGET、
    #被 orchestrator 的 reconfigure 覆盖回低影响 —— 表现就是「加了 --full-speed
    # 还是慢」（红线 41：接线不一致会静默成功）。环境变量是 detect_budget 已支持的
    # 正式覆盖通道，参数优先级高于它，所以 --low-impact 仍能压回低影响。
    if full:
        os.environ[res.ENV_LOW_IMPACT] = "0"
    low = False if full else (True if forced_low else None)
    b = res.activate(low_impact=low, cpu_share=getattr(args, "cpu_share", None))
    # 走 stderr：stdout 保持机器可读（与 engine/progress.py 同一条纪律）。
    sys.stderr.write(f"[资源] {b.posture_line()}\n")
    sys.stderr.flush()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _activate_resources(args)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130
    except Exception as e:  # noqa: BLE001
        print(f"\n执行失败：{type(e).__name__}: {e}")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
