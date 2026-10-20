# -*- coding: utf-8 -*-
"""aiscan 全量回归入口
=======================
一条命令跑完所有自测与校验，输出单一的通过 / 不通过结论。

为什么要有这个文件：在此之前，「全量回归」是一串靠记忆手敲的命令。
漏跑其中一条不会有任何提示 —— 而漏掉的那条往往正是挡住假通过的那道闸。
把清单固化成代码，漏跑就变成不可能。

顺序有意为之（由内到外）：

  覆盖率校验 → 引擎自测（全量检查项 + 各条不变量）→ 报告闸门 →
  靶场标定（对照 ground_truth 算检出 / 漏报率）→ 红队链路 → 调度与通知 →
  检测器强度审计（查「没发请求却下结论」）→
  一串模块自测（wafgate / credguide / sessionctx / attackchain / credhunt /
  credosint / nuclei_map / progress / proofs / resources / nuclei_budget /
  openapi / sqlmap_probe）→ 同步工具自测 → 三个跨进程闭环（凭据索取、
  黑客视角凭据、前端产物汇聚）→ 三副本一致性与台账。

  「哪一环在第几位」不在这里写死 —— 手工维护的编号必然漂移，而漂移的文档
  比没有文档更坏（读者会以为自己漏跑了一环，或者以为某个环不存在）。
  要准确的清单请跑 `--list`，那是从 `_steps()` 直接生成的。

  模块自测这一串是历次盘查的产物，判据始终是同一条：
  **枚举所有含 `def _selftest(` 的模块，再看有没有真的调用点**
  （路径形态 `str(ROOT / "engine" / "x.py")`，或
  `from engine import x as _alias` + `_alias._selftest()`）。
  这些自测失效时都不报错 —— 整站同一响应判据失效会让适用性凭空放大且零提示；
  登录入口判据与指纹侧分叉会让报告自相矛盾；复现脚本内联片段有语法错误
  要到交付后才炸；sqlmap 调用层会静默外泄会话凭据；
  credosint 会把通用路径当成产品证据、把「检索被限流」写成「没有线索」。
  **模块自测写得再全，不进清单就等于没有。**
  新增模块时记得在这里加一行，否则又会长出新的「白写的自测」。

用法：
    python run_all_tests.py            # 跑全部
    python run_all_tests.py --fast     # 跳过最慢的引擎自测与靶场标定
    python run_all_tests.py --list     # 只看会跑哪些（权威清单）
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

# 三副本是否都在本机。run_all_tests 要能分发给同事单独跑，
# 那边没有兄弟副本，所以「三副本一致性」这一环必须可省略，而不是误报失败。
try:
    from sync_copies import COPIES as _COPIES
    _ALL_COPIES_HERE = all(p.exists() for p in _COPIES)
except Exception:  # noqa: BLE001
    _ALL_COPIES_HERE = False


def _steps(fast: bool) -> list[tuple[str, list[str], bool, str, str]]:
    """(名称, 命令, 是否慢, 通过标记, 运行标记)。

    两个标记分开是有意的：
      · 通过标记 —— 出现了才算这一环真的通过；
      · 运行标记 —— 出现了才证明它真的跑到了判定阶段。
    只看退出码会被「一个断言都没跑就返回 0」骗过去。
    """
    out: list[tuple[str, list[str], bool, str, str]] = [
        ("绑定覆盖率校验", [PY, str(ROOT / "validate_coverage.py"), "--strict"],
         False, "结果：通过", "检测器覆盖率校验"),
        ("引擎自测（全量检查项 + 不变量）", [PY, str(ROOT / "aiscan.py"), "selftest"],
         True, "自测通过", "逐项执行结果"),
        ("报告闸门自测", [PY, str(ROOT / "selftest_report_gate.py")],
         False, "全部通过", "断言"),
        ("靶场标定（检出/漏报率）", [PY, str(ROOT / "selftest_bench.py")],
         True, "靶场通过", "检出率"),
        ("红队链路自测", [PY, str(ROOT / "selftest_redteam.py")],
         False, "自测通过", "红队"),
        ("调度与通知自测", [PY, str(ROOT / "selftest_schedule.py")],
         False, "自测通过", "周期化"),
        ("检测器强度审计", [PY, str(ROOT / "audit_detectors.py")],
         False, "", "结论："),
        # 边界判定 / 拦截页归一化的纯函数自测。它守的是「整站同一响应」这条
        # 判据的**三个失效通道**（样本不足、状态码被打散、正文同码但无厂商
        # 特征）以及方向误杀（SPA 兜底页不得判成接管）。
        # 不进回归的后果很具体：这些断言只在你记得手敲时才跑，而它们一旦
        # 失效的表现是「适用性凭空放大、报告却零提示」，没有任何报错。
        ("边界判定模块自测（wafgate）",
         [PY, str(ROOT / "engine" / "wafgate.py")],
         False, "全部断言通过", "整站同一响应识别"),
        # 登录入口推断 / 凭据库读写 / 需求单生成。判据不得与 fingerprint 分叉 ——
        # 一处说「整站被接管」，另一处却推荐 https://目标/login，最难查。
        ("凭据指引模块自测（credguide）",
         [PY, str(ROOT / "engine" / "credguide.py")],
         False, "结果：全部通过", "凭据指引自测"),
        # 会话上下文：越权类复现脚本的内联片段（语法 + 与脚本头拼接后不得重复
        # 定义符号 + 凭据解析与哨兵过滤）。它原先**不在任何回归清单里** ——
        # 模块自测写得再全，没人跑就等于没有。而它的失效方式是静默的：
        # 内联片段有语法错误时，生成出来的复现脚本才报错，那时已经交付了。
        ("会话上下文模块自测（sessionctx）",
         [PY, str(ROOT / "verify" / "sessionctx.py")],
         False, "结果：全部通过", "会话上下文模块自测"),
        # 下面 5 个也是 2026-09-29 盘查出来的「写了但没人跑」——
        # 它们的 _selftest() 在代码里躺了不知道多久，任何回归入口都没调用过。
        # 一次确定性盘查（枚举所有含 `def _selftest(` 的模块，再看有没有
        # 真的调用点：路径形态 `str(ROOT / "engine" / "x.py")`，
        # 或 `from engine import x as _alias` + `_alias._selftest()`）找出来的。
        # 盘查脚本本身是临时的，但**结论固化在这里** —— 以后新增模块时，
        # 记得同步在这里加一行，否则又会长出新的「白写的自测」。
        ("攻击链模块自测（attackchain）",
         [PY, str(ROOT / "engine" / "attackchain.py")],
         False, "能力缺口回填只认真实测量", "复测入口"),
        # 链补证器：把「候选链 + 待确认清单」推进到「真的打一枪」。
        # 这一环守的是三类**不报错却让结论变味**的错：
        #   ① 把「前提条件」当「已获得能力」→ 组合出缺两环的纸面链；
        #   ② 缺环过多的链与可验证链混排 → 读者分不清哪条是打出来的；
        #   ③ 没有验证体的能力静默跳过 → 与「测了没问题」长得一样。
        ("链补证模块自测（chainclose）",
         [PY, str(ROOT / "engine" / "chainclose.py")],
         False, "链补证器自测：全部 9 组断言通过", "纸面推演链不派发"),
        ("凭据获取模块自测（credhunt）",
         [PY, str(ROOT / "engine" / "credhunt.py")],
         False, "凭据获取自测：通过", ""),
        # 凭据情报（credosint）：红队的第三条路 —— 自己上网找登录凭据。
        # 这一环守的是两类**不报错却让结论变味**的错：
        #   ① 拿通用路径（如 /login）当产品证据 → 会拿 A 产品的默认口令去打 B，
        #      几次失败登录留在对方日志里，还消耗掉本就极少的尝试配额；
        #   ② 把「检索被限流 / 解析失败」写成「没找到线索」→ 读者会以为
        #      公开渠道已经查干净了。
        # 全程离线（假 fetcher），不发任何真实网络请求。
        #
        # 运行标记用「第 ⑳ 组」= 自测最后一组的登记行：它出现才说明这一环
        # 真的跑到了结尾，而不是中途提前 return 却带着退出码 0 返回。
        # （这一环第一次登记时运行标记写的是「产品识别」，而模块当时压根不打印
        #   分组进度 —— 结果首跑就报「未见『产品识别』」。这件事本身就是个提醒：
        #   标记必须对着模块的真实输出写，不能对着「我以为它会打印什么」写。）
        ("凭据情报模块自测（credosint）",
         [PY, str(ROOT / "engine" / "credosint.py")],
         False, "凭据情报自测：通过", "第 ⑳ 组"),
        ("nuclei 归口模块自测（nuclei_map）",
         [PY, str(ROOT / "engine" / "nuclei_map.py")],
         False, "组断言通过", "归口表覆盖"),
        ("进度显示模块自测（progress）",
         [PY, str(ROOT / "engine" / "progress.py")],
         False, "进度显示自测：通过", ""),
        ("利用证明模块自测（proofs）",
         [PY, str(ROOT / "engine" / "proofs.py")],
         False, "未能验证", "命令执行"),
        # 同步工具自身的两道闸：台账并集语义 + 方向守卫判据。
        # 纯临时目录自测，任何机器都能跑。守卫判据错了的后果是「每次同步都被拦」，
        # 人就会把它关掉 —— 那比没有守卫更糟，所以它必须被回归天天看着。
        ("同步工具自测（台账并集 + 方向守卫）",
         [PY, str(ROOT / "sync_copies.py"), "--self-test"],
         False, "结果：通过", "同步方向守卫自测"),
        # 凭据闭环：跨进程起本地假应用，验证「指引 → 写库 → 回验」真的连通。
        # 放在这里是因为它是最外一环 —— 前面几环测的是「模块能算对」，
        # 这一环测的是「接线没断」。
        ("凭据索取闭环",
         [PY, str(ROOT / "selftest_creds.py")],
         False, "凭据闭环自测通过", "授权闸门"),
        # 黑客视角凭据获取（credhunt）：与上一环互为镜像 —— 上一环测「运维给的凭据
        # 能不能用」，这一环测「一个凭据都没有时能不能自己进场」。
        # 它守的是一类会**静默消失**的发现：默认口令试出来了，却因为复现模板选错
        # （没有可注入参数 → 判「未复现」）被准入闸门踢出漏洞清单，报告上只剩
        # 一句「未复现」—— 真实存在的高危发现凭空蒸发，且没有任何报错。
        # 这一环整条打通：零凭据试出默认口令 → 产出发现 → 生成复现脚本 → 真跑一遍。
        ("黑客视角凭据获取（默认口令 → 复现闭环）",
         [PY, str(ROOT / "selftest_credhunt.py")],
         False, "全部通过", "命中与发现产出"),
        # 红队自取注册（regself）：取号决策链第 1 条 —— 目标有开放注册就
        # 自己建测试号，不再依赖业务方给账号。它守的三类坑全部实测过：
        #   ① 环境代理在 keep-alive 复用连接上错误路由第二个请求 →
        #      「注册成功」「登录未下发令牌」两层假象同源（trust_env 纪律）；
        #   ② 令牌正文被截断 → 闭合引号被切掉 → 真登录被误判失败；
        #   ③ 表单字段名（email/pass）没记录 → 会话池合成登录发默认
        #      username/password → 号是好的也被判「未下发会话凭据」。
        # 同时钉住两把锁（deep 档 + 台账写授权）、幂等（季度扫描不刷号）、
        # 失败具名（能力缺口不静默）、口令零泄漏。
        ("红队自取注册（开放注册自建测试身份）",
         [PY, str(ROOT / "selftest_regself.py")],
         False, "全部通过", "门控与两型登录"),
        # 深度验证四项（2026-10-10，由 Strix 实战结果倒逼）：把四个「原本只能人工」
        # 的能力压成可自动确证 —— ① JWT 伪造回验（原来只做静态结构分析，
        # 「疑似」冒充「证明」）；② 批量赋值（注册接口注入特权字段）；
        # ③ 存储型 XSS（受控写 + 读回 + 编码比对）；④ 水平越权（两个登录态互读对象）。
        # 每一项都配**漏洞实现 / 安全实现**两台假应用做反向对照：安全模式下不许报。
        ("深度验证四项（伪造回验/批量赋值/存储XSS/水平越权）",
         [PY, str(ROOT / "selftest_deep4.py")],
         False, "全部通过", "伪造回验：三路对照"),
        # 前端产物汇聚：起一个本地假 SPA，验证「采集阶段拿不到素材时，
        # 渲染 DOM / modulepreload / 动态分包这几条腿能不能把素材补齐」，
        # 并反向钉住「没素材时必须如实报降级，不得因兜底探测过了就假装有素材」。
        # 素材判据一旦走偏，17 项依赖前端产物的检查会集体假「未执行」或假「通过」。
        ("前端产物汇聚",
         [PY, str(ROOT / "selftest_frontend.py")],
         False, "前端汇聚自测通过", "[7] 前置条件闸门"),
        # 前端产物里的**接口字面量**：接口文档可能是假的（实测 Juice Shop v20
        # 的 `/api-docs` 挂的是只有 `/b2b/v2/orders` 一个接口的 B2B 规范，
        # 与真实接口面零重合），这一路是「接口清单」最后的、也最可信的来源。
        # 它失效时**没有报错**，只表现为枚举数少一截，看不出是哪一环空的。
        ("SPA 前端产物接口提取",
         [PY, str(ROOT / "engine" / "spa.py")],
         False, "SPA 自测通过", "前缀拼接形态"),
        # 浏览器渲染：守的是**整段失明**这条连锁故障（第 22 轮实测：
        # 首选浏览器无 DOM → 记坏名单；回退浏览器冷启动超时 → 直接放弃，
        # 于是 17 个依赖渲染 DOM 的检查项集体 N/A，基准 57.5% → 41.2%）。
        # 自测用注入的 runner 覆盖「超时重试 / 无 DOM 不重试 / 浏览器不存在」
        # 三条分支，任何一条退化都不会报错，只会表现为覆盖率少一截。
        ("浏览器渲染回退与重试",
         [PY, str(ROOT / "engine" / "render.py")],
         False, "渲染模块自测：通过", "首次超时后"),
        # 资源预算：守的是「跑扫描把整台电脑吃满」这个真实故障。
        # 它盯的四条都是**静默失效**型的：
        #   ① HANDLE 未声明 argtypes → SetPriorityClass 返回 0 但 Python 不报错，
        #      「降优先级」变成一个空操作；
        #   ② 只降父进程不降子进程 → 吃 CPU 的多半是子进程，降了等于没降；
        #   ③ 子进程没带 GOMAXPROCS / GOMEMLIMIT → nuclei 按全部逻辑核跑、堆无上限；
        #   ④ 并发没有取「档位声明」与「本机预算」的更小者 → 档位写 20 就真开 20。
        # 这四条任何一条失效都不会有报错，只会表现为「优化了但没效果」。
        ("资源预算模块自测（resources）",
         [PY, str(ROOT / "engine" / "resources.py")],
         False, "资源预算自测：通过", "运行姿态"),
        ("nuclei 预算与并发封顶自测（nuclei_budget）",
         [PY, str(ROOT / "engine" / "nuclei_budget.py")],
         False, "nuclei 预算自测通过", "不超档位声明"),
        # 接口文档（OpenAPI / Swagger）：把「文档能打开」变成「按文档把接口摸出来」。
        # 它守的是本项目最容易犯的那类错 —— **把「解不开」写成「没有接口」**：
        # 三种状态（未发现 / 找到但未解析 / 已解析）必须互斥且各有原因，
        # 写方法不得进只读枚举，模板变量必须具体化（否则枚举出来全是 404）。
        ("接口文档模块自测（openapi）",
         [PY, str(ROOT / "engine" / "openapi.py")],
         False, "接口文档模块自测：通过", "可只读枚举"),
        # sqlmap 调用层：本工具风险最高的一个外部依赖。
        # engine/sqlmap_probe.py 的约束原先只靠 selftest_engine 的不变量⑲看着，
        # 而那一层测不到三件事：
        #   ① 假执行体路径与真实子进程路径的判定分叉 —— 两条路径原先各写一份
        #      「命中 / 未命中 / 没得出结论」的措辞，自测看到的结论与生产不同；
        #   ② 复现命令里的凭据 —— cmd_preview 会进 reproduction / evidence，
        #      最终落到要交给运维的报告与复现脚本里，带认证的目标下
        #      它原来带着真实会话 Cookie 原文；
        #   ③ 档位门控被自测执行体短路（安全档的「绝不调用」有旁路）。
        # 这三条失效时都不会报错：第一条让报告措辞失真，第二条让凭据静默外泄，
        # 第三条让「最低干扰」的承诺失效。所以必须有独立的一环钉住。
        ("sqlmap 调用层自测（白名单 / 档位 / 凭据遮盖）",
         [PY, str(ROOT / "engine" / "sqlmap_probe.py")],
         False, "sqlmap 调用层自测：通过", "凭据以"),
        # 外部工具定位。原先三处各写死一份 `C:/Users/<用户名>/...` 绝对路径 ——
        # 本机没问题，但工具链是要被拷到**另一台电脑**上跑的，那边用户名不同
        # 就会一个候选都命中不了：工具被判「未安装」，而报告上只看得出
        # 「未安装」，看不出其实是路径没找对（跟「目标没问题」长得一样）。
        # 这一环还钉住「等 stdin 的工具不得被误判为不可用」——
        # pip 版 sqlmap 的 `--version` 会等回车，探测不关 stdin 就挂到超时。
        ("外部工具定位自测（binlocate / 换机可用性）",
         [PY, str(ROOT / "selftest_binlocate.py")],
         False, "全部通过", "换台电脑"),
        # 全局硬约束（config/profiles.yaml 的 hard_limits + 档位里的 rate 子项）
        # 的执行体。这一环守的是本项目最隐蔽的一类缺陷 —— **配了却没人读**：
        #   · per_host_rps / delay_between_items_ms / rate_ceiling_rps / stop_on
        #     长期在代码里零读取点，而 yaml 的措辞让操作者以为有兜底。
        # 它比「字段缺失」更危险：缺失时人会去确认，虚假保证会让人放心。
        # 断言里既有正向（真的生效）也有反向（未触发时不得留痕 / 不得放假告警），
        # 少一半就等于把「配了却没人读」换个形式再犯一次。
        ("全局硬约束执行体自测（rate_ceiling / per_host_rps / item_gap / stop_on）",
         [PY, str(ROOT / "selftest_hardlimits.py")],
         False, "全部通过", "不得写进 boundary_block"),
        # 外部靶场（Juice Shop）能力映射的自洽检验。
        # 这一环守的不是「能不能检」，而是**答案表会不会漂**：
        #   · 官方 challenges.yml 换了版本、增删了挑战 → 判定表必须要么补要么报错，
        #     不许静默少算几条（少一条分母就小一分，召回率虚高，且看不出来）；
        #   · 判定表里写了清单中不存在的检查项 id → 那条永远匹配不上产出，
        #     会被算成「引擎漏报」，把**我们自己的笔误**报成别人的能力缺陷；
        #   · 某条判定没写依据 → 那就是拍脑袋，不允许进答案表。
        # 注意它输出的是**静态能力上界**，不是实测检出率 —— 两者不能混叫，
        # 混叫就是把「理论上碰得到」说成「已经扫出来了」。
        ("Juice Shop 能力映射自洽（答案表 / 归口 id / 依据齐备）",
         [PY, str(ROOT / "bench" / "juice_report.py")],
         False, "静态能力映射", "黑盒量程之内"),
    ]
    if _ALL_COPIES_HERE:
        # 只有三处目录都在本机时才有意义。--check 是只读的，不写入任何东西。
        out.append(("三副本一致性与台账",
                    [PY, str(ROOT / "sync_copies.py"), "--check"],
                    False, "内容与台账均一致", "授权台账"))
    if fast:
        out = [s for s in out if not s[2]]
    return out


def _grade(stdout: str, rc: int, want: str, ran_mark: str) -> tuple[bool, str]:
    """除退出码外的额外判据。"""
    if rc != 0:
        return False, f"退出码 {rc}"
    if ran_mark and ran_mark not in stdout:
        return False, f"未见「{ran_mark}」—— 可能未跑到判定阶段"
    if want and want not in stdout:
        return False, f"未见「{want}」—— 可能一个断言都没跑"
    return True, ""


def main() -> int:
    # 逐行刷新：这一环要跑好几分钟，输出攒到最后才吐会让人以为它卡住了。
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:  # noqa: BLE001
        pass

    ap = argparse.ArgumentParser(description="aiscan 全量回归")
    ap.add_argument("--fast", action="store_true", help="跳过慢步骤")
    ap.add_argument("--list", action="store_true", help="只列出步骤")
    ap.add_argument("--full-speed", action="store_true",
                    help="不降回归自身的进程优先级、也不给子进程设资源限额。"
                         "默认是低影响：回归要跑十几分钟，那段时间你要能继续用电脑")
    args = ap.parse_args()

    # 回归自身先降优先级，再让每一环继承低影响设置。
    # 这一步很有必要：回归峰值就在引擎自测与靶场标定两环（各 2 分多钟），
    # 那两环会起本地假应用 + 跑 nuclei + 渲染，是「电脑卡住」的主要时段。
    # 注意 posture_line() 自带「运行姿态：」前缀，这里不要再拼一次。
    if not args.full_speed:
        try:
            from engine import resources as _res
            b = _res.activate(low_impact=True)
            low_note = b.posture_line()
        except Exception as e:  # noqa: BLE001
            low_note = f"运行姿态：资源预算不可用（{type(e).__name__}）"
    else:
        low_note = "运行姿态：全速（不降优先级、不限子进程资源）"
    print(low_note)
    print()

    steps = _steps(args.fast)
    if args.list:
        for i, (name, cmd, slow, _want, _ran) in enumerate(steps, 1):
            print(f"{i}. {name}{'（慢）' if slow else ''}\n   {' '.join(cmd)}")
        return 0

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    # 每一环都继承低影响设置（除非显式要全速）。显式写进子环境而不是指望
    # 子进程自己去读配置：子进程读的是同一份 profiles.yaml，但自测里很多
    # 环节根本不加载档位，只靠 profiles 会漏掉一大半。
    if not args.full_speed:
        env["AISCAN_LOW_IMPACT"] = "1"
    else:
        env["AISCAN_LOW_IMPACT"] = "0"
    # 回归时不得把通知真的发出去 —— 否则每次跑测试都会给全员群发卡片。
    env.pop("AISCAN_FEISHU_WEBHOOK", None)
    env.pop("AISCAN_FEISHU_SECRET", None)

    results: list[tuple[str, bool, str, float]] = []
    t_all = time.time()
    # 每环的完整输出必须落盘。只打印末 12 行的后果是：某环偶发失败时，
    # 它的问题清单（诊断信息）直接丢掉 —— 复现不出来的失败就成了死案。
    # 本目录在 sync_copies 的 SKIP_DIRS 里，不会被同步带走。
    log_dir = ROOT / "outputs" / "_回归日志"
    log_dir.mkdir(parents=True, exist_ok=True)
    for name, cmd, _slow, want, ran_mark in steps:
        print("=" * 74)
        print(f"▶ {name}")
        print("=" * 74)
        t0 = time.time()
        safe = "".join(c if c not in '\\/:*?"<>|' else "_" for c in name)
        log_path = log_dir / f"{safe}.log"
        try:
            # 每一环的子进程也降优先级：直接跑的 selftest_*.py 不会自己调
            # resources（只有走 aiscan.py 的才会），不在这里降就会出现
            # 「父进程在让路、子进程在抢 CPU」，降了等于没降。
            kw: dict[str, object] = {}
            if not args.full_speed:
                try:
                    from engine import resources as _res
                    # 在**已剔除敏感项**的 env 上叠加限额，而不是让 resources
                    # 从 os.environ 重建一份 —— 后者会把上面删掉的飞书 webhook
                    # 原样带回来，每次回归都会真的给全员群发卡片。
                    _res.apply_child_limits(env)
                    flags = _res.child_creationflags()
                    if flags:
                        kw["creationflags"] = flags
                except Exception:  # noqa: BLE001
                    pass
            p = subprocess.run(cmd, cwd=str(ROOT), env=env, timeout=1800,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", **kw)
            out, err, rc = p.stdout or "", p.stderr or "", p.returncode
        except subprocess.TimeoutExpired:
            out, err, rc = "", "超时（1800s）", 124
        dt = time.time() - t0
        # 落盘放在判定之前：就算程序中途崩了，日志也已经在。
        try:
            log_path.write_text(
                f"# {name}\n# 命令：{' '.join(cmd)}\n# 退出码：{rc}　用时：{dt:.1f}s\n"
                f"\n===== stdout =====\n{out}\n\n===== stderr =====\n{err}\n",
                encoding="utf-8")
        except OSError as e:  # noqa: BLE001
            print(f"⚠ 回归日志落盘失败（不影响判定）：{e}")
        tail = [x for x in (out or "").strip().splitlines() if x.strip()]
        print("\n".join(tail[-12:]) if tail else "（无输出）")
        if err.strip():
            print("stderr：")
            print("\n".join(err.strip().splitlines()[-6:]))
        ok, why = _grade(out, rc, want, ran_mark)
        results.append((name, ok, why, dt))
        print(f"\n{'✓ 通过' if ok else '✗ 不通过'}"
              f"{('（' + why + '）') if why else ''}　用时 {dt:.1f}s")
        if not ok:
            # 失败时必须指出去哪看完整输出 —— 只留一句「退出码 1」没法排查。
            print(f"  完整输出已留存：{log_path}")
        print()

    print("=" * 74)
    print("回归结果汇总")
    print("=" * 74)
    for name, ok, why, dt in results:
        print(f"  {'✓' if ok else '✗'} {name:<28} {dt:>7.1f}s"
              + (f"  ← {why}" if why else ""))
    bad = [r for r in results if not r[1]]
    print()
    if bad:
        print(f"结果：不通过（{len(bad)}/{len(results)} 环失败，"
              f"总用时 {time.time() - t_all:.1f}s）")
        for name, _ok, why, _dt in bad:
            print(f"  ✗ {name}：{why}")
        return 1
    print(f"结果：全部通过（{len(results)} 环，总用时 {time.time() - t_all:.1f}s）")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
