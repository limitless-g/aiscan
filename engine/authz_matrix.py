# -*- coding: utf-8 -*-
"""
权限矩阵验证（扫描器盲区专项）
==============================
职责：用多个测试账号对同一批接口发起只读请求，横向比对响应，识别「越权」。

为什么单列而不混入扫描结果：
  任何自动化扫描器都扫不出越权 —— 越权不是「某个请求有恶意参数」，而是
  「A 的凭据能读到 B 的数据」这个语义事实。它必须靠多账号交叉比对才能发现，
  且需要理解哪些数据本不该被 A 看到。

安全约束（硬性，不可绕过）：
  1. 只使用授权书里登记的测试账号，账号必须属于本系统且为专用测试账号
  2. 只发只读请求（GET/HEAD），绝不执行写操作
  3. 不遍历 ID 区间 —— 只做有限采样（默认 5 个），避免演变为数据爬取
  4. 采样到的他人数据一律脱敏，报告中不出现真实业务数据
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Evidence, Finding  # noqa: E402
from verify.mask import Masker  # noqa: E402

# 响应中用于判断「是否拿到真实数据」的信号
DATA_SIGNALS = [
    ("json_object", re.compile(r'^\s*[\{\[]')),
    ("has_id_field", re.compile(r'"(?:id|userId|orderId|uid|customerId)"\s*:', re.I)),
    ("has_pii_field", re.compile(r'"(?:phone|mobile|idcard|email|address|realName|name)"\s*:', re.I)),
    ("has_money_field", re.compile(r'"(?:amount|price|total|balance|payment)"\s*:', re.I)),
    ("non_empty_array", re.compile(r'^\s*\[\s*\{')),
]

# 明确的拒绝信号（说明鉴权生效）
DENY_SIGNALS = [
    (401, "未认证"),
    (403, "无权限"),
]


@dataclass
class Account:
    """一个测试账号。凭据仅存于内存，不落盘。"""

    name: str
    role: str = "user"                 # 角色标识，如 user / vip / admin / tenant_a
    tenant: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    authorized: bool = False           # 必须在授权台账中登记为测试账号
    login: dict[str, Any] = field(default_factory=dict)   # 自动登录配置（凭据走环境变量）
    # 回验会话用哪个页面。**必须是「登录后才能访问」的页面**：拿站点首页回验
    # 是无效的 —— 首页通常对游客也返回 200，「带 Cookie 访问首页没被弹回」
    # 既不能证明会话有效，也不能证明无效。
    verify_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        # 凭据绝不出现在任何输出中
        return {
            "name": self.name, "role": self.role, "tenant": self.tenant,
            "authorized": self.authorized,
            "has_credentials": bool(self.headers or self.cookies),
        }

    def to_pool_dict(self) -> dict[str, Any]:
        """会话池专用：**带凭据**的账号记录，仅供内存中构造会话。

        为什么不能用 to_dict()：它是给报告用的，刻意剥离了凭据（只留
        has_credentials 布尔）。会话池若拿它当输入，每个账号都会被判成
        「没有任何凭据」而拒收 —— 越权检测会整体静默失效，
        而且表现为「账号配置无效」这种看起来合理的原因，极难察觉。

        两个方法必须分开：**能进报告的** 与 **能构造请求的** 是两份不同的数据。
        本方法的返回值只允许在内存中传递，不得写入任何文件 / 日志 / 报告。
        """
        return {
            "name": self.name, "role": self.role, "tenant": self.tenant,
            "authorized": self.authorized,
            "headers": dict(self.headers), "cookies": dict(self.cookies),
            "login": dict(self.login), "verify_path": self.verify_path,
        }


@dataclass
class EndpointProbe:
    """单个接口在多个账号下的响应快照。"""

    url: str
    method: str = "GET"
    per_account: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "method": self.method, "per_account": self.per_account}


def _as_account(obj: Any) -> Account:
    """把 Account 或会话池账号 dict 归一成 Account。

    为什么需要这个：权限矩阵有两个调用方 —— 阶段 8 传的是
    `load_accounts()` 产出的 Account 对象；「凭据就位后补跑」传的是
    会话池的账号 dict（`SessionPool.accounts: list[dict]`，字段名与
    Account 一致，登录后的活会话凭据就在 headers/cookies 里）。

    第 29 轮实测：补跑直接把 dict 传进 `verify_endpoints`，
    `acc.authorized` 抛 AttributeError，被 orchestrator 的 except
    吞掉并打成一句「异常（已捕获，未中断）」—— 终端此前刚打印过
    「凭据就位后自动补跑（无需人工重扫）」，矩阵其实一次都没跑。
    「说了会做、其实没做」正是红线 41 的静默成功，所以在入口归一化，
    让两种来源走同一条路。
    """
    if isinstance(obj, Account):
        return obj
    if isinstance(obj, dict):
        return Account(
            name=str(obj.get("name") or ""),
            role=str(obj.get("role") or "user"),
            tenant=str(obj.get("tenant") or ""),
            headers=dict(obj.get("headers") or {}),
            cookies=dict(obj.get("cookies") or {}),
            authorized=bool(obj.get("authorized", False)),
            login=dict(obj.get("login") or {}),
            verify_path=str(obj.get("verify_path") or ""),
        )
    raise TypeError(f"无法归一化账号对象：{type(obj).__name__}")


class AuthzMatrix:
    """多账号权限矩阵比对。"""

    def __init__(self, client: Any, accounts: list[Any], sample_limit: int = 5):
        self.client = client
        # 入口归一化：Account 对象与会话池 dict 都收（见 _as_account）。
        # 字典形式来自凭据库 / 会话池（creds --set、regself 自建），
        # 它们登录后把活会话凭据放在 headers/cookies 里，必须原样带进矩阵。
        self.accounts = [_as_account(a) for a in (accounts or [])]
        self.sample_limit = sample_limit
        self.masker = Masker("internal")

    # ------------------------------------------------------------------
    def verify_endpoints(self, endpoints: list[str]) -> list[EndpointProbe]:
        """对一组接口做多账号只读采样。"""
        out: list[EndpointProbe] = []
        for url in endpoints[: self.sample_limit]:
            ep = EndpointProbe(url=url)
            for acc in self.accounts:
                if not acc.authorized:
                    ep.per_account[acc.name] = {
                        "error": "账号未在授权台账登记为测试账号，跳过"
                    }
                    continue
                ep.per_account[acc.name] = self._probe_with(acc, url)
            out.append(ep)
        return out

    def _probe_with(self, acc: Account, url: str) -> dict[str, Any]:
        """带指定账号凭据的只读请求。"""
        import requests

        rec: dict[str, Any] = {}
        try:
            resp = requests.get(
                url,
                headers={**self.client.session.headers, **acc.headers},
                cookies=acc.cookies,
                timeout=self.client.timeout,
                verify=False,
                allow_redirects=True,
            )
            body = resp.text[:50_000] if resp.text else ""
            rec["status"] = resp.status_code
            rec["length"] = len(body)
            rec["_body"] = body
            rec["signals"] = [n for n, p in DATA_SIGNALS if p.search(body)]
            rec["content_type"] = resp.headers.get("Content-Type", "")
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {str(e)[:120]}"
        return rec

    # ------------------------------------------------------------------
    def analyze(self, probes: list[EndpointProbe], target: str) -> list[Finding]:
        """从矩阵中推断越权结论。"""
        findings: list[Finding] = []
        roles = {a.name: a.role for a in self.accounts}
        tenants = {a.name: a.tenant for a in self.accounts}

        for ep in probes:
            ok = {k: v for k, v in ep.per_account.items() if "status" in v}
            if len(ok) < 2:
                continue

            f = self._check_anonymous_access(ep, ok, target)
            if f:
                findings.append(f)
                continue

            f = self._check_cross_tenant(ep, ok, tenants, target)
            if f:
                findings.append(f)
                continue

            f = self._check_horizontal(ep, ok, roles, target)
            if f:
                findings.append(f)
        return findings

    # --- 未授权访问：无凭据账号也拿到了数据 ---
    def _check_anonymous_access(self, ep: EndpointProbe, ok: dict, target: str) -> Finding | None:
        anon = next((k for k in ok if "anon" in k.lower() or "未登录" in k or "游客" in k), None)
        if not anon:
            return None
        rec = ok[anon]
        if rec["status"] != 200 or not rec["signals"]:
            return None
        other = [k for k in ok if k != anon and ok[k]["status"] == 200]
        if not other:
            return None
        return self._mk_finding(
            ep, target,
            title="接口缺少鉴权：未认证身份可读取数据",
            sev="高危",
            basis=(
                f"账号「{anon}」不含任何认证凭据，实测返回 200 且响应含数据结构，"
                f"与已认证账号「{other[0]}」返回同类内容"
            ),
            desc="该接口没有校验身份，未登录的访客直接请求就能拿到数据。",
            impact=(
                "任何能访问公网的人都可以批量拉取该接口的数据，无需注册或登录。"
                "若接口支持 ID 参数，影响面可扩展至全量数据。"
            ),
            detail=f"未认证账号 {anon} 状态码 {rec['status']}，"
                   f"命中数据特征 {rec['signals']}，响应长度 {rec['length']}",
            level="A",
        )

    # --- 垂直/水平越权：低权账号读到本不该读的数据 ---
    def _check_cross_tenant(self, ep: EndpointProbe, ok: dict, tenants: dict, target: str) -> Finding | None:
        """跨租户：A 租户账号读到 B 租户数据。"""
        by_tenant: dict[str, list[str]] = {}
        for name, t in tenants.items():
            if name in ok and t:
                by_tenant.setdefault(t, []).append(name)
        if len(by_tenant) < 2:
            return None

        # 检查是否所有租户拿到相同的数据标识（说明未做租户隔离）
        ids = {}
        for t, members in by_tenant.items():
            for m in members:
                rec = ok.get(m, {})
                body = rec.get("_body", "")
                found = re.findall(r'"(?:id|orderId|userId)"\s*:\s*"?(\w+)"?', body)
                if found:
                    ids[t] = sorted(set(found))[:5]
        if len(ids) < 2:
            return None
        vals = list(ids.values())
        if not all(v == vals[0] for v in vals[1:]):
            return None
        return self._mk_finding(
            ep, target,
            title="租户隔离缺失：不同租户账号读到相同数据",
            sev="严重",
            basis=(
                f"实测租户 {list(ids.keys())[0]} 与 {list(ids.keys())[1]} 的账号请求同一接口，"
                f"返回的数据标识完全一致（{vals[0][:3]}），说明服务端未按租户过滤"
            ),
            desc="接口没有按租户隔离数据，不同客户的账号请求同一地址会拿到同样的内容。",
            impact=(
                "跨租户数据泄露。任一客户账号可读取其他客户的数据，"
                "属于最严重级别的越权，通常直接构成数据安全事件。"
            ),
            detail=f"各租户命中标识：{json.dumps(ids, ensure_ascii=False)}",
            level="A",
        )

    # --- 水平越权：同角色不同用户之间 ---
    def _check_horizontal(self, ep: EndpointProbe, ok: dict, roles: dict, target: str) -> Finding | None:
        """同角色账号之间本应隔离，若响应一致则疑似未做归属校验。"""
        same_role: dict[str, list[str]] = {}
        for name, r in roles.items():
            if name in ok:
                same_role.setdefault(r, []).append(name)
        for role, members in same_role.items():
            if len(members) < 2:
                continue
            recs = [(m, ok[m]) for m in members]
            if not all(r["status"] == 200 for _, r in recs):
                continue
            bodies = [r.get("_body", "") for _, r in recs]
            if not all(b == bodies[0] for b in bodies[1:]):
                continue
            if not any(re.search(r'"(?:id|userId|orderId)"', b) for b in bodies):
                continue
            return self._mk_finding(
                ep, target,
                title="疑似水平越权：同角色账号返回完全相同的个人数据",
                sev="高危",
                basis=(
                    f"实测 {len(members)} 个同为「{role}」角色的账号请求同一接口，"
                    "响应内容逐字节相同且均含个人数据标识，"
                    "高度suspect服务端未按当前用户过滤数据归属"
                ),
                desc="同一个角色的不同用户请求同一地址，返回了完全相同的数据。正常情况下每个人的数据应该不同。",
                impact=(
                    "若确认为越权，任一用户可读取其他用户的数据。"
                    "因采样有限，本条须人工确认后再最终定级。"
                ),
                detail=f"同角色账号：{', '.join(members)}；响应长度一致：{[ok[m]['length'] for m in members]}",
                level="B",  # 采样推断，未经人工确认，上限中危
                confidence="Medium",
            )

    # ------------------------------------------------------------------
    def _mk_finding(
        self, ep: EndpointProbe, target: str, *, title: str, sev: str, basis: str,
        desc: str, impact: str, detail: str, level: str = "B", confidence: str = "High",
    ) -> Finding:
        masked_detail = self.masker.mask(detail)
        return Finding(
            item_id="WSTG-ATHZ-02",
            title=title,
            target=target,
            endpoint=ep.url,
            method="GET",
            severity=sev,
            confidence=confidence,
            evidence_level=level,
            grading_basis=basis,
            description=desc,
            technical_detail=masked_detail,
            impact=impact,
            reproduction=(
                f"1. 用两个不同账号分别获取各自凭据\n"
                f"2. 携带各自凭据请求 {ep.url}\n"
                f"3. 比对两者返回的状态码与响应体\n"
                f"4. 若低权账号拿到高权/他人的数据，即为越权"
            ),
            remediation=(
                "1. 在服务端对每个请求做数据归属校验：查询条件强制附带当前用户 / 租户 ID\n"
                "2. 不要依赖前端传入的 userId 参数决定查询范围\n"
                "3. 建立统一的鉴权中间件，避免逐接口手写校验导致遗漏\n"
                "4. 补充针对越权的自动化回归测试（多账号矩阵）"
            ),
            compliance="等保2.0 安全计算环境-访问控制 / OWASP API1:2023 BOLA / ISO 27001 A.8.3",
            evidence=[Evidence(
                kind="response", content=masked_detail,
                note="多账号响应比对（已脱敏）", masked=True,
                raw_hash=Masker.fingerprint(detail),
            )],
            source_tool="authz_matrix",
            extra={"accounts": list(ep.per_account.keys())},
        )


def load_accounts(config_path: Path | str) -> list[Account]:
    """从配置文件加载测试账号。凭据字段支持环境变量引用，避免明文落盘。

    配置文件格式（targets.yaml 的 accounts 段，或独立文件）：
        accounts:
          - name: user_a
            role: user
            tenant: tenant_a
            authorized: true
            headers:
              Authorization: "Bearer ${ENV:USER_A_TOKEN}"
            # 或者交给扫描器自动登录（凭据只能是环境变量引用）
            login:
              url: /api/login
              method: POST
              username_env: USER_A_NAME
              password_env: USER_A_PASS
            # 回验会话用哪个页面 —— 必须是「登录后才能访问」的页面。
            # 不填则退化为站点首页，而首页对游客也返回 200，
            # 那种情况下登录态只能判「未验证」（不是「已登录」）。
            verify_path: /api/whoami
    """
    import os

    p = Path(config_path)
    if not p.exists():
        return []
    import yaml

    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    raw_list = data.get("accounts", []) if isinstance(data, dict) else []

    def resolve(v: str) -> str:
        m = re.match(r"^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$", str(v))
        return os.environ.get(m.group(1), "") if m else str(v)

    def resolve_tree(node: Any) -> Any:
        """递归解析配置树里的 ${ENV:...} 引用（login 块是嵌套结构）。"""
        if isinstance(node, dict):
            return {k: resolve_tree(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve_tree(v) for v in node]
        if isinstance(node, str):
            return resolve(node)
        return node

    out: list[Account] = []
    for rec in raw_list:
        out.append(Account(
            name=rec.get("name", "unnamed"),
            role=rec.get("role", "user"),
            tenant=rec.get("tenant", ""),
            headers={k: resolve(v) for k, v in (rec.get("headers") or {}).items()},
            cookies={k: resolve(v) for k, v in (rec.get("cookies") or {}).items()},
            authorized=bool(rec.get("authorized", False)),
            login=resolve_tree(rec.get("login") or {}),
            verify_path=str(rec.get("verify_path") or ""),
        ))
    return out


def check_anonymous_access(client: Any, endpoints: list[str], target: str) -> list[Finding]:
    """无账号版本的最小检查：仅测试「不带任何凭据能否拿到数据」。

    这是最保守也是最高价值的越权检查 —— 不需要任何测试账号即可执行。
    """
    matrix = AuthzMatrix(client, accounts=[])
    findings: list[Finding] = []
    for url in endpoints:
        try:
            resp = client.fetch(url)
        except Exception:  # noqa: BLE001
            continue
        if not resp.reachable or resp.status != 200:
            continue
        body = resp.body_snippet
        signals = [n for n, p in DATA_SIGNALS if p.search(body)]
        if not signals:
            continue
        # 排除公共可读页面（HTML 页面不算越权）
        if "text/html" in resp.headers.get("Content-Type", "").lower():
            continue
        findings.append(matrix._mk_finding(
            EndpointProbe(url=url, per_account={"anon": {"status": 200, "length": len(body)}}),
            target,
            title="疑似未授权数据接口：无需认证即可访问",
            sev="中危",
            basis=(
                f"实测不带任何凭据请求返回 200，Content-Type 为 "
                f"{resp.headers.get('Content-Type', '未知')}，响应含数据结构特征 {signals}"
            ),
            desc="该地址不需要登录就能访问，并且返回的是结构化数据而不是普通网页。",
            impact=(
                "若其中含业务数据，则任何访客可直接读取。"
                "当前仅确证「可达且返回数据结构」，尚未确证含敏感内容，故按中危定级。"
            ),
            detail=f"URL: {url}\n状态码: 200\n数据特征: {signals}\n响应片段:\n{self_mask(body[:600])}",
            level="B",
            confidence="Medium",
        ))
    return findings


def self_mask(text: str) -> str:
    return Masker("internal").mask(text)


if __name__ == "__main__":
    print("权限矩阵模块自测")
    print("=" * 70)

    # 离线自测：验证越权推断逻辑（不发起真实请求）
    class FakeClient:
        class session:
            headers = {"User-Agent": "test"}

        timeout = 10

    m = AuthzMatrix(FakeClient(), accounts=[])

    # 场景 1：跨租户读到相同数据标识
    probe = EndpointProbe(url="https://api.example.com/orders")
    probe.per_account = {
        "user_a": {"status": 200, "length": 800, "_body": '{"id":"1001","orderId":"O-1001","name":"x"}', "signals": ["json_object"]},
        "user_b": {"status": 200, "length": 800, "_body": '{"id":"1001","orderId":"O-1001","name":"x"}', "signals": ["json_object"]},
    }
    f = m._check_cross_tenant(probe, probe.per_account, {"user_a": "tenant_a", "user_b": "tenant_b"}, "api.example.com")
    print(f"\n场景1 跨租户：{'命中 → ' + f.title if f else '未命中'}")
    if f:
        print(f"  定级 {f.severity} / 证据级别 {f.evidence_level}")

    # 场景 2：未认证可访问
    probe2 = EndpointProbe(url="https://api.example.com/users")
    probe2.per_account = {
        "anon": {"status": 200, "length": 500, "_body": '{"id":"1","phone":"138****0000"}', "signals": ["json_object", "has_pii_field"]},
        "user_a": {"status": 200, "length": 500, "_body": '{"id":"1"}', "signals": ["json_object"]},
    }
    f2 = m._check_anonymous_access(probe2, probe2.per_account, "api.example.com")
    print(f"场景2 未认证：{'命中 → ' + f2.title if f2 else '未命中'}")
    if f2:
        print(f"  定级 {f2.severity} / 证据级别 {f2.evidence_level}")

    # 场景 3：正常隔离（不应命中）
    probe3 = EndpointProbe(url="https://api.example.com/profile")
    probe3.per_account = {
        "user_a": {"status": 200, "length": 300, "_body": '{"id":"1001","name":"a"}', "signals": ["json_object"]},
        "user_b": {"status": 200, "length": 320, "_body": '{"id":"1002","name":"b"}', "signals": ["json_object"]},
    }
    f3 = m._check_horizontal(probe3, probe3.per_account, {"user_a": "user", "user_b": "user"}, "api.example.com")
    print(f"场景3 隔离正常：{'误报！' if f3 else '正确未命中 ✓'}")

    assert f, "跨租户场景未识别"
    assert f2, "未认证场景未识别"
    assert not f3, "隔离正常场景出现误报"
    print("\n✓ 越权推断逻辑自测通过（含误报防护）")
