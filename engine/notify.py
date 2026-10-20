# -*- coding: utf-8 -*-
"""
周期化扫描 —— 飞书通知
========================
把一次扫描的结论推成一张飞书卡片。看着简单，但它是整条链路上**最容易被
糊掉结论**的一环，因为卡片天生只能放得下几行字：

  · 汇总卡里写「本次共 34 项发现，严重 6 / 高危 12」，读者自然得出
    「其余几百项都没问题」—— 而实际情况可能是「全量检查项里有 26 项没测」；
  · 卡片全绿，读者就不会去点报告。而报告里写着「挡在边界外，整份结论为
    无法评估」。绿卡片把「不知道」传成了「没事」。

所以本模块的红线只有一条：**卡片必须把「没有结论」的部分和「没问题」的部分
分开写，且颜色不得掩盖它。** 具体落成三条硬规则：

  1. **未执行 / 待人工执行 / 待确认 必须单独成行出现**，不并入「其余项正常」；
  2. **颜色规则**：只要存在未执行、待人工执行或边界拦截，一律用警示色，
     绝不用「安全绿」；只有「全部执行完且零发现」才允许绿。
  3. **卡片只给结论与入口**（报告路径 / 目标数 / 复测率），不放证据细节 ——
     细节在报告里，卡片糊一遍只会丢失上下文。

另外两条工程约束：
  · **凭据只从环境变量取**（`AISCAN_FEISHU_WEBHOOK` / `AISCAN_FEISHU_SECRET`），
    绝不写进配置文件或代码 —— 与全项目「凭据不得出现在代码里」一致；
  · 发送失败**不得中断扫描**（通知是附带动作），但必须如实记录失败原因，
    由调用方决定是否重试或告警。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verify.mask import Masker  # noqa: E402

#: 凭据来源（环境变量名）。写进常量是为了让「从哪取凭据」这件事可审计。
WEBHOOK_ENV = "AISCAN_FEISHU_WEBHOOK"
SECRET_ENV = "AISCAN_FEISHU_SECRET"

#: 卡片颜色。刻意不用绿色代表「安全」以外的任何含义。
COLOR_RED = "red"
COLOR_ORANGE = "orange"
COLOR_BLUE = "blue"
COLOR_GREEN = "green"

#: 需要单独警示的项状态（有这些就不能用绿卡片）。
CONCERNING_STATES = ("未执行", "待人工执行", "待确认")


@dataclass
class NotifyResult:
    """一次通知的结果。**失败必须能被读到**，不允许静默吞掉。"""

    sent: bool = False
    dry_run: bool = False
    skipped_reason: str = ""
    error: str = ""
    http_status: int = 0
    payload: dict[str, Any] = field(default_factory=dict)
    masked_hits: dict[str, int] = field(default_factory=dict)
    attempts: int = 0

    def summary(self) -> str:
        if self.dry_run:
            return "飞书通知：试发（dry-run），未实际发送"
        if self.sent:
            return f"飞书通知：已发送（HTTP {self.http_status}）"
        if self.skipped_reason:
            return f"飞书通知：未发送（{self.skipped_reason}）"
        return f"飞书通知：发送失败（{self.error or '未知原因'}）"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "dry_run": self.dry_run,
            "skipped_reason": self.skipped_reason,
            "error": self.error,
            "http_status": self.http_status,
            "masked_hits": dict(self.masked_hits),
            "attempts": self.attempts,
        }


def feishu_sign(timestamp: int | str, secret: str) -> str:
    """飞书自定义机器人签名。

    算法（官方口径）：以 `"{timestamp}\\n{secret}"` 为 HMAC-SHA256 的**密钥**、
    空串为消息，结果做 base64。注意密钥与消息的位置容易写反 ——
    写反后签名永远校验不过，而飞书只回一个笼统的失败码。
    """
    if not secret:
        return ""
    key = f"{timestamp}\n{secret}".encode("utf-8")
    return base64.b64encode(hmac.new(key, b"", digestmod=hashlib.sha256).digest()).decode("utf-8")


class FeishuNotifier:
    """飞书自定义机器人通知。

    webhook / secret 一律优先显式传参，其次环境变量。两者都没有时
    `available` 为假，调用方应把它当成「未配置通知」而不是失败。
    """

    def __init__(self, webhook: str | None = None, secret: str | None = None,
                 *, dry_run: bool = False, timeout: float = 10.0,
                 masker: Masker | None = None, out_dir: Path | None = None):
        self.webhook = (webhook if webhook is not None
                        else os.environ.get(WEBHOOK_ENV, "")) or ""
        self.secret = (secret if secret is not None
                       else os.environ.get(SECRET_ENV, "")) or ""
        self.dry_run = bool(dry_run)
        self.timeout = float(timeout)
        self.masker = masker or Masker("external")
        self.out_dir = Path(out_dir) if out_dir else (ROOT / "outputs")
        self._mask_report = None

    # ------------------------------------------------------------------
    @property
    def available(self) -> bool:
        return bool(self.webhook)

    def _m(self, text: Any) -> str:
        """所有进入卡片的文本都必须过一遍脱敏。

        卡片会离开本机（进企业 IM），所以按 external profile 处理：
        凭据与 PII 在任何 profile 下都会被脱敏，不存在「不脱敏」的选项。
        """
        if text is None:
            return ""
        from verify.mask import MaskReport  # noqa: PLC0415
        if self._mask_report is None:
            self._mask_report = MaskReport()
        return self.masker.mask(str(text), self._mask_report)

    # ------------------------------------------------------------------
    def _color(self, summary: dict[str, Any]) -> tuple[str, str]:
        """决定卡片颜色，并返回（颜色，原因）。原因要写进卡片，避免读者猜。"""
        states = summary.get("item_states") or {}
        missing = sum(int(states.get(s, 0) or 0) for s in CONCERNING_STATES)
        if summary.get("boundary_blocked"):
            return COLOR_ORANGE, "请求被边界防护接管，本次对应用本身没有结论"
        if missing:
            return COLOR_ORANGE, (f"有 {missing} 项没有结论（未执行 / 待人工执行 / 待确认），"
                                  "「无发现」不能读成「没问题」")
        counts = summary.get("counts") or {}
        high = int(counts.get("严重", 0) or 0) + int(counts.get("高危", 0) or 0)
        if high:
            return COLOR_RED, f"存在 {high} 条严重 / 高危问题"
        if int(counts.get("中危", 0) or 0):
            return COLOR_ORANGE, f"存在 {int(counts.get('中危', 0) or 0)} 条中危问题"
        if int(counts.get("合计", 0) or 0) == 0 and not summary.get("partial"):
            return COLOR_GREEN, "全部检查项均已执行且零发现"
        return COLOR_BLUE, "本次有发现但均为低危 / 信息级"

    def build_card(self, summary: dict[str, Any]) -> dict[str, Any]:
        """把扫描结论编成飞书交互卡片。"""
        name = self._m(summary.get("target_name") or summary.get("domain") or "未命名目标")
        color, why = self._color(summary)
        counts = summary.get("counts") or {}
        states = summary.get("item_states") or {}

        lines: list[str] = []
        lines.append(f"**目标**：{name}　`{self._m(summary.get('domain') or '')}`")
        lines.append(f"**时间**：{self._m(summary.get('scan_time') or '')}"
                     f"　档位 {self._m(summary.get('profile') or '')}")
        counts_txt = " / ".join(
            f"{k} {int(counts.get(k, 0) or 0)}"
            for k in ("严重", "高危", "中危", "低危", "信息") if counts.get(k))
        lines.append(f"**漏洞**：{counts_txt or '无'}"
                     f"（合计 {int(counts.get('合计', 0) or 0)}）")

        # 执行落实 —— 这一段是整张卡片最重要的部分
        total = int(states.get("合计", 0) or 0)
        passed = int(states.get("通过", 0) or 0)
        lines.append(f"**执行落实**：共 {total} 项，其中通过 {passed} 项"
                     f"（可信通过率 {float(summary.get('retest_rate', 0) or 0):.1%} 可复测）")
        miss_bits = [f"{s} {int(states.get(s, 0) or 0)}"
                     for s in CONCERNING_STATES if states.get(s)]
        if miss_bits:
            lines.append("**⚠ 以下部分本次没有结论**：" + " / ".join(miss_bits)
                         + " —— 这些项**不代表安全**，需按报告中的补齐方式处理")
        else:
            lines.append("本次所有适用项均已实际执行完毕。")

        diff = summary.get("diff")
        if diff:
            bits = [f"新增 {int(diff.get('新增', 0) or 0)}",
                    f"已修复 {int(diff.get('已修复', 0) or 0)}",
                    f"仍存在 {int(diff.get('仍存在', 0) or 0)}",
                    f"等级变化 {int(diff.get('等级变化', 0) or 0)}"]
            if diff.get("重新归类"):
                bits.append(f"重新归类 {int(diff['重新归类'])}（非修复）")
            if diff.get("本轮未判定"):
                # 不能只写「已修复」—— 本轮没跑的那几项长得就像已修复。
                bits.append(f"本轮未判定 {int(diff['本轮未判定'])}（非修复，"
                            f"该几项本轮没执行）")
            lines.append("**较上次**：" + " / ".join(bits))
            if summary.get("diff_state_known") is False:
                lines.append("　└ ⚠ 本次比对未带本轮逐项结论，「已修复」可能含本轮"
                             "未执行的项，仅供参考")

        objs = summary.get("objectives") or []
        if objs:
            bits = [f"{self._m(o.get('label'))}：**{self._m(o.get('result'))}**"
                    for o in objs[:4]]
            lines.append("**攻击目标**：" + "；".join(bits))

        elements: list[dict[str, Any]] = [
            {"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(lines)}},
        ]
        notes = [f"颜色依据：{why}"]
        if summary.get("boundary_blocked"):
            notes.append("目标在边缘被接管，结论范围已收缩")
        rp = summary.get("report_path")
        if rp:
            notes.append(f"报告：{self._m(rp)}")
        elements.append({"tag": "hr"})
        elements.append({"tag": "note", "elements": [
            {"tag": "plain_text", "content": "　|　".join(notes)}]})

        return {
            "msg_type": "interactive",
            "card": {
                "config": {"wide_screen_mode": True},
                "header": {
                    "template": color,
                    "title": {"tag": "plain_text",
                              "content": f"安全扫描结果：{name}"},
                },
                "elements": elements,
            },
        }

    def render_text(self, summary: dict[str, Any]) -> str:
        """纯文本版（无卡片能力的通道 / 自测用）。与卡片信息量保持一致。"""
        card = self.build_card(summary)
        out = [card["card"]["header"]["title"]["content"]]
        for el in card["card"]["elements"]:
            if el.get("tag") == "div":
                out.append(el["text"]["content"])
            elif el.get("tag") == "note":
                out.append("　|　".join(x["content"] for x in el.get("elements") or []))
        return "\n".join(out)

    # ------------------------------------------------------------------
    def send(self, summary: dict[str, Any]) -> NotifyResult:
        """发送。**任何异常都不抛出** —— 通知是附带动作，不能拖垮扫描。"""
        payload = self.build_card(summary)
        res = NotifyResult(payload=payload)
        try:
            res.masked_hits = dict(getattr(self._mask_report, "hits", {}) or {}) \
                if self._mask_report is not None else {}
        except Exception:  # noqa: BLE001
            res.masked_hits = {}

        if self.dry_run:
            res.dry_run = True
            self._dump(payload, "dry_run.json")
            return res
        if not self.available:
            res.skipped_reason = f"未配置 webhook（环境变量 {WEBHOOK_ENV} 为空）"
            return res

        body = dict(payload)
        if self.secret:
            ts = int(time.time())
            body["timestamp"] = str(ts)
            body["sign"] = feishu_sign(ts, self.secret)

        try:
            import requests  # noqa: PLC0415

            res.attempts += 1
            r = requests.post(self.webhook, json=body, timeout=self.timeout,
                              headers={"Content-Type": "application/json"})
            res.http_status = int(getattr(r, "status_code", 0) or 0)
            # 飞书对「webhook 无效 / 签名错」这类问题返回 HTTP 200 + code != 0，
            # 只看状态码会把失败当成功 —— 这正是「假成功」的典型形态。
            code = None
            try:
                code = (r.json() or {}).get("code")
            except Exception:  # noqa: BLE001
                code = None
            if res.http_status != 200 or (code not in (0, None)):
                res.error = (f"飞书返回 HTTP {res.http_status}"
                             + (f"，code={code}" if code is not None else "")
                             + f"，body={str(getattr(r, 'text', ''))[:200]}")
                self._dump(payload, "failed.json")
                return res
            res.sent = True
        except Exception as e:  # noqa: BLE001
            res.error = f"{type(e).__name__}: {str(e)[:200]}"
            self._dump(payload, "failed.json")
        return res

    def _dump(self, payload: dict[str, Any], filename: str) -> None:
        """把卡片原样落盘：试发要能核对内容，失败要能复盘。"""
        try:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            (self.out_dir / filename).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass


# ==============================================================================
# 自测
# ==============================================================================
def _selftest() -> int:
    problems: list[str] = []

    def _base(**over):
        s = {
            "target_name": "自测系统", "domain": "t.example.com",
            "scan_time": "2026-09-21 12:00:00", "profile": "standard",
            "counts": {"严重": 1, "高危": 2, "中危": 0, "低危": 1, "信息": 0, "合计": 4},
            "item_states": {"通过": 100, "不通过": 4, "未执行": 0,
                            "待人工执行": 0, "待确认": 0, "N/A": 10, "合计": 163},
            "retest_rate": 0.87, "report_path": "outputs/x/报告.md",
        }
        s.update(over)
        return s

    n = FeishuNotifier(dry_run=True, out_dir=Path(ROOT / "outputs" / "_通知自测"))

    # ① 有严重/高危 → 红
    c = n.build_card(_base())
    if c["card"]["header"]["template"] != COLOR_RED:
        problems.append("存在严重/高危问题却未用红色标题")

    # ② 有未执行项 → 绝不允许绿（这是核心：绿卡片会把「不知道」传成「没事」）
    s2 = _base(item_states={"通过": 90, "不通过": 4, "未执行": 20,
                            "待人工执行": 6, "待确认": 0, "N/A": 43, "合计": 163})
    c2 = n.build_card(s2)
    if c2["card"]["header"]["template"] == COLOR_GREEN:
        problems.append("存在未执行 / 待人工执行项时用了绿色标题 —— "
                        "绿卡片会让读者以为「都测过了、没问题」")
    txt2 = n.render_text(s2)
    if "没有结论" not in txt2:
        problems.append("卡片未把「没有结论」的部分单独写出来")
    for _s in ("未执行 20", "待人工执行 6"):
        if _s not in txt2:
            problems.append(f"卡片未单独列出「{_s}」—— 它会被并进「其余项正常」")

    # ③ 零发现且全部执行完 → 才允许绿
    s3 = _base(counts={"合计": 0}, retest_rate=0.0,
               item_states={"通过": 137, "不通过": 0, "未执行": 0,
                            "待人工执行": 0, "待确认": 0, "N/A": 26, "合计": 163})
    if n.build_card(s3)["card"]["header"]["template"] != COLOR_GREEN:
        problems.append("全部执行完且零发现时应用绿色标题")
    # 但只要有边界拦截，即使零发现也不许绿
    if n.build_card(_base(counts={"合计": 0}, boundary_blocked=True))[
            "card"]["header"]["template"] == COLOR_GREEN:
        problems.append("被边界拦截（对应用没有结论）时不得用绿色标题")

    # ④ 颜色依据必须写进卡片（否则读者不知道这个颜色代表什么）
    if "颜色依据" not in n.render_text(s2):
        problems.append("卡片未说明标题颜色的判定依据")

    # ⑤ 凭据只从环境变量取，不得内嵌
    if FeishuNotifier(webhook="", secret="").available:
        problems.append("未配置 webhook 时不应判为可用")
    _r = FeishuNotifier(webhook="", secret="", dry_run=False).send(_base())
    if _r.sent or "未配置" not in _r.skipped_reason:
        problems.append("未配置 webhook 时必须如实报「未发送」，不得当成功")
    if WEBHOOK_ENV not in FeishuNotifier(webhook="", secret="").send(_base()).skipped_reason:
        problems.append("未发送原因必须点明凭据来源环境变量名（便于运维定位）")

    # ⑥ 签名算法：密钥与消息不能写反
    sig = feishu_sign(1700000000, "s3cr3t")
    if not sig or len(sig) < 20:
        problems.append("签名生成异常")
    else:
        expect = base64.b64encode(hmac.new(b"1700000000\ns3cr3t", b"",
                                           digestmod=hashlib.sha256).digest()).decode()
        if sig != expect:
            problems.append("飞书签名算法不符（密钥应为 '{timestamp}\\n{secret}'、消息为空）")
    if feishu_sign(1, "") != "":
        problems.append("未配置密钥时不应产出签名")

    # ⑦ 脱敏必须生效：卡片会离开本机（进企业 IM），按 external 档处理
    n7 = FeishuNotifier(dry_run=True, out_dir=Path(ROOT / "outputs" / "_通知自测"))
    _secret_plain = "SUPERSECRET123456"
    _ak_plain = "AKIDabcdefghij123456"
    s7 = _base(target_name=f"泄漏测试 api_key={_secret_plain}",
               report_path=f"outputs/报告.md?password={_ak_plain}")
    _txt7 = n7.render_text(s7)
    for _bad in (_secret_plain, _ak_plain):
        if _bad in _txt7:
            problems.append(f"卡片中残留敏感串：{_bad}")
    if n7._mask_report is None or not n7._mask_report.hits:
        problems.append("脱敏命中数必须可统计（否则无法证明脱敏真的执行过）")
    _r7 = n7.send(s7)
    if not _r7.masked_hits:
        problems.append("脱敏命中数必须随通知结果一起返回（供报告/日志披露）")

    s7b = _base(objectives=[{"label": "拿到数据", "result": "未能验证"}])
    if "未能验证" not in FeishuNotifier(dry_run=True).render_text(s7b):
        problems.append("攻击目标结论必须进卡片（红队模式下它是主结论）")

    # ⑧ 发送失败必须留痕，不得抛异常
    class _Boom(FeishuNotifier):
        pass

    nb = FeishuNotifier(webhook="https://example.invalid/hook", dry_run=False,
                        out_dir=Path(ROOT / "outputs" / "_通知自测"))
    rb = nb.send(_base())
    if rb.sent or not rb.error:
        problems.append("发送失败时必须记录原因，不得当作成功")

    # ⑨ 试发不得真的发送，且要落盘卡片内容供核对
    _out = Path(ROOT / "outputs" / "_通知自测")
    nd = FeishuNotifier(webhook="https://example.invalid/hook", dry_run=True, out_dir=_out)
    rd = nd.send(_base())
    if rd.sent or not rd.dry_run:
        problems.append("dry-run 不得真的发送")
    if not (_out / "dry_run.json").exists():
        problems.append("dry-run 必须把卡片落盘（否则「试发」核对不了内容）")

    # ⑩ 比对数字不得把「本轮没执行」包装成「已修复」
    s10 = _base(diff={"新增": 1, "已修复": 3, "仍存在": 5, "等级变化": 0,
                      "重新归类": 2, "本轮未判定": 4})
    t10 = FeishuNotifier(dry_run=True).render_text(s10)
    if "本轮未判定 4" not in t10:
        problems.append("卡片未列出「本轮未判定」—— 那几项本轮没跑，"
                        "只写「已修复 3」会让读者以为收口了")
    if "非修复" not in t10:
        problems.append("「重新归类 / 本轮未判定」必须标注为非修复")
    if "已修复 3" not in t10:
        problems.append("已修复数字仍需如实保留")
    # 没有这两项时不得凭空多写
    t10b = FeishuNotifier(dry_run=True).render_text(
        _base(diff={"新增": 0, "已修复": 0, "仍存在": 1, "等级变化": 0}))
    if "本轮未判定" in t10b or "重新归类" in t10b:
        problems.append("无对应条目时不得凭空空写一行（会让人以为有这几类）")

    if problems:
        print("飞书通知自测不通过：")
        for x in problems:
            print(f"  ✗ {x}")
        return 1
    print("飞书通知自测通过：未执行项单独列示且禁止绿卡片、颜色依据已注明、"
          "攻击目标结论在卡、比对数字不把「本轮没跑」写成「已修复」、"
          "凭据只取环境变量、dry-run 不发送、发送失败留痕、"
          "签名算法与官方一致")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
