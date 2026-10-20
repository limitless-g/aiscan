# -*- coding: utf-8 -*-
"""
扫描引擎自测（离线可跑）
========================
目的：验证「逐项执行状态机」在最坏情况下也不会把「没测」包装成「通过」。

做法：本地起一个故意埋了若干问题的假应用，把全量检查项全部跑一遍，
然后校验下面这些不变量：

  ① 每一项的结论都落在合法状态集合内（不存在空结论、未知结论）；
  ② 标记为「通过」的项，必须真的执行过（executable=True）且有探测次数记录；
  ③ 每一项要么执行过，要么带有明确的「为什么没执行」说明 ——
     不允许出现「状态为未执行但没有任何原因」的项；
  ④ 人工执行项必须带可照做的步骤与判定标准；
  ⑤ 埋进去的问题要真的被抓到（否则说明检测器是空壳）；
  ⑥ 生成的复现脚本必须全部可编译，且**零告警**编译（非法转义序列这类
     问题默认只告警不报错，会静默存活）；特征串「进脚本再读回来」必须
     与原值一致 —— 串被改动一次，复现就会稳定失败，而报告上看起来
     像「目标已修复」。
  ⑦ 漏洞清单里的每一条都必须有脚本，且闸门判定为「已复现」；
  ⑧ 埋进去的问题必须「既被检出、又被复现」；
  ⑨ URL 枚举的来源必须真的采到（而不是只有一个字典）；
  ⑩ 端口探测必须真的跑过并产出覆盖记录；
  ⑪ 敏感文件的语义准入必须双向守得住：既不能把应用自身的可达页面
     报成「敏感文件」，也不能漏掉 .env / .git/config 这类确定命中；
  ⑫ 普通登录页不能被当成「管理 / 运维接口」上报，真管理入口也不能被漏排；
  ⑬ HTTP 通道必须直连，不得被环境代理接管（代理会让所有路径 404，
     症状看起来像「检测能力退化」，实则流量被劫持）；
  ⑭ 整站同一响应（如边缘防护对所有路径返回 405）不得被当作
     「功能存在」的证据 —— 否则一次性凭空判定十几个特征「具备」，
     检测全部跑在拦截页上，产出的结论一条也复测不出来。
  ⑭-b 上一条的**反面**：对照实验做不成时（探测样本不足）也必须失败关闭。
     守卫在样本不足时返回「非同码」，405/403/401 于是又被静默采信 ——
     实测表现是适用性从 67 项被抬到 124 项。做不了对照 ≠ 可以采信，
     且「对照没生效」这件事必须写进报告，不能悄悄过去。
  ⑭-c 同一守卫的**第三种**失效方式：样本足够，但边缘返回的是**混合**状态码
     （限速 / 挑战 / 部分放行 / 多节点不一致），众数占比跌破阈值 ——
     此时状态码口径判「非同码」，而样本数并不少，连 ⑭-b 的提示都打不出来。
     必须由**正文口径**（归一化后是否同一张页）接管，并叠加拦截页厂商特征
     才下拦截结论；反之，正文同码但没有厂商特征（SPA 兜底路由）**不得**
     判成拦截 —— 否则正常的单页应用会被整场判成「未执行」。
  ⑮ 扫描**中途**才出现的边界封禁必须被检出并转入终态 —— 它与「一开扫
     就被拦」不同：后者结论是诚实的「无法评估」，前者若不察觉，会把
     后半段拿到的拦截页当应用扫完，产出一份格式规范、证据齐全、
     却复测不出来的假报告。
  ⑯ 受控写权限必须是「档位允许 ∩ 台账显式授权」两把锁同时开 ——
     只看档位的后果是：deep 档下台账写着「写验证：不允许」也照样开门，
     写类检测器会真的发出请求。「登记了却不生效」比没登记更危险。
  ⑰ 裸 IP 目标（内网系统最常见形态）的可达范围必须判准：私网地址一律
     「内网可见（非公网暴露）」，不得因为 DNS 解析不出 A 记录就写成
     「未取得解析地址」—— 那会让红线要求的内网标注丢失。
  ⑱ 一个端口只能有一个「上报出口」（net.PORT_OWNER）。同一个端口被多个
     检查项各报一次时，报告里会出现多条标题雷同、指向同一 IP:端口 的发现，
     端口个数会被读成漏洞个数。归属表兜底给 EXT-CL-02，
     专责项（EXT-DM-05 邮件 / EXT-CL-03 容器 / EXT-CL-04 K8s）各自认领；
     认不出服务身份的端口由 owner 以「可达但身份未确认」上报，不留假阴性。
  ⑲ 外部注入工具（sqlmap）必须被**白名单 + 数值下界 + 档位**三重约束：
     危险开关（--dump / --os-shell / --file-read / --sql-query …）一律拒绝，
     `--risk` > 2 拒绝（OR 型改写载荷可能改动目标数据），未登记开关默认拒绝；
     安全档不调用、显式关闭后不调用，且两种情况都必须给出理由。
     名字合法 ≠ 取值安全 —— 这两件事必须分开断言。
  ⑳ 会话池（认证态）必须守住四条：
     · 配置里出现**明文口令** → 该账号被拒收并给出理由，绝不带着明文去登录；
       「登记了但不安全，就不生效，而且要说出来」。
     · **登录接口返回 200 不等于登录成功** —— 必须回验；401/403 是明确的
       「未登录」，不能被当成「已登录」（否则用游客身份测出的「越权」全是噪声）。
     · 已确认登录态**不足 2 个**时必须明说「越权类结论只能判未能验证」，
       而不是照常输出越权结论。
     · 进报告的数据（to_dict，剥凭据）与构造请求的数据（to_pool_dict，带凭据）
       必须是两份，用错任何一份都会静默失效 —— 前者进会话池会让所有账号
       被当成「没凭据」而整批拒收，后者进报告则是直接泄露凭据。
  ㉑ SPA 渲染必须「真生效」且「不越权下结论」，两个方向都要钉住：
     · 渲染写了却没人用（装饰品）→ SPA 目标整体失明，报告里一堆假的 N/A，
       而 N/A 读起来是「该功能不存在，无需测试」；
     · 渲染失败被当成「页面上没有这些东西」→ 把一次工具失效说成了
       关于目标的结论，是本项目红线（孤立信号不得当正面证据）的直接违反。
     另外三条硬约束：安全档不渲染（会在浏览器里执行目标页面 JS，
     有副作用）；命令行必须带一次性配置目录且不吃系统代理、不关沙箱；
     渲染结果必须标明来源，否则复测方式会写错（curl 看不到渲染后的内容）。
  ㉒ 业务逻辑自动侦察必须「真省人工」且「不冒充通过」：
     BUSL 十项长期是「全靠人工」，补它的方式不是把它们标成自动项
     （业务语义的判定权在人手上，标成自动项就是造假通过），
     而是给每个人工项加一层前置侦察：把「找接口、找字段、记当前值、
     做差分」做掉，人工只回答「这个业务结果对不对」。
     两个方向都要钉住：
     · 收不足（侦察写了没人用）→ 人工还得从零找接口，盲区没补上；
     · 收过头（侦察没抓到就判通过）→ 人工项变绿色，
       等于用「工具没看见」冒充「业务逻辑没问题」，正是本项目要根除的。
     差分判据还必须挡住最容易发生的误报：
     **响应里只有被篡改字段自身变成非法值**（回显）不得判成「服务端采信」，
     必须判「不下结论」——业务逻辑类误报代价最高，
     研发一句「服务端会重算」就能否掉整份报告。
     另有三条硬约束：未授权的写差分一次请求都不许发；
     没有有效基线（404/401）不得下任何结论；
     资金/上传/删除/短信/审批类接口一律排除在自动触碰之外。
  ㉓ 攻击链必须「只串实测、不造事实」：
     攻击链是本项目里唯一的**推理层** —— 它靠能力关系把分散的发现串起来，
     也正因为是推理，它最容易把「扫到一个认证绕过」推成「拿到控制权」。
     铁律：链判「已达成」**只认单点实测**，升级边永远只能用来生成
     待确认清单，不能用来下结论（三级推理之后结论会完全脱离实测）。
     三个方向都钉住：
     · 正向：单点实测的能力确实能串成链，并能回填「能力缺口」的目标
       —— 否则实测到的战果会因为「该目标没有独立攻击路径」被埋成
       「未能验证」，那是另一种假结论；
     · 反向：无实测锚点的纯推理链不产出、不判「已达成」、不回填；
     · 隔离：已达成与候选必须分成两档、分开措辞、分桶落盘，
       否则报告会把纸面推演和实测战果量齐。
  ㉔ 越权类复现必须自带会话上下文，且「缺会话」不得冒充实测结论：
     越权是唯一一类**以匿名身份根本复现不出来**的问题 —— 匿名请求必然撞上
     登录页 / 401，脚本于是打印「未复现」，而准确含义是「本次没有验证到」。
     报告里这两句话含义相反：前者是「我确认没有」，后者是「我不知道」。
     混同的后果是把一个真实的越权问题当成已修复关掉。
     生成的复现脚本因此必须能从「会话文件 / 环境变量」自取凭据，
     且**不需要操作者改动脚本的任何一行**（改了就无法作为交付物外发）。
     六个方向全部钉住：
     · 缺凭据（含骨架未填）→ 判「无法判定」并给出填写说明，
       输出里**不得**出现「未复现」这个结论字样；
     · 两个角色解析出相同凭据（同一账号填两遍）→ 拒判，
       否则「两个身份读到同一份数据」退化成「同一个身份读了自己两次」；
     · 两个身份返回逐字节相同的含个人数据响应 → 复现成功，
       且必须保留「数据归属须人工确认」这条边界，不代人工定级；
     · 两个身份拿到不同内容 → 如实判「未复现」，不得一律判成功；
     · 会话文件与环境变量两条通道都要生效；
     · 凭据不得出现在任何输出里。
  ㉕ nuclei 结果必须回填到检查项，且回填方向只能收紧：
     检查项状态是由**该项自己的检测器**决定的；nuclei 的发现挂在同一个
     item_id 上，却不参与状态判定。不做回填，同一份报告里就会出现
     「第 2 章列着一条附请求/响应原文的实测发现、第 3 章同一项写着『通过』」——
     读者只会信更干净的那一栏，于是唯一一条有现成证据的问题被关掉。
     四条都要钉住：
     · 方向只能收紧：回填只可能产出「不通过」，**绝不能产出「通过」**
       —— 一旦能，回填就成了绕过检测的新路径，比不做回填更危险；
     · 覆盖旧状态必须留痕，尤其「N/A」与实测命中直接冲突时要摆出来；
     · 识别类命中（tech-detect / waf-detect 这类）不得回填，否则检查项会
       无端变成「不通过」—— 那是与漏报相反的另一种失真；
     · 找不到归口的发现必须报出来，不得静默丢弃；归口表覆盖规模也须校验，
       防止表被改坏之后全部模板静默走兜底。
  ㉗ nuclei 执行必须受预算约束，且「被掐断」绝不等于「产出归零」：
     nuclei 是全流程里唯一自行发请求的一步，不受本工程节流器约束 ——
     模板选多了，单这一步就能吃掉整轮扫描的时间。三条都要钉住：
     · **减量只动结构性不适用的部分**：file / code / javascript / headless /
       whois 这五类需要本地文件、本地代码运行时、浏览器、注册域名，
       对「只给了一个 URL」的目标一个有效请求也发不出来，排除它们是纯收益；
       限速还必须夹到档位声明的请求速率以内（nuclei 不走我们的节流器，
       配置里那个更大的值等于实际速率超出授权范围）；
     · **分层保序**：先跑 critical/high 再跑其余。预算耗尽时手里至少是全量
       高价值结果，而不是被截断的随机一半；
     · **掐断即抢救**：进程被预算杀掉时，jsonl 里已经写出的就是既成事实，
       必须解析回来并标记「不完整」。旧写法只在退出码正常时才解析 ——
       一次超时就让整批结果归零，而报告上看起来像「nuclei 跑了、没发现」，
       同样是拿「不知道」冒充「没有」。
  ㉘ 抽检是抽样 —— 盲区必须收口，窗口内的「通过」一律作废：
     不变量 ⑮ 只保证「检出封禁后，后续项记未执行」。而两次抽检**之间**那段
     盲区里跑完的检查项，结论是建立在拦截页上的 —— 其中判「通过」的那些是
     **假通过**：不是「我没说」，而是**主动给出的错误结论**，报告看起来完全正常。
     两条互补机制必须同时生效，缺一条就消不掉窗口：
     · **把发现时机提前（缩小窗口）**：探测热路径把每个响应喂给守门做便宜的
       本地判断（只算哈希、不发请求）；同一个「拦截区间状态码 + 同正文且非基线页」
       在**不同 URL** 上重复出现，即触发真抽检，不等节流阈值。要求 ≥2 个不同 URL，
       因为单次 403 太常见（应用自己的鉴权就返 403），拿它当信号会把抽检打成风暴；
       还必须带下限，否则从一个极端翻到另一个极端。
     · **把窗口内的结论作废（消除假通过）**：封禁事件记下窗口
       （上次干净抽检 → 本次发现封禁），窗口内的「通过 / N/A」改判为「待确认」，
       「不通过」只加核对标注（真伪交给复现闸门，不靠启发式翻案）。
       区间相交判定必须精确到端点：多判一个端点就误伤窗口外的正确结论。
  ㉙ 周期化扫描与通知不得把「本轮没跑」传成「已修复 / 没问题」：
     周期化是这套工具变成「持续运营」后，假通过最集中的新入口。
     · **比对层**：`已修复` 只看「本轮没再检出」。若本轮那一项根本是「未执行」（预算被
       掐、配额耗尽、前端采集失败），「没再检出」就是句空话 —— 不是修好了，是没人去看。
       四种「没有结论」的状态（未执行 / 待人工执行 / 待确认 / 已跳过）一律改记
       **「本轮未判定」**，并在报告里明写「不得计入已修复」。
     · **通知层**：绿卡片必须同时满足「全部执行完」+「零发现」+「未被边界拦截」；
       只要有未执行项，就只能橙/红。卡片上「较上次」必须把「重新归类」和
       「本轮未判定」单列并标注**非修复**，不能让读者把脏数字当干净数字。
     · **调度层**：扫描阶段失败或被授权闸门拦下的目标**不得记账** ——
       记了「本周期已执行」，那个周期就再也不会扫它，失败被静默吞掉。
       同时 cron 表达式非法必须**在执行前**报出来：静默不出勤是调度器最典型的失效形态。
  ㉚ 认证 / 会话 / 加密 / 授权 / 数据导出的人工项必须挂上自动前置侦察，且三态分明：
     「必须人工」不等于「全推给人」。这几类人工项里真正只有人能回答的只有最后
     那一句判断（锁定阈值、并发策略、能否解密、导出口径是否越界），而
     「找登录入口、找改密表单、找密文参数、盘点现有防护、定位管理与导出端点」
     占了大头。侦察把它们做掉，人工接手时看到的是
     「接口是这个、字段是这些、已排除这些」。
     三态与 BUSL 一致且不得混淆：① 侦察确证 → 「不通过」；
     ② 侦察跑了没确证 → 仍是「待人工执行」；③ 侦察没跑（档位不足 / 无测试账号）
     → 仍是「待人工执行」，且**必须显式写出原因，并带上「怎么补」** ——
     只写「侦察未执行」而不写补齐方式，操作者知道缺东西却不知道该给什么。
     第 ③ 种最容易糊过去：静默退化成一个空清单，会被读成「已经查过了」。
     同时守住红线：认证类侦察**绝不尝试真实登录爆破**（会锁定真实账号），
     也不对真实账号发起找回（会触发真实短信 / 邮件）—— 没做的原因必须写出来。
     授权 / 导出两类的反向判据同样钉住：匿名自己就能进的端点**不算**权限提升
     （那是未授权访问，另一类问题）；导出端点返回 HTML **不算**拿到数据文件
     （判据必须落在响应类型上，否则「200 = 有东西」毫无区分力）。

外部网络（DNS / crt.sh / 端口扫描）全部打桩，因此这个自测不产生任何外网流量，
可以在任何环境反复运行。

用法：
    python selftest_engine.py
    python selftest_engine.py --verbose   # 打印逐项状态
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import socket
import socketserver
import sys
import threading
import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from checklist.loader import load_checklist  # noqa: E402
from engine.applicability import ApplicabilityResult, Feature, TargetFeatures  # noqa: E402
from engine.checks import net  # noqa: E402
from engine.fingerprint import HttpProbeClient  # noqa: E402
from engine.registry import (  # noqa: E402
    ALL_STATES, MODE_MANUAL, STATE_FIND, STATE_NA, STATE_PENDING, STATE_PASS,
    STATE_SKIP,
)
from engine.registry_runner import build_context, run_all_items, summarize  # noqa: E402
from engine import registry_runner  # noqa: E402

# ======================================================================
# 会话池（认证态）自测用的口令
# ======================================================================
# 这是**本地假应用**的口令，不是任何真实系统的凭据，写在代码里没有泄露风险。
#
# 关键设计：假应用侧的「正确口令」也是**从环境变量读**的。于是
# 「自动登录成功」这件事本身就成了证据 —— 它只能成立，当且仅当
# 扫描器确实把环境变量里的值取出来发出去了。若有人把凭据硬编码进配置，
# 环境变量为空 → 两侧同时为空 → 仍会「相等」→ 这条测试就失去意义。
# 因此下面额外断言了「环境变量为空时必须登录失败」。
TEST_LOGIN_PASS_ENV = "AISCAN_SELFTEST_LOGIN_PASS"
# 口令只用字母数字与连字符：表单编码会把 `#`、`&` 等转义成 %XX，
# 若口令里含这些字符，「子串是否出现」的比对会假失败，
# 而失败原因看起来像「登录逻辑有 bug」，会把人带偏。
TEST_LOGIN_PASS = "AiscanSelfTest-Pass2026"
TEST_LOGIN_USER = "user_a"


def _expected_login_pass() -> str:
    """假应用侧判口令用的值：只从环境变量取，取不到就是空串。"""
    return os.environ.get(TEST_LOGIN_PASS_ENV, "")

# ======================================================================
# 假应用：故意埋问题，用来验证检测器不是空壳
# ======================================================================
APP_JS = """
var API_BASE = "/api";
fetch("/api/user?uid=1").then(r => r.json()).then(d => {
  document.getElementById("who").innerHTML = d.name;
});
localStorage.setItem('password', 'admin123');
var key = "AKIAIOSFODNN7EXAMPLE";
var internal = "10.51.144.111";
var db = "mysql://root:Passw0rd@10.0.0.9:3306/prod";
function render() { document.write(location.hash); }
"""

INDEX_HTML = """<html><head><title>演示系统</title>
<script src="/static/app.js"></script></head>
<body><h1>演示系统</h1>
<div id="who"></div>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="登录">
</form>
<form action="/api/sms/send" method="post">
  <input type="text" name="mobile">
  <button>获取验证码</button>
</form>
</body></html>"""

LOGIN_HTML = """<html><head><title>登录</title></head><body>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="登录">
</form>
<a href="/forgot">忘记密码</a>
</body></html>"""

# SPA 骨架页：直连拿到的是一个空的挂载点，正文全靠 JS 注入。
# 供渲染链路自测（不变量 ㉑ 的 --with-browser 分支）使用。
# 注入内容特意含表单与链接：这两样正是「只有渲染后才看得到」的特征，
# 用来验证渲染真的改变了判定，而不是只多了一行文字。
SPA_HTML = """<html><head><title>SPA 演示</title></head>
<body><div id="app"></div>
<script>
  document.getElementById('app').innerHTML =
    '<h1>管理后台</h1>' +
    '<form action="/api/user/update" method="post">' +
    '<input name="mobile" type="text"></form>' +
    '<a href="/order/list">订单列表</a>';
</script>
</body></html>"""

ENV_FILE = """APP_ENV=production
DB_HOST=10.0.0.9
DB_USER=root
DB_PASSWORD=Sup3rS3cret
REDIS_URL=redis://10.0.0.11:6379/0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY
"""

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /internal/
Sitemap: http://127.0.0.1:PORT/sitemap.xml
"""

ROUTES = {
    "/": (200, "text/html; charset=utf-8", INDEX_HTML),
    "/login": (200, "text/html; charset=utf-8", LOGIN_HTML),
    "/static/app.js": (200, "application/javascript", APP_JS),
    "/robots.txt": (200, "text/plain", ROBOTS),
    "/.env": (200, "text/plain", ENV_FILE),
    "/.git/config": (200, "text/plain", "[core]\n\trepositoryformatversion = 0\n"),
    "/admin/": (200, "text/html", "<html><title>管理后台</title><body>Admin</body></html>"),
    "/server-status": (200, "text/html", "<html><body>Apache Server Status for 127.0.0.1</body></html>"),
    "/api/user": (200, "application/json",
                  '{"uid":1,"name":"张三","mobile":"13900001234",'
                  '"idcard":"110101199003078515","email":"zhangsan@example.org",'
                  '"address":"北京市朝阳区"}'),
    "/v1/models": (200, "application/json", '{"object":"list","data":[]}'),
    "/spa": (200, "text/html; charset=utf-8", SPA_HTML),
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # 请求计数：用来证明「某个分支一个请求都没发」。
    # 只断言返回值是不够的 —— 「判定正确」与「没发请求」是两件事，
    # 而本项目的红线恰恰是「不要在没触达应用的地方下结论」。
    HITS = {"n": 0}

    def _send(self, code: int, ctype: str, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if code == 200 and ctype.startswith(("application/json", "text/html")):
            # 故意不加 Cache-Control，用来验证「用户数据响应缓存策略」检测项
            self.send_header("Server", "Apache/2.4.29 (Ubuntu)")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        Handler.HITS["n"] += 1
        path = self.path.split("?")[0]
        if path == "/api/whoami":
            # 会话池回验专用：**必须携带有效会话 Cookie** 才给 200，否则 401。
            # 有了它，「自动登录到底成没成功」才是一个可证伪的事实，
            # 而不是「登录接口返回 200 就算成功」这种一测就穿的假设。
            # 这里校验的是**值**而不只是键存在：只判「有没有这个键」时，
            # 一个随手编的 `aiscan_sess=bogus` 也会拿到 200，
            # 于是「无效凭据 → 401 → 判未登录」这条分支永远测不到 ——
            # 而它恰恰是越权检测不出噪声的关键一环。
            _ck = self.headers.get("Cookie") or ""
            if re.search(r"(?<![\w-])aiscan_sess=ok(?![\w-])", _ck):
                self._send(200, "application/json", '{"ok":true,"user":"user_a"}')
            else:
                self._send(401, "application/json", '{"ok":false,"err":"unauthorized"}')
            return
        route = ROUTES.get(path)
        if route:
            code, ctype, body = route
            if path == "/robots.txt":
                body = body.replace("PORT", str(self.server.server_address[1]))
            self._send(code, ctype, body)
            return
        self._send(404, "text/html", "<html><title>404 Not Found</title><body>404 Not Found</body></html>")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        path = self.path.split("?")[0]
        if path == "/api/login":
            # 供「会话池自动登录」自测：口令必须与环境变量里的值一致。
            # 注意这里是**从环境变量读**正确口令，而不是比对代码里的常量 ——
            # 这样「登录成功」才能证明凭据确实来自环境变量。
            _want = _expected_login_pass()
            if _want and _want in raw and "username=" in raw:
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "aiscan_sess=ok; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._send(401, "application/json", '{"ok":false,"msg":"bad credentials"}')
            return
        self._send(200, "text/html", "<html><body>received</body></html>")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a) -> None:  # 静音，避免刷屏
        return


def start_app() -> tuple[socketserver.TCPServer, int]:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _cors_edge_gate_problems() -> list[str]:
    """不变量 ⑥-d：CORS 头只有在「响应确实来自应用」时才算证据。

    2026-09-28 实测事故（internal-app.example.com）：
    检测器把 **405 响应**上的 ACAO 反射当成应用配置缺陷，报了一条
    「CORS 反射任意 Origin 且允许携带凭据」，且顺利通过复现准入进了漏洞清单；
    事后复跑同一份复现脚本，200 响应上根本没有 ACAO 头 —— 那条「已复现」站不住。

    405 是「该方法不被允许」的通用错误页，它上面的响应头可能由边缘节点
    （WAF / 网关）统一添加，归不到「这个端点的 CORS 配置」上。
    这与项目红线一致：**孤立信号不得当正面证据** ——
    先证明响应真的来自应用，再谈它是不是配置缺陷。

    这里用一个「所有路径都回 405 + 反射 ACAO + 允许凭据」的假边缘节点，
    同时钉住两面：
      · 不得据此上报发现（会导致复测不出来的误报）；
      · 也不得静默判「未发现问题」（那是用一个不可采信的响应把风险判定掉），
        正确状态是「待确认」。
    """
    problems: list[str] = []

    class _Edge(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a: Any) -> None:  # noqa: ANN401
            return

        def _path(self) -> str:
            from urllib.parse import urlsplit  # noqa: PLC0415

            return urlsplit(self.path).path or "/"

        def do_GET(self) -> None:  # noqa: N802
            body = b"<html><body>405 Method Not Allowed</body></html>"
            self.send_response(405)
            origin = self.headers.get("Origin") or ""
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv: Any = None
    try:
        srv = _Edge(("127.0.0.1", 0), _H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{port}/"
        _client = HttpProbeClient({"rate": {"timeout_seconds": 5,
                                            "requests_per_second": 500}})
        ctx = build_context(
            target_name="CORS 边缘页自测",
            domain="127.0.0.1",
            target_url=url,
            profile={"_key": "deep", "risk_level": "deep",
                     "write_verification": "controlled"},
            profile_key="deep",
            fp_result={"path_probes": {}},
            js_result={},
            nuclei_findings=[],
            accounts=[],
            client=_client,
        )
        from engine.checks.client import clnt07  # noqa: PLC0415

        out = clnt07(ctx)
        if getattr(out, "findings", None):
            problems.append(
                "CORS 检测器把 405 响应上的 ACAO 头当作配置缺陷上报了 —— "
                "该响应可能来自边缘节点、归不到应用，会上报一条复测不出来的误报")
        elif not getattr(out, "pending", False):
            problems.append(
                "CORS 检测器在「ACAO 只能来自边缘页」时既没报发现、也没判「待确认」"
                " —— 这是用一个不可采信的响应把风险判定掉（假通过）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"CORS 边缘页归属校验未能执行：{type(e).__name__}: {str(e)[:120]}")
    finally:
        try:
            if srv is not None:
                srv.shutdown()
        except Exception:  # noqa: BLE001
            pass
    return problems


# ======================================================================
# 外网打桩：DNS / crt.sh / 端口扫描全部走本地假数据，零外网流量
# ======================================================================
def patch_network(domain: str, open_port: int = 0) -> None:
    spf = "v=spf1 include:_spf.example.com -all"
    dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

    def fake_dns_records(name: str, rtype: str) -> list[str]:
        name = name.lower()
        if rtype == "TXT":
            if name.startswith("_dmarc."):
                return [dmarc]
            if "_domainkey." in name:
                return ["v=DKIM1; k=rsa; p=" + "A" * 120] if name.startswith("default.") else []
            if name.rstrip(".") == domain:
                return [spf]
            return []
        if rtype == "MX":
            return ["10 mail.example.com."]
        if rtype == "NS":
            return ["ns1.example.com.", "ns2.example.com."]
        if rtype == "CNAME":
            return []
        if rtype == "A":
            # 只有主域名解析，随机子域返回空 —— 用于验证通配符检测逻辑
            return ["127.0.0.1"] if name.rstrip(".") == domain else []
        return []

    def local_scan(host: str, ports: list[int] | None = None,
                   workers: int = 24) -> dict[int, bool]:
        """只在回环地址上做**真实**探测，绝不产生任何外网流量。

        以前这里直接返回 {}，等于让所有端口类检测器（INFO-04 / EXT-DM-05）
        在自测里一路「无数据」地静默通过 —— 端口这一整块能力从未被验证过。
        现在对回环做真探测：假应用监听的那个端口应当被识别为开放，
        其余端口应当被识别为关闭，两条判定路径都走一遍。
        """
        cand = list(ports or net.PORT_TIERS["standard"])
        if host not in ("127.0.0.1", "localhost"):
            return {p: False for p in cand}
        if open_port:
            cand = sorted(set(cand) | {open_port})
        out: dict[int, bool] = {}
        for p in cand:
            try:
                with socket.create_connection((host, p), timeout=0.3):
                    out[p] = True
            except Exception:  # noqa: BLE001
                out[p] = False
        return out

    net.dns_records = fake_dns_records                       # type: ignore[assignment]
    net.crtsh_subdomains = lambda d, timeout=35: [           # type: ignore[assignment]
        f"www.{d}", f"api.{d}", f"jenkins.{d}", f"test.{d}", f"vpn.{d}",
    ]
    net.scan_ports = local_scan                              # type: ignore[assignment]
    # 端口扫描缓存必须在打桩之后清掉，否则会拿到上一次运行的结果
    net._PORT_SCAN_LOG.clear()
    net.zone_transfer_attempt = lambda d: []                 # type: ignore[assignment]
    net.tcp_open = lambda host, port, timeout=2.5: False     # type: ignore[assignment]
    net.tcp_banner = lambda host, port, timeout=3.0: ""      # type: ignore[assignment]


# ======================================================================
# 适用性：全部判「适用」，把最坏情况摆出来
# ======================================================================
def all_applicable(checklist) -> list[ApplicabilityResult]:
    """全部判「适用」，把最坏情况摆出来：所有项都必须给出明确结论。

    注意 feature 不能给 None —— 报告层会读它的 state 写「判定依据」。
    这类字段缺失正是自测要拦下来的东西。
    """
    out = []
    for item in checklist:
        feat = Feature(name=item.app, state="present",
                       evidence="自测：强制全量适用", source="override")
        out.append(ApplicabilityResult(
            item=item, conclusion="适用", reason="自测：强制全量适用",
            feature=feat,
        ))
    return out


def render_report(out_dir: str, checklist, app, results, findings, ctx,
                  summary: dict, gate_result: Any = None,
                  verify_runs: list[Any] | None = None) -> dict:
    """用自测数据渲染一份完整报告，验证报告层与新状态机的对接。

    关键：这里必须把真实的 gate_result 传进去，并且 fs 里只放「已复现」的发现。
    否则渲染出来的报告又会退回「把没验的当漏洞写」的老问题。
    """
    from datetime import datetime

    from models import FindingSet
    from report.generator import ReportContext, ReportGenerator

    fs = FindingSet(target="自测目标")
    blocked: list[Any] = []
    for f in findings:
        if gate_result is not None and f not in gate_result.reportable_findings():
            blocked.append(f)
            continue
        fs.add(f)

    rc = ReportContext(
        target_name="自测目标",
        primary_domain="127.0.0.1",
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        profile_name="深度档",
        # 本函数是**手工组装**的，不跑 orchestrator 的 L4.5 攻击目标编排，
        # 所以如实标为合规视角 —— 若标成黑客运维，报告会正确地喊出
        # 「未产出任何攻击目标结论」，那是在报一个不存在的生产问题，
        # 会把真正该看的告警淹没掉。
        mode="compliance",
        features={},
        dns={"per_resolver": {"223.5.5.5": ["127.0.0.1"]}, "consistent": True},
        root_probe={},
        authorization={"authorized": True, "authorizer": "自测",
                       "authorization_date": datetime.now().strftime("%Y-%m-%d"),
                       "authorization_ref": "SELFTEST"},
        tools=[],
        fallbacks=[],
        checklist_meta=checklist.meta,
        authz_findings=[],
        verify_runs=verify_runs or [],
        business_notes=[],
        item_results=results,
        detector_summary=summary,
        detector_notes=ctx.notes or [],
        submissions=ctx.submissions,
        collection=dict(ctx._cache.get("collection_report") or {}),
        gate_result=gate_result,
        blocked_findings=blocked,
        coverage={
            "url_pool": list(ctx._cache.get("url_pool_coverage") or []),
            "url_skipped": list(ctx._cache.get("url_pool_skipped") or []),
            "ports": net.port_scan_log(),
            "reach_scope": net.reachability_of(ctx._cache.get("info04_ip") or "")[0],
            "reach_why": net.reachability_of(ctx._cache.get("info04_ip") or "")[2],
        },
    )
    return ReportGenerator(out_dir).generate(rc, fs, app)


def main() -> int:
    ap = argparse.ArgumentParser(description="扫描引擎自测")
    ap.add_argument("--verbose", action="store_true", help="打印逐项状态")
    ap.add_argument("--port", type=int, default=0, help="指定端口（默认随机）")
    ap.add_argument("--report", default="",
                    help="把本次自测结果渲染成报告，输出到指定目录（验证第 3 章渲染）")
    ap.add_argument("--with-browser", action="store_true",
                    help="额外用本机真实浏览器跑一次渲染真链路"
                         "（默认关闭：自测必须在任何环境跑出同一结果）")
    args = ap.parse_args()
    _with_browser = bool(args.with_browser)

    # 自测全程关闭外部注入工具（sqlmap）。理由：
    #   ① 假应用跑在 localhost，sqlmap 对它没有额外信息价值；
    #   ② 真拉起外部进程会让自测变慢且结果依赖本机是否装了工具 ——
    #      自测必须「任何环境跑出同一结果」；
    #   ③ sqlmap 那条链路由不变量 ⑲ 用假执行体覆盖（含安全断言），
    #      比真跑一次更能验证「该拦的拦住了」。
    os.environ["AISCAN_SQLMAP"] = "off"

    # 会话池自测用的口令走环境变量导出 —— 与真实使用时完全一致的口径。
    # 不变量 ⑳ 会额外验证「环境变量缺失时登录必须失败」，
    # 保证这条链路上不存在「两侧同为空所以算相等」的假通过。
    os.environ[TEST_LOGIN_PASS_ENV] = TEST_LOGIN_PASS

    srv, port = start_app()
    domain = "127.0.0.1"
    target_url = f"http://127.0.0.1:{port}"
    print(f"假应用已启动：{target_url}")

    patch_network(domain, open_port=port)

    checklist = load_checklist()
    app = all_applicable(checklist)
    client = HttpProbeClient({"rate": {"timeout_seconds": 5, "requests_per_second": 500}})

    # ---- 先跑 JS 分析：大量检测器（客户端类、供应链类）依赖它的产出 ----
    # 直接把 ctx.js_result 留空去跑，等于把这批检测器全部变成「未执行」，
    # 测不出它们到底能不能干活。
    from engine.js_analyzer import JsAnalyzer  # noqa: PLC0415

    js_result: dict[str, Any] = {}
    try:
        jr = JsAnalyzer(client).analyze(target_url)
        js_result = {
            "urls": list(jr.urls),
            "components": list(jr.components),
            "bodies": list(jr.bodies),
            "inline_scripts": list(jr.inline_scripts),
        }
        print(f"JS 分析：抓取 {jr.scripts_fetched} 份产物，"
              f"提取接口地址 {len(jr.urls)} 条，"
              f"识别组件 {len(jr.components)} 个")
    except Exception as e:  # noqa: BLE001
        print(f"[警告] JS 分析失败：{type(e).__name__}: {e}")

    ctx = build_context(
        target_name="自测目标",
        domain=domain,
        target_url=target_url,
        profile={"_key": "deep", "risk_level": "deep",
                 "write_verification": "controlled"},
        profile_key="deep",
        fp_result={"path_probes": {}},
        js_result=js_result,
        nuclei_findings=[],
        accounts=[{"name": "u1"}, {"name": "u2"}],
        client=client,
        # 自测跑的是本地假应用，写操作无外部副作用 —— 这里显式声明「台账已授权写」，
        # 目的是让全量检查项**全部**有执行记录（保持覆盖面基线）。
        # 「未授权时写必须关闭」由不变量 ⑯ 单独钉住。
        ledger_write_authorized=True,
    )

    try:
        results, findings = run_all_items(checklist, app, ctx)

        # ---- 复现链路：生成脚本 → 执行 → 准入闸门 ----
        # 这一段以前是缺的：自测只跑检测器，不跑复现，结果 verify_script /
        # verify_result 全为空，而报告里却写着「每项均附可独立执行的复现脚本」。
        # 现在补上，并让自测直接断言「写进漏洞清单的每条都能复现」。
        out_root = Path(args.report) if args.report else (ROOT / "outputs" / "_selftest")
        vdir = out_root / "verify"
        verify_runs: list[Any] = []
        gate_result: Any = None
        generated: list[Path] = []
        try:
            from engine.gate import ReportGate  # noqa: PLC0415
            from verify.framework import ScriptBuilder, VerifyRunner  # noqa: PLC0415

            # 只执行**本次生成**的脚本。产出目录里可能残留上一轮的脚本
            # （清理操作在某些环境会被安全策略拦下），直接 glob 会把两轮
            # 扫描的结果混进同一份闸门统计里。
            generated = ScriptBuilder(vdir).generate_all(findings, target_url)
            verify_runs = VerifyRunner(vdir).run_paths(sorted(set(generated)))
            gate_result = ReportGate().evaluate(
                findings, runs=verify_runs, verify_ran=True,
                verify_note=f"自测生成并执行 {len(verify_runs)} 份复现脚本")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"[警告] 复现链路执行失败：{type(e).__name__}: {e}")
            print(traceback.format_exc()[:800])
    finally:
        srv.shutdown()

    summary = summarize(results)
    problems: list[str] = []

    # ---- 不变量 ①：状态合法 ----
    for r in results:
        if r.state not in ALL_STATES:
            problems.append(f"{r.item_id} 结论非法：{r.state!r}")

    # ---- 不变量 ②：通过必须有执行凭据 ----
    for r in results:
        if r.state == STATE_PASS:
            if not r.executable:
                problems.append(f"{r.item_id} 判「通过」但没有执行记录（典型假阴性）")
            if not r.evidence_kind:
                problems.append(f"{r.item_id} 判「通过」但未声明证据类型")

    # ---- 不变量 ③：非「通过」必须有说明 ----
    for r in results:
        if r.state in (STATE_FIND, STATE_NA, STATE_PENDING, STATE_SKIP, "未执行"):
            if not (r.note or "").strip():
                problems.append(f"{r.item_id} 结论为「{r.state}」但未说明原因")

    # ---- 不变量 ④：人工项必须有步骤与判定标准 ----
    for r in results:
        if r.state == "待人工执行":
            spec = registry_runner.build_registry().get(r.item_id)
            if spec is None or spec.mode != MODE_MANUAL:
                problems.append(f"{r.item_id} 判为人工项但注册表里不是人工模式")
            elif not spec.procedure or not spec.expect or not spec.why_manual:
                problems.append(f"{r.item_id} 人工项步骤 / 判定标准 / 原因缺失")

    # ---- 不变量 ⑤：埋的问题要被抓到 ----
    by_item: dict[str, list[str]] = {}
    for f in findings:
        by_item.setdefault(f.item_id, []).append(f.title)
    expected = {
        "WSTG-CONF-04": "敏感文件暴露（.env / .git）",
        "WSTG-CONF-04": "目录列表或敏感文件",
        "EXT-CD-03": "版本控制与配置泄露",
        "EXT-DP-01": "响应中明文敏感数据",
    }
    missed = [k for k in expected if k not in by_item]

    # ---- 不变量 ⑥：复现脚本必须全部可编译 ----
    # 脚本是交付物的一部分，语法错 = 交付物是坏的。
    # 只校验本次生成的脚本（产出目录可能残留上一轮的）
    #
    # 这里必须用 -W error::SyntaxWarning 编译，而不是默认编译 ——
    # 默认编译对「非法转义序列」只发告警不报错，于是这类缺陷会静默存活。
    # 实测踩过：证据里的 JSON 转义残留（`\"`）被带进生成的脚本，
    # 复现脚本的特征串被改成了 `{\object\:\list`，与真实响应永远匹配不上，
    # 一个真实存在的问题被工具自己的脚本判成「未复现」，从漏洞清单里掉出去。
    script_srcs = sorted(set(generated))
    compile_fail: list[str] = []
    for p in script_srcs:
        src = p.read_text(encoding="utf-8")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                compile(src, p.name, "exec")
        except SyntaxError as e:
            compile_fail.append(f"{p.name}: {e}")
        except SyntaxWarning as e:
            compile_fail.append(f"{p.name}: 非法转义序列告警（交付物必须零告警）：{e}")

    # ---- 不变量 ⑥-b：特征串抽出来必须与「响应原文」一致 ----
    # 复现脚本靠这些串去响应里找证据。串在「进脚本」的过程中被改动一次，
    # 复现就会稳定失败，而报告上看起来像「目标已修复」。
    try:
        from verify.repro_templates import _extract_markers, _markers_literal  # noqa: PLC0415

        class _Ev:  # noqa: D401
            kind = "response"
            # 证据是 json.dumps 的产物：响应原文 {"object":"list","data":[]}
            # 在这里被转义成 \"object\" 这个样子。这是问题的最初来源。
            content = '{"v1/models": "{\\"object\\":\\"list\\",\\"data\\":[]}"}'

        class _F:  # noqa: D401
            evidence = [_Ev()]

        _ms = _extract_markers(_F())
        if not _ms:
            problems.append("特征串抽取：从 JSON 形态的证据里一条特征串都没抽到"
                            "（复现脚本将失去断言依据）")
        for _m in _ms:
            if "\\" in _m:
                problems.append(f"特征串抽取残留了转义反斜杠：{_m!r} —— "
                                "与真实响应匹配不上，会把真问题判成「未复现」")
        if _ms and '{"object":"list","data":[]}' not in _ms:
            problems.append(f"特征串抽取未还原出响应原文（得到 {_ms!r}）"
                            "—— 期望拿到 JSON 解码后的字符串值")
        # 转义往返：进脚本再读回来必须一致（引号与反斜杠都不能被改动）
        _rt = _markers_literal(['{"a":"b"}', "C:\\Windows\\win.ini", "a'b"])
        if json.loads(_rt) != ['{"a":"b"}', "C:\\Windows\\win.ini", "a'b"]:
            problems.append("复现脚本生成器：特征串转义往返不一致"
                            "（引号 / 反斜杠 / 单引号被改动）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"复现脚本特征串校验未能执行：{type(e).__name__}: {str(e)[:120]}")

    # ---- 不变量 ⑥-c：复现脚本的默认目标必须贴合「发现所在的端点」----
    # 2026-09-28 真实事故（internal-app.example.com 实测）：
    # 桶发现的 endpoint 是目标自有的 OSS 桶
    # （内部生产系统-files.oss-cn-hangzhou.aliyuncs.com）。它不是站点的子域，
    # 于是「同主机 / 子域」这条判据把它当成站外地址，复现脚本回落去打网站首页；
    # 网站对任意路径都返回同一张 HTML，脚本据此判「自定义错误页，非真实暴露」，
    # 退出码 1 → 准入闸门把一条**实测存在的严重暴露**挡在漏洞清单之外，
    # 而报告上只写着「未复现，可能已修复」。人工复核才翻出真相。
    #
    # 这类静默漏报比误报更坏：误报会有人来质疑，漏报只能靠人再手工翻一遍。
    # 所以判据要正反两面都钉住 —— 该认的（目标自有桶）要认，
    # 不该认的（第三方情报源、前缀像目标的站外主机）必须继续回落。
    try:
        from models import Finding  # noqa: PLC0415
        from verify.framework import ScriptBuilder  # noqa: PLC0415

        def _rb(ep: str, extra: dict | None = None,
                tgt: str = "https://internal-app.example.com") -> str:
            _f = Finding(item_id="X", title="t", target="t", endpoint=ep)
            _f.extra = dict(extra or {})
            return ScriptBuilder._repro_base(_f, tgt)

        _cases = [
            ("https://内部生产系统-files.oss-cn-hangzhou.aliyuncs.com/",
             {"repro_base": "https://内部生产系统-files.oss-cn-hangzhou.aliyuncs.com"},
             "https://内部生产系统-files.oss-cn-hangzhou.aliyuncs.com",
             "检测器显式声明的端点必须被采信"),
            ("https://内部生产系统-files.oss-cn-hangzhou.aliyuncs.com/?list-type=2", None,
             "https://内部生产系统-files.oss-cn-hangzhou.aliyuncs.com",
             "目标域名派生的云存储桶（未声明也要认）"),
            ("https://api.internal-app.example.com/v1", None,
             "https://api.internal-app.example.com", "目标子域照旧沿用"),
            ("https://crt.sh/?q=%25.internal-app.example.com", None,
             "https://internal-app.example.com",
             "第三方情报源必须回落 —— 不得越出授权范围"),
            ("https://内部生产系统.evil.com/x", None,
             "https://internal-app.example.com",
             "「前缀像目标」的站外主机不得放行"),
            ("https://内部生产系统-files.s3.amazonaws.com/", None,
             "https://内部生产系统-files.s3.amazonaws.com", "其他云厂商的派生桶同样适用"),
        ]
        for _ep, _extra, _want, _why in _cases:
            _got = _rb(_ep, _extra)
            if _got != _want:
                problems.append(f"复现脚本默认目标判定错误：{_why} —— "
                                f"端点 {_ep} 得到 {_got}，期望 {_want}")
    except Exception as e:  # noqa: BLE001
        problems.append(f"复现脚本目标地址校验未能执行：{type(e).__name__}: {str(e)[:120]}")

    # ---- 不变量 ⑥-d：CORS 头必须能归属到应用才算证据 ----
    problems.extend(_cors_edge_gate_problems())

    # ---- 不变量 ⑦：漏洞清单里的每条都必须有脚本且已复现 ----
    gstats = gate_result.stats() if gate_result is not None else {}
    reportable = gate_result.reportable_findings() if gate_result is not None else []
    for f in reportable:
        if not f.verify_script:
            problems.append(f"{f.item_id} 进了漏洞清单但没有复现脚本（不可复测）")
        if f.verify_result != "confirmed":
            problems.append(f"{f.item_id} 进了漏洞清单但 verify_result={f.verify_result!r}")

    # ---- 不变量 ⑧：埋进去的问题必须「检出且复现成功」 ----
    # 只被检出、没被复现，说明检测判据与复现判据不一致 —— 那是工具缺陷，
    # 不是「目标没问题」。必须自测里暴露出来。
    rep_ids = {f.item_id for f in reportable}
    not_reproduced = [k for k in expected if k in by_item and k not in rep_ids]

    # ---- 不变量 ⑨：URL 枚举来源必须真的被采集到 ----
    # 广度问题的本质不是「字典不够大」，而是「来源太单一」：
    # 只试静态字典，就看不到 robots.txt 自己声明的路径、sitemap 收录的地址、
    # 页面里真实存在的链接、前端产物里调用的接口。
    # 这里把「来源覆盖」变成硬断言，防止以后又退回一张硬编码表。
    pool_rows: list[tuple[str, int, str]] = list(ctx._cache.get("url_pool_coverage") or [])
    pool_skipped = list(ctx._cache.get("url_pool_skipped") or [])
    pool_total = sum(n for _, n, _ in pool_rows)
    pool_sources = [src for src, n, _ in pool_rows if n > 0]
    if len(pool_sources) < 6:
        problems.append(
            f"URL 枚举来源过少（仅 {len(pool_sources)} 类：{pool_sources}）—— "
            f"说明枚举池退化成静态字典了")
    if pool_total < 120:
        problems.append(f"URL 枚举候选过少（{pool_total} 个），广度不足以支撑敏感文件审查")
    for must in ("robots", "页面链接", "前端产物", "备份后缀推导"):
        if must not in pool_sources:
            problems.append(f"URL 枚举缺少来源「{must}」")

    # ---- 不变量 ⑩：端口探测必须真的跑过（不是「无数据」）----
    port_log = net.port_scan_log()
    port_open_hits: dict[str, list[int]] = {}
    for host, rec in port_log.items():
        port_open_hits[host] = list(rec.get("open") or [])
    if not port_log:
        problems.append("端口探测未产生任何覆盖记录（端口类检测器等于没跑）")
    elif not any(port_open_hits.values()):
        problems.append("端口探测未发现任何开放端口（回环上的假应用应当被识别为开放）")

    if gate_result is None:
        problems.append("复现链路未执行：准入闸门无结果（报告将无法证明可复测）")

    # ---- 不变量 ⑪：敏感文件语义准入必须双向守得住 ----
    # 这条守的是最容易崩的一环：URL 枚举池会把应用自己的页面与接口也收进来，
    # 如果「敏感文件」检查对这些地址也放行，任何一个能打开的页面都会变成一条
    # 「敏感文件可直接下载」——脚本能复现、报告自洽，但它根本不是漏洞。
    # 反向也要守：`config.php` / `.env` / `.git/config` 这类真命中不能被误杀。
    from engine.checks.config import _classify_sensitive  # noqa: PLC0415

    class _FakeProbe:  # noqa: D401
        def __init__(self, ctype: str) -> None:
            self.headers = {"Content-Type": ctype}

    _html = _FakeProbe("text/html; charset=utf-8")
    # 必须用**真实性**的 content-type：robots.txt 实际返回 text/plain。
    # 之前这里统一用 text/html，robots.txt 是因为撞上「HTML 与后缀不符」
    # 才被判不报 —— 测试通过了，但真实扫描照样误报（真站点返回 text/plain
    # 时后缀规则生效，被报成「日志 / 文本文件」）。测试用错探针等于没测。
    _plain = _FakeProbe("text/plain")
    _xml = _FakeProbe("application/xml")
    _text_targets = {"robots.txt": _plain, "sitemap.xml": _xml,
                     "sitemap.txt": _plain, "security.txt": _plain,
                     "humans.txt": _plain}
    must_not = [
        "login", "api/user", "api/user?uid=1", "admin/", "admin/login",
        "keyword-search", "settings-page", "backup-status", "config-guide",
        "auth-login", "dashboard", "help", "about", "manifest.json",
        "data.json", "static/app.js",
    ]
    must_hit = [
        ".env", ".git/config", "server-status", "config.php", "backup.zip",
        "db.sql", "id_rsa", ".htpasswd", "credentials.json", "token.txt",
        "WEB-INF/web.xml",
    ]
    fp = [p for p in must_not if _classify_sensitive(p, _html)]
    fp += [p for p, pr in _text_targets.items() if _classify_sensitive(p, pr)]
    fn = [p for p in must_hit if not _classify_sensitive(p, None)]
    if fp:
        problems.append(f"敏感文件检查把应用自身可达地址误判为敏感文件：{fp}")
    if fn:
        problems.append(f"敏感文件检查漏掉了确定的敏感文件：{fn}")

    # ---- 不变量 ⑫：管理接口检查不能把普通登录页当管理入口 ----
    # ADMIN_PATHS 里含裸 login / signin / portal，而「页面有口令输入框」这个
    # 判据对任何登录页都成立 —— 两者叠加会把站点上每个登录页都报成
    # 「管理 / 运维接口对外可达」。这是必须堵住的误报类。
    from engine.checks.config import (  # noqa: PLC0415
        _ADMIN_PATH_HINT, _PLAIN_AUTH_PATH,
    )

    auth_paths = ["login", "signin", "user/login", "auth/login", "sso/login",
                  "account/login", "passport/login"]
    admin_paths = ["admin", "admin/login", "wp-admin", "grafana", "jenkins",
                   "console", "actuator", "system", "dashboard"]
    bad_auth = [p for p in auth_paths if not _PLAIN_AUTH_PATH.match(p)]
    bad_admin = [p for p in admin_paths
                 if not _ADMIN_PATH_HINT.search(p) or _PLAIN_AUTH_PATH.match(p)]
    if bad_auth:
        problems.append(f"普通登录页未被排除出管理接口枚举：{bad_auth}")
    if bad_admin:
        problems.append(f"真正的管理入口被漏排或误排：{bad_admin}")

    # ---- 不变量 ⑬：HTTP 通道必须直连，不得被环境代理接管 ----
    # 这条是踩坑之后补的。requests 默认 trust_env=True，会读取 HTTP_PROXY /
    # HTTPS_PROXY。一旦运行环境里有代理（企业上网代理、抓包工具、CI 沙箱），
    # 后果是：所有路径 404（代理用绝对形式请求行转发）、页面链接与 robots 采不到、
    # 检测器大面积判「目标没有该功能」→ 发现数腰斩、N/A 暴涨。
    # 症状看起来像「检测能力退化」，其实是流量被劫持。必须机械守住。
    try:
        from engine.fingerprint import PROXY_ENV_REMOVED  # noqa: PLC0415

        if os.environ.get("NO_PROXY") != "*":
            problems.append(
                "HTTP 通道未禁用环境代理（NO_PROXY != '*'）：扫描流量可能被代理接管。"
                "这会同时造成「采不到内容」与「来源 IP 变更」，两条都会让结论失真")
        _probe = ctx.probe_path("robots.txt")
        _st = getattr(_probe, "status", 0)
        if _st != 200:
            problems.append(
                f"靶场已知路由 /robots.txt 返回 {_st}（应为 200）—— "
                "HTTP 通道异常，本次自测的采集类结论不可信")
        if PROXY_ENV_REMOVED:
            print(f"\n[环境] 已禁用环境代理：{', '.join(PROXY_ENV_REMOVED)}")
    except Exception as e:  # noqa: BLE001
        problems.append(f"HTTP 通道检查未能执行：{type(e).__name__}: {str(e)[:120]}")

    # ---- 不变量 ⑭：整站同一响应不得被当作「功能存在」的证据 ----
    # 这条是事故之后补的。某目标被边缘防护全量拦截，**所有路径都返回 405**。
    # 特征判定把「405 = 路径存在但方法不对」当成正面证据，于是
    # /login、/admin、/api、/graphql 全部「存在」，15 项特征凭空变成「具备」，
    # 适用性被抬到 124 项；引擎随即把拦截页当应用扫，产出一整份
    # 一条也复测不出来的「漏洞」，还把端口连通当成了严重级公网暴露。
    #
    # 全程离线构造，不依赖网络：直接喂给特征判定一批「全站 405」的探测结果。
    try:
        from engine.fingerprint import FEATURE_PATHS, FeatureDeriver, HttpProbe  # noqa: PLC0415
        from engine.wafgate import (  # noqa: PLC0415
            assess_boundary, sitewide_uniform_status)

        _block_body = "<html><head><title>405</title></head><body>405 Not Allowed</body></html>"
        _paths = sorted({p for paths in FEATURE_PATHS.values() for p in paths})
        _probes = {
            p: HttpProbe(url=f"https://blocked.test/{p}", final_url=f"https://blocked.test/{p}",
                         status=405, body_snippet=_block_body,
                         headers={"Server": "Tengine"})
            for p in _paths
        }
        _root = HttpProbe(url="https://blocked.test/", final_url="https://blocked.test/",
                          status=405, body_snippet=_block_body,
                          headers={"Server": "Tengine"})

        _modal, _ratio, _n = sitewide_uniform_status(_probes)
        if _modal != 405:
            problems.append(
                f"整站同一响应未被识别：探测 {_n} 个路径全部返回 405，"
                f"却判定众数状态码为 {_modal}。这会让后续所有"
                "「路径存在」类推断同时假成立")

        _tf = FeatureDeriver().derive("拦截靶场", "https://blocked.test",
                                      _root, _probes, dns=None, preset=None)
        _falsely = [k for k, f in _tf.features.items()
                    if f.present and k not in ("tls_info", "resolved_ips")]
        if _falsely:
            problems.append(
                f"整站 405 的目标被判出「具备」特征 {_falsely} —— "
                "这些结论来自拦截页/状态码，不是应用本身；"
                "会直接抬高适用性并让检测跑在拦截页上")

        _verdict = assess_boundary(
            {"status": 405, "headers": {"Server": "Tengine"},
             "body_snippet": "", "cookies": []},
            control_fetcher=None, base_url="https://blocked.test",
            path_probes={p: pr.to_dict() for p, pr in _probes.items()})
        if not any("整站同一响应" in x for x in _verdict.notes):
            problems.append(
                "边界判定未对「整站同一响应」给出提示；"
                "未命中厂商特征时这一提示是拦住状态码类误判的唯一线索")
        print(f"\n[环境] 整站同码护栏已生效：{_n} 个路径全部 HTTP 405，"
              f"判定具备特征 0 项（不含 tls_info / resolved_ips）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"整站同码护栏检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑭-b：对照样本不足时，拦截类状态码不得「静默采信」 ----
    # ⑭ 只钉住了「样本够、判得出整站同码」那一条正向路径。
    # 而这个守卫**失败时是会朝危险方向倒的**：n < SITEWIDE_MIN_SAMPLES 时
    # sitewide_uniform_status 返回「非同码」，405/403/401 于是又被当成
    # 「路径存在」的正面证据 —— 守卫看着在，其实失效了，而且悄无声息。
    # 实测踩过：同一目标、同一份代码，某次路径探测只采到极少样本，
    # 适用性从 67 项被抬到 124 项，has_login / has_admin / has_api 全部「具备」，
    # 后续检测全跑在拦截页上。所以这里反向再钉一遍：**做不了对照 ≠ 可以采信**。
    try:
        from engine.fingerprint import (  # noqa: PLC0415
            FeatureDeriver as _FD2,
            HttpProbe as _HP2,
            path_hit_usable,
        )
        from engine.wafgate import SITEWIDE_MIN_SAMPLES as _MIN2  # noqa: PLC0415
        from engine.wafgate import sitewide_uniform_status as _sus2  # noqa: PLC0415

        # 纯函数层：三向都要钉住，漏任何一向都会让回退重新变得静默
        if path_hit_usable(405, 0, max(0, _MIN2 - 2)):
            problems.append(
                f"样本不足（{_MIN2 - 2} 个）时 405 仍被判为可用 —— 无对照就采信，"
                "会把「边缘统一拦截」当成「该路径存在」")
        if not path_hit_usable(200, 0, max(0, _MIN2 - 2)):
            problems.append("样本不足时 2xx 仍应可用：页面确实被送达，不依赖对照实验")
        if path_hit_usable(405, 405, 51):
            problems.append("整站同码时 405 仍被判为可用")

        # 端到端：只探 3 个路径、全 405（刻意低于对照下限）
        _blk2 = "<html><head><title>405</title></head><body>405 Not Allowed</body></html>"
        _few = {
            k: _HP2(url=f"https://few.test/{k}", final_url=f"https://few.test/{k}",
                    status=405, body_snippet=_blk2, headers={"Server": "Tengine"})
            for k in ("login", "admin", "api")
        }
        _root2 = _HP2(url="https://few.test/", final_url="https://few.test/",
                      status=405, body_snippet=_blk2, headers={"Server": "Tengine"})
        _m2, _r2, _n2 = _sus2(_few)
        if _m2 != 0 or _n2 >= _MIN2:
            problems.append(f"前置不成立：{_n2} 个样本不应构成整站同码（modal={_m2}）")
        _tf2 = _FD2().derive("样本不足靶场", "https://few.test",
                             _root2, _few, dns=None, preset=None)
        _bad2 = [k for k, f in _tf2.features.items()
                 if f.present and k not in ("tls_info", "resolved_ips")]
        if _bad2:
            problems.append(
                f"路径探测样本仅 {_n2} 个（低于对照下限 {_MIN2}）时，仍从拦截类"
                f"状态码判出「具备」特征 {_bad2} —— 守卫静默失效，适用性被凭空放大")
        if not any("对照未能生效" in x for x in _tf2.notes):
            problems.append(
                "样本不足导致对照失效时**必须显式披露** —— 不说，读者会把"
                "「适用 67 项」与「适用 124 项」当成目标变了，其实是判据没跑起来")
        print(f"[环境] 样本不足护栏已生效：仅 {_n2} 个样本"
              f"（下限 {_MIN2}）时不再采信拦截类状态码，具备特征 0 项")
    except Exception as e:  # noqa: BLE001
        problems.append(f"样本不足护栏检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑭-c：状态码被打散时，必须由**正文口径**接管 ----
    # ⑭ 与 ⑭-b 钉的都还是状态码口径。这个口径有第三种失效方式，而且连
    # ⑭-b 的「样本不足」提示都打不出来：**样本足够**（n ≥ 5），但边缘对同一批
    # 请求返回**混合**状态码 —— 限速、挑战、部分放行、多节点行为不一致都会让
    # 众数占比跌破 80%。此时 `sitewide_uniform_status` 判「非同码」，405/403
    # 又被当成「路径存在」的证据；而 `_no_contrast` 只查 n < 5，于是
    # **一条提示都不会打**。
    # 2026-09-29 实测踩到：同一目标、同一份代码，适用性从 67 项抬到 124 项，
    # has_login / has_admin / has_api 全部「具备」，零提示。那时唯一还成立的
    # 线索是：正文**归一化后仍然完全相同**（剔除 traceid / acw_tc 等易变标识），
    # 且该页面命中拦截页厂商特征。
    #
    # 两个方向都要钉，缺一边都不算修好：
    #   正：混合状态码 + 拦截页正文 → 必须判为「整站被接管」，路径类特征转 unknown；
    #   反：正文同码但**没有**厂商特征（SPA 兜底路由）→ **不得**判为拦截 ——
    #       否则一个完全正常的单页应用会被整场判成「未执行」，那比漏判更难发现。
    try:
        from engine.fingerprint import (  # noqa: PLC0415
            FEATURE_PATHS as _FP3,
            FeatureDeriver as _FD3,
            HttpProbe as _HP3,
        )
        from engine.wafgate import SITEWIDE_DOMINANCE as _DOM3  # noqa: PLC0415
        from engine.wafgate import (  # noqa: PLC0415
            detect_block_page as _dbp3,
            representative_probe as _rp3,
            sitewide_uniform_body as _sub3,
            sitewide_uniform_status as _sus3,
            status_mix as _sm3,
        )

        _ali3 = ('<!doctypehtml><html lang="zh-cn"><title>405</title>'
                 '<script>function getRenderData(){}</script>'
                 '<img src="https://errors.aliyun.com/images/TB1.png">'
                 '<div>很抱歉，由于您访问的URL有可能对网站造成安全威胁，'
                 '您的访问被阻断。</div></html>')
        _all3 = sorted({p for ps in _FP3.values() for p in ps})

        # 12 个路径、3 种状态码：最高频的 405 只占 5/12 ≈ 42%，远低于阈值
        _mix3 = {}
        for _i3, _p3 in enumerate(_all3[:12]):
            _mix3[_p3] = _HP3(
                url=f"https://mix.test/{_p3}", final_url=f"https://mix.test/{_p3}",
                status=405 if _i3 < 5 else (403 if _i3 < 9 else 200),
                body_snippet=_ali3, headers={"Server": "Tengine"})

        # 前置条件必须成立，否则后面几条断言会变成空跑（这个坑本轮踩过一次）
        _m3, _r3, _n3 = _sus3(_mix3)
        if _m3:
            problems.append(
                f"前置不成立：混合状态码不该被状态码口径判成整站同码"
                f"（modal={_m3} / {_r3:.0%}）")
        if _n3 < 5:
            problems.append(f"前置不成立：正文口径需 ≥5 个样本，当前只有 {_n3} 个")
        _sm3v, _sr3, _sn3 = _sm3(_mix3)
        if not (_sm3v == 405 and _sr3 < _DOM3):
            problems.append(
                f"前置不成立：最高频状态码应为 405 且占比低于 {_DOM3:.0%}"
                f"（实为 {_sm3v} / {_sr3:.0%}）")

        _h3, _hr3, _hn3 = _sub3(_mix3)
        if not _h3:
            problems.append(
                "混合状态码下正文口径未能识别出「整站同一张页」—— 这个洞会让"
                "适用性被凭空放大，而且不会有任何提示")
        _rpv = _rp3(_mix3, _h3)
        _bl3, _vn3, _wy3 = _dbp3(
            int(getattr(_rpv, "status", 0) or 0), getattr(_rpv, "headers", None),
            getattr(_rpv, "body_snippet", "") or "", getattr(_rpv, "cookies", None))
        if not _bl3:
            problems.append(f"代表探针未命中拦截页特征，两个口径无法叠加：{_wy3}")

        # 端到端：混合状态码 + 拦截页正文 → 不得判出任何「具备」类特征
        _root3 = _HP3(url="https://mix.test/", final_url="https://mix.test/",
                      status=405, body_snippet=_ali3, headers={"Server": "Tengine"})
        _tf3 = _FD3().derive("混合状态码靶场", "https://mix.test",
                             _root3, _mix3, dns=None, preset=None)
        _pf3 = [k for k, f in _tf3.features.items()
                if f.present and k not in ("tls_info", "resolved_ips")]
        if _pf3:
            problems.append(
                f"混合状态码 + 拦截页正文时仍判出「具备」特征 {_pf3} —— "
                "这正是 2026-09-29 那次适用性 67 → 124 的成因")
        if not any("整站同一响应" in x for x in _tf3.notes):
            problems.append(
                "状态码被打散、改由正文口径判出拦截时**必须显式披露** —— "
                "不披露，读者只会看到适用性凭空变大而找不到原因")
        _ev3 = " ".join(f.evidence or "" for f in _tf3.features.values())
        if "HTTP 0" in _ev3 or "占比 0%" in _ev3:
            problems.append(
                "正文口径命中时依据文案仍在硬写状态码，渲染出「HTTP 0」/"
                "「占比 0%」—— 自相矛盾的证据会让整份报告失去可信度")

        # ---- 反向：SPA 兜底同页**不得**被判成拦截 ----
        _spa3 = ('<html><head><title>App</title></head><body>'
                 '<div id="root"></div><script src="/static/app.js"></script>'
                 '</body></html>')
        _spa3p = {
            _p3: _HP3(url=f"https://spa.test/{_p3}", final_url=f"https://spa.test/{_p3}",
                      status=200, body_snippet=_spa3, headers={"Server": "nginx"})
            for _p3 in _all3[:10]
        }
        _roots = _HP3(url="https://spa.test/", final_url="https://spa.test/",
                      status=200, body_snippet=_spa3, headers={"Server": "nginx"})
        _tfspa = _FD3().derive("SPA 靶场", "https://spa.test", _roots, _spa3p,
                               dns=None, preset=None)
        _badspa = [k for k, f in _tfspa.features.items()
                   if "目标疑似对任意路径返回同一张页面" in (f.evidence or "")]
        if _badspa:
            problems.append(
                f"SPA 兜底路由的「整站同一张页」被当成了边界接管 {_badspa} —— "
                "正常的单页应用会被整场判成「未执行」，比漏判更难被发现")
        if not any("不据此判「整站被接管」" in x for x in _tfspa.notes):
            problems.append(
                "正文同码但未命中拦截页特征时**必须披露**且**不得替读者选边** —— "
                "「应用兜底路由」与「自研防护统一接管」在本步无法区分，"
                "两种处置完全相反，写死一个方向就是给读者一个错误的前提")

        print(f"[环境] 混合状态码护栏已生效：{_n3} 个样本中最高频者 HTTP {_sm3v} "
              f"仅占 {_sr3:.0%}（阈值 {_DOM3:.0%}），状态码口径不成立、"
              f"由正文口径接管，具备特征 0 项；SPA 同页未被误判为拦截")
    except Exception as e:  # noqa: BLE001
        problems.append(f"混合状态码护栏检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑮：扫描中途出现的边界封禁必须被检出并转入终态 ----
    # A 类（一开扫就被拦）的结论是诚实的「无法评估」；B 类（扫到一半被拉黑）
    # 不察觉则更坏 —— 后半段会把拦截页当应用扫完。这里用离线假 fetch
    # 走一遍完整的「检测 → 退避 → 终态 → 短路后续检查项」链路。
    try:
        from engine.banguard import BoundaryGuard  # noqa: PLC0415
        from engine.registry_runner import _guard_tick  # noqa: PLC0415

        _BLOCK = "<html><body><h1>405 Not Allowed</h1></body></html>"
        _HOME = "<html><body><h1>首页</h1></body></html>"
        _ban = {"on": False}

        def _fx(u: str) -> dict:
            b = _ban["on"]
            return {"status": 405 if b else 200,
                    "body_snippet": _BLOCK if b else _HOME,
                    "headers": {}, "cookies": []}

        _slept: list[float] = []
        _g = BoundaryGuard(_fx, sleep=_slept.append, budget_s=50.0,
                           check_every=25)
        _g.arm("https://midban.test/", 200, _HOME)

        class _Ctx:
            _cache: dict = {}
            probe_count = 0
            _client = None

        _c = _Ctx()
        _guard_tick(_g, _c)                     # 抽检一次：此时目标正常
        if _g.report.occurred:
            problems.append("正常响应被判「扫描中途封禁」—— 守门误报会"
                            "打断本可完成的扫描")

        _ban["on"] = True                       # 扫描到一半，目标开始全量拦截
        _c.probe_count = 30                     # 越过抽检节流阈值
        _guard_tick(_g, _c)                     # 应检出、退避、转终态
        if not _g.report.occurred:
            problems.append("扫描中途开始全量拦截，守门未检出 —— "
                            "后续检查项会把拦截页当成应用页面继续扫")
        if not _g.report.terminal:
            problems.append("封禁后未能恢复却未转入终态 —— 扫描会带着"
                            "被污染的结论继续跑完")
        if _c._cache.get("boundary_block", {}).get("kind") != "mid_scan_ban":
            problems.append("封禁终态未写入检测上下文 —— 后续检查项不会被"
                            "短路成「未执行」，会产出建立在拦截页上的假结论")
        if "不得据此认为通过" not in (_g.report.terminal_reason or ""):
            problems.append("终态措辞未显式禁止把「未执行」读成「通过」")
        print(f"\n[环境] 中途封禁守门已生效：检出封禁并转终态，"
              f"退避等待 {_g.report.total_waited_s:.0f}s 后放弃，"
              f"后续检查项一律「未执行」")

        # ---- 不变量 ⑮-b：终态**先于逐项检测**成立时，门控必须照常生效 ----
        # 2026-09-29 内部生产系统 实测事故：封禁在 L2 采集期间就转 persistent，
        # 逐项检测随后开始时 tick() 因终态恒返回 None，而门控原先只在
        # 「拿到本次事件」时才写短路标记 —— 于是全量检查项在 405 拦截页上
        # 全部跑完，产出 73 项假通过 + 16 项假不通过。
        # 这里模拟「终态已成立后才进入逐项循环」：把上下文清空后，
        # 在**没有任何新事件**的前提下调用门控，短路标记必须照样写进去。
        _ALIYUN = ("<html><body><h1>405 Not Allowed</h1>"
                   "<p><a href='https://errors.aliyun.com'>errors.aliyun.com</a></p>"
                   "</body></html>")

        def _fxa(u: str) -> dict:
            return {"status": 405, "body_snippet": _ALIYUN,
                    "headers": {}, "cookies": []}

        _g2 = BoundaryGuard(_fxa, sleep=_slept.append, budget_s=50.0)
        _g2.arm("https://preban.test/", 200, _HOME)
        _g2.check()                       # L2 期间就已终态
        if not _g2.report.terminal:
            problems.append("预置终态未成立，⑮-b 的前提不成立（用例本身失效）")
        _c2 = _Ctx()
        _c2._cache = {}                   # 彻头彻尾干净的上下文
        if _g2.tick(0) is not None:
            problems.append("终态后 tick 仍返回事件 —— 不该再抽检（白耗对方容忍度）")
        _guard_tick(_g2, _c2)
        if _c2._cache.get("boundary_block", {}).get("kind") != "mid_scan_ban":
            problems.append(
                "终态先于逐项检测成立时，门控未写入短路标记 —— "
                "整段逐项检测会在拦截页上跑完（内部生产系统 事故原形）")
        if _c2._cache.get("boundary_block", {}).get("vendor") != "阿里云 WAF":
            problems.append(
                "短路标记未带拦截页厂商 —— 报告只能写「厂商特征未确认」，"
                "而特征明明命中了（证据在手上却没接到消费方）")

        # 已恢复的封禁不得被当成「此刻仍被封」：否则后续检查项会被
        # 整批误短路成「未执行」，那是用另一个错误换掉这个错误。
        _state = {"n": 0}

        def _fxr(u: str) -> dict:
            _state["n"] += 1
            if _state["n"] <= 2:
                return {"status": 405, "body_snippet": _BLOCK,
                        "headers": {}, "cookies": []}
            return {"status": 200, "body_snippet": _HOME,
                    "headers": {}, "cookies": []}

        _g3 = BoundaryGuard(_fxr, sleep=_slept.append)
        _g3.arm("https://resumed.test/", 200, _HOME)
        _ev3 = _g3.check()
        if _ev3 is None or _ev3.outcome != "resumed":
            problems.append(f"用例本身失效：期望 resumed，实为 {_ev3}")
        _c3 = _Ctx()
        _c3._cache = {}
        _guard_tick(_g3, _c3)
        if _c3._cache.get("boundary_block"):
            problems.append(
                "已恢复的封禁被判成「仍在封禁中」—— 后续检查项会被误短路，"
                "用错误的「未执行」换掉本可拿到的结论")
        print("[环境] 终态先成立时的门控亦生效（含厂商回填）；"
              "已恢复的封禁不误短路")

        # ---- 不变量 ⑮-c：逐项检测前的短路判据必须两类同权 ----
        # 内部生产系统 事故的另一半：逐项检测**开始前**的短路只认 A 类（L1 全量拦截），
        # B 类（运行期终态）那一支根本不存在。它不报错、只静默放行全量检查项。
        from engine.orchestrator import boundary_short_circuit  # noqa: PLC0415

        class _V:
            blocked = True
            vendor = "阿里云 WAF"
            status = 405

        _p_a, _n_a = boundary_short_circuit(True, _V(), None)
        if not _p_a or _p_a.get("kind") is not None:
            problems.append("A 类短路标记形态变了（不应带 mid_scan_ban）")
        if _p_a.get("vendor") != "阿里云 WAF" or int(_p_a.get("status")) != 405:
            problems.append("A 类短路标记未携带厂商 / 状态码")
        if "未执行" not in (_n_a or ""):
            problems.append("A 类短路说明未点明「未执行」")

        _p_b, _n_b = boundary_short_circuit(False, None, _g2)
        if not _p_b or _p_b.get("kind") != "mid_scan_ban":
            problems.append(
                "B 类（运行期终态）在逐项检测前未短路 —— "
                "全量检查项会在拦截页上跑完（内部生产系统 事故原形，本用例即为其断言的钉子）")
        if _p_b.get("vendor") != "阿里云 WAF":
            problems.append("B 类短路标记未携带厂商（报告只能写「厂商特征未确认」）")
        if "不得把「未执行」读成「通过」" not in (_n_b or ""):
            problems.append("B 类短路说明未禁止把「未执行」读成「通过」")

        if boundary_short_circuit(False, None, None) != (None, ""):
            problems.append("无拦截时不得写短路标记")
        _p_r, _n_r = boundary_short_circuit(False, None, _g3)
        if _p_r is not None or _n_r:
            problems.append(
                "已恢复的封禁（occurred 但未终态）不得短路 —— "
                "那会把本可拿到的结论整批变成「未执行」")
        print("[环境] 逐项检测前的短路两类同权（A 类 / B 类均短路，已恢复不短路）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"中途封禁守门检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑮-d：报告承接必须回溯**多轮**，不能只看上一轮 ----
    # 2026-09-30 安全负责人指出：「问题清单怎么能为空呢，之前的报告里还有严重和
    # 中危漏洞」。查归档发现正是这个形态 —— 报出严重漏洞那轮（9 条）与
    # 「0 条」那轮中间**隔了一轮**；只看上一轮，那条严重漏洞就凭空消失了。
    # 这里把三种情形全钉住：多轮回溯取到 / 本轮有结论不承接 / 被有效轮次清掉。
    try:
        import tempfile as _tf  # noqa: PLC0415

        from engine.orchestrator import Orchestrator  # noqa: PLC0415
        from models import Finding, FindingSet  # noqa: PLC0415

        def _mkf(iid, title, sev, endpoint):
            return Finding(item_id=iid, title=title, target="承接自测",
                           endpoint=endpoint, method="GET", severity=sev,
                           confidence="High", evidence_level="A",
                           description="自测", impact="自测", remediation="自测")

        def _write_run(base, name, findings, states, weak_ids=()):
            d = base / name
            d.mkdir(parents=True, exist_ok=True)
            fs = FindingSet(target="承接自测")
            for f in findings:
                fs.add(f)
            fs.save(d / "承接自测_findings.json")
            _items = []
            for k, v in states.items():
                _it = {"item_id": k, "state": v}
                if k in weak_ids:
                    _it["weak_na"] = True
                _items.append(_it)
            (d / "检查项结论.json").write_text(json.dumps(
                {"target": "承接自测", "items": _items},
                ensure_ascii=False), encoding="utf-8")
            return d

        _NO = "未执行"
        with _tf.TemporaryDirectory() as _td:
            _base = Path(_td)
            # ① 最早一轮：真报出问题（含一条严重）
            _write_run(_base, "20260101_100000",
                       [_mkf("WSTG-CONF-11", "对象存储桶允许匿名列举", "严重",
                             "https://x-files.oss-cn-hangzhou.aliyuncs.com"),
                        _mkf("EXT-DM-03", "域名未配置 DMARC 记录", "中危",
                             "DNS TXT _dmarc.x.test")],
                       {"WSTG-CONF-11": "不通过", "EXT-DM-03": "不通过"})
            # ② 中间一轮：整场被边界拦住 —— 0 条发现，逐项全是「未执行」
            _write_run(_base, "20260102_100000", [],
                       {"WSTG-CONF-11": _NO, "EXT-DM-03": _NO})
            # ③ 上一轮：同样 0 条（这就是「只看上一轮」会漏光的形态）
            _write_run(_base, "20260103_100000", [],
                       {"WSTG-CONF-11": _NO, "EXT-DM-03": _NO})
            # ④ 本轮（必须被排除）
            _cur = _write_run(_base, "20260104_100000", [],
                              {"WSTG-CONF-11": _NO, "EXT-DM-03": _NO})

            class _R:
                def __init__(self, iid, state, weak_na=False):
                    self.item_id, self.state = iid, state
                    self.weak_na = weak_na

            _res = [_R("WSTG-CONF-11", _NO), _R("EXT-DM-03", _NO)]
            _got = Orchestrator._collect_prior_unverified(_cur, _res)
            _ids = {e["item_id"] for e in _got}
            if _ids != {"WSTG-CONF-11", "EXT-DM-03"}:
                problems.append(
                    f"承接未回溯多轮：期望取到 {{CONF-11, DM-03}}，实为 {_ids} —— "
                    "只看上一轮会让「隔了一轮无效扫描」的历史发现凭空消失")
            if not any(e["severity"] == "严重" for e in _got):
                problems.append("承接项丢了等级 —— 只给数字读者排不出优先级")
            if any(e.get("from_run") != "20260101_100000" for e in _got):
                problems.append("承接项未标明来自哪一轮（技术版要能点名出处）")
            if any(e["item_id"] == "WSTG-CONF-11" and "匿名列举" not in e["title"]
                   for e in _got):
                problems.append("承接项的标题被改写 —— 读者对不上历史报告")

            # ⑤ 本轮该项**有结论** → 不得承接（本轮已经替它说话了）
            _got2 = Orchestrator._collect_prior_unverified(
                _cur, [_R("WSTG-CONF-11", "通过"), _R("EXT-DM-03", _NO)])
            if any(e["item_id"] == "WSTG-CONF-11" for e in _got2):
                problems.append(
                    "本轮该项已「通过」却仍被承接 —— 承接块塞进复看过的项，"
                    "会让读者对整块失去信任")
            if not any(e["item_id"] == "EXT-DM-03" for e in _got2):
                problems.append("一项有结论不得连带把另一项也漏掉")
            # ⑥ 「不通过」也不算「没去看」：本轮有结论，同样不承接
            _got3 = Orchestrator._collect_prior_unverified(
                _cur, [_R("WSTG-CONF-11", "不通过")])
            if any(e["item_id"] == "WSTG-CONF-11" for e in _got3):
                problems.append("本轮「不通过」被误判成「没有结论」")

        # ⑦ 中央一轮以「通过 / N/A」清掉的项，不得从更老的轮次里再翻出来
        with _tf.TemporaryDirectory() as _td2:
            _b2 = Path(_td2)
            _write_run(_b2, "20260101_100000",
                       [_mkf("EXT-DM-03", "域名未配置 DMARC 记录", "中危",
                             "DNS TXT _dmarc.x.test")],
                       {"EXT-DM-03": "不通过"})
            _write_run(_b2, "20260102_100000", [], {"EXT-DM-03": "通过"})
            _cur2 = _write_run(_b2, "20260103_100000", [], {"EXT-DM-03": _NO})
            _got4 = Orchestrator._collect_prior_unverified(
                _cur2, [_R("EXT-DM-03", _NO)])
            if any(e["item_id"] == "EXT-DM-03" for e in _got4):
                problems.append(
                    "被「通过」清掉的项仍被更老的轮次翻了出来 —— "
                    "这会把已修复的问题重新算成未复测")

        # ⑦-b 历史轮次以**弱证据 N/A** 判定的项，同样没有推翻历史的资格。
        # 归档里的 `weak_na` 必须被读到 —— 只在本轮内存结果里区分强弱是不够的：
        # 「上一轮我们自己也只探了几个路径」这个事实只存在于归档里，
        # 漏读它，更早那条实测证实的严重漏洞就会被上一轮的弱 N/A 清掉。
        with _tf.TemporaryDirectory() as _td3:
            _b3 = Path(_td3)
            _write_run(_b3, "20260101_100000",
                       [_mkf("WSTG-CONF-11", "对象存储桶允许匿名列举", "严重",
                             "https://x-files.oss-cn-hangzhou.aliyuncs.com")],
                       {"WSTG-CONF-11": "不通过"})
            _write_run(_b3, "20260102_100000", [],
                       {"WSTG-CONF-11": "N/A"}, weak_ids={"WSTG-CONF-11"})
            _cur3 = _write_run(_b3, "20260103_100000", [],
                               {"WSTG-CONF-11": _NO})
            _got5 = Orchestrator._collect_prior_unverified(
                _cur3, [_R("WSTG-CONF-11", _NO)])
            if not any(e["item_id"] == "WSTG-CONF-11" for e in _got5):
                problems.append(
                    "上一轮以**弱证据 N/A**（有限路径没看到）判定后，"
                    "更早那条实测证实的严重漏洞未被承接 —— "
                    "弱 N/A 只是「没看到」，不该有推翻历史的能力")
            # 对照：把同一轮的 N/A 改成**强证据**，就应当清项（确证不具备）
            _write_run(_b3, "20260102_100000", [], {"WSTG-CONF-11": "N/A"})
            _got6 = Orchestrator._collect_prior_unverified(
                _cur3, [_R("WSTG-CONF-11", _NO)])
            if any(e["item_id"] == "WSTG-CONF-11" for e in _got6):
                problems.append(
                    "上一轮已**确证不具备**该特征（强 N/A）却仍翻出更早的报法 —— "
                    "那会把已修复的问题重新算成未复测")

        # ⑧ 判定用的「没有结论」状态必须与 diff 层同源（防两处各写一份漂移）
        #
        # 2026-09-30 起多了第五项：**弱证据 N/A**。它的含义是「有限路径探测
        # 没看到」，和「未执行」一样不能支撑任何结论 —— 把它排除在外，
        # 一次「没看到」就会把此前实测证实的严重漏洞清掉（与「隔一轮 0 条」
        # 是同一类错误，只是入口不同）。守卫仍保留「不许悄悄变」的作用：
        # 变了就必须来复核承接判据。
        from diff.differ import Differ as _D  # noqa: PLC0415
        _want = {"未执行", "待人工执行", "待确认", "已跳过", _D.WEAK_NA_STATE}
        if set(_D.NO_CONCLUSION_STATES) != _want:
            problems.append(
                f"diff 层的「没有结论」状态集合变了：{_D.NO_CONCLUSION_STATES} —— "
                "承接判据直接引用它，变了要一起复核")

        # ⑨ 本轮判**弱证据 N/A** 时，历史发现必须照常承接 ——
        # 弱 N/A 的确切含义是「没看到」，不是「确证不具备」。
        # 若把它当成「本轮有结论且没问题」，一条已实测证实的严重漏洞
        # 会因为「路径探测没命中」而从通告里凭空消失。
        # ⚠ 必须自带历史目录：上面 `_td` 的 `with` 块已退出，`_cur` 指向的
        #   目录已被删除 —— 复用它只会得到空集合，测出来的「通过」是假的。
        with _tf.TemporaryDirectory() as _td4:
            _b4 = Path(_td4)
            _write_run(_b4, "20260101_100000",
                       [_mkf("WSTG-CONF-11", "对象存储桶允许匿名列举", "严重",
                             "https://x-files.oss-cn-hangzhou.aliyuncs.com"),
                        _mkf("EXT-DM-03", "域名未配置 DMARC 记录", "中危",
                             "DNS TXT _dmarc.x.test")],
                       {"WSTG-CONF-11": "不通过", "EXT-DM-03": "不通过"})
            _cur4 = _write_run(_b4, "20260104_100000", [], {})
            _got_w = Orchestrator._collect_prior_unverified(
                _cur4, [_R("WSTG-CONF-11", "N/A", weak_na=True),
                        _R("EXT-DM-03", "N/A", weak_na=True)])
            _w_ids = {e["item_id"] for e in _got_w}
            if _w_ids != {"WSTG-CONF-11", "EXT-DM-03"}:
                problems.append(
                    f"本轮为弱证据 N/A 时历史发现未被承接：实为 {_w_ids} —— "
                    "弱 N/A 是「没看到」而非「确证不具备」，"
                    "拿它当结论会用一次没看到推翻实测证实的严重漏洞")
            # 对照：**强证据** N/A 仍应清项（确证不具备，有资格推翻历史）
            _got_s = Orchestrator._collect_prior_unverified(
                _cur4, [_R("WSTG-CONF-11", "N/A"), _R("EXT-DM-03", "N/A")])
            if any(e["item_id"] == "WSTG-CONF-11" for e in _got_s):
                problems.append(
                    "本轮确证不具备（强 N/A）却仍被承接 —— "
                    "承接块塞进已确证不适用项会让读者对整块失去信任")
        print("[环境] 承接必须回溯多轮（有结论不承接 / 被通过清掉不翻旧账 / "
              "弱 N/A 不构成推翻历史的证据）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"承接回溯检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑯：写权限必须两把锁同时开（档位 ∩ 台账）----
    # 曾经只读档位：deep 档下**即使台账写着「写验证：不允许」**，写权限仍被判为
    # 打开 —— 写方法的 PermissionError 门控被越过，requires=["write"] 的自动
    # 检测器（含向 AI 端点 POST 注入探针的 EXT-AI-02 / EXT-AI-04）会真的发出
    # 请求。三种组合全部钉住，防止任何一侧被单独用来开门。
    try:
        _base = dict(
            target_name="写权限自测",
            domain="wtest.local",
            target_url="http://wtest.local/",
            profile={"_key": "deep", "risk_level": "deep",
                     "write_verification": "controlled"},
            profile_key="deep",
        )
        _c_unauth = build_context(**_base)                    # 档位允许 + 台账未授权
        _c_auth = build_context(**_base, ledger_write_authorized=True)
        _c_profile_deny = build_context(                          # 台账授权 + 档位禁止
            target_name="写权限自测",
            domain="wtest.local",
            target_url="http://wtest.local/",
            profile={"_key": "safe", "risk_level": "safe",
                     "write_verification": False},
            profile_key="safe",
            ledger_write_authorized=True,
        )
        if _c_unauth.allow_write:
            problems.append("档位允许写但台账未授权，写权限仍被打开 —— "
                            "台账的「写验证：不允许」形同虚设")
        if not _c_auth.allow_write:
            problems.append("档位与台账都允许写，写权限反被关闭 —— "
                            "过度收紧会让已授权的写验证永远测不出来")
        if _c_profile_deny.allow_write:
            problems.append("台账允许写但档位禁止，写权限被打开 —— "
                            "两把锁必须取「与」，不能取「或」")
        print("\n[环境] 写权限双锁已生效：档位允许+未授权 → 关；"
              "档位允许+已授权 → 开；档位禁止+已授权 → 仍关")
    except Exception as e:  # noqa: BLE001
        problems.append(f"写权限双锁检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑰：裸 IP 目标的可达范围必须判准 ----
    # 内网系统最常见的形态就是直接给一个私网 IP。这条回退不做，报告的可达范围
    # 会被写成「未取得解析地址」—— 读者读出来是「没解析出来（技术故障）」，
    # 而不是「这是私网地址、公网根本不可达」。公网基线红线要求的内网标注就此丢失，
    # 而它恰恰是内网扫描里最重要的一行。
    # 自测的 DNS 打桩对非主域名一律返回空，正好等价于「DNS 解析不出 IP」。
    try:
        from engine.checks.base import reachability_scope  # noqa: PLC0415

        class _RC:
            _client = None

            def __init__(self, d: str) -> None:
                self.domain = d
                self._cache: dict = {}

        for _d, _want in (("10.201.224.25", "内网可见（非公网暴露）"),
                          ("192.168.31.7", "内网可见（非公网暴露）"),
                          ("127.0.0.1", "内网可见（非公网暴露）"),
                          ("1.1.1.1", "公网可达")):
            _got = reachability_scope(_RC(_d))[0]
            if _got != _want:
                problems.append(
                    f"裸 IP 目标 {_d} 的可达范围判为「{_got}」，应为「{_want}」"
                    "—— 要么内网标注丢失，要么公网误判")

        # 同一根因的另一半：**邮件域名类检查（EXT-DM 组）对 IP 目标必须判 N/A**。
        # 不做这道判断的话，空 DNS 结果会被读成「该域名未配置 SPF / DMARC」，
        # 产出从公网位置**根本无法复现**的误报；反向还会让「查不到 MX」
        # 被读成「不接收邮件，符合预期」而判通过 —— 一个毫无执行意义的「通过」。
        from engine.checks import extras3  # noqa: PLC0415

        class _IC:
            domain = "10.201.224.25"
            probe_count = 0
            _cache: dict = {}

            def __getattr__(self, k: str) -> None:
                return None

        for _name in ("SPF 记录配置", "DKIM 公钥记录探测", "DMARC 策略核查",
                      "域名劫持与停放页检查", "证书透明度日志子域枚举"):
            if extras3._no_domain(_IC(), _name) is None:
                problems.append(
                    f"IP 目标下「{_name}」未被判为不适用 —— 空 DNS 结果会被读成"
                    "「未配置记录」，产出运维无法复现的误报")

        print("\n[环境] 裸 IP 目标判定正确：可达范围 → 内网可见（非公网暴露）；"
              "邮件域名类 5 项 → 不适用")
    except Exception as e:  # noqa: BLE001
        problems.append(f"裸 IP 可达范围检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑱：一个端口只能有一个「上报出口」----
    # 端口暴露是一件事，不是几件事。历史上同一个端口（真实目标上 5432 / 9200）
    # 被 WSTG-INFO-04、EXT-CL-02、EXT-DM-05 各报一次，报告里四条发现标题几乎一样、
    # 指向同一对 IP:端口 —— 读者会把「端口个数」当成「漏洞个数」，
    # 客户拿着报告去安全组收口时其实只有一个端口要处理。
    # 归属表（net.PORT_OWNER）保证不会重复；这条不变量在**报告产出后**再核一遍，
    # 防止将来有人新增检查项时又把同一个端口报一次。
    try:
        from engine.checks import net as _net  # noqa: PLC0415

        _port_kw = ("不应开放的端口", "端口开放", "端口可直连", "非标准开放端口")
        _seen_port: dict[int, str] = {}
        _dup: list[str] = []
        for _f in findings:
            _title = getattr(_f, "title", "") or ""
            _ep = getattr(_f, "endpoint", "") or ""
            if "端口" not in (_title + " " + _ep):
                continue
            if not any(_w in (_title + " " + _ep) for _w in _port_kw):
                continue
            _who = getattr(_f, "item_id", "") or "?"
            # endpoint 常见形态是「多个端口逗号列表」：`10.0.0.1:135,445,5900`。
            # 先把 IP 剔除（否则 127 / 0 / 1 会被当成端口），再把剩下的数字全部取出。
            _ep_clean = re.sub(r"\d+\.\d+\.\d+\.\d+", "", _ep)
            _pts = {int(m) for m in re.findall(r"(?<!\d)(\d{1,5})(?!\d)", _ep_clean)}
            _pts |= {int(m) for m in re.findall(r"端口\s*(\d{1,5})", _title)}
            for _p in sorted(p for p in _pts if 1 <= p <= 65535):
                if _p in _seen_port and _seen_port[_p] != _who:
                    _dup.append(f"端口 {_p} 被 {_seen_port[_p]} 与 {_who} 各报一次")
                else:
                    _seen_port.setdefault(_p, _who)
        if _dup:
            problems.append("同一端口存在重复上报（一个端口应只有一个出口）："
                            + "；".join(_dup[:6]))
        # 归属表自检：登记的 owner 必须都是真实存在的检查项 ID，
        # 且邮件 / 容器 / K8s 三类端口各有明确归属（不能全落到兜底）。
        for _p, _o in sorted(_net.PORT_OWNER.items()):
            if _net.port_owner(_p) != _o:
                problems.append(f"端口 {_p} 的归属查表结果与登记不一致")
        if _net.port_owner(5432) != "EXT-CL-02":
            problems.append("未登记端口的兜底归属不是 EXT-CL-02 —— "
                            "兜底错了会出现「探到了却没人上报」的假阴性")
        print(f"\n[环境] 端口归属唯一性已校验：端口类发现覆盖 "
              f"{len(_seen_port)} 个不同端口，重复上报 {len(_dup)} 处")
    except Exception as e:  # noqa: BLE001
        problems.append(f"端口归属唯一性检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑲：外部注入工具（sqlmap）必须被白名单与档位双重约束 ----
    # 这是本项目里风险最高的一个外部依赖：sqlmap 有 `--dump`（导出数据）、
    # `--os-shell`（取得命令执行）、`--file-read`（读服务器文件）、
    # `--risk=3`（OR 型改写载荷，可能真的改动数据）这些开关。
    # 一旦它们漏进命令行，扫描器就从「验证工具」变成「数据导出工具」——
    # 这类事故不可逆（数据已经出去了），所以必须由断言钉住，而不是靠代码惯例。
    try:
        from engine import sqlmap_probe as _smp  # noqa: PLC0415

        # ① 危险开关必须被拒（含带值写法）
        for _bad in (["--dump"], ["--dump-all"], ["--os-shell"], ["--os-pwn"],
                     ["--file-read=/etc/passwd"], ["--file-write=/tmp/x"],
                     ["--sql-query=select 1"], ["--eval=1"], ["--priv-esc"]):
            if not _smp.is_safe_argv(_bad + ["-u", "http://x/a?q=1", "--batch"]):
                problems.append(f"sqlmap 安全断言漏放了禁用开关：{_bad[0]}")
        # ② 数值级下界：名字合法 ≠ 取值安全
        if not _smp.is_safe_argv(["--risk=3", "-u", "http://x/a?q=1"]):
            problems.append("sqlmap --risk=3 未被拒 —— 它会启用 OR 型改写载荷，"
                            "可能改动目标数据")
        if not _smp.is_safe_argv(["--level=9", "-u", "http://x/a?q=1"]):
            problems.append("sqlmap --level 超上限未被拒")
        if _smp.is_safe_argv(["--risk=2", "--level=2", "-u", "http://x/a?q=1"]):
            problems.append("合法的只读参数被误拒（会把能力误判成不可用）")
        # ③ 未登记的开关默认拒绝（白名单语义：新开关默认不允许）
        if not _smp.is_safe_argv(["--some-future-danger", "-u", "http://x/a?q=1"]):
            problems.append("未登记开关未被拒 —— 白名单退化成了黑名单，"
                            "sqlmap 将来新增危险开关会自动放行")
        # ④ 本模块自己构造的 argv（标准档 / 深度档）必须通过自检
        for _plan in (_smp.SqlmapPlan(True, "", timeout=30),
                      _smp.SqlmapPlan(True, "", risk=2, level=2, technique="BEUST",
                                      timeout=30)):
            _argv = _smp.build_argv("sqlmap", "http://x/a?q=1", "q", _plan)
            _v = _smp.is_safe_argv(_argv)
            if _v:
                problems.append(f"自身构造的 sqlmap argv 未通过安全自检：{_v}")
        # ⑤ 档位门控：安全档不调用；关闭开关不调用；两者都要给出理由
        class _C:  # noqa: D401
            profile_key = "safe"

        _safe_plan = _smp.plan_for(_C())
        if _safe_plan.enabled:
            problems.append("安全档不应调用 sqlmap（会向目标发大量载荷）")
        elif not _safe_plan.reason:
            problems.append("安全档不调用 sqlmap 时必须给出理由（不能静默跳过）")
        _prev_env = os.environ.get("AISCAN_SQLMAP")
        os.environ["AISCAN_SQLMAP"] = "off"
        _off_plan = _smp.plan_for(_C())
        if _off_plan.enabled or not _off_plan.reason:
            problems.append("显式关闭 sqlmap 后仍被判定为可调用（开关失效）")
        if _prev_env is None:
            os.environ.pop("AISCAN_SQLMAP", None)
        else:
            os.environ["AISCAN_SQLMAP"] = _prev_env
        # ⑥ 解析：确认注入 / 未确认注入 两个方向都不能搞反
        _hit = _smp.parse_output("Parameter: q (GET)\n    Type: boolean-based blind\n"
                                 "back-end DBMS: MySQL >= 5.0\nbanner: '8.0.32'")
        if not _hit["injected"]:
            problems.append("sqlmap 确证注入的输出未被识别（会漏报）")
        _miss = _smp.parse_output("all tested parameters do not appear to be injectable")
        if _miss["injected"]:
            problems.append("sqlmap 判定不可注入的输出被误判为命中（会误报）")
        print("\n[环境] sqlmap 约束已校验：危险开关 9 类全拦、"
              "数值下界（risk>2 / level>3）已拦、安全档与关闭开关均生效")
    except Exception as e:  # noqa: BLE001
        problems.append(f"sqlmap 约束检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ⑳：会话池（认证态）必须守住四条 ----
    # 这一层的意义：**「最容易被拿走数据的一类问题」是登录之后的越权**，
    # 而它不在任何匿名扫描的视野里。要看见它，前提是扫描器先成为一个
    # 合法的登录用户。于是「登录到底成没成功」就成了整条链路的命门 ——
    # 判错一次，后面所有越权结论都是噪声。
    try:
        from engine.authz_matrix import Account as _Acct  # noqa: PLC0415
        from engine.sessionpool import (  # noqa: PLC0415
            LOGIN_FAIL, LOGIN_NO_CRED, LOGIN_OK, LOGIN_UNVERIFIED,
            build_pool, verify_session,
        )

        _srv2, _port2 = start_app()
        _base2 = f"http://127.0.0.1:{_port2}"
        try:
            def _acct(name: str, *, fields: dict[str, str], authorized: bool = True,
                      pw_env: str = "", verify: str = "/api/whoami") -> dict[str, Any]:
                login: dict[str, Any] = {"url": "/api/login", "method": "POST"}
                if pw_env:
                    login["password_env"] = pw_env
                    login["username_env"] = "AISCAN_SELFTEST_LOGIN_USER"
                    login["username_field"] = "username"
                else:
                    login["fields"] = fields
                return {"name": name, "role": "user", "authorized": authorized,
                        "login": login}

            os.environ["AISCAN_SELFTEST_LOGIN_USER"] = TEST_LOGIN_USER

            # ① 环境变量凭据 → 自动登录成功，且回验为「已登录」
            _p1 = build_pool([_acct("env_ok", fields={}, pw_env=TEST_LOGIN_PASS_ENV)],
                             _base2, profile_key="deep", verify_path="/api/whoami")
            _a1 = _p1.accounts[0] if _p1.accounts else {}
            if _a1.get("login_state") != LOGIN_OK:
                problems.append(
                    f"会话池：环境变量凭据的正常登录未通过"
                    f"（state={_a1.get('login_state')!r}，"
                    f"note={_a1.get('login_note') or _a1.get('rejected')!r}）"
                    "—— 认证态打不通，越权类检测会整体失效")
            elif "aiscan_sess" not in (_a1.get("cookies") or {}):
                problems.append("会话池：登录成功但未取到会话 Cookie")

            # ①-b 人工 Cookie 通道（cookies_env）必须真的能取到会话。
            # 这一条单独立案的理由：配置项存在 ≠ 功能存在。写 `cookies_env` 很容易，
            # 但若没有代码去读那个环境变量，账号会被判成「没凭据」，
            # 而失败原因看起来完全合理（「会话不成立」）—— 越权检测整体静默失效。
            os.environ["AISCAN_SELFTEST_COOKIE"] = "aiscan_sess=ok; tz=Asia/Shanghai"
            _p1b = build_pool([{"name": "manual_ok", "authorized": True,
                                "cookies_env": "AISCAN_SELFTEST_COOKIE"}],
                              _base2, profile_key="deep", verify_path="/api/whoami")
            _a1b = _p1b.accounts[0] if _p1b.accounts else {}
            if _a1b.get("login_state") != LOGIN_OK:
                problems.append(
                    f"会话池：人工 Cookie 通道（cookies_env）未生效"
                    f"（state={_a1b.get('login_state')!r}，"
                    f"note={_a1b.get('login_note') or _a1b.get('rejected')!r}）"
                    "—— 配置项存在但没人读它，这正是「登记了却不生效」")
            elif (_a1b.get("cookies") or {}).get("aiscan_sess") != "ok":
                problems.append("会话池：人工 Cookie 通道未把 Cookie 解析成字典")
            # 环境变量没导出时必须明确报「未提供有效凭据」，而不是静默以游客身份开跑
            _saved_ck = os.environ.pop("AISCAN_SELFTEST_COOKIE", None)
            try:
                _p1c = build_pool([{"name": "manual_missing", "authorized": True,
                                    "cookies_env": "AISCAN_SELFTEST_COOKIE"}],
                                  _base2, profile_key="deep",
                                  verify_path="/api/whoami")
                _a1c = _p1c.accounts[0] if _p1c.accounts else {}
                if _a1c.get("login_state") == LOGIN_OK:
                    problems.append("会话池：人工 Cookie 环境变量未导出却判为已登录")
                elif "有效凭据" not in str(_a1c.get("rejected") or ""):
                    problems.append("会话池：人工 Cookie 未取到时未明说「未提供有效凭据」"
                                    f"（实际：{_a1c.get('rejected')!r}）")
            finally:
                if _saved_ck is not None:
                    os.environ["AISCAN_SELFTEST_COOKIE"] = _saved_ck

            # ② 明文口令 → 拒收该账号，并给出理由（不得带明文去登录）
            _p2 = build_pool([{"name": "plain", "authorized": True,
                               "login": {"url": "/api/login", "method": "POST",
                                         "fields": {"username": "u",
                                                    "password": "hunter2"}}}],
                             _base2, profile_key="deep", verify_path="/api/whoami")
            _a2 = _p2.accounts[0] if _p2.accounts else {}
            if not _a2.get("rejected"):
                problems.append("会话池：配置里的**明文口令**未被拒收"
                                "（凭据会随配置文件一起被复制 / 提交 / 外发）")
            elif "明文" not in str(_a2.get("rejected")):
                problems.append(f"会话池：明文口令被拒但理由没说清："
                                f"{_a2.get('rejected')!r}")
            if len(_p2.accounts) != 1:
                problems.append("会话池：被拒收的账号被静默丢弃了 —— "
                                "上层会以为「只配了 0 个账号」，"
                                "而越权判断恰恰依赖账号数量")
            if _a2.get("login_state") == LOGIN_OK:
                problems.append("会话池：被拒收的账号竟然还是「已登录」状态")

            # ②-b 明文的 Authorization 头也必须被拒。
            # 键名 "Authorization" 里不含 password / secret / token，
            # 早期版本会直接漏掉它 —— 而 Bearer token 恰恰是最常见的凭据形态。
            _p2b = build_pool([{"name": "plain_hdr", "authorized": True,
                                "headers": {"Authorization": "Bearer abc123def456"}}],
                              _base2, profile_key="deep", verify_path="/api/whoami")
            _a2b = _p2b.accounts[0] if _p2b.accounts else {}
            if not _a2b.get("rejected"):
                problems.append("会话池：明文的 Authorization 头未被判为明文凭据"
                                "（Bearer token 是最常见的凭据形态，不能漏）")

            # ③ 环境变量缺失 → 必须登录失败（不得因为「两侧都空」而假通过）
            _saved = os.environ.pop(TEST_LOGIN_PASS_ENV, None)
            try:
                _p3 = build_pool([_acct("env_missing", fields={},
                                        pw_env=TEST_LOGIN_PASS_ENV)],
                                 _base2, profile_key="deep",
                                 verify_path="/api/whoami")
                _a3 = _p3.accounts[0] if _p3.accounts else {}
                if _a3.get("login_state") == LOGIN_OK:
                    problems.append("会话池：凭据环境变量未导出却判为「已登录」"
                                    "—— 登录成功判据存在假阳性通道")
            finally:
                if _saved is not None:
                    os.environ[TEST_LOGIN_PASS_ENV] = _saved

            # ④ 401 必须判「未登录」——这是最容易漏的一条：401 既没有
            #    重定向也没有登录表单，若只判那两条，携带无效凭据的账号
            #    会被判成「已登录」，之后所有越权结论都是噪声。
            #    这里必须**带上一个无效 Cookie**：零凭据会先被守卫拦下
            #    （那是另一条断言），测不到 401 这一支。
            _st, _why = verify_session({"cookies": {"aiscan_sess": "bogus"}},
                                       _base2, "/api/whoami")
            if _st != LOGIN_FAIL:
                problems.append(f"会话池：服务端返回 401（明确拒绝）时"
                                f"登录态判成了「{_st}」，应为「{LOGIN_FAIL}」"
                                "—— 未认证身份会被当成已认证身份使用")

            # ⑤ 已确认登录态不足 2 个 → 必须明说越权只能判「未能验证」
            _only_one = build_pool([_acct("env_ok", fields={},
                                         pw_env=TEST_LOGIN_PASS_ENV)],
                                   _base2, profile_key="deep",
                                   verify_path="/api/whoami")
            _txt = " ".join(_only_one.summary_lines())
            if _only_one.authenticated_pairs() < 2 and "未能验证" not in _txt:
                problems.append("会话池：已确认登录态不足 2 个时未提示"
                                "「越权类结论只能判未能验证」—— "
                                "会拿单账号结论冒充越权证据")

            # ⑥ 进报告的数据与构造请求的数据必须是两份
            _acc = _Acct(name="x", role="vip", authorized=True,
                         cookies={"sess": "s1"}, headers={"X-T": "t1"},
                         login={"url": "/api/login",
                                "password_env": TEST_LOGIN_PASS_ENV})
            _for_report = _acc.to_dict()
            _for_pool = _acc.to_pool_dict()
            for _leak in ("cookies", "headers", "login"):
                if _leak in _for_report:
                    problems.append(f"会话池：报告用数据里出现了 {_leak}（凭据泄露）")
            if not _for_report.get("has_credentials"):
                problems.append("会话池：报告用数据丢了 has_credentials 标记"
                                "（报告将无法说明「该账号是否带凭据」）")
            if "cookies" not in _for_pool or "login" not in _for_pool:
                problems.append("会话池：请求用数据缺了 cookies / login —— "
                                "它会构造不出会话（真实的失效形态是"
                                "「所有账号都被判成没凭据」，看起来还很合理）")
            # 用报告数据去建会话池 → 必须登不上（这正是那个坑的实证）
            _bad_input = dict(_for_report)
            _bad_input["authorized"] = True
            _p6 = build_pool([_bad_input], _base2, profile_key="deep",
                             verify_path="/api/whoami")
            _a6 = _p6.accounts[0] if _p6.accounts else {}
            if _a6.get("login_state") == LOGIN_OK:
                problems.append("会话池：用**剥了凭据**的报告数据竟然也能构成"
                                "「已登录」—— 说明判定链路上有臆断")

            # ⑦ 未声明授权的账号不得启用
            #    Cookie 名特意用 `theme` 这种显然不是凭据的名字：
            #    若用 `sess` 之类的名字，会先被「明文凭据」那条正确拦下，
            #    拒收理由就不是授权问题 —— 断言也就测不到这条规则了。
            _p7 = build_pool([{"name": "unauth", "authorized": False,
                               "cookies": {"theme": "dark"}}],
                             _base2, profile_key="deep", verify_path="/api/whoami")
            _a7 = _p7.accounts[0] if _p7.accounts else {}
            if not _a7.get("rejected"):
                problems.append("会话池：未标记 authorized 的账号被启用了")
            elif "授权" not in str(_a7.get("rejected")):
                problems.append("会话池：未授权账号的拒收理由未提到「授权」"
                                f"（实际：{_a7.get('rejected')!r}）")

            # ⑧ 零凭据账号**不得**被判「已登录」，且**一个请求都不许发**。
            #    实测过的误报：判据是「带会话访问没被弹回认证页」，而匿名请求
            #    访问公开首页同样不会被弹回 —— 于是「什么凭据都没有的账号」
            #    被判已登录，`authenticated_pairs()` 记 1，两个空账号就凑够
            #    「≥2 个已登录态」，扫描器随后以游客身份跑越权检测，
            #    产出一批复测不出来的「越权」。
            #    这里特意打目标**首页**（公开 200）而不是 /api/whoami：
            #    用 whoami 测会因为它是 401 而侥幸通过，掩盖真正的缺陷。
            _hits_before = Handler.HITS["n"]
            _p8 = build_pool([{"name": "no_cred", "authorized": True}],
                             _base2, profile_key="deep", verify_path="/")
            _a8 = _p8.accounts[0] if _p8.accounts else {}
            if _a8.get("login_state") == LOGIN_OK:
                problems.append("会话池：**没有任何凭据**的账号被判成了「已登录」"
                                "—— 两个空账号即可满足「≥2 个已登录态」的门槛，"
                                "越权检测会以游客身份开跑并产出假结论")
            elif _a8.get("login_state") != LOGIN_NO_CRED:
                problems.append("会话池：零凭据账号的状态应为「未提供凭据」，"
                                f"实际是「{_a8.get('login_state')}」"
                                "（写成「登录失败」也是假话：那意味着试过登录）")
            if _p8.authenticated_pairs() != 0:
                problems.append("会话池：零凭据账号被计入已确认登录态")
            _hits_after = Handler.HITS["n"]
            if _hits_after != _hits_before:
                problems.append(f"会话池：零凭据账号竟然发出了 {_hits_after - _hits_before} "
                                "个请求 —— 没有会话就没有「会话是否有效」可验证，"
                                "发请求只会得到「游客看起来也正常」这种假证据")

            # ⑨ 对照实验：拿**公开页面**当回验路径时，带凭据也不得判「已登录」。
            #    「带着 Cookie 访问首页没被弹回」既不能证明会话有效，也不能证明无效 ——
            #    它对这个路径毫无区分力，只能判「未验证」。
            #    旧实现缺这一步，于是所有只配了 Cookie、没指定登录后页面的扫描，
            #    100% 会把账号判成「已登录」。
            _st_pub, _why_pub = verify_session({"cookies": {"aiscan_sess": "bogus"}},
                                               _base2, "/")
            if _st_pub == LOGIN_OK:
                problems.append("会话池：用**公开首页**回验时把任意 Cookie 判成了"
                                "「已登录」—— 缺少「匿名对照」，"
                                "登录态结论没有区分力")
            elif _st_pub != LOGIN_UNVERIFIED:
                problems.append(f"会话池：公开页对照后应判「未验证」，"
                                f"实际「{_st_pub}」（{str(_why_pub)[:60]}）")
            # 反向：换成真正需要登录的页面，会话有效就必须能确证「已登录」。
            # 没有这一条，上面的守卫就可以靠「一律判未验证」蒙混过关 ——
            # 一个永不判定的检查等于没做。
            _st_auth, _why_auth = verify_session({"cookies": {"aiscan_sess": "ok"}},
                                                 _base2, "/api/whoami")
            if _st_auth != LOGIN_OK:
                problems.append(f"会话池：凭据有效 + 回验路径需登录，却未判「已登录」"
                                f"（实际「{_st_auth}」：{str(_why_auth)[:60]}）"
                                "—— 守卫过头会让认证类检查项永远跑不起来")

            # ⑩ 本机凭据库必须能**独立**激活账号（不依赖任何环境变量）。
            #    这是「凭据索取闭环」的最后一环：操作者按指引把令牌写进文件，
            #    扫描期就得真的用上。写不进去 / 读不出来，
            #    整条闭环就退化成「文档里写了但功能不存在」。
            import tempfile as _tf  # noqa: PLC0415
            _cred_dir = Path(_tf.mkdtemp(prefix="aiscan_cred_"))
            _old_cred_env = os.environ.get("AISCAN_CRED_DIR")
            os.environ["AISCAN_CRED_DIR"] = str(_cred_dir)
            try:
                from engine import credguide as _CG  # noqa: PLC0415
                import importlib as _il  # noqa: PLC0415
                _il.reload(_CG)   # 目录来自环境变量，必须重载才看得到新值
                _cf = _cred_dir / "t.example.json"
                _cf.write_text(_CG.skeleton(["cred_user"]), encoding="utf-8")
                # 先验骨架（占位）不得被当成凭据
                _p10a = build_pool([{"name": "cred_user", "authorized": True,
                                     "cookies_env": "AISCAN_NOPE_ENV"}],
                                   _base2, profile_key="deep",
                                   verify_path="/api/whoami", cred_file=_cf)
                _a10a = _p10a.accounts[0] if _p10a.accounts else {}
                if _a10a.get("login_state") == LOGIN_OK:
                    problems.append("会话池：凭据库里的**占位骨架**被当成了真凭据")
                # 再写真凭据 → 必须激活并可判「已登录」
                _CG.write_role(_cf, "cred_user", {"aiscan_sess": "ok"}, {})
                _p10 = build_pool([{"name": "cred_user", "authorized": True,
                                    "cookies_env": "AISCAN_NOPE_ENV"}],
                                  _base2, profile_key="deep",
                                  verify_path="/api/whoami", cred_file=_cf)
                _a10 = _p10.accounts[0] if _p10.accounts else {}
                if _a10.get("supplied_by") != "cred_file":
                    problems.append("会话池：凭据库里写了真凭据，账号却没取到"
                                    f"（supplied_by={_a10.get('supplied_by')!r}）"
                                    "—— 凭据索取闭环断裂")
                elif _a10.get("login_state") != LOGIN_OK:
                    problems.append("会话池：凭据库供上的凭据未能构成有效会话"
                                    f"（state={_a10.get('login_state')!r}）")
            finally:
                if _old_cred_env is None:
                    os.environ.pop("AISCAN_CRED_DIR", None)
                else:
                    os.environ["AISCAN_CRED_DIR"] = _old_cred_env
                import shutil as _sh  # noqa: PLC0415
                _sh.rmtree(_cred_dir, ignore_errors=True)
        finally:
            _srv2.shutdown()

        print("\n[环境] 会话池约束已校验：明文口令拒收、"
              "登录必须回验（401 判未登录）、不足 2 个登录态明示「未能验证」、"
              "报告数据与请求数据已分离、"
              "零凭据账号不得判「已登录」且一个请求都不发、"
              "回验必须带匿名对照（公开页不得当登录证据）、"
              "本机凭据库能独立激活账号（骨架占位不算凭据）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"会话池约束检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ㉑：SPA 渲染必须「能生效」且「不越权下结论」----
    # 这一条防的是两个方向相反的错误：
    #   · 渲染写了却没人用（装饰品）→ SPA 目标整体失明，报告里一堆假的 N/A；
    #   · 渲染失败被当成「页面上没有这些东西」→ 把一次工具失效说成了关于目标的结论。
    # 默认不启动真实浏览器（自测必须在任何环境跑出同一结果），
    # 用注入执行体覆盖全部分支；本机存在浏览器时可用 --with-browser 额外验一次真链路。
    try:
        from engine import render as _rnd  # noqa: PLC0415
        from engine.fingerprint import FeatureDeriver, HttpProbe  # noqa: PLC0415
        from engine.urlpool import build_url_pool  # noqa: PLC0415

        _SKELETON = ('<html><head><title>演示系统</title>'
                     '<script src="/assets/index-abc123.js"></script></head>'
                     '<body><div id="app"></div><noscript>请开启 JavaScript</noscript>'
                     '</body></html>')
        _RENDERED = ('<html><head><title>演示系统</title></head><body>'
                     '<div id="app"><h1>管理后台</h1>'
                     '<a href="/order/list">订单列表</a>'
                     '<a href="/user/profile">个人中心</a>'
                     '<form action="/api/user/update" method="post">'
                     '<input name="mobile" type="text"></form>'
                     '</div></body></html>')

        # ① 骨架识别：骨架页要认得出来，内容页不能误判
        if not _rnd.looks_like_skeleton(_SKELETON):
            problems.append("渲染：明显的骨架页（空挂载点 + 仅脚本引用）未被识别")
        if _rnd.looks_like_skeleton(_RENDERED):
            problems.append("渲染：已含完整内容的页面被误判为骨架页")
        # ② 可见文本提取要剔掉 script / 标签，否则「渲染前后正文量」永远相等
        _txt = _rnd.strip_tags(_SKELETON)
        if "index-abc123" in _txt or "<" in _txt:
            problems.append("渲染：可见文本提取未剔除脚本与标签")

        # ③ 安全约束：命令行必须带一次性配置目录与「不吃系统代理」，
        #    且**不得**关闭沙箱（执行不可信 JS 时那会降低隔离度）
        _argv = _rnd._build_argv("http://x/", _rnd.RenderPlan(True, "", "edge"), "/tmp/p")
        if not any(a.startswith("--user-data-dir=") for a in _argv):
            problems.append("渲染：命令行未指定一次性 user-data-dir —— "
                            "会复用使用者的浏览器配置（可能带上使用者已登录的 Cookie）")
        if "--no-proxy-server" not in _argv:
            problems.append("渲染：未禁用系统代理 —— 与 HTTP 探测口径不一致，"
                            "代理会让渲染拿到代理的页面而不是目标的页面")
        if "--no-sandbox" in _argv:
            problems.append("渲染：命令行含 --no-sandbox —— 执行目标页面 JS 时"
                            "沙箱是可用的，不应默认关闭")
        if "--dump-dom" not in _argv:
            problems.append("渲染：命令行未包含 --dump-dom")

        # ④ 档位门控：安全档不渲染；显式关闭不渲染；两种都要给理由
        _prev_render_env = os.environ.get("AISCAN_RENDER")
        os.environ["AISCAN_RENDER"] = "off"
        _off_plan = _rnd.plan_for("deep")
        if _off_plan.enabled or not _off_plan.reason:
            problems.append("渲染：AISCAN_RENDER=off 未生效或未给理由")
        os.environ["AISCAN_RENDER"] = "auto"
        _prev_browser_env = os.environ.get("AISCAN_BROWSER")
        # 用「指向一个不存在的路径」来稳定地模拟「本机没有浏览器」
        os.environ["AISCAN_BROWSER"] = "/nonexistent/aiscan-no-browser"
        _nob_plan = _rnd.plan_for("deep")
        if _nob_plan.enabled:
            problems.append("渲染：本机没有浏览器时仍判定为可渲染")
        elif not _nob_plan.reason or "人工" not in _nob_plan.reason:
            problems.append("渲染：没有浏览器时不渲染，但未说明后果（应提示需人工确认，"
                            f"而不是留白）。实际：{_nob_plan.reason!r}")
        # 恢复真实探测，用真实结果判断安全档
        if _prev_browser_env is None:
            os.environ.pop("AISCAN_BROWSER", None)
        else:
            os.environ["AISCAN_BROWSER"] = _prev_browser_env
        _real_browser = _rnd.find_browser()
        if _real_browser:
            _safe_plan = _rnd.plan_for("safe")
            if _safe_plan.enabled:
                problems.append("渲染：安全档不应渲染（会在浏览器里执行目标页面的 JS）")
            elif not _safe_plan.reason:
                problems.append("渲染：安全档不渲染但未给理由")
        # 恢复渲染开关
        if _prev_render_env is None:
            os.environ.pop("AISCAN_RENDER", None)
        else:
            os.environ["AISCAN_RENDER"] = _prev_render_env

        # ⑤ 成功路径 + 临时配置目录必须被清理
        _seen_dir: list[str] = []

        def _stub_ok(browser, argv, timeout):  # noqa: ANN001
            _seen_dir.extend(a.split("=", 1)[1] for a in argv
                             if a.startswith("--user-data-dir="))
            return 0, _RENDERED.encode("utf-8"), b""

        _deep_plan = _rnd.RenderPlan(True, "自测", _real_browser or "/x", timeout=5)
        _rnd.forget_broken_browsers()      # 同 ⑥：跨场景清一次
        _out = _rnd.render("http://127.0.0.1:1/", _deep_plan,
                           before_html=_SKELETON, runner=_stub_ok)
        if not (_out.ok and _out.state == _rnd.STATE_RENDERED):
            problems.append(f"渲染：正常渲染路径未成功（state={_out.state!r} "
                            f"reason={_out.reason!r}）")
        if not _out.refilled:
            problems.append("渲染：渲染后正文明显增多却未判定为「确有增补」"
                            "—— 这会让「渲染到底有没有用」无从判断")
        if _seen_dir and os.path.exists(_seen_dir[0]):
            problems.append("渲染：一次性浏览器配置目录未被清理"
                            "（里面可能有目标站点种下的 Cookie / 存储）")

        # ⑥ 失败路径：超时 / 空输出 / 浏览器不存在 —— 三者都不得变成「没有内容」
        #
        # ⚠ 每个场景前必须清一次「坏浏览器记忆」。`render()` 会把
        # rc=0 但无输出、以及可执行文件缺失的浏览器记进进程级的
        # _BROKEN_BROWSERS，本轮后续不再尝试（生产上这救回了每渲染一次
        # 白等十几秒的问题）。但自测是**同一进程里连跑多个场景**，
        # 前一个场景把浏览器拉黑，后一个场景就会直接跳过所有候选 ——
        # 于是「回退成功」「全失败措辞」这类断言全部假红。
        # 这不是生产的错，是自测没有隔离进程状态；忘记清就是
        # 「配了却没人读」的镜像：机制生效了，反而把断言打废。
        for _name, _runner, _kw in (
            ("超时", lambda b, a, t: (124, b"", b"[timeout]"), "未结束"),
            ("空输出", lambda b, a, t: (0, b"", b"crash"), "不是「页面上没有内容」"),
            ("浏览器缺失", lambda b, a, t: (_ for _ in ()).throw(
                FileNotFoundError("no such file")), "浏览器可执行文件不存在"),
        ):
            _rnd.forget_broken_browsers()
            _o = _rnd.render("http://127.0.0.1:1/", _deep_plan,
                             before_html=_SKELETON, runner=_runner)
            if _o.ok or _o.state != _rnd.STATE_FAILED:
                problems.append(f"渲染：{_name}路径未判为「{_rnd.STATE_FAILED}」"
                                f"（state={_o.state!r}）")
            elif _kw not in (_o.reason or ""):
                problems.append(f"渲染：{_name}的说明未点明「这是渲染失败，"
                                f"不是目标情况」。实际：{_o.reason!r}")

        # ⑥b 逐浏览器回退：首选空输出、次选成功 → 必须回退成功并具名
        # （2026-10-09 Juice Shop 基准实测：本机 Edge rc=0 却不输出任何 DOM，
        #  只认首选候选 = 渲染整体失明，SPA 类目标大批 N/A）
        _calls: list[str] = []

        def _stub_flaky(browser, argv, timeout):  # noqa: ANN001
            _calls.append(browser)
            if len(_calls) == 1:
                return 0, b"", b""          # 首选浏览器：空输出
            return 0, _RENDERED.encode("utf-8"), b""   # 次选：成功

        _fb_plan = _rnd.RenderPlan(True, "自测", "/fake/preferred", timeout=5)
        _rnd.forget_broken_browsers()      # 见 ⑥ 处的说明：跨场景必须清记忆
        _fb = _rnd.render("http://127.0.0.1:1/", _fb_plan,
                          before_html=_SKELETON, runner=_stub_flaky)
        if not (_fb.ok and _fb.state == _rnd.STATE_RENDERED):
            problems.append(f"渲染：首选空输出后未回退到次选浏览器"
                            f"（state={_fb.state!r} reason={_fb.reason!r}）")
        elif "回退" not in (_fb.reason or ""):
            problems.append(f"渲染：回退成功但未在 reason 里具名（{_fb.reason!r}）"
                            "—— 「换了一个浏览器才渲染出来」必须能被说出来")
        if len(_calls) < 2:
            problems.append("渲染：首选失败后没有尝试第二个浏览器候选")

        # ⑥c 全部浏览器都空输出 → 仍判「渲染失败」且措辞不变成「没有内容」
        _rnd.forget_broken_browsers()
        _all_empty = _rnd.render(
            "http://127.0.0.1:1/", _fb_plan, before_html=_SKELETON,
            runner=lambda b, a, t: (0, b"", b""))
        if _all_empty.ok or _all_empty.state != _rnd.STATE_FAILED:
            problems.append("渲染：全部浏览器空输出时未判「渲染失败」")
        elif "不是「页面上没有内容」" not in (_all_empty.reason or ""):
            problems.append(f"渲染：全失败时的措辞丢失了「不是页面上没有内容」"
                            f"（{_all_empty.reason!r}）")

        # ⑥d 超时也必须回退到下一个浏览器（基准五轮实测：同一目标，
        #  四轮 Chrome 数秒渲染成功，五轮首选浏览器挂死 60s —— 超时是
        #  浏览器侧故障，不是目标侧慢，不回退 = 整页渲染假失败）
        _t_calls: list[str] = []

        def _stub_timeout_then_ok(browser, argv, timeout):  # noqa: ANN001
            _t_calls.append(browser)
            if len(_t_calls) == 1:
                return 124, b"", b"[timeout]"
            return 0, _RENDERED.encode("utf-8"), b""

        _rnd.forget_broken_browsers()
        _tf = _rnd.render("http://127.0.0.1:1/", _fb_plan,
                          before_html=_SKELETON, runner=_stub_timeout_then_ok)
        if not (_tf.ok and _tf.state == _rnd.STATE_RENDERED):
            problems.append(f"渲染：首选超时后未回退到次选浏览器"
                            f"（state={_tf.state!r} reason={_tf.reason!r}）")
        elif "回退" not in (_tf.reason or ""):
            problems.append(f"渲染：超时回退成功但未具名（{_tf.reason!r}）")

        # ⑥e 全部浏览器都超时 → 仍判「渲染失败」且每个超时都具名
        _rnd.forget_broken_browsers()
        _all_to = _rnd.render(
            "http://127.0.0.1:1/", _fb_plan, before_html=_SKELETON,
            runner=lambda b, a, t: (124, b"", b"[timeout]"))
        if _all_to.ok or _all_to.state != _rnd.STATE_FAILED:
            problems.append("渲染：全部浏览器超时时未判「渲染失败」")
        elif "未结束" not in (_all_to.reason or ""):
            problems.append(f"渲染：全超时的措辞丢了「未结束」"
                            f"（{_all_to.reason!r}）")

        # ⑦ 边缘拦截页不该浪费一次渲染（渲染出来仍是拦截页，还会误导）
        _rnd.forget_broken_browsers()
        _edge = _rnd.render_entry("http://x/", profile_key="deep", status=405,
                                  content_type="text/html", before_html="",
                                  plan=_deep_plan, runner=_stub_ok)
        if _edge.state != _rnd.STATE_SKIPPED or "405" not in (_edge.reason or ""):
            problems.append(f"渲染：HTTP 405 的入口页仍被执行了渲染"
                            f"（state={_edge.state!r} reason={_edge.reason!r}）")

        # ⑧ 接线有效性之一：渲染后的正文必须真的改变特征判定，且标明来源
        _probe = HttpProbe(url="http://x/", status=200, headers={},
                           body_snippet=_SKELETON)

        _der = FeatureDeriver()
        _tf_off = _der.derive("t", "http://x/", _probe, {}, None, None, "")
        _tf_on = _der.derive("t", "http://x/", _probe, {}, None, None, _RENDERED)
        _off_state = _tf_off.features.get("has_input")
        _on_state = _tf_on.features.get("has_input")
        if _off_state is not None and _off_state.state != "absent":
            problems.append("渲染：直连骨架页（无表单）本应判「无输入入口」，"
                            f"实际为 {_off_state.state!r}")
        if _on_state is None or _on_state.state != "present":
            problems.append("渲染：渲染后出现了表单，特征却仍未判「具备」"
                            "—— 渲染就是装饰品，SPA 目标整体失明")
        elif _on_state.source != "rendered":
            problems.append(f"渲染：判定来源未标为 rendered（实际 {_on_state.source!r}）"
                            "—— 报告将无法区分「直连可见」与「渲染才可见」")
        elif "渲染" not in (_on_state.evidence or ""):
            problems.append("渲染：证据未说明该结论依赖浏览器渲染，"
                            "复测方式会写错（curl 看不到）")

        # ⑧-b 「写在脚本字符串里的 <form」不算页面上有表单。
        #    SPA 常用 innerHTML / 模板字符串拼要渲染的 HTML，于是 `<form` 会以
        #    **字面文本**出现在内联脚本里。若直接对原始 HTML 做子串匹配，
        #    一个纯骨架页也会「命中」表单 —— 结论看着对，依据却是脚本里的字符串。
        #    这类「碰巧对」比判错更危险：它让检测器以为自己看到了表单，
        #    于是不再报「没看到页面」，真正的漏报被永久掩盖。
        _JSSTR = ("<html><head><script>document.getElementById('app').innerHTML = "
                  "'<form action=\\\"/x\\\"><input name=\\\"a\\\"></form>';</script></head>"
                  "<body><div id='app'></div></body></html>")
        _probe_js = HttpProbe(url="http://x/", status=200, headers={},
                              body_snippet=_JSSTR)
        _tf_js = _der.derive("t", "http://x/", _probe_js, {}, None, None, "")
        _js_state = _tf_js.features.get("has_input")
        if _js_state is not None and _js_state.state == "present":
            problems.append("渲染：骨架页把 <form / <input 写在**脚本字符串**里，"
                            "却被判为「有输入入口」—— 依据是脚本字面量，"
                            "不是页面上真实存在的表单；这类「碰巧对」会掩盖真正的漏报")
        #    但渲染之后，那个 <form 就是真的了 → 必须判 present
        _tf_js2 = _der.derive("t", "http://x/", _probe_js, {}, None, None, _RENDERED)
        _js2_state = _tf_js2.features.get("has_input")
        if _js2_state is None or _js2_state.state != "present":
            problems.append("渲染：骨架页渲染后出现了真实表单，特征却仍判"
                            "「无输入入口」（渲染等于没接上）")

        # ⑨ 接线有效性之二：渲染后的链接必须真的进入 URL 枚举池
        class _UCtx:  # noqa: D401
            target_url = "http://127.0.0.1:1/"
            domain = "127.0.0.1"
            profile_key = "standard"
            js_result: dict[str, Any] = {}

            def __init__(self, rendered: str) -> None:
                self.fp_result = {"path_probes": {}, "_render_html": rendered}

            def get(self, url: str) -> Any:  # noqa: ANN401
                class _P:  # noqa: D401
                    body_snippet = ""
                return _P()

        _pool_off = build_url_pool(_UCtx(""), "standard")
        _pool_on = build_url_pool(_UCtx(_RENDERED), "standard")
        _n_off = len(_pool_off.sources.get("页面链接") or [])
        _n_on = len(_pool_on.sources.get("页面链接") or [])
        if _n_on <= _n_off:
            problems.append(f"URL 枚举未使用渲染后的 DOM 抽链接"
                            f"（渲染前 {_n_off} 条 → 渲染后 {_n_on} 条）"
                            "—— SPA 的真实路由进不了池子")
        elif "/order/list" not in [p.rstrip("/") for p in
                                  (_pool_on.sources.get("页面链接") or [])]:
            problems.append("URL 枚举虽使用渲染正文，但未抽出渲染后才出现的路由")

        # ⑪ 「骨架页 + 未渲染」必须把采集充分度压到「不足」。
        #    这是渲染链路与报告之间最关键的一根线：不压下来，
        #    报告里那些 N/A 会被读成「目标没有该功能」。
        try:
            from engine.checks.base import collection_report  # noqa: PLC0415

            class _CtxColl:  # noqa: D401
                baseline_body = _SKELETON
                js_result: dict[str, Any] = {}
                root_headers = {"server": "nginx"}
                target_url = "http://127.0.0.1:1/"

                def __init__(self, entry: dict[str, Any]) -> None:
                    self.fp_result = {"render": {"entry": entry},
                                      "path_probes": {}}

                def get(self, url: str) -> Any:  # noqa: ANN401
                    class _P:  # noqa: D401
                        body_snippet = _SKELETON
                        headers: dict[str, str] = {}
                    return _P()

            _gap = collection_report(_CtxColl(
                {"ok": False, "state": "未渲染", "reason": "本机未找到浏览器",
                 "skeleton_before": True}))
            if not _gap.get("spa_render_gap") or not _gap.get("degraded"):
                problems.append("采集充分度：入口页是骨架页且未渲染，却未判为"
                                "「采集不足」—— 报告里的 N/A 会被读成「不存在」"
                                f"（score={_gap.get('score')} level={_gap.get('level')!r}）")
            elif not (_gap.get("notes") or []):
                problems.append("采集充分度：判了 SPA 采集缺口却没给出原因说明")
            if "未渲染" not in (_gap.get("summary") or ""):
                problems.append("采集充分度：摘要里未提示 SPA 未渲染")
            _ok = collection_report(_CtxColl(
                {"ok": True, "state": "已渲染", "skeleton_before": True,
                 "text_before": 0, "text_after": 4000, "refilled": True}))
            if _ok.get("spa_render_gap"):
                problems.append("采集充分度：入口页已成功渲染，却被判为渲染缺口")
        except Exception as e:  # noqa: BLE001
            problems.append(f"采集充分度渲染缺口检查未能执行："
                            f"{type(e).__name__}: {str(e)[:140]}")

        # ⑩ 可选：真实浏览器链路（--with-browser）
        if _with_browser:
            _bsrv, _bport = start_app()
            try:
                _burl = f"http://127.0.0.1:{_bport}/spa"
                if not _real_browser:
                    print("\n[环境] 渲染真链路：本机未找到 Edge / Chrome，跳过")
                else:
                    _plan_real = _rnd.plan_for("deep")
                    _res = _rnd.render(_burl, _plan_real,
                                       before_html="<html><body><div id='app'></div>"
                                                   "<script src='/static/app.js'></script>"
                                                   "</body></html>")
                    if not _res.ok:
                        problems.append(f"渲染真链路失败：{_res.reason}")
                    elif "管理后台" not in _res.html:
                        problems.append("渲染真链路：JS 注入的内容未出现在 DOM 中"
                                        "（拿到的仍是骨架）")
                    else:
                        print(f"\n[环境] 渲染真链路已验证：{_res.summary_line()}")

                    # 端到端：前面几条断言验的是**各个部件**，这一条验的是
                    # 「它们连起来在生产路径上能用」—— 走真正的 Fingerprinter.assess。
                    # 本项目有过一次教训：自测全绿、真实扫描必崩（粘在 scan() 里的
                    # 胶水代码从未被自测覆盖）。渲染是新加的一环，必须按同样标准验。
                    from engine.fingerprint import Fingerprinter  # noqa: PLC0415

                    _fp2 = Fingerprinter({"rate": {"timeout_seconds": 5,
                                                   "requests_per_second": 200}})
                    _e2 = _fp2.assess("自测SPA", "127.0.0.1", _burl, None,
                                      profile_key="deep")
                    _rt = _e2.get("render") or {}
                    _re2 = _rt.get("entry") or {}
                    if not _re2.get("ok"):
                        problems.append(
                            "渲染未接进主链路：Fingerprinter.assess 返回的 "
                            f"render.entry.ok=False（{_re2.get('reason') or _re2.get('state')}）")
                    elif not _e2.get("_render_html"):
                        problems.append(
                            "渲染未接进主链路：渲染成功但渲染正文没有交给后续阶段 —— "
                            "URL 枚举拿不到 SPA 的真实路由")
                    else:
                        _hi = (_e2.get("features") or {}).get("has_input") or {}
                        if _hi.get("state") != "present":
                            problems.append(
                                "渲染未改变特征判定：SPA 渲染后页面里已有表单，"
                                f"has_input 仍为 {_hi.get('state')!r}")
                        elif _hi.get("source") != "rendered":
                            problems.append(
                                "渲染改变了判定但未标来源：has_input 的 source 为 "
                                f"{_hi.get('source')!r}，应为 'rendered'"
                                "（否则报告无法区分「直连可见」与「渲染才可见」）")
                        else:
                            print("[环境] 渲染已接入主链路：Fingerprinter.assess "
                                  "产出 render.entry.ok=True、_render_html 非空、"
                                  "has_input → present/rendered")
            finally:
                _bsrv.shutdown()

        print("\n[环境] 渲染链路已校验：档位门控与「没有浏览器」的后果说明、"
              "失败不等于「不存在」、渲染结果确实改变特征与链接枚举、"
              "临时配置目录已清理、未关闭沙箱")
    except Exception as e:  # noqa: BLE001
        problems.append(f"渲染约束检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ㉒：业务逻辑自动侦察必须「真省人工」且「不冒充通过」----
    #
    # BUSL 是用户明确点名的盲区（「业务逻辑全靠人工，自动化一律测不了」）。
    # 补它的方式不是把这 10 项标成自动项 —— 而是给人工项加一层前置侦察：
    # 扫描器把「找接口、找字段、记当前值、做差分」做掉，人工只回答
    # 「这个业务结果对不对」。这条不变量钉住的就是这件事的两个反面：
    #
    #   · **收不足**（侦察写了没人用）→ 人工还要从零找接口，盲区没补上；
    #   · **收过头**（侦察没抓到就当通过）→ 人工项被判成绿色，
    #     等于用「工具没看见」冒充「业务逻辑没问题」，这正是本项目要根除的行为。
    #
    # 另一条暗线是差分判据的**误报防线**：业务逻辑类问题的误报代价最高
    # （研发一句「服务端会重算」就能否掉整份报告），所以判据必须能挡住
    # 「只看到回显就报采信」这种最容易发生的升级。
    try:
        from engine import business as _biz  # noqa: PLC0415
        # STATE_FIND 在模块顶部已导入，这里**不能**再导一次：
        # 函数内的 import 会让整个 main() 里的同名变量变成局部变量，
        # 于是本段之前的引用（不变量 ② 附近）会直接抛 UnboundLocalError。
        # 这个坑的表现是「改一段无关代码，前面早就跑通的不变量突然崩」，
        # 排查起来极费时间，所以只导入真正缺的那个名字。
        from engine.registry import DetectorRegistry, make_manual, STATE_MANUAL  # noqa: PLC0415

        # ① 参数分类双向：该认的认出来，不该认的别乱认
        _KIND_CASES = {
            "orderStatus": "state", "total_amount": "amount", "qty": "quantity",
            "couponId": "discount", "role": "role", "userId": "identity",
            "sign": "sign", "sign_time": "sign", "payAmount": "amount",
            "order_status": "state", "用户角色": "role", "有效期": "time",
        }
        for _n, _want in _KIND_CASES.items():
            _got = _biz.classify(_n)
            if _got != _want:
                problems.append(f"业务参数分类：`{_n}` 应判为 {_want}，实际 {_got!r}")
        for _n in ("pageSize", "keyword", "sortBy", "offset", "callback", "t"):
            if _biz.classify(_n):
                problems.append(f"业务参数分类：`{_n}` 不是业务敏感参数，"
                                f"却被判为 {_biz.classify(_n)!r}（会让 lead 全是噪声）")

        # ② 安全过滤：这些接口一律不得进入自动差分
        for _u, _why in (
            ("https://x/api/order/pay", "资金"),
            ("https://x/api/refund/apply", "资金"),
            ("https://x/api/file/upload", "上传"),
            ("https://x/api/user/delete", "删除"),
            ("https://x/api/sms/sendCode", "短信"),
            ("https://x/api/auth/logout", "会话"),
            ("https://x/api/workflow/approve", "审批"),
        ):
            _r = _biz.unsafe_reason(_u)
            if not _r:
                problems.append(f"安全过滤：`{_u}`（{_why}类）未拦下，"
                                "自动化会去触碰不可逆的写操作")
        for _u in ("https://x/api/order/save", "https://x/api/goods/list"):
            if _biz.unsafe_reason(_u):
                problems.append(f"安全过滤：`{_u}` 是普通业务接口，却被误拦"
                                f"（{_biz.unsafe_reason(_u)}）—— 过滤过宽会让侦察整体失效")

        # ③ 业务面识别：隐藏字段 / 渲染后 DOM / 查询参数三个来源都要接上
        _BIZ_HTML = (
            '<html><body><form action="/api/order/save" method="post">'
            '<input type="hidden" name="orderStatus" value="0">'
            '<input type="hidden" name="amount" value="100">'
            '<input type="text" name="remark">'
            '<input type="text" name="keyword">'
            '</form>'
            '<form action="/api/pay/submit" method="post">'
            '<input type="hidden" name="payAmount" value="100">'
            '</form>'
            '<script src="/static/app.js"></script></body></html>')
        _BIZ_JS = ('var cfg={sign:"abc", couponId:1};'
                   'var key="secretKey12345";'
                   'var s = md5(params + key); var signature = s;')

        class _Probe:  # noqa: D401
            """与 HttpProbe 同形的最小对象。"""

            def __init__(self, url: str, payload: dict[str, Any]) -> None:
                self.status = payload.get("status", 0)
                self.headers = payload.get("headers", {})
                self.body_snippet = payload.get("body", "")
                self.final_url = url
                self.tls: dict[str, Any] = {}

        class _BizCtx:  # noqa: D401
            """只实现侦察真正会用到的接口，避免自测依赖完整上下文。"""

            target_name = "自测业务系统"
            target_url = "https://x/"
            domain = "x"
            baseline_body = _BIZ_HTML
            profile = {"name": "深度档", "risk_level": "deep", "_key": "deep"}
            probe_count = 0

            def __init__(self, *, allow_write: bool = False,
                         accounts: list[Any] | None = None,
                         responses: dict[str, Any] | None = None) -> None:
                self.fp_result = {"_render_html": _BIZ_HTML}
                self.js_result = {"bodies": [_BIZ_JS], "inline_scripts": [],
                                  "urls": ["/api/goods/list?goodsId=1001"]}
                self.allow_write = allow_write
                self.accounts = accounts or []
                self.submissions: list[dict[str, Any]] = []
                self._cache: dict[str, Any] = {"url_pool_coverage": [
                    "https://x/api/goods/detail?goodsId=1001"]}
                self.responses = responses or {}
                self.errors: list[str] = []
                self.notes: list[str] = []
                self.profile_name = "deep"

            def risk_allowed(self, risk: str) -> bool:  # noqa: ANN401
                return risk in ("safe", "standard", "deep")

            def get(self, url: str, method: str = "GET", **kw: Any) -> Any:  # noqa: ANN401, ARG002
                payload = self.responses.get(url)
                if payload is None:
                    payload = {"status": 404, "headers": {}, "body": ""}
                return _Probe(url, payload)

            def data_submit(self, url: str, payload: dict[str, Any], **kw: Any) -> dict[str, Any]:  # noqa: ANN401
                # 这里刻意**不**复用生产实现：自测要验证的是「侦察会不会在
                # 未授权时也去发写请求」，用生产实现会把「闸门在哪一层」测糊。
                if not self.allow_write:
                    raise PermissionError("未开启受控写验证")
                self.submissions.append({"url": url, "fields": sorted(payload),
                                         "kind": "业务参数差分"})
                return self.responses.get(
                    f"POST::{url}::" + json.dumps(payload, sort_keys=True),
                    {"status": 200, "body": "{}", "headers": {}})

        _bc = _BizCtx()
        _surf = _biz.build_surface(_bc)
        _hidden = [p for p in _surf.params if p.origin == "form-hidden"]
        if not _hidden:
            problems.append("业务面识别：表单里的隐藏字段未被识别"
                            "（隐藏字段是「客户端可控」最直接的证据，漏了就少一块）")
        if not any(p.param == "amount" for p in _surf.params):
            problems.append("业务面识别：隐藏字段 amount 未进入敏感参数清单")
        if not any(p.kind == _biz.PK_IDENTITY and p.origin == "url-query"
                   for p in _surf.params):
            problems.append("业务面识别：已枚举 URL 的查询参数未参与识别"
                            "（如 ?goodsId=1001 → 可枚举标识）")
        if not any(p.origin == "js-payload" for p in _surf.params):
            problems.append("业务面识别：前端脚本里的请求字段未参与识别")
        _paid = [e for e in _surf.unsafe if "资金" in (e.unsafe_reason or "")]
        if not _paid:
            problems.append("业务面识别：支付表单未被安全过滤标记为「不可自动触碰」")

        # ④ 差分判据三段式 —— 这条是整个 P4 的误报防线
        #    最容易犯的错是「看到响应里出现了篡改值就报高危」。
        #    但响应里出现该值可能只是**回显**，不代表服务端采信。
        #    三段式必须能把「只有被篡改字段自身变了」判成「不下结论」。
        def _diff(base_body: str, tmpr_body: str) -> str:
            rec = _biz.DiffRecord(kind="write", endpoint="https://x/api/order/save",
                                  method="POST", param="amount", original="100",
                                  tampered="0.01", verdict="", detail="")
            _biz._judge_differential(rec, base_body, tmpr_body, "amount", "0.01")
            return rec.verdict

        _B = '{"code":0,"data":{"amount":100,"total":100,"qty":1}}'
        _T_trust = '{"code":0,"data":{"amount":0.01,"total":0.01,"qty":1}}'
        _T_echo = '{"code":0,"data":{"amount":0.01,"total":100,"qty":1}}'
        _T_ignore = '{"code":0,"data":{"amount":100,"total":100,"qty":1}}'

        if _diff(_B, _T_trust) != "PROVEN":
            problems.append("差分判据：服务端用客户端值算出了**其他**业务字段"
                            f"（total 跟着变成 0.01），却未判为确证"
                            f"（实际 {_diff(_B, _T_trust)!r}）—— 真问题被漏掉")
        if _diff(_B, _T_echo) != "INCONCLUSIVE":
            problems.append("差分判据：响应中**只有被篡改字段自身**变成非法值，"
                            f"这是回显不是采信，必须判「不下结论」，实际 "
                            f"{_diff(_B, _T_echo)!r} —— 这正是业务逻辑类误报的主源")
        if _diff(_B, _T_ignore) != "VALIDATED":
            problems.append("差分判据：篡改后所有业务字段与基线一致（服务端忽略了该字段），"
                            f"应判「服务端未采信」，实际 {_diff(_B, _T_ignore)!r}")
        if _diff(_B, "<html>not json</html>") != "INCONCLUSIVE":
            problems.append("差分判据：响应不是结构化 JSON，逐字段比对无从谈起，"
                            "必须判「不下结论」")

        # ⑤ 没有对照就没有结论：基线失败 / 响应不可采信时不得下任何结论
        _r404 = _biz.readonly_diff(_bc, _surf)[0]
        _bad = [r for r in _r404 if r.baseline_status == 404 and r.verdict != "INCONCLUSIVE"]
        if _bad:
            problems.append("差分实验：基线请求返回 404（拿不到有效对照）却仍下了结论 —— "
                            "无对照的结论不可复测")

        # ⑥ 写差分三重约束：未授权时一次请求都不许发
        _wrecs, _wnotes, _wblocks = _biz.write_diff(_bc, _surf)
        if _wrecs or _bc.submissions:
            problems.append("写差分：未开启受控写验证却发出了写请求"
                            f"（{len(_bc.submissions)} 次）")
        if not _wblocks:
            problems.append("写差分：未授权时未给出「为什么没做」的说明"
                            "（报告会显示成「做过且没问题」）")

        # ⑦ 走**真实执行路径**：DetectorRegistry.execute 对人工项的处理
        #    前面几条验的是侦察部件，这一条验的是「它在生产路径上怎么被用」。
        class _CheckItemLike:  # noqa: D401
            id = "WSTG-BUSL-01"
            name = "业务逻辑数据验证测试"
            category = "BUSL"
            category_name = "业务逻辑"
            compliance = "等保2.0 数据完整性"

        _manual_spec = make_manual(
            "WSTG-BUSL-01", name="业务逻辑数据验证测试",
            procedure="1) 逐字段测边界值", expect="服务端做三重校验",
            why_manual="需要业务知识", recon=_biz.recon_busl01)
        _reg2 = DetectorRegistry()
        _reg2.register(_manual_spec)

        _res_manual = _reg2.execute(_CheckItemLike(), _bc,
                                    applicability_state="适用")
        if _res_manual.state != STATE_MANUAL:
            problems.append(f"业务逻辑项：侦察跑了但**没有确证**任何问题时，"
                            f"状态必须是「{STATE_MANUAL}」，实际 {_res_manual.state!r} "
                            "—— 侦察没抓到不等于业务逻辑没问题，判通过就是造假")
        if not _res_manual.recon_ran:
            problems.append("业务逻辑项：侦察明明执行了，recon_ran 却是 False "
                            "（报告会把「已做过功课」显示成「没做」）")
        if "自动侦察结论" not in (_res_manual.note or ""):
            problems.append("业务逻辑项：侦察结论未写进该项说明（报告里看不到）")
        if "已定位到的具体对象" not in (_res_manual.note or ""):
            problems.append("业务逻辑项：已定位对象清单未写进该项说明 —— "
                            "这是「省人工时间」的实际产出，丢了就等于没补盲区")
        if "人工执行步骤" not in (_res_manual.note or ""):
            problems.append("业务逻辑项：原始人工步骤被侦察结论挤掉了"
                            "（侦察只覆盖可自动证的部分，人工步骤必须保留）")
        if _res_manual.executable:
            problems.append("业务逻辑项：人工项被标成 executable=True，"
                            "会让它混进「自动执行」统计里虚高可信通过率")

        # 附：侦察确证时必须升级为「不通过」，否则等于把已经拿到手的漏洞藏起来
        _bc_trust = _BizCtx()
        _bc_trust.responses = {
            "https://x/api/goods/detail?goodsId=1":
                {"status": 200, "body": '{"code":0,"data":{"goodsId":1,"stock":99}}'},
            "https://x/api/goods/detail?goodsId=1001":
                {"status": 200, "body": _B},
        }
        # 直接注入一条确证的差分记录，验证注册表的升级路径
        _bc_trust._cache["business_diffs"] = ([_biz.DiffRecord(
            kind="write", endpoint="https://x/api/order/save", method="POST",
            param="amount", original="100", tampered="0.01", verdict="PROVEN",
            detail="total 随之变成 0.01", changed_fields=["total"],
            derived_fields=["total"])], [], [])
        _res_proved = _reg2.execute(_CheckItemLike(), _bc_trust,
                                    applicability_state="适用")
        if _res_proved.state != STATE_FIND:
            problems.append(f"业务逻辑项：侦察**确证**了问题，状态却仍是 "
                            f"{_res_proved.state!r}（应为「{STATE_FIND}」）"
                            "—— 已确证的问题被留在了人工清单里，等于藏漏洞")
        elif not _res_proved.findings:
            problems.append("业务逻辑项：状态判为「不通过」却没有携带发现对象")
        elif "人工执行步骤" not in (_res_proved.note or ""):
            problems.append("业务逻辑项：确证后未保留残留人工步骤的提示 —— "
                            "读者会以为这一项已经全部验完")
        elif "仍有" not in (_res_proved.note or "") and \
                "仍须执行" not in (_res_proved.note or ""):
            problems.append("业务逻辑项：确证后未说明「还有人工作业没做」")

        # 归口一致性：差分确证的发现**不得**归到那些被安全过滤排除的项。
        # 曾经按「金额类参数 → BUSL-10（支付功能）」归口，但 BUSL-10 的侦察原则
        # 正是「资金链路不做任何自动化触碰」—— 支付类接口在安全过滤那一步就被
        # 拦下了，永远跑不到差分。于是那条归口分支是死代码，
        # 真问题是「订单金额被采信」被归到了一个不会被执行、报告里也不会出现的项下。
        _routed = {f.item_id for f in _biz._diff_findings(_bc_trust, [_biz.DiffRecord(
            kind="write", endpoint="https://x/api/order/save", method="POST",
            param="amount", original="100", tampered="0.01", verdict="PROVEN",
            detail="total 随之变成 0.01", changed_fields=["total"],
            derived_fields=["total"])])}
        if not _routed:
            problems.append("差分归口：确证的差分记录未产出任何发现")
        if "WSTG-BUSL-10" in _routed:
            problems.append("差分归口：确证的发现被归到 BUSL-10（支付功能），"
                            "而该项的侦察原则是「资金链路不做任何自动化触碰」—— "
                            "归口按「字段叫什么名字」而不是按「证明了什么」，"
                            "问题会被归进一个永远不会执行的项里")
        if "WSTG-BUSL-01" not in _routed:
            problems.append(f"差分归口：金额类字段被采信应归 BUSL-01，实际归到 {_routed}")

        # ⑧ 侦察自身出错时，必须是「说明原因 + 保持人工项」，不得静默降级
        def _boom(_ctx: Any) -> Any:  # noqa: ANN401
            raise RuntimeError("自测注入的侦察异常")

        _reg3 = DetectorRegistry()
        _reg3.register(make_manual(
            "WSTG-BUSL-01", name="侦察异常项", procedure="1) 人工步骤",
            expect="判定标准", why_manual="需要业务知识", recon=_boom))
        _res_err = _reg3.execute(_CheckItemLike(), _bc, applicability_state="适用")
        if _res_err.state != STATE_MANUAL:
            problems.append(f"业务逻辑项：侦察抛异常时状态变成了 {_res_err.state!r}"
                            "（应保持「待人工执行」，异常不等于没问题）")
        elif "侦察异常" not in (_res_err.note or ""):
            problems.append("业务逻辑项：侦察异常未写进结论（会静默降级成普通人工项）")
        elif "没有任何自动化前置覆盖" not in (_res_err.note or ""):
            problems.append("业务逻辑项：侦察异常时未提示「本项无自动化覆盖」")

        # ⑨ 前端签名证明必须双向：只有算法没有密钥时不得报
        #    （签名可能由服务端下发的 nonce 参与，前端算不出完整签名 ——
        #     这时报「签名可伪造」就是孤立信号误报）
        _sig_hit = _biz.prove_frontend_signature(_bc, _surf)
        if not _sig_hit:
            problems.append("前端签名：脚本里同时出现签名算法与硬编码密钥，却未确证"
                            "（签名可复算 = 防篡改归零，这是能自动证的硬问题）")

        class _BizNoKey(_BizCtx):  # noqa: D401
            def __init__(self) -> None:
                super().__init__()
                self.js_result = {"bodies": ["var s = md5(params + nonce);"
                                             "var signature = s;"],
                                  "inline_scripts": [], "urls": []}

        _bc_nokey = _BizNoKey()
        if _biz.prove_frontend_signature(_bc_nokey, _biz.build_surface(_bc_nokey)):
            problems.append("前端签名：脚本里只有签名算法、**没有**密钥常量，"
                            "却仍报「签名可伪造」—— 密钥可能在服务端，属孤立信号误报")

        _recon_n = sum(1 for i in range(1, 11)
                       if getattr(_biz, f"recon_busl{i:02d}", None))

        # ⑩ lead 不得出现重复行。
        #    这条是被真实 bug 逼出来的：安全过滤清单原本在分支里和公共收尾处
        #    各追加一次，于是 BUSL-10 的「未自动触碰」清单印了两遍，
        #    读者会以为有两批不同的接口被排除。这类重复不会让任何断言失败，
        #    只会让报告悄悄变长、变不可信。
        for _tail in ("01", "02", "03", "04", "05", "06", "08", "09", "10"):
            _iid = f"WSTG-BUSL-{_tail}"
            _fn = getattr(_biz, f"recon_busl{_tail}", None)
            if _fn is None:
                continue
            _o = _fn(_bc)
            _lines = [x for x in (_o.lead or []) if x.strip()]
            _dupes = {x for x in _lines if _lines.count(x) > 1}
            if _dupes:
                problems.append(f"业务逻辑 lead：{_iid} 的已定位清单出现重复行 "
                                f"（{len(_dupes)} 条，如 {sorted(_dupes)[0][:60]!r}）"
                                "—— 读者会以为有两批不同的对象")

        print(f"\n[环境] 业务逻辑侦察已校验：参数分类双向、安全过滤双向、"
              f"三个来源识别、差分三段式判据、无对照不下结论、"
              f"写差分未授权零请求、注册表三种路径（未确证/确证/异常）、"
              f"前端签名双向、lead 无重复行；{_recon_n} 项挂有侦察入口")
    except Exception as e:  # noqa: BLE001
        problems.append(f"业务逻辑侦察检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ㉓：攻击链必须「只串实测、不造事实」----
    # 攻击链是本轮新增的**推理层**，也是整个引擎里最容易产出假结论的一层：
    # 它靠能力关系把发现串起来，一不小心就会把「扫到一个认证绕过」
    # 推成「拿到控制权」。三个方向都要钉住：
    #   ① 正向：单点实测的能力确实能串成链、能回填「能力缺口」的目标；
    #   ② 反向：纯推理链不产出、不判「已达成」、不回填；
    #   ③ 隔离：已达成与候选必须分成两档，否则报告会把推理与实测量齐。
    try:
        from engine.attackchain import plan_attack_chains  # noqa: PLC0415
        from engine.redteam import (  # noqa: PLC0415
            INCONCLUSIVE as _RT_INC,
        )
        from engine.redteam import OBJ_TAKE_CONTROL as _RT_TC  # noqa: PLC0415
        from engine.redteam import ObjectiveOutcome as _RtObj  # noqa: PLC0415

        class _CF:  # noqa: D401
            """轻量发现替身：只实现攻击链真正会读的字段。"""

            def __init__(self, item_id: str, title: str = "",
                         endpoint: str = "", proof: dict | None = None,
                         severity: str = "高危"):
                self.item_id = item_id
                self.title = title
                self.endpoint = endpoint
                self.method = "POST"
                self.severity = severity
                self.evidence_level = "B"
                self.extra = {"proof": proof} if proof else {}

        _rce = _CF("WSTG-INPV-12", "命令注入", "https://t/runcmd",
                   proof={"state": "已达成"})
        _git = _CF("EXT-CD-03", "版本控制目录可访问", "https://t/.git/",
                   proof={"state": "已达成"})
        _authn = _CF("WSTG-ATHN-04", "认证方案可绕过", "https://t/login")
        _hdr = _CF("WSTG-CONF-07", "缺少 HSTS", "https://t/")

        # ① 正向：单点实测 → 链尾命中目标能力 → 回填「能力缺口」的目标。
        #    没有这条通道，实测到的战果会因为「该目标没有独立攻击路径」
        #    被埋成「未能验证」—— 那是另一种形式的假结论。
        _oc_tc = _RtObj(objective=_RT_TC, label="拿到控制权", result=_RT_INC)
        plan_attack_chains([_rce, _hdr], [_oc_tc])
        if _oc_tc.result != "已达成":
            problems.append(
                "攻击链：命令注入已实测证明，却未回填「拿到控制权」—— "
                "实测战果会被埋成「未能验证」")
        if _oc_tc.result == "已达成" and not _oc_tc.chain_evidence:
            problems.append("攻击链：回填后的目标必须带可见证据（否则「已达成」无据）")
        if _oc_tc.result == "已达成" and not _oc_tc.chain_note:
            problems.append("攻击链：回填必须标明来源（打出来的 vs 推出来的）")

        # ② 反向：没有任何实测证据时一条链都不许产出，更不许回填
        _oc_tc2 = _RtObj(objective=_RT_TC, label="拿到控制权", result=_RT_INC)
        _plan2 = plan_attack_chains([_authn], [_oc_tc2])
        if _plan2.proven:
            problems.append("攻击链：无实测证据时不得产出「已达成」链")
        if _oc_tc2.result == "已达成":
            problems.append("攻击链：候选链绝不能回填「已达成」")
        if not _plan2.notes:
            problems.append("攻击链：未产链时必须给出说明，不得静默跳过")

        # ③ 隔离：已达成与候选必须分成两档
        _plan3 = plan_attack_chains([_rce, _git, _authn], [])
        _states = {c.state for c in _plan3.chains}
        if len(_states) < 2:
            problems.append(
                "攻击链：已达成与候选必须分成两档（否则报告会把推理与实测量齐）")
        if not _plan3.candidates:
            problems.append("攻击链：凭据 + 认证绕过应产出候选链（通向管理功能）")
        if any(len(c.nodes) > 3 for c in _plan3.chains):
            problems.append(
                "攻击链：链长超过上限 —— 4 环以上的链几乎全是纸面推演，"
                "累积条件概率极低，写进报告只会稀释真正有价值的链")

        # ④ 与攻击能力无关的发现不得成为节点
        _plan4 = plan_attack_chains([_hdr], [])
        if _plan4.chains:
            problems.append("攻击链：与攻击能力无关的发现（如缺 HSTS）不得入链")

        print(f"\n[环境] 攻击链已校验：单点实测可回填能力缺口（含证据与来源）、"
              f"无实测锚点不产链且给说明、已达成与候选分档、"
              f"链长限于 3 环以内、无关发现不入链；"
              f"本次示例产出 {len(_plan3.chains)} 条链"
              f"（已达成 {len(_plan3.proven)}、候选 {len(_plan3.candidates)}）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"攻击链检查未能执行：{type(e).__name__}: {str(e)[:160]}")

    # ---- 不变量 ㉔：越权类复现必须自带会话上下文（详见模块文档）----
    # 这一条要**真的把生成的脚本跑起来**才算验证 —— 只检查模板字符串里有没有
    # 「SESSION_ROLES」这种断言，恰恰是本项目最容易自欺的一种：
    # 变量名在、逻辑不通，字符串断言照样通过。
    # 所以这里起一个本地假应用，把脚本以六种配置各跑一次，只看**退出码与结论字样**。
    try:
        import subprocess as _sp  # noqa: PLC0415
        import tempfile as _tf  # noqa: PLC0415

        from models import Finding  # noqa: PLC0415
        from verify.framework import ScriptBuilder as _SB  # noqa: PLC0415

        _mode = {"same": True}

        class _AuthzApp(http.server.BaseHTTPRequestHandler):
            """假应用：/api/orders/1002 是「疑似越权」接口，其余路径 404。

            匿名 → 401；带 sid Cookie → 200。
            same=True 时无论谁请求都返回同一份数据（越权）；
            same=False 时按当前身份返回（正常实现）。
            """

            protocol_version = "HTTP/1.1"

            def _emit(self, code, payload):
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):  # noqa: N802
                if self.path.split("?")[0] != "/api/orders/1002":
                    self._emit(404, {"error": "not found"})
                    return
                sid = ""
                for part in (self.headers.get("Cookie") or "").split(";"):
                    if part.strip().startswith("sid="):
                        sid = part.strip()[4:]
                if not sid:
                    self._emit(401, {"error": "login required"})
                    return
                self._emit(200, {"id": 1002,
                                 "userId": "victim_owner" if _mode["same"] else sid,
                                 "total": 88})

            def log_message(self, *a):  # noqa: D102
                pass

        class _AuthzSrv(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        _srv = _AuthzSrv(("127.0.0.1", 0), _AuthzApp)
        _port = _srv.server_address[1]
        threading.Thread(target=_srv.serve_forever, daemon=True).start()
        _base = f"http://127.0.0.1:{_port}"

        _azf = Finding(
            item_id="WSTG-ATHZ-02",
            title="疑似水平越权：同角色账号返回完全相同的个人数据",
            target=_base, endpoint=_base + "/api/orders/1002",
            method="GET", severity="高危", confidence="Medium", evidence_level="B",
            grading_basis="多账号响应比对", description="同一角色不同用户返回相同数据",
            technical_detail="同角色账号：user_a, user_b；响应长度一致：[1234, 1234]",
            impact="任一用户可读取他人数据", reproduction="两个账号分别请求该地址",
            remediation="服务端强制附带当前用户 ID", compliance="等保2.0 访问控制",
            source_tool="authz_matrix", extra={"accounts": ["user_a", "user_b"]},
        )
        _td = Path(_tf.mkdtemp(prefix="aiscan_sess_"))
        _sb = _SB(_td)
        _script = _sb.generate(_azf, _base)
        _skel = Path(_sb.session_template) if _sb.session_template else None

        if not _azf.extra.get("repro_needs_session"):
            problems.append("会话上下文：越权类发现未标记 repro_needs_session，"
                            "报告将看不出该条复现需要凭据")
        if _azf.extra.get("repro_kind") != "cross_role":
            problems.append("会话上下文：多账号越权发现未使用跨身份复现模板")
        if _skel is None or not _skel.exists():
            problems.append("会话上下文：未落盘会话文件骨架（操作者将无从填写）")

        def _run_script(env_extra):
            _env = dict(os.environ)
            _env.pop("AISCAN_SESSION_FILE", None)
            for _k in list(_env):
                if _k.startswith(("AISCAN_COOKIE_", "AISCAN_AUTH_")):
                    _env.pop(_k, None)
            _env.update(env_extra)
            _pr = _sp.run([sys.executable, str(_script), "--target", _base],
                          capture_output=True, text=True, timeout=90,
                          encoding="utf-8", errors="replace", env=_env)
            return _pr.returncode, (_pr.stdout or "") + (_pr.stderr or "")

        # ① 骨架原样未填：这是最常见的疏漏路径
        _c, _o = _run_script({})
        if _c != 2 or "无法判定" not in _o:
            problems.append("会话上下文：缺凭据时必须判「无法判定」并说明补齐方式，"
                            f"实际退出码 {_c}")
        if "[未复现]" in _o:
            problems.append("会话上下文：缺凭据时给出了「未复现」结论 —— "
                            "这是把「没验证到」冒充成「已修复」")

        # ② 两个角色填成同一个账号
        _c, _o = _run_script({"AISCAN_COOKIE_user_a": "sid=A",
                              "AISCAN_COOKIE_user_b": "sid=A"})
        if _c != 2 or "填了两遍" not in _o:
            problems.append("会话上下文：两个角色凭据相同时必须拒判"
                            "（否则「两个身份读到同一份数据」是伪结论）")

        # ③ 两个身份拿到同一份数据 → 复现成功，且保留归属确认边界
        _mode["same"] = True
        _c, _o = _run_script({"AISCAN_COOKIE_user_a": "sid=A",
                              "AISCAN_COOKIE_user_b": "sid=B"})
        if _c != 0:
            problems.append(f"会话上下文：跨身份越权应复现成功，实际退出码 {_c}")
        if _c == 0 and "须人工核对" not in _o:
            problems.append("会话上下文：复现成功必须保留「数据归属须人工确认」"
                            "的边界说明，不得代替人工定级")

        # ④ 服务端按身份过滤（正常实现）→ 如实判未复现
        _mode["same"] = False
        _c, _o = _run_script({"AISCAN_COOKIE_user_a": "sid=A",
                              "AISCAN_COOKIE_user_b": "sid=B"})
        if _c != 1:
            problems.append(f"会话上下文：服务端已按身份过滤时应判「未复现」，"
                            f"实际退出码 {_c}")

        # ⑤ 会话文件通道（不依赖环境变量）必须同样生效
        _mode["same"] = True
        if _skel is not None:
            _skel.write_text(json.dumps({
                "roles": {"user_a": {"cookies": "sid=A", "headers": {}},
                          "user_b": {"cookies": "sid=B", "headers": {}}}
            }, ensure_ascii=False), encoding="utf-8")
            _c, _o = _run_script({})
            if _c != 0:
                problems.append(f"会话上下文：会话文件通道未生效（退出码 {_c}）—— "
                                "操作者将不得不手工改脚本")
            if "sid=A" in _o or "sid=B" in _o:
                problems.append("会话上下文：凭据原文出现在脚本输出里")

        _srv.shutdown()
        print("\n[环境] 会话上下文已校验：越权复现脚本自行读取会话文件 / 环境变量"
              "（无需改脚本）；缺凭据判「无法判定」而非「未复现」；"
              "同一账号填两遍拒判；跨身份同数据判复现成功并保留归属确认边界；"
              "按身份过滤如实判未复现；凭据不出现在输出中")
    except Exception as e:  # noqa: BLE001
        problems.append(f"会话上下文检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 不变量 ㉕：nuclei 结果必须回填到检查项，方向只能收紧（详见模块文档）----
    # 这一条要钉的是「报告自相矛盾」：同一检查项在第 2 章有实测发现、
    # 在第 3 章却写「通过」。两个栏目打架时读者只会信更干净的那个。
    try:
        from engine.nuclei_map import (  # noqa: PLC0415
            backfill_external_findings,
            is_vulnerability_template,
            map_template,
            mapping_stats,
        )
        # 全部用别名导入：在函数内 `from ... import STATE_PASS` 会把这个名字
        # 变成整个 main() 的局部变量，于是本块之前对模块级 STATE_PASS 的引用
        # 全部变成「访问未绑定局部变量」。这个坑刚踩过一次。
        from engine.registry import STATE_FIND as _S_FIND  # noqa: PLC0415
        from engine.registry import STATE_MANUAL as _S_MANUAL  # noqa: PLC0415
        from engine.registry import STATE_NA as _S_NA  # noqa: PLC0415
        from engine.registry import STATE_NOTRUN as _S_NOTRUN  # noqa: PLC0415
        from engine.registry import STATE_PASS as _S_PASS  # noqa: PLC0415
        from engine.registry import ItemResult  # noqa: PLC0415

        _stats = mapping_stats()
        # 归口表退化是静默的：表被改坏后所有模板走兜底，报告只表现为
        # 「某几项忽然不通过」，没人会注意。用下界把它钉住。
        if _stats.get("规则数", 0) < 40 or _stats.get("覆盖 tag 数", 0) < 150:
            problems.append(
                f"nuclei 归口：归口表规模异常（{_stats}）—— "
                "表被改坏后所有模板会静默走兜底项，某几项将永远收不到结论")
        if _stats.get("覆盖检查项数", 0) < 30:
            problems.append(
                f"nuclei 归口：仅覆盖 {_stats.get('覆盖检查项数')} 个检查项，"
                "归口粒度过粗，多数模板会挤进同一个兜底项")

        # 注入家族必须归到**不同**检查项 —— 早期「xss 一锅端」把存储型/反射型/
        # DOM 型全归成反射型，报告上三处是同一个检查项
        _ids = {map_template("x", {"tags": [t]}).item_id
                for t in ("sqli", "ssrf", "xss", "stored-xss", "rce", "lfi", "ssti")}
        if len(_ids) != 7:
            problems.append(f"nuclei 归口：注入类未能区分开，只落到 {len(_ids)} 个检查项")
        # 分不清受影响层的 CVE 必须标「依据不足」，不得静默猜一个
        if map_template("CVE-2024-0001", {"tags": ["cve"]}).confident:
            problems.append("nuclei 归口：分不清受影响层的 CVE 被当成了确定归口")
        if not map_template("CVE-2021-44228", {"tags": ["cve", "log4j"]}).confident:
            problems.append("nuclei 归口：带产品 tag 的 CVE 应给出确定归口")

        # 识别类命中不得回填 —— 否则检查项无端变「不通过」
        for _t, _sev, _want in (("tech-detect", "info", False),
                                ("waf-detect", "info", False),
                                ("sqli", "high", True),
                                ("exposure", "medium", True)):
            _got, _ = is_vulnerability_template({"tags": [_t]}, _sev)
            if _got is not _want:
                problems.append(
                    f"nuclei 回填：{_t}/{_sev} 的漏洞判定应为 {_want}，实际 {_got}")

        # 回填方向只能收紧 + 覆盖旧状态必须留痕 + 无归口必须报出来
        _res = [
            ItemResult(item_id="WSTG-INPV-05", name="SQL 注入", category="WSTG",
                       category_name="WSTG", state=_S_PASS, mode="自动"),
            ItemResult(item_id="WSTG-CONF-02", name="应用平台配置", category="WSTG",
                       category_name="WSTG", state=_S_NA, mode="自动"),
            ItemResult(item_id="WSTG-CONF-05", name="管理接口枚举", category="WSTG",
                       category_name="WSTG", state=_S_NOTRUN, mode="自动"),
            ItemResult(item_id="WSTG-ATHN-02", name="默认凭据", category="WSTG",
                       category_name="WSTG", state=_S_MANUAL, mode="人工"),
        ]

        class _NucF:  # noqa: D401
            """nuclei 发现替身：只实现回填真正会读的字段。"""

            def __init__(self, item_id, sev="高危", tags=("sqli",)):
                self.item_id = item_id
                self.title = f"{item_id} 实测命中"
                self.severity = sev
                self.source_tool = "nuclei"
                self.extra = {"template_id": "t", "tags": list(tags)}

        _finds = [
            _NucF("WSTG-INPV-05"), _NucF("WSTG-INPV-05"),
            _NucF("WSTG-CONF-02", tags=("misconfig",)),
            _NucF("WSTG-CONF-05", tags=("actuator",)),
            _NucF("WSTG-ATHN-02", tags=("default-login",)),
            _NucF("WSTG-NOSUCH-99", tags=("sqli",)),          # 清单里没有该项
            _NucF("WSTG-CONF-02", sev="info", tags=("tech-detect", "nginx")),
        ]
        _other = _NucF("WSTG-INPV-05")            # 非本来源，不得被回填处理
        _other.source_tool = "builtin"
        _finds.append(_other)
        _rep = backfill_external_findings(_res, _finds)

        if _res[0].state != _S_FIND:
            problems.append("nuclei 回填：「通过」项有实测发现时未收紧为「不通过」")
        if "原状态：通过" not in _res[0].note:
            problems.append("nuclei 回填：覆盖旧状态未留痕（读者无法判断是否被改判过）")
        if _res[1].state != _S_FIND or "适用性" not in _res[1].note:
            problems.append("nuclei 回填：N/A 项与实测命中冲突时必须改判并写明冲突")
        if _res[2].state != _S_FIND or _res[3].state != _S_FIND:
            problems.append("nuclei 回填：「未执行 / 待人工」项有实测证据时未收紧")
        if _rep.attached != 5 or _rep.items_touched != 4:
            problems.append(f"nuclei 回填：挂接计数异常"
                            f"（条数 {_rep.attached}/期望 5，项数 {_rep.items_touched}/期望 4）")
        if _rep.skipped_non_vuln != 1:
            problems.append("nuclei 回填：识别类命中未被拦下"
                            "（会让检查项无端变成「不通过」）")
        if len(_rep.unmapped) != 1:
            problems.append("nuclei 回填：找不到归口的发现必须报出来，不得静默丢弃")
        if "找不到对应检查项" not in "".join(_rep.notes):
            problems.append("nuclei 回填：未归口发现必须写进 notes（否则没人会去补归口表）")

        # 无发现时回填必须完全不动状态 —— 尤其不能把「未执行」悄悄变成「通过」
        _res2 = [
            ItemResult(item_id="WSTG-INPV-05", name="x", category="WSTG",
                       category_name="WSTG", state=_S_NOTRUN, mode="自动"),
            ItemResult(item_id="WSTG-CONF-02", name="x", category="WSTG",
                       category_name="WSTG", state=_S_PASS, mode="自动"),
        ]
        backfill_external_findings(_res2, [])
        if [_r.state for _r in _res2] != [_S_NOTRUN, _S_PASS]:
            problems.append("nuclei 回填：无发现时改动了状态 —— "
                            "回填放宽了结论，这是绕过检测的新路径")

        print(f"\n[环境] nuclei 回填已校验：归口表覆盖 {_stats.get('覆盖 tag 数')} 个 tag / "
              f"{_stats.get('覆盖检查项数')} 个检查项；注入类归口互不吞并；"
              f"CVE 分层归口、分不清即标注依据不足；识别类命中不回填；"
              f"回填方向只能收紧且留痕；未归口发现如实报出")
        print(f"[环境] 回填示例：{_rep.summary()}")
    except Exception as e:  # noqa: BLE001
        problems.append(f"nuclei 回填检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 不变量 ㉖：前端产物采集失败必须给出「覆盖度下降」并点名受影响项 ----
    # 这是与「骨架页未渲染」并列的第二种结构性缺口，且更隐蔽：根页面正文很长、
    # 响应头齐全、表单也有，充分度看起来不低 —— 但依赖前端产物的那一整类检查项
    # 其实是在**空数据上跑完的**，它们报的「通过」没有任何依据。
    # 只给一个分数不够：读者不知道该怀疑哪几项，等于没说。
    try:
        from engine.checks.base import artifact_coverage  # noqa: PLC0415
        from engine.registry_runner import build_registry  # noqa: PLC0415

        _reg = build_registry()

        def _jsctx(ref, fetched, inline=0, urls=0, errors=None):
            return SimpleNamespace(js_result={
                "scripts_found": [f"https://t/s{i}.js" for i in range(ref)],
                "scripts_fetched": fetched,
                "bodies": ["x"] * fetched,
                "inline_scripts": ["y"] * inline,
                "urls": [f"/api/{i}" for i in range(urls)],
                "errors": list(errors or []),
            })

        # ① 全部抓取失败 → full，且必须点名受影响检查项（按注册表 requires=["js"] 取）
        _a = artifact_coverage(_jsctx(5, 0, errors=["https://t/s0.js: Timeout"]), _reg)
        if _a["loss"] != "full":
            problems.append(f"覆盖度：产物全抓失败应判 full，实际 {_a['loss']}")
        if _a["affected_count"] < 5:
            problems.append(
                f"覆盖度：受影响检查项只有 {_a['affected_count']} 项 —— "
                "应覆盖注册表里全部 requires=[\"js\"] 的项，否则读者不知道该怀疑哪些结论")
        if not _a["affected_items"]:
            problems.append("覆盖度：受影响检查项清单为空（点名是本项唯一的行动价值）")
        if not _a["notes"]:
            problems.append("覆盖度：产物全抓失败必须给出说明，不得静默降分")
        if not _a["degraded"]:
            problems.append("覆盖度：产物全抓失败必须标记 degraded（否则 N/A 会被当成结论）")

        # ② 部分抓取失败 → partial，且要写明「未取回的那几份里有什么完全未知」
        _b = artifact_coverage(_jsctx(5, 2), _reg)
        if _b["loss"] != "partial" or not _b["degraded"]:
            problems.append(f"覆盖度：5 份只取回 2 份应判 partial，实际 {_b['loss']}")
        if _b["failed"] != 3:
            problems.append(f"覆盖度：未取回份数应为 3，实际 {_b['failed']}")

        # ③ 页面本就没引用外部脚本 → 不得报覆盖度下降
        #    （服务端渲染的站点本就如此；每份报告都报警等于没报警）
        _c = artifact_coverage(_jsctx(0, 0, inline=2, urls=3), _reg)
        if _c["loss"] != "none" or _c["degraded"]:
            problems.append("覆盖度：页面未引用外部脚本时不得报覆盖度下降")
        if _c["notes"]:
            problems.append("覆盖度：无反例时不应产生告警说明")

        # ④ 完全没素材（既无外部脚本也无内联脚本）→ 要提示依赖产物的项按「未覆盖」读
        _d = artifact_coverage(_jsctx(0, 0), _reg)
        if _d["loss"] != "none" or not _d["notes"]:
            problems.append("覆盖度：页面无任何前端素材时必须给出说明")

        # ⑤ 素材已取得但一条接口都没提取到 → 说明接口面未知（不改 loss 档）
        _e = artifact_coverage(_jsctx(3, 3, urls=0), _reg)
        if not _e["notes"]:
            problems.append("覆盖度：提取不到接口地址时必须说明接口面未知")

        # ⑥ 分数必须真的被压低：采集素材齐全但产物全抓失败时，
        #    充分度不得仍报「充分」—— 否则那一整类检查项的 N/A 会被当成结论。
        class _CtxStub:  # noqa: D401
            """最小上下文替身：只实现 collection_report 真正会读的字段。"""

            def __init__(self, js):
                self.js_result = js
                self.baseline_body = "z" * 3000
                self.root_headers = {"Server": "nginx"}
                self.fp_result = {}
                self.target_url = "http://127.0.0.1:1"
                self.domain = "example.invalid"

            def get(self, url):  # noqa: D102
                return SimpleNamespace(body_snippet="", status=0, final_url="")

        from engine.checks.base import collection_report as _cr  # noqa: PLC0415

        def _mkjs(fetched):
            return {
                "scripts_found": [f"https://t/s{i}.js" for i in range(3)],
                "scripts_fetched": fetched,
                "bodies": ["x" * 3000] * fetched,
                "inline_scripts": ["y"],
                "urls": [f"/api/{i}" for i in range(8)],
                "errors": [] if fetched == 3 else ["timeout"],
            }

        _ok = _cr(_CtxStub(_mkjs(3)), _reg)
        _bad = _cr(_CtxStub(_mkjs(0)), _reg)
        if _ok.get("artifact_loss") != "none":
            problems.append(f"覆盖度：产物全部取回时应判 none，实际 {_ok.get('artifact_loss')}")
        if _bad.get("artifact_loss") != "full":
            problems.append("覆盖度：collection_report 未把 artifact_loss 带出来")
        if not _bad.get("artifact_affected_items"):
            problems.append("覆盖度：collection_report 未带出受影响检查项清单")
        if _bad["score"] > 39 or _bad["level"] != "不足":
            problems.append(
                f"覆盖度：产物全抓失败时充分度未压到「不足」"
                f"（实际 {_bad['score']}/{_bad['level']}）—— "
                "依赖产物的检查项的 N/A 会被当成「目标不具备该功能」")
        if _bad["score"] >= _ok["score"]:
            problems.append(
                f"覆盖度：产物全抓失败的充分度（{_bad['score']}）没有低于采集成功的"
                f"（{_ok['score']}）—— 覆盖度下降没有被评分反映")
        if not _bad.get("notes"):
            problems.append("覆盖度：覆盖度下降必须在 notes 里说明原因")

        print("\n[环境] 前端产物覆盖度已校验：全抓失败判 full 并点名受影响项"
              f"（{_a['affected_count']} 项）；部分失败判 partial；"
              f"页面无外部脚本时不误报；充分度 {_ok['score']} → {_bad['score']}"
              "（确实被压低）")
    except Exception as e:  # noqa: BLE001
        problems.append(f"前端产物覆盖度检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 不变量 ㉗：nuclei 预算约束 + 掐断抢救 ----
    # nuclei 自己发请求，不受本工程节流器控制。这里要钉住的是三件事：
    # 减量只砍结构性跑不动的、分层保证高价值先跑完、被掐断时已写出的结果必须捡回来。
    try:
        from engine import nuclei_budget as _nbmod  # noqa: PLC0415
        from engine import nuclei_runner as _nrmod  # noqa: PLC0415

        # 预算模块自己的内建自测也在这里跑一遍 —— 光靠手动 `-m` 触发，
        # 等于它永远不会在回归里被执行（这正是「静默失效」的典型形态）。
        import contextlib  # noqa: PLC0415
        import io as _io  # noqa: PLC0415

        _buf = _io.StringIO()
        with contextlib.redirect_stdout(_buf):
            _rc = _nbmod._selftest()
        if _rc != 0:
            problems.append("nuclei 预算模块内建自测未通过："
                            + _buf.getvalue().strip()[:220])

        _std_profile = {
            "risk_level": "standard",
            "rate": {"requests_per_second": 20, "timeout_seconds": 12, "retries": 2},
            "nuclei": {
                "severity_filter": ["critical", "high", "medium"],
                "template_tags_include": ["cve", "misconfig"],
                "template_tags_exclude": ["intrusive", "fuzz", "dos"],
                "rate_limit": 20, "bulk_size": 20, "concurrency": 8,
            },
        }

        def _rec(i, tid="t-cve-2024-0001", sev="high", path=None):
            p = path if path is not None else f"/p{i}"
            return {
                "template-id": tid,
                "info": {"name": f"T-{tid}", "severity": sev, "tags": ["cve"]},
                "host": "http://127.0.0.1:1",
                "matched-at": f"http://127.0.0.1:1{p}",
                "type": "http",
            }

        def _out_of(cmd):
            return Path(cmd[cmd.index("-o") + 1])

        class _FakeProc:
            def __init__(self, rc=1, stdout=""):
                self.returncode = rc
                self.stdout = stdout

        _real_subprocess = _nrmod.subprocess

        class _FakeSubprocess:
            TimeoutExpired = _real_subprocess.TimeoutExpired

            def __init__(self, behavior):
                self.behavior = behavior
                _FakeSubprocess.run = staticmethod(self._run)
                self.calls = 0

            def _run(self, cmd, **kw):  # noqa: D102
                self.calls += 1
                return self.behavior(self.calls, cmd)

        def _with_fake(behavior, fn, clock=None, measure_scope=False):
            fake = _FakeSubprocess(behavior)
            _nrmod.subprocess = fake
            try:
                nr = _nrmod.NucleiRunner(_std_profile, timeout=420,
                                         clock=clock or (lambda: 0.0),
                                         measure_scope=measure_scope)
                nr.binary = "nuclei"      # 假装已安装，走原生分支
                return fn(nr, fake)
            finally:
                _nrmod.subprocess = _real_subprocess

        # ① 计划本身：分层、排除不适用类型、限速不超声明
        _plan = _nrmod.build_plan(_std_profile)
        if len(_plan.passes) != 2:
            problems.append(f"nuclei 计划应分 2 趟（高价值 + 其余），实际 {len(_plan.passes)}")
        elif set(_plan.passes[0].severity) != {"critical", "high"}:
            problems.append("nuclei 第一趟必须是 critical/high（预算耗尽时它得先在手里）")
        for ps in _plan.passes:
            if "headless" not in ps.protocols_exclude or "code" not in ps.protocols_exclude:
                problems.append("nuclei 计划未排除结构性不适用的模板类型（减量没生效）")

        # ② 被掐断时抢救已写出的结果，且末行写残不得中断解析
        def _beh_timeout(call, cmd):
            out = _out_of(cmd)
            if call == 1:
                out.write_text(
                    "\n".join(json.dumps(_rec(i), ensure_ascii=False) for i in range(2)),
                    encoding="utf-8")
                return _FakeProc(1)
            # 第二趟：写出 1 条完整记录 + 1 行被硬截断的残行，随后被预算掐死
            out.write_text(
                json.dumps(_rec(9), ensure_ascii=False) + "\n" + '{"template-id": "trunc',
                encoding="utf-8")
            raise _real_subprocess.TimeoutExpired(cmd, 420)

        def _case_timeout(nr, fake):
            return nr.run("http://127.0.0.1:1"), fake

        res_t, fake_t = _with_fake(_beh_timeout, _case_timeout)
        if len(res_t.findings) != 3:
            problems.append(
                f"nuclei 被掐断后应抢救回 3 条（2 + 1），实际 {len(res_t.findings)} —— "
                "超时=整批归零等于把「没跑完」说成「没发现」")
        if not res_t.partial or not res_t.budget_exhausted:
            problems.append("nuclei 被掐断必须标记 partial / budget_exhausted")
        if not any("抢救" in n for n in res_t.notes):
            problems.append("nuclei 抢救了部分产出却未在 notes 里说明")
        if "截断" not in res_t.summary():
            problems.append("nuclei 执行摘要未提示「已截断」（读者会当成跑完了）")
        _pr = res_t.pass_results
        if not _pr or _pr[-1].get("status") != "timeout":
            problems.append(f"nuclei 趟状态未记录为 timeout：{_pr[-1] if _pr else '(空)'}")
        if len(res_t.commands) < 2 or "-jsonl" not in res_t.commands[0]:
            problems.append("nuclei 命令行未落盘 / 缺少 jsonl 输出（捡不回部分产出）")

        # ③ 预算在前一趟被吃光 → 后一趟是「未执行」，不是「跑了没发现」
        _clock = {"t": 0.0}

        def _beh_burn(call, cmd):
            _clock["t"] += 10_000.0      # 第一趟把整轮预算吃光
            _out_of(cmd).write_text(json.dumps(_rec(0), ensure_ascii=False), encoding="utf-8")
            return _FakeProc(1)

        def _case_burn(nr, fake):
            return nr.run("http://127.0.0.1:1"), fake

        res_b, fake_b = _with_fake(_beh_burn, _case_burn, clock=lambda: _clock["t"])
        if fake_b.calls != 1:
            problems.append(f"预算耗尽后不应再发起第二趟，实际发起了 {fake_b.calls} 趟")
        if len(res_b.pass_results) < 2 or res_b.pass_results[1].get("status") != "skipped":
            problems.append("预算耗尽导致未执行的趟必须记录为 skipped（不得并入「无发现」）")
        if not any("未执行" in n for n in res_b.notes):
            problems.append("预算耗尽致某趟未执行时必须在 notes 里点名")

        # ④ 分层引入的新风险：同一命中被两趟都跑到 → 必须去重
        def _beh_dup(call, cmd):
            _out_of(cmd).write_text(json.dumps(_rec(0, path="/same"), ensure_ascii=False),
                                    encoding="utf-8")
            return _FakeProc(1)

        def _case_dup(nr, fake):
            return nr.run("http://127.0.0.1:1"), fake

        res_d, _ = _with_fake(_beh_dup, _case_dup)
        if len(res_d.findings) != 1:
            problems.append(
                f"同一模板命中同一地址被两趟都跑到时应去重为 1 条，实际 {len(res_d.findings)} —— "
                "重复计数会让报告里的发现数虚高")

        # ⑤ 不可用 / 档位未启用严重度 → 必须显式说明，而不是静默产出 0 条
        _nr_off = _nrmod.NucleiRunner(_std_profile, timeout=420)
        _nr_off.binary = None
        _off = _nr_off.run("http://127.0.0.1:1")
        if _off.executed or "未安装" not in _off.error:
            problems.append("nuclei 不可用时必须如实说明未执行，不得当作「跑了没发现」")
        if _nr_off.count_templates(_plan.passes[0]) is not None:
            problems.append("工具不可用时清点模板应返回「未知」，不得返回 0（0 = 一份都没有）")
        _no_sev = dict(_std_profile)
        _no_sev["nuclei"] = dict(_std_profile["nuclei"], severity_filter=[])
        _nr_ns = _nrmod.NucleiRunner(_no_sev, timeout=420)
        _nr_ns.binary = "nuclei"
        _ns = _nr_ns.run("http://127.0.0.1:1")
        if _ns.executed or not _ns.error:
            problems.append("档位未启用任何严重度时必须说明跳过，不得产出空结论")

        # ⑥ 执行范围必须清点出来：这是解读「nuclei 没有发现」最关键的单一数字
        def _beh_scope(call, cmd):
            if "-tl" in cmd:                      # 清点：只加载元数据
                return _FakeProc(0, stdout="a.yaml\nb.yaml\nc.yaml\n")
            _out_of(cmd).write_text(json.dumps(_rec(0), ensure_ascii=False), encoding="utf-8")
            return _FakeProc(1)

        def _case_scope(nr, fake):
            return nr.run("http://127.0.0.1:1"), fake

        res_sc, _ = _with_fake(_beh_scope, _case_scope, measure_scope=True)
        if not res_sc.scope_known or res_sc.scope_total != 2 * 3:
            problems.append(
                f"执行范围应清点为 2 趟 × 3 份 = 6 份，实际 "
                f"{res_sc.scope_total}（known={res_sc.scope_known}）")
        if "纳入模板 6 份" not in res_sc.summary():
            problems.append("执行摘要未给出纳入模板份数 —— 读者无从判断「无发现」的分量")
        if any(p.get("templates") != 3 for p in res_sc.pass_results):
            problems.append(f"每趟的模板份数应落进趟次明细，实际 {res_sc.pass_results}")

        # ⑦ 清点失败不得中断扫描，也不得伪造成「0 份」
        def _beh_scope_fail(call, cmd):
            if "-tl" in cmd:
                raise OSError("nuclei: 清点失败")
            _out_of(cmd).write_text(json.dumps(_rec(0), ensure_ascii=False), encoding="utf-8")
            return _FakeProc(1)

        def _case_scope_fail(nr, fake):
            return nr.run("http://127.0.0.1:1"), fake

        res_sf, _ = _with_fake(_beh_scope_fail, _case_scope_fail, measure_scope=True)
        if res_sf.scope_known or res_sf.scope_total != 0:
            problems.append("清点失败时必须报「未清点」，不得伪造成「纳入 0 份模板」")
        if not res_sf.findings:
            problems.append("清点失败不得影响主流程（该扫的还得扫）")
        _nr_nomeas = _nrmod.NucleiRunner(_std_profile, timeout=420, measure_scope=False)
        _nr_nomeas.binary = "nuclei"
        if _nr_nomeas.count_templates(_plan.passes[0]) is not None:
            problems.append("关掉清点时应返回「未知」（None），而不是 0（0 = 一份都没有）")

        print("\n[环境] nuclei 预算已校验："
              f"{len(_plan.passes)} 趟分层（高价值先跑）、"
              f"排除 {'+'.join(_plan.passes[0].protocols_exclude)} 共 "
              f"{len(_plan.passes[0].protocols_exclude)} 类不适用模板、"
              f"限速 {_plan.passes[0].rate_limit}/s；"
              f"被掐断仍抢救回 {len(res_t.findings)} 条并标记截断；"
              f"预算耗尽后第二趟记 skipped；重复命中已去重"
              f"（{len(res_d.findings)} 条）；执行范围已清点"
              f"（{res_sc.scope_total} 份），清点失败不伪造成 0")
    except Exception as e:  # noqa: BLE001
        problems.append(f"nuclei 预算检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 不变量 ㉘：抽检是抽样 —— 盲区必须收口，窗口内的「通过」一律作废 ----
    # 不变量 ⑮ 只保证「检出封禁后，后续项记未执行」。但两次抽检**之间**那段
    # 盲区里跑完的检查项，其结论是建立在拦截页上的 —— 其中判「通过」的那些
    # 是**假通过**：不是「没测」，而是主动给出的错误结论，而报告看起来完全正常。
    # 两条互补机制必须同时生效，缺一条就消不掉这个窗口：
    #   · 探测热路径把每个响应喂给守门 → 可疑迹象出现时提前抽检（缩小窗口）；
    #   · 封禁事件记下窗口 → 窗口内的结论改判（消除假通过）。
    try:
        import contextlib  # noqa: PLC0415
        import io as _io  # noqa: PLC0415

        from engine import banguard as _bgmod  # noqa: PLC0415
        from engine.banguard import BoundaryGuard as _BG  # noqa: PLC0415
        from engine.registry import DetectorContext as _DC  # noqa: PLC0415
        from engine.registry import ItemResult as _IR  # noqa: PLC0415
        from engine.registry_runner import (  # noqa: PLC0415
            _invalidate_contaminated as _inv,
        )
        from engine import registry_runner as _rrmod  # noqa: PLC0415

        # 守门模块自己的 15 项离线断言也在这里跑一遍 —— 只靠手动触发，
        # 等于它永远不进回归，而它恰恰是唯一挡住「假通过」的那道闸。
        _bg_buf = _io.StringIO()
        with contextlib.redirect_stdout(_bg_buf):
            _bg_rc = _bgmod._selftest()
        if _bg_rc != 0:
            problems.append("边界守门模块内建自测未通过："
                            + _bg_buf.getvalue().strip()[-220:])

        _BLK = "<html><body><h1>403 Forbidden by edge</h1></body></html>"
        _OK = "<html><body><h1>首页</h1></body></html>"

        def _clean(_u, **_k):
            return {"status": 200, "body_snippet": _OK, "headers": {}, "cookies": []}

        # ① 热路径喂入：两个不同 URL 返回同一张非基线拦截页 → 提前触发真抽检
        class _Cli:
            """最小客户端替身：只实现 DetectorContext 会用到的方法。"""

            def __init__(self):
                self.rps = 20.0
                self.timeout = 5
                self._base_rps = None
                self.calls = 0

            def fetch(self, url, **_k):
                self.calls += 1
                return SimpleNamespace(status=403, body_snippet=_BLK,
                                       headers={}, cookies=[], final_url=url)

            def probe_many(self, base, paths):
                out = {}
                for p in paths:
                    self.calls += 1
                    out[p] = SimpleNamespace(status=403, body_snippet=_BLK,
                                             headers={}, cookies=[],
                                             final_url=base + p)
                return out

        _cli = _Cli()
        _g1 = _BG(_clean, sleep=lambda _s: None)
        _g1.arm("https://feed.test/", 200, _OK)
        _cx = _DC(target_name="喂入自测", domain="feed.test",
                  target_url="https://feed.test/", client=_cli)
        _cx.attach_guard(_g1)
        _cx.get("https://feed.test/a")
        if _g1.report.suspicion_checks != 0:
            problems.append("单个 URL 返回 403 就触发抽检 —— 应用自身的鉴权"
                            "天天返 403，这样会把抽检打成风暴")
        _cx.get("https://feed.test/b")      # 换一个路径，同一张非基线拦截页
        if _g1.report.suspicion_checks != 1:
            problems.append(
                f"两个不同 URL 返回同一张拦截页却未提前抽检（"
                f"suspicion_checks={_g1.report.suspicion_checks}）—— "
                "封禁要等到下一次到点抽检才被发现，中间那段就是假通过窗口")
        if _g1.report.checks < 1:
            problems.append("提前抽检未真正发起请求")
        # 批量探测也必须逐条喂入（它是最密集的一条路径）。
        # 注意这里校验的是**喂入**，不是**触发抽检** —— 后者受即时抽检下限约束，
        # 刚抽检过就不该再抽（那是防风暴的那条判断，另一条断言管它）。
        _cx.probe_many(["c", "d"])
        _fed = sum(len(v) for v in _g1._seen_pages.values())
        if _fed < 4:
            problems.append(
                f"批量路径探测未逐条喂入守门（累计只喂入 {_fed} 个不同 URL）—— "
                "一次几十上百条路径全在拦截页上，不逐条喂就只能等下一个检查项边界")
        # 喂入必须永不抛异常（它是热路径，故障不得中断检测）
        for _bad in (None, object(), {"status": None}, {"status": 403, "body": None}):
            try:
                _cx._feed_guard("https://feed.test/e", _bad)
            except Exception as e:  # noqa: BLE001
                problems.append(f"喂入异常响应时抛出 {type(e).__name__} —— "
                                "守门是保护措施，它自己的故障绝不能中断检测器")

        # ② 窗口内的结论必须作废；窗口外的一个都不许动
        _ban = {"on": False}

        def _scripted(u, **_k):
            on = _ban["on"]
            return {"status": 403 if on else 200,
                    "body_snippet": _BLK if on else _OK,
                    "headers": {}, "cookies": []}

        _g2 = _BG(_scripted, sleep=lambda _s: None, budget_s=50.0)
        _g2.arm("https://win.test/", 200, _OK)
        _g2.tick(0)                                  # 干净抽检 → 窗口左端点 0
        _ban["on"] = True
        _ev = _g2.check(probe_count=30)              # 封禁 → 窗口 (0, 30]
        _ban["on"] = False
        if _ev is None or _ev.window != (0, 30):
            problems.append(f"封禁窗口未按预期记录：{_ev.window if _ev else '(未检出)'}")

        def _mk(iid, state):
            return _IR(item_id=iid, name=iid, category="T", category_name="T",
                       state=state, mode="自动")

        _rs = [_mk("A", "通过"), _mk("B", "不通过"), _mk("C", "通过"), _mk("D", "N/A")]
        _inv(_rs, {"A": (0, 10), "B": (10, 40), "C": (40, 50), "D": (5, 6)}, _g2)
        if _rs[0].state != "待确认" or "不作数" not in _rs[0].note:
            problems.append(
                f"封禁窗口内的「通过」未改判为「待确认」（实为 {_rs[0].state}）—— "
                "这正是本机制要消灭的假通过")
        if _rs[1].state != "不通过" or "窗口" not in _rs[1].note:
            problems.append("窗口内的「不通过」不得改状态（真伪由复现闸门裁决），"
                            "但必须加核对标注")
        if _rs[2].state != "通过" or _rs[2].note:
            problems.append("窗口之外的「通过」被误伤 —— 作废必须精确到窗口端点")
        if _rs[3].state != "待确认":
            problems.append("窗口内的「N/A」也要改判：「目标没有该功能」也可能"
                            "只是拦截页造成的假象，两者从外部无法区分")
        if _g2.report.invalidated_items != 2 or _g2.report.annotated_items != 1:
            problems.append(
                f"作废动作量未正确统计（invalidated={_g2.report.invalidated_items} "
                f"annotated={_g2.report.annotated_items}）—— 报告要披露清掉了多少假通过")
        if not any("100–130" in n or "0–30" in n for n in _g2.report.notes):
            problems.append("封禁窗口未写进 notes，读者无从知道该怀疑哪一段")
        if "待确认" not in _g2.report.summary():
            problems.append("摘要未披露被改判的项数")

        # ③ 整轮执行必须真的调用作废逻辑（只测单元函数会漏掉「没接上」）
        _real_build = _rrmod.build_registry
        _script = {"A": 10, "B": 30, "C": 10}
        _states = {"A": "通过", "B": "不通过", "C": "通过"}

        class _RegStub:
            def __init__(self, real):
                self._real = real

            def __getattr__(self, k):
                return getattr(self._real, k)

            def execute(self, item, ctx, **_kw):
                ctx.probe_count += _script.get(item.id, 0)
                return _IR(item_id=item.id, name=item.id, category="T",
                           category_name="T", state=_states[item.id], mode="自动")

        _rrmod.build_registry = lambda: _RegStub(_real_build())
        try:
            _items = [SimpleNamespace(id="A"), SimpleNamespace(id="B"),
                      SimpleNamespace(id="C")]
            _cx2 = _DC(target_name="整轮自测", domain="win.test",
                       target_url="https://win.test/", client=_cli)
            _g3 = _BG(_scripted, sleep=lambda _s: None, budget_s=50.0)
            _g3.arm("https://win.test/", 200, _OK)
            _g3.tick(0)
            _ban["on"] = True
            _g3.check(probe_count=30)      # 窗口 (0, 30]：A(0–10)、B(10–40) 在内，C(40–50) 在外
            _ban["on"] = False
            _res, _ = _rrmod.run_all_items(_items, [], _cx2, guard=_g3)
        finally:
            _rrmod.build_registry = _real_build
        _by = {r.item_id: r for r in _res}
        if _by["A"].state != "待确认":
            problems.append("整轮执行未作废窗口内的「通过」—— "
                            "作废逻辑没接上，单测再好也不生效")
        if _by["B"].state != "不通过" or "窗口" not in _by["B"].note:
            problems.append("整轮执行未给窗口内的「不通过」加核对标注")
        if _by["C"].state != "通过" or _by["C"].note:
            problems.append("整轮执行误伤了窗口外的结论（取证时段与窗口不重叠）")
        if _cx2._guard is not _g3:
            problems.append("整轮执行未把守门挂到探测热路径上 —— "
                            "可疑迹象无法提前触发抽检，窗口会一直存在")

        print("\n[环境] 抽检盲区已收口：热路径喂入（≥2 个不同 URL 同一张拦截页即"
              "提前抽检，且有下限防风暴）、批量路径逐条喂入、"
              "封禁窗口区间相交判定精确到端点；窗口内「通过/N-A」改判为「待确认」"
              f"（{_g2.report.invalidated_items} 项）、「不通过」只加标注"
              f"（{_g2.report.annotated_items} 项）、窗口外结论不受影响")
    except Exception as e:  # noqa: BLE001
        problems.append(f"抽检盲区收口检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 不变量 ㉙：周期化扫描与通知不得把「本轮没跑」传成「已修复 / 没问题」 ----
    # 周期化是这套工具从「一次性检查」变成「持续运营」之后，假通过最集中的新入口：
    #   · 通知卡片上写「已修复 6」很自然，但如果那 6 项本轮根本没执行，
    #     「本轮没再检出」就是句空话 —— 假通过从清单层搬到了通知层；
    #   · 卡片是绿的，读者就会以为「都测过了、没问题」，而绿卡片必须
    #     同时满足「全部执行完」+「零发现」+「未被边界拦截」三个条件。
    # 调度侧同理：扫描失败/被闸门拦下的目标若记了「已执行」，那个周期就再不会扫它。
    try:
        import contextlib  # noqa: PLC0415
        import io as _io  # noqa: PLC0415
        import tempfile as _tf  # noqa: PLC0415
        from datetime import datetime  # noqa: PLC0415

        from diff.differ import Differ as _Differ  # noqa: PLC0415
        from engine import notify as _nmod  # noqa: PLC0415
        from engine import scheduler as _smod  # noqa: PLC0415
        from engine.notify import (  # noqa: PLC0415
            COLOR_GREEN as _GREEN,
        )
        from engine.notify import FeishuNotifier as _FN  # noqa: PLC0415
        from engine.scheduler import (  # noqa: PLC0415
            Scheduler as _Sched,
        )
        from engine.scheduler import summary_from_scan as _summ  # noqa: PLC0415

        # 两个模块自己的离线断言也在这里跑 —— 只靠手动触发就等于它们不进回归。
        for _name, _mod in (("飞书通知", _nmod), ("周期化调度", _smod)):
            _buf = _io.StringIO()
            with contextlib.redirect_stdout(_buf):
                _rc = _mod._selftest()
            if _rc != 0:
                problems.append(f"{_name}模块内建自测未通过："
                                + _buf.getvalue().strip()[-220:])

        # ① 比对：「本轮该项没执行」不得被记成「已修复」
        from models import Finding as _F  # noqa: PLC0415
        from models import FindingSet as _FS  # noqa: PLC0415

        def _mk(i, t, ep, sev):
            return _F(item_id=i, target="示例系统", title=t, endpoint=ep, severity=sev)

        _base_fs = _FS(target="示例系统")
        _base_fs.add(_mk("WSTG-ATHN-01", "登录页明文传输口令",
                         "https://sso.example.com/login", "高危"))
        _base_fs.add(_mk("WSTG-CONF-07", "HTTP 安全响应头缺失",
                         "https://a.example.com/", "低危"))
        _cur_fs = _FS(target="示例系统")
        _cur_fs.add(_mk("WSTG-CONF-07", "HTTP 安全响应头缺失",
                        "https://a.example.com/", "低危"))
        _d1 = _Differ().compare(_base_fs, _cur_fs,
                                item_states={"WSTG-ATHN-01": "未执行"})
        if any(e.item_id == "WSTG-ATHN-01" for e in _d1.fixed):
            problems.append("本轮未执行的检查项被记成「已修复」—— 这是把假通过"
                            "从清单层搬到了比对层（周期化场景下最致命）")
        if len(_d1.unverified) != 1 or "不得计入「已修复」" not in _d1.render_markdown():
            problems.append("「本轮未判定」既未单列、也未在报告里禁止计入已修复")
        _d2 = _Differ().compare(_base_fs, _cur_fs,
                                item_states={"WSTG-ATHN-01": "通过"})
        if len(_d2.fixed) != 1 or _d2.unverified:
            problems.append("本轮该项确有结论（通过）时应照旧判「已修复」")

        # ② 摘要：截断必须体现为 partial；比对没带结论必须能说出来
        _res = SimpleNamespace(
            target_name="自测系统", domain="t.example.com",
            item_results=[SimpleNamespace(item_id="WSTG-INFO-01", state="通过")],
            detector_summary={"档位": "standard", "可复测率": 0.8, "采集充分度": {}},
            finding_set=None, reports={}, archive_dir="x", nuclei_run={})
        _orch = SimpleNamespace(_objectives=[], _last_diff=None, _boundary=None)
        if _summ(_res, _orch)["partial"] is not False:
            problems.append("没有 nuclei 信息时不得瞎判「覆盖被截断」")
        _res.nuclei_run = {"executed": True, "partial": True}
        _s_trunc = _summ(_res, _orch)
        if _s_trunc["partial"] is not True:
            problems.append("nuclei 被截断必须体现为 partial —— 否则通知里的"
                            "「零发现」会被读成「干净」")
        if _s_trunc["diff_state_known"] is not None:
            problems.append("没有比对时 diff_state_known 应为「不适用」（None），"
                            "不得伪造成 True")

        class _DNoStates:  # 有比对，但没拿到本轮逐项结论
            states_loaded = False

            def summary(self):
                return {"新增": 0, "已修复": 3, "仍存在": 1, "等级变化": 0,
                        "重新归类": 0, "本轮未判定": 4}

        _s_diff = _summ(_res, _orch, _DNoStates())
        if _s_diff["diff_state_known"] is not False:
            problems.append("比对未带本轮结论时必须能说出来（否则「已修复」里"
                            "混着没跑过的项，发出去就是脏数字）")
        if _s_diff["diff"]["本轮未判定"] != 4:
            problems.append("「本轮未判定」必须随摘要一起传给通知")
        _txt_diff = _FN(dry_run=True).render_text(_s_diff)
        if "本轮未判定 4" not in _txt_diff or "未带本轮逐项结论" not in _txt_diff:
            problems.append("通知卡片必须单列「本轮未判定」并说明比对未带本轮结论")

        # ③ 绿卡片三条件：全部执行完 + 零发现 + 未被拦截，缺一不可
        _green_ok = {"target_name": "x", "counts": {"合计": 0},
                     "item_states": {"通过": 163, "未执行": 0,
                                     "待人工执行": 0, "待确认": 0, "合计": 163}}
        if _FN(dry_run=True).build_card(_green_ok)["card"]["header"]["template"] \
                != _GREEN:
            problems.append("全部执行完且零发现时应当允许绿卡片")
        for _key, _val in (("boundary_blocked", True), ("partial", True)):
            _bad = dict(_green_ok)
            _bad[_key] = _val
            if _FN(dry_run=True).build_card(_bad)["card"]["header"]["template"] \
                    == _GREEN:
                problems.append(f"{_key} 成立时不得用绿卡片")

        # ④ 调度：失败/被拦的目标不得记账，否则那个周期永久跳过它
        with _tf.TemporaryDirectory() as _td:
            _root = Path(_td)
            (_root / "outputs").mkdir()
            _tp = _root / "targets.yaml"
            _tp.write_text(
                "settings: {profile: safe, output_root: outputs}\n"
                "schedule: {enabled: true, mode: daily}\n"
                "targets:\n"
                "  - name: 甲系统\n"
                "    primary_domain: a.example.com\n"
                "    authorization: {authorizer: 安全负责人}\n"
                "  - name: 乙无授权\n"
                "    primary_domain: b.example.com\n",
                encoding="utf-8")
            _s = _Sched(_tp, now=lambda: datetime(2026, 9, 21, 3, 0))
            _dec = {t["name"]: d for t, d in _s.due()}
            if not _dec["甲系统"].due:
                problems.append("已授权目标到点却未判到点")
            if _dec["乙无授权"].due:
                problems.append("未登记授权人的目标被判到点 —— 没有扫描依据")
            _s.mark_ran("甲系统", now=datetime(2026, 9, 21, 3, 0))
            _s2 = _Sched(_tp, now=lambda: datetime(2026, 9, 21, 3, 5))
            if _s2.decide(_s2.targets()[0], datetime(2026, 9, 21, 3, 5)).due:
                problems.append("同一周期内已执行过，不得重复判到点")
            if not (_root / "outputs" / ".schedule_state.json").exists():
                problems.append("mark_ran 未落盘 —— 崩一次就会重复扫整个周期")

        print("\n[环境] 周期化与通知已校验：比对把「本轮未执行」摘出「已修复」"
              f"（{len(_d1.unverified)} 项单列并在报告里禁止计入），"
              "nuclei 截断体现为 partial，绿卡片需同时满足「全执行完 + 零发现 + "
              "未被拦截」，调度同周期幂等且失败不记账")
    except Exception as e:  # noqa: BLE001
        problems.append(f"周期化与通知检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 不变量 ㉚：认证 / 会话 / 加密 / 授权 / 数据导出的人工项必须挂上自动前置侦察 ----
    # 「必须人工」不等于「全推给人」。这几类人工项里真正只有人能回答的只有最后
    # 那一句判断（锁定阈值、并发策略、能否解密、导出口径是否越界），而「找登录入口、
    # 找改密表单、找密文参数、找管理端点、找导出端点」占了大头。侦察不挂上，
    # 人工拿到的就是「请从零开始测」。
    # 更要紧的是：侦察要么跑出结论、要么明确报「没执行」，
    # **不允许**静默退化 —— 那会让人误以为自动化已经把能做的都做了。
    try:
        import contextlib  # noqa: PLC0415
        import io as _io  # noqa: PLC0415

        from engine import recon_identity as _rimod  # noqa: PLC0415
        from engine.registry import MODE_MANUAL as _MM  # noqa: PLC0415
        from engine.registry_runner import build_registry as _br  # noqa: PLC0415
        from checklist.loader import load_checklist as _lck  # noqa: PLC0415

        _rbuf = _io.StringIO()
        with contextlib.redirect_stdout(_rbuf):
            _rrc = _rimod._selftest()
        if _rrc != 0:
            problems.append("认证类侦察模块内建自测未通过："
                            + _rbuf.getvalue().strip()[-220:])

        _reg2 = _br()
        _ck2 = _lck()
        _want = ("WSTG-ATHN-03", "WSTG-ATHN-08", "WSTG-ATHN-09",
                 "WSTG-SESS-11", "WSTG-CRYP-02",
                 "WSTG-ATHZ-03", "EXT-DP-03")
        _missing = []
        for _iid in _want:
            _sp = _reg2.get(_iid)
            if _sp is None:
                _missing.append(f"{_iid}(未登记)")
                continue
            if _sp.mode != _MM:
                _missing.append(f"{_iid}(不再是人工项)")
                continue
            if _sp.recon is None:
                _missing.append(f"{_iid}(未挂侦察)")
        if _missing:
            problems.append("人工项未挂自动前置侦察："
                            + "、".join(_missing))

        # 侦察函数必须真的可调用并返回 ReconOutcome（而不是挂了个假函数）
        _ro = _rimod.recon_athn03(SimpleNamespace(
            target="t.example.com", target_url="https://t.example.com/",
            accounts=[], probe_count=0, _cache={},
            probe_many=lambda paths, base=None: {
                p: {"status": 0, "body_snippet": "", "error": "不可达"}
                for p in paths},
            risk_allowed=lambda risk: True,
            get=lambda url, method="GET", allow_redirects=True: {
                "status": 0, "body_snippet": "", "error": "不可达"},
            note=lambda msg: None, content_matches=lambda a, b: True))
        if _ro.ran is not False or not _ro.error:
            problems.append("侦察拿不到任何页面时必须 ran=False 且写出原因 —— "
                            "静默退化成空清单会被读成「已经查过了」")

        # 安全档必须能说清「是档位不足没跑」，而不是「目标没有这个入口」
        _ro_safe = _rimod.recon_athn03(SimpleNamespace(
            target="t.example.com", target_url="https://t.example.com/",
            accounts=[], probe_count=0, _cache={},
            probe_many=lambda paths, base=None: {},
            risk_allowed=lambda risk: False,
            get=lambda url, method="GET", allow_redirects=True: {
                "status": 0, "body_snippet": "", "error": "不可达"},
            note=lambda msg: None, content_matches=lambda a, b: True))
        if "档位" not in _ro_safe.error:
            problems.append("安全档未执行时必须点明「档位不足」，"
                            "否则会让人以为目标压根没有登录入口")

        # 垂直越权 / 导出越界：定位不到对象时必须 ran=False。
        # 这两项的反向判据（匿名可进不算提权、响应是 HTML 不算导出产物）由
        # recon_identity 的内建自测逐条把守，这里只钉住「找不到对象就别硬下结论」。
        _ro_az = _rimod.recon_athz03(SimpleNamespace(
            target="t.example.com", target_url="https://t.example.com/",
            domain="t.example.com", accounts=[], probe_count=0, _cache={},
            risk_allowed=lambda risk: True))
        if _ro_az.ran is not False or "端点" not in (_ro_az.error or ""):
            problems.append("垂直越权侦察在定位不到管理端点时必须 ran=False 并说明"
                            "「无对象可比对」，不能给一份看起来做过功课的空清单")
        _ro_dp = _rimod.recon_dp03(SimpleNamespace(
            target="t.example.com", target_url="https://t.example.com/",
            domain="t.example.com", accounts=[], probe_count=0, _cache={},
            risk_allowed=lambda risk: True))
        if _ro_dp.ran is not False or "导出" not in (_ro_dp.error or ""):
            problems.append("导出越界侦察在定位不到导出端点时必须 ran=False —— "
                            "报「未发现导出越界」等于把「没测」说成「没问题」")

        # 侦察未执行时，「怎么补」必须出现在结论里。
        # `_manual_only(reason, extra=...)` 把原因写 error、补齐方式写 note；
        # `_apply_recon` 曾经只渲染 error，于是报告上只剩一句「侦察未执行」——
        # 操作者知道缺东西，却不知道该给什么。这条断言专门钉住它不回归。
        from engine.registry import (  # noqa: PLC0415
            DetectorRegistry as _DR, DetectorSpec as _DSpec, ItemResult as _IRes,
            ReconOutcome as _ROut,
        )
        _spec_rc = _DSpec(
            item_id="WSTG-ATHZ-03", mode=_MM,
            name="垂直 / 水平权限提升矩阵测试",
            procedure="1) 用低权账号逐个调用管理接口……",
            expect="越权请求返回 403 而非数据。", why_manual="需要多个真实账号。",
            recon=lambda _c: _ROut(
                ran=False, error="缺少低权测试身份",
                note="补齐方式：aiscan.py creds --target <域名> --set <角色>"))
        _base_rc = _IRes(item_id="WSTG-ATHZ-03", name="垂直 / 水平权限提升矩阵测试",
                         category="ATHZ", category_name="授权",
                         state="待人工执行", mode=_MM)
        _DR._apply_recon(_base_rc, _spec_rc,  # type: ignore[arg-type]
                         SimpleNamespace(errors=[]))
        if "aiscan.py creds" not in (_base_rc.note or ""):
            problems.append("侦察未执行时，补齐方式（note）必须一并渲染进结论 —— "
                            "否则报告只剩「侦察未执行」，操作者不知道该给什么")
        if "侦察未执行" not in (_base_rc.note or ""):
            problems.append("侦察未执行时必须在结论里显式写出「侦察未执行 + 原因」")

        _n_recon = sum(1 for _k in _want if _reg2.get(_k) is not None
                       and _reg2.get(_k).recon is not None)
        print(f"\n[环境] 人工项前置侦察已校验：认证 / 会话 / 加密 / 授权 / 数据导出 "
              f"{_n_recon} 项已挂自动侦察（找入口、找字段、盘点防护、定位密文候选、"
              "定位管理与导出端点），且三态分明 —— 确证即「不通过」、"
              "跑过没确证仍「待人工执行」、"
              "档位不足则显式报「侦察未执行 + 原因 + 补齐方式」")
    except Exception as e:  # noqa: BLE001
        problems.append(f"人工项前置侦察检查未能执行：{type(e).__name__}: {str(e)[:200]}")

    # ---- 靶场落盘：把「本次离线扫描实际报出了什么」写成机器可读文件 ----
    # 由 selftest_bench.py 读取，用于计算检出率 / 漏报率（对照 bench/ground_truth.yaml）。
    # 落盘只是一份副产物，不影响自测本身的判定；写失败也不该让自测失败。
    _bench_dump = os.environ.get("AISCAN_BENCH_DUMP")
    if _bench_dump:
        try:
            Path(_bench_dump).write_text(json.dumps({
                "summary": summary,
                "by_item": by_item,
                "findings": [
                    {
                        "item_id": getattr(f, "item_id", ""),
                        "title": getattr(f, "title", ""),
                        "endpoint": getattr(f, "endpoint", "") or "",
                        "severity": getattr(f, "severity", ""),
                    }
                    for f in findings
                ],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\n[靶场] 本次检出结果已落盘：{_bench_dump}")
        except Exception as e:  # noqa: BLE001
            print(f"\n[靶场] 检出结果落盘失败（不影响自测）：{type(e).__name__}: {e}")

    print()
    print("=" * 70)
    print("逐项执行结果")
    print("=" * 70)
    print(f"清单条目数        ：{summary.get('合计', 0)}")
    for st in ALL_STATES:
        if summary.get(st):
            print(f"  {st:<8}        ：{summary[st]}")
    print(f"实际执行（跑通）  ：{summary.get('自动执行', 0)}")
    print(f"可信通过率        ：{summary.get('通过率', 0):.1%}")
    print(f"产出发现          ：{len(findings)} 条，"
          f"覆盖 {len(by_item)} 个检查项")
    print(f"探测请求累计      ：{ctx.probe_count} 次")
    print(f"主动提交动作      ：{len(ctx.submissions)} 次")
    if pool_rows:
        print(f"URL 枚举覆盖      ：{pool_total} 个候选 / {len(pool_sources)} 类来源"
              f"（剔除破坏性 {len(pool_skipped)} 个）")
        for src, n, _note in pool_rows:
            print(f"  {src:<14} {n:>4}")
    if port_log:
        print(f"端口探测覆盖      ：" + "；".join(
            f"{h} 扫 {rec.get('scanned', 0)} 个端口，开放 "
            f"{rec.get('open') or '无'}" for h, rec in port_log.items()))
    if gstats:
        print(f"复现脚本          ：生成 {len(script_srcs)} 份，"
              f"编译失败 {len(compile_fail)} 份")
        print(f"准入闸门          ：{gate_result.gate_summary()}")
        print(f"  可复测率        ：{gstats['可复测率']:.1%}"
              f"（已复现 / 发现总数）")
        print(f"  强 / 中 / 弱    ：{gstats['强复现']} / "
              f"{gstats['已复现'] - gstats['强复现'] - gstats['弱复现']} / "
              f"{gstats['弱复现']}")
        print(f"  进入漏洞清单    ：{len(reportable)} 条"
              f"（其余 {gstats['未复现'] + gstats['无法判定'] + gstats['未验证']} 条"
              f"按判定分类披露）")

    if args.verbose:
        print()
        print("-" * 70)
        for r in results:
            print(f"{r.item_id:<16} {r.state:<6} {r.mode:<4} "
                  f"{'跑通' if r.executable else '—':<4} {r.name}")

    print()
    print("=" * 70)

    # ---- 可选：渲染一份真实报告，验证第 3 章与新状态机的对接 ----
    if args.report:
        try:
            report_paths = render_report(args.report, checklist, app, results,
                                         findings, ctx, summary,
                                         gate_result=gate_result,
                                         verify_runs=verify_runs)
            print("报告已生成：")
            for k, v in report_paths.items():
                print(f"  {k:<12} {v}")
            print()
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"[错误] 报告渲染失败：{type(e).__name__}: {e}")
            print(traceback.format_exc()[:1200])
            problems.append("报告渲染失败")

    if missed:
        print("未按预期命中的埋点（检测器可能是空壳）：")
        for k in missed:
            print(f"  ✗ {k}  {expected[k]}")
        problems.append(f"{len(missed)} 个埋点未被检出")

    if compile_fail:
        print("复现脚本编译失败（交付物损坏）：")
        for c in compile_fail[:10]:
            print(f"  ✗ {c}")
        problems.append(f"{len(compile_fail)} 份复现脚本无法编译")

    if not_reproduced:
        print("埋点被检出但未复现（检测判据与复现判据不一致）：")
        for k in not_reproduced:
            print(f"  ✗ {k}  {by_item.get(k, [''])[0]}")
        problems.append(f"{len(not_reproduced)} 个埋点无法复现")

    # ------------------------------------------------------------------
    # D6：报错特征表必须认得数据库原生错误码（不是只有驱动包装形态）
    # 2026-10-09 Juice Shop 基准六轮实测：q='-- 触发 500 +
    # `Error: SQLITE_ERROR: near "--": syntax error`，但特征表原有三条
    # SQLite 特征（SQLite3:: / sqlite3.OperationalError / SQLite/JDBCDriver）
    # 全是 Python/Java 驱动的包装形态，一条都匹配不上 —— 注入点在眼皮底下
    # 溜走，检查项写「通过」。
    # ------------------------------------------------------------------
    from engine.checks.injection import ERROR_SIGNATURES as _ES, PAYLOADS as _PL  # noqa: E402
    import re as _re_d6

    _d6_sqlite_native = (
        '<title>Error: SQLITE_ERROR: near &quot;--&quot;: syntax error</title>')
    _d6_pats = _ES.get("sql", [])
    if not any(_re_d6.search(p, _d6_sqlite_native, _re_d6.I) for p in _d6_pats):
        problems.append("报错特征表不认 SQLite 原生错误码（SQLITE_ERROR 形态，"
                        "D6：特征表只认驱动包装形态时，原生报错 = 注入漏报）")
    # 载荷表不得被截断执行（D6：曾 [:4] —— sql 7 条只跑前 4 条）
    _inj_src = (Path(__file__).resolve().parent
                / "engine" / "checks" / "injection.py").read_text(encoding="utf-8")
    if "PAYLOADS.get(kind, [])[:4]" in _inj_src:
        problems.append("注入载荷被 [:4] 截断执行（D6：配置了 7 条只跑 4 条，"
                        "配了没人读）")
    if len(_PL.get("sql", [])) < 7:
        problems.append("sql 载荷表意外缩水（D6 断言基线）")

    if problems:
        print("自测不通过：")
        for p in problems:
            print(f"  ✗ {p}")
        print("=" * 70)
        return 1

    print("自测通过：全部检查项均落到明确状态，无凭据的「通过」为 0，"
          "人工项步骤完整，埋点全部命中。")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
