# -*- coding: utf-8 -*-
"""
juice_verdicts.py —— 「Juice Shop 的每条挑战，aiscan 到底有没有能力碰」的判定表。

这张表是全 JupytererBench 里**唯一由 aiscan 一侧主观给出**的东西，
所以它写得比其它文件啰嗦：每条除了结论还给 `because`（依据）和
`witness`（任何人都可以照着复的最小动作）。理由见 bench/juice_gen.py
头部的说明 —— 答案的分母必须来自官方，判断的科目必须可逐个复核。

verdict 五个值：
    auto    黑盒可达 + 有检测体 + 适用性成立          = 能力上界
    semi    有检测体但要前置（账号/写/渲染/字典/OOB）= 补齐后可自动
    manual  业务逻辑与多步推理，只能做人工项（红线 3/32）
    gap     清单里没有任何一项声明负责它（红线 14 必须显式列出）
    na      量程之外：白盒 / OSINT / Web3 / DoS(红线 11) / 非安全 Bug

判定规则（写之前先抄在这，防止自己漂）：
    ① acceptable_items 按清单 **detect 字段** 定，不按「谁报出来的」定
       （ground_truth.yaml 头部「坑二」踩过一次）
    ② 清单项的适用性标记 app 必须在 Juice Shop 上成立才认
       （Juice Shop 有登录 has_login、有 OpenAPI has_api、有前端产物
        has_client / has_component、有上传 has_upload、有 AI 端点 has_ai）
    ③ 拿不准的一律降级，**不许往上抬**。抬一格 = 虚报召回率。
"""
from __future__ import annotations

from typing import Any, Dict

# 为了紧凑，用 V(verdict, items, because, witness) 造。
def _V(verdict: str, items: list, because: str, witness: str) -> Dict[str, Any]:
    return {"verdict": verdict, "items": items,
            "because": because, "witness": witness}


# Juice Shop 适用集：有登录/注册/会话、有 REST API 与 /api-docs、
# 有 SPA 前端产物（含 old jQuery）、有文件上传、有 AI chatbot 端点。
# → has_login has_session has_account has_api has_client has_component
#   has_upload has_input has_ai 均成立。
# 不成立：has_oauth has_graphql has_websocket has_payment has_cicd
#         has_storage has_cloud（本机 Docker 靶场）

VERDICTS: Dict[str, Dict[str, Any]] = {

    # ===================== Sensitive Data Exposure (17) =====================
    "Password Hash Leak": _V(
        "semi",
        ["WSTG-APIT-03", "EXT-DP-01"],
        "归口按 detect：APIT-03「接口返回超出业务需要的大量字段」是对的；"
        "EXT-DP-01 的 PII 正则针对手机/身份证/银行卡，hash 不在模式里，"
        "所以只写 APIT-03 为准、DP-01 为可能命中。两者都 app=has_api，Juice Shop 成立。",
        "匿名 GET /rest/user/whoami 或 /api/Users/{id}，响应里含 password 字段（MD5）。"),

    "Confidential Document": _V(
        "auto",
        ["WSTG-CONF-09", "WSTG-CONF-04"],
        "CONF-09 detect 明确写了「目录列表开启」，CONF-04 写「归档目录/未被引用的静态文件」。"
        "/ftp 开目录列举是黑盒一眼可见的配置项。",
        "GET /ftp/ → 200 目录列举，含 acquisitions.md。"),

    "Forgotten Developer Backup": _V(
        "auto",
        ["WSTG-CONF-03", "WSTG-CONF-04"],
        "CONF-03 detect 写死「.bak/.old/.swp 等备份扩展名」，命中线完全一致。",
        "GET /ftp/package.json.bak → 200。"),

    "Forgotten Sales Backup": _V(
        "auto",
        ["WSTG-CONF-03", "WSTG-CONF-04"],
        "同 Dev Backup，都是备份扩展名 + 归档目录。",
        "GET /ftp/coupons_2013.md.bak → 200。"),

    "Misplaced Signature File": _V(
        "auto",
        ["WSTG-CONF-03", "WSTG-CONF-04"],
        "/ftp 下可疑文件，属 CONF-03 扩展名清单（.yml 未必在其中）。"
        "保守起见仍按 CONF-04「归档目录」为主归口。",
        "GET /ftp/suspicious_errors.yml → 200。"),

    "Retrieve Blueprint": _V(
        "auto",
        ["WSTG-CONF-03", "WSTG-CONF-04", "WSTG-INFO-05"],
        "属于归档目录 + 未引用静态文件。",
        "GET /ftp/juice.crt 系列 / blueprint 文件 → 200。"),

    "Misplaced IaC Files": _V(
        "auto",
        ["EXT-CD-01", "WSTG-CONF-04"],
        "EXT-CD-01 detect 列举了CI 配置文件（Jenkinsfile / azure-pipelines 等）；"
        "Juice Shop 的 IaC 落在 /ftp 里，同样被 CONF-04 归档目录命中。",
        "GET /ftp 下的 .tf / .yml / Dockerfile 等 → 200。"),

    "Exposed Metrics": _V(
        "auto",
        ["WSTG-CONF-05", "WSTG-CONF-02"],
        "CONF-05 detect 写了「actuator 端点」，CONF-02 写「管理端点暴露」；"
        "/metrics 属标准管理端点点 franch。",
        "GET /metrics → 200 Prometheus 格式指标。"),

    "Email Leak": _V(
        "semi",
        ["EXT-DP-01", "EXT-DP-02"],
        "依赖「响应体里能不能抓到 email」。DP-01 的 PII 模式里 email 通常覆盖；"
        "但这是 attaches for their feedback — 需要走到具体端点。app=always 成立。",
        "匿名 GET /api/Feedbacks 或用户相关端点，响应含他人 email。"),

    "Leaked Access Logs": _V(
        "manual",
        ["WSTG-CONF-04", "WSTG-CONF-09"],
        "日志落在特定路径且内容是「能打开但看不懂」的流水，判断它是不是日志要靠人。"
        "路径枚举若撞到可命中 CONF-04；但命中率低，不抬到 auto。",
        "需枚举到 /support/logs 之类路径并人工确认内容性质。"),

    "GDPR Data Theft": _V(
        "semi",
        ["EXT-DP-03", "WSTG-APIT-03"],
        "EXT-DP-03 detect 「导出接口未限制数据范围」正对 over-export。"
        "app=has_download —— Juice Shop 有数据导出端点（小 round trip）。",
        "调用数据导出端点拿到全表而非当前用户数据。"),

    "Exposed Credentials": _V(
        "semi",
        ["EXT-SC-07", "EXT-CL-06", "WSTG-INFO-05"],
        "前端产物/日志里残留凭据。SC-07 detect 明确「前端或仓库中残留第三方服务密钥」；"
        "app=always 成立。但要看 goal 是「被ाली 前端能读到」还是「在特定 log」。",
        "从前端 / logs / 配置取到可用凭据。"),

    "Leaked API Key": _V(
        "semi",
        ["EXT-SC-07", "EXT-CL-06"],
        "同 Exposed Credentials 类。",
        "从响应或前端取到第三方服务 API Key。"),

    "Meta Geo Stalking": _V(
        "semi",
        ["EXT-DP-06"],
        "EXT-DP-06（2026-10-10 新增）已能下载对外发布的 JPEG 并本地解析 EXIF/TIFF "
        "GPS 段 —— 「不解析图片二进制」这条缺口已不成立，故不再记 gap。"
        "但本条挑战还要求「由坐标推断地点名」并用于密码重置：坐标→地名属于 OSINT 推断，"
        "「用答案改他人密码」是有副作用的写动作（红线 33 不自动触碰），两步都不在自动范围内 → semi。",
        "下载某个渠道图片，exiftool 查到 GPS 坐标 → 推断地点 → 用答案重置密码。"),

    "Visual Geo Stalking": _V(
        "na",
        [],
        "需要人看图推断地理位置（OSINT）。不是HTTP 层的缺陷。",
        "人工看照片背景 → 推断地点。"),

    "Reset Uvogin's Password": _V(
        "na",
        [],
        "OSINT 类密保问题，需外部情报，不是服务端缺陷。",
        "需从公开渠道推断加密问题答案。"),

    "Login Cloud Admin": _V(
        "semi",
        ["WSTG-ATHN-02", "EXT-CD-01"],
        "IaC 文件里硬编码口令。ATHN-02「默认凭据」+ EXT-CD-01「流水线/配置泄露」"
        "能覆盖「发现这串口令」这一步；但 Juice Shop 的具体账户入口需要+jp. "
        "保守降级到 semi。",
        "从 IaC/配置文件取到 cloud admin 口令并用于登录。"),

    # ===================== Injection (14) =====================
    "Login Admin": _V(
        "auto",
        ["WSTG-INPV-05"],
        "经典的登录框 SQLi（' or 1=1--）。INPV-05 detect 覆盖布尔盲注/报错/联合/堆叠；"
        "sqlmap_probe.py 会在 standard 档以上对登录表单跑。",
        "POST /rest/user/login {email:\"admin'--\"} → 200 拿到 JWT。"),

    "Login Jim": _V(
        "auto",
        ["WSTG-INPV-05"],
        "同为登录框 SQLi。",
        "POST /rest/user/login {email:\"jim@example.com'--\"}。"),

    "Login Bender": _V(
        "auto",
        ["WSTG-INPV-05"],
        "同为登录框 SQLi。",
        "POST /rest/user/login {email:\"bender@...'--\"}。"),

    "Database Schema": _V(
        "auto",
        ["WSTG-INPV-05"],
        "搜索接口的 UNION SELECT，sqlmap 在 standard 档能出 union-based 结果。",
        "GET /rest/products/search?q=')) UNION SELECT ... -- → 响应用数据。"),

    "User Credentials": _V(
        "auto",
        ["WSTG-INPV-05"],
        "同上，UNION 查询把 Users 表拖出来。sqlmap 阶要 very --level/risk 但被限制到 3/2 下界内。"
        "注意红线 27：sqlmap 的 --risk/--level 有数值钳，深 schema dump 可能拿不到，故命中不确定。",
        "搜索接口 UNION SELECT 出 Users 表的 email/password。"),

    "Ephemeral Accountant": _V(
        "semi",
        ["WSTG-INPV-05"],
        "注入点在进一步完善处（订单/评论的 author 字段），非匿名可达 —— "
        "需登录后触发（has_login 成立），故 semi。",
        "登录态下把作者字段改成特定值即永久生效，说明存在持久注入点。"),

    "Christmas Special": _V(
        "semi",
        ["WSTG-INPV-05"],
        "需要通过 SQLi 批量改 product 描述 —— 属有副作用的写。"
        "红线 7：受控写必须 deep 档 + 台账 write 授权 + 上限 6 次。不给授权则做不了。",
        "注入语句更新全部产品描述。"),

    "NoSQL DoS": _V(
        "gap",
        [],
        "两条硬约束叠加：①清单 INPV 止于 23（不安全反序列化），没有 NoSQL 注入项；"
        "②这是 DoS，红线 11 明确「DoS 不列攻击目标」。显式记为缺口，不许算成没问题。",
        "向 review API 提交 $where 类负载使服务不可用。"),

    "NoSQL Exfiltration": _V(
        "gap",
        [],
        "aiscan 没有 NoSQL 注入检测体 —— 清单层面的缺口（红线 14）。"
        "【易误判提醒】全库 grep mongodb **是有命中的**，但那几处都不是注入检测："
        "engine/checks/net.py 与 base.py 把 27017 当**端口暴露**识别服务名；"
        "extras.py 把 MongoDB 算作**未授权访问面**；nuclei_map.py 里它和 redis/mysql 并列 "
        "在 exposed-panels 分类。也就是说「27017 开着」会被 EXT-CL-02 上报，"
        "但「$ne 操作符取到他人数据」检测不到。补法：新增 WSTG-INPV-24 NoSQL 注入项并绑执行体。",
        "更新数据 API 提交 {\"$ne\": \"\"} 取回他人数据。"),

    "NoSQL Manipulation": _V(
        "gap",
        [],
        "同 NoSQL Exfiltration —— INPV 系列里没有任何一项声明负责 NoSQL 语法注入。",
        "利用 $ne 更新他人 review。"),

    "SSTi": _V(
        "semi",
        ["WSTG-INPV-18"],
        "INPV-18 detect 明写「Jinja2 / Twig / FreeMarker 等模板渲染」。"
        "Juice Shop 的 SSTI 在 profile image URL 字段，需登录态+特定注入点，降 semi。",
        "username 置为模板表达式，用户名渲染处执行。"),

    # ===================== XXE (2) =====================
    "XXE Data Access": _V(
        "semi",
        ["WSTG-INPV-07"],
        "INPV-07 detect 「XML 解析器未禁用外部实体，可读文件 / SSRF / OOB」完全对口。"
        "需上传/提交 XML（has_upload 成立）且读文件效果需要签发 B — 降 semi。",
        "上传含 SYSTEM \\\"file:///etc/passwd\\\" 的 XML → 文件内容回显。"),

    "XXE DoS": _V(
        "na",
        [],
        "DoS 类按红线 11 不做，且要做的是 billion laughs —— "
        "即使 detects 存在也不允许触发。",
        "上传带大量实体的 XML 使解析耗尽内存。"),

    # ===================== XSS (9) =====================
    "Reflected XSS": _V(
        "auto",
        ["WSTG-INPV-01"],
        "INPV-01 detect 「输入在响应中原样回显且未做上下文编码」。"
        "搜索接口 + 尖括号回显是典型的 auto 命中场景。",
        "GET /#/search?q=<iframe src=\\\"javascript:alert(1)\\\"> → 报错/日志确认。"),

    "API-only XSS": _V(
        "semi",
        ["WSTG-INPV-02"],
        "INPV-02 存储型 XSS，但需要向 API **写入** payload —— "
        "红线 7 的受控写约束（deep + 台账授权 + 6 次封顶）适用，故 semi。",
        "PUT /api/Products/{id} 把 description 写成 XSS payload。"),

    "DOM XSS": _V(
        "semi",
        ["WSTG-CLNT-01"],
        "CLNT-01 是 DOM XSS（has_client 成立）。但 Juice Shop 的 sink 要"
        " SPA 渲染后才执行 —— 依赖 render.py（红线 29，deep 档 + 有副作用）。",
        "把 <script>alert</script> 置入 search params → 渲染后执行。"),

    "HTTP-Header XSS": _V(
        "semi",
        ["WSTG-INPV-01", "WSTG-CLNT-03"],
        "反射点在 HTTP 头（如 User-Agent/True-Client-IP）而非普通参数。"
        "检测器要打到「header 也是输入点」才成立 —— INFO-06 会枚举 header 输入点，"
        "但能否污染这个具体端点不确定，降 semi。",
        "把恶意值放进特定请求头 → 出现在响应里。"),

    "CSP Bypass": _V(
        "manual",
        ["WSTG-CONF-12"],
        "CONF-12 只判「CSP 是否缺失/unsafe-inline/通配符」—— 这是策略体检，"
        "不是「绕过某个精心配的 CSP 完成 XSS」。后者要人读策略再构造。",
        "读 CSP 指令 → 找出被放行的域 → 在该域上托管 payload 完成 bypass。"),

    "Client-side XSS Protection": _V(
        "manual",
        ["WSTG-CLNT-01", "WSTG-CONF-12"],
        "需要绕过前端过滤/编码逻辑。客户端防护的绕过要人读 JS 再构造 —— "
        "这是 Blackbox 自动化的经典盲区。",
        "读 bundle 里过滤函数 → 构造绕过 payload。"),

    "Server-side XSS Protection": _V(
        "manual",
        ["WSTG-INPV-01"],
        "服务端 sanitizer 的绕过同样需要人机迭代，自动化只会报「被过滤了」。",
        "迭代 payload 绕过服务端黑名单。"),

    "Video XSS": _V(
        "manual",
        [],
        "原挂 BUSL-08/09 会在上传类发现确证时被顺带计数——但上传大小/类型/毒字节"
        "的证据证明不了「字幕注入 XSS」，属夸大归口（红线 19），已摘除。"
        "该挑战的真实链是：zip 路径穿越覆写 frontend 字幕文件 → /promotion 注入，"
        "v20.2.0 实测 fileWrite 挑战默认关闭（zip 上传返回 204 但不解包落盘），"
        "字幕文件无法覆写，本实例不可为。",
        "上传带 HLS/manifest 的视频，誓执行侧加载外部字幕。"),

    "Bonus Payload": _V(
        "manual",
        ["WSTG-INPV-01"],
        "往 Gitter/推广面里注入——通常 Neo cross-context payload，靠人構造。",
        "在特定环境触发 alert 的额外 payload 变种。"),

    # ===================== Broken Access Control (12) =====================
    "Admin Section": _V(
        "auto",
        ["WSTG-CONF-05", "WSTG-ATHZ-02"],
        "CONF-05 detect「管理接口枚举」+ ATHZ-02「直接访问受保护资源」。"
        "aiscan 有 ADMIN_PATHS 字典 + SPA 路由提取，/administration 是标准路径。",
        "匿名访问 /#/administration → 管理面板直接可用。"),

    "View Basket": _V(
        "semi",
        ["WSTG-ATHZ-04", "WSTG-APIT-02"],
        "ATHZ-04 / APIT-02 都是 IDOR/BOLA —— 归口准确。"
        "但**证据必须来自两个不同账号的比对**（READ-04 路径 requires=[\"accounts\"]），"
        "Juice Shop 需要真注册两个账号，sessionpool 配置到位才行，故 semi。",
        "用 A 账号的 token 读 basket/{B_id} → 返回 B 的内容。"),

    "Manipulate Basket": _V(
        "manual",
        ["WSTG-ATHZ-04", "WSTG-BUSL-03"],
        "「把别人的商品塞进自己篮子」的确认需要理解业务语义："
        "同样一串响应，什么叫「成功」只有人能判断。红线 3/32：业务正确性只能人判。",
        "持有 A 的 basket 调用两条 basketId 不匹配的 PUT → 断言 amalgam。"),

    "Forged Feedback": _V(
        "semi",
        ["WSTG-BUSL-02", "WSTG-ATHZ-03"],
        "冒名提交（不校验 authorship）。需写操作 → 受红线 7 写约束。"
        "差分检测（business.py）在 deep 档能给出证据，故 semi 而非 manual。",
        "POST /api/Feedbacks 携带 UserId 字段 → 以他人身份留下评论。"),

    "Forged Review": _V(
        "semi",
        ["WSTG-BUSL-02", "WSTG-ATHZ-03"],
        "同 Forged Feedback，另一类 review API。",
        "PUT /api/Products/{id}/reviews 携带 author 字段。"),

    "Five-Star Feedback": _V(
        "semi",
        ["WSTG-ATHZ-03", "WSTG-APIT-02"],
        "删除他人 feedback —— 需要两个账号 + 写操作。",
        "A 账号 DELETE /api/Feedbacks/{B 的 id} → 200。"),

    "Product Tampering": _V(
        "semi",
        ["WSTG-BUSL-02", "WSTG-ATHZ-04", "WSTG-INPV-05"],
        "改他人产品描述。官方提示是 SQLi 路径也能达到；"
        "若走 write 路线则受红线 7 约束。",
        "PUT /api/Products/{id} 改 description/image。"),

    "CSRF": _V(
        "semi",
        ["WSTG-SESS-05"],
        "SESS-05 detect 「缺 Token / Token 不校验 / SameSite 缺失」正对口。"
        "Juice Shop 的 CSRF 在密码修改 —— 需要会话态复现，降 semi。",
        "构造跨域表单改密码 → 带上受害者的 Cookie 后生效。"),

    "SSRF": _V(
        "semi",
        ["WSTG-INPV-19", "EXT-CL-01"],
        "INPV-19 detect「URL/回调参数可发起服务端请求」对口。"
        "但**证明**要带外（OOB）回调服务 —— 没有 OOB 监听器时最多只能判断"
        "「接受了外部 URL」，确认不了请求真发出去了（红线 9：孤证不能当结论）。",
        "把 avatar URL 指向攻击者主机 → 收到来自服务端的请求。"),

    "Easter Egg": _V(
        "na",
        [],
        "官方自己标 Shenanigans —— 找隐藏彩蛋，不是漏洞。",
        "按官方引导打开隐藏页面。"),

    "Web3 Sandbox": _V(
        "na",
        [],
        "Web3/合约沙箱，非 HTTP 协议面。量程之外。",
        "通过 Web3 交互笔屿。"),

    # ===================== Broken Authentication (9) =====================
    "Password Strength": _V(
        "semi",
        ["WSTG-ATHN-02"],
        "ATHN-02「默认凭据」—— 但需要一份命中 answers 的字典。"
        "aiscan 的 sessionpool 支持配置凭据与默认口令表；字典内容决定成败，降 semi。",
        "用配置字典撞出弱口令账户。"),

    "Admin Registration": _V(
        "semi",
        ["WSTG-INPV-20", "WSTG-IDNT-02"],
        "注册时注入 role:admin 字段 —— INPV-20 批量赋值 detect 完全对口，"
        "app=has_api 成立。需写操作（注册）→ 受红线 7 约束。",
        "POST /api/Users 携带 role:\"admin\" → 建出管理员。"),

    "Login Support Team": _V(
        "na",
        [],
        "官方标 Brute Force + Code Analysis：需要源码里的一串凭据。"
        "黑盒 + 无字典时不成立。",
        "需先用源码里的信息撞/直接得到账户。"),

    "Login Bjoern": _V(
        "na",
        [],
        "需要拿到并破解他的 MD5 口令散列（OSINT/离线爆破），非服务端可判定缺陷。",
        "对泄露的 MD5 做字典还原。"),

    "Login Amy": _V(
        "na",
        [],
        "OSINT 推导同侪关系得到口令。非 HTTP 层。",
        "从公开线索推导出密码。"),

    "Change Bender's Password": _V(
        "semi",
        ["WSTG-ATHN-09", "WSTG-ATHZ-03"],
        "口令重置/修改流程未绑定用户。ATHN-09 detect 正对口；"
        "需两个账号才能证明「改到别人头上」，降 semi。",
        "A 会话里 POST 修改 B 的密码 → B 的原密码失效。"),

    "Reset Bender's Password": _V(
        "na", [], "OSINT 密保问题。", "从公开信息推出密保答案。"),
    "Reset Bjoern's Password": _V(
        "na", [], "OSINT + MD5 散列还原（同 Login Bjoern）。", "推出密保答案或还原散列。"),
    "Bjoern's Favorite Pet": _V(
        "na", [], "OSINT：从公开渠道查出他的宠物名字作为答案。非 HTTP 层缺陷。",
        "从公开资料查出宠物名，作为密保答案使用。"),
    "Login MC SafeSearch": _V(
        "na", [], "官方标 OSINT/Shenanigans：需从歌词等公开线索推出口令。",
        "从公开歌词线索推导出账户口令。"),

    # ---- JWT 两条：Juice Shop 的重头戏，aiscan 有归口但只到「结构分析」 ----
    "Unsigned JWT": _V(
        "semi",
        ["WSTG-SESS-10"],
        "SESS-10 detect 明写「alg 可改为 none / HS256 弱密钥 / 未校验签名与过期 / kid 注入」"
        "—— 归口完全对口。但 session.py 的 WSTG-SESS-10 做的是**解析采集到的 token 做静态结构分析**"
        "（alg 字段、缺失 exp 等），不会**伪造一个 alg=none 的 token 再拿去访问接口**。"
        "差一步就是「疑似」和「证明」的区别（红线 1：通过只能来自真实执行），故 semi 不抬 auto。",
        "取到的 token 头部 alg=none，伪造后仍能通过校验。"),

    "Forged Signed JWT": _V(
        "semi",
        ["WSTG-SESS-10"],
        "同 Unsigned JWT —— 这条还要从 jwks.json 取公钥并用 Kid mistakes 伪造。"
        "静态分析能发现「用了 JWKS」，伪造+验证的那一步没有自动化执行体。",
        "用 JWKS 公钥伪造签名后的 token 被服务端接受。"),

    "Missing Encoding": _V(
        "na", [], "官方标 Shenanigans：非安全缺陷。", "按茧引导完成。"),
    "Reset Jim's Password": _V(
        "na", [], "OSINT 密保问题。", "推出密保答案。"),
    "Reset Morty's Password": _V(
        "na", [], "OSINT + Brute Force。", "推出密保答案。"),

    "Two Factor Authentication": _V(
        "manual",
        ["WSTG-ATHN-11"],
        "ATHN-11 detect 写了 MFA 弱点的范畴，但**验证**需要 TOTP 爆破或分子逻辑，"
        "属于需要人参与的多步操作。",
        "枚举 TOTP 重置受害者 2FA。"),

    "CAPTCHA Bypass": _V(
        "manual",
        ["WSTG-BUSL-07", "EXT-RB-03"],
        "BUSL-07/RB-03 判「有没有验证码」；判它不是判「验证码能不能被绕过」。"
        "绕过要解决实际验证码 —— 人也得有工具。",
        "重放/复用 CAPTCHA 响应绕过限制。"),

    "Multiple Likes": _V(
        "manual",
        ["WSTG-BUSL-05", "EXT-RB-01"],
        "「同一富强: 一个账号只能点赞一次」的绕过是典型inctrl multi-step；"
        "RB-01 能判「有无频控」但判不了「频控可绕过」。",
        "绕过一次性点赞限制。"),

    "Extra Language": _V(
        "manual",
        ["WSTG-CONF-15"],
        "隐藏语言包需要通过特定兰姆达/请求构造解锁，不是常规配置缺陷。",
        "构造请求/ host 取出隐藏语言资源。"),

    # ===================== Improper Input Validation (12) =====================
    "Repetitive Registration": _V(
        "semi",
        ["WSTG-IDNT-02", "EXT-RB-03"],
        "重复注册/批量注册。IDNT-02 detect 明写「批量注册」。"
        "但会产生副作用（建账号），受红线 7 写约束。",
        "绕过客户端限制重复提交相同用户。"),

    "Empty User Registration": _V(
        "semi",
        ["WSTG-IDNT-02"],
        "空值/越界注册。同上，需写操作。",
        "提交空 email / 空 password 建号成功。"),

    "Expired Coupon": _V(
        "semi",
        ["WSTG-BUSL-05"],
        "BUSL-05「优惠券无次数/有效期限制」detect 正对口；"
        "但需要真正走到结账流程，属多步且带副作用 → semi。",
        "使用已过期优惠券结账成功。"),

    "Upload Size": _V(
        "semi",
        ["WSTG-BUSL-08", "EXT-RB-02"],
        "BUSL-08/RB-02 detect「文件大小无限制」。app=has_upload 成立。"
        "需上传 → 受红线 7 写约束。",
        "上传超预期大小的头像成功。"),

    "Upload Type": _V(
        "semi",
        ["WSTG-BUSL-08"],
        "MIME/内容校验缺失。同上。",
        "上传非 PDF 的营业执照文件成功。"),

    "Poison Null Byte": _V(
        "semi",
        ["WSTG-BUSL-08"],
        "文件名 %00 截断。同上（通常算是 business.recon 的差分对象）。",
        "上传 xx.pdf%00.exe 绕过类型校验。"),

    "Zero Stars": _V(
        "manual",
        ["WSTG-BUSL-01"],
        "「评 0 星」需要绕过前端滑块/禁用 UI —— 服务端接受 0 是 USES 一句话，"
        "但这条挑战的灵魂是「怎么绕过 UI」，不是业务逻辑错误。",
        "绕过前端限制提交 0 星评价。"),

    "Payback Time": _V(
        "manual",
        ["WSTG-BUSL-03", "WSTG-ATHZ-04"],
        "负购物篮/非法金额。BUSL-03 detect「关键参数客户端提交且服务端不重算」对口；"
        "但凑出一个「总价为负还要能结账」的具体序列是典型商业中心推理 → manual。",
        "把购物篮改成负数总额并完成结账。"),

    "Deluxe Fraud": _V(
        "manual",
        ["WSTG-BUSL-10"],
        "支付金额篡改/ariusel Membership。app=has_payment —— "
        "Juice Shop 的「支付」是模拟流程，适用性本身就可疑，且需多步。",
        "用 2889 free 流程 bought deluxe membership。"),

    "GDPR Data Erasure": _V(
        "manual",
        ["WSTG-BUSL-06"],
        "「用错误的删 Because 请求造成数据实际被删」是流程缺陷，"
        "BUSL-06「工作流绕过」对口，但要人理解 GDPR 移除流程再證。",
        "提交非法 erasure 请求 → 数据真被删。"),

    "Mint the Honey Pot": _V(
        "na", [], "Web3 合约交互。", "调用合约 mint。"),

    # ===================== Security Misconfiguration (5) =====================
    "Error Handling": _V(
        "auto",
        ["WSTG-ERRH-01", "WSTG-ERRH-02"],
        "ERRH-01/02 detect「触发异常返回原始错误/数据库语句/内部路径」+「堆栈跟踪泄露」。"
        "Juice Shop 的 /rest/qrcode-error-correction 是标准 course of failure 端点。",
        "构造非法 qr code 值 → 响应含完整堆栈。"),

    "Security Policy": _V(
        "auto",
        ["WSTG-INFO-03"],
        "INFO-03 detect 明写「robots.txt / sitemap.xml / .well-known / security.txt」。"
        "直接对口。",
        "GET /.well-known/security.txt → 200。"),

    "Deprecated Interface": _V(
        "manual",
        ["WSTG-CONF-02", "WSTG-APIT-01"],
        "「发现并正确使用被弃用的 B2B 接口」涉及 legacy 协议细节，"
        "APIT-01 能枚举到路由，但是否「弃用且仍开放」需要语义判断。",
        "向弃用端点提交订单成功。"),

    "Cross-Site Imaging": _V(
        "na",
        [],
        "官方标 Contraption —— 依赖特定 misconfigured OTORS + // 双重具体 payload，"
        "不是 SDL 意义的安全缺陷。",
        "构造特定路径让外部图片被当作本站资源。"),

    # ===================== Miscellaneous (6) =====================
    "Score Board": _V(
        "auto",
        ["WSTG-CONF-05", "WSTG-APIT-01"],
        "隐藏分数板对外开放。路径枚举 + SPA 路由提取能直接找到 /score-board。"
        "（ground_truth.yaml 头部「坑一」提醒：这类命中报的是路径，不是 .js URL。）",
        "GET /#/score-board → 200。"),

    "Privacy Policy": _V(
        "na", [], "官方标 Good Practice/Tutorial，非漏洞。", "阅读隐私政策。"),
    "Privacy Policy Inspection": _V(
        "na", [], "官方标 Shenanigans。", "检查隐私政策里隐藏信息。"),
    "Wallet Depletion": _V(
        "na", [], "Web3。", "耗尽钱包。"),
    "Mass Dispel": _V(
        "na", [], "官方标 Prerequisite/非漏洞类：拿到一次性赝品验证码即可完成。",
        "使用赝品一次性验证码完成任务。"),
    "Security Advisory": _V(
        "na", [], "OSINT：找到并对照官方安全公告。", "检索到组件安全公告。"),

    # ===================== Vulnerable Components (9) =====================
    "Vulnerable Library": _V(
        "semi",
        ["EXT-SC-01", "EXT-SC-08"],
        "EXT-SC-01 detect「提取打包 JS 中 jQuery/Lodash/Vue/React 版本，比对 NVD」对口，"
        "app=has_component 成立。Juice Shop 的 jQuery 版本可从 bundle 拿到。"
        "命中与否取决于本地 CVE 数据是否最新 → semi。",
        "从 bundle 提取 jQuery 版本 → 对应已知 CVE。"),

    "Frontend Typosquatting": _V(
        "semi",
        ["EXT-SC-09"],
        "EXT-SC-09（2026-10-10 新增）已能离线做包名近似比对（编辑距离 ≤1 + "
        "-js/node- 伪装前后缀），「没有任何 typosquatting 检查项」这条缺口已不成立，"
        "故不再记 gap。但命中前提是**真拿到依赖清单**：Juice Shop 的 /package.json "
        "返回 SPA 首页（不是 JSON），/ftp/package.json.bak 返回 403，"
        "本轮 EXT-SC-09 落到「未取得依赖清单」的覆盖度说明 → 未命中，记 semi。",
        "比对 npm 包名与官方 registry 的近似包。"),

    "Legacy Typosquatting": _V(
        "semi", ["EXT-SC-09"],
        "同 Frontend Typosquatting —— 归口 EXT-SC-09（新增），"
        "命中与否同样取决于能否取得依赖清单。",
        "比对 legacy 包名。"),

    "Supply Chain Attack": _V(
        "na", [], "官方标 OSINT：需要比对 external dependency 的来源真实性。",
        "验证某个依赖实际来自恶意 fork。"),

    "Arbitrary File Write": _V(
        "na", [], "依赖 CVE 的完整利用链（非黑盒 + Danger Zone）。", "利用组件 CVE 写文件。"),
    "Local File Read": _V(
        "manual",
        ["WSTG-ATHZ-01"],
        "ATHZ-01 目录遍历/文件包含 detect 对口，但 Juice Shop 这条要走"
        "特定依赖 CVE/ jsonify 路径 + Danger Zone，常规遍历 payload 打不中 → 不抬到 auto。",
        "通过特定路径读取服务端本地文件。"),

    "Vulnerable Infrastructure": _V(
        "manual",
        ["EXT-CL-05", "EXT-CL-09"],
        "需要判定『运行环境/IaC 配置不当』——黑盒只能看到服务版本，"
        "看不到 Terraform/misconfig。EXT-CL-09 说得很清楚是「外部可判定部分」，量有限。",
        "对照 IaC/容器配置找出暴露面。"),

    # ===================== Cryptographic Issues (5) =====================
    "Weird Crypto": _V(
        "manual",
        ["WSTG-CRYP-04"],
        "CRYP-04 detect「MD5/SHA1/DES/RC4/ECB/硬编码密钥」对口。"
        "但 Juice Shop 这条考的是 z85/base85 这类「奇怪编码」本身；"
        "识别要读代码 → manual。",
        "解码出隐藏字符串。"),

    "Forged Coupon": _V(
        "na", [], "官方标 Code Analysis：需要算出 coupon 的签名/编码规则。",
        "算出并伪造有效优惠券码。"),

    "Imaginary Challenge": _V(
        "na", [], "官方标 Shenanigans —— 不存在的视频/54 Challenges。", "按茧引导完成。"),

    "Nested Easter Egg": _V(
        "na", [], "官方标 Shenanigans。", "找到多层嵌套彩蛋。"),

    "Premium Paywall": _V(
        "na", [], "官方标 Shenanigans：纯前端/客户端逻辑绕过。", "跳过付费墙 UI。"),

    # ===================== Security through Obscurity (3) =====================
    "Blockchain Hype": _V(
        "na", [], "官方标 Code Analysis/Web3。", "从源码找到 Web3 相关 afinidad。"),
    "Steganography": _V(
        "na", [], "官方标 Shenanigans：图片隐写，非 HTTP 层缺陷。", "从图片提取隐藏数据。"),

    # ===================== Observability Failures (4) =====================
    "Access Log": _V(
        "manual",
        ["WSTG-CONF-04", "WSTG-INFO-07"],
        "日志路径可达。路径枚举可能撞到，但「这是日志」的定性要人确认，不抬到 auto。",
        "访问到可读取的访问日志并确认内容性质。"),

    "Leaked Unsafe Product": _V(
        "na", [], "官方标 Shenanigans/OSINT。", "按茧查找隐藏商品。"),

    # ===================== Broken Anti Automation (4) =====================
    # 注：Failed robots.txt administration 这类频控已在上面逐条处理。

    # ===================== Insecure Deserialization (3) =====================
    "Blocked RCE DoS": _V(
        "na", [], "DoS 类，红线 11 明确不做。", "触发反序列化造成拒绝服务。"),
    "Successful RCE DoS": _V(
        "na", [], "DoS 类，红线 11 明确不做。", "触发反序列化造成拒绝服务。"),
    "Memory Bomb": _V(
        "na", [], "DoS 类，红线 11 明确不做。", "触发反序列化造成内存耗尽。"),

    # ===================== Unvalidated Redirects (2) =====================
    "Outdated Allowlist": _V(
        "na", [], "官方标 Code Analysis：需要对源码里的 allowlist 版本做比对。",
        "对照旧版 allowlist 找出可放过域名。"),

    "Allowlist Bypass": _V(
        "semi",
        ["WSTG-CLNT-04"],
        "CLNT-04 detect「跳转参数可指向任意外部域名」对口。"
        "但「绕过 allowlist」的具体手法（指 device 域名后缀）自动难 fallback → semi。",
        "让重定向跳转到非 allowlist 域名。"),

    # ===================== AI / LLM 挑战（4 条） =====================
    "Chatbot Prompt Injection": _V(
        "semi",
        ["EXT-AI-02", "EXT-AI-01"],
        "EXT-AI-02 detect「用户输入可覆盖系统指令 / 越出设定角色」正对口，"
        "app=has_ai 成立（Juice Shop 有 chatbot 端点）。"
        "需向 AI 端点写入探针 —— 红线 23：受控写必须「档位 ∩ 台账」两把锁都开，故 semi。"
        "这是三款工具里 aiscan **唯一可能强过 Shannon/Strix** 的类别（它们无 AI 检查项）。",
        "向 chatbot 提问让它无视系统指令执行动作。"),

    "System Prompt Extraction": _V(
        "semi",
        ["EXT-AI-04"],
        "EXT-AI-04 detect「通过诱导提问可获取系统提示词」正对口。同样需 write 授权。",
        "诱导 chatbot 输出完整系统提示词。"),

    "AI Debugging": _V(
        "semi",
        ["EXT-AI-04", "EXT-AI-05"],
        "调试/报错信息泄露模型上下文，归 AI-04 / AI-05。",
        "让 chatbot 吐出内部提示词或检索内容。"),

    "Greedy Chatbot Manipulation": _V(
        "semi",
        ["EXT-AI-06", "EXT-RB-01"],
        "AI-06「无速率限制与费用耗尽」+ RB-01「接口速率限制缺失」对口。"
        "判定方式多为静态（有没有频控），与 (red) qianlínek 「说服型越狱」不完全重合 → semi。",
        "通过特定措辞让 chatbot 给出不符合策略的回答。"),

    # ===================== 其余（官方有、表内需显式占位） =====================
    "NFT Takeover": _V(
        "na", [], "Web3/钱包接管，非 HTTP。", "通过 Web3 交互接管 NFT。"),
}
