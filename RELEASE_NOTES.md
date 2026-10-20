# Release v1.0.0 — Release Notes 文案（可直接复制粘贴）

> 本文件是给你在 GitHub 网页端创建 Release 时用的现成文案。
> 仓库名：`aiscan`｜标签：`v1.0.0`｜目标分支：`main`

---

## 一、Release 标题（Title）

```
aiscan v1.0.0 — AI 驱动黑盒扫描器：Juice Shop v20.2.0 基准 64/80（80.0%）
```

## 二、Release 说明正文（Describe this release）

```markdown
首个公开发布版本。核心交付：**一套能用官方基准证明自身能力的黑盒扫描器**。

## 🎯 基准成绩（可复现，不是自说自话）

在 OWASP Juice Shop **v20.2.0** 官方 116 条答案表上，去重后真分母 80 项：

| 版本 | 命中 | 召回率 | 变化 |
|---|---|---|---|
| 基线（旧天花板） | 57 | 71.2% | — |
| + 业务逻辑主动验证（8 探针） | 61 | 76.2% | +4 |
| + 权限矩阵夹具修复 | **64** | **80.0%** | +3 |

复现方法（检查清单、测试账号夹具、计分器）全部开源在 `bench/`，跑法见 `部署手册.md` 第 7 章。

## ✨ 主要特性

- **166 项固定检查项**（WSTG 骨架 118 + 场景扩展 48），覆盖 10 大类
- **三态判定 + 禁止假通过**：通过 / 不通过 / 待确认；没有检测代码的项**不会默认「通过」**
- **LLM 应用攻击面检测族** `EXT-AI-*`：提示词注入、系统提示词泄露、AI 调试信息泄露、Chatbot 越权
- **业务逻辑主动验证**：8 个探针在测试靶场模式下真实演练（上传限制、评分边界、优惠券、GDPR、Deluxe、验证码、2FA）
- **权限矩阵验证**：多身份交叉比对，检测越权 / IDOR
- **深度验证**：每个漏洞配可独立执行的验证脚本，目标是「拿数据 / 改数据 / 拿控制权」而非只报疑似
- **零 API Key**：不依赖任何云端服务与大模型接口，离线可跑；缺 nuclei / sqlmap 自动降级并标注
- **合规闸门**：未登记授权的目标引擎直接拒绝扫描

## ⚠️ 诚实口径（未命中的 16 项，逐项列明不为好看虚报）

- **AI 类 3 项**：靶场接 DeepSeek 强模型后，提示注入 / 系统提示词泄露 / AI 调试三项均被得体拒答；换弱模型可以刷到，但那测的是模型不是靶场，故不刷
- **靶场无利用面 9 项**：Expired Coupon（v20.2.0 券码不匹配）、Video XSS（本实例 fileWrite 禁用）、Typosquatting×2（无真抢注包）、Leaked API Key（前端无真密钥）、SSRF（401 墙）、SSTi（入口未匹配）、Vulnerable Infrastructure、XXE（官方已修补）
- **方差 1 项**：Error Handling

## 📦 安装

```bash
git clone https://github.com/limitless-g/aiscan.git
cd aiscan
install.cmd            # Windows（或 powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1）
```

## 📄 许可

MIT。仅限用于**你有权测试的系统**——未授权扫描违法。
```

---

## 三、仓库 About 栏（仓库页右上 ⚙️）

**Description（英文，贴这段）：**

```
AI-driven black-box web security scanner: 166 deterministic checks, tri-state verdicts that forbid false "pass", LLM attack-surface detection (prompt injection / system prompt leakage), and a reproducible 64/80 = 80% recall benchmark on OWASP Juice Shop v20.2.0. Zero API keys.
```

**Homepage（可留空或填仓库地址）**

**Topics（逐个添加，共 14 个）：**

```
security              web-security        dast
black-box-testing     penetration-testing  vulnerability-scanner
llm-security          prompt-injection    ai-security
owasp                 juice-shop          security-automation
python                redteam
```

---

## 四、发布后自检清单

- [ ] 仓库页首屏 README 渲染正常（含 5 个 badge、卖点表、架构图）
- [ ] 架构图能正常渲染（Mermaid 在 GitHub 上生效，若显示纯文本说明语法有误）
- [ ] About 栏 Description 与 Topics 已填
- [ ] Release v1.0.0 已发布，标签指向 `main`
- [ ] **全站搜索无内网痕迹**：在仓库页按 `/` 搜索你公司的域名后缀、内部系统代号、内网网段，均应为 0 结果
  （本仓库发布前已按同一口径扫过一遍；此处是给二次分发/合并分支后的复检提示，不在仓库内留存任何原字符串）
- [ ] 克隆一份到新目录跑 `install.cmd`，确认干净环境可部署
