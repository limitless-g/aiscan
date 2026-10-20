# 第三方署名

## OWASP Juice Shop

`bench/` 下的基准体系（答案表 `juice_ground_truth.yaml` 与计分器 `juice_score.py`）
以 **OWASP Juice Shop** 作为评测靶场，其挑战清单与官方答案表来源于该项目。

- 项目：https://github.com/juice-shop/juice-shop
- 许可证：MIT（Juice Shop 本体）；其配套的 《Pwning OWASP Juice Shop》 指南为 CC BY-NC-SA
- 本项目基准实测版本：**v20.2.0**（换版本则分数不可比）

本仓库不分发 Juice Shop 本体，仅引用其挑战清单用于评测。若你是 Juice Shop
维护者且不希望被引用，请开 issue 联系我们移除。

## 第三方可选工具

nuclei / sqlmap / nmap 为**可选依赖**，缺失时本工具自动降级并在报告中标注，
本仓库不包含它们的任何代码，其许可遵循各自上游项目。
