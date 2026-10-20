Juice Shop × aiscan 静态能力映射
==============================================================================
官方挑战总数            : 116  (源 sha256 8efa070380ab)
黑盒量程之内（分母）    : 80  (69.0%)
量程之外（不计分母）    : 36  (31.0%)

判定          数量      占总量   含义
------------------------------------------------------------------------------
auto        17   14.7%   能力强上界（黑盒可自动）
semi        37   31.9%   需前置条件（账号/写/渲染/OOB）
manual      20   17.2%   只能人工项
gap          6    5.2%   能力缺口（清单无该项）
na          36   31.0%   量程之外（白盒/OSINT/Web3/DoS/非漏洞）

能力上界（auto）        : 17 / 80 = 21.2%   ← 这是天花板，不是命中数
能力缺口（gap）         : 6 / 80 = 7.5%   ← 清单里没人负责，需显式列出

按官方类别分布（na 单独列，便于看出哪些类别整体在量程外）
------------------------------------------------------------------------------
类别                               总  auto  semi  man  gap   na
Sensitive Data Exposure         17     4     6    0    1    6
Injection                       14     5     6    0    3    0
Improper Input Validation       12     0     7    3    0    2
Broken Access Control           12     1     8    1    0    2
XSS                              9     1     3    5    0    0
Vulnerable Components            9     0     3    2    2    2
Broken Authentication            9     0     2    2    0    5
Miscellaneous                    6     2     0    0    0    4
Security Misconfiguration        5     2     0    1    0    2
Cryptographic Issues             5     0     0    1    0    4
Observability Failures           4     2     0    2    0    0
Broken Anti Automation           4     0     0    3    0    1
Security through Obscurity       3     0     0    0    0    3
Insecure Deserialization         3     0     0    0    0    3
Unvalidated Redirects            2     0     1    0    0    1
XXE                              2     0     1    0    0    1

【auto】能力强上界（黑盒可自动）  —— 17 条
------------------------------------------------------------------------------
  · Retrieve Blueprint  (难度5, Sensitive Data Exposure)
      归口: WSTG-CONF-03,WSTG-CONF-04,WSTG-INFO-05
  · Forgotten Developer Backup  (难度4, Sensitive Data Exposure)
      归口: WSTG-CONF-03,WSTG-CONF-04
  · Forgotten Sales Backup  (难度4, Sensitive Data Exposure)
      归口: WSTG-CONF-03,WSTG-CONF-04
  · Misplaced Signature File  (难度4, Observability Failures)
      归口: WSTG-CONF-03,WSTG-CONF-04
  · User Credentials  (难度4, Injection)
      归口: WSTG-INPV-05
  · Database Schema  (难度3, Injection)
      归口: WSTG-INPV-05
  · Login Bender  (难度3, Injection)
      归口: WSTG-INPV-05
  · Login Jim  (难度3, Injection)
      归口: WSTG-INPV-05
  · Admin Section  (难度2, Broken Access Control)
      归口: WSTG-CONF-05,WSTG-ATHZ-02
  · Login Admin  (难度2, Injection)
      归口: WSTG-INPV-05
  · Misplaced IaC Files  (难度2, Security Misconfiguration)
      归口: EXT-CD-01,WSTG-CONF-04
  · Reflected XSS  (难度2, XSS)
      归口: WSTG-INPV-01
  · Security Policy  (难度2, Miscellaneous)
      归口: WSTG-INFO-03
  · Confidential Document  (难度1, Sensitive Data Exposure)
      归口: WSTG-CONF-09,WSTG-CONF-04
  · Error Handling  (难度1, Security Misconfiguration)
      归口: WSTG-ERRH-01,WSTG-ERRH-02
  · Exposed Metrics  (难度1, Observability Failures)
      归口: WSTG-CONF-05,WSTG-CONF-02
  · Score Board  (难度1, Miscellaneous)
      归口: WSTG-CONF-05,WSTG-APIT-01

【semi】需前置条件（账号/写/渲染/OOB）  —— 37 条
------------------------------------------------------------------------------
  · Forged Signed JWT  (难度6, Vulnerable Components)
      归口: WSTG-SESS-10
  · SSRF  (难度6, Broken Access Control)
      归口: WSTG-INPV-19,EXT-CL-01
  · SSTi  (难度6, Injection)
      归口: WSTG-INPV-18
  · Change Bender's Password  (难度5, Broken Authentication)
      归口: WSTG-ATHN-09,WSTG-ATHZ-03
  · Email Leak  (难度5, Sensitive Data Exposure)
      归口: EXT-DP-01,EXT-DP-02
  · Leaked API Key  (难度5, Sensitive Data Exposure)
      归口: EXT-SC-07,EXT-CL-06
  · Unsigned JWT  (难度5, Vulnerable Components)
      归口: WSTG-SESS-10
  · Allowlist Bypass  (难度4, Unvalidated Redirects)
      归口: WSTG-CLNT-04
  · Christmas Special  (难度4, Injection)
      归口: WSTG-INPV-05
  · Ephemeral Accountant  (难度4, Injection)
      归口: WSTG-INPV-05
  · Expired Coupon  (难度4, Improper Input Validation)
      归口: WSTG-BUSL-05
  · GDPR Data Theft  (难度4, Sensitive Data Exposure)
      归口: EXT-DP-03,WSTG-APIT-03
  · HTTP-Header XSS  (难度4, XSS)
      归口: WSTG-INPV-01,WSTG-CLNT-03
  · Login Cloud Admin  (难度4, Sensitive Data Exposure)
      归口: WSTG-ATHN-02,EXT-CD-01
  · Poison Null Byte  (难度4, Improper Input Validation)
      归口: WSTG-BUSL-08
  · Vulnerable Library  (难度4, Vulnerable Components)
      归口: EXT-SC-01,EXT-SC-08
  · API-only XSS  (难度3, XSS)
      归口: WSTG-INPV-02
  · Admin Registration  (难度3, Improper Input Validation)
      归口: WSTG-INPV-20,WSTG-IDNT-02
  · CSRF  (难度3, Broken Access Control)
      归口: WSTG-SESS-05
  · Forged Feedback  (难度3, Broken Access Control)
      归口: WSTG-BUSL-02,WSTG-ATHZ-03
  · Forged Review  (难度3, Broken Access Control)
      归口: WSTG-BUSL-02,WSTG-ATHZ-03
  · Greedy Chatbot Manipulation  (难度3, Injection)
      归口: EXT-AI-06,EXT-RB-01
  · Product Tampering  (难度3, Broken Access Control)
      归口: WSTG-BUSL-02,WSTG-ATHZ-04,WSTG-INPV-05
  · System Prompt Extraction  (难度3, Injection)
      归口: EXT-AI-04
  · Upload Size  (难度3, Improper Input Validation)
      归口: WSTG-BUSL-08,EXT-RB-02
  · Upload Type  (难度3, Improper Input Validation)
      归口: WSTG-BUSL-08
  · XXE Data Access  (难度3, XXE)
      归口: WSTG-INPV-07
  · AI Debugging  (难度2, Broken Access Control)
      归口: EXT-AI-04,EXT-AI-05
  · Chatbot Prompt Injection  (难度2, Injection)
      归口: EXT-AI-02,EXT-AI-01
  · Empty User Registration  (难度2, Improper Input Validation)
      归口: WSTG-IDNT-02
  · Exposed Credentials  (难度2, Sensitive Data Exposure)
      归口: EXT-SC-07,EXT-CL-06,WSTG-INFO-05
  · Five-Star Feedback  (难度2, Broken Access Control)
      归口: WSTG-ATHZ-03,WSTG-APIT-02
  · Password Hash Leak  (难度2, Sensitive Data Exposure)
      归口: WSTG-APIT-03,EXT-DP-01
  · Password Strength  (难度2, Broken Authentication)
      归口: WSTG-ATHN-02
  · View Basket  (难度2, Broken Access Control)
      归口: WSTG-ATHZ-04,WSTG-APIT-02
  · DOM XSS  (难度1, XSS)
      归口: WSTG-CLNT-01
  · Repetitive Registration  (难度1, Improper Input Validation)
      归口: WSTG-IDNT-02,EXT-RB-03

【manual】只能人工项  —— 20 条
------------------------------------------------------------------------------
  · Multiple Likes  (难度6, Broken Anti Automation)
      归口: WSTG-BUSL-05,EXT-RB-01
  · Video XSS  (难度6, XSS)
      归口: WSTG-BUSL-08,WSTG-BUSL-09
  · Extra Language  (难度5, Broken Anti Automation)
      归口: WSTG-CONF-15
  · Leaked Access Logs  (难度5, Observability Failures)
      归口: WSTG-CONF-04,WSTG-CONF-09
  · Local File Read  (难度5, Vulnerable Components)
      归口: WSTG-ATHZ-01
  · Two Factor Authentication  (难度5, Broken Authentication)
      归口: WSTG-ATHN-11
  · Access Log  (难度4, Observability Failures)
      归口: WSTG-CONF-04,WSTG-INFO-07
  · CSP Bypass  (难度4, XSS)
      归口: WSTG-CONF-12
  · Server-side XSS Protection  (难度4, XSS)
      归口: WSTG-INPV-01
  · CAPTCHA Bypass  (难度3, Broken Anti Automation)
      归口: WSTG-BUSL-07,EXT-RB-03
  · Client-side XSS Protection  (难度3, XSS)
      归口: WSTG-CLNT-01,WSTG-CONF-12
  · Deluxe Fraud  (难度3, Improper Input Validation)
      归口: WSTG-BUSL-10
  · GDPR Data Erasure  (难度3, Broken Authentication)
      归口: WSTG-BUSL-06
  · Manipulate Basket  (难度3, Broken Access Control)
      归口: WSTG-ATHZ-04,WSTG-BUSL-03
  · Payback Time  (难度3, Improper Input Validation)
      归口: WSTG-BUSL-03,WSTG-ATHZ-04
  · Vulnerable Infrastructure  (难度3, Vulnerable Components)
      归口: EXT-CL-05,EXT-CL-09
  · Deprecated Interface  (难度2, Security Misconfiguration)
      归口: WSTG-CONF-02,WSTG-APIT-01
  · Weird Crypto  (难度2, Cryptographic Issues)
      归口: WSTG-CRYP-04
  · Bonus Payload  (难度1, XSS)
      归口: WSTG-INPV-01
  · Zero Stars  (难度1, Improper Input Validation)
      归口: WSTG-BUSL-01

【gap】能力缺口（清单无该项）  —— 6 条
------------------------------------------------------------------------------
  · Frontend Typosquatting  (难度5, Vulnerable Components)
      归口: —无归口—
  · NoSQL Exfiltration  (难度5, Injection)
      归口: —无归口—
  · Legacy Typosquatting  (难度4, Vulnerable Components)
      归口: —无归口—
  · NoSQL DoS  (难度4, Injection)
      归口: —无归口—
  · NoSQL Manipulation  (难度4, Injection)
      归口: —无归口—
  · Meta Geo Stalking  (难度2, Sensitive Data Exposure)
      归口: —无归口—

【na】量程之外（白盒/OSINT/Web3/DoS/非漏洞）  —— 36 条
------------------------------------------------------------------------------
  · Arbitrary File Write  (难度6, Vulnerable Components)
      归口: —无归口—
  · Forged Coupon  (难度6, Cryptographic Issues)
      归口: —无归口—
  · Imaginary Challenge  (难度6, Cryptographic Issues)
      归口: —无归口—
  · Login Support Team  (难度6, Security Misconfiguration)
      归口: —无归口—
  · Premium Paywall  (难度6, Cryptographic Issues)
      归口: —无归口—
  · Successful RCE DoS  (难度6, Insecure Deserialization)
      归口: —无归口—
  · Wallet Depletion  (难度6, Miscellaneous)
      归口: —无归口—
  · Blockchain Hype  (难度5, Security through Obscurity)
      归口: —无归口—
  · Blocked RCE DoS  (难度5, Insecure Deserialization)
      归口: —无归口—
  · Cross-Site Imaging  (难度5, Security Misconfiguration)
      归口: —无归口—
  · Memory Bomb  (难度5, Insecure Deserialization)
      归口: —无归口—
  · Reset Bjoern's Password  (难度5, Broken Authentication)
      归口: —无归口—
  · Reset Morty's Password  (难度5, Broken Anti Automation)
      归口: —无归口—
  · Supply Chain Attack  (难度5, Vulnerable Components)
      归口: —无归口—
  · XXE DoS  (难度5, XXE)
      归口: —无归口—
  · Easter Egg  (难度4, Broken Access Control)
      归口: —无归口—
  · Leaked Unsafe Product  (难度4, Sensitive Data Exposure)
      归口: —无归口—
  · Login Bjoern  (难度4, Broken Authentication)
      归口: —无归口—
  · Nested Easter Egg  (难度4, Cryptographic Issues)
      归口: —无归口—
  · Reset Bender's Password  (难度4, Broken Authentication)
      归口: —无归口—
  · Reset Uvogin's Password  (难度4, Sensitive Data Exposure)
      归口: —无归口—
  · Steganography  (难度4, Security through Obscurity)
      归口: —无归口—
  · Bjoern's Favorite Pet  (难度3, Broken Authentication)
      归口: —无归口—
  · Login Amy  (难度3, Sensitive Data Exposure)
      归口: —无归口—
  · Mint the Honey Pot  (难度3, Improper Input Validation)
      归口: —无归口—
  · Privacy Policy Inspection  (难度3, Security through Obscurity)
      归口: —无归口—
  · Reset Jim's Password  (难度3, Broken Authentication)
      归口: —无归口—
  · Security Advisory  (难度3, Miscellaneous)
      归口: —无归口—
  · Login MC SafeSearch  (难度2, Sensitive Data Exposure)
      归口: —无归口—
  · NFT Takeover  (难度2, Sensitive Data Exposure)
      归口: —无归口—
  · Visual Geo Stalking  (难度2, Sensitive Data Exposure)
      归口: —无归口—
  · Mass Dispel  (难度1, Miscellaneous)
      归口: —无归口—
  · Missing Encoding  (难度1, Improper Input Validation)
      归口: —无归口—
  · Outdated Allowlist  (难度1, Unvalidated Redirects)
      归口: —无归口—
  · Privacy Policy  (难度1, Miscellaneous)
      归口: —无归口—
  · Web3 Sandbox  (难度1, Broken Access Control)
      归口: —无归口—
