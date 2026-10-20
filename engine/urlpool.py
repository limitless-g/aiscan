# -*- coding: utf-8 -*-
"""
URL 枚举池
==========
把「目标上有哪些地址值得试」从各检测器里抽出来，统一来源、统一去重、
统一限流、统一安全过滤。

为什么必须抽出来
----------------
以前每个检测器各带一份硬编码路径表（`SENSITIVE_FILE_PATHS`、若干 `("backup/", "logs/")`
之类的元组）。结果是三件事同时发生：

  ① **覆盖面说不清**：没人算得出本次一共试了多少地址、来自哪几个来源。
     报告里只能写「已检查敏感文件」，读者无法判断漏了什么。
  ② **来源单一**：只试静态字典，不看 robots.txt 主动交代的路径、不看 sitemap.xml
     列出的地址、不看页面里真实存在的链接、不看前端产物里的接口。
     目标自己已经告诉我们有哪些路径了，反而不用。
  ③ **安全靠自觉**：枚举会发大量 GET。如果某个路径叫 `/logout` 或
     `/api/order/cancel`，一次 GET 就可能产生真实副作用（登出、取消订单）。
     分散在各检测器里，没有任何地方能统一拦下这类地址。

来源（按可信度从高到低）
------------------------
1. `robots.txt` 的 Disallow / Allow / Sitemap        —— 目标自己声明的路径
2. `sitemap.xml` / `sitemap_index.xml` 的 `<loc>`     —— 目标自己声明的页面
3. 根页面与入口页的 href / src / action              —— 页面里真实存在的地址
4. 前端产物中提取的接口与路径                        —— 代码里真实调用的地址
5. 静态字典（模块 / 面板 / 备份 / 接口 / 配置）      —— 通用猜测
6. 备份与临时文件后缀推导                            —— 针对可疑文件的变体猜测

安全约束
--------
- **只输出站内路径**：站外 URL 一律丢弃，绝不把发现里出现的第三方地址放进枚举。
- **破坏性路径剔除**：登出 / 注销 / 删除 / 取消 / 退订 / 支付确认这类路径
  一进候选就被剔除，并记录剔除原因（报告要能看到「我们刻意没碰哪些地址」）。
- **数量上限按档位收敛**：safe / standard / deep 三档各有上限，避免枚举失控。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

# ==============================================================================
# 破坏性路径：GET 一下就可能产生真实副作用，一律不枚举
# ==============================================================================
# 判定放在**最后一段路径**上，避免误伤 /api/delete-account-guide 这类
# 只是名字里带关键词的正常地址。
DESTRUCTIVE_SEGMENT = re.compile(
    r"(?i)^("
    r"log[\-_]?out|sign[\-_]?out|logout|注销|登出|退出登录"
    r"|delete[a-z\-_]*|remove[a-z\-_]*|destroy|drop|purge|删除"
    r"|unsubscribe|退订"
    r"|cancel[a-z\-_]*|取消"
    r"|disable[a-z\-_]*|deactivate[a-z\-_]*|revoke|停用|禁用"
    r"|pay|paynow|confirm[a-z\-_]*pay[a-z\-_]*|checkout"
    r"|reset[a-z\-_]*(pw|pwd|password)|重置密码"
    r"|shutdown|restart|reboot|kill|terminate|stop"
    r")$"
)

# 只读语义词：命中则**豁免**上面的剔除（例如 /api/delete-status 是查询）
READONLY_HINT = re.compile(r"(?i)(status|list|query|search|check|preview|get|detail|view|info)$")

# ==============================================================================
# 静态字典：按语义分组，报告里按组汇报覆盖
# ==============================================================================
DICT_META = [
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "humans.txt",
    "security.txt", ".well-known/security.txt", ".well-known/change-password",
    "manifest.json", "crossdomain.xml", "clientaccesspolicy.xml", "ads.txt",
    "favicon.ico", "apple-app-site-association", ".well-known/assetlinks.json",
]

DICT_CONFIG = [
    ".env", ".env.local", ".env.development", ".env.production", ".env.backup",
    ".git/config", ".git/HEAD", ".git/index", ".svn/entries", ".hg/hgrc",
    ".DS_Store", ".htaccess", ".htpasswd", "web.config", "app.config",
    "WEB-INF/web.xml", "WEB-INF/classes/application.properties",
    "phpinfo.php", "info.php", "test.php", "config.php", "configuration.php",
    "config.json", "config.yaml", "config.yml", "config.xml", "settings.json",
    "application.yml", "application.properties", "docker-compose.yml",
    "Dockerfile", "Vagrantfile", "Jenkinsfile", ".npmrc", ".dockercfg",
    ".aws/credentials", ".ssh/id_rsa", "id_rsa", "server.key", "cert.pem",
]

DICT_ADMIN = [
    "admin", "admin/", "administrator", "manage", "manager", "console",
    "admin/login", "admin/index", "wp-admin", "wp-login.php", "phpmyadmin",
    "pma", "adminer.php", "adminer", "cpanel", "webmail", "grafana",
    "kibana", "jenkins", "hudson", "nexus", "harbor", "rancher", "portainer",
    "actuator", "actuator/env", "actuator/health", "actuator/beans",
    "actuator/mappings", "actuator/heapdump", "swagger-ui.html",
    "swagger/index.html", "api-docs", "v2/api-docs", "v3/api-docs",
    "openapi.json", "swagger.json", "graphql", "graphiql", "druid",
    "solr", "elasticsearch", "_cat/indices", "server-status", "server-info",
    ".git", ".svn", "metrics", "prometheus", "debug", "debug/pprof",
    "debug/vars", "trace", "env", "health", "status", "version",
]

DICT_BACKUP_DIRS = [
    "backup/", "backups/", "bak/", "old/", "temp/", "tmp/", "cache/",
    "log/", "logs/", "data/", "db/", "dump/", "dumps/", "sql/", "export/",
    "uploads/", "upload/", "files/", "file/", "static/", "assets/",
    "dist/", "build/", "src/", "test/", "tests/", "demo/", "dev/", "staging/",
]

DICT_API = [
    "api", "api/", "api/v1", "api/v2", "api/v1/", "api/v2/", "api/users",
    "api/user", "api/me", "api/profile", "api/account", "api/accounts",
    "api/config", "api/settings", "api/health", "api/status", "api/version",
    "api/docs", "api/swagger.json", "api/export", "api/download",
    "user/info", "user/list", "users", "rest", "rest/api", "graphql",
    "internal", "internal/", "private", "private/", "system/info",
    "monitor", "metrics", "trace/", "jolokia", "jolokia/list",
]

# ==============================================================================
# 备份 / 临时文件后缀推导
# ==============================================================================
# 编辑器与部署流程会在源文件旁留下这些变体，Web 服务器往往照常当静态文件发出去。
BACKUP_SUFFIXES = [
    # 高价值：备份包、源码 / 数据导出。命中即等于拿到源码或整库数据。
    ".bak", ".old", ".orig", ".save", ".sav", ".copy",
    ".zip", ".tar.gz", ".tgz", ".tar", ".rar", ".7z", ".gz", ".sql",
    ".bak1", ".bak2", ".1", ".2",
    # 中价值：编辑器临时文件与配置数据文件
    ".swp", ".swo", "~", ".tmp", ".temp",
    ".json", ".xml", ".txt", ".log",
    # 低价值：年份后缀。命中率低、噪声大，排在最后以让高价值变体先铺满
    ".2019", ".2020", ".2021", ".2022", ".2023", ".2024", ".2025",
]

# 前缀式变体：.index.php.swp 这类隐藏交换文件
BACKUP_PREFIXES = [".", "._"]

# 值得派生后缀的种子：真实存在且内容是配置 / 源码 / 数据的文件
BACKUP_SEEDS = [
    "index.php", "index.html", "index.htm", "index.jsp", "index.asp",
    "index.aspx", "index.action", "index.do", "index.py", "app.py",
    "config.php", "config.js", "config.json", "config.yaml", "config.yml",
    "config.xml", "settings.php", "settings.py", "database.yml", "db.php",
    "conn.php", "connection.php", "common.php", "functions.php",
    "web.config", "app.config", ".env", ".htaccess", "nginx.conf",
    "application.properties", "application.yml", "pom.xml", "package.json",
    "backup.sql", "db.sql", "data.sql", "dump.sql", "init.sql",
    "www.zip", "web.zip", "site.zip", "html.zip", "public_html.zip",
    "backup.zip", "backup.tar.gz", "wwwroot.zip", "source.zip",
    "login.php", "admin.php", "upload.php", "api.php", "user.php",
]

# 档位 → 上限。上限不是「能力」，是「克制度」：枚举必须可预测、可解释。
TIER_LIMITS: dict[str, int] = {"safe": 60, "standard": 420, "deep": 1500}

# 各来源在最终列表里的排序权重（越小越靠前）
SOURCE_WEIGHT = {
    "robots": 0, "sitemap": 1, "页面链接": 2, "前端产物": 3,
    # 接口文档解析出的路径排在「前端产物」之前：它来自目标自己声明的
    # OpenAPI / Swagger schema，是**精确**的（路径、层级、参数名都明确），
    # 不含前端打包产物里那些已经废弃或指向别的服务的地址。
    # 枚举预算有限，越精确的来源越该先占位。
    "接口文档(schema)": 2.5,
    "字典(元信息)": 4, "字典(配置)": 5, "字典(管理面)": 6,
    "字典(接口)": 7, "字典(备份目录)": 8, "备份后缀推导": 9,
}

_ASSET_SUFFIX = re.compile(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|map)$", re.I)
# 页面里可能出现的「像路径」的字符串
_LOOSE_PATH = re.compile(r"""["'\s(](/(?:[\w\-.]{1,60}/){0,6}[\w\-.]{1,60})(?=["'\s)?])""")
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_HREF_RE = re.compile(r"""<(?:a|area)\b[^>]+href\s*=\s*["']([^"']+)["']""", re.I)
_SRC_RE = re.compile(
    r"""<(?:script|link|img|iframe|source|form)\b[^>]+(?:src|href|action)\s*=\s*["']([^"']+)["']""",
    re.I)
_ROBOTS_RULE = re.compile(r"(?im)^\s*(Disallow|Allow)\s*:\s*(\S+)\s*$")
_ROBOTS_SITEMAP = re.compile(r"(?im)^\s*Sitemap\s*:\s*(\S+)\s*$")


@dataclass
class UrlPool:
    """一次枚举的全部候选地址与来源统计。"""

    paths: list[str] = field(default_factory=list)
    sources: dict[str, list[str]] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    #: 与「剔除」无关的覆盖度说明（例如接口文档未解析）。
    #: 不塞进 `skipped` —— 那是一张「因破坏性风险被剔掉」的表，
    #: 混进别的原因会让报告里的「因破坏性风险剔除 N 个」变成错话。
    notes: list[str] = field(default_factory=list)
    tier: str = "standard"
    limit: int = 0

    # ---- 统计 ----
    def count_by_source(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.sources.items()}

    @property
    def total_candidates(self) -> int:
        return sum(len(v) for v in self.sources.values())

    def summary(self) -> str:
        parts = "、".join(f"{k} {v}" for k, v in sorted(
            self.count_by_source().items(),
            key=lambda x: SOURCE_WEIGHT.get(x[0], 99)) if v)
        return (f"{self.tier} 档枚举 {len(self.paths)} 个地址（候选 "
                f"{self.total_candidates} 个，去重后 {len(self.paths)} 个）；"
                f"来源：{parts or '无'}；"
                f"因破坏性风险剔除 {len(self.skipped)} 个")
    def coverage_rows(self) -> list[tuple[str, int, str]]:
        """供报告渲染：(来源, 数量, 说明)。"""
        note = {
            "robots": "robots.txt 主动声明的路径 —— 目标自己交代的",
            "sitemap": "sitemap.xml 收录的地址",
            "页面链接": "根页面与入口页里真实存在的链接（含浏览器渲染后 DOM 中"
                        "才出现的链接，即 SPA 的真实路由）",
            "前端产物": "前端代码里真实调用的接口与路径",
            "字典(元信息)": "站点元信息文件",
            "字典(配置)": "配置 / 凭据 / 版本控制残留",
            "字典(管理面)": "管理与运维入口（含 Spring Actuator 等）",
            "字典(接口)": "接口与文档入口",
            "字典(备份目录)": "常见备份 / 日志 / 上传目录",
            "备份后缀推导": "由已知文件派生的备份与临时文件变体",
        }
        rows = [(k, len(v), note.get(k, "")) for k, v in self.sources.items() if v]
        return sorted(rows, key=lambda r: SOURCE_WEIGHT.get(r[0], 99))


# ==============================================================================
# 主入口
# ==============================================================================
def build_url_pool(ctx: Any, tier: str = "") -> UrlPool:
    """构造 URL 枚举池。

    ctx 需要提供：target_url、domain、get(url)、js_result。
    任何来源取不到都不报错 —— 缺一个来源只影响覆盖面，不该让整轮扫描失败。
    """
    tier = (tier or getattr(ctx, "profile_key", "standard") or "standard").lower()
    limit = TIER_LIMITS.get(tier, TIER_LIMITS["standard"])
    pool = UrlPool(tier=tier, limit=limit)

    host = _host_of(getattr(ctx, "target_url", ""))
    root_body = ""

    # ---- 1) 根页面（页面链接与后续来源都依赖它）----
    try:
        root = ctx.get(ctx.target_url)
        root_body = getattr(root, "body_snippet", "") or ""
    except Exception:  # noqa: BLE001
        root_body = ""

    # ---- 2) robots.txt ----
    robots_body = _safe_get(ctx, "robots.txt")
    if robots_body:
        for m in _ROBOTS_RULE.finditer(robots_body):
            p = m.group(2).strip()
            if p and p != "/" and not p.startswith(("*", "?", "$")):
                _add(pool, "robots", _norm(p))

    # ---- 3) sitemap.xml ----
    for sm in ("sitemap.xml", "sitemap_index.xml"):
        body = _safe_get(ctx, sm)
        if not body:
            continue
        for m in _LOC_RE.finditer(body):
            u = m.group(1).strip()
            rp = _relative(u, host)
            if rp:
                _add(pool, "sitemap", rp)

    # ---- 4) 页面链接 ----
    # SPA 的链接只存在于**渲染后**的 DOM 里：骨架页通常一个 <a> 都没有，
    # 于是「页面链接」这个来源退化为 0 条，枚举只剩静态字典 ——
    # 目标真实的路由（/order/list、/user/profile 之类）一条都进不了池子，
    # 后面的注入、越权、访问控制类检查全部无从下手。
    # 渲染正文在这里作为**补充来源**加入，并额外记一条来源说明，
    # 让报告能看出这部分链接是靠浏览器执行 JS 才拿到的。
    _render_html = str(getattr(ctx, "fp_result", {}).get("_render_html") or "")
    _link_pages = _entry_pages(ctx, root_body)
    if _render_html:
        _link_pages = _link_pages + [_render_html]
    for page in _link_pages:
        for m in _HREF_RE.finditer(page):
            rp = _relative(m.group(1), host)
            if rp:
                _add(pool, "页面链接", rp)
        for m in _SRC_RE.finditer(page):
            rp = _relative(m.group(1), host)
            if rp:
                _add(pool, "页面链接", rp)

    # ---- 5) 前端产物中的接口与路径 ----
    for u in (getattr(ctx, "js_result", {}) or {}).get("urls") or []:
        if not isinstance(u, str):
            continue
        rp = _relative(u, host)
        if rp:
            _add(pool, "前端产物", rp)
    for body in ((getattr(ctx, "js_result", {}) or {}).get("bodies") or [])[:40]:
        for m in _LOOSE_PATH.finditer(body or ""):
            rp = _norm(m.group(1))
            if rp and not _ASSET_SUFFIX.search(rp):
                _add(pool, "前端产物", rp)

    # ---- 5.5) 接口文档（OpenAPI / Swagger schema）----
    # 「文档能打开」与「按文档把接口摸出来」是两件事。原实现只做前者：
    # 报告写「接口文档对外可达」，而文档里的接口一条没进枚举池 ——
    # 目标自己把全部接口、参数名、必填项写在文档里递过来，我们还在拿字典猜。
    #
    # 这里复用 `_safe_get`（与 robots / sitemap 同一套），只多花几个请求；
    # 命中后立刻停（第一个解析成功的文档即为准），不会把全部候选都打一遍。
    spec = None
    if tier == "safe":
        # 安全档（生产核心系统首扫）不多发这几个请求 —— 本档的定义是
        # 「最低干扰」。但必须留痕：否则「本次没枚举到文档接口」会被
        # 读成「目标没有文档」，而事实是「这一档没去取」。
        pool.notes.append(
            "接口文档解析：安全档不执行（本档以最低干扰为先，不额外探测文档地址）"
            "—— 文档内的接口本次未纳入枚举，属覆盖度缺口")
    else:
        try:
            from engine import openapi as _oa  # noqa: PLC0415
            spec = _oa.discover(ctx)
            if spec is not None and spec.read_paths:
                for p in spec.read_paths:
                    _add(pool, "接口文档(schema)", _norm(p))
            if spec is not None:
                # 无论拿到几个地址，都把这三种状态之一写进覆盖度说明。
                # 「未发现文档」与「文档找到了但解不开」必须区分 —— 后者是
                # 覆盖度缺口，前者是目标确实没暴露文档，两者的补齐路径完全不同。
                pool.notes.append(spec.summary())
                pool.notes.extend(spec.notes)
        except Exception as e:  # noqa: BLE001
            # 接口文档是**加分项**不是必需项：它的失败不能影响其它来源。
            # 但必须留痕 —— 否则「本次没枚举到文档接口」会被读成「目标没有文档」。
            pool.notes.append(
                f"接口文档解析未完成（{type(e).__name__}: {str(e)[:80]}）—— "
                "本次未按接口文档枚举路径，属覆盖度缺口")

    # ---- 6) 静态字典（按档位裁剪）----
    _add_many(pool, "字典(元信息)", DICT_META)
    _add_many(pool, "字典(配置)", DICT_CONFIG)
    _add_many(pool, "字典(管理面)", DICT_ADMIN)
    _add_many(pool, "字典(接口)", DICT_API)
    if tier != "safe":
        _add_many(pool, "字典(备份目录)", DICT_BACKUP_DIRS)

    # ---- 7) 备份后缀推导（deep 档才做全量）----
    if tier != "safe":
        seeds = list(BACKUP_SEEDS)
        # 目标实际存在的可疑文件也纳入种子（例如已发现的 /config.php）
        for group in ("字典(配置)", "页面链接", "前端产物"):
            for p in pool.sources.get(group, []):
                if not _ASSET_SUFFIX.search(p) and "/" not in p.strip("/") and p not in seeds:
                    seeds.append(p.strip("/"))
        derived_cap = 200 if tier == "standard" else 900
        n = 0
        # 外层遍历后缀、内层遍历种子 —— 顺序很关键。
        # 反过来的话，排在最前的种子（index.php / config.php 各有 30+ 变体）
        # 会一口气吃掉整个预算，login.php / admin.php 一个变体都试不到：
        # 覆盖面变成由种子的书写顺序随机决定，而不是由价值决定。
        # 现在高价值后缀会先覆盖**所有**种子，再轮到 .2021 / .log 这类噪声变体。
        for sfx in BACKUP_SUFFIXES:
            if n >= derived_cap:
                break
            for seed in seeds:
                if n >= derived_cap:
                    break
                _add(pool, "备份后缀推导", seed + sfx, dedupe_only=True)
                n += 1
        for pre in BACKUP_PREFIXES:
            if n >= derived_cap:
                break
            for seed in seeds:
                if n >= derived_cap:
                    break
                tail = seed.rsplit("/", 1)[-1]
                _add(pool, "备份后缀推导", f"{pre}{tail}.swp", dedupe_only=True)
                n += 1

    # ---- 8) 安全过滤 + 排序 + 截断 ----
    final: list[str] = []
    seen: set[str] = set()
    ordered: list[tuple[int, str]] = []
    for src, items in pool.sources.items():
        w = SOURCE_WEIGHT.get(src, 99)
        for p in items:
            if p in seen:
                continue
            seen.add(p)
            ordered.append((w, p))
    ordered.sort(key=lambda x: x[0])

    for _, p in ordered:
        if _is_destructive(p):
            pool.skipped.append((p, "路径语义为破坏性操作（登出 / 删除 / 取消 / 支付等），"
                                    "GET 一次即可能产生真实副作用"))
            continue
        if _too_deep(p):
            pool.skipped.append((p, "路径层级过深，命中率极低且浪费请求预算"))
            continue
        final.append(p)
        if len(final) >= limit:
            break

    pool.paths = final
    return pool


# ==============================================================================
# 内部工具
# ==============================================================================
def _safe_get(ctx: Any, path: str) -> str:
    try:
        pr = ctx.probe_path(path)
        if pr is None or getattr(pr, "status", 0) != 200:
            return ""
        return getattr(pr, "body_snippet", "") or ""
    except Exception:  # noqa: BLE001
        return ""


def _entry_pages(ctx: Any, root_body: str) -> list[str]:
    """根页面 + 常见的入口页正文（只取 200 的）。"""
    pages = [root_body] if root_body else []
    for extra in ("login", "index", "home", "default"):
        body = _safe_get(ctx, extra)
        if body:
            pages.append(body)
    return pages


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _relative(raw: str, host: str) -> str:
    """把任意形态的地址归一成站内相对路径；站外地址返回空串。"""
    s = (raw or "").strip()
    if not s or s.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "?")):
        return ""
    if s.startswith("//"):
        return ""
    if s.lower().startswith(("http://", "https://")):
        h = _host_of(s)
        if not host or h != host:
            return ""          # 站外地址：一律不进枚举
        try:
            p = urlparse(s)
            return _norm(p.path + (("?" + p.query) if p.query else ""))
        except Exception:  # noqa: BLE001
            return ""
    return _norm(s)


def _norm(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    if not p.startswith("/"):
        p = "/" + p
    # 去掉 ./ 、多余的 /
    p = re.sub(r"/{2,}", "/", p)
    p = p.replace("/./", "/")
    if len(p) > 200:
        return ""
    return p


def _too_deep(p: str) -> bool:
    return p.strip("/").count("/") > 5


def _is_destructive(p: str) -> bool:
    path = p.split("?", 1)[0].rstrip("/")
    seg = path.rsplit("/", 1)[-1]
    if not seg:
        return False
    if READONLY_HINT.search(seg):
        return False
    return bool(DESTRUCTIVE_SEGMENT.match(seg))


def _add(pool: UrlPool, source: str, path: str, dedupe_only: bool = False) -> None:
    p = _norm(path)
    if not p or p == "/":
        return
    if p.startswith("/.") and p.count("/") > 2:
        return
    bucket = pool.sources.setdefault(source, [])
    if dedupe_only:
        for other in pool.sources.values():
            if p in other:
                return
    if p not in bucket:
        bucket.append(p)


def _add_many(pool: UrlPool, source: str, items: list[str]) -> None:
    for it in items:
        _add(pool, source, it)


if __name__ == "__main__":  # pragma: no cover
    print("URL 枚举池自测（不联网，用桩上下文）")

    class _Probe:
        def __init__(self, status, body):
            self.status, self.body_snippet = status, body

    class _Ctx:
        target_url = "https://demo.example.com"
        domain = "example.com"
        profile_key = "standard"
        js_result = {"urls": ["/api/user?uid=1", "https://evil.example.net/x", "/static/app.js"],
                     "bodies": ['var u="/api/order/list";']}
        _pages = {
            "robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /internal/\n",
            "sitemap.xml": "<urlset><url><loc>https://demo.example.com/help</loc></url></urlset>",
            "login": '<form action="/session"><a href="/forgot-password">x</a></form>',
        }

        def get(self, url):
            if url.rstrip("/").endswith("demo.example.com"):
                return _Probe(200, '<a href="/about">a</a><a href="/logout">出</a>'
                                   '<form action="/api/order/cancel"></form>')
            return _Probe(404, "")

        def probe_path(self, p):
            body = self._pages.get(p.lstrip("/"))
            return _Probe(200, body) if body else _Probe(404, "")

    pool = build_url_pool(_Ctx(), "standard")
    print(pool.summary())
    for src, n, note in pool.coverage_rows():
        print(f"  {src:<14} {n:>4}  {note}")
    print("\n刻意剔除的地址：")
    for p, why in pool.skipped[:8]:
        print(f"  {p}  <-  {why}")
    assert "/logout" in {p for p, _ in pool.skipped}, "登出路径必须被剔除"
    assert "/api/order/cancel" in {p for p, _ in pool.skipped}, "取消订单路径必须被剔除"
    assert not any(p.startswith("/evil") for p in pool.paths), "站外地址必须被丢弃"
    assert "/help" in pool.paths and "/about" in pool.paths

    # 备份推导必须按「后缀价值」展开，而不是按「种子书写顺序」。
    # 判据：从高价值后缀开始，能**连续**铺满全部种子的后缀个数。
    #   后缀在外层 → 至少前两个后缀覆盖所有种子（受 derived_cap 限制）；
    #   种子在外层 → 排在最前的几个种子吃掉预算，连续个数会掉到 0。
    derived = set(pool.sources.get("备份后缀推导", []))
    # 注意：池里的路径统一带前导斜杠（_norm 的结果），比较时不能漏。
    missing_bak = [s for s in BACKUP_SEEDS if f"/{s}.bak" not in derived]
    covered_suffixes = 0
    for sfx in BACKUP_SUFFIXES:
        if all(f"/{s}{sfx}" in derived for s in BACKUP_SEEDS):
            covered_suffixes += 1
        else:
            break
    assert covered_suffixes >= 2, (
        f"备份推导未按后缀价值铺开（连续铺满全部种子的后缀仅 {covered_suffixes} 个，"
        f"推导总数 {len(derived)}）——"
        f"缺少 .bak 变体的种子 {len(missing_bak)} 个：{missing_bak[:8]}；"
        f"检查 BACKUP_SUFFIXES / BACKUP_SEEDS 的循环顺序是否被改回种子在外层")
    print(f"  备份推导顺序校验：前 {covered_suffixes} 个高价值后缀 "
          f"（{'、'.join(BACKUP_SUFFIXES[:covered_suffixes])}）已覆盖全部 "
          f"{len(BACKUP_SEEDS)} 个种子")
    print("\n断言通过")
