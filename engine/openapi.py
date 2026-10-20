# -*- coding: utf-8 -*-
"""接口文档（OpenAPI / Swagger）驱动 —— 把「文档能打开」变成「按文档把接口摸出来」
================================================================================

要解决的问题
--------------------------------------------------------------------------------
原实现只做了一半：探到 `/v3/api-docs` 返回 200 就报一条
「接口文档对外可达」，然后**文档里的接口与参数一条都没进枚举池**。
结果是报告上有一份「接口清单暴露」的中危发现，而实际的接口枚举还在
拿静态字典猜路径 —— 目标自己把全部接口、参数名、必填项写在文档里递过来，
我们却没用。

这个缺口很具体：接口类漏洞（越权、批量赋值、注入、参数遍历）的**起点是接口清单**。
文档里的 `paths` 是目标自己声明的、100% 准确的接口集合，比任何字典与正则
提取都干净。拿不到它，覆盖率就永远差一截，而且这一截是「本来白送的」。

本模块做三件事
--------------------------------------------------------------------------------
1. **解析**：把 JSON / YAML 两种形态的 OpenAPI 3.x 与 Swagger 2.0 文档解成
   统一的「接口 + 参数」结构（`SpecResult`）。
2. **落地为可用地址**：把 `/api/user/{id}` 这种模板路径具体化成可 GET 的地址，
   交给 URL 枚举池作为一个**高权重来源**。
3. **如实交代**：三种状态分开写，**绝不合并**：
   · `found=False`     —— 没探到接口文档（不等于「没有接口」）
   · `found, !parsed`  —— 探到了但解不开（是 YAML 里写了自定义标签？还是返回的
                          其实是一张 HTML 登录页？）—— 必须把原因说出来
   · `found, parsed`   —— 拿到 N 个接口 / M 个参数（这个数字要进报告）

红线
--------------------------------------------------------------------------------
**「解不开」不得写成「没有接口」。** 这是本项目反复出问题的那一类：
把一次工具失效当成关于目标的结论。所以 `SpecResult` 里没有「空结果」这种
默认值 —— 解析成功就必须带出**非空**的接口清单，解析失败就必须带出原因。

零新依赖：YAML 用已在用的 PyYAML，JSON 用标准库。两者都不可用时走
「探到了但解不开（本环境无解析器）」—— 如实说，不静默跳过。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ==============================================================================
# 常量
# ==============================================================================

#: 候选文档地址。**刻意只放常见的**：
#: 每多一个候选就多一次请求，而文档地址的命中集中在少数几个约定俗成名上。
#: 全量爆破文档路径是另一回事（那属于内容发现，不是本模块的职责）。
#:
#: ⚠ 前两个是 **JS 包装形态**，不是 JSON —— 见 `_extract_embedded_spec()`。
#: 它们是 2026-10-12 第 19 轮实测补进来的：Juice Shop 20.2 的 `/api-docs`
#: 只返回 Swagger UI 的骨架 HTML，真正的规范**内嵌在它加载的
#: `swagger-ui-init.js` 里**（`var spec1 = options.swaggerDoc`）。
#: 原先候选表里一个 JS 包装地址都没有，于是整轮扫描拿到「接口文档可达」
#: 的中危发现，而文档里的接口与参数一条都没进枚举池 ——
#: 目标把全部接口、参数名、必填项写在文档里递过来，我们却只记了一句「文档能开」。
SPEC_CANDIDATES: tuple[str, ...] = (
    "api-docs/swagger-ui-init.js",          # Juice Shop / swagger-ui-express 常见
    "swagger-ui-init.js",
    "openapi.json", "swagger.json", "v3/api-docs", "v2/api-docs",
    "api-docs", "swagger/v1/swagger.json", "api/openapi.json",
    "openapi.yaml", "swagger.yaml", "api-docs/swagger.json",
)

#: 单轮最多探几个候选。上限存在的意义：文档地址通常是 404，
#: 每探一个都是对一个 404 的等待。探满即停，并在结论里说明「尚未探完」。
MAX_SPEC_PROBES = 5

#: 接口数量上限与单接口参数上限。防「文档里列了 3000 个接口」把枚举池冲掉：
#: 枚举池本身有档位限额，这里先截一道，避免把预算全喂给文档接口。
MAX_ENDPOINTS = 150
MAX_PARAMS_PER_ENDPOINT = 20

#: 探到的响应体长度下限。低于它多半是空 200 或占位页，解析必然失败 ——
#: 与其产生一条「解析失败」的噪声，不如按「不像文档」处理（不置 found）。
MIN_SPEC_BODY = 40

#: 明显「不是文档」的响应特征：登录页 / 首页骨架 / 错误页。
#: 自定义 404 返回 200 是常见部署，识别不出来就会报「文档可访问」的假阳性。
_NOT_SPEC_MARKERS = (
    "<!doctype html", "<html", "<head", "<body",
    "login", "not found", "404", "access denied",
)

#: 路径模板变量的具体化取值。原则是**保持只读语义**且不触发真实副作用：
#: 用 1 / example 这类中性值，不用 0 或 -1（有些实现在 0 上会走异常分支，
#: 那会把一次正常的枚举变成一条噪声发现）。
_TEMPLATE_VALUES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)^(id|.*_id|.*id)$"), "1"),
    (re.compile(r"(?i)^(uid|user_id|userid)$"), "1"),
    (re.compile(r"(?i)^(uuid|guid)$"), "00000000-0000-0000-0000-000000000001"),
    (re.compile(r"(?i)^(page|offset|start|limit|size|count)$"), "1"),
    (re.compile(r"(?i)^(name|keyword|q|query|search)$"), "test"),
    (re.compile(r"(?i)^(date|time|from|to)$"), "2026-01-01"),
)

_TPL_VAR = re.compile(r"\{([^}/]+)\}")

#: HTTP 方法 → 是否值得作为「只读枚举」发出。WSTG 的红线是只读，
#: 所以写方法不进枚举池（它们照样会在文档清单里体现，只是不作为探测地址）。
READ_METHODS = ("get", "head", "options")


# ==============================================================================
# 数据结构
# ==============================================================================

@dataclass
class SpecEndpoint:
    """文档里的一个接口。"""

    raw_path: str
    method: str
    url_path: str                     # 模板变量已具体化，可直接 GET
    #: **已拼上 base path** 的完整路径。注入必须打在它上面 ——
    #: 只用 `url_path` 会把 `/b2b/v2/orders` 打成了 `/orders`（404），
    #: 服务端根本没处理载荷，结论却记成「未发现」。
    full_path: str = ""
    params: list[str] = field(default_factory=list)   # 查询 / 路径参数名
    #: 请求体（requestBody / in:body）里的顶层字段名。**与 params 分开存**：
    #: 两者走完全不同的注入通道 —— 前者进查询串，后者只能进 JSON body。
    #: 混在一张表里，注入器就无法判断「这个参数该怎么送出去」，
    #: 于是所有 body 类注入点（SSRF 的 imageUrl、存储型 XSS 的 comment…）
    #: 会被当成查询参数送出去，拿到 400/500，然后记一条「通过」。
    body_params: list[str] = field(default_factory=list)
    #: 请求体里声明为必填的字段名。构造探测 body 时必须先填满它们，
    #: 否则服务端在校验阶段就返回 400/500，注入载荷根本没有被处理 ——
    #: 那不是「没有漏洞」，是「请求不合法」。
    body_required: list[str] = field(default_factory=list)
    #: 请求体的样例（来自 schema 的 example / 默认值），用来构造合法 body。
    body_example: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    #: 写方法（POST/PUT/DELETE...）不会被枚举（红线：只读），但要在清单里留名，
    #: 否则「文档里有 40 个接口、我们只枚举了 12 个」这件事就说不清楚。
    readonly: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.raw_path, "method": self.method,
                "url_path": self.url_path, "full_path": self.full_path,
                "params": list(self.params),
                "body_params": list(self.body_params),
                "body_required": list(self.body_required),
                "summary": self.summary, "tags": list(self.tags),
                "readonly": self.readonly}


@dataclass
class SpecResult:
    """一次接口文档解析的结果。三种状态互斥，不留「空结果」这个第四种。"""

    found: bool = False               # 是否探到了像文档的响应
    parsed: bool = False              # 是否成功解析出结构
    url: str = ""                     # 命中的文档地址
    spec_version: str = ""            # openapi 3.x / swagger 2.0
    base_path: str = ""               # servers[0].url 或 basePath 的路径部分
    endpoints: list[SpecEndpoint] = field(default_factory=list)
    reason: str = ""                  # 未发现 / 未解析的原因（必须非空才有解释力）
    probes: int = 0
    truncated: bool = False           # 接口数是否被 MAX_ENDPOINTS 截断
    notes: list[str] = field(default_factory=list)

    # ---- 派生量 ----------------------------------------------------------
    @property
    def read_paths(self) -> list[str]:
        """可作为只读探测地址的路径（去重、保持文档顺序）。"""
        out: list[str] = []
        seen: set[str] = set()
        for e in self.endpoints:
            if not e.readonly:
                continue
            p = (self.base_path.rstrip("/") + "/" + e.url_path.lstrip("/")).strip()
            p = "/" + p.strip("/")
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    @property
    def param_names(self) -> list[str]:
        """文档声明的全部参数名（去重）。是「参数测试该测哪些」的第一手依据。"""
        out: list[str] = []
        seen: set[str] = set()
        for e in self.endpoints:
            for p in e.params:
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    @property
    def body_param_names(self) -> list[str]:
        """文档声明的请求体字段名（去重）。注入面里最容易漏掉的一块。"""
        out: list[str] = []
        seen: set[str] = set()
        for e in self.endpoints:
            for p in e.body_params:
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    @property
    def write_endpoints(self) -> list[SpecEndpoint]:
        """带请求体的写方法接口 —— 注入 / 越权检查的第二批目标（需单独授权）。"""
        return [e for e in self.endpoints if not e.readonly and e.body_params]

    @property
    def write_count(self) -> int:
        return sum(1 for e in self.endpoints if not e.readonly)

    def summary(self) -> str:
        if not self.found:
            return f"接口文档：未发现（探了 {self.probes} 个候选地址）"
        if not self.parsed:
            return (f"接口文档：{self.url} 可达但未解析 —— {self.reason}"
                    "（属覆盖度缺口，不是关于目标的结论）")
        w = f"，其中写方法 {self.write_count} 个（不枚举，只登记）" if self.write_count else ""
        b = (f"，请求体字段 {len(self.body_param_names)} 个（可注入面）"
             if self.body_param_names else "")
        tr = "，已达枚举上限被截断" if self.truncated else ""
        return (f"接口文档：{self.url}（{self.spec_version}）解析出 "
                f"{len(self.endpoints)} 个接口{w}、{len(self.param_names)} 个参数名{b}{tr}；"
                f"可只读枚举 {len(self.read_paths)} 个")

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found, "parsed": self.parsed, "url": self.url,
            "spec_version": self.spec_version, "base_path": self.base_path,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "endpoint_count": len(self.endpoints),
            "param_names": self.param_names,
            "body_param_names": self.body_param_names,
            "read_paths": self.read_paths,
            "write_count": self.write_count,
            "write_endpoint_count": len(self.write_endpoints),
            "reason": self.reason, "probes": self.probes,
            "truncated": self.truncated, "notes": list(self.notes),
        }


# ==============================================================================
# 解析
# ==============================================================================

def concretize(path: str) -> str:
    """把 `/api/user/{id}/orders/{orderId}` 变成可 GET 的具体路径。

    取值一律中性（1 / test / 2026-01-01）：枚举是只读动作，不该因为
    「填了 0 触发除零」而多出一条与被测系统无关的噪声。
    """
    def _sub(m: re.Match[str]) -> str:
        var = m.group(1).strip()
        bare = var.lstrip("*")
        for pat, val in _TEMPLATE_VALUES:
            if pat.match(bare):
                return val
        return "1"
    return _TPL_VAR.sub(_sub, path)


def _scan_balanced(text: str, start: int) -> str | None:
    """从左花括号起扫出一段括号平衡、且正确跳过字符串与转义的 JSON 片段。

    **为什么不能直接用正则或 `text.find('}')`**：规范正文里到处是
    `"description": "uses {id} or } in text"` 这类内容 —— 遇到字符串里的
    花括号就收尾，取出来的一定是半截 JSON，`json.loads` 必然失败，
    而失败会被解读成「文档解不开」，于是把一份白送的接口清单当成没有。
    """
    if start < 0 or start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def extract_embedded_spec(text: str) -> dict[str, Any] | None:
    """从 JS 包装里剥出内嵌的接口规范。

    覆盖三种真实形态（都是「文档页是 HTML、规范在 JS 里」这一类部署）：

      1. swagger-ui-express 的 `swagger-ui-init.js`：`var options = {"swaggerDoc": {...}}`
      2. 直接 `var spec = {...}` / `window.spec = {...}`
      3. 整段就是一个大 JSON 对象（不带任何包装键）

    判据只有一条：**解出来的对象必须真的有 `paths`** ——
    否则宁可返回 None，让调用方按「不是文档」处理，也不拿一个碰巧
    解成功的普通 JS 配置对象当接口清单。
    """
    t = text or ""
    if not t:
        return None
    cands: list[str] = []
    # 1) 具名包装键优先（命中率最高、语义最明确）
    for key in ('"swaggerDoc"', "'swaggerDoc'", "swaggerDoc"):
        idx = t.find(key)
        while idx >= 0:
            brace = t.find("{", idx + len(key))
            seg = _scan_balanced(t, brace) if brace >= 0 else None
            if seg:
                cands.append(seg)
            idx = t.find(key, idx + 1)
    # 2) 变量名形如 spec / swaggerDoc / apiSpec
    for m in re.finditer(r"(?i)\b(?:var|let|const|window\.\w+)\s*=?\s*(\{)", t):
        seg = _scan_balanced(t, m.start(1))
        if seg:
            cands.append(seg)
    # 3) 第一个顶层花括号
    first = t.find("{")
    seg = _scan_balanced(t, first) if first >= 0 else None
    if seg:
        cands.append(seg)

    for seg in cands:
        try:
            data = json.loads(seg)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, dict) and _looks_like_spec(data):
            return data
    return None


def loads_spec(text: str) -> dict[str, Any] | None:
    """把文档文本解成 dict。JSON 优先，JS 包装次之，最后试 YAML。

    顺序有意为之：绝大多数接口文档由框架自动生成（springdoc / swagger-ui），
    默认输出 JSON；先试 JSON 命中率更高，也避免 YAML 把某些合法 JSON 解成
    「一个标量字符串」这种意外结果。
    """
    t = (text or "").strip()
    if not t:
        return None
    if t[0] in "{[":
        try:
            data = json.loads(t)
            return data if isinstance(data, dict) else None
        except Exception:  # noqa: BLE001
            pass
    # 整段不是 JSON —— 但可能是一段把规范包在里面的 JS。
    # 这一环是 2026-10-12 补的：直接按「解析失败」处理会把
    # 「规范就在响应体里、只是外面套了层 JS」误判成「没有接口文档」。
    embedded = extract_embedded_spec(t)
    if embedded is not None:
        return embedded
    try:
        import yaml
        data = yaml.safe_load(t)
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _looks_like_spec(data: dict[str, Any]) -> bool:
    """是不是一份 OpenAPI / Swagger 文档。

    判据取「有 paths 且 paths 是 dict」为主，加上 openapi/swagger 版本声明为佐证。
    只看版本声明会漏掉大量裁剪过版本字段的框架输出；只看 paths 会把
    任意一个恰好有 paths 键的 JSON（如某些前端配置）当文档。
    """
    if not isinstance(data, dict):
        return False
    paths = data.get("paths")
    if isinstance(paths, dict) and paths:
        return True
    if str(data.get("openapi") or "").startswith("3") and isinstance(paths, dict):
        return True
    return False


def _extract_params(op: dict[str, Any], path_item: dict[str, Any]) -> list[str]:
    """收集一个操作的**查询 / 路径**参数名（不含请求体字段）。

    请求体字段由 `_extract_body` 单独收集 —— 见 `SpecEndpoint.body_params`
    处对「为什么要分开」的说明。
    """
    out: list[str] = []

    def _take(container: Any) -> None:
        if not isinstance(container, list):
            return
        for prm in container:
            if not isinstance(prm, dict):
                continue
            name = str(prm.get("name") or "").strip()
            place = str(prm.get("in") or "").strip().lower()
            # 只收 query / path：header 与 cookie 参数不该塞进 URL 枚举。
            if name and place in ("query", "path") and name not in out:
                out.append(name)

    _take(path_item.get("parameters"))
    _take(op.get("parameters"))
    return out[:MAX_PARAMS_PER_ENDPOINT]


#: `$ref` 解引用的最大深度。环引用（A→B→A）在真实文档里并不罕见，
#: 没有上限会把一次文档解析变成死循环。
_MAX_REF_DEPTH = 6


def _resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any] | None:
    """解一个 OpenAPI 内部引用（形如 `#/components/schemas/Order`）。

    只解**文档内**引用（`#/` 开头）—— 外部 URL 引用意味着要联网去取，
    而底座默认零外联（红线 65），取不到时必须如实说「没解」，不能假装解开了。
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node if isinstance(node, dict) else None


def _schema_fields(schema: Any, root: dict[str, Any] | None = None,
                   _depth: int = 0) -> tuple[list[str], list[str], dict[str, Any]]:
    """从一个 schema 里取出（顶层字段名, 必填字段名, 样例值）。

    只取**顶层**：嵌套对象要展开成注入点会组合爆炸，而绝大多数真实注入点
    （SSRF 的 url、XSS 的 comment、越权的 role）都在顶层。

    ⚠ 必须解 `$ref`：框架自动生成的文档几乎总是把 requestBody 写成
    `{"$ref": "#/components/schemas/Order"}`。不解引用，解析出来的
    「请求体字段」是空的 —— 看上去文档解开了，实际上注入面一个点都没拿到，
    而且不会有任何报错。
    """
    if not isinstance(schema, dict):
        return [], [], {}
    if "$ref" in schema and root is not None and _depth < _MAX_REF_DEPTH:
        target = _resolve_ref(str(schema.get("$ref") or ""), root)
        if target is not None:
            return _schema_fields(target, root, _depth + 1)
    # OAS3 的 allOf：把每个分支的字段并起来（框架常用它拼「基类 + 扩展」）
    branches = schema.get("allOf")
    if isinstance(branches, list) and branches:
        names: list[str] = []
        required: list[str] = []
        example: dict[str, Any] = {}
        for br in branches:
            n2, r2, e2 = _schema_fields(br, root, _depth + 1)
            names += [x for x in n2 if x not in names]
            required += [x for x in r2 if x not in required]
            example.update(e2)
        if names:
            return names[:MAX_PARAMS_PER_ENDPOINT], required, example
    props = schema.get("properties")
    if not isinstance(props, dict):
        return [], [], {}
    names = [str(k) for k in props if isinstance(k, str)]
    req = schema.get("required")
    required = [str(x) for x in req if isinstance(x, (str, int))] if isinstance(req, list) else []
    example = {}
    for n in names:
        p = props.get(n)
        if not isinstance(p, dict):
            continue
        if "example" in p:
            example[n] = p.get("example")
        elif "default" in p:
            example[n] = p.get("default")
        elif "enum" in p and isinstance(p.get("enum"), list) and p["enum"]:
            example[n] = p["enum"][0]
    return names[:MAX_PARAMS_PER_ENDPOINT], required, example


def _extract_body(op: dict[str, Any],
                  root: dict[str, Any] | None = None
                  ) -> tuple[list[str], list[str], dict[str, Any]]:
    """收集一个操作的请求体字段。同时覆盖 OAS3 与 Swagger 2.0 两种写法。

      · OAS3      —— `requestBody.content.<media-type>.schema`
      · Swagger2  —— `parameters[]` 里 `in: body` 那一项的 `schema`

    `root` 是整个文档，用于解 `$ref`。
    """
    # ① OAS3
    body = op.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            for mt, mtobj in content.items():
                if not isinstance(mtobj, dict):
                    continue
                # JSON 优先：我们要构造的是 JSON body
                if "json" not in str(mt).lower() and "json" not in " ".join(content):
                    continue
                names, req, ex = _schema_fields(mtobj.get("schema"), root)
                if names:
                    return names, req, ex
            # 没有 json 形态时退回任意形态的 schema
            for mtobj in content.values():
                if not isinstance(mtobj, dict):
                    continue
                names, req, ex = _schema_fields(mtobj.get("schema"), root)
                if names:
                    return names, req, ex
    # ② Swagger 2.0：in=body 的参数
    for prm in (op.get("parameters") or []):
        if not isinstance(prm, dict):
            continue
        if str(prm.get("in") or "").strip().lower() != "body":
            continue
        names, req, ex = _schema_fields(prm.get("schema"), root)
        if names:
            return names, req, ex
    return [], [], {}


def parse_spec(text: str, *, url: str = "") -> SpecResult:
    """解析接口文档文本。永远返回一个 `SpecResult`，不抛异常。

    调用方据 `found` / `parsed` / `reason` 三个字段决定怎么在报告里写 ——
    本函数**不替调用方决定**「解不开算不算没有接口」。
    """
    res = SpecResult(url=url)
    data = loads_spec(text)
    if data is None:
        res.found = True      # 拿到了响应体，只是解不开
        res.reason = "响应不是可解析的 JSON / YAML"
        return res
    if not _looks_like_spec(data):
        # 能解析、但不是接口文档（典型的：自定义 404 返回的 JSON 错误体）
        res.found = False
        res.reason = "响应可解析，但不含 paths，不是接口文档"
        return res

    res.found = True
    res.parsed = True
    res.spec_version = ("openapi " + str(data.get("openapi"))) if data.get("openapi") \
        else ("swagger " + str(data.get("swagger")) if data.get("swagger") else "未声明版本")

    # base path：OAS3 取 servers[0].url 的路径部分；Swagger2 取 basePath。
    base = ""
    servers = data.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        su = str(servers[0].get("url") or "")
        if su:
            base = "/" + su.split("://", 1)[-1].split("/", 1)[-1].strip("/") if "/" in su.split("://", 1)[-1] else ""
            if base == "/":
                base = ""
    if not base:
        bp = str(data.get("basePath") or "").strip()
        if bp and bp != "/":
            base = "/" + bp.strip("/")
    res.base_path = base

    paths = data.get("paths") or {}
    n = 0
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        for method in ("get", "head", "options", "post", "put", "patch", "delete", "trace"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            if n >= MAX_ENDPOINTS:
                res.truncated = True
                break
            _b_names, _b_req, _b_ex = _extract_body(op, data)
            res.endpoints.append(SpecEndpoint(
                raw_path=raw_path,
                method=method.upper(),
                url_path=concretize(raw_path),
                full_path="/" + (base.strip("/") + "/" + concretize(raw_path).strip("/")).strip("/"),
                params=_extract_params(op, item),
                body_params=_b_names,
                body_required=_b_req,
                body_example=_b_ex,
                summary=str(op.get("summary") or "")[:120],
                tags=[str(t) for t in (op.get("tags") or []) if isinstance(t, (str, int))][:5],
                readonly=method in READ_METHODS,
            ))
            n += 1
        if res.truncated:
            break

    if not res.endpoints:
        # 有 paths 但一个操作都没解出来 —— 这是「解析器失效」，不是「没有接口」。
        res.parsed = False
        res.reason = "文档含 paths 但未解析出任何操作（结构非常规，需人工查看）"
        return res

    if res.truncated:
        res.notes.append(
            f"接口数超过上限 {MAX_ENDPOINTS}，已截断 —— 报告中的接口数为下限而非全量")
    if res.write_count:
        res.notes.append(
            f"文档含 {res.write_count} 个写方法接口，按只读红线不纳入枚举，"
            "仅登记在清单中（它们仍是越权与批量赋值检查的候选，需单独授权）")
    return res


# ==============================================================================
# 从探测上下文发现并解析
# ==============================================================================

def discover(ctx: Any, *, candidates: tuple[str, ...] = SPEC_CANDIDATES,
             max_probes: int = MAX_SPEC_PROBES) -> SpecResult:
    """在目标上找接口文档并解析。

    解析结果会缓存进 `ctx._cache["openapi_spec"]` —— 同一轮扫描里
    URL 枚举池与 API 检查都要用它，各找一遍就会重复发请求。
    """
    cached = None
    try:
        cached = ctx._cache.get("openapi_spec")
    except Exception:  # noqa: BLE001
        cached = None
    if isinstance(cached, SpecResult):
        return cached
    if isinstance(cached, dict) and cached.get("_done"):
        return _from_dict(cached)

    res = SpecResult()
    tried: list[str] = []
    for cand in list(candidates)[:max_probes]:
        tried.append(cand)
        res.probes += 1
        body = ""
        try:
            pr = ctx.probe_path(cand)
            if pr is None:
                continue
            status = int(getattr(pr, "status", 0) or 0)
            if status != 200:
                continue
            body = getattr(pr, "body_snippet", "") or ""
            if len(body) < MIN_SPEC_BODY:
                continue
            low = body[:2000].lower()
            # 自定义 404 返回 200 的站点：正文是首页 / 登录页 / 错误页。
            # 不排掉就会报一条「接口文档可达」的假阳性，且后续解析必然失败。
            if low.lstrip().startswith(("<",)) or any(
                    m in low for m in _NOT_SPEC_MARKERS) and "{" not in body[:200]:
                continue
            final = getattr(pr, "final_url", "") or ""
            res = parse_spec(body, url=final or _abs(ctx, cand))
            if res.found or res.parsed:
                break
        except Exception as e:  # noqa: BLE001
            res.notes.append(f"探测 {cand} 异常：{type(e).__name__}: {str(e)[:100]}")

    if not res.found and not res.reason:
        res.reason = f"未探到接口文档（已试 {res.probes} 个候选地址）"
    if not res.found and res.probes >= max_probes and len(candidates) > max_probes:
        res.notes.append(
            f"候选地址只探了前 {max_probes} 个（共 {len(candidates)} 个）—— "
            "未探到的部分本次没有结论")
    try:
        ctx._cache["openapi_spec"] = res
        ctx._cache["openapi_spec_probed"] = tried
    except Exception:  # noqa: BLE001
        pass
    return res


def _abs(ctx: Any, path: str) -> str:
    try:
        return urljoin(getattr(ctx, "target_url", "") + "/", path.lstrip("/"))
    except Exception:  # noqa: BLE001
        return path


def _from_dict(d: dict[str, Any]) -> SpecResult:
    """从落盘的 dict 还原（跨进程/跨阶段读取用）。"""
    r = SpecResult(found=bool(d.get("found")), parsed=bool(d.get("parsed")),
                   url=str(d.get("url") or ""), reason=str(d.get("reason") or ""))
    return r


def cached_result(ctx: Any) -> SpecResult | None:
    """读已缓存的结果（不触发任何探测）。"""
    try:
        v = ctx._cache.get("openapi_spec")
    except Exception:  # noqa: BLE001
        return None
    return v if isinstance(v, SpecResult) else None


# ==============================================================================
# 自测
# ==============================================================================

_SPEC3 = json.dumps({
    "openapi": "3.0.1",
    "info": {"title": "Demo", "version": "1.0"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "paths": {
        "/user/{userId}": {
            "get": {"summary": "读用户", "tags": ["user"],
                    "parameters": [{"name": "userId", "in": "path"},
                                   {"name": "withDetail", "in": "query"}],
                    "responses": {"200": {"description": "ok"}}},
                },
        "/user/{userId}/orders": {
            "get": {"parameters": [{"name": "userId", "in": "path"},
                                   {"name": "page", "in": "query"}]},
            "post": {"summary": "下单",
                     "requestBody": {"content": {"application/json": {
                         "schema": {"properties": {"sku": {}, "qty": {}}}}}}},
        },
        "/internal/token": {
            "get": {"parameters": [{"name": "Authorization", "in": "header"}]},
        },
    },
}, ensure_ascii=False)

_YAML2 = """
swagger: "2.0"
basePath: /api
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
      responses:
        "200":
          description: ok
    delete:
      responses:
        "204":
          description: gone
"""


def _selftest() -> int:
    problems: list[str] = []

    # ① OAS3 JSON：接口数 / 方法 / 参数 / base path 全都要对
    r = parse_spec(_SPEC3, url="https://t.example/v3/api-docs")
    if not (r.found and r.parsed):
        problems.append(f"OAS3 文档应解析成功，实际 found={r.found} parsed={r.parsed} "
                        f"reason={r.reason}")
    else:
        if r.spec_version != "openapi 3.0.1":
            problems.append(f"版本识别错误：{r.spec_version}")
        if r.base_path != "/v2":
            problems.append(f"base path 应取 servers[0].url 的路径部分 /v2，实际 {r.base_path}")
        if len(r.endpoints) != 4:
            problems.append(f"应解析出 4 个接口（3 个 GET + 1 个 POST），实际 {len(r.endpoints)}")
        if r.write_count != 1:
            problems.append(f"写方法应记 1 个（POST），实际 {r.write_count}")
        if "userId" not in r.param_names or "withDetail" not in r.param_names:
            problems.append(f"参数名收集不全：{r.param_names}")
        if "Authorization" in r.param_names:
            problems.append("header 参数不该当查询参数收进来（会污染 URL 枚举）")
        # 请求体字段**必须与查询参数分开** —— 两者走不同的注入通道，
        # 混在一张表里注入器就无法判断载荷该怎么送（详见 SpecEndpoint 注释）。
        if "sku" in r.param_names:
            problems.append("请求体字段不该混进查询参数表（注入通道会被选错）")
        if "sku" not in r.body_param_names:
            problems.append("OAS3 requestBody 顶层字段名应登记到 body_param_names")
        _posts = [e for e in r.endpoints if e.method == "POST"]
        if not _posts or list(_posts[0].body_params) != ["sku", "qty"]:
            problems.append(f"POST 接口应带请求体字段 ['sku','qty']，实际 "
                            f"{[list(e.body_params) for e in _posts]}")

    # ② 模板变量必须具体化，否则枚举出来的地址是 404 噪声
    rp = r.read_paths
    if any("{" in p for p in rp):
        problems.append(f"路径模板未被具体化：{[p for p in rp if '{' in p]}")
    if "/v2/user/1" not in rp:
        problems.append(f"应包含 /v2/user/1（base path + 具体化后的路径），实际 {rp}")
    if "/v2/user/1/orders" not in rp:
        problems.append(f"应包含 /v2/user/1/orders，实际 {rp}")

    # ③ 写方法不得进枚举（红线：只读）
    if len(rp) != 3:
        problems.append(f"只读枚举应为 3 个（3 个 GET），实际 {len(rp)}：{rp}")

    # ④ Swagger 2.0 YAML：basePath 与写方法登记
    r2 = parse_spec(_YAML2, url="https://t.example/v2/api-docs")
    if not r2.parsed:
        problems.append(f"Swagger 2.0 YAML 应解析成功，实际 reason={r2.reason}")
    else:
        if r2.base_path != "/api":
            problems.append(f"Swagger2 应取 basePath，实际 {r2.base_path}")
        if r2.read_paths != ["/api/pets"]:
            problems.append(f"只读枚举应为 ['/api/pets']，实际 {r2.read_paths}")
        if r2.write_count != 1:
            problems.append(f"写方法应记 1 个（DELETE），实际 {r2.write_count}")

    # ⑤ 三种状态互斥，且**解不开必须带原因**
    #    这一条守的是本项目最容易犯的错：把「解不开」写成「没有接口」。
    bad = parse_spec("<html><body>login</body></html>", url="https://t.example/x")
    if bad.parsed:
        problems.append("HTML 登录页不该被判为解析成功")
    if not bad.reason:
        problems.append("解析失败必须给出原因（否则读者分不清「没接口」与「没解开」）")
    if bad.endpoints:
        problems.append("解析失败时不得带出接口清单（半成品会被下游当全量用）")
    notdoc = parse_spec('{"error":"not found","code":404}')
    if notdoc.found:
        problems.append("可解析但含 paths 的 JSON 错误体不该被判为「找到文档」")
    if not notdoc.reason:
        problems.append("「找到但不是文档」也要给原因")

    # ⑥ 含 paths 但结构异常 → 必须记「解析器失效」而不是「没有接口」
    weird = parse_spec('{"openapi":"3.0.0","paths":{"/a":"not-an-object"}}')
    if weird.parsed:
        problems.append("paths 值不是对象时不该判解析成功")
    if weird.parsed is False and not weird.reason:
        problems.append("解析器失效必须留原因")

    # ⑦ 上限必须真的生效且留痕（否则 3000 个接口会冲掉整个枚举预算）
    big = {"openapi": "3.0.0", "paths": {
        f"/p{i}": {"get": {"responses": {}}} for i in range(MAX_ENDPOINTS + 30)}}
    rb = parse_spec(json.dumps(big))
    if len(rb.endpoints) != MAX_ENDPOINTS:
        problems.append(f"接口数应被截到 {MAX_ENDPOINTS}，实际 {len(rb.endpoints)}")
    if not rb.truncated or not any("截断" in n for n in rb.notes):
        problems.append("截断必须留痕（报告里的接口数是下限，不说明就会被当全量）")

    # ⑧ 摘要必须能把三种状态说清，且「未发现」不得读成「没有问题」
    if "未发现" not in SpecResult(found=False, probes=5).summary():
        problems.append("未发现时的摘要缺失")
    unparsed = SpecResult(found=True, parsed=False, url="https://t.example/x",
                          reason="响应不是可解析的 JSON / YAML").summary()
    if "覆盖度缺口" not in unparsed:
        problems.append("未解析时必须明写「属覆盖度缺口，不是关于目标的结论」")
    d = r.to_dict()
    for k in ("found", "parsed", "endpoints", "read_paths", "reason", "probes"):
        if k not in d:
            problems.append(f"落盘字段缺失：{k}")

    # ⑨ discover 在假上下文上要能优雅工作，且缓存生效（同一轮不重复探测）
    class _Ctx:
        def __init__(self, spec):
            self.target_url = "https://t.example"
            self._cache = {}
            self._spec = spec
            self.calls = 0
        def probe_path(self, p):
            self.calls += 1
            if p in self._spec:
                return type("P", (), {"status": 200, "body_snippet": self._spec[p],
                                      "final_url": f"https://t.example/{p}"})()
            return type("P", (), {"status": 404, "body_snippet": "", "final_url": ""})()

    ctx = _Ctx({"v3/api-docs": _SPEC3})
    d1 = discover(ctx)
    n1 = ctx.calls
    d2 = discover(ctx)
    if not d1.parsed:
        problems.append(f"discover 应解析出文档，实际 reason={d1.reason}")
    if ctx.calls != n1:
        problems.append("第二次 discover 不得重复探测（缓存失效会让请求量翻倍）")
    if d2 is not d1:
        problems.append("缓存应返回同一对象")

    # ⑩ 自定义 404 返回 200（返回首页 HTML）不得被当成「找到接口文档」
    ctx2 = _Ctx({"openapi.json": "<!DOCTYPE html><html><head><title>首页</title>"})
    d3 = discover(ctx2)
    if d3.found:
        problems.append("返回首页 HTML 的 200 响应不得被判为找到接口文档")

    # ⑪ JS 包装形态：规范内嵌在 swagger-ui-init.js 里
    #
    # 这一条守的是 2026-10-12 实测踩到的部署形态：文档页 `/api-docs`
    # 返回的只是 Swagger UI 骨架，真正的 spec 在它加载的 JS 里。
    # 只认裸 JSON 就会把「文档就在响应体里」误判成「没有接口文档」。
    _JS_WRAPPED = (
        "window.onload = function() {\n"
        "  var url = window.location.origin;\n"
        "  var options = {\n"
        '  "swaggerDoc": ' + _SPEC3 + ",\n"
        '  "customOptions": {}\n'
        "  };\n"
        "  var ui = SwaggerUIBundle(options)\n"
        "}\n"
    )
    rj = parse_spec(_JS_WRAPPED, url="https://t.example/api-docs/swagger-ui-init.js")
    if not (rj.found and rj.parsed):
        problems.append(f"JS 包装形态的规范应能解析，实际 reason={rj.reason}")
    else:
        if rj.spec_version != "openapi 3.0.1":
            problems.append(f"JS 包装形态版本识别错误：{rj.spec_version}")
        if len(rj.endpoints) != 4:
            problems.append(f"JS 包装形态应解析出 4 个接口，实际 {len(rj.endpoints)}")
        if rj.base_path != "/v2":
            problems.append(f"JS 包装形态 base path 应为 /v2，实际 {rj.base_path}")

    # ⑫ 内嵌提取必须**跨过字符串里的花括号** ——
    #    用 find('}') 收尾会在 description 里的 `}` 处截断，取出半截 JSON。
    _TRICKY = (
        '{"note":"uses {id} and } braces",'
        '"paths":{"/z":{"get":{"responses":{}}}}}'
    )
    rt = extract_embedded_spec(_TRICKY)
    if rt is None or "/z" not in (rt.get("paths") or {}):
        problems.append("内嵌提取应跳过字符串内的花括号并取出完整对象")

    # ⑬ 不是文档的 JS 配置对象不得被误当成规范
    if extract_embedded_spec('var conf = {"debug": true, "title": "x"};') is not None:
        problems.append("普通 JS 配置对象（无 paths）不得被当接口文档")

    if problems:
        print("接口文档模块自测不通过：")
        for x in problems:
            print(f"  ✗ {x}")
        return 1
    print("接口文档模块自测：通过（13 组断言）")
    print(f"  {r.summary()}")
    print(f"  {r2.summary()}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(_selftest())
