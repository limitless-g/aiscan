// DeepSeek OpenAI 兼容 shim —— 让 Juice Shop v20.2.0 chatbot（默认连
// localhost:11434/v1 的 Ollama）在不改容器配置、不注入 key 的前提下用上
// DeepSeek。仅用于 localhost 测试靶场，禁止用于任何公网目标。
//
// 用法（key 走环境变量，不落盘、不进 git）：
//   DEEPSEEK_API_KEY=sk-xxx node tools/deepseek_shim.js
//
// 行为：
//   监听 127.0.0.1:11434
//   /v1/chat/completions  透传 DeepSeek，model 映射到 deepseek-chat
//   /api/chat (Ollama)    转 OpenAI 打 DeepSeek 再转回 Ollama 格式
//   /v1/models /api/tags  假模型列表（客户端健康检查用）
const http = require("http");
const https = require("https");

const UPSTREAM = "api.deepseek.com";
const KEY = process.env.DEEPSEEK_API_KEY || "";
const PORT = 11434;
// 容器（bridge）host.docker.internal 流量经 Docker Desktop DNAT 落到宿主；
// EADDRNOTVAIL 证明 192.168.65.254 不属宿主，只能绑 0.0.0.0 等 NAT 转包。
// 0.0.0.0 有被内网白嫖风险 → URL 首段令牌校验，无令牌一律 403。
const LISTEN_HOSTS = ["0.0.0.0"];
const TOKEN = process.env.WIRE_TOKEN || "aiscan-wire-2026";
const MODEL_MAP = {
  "gemma4:e4b": "deepseek-chat",
  "gemma2:2b": "deepseek-chat",
  gemma4: "deepseek-chat",
  deepseek: "deepseek-chat",
};

if (!KEY) {
  console.error("DEEPSEEK_API_KEY 未设置，退出");
  process.exit(1);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function callUpstream(path, raw) {
  return new Promise((resolve, reject) => {
    const pr = https.request(
      {
        hostname: UPSTREAM,
        port: 443,
        path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + KEY,
          "Content-Length": Buffer.byteLength(raw),
        },
      },
      (pres) => {
        const parts = [];
        pres.on("data", (c) => parts.push(c));
        pres.on("end", () =>
          resolve({ status: pres.statusCode, body: Buffer.concat(parts).toString("utf8") })
        );
      }
    );
    pr.on("error", reject);
    pr.write(raw);
    pr.end();
  });
}

function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

const server = http.createServer(async (req, res) => {
  try {
    const parts = req.url.split("/").filter(Boolean);
    if (parts[0] !== TOKEN) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "bad wire token" }));
    }
    const sub = "/" + parts.slice(1).join("/");
    if (sub === "/v1/models" || sub === "/api/tags") {
      return sendJson(res, 200, {
        object: "list",
        data: [{ id: "deepseek-chat", object: "model", owned_by: "deepseek" }],
      });
    }
    if (sub.startsWith("/v1/chat/completions")) {
      let raw = await readBody(req);
      console.log("[shim] req body:", raw.slice(0, 600));
      try {
        const j = JSON.parse(raw);
        j.model = MODEL_MAP[j.model] || "deepseek-chat";
        // 必须透传 stream：Juice Shop 用 Vercel AI SDK 的 SSE 流式协议，
        // 强制 stream:false 返回单体 JSON 会让 SDK 解析出空 choices
        // （2026-10-19 实测：finish_reason:"other" 无 message）。
        if (j.stream === undefined) j.stream = true;
        raw = JSON.stringify(j);
      } catch (e) {
        return sendJson(res, 400, { error: "bad json: " + e.message });
      }
      const up = await callUpstream("/v1/chat/completions", raw);
      console.log("[shim] upstream status:", up.status, "body:", up.body.slice(0, 600));
      res.writeHead(up.status, { "Content-Type": "text/event-stream" });
      return res.end(up.body);
    }
    if (sub.startsWith("/api/chat") || sub.startsWith("/api/generate")) {
      const raw = await readBody(req);
      let j;
      try {
        j = JSON.parse(raw);
      } catch (e) {
        return sendJson(res, 400, { error: "bad json" });
      }
      const oai = {
        model: MODEL_MAP[j.model] || "deepseek-chat",
        messages: j.messages || [],
        stream: false,
      };
      if (j.prompt && !j.messages) oai.messages = [{ role: "user", content: j.prompt }];
      const up = await callUpstream("/v1/chat/completions", JSON.stringify(oai));
      if (up.status !== 200) {
        return sendJson(res, up.status, JSON.parse(up.body || "{}"));
      }
      const d = JSON.parse(up.body);
      const content = d.choices && d.choices[0] && d.choices[0].message
        ? d.choices[0].message.content
        : "";
      return sendJson(res, 200, {
        model: j.model,
        created_at: new Date().toISOString(),
        message: { role: "assistant", content },
        done: true,
      });
    }
    sendJson(res, 404, { error: "not found" });
  } catch (e) {
    sendJson(res, 502, { error: String(e).slice(0, 200) });
  }
});

for (const host of LISTEN_HOSTS) {
  server.listen(PORT, host, () =>
    console.log("deepseek shim listening on " + host + ":" + PORT)
  );
}
server.on("error", (e) => console.error("listen error: " + e.message));
