// AI 后端接线 v5 —— 直接改 default.yml 的 chatBot 段（local.yml 合并未被证实）
// 流程：下载 config tar → Node 解析出 default.yml → 在 chatBot 段注入
//       llmApiUrl/model → 原生 tar 打包单文件 → PUT archive 覆盖 → restart → 实测
const net = require("net");
const fs = require("fs");
const http = require("http");

const SOCK = "\\\\.\\pipe\\docker_engine";
const SHIM_URL = "http://host.docker.internal:11434/aiscan-wire-2026/v1";
const os = require("os");
const path = require("path");
//# 暂存目录走系统临时目录，避免把本机用户名写进仓库
const STAGE = path.join(os.tmpdir(), "aiwire");

function pipeRaw(req) {
  return new Promise((resolve, reject) => {
    const s = net.connect(SOCK);
    const parts = [];
    s.setTimeout(10000, () => {
      s.destroy();
      reject(new Error("pipe timeout"));
    });
    s.on("connect", () => s.write(req));
    s.on("data", (d) => parts.push(d));
    s.on("end", () => resolve(Buffer.concat(parts)));
    s.on("error", reject);
  });
}

async function call(method, path, body) {
  const req =
    method +
    " " +
    path +
    " HTTP/1.0\r\nHost: docker\r\nContent-Type: application/json\r\n" +
    (body ? "Content-Length: " + Buffer.byteLength(body) + "\r\n" : "") +
    "\r\n" +
    (body || "");
  const buf = await pipeRaw(req);
  const t = buf.toString("utf8");
  const i = t.indexOf("\r\n\r\n");
  const head = t.slice(0, i >= 0 ? i : t.length);
  return { code: Number((head.match(/HTTP\/1\.\d (\d+)/) || [])[1] || 0), body: i >= 0 ? t.slice(i + 4) : "" };
}

async function download(id, cpath) {
  const buf = await pipeRaw(
    "GET /containers/" + id + "/archive?path=" + encodeURIComponent(cpath) + " HTTP/1.0\r\nHost: docker\r\n\r\n"
  );
  const i = buf.indexOf("\r\n\r\n");
  const head = buf.slice(0, i).toString("utf8");
  const code = Number((head.match(/HTTP\/1\.\d (\d+)/) || [])[1] || 0);
  return { code, payload: buf.slice(i + 4) };
}

function parseTar(buf) {
  const out = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const name = buf.slice(off, off + 100).toString("utf8").replace(/\0.*$/, "");
    if (!name) break;
    const sizeStr = buf.slice(off + 124, off + 136).toString("ascii").replace(/\0.*$/, "").trim();
    const size = parseInt(sizeStr || "0", 8) || 0;
    const typeflag = String.fromCharCode(buf[off + 156]);
    const content = buf.slice(off + 512, off + 512 + size);
    if (typeflag === "0" || typeflag === "\0") out.push({ name, content });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

function makeTar(name, content) {
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 99), 0, "utf8");
  header.write("0000644\0", 100, "ascii");
  header.write("0000000\0", 108, "ascii");
  header.write("0000000\0", 116, "ascii");
  header.write(data.length.toString(8).padStart(11, "0") + "\0", 124, "ascii");
  header.write("00000000000\0", 136, "ascii");
  header.write("0", 156, "ascii");
  header.write("ustar\0", 257, "ascii");
  header.write("00", 263, "ascii");
  for (let i = 148; i < 156; i++) header[i] = 0x20;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  const pad = (512 - (data.length % 512)) % 512;
  return Buffer.concat([header, data, Buffer.alloc(pad), Buffer.alloc(1024)]);
}

async function upload(id, tar, cpath) {
  const req =
    "PUT /containers/" + id + "/archive?path=" + encodeURIComponent(cpath) +
    " HTTP/1.0\r\nHost: docker\r\nContent-Type: application/x-tar\r\n" +
    "Content-Length: " + tar.length + "\r\n\r\n";
  const buf = await pipeRaw(Buffer.concat([Buffer.from(req), tar]));
  const t = buf.toString("utf8");
  const code = Number((t.match(/HTTP\/1\.\d (\d+)/) || [])[1] || 0);
  console.log("upload default.yml -> " + code);
  return code === 200;
}

function chatTest(msg) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ messages: [{ role: "user", content: msg }] });
    const r = http.request(
      {
        host: "127.0.0.1",
        port: 3000,
        path: "/rest/chat",
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
        timeout: 45000,
      },
      (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => resolve(b.slice(0, 400)));
      }
    );
    r.on("error", (e) => resolve("ERR " + e.message));
    r.on("timeout", () => {
      r.destroy();
      resolve("TIMEOUT");
    });
    r.write(body);
    r.end();
  });
}

(async () => {
  fs.mkdirSync(STAGE, { recursive: true });
  console.log("等待 pipe 窗口 ...");
  let waited = 0;
  while (true) {
    try {
      if ((await call("GET", "/_ping")).code === 200) break;
    } catch (e) {}
    await new Promise((x) => setTimeout(x, 2000));
    waited += 2;
    if (waited % 30 === 0) console.log("已等 " + waited + "s");
    if (waited > 560) {
      console.log("pipe 560s 未恢复，放弃");
      process.exit(3);
    }
  }
  console.log("pipe UP（t+" + waited + "s）");

  const cj = await call("GET", "/containers/json");
  const juice = JSON.parse(cj.body).find(
    (c) => (c.Image || "").toLowerCase().includes("juice") || (c.Names || []).join().includes("juice")
  );
  if (!juice) {
    console.log("未找到 juice 容器");
    process.exit(4);
  }
  const id = juice.Id;
  console.log("容器 " + juice.Names.join(",") + " / " + juice.Image);

  const dl = await download(id, "/juice-shop/config");
  if (dl.code !== 200) {
    console.log("下载 config 失败: " + dl.code);
    process.exit(4);
  }
  const entries = parseTar(dl.payload);
  const dy = entries.find((e) => e.name.replace(/^.*\//, "") === "default.yml");
  if (!dy) {
    console.log("tar 内无 default.yml，条目: " + entries.map((e) => e.name).join(", "));
    process.exit(4);
  }
  console.log("default.yml " + dy.content.length + " bytes，配置目录共 " + entries.length + " 个文件");

  let y = dy.content.toString("utf8");
  if (/llmApiUrl/.test(y)) {
    y = y.replace(/(llmApiUrl:).*/g, '$1 "' + SHIM_URL + '"');
    y = y.replace(/(\n\s*model:).*/g, '$1 "deepseek-chat"');
    console.log("已存在的 llmApiUrl/model 行直接被替换");
  } else {
    const lines = y.split("\n");
    const ci = lines.findIndex((l) => /^\s*chatBot:\s*$/.test(l));
    if (ci < 0) {
      console.log("未找到 chatBot: 行，文件尾部追加");
      y = y.replace(/\s*$/, "") + "\nchatBot:\n  llmApiUrl: \"" + SHIM_URL + "\"\n  model: \"deepseek-chat\"\n";
    } else {
      const indent = (lines[ci].match(/^\s*/) || [""])[0];
      lines.splice(ci + 1, 0,
        indent + '  llmApiUrl: "' + SHIM_URL + '"',
        indent + '  model: "deepseek-chat"');
      y = lines.join("\n");
      console.log("已在第 " + (ci + 1) + " 行 chatBot: 后注入 llmApiUrl/model");
    }
  }
  fs.writeFileSync(STAGE + "/default.yml", y);
  const around = y.split("\n").findIndex((l) => /llmApiUrl/.test(l));
  console.log("--- 改后上下文 ---\n" + y.split("\n").slice(Math.max(0, around - 2), around + 4).join("\n"));

  const tar = makeTar("default.yml", y);
  const ok = await upload(id, tar, "/juice-shop/config");
  if (!ok) process.exit(5);

  const rs = await call("POST", "/containers/" + id + "/restart?t=5", null);
  console.log("restart -> " + rs.code);
  console.log("等容器初始化（18s）...");
  await new Promise((x) => setTimeout(x, 18000));
  for (let i = 1; i <= 8; i++) {
    const t = await chatTest("Reply with the single word: PONG");
    console.log("chatbot#" + i + ": " + t.replace(/\s+/g, " ").slice(0, 260));
    if (/PONG/i.test(t)) {
      console.log("=== AI 后端接线成功 ===");
      process.exit(0);
    }
    await new Promise((x) => setTimeout(x, 6000));
  }
  console.log("仍未通过");
  process.exit(6);
})().catch((e) => {
  console.error("FATAL " + e.message);
  process.exit(9);
});
