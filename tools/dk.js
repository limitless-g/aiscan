// Docker Engine named pipe 客户端 v2 —— net 模块原始 HTTP/1.0
// （v1 用 http.request socketPath 在本机 Docker Desktop 上会得到 404，
//   估计是 path 规范化问题；原始 net 写法稳定返回真 API 响应）
// 用法：node tools/dk.js <METHOD> <PATH> [JSON_BODY]
const net = require("net");

const SOCK = "\\\\.\\pipe\\docker_engine";

const [method, path, body] = process.argv.slice(2);
if (!method || !path) {
  console.error("usage: node tools/dk.js METHOD PATH [BODY]");
  process.exit(1);
}

const sock = net.connect(SOCK);
let buf = Buffer.alloc(0);
sock.on("connect", () => {
  const headers =
    method.toUpperCase() +
    " " +
    path +
    " HTTP/1.0\r\nHost: docker\r\nContent-Type: application/json\r\n" +
    (body ? "Content-Length: " + Buffer.byteLength(body) + "\r\n" : "") +
    "\r\n";
  sock.write(headers);
  if (body) sock.write(body);
});
sock.on("data", (d) => {
  buf = Buffer.concat([buf, d]);
});
sock.on("end", () => {
  const s = buf.toString("utf8");
  const idx = s.indexOf("\r\n\r\n");
  const head = idx >= 0 ? s.slice(0, idx) : s;
  const bodystr = idx >= 0 ? s.slice(idx + 4) : "";
  const statusLine = head.split("\r\n")[0] || "";
  const code = Number((statusLine.match(/HTTP\/1\.\d (\d+)/) || [])[1] || 0);
  console.log("STATUS " + code);
  if (bodystr.trim()) console.log(bodystr);
  else console.log("(no body)");
});
sock.on("error", (e) => {
  console.error("SOCK_ERR " + e.code + " " + e.message);
  process.exit(2);
});
