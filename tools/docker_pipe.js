// Docker Engine named pipe 客户端（供本沙箱无 docker CLI 时使用）
// 用法：node tools/docker_pipe.js <METHOD> <PATH> [JSON_BODY]
// 例：node tools/docker_pipe.js GET /containers/json
const http = require("http");

const SOCK = "\\\\.\\pipe\\docker_engine";

function api(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body || null;
    const req = http.request(
      {
        socketPath: SOCK,
        path,
        method,
        headers: data
          ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }
          : {},
      },
      (res) => {
        const parts = [];
        res.on("data", (c) => parts.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(parts).toString("utf8") })
        );
      }
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

const [method, path, body] = process.argv.slice(2);
if (!method || !path) {
  console.error("usage: node tools/docker_pipe.js METHOD PATH [BODY]");
  process.exit(1);
}
api(method.toUpperCase(), path, body)
  .then((r) => {
    console.log("STATUS " + r.status);
    console.log(r.body);
  })
  .catch((e) => {
    console.error("PIPE_ERROR " + e.message);
    process.exit(2);
  });
