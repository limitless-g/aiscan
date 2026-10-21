// aiscan 控制台前端（原生 JS，无框架无构建）
const $ = (id) => document.getElementById(id);
let current = null;          // 当前项目
let accounts = [];           // 当前账号（含输入框）
let es = null;               // EventSource

// ---------- 工具 ----------
async function api(method, path, body) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  return r.json().catch(() => ({}));
}

function setMsg(el, text, ok) {
  el.textContent = text || "";
  el.style.color = ok ? "#16a34a" : "#dc2626";
}

// ---------- 项目列表 ----------
async function loadProjects() {
  const list = await api("GET", "/api/projects");
  const ul = $("project-list");
  ul.innerHTML = "";
  list.forEach((p) => {
    const li = document.createElement("li");
    li.dataset.id = p.id;
    if (current && current.id === p.id) li.classList.add("active");
    li.innerHTML = `<div class="pl-name">${esc(p.name)}</div>
      <div class="pl-target">${esc(p.target || "—")} · ${esc(p.profile)}</div>`;
    li.onclick = () => selectProject(p.id);
    ul.appendChild(li);
  });
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// ---------- 选择项目 ----------
async function selectProject(id) {
  const p = await api("GET", `/api/projects/${id}`);
  if (p.error) return;
  current = p;
  accounts = p.accounts.map((a) => ({ ...a }));
  $("empty").classList.add("hidden");
  $("detail").classList.remove("hidden");
  $("d-name").textContent = p.name;
  $("d-target").textContent = p.target || "—";
  fillOverview(p);
  renderAccounts();
  await refreshOutputs();
  document.querySelectorAll(".project-list li").forEach((li) =>
    li.classList.toggle("active", li.dataset.id === id));
}

function fillOverview(p) {
  $("f-name").value = p.name || "";
  $("f-target").value = p.target || "";
  $("f-url").value = p.url || "";
  $("f-profile").value = p.profile || "standard";
  $("f-mode").value = p.mode || "manual";
  $("f-impact").value = p.impact_level || "L2";
  $("f-authorizer").value = p.authorizer || "";
  $("f-authref").value = p.auth_ref || "";
  $("f-objectives").value = p.objectives || "";
  $("f-allowwrite").checked = !!p.allow_write;
  $("f-healthoff").checked = !!p.health_guard_off;
  renderStats($("ov-stats"), p.recent_stats || {});
}

function renderStats(el, stats) {
  if (!stats || !stats.total) { el.innerHTML = ""; return; }
  const order = ["严重", "高危", "中危", "低危", "信息"];
  el.innerHTML = order.map((k) =>
    `<div class="stat"><div class="n" style="color:var(--sev-${k})">${stats[k] || 0}</div><div class="l">${k}</div></div>`
  ).join("") + `<div class="stat"><div class="n">${stats.total}</div><div class="l">合计</div></div>`;
}

// ---------- 账号 ----------
function renderAccounts() {
  const tb = $("acct-body");
  tb.innerHTML = "";
  accounts.forEach((a, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input data-i="${i}" data-k="name" value="${esc(a.name)}"></td>
      <td><input data-i="${i}" data-k="role" value="${esc(a.role || "customer")}"></td>
      <td><input data-i="${i}" data-k="tenant" value="${esc(a.tenant || "")}"></td>
      <td><input data-i="${i}" data-k="username" value="${esc(a.username || "")}"></td>
      <td><input data-i="${i}" data-k="login_url" value="${esc(a.login_url || "/login")}"></td>
      <td><input data-i="${i}" data-k="method" value="${esc(a.method || "POST")}" size="6"></td>
      <td><input data-i="${i}" data-k="password" type="password" placeholder="${a.has_secret ? "已设置（留空不改）" : "设置口令"}"></td>
      <td><button class="btn danger" data-del="${i}">×</button></td>`;
    tb.appendChild(tr);
  });
  tb.querySelectorAll("input").forEach((inp) => {
    inp.oninput = () => { accounts[+inp.dataset.i][inp.dataset.k] = inp.value; };
  });
  tb.querySelectorAll("[data-del]").forEach((b) => {
    b.onclick = () => { accounts.splice(+b.dataset.del, 1); renderAccounts(); };
  });
}

$("btn-acct-add").onclick = () => { accounts.push({ name: "", role: "customer", tenant: "", username: "", login_url: "/login", method: "POST" }); renderAccounts(); };

$("btn-acct-save").onclick = async () => {
  const r = await api("PUT", `/api/projects/${current.id}/accounts`, { accounts });
  if (r.error) { setMsg($("ac-msg"), "保存失败", false); return; }
  setMsg($("ac-msg"), "账号已保存（口令已存入本机安全存储）", true);
  current = r; accounts = r.accounts.map((a) => ({ ...a })); renderAccounts();
};

// ---------- 概览保存 ----------
$("btn-save").onclick = async () => {
  const body = {
    name: $("f-name").value, target: $("f-target").value, url: $("f-url").value,
    profile: $("f-profile").value, mode: $("f-mode").value, impact_level: $("f-impact").value,
    authorizer: $("f-authorizer").value, auth_ref: $("f-authref").value,
    objectives: $("f-objectives").value, allow_write: $("f-allowwrite").checked,
    health_guard_off: $("f-healthoff").checked,
  };
  const r = await api("PUT", `/api/projects/${current.id}`, body);
  if (r.error) { setMsg($("ov-msg"), "保存失败", false); return; }
  setMsg($("ov-msg"), "已保存", true);
  current = r; $("d-name").textContent = r.name; $("d-target").textContent = r.target || "—";
  await loadProjects();
};

$("btn-ledger").onclick = async () => {
  const r = await api("POST", `/api/projects/${current.id}/ledger`);
  setMsg($("ov-msg"), r.ok ? "授权台账已登记" : ("登记失败：" + (r.reason || r.stderr || r.returncode)), r.ok);
};

$("btn-del").onclick = async () => {
  if (!confirm("确认删除该项目？本机安全存储中的口令也会一并删除。")) return;
  const r = await api("DELETE", `/api/projects/${current.id}`);
  if (r.deleted) { current = null; $("detail").classList.add("hidden"); $("empty").classList.remove("hidden"); await loadProjects(); }
};

// ---------- 扫描 ----------
$("btn-scan").onclick = async () => {
  const r = await api("POST", `/api/projects/${current.id}/scan`);
  if (r.error) { alert("启动失败：" + r.error); return; }
  startStream(r.task_id);
};

function startStream(taskId) {
  if (es) es.close();
  $("scan-log").textContent = "";
  $("scan-bar").style.width = "0%";
  $("scan-stage").textContent = "连接中…";
  es = new EventSource(`/api/tasks/${taskId}/stream`);
  es.addEventListener("update", (e) => {
    const t = JSON.parse(e.data);
    $("scan-stage").textContent = `阶段 ${t.stage}${t.stage_total ? "/" + t.stage_total : ""} · ${t.status}`;
    if (t.stage_total) $("scan-bar").style.width = Math.min(100, (t.stage / t.stage_total) * 100) + "%";
    $("scan-log").textContent = t.log_tail.join("\n");
    $("scan-log").scrollTop = $("scan-log").scrollHeight;
    if (t.stats && t.stats.total) { renderStats($("scan-stats"), t.stats); $("scan-bar").style.width = "100%"; }
    if (t.status === "done" || t.status === "error") {
      es.close(); es = null;
      $("scan-stage").textContent = `完成（退出码 ${t.exit_code}）`;
      refreshOutputs();
    }
  });
  es.onerror = () => { if (es) { es.close(); es = null; } };
}

// ---------- 产出 ----------
async function refreshOutputs() {
  const r = await api("GET", `/api/projects/${current.id}/outputs`);
  const box = $("out-list");
  box.innerHTML = "";
  if (!r.outputs || !r.outputs.length) {
    box.innerHTML = `<div class="hint">暂无扫描产出。</div>`;
    return;
  }
  r.outputs.forEach((o) => {
    const div = document.createElement("div");
    div.className = "out-item";
    const links = o.reports.map((f) =>
      `<a data-d="${o.dir}" data-f="${f}">${esc(f.replace(/^.*_/, ""))}</a>`).join("");
    div.innerHTML = `<div class="ot">${esc(o.time)}</div><div class="or">${links || "<span class='hint'>无报告</span>"}</div>`;
    box.appendChild(div);
  });
  box.querySelectorAll("a").forEach((a) => {
    a.onclick = () => openReport(a.dataset.d, a.dataset.f);
  });
}

async function openReport(d, f) {
  const r = await api("GET", `/api/report?name=${encodeURIComponent(current.name)}&d=${encodeURIComponent(d)}&f=${encodeURIComponent(f)}`);
  $("out-list").classList.add("hidden");
  $("report-view").classList.remove("hidden");
  $("report-body").textContent = r.text || r.error || "（无法读取）";
}
$("btn-back").onclick = () => { $("report-view").classList.add("hidden"); $("out-list").classList.remove("hidden"); };

// ---------- 标签页 ----------
document.querySelectorAll(".tab").forEach((t) => {
  t.onclick = () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    ["overview", "accounts", "scan", "outputs"].forEach((k) =>
      $(`tab-${k}`).classList.toggle("hidden", t.dataset.tab !== k));
  };
});

// ---------- 新建项目 ----------
$("btn-new").onclick = () => { $("modal").classList.remove("hidden"); };
$("btn-cancel").onclick = () => { $("modal").classList.add("hidden"); };
$("btn-create").onclick = async () => {
  const body = {
    name: $("n-name").value, target: $("n-target").value, url: $("n-url").value,
    profile: $("n-profile").value, authorizer: $("n-authorizer").value, auth_ref: $("n-authref").value,
  };
  if (!body.name || !body.target) { setMsg($("n-msg"), "项目名与目标必填", false); return; }
  const r = await api("POST", "/api/projects", body);
  if (r.error) { setMsg($("n-msg"), "创建失败", false); return; }
  $("modal").classList.add("hidden");
  await loadProjects();
  selectProject(r.id);
};

// ---------- 启动 ----------
loadProjects();
