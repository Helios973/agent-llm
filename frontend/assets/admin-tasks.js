import {
  AUTH_TOKEN_STORAGE_KEY,
  appendAccessToken,
  createJsonClient,
  escapeHtml,
  localizeFindingDescription,
  localizeFindingSeverity,
  localizeFindingSource,
  localizeFindingTitle,
  normalizeBaseUrl,
} from "./core.js";

const runtimeConfig = window.AUDITPILOT_CONFIG || {};
const state = {
  accessToken: window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY),
  currentUser: null,
  users: [],
  selectedUserId: new URLSearchParams(window.location.search).get("user_id") || "",
};
const elements = {
  adminApp: document.getElementById("adminApp"), adminGate: document.getElementById("adminGate"),
  adminGateMessage: document.getElementById("adminGateMessage"), adminIdentity: document.getElementById("adminIdentity"),
  adminLogoutBtn: document.getElementById("adminLogoutBtn"), adminMessage: document.getElementById("adminMessage"),
  taskUserSelect: document.getElementById("taskUserSelect"), refreshTasksBtn: document.getElementById("refreshTasksBtn"),
  selectedUserLabel: document.getElementById("selectedUserLabel"), tasksTable: document.getElementById("tasksTable"),
  adminTaskDetail: document.getElementById("adminTaskDetail"),
};
const fetchJson = createJsonClient({ getToken: () => state.accessToken });
const apiBase = () => normalizeBaseUrl(runtimeConfig.apiBaseUrl);
const withAccessToken = (url) => appendAccessToken(url, state.accessToken);

function setMessage(message, level = "error") {
  elements.adminMessage.hidden = !message;
  elements.adminMessage.textContent = message || "";
  elements.adminMessage.className = message ? `auth-message ${level}` : "auth-message";
}
function showGate(message) { elements.adminApp.hidden = true; elements.adminGate.hidden = false; elements.adminGateMessage.textContent = message; }
function showApp() { elements.adminGate.hidden = true; elements.adminApp.hidden = false; elements.adminIdentity.textContent = `${state.currentUser.username} / 管理员`; }

function renderUserOptions() {
  if (!state.users.length) {
    elements.taskUserSelect.innerHTML = '<option value="">暂无用户</option>';
    return;
  }
  if (!state.users.some((user) => user.id === state.selectedUserId)) state.selectedUserId = state.users[0].id;
  elements.taskUserSelect.innerHTML = state.users.map((user) => `<option value="${escapeHtml(user.id)}" ${user.id === state.selectedUserId ? "selected" : ""}>${escapeHtml(user.username)}（${user.role === "admin" ? "管理员" : "普通用户"}，${user.task_count} 个任务）</option>`).join("");
}

function renderTasks(tasks, user) {
  elements.selectedUserLabel.textContent = user ? `${user.username} 的任务` : "未选择用户";
  elements.adminTaskDetail.className = "empty";
  elements.adminTaskDetail.textContent = "选择任务后查看漏洞详情。";
  if (!tasks.length) {
    elements.tasksTable.className = "empty";
    elements.tasksTable.textContent = "该用户暂无任务。";
    return;
  }
  elements.tasksTable.className = "table-wrap";
  elements.tasksTable.innerHTML = `<table class="data-table"><thead><tr><th>任务</th><th>状态</th><th>上传</th><th>发现</th><th>创建时间</th><th>操作</th></tr></thead><tbody>${tasks.map((task) => {
    const canStop = user?.role === "user" && ["queued", "running"].includes(task.status);
    return `<tr><td><strong>${escapeHtml(task.task_name)}</strong><br /><span class="helper-text">${escapeHtml(task.id)}</span></td><td><span class="chip">${escapeHtml(task.status)}</span></td><td>${escapeHtml(task.upload_name || "-")}</td><td>${task.finding_count}</td><td>${new Date(task.created_at).toLocaleString()}</td><td><div class="table-actions"><button class="ghost" data-action="view-task" data-task-id="${escapeHtml(task.id)}" type="button">查看</button><button class="stop-action ${canStop ? "danger-action" : "stop-action-disabled"}" data-action="stop-task" data-task-id="${escapeHtml(task.id)}" type="button" ${canStop ? "" : "disabled"} title="${canStop ? "停止当前审计任务" : "当前状态不可停止"}">停止</button></div></td></tr>`;
  }).join("")}</tbody></table>`;
}

function renderTaskDetail(task) {
  const findings = task.findings || [];
  const reports = task.status === "completed" ? `<div class="report-actions"><a class="link-button ghost" href="${withAccessToken(`${apiBase()}/report/${task.id}?format=html`)}" download="report.html">HTML</a><a class="link-button ghost" href="${withAccessToken(`${apiBase()}/report/${task.id}?format=markdown`)}" download="report.md">Markdown</a><a class="link-button ghost" href="${withAccessToken(`${apiBase()}/report/${task.id}?format=json`)}" download="report.json">JSON</a></div>` : "";
  elements.adminTaskDetail.className = "";
  elements.adminTaskDetail.innerHTML = `<div class="finding-header"><span class="chip">${escapeHtml(task.status)}</span><span class="chip">${findings.length} 个发现</span><span class="chip">${escapeHtml(task.id)}</span></div>${reports}${findings.length ? findings.map((item) => `<article class="finding-card"><div class="finding-header"><span class="severity-pill severity-${escapeHtml(String(item.severity || "").toLowerCase())}">${escapeHtml(localizeFindingSeverity(item.severity))}</span><span class="chip">${escapeHtml(item.owasp_label || "未分类")}</span><span class="chip">${escapeHtml(localizeFindingSource(item.source))}</span></div><h3>${escapeHtml(localizeFindingTitle(item.title))}</h3><p>${escapeHtml(localizeFindingDescription(item.description))}</p><div class="finding-meta"><span>位置: ${escapeHtml(item.file_path)}:${escapeHtml(item.line_number)}</span><span>CWE: ${escapeHtml(item.cwe_id || "N/A")}</span><span>CVSS: ${escapeHtml(item.cvss_score)}</span></div></article>`).join("") : '<div class="empty">该任务暂未产生漏洞详情。</div>'}`;
}

async function loadUsers() {
  state.users = await fetchJson(`${apiBase()}/admin/users`);
  renderUserOptions();
  if (state.selectedUserId) await loadUserTasks(state.selectedUserId);
  else renderTasks([], null);
}
async function loadUserTasks(userId) {
  state.selectedUserId = userId;
  const user = state.users.find((item) => item.id === userId);
  const tasks = await fetchJson(`${apiBase()}/admin/users/${encodeURIComponent(userId)}/tasks`);
  renderTasks(tasks, user);
  const url = new URL(window.location.href);
  url.searchParams.set("user_id", userId);
  window.history.replaceState({}, "", url);
}
async function viewTask(taskId) { renderTaskDetail(await fetchJson(`${apiBase()}/audit/${encodeURIComponent(taskId)}`)); }
async function stopTask(taskId) {
  await fetchJson(`${apiBase()}/admin/tasks/${encodeURIComponent(taskId)}/stop`, { method: "POST" });
  await loadUserTasks(state.selectedUserId);
  await viewTask(taskId);
  setMessage("任务已停止。", "ok");
}
async function logout() {
  try { await fetchJson(`${apiBase()}/auth/logout`, { method: "POST" }); } catch { /* local sign-out still proceeds */ }
  window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY); window.location.href = "./index.html";
}
async function init() {
  if (!state.accessToken) return showGate("请先登录管理员账号。");
  try {
    state.currentUser = await fetchJson(`${apiBase()}/auth/me`);
    if (state.currentUser.role !== "admin") return showGate("当前账号不是管理员。");
    showApp(); await loadUsers();
  } catch (error) { showGate(error.message); }
}

elements.taskUserSelect.addEventListener("change", () => loadUserTasks(elements.taskUserSelect.value).catch((error) => setMessage(error.message)));
elements.refreshTasksBtn.addEventListener("click", () => loadUsers().catch((error) => setMessage(error.message)));
elements.adminLogoutBtn.addEventListener("click", logout);
elements.tasksTable.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]"); if (!target) return;
  const taskId = target.dataset.taskId;
  if (target.dataset.action === "view-task") viewTask(taskId).catch((error) => setMessage(error.message));
  if (target.dataset.action === "stop-task" && window.confirm("停止这个正在运行的审计任务？")) stopTask(taskId).catch((error) => setMessage(error.message));
});

init();
