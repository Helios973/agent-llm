import { AUTH_TOKEN_STORAGE_KEY, createJsonClient, escapeHtml, normalizeBaseUrl } from "./core.js";

const runtimeConfig = window.AUDITPILOT_CONFIG || {};
const state = { accessToken: window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY), currentUser: null, usersById: new Map(), logs: [] };
const elements = {
  adminApp: document.getElementById("adminApp"), adminGate: document.getElementById("adminGate"), adminGateMessage: document.getElementById("adminGateMessage"),
  adminIdentity: document.getElementById("adminIdentity"), adminLogoutBtn: document.getElementById("adminLogoutBtn"), adminMessage: document.getElementById("adminMessage"),
  refreshAuditLogsBtn: document.getElementById("refreshAuditLogsBtn"), clearSelectedLogsBtn: document.getElementById("clearSelectedLogsBtn"),
  clearAllLogsBtn: document.getElementById("clearAllLogsBtn"), auditLogsTable: document.getElementById("auditLogsTable"),
};
const fetchJson = createJsonClient({ getToken: () => state.accessToken });
const apiBase = () => normalizeBaseUrl(runtimeConfig.apiBaseUrl);

function setMessage(message, level = "error") {
  elements.adminMessage.hidden = !message;
  elements.adminMessage.textContent = message || "";
  elements.adminMessage.className = message ? `auth-message ${level}` : "auth-message";
}
function showGate(message) { elements.adminApp.hidden = true; elements.adminGate.hidden = false; elements.adminGateMessage.textContent = message; }
function showApp() { elements.adminGate.hidden = true; elements.adminApp.hidden = false; elements.adminIdentity.textContent = `${state.currentUser.username} / 管理员`; }
function userName(userId) { return state.usersById.get(userId)?.username || `用户 ${String(userId || "-").slice(0, 8)}`; }

function describeLog(item) {
  const details = item.details || {};
  const target = userName(item.target_id);
  if (item.action === "user.update") {
    const before = details.before || {}; const after = details.after || {};
    const changes = [];
    if (before.role !== after.role) changes.push(`角色从“${before.role === "admin" ? "管理员" : "普通用户"}”改为“${after.role === "admin" ? "管理员" : "普通用户"}”`);
    if (before.is_active !== after.is_active) changes.push(`账号${after.is_active ? "已启用" : "已停用"}`);
    return `修改了 ${target}：${changes.join("，") || "更新了账号设置"}`;
  }
  if (item.action === "user.llm_quota.update") return `将 ${target} 的月度 Token 配额从 ${Number(details.before || 0).toLocaleString()} 调整为 ${Number(details.after || 0).toLocaleString()}`;
  if (item.action === "user.sessions.revoke") return `让 ${target} 下线，撤销了 ${Number(details.revoked_count || 0)} 个活动会话`;
  if (item.action === "task.stop") return `停止了 ${userName(details.owner_id)} 的审计任务`;
  return `完成了“${item.action}”操作`;
}

function targetLabel(item) {
  if (item.target_type === "user") return userName(item.target_id);
  if (item.target_type === "audit_task") return `审计任务 ${String(item.target_id || "-").slice(0, 8)}`;
  return item.target_id ? `${item.target_type} / ${String(item.target_id).slice(0, 8)}` : item.target_type;
}

function selectedIds() { return [...elements.auditLogsTable.querySelectorAll("[data-log-id]:checked")].map((input) => input.dataset.logId); }
function updateSelectionControls() {
  const count = selectedIds().length;
  elements.clearSelectedLogsBtn.disabled = count === 0;
  elements.clearSelectedLogsBtn.textContent = count ? `清空选中（${count}）` : "清空选中";
  const selectAll = elements.auditLogsTable.querySelector("#selectAllLogs");
  if (selectAll) selectAll.checked = state.logs.length > 0 && count === state.logs.length;
}

function renderAuditLogs(logs) {
  state.logs = logs;
  if (!logs.length) {
    elements.auditLogsTable.className = "empty";
    elements.auditLogsTable.textContent = "暂无管理员操作日志。";
    updateSelectionControls();
    return;
  }
  elements.auditLogsTable.className = "table-wrap";
  elements.auditLogsTable.innerHTML = `<table class="data-table"><thead><tr><th><input id="selectAllLogs" type="checkbox" aria-label="全选日志" /></th><th>什么时候</th><th>谁操作的</th><th>做了什么</th><th>涉及对象</th></tr></thead><tbody>${logs.map((item) => `<tr><td><input type="checkbox" data-log-id="${escapeHtml(item.id)}" aria-label="选择这条日志" /></td><td>${new Date(item.created_at).toLocaleString()}</td><td>${escapeHtml(userName(item.admin_user_id))}</td><td>${escapeHtml(describeLog(item))}</td><td>${escapeHtml(targetLabel(item))}</td></tr>`).join("")}</tbody></table>`;
  updateSelectionControls();
}

async function loadAuditLogs() {
  const [users, logs] = await Promise.all([fetchJson(`${apiBase()}/admin/users`), fetchJson(`${apiBase()}/admin/audit-logs?limit=500`)]);
  state.usersById = new Map(users.map((user) => [user.id, user]));
  renderAuditLogs(logs);
}
async function clearLogs(payload, successText) {
  const result = await fetchJson(`${apiBase()}/admin/audit-logs`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  setMessage(`${successText} ${result.deleted_count} 条日志。`, "ok");
  await loadAuditLogs();
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
    showApp(); await loadAuditLogs();
  } catch (error) { showGate(error.message); }
}

elements.refreshAuditLogsBtn.addEventListener("click", () => loadAuditLogs().catch((error) => setMessage(error.message)));
elements.adminLogoutBtn.addEventListener("click", logout);
elements.auditLogsTable.addEventListener("change", (event) => {
  if (event.target.id === "selectAllLogs") elements.auditLogsTable.querySelectorAll("[data-log-id]").forEach((input) => { input.checked = event.target.checked; });
  updateSelectionControls();
});
elements.clearSelectedLogsBtn.addEventListener("click", () => {
  const ids = selectedIds();
  if (ids.length && window.confirm(`清空选中的 ${ids.length} 条操作日志？`)) clearLogs({ ids }, "已清空").catch((error) => setMessage(error.message));
});
elements.clearAllLogsBtn.addEventListener("click", () => {
  if (state.logs.length && window.confirm("清空全部管理员操作日志？此操作不可恢复。")) clearLogs({ clear_all: true }, "已清空").catch((error) => setMessage(error.message));
});

init();
