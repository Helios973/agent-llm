import {
  AUTH_TOKEN_STORAGE_KEY,
  createJsonClient,
  escapeHtml,
  normalizeBaseUrl,
} from "./core.js";

const runtimeConfig = window.AUDITPILOT_CONFIG || {};
const state = {
  accessToken: window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY),
  currentUser: null,
  users: [],
};

const elements = {
  adminApp: document.getElementById("adminApp"),
  adminGate: document.getElementById("adminGate"),
  adminGateMessage: document.getElementById("adminGateMessage"),
  adminIdentity: document.getElementById("adminIdentity"),
  adminLogoutBtn: document.getElementById("adminLogoutBtn"),
  refreshUsersBtn: document.getElementById("refreshUsersBtn"),
  adminMessage: document.getElementById("adminMessage"),
  usersTable: document.getElementById("usersTable"),
};

const fetchJson = createJsonClient({ getToken: () => state.accessToken });
const apiBase = () => normalizeBaseUrl(runtimeConfig.apiBaseUrl);

function setMessage(message, level = "error") {
  if (!message) {
    elements.adminMessage.hidden = true;
    elements.adminMessage.textContent = "";
    elements.adminMessage.className = "auth-message";
    return;
  }
  elements.adminMessage.hidden = false;
  elements.adminMessage.textContent = message;
  elements.adminMessage.className = `auth-message ${level}`;
}

function showGate(message) {
  elements.adminApp.hidden = true;
  elements.adminGate.hidden = false;
  elements.adminGateMessage.textContent = message;
}

function showApp() {
  elements.adminGate.hidden = true;
  elements.adminApp.hidden = false;
  elements.adminIdentity.textContent = `${state.currentUser.username} / 管理员`;
}

function renderUsers() {
  if (!state.users.length) {
    elements.usersTable.className = "empty";
    elements.usersTable.textContent = "暂无用户。";
    return;
  }

  elements.usersTable.className = "table-wrap";
  elements.usersTable.innerHTML = `
    <table class="data-table">
      <thead><tr><th>账号</th><th>角色</th><th>状态</th><th>任务</th><th>月度 Token 配额</th><th>创建时间</th><th>操作</th></tr></thead>
      <tbody>${state.users.map((user) => `
        <tr>
          <td><strong>${escapeHtml(user.username)}</strong><br /><span class="helper-text">${escapeHtml(user.email)}</span></td>
          <td><select data-action="role" data-user-id="${escapeHtml(user.id)}"><option value="user" ${user.role === "user" ? "selected" : ""}>普通用户</option><option value="admin" ${user.role === "admin" ? "selected" : ""}>管理员</option></select></td>
          <td><span class="badge ${user.is_active ? "ok" : "error"}">${user.is_active ? "启用" : "停用"}</span></td>
          <td>${user.task_count}</td>
          <td><input class="quota-input" data-quota-user-id="${escapeHtml(user.id)}" type="number" min="0" max="1000000000" value="${Number(user.monthly_token_limit || 0)}" aria-label="月度 Token 配额" /></td>
          <td>${new Date(user.created_at).toLocaleString()}</td>
          <td><div class="table-actions">
            <button class="ghost" data-action="tasks" data-user-id="${escapeHtml(user.id)}" type="button">任务</button>
            <button class="${user.is_active ? "ghost" : "secondary"}" data-action="active" data-user-id="${escapeHtml(user.id)}" data-active="${String(!user.is_active)}" type="button">${user.is_active ? "停用" : "启用"}</button>
            <button class="ghost" data-action="revoke-sessions" data-user-id="${escapeHtml(user.id)}" type="button">下线会话</button>
          </div></td>
        </tr>`).join("")}</tbody>
    </table>`;
}

async function loadUsers() {
  setMessage("");
  state.users = await fetchJson(`${apiBase()}/admin/users`);
  renderUsers();
}

async function updateUser(userId, payload) {
  await fetchJson(`${apiBase()}/admin/users/${userId}`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
  await loadUsers();
}

async function updateQuota(userId, monthlyTokenLimit) {
  await fetchJson(`${apiBase()}/admin/users/${userId}/llm-quota`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ monthly_token_limit: monthlyTokenLimit }),
  });
  setMessage("Token 配额已更新。", "ok");
  await loadUsers();
}

async function revokeUserSessions(userId) {
  await fetchJson(`${apiBase()}/admin/users/${userId}/sessions/revoke`, { method: "POST" });
  setMessage("该用户的活动会话已撤销。", "ok");
}

async function logout() {
  try {
    await fetchJson(`${apiBase()}/auth/logout`, { method: "POST" });
  } catch {
    // Finish local sign-out even while the API is restarting.
  } finally {
    window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    window.location.href = "./index.html";
  }
}

async function init() {
  if (!state.accessToken) return showGate("请先登录管理员账号。");
  try {
    state.currentUser = await fetchJson(`${apiBase()}/auth/me`);
    if (state.currentUser.role !== "admin") return showGate("当前账号不是管理员。");
    showApp();
    await loadUsers();
  } catch (error) {
    showGate(error.message);
  }
}

elements.refreshUsersBtn.addEventListener("click", () => loadUsers().catch((error) => setMessage(error.message)));
elements.adminLogoutBtn.addEventListener("click", logout);
elements.usersTable.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const userId = target.dataset.userId;
  if (target.dataset.action === "tasks") {
    window.location.href = `./admin-tasks.html?user_id=${encodeURIComponent(userId)}`;
  } else if (target.dataset.action === "active") {
    updateUser(userId, { is_active: target.dataset.active === "true" }).catch((error) => setMessage(error.message));
  } else if (target.dataset.action === "revoke-sessions" && window.confirm("撤销该用户的全部活动会话？")) {
    revokeUserSessions(userId).catch((error) => setMessage(error.message));
  }
});
elements.usersTable.addEventListener("change", (event) => {
  const quotaTarget = event.target.closest("[data-quota-user-id]");
  if (quotaTarget) {
    updateQuota(quotaTarget.dataset.quotaUserId, Number(quotaTarget.value)).catch((error) => setMessage(error.message));
    return;
  }
  const target = event.target.closest("[data-action='role']");
  if (target) updateUser(target.dataset.userId, { role: target.value }).catch((error) => setMessage(error.message));
});

init();
