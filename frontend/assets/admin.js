const runtimeConfig = window.AUDITPILOT_CONFIG || {};
const AUTH_TOKEN_STORAGE_KEY = "auditpilot.accessToken";

const state = {
  accessToken: window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY),
  currentUser: null,
  users: [],
  selectedUserId: null,
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
  tasksTable: document.getElementById("tasksTable"),
  selectedUserLabel: document.getElementById("selectedUserLabel"),
  adminTaskDetail: document.getElementById("adminTaskDetail"),
};

function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function apiBase() {
  return normalizeBaseUrl(runtimeConfig.apiBaseUrl);
}

function withAccessToken(url) {
  if (!state.accessToken) {
    return url;
  }
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}access_token=${encodeURIComponent(state.accessToken)}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

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

async function fetchJson(url, options = {}) {
  const { headers, ...rest } = options;
  const requestHeaders = new Headers(headers || {});
  if (state.accessToken) {
    requestHeaders.set("Authorization", `Bearer ${state.accessToken}`);
  }

  const response = await fetch(url, {
    ...rest,
    headers: requestHeaders,
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = await response.json();
      detail = payload.detail || JSON.stringify(payload);
    } catch {
      detail = (await response.text()) || detail;
    }
    throw new Error(detail);
  }
  return response.json();
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
      <thead>
        <tr>
          <th>账号</th>
          <th>角色</th>
          <th>状态</th>
          <th>任务</th>
          <th>创建时间</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        ${state.users.map((user) => `
          <tr>
            <td>
              <strong>${escapeHtml(user.username)}</strong><br />
              <span class="helper-text">${escapeHtml(user.email)}</span>
            </td>
            <td>
              <select data-action="role" data-user-id="${escapeHtml(user.id)}">
                <option value="user" ${user.role === "user" ? "selected" : ""}>普通用户</option>
                <option value="admin" ${user.role === "admin" ? "selected" : ""}>管理员</option>
              </select>
            </td>
            <td><span class="badge ${user.is_active ? "ok" : "error"}">${user.is_active ? "启用" : "停用"}</span></td>
            <td>${user.task_count}</td>
            <td>${new Date(user.created_at).toLocaleString()}</td>
            <td>
              <div class="table-actions">
                <button class="ghost" data-action="tasks" data-user-id="${escapeHtml(user.id)}" type="button">任务</button>
                <button class="${user.is_active ? "ghost" : "secondary"}" data-action="active" data-user-id="${escapeHtml(user.id)}" data-active="${String(!user.is_active)}" type="button">
                  ${user.is_active ? "停用" : "启用"}
                </button>
              </div>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
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
  elements.tasksTable.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>任务</th>
          <th>状态</th>
          <th>上传</th>
          <th>发现</th>
          <th>创建时间</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        ${tasks.map((task) => `
          <tr>
            <td>
              <strong>${escapeHtml(task.task_name)}</strong><br />
              <span class="helper-text">${escapeHtml(task.id)}</span>
            </td>
            <td><span class="chip">${escapeHtml(task.status)}</span></td>
            <td>${escapeHtml(task.upload_name || "-")}</td>
            <td>${task.finding_count}</td>
            <td>${new Date(task.created_at).toLocaleString()}</td>
            <td>
              <div class="table-actions">
                <button class="ghost" data-action="view-task" data-task-id="${escapeHtml(task.id)}" type="button">查看</button>
                <button class="secondary" data-action="start-task" data-task-id="${escapeHtml(task.id)}" type="button">审计</button>
              </div>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderTaskDetail(task) {
  const findings = task.findings || [];
  const reportLinks = task.status === "completed"
    ? `
      <div class="report-actions">
        <a class="link-button ghost" href="${withAccessToken(`${apiBase()}/report/${task.id}?format=html`)}" download="report.html">HTML</a>
        <a class="link-button ghost" href="${withAccessToken(`${apiBase()}/report/${task.id}?format=markdown`)}" download="report.md">Markdown</a>
        <a class="link-button ghost" href="${withAccessToken(`${apiBase()}/report/${task.id}?format=json`)}" download="report.json">JSON</a>
      </div>
    `
    : "";

  elements.adminTaskDetail.className = "";
  elements.adminTaskDetail.innerHTML = `
    <div class="finding-header">
      <span class="chip">${escapeHtml(task.status)}</span>
      <span class="chip">${findings.length} 个发现</span>
      <span class="chip">${escapeHtml(task.id)}</span>
    </div>
    ${reportLinks}
    ${
      findings.length
        ? findings.map((item) => `
          <article class="finding-card">
            <div class="finding-header">
              <span class="severity-pill severity-${escapeHtml(String(item.severity || "").toLowerCase())}">${escapeHtml(item.severity)}</span>
              <span class="chip">${escapeHtml(item.owasp_label || "未分类")}</span>
              <span class="chip">${escapeHtml(item.source || "Unknown")}</span>
            </div>
            <h3>${escapeHtml(item.title)}</h3>
            <p>${escapeHtml(item.description)}</p>
            <div class="finding-meta">
              <span>位置: ${escapeHtml(item.file_path)}:${escapeHtml(item.line_number)}</span>
              <span>CWE: ${escapeHtml(item.cwe_id || "N/A")}</span>
              <span>CVSS: ${escapeHtml(item.cvss_score)}</span>
            </div>
          </article>
        `).join("")
        : `<div class="empty">该任务暂未产生漏洞详情。</div>`
    }
  `;
}

async function loadUsers() {
  setMessage("");
  state.users = await fetchJson(`${apiBase()}/admin/users`);
  renderUsers();
}

async function loadUserTasks(userId) {
  state.selectedUserId = userId;
  const user = state.users.find((item) => item.id === userId);
  const tasks = await fetchJson(`${apiBase()}/admin/users/${userId}/tasks`);
  renderTasks(tasks, user);
}

async function updateUser(userId, payload) {
  await fetchJson(`${apiBase()}/admin/users/${userId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  await loadUsers();
  if (state.selectedUserId === userId) {
    await loadUserTasks(userId);
  }
}

async function viewTask(taskId) {
  const task = await fetchJson(`${apiBase()}/audit/${taskId}`);
  renderTaskDetail(task);
}

async function startTask(taskId) {
  await fetchJson(`${apiBase()}/audit/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ task_id: taskId }),
  });
  await viewTask(taskId);
  if (state.selectedUserId) {
    await loadUserTasks(state.selectedUserId);
  }
}

function logout() {
  window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
  window.location.href = "./index.html";
}

async function init() {
  if (!state.accessToken) {
    showGate("请先登录管理员账号。");
    return;
  }

  try {
    state.currentUser = await fetchJson(`${apiBase()}/auth/me`);
    if (state.currentUser.role !== "admin") {
      showGate("当前账号不是管理员。");
      return;
    }
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
  if (!target) {
    return;
  }
  const userId = target.dataset.userId;
  if (target.dataset.action === "tasks") {
    loadUserTasks(userId).catch((error) => setMessage(error.message));
  }
  if (target.dataset.action === "active") {
    updateUser(userId, { is_active: target.dataset.active === "true" }).catch((error) => setMessage(error.message));
  }
});

elements.usersTable.addEventListener("change", (event) => {
  const target = event.target.closest("[data-action='role']");
  if (!target) {
    return;
  }
  updateUser(target.dataset.userId, { role: target.value }).catch((error) => setMessage(error.message));
});

elements.tasksTable.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) {
    return;
  }
  const taskId = target.dataset.taskId;
  if (target.dataset.action === "view-task") {
    viewTask(taskId).catch((error) => setMessage(error.message));
  }
  if (target.dataset.action === "start-task") {
    startTask(taskId).catch((error) => setMessage(error.message));
  }
});

init();
