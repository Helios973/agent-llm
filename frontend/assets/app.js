const runtimeConfig = window.AUDITPILOT_CONFIG || {};
const AUTH_TOKEN_STORAGE_KEY = "auditpilot.accessToken";

function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function normalizePath(value) {
  const path = String(value || "/api/v1").trim();
  const withSlash = path.startsWith("/") ? path : `/${path}`;
  return withSlash.length > 1 ? withSlash.replace(/\/+$/, "") : withSlash;
}

function configuredApiBase() {
  return normalizeBaseUrl(runtimeConfig.apiBaseUrl);
}

const OWASP_TOP10 = [
  {
    id: "A01:2021",
    name: "访问控制失效",
    summary: "接口或资源缺少授权校验，可能导致越权访问。",
  },
  {
    id: "A02:2021",
    name: "加密机制失效",
    summary: "敏感信息明文、硬编码密钥或弱保护方式会扩大泄露影响。",
  },
  {
    id: "A03:2021",
    name: "注入",
    summary: "未受信输入进入命令、查询或解释器上下文，可能触发注入。",
  },
  {
    id: "A04:2021",
    name: "不安全设计",
    summary: "安全控制设计不足，会在业务流程中留下系统性风险。",
  },
  {
    id: "A05:2021",
    name: "安全配置错误",
    summary: "调试开关、TLS 校验关闭或过度暴露会削弱防护能力。",
  },
  {
    id: "A06:2021",
    name: "易受攻击和过时的组件",
    summary: "已知脆弱组件会把公开漏洞直接带进系统。",
  },
  {
    id: "A07:2021",
    name: "身份认证失效",
    summary: "硬编码凭据、弱散列或认证保护不足会破坏身份验证。",
  },
  {
    id: "A08:2021",
    name: "软件和数据完整性失效",
    summary: "不安全反序列化或完整性校验缺失可能导致恶意对象执行。",
  },
  {
    id: "A09:2021",
    name: "安全日志和监控失效",
    summary: "关键异常和安全事件没有被记录，会延迟发现和响应。",
  },
  {
    id: "A10:2021",
    name: "服务端请求伪造",
    summary: "服务端代表用户访问任意地址时，可能被利用探测内网。",
  },
];

const state = {
  taskId: null,
  taskStatus: "未开始",
  progress: 0,
  socket: null,
  pollTimer: null,
  accessToken: window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY),
  currentUser: null,
  logs: ["[system] 等待任务开始..."],
};

const elements = {
  appShell: document.getElementById("appShell"),
  authScreen: document.getElementById("authScreen"),
  loginTabBtn: document.getElementById("loginTabBtn"),
  registerTabBtn: document.getElementById("registerTabBtn"),
  loginForm: document.getElementById("loginForm"),
  registerForm: document.getElementById("registerForm"),
  loginIdentifierInput: document.getElementById("loginIdentifierInput"),
  loginPasswordInput: document.getElementById("loginPasswordInput"),
  loginSubmitBtn: document.getElementById("loginSubmitBtn"),
  registerUsernameInput: document.getElementById("registerUsernameInput"),
  registerEmailInput: document.getElementById("registerEmailInput"),
  registerPasswordInput: document.getElementById("registerPasswordInput"),
  registerSubmitBtn: document.getElementById("registerSubmitBtn"),
  authMessage: document.getElementById("authMessage"),
  currentUsernameLabel: document.getElementById("currentUsernameLabel"),
  currentEmailLabel: document.getElementById("currentEmailLabel"),
  currentRoleLabel: document.getElementById("currentRoleLabel"),
  adminPageLink: document.getElementById("adminPageLink"),
  logoutBtn: document.getElementById("logoutBtn"),
  apiBaseInput: document.getElementById("apiBaseInput"),
  taskNameInput: document.getElementById("taskNameInput"),
  fileInput: document.getElementById("fileInput"),
  folderInput: document.getElementById("folderInput"),
  pickFolderBtn: document.getElementById("pickFolderBtn"),
  uploadSelectionText: document.getElementById("uploadSelectionText"),
  uploadBtn: document.getElementById("uploadBtn"),
  demoBtn: document.getElementById("demoBtn"),
  startBtn: document.getElementById("startBtn"),
  docsBtn: document.getElementById("docsBtn"),
  refreshHealthBtn: document.getElementById("refreshHealthBtn"),
  backendHealth: document.getElementById("backendHealth"),
  databaseHealth: document.getElementById("databaseHealth"),
  redisHealth: document.getElementById("redisHealth"),
  taskIdLabel: document.getElementById("taskIdLabel"),
  taskStatusLabel: document.getElementById("taskStatusLabel"),
  taskProgressLabel: document.getElementById("taskProgressLabel"),
  progressBar: document.getElementById("progressBar"),
  highCount: document.getElementById("highCount"),
  mediumCount: document.getElementById("mediumCount"),
  lowCount: document.getElementById("lowCount"),
  totalCount: document.getElementById("totalCount"),
  logBox: document.getElementById("logBox"),
  findingsWrap: document.getElementById("findingsWrap"),
  reportWrap: document.getElementById("reportWrap"),
  top10Grid: document.getElementById("top10Grid"),
};

elements.apiBaseInput.value = configuredApiBase();

function apiBase() {
  return normalizeBaseUrl(elements.apiBaseInput.value || configuredApiBase());
}

function requireApiBase(scope) {
  const base = apiBase();
  if (!base) {
    appendLog(`[${scope}] API base URL is not configured`);
  }
  return base;
}

function docsUrl() {
  const configuredDocsUrl = normalizeBaseUrl(runtimeConfig.docsUrl);
  if (configuredDocsUrl) {
    return configuredDocsUrl;
  }

  const base = apiBase();
  if (!base) {
    return "";
  }

  const apiPrefix = normalizePath(runtimeConfig.apiPrefix);
  return base.endsWith(apiPrefix)
    ? `${base.slice(0, -apiPrefix.length)}/docs`
    : `${base}/docs`;
}

function setAuthMessage(message, level = "error") {
  if (!message) {
    elements.authMessage.hidden = true;
    elements.authMessage.textContent = "";
    elements.authMessage.className = "auth-message";
    return;
  }

  elements.authMessage.hidden = false;
  elements.authMessage.textContent = message;
  elements.authMessage.className = `auth-message ${level}`;
}

function setAuthMode(mode) {
  const isLogin = mode === "login";
  elements.loginForm.hidden = !isLogin;
  elements.registerForm.hidden = isLogin;
  elements.loginTabBtn.classList.toggle("active", isLogin);
  elements.registerTabBtn.classList.toggle("active", !isLogin);
  setAuthMessage("");
}

function setSession(payload) {
  state.accessToken = payload.access_token;
  state.currentUser = payload.user;
  window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, state.accessToken);
}

function clearSession() {
  state.accessToken = null;
  state.currentUser = null;
  window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
}

function showApp() {
  elements.authScreen.hidden = true;
  elements.appShell.hidden = false;
  elements.currentUsernameLabel.textContent = state.currentUser?.username || "-";
  elements.currentEmailLabel.textContent = state.currentUser?.email || "-";
  elements.currentRoleLabel.textContent = state.currentUser?.role === "admin" ? "管理员" : "普通用户";
  elements.adminPageLink.hidden = state.currentUser?.role !== "admin";
  refreshHealth();
}

function showAuth(message = "") {
  stopPolling();
  closeSocket();
  elements.appShell.hidden = true;
  elements.authScreen.hidden = false;
  if (message) {
    setAuthMessage(message);
  } else {
    setAuthMessage("");
  }
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

function appendLog(message) {
  const stamped = `[${new Date().toLocaleTimeString()}] ${message}`;
  state.logs.push(stamped);
  state.logs = state.logs.slice(-180);
  elements.logBox.textContent = state.logs.join("\n");
  elements.logBox.scrollTop = elements.logBox.scrollHeight;
}

function selectedUploadName(file) {
  return file.webkitRelativePath || file.name || "unnamed";
}

function getSelectedUploads() {
  return [
    ...Array.from(elements.fileInput.files || []),
    ...Array.from(elements.folderInput.files || []),
  ];
}

function updateUploadSelectionText() {
  const files = Array.from(elements.fileInput.files || []);
  const folderFiles = Array.from(elements.folderInput.files || []);

  if (!files.length && !folderFiles.length) {
    elements.uploadSelectionText.textContent = "未选择文件或目录";
    return;
  }

  if (folderFiles.length && !files.length) {
    const rootName = folderFiles[0].webkitRelativePath?.split("/")[0] || "目录";
    elements.uploadSelectionText.textContent = `已选择目录 ${rootName}，共 ${folderFiles.length} 个文件`;
    return;
  }

  if (files.length && !folderFiles.length) {
    elements.uploadSelectionText.textContent =
      files.length === 1
        ? `已选择文件 ${selectedUploadName(files[0])}`
        : `已选择 ${files.length} 个文件`;
    return;
  }

  elements.uploadSelectionText.textContent = `已选择 ${files.length} 个文件和 ${folderFiles.length} 个目录文件`;
}

function clearUploadSelection() {
  elements.fileInput.value = "";
  elements.folderInput.value = "";
  updateUploadSelectionText();
}

function setBadge(element, text, level) {
  element.textContent = text;
  element.className = `badge ${level}`;
}

function setTaskMeta() {
  elements.taskIdLabel.textContent = state.taskId || "-";
  elements.taskStatusLabel.textContent = state.taskStatus;
  elements.taskProgressLabel.textContent = `${state.progress}%`;
  elements.progressBar.style.width = `${state.progress}%`;
  elements.startBtn.disabled = !state.taskId || state.taskStatus === "running";
}

function renderTop10(findings) {
  const counts = new Map();
  for (const item of findings) {
    if (item.owasp_id) {
      counts.set(item.owasp_id, (counts.get(item.owasp_id) || 0) + 1);
    }
  }

  elements.top10Grid.innerHTML = OWASP_TOP10.map((item) => {
    const count = counts.get(item.id) || 0;
    return `
      <article class="top10-card ${count ? "detected" : ""}">
        <div class="chip">${item.id}</div>
        <h3>${escapeHtml(item.name)}</h3>
        <p>${escapeHtml(item.summary)}</p>
        <div class="count">${count}</div>
      </article>
    `;
  }).join("");
}

function updateRiskStats(findings) {
  const counters = { HIGH: 0, MEDIUM: 0, LOW: 0, CRITICAL: 0 };
  for (const item of findings) {
    const key = String(item.severity || "").toUpperCase();
    if (counters[key] !== undefined) {
      counters[key] += 1;
    }
  }
  elements.highCount.textContent = counters.HIGH + counters.CRITICAL;
  elements.mediumCount.textContent = counters.MEDIUM;
  elements.lowCount.textContent = counters.LOW;
  elements.totalCount.textContent = findings.length;
}

function renderFindings(findings) {
  updateRiskStats(findings);
  renderTop10(findings);

  if (!findings.length) {
    elements.findingsWrap.className = "empty";
    elements.findingsWrap.innerHTML = "当前任务还没有可展示的漏洞详情。";
    return;
  }

  const cards = findings.map((item) => {
    const severity = String(item.severity || "").toLowerCase();
    const reproduction = (item.reproduction_steps || [])
      .map((step) => `<li>${escapeHtml(step)}</li>`)
      .join("");
    const references = (item.references || [])
      .map((link) => `<li><a href="${escapeHtml(link)}" target="_blank" rel="noreferrer">${escapeHtml(link)}</a></li>`)
      .join("");
    const relatedFiles = (item.related_files || [])
      .map((path) => `<li>${escapeHtml(path)}</li>`)
      .join("");
    const cves = (item.related_cves || [])
      .map((cve) => `<li>${escapeHtml(cve)}</li>`)
      .join("");
    const ctfScenarios = (item.ctf_scenarios || [])
      .map((scenario) => `<li>${escapeHtml(scenario)}</li>`)
      .join("");

    return `
      <article class="finding-card">
        <div class="finding-header">
          <span class="severity-pill severity-${severity}">${escapeHtml(item.severity)}</span>
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
        <div class="detail-grid">
          <section class="detail-block">
            <h4>影响</h4>
            <p>${escapeHtml(item.impact || "待人工确认")}</p>
          </section>
          <section class="detail-block">
            <h4>修复建议</h4>
            <p>${escapeHtml(item.recommendation || "待补充")}</p>
          </section>
          <section class="detail-block">
            <h4>证据</h4>
            <p>${escapeHtml(item.evidence || "未提供额外证据")}</p>
          </section>
          <section class="detail-block">
            <h4>关联文件</h4>
            <ul>${relatedFiles || "<li>无</li>"}</ul>
          </section>
          <section class="detail-block">
            <h4>关联 CVE</h4>
            <ul>${cves || "<li>通用代码缺陷，需结合具体组件版本进一步匹配 CVE。</li>"}</ul>
          </section>
          <section class="detail-block">
            <h4>复现步骤</h4>
            <ul>${reproduction || "<li>待人工进一步验证。</li>"}</ul>
          </section>
        </div>
        <div class="detail-block">
          <h4>CTF 常见利用点</h4>
          <ul>${ctfScenarios || "<li>该问题在 CTF 中通常会和其他信息泄露或提权链组合利用。</li>"}</ul>
        </div>
        ${
          item.code_snippet
            ? `<div class="detail-block"><h4>代码片段</h4><pre class="code-block">${escapeHtml(item.code_snippet)}</pre></div>`
            : ""
        }
        ${
          references
            ? `<div class="detail-block"><h4>参考资料</h4><ul class="reference-list">${references}</ul></div>`
            : ""
        }
      </article>
    `;
  }).join("");

  elements.findingsWrap.className = "findings-grid";
  elements.findingsWrap.innerHTML = cards;
}

function renderReports(taskId) {
  const base = requireApiBase("report");
  if (!base) {
    return;
  }
  const htmlUrl = withAccessToken(`${base}/report/${taskId}?format=html`);
  const markdownUrl = withAccessToken(`${base}/report/${taskId}?format=markdown`);
  const jsonUrl = withAccessToken(`${base}/report/${taskId}?format=json`);

  elements.reportWrap.hidden = false;
  elements.reportWrap.className = "report-actions";
  elements.reportWrap.innerHTML = `
    <a class="link-button ghost" href="${htmlUrl}" download="report.html">下载 HTML 报告</a>
    <a class="link-button ghost" href="${markdownUrl}" download="report.md">下载 Markdown</a>
    <a class="link-button ghost" href="${jsonUrl}" download="report.json">下载 JSON</a>
  `;
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function closeSocket() {
  if (state.socket) {
    state.socket.close();
    state.socket = null;
  }
}

async function fetchJson(url, options = {}) {
  const { auth = true, headers, ...rest } = options;
  const requestHeaders = new Headers(headers || {});
  if (auth && state.accessToken) {
    requestHeaders.set("Authorization", `Bearer ${state.accessToken}`);
  }

  const response = await fetch(url, {
    ...rest,
    headers: requestHeaders,
  });
  if (response.status === 401 && auth) {
    clearSession();
    showAuth("登录已过期，请重新登录。");
  }
  if (!response.ok) {
    const fallback = `${response.status} ${response.statusText}`;
    let detail = fallback;
    try {
      const payload = await response.json();
      detail = payload.detail || JSON.stringify(payload);
    } catch {
      detail = (await response.text()) || fallback;
    }
    throw new Error(detail);
  }
  return response.json();
}

async function refreshHealth() {
  const base = requireApiBase("health");
  if (!base) {
    return;
  }

  try {
    const data = await fetchJson(`${base}/health`);
    setBadge(elements.backendHealth, data.app, "ok");
    setBadge(elements.databaseHealth, data.database, data.database === "ok" ? "ok" : "error");
    setBadge(elements.redisHealth, data.redis, data.redis === "ok" ? "ok" : "error");
    appendLog("[health] 后端连接正常");
  } catch (error) {
    setBadge(elements.backendHealth, "连接失败", "error");
    setBadge(elements.databaseHealth, "未知", "warn");
    setBadge(elements.redisHealth, "未知", "warn");
    appendLog(`[health] ${error.message}`);
  }
}

async function restoreSession() {
  if (!state.accessToken) {
    showAuth();
    return;
  }

  const base = requireApiBase("auth");
  if (!base) {
    showAuth("API base URL is not configured");
    return;
  }

  try {
    state.currentUser = await fetchJson(`${base}/auth/me`);
    showApp();
  } catch {
    clearSession();
    showAuth();
  }
}

async function submitLogin(event) {
  event.preventDefault();
  const base = requireApiBase("auth");
  if (!base) {
    return;
  }

  try {
    elements.loginSubmitBtn.disabled = true;
    setAuthMessage("");
    const payload = await fetchJson(`${base}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username_or_email: elements.loginIdentifierInput.value.trim(),
        password: elements.loginPasswordInput.value,
      }),
      auth: false,
    });
    setSession(payload);
    elements.loginPasswordInput.value = "";
    showApp();
  } catch (error) {
    setAuthMessage(error.message);
  } finally {
    elements.loginSubmitBtn.disabled = false;
  }
}

async function submitRegister(event) {
  event.preventDefault();
  const base = requireApiBase("auth");
  if (!base) {
    return;
  }

  try {
    elements.registerSubmitBtn.disabled = true;
    setAuthMessage("");
    const payload = await fetchJson(`${base}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: elements.registerUsernameInput.value.trim(),
        email: elements.registerEmailInput.value.trim(),
        password: elements.registerPasswordInput.value,
      }),
      auth: false,
    });
    setSession(payload);
    elements.registerPasswordInput.value = "";
    showApp();
  } catch (error) {
    setAuthMessage(error.message);
  } finally {
    elements.registerSubmitBtn.disabled = false;
  }
}

function logout() {
  clearSession();
  state.taskId = null;
  state.taskStatus = "未开始";
  state.progress = 0;
  state.logs = ["[system] 等待任务开始..."];
  elements.logBox.textContent = state.logs.join("\n");
  elements.reportWrap.hidden = true;
  elements.reportWrap.className = "";
  elements.reportWrap.innerHTML = "";
  setTaskMeta();
  renderFindings([]);
  showAuth();
}

function rememberTask(taskId, status) {
  state.taskId = taskId;
  state.taskStatus = status;
  state.progress = 0;
  renderFindings([]);
  elements.reportWrap.hidden = true;
  elements.reportWrap.className = "";
  elements.reportWrap.innerHTML = "";
  setTaskMeta();
}

async function uploadFile() {
  const files = getSelectedUploads();
  if (!files.length) {
    appendLog("[upload] 请先选择要上传的任意文件、压缩包或目录");
    return;
  }

  const form = new FormData();
  for (const file of files) {
    form.append("files", file, selectedUploadName(file));
  }
  form.append("task_name", elements.taskNameInput.value.trim() || (files.length === 1 ? files[0].name : `${files.length}-files-audit`));

  try {
    elements.uploadBtn.disabled = true;
    const base = requireApiBase("upload");
    if (!base) {
      return;
    }
    const data = await fetchJson(`${base}/upload`, {
      method: "POST",
      body: form,
    });
    rememberTask(data.task_id, data.status);
    appendLog(`[upload] 已上传 ${data.upload_count || files.length} 个文件，task_id=${data.task_id}`);
    clearUploadSelection();
  } catch (error) {
    appendLog(`[upload] ${error.message}`);
  } finally {
    elements.uploadBtn.disabled = false;
  }
}

async function uploadDemoProject() {
  const form = new FormData();
  form.append("task_name", elements.taskNameInput.value.trim() || "demo-audit");

  try {
    elements.demoBtn.disabled = true;
    const base = requireApiBase("demo");
    if (!base) {
      return;
    }
    const data = await fetchJson(`${base}/upload/demo`, {
      method: "POST",
      body: form,
    });
    rememberTask(data.task_id, data.status);
    appendLog(`[demo] 已导入示例项目 ${data.upload_name}，task_id=${data.task_id}`);
  } catch (error) {
    appendLog(`[demo] ${error.message}`);
  } finally {
    elements.demoBtn.disabled = false;
  }
}

function connectSocket(taskId) {
  closeSocket();
  const base = requireApiBase("ws");
  if (!base) {
    return;
  }
  const wsUrl = withAccessToken(base.replace(/^http/i, "ws") + `/ws/audit/${taskId}`);
  state.socket = new WebSocket(wsUrl);

  state.socket.onopen = () => appendLog("[ws] 已连接实时事件通道");
  state.socket.onclose = () => appendLog("[ws] 实时事件通道已关闭");
  state.socket.onerror = () => appendLog("[ws] WebSocket 连接出现异常");
  state.socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.event === "progress" && typeof payload.value === "number") {
        state.progress = payload.value;
        if (payload.message) {
          appendLog(`[progress] ${payload.value}% ${payload.message}`);
        }
        setTaskMeta();
        return;
      }
      if (payload.event === "agent") {
        appendLog(`[agent] ${payload.agent} -> ${payload.status} ${payload.message || ""}`.trim());
        return;
      }
      if (payload.message) {
        appendLog(`[event] ${payload.message}`);
      }
    } catch (error) {
      appendLog(`[ws] 事件解析失败: ${error.message}`);
    }
  };
}

async function loadTaskResult() {
  if (!state.taskId) {
    return;
  }

  try {
    const base = requireApiBase("result");
    if (!base) {
      return;
    }
    const task = await fetchJson(`${base}/audit/${state.taskId}`);
    state.taskStatus = task.status;
    if (task.status === "completed") {
      state.progress = 100;
    }
    setTaskMeta();
    renderFindings(task.findings || []);

    if (task.status === "completed") {
      renderReports(task.id);
      stopPolling();
    } else if (task.status === "failed") {
      stopPolling();
    }
  } catch (error) {
    appendLog(`[result] ${error.message}`);
    stopPolling();
  }
}

function beginPolling() {
  stopPolling();
  state.pollTimer = setInterval(loadTaskResult, 1800);
}

async function startAudit() {
  if (!state.taskId) {
    appendLog("[audit] 请先上传文件或导入示例项目");
    return;
  }

  try {
    elements.startBtn.disabled = true;
    const base = requireApiBase("audit");
    if (!base) {
      return;
    }
    const payload = await fetchJson(`${base}/audit/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ task_id: state.taskId }),
    });
    state.taskStatus = payload.status;
    state.progress = 5;
    setTaskMeta();
    appendLog(`[audit] 审计已启动，task_id=${payload.task_id}`);
    connectSocket(payload.task_id);
    beginPolling();
    await loadTaskResult();
  } catch (error) {
    appendLog(`[audit] ${error.message}`);
  } finally {
    setTaskMeta();
  }
}

function openDocs() {
  const target = docsUrl();
  if (!target) {
    appendLog("[docs] API base URL is not configured");
    return;
  }
  window.open(target, "_blank", "noopener,noreferrer");
}

elements.loginTabBtn.addEventListener("click", () => setAuthMode("login"));
elements.registerTabBtn.addEventListener("click", () => setAuthMode("register"));
elements.loginForm.addEventListener("submit", submitLogin);
elements.registerForm.addEventListener("submit", submitRegister);
elements.logoutBtn.addEventListener("click", logout);
elements.pickFolderBtn.addEventListener("click", () => elements.folderInput.click());
elements.fileInput.addEventListener("change", updateUploadSelectionText);
elements.folderInput.addEventListener("change", updateUploadSelectionText);
elements.uploadBtn.addEventListener("click", uploadFile);
elements.demoBtn.addEventListener("click", uploadDemoProject);
elements.startBtn.addEventListener("click", startAudit);
elements.docsBtn.addEventListener("click", openDocs);
elements.refreshHealthBtn.addEventListener("click", refreshHealth);

window.addEventListener("beforeunload", () => {
  stopPolling();
  closeSocket();
});

setTaskMeta();
renderTop10([]);
updateUploadSelectionText();
restoreSession();
