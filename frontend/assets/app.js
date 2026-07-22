import {
  AUTH_TOKEN_STORAGE_KEY,
  appendAccessToken,
  createJsonClient,
  escapeHtml,
  initials,
  normalizeBaseUrl,
  normalizePath,
} from "./core.js";

const runtimeConfig = window.AUDITPILOT_CONFIG || {};
const REGISTER_SLIDER_TEXT = {
  idle: "\u8bf7\u62d6\u52a8\u6ed1\u5757\u5b8c\u6210\u4eba\u673a\u9a8c\u8bc1",
  active: "\u7ee7\u7eed\u62d6\u52a8\u5230\u6700\u53f3\u4fa7",
  verifying: "\u6b63\u5728\u63d0\u4ea4\u540e\u7aef\u9a8c\u8bc1",
  failed: "\u9a8c\u8bc1\u672a\u5b8c\u6210\uff0c\u8bf7\u91cd\u8bd5",
  success: "\u9a8c\u8bc1\u901a\u8fc7\uff0c\u53ef\u4ee5\u521b\u5efa\u8d26\u53f7",
  hint: "\u6ce8\u518c\u524d\u9700\u5148\u901a\u8fc7\u6ed1\u52a8\u9a8c\u8bc1",
  reset: "\u5df2\u91cd\u7f6e\u6ed1\u5757\uff0c\u8bf7\u91cd\u65b0\u9a8c\u8bc1",
};
const REGISTER_SLIDER_KEYBOARD_STEP = 12;
const PROVIDER_DEFAULTS = {
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  deepseek: { baseUrl: "https://api.deepseek.com", model: "deepseek-chat" },
  "openai-compatible": { baseUrl: "", model: "" },
};

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
  registerSlider: {
    challengeToken: "",
    dragging: false,
    offset: 0,
    pointerId: null,
    proofToken: "",
    startOffset: 0,
    startX: 0,
    status: "idle",
    verified: false,
    verifying: false,
  },
  taskId: null,
  taskStatus: "未开始",
  progress: 0,
  socket: null,
  pollTimer: null,
  accessToken: window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY),
  currentUser: null,
  llmApiKeyConfigured: false,
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
  registerSliderCaptcha: document.getElementById("registerSliderCaptcha"),
  registerSliderTrack: document.getElementById("registerSliderTrack"),
  registerSliderFill: document.getElementById("registerSliderFill"),
  registerSliderLabel: document.getElementById("registerSliderLabel"),
  registerSliderThumb: document.getElementById("registerSliderThumb"),
  registerVerifyHint: document.getElementById("registerVerifyHint"),
  registerVerifyResetBtn: document.getElementById("registerVerifyResetBtn"),
  registerSubmitBtn: document.getElementById("registerSubmitBtn"),
  authMessage: document.getElementById("authMessage"),
  currentUsernameLabel: document.getElementById("currentUsernameLabel"),
  currentEmailLabel: document.getElementById("currentEmailLabel"),
  currentRoleLabel: document.getElementById("currentRoleLabel"),
  currentUserAvatar: document.getElementById("currentUserAvatar"),
  adminPageLink: document.getElementById("adminPageLink"),
  logoutBtn: document.getElementById("logoutBtn"),
  llmConfigForm: document.getElementById("llmConfigForm"),
  llmProviderSelect: document.getElementById("llmProviderSelect"),
  llmBaseUrlInput: document.getElementById("llmBaseUrlInput"),
  llmModelInput: document.getElementById("llmModelInput"),
  llmModelOptions: document.getElementById("llmModelOptions"),
  llmApiKeyInput: document.getElementById("llmApiKeyInput"),
  saveLlmConfigBtn: document.getElementById("saveLlmConfigBtn"),
  discoverLlmModelsBtn: document.getElementById("discoverLlmModelsBtn"),
  clearLlmApiKeyBtn: document.getElementById("clearLlmApiKeyBtn"),
  llmConfigStatus: document.getElementById("llmConfigStatus"),
  llmConfigMessage: document.getElementById("llmConfigMessage"),
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

function setRegisterSubmitState(isSubmitting = false) {
  if (!elements.registerSubmitBtn) {
    return;
  }
  elements.registerSubmitBtn.disabled = (
    isSubmitting
    || state.registerSlider.verifying
    || !state.registerSlider.verified
    || !state.registerSlider.proofToken
  );
}

function getRegisterSliderMaxOffset() {
  const trackWidth = elements.registerSliderTrack?.clientWidth || 0;
  const thumbWidth = elements.registerSliderThumb?.offsetWidth || 0;
  return Math.max(trackWidth - thumbWidth - 10, 0);
}

function releaseRegisterSliderPointer() {
  const thumb = elements.registerSliderThumb;
  if (!thumb || state.registerSlider.pointerId === null) {
    return;
  }

  try {
    thumb.releasePointerCapture(state.registerSlider.pointerId);
  } catch (error) {
    // Pointer capture can already be released when the gesture ends naturally.
  }
}

async function fetchRegisterHumanCheckChallenge(force = false) {
  if (state.registerSlider.challengeToken && !force) {
    return true;
  }

  const base = requireApiBase("human-check");
  if (!base) {
    return false;
  }

  try {
    const payload = await fetchJson(`${base}/auth/human-check/challenge`, {
      method: "POST",
      auth: false,
    });
    state.registerSlider.challengeToken = payload.challenge_token;
    state.registerSlider.proofToken = "";
    return true;
  } catch (error) {
    state.registerSlider.challengeToken = "";
    state.registerSlider.proofToken = "";
    setAuthMessage(error.message);
    return false;
  }
}

function renderRegisterSlider() {
  const captcha = elements.registerSliderCaptcha;
  const track = elements.registerSliderTrack;
  const fill = elements.registerSliderFill;
  const label = elements.registerSliderLabel;
  const thumb = elements.registerSliderThumb;
  const hint = elements.registerVerifyHint;
  if (!captcha || !track || !fill || !label || !thumb || !hint) {
    return;
  }

  const maxOffset = getRegisterSliderMaxOffset();
  if (state.registerSlider.verified) {
    state.registerSlider.offset = maxOffset;
    state.registerSlider.status = "verified";
  } else {
    state.registerSlider.offset = Math.min(Math.max(state.registerSlider.offset, 0), maxOffset);
  }

  const fillWidth = Math.min(track.clientWidth, state.registerSlider.offset + thumb.offsetWidth + 5);
  const progress = maxOffset > 0 ? Math.round((state.registerSlider.offset / maxOffset) * 100) : 0;

  captcha.dataset.status = state.registerSlider.status;
  fill.style.width = `${fillWidth}px`;
  thumb.style.transform = `translateX(${state.registerSlider.offset}px)`;
  thumb.classList.toggle("is-dragging", state.registerSlider.dragging);
  thumb.setAttribute("aria-valuenow", String(progress));
  thumb.setAttribute(
    "aria-valuetext",
    state.registerSlider.verified ? REGISTER_SLIDER_TEXT.success : `${progress}%`,
  );

  if (state.registerSlider.verifying) {
    label.textContent = REGISTER_SLIDER_TEXT.verifying;
    hint.textContent = REGISTER_SLIDER_TEXT.verifying;
  } else if (state.registerSlider.status === "verified") {
    label.textContent = REGISTER_SLIDER_TEXT.success;
    hint.textContent = REGISTER_SLIDER_TEXT.success;
  } else if (state.registerSlider.status === "failed") {
    label.textContent = REGISTER_SLIDER_TEXT.failed;
    hint.textContent = REGISTER_SLIDER_TEXT.reset;
  } else if (state.registerSlider.status === "active") {
    label.textContent = REGISTER_SLIDER_TEXT.active;
    hint.textContent = REGISTER_SLIDER_TEXT.hint;
  } else {
    label.textContent = REGISTER_SLIDER_TEXT.idle;
    hint.textContent = REGISTER_SLIDER_TEXT.hint;
  }

  setRegisterSubmitState(false);
}

function resetRegisterSlider(status = "idle") {
  releaseRegisterSliderPointer();
  state.registerSlider.challengeToken = "";
  state.registerSlider.dragging = false;
  state.registerSlider.offset = 0;
  state.registerSlider.pointerId = null;
  state.registerSlider.proofToken = "";
  state.registerSlider.startOffset = 0;
  state.registerSlider.startX = 0;
  state.registerSlider.status = status;
  state.registerSlider.verified = false;
  state.registerSlider.verifying = false;
  renderRegisterSlider();
}

async function completeRegisterSlider() {
  const base = requireApiBase("human-check");
  if (!base) {
    resetRegisterSlider("failed");
    return;
  }
  const challengeReady = await fetchRegisterHumanCheckChallenge();
  if (!challengeReady || !state.registerSlider.challengeToken) {
    resetRegisterSlider("failed");
    return;
  }

  state.registerSlider.dragging = false;
  state.registerSlider.pointerId = null;
  state.registerSlider.startOffset = 0;
  state.registerSlider.startX = 0;
  state.registerSlider.status = "active";
  state.registerSlider.verifying = true;
  renderRegisterSlider();

  try {
    const payload = await fetchJson(`${base}/auth/human-check/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_token: state.registerSlider.challengeToken,
      }),
      auth: false,
    });
    state.registerSlider.proofToken = payload.proof_token;
    state.registerSlider.status = "verified";
    state.registerSlider.verified = true;
    state.registerSlider.offset = getRegisterSliderMaxOffset();
  } catch (error) {
    state.registerSlider.challengeToken = "";
    state.registerSlider.proofToken = "";
    state.registerSlider.status = "failed";
    state.registerSlider.verified = false;
    state.registerSlider.offset = 0;
    setAuthMessage(error.message);
    await fetchRegisterHumanCheckChallenge(true);
  } finally {
    state.registerSlider.verifying = false;
    renderRegisterSlider();
  }
}

function syncRegisterSliderLayout() {
  if (state.registerSlider.verified) {
    state.registerSlider.offset = getRegisterSliderMaxOffset();
  }
  renderRegisterSlider();
}

function handleRegisterSliderPointerDown(event) {
  if (state.registerSlider.verified || state.registerSlider.verifying) {
    return;
  }
  if (typeof event.button === "number" && event.button !== 0) {
    return;
  }
  if (!state.registerSlider.challengeToken) {
    setAuthMessage("\u6b63\u5728\u51c6\u5907\u4eba\u673a\u9a8c\u8bc1\uff0c\u8bf7\u7a0d\u540e\u91cd\u8bd5");
    void fetchRegisterHumanCheckChallenge(true);
    event.preventDefault();
    return;
  }

  state.registerSlider.dragging = true;
  state.registerSlider.pointerId = event.pointerId;
  state.registerSlider.startOffset = state.registerSlider.offset;
  state.registerSlider.startX = event.clientX;
  state.registerSlider.status = "active";
  elements.registerSliderThumb?.setPointerCapture?.(event.pointerId);
  renderRegisterSlider();
  event.preventDefault();
}

function handleRegisterSliderPointerMove(event) {
  if (!state.registerSlider.dragging || state.registerSlider.pointerId !== event.pointerId) {
    return;
  }

  const delta = event.clientX - state.registerSlider.startX;
  state.registerSlider.offset = state.registerSlider.startOffset + delta;
  renderRegisterSlider();
}

async function finishRegisterSliderGesture() {
  const successThreshold = Math.max(getRegisterSliderMaxOffset() - 6, 0);
  if (state.registerSlider.offset >= successThreshold) {
    await completeRegisterSlider();
    return;
  }
  resetRegisterSlider("failed");
  await fetchRegisterHumanCheckChallenge(true);
}

function handleRegisterSliderPointerUp(event) {
  if (state.registerSlider.pointerId !== event.pointerId) {
    return;
  }

  releaseRegisterSliderPointer();
  void finishRegisterSliderGesture();
}

function handleRegisterSliderPointerCancel(event) {
  if (state.registerSlider.pointerId !== event.pointerId) {
    return;
  }

  releaseRegisterSliderPointer();
  resetRegisterSlider("idle");
}

function handleRegisterSliderKeyDown(event) {
  if (state.registerSlider.verified && !["Home", "Escape"].includes(event.key)) {
    return;
  }
  if (!state.registerSlider.challengeToken && !["Home", "Escape"].includes(event.key)) {
    setAuthMessage("\u6b63\u5728\u51c6\u5907\u4eba\u673a\u9a8c\u8bc1\uff0c\u8bf7\u7a0d\u540e\u91cd\u8bd5");
    void fetchRegisterHumanCheckChallenge(true);
    event.preventDefault();
    return;
  }

  const maxOffset = getRegisterSliderMaxOffset();
  if (event.key === "End") {
    event.preventDefault();
    void completeRegisterSlider();
    return;
  }
  if (event.key === "Home" || event.key === "Escape") {
    event.preventDefault();
    resetRegisterSlider("idle");
    void fetchRegisterHumanCheckChallenge(true);
    return;
  }
  if (!["ArrowRight", "ArrowUp", "ArrowLeft", "ArrowDown"].includes(event.key)) {
    return;
  }

  event.preventDefault();
  state.registerSlider.status = "active";
  if (event.key === "ArrowRight" || event.key === "ArrowUp") {
    state.registerSlider.offset = Math.min(
      state.registerSlider.offset + REGISTER_SLIDER_KEYBOARD_STEP,
      maxOffset,
    );
  } else {
    state.registerSlider.offset = Math.max(
      state.registerSlider.offset - REGISTER_SLIDER_KEYBOARD_STEP,
      0,
    );
  }

  if (state.registerSlider.offset >= Math.max(maxOffset - 1, 0) && maxOffset > 0) {
    void completeRegisterSlider();
    return;
  }

  renderRegisterSlider();
}

function handleRegisterFormInput() {
  if (state.registerSlider.dragging || state.registerSlider.verifying) {
    return;
  }
  if (state.registerSlider.verified) {
    resetRegisterSlider("idle");
    void fetchRegisterHumanCheckChallenge(true);
  }
}

function setAuthMode(mode) {
  const isLogin = mode === "login";
  elements.loginForm.hidden = !isLogin;
  elements.registerForm.hidden = isLogin;
  elements.loginTabBtn.classList.toggle("active", isLogin);
  elements.registerTabBtn.classList.toggle("active", !isLogin);
  elements.loginTabBtn.setAttribute("aria-selected", String(isLogin));
  elements.registerTabBtn.setAttribute("aria-selected", String(!isLogin));
  resetRegisterSlider();
  if (!isLogin) {
    void fetchRegisterHumanCheckChallenge(true);
  }
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
  elements.currentUserAvatar.textContent = initials(state.currentUser?.username);
  elements.adminPageLink.hidden = state.currentUser?.role !== "admin";
  refreshHealth();
  void loadLlmConfig();
}

function setLlmConfigMessage(message = "", level = "error") {
  if (!message) {
    elements.llmConfigMessage.hidden = true;
    elements.llmConfigMessage.textContent = "";
    elements.llmConfigMessage.className = "auth-message";
    return;
  }
  elements.llmConfigMessage.hidden = false;
  elements.llmConfigMessage.textContent = message;
  elements.llmConfigMessage.className = `auth-message ${level}`;
}

function setLlmConfigStatus(config) {
  const configured = Boolean(config?.api_key_configured);
  state.llmApiKeyConfigured = configured;
  elements.llmConfigStatus.textContent = configured ? "Key 已配置" : "未配置";
  elements.llmConfigStatus.className = `badge ${configured ? "ok" : "neutral"}`;
  elements.clearLlmApiKeyBtn.disabled = !configured;
}

function renderLlmModelOptions(models) {
  elements.llmModelOptions.innerHTML = models
    .map((model) => `<option value="${escapeHtml(model)}"></option>`)
    .join("");
}

function applyProviderDefaults({ force = false } = {}) {
  const defaults = PROVIDER_DEFAULTS[elements.llmProviderSelect.value] || PROVIDER_DEFAULTS["openai-compatible"];
  if (force || !elements.llmBaseUrlInput.value.trim()) elements.llmBaseUrlInput.value = defaults.baseUrl;
  if (force || !elements.llmModelInput.value.trim()) elements.llmModelInput.value = defaults.model;
}

async function loadLlmConfig() {
  const base = requireApiBase("LLM configuration");
  if (!base) return;
  try {
    const config = await fetchJson(`${base}/auth/llm-config`);
    elements.llmProviderSelect.value = config.provider || "openai";
    elements.llmBaseUrlInput.value = config.base_url || "";
    elements.llmModelInput.value = config.model || "";
    elements.llmApiKeyInput.value = "";
    applyProviderDefaults();
    setLlmConfigStatus(config);
    setLlmConfigMessage("");
    if (config.api_key_configured) {
      await discoverLlmModels();
    }
  } catch (error) {
    setLlmConfigMessage(error.message);
  }
}

async function discoverLlmModels({ silent = false } = {}) {
  const base = requireApiBase("model discovery");
  if (!base) return [];
  const baseUrl = elements.llmBaseUrlInput.value.trim();
  const apiKey = elements.llmApiKeyInput.value.trim();
  if (!baseUrl) {
    if (!silent) setLlmConfigMessage("请先填写 API Base URL。");
    return [];
  }
  if (!apiKey && !state.llmApiKeyConfigured) {
    if (!silent) setLlmConfigMessage("请先填写 API Key。");
    return [];
  }

  const originalLabel = elements.discoverLlmModelsBtn.textContent;
  try {
    elements.discoverLlmModelsBtn.disabled = true;
    elements.discoverLlmModelsBtn.textContent = "识别中…";
    const payload = await fetchJson(`${base}/auth/llm-models/discover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: elements.llmProviderSelect.value,
        base_url: baseUrl,
        ...(apiKey ? { api_key: apiKey } : {}),
      }),
    });
    const models = payload.models || [];
    renderLlmModelOptions(models);
    if (!elements.llmModelInput.value.trim() && models.length) {
      elements.llmModelInput.value = models[0];
    }
    if (!silent) setLlmConfigMessage(`已识别 ${models.length} 个可用模型，可在模型名称中选择。`, "ok");
    return models;
  } catch (error) {
    renderLlmModelOptions([]);
    if (!silent) setLlmConfigMessage(`模型识别失败：${error.message}`);
    return [];
  } finally {
    elements.discoverLlmModelsBtn.disabled = false;
    elements.discoverLlmModelsBtn.textContent = originalLabel;
  }
}

async function saveLlmConfig(event) {
  event.preventDefault();
  const base = requireApiBase("LLM configuration");
  if (!base) return;
  const originalLabel = elements.saveLlmConfigBtn.textContent;
  try {
    elements.saveLlmConfigBtn.disabled = true;
    const apiKey = elements.llmApiKeyInput.value.trim();
    const config = await fetchJson(`${base}/auth/llm-config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: elements.llmProviderSelect.value,
        base_url: elements.llmBaseUrlInput.value.trim(),
        model: elements.llmModelInput.value.trim(),
        ...(apiKey ? { api_key: apiKey } : {}),
      }),
    });
    elements.llmApiKeyInput.value = "";
    setLlmConfigStatus(config);
    const models = await discoverLlmModels({ silent: true });
    setLlmConfigMessage(`API 配置已保存${models.length ? `，已识别 ${models.length} 个可用模型` : ""}。`, "ok");
  } catch (error) {
    setLlmConfigMessage(error.message);
  } finally {
    elements.saveLlmConfigBtn.disabled = false;
    elements.saveLlmConfigBtn.textContent = originalLabel;
  }
}

async function clearLlmApiKey() {
  const base = requireApiBase("LLM configuration");
  if (!base) return;
  try {
    const config = await fetchJson(`${base}/auth/llm-config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: elements.llmProviderSelect.value,
        base_url: elements.llmBaseUrlInput.value.trim(),
        model: elements.llmModelInput.value.trim(),
        clear_api_key: true,
      }),
    });
    setLlmConfigStatus(config);
    renderLlmModelOptions([]);
    setLlmConfigMessage("已删除保存的 API Key。", "ok");
  } catch (error) {
    setLlmConfigMessage(error.message);
  }
}

function showAuth(message = "") {
  stopPolling();
  closeSocket();
  elements.appShell.hidden = true;
  elements.authScreen.hidden = false;
  resetRegisterSlider();
  void fetchRegisterHumanCheckChallenge(true);
  if (message) {
    setAuthMessage(message);
  } else {
    setAuthMessage("");
  }
}

function withAccessToken(url) {
  return appendAccessToken(url, state.accessToken);
}

function appendLog(message) {
  const stamped = `[${new Date().toLocaleTimeString()}] ${message}`;
  state.logs.push(stamped);
  state.logs = state.logs.slice(-180);
  elements.logBox.textContent = state.logs.join("\n");
  elements.logBox.scrollTop = elements.logBox.scrollHeight;
}

function setText(element, value) {
  if (element) {
    element.textContent = value;
  }
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
    setText(elements.uploadSelectionText, "未选择文件或目录");
    return;
  }

  if (folderFiles.length && !files.length) {
    const rootName = folderFiles[0].webkitRelativePath?.split("/")[0] || "目录";
    setText(elements.uploadSelectionText, `已选择目录 ${rootName}，共 ${folderFiles.length} 个文件`);
    return;
  }

  if (files.length && !folderFiles.length) {
    setText(
      elements.uploadSelectionText,
      files.length === 1
        ? `已选择文件 ${selectedUploadName(files[0])}`
        : `已选择 ${files.length} 个文件`,
    );
    return;
  }

  setText(elements.uploadSelectionText, `已选择 ${files.length} 个文件和 ${folderFiles.length} 个目录文件`);
}

function clearUploadSelection() {
  elements.fileInput.value = "";
  elements.folderInput.value = "";
  updateUploadSelectionText();
}

function setBadge(element, text, level) {
  if (!element) {
    return;
  }
  element.textContent = text;
  element.className = `badge ${level}`;
}

function setTaskMeta() {
  elements.taskIdLabel.textContent = state.taskId || "-";
  elements.taskStatusLabel.textContent = state.taskStatus;
  elements.taskProgressLabel.textContent = `${state.progress}%`;
  elements.progressBar.style.width = `${state.progress}%`;
  elements.progressBar.parentElement?.setAttribute("aria-valuenow", String(state.progress));
  elements.startBtn.disabled = !state.taskId || state.taskStatus === "running";
  elements.taskStatusLabel.className = `badge ${
    state.taskStatus === "completed"
      ? "ok"
      : state.taskStatus === "failed"
        ? "error"
        : state.taskStatus === "running"
          ? "warn"
          : "neutral"
  }`;
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
  setText(elements.highCount, String(counters.HIGH + counters.CRITICAL));
  setText(elements.mediumCount, String(counters.MEDIUM));
  setText(elements.lowCount, String(counters.LOW));
  setText(elements.totalCount, String(findings.length));
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

const fetchJson = createJsonClient({
  getToken: () => state.accessToken,
  onUnauthorized: () => {
    clearSession();
    showAuth("登录已过期，请重新登录。");
  },
});

async function refreshHealth() {
  const base = requireApiBase("health");
  if (!base) {
    return;
  }

  const originalLabel = elements.refreshHealthBtn?.textContent || "刷新系统状态";
  try {
    if (elements.refreshHealthBtn) {
      elements.refreshHealthBtn.disabled = true;
      elements.refreshHealthBtn.textContent = "检测中...";
    }
    const data = await fetchJson(`${base}/health`);
    setBadge(elements.backendHealth, data.app, "ok");
    setBadge(elements.databaseHealth, data.database, data.database === "ok" ? "ok" : "error");
    setBadge(elements.redisHealth, data.redis, data.redis === "ok" ? "ok" : "error");
    appendLog(`[health] 系统状态已刷新：backend=${data.app}, db=${data.database}, redis=${data.redis}`);
  } catch (error) {
    setBadge(elements.backendHealth, "连接失败", "error");
    setBadge(elements.databaseHealth, "未知", "warn");
    setBadge(elements.redisHealth, "未知", "warn");
    appendLog(`[health] ${error.message}`);
  } finally {
    if (elements.refreshHealthBtn) {
      elements.refreshHealthBtn.disabled = false;
      elements.refreshHealthBtn.textContent = originalLabel;
    }
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
  if (!state.registerSlider.verified || !state.registerSlider.proofToken) {
    setAuthMessage("\u8bf7\u5148\u5b8c\u6210\u6ed1\u52a8\u9a8c\u8bc1");
    resetRegisterSlider("failed");
    await fetchRegisterHumanCheckChallenge(true);
    return;
  }

  const base = requireApiBase("auth");
  if (!base) {
    return;
  }

  try {
    setRegisterSubmitState(true);
    setAuthMessage("");
    const payload = await fetchJson(`${base}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: elements.registerUsernameInput.value.trim(),
        email: elements.registerEmailInput.value.trim(),
        password: elements.registerPasswordInput.value,
        human_check_proof: state.registerSlider.proofToken,
      }),
      auth: false,
    });
    setSession(payload);
    elements.registerPasswordInput.value = "";
    resetRegisterSlider();
    showApp();
  } catch (error) {
    setAuthMessage(error.message);
    resetRegisterSlider("idle");
    await fetchRegisterHumanCheckChallenge(true);
  } finally {
    setRegisterSubmitState(false);
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
    } else if (task.status === "failed" || task.status === "stopped") {
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

elements.loginTabBtn?.addEventListener("click", () => setAuthMode("login"));
elements.registerTabBtn?.addEventListener("click", () => setAuthMode("register"));
elements.loginForm?.addEventListener("submit", submitLogin);
elements.registerForm?.addEventListener("submit", submitRegister);
elements.registerVerifyResetBtn?.addEventListener("click", () => {
  resetRegisterSlider("idle");
  void fetchRegisterHumanCheckChallenge(true);
});
elements.registerSliderThumb?.addEventListener("pointerdown", handleRegisterSliderPointerDown);
elements.registerSliderThumb?.addEventListener("pointermove", handleRegisterSliderPointerMove);
elements.registerSliderThumb?.addEventListener("pointerup", handleRegisterSliderPointerUp);
elements.registerSliderThumb?.addEventListener("pointercancel", handleRegisterSliderPointerCancel);
elements.registerSliderThumb?.addEventListener("keydown", handleRegisterSliderKeyDown);
elements.registerUsernameInput?.addEventListener("input", handleRegisterFormInput);
elements.registerEmailInput?.addEventListener("input", handleRegisterFormInput);
elements.registerPasswordInput?.addEventListener("input", handleRegisterFormInput);
elements.logoutBtn?.addEventListener("click", logout);
elements.llmConfigForm?.addEventListener("submit", saveLlmConfig);
elements.llmProviderSelect?.addEventListener("change", () => {
  applyProviderDefaults({ force: true });
  void discoverLlmModels({ silent: true });
});
elements.llmBaseUrlInput?.addEventListener("change", () => void discoverLlmModels({ silent: true }));
elements.llmApiKeyInput?.addEventListener("change", () => void discoverLlmModels());
elements.discoverLlmModelsBtn?.addEventListener("click", () => void discoverLlmModels());
elements.clearLlmApiKeyBtn?.addEventListener("click", clearLlmApiKey);
elements.pickFolderBtn?.addEventListener("click", () => elements.folderInput.click());
elements.fileInput?.addEventListener("change", updateUploadSelectionText);
elements.folderInput?.addEventListener("change", updateUploadSelectionText);
elements.uploadBtn?.addEventListener("click", uploadFile);
elements.demoBtn?.addEventListener("click", uploadDemoProject);
elements.startBtn?.addEventListener("click", startAudit);
elements.docsBtn?.addEventListener("click", openDocs);
elements.refreshHealthBtn?.addEventListener("click", refreshHealth);

window.addEventListener("beforeunload", () => {
  stopPolling();
  closeSocket();
});
window.addEventListener("resize", syncRegisterSliderLayout);

setTaskMeta();
renderTop10([]);
updateUploadSelectionText();
resetRegisterSlider();
restoreSession();
