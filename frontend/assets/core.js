export const AUTH_TOKEN_STORAGE_KEY = "auditpilot.accessToken";

export function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

export function normalizePath(value) {
  const path = String(value || "/api/v1").trim();
  const withSlash = path.startsWith("/") ? path : `/${path}`;
  return withSlash.length > 1 ? withSlash.replace(/\/+$/, "") : withSlash;
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function appendAccessToken(url, token) {
  if (!token) return url;
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}access_token=${encodeURIComponent(token)}`;
}

export function createJsonClient({ getToken, onUnauthorized } = {}) {
  return async function fetchJson(url, options = {}) {
    const { auth = true, headers, ...rest } = options;
    const requestHeaders = new Headers(headers || {});
    const token = getToken?.();
    if (auth && token) requestHeaders.set("Authorization", `Bearer ${token}`);

    const response = await fetch(url, { ...rest, headers: requestHeaders });
    if (response.status === 401 && auth) onUnauthorized?.();
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
    if (response.status === 204) return null;
    return response.json();
  };
}

export function initials(value, fallback = "U") {
  const normalized = String(value || "").trim();
  return normalized ? normalized.slice(0, 2).toUpperCase() : fallback;
}

const FINDING_SEVERITY_LABELS = {
  CRITICAL: "严重",
  HIGH: "高危",
  MEDIUM: "中危",
  LOW: "低危",
  INFO: "提示",
};

const FINDING_SOURCE_LABELS = {
  TaintFlow: "污点流分析",
  BaselineHeuristic: "基线启发式扫描",
  Top10Heuristic: "OWASP 启发式扫描",
  LLMReview: "模型语义复核",
  JavaVulnSkill: "Java 组件漏洞扫描",
  Semgrep: "Semgrep 规则扫描",
  Bandit: "Bandit 安全扫描",
  Gitleaks: "敏感信息扫描",
  Trivy: "依赖组件扫描",
};

const FINDING_TITLE_LABELS = {
  "Potential Source-to-Sink Data Flow": "潜在的输入源到危险操作点数据流",
  "Untrusted Input Reaches SQL Execution Path": "不可信输入进入 SQL 执行路径",
  "Possible Remote Command Execution Chain": "潜在的远程命令执行链",
  "Credential Exposure and Authentication Weakness": "凭据泄露与身份认证薄弱",
  "Sensitive Route May Miss Server-Side Authorization": "敏感接口可能缺少服务端鉴权",
  "Potential Path Traversal / File Inclusion": "潜在路径遍历或文件包含",
  "Potential SQL Injection": "潜在 SQL 注入",
  "Potential Command Injection": "潜在命令注入",
  "Potential Cross-Site Scripting (XSS)": "潜在跨站脚本攻击（XSS）",
  "Potential SSRF": "潜在服务端请求伪造（SSRF）",
  "Potential Open Redirect": "潜在开放重定向",
  "Potential XXE": "潜在 XML 外部实体注入（XXE）",
  "Potential Server-Side Template Injection": "潜在服务端模板注入",
  "Potential Code Injection via Eval": "潜在动态执行代码注入",
  "Unsafe PHP Deserialization": "不安全的 PHP 反序列化",
  "Hardcoded Secret Key": "硬编码密钥",
  "Hardcoded Password": "硬编码密码",
  "Known Vulnerable Dependency": "已知高风险依赖组件",
  "SQL Injection": "SQL 注入",
  "Shell Injection Risk": "Shell 命令注入风险",
  "Command Execution Sink": "命令执行危险点",
  "Overly Permissive CORS Configuration": "过度宽松的 CORS 配置",
  "Missing Admin Authorization Check": "管理接口缺少权限校验",
  "Debug Mode Enabled": "生产环境启用了调试模式",
  "TLS Verification Disabled": "TLS 证书校验已关闭",
  "Weak Credential Hashing": "凭据使用弱散列算法",
  "Exception Swallowed Without Logging": "异常被忽略且未记录日志",
};

export function localizeFindingSeverity(value) {
  const normalized = String(value || "").toUpperCase();
  return FINDING_SEVERITY_LABELS[normalized] || value || "未知";
}

export function localizeFindingSource(value) {
  return String(value || "未知来源")
    .split(/[,，、]/)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => FINDING_SOURCE_LABELS[item] || item)
    .join("、");
}

export function localizeFindingTitle(value) {
  const title = String(value || "未命名漏洞");
  return FINDING_TITLE_LABELS[title] || title;
}

export function localizeFindingDescription(value) {
  const description = String(value || "");
  const directFlow = description.match(/^Function (.+) contains an input source and sensitive sink\.$/i);
  if (directFlow) return `函数 ${directFlow[1]} 同时包含外部输入源和敏感操作点，存在数据流风险。`;
  const linkedFlow = description.match(/^Function (.+) receives input and calls sink function\(s\): (.+)\.$/i);
  if (linkedFlow) return `函数 ${linkedFlow[1]} 接收外部输入，并调用敏感函数：${linkedFlow[2]}。`;
  return description || "暂无补充描述。";
}
