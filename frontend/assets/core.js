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
