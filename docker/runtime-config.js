(() => {
  const origin = window.location.origin;
  window.AUDITPILOT_CONFIG = Object.freeze({
    apiBaseUrl: `${origin}/api/v1`,
    apiPrefix: "/api/v1",
    backendUrl: origin,
    docsUrl: `${origin}/docs`,
  });
})();
