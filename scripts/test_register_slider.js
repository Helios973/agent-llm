const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const FRONTEND_ROOT = path.join(ROOT, "frontend");
const TMP_ROOT = path.join(ROOT, "tmp");
const CLI_ARGS = process.argv.slice(2);

const BROWSER_CANDIDATES = {
  chrome: [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ],
  edge: [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  ],
};

const CONTENT_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getBrowserPreference() {
  const browserArg = CLI_ARGS.find((arg) => arg.startsWith("--browser="));
  const browserName = browserArg?.split("=")[1]?.trim().toLowerCase();
  if (!browserName) {
    return "";
  }
  if (!BROWSER_CANDIDATES[browserName]) {
    throw new Error(`Unsupported browser "${browserName}". Use --browser=chrome or --browser=edge.`);
  }
  return browserName;
}

function getOptionValue(name) {
  const match = CLI_ARGS.find((arg) => arg.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1).trim() : "";
}

function getTargetUrl() {
  return getOptionValue("--url");
}

function browserLaunchArgs(browserName, debugPort, userDataDir, url) {
  const args = [
    "--headless",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${userDataDir}`,
    "--window-size=1280,900",
    url,
  ];

  if (browserName === "edge") {
    args.unshift("--disable-features=msHubApps");
  }

  return args;
}

function debugPortForBrowser(browserName) {
  return browserName === "edge" ? 9336 : 9335;
}

async function ensureBrowserPath() {
  const explicitPath = process.env.BROWSER_PATH;
  if (explicitPath) {
    await fs.access(explicitPath);
    return {
      browserName: process.env.BROWSER_NAME || "custom",
      browserPath: explicitPath,
    };
  }

  const preferredBrowser = getBrowserPreference();
  const candidateGroups = preferredBrowser
    ? [[preferredBrowser, BROWSER_CANDIDATES[preferredBrowser] || []]]
    : Object.entries(BROWSER_CANDIDATES);

  for (const [browserName, candidates] of candidateGroups) {
    for (const candidate of candidates) {
      try {
        await fs.access(candidate);
        return { browserName, browserPath: candidate };
      } catch (error) {
        // Try the next installed browser.
      }
    }
  }

  if (preferredBrowser) {
    throw new Error(`No supported ${preferredBrowser} browser binary was found for slider testing.`);
  }

  throw new Error("No supported Chrome/Edge browser was found for slider testing.");
}

async function startStaticServer() {
  const server = http.createServer(async (request, response) => {
    try {
      const rawPath = request.url?.split("?")[0] || "/";
      const pathname = rawPath === "/" ? "/index.html" : rawPath;
      const resolvedPath = path.resolve(FRONTEND_ROOT, `.${pathname}`);
      if (!resolvedPath.startsWith(FRONTEND_ROOT)) {
        response.writeHead(403);
        response.end("Forbidden");
        return;
      }

      const stat = await fs.stat(resolvedPath);
      const filePath = stat.isDirectory() ? path.join(resolvedPath, "index.html") : resolvedPath;
      const body = await fs.readFile(filePath);
      const ext = path.extname(filePath).toLowerCase();
      response.writeHead(200, {
        "Content-Type": CONTENT_TYPES[ext] || "application/octet-stream",
        "Cache-Control": "no-store",
      });
      response.end(body);
    } catch (error) {
      response.writeHead(404);
      response.end("Not Found");
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  return {
    server,
    url: `http://127.0.0.1:${address.port}/index.html`,
  };
}

async function waitForJson(url, attempts = 50) {
  let lastError;
  for (let index = 0; index < attempts; index += 1) {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} for ${url}`);
      }
      return await response.json();
    } catch (error) {
      lastError = error;
      await delay(200);
    }
  }
  throw lastError;
}

async function connectToPage(debugPort, pageUrl) {
  const targets = await waitForJson(`http://127.0.0.1:${debugPort}/json/list`);
  const page = targets.find((target) => target.type === "page" && target.url.includes(pageUrl));
  assert(page?.webSocketDebuggerUrl, "Failed to locate the browser page target.");

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let commandId = 0;
  const pending = new Map();

  ws.addEventListener("message", (event) => {
    const payload = JSON.parse(event.data);
    if (payload.id && pending.has(payload.id)) {
      const { resolve, reject } = pending.get(payload.id);
      pending.delete(payload.id);
      if (payload.error) {
        reject(new Error(payload.error.message));
      } else {
        resolve(payload.result);
      }
    }
  });

  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });

  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      commandId += 1;
      pending.set(commandId, { resolve, reject });
      ws.send(JSON.stringify({ id: commandId, method, params }));
    });

  await send("Page.enable");
  await send("Runtime.enable");

  return {
    close() {
      ws.close();
    },
    send,
  };
}

async function main() {
  await fs.mkdir(TMP_ROOT, { recursive: true });
  const { browserName, browserPath } = await ensureBrowserPath();
  const targetUrl = getTargetUrl();
  const staticServer = targetUrl ? null : await startStaticServer();
  const url = targetUrl || staticServer.url;
  const debugPort = debugPortForBrowser(browserName);
  const userDataDir = path.join(TMP_ROOT, `register-slider-${browserName}`);
  const screenshotPath = path.join(TMP_ROOT, `register-slider-${browserName}.png`);

  await fs.rm(userDataDir, { recursive: true, force: true });
  const browser = spawn(
    browserPath,
    browserLaunchArgs(browserName, debugPort, userDataDir, url),
    {
      stdio: "ignore",
      windowsHide: true,
    },
  );

  let client;
  try {
    client = await connectToPage(debugPort, url);
    const { send } = client;

    await delay(600);
    const initialState = await send("Runtime.evaluate", {
      expression: `(() => {
        document.getElementById("registerTabBtn")?.click();
        const track = document.getElementById("registerSliderTrack");
        return {
          label: document.getElementById("registerSliderLabel")?.textContent,
          registerHidden: document.getElementById("registerForm")?.hidden,
          submitDisabled: document.getElementById("registerSubmitBtn")?.disabled,
          sliderStatus: document.getElementById("registerSliderCaptcha")?.dataset.status,
          trackWidth: Math.round(track?.getBoundingClientRect().width || 0),
        };
      })()`,
      returnByValue: true,
    });

    const initialValue = initialState.result.value;
    assert(initialValue.registerHidden === false, "Register form should be visible after switching tabs.");
    assert(initialValue.submitDisabled === true, "Register submit button should start disabled.");
    assert(initialValue.sliderStatus === "idle", "Slider should start in the idle state.");
    assert(initialValue.trackWidth >= 300, "Slider track should render at a usable width.");
    assert(
      String(initialValue.label || "").includes("拖动滑块"),
      "Slider label should prompt the user to drag the control.",
    );

    const verifiedState = await send("Runtime.evaluate", {
      expression: `(() => {
        const thumb = document.getElementById("registerSliderThumb");
        thumb?.focus();
        thumb?.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true }));
        return {
          submitDisabled: document.getElementById("registerSubmitBtn")?.disabled,
          sliderStatus: document.getElementById("registerSliderCaptcha")?.dataset.status,
          sliderText: document.getElementById("registerSliderLabel")?.textContent,
        };
      })()`,
      returnByValue: true,
    });

    const verifiedValue = verifiedState.result.value;
    assert(verifiedValue.submitDisabled === false, "Submit button should unlock after slider verification.");
    assert(verifiedValue.sliderStatus === "verified", "Slider should move into the verified state.");

    const resetState = await send("Runtime.evaluate", {
      expression: `(() => {
        const input = document.getElementById("registerUsernameInput");
        input.value = "changed-user";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        return {
          submitDisabled: document.getElementById("registerSubmitBtn")?.disabled,
          sliderStatus: document.getElementById("registerSliderCaptcha")?.dataset.status,
          sliderText: document.getElementById("registerSliderLabel")?.textContent,
        };
      })()`,
      returnByValue: true,
    });

    const resetValue = resetState.result.value;
    assert(resetValue.submitDisabled === true, "Changing registration input should require verification again.");
    assert(resetValue.sliderStatus === "idle", "Slider should reset to idle after registration input changes.");

    const screenshot = await send("Page.captureScreenshot", {
      format: "png",
      fromSurface: true,
    });
    await fs.writeFile(screenshotPath, Buffer.from(screenshot.data, "base64"));

    console.log(`Slider register test passed in ${browserName}.`);
    console.log(`Screenshot saved to ${screenshotPath}`);
  } finally {
    client?.close();
    browser.kill("SIGTERM");
    staticServer?.server.close();
  }
}

main().catch((error) => {
  console.error(`Slider register test failed: ${error.message}`);
  process.exitCode = 1;
});
