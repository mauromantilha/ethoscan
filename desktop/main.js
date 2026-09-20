const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const { autoUpdater } = require("electron-updater");
const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG = {
  apiBaseUrl: "http://127.0.0.1:8000",
  apiKey: "",
  username: "",
};

function configPath() {
  return path.join(app.getPath("userData"), "ethoscan-desktop.json");
}

function readConfig() {
  try {
    const raw = fs.readFileSync(configPath(), "utf8");
    return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function writeConfig(next) {
  const merged = {
    apiBaseUrl: String(next.apiBaseUrl || DEFAULT_CONFIG.apiBaseUrl).replace(/\/$/, ""),
    apiKey: String(next.apiKey || ""),
    username: String(next.username || ""),
  };
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(merged, null, 2), "utf8");
  return merged;
}

function clearSession() {
  const config = readConfig();
  return writeConfig({
    apiBaseUrl: config.apiBaseUrl,
    apiKey: "",
    username: "",
  });
}

function buildHeaders(config, json = false) {
  const headers = {};
  if (json) headers["Content-Type"] = "application/json";
  if (config.apiKey) headers["X-API-Key"] = config.apiKey;
  return headers;
}

async function apiFetch(pathname, options = {}) {
  const config = readConfig();
  const url = `${config.apiBaseUrl}${pathname}`;
  let res;
  try {
    res = await fetch(url, {
      method: options.method || "GET",
      headers: buildHeaders(config, Boolean(options.body)),
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
  } catch (err) {
    throw new Error(
      `Não foi possível contactar ${config.apiBaseUrl} (${err.cause?.code || err.message}). ` +
        "Confirme que a API está a correr.",
    );
  }
  const contentType = res.headers.get("content-type") || "";
  let data = null;
  if (contentType.includes("application/json")) {
    data = await res.json();
  } else {
    data = await res.text();
  }
  if (!res.ok) {
    const detail =
      typeof data === "object" && data !== null
        ? data.detail || JSON.stringify(data)
        : String(data);
    const err = new Error(detail || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function login({ apiBaseUrl, username, password }) {
  const base = String(apiBaseUrl || DEFAULT_CONFIG.apiBaseUrl).replace(/\/$/, "");
  let res;
  try {
    res = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch (err) {
    throw new Error(
      `Não foi possível contactar ${base} (${err.cause?.code || err.message}). ` +
        "Confirme que a API está a correr.",
    );
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail =
      typeof data === "object" && data !== null
        ? data.detail || JSON.stringify(data)
        : String(data);
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return writeConfig({
    apiBaseUrl: base,
    apiKey: data.token,
    username: data.username || username,
  });
}

function sendUpdaterStatus(payload) {
  for (const win of BrowserWindow.getAllWindows()) {
    if (!win.isDestroyed()) {
      win.webContents.send("updater:status", payload);
    }
  }
}

function setupAutoUpdater() {
  if (!app.isPackaged) {
    const devStatus = {
      state: "dev",
      message: "Atualizações só na app empacotada (não em npm start).",
      version: app.getVersion(),
    };
    ipcMain.handle("updater:check", () => {
      sendUpdaterStatus(devStatus);
      return devStatus;
    });
    ipcMain.handle("updater:install", () => ({
      ok: false,
      message: "Reinício/instalação só na app empacotada.",
    }));
    // Informa o renderer assim que a janela existir
    setTimeout(() => sendUpdaterStatus(devStatus), 500);
    return;
  }

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  // Releases públicos; sem code signing (lab/privado — SmartScreen pode avisar)
  autoUpdater.setFeedURL({
    provider: "github",
    owner: "mauromantilha",
    repo: "ethoscan",
  });

  autoUpdater.on("checking-for-update", () => {
    sendUpdaterStatus({
      state: "checking",
      message: "A verificar atualizações…",
      version: app.getVersion(),
    });
  });

  autoUpdater.on("update-available", (info) => {
    sendUpdaterStatus({
      state: "available",
      message: `Atualização disponível: v${info.version}`,
      version: info.version,
    });
  });

  autoUpdater.on("update-not-available", () => {
    sendUpdaterStatus({
      state: "up-to-date",
      message: `Está na versão mais recente (v${app.getVersion()})`,
      version: app.getVersion(),
    });
  });

  autoUpdater.on("download-progress", (progress) => {
    const percent = Math.round(progress.percent || 0);
    sendUpdaterStatus({
      state: "downloading",
      message: `A descarregar… ${percent}%`,
      percent,
      version: app.getVersion(),
    });
  });

  autoUpdater.on("update-downloaded", (info) => {
    sendUpdaterStatus({
      state: "ready",
      message: "Atualização instalada — reinicie para aplicar",
      version: info.version,
    });
  });

  autoUpdater.on("error", (err) => {
    sendUpdaterStatus({
      state: "error",
      message: `Erro ao atualizar: ${err?.message || err}`,
      version: app.getVersion(),
    });
  });

  ipcMain.handle("updater:check", async () => {
    try {
      const result = await autoUpdater.checkForUpdates();
      return {
        ok: true,
        version: app.getVersion(),
        updateInfo: result?.updateInfo || null,
      };
    } catch (err) {
      const status = {
        state: "error",
        message: `Erro ao atualizar: ${err?.message || err}`,
        version: app.getVersion(),
      };
      sendUpdaterStatus(status);
      return status;
    }
  });

  ipcMain.handle("updater:install", () => {
    // isSilent=false, isForceRunAfter=true
    setImmediate(() => autoUpdater.quitAndInstall(false, true));
    return { ok: true };
  });

  // Arranque: verificar sem depender da API local
  setTimeout(() => {
    autoUpdater.checkForUpdates().catch(() => {});
  }, 1500);
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1180,
    height: 860,
    minWidth: 900,
    minHeight: 640,
    title: "Ethoscan Desktop",
    backgroundColor: "#07100d",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  win.loadFile(path.join(__dirname, "renderer", "index.html"));
}

app.whenReady().then(() => {
  setupAutoUpdater();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

ipcMain.handle("config:get", () => readConfig());

ipcMain.handle("config:set", (_event, next) => writeConfig(next || {}));

ipcMain.handle("auth:login", async (_event, payload) => login(payload || {}));

ipcMain.handle("auth:logout", async () => {
  const config = readConfig();
  if (config.apiKey) {
    try {
      await apiFetch("/api/auth/logout", { method: "POST" });
    } catch {
      // limpa sessão local mesmo se a API estiver offline
    }
  }
  return clearSession();
});

ipcMain.handle("api:health", async () => apiFetch("/health"));

ipcMain.handle("api:labTools", async () => apiFetch("/api/lab/tools"));

ipcMain.handle("api:toolCatalog", async () => apiFetch("/api/tools"));

ipcMain.handle("api:launchBurp", async () =>
  apiFetch("/api/tools/burpsuite/launch", { method: "POST" }),
);

ipcMain.handle("api:listEngagements", async () => apiFetch("/api/engagements"));

ipcMain.handle("api:createEngagement", async (_event, payload) =>
  apiFetch("/api/engagements", { method: "POST", body: payload }),
);

ipcMain.handle("api:startJob", async (_event, engagementId, body) =>
  apiFetch(`/api/engagements/${engagementId}/jobs`, {
    method: "POST",
    body: body && Object.keys(body).length ? body : undefined,
  }),
);

ipcMain.handle("api:listJobs", async (_event, engagementId) => {
  const q =
    engagementId != null && engagementId !== ""
      ? `?engagement_id=${encodeURIComponent(engagementId)}`
      : "";
  return apiFetch(`/api/jobs${q}`);
});

ipcMain.handle("api:cancelJob", async (_event, jobId) =>
  apiFetch(`/api/jobs/${jobId}/cancel`, { method: "POST" }),
);

ipcMain.handle("api:listFindings", async (_event, filters = {}) => {
  const params = new URLSearchParams();
  if (filters.engagementId != null) params.set("engagement_id", String(filters.engagementId));
  if (filters.jobId != null) params.set("job_id", String(filters.jobId));
  const q = params.toString() ? `?${params}` : "";
  return apiFetch(`/api/findings${q}`);
});

ipcMain.handle("api:downloadReport", async (event, jobId) => {
  const config = readConfig();
  const url = `${config.apiBaseUrl}/api/jobs/${jobId}/report`;
  const res = await fetch(url, { headers: buildHeaders(config) });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  const buffer = Buffer.from(await res.arrayBuffer());
  const win = BrowserWindow.fromWebContents(event.sender);
  const result = await dialog.showSaveDialog(win, {
    title: "Guardar relatório Ethoscan",
    defaultPath: `ethoscan-report-job-${jobId}.html`,
    filters: [{ name: "HTML", extensions: ["html"] }],
  });
  if (result.canceled || !result.filePath) {
    return { saved: false };
  }
  fs.writeFileSync(result.filePath, buffer);
  return { saved: true, path: result.filePath };
});

ipcMain.handle("api:downloadReportPdf", async (event, jobId) => {
  const config = readConfig();
  const url = `${config.apiBaseUrl}/api/jobs/${jobId}/report.pdf`;
  const res = await fetch(url, { headers: buildHeaders(config) });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  const buffer = Buffer.from(await res.arrayBuffer());
  const win = BrowserWindow.fromWebContents(event.sender);
  const result = await dialog.showSaveDialog(win, {
    title: "Guardar PDF Ethoscan",
    defaultPath: `ethoscan-report-job-${jobId}.pdf`,
    filters: [{ name: "PDF", extensions: ["pdf"] }],
  });
  if (result.canceled || !result.filePath) {
    return { saved: false };
  }
  fs.writeFileSync(result.filePath, buffer);
  return { saved: true, path: result.filePath };
});

ipcMain.handle("shell:openPath", async (_event, targetPath) => {
  if (!targetPath) return;
  await shell.openPath(targetPath);
});
