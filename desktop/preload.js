const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ethoscan", {
  getConfig: () => ipcRenderer.invoke("config:get"),
  setConfig: (config) => ipcRenderer.invoke("config:set", config),
  login: (payload) => ipcRenderer.invoke("auth:login", payload),
  logout: () => ipcRenderer.invoke("auth:logout"),
  health: () => ipcRenderer.invoke("api:health"),
  labTools: () => ipcRenderer.invoke("api:labTools"),
  toolCatalog: () => ipcRenderer.invoke("api:toolCatalog"),
  launchBurp: () => ipcRenderer.invoke("api:launchBurp"),
  listEngagements: () => ipcRenderer.invoke("api:listEngagements"),
  createEngagement: (payload) => ipcRenderer.invoke("api:createEngagement", payload),
  startJob: (engagementId, body) => ipcRenderer.invoke("api:startJob", engagementId, body),
  listJobs: (engagementId) => ipcRenderer.invoke("api:listJobs", engagementId),
  getJob: (jobId) => ipcRenderer.invoke("api:getJob", jobId),
  listHistory: (filters) => ipcRenderer.invoke("api:listHistory", filters),
  cancelJob: (jobId) => ipcRenderer.invoke("api:cancelJob", jobId),
  listFindings: (filters) => ipcRenderer.invoke("api:listFindings", filters),
  downloadReport: (jobId) => ipcRenderer.invoke("api:downloadReport", jobId),
  downloadReportPdf: (jobId) => ipcRenderer.invoke("api:downloadReportPdf", jobId),
  openPath: (targetPath) => ipcRenderer.invoke("shell:openPath", targetPath),
  getAppVersion: () => ipcRenderer.invoke("app:getVersion"),
  checkForUpdates: () => ipcRenderer.invoke("updater:check"),
  installUpdate: () => ipcRenderer.invoke("updater:install"),
  onUpdaterStatus: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on("updater:status", handler);
    return () => ipcRenderer.removeListener("updater:status", handler);
  },
});
