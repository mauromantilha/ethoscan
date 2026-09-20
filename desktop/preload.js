const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ethoscan", {
  getConfig: () => ipcRenderer.invoke("config:get"),
  setConfig: (config) => ipcRenderer.invoke("config:set", config),
  health: () => ipcRenderer.invoke("api:health"),
  listEngagements: () => ipcRenderer.invoke("api:listEngagements"),
  createEngagement: (payload) => ipcRenderer.invoke("api:createEngagement", payload),
  startJob: (engagementId) => ipcRenderer.invoke("api:startJob", engagementId),
  listJobs: (engagementId) => ipcRenderer.invoke("api:listJobs", engagementId),
  cancelJob: (jobId) => ipcRenderer.invoke("api:cancelJob", jobId),
  listFindings: (filters) => ipcRenderer.invoke("api:listFindings", filters),
  downloadReport: (jobId) => ipcRenderer.invoke("api:downloadReport", jobId),
  openPath: (targetPath) => ipcRenderer.invoke("shell:openPath", targetPath),
});
