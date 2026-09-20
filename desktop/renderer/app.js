const PHASE_ORDER = ["F0", "F1", "F2", "F3", "F4", "F5", "F6"];
const PHASE_LABELS = {
  F0: "Gate",
  F1: "Recon",
  F2: "Enum",
  F3: "Web",
  F4: "Vuln",
  F5: "Correlação",
  F6: "Relatório",
};

const el = {
  loginPanel: document.getElementById("loginPanel"),
  appPanels: document.getElementById("appPanels"),
  loginForm: document.getElementById("loginForm"),
  loginStatus: document.getElementById("loginStatus"),
  apiBaseUrl: document.getElementById("apiBaseUrl"),
  username: document.getElementById("username"),
  password: document.getElementById("password"),
  apiKey: document.getElementById("apiKey"),
  btnLogin: document.getElementById("btnLogin"),
  btnSkipAuth: document.getElementById("btnSkipAuth"),
  btnLogout: document.getElementById("btnLogout"),
  btnRefresh: document.getElementById("btnRefresh"),
  sessionUser: document.getElementById("sessionUser"),
  connectionStatus: document.getElementById("connectionStatus"),
  formStatus: document.getElementById("formStatus"),
  healthMeta: document.getElementById("healthMeta"),
  toolGrid: document.getElementById("toolGrid"),
  phaseList: document.getElementById("phaseList"),
  labNote: document.getElementById("labNote"),
  labGrid: document.getElementById("labGrid"),
  engagementList: document.getElementById("engagementList"),
  jobList: document.getElementById("jobList"),
  historyList: document.getElementById("historyList"),
  findingList: document.getElementById("findingList"),
  findingsTitle: document.getElementById("findingsTitle"),
  createForm: document.getElementById("createForm"),
  name: document.getElementById("name"),
  targets: document.getElementById("targets"),
  intensity: document.getElementById("intensity"),
  ack: document.getElementById("ack"),
  btnCreate: document.getElementById("btnCreate"),
  toolCatalog: document.getElementById("toolCatalog"),
  toolCatalogHint: document.getElementById("toolCatalogHint"),
  btnLaunchBurp: document.getElementById("btnLaunchBurp"),
  updateBanner: document.getElementById("updateBanner"),
  updateStatus: document.getElementById("updateStatus"),
  btnCheckUpdate: document.getElementById("btnCheckUpdate"),
  btnCheckUpdateLab: document.getElementById("btnCheckUpdateLab"),
  btnInstallUpdate: document.getElementById("btnInstallUpdate"),
  appVersion: document.getElementById("appVersion"),
  toastHost: document.getElementById("toastHost"),
  progressDialog: document.getElementById("progressDialog"),
  progressJobMeta: document.getElementById("progressJobMeta"),
  progressBar: document.getElementById("progressBar"),
  progressPct: document.getElementById("progressPct"),
  progressPhases: document.getElementById("progressPhases"),
  progressTool: document.getElementById("progressTool"),
  progressEta: document.getElementById("progressEta"),
  progressError: document.getElementById("progressError"),
  btnDismissProgress: document.getElementById("btnDismissProgress"),
  btnCopyJobId: document.getElementById("btnCopyJobId"),
  btnCancelProgress: document.getElementById("btnCancelProgress"),
  btnOpenReport: document.getElementById("btnOpenReport"),
  btnOpenReportPdf: document.getElementById("btnOpenReportPdf"),
};

let selectedEngagement = null;
let busy = false;
let pollTimer = null;
let progressPollTimer = null;
let watchingJobId = null;
let watchStartedAt = null;
let lastCatalog = null;
let defaultPipeline = ["nmap", "whatweb", "gobuster", "sslscan", "nuclei"];
let updateCheckInFlight = false;
let checkedUpdateAfterConnect = false;
let activeTab = "dashboard";

function setBusy(value) {
  busy = value;
  if (el.btnCreate) el.btnCreate.disabled = value;
  if (el.btnLogin) el.btnLogin.disabled = value;
  document.querySelectorAll("[data-action]").forEach((btn) => {
    btn.disabled = value;
  });
}

function toast(message, kind = "info") {
  if (!el.toastHost) return;
  const node = document.createElement("div");
  node.className = `toast toast-${kind}`;
  node.textContent = message;
  el.toastHost.appendChild(node);
  setTimeout(() => {
    node.classList.add("toast-out");
    setTimeout(() => node.remove(), 280);
  }, 3200);
}

function applyUpdaterStatus(payload) {
  if (!payload || !el.updateStatus) return;
  const state = payload.state || "idle";
  el.updateBanner.dataset.state = state;
  el.updateStatus.textContent = payload.message || "Atualização…";
  const interesting = ["checking", "downloading", "available", "ready", "error"].includes(state);
  el.updateBanner.hidden = !interesting && state !== "up-to-date";
  if (state === "up-to-date") {
    el.updateBanner.hidden = false;
    setTimeout(() => {
      if (el.updateBanner.dataset.state === "up-to-date") el.updateBanner.hidden = true;
    }, 4000);
  }
  const ready = state === "ready";
  el.btnInstallUpdate.hidden = !ready;
  el.btnCheckUpdate.disabled = state === "checking" || state === "downloading";
  if (el.btnCheckUpdateLab) {
    el.btnCheckUpdateLab.disabled = state === "checking" || state === "downloading";
  }
}

async function checkForAppUpdates() {
  if (!window.ethoscan?.checkForUpdates || updateCheckInFlight) return;
  updateCheckInFlight = true;
  try {
    await window.ethoscan.checkForUpdates();
  } catch (err) {
    applyUpdaterStatus({
      state: "error",
      message: `Erro ao atualizar: ${err.message || err}`,
    });
  } finally {
    updateCheckInFlight = false;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDate(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("pt-BR", {
      dateStyle: "short",
      timeStyle: "short",
    });
  } catch {
    return String(value);
  }
}

function switchTab(name) {
  activeTab = name;
  document.querySelectorAll(".tab").forEach((tab) => {
    const on = tab.dataset.tab === name;
    tab.classList.toggle("active", on);
    tab.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    const on = panel.dataset.panel === name;
    panel.hidden = !on;
    panel.classList.toggle("active", on);
  });
}

function showLogin() {
  el.loginPanel.hidden = false;
  el.appPanels.hidden = true;
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  stopProgressWatch();
}

function showApp(config) {
  el.loginPanel.hidden = true;
  el.appPanels.hidden = false;
  const who = config.username ? `Sessão: ${config.username}` : "Sessão local";
  el.sessionUser.textContent = who;
  if (!pollTimer) {
    pollTimer = setInterval(() => {
      refresh().catch(() => {});
    }, 2500);
  }
}

async function loadConfigIntoForm() {
  const config = await window.ethoscan.getConfig();
  el.apiBaseUrl.value = config.apiBaseUrl || "http://127.0.0.1:8000";
  el.username.value = config.username || "";
  el.apiKey.value = "";
  el.password.value = "";
  return config;
}

async function loadAppVersion() {
  try {
    if (window.ethoscan?.getAppVersion) {
      const v = await window.ethoscan.getAppVersion();
      if (v && el.appVersion) el.appVersion.textContent = `v${v}`;
    }
  } catch {
    /* ignore */
  }
}

function renderHealth(health) {
  if (!health) {
    el.healthMeta.textContent = "Sem dados de health.";
    el.toolGrid.innerHTML = `<p class="meta">Aguardando /health…</p>`;
    return;
  }

  el.healthMeta.textContent = [
    `estado: ${health.status}`,
    `redis: ${health.redis_ok ? "ok" : "down"}`,
    `auth: ${health.auth_enabled ? "on" : "off"}`,
    `mock: ${health.mock_allowed ? "permitido" : "off"}`,
  ].join(" · ");

  const tools = Object.entries(health.tools || {});
  if (!tools.length) {
    el.toolGrid.innerHTML = `<p class="meta">Sem tools reportadas.</p>`;
    return;
  }

  el.toolGrid.innerHTML = tools
    .map(([name, info]) => {
      const mode = info.available ? "real" : info.will_mock ? "mock" : "indisponível";
      const badge = info.available ? "real" : info.will_mock ? "mock" : "down";
      return `<div class="tool-chip">
        <strong>${escapeHtml(name)}</strong>
        <span class="mode-badge ${badge}">${mode}</span>
        <span class="meta">${escapeHtml(info.binary || "")}</span>
      </div>`;
    })
    .join("");

  renderPhases(health.phases || {});
}

function renderPhases(phases) {
  const entries = PHASE_ORDER.map((id) => [id, phases[id] || ""]).filter(([, label]) => label);
  if (!entries.length) {
    el.phaseList.innerHTML = `<p class="meta">Sem fases reportadas.</p>`;
    return;
  }
  el.phaseList.innerHTML = entries
    .map(
      ([id, label]) =>
        `<div class="phase-row"><span class="phase-id">${escapeHtml(id)}</span>` +
        `<span>${escapeHtml(label)}</span></div>`,
    )
    .join("");
}

function renderLabInventory(inventory) {
  if (!inventory) {
    el.labGrid.innerHTML = `<p class="meta">Inventário indisponível (auth ou API).</p>`;
    return;
  }
  el.labNote.textContent =
    inventory.note || "Disponível / em falta no PATH da API (sem executar scans).";
  if (inventory.phases) renderPhases(inventory.phases);

  const tools = inventory.tools || [];
  if (!tools.length) {
    el.labGrid.innerHTML = `<p class="meta">Sem tools no inventário.</p>`;
    return;
  }

  el.labGrid.innerHTML = tools
    .map((t) => {
      const badge = t.available ? "real" : "down";
      const mode = t.available ? "disponível" : "em falta";
      return `<div class="tool-chip">
        <strong>${escapeHtml(t.name)}</strong>
        <span class="mode-badge ${badge}">${mode}</span>
        <span class="meta">${escapeHtml(t.binary || "")}</span>
      </div>`;
    })
    .join("");
}

function renderToolCatalog(catalog) {
  lastCatalog = catalog;
  if (!catalog || !el.toolCatalog) return;
  if (catalog.default_pipeline?.length) {
    defaultPipeline = catalog.default_pipeline;
  }
  if (catalog.note && el.toolCatalogHint) {
    el.toolCatalogHint.innerHTML =
      "Vazio = pipeline clássico. <strong>ZAP</strong> = scan automatizado no pipeline; " +
      "<strong>Burp</strong> = só lançamento GUI. Metasploit = aux/scanner apenas.";
  }

  const tools = (catalog.tools || []).filter(
    (t) => t.runnable || t.launchable || ["burpsuite", "metasploit", "zap"].includes(t.id),
  );
  if (!tools.length) {
    el.toolCatalog.innerHTML = `<p class="meta">Catálogo indisponível.</p>`;
    return;
  }

  const prev = new Set(getSelectedToolsFromForm());
  el.toolCatalog.innerHTML = tools
    .map((t) => {
      const canRun = Boolean(t.runnable) && (Boolean(t.available) || Boolean(t.will_mock));
      const disabled = !canRun && t.id !== "burpsuite";
      const checked = prev.has(t.id);
      const status = escapeHtml(t.status || "");
      const burpNote =
        t.id === "burpsuite"
          ? " — GUI apenas (não entra no pipeline)"
          : t.id === "zap"
            ? " — scan automatizado + relatório"
            : "";
      return `<label class="tool-select-item">
        <input type="checkbox" data-tool-id="${escapeHtml(t.id)}" ${
          disabled || t.id === "burpsuite" ? "disabled" : ""
        } ${!disabled && checked ? "checked" : ""} />
        <span>
          <strong>${escapeHtml(t.display_name || t.id)}</strong>
          <span class="mode-badge ${t.available ? "real" : t.will_mock ? "mock" : "down"}">${status}</span>
        </span>
        <span class="meta">${escapeHtml(t.description || "")}${burpNote}${
          t.ethics_note && t.id !== "burpsuite" ? ` — ${escapeHtml(t.ethics_note)}` : ""
        }</span>
      </label>`;
    })
    .join("");

  const burp = (catalog.tools || []).find((t) => t.id === "burpsuite");
  if (el.btnLaunchBurp) {
    el.btnLaunchBurp.hidden = !(burp && burp.available && burp.launchable);
  }
}

function getSelectedToolsFromForm() {
  if (!el.toolCatalog) return [];
  return Array.from(el.toolCatalog.querySelectorAll("input[data-tool-id]:checked:not(:disabled)"))
    .map((input) => input.dataset.toolId)
    .filter(Boolean);
}

function renderEngagements(engagements) {
  if (!engagements.length) {
    el.engagementList.innerHTML = `<p class="meta">Nenhum engagement ainda. Crie o primeiro à esquerda.</p>`;
    return;
  }

  el.engagementList.innerHTML = engagements
    .map(
      (e) => `<div class="item">
        <strong>#${e.id} ${escapeHtml(e.name)}</strong>
        <div class="meta">${escapeHtml((e.scope_targets || []).join(", "))} · ${escapeHtml(e.intensity)}</div>
        <div class="meta">${formatDate(e.created_at)}</div>
        <div class="row" style="margin-top: 0.65rem">
          <button class="btn" data-action="start" data-id="${e.id}">Rodar pipeline</button>
          <button class="btn secondary" data-action="select" data-id="${e.id}">Ver achados</button>
        </div>
      </div>`,
    )
    .join("");
}

function renderJobs(jobs) {
  const active = jobs.filter((j) => j.status === "pending" || j.status === "running");
  const slice = (active.length ? active : jobs).slice(0, 12);
  if (!slice.length) {
    el.jobList.innerHTML = `<p class="meta">Sem jobs. Inicie um pipeline a partir de um engagement.</p>`;
    return;
  }

  el.jobList.innerHTML = slice
    .map((j) => {
      const cur = PHASE_ORDER.indexOf(j.phase);
      const pills = PHASE_ORDER.map((p, idx) => {
        const done = j.status === "completed" || (cur >= 0 && idx < cur);
        const activePhase = j.phase === p && j.status === "running";
        return `<span class="phase-pill ${done ? "done" : ""} ${activePhase ? "active" : ""}">${p}</span>`;
      }).join("");

      const actions = [];
      if (j.status === "pending" || j.status === "running") {
        actions.push(
          `<button class="btn secondary" data-action="watch" data-id="${j.id}">Ver progresso</button>`,
        );
        actions.push(
          `<button class="btn secondary" data-action="cancel" data-id="${j.id}">Cancelar</button>`,
        );
      }
      if (j.status === "completed") {
        actions.push(
          `<button class="btn" data-action="report" data-id="${j.id}">HTML</button>`,
        );
        actions.push(
          `<button class="btn secondary" data-action="report-pdf" data-id="${j.id}">PDF</button>`,
        );
      }
      actions.push(
        `<button class="btn secondary" data-action="copy-id" data-id="${j.id}">Copiar ID</button>`,
      );

      return `<div class="item">
        <strong>Job #${j.id} · eng ${j.engagement_id}</strong>
        <div class="phase-track">${pills}</div>
        <div class="meta">
          ${escapeHtml(j.status)} · ${escapeHtml(j.phase)} · ${j.progress}%
          ${j.current_tool ? ` · ${escapeHtml(j.current_tool)}` : ""}
          ${j.error ? ` · erro: ${escapeHtml(j.error)}` : ""}
        </div>
        <div class="row" style="margin-top: 0.65rem">${actions.join("")}</div>
      </div>`;
    })
    .join("");
}

function renderHistory(items) {
  if (!el.historyList) return;
  if (!items.length) {
    el.historyList.innerHTML = `<p class="meta">Sem histórico ainda. Os jobs concluídos aparecem aqui.</p>`;
    return;
  }

  el.historyList.innerHTML = items
    .map((h) => {
      const tools = (h.selected_tools || []).join(", ") || "pipeline clássico";
      const actions = [];
      if (h.has_html_report) {
        actions.push(
          `<button class="btn" data-action="report" data-id="${h.job_id}">HTML</button>`,
        );
      }
      if (h.has_pdf_report && h.status === "completed") {
        actions.push(
          `<button class="btn secondary" data-action="report-pdf" data-id="${h.job_id}">PDF</button>`,
        );
      }
      actions.push(
        `<button class="btn secondary" data-action="copy-id" data-id="${h.job_id}">Copiar ID</button>`,
      );
      if (h.status === "pending" || h.status === "running") {
        actions.push(
          `<button class="btn secondary" data-action="watch" data-id="${h.job_id}">Progresso</button>`,
        );
      }
      return `<div class="item">
        <strong>Job #${h.job_id} · ${escapeHtml(h.engagement_name)}</strong>
        <div class="meta">
          ${escapeHtml(h.status)} · ${escapeHtml(h.intensity)} ·
          ${h.findings_count} achado(s) · ${formatDate(h.finished_at || h.created_at)}
        </div>
        <div class="meta">Tools: ${escapeHtml(tools)}</div>
        <div class="row" style="margin-top: 0.65rem">${actions.join("")}</div>
      </div>`;
    })
    .join("");
}

function renderFindings(findings) {
  el.findingsTitle.textContent = selectedEngagement
    ? `Achados (engagement #${selectedEngagement})`
    : "Achados recentes";

  const filtered = findings.filter((f) =>
    selectedEngagement ? f.engagement_id === selectedEngagement : true,
  );

  if (!filtered.length) {
    el.findingList.innerHTML = `<p class="meta">Sem achados ainda. Corra um job para ver resultados aqui.</p>`;
    return;
  }

  el.findingList.innerHTML = filtered
    .slice(0, 40)
    .map(
      (f) => `<div class="item">
        <strong>
          <span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          ${escapeHtml(f.title)}
        </strong>
        <div class="meta">
          ${escapeHtml(f.target)} · ${escapeHtml(f.tool)}
          <span class="mode-badge ${f.mocked ? "mock" : "real"}">${f.mocked ? "mock" : "real"}</span>
        </div>
        <div class="meta">${escapeHtml(f.description)}</div>
      </div>`,
    )
    .join("");
}

function roughEta(job) {
  if (!watchStartedAt || !job || job.progress <= 0) return "";
  if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") {
    return "";
  }
  const elapsed = (Date.now() - watchStartedAt) / 1000;
  const pct = Math.max(job.progress, 1);
  const totalEst = (elapsed / pct) * 100;
  const remain = Math.max(0, Math.round(totalEst - elapsed));
  if (remain < 5) return "ETA ~ poucos segundos";
  if (remain < 90) return `ETA ~ ${remain}s`;
  return `ETA ~ ${Math.round(remain / 60)} min`;
}

function updateProgressModal(job) {
  if (!job || !el.progressDialog) return;
  el.progressJobMeta.textContent = `Job #${job.id} · eng ${job.engagement_id} · ${job.status}`;
  const pct = Math.min(100, Math.max(0, Number(job.progress) || 0));
  el.progressBar.style.width = `${pct}%`;
  el.progressPct.textContent = `${pct}%`;
  const cur = PHASE_ORDER.indexOf(job.phase);
  el.progressPhases.innerHTML = PHASE_ORDER.map((p, idx) => {
    const done = job.status === "completed" || (cur >= 0 && idx < cur);
    const active = job.phase === p && (job.status === "running" || job.status === "pending");
    const label = PHASE_LABELS[p] || p;
    return `<span class="phase-pill ${done ? "done" : ""} ${active ? "active" : ""}" title="${label}">${p}</span>`;
  }).join("");

  if (job.status === "pending") {
    el.progressTool.textContent = "Na fila do worker…";
  } else if (job.current_tool) {
    el.progressTool.textContent = `Tool atual: ${job.current_tool} · fase ${job.phase} (${PHASE_LABELS[job.phase] || ""})`;
  } else {
    el.progressTool.textContent = `Fase ${job.phase} (${PHASE_LABELS[job.phase] || job.phase})`;
  }
  el.progressEta.textContent = roughEta(job);

  const terminal = ["completed", "failed", "cancelled"].includes(job.status);
  el.btnCancelProgress.hidden = terminal;
  el.btnOpenReport.hidden = !(job.status === "completed");
  el.btnOpenReportPdf.hidden = !(job.status === "completed");

  if (job.error) {
    el.progressError.hidden = false;
    el.progressError.textContent = job.error;
  } else if (job.status === "completed") {
    el.progressError.hidden = false;
    el.progressError.textContent = "Concluído — pode abrir o relatório.";
  } else {
    el.progressError.hidden = true;
    el.progressError.textContent = "";
  }
}

function stopProgressWatch() {
  if (progressPollTimer) {
    clearInterval(progressPollTimer);
    progressPollTimer = null;
  }
}

function openProgressModal(jobId) {
  watchingJobId = jobId;
  watchStartedAt = Date.now();
  el.btnOpenReport.dataset.id = String(jobId);
  el.btnOpenReportPdf.dataset.id = String(jobId);
  el.btnCancelProgress.dataset.id = String(jobId);
  el.btnCopyJobId.dataset.id = String(jobId);
  updateProgressModal({
    id: jobId,
    engagement_id: "—",
    status: "pending",
    phase: "F0",
    progress: 0,
    current_tool: null,
  });
  if (typeof el.progressDialog.showModal === "function") {
    el.progressDialog.showModal();
  } else {
    el.progressDialog.setAttribute("open", "");
  }
  stopProgressWatch();
  const tick = async () => {
    if (watchingJobId == null) return;
    try {
      const job = await window.ethoscan.getJob(watchingJobId);
      updateProgressModal(job);
      if (["completed", "failed", "cancelled"].includes(job.status)) {
        stopProgressWatch();
        refresh().catch(() => {});
      }
    } catch (err) {
      el.progressError.hidden = false;
      el.progressError.textContent = String(err.message || err);
    }
  };
  tick();
  progressPollTimer = setInterval(tick, 1200);
}

async function refresh() {
  try {
    const health = await window.ethoscan.health();
    renderHealth(health);

    let inventory = null;
    try {
      inventory = await window.ethoscan.labTools();
    } catch {
      inventory = null;
    }
    renderLabInventory(inventory);

    try {
      const catalog = await window.ethoscan.toolCatalog();
      renderToolCatalog(catalog);
    } catch {
      renderToolCatalog(null);
    }

    const [engagements, jobs, findings, history] = await Promise.all([
      window.ethoscan.listEngagements(),
      window.ethoscan.listJobs(),
      window.ethoscan.listFindings(
        selectedEngagement ? { engagementId: selectedEngagement } : {},
      ),
      window.ethoscan.listHistory ? window.ethoscan.listHistory() : Promise.resolve([]),
    ]);

    renderEngagements(engagements);
    renderJobs(jobs);
    renderFindings(findings);
    renderHistory(history || []);

    el.connectionStatus.textContent = health.redis_ok
      ? `API ok · Redis ok · auth ${health.auth_enabled ? "on" : "off"}`
      : `API ok · Redis DOWN — ${health.worker_hint || "suba Redis + worker"}`;
    if (!checkedUpdateAfterConnect) {
      checkedUpdateAfterConnect = true;
      checkForAppUpdates().catch(() => {});
    }
  } catch (err) {
    el.connectionStatus.textContent = `API indisponível — ${err.message || err}`;
    renderHealth(null);
    renderLabInventory(null);
    toast(String(err.message || err), "error");
    if (err.status === 401) {
      await window.ethoscan.logout();
      showLogin();
      el.loginStatus.textContent = "Sessão expirada ou inválida — entre novamente.";
    }
  }
}

async function probeLoginGate() {
  const config = await loadConfigIntoForm();
  let health = null;
  try {
    health = await window.ethoscan.health();
    el.loginStatus.textContent = health.local_login_available
      ? "API ok — entre com utilizador/palavra-passe local."
      : health.auth_enabled
        ? "API ok — auth ativa (X-API-Key ou login local se configurado)."
        : "API ok — auth desligada (lab). Pode continuar sem login.";
    el.btnSkipAuth.hidden = Boolean(health.auth_enabled);
  } catch (err) {
    el.loginStatus.textContent = `API indisponível — ${err.message || err}`;
    el.btnSkipAuth.hidden = true;
    showLogin();
    return;
  }

  const hasSession = Boolean(config.apiKey);
  if (hasSession) {
    try {
      await window.ethoscan.listEngagements();
      showApp(config);
      await refresh();
      return;
    } catch (err) {
      if (err.status === 401) {
        await window.ethoscan.logout();
        el.loginStatus.textContent = "Sessão inválida — entre novamente.";
      }
    }
  }

  if (!health.auth_enabled && !hasSession) {
    showApp(config);
    await refresh();
    return;
  }

  showLogin();
}

el.loginForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setBusy(true);
  el.loginStatus.textContent = "A autenticar…";
  try {
    const base = el.apiBaseUrl.value.trim() || "http://127.0.0.1:8000";
    const user = el.username.value.trim();
    const pass = el.password.value;
    const key = el.apiKey.value.trim();

    if (user && pass) {
      const config = await window.ethoscan.login({
        apiBaseUrl: base,
        username: user,
        password: pass,
      });
      el.password.value = "";
      checkedUpdateAfterConnect = false;
      showApp(config);
      switchTab("dashboard");
      await refresh();
      checkForAppUpdates().catch(() => {});
      return;
    }

    if (key) {
      const config = await window.ethoscan.setConfig({
        apiBaseUrl: base,
        apiKey: key,
        username: user || "",
      });
      el.apiKey.value = "";
      await window.ethoscan.listEngagements();
      checkedUpdateAfterConnect = false;
      showApp(config);
      switchTab("dashboard");
      await refresh();
      checkForAppUpdates().catch(() => {});
      return;
    }

    el.loginStatus.textContent =
      "Indique utilizador + palavra-passe, ou uma X-API-Key no painel avançado.";
  } catch (err) {
    el.loginStatus.textContent = String(err.message || err);
    toast(String(err.message || err), "error");
  } finally {
    setBusy(false);
  }
});

el.btnSkipAuth.addEventListener("click", async () => {
  setBusy(true);
  try {
    const config = await window.ethoscan.setConfig({
      apiBaseUrl: el.apiBaseUrl.value.trim() || "http://127.0.0.1:8000",
      apiKey: "",
      username: "",
    });
    checkedUpdateAfterConnect = false;
    showApp(config);
    switchTab("dashboard");
    await refresh();
    checkForAppUpdates().catch(() => {});
  } catch (err) {
    el.loginStatus.textContent = String(err.message || err);
  } finally {
    setBusy(false);
  }
});

el.btnLogout.addEventListener("click", async () => {
  await window.ethoscan.logout();
  await loadConfigIntoForm();
  showLogin();
  el.loginStatus.textContent = "Sessão terminada.";
  probeLoginGate().catch(() => {});
});

el.btnRefresh.addEventListener("click", () => {
  refresh()
    .then(() => checkForAppUpdates())
    .catch((err) => {
      el.connectionStatus.textContent = String(err.message || err);
      toast(String(err.message || err), "error");
    });
});

function wireUpdateCheck(btn) {
  if (!btn) return;
  btn.addEventListener("click", () => {
    checkForAppUpdates().catch(() => {});
  });
}
wireUpdateCheck(el.btnCheckUpdate);
wireUpdateCheck(el.btnCheckUpdateLab);

el.btnInstallUpdate.addEventListener("click", async () => {
  el.btnInstallUpdate.disabled = true;
  applyUpdaterStatus({
    state: "ready",
    message: "A reiniciar para instalar a atualização…",
  });
  try {
    await window.ethoscan.installUpdate();
  } catch (err) {
    el.btnInstallUpdate.disabled = false;
    applyUpdaterStatus({
      state: "error",
      message: `Erro ao instalar: ${err.message || err}`,
    });
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

document.body.addEventListener("click", (ev) => {
  const goto = ev.target.closest("[data-goto]");
  if (goto) {
    switchTab(goto.dataset.goto);
  }
});

if (el.btnLaunchBurp) {
  el.btnLaunchBurp.addEventListener("click", async () => {
    setBusy(true);
    try {
      const res = await window.ethoscan.launchBurp();
      const msg = res.message || (res.launched ? "Burp lançado." : "Burp indisponível.");
      el.formStatus.textContent = msg;
      toast(msg, res.launched ? "info" : "error");
    } catch (err) {
      el.formStatus.textContent = String(err.message || err);
      toast(String(err.message || err), "error");
    } finally {
      setBusy(false);
    }
  });
}

el.createForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (busy) return;
  if (!el.ack.checked) {
    el.formStatus.textContent = "Confirme o RoE/autorização antes de criar.";
    toast("Confirme o RoE antes de criar.", "error");
    return;
  }
  setBusy(true);
  try {
    const scope_targets = el.targets.value
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    const eng = await window.ethoscan.createEngagement({
      name: el.name.value.trim(),
      scope_targets,
      intensity: el.intensity.value || "safe",
      roe_acknowledged: true,
      selected_tools: getSelectedToolsFromForm(),
    });
    selectedEngagement = eng.id;
    el.formStatus.textContent = `Engagement #${eng.id} criado`;
    toast(`Engagement #${eng.id} criado`, "info");
    await refresh();
  } catch (err) {
    el.formStatus.textContent = String(err.message || err);
    toast(String(err.message || err), "error");
  } finally {
    setBusy(false);
  }
});

async function copyJobId(id) {
  const text = String(id);
  try {
    await navigator.clipboard.writeText(text);
    toast(`Job #${text} copiado`, "info");
  } catch {
    toast(`Job ID: ${text}`, "info");
  }
}

el.btnDismissProgress.addEventListener("click", () => {
  stopProgressWatch();
  watchingJobId = null;
  if (el.progressDialog.open) el.progressDialog.close();
});

el.btnCopyJobId.addEventListener("click", () => {
  const id = el.btnCopyJobId.dataset.id || watchingJobId;
  if (id) copyJobId(id);
});

el.btnCancelProgress.addEventListener("click", async () => {
  const id = Number(el.btnCancelProgress.dataset.id || watchingJobId);
  if (!id) return;
  try {
    await window.ethoscan.cancelJob(id);
    toast(`Cancelamento pedido para job #${id}`, "info");
    el.formStatus.textContent = `Cancelamento pedido para job #${id}`;
  } catch (err) {
    toast(String(err.message || err), "error");
  }
});

el.btnOpenReport.addEventListener("click", async () => {
  const id = Number(el.btnOpenReport.dataset.id || watchingJobId);
  if (!id) return;
  try {
    const result = await window.ethoscan.downloadReport(id);
    if (result.saved) {
      await window.ethoscan.openPath(result.path);
      toast("Relatório HTML aberto", "info");
    }
  } catch (err) {
    toast(String(err.message || err), "error");
  }
});

el.btnOpenReportPdf.addEventListener("click", async () => {
  const id = Number(el.btnOpenReportPdf.dataset.id || watchingJobId);
  if (!id) return;
  try {
    const result = await window.ethoscan.downloadReportPdf(id);
    if (result.saved) {
      await window.ethoscan.openPath(result.path);
      toast("PDF aberto", "info");
    }
  } catch (err) {
    toast(String(err.message || err), "error");
  }
});

document.body.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-action]");
  if (!btn || busy) return;

  const action = btn.dataset.action;
  const id = Number(btn.dataset.id);

  if (action === "select") {
    selectedEngagement = id;
    switchTab("dashboard");
    await refresh();
    return;
  }

  if (action === "copy-id") {
    await copyJobId(id);
    return;
  }

  if (action === "watch") {
    openProgressModal(id);
    return;
  }

  setBusy(true);
  try {
    if (action === "start") {
      const selected_tools = getSelectedToolsFromForm();
      const data = await window.ethoscan.startJob(id, {
        selected_tools: selected_tools.length ? selected_tools : undefined,
      });
      selectedEngagement = id;
      el.formStatus.textContent = `Job #${data.job.id} enfileirado no worker`;
      toast(`Job #${data.job.id} iniciado`, "info");
      switchTab("jobs");
      openProgressModal(data.job.id);
    } else if (action === "cancel") {
      await window.ethoscan.cancelJob(id);
      el.formStatus.textContent = `Cancelamento pedido para job #${id}`;
      toast(`Cancelamento pedido para job #${id}`, "info");
    } else if (action === "report") {
      const result = await window.ethoscan.downloadReport(id);
      if (result.saved) {
        el.formStatus.textContent = `Relatório guardado: ${result.path}`;
        await window.ethoscan.openPath(result.path);
        toast("Relatório HTML guardado", "info");
      } else {
        el.formStatus.textContent = "Download cancelado.";
      }
    } else if (action === "report-pdf") {
      const result = await window.ethoscan.downloadReportPdf(id);
      if (result.saved) {
        el.formStatus.textContent = `PDF guardado: ${result.path}`;
        await window.ethoscan.openPath(result.path);
        toast("PDF guardado", "info");
      } else {
        el.formStatus.textContent = "Download cancelado.";
      }
    }
    await refresh();
  } catch (err) {
    el.formStatus.textContent = String(err.message || err);
    toast(String(err.message || err), "error");
  } finally {
    setBusy(false);
  }
});

(async function boot() {
  await loadAppVersion();
  if (window.ethoscan?.onUpdaterStatus) {
    window.ethoscan.onUpdaterStatus(applyUpdaterStatus);
  }
  checkForAppUpdates().catch(() => {});
  await probeLoginGate();
})();
