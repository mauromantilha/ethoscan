const PHASE_ORDER = ["F0", "F1", "F2", "F3", "F4", "F5", "F6"];

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
  btnInstallUpdate: document.getElementById("btnInstallUpdate"),
};

let selectedEngagement = null;
let busy = false;
let pollTimer = null;
let lastCatalog = null;
let defaultPipeline = ["nmap", "whatweb", "gobuster", "sslscan", "nuclei"];
let updateCheckInFlight = false;
let checkedUpdateAfterConnect = false;

function setBusy(value) {
  busy = value;
  el.btnCreate.disabled = value;
  el.btnLogin.disabled = value;
  document.querySelectorAll("[data-action]").forEach((btn) => {
    btn.disabled = value;
  });
}

function applyUpdaterStatus(payload) {
  if (!payload || !el.updateStatus) return;
  const state = payload.state || "idle";
  el.updateBanner.dataset.state = state;
  el.updateStatus.textContent = payload.message || "Atualização…";
  const ready = state === "ready";
  el.btnInstallUpdate.hidden = !ready;
  el.btnCheckUpdate.disabled = state === "checking" || state === "downloading";
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

function showLogin() {
  el.loginPanel.hidden = false;
  el.appPanels.hidden = true;
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function showApp(config) {
  el.loginPanel.hidden = true;
  el.appPanels.hidden = false;
  const who = config.username ? `Sessão: ${config.username}` : "Sessão local";
  el.sessionUser.textContent = who;
  if (!pollTimer) {
    pollTimer = setInterval(() => {
      refresh().catch(() => {});
    }, 3000);
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

function renderHealth(health) {
  if (!health) {
    el.healthMeta.textContent = "Sem dados de health.";
    el.toolGrid.innerHTML = `<p class="meta">Aguardando /health…</p>`;
    return;
  }

  el.healthMeta.textContent = [
    `estado: ${health.status}`,
    `modo: ${health.mode}`,
    `auth: ${health.auth_enabled ? "on" : "off"}`,
    `login local: ${health.local_login_available ? "sim" : "não"}`,
    `redis: ${health.redis_ok ? "ok" : "down"}`,
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
    el.toolCatalogHint.textContent = catalog.note;
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
      const disabled = !canRun;
      const checked = prev.has(t.id);
      const status = escapeHtml(t.status || "");
      return `<label class="tool-select-item">
        <input type="checkbox" data-tool-id="${escapeHtml(t.id)}" ${disabled ? "disabled" : ""} ${
          !disabled && checked ? "checked" : ""
        } />
        <span>
          <strong>${escapeHtml(t.display_name || t.id)}</strong>
          <span class="mode-badge ${t.available ? "real" : t.will_mock ? "mock" : "down"}">${status}</span>
        </span>
        <span class="meta">${escapeHtml(t.description || "")}${
          t.ethics_note ? ` — ${escapeHtml(t.ethics_note)}` : ""
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
    el.engagementList.innerHTML = `<p class="meta">Nenhum engagement ainda.</p>`;
    return;
  }

  el.engagementList.innerHTML = engagements
    .map(
      (e) => `<div class="item">
        <strong>#${e.id} ${escapeHtml(e.name)}</strong>
        <div class="meta">${escapeHtml((e.scope_targets || []).join(", "))} · ${escapeHtml(e.intensity)}</div>
        <div class="row" style="margin-top: 0.65rem">
          <button class="btn" data-action="start" data-id="${e.id}">Rodar pipeline</button>
          <button class="btn secondary" data-action="select" data-id="${e.id}">Ver achados</button>
        </div>
      </div>`,
    )
    .join("");
}

function renderJobs(jobs) {
  const slice = jobs.slice(0, 8);
  if (!slice.length) {
    el.jobList.innerHTML = `<p class="meta">Sem jobs.</p>`;
    return;
  }

  el.jobList.innerHTML = slice
    .map((j) => {
      const cur = PHASE_ORDER.indexOf(j.phase);
      const pills = PHASE_ORDER.map((p, idx) => {
        const done = j.status === "completed" || (cur >= 0 && idx < cur);
        const active = j.phase === p && j.status === "running";
        return `<span class="phase-pill ${done ? "done" : ""} ${active ? "active" : ""}">${p}</span>`;
      }).join("");

      const toolRuns = Object.entries(j.tool_runs || {})
        .map(
          ([tool, info]) =>
            `<span class="mode-badge ${info.mocked ? "mock" : "real"}">${escapeHtml(tool)}:${info.mocked ? "mock" : "real"}</span>`,
        )
        .join("");

      const actions = [];
      if (j.status === "pending" || j.status === "running") {
        actions.push(
          `<button class="btn secondary" data-action="cancel" data-id="${j.id}">Cancelar</button>`,
        );
      }
      if (j.status === "completed") {
        actions.push(
          `<button class="btn" data-action="report" data-id="${j.id}">Descarregar HTML</button>`,
        );
        actions.push(
          `<button class="btn" data-action="report-pdf" data-id="${j.id}">Descarregar PDF</button>`,
        );
      }

      return `<div class="item">
        <strong>Job #${j.id} · eng ${j.engagement_id}</strong>
        <div class="phase-track">${pills}</div>
        <div class="meta">
          ${escapeHtml(j.status)} · ${escapeHtml(j.phase)} · ${j.progress}%
          ${j.current_tool ? ` · ${escapeHtml(j.current_tool)}` : ""}
          ${j.error ? ` · erro: ${escapeHtml(j.error)}` : ""}
        </div>
        <div class="tool-run-row">${toolRuns}</div>
        <div class="row" style="margin-top: 0.65rem">${actions.join("")}</div>
      </div>`;
    })
    .join("");
}

function renderFindings(findings) {
  el.findingsTitle.textContent = selectedEngagement
    ? `Achados (engagement #${selectedEngagement})`
    : "Achados";

  const filtered = findings.filter((f) =>
    selectedEngagement ? f.engagement_id === selectedEngagement : true,
  );

  if (!filtered.length) {
    el.findingList.innerHTML = `<p class="meta">Sem achados ainda.</p>`;
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

    const [engagements, jobs, findings] = await Promise.all([
      window.ethoscan.listEngagements(),
      window.ethoscan.listJobs(),
      window.ethoscan.listFindings(
        selectedEngagement ? { engagementId: selectedEngagement } : {},
      ),
    ]);

    renderEngagements(engagements);
    renderJobs(jobs);
    renderFindings(findings);

    el.connectionStatus.textContent = health.redis_ok
      ? `API ok · Redis ok · auth ${health.auth_enabled ? "on" : "off"} · mock ${health.mock_allowed ? "on" : "off"}`
      : `API ok · Redis DOWN — ${health.worker_hint || "suba Redis + worker"}`;
    if (!checkedUpdateAfterConnect) {
      checkedUpdateAfterConnect = true;
      checkForAppUpdates().catch(() => {});
    }
  } catch (err) {
    el.connectionStatus.textContent = `API indisponível — ${err.message || err}`;
    renderHealth(null);
    renderLabInventory(null);
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
    // health é público — usa fetch via IPC que inclui apiKey se existir
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
    // Lab aberto: entrar direto na app
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
      await refresh();
      checkForAppUpdates().catch(() => {});
      return;
    }

    el.loginStatus.textContent =
      "Indique utilizador + palavra-passe, ou uma X-API-Key no painel avançado.";
  } catch (err) {
    el.loginStatus.textContent = String(err.message || err);
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
    });
});

el.btnCheckUpdate.addEventListener("click", () => {
  checkForAppUpdates().catch(() => {});
});

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

if (el.btnLaunchBurp) {
  el.btnLaunchBurp.addEventListener("click", async () => {
    setBusy(true);
    try {
      const res = await window.ethoscan.launchBurp();
      el.formStatus.textContent = res.message || (res.launched ? "Burp lançado." : "Burp indisponível.");
    } catch (err) {
      el.formStatus.textContent = String(err.message || err);
    } finally {
      setBusy(false);
    }
  });
}

el.createForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!el.ack.checked) {
    el.formStatus.textContent = "Confirme o RoE/autorização antes de criar.";
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
    await refresh();
  } catch (err) {
    el.formStatus.textContent = String(err.message || err);
  } finally {
    setBusy(false);
  }
});

document.body.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-action]");
  if (!btn || busy) return;

  const action = btn.dataset.action;
  const id = Number(btn.dataset.id);

  if (action === "select") {
    selectedEngagement = id;
    await refresh();
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
    } else if (action === "cancel") {
      await window.ethoscan.cancelJob(id);
      el.formStatus.textContent = `Cancelamento pedido para job #${id}`;
    } else if (action === "report") {
      const result = await window.ethoscan.downloadReport(id);
      if (result.saved) {
        el.formStatus.textContent = `Relatório guardado: ${result.path}`;
        await window.ethoscan.openPath(result.path);
      } else {
        el.formStatus.textContent = "Download cancelado.";
      }
    } else if (action === "report-pdf") {
      const result = await window.ethoscan.downloadReportPdf(id);
      if (result.saved) {
        el.formStatus.textContent = `PDF guardado: ${result.path}`;
        await window.ethoscan.openPath(result.path);
      } else {
        el.formStatus.textContent = "Download cancelado.";
      }
    }
    await refresh();
  } catch (err) {
    el.formStatus.textContent = String(err.message || err);
  } finally {
    setBusy(false);
  }
});

(async function boot() {
  if (window.ethoscan?.onUpdaterStatus) {
    window.ethoscan.onUpdaterStatus(applyUpdaterStatus);
  }
  // Verificação independente da API (arranque / offline API)
  checkForAppUpdates().catch(() => {});
  await probeLoginGate();
})();
