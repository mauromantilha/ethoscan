const PHASE_ORDER = ["F0", "F1", "F2", "F3", "F4", "F5", "F6"];

const el = {
  apiBaseUrl: document.getElementById("apiBaseUrl"),
  apiKey: document.getElementById("apiKey"),
  connectionStatus: document.getElementById("connectionStatus"),
  formStatus: document.getElementById("formStatus"),
  healthMeta: document.getElementById("healthMeta"),
  toolGrid: document.getElementById("toolGrid"),
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
  btnSaveConfig: document.getElementById("btnSaveConfig"),
  btnRefresh: document.getElementById("btnRefresh"),
};

let selectedEngagement = null;
let busy = false;

function setBusy(value) {
  busy = value;
  el.btnCreate.disabled = value;
  document.querySelectorAll("[data-action]").forEach((btn) => {
    btn.disabled = value;
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function loadConfig() {
  const config = await window.ethoscan.getConfig();
  el.apiBaseUrl.value = config.apiBaseUrl || "http://127.0.0.1:8000";
  el.apiKey.value = config.apiKey || "";
}

async function saveConfig() {
  await window.ethoscan.setConfig({
    apiBaseUrl: el.apiBaseUrl.value.trim() || "http://127.0.0.1:8000",
    apiKey: el.apiKey.value.trim(),
  });
  el.connectionStatus.textContent = "Configuração guardada.";
  await refresh();
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
          `<button class="btn" data-action="report" data-id="${j.id}">Descarregar relatório</button>`,
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
  } catch (err) {
    el.connectionStatus.textContent = `API indisponível — ${err.message || err}`;
    renderHealth(null);
  }
}

el.btnSaveConfig.addEventListener("click", () => {
  saveConfig().catch((err) => {
    el.connectionStatus.textContent = String(err.message || err);
  });
});

el.btnRefresh.addEventListener("click", () => {
  refresh().catch((err) => {
    el.connectionStatus.textContent = String(err.message || err);
  });
});

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
      const data = await window.ethoscan.startJob(id);
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
    }
    await refresh();
  } catch (err) {
    el.formStatus.textContent = String(err.message || err);
  } finally {
    setBusy(false);
  }
});

(async function boot() {
  await loadConfig();
  await refresh();
  setInterval(() => {
    refresh().catch(() => {});
  }, 3000);
})();
