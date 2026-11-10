"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import ThemeToggle from "./components/ThemeToggle";

type ToolInfo = {
  binary: string;
  available: boolean;
  will_mock?: boolean;
  mode?: string;
};

type CatalogTool = {
  id: string;
  display_name: string;
  category: string;
  available: boolean;
  runnable: boolean;
  launchable?: boolean;
  description: string;
  status: string;
  role?: string;
  will_mock?: boolean;
  ethics_note?: string | null;
};

type Health = {
  status: string;
  mode: string;
  mock_allowed: boolean;
  auth_enabled: boolean;
  redis_ok: boolean;
  worker_ok?: boolean;
  worker_hint: string;
  tools: Record<string, ToolInfo>;
  phases: Record<string, string>;
};

type Engagement = {
  id: number;
  name: string;
  scope_targets: string[];
  intensity: string;
};

type Job = {
  id: number;
  engagement_id: number;
  status: string;
  phase: string;
  progress: number;
  current_tool: string | null;
  error: string | null;
  report_path: string | null;
  tool_runs: Record<string, { mocked?: boolean; available?: boolean; mode?: string }>;
};

type Finding = {
  id: number;
  engagement_id: number;
  title: string;
  severity: string;
  target: string;
  tool: string;
  description: string;
  evidence?: string | null;
  remediation?: string | null;
  cve?: string | null;
  cwe?: string | null;
  mocked?: boolean;
};

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";
const PHASE_ORDER = ["F0", "F1", "F2", "F3", "F4", "F5", "F6"];

function headers(json = false): HeadersInit {
  const h: Record<string, string> = {};
  if (json) h["Content-Type"] = "application/json";
  if (API_KEY) h["X-API-Key"] = API_KEY;
  return h;
}

export default function HomePage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [status, setStatus] = useState("Carregando…");
  const [name, setName] = useState("Lab local");
  const [targets, setTargets] = useState("scanme.nmap.org");
  const [intensity, setIntensity] = useState("safe");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [catalog, setCatalog] = useState<CatalogTool[]>([]);
  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [findingQuery, setFindingQuery] = useState("");

  const refresh = useCallback(async () => {
    try {
      const healthRes = await fetch(`${API}/health`);
      if (!healthRes.ok) throw new Error(`health ${healthRes.status}`);
      const h = await healthRes.json();
      setHealth(h);

      const [eRes, jRes, fRes, tRes] = await Promise.all([
        fetch(`${API}/api/engagements`, { headers: headers() }),
        fetch(`${API}/api/jobs`, { headers: headers() }),
        fetch(`${API}/api/findings`, { headers: headers() }),
        fetch(`${API}/api/tools`, { headers: headers() }),
      ]);
      if (!eRes.ok) throw new Error(`engagements ${eRes.status}`);
      if (!jRes.ok) throw new Error(`jobs ${jRes.status}`);
      if (!fRes.ok) throw new Error(`findings ${fRes.status}`);
      setEngagements(await eRes.json());
      setJobs(await jRes.json());
      setFindings(await fRes.json());
      if (tRes.ok) {
        const cat = await tRes.json();
        setCatalog(cat.tools || []);
      }
      setStatus(
        h.redis_ok
          ? `API ok · Redis ok · worker ${h.worker_ok ? "ok" : "DOWN"} · auth ${
              h.auth_enabled ? "on" : "off"
            } · mock ${h.mock_allowed ? "on" : "off"}`
          : `API ok · Redis DOWN — ${h.worker_hint}`,
      );
    } catch (err) {
      setStatus(`API indisponível (:8000) — ${String(err)}`);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [refresh]);

  async function onCreate(ev: FormEvent) {
    ev.preventDefault();
    if (!ack) {
      setStatus("Confirme o RoE/autorização antes de criar.");
      return;
    }
    setBusy(true);
    try {
      const scope_targets = targets
        .split(/[\n,]/)
        .map((t) => t.trim())
        .filter(Boolean);
      const res = await fetch(`${API}/api/engagements`, {
        method: "POST",
        headers: headers(true),
        body: JSON.stringify({
          name,
          scope_targets,
          intensity,
          roe_acknowledged: true,
          selected_tools: selectedTools.length ? selectedTools : null,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const eng = await res.json();
      setSelected(eng.id);
      setStatus(`Engagement #${eng.id} criado`);
      await refresh();
    } catch (err) {
      setStatus(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function startJob(engagementId: number) {
    const engagement = engagements.find((item) => item.id === engagementId);
    const toolsLabel = selectedTools.length
      ? selectedTools.join(", ")
      : "pipeline clássico";
    const summary = [
      "Iniciar scan?",
      "",
      `Engagement: #${engagementId} ${engagement?.name || ""}`.trim(),
      `Alvos: ${(engagement?.scope_targets || []).join(", ") || "(ver escopo)"}`,
      `Intensidade: ${engagement?.intensity || intensity}`,
      `Tools: ${toolsLabel}`,
      "",
      "Confirme que existe autorização/RoE para estes alvos.",
    ].join("\n");
    if (!window.confirm(summary)) return;

    setBusy(true);
    try {
      const res = await fetch(`${API}/api/engagements/${engagementId}/jobs`, {
        method: "POST",
        headers: headers(true),
        body: JSON.stringify(
          selectedTools.length ? { selected_tools: selectedTools } : {},
        ),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setSelected(engagementId);
      setStatus(`Job #${data.job.id} enfileirado no worker`);
      await refresh();
    } catch (err) {
      setStatus(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function cancelJob(jobId: number) {
    if (!window.confirm(`Cancelar o job #${jobId}? A tool atual pode terminar antes do próximo checkpoint.`)) {
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${API}/api/jobs/${jobId}/cancel`, {
        method: "POST",
        headers: headers(),
      });
      if (!res.ok) throw new Error(await res.text());
      setStatus(`Cancelamento pedido para job #${jobId}`);
      await refresh();
    } catch (err) {
      setStatus(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function downloadReport(jobId: number) {
    try {
      const res = await fetch(`${API}/api/jobs/${jobId}/report`, { headers: headers() });
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ethoscan-report-job-${jobId}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setStatus(String(err));
    }
  }

  async function downloadReportPdf(jobId: number) {
    try {
      const res = await fetch(`${API}/api/jobs/${jobId}/report.pdf`, { headers: headers() });
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ethoscan-report-job-${jobId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setStatus(String(err));
    }
  }

  function toggleTool(id: string, enabled: boolean) {
    setSelectedTools((prev) =>
      enabled ? (prev.includes(id) ? prev : [...prev, id]) : prev.filter((t) => t !== id),
    );
  }

  const filteredFindings = useMemo(() => {
    const query = findingQuery.trim().toLowerCase();
    return findings.filter((finding) => {
      if (selected && finding.engagement_id !== selected) return false;
      if (severityFilter !== "all" && finding.severity !== severityFilter) return false;
      if (!query) return true;
      return [finding.title, finding.target, finding.tool, finding.description]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [findings, selected, severityFilter, findingQuery]);

  const toolEntries = health ? Object.entries(health.tools || {}) : [];

  return (
    <main className="shell">
      <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=IBM+Plex+Sans:wght@400;500;650&display=swap"
      />
      <header className="hero">
        <div className="hero-top">
          <h1 className="brand">Ethoscan</h1>
          <ThemeToggle />
        </div>
        <p className="tagline">
          Orquestrador local de pentest ético. Escopo allowlist, RoE obrigatório, pipeline F0–F6 e
          relatório. Intensidade recomendada: <strong>safe</strong>. Scans reais no Kali Linux;
          mock quando as tools não estiverem no PATH.
        </p>
      </header>

      {health?.mock_allowed && (
        <div className="mock-banner" role="status">
          <strong>Modo mock ativo:</strong> ferramentas em falta podem produzir achados simulados.
          Confirme o badge <strong>MOCK</strong> antes de usar um relatório como evidência real.
        </div>
      )}

      <details className="panel" style={{ marginBottom: "1.25rem" }}>
        <summary style={{ cursor: "pointer", color: "var(--accent)", fontWeight: 600 }}>
          Tools · real vs mock (clique para expandir)
        </summary>
        <div className="tool-grid" style={{ marginTop: "0.85rem" }}>
          {toolEntries.length === 0 && <p className="meta">Aguardando /health…</p>}
          {toolEntries.map(([toolName, info]) => (
            <div key={toolName} className="tool-chip">
              <strong>{toolName}</strong>
              <span className={`mode-badge ${info.available ? "real" : info.will_mock ? "mock" : "down"}`}>
                {info.available ? "real" : info.will_mock ? "mock" : "indisponível"}
              </span>
              <span className="meta">{info.binary}</span>
            </div>
          ))}
        </div>
      </details>

      <div className="grid">
        <section className="panel">
          <h2>Novo engagement</h2>
          <form onSubmit={onCreate}>
            <div className="field">
              <label htmlFor="name">Nome</label>
              <input id="name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="targets">Alvos (escopo)</label>
              <textarea
                id="targets"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder="dominio.com ou IP, um por linha"
              />
            </div>
            <div className="field">
              <label htmlFor="intensity">Intensidade (recomendado: safe)</label>
              <select
                id="intensity"
                value={intensity}
                onChange={(e) => setIntensity(e.target.value)}
              >
                <option value="safe">safe — recomendado</option>
                <option value="standard">standard — lab próprio / RoE explícito</option>
                <option value="aggressive">aggressive — lab controlado apenas</option>
              </select>
            </div>
            <div className="field">
              <details>
                <summary style={{ cursor: "pointer", color: "var(--accent-2)" }}>
                  Avançado · seleção de tools
                </summary>
                <p className="meta" style={{ marginTop: "0.5rem" }}>
                  Vazio = pipeline clássico. Badges: <strong>executável</strong> /{" "}
                  <strong>só GUI</strong> / <strong>inventário</strong>. Instalado ≠ selecionável.
                </p>
                <div className="tool-grid" style={{ marginTop: "0.5rem", maxHeight: 360, overflow: "auto" }}>
                  {catalog.map((t) => {
                      const canRun = t.runnable && (t.available || t.will_mock);
                      return (
                        <label key={t.id} className="tool-chip" style={{ cursor: canRun ? "pointer" : "default" }}>
                          <span>
                            <input
                              type="checkbox"
                              disabled={!canRun}
                              checked={selectedTools.includes(t.id)}
                              onChange={(e) => toggleTool(t.id, e.target.checked)}
                            />{" "}
                            <strong>{t.display_name}</strong>
                          </span>
                          <span className={`mode-badge ${t.available ? "real" : t.will_mock ? "mock" : "down"}`}>
                            {t.status}
                          </span>
                          {t.available && <span className="mode-badge real">disponível</span>}
                          <span className="meta">{t.description}</span>
                        </label>
                      );
                    })}
                </div>
              </details>
            </div>
            <label className="checkbox">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              <span>
                Confirmo autorização/RoE: assessment apenas nos alvos do escopo, em contexto ético.
              </span>
            </label>
            <div className="row" style={{ marginTop: "1rem" }}>
              <button className="btn" type="submit" disabled={busy}>
                Criar engagement
              </button>
              <button className="btn secondary" type="button" onClick={() => refresh()}>
                Atualizar
              </button>
            </div>
          </form>
          <p className="status">{status}</p>
        </section>

        <section className="panel">
          <h2>Engagements</h2>
          <div className="list">
            {engagements.length === 0 && <p className="meta">Nenhum engagement ainda.</p>}
            {engagements.map((e) => (
              <div key={e.id} className="item">
                <strong>
                  #{e.id} {e.name}
                </strong>
                <div className="meta">
                  {e.scope_targets.join(", ")} · {e.intensity}
                </div>
                <div className="row" style={{ marginTop: "0.65rem" }}>
                  <button className="btn" disabled={busy} onClick={() => startJob(e.id)}>
                    Rodar pipeline
                  </button>
                  <button className="btn secondary" onClick={() => setSelected(e.id)}>
                    Ver achados
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel" style={{ marginTop: "1.25rem" }}>
        <h2>Jobs · progresso F0–F6</h2>
        <div className="list">
          {jobs.slice(0, 8).map((j) => {
            const cur = PHASE_ORDER.indexOf(j.phase);
            return (
              <div key={j.id} className="item">
                <strong>
                  Job #{j.id} · eng {j.engagement_id}
                </strong>
                <div className="phase-track" aria-label="Progresso das fases">
                  {PHASE_ORDER.map((p, idx) => {
                    const done = j.status === "completed" || (cur >= 0 && idx < cur);
                    const active = j.phase === p && j.status === "running";
                    return (
                      <span
                        key={p}
                        className={`phase-pill ${done ? "done" : ""} ${active ? "active" : ""}`}
                      >
                        {p}
                      </span>
                    );
                  })}
                </div>
                <div className="meta">
                  {j.status} · {j.phase} · {j.progress}%
                  {j.current_tool ? ` · ${j.current_tool}` : ""}
                  {j.error ? ` · erro: ${j.error}` : ""}
                </div>
                <div className="tool-run-row">
                  {Object.entries(j.tool_runs || {})
                    .filter(([tool]) => !tool.startsWith("_"))
                    .map(([tool, info]) => (
                      <span
                        key={tool}
                        className={`mode-badge ${info.mocked ? "mock" : "real"}`}
                      >
                        {tool}:{info.mocked ? "mock" : "real"}
                      </span>
                    ))}
                </div>
                <div className="row" style={{ marginTop: "0.65rem" }}>
                  {(j.status === "pending" || j.status === "running") && (
                    <button
                      className="btn secondary"
                      disabled={busy}
                      onClick={() => cancelJob(j.id)}
                    >
                      Cancelar
                    </button>
                  )}
                  {j.status === "completed" && (
                    <>
                      <button className="btn" type="button" onClick={() => downloadReport(j.id)}>
                        Descarregar HTML
                      </button>
                      <button className="btn" type="button" onClick={() => downloadReportPdf(j.id)}>
                        Descarregar PDF
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="panel" style={{ marginTop: "1.25rem" }}>
        <h2>Achados {selected ? `(engagement #${selected})` : ""}</h2>
        <div className="row filters">
          <input
            aria-label="Filtrar achados"
            placeholder="Filtrar por título, alvo, tool…"
            value={findingQuery}
            onChange={(e) => setFindingQuery(e.target.value)}
          />
          <select
            aria-label="Filtrar por severidade"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">Todas as severidades</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>
        <p className="meta">
          {filteredFindings.length} achado(s){selected ? ` no engagement #${selected}` : ""}
        </p>
        <div className="list">
          {filteredFindings.length === 0 && <p className="meta">Sem achados para este filtro.</p>}
          {filteredFindings.slice(0, 40).map((f) => (
            <div key={f.id} className="item">
              <strong>
                <span className={`sev ${f.severity}`}>{f.severity}</span>
                {f.title}
              </strong>
              <div className="meta">
                {f.target} · {f.tool}{" "}
                <span className={`mode-badge ${f.mocked ? "mock" : "real"}`}>
                  {f.mocked ? "mock" : "real"}
                </span>
                {f.cve ? ` · ${f.cve}` : ""}
                {f.cwe ? ` · ${f.cwe}` : ""}
              </div>
              <div className="meta">{f.description}</div>
              {(f.evidence || f.remediation) && (
                <details className="finding-details">
                  <summary>Evidência / remediação</summary>
                  {f.evidence && <pre>{f.evidence}</pre>}
                  {f.remediation && <p>{f.remediation}</p>}
                </details>
              )}
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
