"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type ToolInfo = {
  binary: string;
  available: boolean;
  will_mock?: boolean;
  mode?: string;
};

type Health = {
  status: string;
  mode: string;
  mock_allowed: boolean;
  auth_enabled: boolean;
  redis_ok: boolean;
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

  const refresh = useCallback(async () => {
    try {
      const healthRes = await fetch(`${API}/health`);
      const h = await healthRes.json();
      setHealth(h);

      const [eRes, jRes, fRes] = await Promise.all([
        fetch(`${API}/api/engagements`, { headers: headers() }),
        fetch(`${API}/api/jobs`, { headers: headers() }),
        fetch(`${API}/api/findings`, { headers: headers() }),
      ]);
      if (!eRes.ok) throw new Error(`engagements ${eRes.status}`);
      setEngagements(await eRes.json());
      setJobs(await jRes.json());
      setFindings(await fRes.json());
      setStatus(
        h.redis_ok
          ? `API ok · Redis ok · auth ${h.auth_enabled ? "on" : "off"} · mock ${h.mock_allowed ? "on" : "off"}`
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
    setBusy(true);
    try {
      const res = await fetch(`${API}/api/engagements/${engagementId}/jobs`, {
        method: "POST",
        headers: headers(),
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

  const filteredFindings = useMemo(
    () => findings.filter((f) => (selected ? f.engagement_id === selected : true)),
    [findings, selected],
  );

  const toolEntries = health ? Object.entries(health.tools || {}) : [];

  return (
    <main className="shell">
      <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=IBM+Plex+Sans:wght@400;500;650&display=swap"
      />
      <h1 className="brand">Ethoscan</h1>
      <p className="tagline">
        Orquestrador local de pentest ético. Escopo allowlist, RoE obrigatório, pipeline F0–F6 e
        relatório. Intensidade recomendada: <strong>safe</strong>. Scans reais no Kali Linux; mock
        quando as tools não estiverem no PATH.
      </p>

      <section className="panel" style={{ marginBottom: "1.25rem" }}>
        <h2>Tools · real vs mock</h2>
        <div className="tool-grid">
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
      </section>

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
                  {Object.entries(j.tool_runs || {}).map(([tool, info]) => (
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
                    <button className="btn" type="button" onClick={() => downloadReport(j.id)}>
                      Descarregar relatório
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="panel" style={{ marginTop: "1.25rem" }}>
        <h2>Achados {selected ? `(engagement #${selected})` : ""}</h2>
        <div className="list">
          {filteredFindings.length === 0 && <p className="meta">Sem achados ainda.</p>}
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
              </div>
              <div className="meta">{f.description}</div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
