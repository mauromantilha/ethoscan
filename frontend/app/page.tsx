"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

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
};

type Finding = {
  id: number;
  engagement_id: number;
  title: string;
  severity: string;
  target: string;
  tool: string;
  description: string;
};

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (API_KEY) headers.set("X-API-Key", API_KEY);
  const res = await fetch(`${API}${path}`, { ...init, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* corpo não-JSON */
    }
    if (res.status === 401) {
      throw new Error("401 — API key inválida. Defina NEXT_PUBLIC_API_KEY igual à do backend.");
    }
    throw new Error(`${res.status} — ${detail}`);
  }
  return res;
}

async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  return (await res.json()) as T;
}

export default function HomePage() {
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
      const [e, j, f] = await Promise.all([
        apiJson<Engagement[]>("/api/engagements"),
        apiJson<Job[]>("/api/jobs"),
        apiJson<Finding[]>("/api/findings?limit=200"),
      ]);
      setEngagements(e);
      setJobs(j);
      setFindings(f);
      setStatus(API_KEY ? "API conectada" : "API conectada — defina NEXT_PUBLIC_API_KEY");
    } catch (err) {
      setStatus(`API indisponível — ${errorText(err)}`);
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
      const res = await apiFetch("/api/engagements", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          scope_targets,
          intensity,
          roe_acknowledged: true,
        }),
      });
      const eng = (await res.json()) as Engagement;
      setSelected(eng.id);
      setStatus(`Engagement #${eng.id} criado`);
      await refresh();
    } catch (err) {
      setStatus(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function startJob(engagementId: number) {
    setBusy(true);
    try {
      const data = await apiJson<{ job: Job; message: string }>(
        `/api/engagements/${engagementId}/jobs`,
        { method: "POST" },
      );
      setSelected(engagementId);
      setStatus(`Job #${data.job.id} enfileirado`);
      await refresh();
    } catch (err) {
      setStatus(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function cancelJob(jobId: number) {
    setBusy(true);
    try {
      await apiJson<Job>(`/api/jobs/${jobId}/cancel`, { method: "POST" });
      setStatus(`Cancelamento solicitado para o job #${jobId}`);
      await refresh();
    } catch (err) {
      setStatus(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function openReport(jobId: number) {
    try {
      // o relatório exige a API key: busca autenticada + blob no navegador
      const res = await apiFetch(`/api/jobs/${jobId}/report`);
      const url = URL.createObjectURL(new Blob([await res.text()], { type: "text/html" }));
      window.open(url, "_blank", "noopener,noreferrer");
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (err) {
      setStatus(errorText(err));
    }
  }

  const filteredFindings = findings.filter((f) =>
    selected ? f.engagement_id === selected : true,
  );

  return (
    <main className="shell">
      <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=IBM+Plex+Sans:wght@400;500;650&display=swap"
      />
      <h1 className="brand">Ethoscan</h1>
      <p className="tagline">
        Orquestrador local de pentest ético. Escopo allowlist, RoE obrigatório, pipeline F0–F6 e
        relatório — tools reais quando existirem, mock no host.
      </p>

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
              <label htmlFor="intensity">Intensidade</label>
              <select
                id="intensity"
                value={intensity}
                onChange={(e) => setIntensity(e.target.value)}
              >
                <option value="safe">safe</option>
                <option value="standard">standard</option>
                <option value="aggressive">aggressive</option>
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
              <button className="btn secondary" type="button" onClick={refresh}>
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
                    Enfileirar pipeline
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
        <h2>Jobs</h2>
        <div className="list">
          {jobs.slice(0, 8).map((j) => (
            <div key={j.id} className="item">
              <strong>
                Job #{j.id} · eng {j.engagement_id}
              </strong>
              <div className="meta">
                {j.status} · {j.phase} · {j.progress}%
                {j.current_tool ? ` · ${j.current_tool}` : ""}
                {j.error ? ` · erro: ${j.error}` : ""}
              </div>
              <div className="row" style={{ marginTop: "0.65rem" }}>
                {j.report_path && (
                  <button className="btn secondary" onClick={() => openReport(j.id)}>
                    Ver relatório
                  </button>
                )}
                {(j.status === "pending" || j.status === "running") && (
                  <button className="btn secondary" disabled={busy} onClick={() => cancelJob(j.id)}>
                    Cancelar
                  </button>
                )}
              </div>
            </div>
          ))}
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
                {f.target} · {f.tool}
              </div>
              <div className="meta">{f.description}</div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
