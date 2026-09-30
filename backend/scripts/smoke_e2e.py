"""Smoke E2E do Ethoscan — roda offline, tudo em modo mock.

Cobre o que a CI precisa garantir: autenticação, allowlist, RoE, pipeline,
worker persistente (pending → running → completed), cancelamento cooperativo,
isolamento de falha de tool (tool_error), relatório, auditoria e download.

Sempre roda em sandbox: banco/artefatos temporários, mock forçado e allowlist
própria — nunca toca o banco do ambiente (use ETHOSCAN_SMOKE_DIR para escolher o
diretório do sandbox).

Uso:  python scripts/smoke_e2e.py
Sai com código 1 se algum check falhar.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Sandbox: força um ambiente determinístico ANTES de importar a app (config é cacheada).
_smoke_dir = Path(
    os.environ.get("ETHOSCAN_SMOKE_DIR") or tempfile.mkdtemp(prefix="ethoscan-smoke-")
)
_smoke_dir.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_smoke_dir / 'ethoscan.db'}"
os.environ["ETHOSCAN_ARTIFACTS_DIR"] = str(_smoke_dir)
os.environ["ETHOSCAN_FORCE_MOCK"] = "true"
os.environ["ETHOSCAN_ALLOW_MOCK"] = "true"
os.environ["ETHOSCAN_ALLOWLIST"] = "scanme.nmap.org,10.10.0.0/24"
if not os.environ.get("ETHOSCAN_API_KEY"):
    os.environ["ETHOSCAN_API_KEY"] = "smoke-key"

from fastapi.testclient import TestClient  # noqa: E402

from app.adapters import all_adapters  # noqa: E402
from app.adapters.base import AdapterResult, BaseAdapter  # noqa: E402
from app.core.worker import get_worker  # noqa: E402
from app.main import app  # noqa: E402

KEY = os.environ["ETHOSCAN_API_KEY"]
H = {"X-API-Key": KEY}
MOCK_FINDINGS = 9  # nmap 2 + whatweb 1 + gobuster 3 + sslscan 1 + nuclei 2
FAILURES: list[str] = []


def check(label: str, ok: bool, extra: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {label}{(' -> ' + extra) if extra else ''}")
    if not ok:
        FAILURES.append(label)


class StubAdapter(BaseAdapter):
    """Adapter determinístico: simula falha (exit != 0) ou lentidão."""

    binary = "ethoscan-stub"

    def __init__(
        self, name: str, *, exit_code: int = 0, error: str | None = None, delay: float = 0.0
    ) -> None:
        self.name = name
        self._exit_code = exit_code
        self._error = error
        self._delay = delay

    def available(self) -> bool:
        return True

    def run(self, target: str, _job_dir: Path, _intensity: str = "safe") -> AdapterResult:
        if self._delay:
            time.sleep(self._delay)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["stub", self.name, target],
            stdout=f"stub {self.name}",
            exit_code=self._exit_code,
            error=self._error,
        )

    def _run_real(self, target: str, _job_dir: Path, _intensity: str) -> AdapterResult:
        raise NotImplementedError

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        raise NotImplementedError


def adapters_with(**replacements: BaseAdapter):
    def factory():
        return [replacements.get(adapter.name, adapter) for adapter in all_adapters()]

    return factory


def wait_job(client: TestClient, job_id: int, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    job: dict = {}
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}", headers=H).json()
        if job["status"] in {"completed", "failed", "cancelled"}:
            return job
        time.sleep(0.2)
    raise AssertionError(f"timeout esperando o job {job_id} (status: {job.get('status')})")


def wait_status(client: TestClient, job_id: int, status: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    job: dict = {}
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}", headers=H).json()
        if job["status"] == status:
            return job
        time.sleep(0.1)
    return job


def wait_finished(client: TestClient, job_id: int, timeout: float = 20.0) -> dict:
    """Espera o pipeline realmente parar (finished_at preenchido)."""
    deadline = time.monotonic() + timeout
    job: dict = {}
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}", headers=H).json()
        if job["finished_at"] is not None:
            return job
        time.sleep(0.2)
    return job


def new_engagement(client: TestClient, name: str, target: str = "scanme.nmap.org") -> int:
    response = client.post(
        "/api/engagements",
        headers=H,
        json={"name": name, "scope_targets": [target], "roe_acknowledged": True},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def start_job(client: TestClient, engagement_id: int) -> int:
    response = client.post(f"/api/engagements/{engagement_id}/jobs", headers=H)
    assert response.status_code == 200, response.text
    return response.json()["job"]["id"]


def main() -> int:
    worker = get_worker()
    with TestClient(app) as client:
        print(f"ambiente: {_smoke_dir}")
        print("-" * 72)

        # ---------- auth / health ----------
        health = client.get("/health").json()
        check("/health publico", health["status"] == "ok")
        check("health expoe mock_forced", health["mock_forced"] is True)
        check("health expoe worker_enabled", health["worker_enabled"] is True)
        check("GET /api sem key = 401", client.get("/api/engagements").status_code == 401)
        check(
            "GET /api key errada = 401",
            client.get("/api/engagements", headers={"X-API-Key": "nope"}).status_code == 401,
        )
        check(
            "GET /api com key = 200",
            client.get("/api/engagements", headers=H).status_code == 200,
        )

        # ---------- escopo / allowlist / RoE ----------
        tld = client.post(
            "/api/engagements",
            headers=H,
            json={"name": "TLD", "scope_targets": ["com"], "roe_acknowledged": True},
        )
        check("escopo TLD ('com') = 400", tld.status_code == 400, tld.text[:60])
        outside = client.post(
            "/api/engagements",
            headers=H,
            json={"name": "Fora", "scope_targets": ["example.com"], "roe_acknowledged": True},
        )
        check("fora da ETHOSCAN_ALLOWLIST = 403", outside.status_code == 403, outside.text[:60])

        eng = new_engagement(client, "Smoke")
        no_roe = client.post(
            "/api/engagements",
            headers=H,
            json={"name": "Sem RoE", "scope_targets": ["scanme.nmap.org"]},
        ).json()["id"]
        check(
            "job sem RoE = 403",
            client.post(f"/api/engagements/{no_roe}/jobs", headers=H).status_code == 403,
        )

        # ---------- pipeline via worker persistente ----------
        job1_id = start_job(client, eng)
        check(
            "job nasce pending/running (sem BackgroundTasks)",
            client.get(f"/api/jobs/{job1_id}", headers=H).json()["status"]
            in {"pending", "running"},
        )
        job1 = wait_job(client, job1_id)
        check("worker executou o job 1 (completed)", job1["status"] == "completed", job1["status"])
        check("progress = 100", job1["progress"] == 100, str(job1["progress"]))

        findings = client.get(f"/api/findings?engagement_id={eng}&limit=500", headers=H)
        check(f"findings do job 1 = {MOCK_FINDINGS}", len(findings.json()) == MOCK_FINDINGS)
        check(
            "X-Total-Count do findings",
            findings.headers.get("X-Total-Count") == str(MOCK_FINDINGS),
        )

        report = Path(job1["report_path"]).read_text(encoding="utf-8")
        check("relatorio lista o engagement", f"Achados do engagement ({MOCK_FINDINGS})" in report)
        check("relatorio marca novos", f"Novos nesta execução: {MOCK_FINDINGS}" in report)
        check("relatorio com banner MOCK", "modo MOCK" in report)
        check("relatorio com coluna Categoria", "<th>Categoria</th>" in report)

        # ---------- download do relatorio ----------
        dl = client.get(f"/api/jobs/{job1['id']}/report", headers=H)
        check(
            "GET report = 200 text/html",
            dl.status_code == 200 and "text/html" in dl.headers["content-type"],
        )
        no_key_report = client.get(f"/api/jobs/{job1['id']}/report")
        check("report sem key = 401", no_key_report.status_code == 401)
        attach = client.get(f"/api/jobs/{job1['id']}/report?download=1", headers=H)
        check(
            "report ?download=1 vira anexo",
            "attachment" in attach.headers["content-disposition"],
        )

        # ---------- 2a rodada (bug do relatorio vazio) ----------
        job2 = wait_job(client, start_job(client, eng))
        report2 = Path(job2["report_path"]).read_text(encoding="utf-8")
        check(
            "2a rodada: relatorio nao vazio",
            f"Achados do engagement ({MOCK_FINDINGS})" in report2,
        )
        check("2a rodada: 0 novos", "Novos nesta execução: 0" in report2)
        check(
            "2a rodada sem duplicatas",
            len(client.get(f"/api/findings?engagement_id={eng}&limit=500", headers=H).json())
            == MOCK_FINDINGS,
        )

        # ---------- paginacao e filtros de findings ----------
        page = client.get(f"/api/findings?engagement_id={eng}&limit=2", headers=H)
        check("paginacao: limit=2 devolve 2", len(page.json()) == 2)
        check("paginacao: total no header", page.headers.get("X-Total-Count") == str(MOCK_FINDINGS))
        page2 = client.get(f"/api/findings?engagement_id={eng}&limit=2&offset=2", headers=H)
        check("paginacao: offset muda a pagina", page2.json()[0]["id"] != page.json()[0]["id"])
        sev = client.get(f"/api/findings?engagement_id={eng}&severity=medium", headers=H)
        check(
            "filtro por severity",
            bool(sev.json()) and all(item["severity"] == "medium" for item in sev.json()),
        )

        # ---------- auditoria ----------
        audit = client.get(f"/api/audit?engagement_id={eng}&limit=500", headers=H)
        actions = {event["action"] for event in audit.json()}
        check("GET /api/audit = 200", audit.status_code == 200)
        check("audit tem job_completed", "job_completed" in actions, str(sorted(actions))[:110])
        check("audit tem tool_ran", "tool_ran" in actions)
        by_job = client.get(f"/api/audit?job_id={job1['id']}&limit=500", headers=H).json()
        check(
            "audit filtra por job_id",
            bool(by_job) and all(event["detail"].get("job_id") == job1["id"] for event in by_job),
        )
        check(
            "audit filtra por action",
            client.get("/api/audit?action=job_orphaned&limit=5", headers=H).status_code == 200,
        )
        audit_page = client.get("/api/audit?limit=3", headers=H)
        check(
            "audit paginado (limit=3 + total)",
            len(audit_page.json()) == 3 and bool(audit_page.headers.get("X-Total-Count")),
        )
        nmap_ok = [e for e in by_job if e["action"] == "tool_ran" and e["detail"]["tool"] == "nmap"]
        nmap_detail = nmap_ok[0]["detail"] if nmap_ok else {}
        check(
            "audit grava ok/exit_code da tool",
            nmap_detail.get("ok") is True and nmap_detail.get("exit_code") == 0,
        )

        # ---------- cancelamento de job pendente ----------
        worker.stop()
        pending_job = start_job(client, eng)
        cancelled = client.post(f"/api/jobs/{pending_job}/cancel", headers=H)
        check(
            "cancel de job pending = 200 cancelled",
            cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled",
        )
        check(
            "cancel de job terminal = 409",
            client.post(f"/api/jobs/{pending_job}/cancel", headers=H).status_code == 409,
        )
        worker.start()
        check(
            "job cancelado nao e executado depois",
            client.get(f"/api/jobs/{pending_job}", headers=H).json()["status"] == "cancelled",
        )

        # ---------- cancelamento cooperativo de job em execucao ----------
        with patch(
            "app.core.orchestrator.all_adapters",
            adapters_with(whatweb=StubAdapter("whatweb", delay=3.0)),
        ):
            slow_job = start_job(client, eng)
            wait_status(client, slow_job, "running", timeout=10)
            api_cancel = client.post(f"/api/jobs/{slow_job}/cancel", headers=H)
            check(
                "cancel de job running = 200",
                api_cancel.status_code == 200,
                api_cancel.text[:60],
            )
            check(
                "status vira cancelled imediatamente",
                api_cancel.json()["status"] == "cancelled",
            )
            # o pipeline para de forma cooperativa no proximo checkpoint
            stopped = wait_finished(client, slow_job, timeout=25)
        check(
            "pipeline para no cancelamento (cancelled)",
            stopped["status"] == "cancelled",
            str(stopped["status"]),
        )
        check("job cancelado tem finished_at", stopped["finished_at"] is not None)
        check(
            "audit registrou job_cancel_stopped",
            any(
                event["action"] == "job_cancel_stopped"
                for event in client.get(f"/api/audit?job_id={slow_job}&limit=100", headers=H).json()
            ),
        )

        # ---------- isolamento de falha de tool ----------
        with patch(
            "app.core.orchestrator.all_adapters",
            adapters_with(nmap=StubAdapter("nmap", exit_code=2, error="exit code 2")),
        ):
            err_job = wait_job(client, start_job(client, eng))
        check(
            "falha de tool nao derruba o pipeline",
            err_job["status"] == "completed",
            str(err_job["error"]),
        )
        err_findings = client.get(
            f"/api/findings?job_id={err_job['id']}&limit=100", headers=H
        ).json()
        check(
            "tool_error virou achado do job",
            any(
                item["category"] == "tool_error" and item["tool"] == "nmap"
                for item in err_findings
            ),
        )
        err_report = Path(err_job["report_path"]).read_text(encoding="utf-8")
        check("relatorio mostra tool_error", "tool_error" in err_report and "falhou" in err_report)
        err_audit = client.get(f"/api/audit?job_id={err_job['id']}&limit=100", headers=H).json()
        nmap_err = [
            e
            for e in err_audit
            if e["action"] == "tool_ran" and e["detail"]["tool"] == "nmap"
        ]
        check(
            "audit marca ok=false e exit_code",
            bool(nmap_err)
            and nmap_err[0]["detail"]["ok"] is False
            and nmap_err[0]["detail"]["exit_code"] == 2,
        )

    print("-" * 72)
    if FAILURES:
        print(f"FALHAS ({len(FAILURES)}):")
        for item in FAILURES:
            print(f"  - {item}")
        return 1
    print("smoke OK — todos os checks passaram")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
