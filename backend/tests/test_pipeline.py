"""E2E do pipeline via worker: mock, relatório, tool_error e cancelamento."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


def test_pipeline_completes_and_reports(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
    mock_findings: int,
) -> None:
    engagement_id = make_engagement("Pipeline")
    job_id = start_job(engagement_id)

    # job nasce pending e é reivindicado pelo worker (sem BackgroundTasks)
    assert client.get(f"/api/jobs/{job_id}", headers=headers).json()["status"] in {
        "pending",
        "running",
    }

    job = wait_job(job_id)
    assert job["status"] == "completed", job
    assert job["progress"] == 100
    assert job["report_path"]

    findings = client.get(
        f"/api/findings?engagement_id={engagement_id}&limit=500", headers=headers
    ).json()
    assert len(findings) == mock_findings
    categories = {item["category"] for item in findings}
    assert categories >= {"network", "recon", "web-discovery", "tls", "vuln"}

    report = Path(job["report_path"]).read_text(encoding="utf-8")
    assert f"Achados do engagement ({mock_findings})" in report
    assert f"Novos nesta execução: {mock_findings}" in report
    assert "modo MOCK" in report


def test_second_run_keeps_report_and_dedups(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
    mock_findings: int,
) -> None:
    engagement_id = make_engagement("Segunda rodada")
    wait_job(start_job(engagement_id))
    second = wait_job(start_job(engagement_id))

    report = Path(second["report_path"]).read_text(encoding="utf-8")
    # regressão Sprint 1: o relatório da 2ª rodada ficava vazio
    assert f"Achados do engagement ({mock_findings})" in report
    assert "Novos nesta execução: 0" in report

    findings = client.get(
        f"/api/findings?engagement_id={engagement_id}&limit=500", headers=headers
    ).json()
    assert len(findings) == mock_findings
    assert len({item["fingerprint"] for item in findings}) == mock_findings


def test_tool_failure_is_isolated(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
    stub_adapter: Callable[..., Any],
    adapters_patch: Callable[..., Any],
) -> None:
    """Uma tool com exit != 0 não derruba o pipeline e vira achado explícito."""
    engagement_id = make_engagement("Tool error")
    failing = stub_adapter("nmap", exit_code=2, error="exit code 2")

    with adapters_patch(nmap=failing):
        job = wait_job(start_job(engagement_id))

    assert job["status"] == "completed", job
    assert job["error"] is None

    findings = client.get(
        f"/api/findings?job_id={job['id']}&limit=100", headers=headers
    ).json()
    tool_errors = [item for item in findings if item["category"] == "tool_error"]
    assert len(tool_errors) == 1
    assert tool_errors[0]["tool"] == "nmap"
    assert "falhou" in tool_errors[0]["title"]

    report = Path(job["report_path"]).read_text(encoding="utf-8")
    assert "tool_error" in report

    audit = client.get(f"/api/audit?job_id={job['id']}&limit=100", headers=headers).json()
    nmap_event = [
        event
        for event in audit
        if event["action"] == "tool_ran" and event["detail"]["tool"] == "nmap"
    ][0]
    assert nmap_event["detail"]["ok"] is False
    assert nmap_event["detail"]["exit_code"] == 2


def test_cancel_pending_job_is_never_executed(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    worker: Any,
) -> None:
    engagement_id = make_engagement("Cancel pending")
    worker.stop()
    try:
        job_id = start_job(engagement_id)
        cancelled = client.post(f"/api/jobs/{job_id}/cancel", headers=headers)
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        assert cancelled.json()["finished_at"] is not None
    finally:
        worker.start()

    assert client.get(f"/api/jobs/{job_id}", headers=headers).json()["status"] == "cancelled"


def test_cancel_running_job_stops_pipeline(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    stub_adapter: Callable[..., Any],
    adapters_patch: Callable[..., Any],
) -> None:
    """Cancelamento é cooperativo: a API marca e o pipeline para no checkpoint."""
    engagement_id = make_engagement("Cancel running")
    slow = stub_adapter("whatweb", delay=3.0)

    with adapters_patch(whatweb=slow):
        job_id = start_job(engagement_id)
        waited = 0.0
        while waited < 10.0:
            job = client.get(f"/api/jobs/{job_id}", headers=headers).json()
            if job["status"] == "running":
                break
            waited += 0.1
            time.sleep(0.1)

        assert client.post(f"/api/jobs/{job_id}/cancel", headers=headers).status_code == 200

        # espera o pipeline realmente parar (finished_at preenchido)
        waited = 0.0
        job = client.get(f"/api/jobs/{job_id}", headers=headers).json()
        while waited < 25.0 and job["finished_at"] is None:
            time.sleep(0.2)
            waited += 0.2
            job = client.get(f"/api/jobs/{job_id}", headers=headers).json()

    assert job["status"] == "cancelled", job
    assert job["finished_at"] is not None
    audit = client.get(f"/api/audit?job_id={job_id}&limit=100", headers=headers).json()
    assert any(event["action"] == "job_cancel_stopped" for event in audit)
