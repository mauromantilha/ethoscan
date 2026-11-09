"""Regressões da Fase 2: dedupe entre jobs, relatório fiel e Nuclei safe."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from app import db as dbmod
from app.adapters.nuclei import NucleiAdapter
from app.core.orchestrator import run_pipeline
from app.models import Finding, Job, JobStatus, Severity


def _queue_and_run(client, engagement_id: int) -> int:
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        response = client.post(f"/api/engagements/{engagement_id}/jobs")
    assert response.status_code == 200, response.text
    job_id = response.json()["job"]["id"]
    run_pipeline(dbmod.SessionLocal(), job_id)
    return job_id


def _create_engagement(client) -> int:
    response = client.post(
        "/api/engagements",
        json={
            "name": "Report integrity",
            "scope_targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
            "selected_tools": ["nmap"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_rerun_keeps_findings_visible_for_each_job(client) -> None:
    engagement_id = _create_engagement(client)
    job1 = _queue_and_run(client, engagement_id)
    job2 = _queue_and_run(client, engagement_id)

    for job_id in (job1, job2):
        response = client.get("/api/findings", params={"job_id": job_id})
        assert response.status_code == 200
        assert response.headers["X-Total-Count"] == "2"
        assert len(response.json()) == 2

    # O engagement não duplica os findings entre execuções.
    all_findings = client.get(
        "/api/findings", params={"engagement_id": engagement_id}
    )
    assert all_findings.headers["X-Total-Count"] == "2"

    history = client.get("/api/history", params={"engagement_id": engagement_id}).json()
    by_job = {item["job_id"]: item for item in history}
    assert by_job[job1]["findings_count"] == 2
    assert by_job[job2]["findings_count"] == 2

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job2)
        assert job is not None
        assert job.status == JobStatus.completed
        assert job.report_path
        html = Path(job.report_path).read_text()
    finally:
        db.close()

    assert "Job #2 — completed — fase F6" in html
    assert "Achados (2)" in html
    assert "MOCK" in html


def test_report_pdf_is_generated_for_second_job(client) -> None:
    engagement_id = _create_engagement(client)
    _queue_and_run(client, engagement_id)
    job2 = _queue_and_run(client, engagement_id)

    response = client.get(f"/api/jobs/{job2}/report.pdf")
    assert response.status_code == 200
    assert response.content[:4] == b"%PDF"

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job2)
        assert job is not None
        assert job.report_pdf_path
        assert Path(job.report_pdf_path).is_file()
    finally:
        db.close()


def test_nuclei_safe_keeps_high_and_critical(tmp_path, monkeypatch) -> None:
    adapter = NucleiAdapter()
    payload = (
        '{"info":{"name":"CVE crítica","severity":"critical"},'
        '"matched-at":"https://scanme.nmap.org"}\n'
    )
    captured: dict[str, list[str]] = {}

    def fake_exec(command, timeout=120):
        captured["command"] = command
        return payload, "", 0

    monkeypatch.setattr(adapter, "_exec", fake_exec)
    result = adapter._run_real("scanme.nmap.org", tmp_path, "safe")

    command = captured["command"]
    severity = command[command.index("-severity") + 1]
    assert "high" in severity
    assert "critical" in severity
    assert result.findings
    assert result.findings[0].severity == Severity.critical


def test_finding_unique_per_engagement(client) -> None:
    """A dedupe é garantida também no schema (unique engagement+fingerprint)."""
    engagement_id = _create_engagement(client)
    _queue_and_run(client, engagement_id)
    _queue_and_run(client, engagement_id)

    db = dbmod.SessionLocal()
    try:
        findings = db.query(Finding).filter(Finding.engagement_id == engagement_id).all()
        fingerprints = [finding.fingerprint for finding in findings]
        assert len(fingerprints) == len(set(fingerprints)) == 2
    finally:
        db.close()
