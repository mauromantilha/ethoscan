"""Testes do endpoint /api/history e prune de tools redundantes."""

from __future__ import annotations

from unittest.mock import patch

from app.core.orchestrator import _prune_redundant_tools, run_pipeline
from app import db as dbmod
from app.models import Job, JobStatus


def test_prune_redundant_skips_masscan_msf_when_nmap_safe():
    assert _prune_redundant_tools(
        ["nmap", "sslscan", "masscan", "metasploit", "nuclei"],
        "safe",
    ) == ["nmap", "sslscan", "nuclei"]
    assert _prune_redundant_tools(["masscan", "nuclei"], "safe") == ["masscan", "nuclei"]
    # aggressive mantém tudo
    assert _prune_redundant_tools(
        ["nmap", "masscan", "metasploit"],
        "aggressive",
    ) == ["nmap", "masscan", "metasploit"]


def test_history_endpoint_lists_jobs_with_findings(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Histórico Lab",
            "scope_targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
            "selected_tools": ["nmap"],
        },
    )
    assert r.status_code == 200
    eng = r.json()
    eng_id = eng["id"]

    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        jr = client.post(
            f"/api/engagements/{eng_id}/jobs",
            json={"selected_tools": ["nmap"]},
        )
    assert jr.status_code == 200
    job_id = jr.json()["job"]["id"]

    with dbmod.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job is not None
        run_pipeline(db, job_id)
        job = db.get(Job, job_id)
        assert job.status == JobStatus.completed

    hist = client.get("/api/history")
    assert hist.status_code == 200
    items = hist.json()
    assert isinstance(items, list)
    assert len(items) >= 1
    item = next(i for i in items if i["job_id"] == job_id)
    assert item["engagement_id"] == eng_id
    assert item["engagement_name"] == "Histórico Lab"
    assert item["status"] == "completed"
    assert item["findings_count"] >= 1
    assert item["has_html_report"] is True
    assert "nmap" in item["selected_tools"]
    assert item["intensity"] == "safe"

    filtered = client.get(f"/api/history?engagement_id={eng_id}")
    assert filtered.status_code == 200
    assert all(i["engagement_id"] == eng_id for i in filtered.json())
