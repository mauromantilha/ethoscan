"""Smoke tests Ethoscan — sem tools Kali (mock)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from app.core.orchestrator import run_pipeline
from app import db as dbmod
from app.models import Job, JobStatus


def test_health_exposes_tools_and_mock(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["mock_allowed"] is True
    assert "auth_enabled" in data
    tools = data["tools"]
    for name in ("nmap", "whatweb", "gobuster", "sslscan", "nuclei"):
        assert name in tools
        assert "available" in tools[name]
        assert "will_mock" in tools[name]
        assert "mode" in tools[name]
    assert "F0" in data["phases"]
    assert "F6" in data["phases"]


def test_roe_denied_on_start(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Sem RoE",
            "scope_targets": ["scanme.nmap.org"],
            "roe_acknowledged": False,
        },
    )
    assert r.status_code == 200
    eng_id = r.json()["id"]
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        jr = client.post(f"/api/engagements/{eng_id}/jobs")
    assert jr.status_code == 403


def test_invalid_scope_rejected(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Bad",
            "scope_targets": ["not a host!!!"],
            "roe_acknowledged": True,
        },
    )
    assert r.status_code == 400


def test_create_run_findings_report_under_mock(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Mock Lab",
            "scope_targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
        },
    )
    assert r.status_code == 200
    eng_id = r.json()["id"]

    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ) as enq:
        jr = client.post(f"/api/engagements/{eng_id}/jobs")
        assert jr.status_code == 200
        job = jr.json()["job"]
        job_id = job["id"]
        assert job["phase"] == "F0"
        assert job["status"] == "pending"
        enq.assert_called_once_with(job_id)

    # Simula worker (sem Redis)
    run_pipeline(dbmod.SessionLocal(), job_id)

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.status == JobStatus.completed
        assert job.phase == "F6"
        assert job.progress == 100
        assert job.report_path
        assert Path(job.report_path).is_file()
        assert isinstance(job.tool_runs, dict)
        assert any(v.get("mocked") for v in job.tool_runs.values())
    finally:
        db.close()

    fr = client.get("/api/findings", params={"engagement_id": eng_id})
    assert fr.status_code == 200
    findings = fr.json()
    assert len(findings) >= 1
    assert any(f.get("mocked") for f in findings)

    rr = client.get(f"/api/jobs/{job_id}/report")
    assert rr.status_code == 200
    assert "text/html" in rr.headers.get("content-type", "")
    assert b"Ethoscan" in rr.content or b"ethoscan" in rr.content.lower()


def test_cancel_pending(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Cancel Me",
            "scope_targets": ["scanme.nmap.org"],
            "roe_acknowledged": True,
        },
    )
    eng_id = r.json()["id"]
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ), patch("app.api.routes.request_cancel"):
        jr = client.post(f"/api/engagements/{eng_id}/jobs")
        job_id = jr.json()["job"]["id"]
        cr = client.post(f"/api/jobs/{job_id}/cancel")
    assert cr.status_code == 200
    assert cr.json()["status"] == "cancelled"


def test_auth_required_when_key_set(tmp_path, monkeypatch):
    from app.config import get_settings
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "false")
    monkeypatch.setenv("ETHOSCAN_API_KEY", "secret-test-key")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'auth.db'}")
    monkeypatch.setenv("ETHOSCAN_ARTIFACTS_DIR", str(tmp_path / "art"))
    (tmp_path / "art").mkdir()
    get_settings.cache_clear()

    from app import db as dbmod
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db import Base
    from app import models  # noqa: F401
    from importlib import reload
    import app.main as mainmod

    dbmod.engine = create_engine(
        f"sqlite:///{tmp_path / 'auth.db'}", connect_args={"check_same_thread": False}
    )
    dbmod.SessionLocal = sessionmaker(bind=dbmod.engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=dbmod.engine)
    reload(mainmod)

    c = TestClient(mainmod.app)
    denied = c.get("/api/engagements")
    assert denied.status_code == 401
    ok = c.get("/api/engagements", headers={"X-API-Key": "secret-test-key"})
    assert ok.status_code == 200

    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "true")
    get_settings.cache_clear()
