"""Catálogo de tools, selected_tools e relatório PDF."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from app.core.orchestrator import run_pipeline
from app import db as dbmod
from app.models import Job, JobStatus
from app.tool_catalog import resolve_selected_tools, validate_selected_tools


def test_tool_catalog_schema(client):
    r = client.get("/api/tools")
    assert r.status_code == 200
    data = r.json()
    assert "tools" in data
    assert "default_pipeline" in data
    assert set(data["default_pipeline"]) == {"nmap", "whatweb", "gobuster", "sslscan", "nuclei"}
    ids = {t["id"] for t in data["tools"]}
    for required in ("nmap", "nuclei", "zap", "burpsuite", "metasploit", "nikto", "masscan"):
        assert required in ids
    by_id = {t["id"]: t for t in data["tools"]}
    assert by_id["nmap"]["runnable"] is True
    assert by_id["burpsuite"]["runnable"] is False
    assert by_id["burpsuite"]["launchable"] is True
    assert by_id["metasploit"]["runnable"] is True
    for t in data["tools"]:
        assert "display_name" in t
        assert "category" in t
        assert "available" in t
        assert "status" in t
        assert "description" in t


def test_resolve_selected_tools_defaults():
    assert resolve_selected_tools(None) == [
        "nmap",
        "whatweb",
        "gobuster",
        "sslscan",
        "nuclei",
    ]
    assert resolve_selected_tools([]) == [
        "nmap",
        "whatweb",
        "gobuster",
        "sslscan",
        "nuclei",
    ]
    assert resolve_selected_tools(["nmap", "nikto", "burpsuite"]) == ["nmap", "nikto"]


def test_validate_rejects_unknown():
    try:
        validate_selected_tools(["nmap", "not-a-tool"])
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "desconhecidas" in str(exc).lower() or "not-a-tool" in str(exc)


def test_selected_tools_filters_pipeline(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Só Nmap",
            "scope_targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
            "selected_tools": ["nmap"],
        },
    )
    assert r.status_code == 200
    eng = r.json()
    assert eng["selected_tools"] == ["nmap"]
    eng_id = eng["id"]

    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        jr = client.post(f"/api/engagements/{eng_id}/jobs", json={})
    assert jr.status_code == 200
    job_id = jr.json()["job"]["id"]
    assert jr.json()["job"]["selected_tools"] == ["nmap"]

    run_pipeline(dbmod.SessionLocal(), job_id)

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.status == JobStatus.completed
        assert job.selected_tools == ["nmap"]
        # Apenas nmap deve ter corrido (além do gate)
        ran = {k for k, v in (job.tool_runs or {}).items() if v.get("command") or v.get("last_target")}
        assert "nmap" in (job.tool_runs or {})
        assert "nuclei" not in ran
        assert "gobuster" not in ran
    finally:
        db.close()

    fr = client.get("/api/findings", params={"job_id": job_id})
    assert fr.status_code == 200
    assert all(f["tool"] == "nmap" for f in fr.json())


def test_empty_selection_runs_classic_pipeline(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Pipeline clássico",
            "scope_targets": ["scanme.nmap.org"],
            "roe_acknowledged": True,
            "selected_tools": [],
        },
    )
    eng_id = r.json()["id"]
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        jr = client.post(f"/api/engagements/{eng_id}/jobs")
    job_id = jr.json()["job"]["id"]
    run_pipeline(dbmod.SessionLocal(), job_id)
    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job.status == JobStatus.completed
        assert set(job.selected_tools) == {"nmap", "whatweb", "gobuster", "sslscan", "nuclei"}
    finally:
        db.close()


def test_pdf_report_endpoint(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "PDF Lab",
            "scope_targets": ["scanme.nmap.org"],
            "roe_acknowledged": True,
            "selected_tools": ["nmap"],
        },
    )
    eng_id = r.json()["id"]
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        jr = client.post(f"/api/engagements/{eng_id}/jobs", json={"selected_tools": ["nmap"]})
    job_id = jr.json()["job"]["id"]
    run_pipeline(dbmod.SessionLocal(), job_id)

    pdf = client.get(f"/api/jobs/{job_id}/report.pdf")
    assert pdf.status_code == 200
    assert "application/pdf" in pdf.headers.get("content-type", "")
    assert pdf.content[:4] == b"%PDF"

    html = client.get(f"/api/jobs/{job_id}/report")
    assert html.status_code == 200
    assert "text/html" in html.headers.get("content-type", "")

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job.report_pdf_path
        assert Path(job.report_pdf_path).is_file()
    finally:
        db.close()


def test_roe_still_required_with_selected_tools(client):
    r = client.post(
        "/api/engagements",
        json={
            "name": "Sem RoE tools",
            "scope_targets": ["scanme.nmap.org"],
            "roe_acknowledged": False,
            "selected_tools": ["nmap"],
        },
    )
    eng_id = r.json()["id"]
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        jr = client.post(
            f"/api/engagements/{eng_id}/jobs",
            json={"selected_tools": ["nmap"]},
        )
    assert jr.status_code == 403
