"""Testes de isolamento de falha de tool e dos endpoints de auditoria/paginação.

Cobrem os deltas ainda ausentes no main: exit_code/ok do AdapterResult,
tool_error como achado (sem derrubar o job), /api/audit e paginação.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from app import db as dbmod
from app.adapters import all_adapters
from app.adapters.base import AdapterResult, BaseAdapter
from app.core.orchestrator import run_pipeline
from app.models import Finding, Job, JobStatus


class _FailingAdapter(BaseAdapter):
    """Stub determinístico: sempre falha (exit code != 0)."""

    binary = "ethoscan-stub"

    def __init__(self, name: str, *, exit_code: int = 2) -> None:
        self.name = name
        self._exit_code = exit_code

    def available(self) -> bool:
        return True

    def run(self, target: str, _job_dir: Any, _intensity: str = "safe") -> AdapterResult:
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=["stub", self.name, target],
            stderr="stub: falhou ao executar",
            exit_code=self._exit_code,
            error=f"exit code {self._exit_code}",
        )

    def _run_real(self, target: str, job_dir: Any, intensity: str) -> AdapterResult:
        raise NotImplementedError

    def _run_mock(self, target: str, job_dir: Any, intensity: str) -> AdapterResult:
        raise NotImplementedError


def _adapters_with(**replacements: BaseAdapter):
    def factory():
        return [replacements.get(adapter.name, adapter) for adapter in all_adapters()]

    return factory


def _create_engagement(client, name: str = "Tool error") -> int:
    response = client.post(
        "/api/engagements",
        json={
            "name": name,
            "scope_targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _enqueue_and_run(client, engagement_id: int) -> int:
    """Enfileira via API (Redis mockado) e roda o pipeline no processo do teste."""
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        response = client.post(f"/api/engagements/{engagement_id}/jobs")
    assert response.status_code == 200, response.text
    job_id = response.json()["job"]["id"]
    run_pipeline(dbmod.SessionLocal(), job_id)
    return job_id


def test_adapter_result_ok_semantics() -> None:
    base = AdapterResult(tool="t", mocked=False, command=["t"])
    assert base.ok is True
    assert AdapterResult(tool="t", mocked=False, command=["t"], exit_code=0).ok is True
    assert AdapterResult(tool="t", mocked=False, command=["t"], exit_code=2).ok is False
    assert AdapterResult(tool="t", mocked=False, command=["t"], error="boom").ok is False


def test_tool_failure_becomes_finding_and_job_completes(client):
    engagement_id = _create_engagement(client)
    failing = _FailingAdapter("whatweb", exit_code=2)

    with patch("app.core.orchestrator.all_adapters", _adapters_with(whatweb=failing)):
        job_id = _enqueue_and_run(client, engagement_id)

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        # falha de uma tool não derruba o pipeline
        assert job.status == JobStatus.completed, job.error
        assert job.report_path
        # tool_runs registra ok/exit_code do adapter
        assert job.tool_runs["whatweb"]["ok"] is False
        assert job.tool_runs["whatweb"]["exit_code"] == 2
        tool_errors = (
            db.query(Finding)
            .filter(Finding.job_id == job_id, Finding.category == "tool_error")
            .all()
        )
        assert len(tool_errors) == 1
        assert tool_errors[0].tool == "whatweb"
        assert "falhou" in tool_errors[0].title

        found = client.get("/api/findings", params={"job_id": job_id, "limit": 500}).json()
        assert any(item["category"] == "tool_error" for item in found)

        audit = client.get("/api/audit", params={"job_id": job_id, "limit": 500})
        assert audit.status_code == 200
        whatweb_events = [
            event
            for event in audit.json()
            if event["action"] == "tool_ran" and event["detail"]["tool"] == "whatweb"
        ]
        assert whatweb_events and whatweb_events[0]["detail"]["ok"] is False
        assert whatweb_events[0]["detail"]["exit_code"] == 2
    finally:
        db.close()


def test_audit_endpoint_filters_and_pagination(client):
    engagement_id = _create_engagement(client, "Audit")
    job_id = _enqueue_and_run(client, engagement_id)

    everything = client.get("/api/audit", params={"engagement_id": engagement_id, "limit": 500})
    assert everything.status_code == 200
    actions = {event["action"] for event in everything.json()}
    expected = {"engagement_created", "job_queued", "job_started", "tool_ran", "job_completed"}
    assert expected <= actions
    assert everything.headers["X-Total-Count"] == str(len(everything.json()))

    by_job = client.get("/api/audit", params={"job_id": job_id, "limit": 500}).json()
    assert by_job and all(event["detail"].get("job_id") == job_id for event in by_job)

    by_action = client.get("/api/audit", params={"action": "job_queued", "limit": 500}).json()
    assert by_action and all(event["action"] == "job_queued" for event in by_action)

    page = client.get("/api/audit", params={"limit": 2})
    assert len(page.json()) == 2
    assert int(page.headers["X-Total-Count"]) >= 2

    assert client.get("/api/audit", params={"limit": 501}).status_code == 422


def test_findings_pagination_and_severity_filter(client):
    engagement_id = _create_engagement(client, "Paginacao")
    _enqueue_and_run(client, engagement_id)

    listed = client.get("/api/findings", params={"engagement_id": engagement_id})
    total = int(listed.headers["X-Total-Count"])
    assert total >= 1

    page = client.get("/api/findings", params={"engagement_id": engagement_id, "limit": 2})
    assert len(page.json()) == 2

    second = client.get(
        "/api/findings", params={"engagement_id": engagement_id, "limit": 2, "offset": 2}
    ).json()
    assert {item["id"] for item in second}.isdisjoint({item["id"] for item in page.json()})

    medium = client.get(
        "/api/findings",
        params={"engagement_id": engagement_id, "severity": "medium", "limit": 500},
    ).json()
    assert all(item["severity"] == "medium" for item in medium)

    assert client.get("/api/findings", params={"limit": 501}).status_code == 422
