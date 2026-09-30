"""Testes dos endpoints HTTP: contratos, validações, paginação e audit."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient


def test_engagements_crud_and_errors(
    client: TestClient, headers: dict[str, str]
) -> None:
    created = client.post(
        "/api/engagements",
        headers=headers,
        json={"name": "Lab", "scope_targets": ["http://Scanme.NMAP.org/x"]},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["scope_targets"] == ["scanme.nmap.org"]
    assert body["roe_acknowledged"] is False

    assert client.get("/api/engagements", headers=headers).status_code == 200
    assert client.get(f"/api/engagements/{body['id']}", headers=headers).status_code == 200
    assert client.get("/api/engagements/999999", headers=headers).status_code == 404


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        ({"name": "X", "scope_targets": ["ex.com"]}, 422),  # nome curto
        ({"name": "Valido", "scope_targets": ["com"]}, 400),  # TLD
        ({"name": "Valido", "scope_targets": ["nao eh alvo!"]}, 400),
        ({"name": "Valido", "scope_targets": ["example.com"]}, 403),  # fora da allowlist
    ],
)
def test_create_engagement_validations(
    client: TestClient, headers: dict[str, str], payload: dict[str, Any], status: int
) -> None:
    response = client.post("/api/engagements", headers=headers, json=payload)
    assert response.status_code == status, response.text


def test_job_requires_roe(
    client: TestClient, headers: dict[str, str], make_engagement: Callable[..., int]
) -> None:
    engagement_id = make_engagement("Sem RoE", roe=False)
    response = client.post(f"/api/engagements/{engagement_id}/jobs", headers=headers)
    assert response.status_code == 403


def test_jobs_endpoints(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
) -> None:
    engagement_id = make_engagement("Jobs")
    job_id = start_job(engagement_id)

    listed = client.get(f"/api/jobs?engagement_id={engagement_id}", headers=headers).json()
    assert [job["id"] for job in listed] == [job_id]
    detail = client.get(f"/api/jobs/{job_id}", headers=headers).json()
    assert detail["engagement_id"] == engagement_id
    assert client.get("/api/jobs/999999", headers=headers).status_code == 404


def test_findings_pagination_and_filters(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
    mock_findings: int,
) -> None:
    engagement_id = make_engagement("Findings")
    wait_job(start_job(engagement_id))

    page = client.get(f"/api/findings?engagement_id={engagement_id}&limit=2", headers=headers)
    assert len(page.json()) == 2
    assert page.headers["X-Total-Count"] == str(mock_findings)

    second = client.get(
        f"/api/findings?engagement_id={engagement_id}&limit=2&offset=2", headers=headers
    ).json()
    assert {item["id"] for item in second}.isdisjoint({item["id"] for item in page.json()})

    medium = client.get(
        f"/api/findings?engagement_id={engagement_id}&severity=medium&limit=100", headers=headers
    ).json()
    assert medium and all(item["severity"] == "medium" for item in medium)

    too_big = client.get(
        f"/api/findings?engagement_id={engagement_id}&limit=501", headers=headers
    )
    assert too_big.status_code == 422


def test_audit_filters_and_pagination(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
) -> None:
    engagement_id = make_engagement("Audit")
    job_id = start_job(engagement_id)
    wait_job(job_id)

    everything = client.get(f"/api/audit?engagement_id={engagement_id}&limit=500", headers=headers)
    actions = {event["action"] for event in everything.json()}
    expected = {"engagement_created", "job_queued", "job_started", "tool_ran", "job_completed"}
    assert expected <= actions
    assert everything.headers["X-Total-Count"] == str(len(everything.json()))

    by_job = client.get(f"/api/audit?job_id={job_id}&limit=500", headers=headers).json()
    assert by_job and all(event["detail"].get("job_id") == job_id for event in by_job)

    by_action = client.get("/api/audit?action=job_queued&limit=5", headers=headers)
    assert by_action.status_code == 200
    assert all(event["action"] == "job_queued" for event in by_action.json())

    tool_events = [
        event
        for event in by_job
        if event["action"] == "tool_ran" and event["detail"]["tool"] == "nmap"
    ]
    assert tool_events and tool_events[0]["detail"]["ok"] is True
    assert tool_events[0]["detail"]["exit_code"] == 0


def test_report_download_rules(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
) -> None:
    engagement_id = make_engagement("Relatório")
    job_id = start_job(engagement_id)

    wait_job(job_id)
    inline = client.get(f"/api/jobs/{job_id}/report", headers=headers)
    assert inline.status_code == 200
    assert "text/html" in inline.headers["content-type"]
    assert "content-disposition" not in inline.headers

    attachment = client.get(f"/api/jobs/{job_id}/report?download=1", headers=headers)
    assert attachment.headers["content-disposition"].startswith("attachment")

    assert client.get(f"/api/jobs/{job_id}/report").status_code == 401


def test_cancel_terminal_job_conflicts(
    client: TestClient,
    headers: dict[str, str],
    make_engagement: Callable[..., int],
    start_job: Callable[..., int],
    wait_job: Callable[..., dict[str, Any]],
) -> None:
    engagement_id = make_engagement("Cancel 409")
    job_id = start_job(engagement_id)
    wait_job(job_id)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=headers).status_code == 409
    assert client.post("/api/jobs/999999/cancel", headers=headers).status_code == 404


@pytest.mark.parametrize("path", ["/api/engagements", "/api/jobs", "/api/findings", "/api/audit"])
def test_api_paths_require_key(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 401
