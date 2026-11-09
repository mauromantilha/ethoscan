"""Cancelamento: o DB é a fonte de verdade mesmo com Redis indisponível."""

from __future__ import annotations

from unittest.mock import patch

from app import db as dbmod
from app.models import Job, JobStatus


def _create_job(client) -> int:
    response = client.post(
        "/api/engagements",
        json={
            "name": "Cancel running",
            "scope_targets": ["scanme.nmap.org"],
            "roe_acknowledged": True,
        },
    )
    assert response.status_code == 200, response.text
    engagement_id = response.json()["id"]
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        job_response = client.post(f"/api/engagements/{engagement_id}/jobs")
    assert job_response.status_code == 200, job_response.text
    return job_response.json()["job"]["id"]


def test_cancel_running_job_sets_db_status_without_redis(client) -> None:
    job_id = _create_job(client)

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        job.status = JobStatus.running
        db.commit()
    finally:
        db.close()

    with patch("app.api.routes.request_cancel", return_value=False):
        response = client.post(f"/api/jobs/{job_id}/cancel")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "cancelled"

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.status == JobStatus.cancelled
        assert job.error
    finally:
        db.close()


def test_cancel_completed_job_is_conflict(client) -> None:
    job_id = _create_job(client)
    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        job.status = JobStatus.completed
        db.commit()
    finally:
        db.close()

    response = client.post(f"/api/jobs/{job_id}/cancel")
    assert response.status_code == 409
