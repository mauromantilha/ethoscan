"""Testes do worker: seleção de jobs e delegação ao pipeline."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app import db as dbmod
from app.models import Engagement, Job, JobStatus
from app.worker import process_one


@pytest.fixture(autouse=True)
def _patch_ack() -> None:
    """Evita chamadas reais ao Redis no ack do job."""
    with patch("app.worker.ack_job"):
        yield


def _make_job(status: JobStatus) -> int:
    db = dbmod.SessionLocal()
    try:
        engagement = Engagement(
            name="Worker test",
            scope_targets=["scanme.nmap.org"],
            roe_acknowledged=True,
        )
        db.add(engagement)
        db.commit()
        db.refresh(engagement)
        job = Job(
            engagement_id=engagement.id,
            status=status,
            phase="F0",
            progress=0,
            tool_runs={},
            selected_tools=[],
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job.id
    finally:
        db.close()


def test_process_one_ignores_missing_job(client) -> None:
    # Não deve levantar para um job inexistente.
    process_one(999_999)


def test_process_one_skips_cancelled_job(client) -> None:
    job_id = _make_job(JobStatus.cancelled)
    with patch("app.worker.clear_cancel") as clear_cancel:
        process_one(job_id)
    clear_cancel.assert_called_once_with(job_id)


def test_process_one_skips_terminal_job(client) -> None:
    job_id = _make_job(JobStatus.completed)
    with patch("app.worker.run_pipeline") as run_pipeline:
        process_one(job_id)
    run_pipeline.assert_not_called()


def test_process_one_runs_pending_job(client) -> None:
    job_id = _make_job(JobStatus.pending)
    with patch("app.worker.run_pipeline") as run_pipeline:
        process_one(job_id)
    run_pipeline.assert_called_once()
    assert run_pipeline.call_args.args[1] == job_id
