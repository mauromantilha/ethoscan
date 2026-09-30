"""Testes do worker persistente: claim atômico, watchdog de órfãos e poller."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.orm import Session

from app.core import worker as worker_module
from app.core.worker import ORPHAN_ERROR, JobWorker, claim_next_job, recover_orphan_jobs
from app.db import SessionLocal
from app.models import AuditEvent, Engagement, Job, JobStatus


@pytest.fixture
def db() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def quiet_worker(worker: Any) -> Iterator[Any]:
    """Para o worker da app: evita que ele reivindique os jobs dos testes unitários."""
    worker.stop()
    yield worker
    worker.start()


def _engagement(db: Session, name: str = "Worker") -> Engagement:
    engagement = Engagement(name=name, scope_targets=["scanme.nmap.org"], roe_acknowledged=True)
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return engagement


def _job(db: Session, engagement: Engagement, status: JobStatus) -> Job:
    job = Job(engagement_id=engagement.id, status=status, phase="F0", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _drain(db: Session) -> int:
    drained = 0
    while claim_next_job(db) is not None:
        drained += 1
    return drained


def test_claim_returns_none_without_pending_jobs(db: Session, quiet_worker: Any) -> None:
    _drain(db)
    assert claim_next_job(db) is None


def test_claim_is_atomic_and_marks_running(db: Session, quiet_worker: Any) -> None:
    _drain(db)
    engagement = _engagement(db)
    job = _job(db, engagement, JobStatus.pending)

    claimed = claim_next_job(db)
    assert claimed == job.id

    db.refresh(job)
    assert job.status is JobStatus.running
    assert job.started_at is not None
    # segundo claim não pega o mesmo job
    assert claim_next_job(db) is None


def test_recover_orphan_jobs_marks_failed_with_audit(db: Session, quiet_worker: Any) -> None:
    _drain(db)
    engagement = _engagement(db, "Órfãos")
    running = _job(db, engagement, JobStatus.running)
    running.current_tool = "nuclei"
    running.started_at = datetime.now(UTC)
    pending = _job(db, engagement, JobStatus.pending)
    db.commit()

    assert recover_orphan_jobs(db) == 1

    db.refresh(running)
    db.refresh(pending)
    assert running.status is JobStatus.failed
    assert running.error == ORPHAN_ERROR
    assert running.finished_at is not None
    assert running.current_tool is None
    assert pending.status is JobStatus.pending  # não mexe no que ainda não rodou

    actions = {event.action for event in db.query(AuditEvent).all()}
    assert "job_orphaned" in actions


def test_recover_orphan_jobs_without_running_returns_zero(db: Session, quiet_worker: Any) -> None:
    _drain(db)
    db.query(Job).filter(Job.status == JobStatus.running).update({"status": JobStatus.failed})
    db.commit()
    assert recover_orphan_jobs(db) == 0


def test_worker_disabled_does_not_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        worker_module,
        "get_settings",
        lambda: SimpleNamespace(
            ethoscan_worker_enabled=False,
            ethoscan_worker_concurrency=1,
            ethoscan_worker_poll_interval=0.5,
        ),
    )
    disabled = JobWorker()
    disabled.start()
    assert disabled.enabled is False
    assert disabled.running_threads == 0


def test_poll_once_is_noop_without_jobs(db: Session, quiet_worker: Any) -> None:
    _drain(db)
    assert quiet_worker.poll_once() is False
