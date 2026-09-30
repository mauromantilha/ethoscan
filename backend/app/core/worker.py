"""Worker de execução de jobs (Sprint 2 — P1).

Substitui o ``BackgroundTasks`` in-process por um poller de banco:

- jobs nascem ``pending`` e são reivindicados de forma atômica (``UPDATE ... WHERE
  status='pending'``), então sobrevivem ao restart da API e funcionam com vários
  processos/workers sem executar o mesmo job duas vezes;
- no startup, jobs ``running`` deixados por uma instância anterior (job órfão) são
  marcados como ``failed`` com motivo explícito;
- o cancelamento é cooperativo: a API marca ``cancelled`` e o pipeline verifica o
  status entre fases/tools e para.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.orchestrator import audit, run_pipeline
from app.db import SessionLocal
from app.models import Job, JobStatus

logger = logging.getLogger(__name__)

ORPHAN_ERROR = "interrompido: instância anterior encerrou com o job em execução (job órfão)"


def claim_next_job(db: Session) -> int | None:
    """Reivindica o job ``pending`` mais antigo. Atômico entre processos."""
    job_id = db.execute(
        select(Job.id).where(Job.status == JobStatus.pending).order_by(Job.id.asc()).limit(1)
    ).scalar_one_or_none()
    if job_id is None:
        return None

    claimed = db.execute(
        update(Job)
        .where(Job.id == job_id, Job.status == JobStatus.pending)
        .values(status=JobStatus.running, started_at=datetime.now(UTC))
    )
    db.commit()
    if claimed.rowcount != 1:
        # outro worker venceu a corrida
        return None
    logger.info("job reivindicado", extra={"job_id": job_id})
    return job_id


def recover_orphan_jobs(db: Session) -> int:
    """Marca como ``failed`` os jobs que ficaram ``running`` de uma instância anterior."""
    rows = db.execute(
        select(Job.id, Job.engagement_id).where(Job.status == JobStatus.running)
    ).all()
    if not rows:
        return 0

    now = datetime.now(UTC)
    db.execute(
        update(Job)
        .where(Job.id.in_([row[0] for row in rows]), Job.status == JobStatus.running)
        .values(status=JobStatus.failed, error=ORPHAN_ERROR, finished_at=now, current_tool=None)
    )
    db.commit()
    for job_id, engagement_id in rows:
        logger.warning(
            "job órfão marcado como failed",
            extra={"job_id": job_id, "engagement_id": engagement_id, "status": "failed"},
        )
        audit(db, engagement_id, "job_orphaned", {"job_id": job_id, "reason": ORPHAN_ERROR})
    return len(rows)


def _mark_failed(job_id: int, error: str) -> None:
    """Rede de segurança: garante que nenhum job fique preso em ``running``."""
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        finished = {JobStatus.completed, JobStatus.failed, JobStatus.cancelled}
        if job is None or job.status in finished:
            return
        job.status = JobStatus.failed
        job.error = job.error or error
        job.finished_at = datetime.now(UTC)
        db.commit()
        logger.error("job marcado como failed", extra={"job_id": job.id, "status": "failed"})
        audit(db, job.engagement_id, "job_failed", {"job_id": job.id, "error": job.error})
    finally:
        db.close()


class JobWorker:
    """Poller com N threads: cada thread reivindica e executa um job por vez."""

    def __init__(self) -> None:
        settings = get_settings()
        self.enabled = settings.ethoscan_worker_enabled
        self.concurrency = max(1, min(4, settings.ethoscan_worker_concurrency))
        self.poll_interval = max(0.1, settings.ethoscan_worker_poll_interval)
        self.orphans_recovered = 0
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    @property
    def running_threads(self) -> int:
        return sum(1 for thread in self._threads if thread.is_alive())

    def start(self) -> None:
        if not self.enabled:
            logger.warning(
                "worker desabilitado (ETHOSCAN_WORKER_ENABLED=false): jobs ficam pending"
            )
            return
        if self.running_threads:
            return

        db = SessionLocal()
        try:
            self.orphans_recovered = recover_orphan_jobs(db)
        finally:
            db.close()
        if self.orphans_recovered:
            logger.warning(
                "worker: %s job(s) órfão(s) marcado(s) como failed", self.orphans_recovered
            )

        self._stop.clear()
        for index in range(self.concurrency):
            thread = threading.Thread(
                target=self._loop, name=f"ethoscan-worker-{index + 1}", daemon=True
            )
            thread.start()
            self._threads.append(thread)

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=timeout)
        self._threads.clear()

    def _loop(self) -> None:
        while not self._stop.is_set():
            if not self.poll_once():
                self._stop.wait(self.poll_interval)

    def poll_once(self) -> bool:
        """Reivindica e executa um job de forma síncrona. True se executou algo."""
        db = SessionLocal()
        try:
            job_id = claim_next_job(db)
        finally:
            db.close()
        if job_id is None:
            return False

        db = SessionLocal()
        try:
            run_pipeline(db, job_id)
        except Exception:  # noqa: BLE001 - worker nunca pode morrer por causa de um job
            logger.exception("worker: falha inesperada no job %s", job_id, extra={"job_id": job_id})
            _mark_failed(job_id, "erro inesperado no worker")
        finally:
            db.close()
        return True


_worker: JobWorker | None = None


def get_worker() -> JobWorker:
    global _worker
    if _worker is None:
        _worker = JobWorker()
    return _worker
