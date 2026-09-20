"""Worker dedicado — consome a fila Redis fora do processo da API."""

from __future__ import annotations

import logging
import signal
import sys
import time

from app.config import get_settings
from app.core.orchestrator import run_pipeline
from app.db import SessionLocal, init_db
from app.models import Job, JobStatus
from app.queue import clear_cancel, ping_redis, pop_job

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ethoscan.worker")

_running = True


def _handle_signal(signum, _frame) -> None:  # noqa: ANN001
    global _running
    logger.info("sinal %s — encerrando worker após job atual", signum)
    _running = False


def process_one(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        if not job:
            logger.warning("job %s não encontrado — ignorando", job_id)
            return
        if job.status == JobStatus.cancelled:
            logger.info("job %s já cancelado — não executa", job_id)
            clear_cancel(job_id)
            return
        if job.status not in {JobStatus.pending, JobStatus.running}:
            logger.info("job %s status=%s — ignorando", job_id, job.status.value)
            return
        logger.info("processando job %s (engagement %s)", job_id, job.engagement_id)
        run_pipeline(db, job_id)
    finally:
        db.close()


def main() -> int:
    settings = get_settings()
    init_db()
    logger.info(
        "Ethoscan worker mode=%s redis=%s queue=%s",
        settings.ethoscan_mode,
        settings.redis_url,
        settings.ethoscan_queue_key,
    )
    if not ping_redis():
        logger.error("Redis indisponível em %s — abortando", settings.redis_url)
        return 1

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    while _running:
        try:
            job_id = pop_job(timeout=1)
        except Exception as exc:  # noqa: BLE001
            logger.error("erro ao ler fila: %s", exc)
            time.sleep(2)
            continue
        if job_id is None:
            continue
        try:
            process_one(job_id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("falha ao processar job %s: %s", job_id, exc)

    logger.info("worker parado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
