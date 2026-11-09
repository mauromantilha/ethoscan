"""Worker dedicado — consome a fila Redis fora do processo da API."""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time

from app import db as dbmod
from app.config import get_settings
from app.core.orchestrator import run_pipeline
from app.db import init_db
from app.logging_conf import configure_logging
from app.models import Job, JobStatus
from app.queue import (
    ack_job,
    clear_cancel,
    ping_redis,
    pop_job,
    requeue_processing,
    set_worker_heartbeat,
)

configure_logging()
# libs de terceiros (redis, sqlalchemy) mantêm o handler do root
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ethoscan.worker")

_running = True


def _handle_signal(signum, _frame) -> None:
    global _running
    logger.info("sinal %s — encerrando worker após job atual", signum)
    _running = False


def process_one(job_id: int) -> None:
    db = dbmod.SessionLocal()
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
        # Mesmo que o pipeline falhe, o job sai da lista de processamento.
        ack_job(job_id)


def _heartbeat_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        set_worker_heartbeat()
        stop_event.wait(10)


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

    requeued = requeue_processing()
    if requeued:
        logger.warning("recuperados %s job(s) órfão(s) do worker %s", requeued, settings.worker_id)

    heartbeat_stop = threading.Event()
    heartbeat = threading.Thread(
        target=_heartbeat_loop, args=(heartbeat_stop,), name="ethoscan-heartbeat", daemon=True
    )
    heartbeat.start()
    set_worker_heartbeat()

    try:
        while _running:
            try:
                job_id = pop_job(timeout=1)
            except Exception as exc:
                logger.error("erro ao ler fila: %s", exc)
                time.sleep(2)
                continue
            if job_id is None:
                continue
            try:
                process_one(job_id)
            except Exception:
                logger.exception("falha ao processar job %s", job_id)
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=2)
        logger.info("worker parado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
