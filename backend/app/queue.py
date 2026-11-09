"""Fila Redis — API enfileira; worker consome fora do processo HTTP."""

from __future__ import annotations

import logging

import redis

from app.config import get_settings

logger = logging.getLogger("ethoscan.queue")


def get_redis() -> redis.Redis:
    settings = get_settings()
    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=5,
        retry_on_timeout=True,
        health_check_interval=30,
    )


def enqueue_job(job_id: int) -> None:
    settings = get_settings()
    client = get_redis()
    client.lpush(settings.ethoscan_queue_key, str(job_id))
    logger.info("job %s enqueued on %s", job_id, settings.ethoscan_queue_key)


def request_cancel(job_id: int) -> bool:
    """Marca cancelamento no Redis (best-effort; o DB é a fonte de verdade)."""
    settings = get_settings()
    try:
        client = get_redis()
        key = f"{settings.ethoscan_cancel_prefix}{job_id}"
        client.set(key, "1", ex=86400)
        return True
    except redis.RedisError:
        logger.warning("não foi possível marcar cancelamento do job %s no Redis", job_id)
        return False


def is_cancel_requested(job_id: int) -> bool:
    settings = get_settings()
    try:
        client = get_redis()
        key = f"{settings.ethoscan_cancel_prefix}{job_id}"
        return client.exists(key) == 1
    except redis.RedisError:
        return False


def clear_cancel(job_id: int) -> None:
    settings = get_settings()
    try:
        client = get_redis()
        key = f"{settings.ethoscan_cancel_prefix}{job_id}"
        client.delete(key)
    except redis.RedisError:
        return


def pop_job(timeout: int = 5) -> int | None:
    """Move o próximo job da fila para a lista de processamento deste worker."""
    settings = get_settings()
    client = get_redis()
    raw = client.brpoplpush(
        settings.ethoscan_queue_key, settings.processing_key, timeout=timeout
    )
    if not raw:
        return None
    return int(raw)


def ack_job(job_id: int) -> bool:
    """Remove o job da lista de processamento após execução (sucesso ou falha)."""
    settings = get_settings()
    try:
        client = get_redis()
        client.lrem(settings.processing_key, 1, str(job_id))
        return True
    except redis.RedisError:
        logger.warning("não foi possível confirmar (ack) o job %s no Redis", job_id)
        return False


def requeue_processing() -> int:
    """Devolve à fila jobs órfãos deste worker (crash/restart).

    Usa lock Redis curto para evitar duas instâncias com o mesmo worker_id a
    moverem a mesma lista ao mesmo tempo. O worker_id deve ser estável no deploy.
    """
    settings = get_settings()
    try:
        client = get_redis()
        lock_key = f"{settings.processing_key}:requeue-lock"
        if not client.set(lock_key, "1", nx=True, ex=10):
            return 0
        moved = 0
        try:
            while True:
                item = client.rpoplpush(settings.processing_key, settings.ethoscan_queue_key)
                if not item:
                    break
                moved += 1
        finally:
            try:
                client.delete(lock_key)
            except redis.RedisError:
                pass
        return moved
    except redis.RedisError:
        logger.warning("não foi possível recuperar jobs órfãos do worker %s", settings.worker_id)
        return 0


def set_worker_heartbeat() -> bool:
    settings = get_settings()
    try:
        client = get_redis()
        client.setex(
            settings.ethoscan_worker_heartbeat_key,
            max(5, settings.ethoscan_worker_heartbeat_ttl_seconds),
            settings.worker_id,
        )
        return True
    except redis.RedisError:
        return False


def worker_heartbeat_alive() -> bool:
    settings = get_settings()
    try:
        return bool(get_redis().exists(settings.ethoscan_worker_heartbeat_key))
    except redis.RedisError:
        return False


def ping_redis() -> bool:
    try:
        return bool(get_redis().ping())
    except redis.RedisError:
        return False


# --- Webhook de conclusão (usado pela API de integração/n8n) ----------------
# Guardado no Redis com TTL para sobreviver a restart da API/worker sem schema novo.
CALLBACK_TTL_SECONDS = 7 * 24 * 3600


def set_callback(job_id: int, url: str) -> bool:
    """Registra o webhook de conclusão do job. Best-effort: nunca derruba a requisição."""
    settings = get_settings()
    try:
        client = get_redis()
        client.set(f"{settings.ethoscan_callback_prefix}{job_id}", url, ex=CALLBACK_TTL_SECONDS)
        return True
    except redis.RedisError:
        logger.warning("não foi possível registrar callback do job %s (Redis indisponível)", job_id)
        return False


def get_callback(job_id: int) -> str | None:
    settings = get_settings()
    try:
        client = get_redis()
        value = client.get(f"{settings.ethoscan_callback_prefix}{job_id}")
        return str(value) if value else None
    except redis.RedisError:
        return None


def clear_callback(job_id: int) -> None:
    settings = get_settings()
    try:
        client = get_redis()
        client.delete(f"{settings.ethoscan_callback_prefix}{job_id}")
    except redis.RedisError:
        return
