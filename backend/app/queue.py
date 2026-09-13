"""Fila Redis — API enfileira; worker consome fora do processo HTTP."""

from __future__ import annotations

import logging

import redis

from app.config import get_settings

logger = logging.getLogger("ethoscan.queue")


def get_redis() -> redis.Redis:
    settings = get_settings()
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def enqueue_job(job_id: int) -> None:
    settings = get_settings()
    client = get_redis()
    client.lpush(settings.ethoscan_queue_key, str(job_id))
    logger.info("job %s enqueued on %s", job_id, settings.ethoscan_queue_key)


def request_cancel(job_id: int) -> None:
    settings = get_settings()
    client = get_redis()
    key = f"{settings.ethoscan_cancel_prefix}{job_id}"
    client.set(key, "1", ex=86400)


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
    settings = get_settings()
    client = get_redis()
    item = client.brpop(settings.ethoscan_queue_key, timeout=timeout)
    if not item:
        return None
    _, raw = item
    return int(raw)


def ping_redis() -> bool:
    try:
        return bool(get_redis().ping())
    except redis.RedisError:
        return False
