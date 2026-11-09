"""Testes da fila Redis: ack, requeue, heartbeat e cancelamento best-effort."""

from __future__ import annotations

import pytest
import redis

from app import queue
from app.config import get_settings


class FakeRedis:
    """Redis mínimo em memória para listas e chaves."""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.kv: dict[str, str] = {}

    def lpush(self, key: str, *values: str) -> int:
        items = self.lists.setdefault(key, [])
        for value in values:
            items.insert(0, str(value))
        return len(items)

    def rpush(self, key: str, *values: str) -> int:
        items = self.lists.setdefault(key, [])
        items.extend(str(value) for value in values)
        return len(items)

    def _move_right_to_left(self, src: str, dst: str) -> str | None:
        source = self.lists.get(src, [])
        if not source:
            return None
        item = source.pop()
        self.lists.setdefault(dst, []).insert(0, item)
        return item

    def brpoplpush(self, src: str, dst: str, timeout: int = 0) -> str | None:
        return self._move_right_to_left(src, dst)

    def rpoplpush(self, src: str, dst: str) -> str | None:
        return self._move_right_to_left(src, dst)

    def lrem(self, key: str, count: int, value: str) -> int:
        items = self.lists.get(key, [])
        removed = 0
        kept: list[str] = []
        for item in items:
            if item == value and (count == 0 or removed < count):
                removed += 1
                continue
            kept.append(item)
        self.lists[key] = kept
        return removed

    def set(self, key: str, value: str, ex: int | None = None, nx: bool = False):
        if nx and key in self.kv:
            return None
        self.kv[key] = str(value)
        return True

    def setex(self, key: str, ttl: int, value: str) -> bool:
        self.kv[key] = str(value)
        return True

    def exists(self, key: str) -> int:
        return int(key in self.kv)

    def delete(self, key: str) -> int:
        return 1 if self.kv.pop(key, None) is not None else 0

    def get(self, key: str) -> str | None:
        return self.kv.get(key)

    def ping(self) -> bool:
        return True


@pytest.fixture()
def fake_redis(monkeypatch) -> FakeRedis:
    fake = FakeRedis()
    monkeypatch.setattr(queue, "get_redis", lambda: fake)
    return fake


def test_pop_moves_to_processing_and_ack_removes(fake_redis: FakeRedis) -> None:
    settings = get_settings()
    queue.enqueue_job(7)
    assert fake_redis.lists[settings.ethoscan_queue_key] == ["7"]

    assert queue.pop_job(timeout=1) == 7
    assert fake_redis.lists[settings.ethoscan_queue_key] == []
    assert fake_redis.lists[settings.processing_key] == ["7"]

    assert queue.ack_job(7) is True
    assert fake_redis.lists[settings.processing_key] == []


def test_requeue_processing_moves_orphans(fake_redis: FakeRedis) -> None:
    settings = get_settings()
    fake_redis.lists[settings.processing_key] = ["1", "2"]

    assert queue.requeue_processing() == 2
    assert fake_redis.lists[settings.processing_key] == []
    assert set(fake_redis.lists[settings.ethoscan_queue_key]) == {"1", "2"}


def test_requeue_processing_respects_lock(fake_redis: FakeRedis) -> None:
    settings = get_settings()
    fake_redis.lists[settings.processing_key] = ["1"]
    fake_redis.kv[f"{settings.processing_key}:requeue-lock"] = "1"

    assert queue.requeue_processing() == 0
    assert fake_redis.lists[settings.processing_key] == ["1"]


def test_worker_heartbeat(fake_redis: FakeRedis) -> None:
    assert queue.worker_heartbeat_alive() is False
    assert queue.set_worker_heartbeat() is True
    assert queue.worker_heartbeat_alive() is True


def test_request_cancel_returns_true(fake_redis: FakeRedis) -> None:
    settings = get_settings()
    assert queue.request_cancel(42) is True
    assert fake_redis.kv[f"{settings.ethoscan_cancel_prefix}42"] == "1"


def test_request_cancel_is_best_effort_when_redis_down(monkeypatch) -> None:
    def boom():
        raise redis.RedisError("sem redis")

    monkeypatch.setattr(queue, "get_redis", boom)
    assert queue.request_cancel(42) is False


def test_get_redis_sets_timeouts() -> None:
    client = queue.get_redis()
    kwargs = client.connection_pool.connection_kwargs
    assert kwargs["socket_connect_timeout"] == 2
    assert kwargs["socket_timeout"] == 5
