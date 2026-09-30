"""Sessões de login: persistidas no Redis (sobrevivem a restart) com fallback em memória."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import redis

from app.core import security


class FakeRedis:
    """Redis mínimo em memória (setex/get/delete) para os testes."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    def setex(self, key: str, ttl: int, value: str) -> bool:
        self.store[key] = value
        self.ttls[key] = ttl
        return True

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def delete(self, key: str) -> int:
        self.ttls.pop(key, None)
        return 1 if self.store.pop(key, None) is not None else 0


@pytest.fixture
def fake_redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture(autouse=True)
def _clean_memory_sessions():
    """Isola o fallback em memória entre os testes."""
    security._sessions.clear()
    yield
    security._sessions.clear()


def test_session_goes_to_redis_with_configured_ttl(fake_redis: FakeRedis) -> None:
    with patch("app.core.security.get_redis", return_value=fake_redis):
        token, expires = security.create_session_token("mauro")
        assert security.session_username(token) == "mauro"

    key = f"ethoscan:session:{token}"
    assert fake_redis.store[key] == "mauro"
    assert fake_redis.ttls[key] == 12 * 3600  # ETHOSCAN_SESSION_TTL_HOURS default
    assert security._sessions == {}  # nada no fallback em memória
    assert expires > security._utcnow()


def test_session_survives_api_restart(fake_redis: FakeRedis) -> None:
    """Antes as sessões viviam só em memória: um restart derrubava o login do desktop."""
    with patch("app.core.security.get_redis", return_value=fake_redis):
        token, _ = security.create_session_token("mauro")

    # simula restart: o processo perde o estado em memória, o Redis permanece
    security._sessions.clear()

    with patch("app.core.security.get_redis", return_value=fake_redis):
        assert security.session_username(token) == "mauro"
        assert security.credential_accepted(token) is True


def test_revoke_removes_from_redis_and_memory(fake_redis: FakeRedis) -> None:
    with patch("app.core.security.get_redis", return_value=fake_redis):
        token, _ = security.create_session_token("mauro")
        assert security.revoke_session_token(token) is True
        assert security.session_username(token) is None
    assert fake_redis.store == {}


def test_fallback_to_memory_when_redis_is_down() -> None:
    def boom() -> None:
        raise redis.RedisError("sem redis")

    with patch("app.core.security.get_redis", side_effect=boom):
        token, _ = security.create_session_token("mauro")
        assert token in security._sessions  # fallback em memória
        assert security.session_username(token) == "mauro"
        assert security.revoke_session_token(token) is True
        assert security.session_username(token) is None


def test_unknown_token_is_rejected(fake_redis: FakeRedis) -> None:
    with patch("app.core.security.get_redis", return_value=fake_redis):
        assert security.session_username("token-inexistente") is None
        assert security.credential_accepted("token-inexistente") is False
