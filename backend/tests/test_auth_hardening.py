"""Hardening de auth: rate limit, timing e epoch de sessão."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import redis
from fastapi import HTTPException

from app.config import Settings, get_settings
from app.core import security


def test_login_rate_limit_per_ip(monkeypatch) -> None:
    monkeypatch.setenv("ETHOSCAN_LOGIN_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("ETHOSCAN_LOGIN_WINDOW_SECONDS", "60")
    get_settings.cache_clear()
    security.reset_login_rate_limit()

    security.check_login_rate_limit("1.2.3.4")
    security.check_login_rate_limit("1.2.3.4")
    with pytest.raises(HTTPException) as exc:
        security.check_login_rate_limit("1.2.3.4")
    assert exc.value.status_code == 429

    # Outro IP não é afetado.
    security.check_login_rate_limit("5.6.7.8")
    security.reset_login_rate_limit()
    get_settings.cache_clear()


def test_wrong_username_still_runs_bcrypt(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        ethoscan_local_username="mauro",
        ethoscan_local_password_hash="$2b$12$invalid-but-not-used",
        ethoscan_session_epoch=1,
    )
    monkeypatch.setattr(security, "get_settings", lambda: settings)

    with patch("app.core.security.verify_password", return_value=False) as verify:
        with pytest.raises(HTTPException) as exc:
            security.authenticate_local_user("nao-existe", "qualquer")
    assert exc.value.status_code == 401
    verify.assert_called_once()
    assert verify.call_args.args[1] == security._DUMMY_PASSWORD_HASH


def test_session_epoch_invalidates_memory_sessions(monkeypatch) -> None:
    epoch1 = Settings(_env_file=None, ethoscan_session_epoch=1)
    epoch2 = Settings(_env_file=None, ethoscan_session_epoch=2)
    security._sessions.clear()

    with patch("app.core.security.get_redis", side_effect=redis.RedisError("sem redis")):
        monkeypatch.setattr(security, "get_settings", lambda: epoch1)
        token, _ = security.create_session_token("mauro")
        assert security.session_username(token) == "mauro"

        monkeypatch.setattr(security, "get_settings", lambda: epoch2)
        assert security.session_username(token) is None

    security._sessions.clear()
