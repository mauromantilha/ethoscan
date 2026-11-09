"""Testes da Fase 1: auth fail-closed e defaults seguros."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.core import security
from app.main import _validate_auth_settings


def _settings(**overrides) -> Settings:
    base = {
        "_env_file": None,
        "ethoscan_mode": "local",
        "ethoscan_api_key": "",
        "ethoscan_disable_auth": False,
        "ethoscan_local_username": "",
        "ethoscan_local_password_hash": "",
        "ethoscan_service_keys": "",
        "ethoscan_allow_mock": False,
    }
    base.update(overrides)
    return Settings(**base)


def test_allow_mock_default_is_false(monkeypatch) -> None:
    monkeypatch.delenv("ETHOSCAN_ALLOW_MOCK", raising=False)
    assert Settings(_env_file=None).ethoscan_allow_mock is False


def test_service_keys_enable_auth() -> None:
    settings = _settings(ethoscan_service_keys="n8n-key, outra-key")
    assert settings.service_keys == ["n8n-key", "outra-key"]
    assert settings.auth_enabled is True


def test_disable_auth_still_wins() -> None:
    settings = _settings(ethoscan_service_keys="n8n-key", ethoscan_disable_auth=True)
    assert settings.auth_enabled is False


def test_non_local_without_auth_fails() -> None:
    with pytest.raises(RuntimeError, match="Auth obrigatória"):
        _validate_auth_settings(_settings(ethoscan_mode="remote"))


def test_non_local_disable_auth_fails() -> None:
    with pytest.raises(RuntimeError, match="DISABLE_AUTH"):
        _validate_auth_settings(
            _settings(ethoscan_mode="remote", ethoscan_disable_auth=True)
        )


def test_non_local_weak_master_key_fails() -> None:
    with pytest.raises(RuntimeError, match="default/fracas"):
        _validate_auth_settings(
            _settings(ethoscan_mode="remote", ethoscan_api_key="change-me-local")
        )


def test_non_local_weak_service_key_fails() -> None:
    with pytest.raises(RuntimeError, match="default/fracas"):
        _validate_auth_settings(
            _settings(
                ethoscan_mode="remote",
                ethoscan_service_keys="n8n-key,change-me-local",
            )
        )


def test_local_without_auth_only_warns() -> None:
    with patch("app.main.logger.warning") as warning:
        _validate_auth_settings(_settings())
    warning.assert_called_once()
    assert "Auth desligada" in warning.call_args.args[0]


def test_local_weak_key_warns() -> None:
    with patch("app.main.logger.warning") as warning:
        _validate_auth_settings(_settings(ethoscan_api_key="change-me-local"))
    warning.assert_called_once()
    assert "default/fracas" in warning.call_args.args[0]


def test_require_api_key_accepts_service_key_only(monkeypatch) -> None:
    settings = _settings(ethoscan_service_keys="n8n-key")
    monkeypatch.setattr(security, "get_settings", lambda: settings)

    with pytest.raises(HTTPException) as exc:
        security.require_api_key(None)
    assert exc.value.status_code == 401

    # Não levanta: a service key é credencial válida e auth está ativa.
    security.require_api_key("n8n-key")


def test_lifespan_fails_closed_outside_local(tmp_path, monkeypatch) -> None:
    """Garante que a validação está ligada ao lifespan da API, não só ao helper."""
    from importlib import reload

    from fastapi.testclient import TestClient

    from app.config import get_settings

    monkeypatch.setenv("ETHOSCAN_MODE", "remote")
    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "false")
    monkeypatch.setenv("ETHOSCAN_API_KEY", "")
    monkeypatch.setenv("ETHOSCAN_SERVICE_KEYS", "")
    monkeypatch.setenv("ETHOSCAN_LOCAL_USERNAME", "")
    monkeypatch.setenv("ETHOSCAN_LOCAL_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'fail-closed.db'}")
    monkeypatch.setenv("ETHOSCAN_ARTIFACTS_DIR", str(tmp_path / "art"))
    (tmp_path / "art").mkdir()
    get_settings.cache_clear()

    import app.main as mainmod

    reload(mainmod)

    with pytest.raises(RuntimeError, match="Auth obrigatória"):
        with TestClient(mainmod.app):
            pass

    get_settings.cache_clear()
