"""Testes da dependência de autenticação (Sprint 1) — fail-closed."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from app.core import security


def _settings(**overrides: Any) -> Any:
    base = {"ethoscan_api_key": "chave-correta"}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_require_api_key_accepts_valid_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "get_settings", lambda: _settings())
    security.require_api_key("chave-correta")  # não levanta


@pytest.mark.parametrize("provided", [None, "", "chave-errada"])
def test_require_api_key_rejects(monkeypatch: pytest.MonkeyPatch, provided: str | None) -> None:
    monkeypatch.setattr(security, "get_settings", lambda: _settings())
    with pytest.raises(HTTPException) as exc:
        security.require_api_key(provided)
    assert exc.value.status_code == 401


def test_require_api_key_fail_closed_without_configured_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sem ETHOSCAN_API_KEY a API não libera nada (503), mesmo com header."""
    monkeypatch.setattr(security, "get_settings", lambda: _settings(ethoscan_api_key=""))
    with pytest.raises(HTTPException) as exc:
        security.require_api_key("qualquer")
    assert exc.value.status_code == 503
    assert "ETHOSCAN_API_KEY" in str(exc.value.detail)


def test_api_rejects_without_header(client: Any) -> None:
    assert client.get("/api/engagements").status_code == 401


def test_health_is_public_and_describes_runtime(client: Any) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["mock_forced"] is True
    assert body["worker_enabled"] is True
    assert set(body["tools"]) == {"nmap", "whatweb", "gobuster", "sslscan", "nuclei"}
