"""Testes do hardening de escopo/allowlist: rejeição de TLD + ETHOSCAN_ALLOWLIST global.

Contexto: no main anterior, ``validate_scope("com")`` era aceito e não havia allowlist global —
qualquer credencial válida podia escanear qualquer host. Estes testes fixam o comportamento novo.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.config import get_settings
from app.core.authz import (
    assert_in_allowlist,
    assert_in_scope,
    assert_targets_allowed,
    is_valid_target,
    normalize_target,
    validate_allowlist,
    validate_scope,
)

ENGAGEMENTS = "/api/engagements"
SCAN = "/api/integrations/n8n/scan"


@pytest.mark.parametrize("raw", ["com", "io", "co.uk", "com.br", "-bad.com", "a..b", ""])
def test_is_valid_target_rejects_tld_and_junk(raw: str) -> None:
    assert is_valid_target(raw) is False


@pytest.mark.parametrize(
    "raw", ["scanme.nmap.org", "localhost", "10.0.0.0/24", "10.0.0.5", "http://ex.com/x"]
)
def test_is_valid_target_accepts(raw: str) -> None:
    assert is_valid_target(raw) is True


def test_normalize_target_forms() -> None:
    assert normalize_target("http://Example.COM/path") == "example.com"
    assert normalize_target("10.0.0.5/24") == "10.0.0.0/24"
    assert normalize_target("example.com.") == "example.com"


def test_validate_scope_rejects_tld_and_normalizes() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_scope(["com"])
    assert exc.value.status_code == 400
    assert validate_scope(["http://Example.com/x"]) == ["example.com"]


def test_validate_allowlist() -> None:
    assert validate_allowlist([]) == []
    assert validate_allowlist(["lab.ex.com", "10.10.0.0/24"]) == ["lab.ex.com", "10.10.0.0/24"]
    for bad in ("com", "co.uk", "nao eh alvo!"):
        with pytest.raises(ValueError, match="entradas inválidas"):
            validate_allowlist([bad])


def test_assert_in_allowlist_semantics() -> None:
    assert_in_allowlist("qualquercoisa.com", [])  # vazia = sem restrição adicional
    assert_in_allowlist("sub.scanme.nmap.org", ["scanme.nmap.org"])
    assert_in_allowlist("10.0.0.5", ["10.0.0.0/24"])

    with pytest.raises(HTTPException) as exc:
        assert_in_allowlist("example.com", ["scanme.nmap.org"])
    assert exc.value.status_code == 403

    # entrada inválida (TLD) não pode ampliar o escopo por casamento de sufixo
    with pytest.raises(HTTPException):
        assert_in_allowlist("qualquercoisa.com", ["com"])
    with pytest.raises(HTTPException):
        assert_targets_allowed(["ok.com", "fora.org"], ["ok.com"])


def test_assert_in_scope_semantics_preserved() -> None:
    assert_in_scope("sub.ex.com", ["ex.com"])
    with pytest.raises(HTTPException):
        assert_in_scope("ex.com.evil.io", ["ex.com"])


def test_create_engagement_respects_global_allowlist(client, monkeypatch) -> None:
    monkeypatch.setenv("ETHOSCAN_ALLOWLIST", "scanme.nmap.org,10.10.0.0/24")
    get_settings.cache_clear()

    inside = client.post(
        ENGAGEMENTS,
        json={"name": "Dentro", "scope_targets": ["scanme.nmap.org"], "roe_acknowledged": True},
    )
    assert inside.status_code == 200, inside.text

    outside = client.post(
        ENGAGEMENTS,
        json={"name": "Fora", "scope_targets": ["example.com"], "roe_acknowledged": True},
    )
    assert outside.status_code == 403
    assert "ETHOSCAN_ALLOWLIST" in outside.json()["detail"]

    tld = client.post(
        ENGAGEMENTS,
        json={"name": "TLD", "scope_targets": ["com"], "roe_acknowledged": True},
    )
    assert tld.status_code == 400


def test_integration_scan_respects_global_allowlist(client, monkeypatch) -> None:
    monkeypatch.setenv("ETHOSCAN_ALLOWLIST", "scanme.nmap.org")
    get_settings.cache_clear()
    response = client.post(
        SCAN,
        json={"name": "n8n fora", "targets": ["example.com"], "roe_acknowledged": True},
    )
    assert response.status_code == 403
    assert "ETHOSCAN_ALLOWLIST" in response.json()["detail"]


def test_allowlist_empty_keeps_previous_behaviour(client) -> None:
    """Sem ETHOSCAN_ALLOWLIST a criação continua livre (só o escopo do engagement)."""
    response = client.post(
        ENGAGEMENTS,
        json={"name": "Livre", "scope_targets": ["example.com"], "roe_acknowledged": True},
    )
    assert response.status_code == 200, response.text
