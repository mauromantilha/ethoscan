"""Testes do endurecimento de escopo/allowlist (Sprint 1) — sem HTTP."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.core.authz import (
    assert_in_allowlist,
    assert_in_scope,
    is_valid_target,
    normalize_target,
    validate_allowlist,
    validate_scope,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://Example.COM/path?x=1", "example.com"),
        ("https://sub.ex.com:8443/a", "sub.ex.com"),
        ("10.0.0.5/24", "10.0.0.0/24"),
        ("example.com.", "example.com"),
        ("  SCANME.NMAP.ORG  ", "scanme.nmap.org"),
    ],
)
def test_normalize_target(raw: str, expected: str) -> None:
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("raw", ["scanme.nmap.org", "10.0.0.0/24", "localhost", "http://ex.com/x"])
def test_is_valid_target_accepts(raw: str) -> None:
    assert is_valid_target(raw) is True


@pytest.mark.parametrize(
    "raw", ["", "com", "io", "co.uk", "com.br", "-bad.com", "a..b", "nao eh alvo!"]
)
def test_is_valid_target_rejects(raw: str) -> None:
    """TLD/sufixo público e lixo não podem virar escopo (Sprint 1: allowlist por TLD)."""
    assert is_valid_target(raw) is False


def test_validate_scope_normalizes_and_rejects() -> None:
    assert validate_scope(["http://Example.com/x", "10.0.0.5/24"]) == ["example.com", "10.0.0.0/24"]
    with pytest.raises(HTTPException) as exc:
        validate_scope(["com"])
    assert exc.value.status_code == 400


def test_assert_in_scope_exact_cidr_and_subdomain() -> None:
    assert_in_scope("scanme.nmap.org", ["scanme.nmap.org"])
    assert_in_scope("10.0.0.5", ["10.0.0.0/24"])
    assert_in_scope("sub.ex.com", ["ex.com"])


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("outro.com", ["ex.com"]),
        ("ex.com.evil.io", ["ex.com"]),
        ("10.0.1.5", ["10.0.0.0/24"]),
        ("169.254.169.254", ["ex.com"]),
    ],
)
def test_assert_in_scope_blocks(target: str, scope: list[str]) -> None:
    with pytest.raises(HTTPException) as exc:
        assert_in_scope(target, scope)
    assert exc.value.status_code == 403


def test_validate_allowlist() -> None:
    assert validate_allowlist(["lab.ex.com", "10.10.0.0/24"]) == ["lab.ex.com", "10.10.0.0/24"]
    for bad in ("com", "co.uk"):
        with pytest.raises(ValueError, match="entradas inválidas"):
            validate_allowlist([bad])


def test_assert_in_allowlist_is_noop_when_empty() -> None:
    assert_in_allowlist("qualquercoisa.com", [])


def test_assert_in_allowlist_blocks_and_ignores_invalid_entries() -> None:
    assert_in_allowlist("sub.scanme.nmap.org", ["scanme.nmap.org"])
    with pytest.raises(HTTPException) as exc:
        assert_in_allowlist("example.com", ["scanme.nmap.org"])
    assert exc.value.status_code == 403
    # entrada inválida (TLD) não pode ampliar o escopo por casamento de sufixo
    with pytest.raises(HTTPException):
        assert_in_allowlist("qualquercoisa.com", ["com"])


def test_assert_roe_requires_ack() -> None:
    from app.core.authz import assert_roe

    assert_roe(True)
    with pytest.raises(HTTPException) as exc:
        assert_roe(False)
    assert exc.value.status_code == 403
