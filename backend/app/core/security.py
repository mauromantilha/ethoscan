"""Controle de acesso da API (Sprint 1 — P0: API sem autenticação).

A API roda ferramentas de varredura e por isso falha fechada: sem
``ETHOSCAN_API_KEY`` configurada nada em ``/api/*`` é liberado.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from app.config import get_settings

API_KEY_HEADER = "X-API-Key"


def require_api_key(x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER)) -> None:
    """Dependência que exige o header ``X-API-Key`` válido em ``/api/*``."""
    expected = get_settings().ethoscan_api_key.strip()

    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "ETHOSCAN_API_KEY não configurada: API bloqueada (fail-closed). "
                "Gere uma chave com `openssl rand -hex 32`, defina ETHOSCAN_API_KEY no .env "
                "e reinicie a API."
            ),
        )

    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"API key ausente ou inválida (envie o header {API_KEY_HEADER}).",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )
