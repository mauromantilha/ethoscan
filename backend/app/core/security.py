"""Autenticação mínima por API key (header X-API-Key)."""

from __future__ import annotations

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from app.config import get_settings

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(API_KEY_HEADER)) -> None:
    settings = get_settings()
    if not settings.auth_enabled:
        return
    expected = settings.ethoscan_api_key.strip()
    if not api_key or api_key.strip() != expected:
        raise HTTPException(
            status_code=401,
            detail="API key inválida ou ausente. Envie o header X-API-Key.",
        )
