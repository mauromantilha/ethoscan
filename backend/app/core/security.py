"""Autenticação por API key e sessões locais (login username/password)."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import bcrypt
import redis
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from app.config import get_settings
from app.queue import get_redis

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_lock = threading.Lock()
_sessions: dict[str, "_Session"] = {}


@dataclass
class _Session:
    username: str
    expires_at: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def verify_password(plain: str, password_hash: str) -> bool:
    """Verifica password contra hash bcrypt (bytes ou str UTF-8)."""
    if not plain or not password_hash:
        return False
    try:
        hashed = password_hash.strip().encode("utf-8")
        return bcrypt.checkpw(plain.encode("utf-8"), hashed)
    except (ValueError, TypeError):
        return False


def _session_ttl_seconds(ttl_hours: int | None = None) -> int:
    settings = get_settings()
    hours = ttl_hours if ttl_hours is not None else max(1, settings.ethoscan_session_ttl_hours)
    return int(hours * 3600)


def _store_session(token: str, username: str, ttl_seconds: int) -> bool:
    """Persiste a sessão no Redis (sobrevive a restart). False => fallback em memória."""
    try:
        client = get_redis()
        client.setex(f"{get_settings().ethoscan_session_prefix}{token}", ttl_seconds, username)
        return True
    except redis.RedisError:
        return False


def _load_session(token: str) -> str | None:
    try:
        client = get_redis()
        value = client.get(f"{get_settings().ethoscan_session_prefix}{token}")
    except redis.RedisError:
        return None
    return str(value) if value else None


def _drop_session(token: str) -> bool:
    try:
        client = get_redis()
        return bool(client.delete(f"{get_settings().ethoscan_session_prefix}{token}"))
    except redis.RedisError:
        return False


def create_session_token(username: str, ttl_hours: int | None = None) -> tuple[str, datetime]:
    """Emite token de sessão: Redis quando disponível, senão memória do processo."""
    ttl_seconds = _session_ttl_seconds(ttl_hours)
    token = secrets.token_urlsafe(32)
    expires = _utcnow() + timedelta(seconds=ttl_seconds)
    if not _store_session(token, username, ttl_seconds):
        with _lock:
            _sessions[token] = _Session(username=username, expires_at=expires)
    return token, expires


def revoke_session_token(token: str) -> bool:
    value = token.strip()
    dropped = _drop_session(value)
    with _lock:
        return _sessions.pop(value, None) is not None or dropped


def clear_expired_sessions() -> None:
    now = _utcnow()
    with _lock:
        dead = [k for k, s in _sessions.items() if s.expires_at <= now]
        for k in dead:
            del _sessions[k]


def session_username(token: str) -> str | None:
    value = token.strip()
    username = _load_session(value)
    if username:
        return username
    # fallback: memória do processo (Redis indisponível)
    clear_expired_sessions()
    with _lock:
        session = _sessions.get(value)
        if not session:
            return None
        if session.expires_at <= _utcnow():
            del _sessions[value]
            return None
        return session.username


def credential_accepted(credential: str | None) -> bool:
    """Aceita ETHOSCAN_API_KEY, uma ETHOSCAN_SERVICE_KEYS ou token de sessão válido."""
    if not credential or not credential.strip():
        return False
    value = credential.strip()
    settings = get_settings()
    expected = settings.ethoscan_api_key.strip()
    if expected and secrets.compare_digest(value, expected):
        return True
    for service_key in settings.ethoscan_service_keys.split(","):
        candidate = service_key.strip()
        if candidate and secrets.compare_digest(value, candidate):
            return True
    return session_username(value) is not None


def require_api_key(api_key: str | None = Security(API_KEY_HEADER)) -> None:
    settings = get_settings()
    if not settings.auth_enabled:
        return
    if credential_accepted(api_key):
        return
    raise HTTPException(
        status_code=401,
        detail="API key inválida ou ausente. Envie o header X-API-Key (key ou token de sessão).",
    )


def authenticate_local_user(username: str, password: str) -> tuple[str, datetime]:
    """Valida utilizador local e emite token de sessão (não devolve a master key)."""
    settings = get_settings()
    if not settings.local_user_configured:
        raise HTTPException(
            status_code=503,
            detail="Login local não configurado. Defina ETHOSCAN_LOCAL_USERNAME e "
            "ETHOSCAN_LOCAL_PASSWORD_HASH.",
        )
    expected_user = settings.ethoscan_local_username.strip()
    if username.strip() != expected_user:
        raise HTTPException(status_code=401, detail="Utilizador ou palavra-passe inválidos.")
    if not verify_password(password, settings.ethoscan_local_password_hash):
        raise HTTPException(status_code=401, detail="Utilizador ou palavra-passe inválidos.")
    return create_session_token(expected_user)
