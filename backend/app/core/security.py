"""Autenticação por API key, service keys e sessões locais (login username/password)."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import bcrypt
import redis
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from app.config import get_settings
from app.queue import get_redis

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_lock = threading.Lock()
_sessions: dict[str, _Session] = {}

# Hash válido para gastar o mesmo tempo de bcrypt quando o username não existe.
# Hash público usado só para igualar o custo de bcrypt; não é uma credencial.
_DUMMY_PASSWORD_HASH = "$2b$12$wtzQpnf9fTjiWgTExodQMOFEP8/79aWp/PuabPzDDR25Pcfi1cK4O"  # noqa: S105

_login_lock = threading.Lock()
_login_attempts: dict[str, list[float]] = {}


@dataclass
class _Session:
    username: str
    expires_at: datetime
    epoch: int


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _constant_time_equal(left: str, right: str) -> bool:
    """Comparação timing-safe também para valores não-ASCII."""
    if not left or not right:
        return False
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


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


def _session_key(token: str, epoch: int | None = None) -> str:
    settings = get_settings()
    current_epoch = settings.ethoscan_session_epoch if epoch is None else epoch
    return f"{settings.ethoscan_session_prefix}{current_epoch}:{token}"


def _store_session(token: str, username: str, ttl_seconds: int, epoch: int) -> bool:
    """Persiste a sessão no Redis (sobrevive a restart). False => fallback em memória."""
    try:
        client = get_redis()
        client.setex(_session_key(token, epoch), ttl_seconds, username)
        return True
    except redis.RedisError:
        return False


def _load_session(token: str) -> str | None:
    try:
        client = get_redis()
        value = client.get(_session_key(token))
    except redis.RedisError:
        return None
    return str(value) if value else None


def _drop_session(token: str) -> bool:
    try:
        client = get_redis()
        return bool(client.delete(_session_key(token)))
    except redis.RedisError:
        return False


def create_session_token(username: str, ttl_hours: int | None = None) -> tuple[str, datetime]:
    """Emite token de sessão: Redis quando disponível, senão memória do processo."""
    ttl_seconds = _session_ttl_seconds(ttl_hours)
    token = secrets.token_urlsafe(32)
    expires = _utcnow() + timedelta(seconds=ttl_seconds)
    epoch = get_settings().ethoscan_session_epoch
    if not _store_session(token, username, ttl_seconds, epoch):
        with _lock:
            _sessions[token] = _Session(username=username, expires_at=expires, epoch=epoch)
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
    settings = get_settings()
    with _lock:
        session = _sessions.get(value)
        if not session:
            return None
        if session.expires_at <= _utcnow() or session.epoch != settings.ethoscan_session_epoch:
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
    if expected and _constant_time_equal(value, expected):
        return True
    for service_key in settings.service_keys:
        if _constant_time_equal(value, service_key):
            return True
    return session_username(value) is not None


def credential_actor(credential: str | None) -> str:
    """Rótulo de auditoria sem expor a credencial."""
    if not credential or not credential.strip():
        return "anonymous"
    value = credential.strip()
    settings = get_settings()
    if settings.ethoscan_api_key.strip() and _constant_time_equal(
        value, settings.ethoscan_api_key.strip()
    ):
        return "master-key"
    for service_key in settings.service_keys:
        if _constant_time_equal(value, service_key):
            return "service-key"
    username = session_username(value)
    return f"session:{username}" if username else "anonymous"


def check_login_rate_limit(identity: str) -> None:
    """Limite de tentativas de login por IP (memória do processo)."""
    settings = get_settings()
    window = max(1, settings.ethoscan_login_window_seconds)
    limit = max(1, settings.ethoscan_login_max_attempts)
    now = time.monotonic()
    key = identity or "unknown"
    with _login_lock:
        attempts = [stamp for stamp in _login_attempts.get(key, []) if now - stamp < window]
        if len(attempts) >= limit:
            raise HTTPException(
                status_code=429,
                detail="Muitas tentativas de login. Tente novamente em instantes.",
                headers={"Retry-After": str(window)},
            )
        attempts.append(now)
        _login_attempts[key] = attempts


def reset_login_rate_limit() -> None:
    with _login_lock:
        _login_attempts.clear()


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
    user_ok = _constant_time_equal(username.strip(), expected_user)
    # Sempre executa bcrypt (hash dummy se o username não existe) para evitar timing.
    password_hash = settings.ethoscan_local_password_hash if user_ok else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(password, password_hash)
    if not (user_ok and password_ok):
        raise HTTPException(status_code=401, detail="Utilizador ou palavra-passe inválidos.")
    return create_session_token(expected_user)
