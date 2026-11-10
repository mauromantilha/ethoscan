"""Rotas públicas de autenticação local (sem X-API-Key prévia)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.orchestrator import audit
from app.core.security import (
    authenticate_local_user,
    check_login_rate_limit,
    credential_actor,
    revoke_session_token,
)
from app.db import get_db
from app.schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> LoginResponse:
    ip = _client_ip(request)
    check_login_rate_limit(ip)
    username = payload.username.strip()
    try:
        token, expires_at = authenticate_local_user(
            payload.username, payload.password, payload.totp_code
        )
    except HTTPException as exc:
        audit(
            db,
            None,
            "auth_login_failed",
            {
                "username": username[:128],
                "ip": ip,
                "status": exc.status_code,
                "totp_present": bool(payload.totp_code),
            },
            actor="anonymous",
            client_ip=ip,
        )
        raise
    audit(
        db,
        None,
        "auth_login_success",
        {"username": username[:128], "ip": ip},
        actor=f"user:{username[:90]}",
        client_ip=ip,
    )
    return LoginResponse(
        token=token,
        username=username,
        expires_at=expires_at,
    )


@router.post("/logout")
def logout(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=400, detail="Envie o token de sessão em X-API-Key.")
    actor = credential_actor(x_api_key)
    revoked = revoke_session_token(x_api_key)
    audit(
        db,
        None,
        "auth_logout",
        {"revoked": revoked},
        actor=actor,
        client_ip=_client_ip(request),
    )
    if not revoked:
        # Idempotente: token já inválido / era master key
        return {"status": "ok", "message": "Sessão encerrada (ou token já inválido)."}
    return {"status": "ok", "message": "Sessão encerrada."}
