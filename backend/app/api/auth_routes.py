"""Rotas públicas de autenticação local (sem X-API-Key prévia)."""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from app.core.security import authenticate_local_user, revoke_session_token
from app.schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    token, expires_at = authenticate_local_user(payload.username, payload.password)
    return LoginResponse(
        token=token,
        username=payload.username.strip(),
        expires_at=expires_at,
    )


@router.post("/logout")
def logout(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> dict[str, str]:
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=400, detail="Envie o token de sessão em X-API-Key.")
    revoked = revoke_session_token(x_api_key)
    if not revoked:
        # Idempotente: token já inválido / era master key
        return {"status": "ok", "message": "Sessão encerrada (ou token já inválido)."}
    return {"status": "ok", "message": "Sessão encerrada."}
