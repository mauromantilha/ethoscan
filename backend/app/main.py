import logging
from contextlib import asynccontextmanager

import pyotp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.adapters import tools_status
from app.api.auth_routes import router as auth_router
from app.api.integration_routes import router as integration_router
from app.api.llm_routes import router as llm_router
from app.api.routes import router
from app.config import Settings, get_settings
from app.core.authz import validate_allowlist
from app.core.orchestrator import PHASE_LABELS
from app.db import init_db
from app.logging_conf import configure_logging
from app.queue import ping_redis, worker_heartbeat_alive
from app.schemas import HealthOut

configure_logging()
logger = logging.getLogger("ethoscan")


def _validate_auth_settings(settings: Settings) -> None:
    """Fail-closed: fora de mode=local, a API não sobe sem auth válida.

    Em local, auth desligada é permitida com aviso explícito (lab). Credenciais
    default/fracas são rejeitadas fora de local e avisadas em local.
    """
    if settings.local_user_2fa_enabled:
        if not settings.local_user_configured:
            raise RuntimeError(
                "ETHOSCAN_LOCAL_TOTP_SECRET definido sem utilizador local. Defina "
                "ETHOSCAN_LOCAL_USERNAME e ETHOSCAN_LOCAL_PASSWORD_HASH."
            )
        try:
            # .now() valida o base32 (o construtor do pyotp é preguiçoso).
            pyotp.TOTP(settings.ethoscan_local_totp_secret.strip()).now()
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                "ETHOSCAN_LOCAL_TOTP_SECRET inválido: use um segredo base32 "
                "(ex.: python -c \"import pyotp; print(pyotp.random_base32())\")."
            ) from exc

    if settings.ethoscan_mode != "local":
        if settings.ethoscan_disable_auth:
            raise RuntimeError(
                "ETHOSCAN_DISABLE_AUTH=true só é permitido em mode=local. "
                f"mode atual: {settings.ethoscan_mode}."
            )
        if not settings.auth_enabled:
            raise RuntimeError(
                f"Auth obrigatória em mode={settings.ethoscan_mode}: defina "
                "ETHOSCAN_API_KEY, ETHOSCAN_SERVICE_KEYS ou ETHOSCAN_LOCAL_*."
            )
        if settings.weak_credentials:
            raise RuntimeError(
                "Credenciais default/fracas detectadas fora de mode=local. "
                "Gere uma key forte (ex.: openssl rand -hex 32)."
            )
        return

    if not settings.auth_enabled:
        if settings.ethoscan_disable_auth:
            logger.warning("ETHOSCAN_DISABLE_AUTH=true — API sem autenticação (lab apenas).")
        else:
            logger.warning(
                "Auth desligada (sem ETHOSCAN_API_KEY, ETHOSCAN_SERVICE_KEYS nem "
                "utilizador local). Aceitável só em lab local. Defina uma key ou "
                "ETHOSCAN_DISABLE_AUTH=true de forma explícita."
            )
        return

    if settings.weak_credentials:
        logger.warning(
            "Credenciais default/fracas em mode=local — troque antes de expor a API."
        )
    elif (
        settings.service_keys
        and not settings.ethoscan_api_key.strip()
        and not settings.local_user_configured
    ):
        logger.info(
            "Auth ativa via ETHOSCAN_SERVICE_KEYS (%d chave(s)).", len(settings.service_keys)
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    # Fail-fast: allowlist global inválida (ex.: um TLD) impede a API de subir.
    try:
        validate_allowlist(settings.allowlist_targets)
    except ValueError as exc:
        raise RuntimeError(f"Configuração inválida: {exc}") from exc
    # Validar auth antes de criar/migrar a DB: configuração inválida não deixa side effects.
    _validate_auth_settings(settings)
    init_db()
    if settings.local_user_configured:
        logger.info(
            "Login local ativo para utilizador '%s'%s (POST /api/auth/login).",
            settings.ethoscan_local_username.strip(),
            " com 2FA TOTP" if settings.local_user_2fa_enabled else "",
        )
    yield


app = FastAPI(
    title="Ethoscan",
    description="Orquestrador de pentest ético (Assess) — local-first; intensidade safe recomendada",
    version="0.5.0",
    lifespan=lifespan,
)

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(router)
app.include_router(llm_router)
app.include_router(integration_router)


@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    """Health público (sem API key) para checklist Kali / orquestração."""
    settings = get_settings()
    redis_ok = ping_redis()
    worker_ok = worker_heartbeat_alive() if redis_ok else False
    if not redis_ok:
        worker_hint = "Redis down — suba redis e o worker antes de enfileirar jobs."
    elif not worker_ok:
        worker_hint = "Redis ok, mas worker sem heartbeat — rode: python -m app.worker."
    else:
        worker_hint = "API + worker ativos (heartbeat ok)."
    return HealthOut(
        status="ok",
        mode=settings.ethoscan_mode,
        mock_allowed=settings.ethoscan_allow_mock,
        auth_enabled=settings.auth_enabled,
        local_login_available=settings.local_user_configured,
        local_login_2fa=settings.local_user_2fa_enabled,
        llm_enabled=settings.llm_enabled,
        redis_ok=redis_ok,
        worker_ok=worker_ok,
        worker_hint=worker_hint,
        tools=tools_status(),
        phases=PHASE_LABELS,
    )
