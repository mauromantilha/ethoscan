from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.adapters import tools_status
from app.api.auth_routes import router as auth_router
from app.api.routes import router
from app.config import get_settings
from app.core.orchestrator import PHASE_LABELS
from app.db import init_db
from app.queue import ping_redis
from app.schemas import HealthOut

logger = logging.getLogger("ethoscan")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    init_db()
    if not settings.auth_enabled:
        if settings.ethoscan_mode != "local":
            logger.error(
                "ETHOSCAN_API_KEY/utilizador local ausente e mode=%s — defina auth. "
                "Auth só pode ficar desligada em mode=local com ETHOSCAN_DISABLE_AUTH=true.",
                settings.ethoscan_mode,
            )
        elif not settings.ethoscan_disable_auth:
            logger.warning(
                "Auth desligada (sem ETHOSCAN_API_KEY nem utilizador local). "
                "Aceitável só em lab local. Defina ETHOSCAN_API_KEY / "
                "ETHOSCAN_LOCAL_* ou ETHOSCAN_DISABLE_AUTH=true de forma explícita."
            )
        else:
            logger.warning("ETHOSCAN_DISABLE_AUTH=true — API sem autenticação (lab apenas).")
    elif settings.local_user_configured:
        logger.info(
            "Login local ativo para utilizador '%s' (POST /api/auth/login).",
            settings.ethoscan_local_username.strip(),
        )
    yield


app = FastAPI(
    title="Ethoscan",
    description="Orquestrador de pentest ético (Assess) — local-first; intensidade safe recomendada",
    version="0.2.0",
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


@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    """Health público (sem API key) para checklist Kali / orquestração."""
    settings = get_settings()
    redis_ok = ping_redis()
    return HealthOut(
        status="ok",
        mode=settings.ethoscan_mode,
        mock_allowed=settings.ethoscan_allow_mock,
        auth_enabled=settings.auth_enabled,
        local_login_available=settings.local_user_configured,
        redis_ok=redis_ok,
        worker_hint=(
            "API + worker separados. Rode: python -m app.worker (requer Redis)."
            if redis_ok
            else "Redis down — suba redis e o worker antes de enfileirar jobs."
        ),
        tools=tools_status(),
        phases=PHASE_LABELS,
    )
