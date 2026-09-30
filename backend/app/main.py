import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.adapters import tools_status
from app.api.routes import router
from app.config import get_settings
from app.core.authz import validate_allowlist
from app.core.worker import get_worker
from app.db import init_db
from app.logging_conf import configure_logging
from app.schemas import HealthOut

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    # Fail-fast: allowlist global inválida (ex.: um TLD) impede a API de subir.
    try:
        validate_allowlist(settings.allowlist_targets)
    except ValueError as exc:
        raise RuntimeError(f"Configuração inválida: {exc}") from exc
    init_db()
    worker = get_worker()
    worker.start()
    logger.info(
        "ethoscan iniciado (modo=%s worker=%s mock_forçado=%s)",
        settings.ethoscan_mode,
        settings.ethoscan_worker_enabled,
        settings.ethoscan_force_mock,
        extra={"worker": settings.ethoscan_worker_enabled, "mocked": settings.ethoscan_force_mock},
    )
    try:
        yield
    finally:
        worker.stop()
        logger.info("ethoscan encerrado")


app = FastAPI(
    title="Ethoscan",
    description="Orquestrador de pentest ético (Assess) — local-first",
    version="0.1.0",
    lifespan=lifespan,
)

_settings = get_settings()
_origins = _settings.cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    # CORS com "*" + credenciais é inseguro: só habilita credenciais com origem explícita.
    allow_credentials="*" not in _origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

app.include_router(router)


@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    settings = get_settings()
    return HealthOut(
        status="ok",
        mode=settings.ethoscan_mode,
        mock_allowed=settings.ethoscan_allow_mock,
        mock_forced=settings.ethoscan_force_mock,
        worker_enabled=settings.ethoscan_worker_enabled,
        tools=tools_status(),
    )
