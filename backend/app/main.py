from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.adapters import tools_status
from app.api.routes import router
from app.config import get_settings
from app.db import init_db
from app.schemas import HealthOut


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Ethoscan",
    description="Orquestrador de pentest ético (Assess) — local-first",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    settings = get_settings()
    return HealthOut(
        status="ok",
        mode=settings.ethoscan_mode,
        mock_allowed=settings.ethoscan_allow_mock,
        tools=tools_status(),
    )
