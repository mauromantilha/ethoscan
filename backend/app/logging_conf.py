"""Logging do Ethoscan: texto (default) ou JSON estruturado.

Env: ``ETHOSCAN_LOG_LEVEL`` (default ``INFO``) e ``ETHOSCAN_LOG_FORMAT`` (``text``|``json``).
Afeta o logger ``ethoscan`` e seus filhos (``ethoscan.orchestrator``, ``ethoscan.worker``...).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from app.config import get_settings

APP_LOGGER = "ethoscan"
_TEXT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
# campos passados via extra= que o formatter JSON promove para o topo do payload
_CONTEXT_KEYS = (
    "job_id",
    "engagement_id",
    "tool",
    "target",
    "phase",
    "status",
    "exit_code",
    "mocked",
    "findings",
)


class JsonFormatter(logging.Formatter):
    """Uma linha JSON por evento (timestamp UTC + contexto)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in _CONTEXT_KEYS:
            value = record.__dict__.get(key)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    """Configura o logger ``ethoscan`` (idempotente; seguro para chamar várias vezes)."""
    settings = get_settings()
    logger = logging.getLogger(APP_LOGGER)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if settings.ethoscan_log_format.strip().lower() == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(_TEXT_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(
        getattr(logging, settings.ethoscan_log_level.strip().upper(), logging.INFO)
    )
    # não vaza para o root (evita linhas duplicadas quando uvicorn/worker configuram root)
    logger.propagate = False
