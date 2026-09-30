"""Logging do Ethoscan: texto por padrão, JSON opcional para agregadores.

Env: ``ETHOSCAN_LOG_LEVEL`` (default INFO) e ``ETHOSCAN_LOG_FORMAT`` (text|json).
Os campos de contexto (job_id, tool, exit_code, ...) são incluídos no JSON.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from app.config import get_settings

APP_LOGGER = "app"

_TEXT_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# chaves de `extra=` que o formatter JSON promove para o topo do payload
_CONTEXT_KEYS = (
    "job_id",
    "engagement_id",
    "tool",
    "target",
    "phase",
    "status",
    "exit_code",
    "mocked",
    "worker",
    "findings",
    "new_findings",
)


class JsonFormatter(logging.Formatter):
    """Uma linha JSON por registro (timestamp em UTC, com contexto)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
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
    """Configura o logger ``app`` (idempotente; seguro para chamar várias vezes)."""
    settings = get_settings()
    level = getattr(logging, settings.ethoscan_log_level.upper(), logging.INFO)

    logger = logging.getLogger(APP_LOGGER)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if settings.ethoscan_log_format.lower() == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(_TEXT_FORMAT))
        logger.addHandler(handler)
    # não deixa o record vazar para o root (evita log duplicado no uvicorn)
    logger.propagate = False
