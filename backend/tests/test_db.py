"""init_db deve falhar explicitamente quando a migração Alembic falha."""

from __future__ import annotations

import alembic.command
import pytest

from app import db as dbmod


def test_init_db_raises_when_alembic_fails(client, monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("migration boom")

    monkeypatch.setattr(alembic.command, "upgrade", boom)
    with pytest.raises(RuntimeError, match="migra"):
        dbmod.init_db()
