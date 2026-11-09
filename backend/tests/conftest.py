import os

import pytest

# Auth explícitamente desligada para smoke local/CI
os.environ["ETHOSCAN_DISABLE_AUTH"] = "true"
os.environ["ETHOSCAN_ALLOW_MOCK"] = "true"
os.environ["ETHOSCAN_MODE"] = "local"


@pytest.fixture(autouse=True)
def _reset_login_rate_limit():
    from app.core import security

    security.reset_login_rate_limit()
    yield
    security.reset_login_rate_limit()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    art = tmp_path / "artifacts"
    art.mkdir()
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ETHOSCAN_ARTIFACTS_DIR", str(art))
    monkeypatch.setenv("ETHOSCAN_ALLOW_MOCK", "true")
    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "true")
    monkeypatch.setenv("ETHOSCAN_MODE", "local")

    from app.config import get_settings

    get_settings.cache_clear()

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app import db as dbmod

    dbmod.engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    dbmod.SessionLocal = sessionmaker(bind=dbmod.engine, autoflush=False, autocommit=False)
    from app import models  # noqa: F401
    from app.db import Base

    Base.metadata.drop_all(bind=dbmod.engine)
    Base.metadata.create_all(bind=dbmod.engine)

    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c

    get_settings.cache_clear()
