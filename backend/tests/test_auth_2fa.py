"""Testes de 2FA TOTP no login local (authenticator app)."""

from __future__ import annotations

from importlib import reload

import bcrypt
import pyotp


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def test_login_requires_valid_totp(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import get_settings

    password = "mauro-2fa-pass"
    secret = pyotp.random_base32()
    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "false")
    monkeypatch.setenv("ETHOSCAN_API_KEY", "")
    monkeypatch.setenv("ETHOSCAN_LOCAL_USERNAME", "mauro")
    monkeypatch.setenv("ETHOSCAN_LOCAL_PASSWORD_HASH", _hash(password))
    monkeypatch.setenv("ETHOSCAN_LOCAL_TOTP_SECRET", secret)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / '2fa.db'}")
    monkeypatch.setenv("ETHOSCAN_ARTIFACTS_DIR", str(tmp_path / "art"))
    (tmp_path / "art").mkdir()
    get_settings.cache_clear()

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.main as mainmod
    from app import db as dbmod
    from app import models  # noqa: F401
    from app.db import Base

    dbmod.engine = create_engine(
        f"sqlite:///{tmp_path / '2fa.db'}", connect_args={"check_same_thread": False}
    )
    dbmod.SessionLocal = sessionmaker(bind=dbmod.engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=dbmod.engine)
    mainmod = reload(mainmod)

    c = TestClient(mainmod.app)

    health = c.get("/health")
    assert health.status_code == 200
    assert health.json()["local_login_2fa"] is True

    missing = c.post(
        "/api/auth/login", json={"username": "mauro", "password": password}
    )
    assert missing.status_code == 401
    assert "2FA" in missing.json()["detail"]

    wrong = c.post(
        "/api/auth/login",
        json={"username": "mauro", "password": password, "totp_code": "000000"},
    )
    assert wrong.status_code == 401

    ok = c.post(
        "/api/auth/login",
        json={
            "username": "mauro",
            "password": password,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert ok.status_code == 200
    token = ok.json()["token"]
    assert token
    authed = c.get("/api/engagements", headers={"X-API-Key": token})
    assert authed.status_code == 200

    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "true")
    get_settings.cache_clear()
