"""Testes de login local (bcrypt) e inventário Kali."""

from __future__ import annotations

from importlib import reload

import bcrypt


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def test_verify_password_hash():
    from app.core.security import verify_password

    hashed = _hash("lab-secret-please")
    assert verify_password("lab-secret-please", hashed) is True
    assert verify_password("wrong", hashed) is False
    assert verify_password("", hashed) is False


def test_lab_inventory_reports_availability(monkeypatch):
    from app import lab_inventory as inv

    def fake_which(name: str):
        return f"/usr/bin/{name}" if name in {"nmap", "nxc"} else None

    monkeypatch.setattr(inv.shutil, "which", fake_which)
    tools = inv.lab_tools_inventory()
    by_name = {t["name"]: t for t in tools}
    assert by_name["nmap"]["available"] is True
    assert by_name["nmap"]["binary"] == "nmap"
    assert by_name["netexec"]["available"] is True
    assert by_name["netexec"]["binary"] == "nxc"
    assert by_name["nikto"]["available"] is False
    assert by_name["bloodhound-python"]["available"] is False
    assert len(tools) >= 16


def test_login_issues_session_token(tmp_path, monkeypatch):
    from app.config import get_settings
    from fastapi.testclient import TestClient

    password = "mauro-lab-pass"
    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "false")
    monkeypatch.setenv("ETHOSCAN_API_KEY", "")
    monkeypatch.setenv("ETHOSCAN_LOCAL_USERNAME", "mauro")
    monkeypatch.setenv("ETHOSCAN_LOCAL_PASSWORD_HASH", _hash(password))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'login.db'}")
    monkeypatch.setenv("ETHOSCAN_ARTIFACTS_DIR", str(tmp_path / "art"))
    (tmp_path / "art").mkdir()
    get_settings.cache_clear()

    from app import db as dbmod
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db import Base
    from app import models  # noqa: F401
    import app.main as mainmod

    dbmod.engine = create_engine(
        f"sqlite:///{tmp_path / 'login.db'}", connect_args={"check_same_thread": False}
    )
    dbmod.SessionLocal = sessionmaker(bind=dbmod.engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=dbmod.engine)
    reload(mainmod)

    c = TestClient(mainmod.app)

    health = c.get("/health")
    assert health.status_code == 200
    assert health.json()["auth_enabled"] is True
    assert health.json()["local_login_available"] is True

    denied = c.get("/api/engagements")
    assert denied.status_code == 401

    bad = c.post("/api/auth/login", json={"username": "mauro", "password": "wrong"})
    assert bad.status_code == 401

    ok = c.post("/api/auth/login", json={"username": "mauro", "password": password})
    assert ok.status_code == 200
    body = ok.json()
    assert body["username"] == "mauro"
    assert body["token"]
    assert body["token_type"] == "api_key"
    # Não devolve a master key (vazia neste cenário)
    assert body["token"] != password

    authed = c.get("/api/engagements", headers={"X-API-Key": body["token"]})
    assert authed.status_code == 200

    inv = c.get("/api/lab/tools", headers={"X-API-Key": body["token"]})
    assert inv.status_code == 200
    data = inv.json()
    assert "F0" in data["phases"] and "F6" in data["phases"]
    assert any(t["name"] == "nmap" for t in data["tools"])
    assert "nmap" in data["pipeline_tools"]

    c.post("/api/auth/logout", headers={"X-API-Key": body["token"]})
    after = c.get("/api/engagements", headers={"X-API-Key": body["token"]})
    assert after.status_code == 401

    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "true")
    get_settings.cache_clear()


def test_api_key_still_works_alongside_local_user(tmp_path, monkeypatch):
    from app.config import get_settings
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "false")
    monkeypatch.setenv("ETHOSCAN_API_KEY", "master-lab-key")
    monkeypatch.setenv("ETHOSCAN_LOCAL_USERNAME", "mauro")
    monkeypatch.setenv("ETHOSCAN_LOCAL_PASSWORD_HASH", _hash("x"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'both.db'}")
    monkeypatch.setenv("ETHOSCAN_ARTIFACTS_DIR", str(tmp_path / "art"))
    (tmp_path / "art").mkdir()
    get_settings.cache_clear()

    from app import db as dbmod
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db import Base
    from app import models  # noqa: F401
    import app.main as mainmod

    dbmod.engine = create_engine(
        f"sqlite:///{tmp_path / 'both.db'}", connect_args={"check_same_thread": False}
    )
    dbmod.SessionLocal = sessionmaker(bind=dbmod.engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=dbmod.engine)
    reload(mainmod)

    c = TestClient(mainmod.app)
    ok = c.get("/api/engagements", headers={"X-API-Key": "master-lab-key"})
    assert ok.status_code == 200

    monkeypatch.setenv("ETHOSCAN_DISABLE_AUTH", "true")
    get_settings.cache_clear()


def test_health_includes_local_login_flag(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert "local_login_available" in r.json()
    assert "phases" in r.json()
