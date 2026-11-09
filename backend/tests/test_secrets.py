"""Hardening de segredos: evidência redigida, argv e ambiente mínimo."""

from __future__ import annotations

from app.adapters.bloodhound import BloodhoundAdapter
from app.adapters.hydra import HydraAdapter
from app.config import get_settings
from app.core.subprocess_env import subprocess_env


def test_hydra_redacts_password_from_evidence() -> None:
    adapter = HydraAdapter()
    findings = adapter._parse(
        "[22][ssh] host: 10.0.0.5 login: admin password: super-secret-123\n",
        "10.0.0.5",
    )
    assert findings
    assert "super-secret-123" not in (findings[0].evidence or "")
    assert "password: ***" in (findings[0].evidence or "")


def test_bloodhound_skips_credentials_in_argv_by_default(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ETHOSCAN_ALLOW_CREDS_IN_ARGV", "false")
    get_settings.cache_clear()
    (tmp_path / "ad_creds.env").write_text(
        "BH_USERNAME=lab\nBH_PASSWORD=super-secret\nBH_DOMAIN=lab.local\n"
    )

    result = BloodhoundAdapter()._run_real("10.0.0.5", tmp_path, "standard")

    assert result.ok is True
    assert result.command == ["bloodhound-python", "--skipped-creds-argv"]
    assert "super-secret" not in result.stdout
    assert result.findings
    assert "argv" in result.findings[0].title
    get_settings.cache_clear()


def test_subprocess_env_does_not_inherit_secrets(monkeypatch) -> None:
    monkeypatch.setenv("ETHOSCAN_API_KEY", "master-secret")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@host/db")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    env = subprocess_env()

    assert "ETHOSCAN_API_KEY" not in env
    assert "DATABASE_URL" not in env
    assert env["PATH"] == "/usr/bin:/bin"
