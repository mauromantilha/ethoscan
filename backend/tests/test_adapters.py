"""Testes dos adapters: exit code, isolamento e parsers (Sprint 2)."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.adapters import all_adapters
from app.adapters import base as base_module
from app.adapters.base import AdapterResult
from app.adapters.gobuster import GobusterAdapter
from app.adapters.nmap import NmapAdapter
from app.adapters.nuclei import NucleiAdapter
from app.adapters.sslscan import SslscanAdapter
from app.adapters.whatweb import WhatWebAdapter
from app.models import Severity


def _fake_settings(*, force_mock: bool, allow_mock: bool) -> SimpleNamespace:
    return SimpleNamespace(ethoscan_force_mock=force_mock, ethoscan_allow_mock=allow_mock)


@pytest.fixture
def fake_settings(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Ajusta o comportamento mock/real dos adapters sob teste."""

    def _apply(*, force_mock: bool, allow_mock: bool) -> None:
        monkeypatch.setattr(
            base_module,
            "get_settings",
            lambda: _fake_settings(force_mock=force_mock, allow_mock=allow_mock),
        )

    return _apply


@pytest.fixture
def real_mode(fake_settings: Callable[..., None]) -> None:
    """Exercita o caminho real (force_mock desligado)."""
    fake_settings(force_mock=False, allow_mock=True)


@pytest.fixture
def job_dir(tmp_path: Path) -> Path:
    path = tmp_path / "job"
    path.mkdir()
    return path


def test_adapter_result_ok_flag() -> None:
    assert AdapterResult(tool="t", mocked=False, command=["t"]).ok is True
    assert AdapterResult(tool="t", mocked=False, command=["t"], exit_code=2).ok is False
    assert AdapterResult(tool="t", mocked=False, command=["t"], error="boom").ok is False


def test_all_adapters_run_mock_without_tools(job_dir: Path) -> None:
    """No sandbox de teste (ETHOSCAN_FORCE_MOCK) todas as tools caem no mock."""
    for adapter in all_adapters():
        result = adapter.run("scanme.nmap.org", job_dir, "safe")
        assert result.mocked is True
        assert result.ok is True, adapter.name
        assert result.findings, adapter.name


def test_run_without_tool_and_without_mock_returns_failure(
    fake_settings: Callable[..., None],
    monkeypatch: pytest.MonkeyPatch,
    job_dir: Path,
) -> None:
    """Antes levantava RuntimeError e derrubava o pipeline inteiro."""
    fake_settings(force_mock=False, allow_mock=False)
    monkeypatch.setattr(NmapAdapter, "available", lambda _self: False)
    result = NmapAdapter().run("scanme.nmap.org", job_dir, "safe")
    assert result.ok is False
    assert "não encontrada" in (result.error or "")


def test_timeout_becomes_failure_not_exception(
    real_mode: None, monkeypatch: pytest.MonkeyPatch, job_dir: Path
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=300)

    monkeypatch.setattr(NmapAdapter, "available", lambda _self: True)
    monkeypatch.setattr(NmapAdapter, "_exec", boom)
    result = NmapAdapter().run("scanme.nmap.org", job_dir, "safe")
    assert result.ok is False
    assert "timeout" in (result.error or "")


def test_oserror_becomes_failure(
    real_mode: None, monkeypatch: pytest.MonkeyPatch, job_dir: Path
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError("binário sumiu")

    monkeypatch.setattr(NmapAdapter, "available", lambda _self: True)
    monkeypatch.setattr(NmapAdapter, "_exec", boom)
    result = NmapAdapter().run("scanme.nmap.org", job_dir, "safe")
    assert result.ok is False
    assert "FileNotFoundError" in (result.error or "")


def test_nmap_real_command_writes_xml(
    real_mode: None, monkeypatch: pytest.MonkeyPatch, job_dir: Path
) -> None:
    """-oX precisa estar no comando executado (antes era código morto)."""
    captured: dict[str, list[str]] = {}

    def fake_exec(
        self: NmapAdapter, command: list[str], timeout: int = 120
    ) -> tuple[str, str, int]:
        captured["command"] = command
        return "", "", 0

    monkeypatch.setattr(NmapAdapter, "available", lambda _self: True)
    monkeypatch.setattr(NmapAdapter, "_exec", fake_exec)
    result = NmapAdapter().run("scanme.nmap.org", job_dir, "standard")
    assert "-oX" in captured["command"]
    assert str(job_dir / "nmap.xml") in captured["command"]
    assert result.ok is True
    assert result.exit_code == 0


def test_nmap_parse_text_finds_open_ports() -> None:
    stdout = (
        "Starting Nmap\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 8.9\n"
        "80/tcp   open  http    nginx 1.24\n"
        "443/tcp  closed https\n"
    )
    findings = NmapAdapter()._parse_text(stdout, "scanme.nmap.org")
    assert [f.title for f in findings] == [
        "Porta 22/tcp aberta (ssh)",
        "Porta 80/tcp aberta (http)",
    ]
    assert findings[0].severity is Severity.info


def test_whatweb_real_failure_produces_no_finding(
    real_mode: None, monkeypatch: pytest.MonkeyPatch, job_dir: Path
) -> None:
    def failing_exec(
        _self: WhatWebAdapter, _cmd: list[str], timeout: int = 120
    ) -> tuple[str, str, int]:
        return "", f"erro após {timeout}s", 1

    monkeypatch.setattr(WhatWebAdapter, "available", lambda _self: True)
    monkeypatch.setattr(WhatWebAdapter, "_exec", failing_exec)
    result = WhatWebAdapter().run("scanme.nmap.org", job_dir, "safe")
    assert result.ok is False
    assert result.findings == []


def test_gobuster_parse_severity_by_path() -> None:
    content = (
        "http://ex.com/admin (Status: 301)\n"
        "http://ex.com/login (Status: 200)\n"
        "http://ex.com/.git (Status: 403)\n"
        "linha sem status\n"
    )
    findings = GobusterAdapter()._parse(content, "ex.com")
    assert len(findings) == 3
    metrics = {f.title: f.severity for f in findings}
    assert metrics["Caminho descoberto: http://ex.com/admin"] is Severity.medium
    assert metrics["Caminho descoberto: http://ex.com/login"] is Severity.info


def test_nuclei_parse_jsonl_maps_severity_and_cwe() -> None:
    rows: list[Any] = [
        {
            "info": {
                "name": "XSS",
                "severity": "high",
                "description": "x",
                "classification": {"cwe-id": ["CWE-79"]},
            },
            "matched-at": "https://ex.com/a",
        },
        {"info": {"name": "Info", "severity": "unknown"}, "matched-at": "https://ex.com"},
        "linha invalida",
    ]
    lines: list[str] = []
    for row in rows:
        lines.append(json.dumps(row) if isinstance(row, dict) else str(row))
    findings = NucleiAdapter()._parse_jsonl("\n".join(lines), "ex.com")
    assert len(findings) == 2
    assert findings[0].severity is Severity.high
    assert findings[0].cwe == "CWE-79"
    assert findings[1].severity is Severity.info


def test_sslscan_parse_and_no_fake_success_finding() -> None:
    """O antigo 'Varredura TLS concluída' aparecia até em falha — foi removido."""
    adapter = SslscanAdapter()
    findings = adapter._parse("TLS 1.0 enabled\nTLS 1.2 enabled", "ex.com")
    assert [f.title for f in findings] == ["TLS 1.0 habilitado"]
    assert findings[0].cwe == "CWE-326"
    assert adapter._parse("TLS 1.2 enabled only", "ex.com") == []
    assert adapter._parse("", "ex.com") == []
