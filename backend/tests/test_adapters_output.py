"""Adapters não devem inventar findings quando a tool não produziu dados."""

from __future__ import annotations

from pathlib import Path

from app.adapters.gobuster import GobusterAdapter
from app.adapters.hydra import HydraAdapter
from app.adapters.netexec import NetExecAdapter
from app.adapters.nikto import NiktoAdapter
from app.adapters.nmap import NmapAdapter
from app.adapters.sqlmap import SqlmapAdapter
from app.adapters.sslscan import SslscanAdapter
from app.adapters.whatweb import WhatWebAdapter
from app.models import Severity


def _force_available(monkeypatch, adapter) -> None:
    monkeypatch.setattr(adapter, "available", lambda: True)


def test_whatweb_empty_output_is_error(tmp_path, monkeypatch) -> None:
    adapter = WhatWebAdapter()
    _force_available(monkeypatch, adapter)
    monkeypatch.setattr(
        adapter,
        "_exec",
        lambda command, timeout=120: ("", "could not connect", 0),
    )

    result = adapter.run("example.com", tmp_path, "safe")

    assert result.findings == []
    assert result.ok is False
    assert "não devolveu output" in (result.error or "")
    assert "could not connect" in Path(result.artifact_path).read_text()


def test_sslscan_version_only_is_error(tmp_path, monkeypatch) -> None:
    adapter = SslscanAdapter()
    _force_available(monkeypatch, adapter)
    monkeypatch.setattr(
        adapter,
        "_exec",
        lambda command, timeout=120: ("Version: 2.1.5\nOpenSSL 3.6.5\n", "", 0),
    )

    result = adapter.run("example.com", tmp_path, "safe")

    assert result.findings == []
    assert result.ok is False
    assert "ligação TLS" in (result.error or "")


def test_nmap_zero_hosts_is_error(tmp_path, monkeypatch) -> None:
    adapter = NmapAdapter()
    _force_available(monkeypatch, adapter)
    output = (
        "Starting Nmap 7.991\n"
        "Nmap done: 0 IP addresses (0 hosts up) scanned in 0.71 seconds\n"
    )
    monkeypatch.setattr(adapter, "_exec", lambda command, timeout=120: (output, "", 0))

    result = adapter.run("example.com", tmp_path, "safe")

    assert result.findings == []
    assert result.ok is False
    assert "nenhum host" in (result.error or "")


def test_gobuster_nonzero_exit_includes_stderr(tmp_path, monkeypatch) -> None:
    adapter = GobusterAdapter()
    _force_available(monkeypatch, adapter)

    def fake_exec(command, timeout=120):
        adapter._last_exit_code = 1
        return "", "dial tcp: lookup example.com: no such host", 1

    monkeypatch.setattr(adapter, "_exec", fake_exec)

    result = adapter.run("example.com", tmp_path, "safe")

    assert result.ok is False
    assert "lookup" in (result.error or "")
    assert "stderr" in Path(result.artifact_path).read_text()


def test_sslscan_unparseable_certificate_is_error(tmp_path, monkeypatch) -> None:
    adapter = SslscanAdapter()
    _force_available(monkeypatch, adapter)
    output = (
        "Version: 2.1.5\nConnected to 104.18.5.243\n"
        "TLSv1.2   disabled\nTLSv1.3   disabled\n"
        "    Unable to parse certificate\n"
    )
    monkeypatch.setattr(adapter, "_exec", lambda command, timeout=120: (output, "", 0))

    result = adapter.run("example.com", tmp_path, "safe")

    assert result.findings == []
    assert result.ok is False
    assert "certificado" in (result.error or "")


def test_netexec_empty_output_is_error(tmp_path, monkeypatch) -> None:
    adapter = NetExecAdapter()
    _force_available(monkeypatch, adapter)
    monkeypatch.setattr(adapter, "_exec", lambda command, timeout=120: ("", "", 0))

    result = adapter.run("example.com", tmp_path, "safe")

    assert result.findings == []
    assert result.ok is False
    assert "output" in (result.error or "")


def test_hydra_connection_failure_has_no_completed_finding(tmp_path, monkeypatch) -> None:
    adapter = HydraAdapter()
    _force_available(monkeypatch, adapter)
    content = "# Hydra run header\n[ERROR] could not connect to ssh://1.2.3.4:22 - Timeout\n"

    def fake_exec(command, timeout=120):
        adapter._last_exit_code = 255
        return content, content, 255

    monkeypatch.setattr(adapter, "_exec", fake_exec)

    result = adapter.run("example.com", tmp_path, "standard")

    assert result.ok is False
    assert not any("concluído" in f.title.lower() for f in result.findings)


def test_sqlmap_warning_is_not_high_injection(tmp_path, monkeypatch) -> None:
    adapter = SqlmapAdapter()
    _force_available(monkeypatch, adapter)
    output = (
        "[WARNING] target URL content is not stable. If no dynamic nor injectable "
        "parameters are detected, refer to the manual.\n"
        "[CRITICAL] no parameter(s) found for testing in the provided data\n"
        "403 (Forbidden) - 3 times\n"
    )
    monkeypatch.setattr(adapter, "_exec", lambda command, timeout=120: (output, "", 0))

    result = adapter.run("example.com/?id=1", tmp_path, "standard")

    assert not any(f.severity == Severity.high for f in result.findings)
    assert result.findings[0].title.startswith("sqlmap concluído")


def test_sqlmap_skips_url_without_query(tmp_path, monkeypatch) -> None:
    adapter = SqlmapAdapter()
    _force_available(monkeypatch, adapter)

    result = adapter.run("example.com", tmp_path, "standard")

    assert result.findings
    assert result.findings[0].category == "tool_error"
    assert "sem parâmetros" in result.findings[0].title


def test_nikto_parser_skips_metadata_and_downgrades_cloudflare() -> None:
    adapter = NiktoAdapter()
    content = (
        "+ Target Port: 80\n"
        "+ GET /: Cloudflare detected via cf-ray header.\n"
        "+ GET /: Suggested security header missing: strict-transport-security.\n"
        "+ GET /user.php?op=x: Post Nuke 0.7.2.3-Phoenix is vulnerable to Cross Site Scripting (XSS).\n"
    )
    findings = adapter._parse(content, "example.com")

    titles = [f.title for f in findings]
    assert not any("Target Port" in title for title in titles)
    assert any(f.severity == Severity.info and "Cloudflare" in f.title for f in findings)
    assert any(f.severity == Severity.low and "strict-transport-security" in f.title for f in findings)
    assert any(f.severity == Severity.medium and "XSS" in f.title for f in findings)
