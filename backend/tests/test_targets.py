"""Helpers de alvo e regressões de IPv6 nos adapters."""

from __future__ import annotations

import socket

from app.adapters.metasploit import MetasploitAdapter
from app.adapters.whatweb import WhatWebAdapter
from app.core.targets import target_host, target_resolution, target_url


def test_target_host_ipv4_ipv6_and_urls() -> None:
    assert target_host("scanme.nmap.org") == "scanme.nmap.org"
    assert target_host("http://Example.com/") == "example.com"
    assert target_host("10.0.0.5:8080") == "10.0.0.5"
    assert target_host("2001:db8::1") == "2001:db8::1"
    assert target_host("[2001:db8::1]") == "2001:db8::1"
    assert target_host("http://[2001:db8::1]/") == "2001:db8::1"


def test_target_url_brackets_ipv6() -> None:
    assert target_url("scanme.nmap.org") == "http://scanme.nmap.org"
    assert target_url("2001:db8::1") == "http://[2001:db8::1]"
    assert target_url("2001:db8::1", "https") == "https://[2001:db8::1]"
    assert target_url("http://[2001:db8::1]/") == "http://[2001:db8::1]/"


def test_target_resolution_skips_dns_for_ip() -> None:
    addresses, error = target_resolution("10.0.0.5")
    assert addresses == ["10.0.0.5"]
    assert error is None


def test_target_resolution_reports_dns_failure(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    addresses, error = target_resolution("nao-existe.example")
    assert addresses == []
    assert "DNS" in (error or "")


def test_whatweb_uses_bracketed_ipv6_url(tmp_path, monkeypatch) -> None:
    adapter = WhatWebAdapter()
    captured: dict[str, list[str]] = {}

    def fake_exec(command, timeout=120):
        captured["command"] = command
        return "http://[2001:db8::1] [200 OK]", "", 0

    monkeypatch.setattr(adapter, "_exec", fake_exec)
    adapter._run_real("2001:db8::1", tmp_path, "safe")

    assert "http://[2001:db8::1]" in captured["command"]


def test_metasploit_rc_uses_full_ipv6_host(tmp_path, monkeypatch) -> None:
    adapter = MetasploitAdapter()

    def fake_exec(command, timeout=120):
        return "[*] 2001:db8::1:80 - TCP OPEN", "", 0

    monkeypatch.setattr(adapter, "_exec", fake_exec)
    adapter._run_real("2001:db8::1", tmp_path, "safe")

    rc = next(tmp_path.glob("*.rc")).read_text()
    assert "set RHOSTS 2001:db8::1" in rc
