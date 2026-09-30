"""Testes do correlator (dedup por fingerprint e ranking de severidade)."""

from __future__ import annotations

from app.adapters.base import RawFinding
from app.core.correlator import correlate
from app.models import Severity


def _finding(
    title: str = "T", severity: Severity = Severity.info, cve: str | None = None
) -> RawFinding:
    return RawFinding(
        title=title,
        severity=severity,
        target="ex.com",
        tool="stub",
        cve=cve,
    )


def test_correlate_empty() -> None:
    assert correlate([]) == []


def test_correlate_keeps_highest_severity_copy() -> None:
    low = _finding("XSS", Severity.low)
    high = _finding("XSS", Severity.high)
    result = correlate([low, high])
    assert len(result) == 1
    assert result[0].severity is Severity.high


def test_correlate_dedups_by_fingerprint_including_cve() -> None:
    without_cve = _finding("Mesmo título", Severity.medium)
    with_cve = _finding("Mesmo título", Severity.medium, cve="CVE-2024-0001")
    result = correlate([without_cve, with_cve])
    assert len(result) == 2  # fingerprints diferentes por causa do CVE
    assert len({f.fingerprint() for f in result}) == 2


def test_correlate_orders_by_severity_then_title() -> None:
    findings = [
        _finding("Beta", Severity.medium),
        _finding("Alfa", Severity.critical),
        _finding("Gama", Severity.medium),
    ]
    result = correlate(findings)
    assert [(f.severity, f.title) for f in result] == [
        (Severity.critical, "Alfa"),
        (Severity.medium, "Beta"),
        (Severity.medium, "Gama"),
    ]
