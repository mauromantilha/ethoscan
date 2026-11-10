"""Cobertura do relatório: DNS/tool errors sem duplicar linhas."""

from __future__ import annotations

from app.core.reports import _coverage_rows
from app.models import Finding, Job, Severity


def test_coverage_rows_dedupe_tool_error_and_tool_run() -> None:
    job = Job(
        id=1,
        tool_runs={
            "_coverage": {
                "dns": [
                    {
                        "target": "sem-dns.example",
                        "addresses": [],
                        "error": "DNS não resolveu 'sem-dns.example'",
                    }
                ]
            },
            "nuclei": {
                "ok": False,
                "last_target": "a.example",
                "error": "timeout após 420s",
            },
        },
    )
    findings = [
        Finding(
            id=1,
            tool="nuclei",
            target="a.example",
            category="tool_error",
            severity=Severity.info,
            title="Ferramenta nuclei falhou",
            description="A execução de nuclei não concluiu (timeout após 420s).",
            mocked=False,
        ),
        Finding(
            id=2,
            tool="nuclei",
            target="b.example",
            category="tool_error",
            severity=Severity.info,
            title="Ferramenta nuclei falhou",
            description="A execução de nuclei não concluiu (timeout após 420s).",
            mocked=False,
        ),
    ]

    rows = _coverage_rows(job, findings)

    assert len(rows) == len(set(rows))
    assert any("sem-dns.example" in row for row in rows)
    assert sum("nuclei" in row and "a.example" in row for row in rows) == 1
    assert sum("nuclei" in row and "b.example" in row for row in rows) == 1


def test_coverage_rows_warn_cloudflare() -> None:
    job = Job(id=1, tool_runs={})
    findings = [
        Finding(
            id=1,
            tool="nuclei",
            target="a.example",
            category="recon",
            severity=Severity.info,
            title="WAF Detection",
            description="A web application firewall was detected.",
            mocked=False,
        )
    ]

    rows = _coverage_rows(job, findings)

    assert any("WAF/Cloudflare" in row for row in rows)
