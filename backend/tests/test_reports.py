"""Testes do relatório HTML: escape (XSS), banner de mock e contadores."""

from __future__ import annotations

from pathlib import Path

from app.core.reports import write_html_report
from app.models import Engagement, Finding, Job, JobStatus, Severity


def _engagement(**overrides: object) -> Engagement:
    defaults: dict[str, object] = {
        "id": 1,
        "name": "Lab <script>alert(1)</script>",
        "scope_targets": ["ex.com"],
    }
    defaults.update(overrides)
    return Engagement(**defaults)


def _job(**overrides: object) -> Job:
    defaults: dict[str, object] = {"id": 7, "status": JobStatus.completed, "phase": "F6"}
    defaults.update(overrides)
    return Job(**defaults)


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "id": 1,
        "job_id": 7,
        "title": "XSS <img src=x onerror=alert(1)>",
        "severity": Severity.high,
        "target": "ex.com",
        "tool": "nuclei",
        "category": "vuln",
        "description": "descrição <b>com</b> html",
        "fingerprint": "abc",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_report_escapes_html(tmp_path: Path) -> None:
    path = write_html_report(_engagement(), _job(), [_finding()], tmp_path)
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_report_empty_findings(tmp_path: Path) -> None:
    path = write_html_report(_engagement(name="Sem achados"), _job(), [], tmp_path)
    html = path.read_text(encoding="utf-8")
    assert "Achados do engagement (0)" in html
    assert "Nenhum achado." in html
    assert "modo MOCK" not in html


def test_report_new_findings_and_mock_banner(tmp_path: Path) -> None:
    path = write_html_report(
        _engagement(name="Rodada 2"),
        _job(id=9),
        [_finding(id=1, job_id=7), _finding(id=2, job_id=9, title="Novo")],
        tmp_path,
        new_findings=1,
        mock_used=True,
    )
    html = path.read_text(encoding="utf-8")
    assert "Achados do engagement (2)" in html
    assert "Novos nesta execução: 1" in html
    assert "modo MOCK" in html
    # colunas e rastreio do job que encontrou cada achado
    assert "<th>Categoria</th>" in html
    assert "<td>7</td>" in html and "<td>9</td>" in html
