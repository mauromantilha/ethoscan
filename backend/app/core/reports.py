from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.models import Engagement, Finding, Job


def _tool_runs(job: Job) -> dict:
    """Tool runs públicas (ignora chaves internas como ``_coverage``)."""
    return {
        name: info
        for name, info in (job.tool_runs or {}).items()
        if not str(name).startswith("_")
    }


def _dns_coverage(job: Job) -> list[dict]:
    coverage = (job.tool_runs or {}).get("_coverage") or {}
    return list(coverage.get("dns") or [])


def _coverage_rows(job: Job, findings: list[Finding]) -> list[str]:
    """Motivos de cobertura parcial: DNS, tool falhada ou mock (sem duplicados)."""
    rows: list[str] = []
    seen: set[tuple[str, str]] = set()
    for item in _dns_coverage(job):
        if item.get("error"):
            rows.append(f"DNS {item.get('target')}: {item['error']}")
    # Primeiro os tool_error por alvo (têm o motivo real do stderr).
    for finding in findings:
        if finding.category != "tool_error":
            continue
        key = (finding.tool, finding.target)
        if key in seen:
            continue
        seen.add(key)
        rows.append(f"{finding.tool} ({finding.target}): {finding.description}")
    # Cloudflare/WAF: explica por que ferramentas HTTP veem challenge/edge.
    if any(
        "waf" in (finding.title or "").lower()
        or "cloudflare" in (finding.title or "").lower()
        for finding in findings
    ):
        rows.append(
            "WAF/Cloudflare detetado: ferramentas HTTP podem receber challenge/edge; "
            "usar origin/staging ou allowlist do scanner."
        )
    # Fallback: tool_runs sem finding correspondente (ex.: último alvo).
    for tool, info in _tool_runs(job).items():
        if not isinstance(info, dict):
            continue
        target = info.get("last_target") or "—"
        key = (tool, target)
        if info.get("mocked"):
            mock_key = (tool, "mock")
            if mock_key not in seen:
                seen.add(mock_key)
                rows.append(f"{tool}: executado em modo mock")
            continue
        if info.get("ok") is False and key not in seen:
            seen.add(key)
            reason = info.get("error") or f"exit code {info.get('exit_code')}"
            rows.append(f"{tool} ({target}): falhou — {reason}")
    return list(dict.fromkeys(rows))


def write_html_report(
    engagement: Engagement,
    job: Job,
    findings: list[Finding],
    out_dir: Path,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"report-job-{job.id}.html"
    html = build_report_html(engagement, job, findings)
    path.write_text(html, encoding="utf-8")
    return path


def write_pdf_report(
    engagement: Engagement,
    job: Job,
    findings: list[Finding],
    out_dir: Path,
) -> Path:
    """Gera PDF imprimível (reportlab) a partir dos mesmos dados do HTML."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"report-job-{job.id}.pdf"
    _write_pdf_reportlab(engagement, job, findings, path)
    return path


def build_report_html(
    engagement: Engagement,
    job: Job,
    findings: list[Finding],
) -> str:
    tool_runs = _tool_runs(job)
    tools_used = list(job.selected_tools or []) or sorted(
        {f.tool for f in findings} | set(tool_runs.keys())
    )
    tools_line = ", ".join(tools_used) if tools_used else "(pipeline clássico)"
    roe = engagement.roe_text or "RoE confirmado pelo operador (assessment só no escopo)."
    real_findings = [f for f in findings if f.category != "tool_error"]
    coverage_rows = _coverage_rows(job, findings)
    mocked_count = sum(1 for finding in real_findings if finding.mocked)
    mock_notice = ""
    if mocked_count:
        mock_notice = (
            f'<div class="mock"><strong>MOCK:</strong> {mocked_count} de '
            f"{len(real_findings)} achado(s) foram gerados em modo mock. "
            "Estes resultados não representam um scan real.</div>"
        )
    coverage_html = ""
    if coverage_rows:
        coverage_items = "".join(f"<li>{_esc(row)}</li>" for row in coverage_rows)
        coverage_html = (
            '<h2>Cobertura / limitações</h2>'
            '<div class="coverage"><ul>'
            f"{coverage_items}"
            "</ul></div>"
        )
    finished = job.finished_at.isoformat() if job.finished_at else "—"
    rows = "\n".join(
        f"<tr><td>{f.severity.value}</td><td>{_esc(f.title)}</td><td>{_esc(f.target)}</td>"
        f"<td>{_esc(f.tool)}</td><td>{'MOCK' if f.mocked else 'real'}</td>"
        f"<td>{_esc(f.description)}</td></tr>"
        for f in real_findings
    )
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>Ethoscan — { _esc(engagement.name) }</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 2rem; background: #f7f4ef; color: #1c1917; }}
    h1 {{ letter-spacing: -0.02em; }}
    .meta {{ color: #57534e; margin-bottom: 1.5rem; }}
    .roe {{ background: #fff; border-left: 4px solid #0f766e; padding: 0.75rem 1rem; margin: 1rem 0; }}
    .mock {{ background: #fef3c7; border-left: 4px solid #b45309; padding: 0.75rem 1rem; margin: 1rem 0; }}
    .coverage {{ background: #fff; border-left: 4px solid #b45309; padding: 0.75rem 1rem; margin: 1rem 0; }}
    .coverage ul {{ margin: 0; padding-left: 1.2rem; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #d6d3d1; padding: 0.6rem 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #1c1917; color: #fafaf9; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; background: #0f766e; color: white; border-radius: 999px; font-size: 0.8rem; }}
    @media print {{
      body {{ background: #fff; margin: 1cm; }}
      .badge {{ background: #000; }}
    }}
  </style>
</head>
<body>
  <p class="badge">Ethoscan</p>
  <h1>{_esc(engagement.name)}</h1>
  <div class="meta">
    <div>Job #{job.id} — {job.status.value} — fase {job.phase}</div>
    <div>Escopo: {_esc(", ".join(engagement.scope_targets))}</div>
    <div>Tools usadas: {_esc(tools_line)}</div>
    <div>Intensidade: {engagement.intensity.value}</div>
    <div>Finalizado em {finished}</div>
    <div>Gerado em {datetime.now(UTC).isoformat()}</div>
  </div>
  <div class="roe"><strong>Nota RoE:</strong> {_esc(roe)}</div>
  {mock_notice}
  {coverage_html}
  <h2>Achados ({len(real_findings)})</h2>
  <table>
    <thead><tr><th>Severidade</th><th>Título</th><th>Alvo</th><th>Tool</th><th>Modo</th><th>Descrição</th></tr></thead>
    <tbody>
      {rows or '<tr><td colspan="6">Nenhum achado de segurança; ver cobertura/limitações.</td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""


def _write_pdf_reportlab(
    engagement: Engagement,
    job: Job,
    findings: list[Finding],
    path: Path,
) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    tool_runs = _tool_runs(job)
    tools_used = list(job.selected_tools or []) or sorted(
        {f.tool for f in findings} | set(tool_runs.keys())
    )
    tools_line = ", ".join(tools_used) if tools_used else "(pipeline clássico)"
    roe = engagement.roe_text or "RoE confirmado pelo operador (assessment só no escopo)."
    real_findings = [f for f in findings if f.category != "tool_error"]
    coverage_rows = _coverage_rows(job, findings)
    mocked_count = sum(1 for finding in real_findings if finding.mocked)
    finished = job.finished_at.isoformat() if job.finished_at else "—"

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title=f"Ethoscan — {engagement.name}",
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>Ethoscan</b> — relatório de assessment ético", styles["Title"]),
        Spacer(1, 0.3 * cm),
        Paragraph(f"<b>{_esc(engagement.name)}</b>", styles["Heading2"]),
        Paragraph(
            f"Job #{job.id} — {job.status.value} — fase {job.phase}<br/>"
            f"Escopo: {_esc(', '.join(engagement.scope_targets))}<br/>"
            f"Tools usadas: {_esc(tools_line)}<br/>"
            f"Intensidade: {engagement.intensity.value}<br/>"
            f"Finalizado em {finished}<br/>"
            f"Gerado em {datetime.now(UTC).isoformat()}",
            styles["Normal"],
        ),
        Spacer(1, 0.4 * cm),
        Paragraph(f"<b>Nota RoE:</b> {_esc(roe)}", styles["Normal"]),
    ]
    if mocked_count:
        story.extend(
            [
                Spacer(1, 0.3 * cm),
                Paragraph(
                    f"<b>MOCK:</b> {mocked_count} de {len(real_findings)} achado(s) foram "
                    "gerados em modo mock. Estes resultados não representam um scan real.",
                    styles["Normal"],
                ),
            ]
        )
    if coverage_rows:
        story.extend(
            [
                Spacer(1, 0.5 * cm),
                Paragraph("<b>Cobertura / limitações</b>", styles["Heading2"]),
            ]
        )
        for row in coverage_rows:
            story.append(Paragraph(f"• {_esc(row)}", styles["Normal"]))
    story.extend(
        [
            Spacer(1, 0.5 * cm),
            Paragraph(f"<b>Achados ({len(real_findings)})</b>", styles["Heading2"]),
        ]
    )

    header = ["Severidade", "Título", "Alvo", "Tool", "Modo", "Descrição"]
    data = [header]
    if not real_findings:
        data.append(
            ["—", "Nenhum achado de segurança; ver cobertura.", "—", "—", "—", "—"]
        )
    else:
        for f in real_findings:
            data.append(
                [
                    f.severity.value,
                    Paragraph(_esc(f.title)[:120], styles["Normal"]),
                    Paragraph(_esc(f.target)[:80], styles["Normal"]),
                    Paragraph(_esc(f.tool), styles["Normal"]),
                    "MOCK" if f.mocked else "real",
                    Paragraph(_esc(f.description or "")[:200], styles["Normal"]),
                ]
            )

    table = Table(
        data,
        colWidths=[2.0 * cm, 4.5 * cm, 3.0 * cm, 2.2 * cm, 1.5 * cm, 4.5 * cm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c1917")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d6d3d1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f4")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(table)
    doc.build(story)


def _esc(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
