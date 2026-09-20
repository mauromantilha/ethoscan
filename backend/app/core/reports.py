from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.models import Engagement, Finding, Job


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
    tools_used = list(job.selected_tools or []) or sorted(
        {f.tool for f in findings} | set((job.tool_runs or {}).keys())
    )
    tools_line = ", ".join(tools_used) if tools_used else "(pipeline clássico)"
    roe = engagement.roe_text or "RoE confirmado pelo operador (assessment só no escopo)."
    rows = "\n".join(
        f"<tr><td>{f.severity.value}</td><td>{_esc(f.title)}</td><td>{_esc(f.target)}</td>"
        f"<td>{_esc(f.tool)}</td><td>{_esc(f.description)}</td></tr>"
        for f in findings
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
    <div>Gerado em {datetime.now(timezone.utc).isoformat()}</div>
  </div>
  <div class="roe"><strong>Nota RoE:</strong> {_esc(roe)}</div>
  <h2>Achados ({len(findings)})</h2>
  <table>
    <thead><tr><th>Severidade</th><th>Título</th><th>Alvo</th><th>Tool</th><th>Descrição</th></tr></thead>
    <tbody>
      {rows or '<tr><td colspan="5">Nenhum achado.</td></tr>'}
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

    tools_used = list(job.selected_tools or []) or sorted(
        {f.tool for f in findings} | set((job.tool_runs or {}).keys())
    )
    tools_line = ", ".join(tools_used) if tools_used else "(pipeline clássico)"
    roe = engagement.roe_text or "RoE confirmado pelo operador (assessment só no escopo)."

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
            f"Gerado em {datetime.now(timezone.utc).isoformat()}",
            styles["Normal"],
        ),
        Spacer(1, 0.4 * cm),
        Paragraph(f"<b>Nota RoE:</b> {_esc(roe)}", styles["Normal"]),
        Spacer(1, 0.5 * cm),
        Paragraph(f"<b>Achados ({len(findings)})</b>", styles["Heading2"]),
    ]

    header = ["Severidade", "Título", "Alvo", "Tool", "Descrição"]
    data = [header]
    if not findings:
        data.append(["—", "Nenhum achado.", "—", "—", "—"])
    else:
        for f in findings:
            data.append(
                [
                    f.severity.value,
                    Paragraph(_esc(f.title)[:120], styles["Normal"]),
                    Paragraph(_esc(f.target)[:80], styles["Normal"]),
                    f.tool,
                    Paragraph(_esc(f.description or "")[:200], styles["Normal"]),
                ]
            )

    table = Table(data, colWidths=[2.2 * cm, 5 * cm, 3.5 * cm, 2.5 * cm, 5 * cm])
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
