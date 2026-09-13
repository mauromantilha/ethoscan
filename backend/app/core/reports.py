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
    rows = "\n".join(
        f"<tr><td>{f.severity.value}</td><td>{_esc(f.title)}</td><td>{_esc(f.target)}</td>"
        f"<td>{_esc(f.tool)}</td><td>{_esc(f.description)}</td></tr>"
        for f in findings
    )
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>Ethoscan — { _esc(engagement.name) }</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 2rem; background: #f7f4ef; color: #1c1917; }}
    h1 {{ letter-spacing: -0.02em; }}
    .meta {{ color: #57534e; margin-bottom: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #d6d3d1; padding: 0.6rem 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #1c1917; color: #fafaf9; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; background: #0f766e; color: white; border-radius: 999px; font-size: 0.8rem; }}
  </style>
</head>
<body>
  <p class="badge">Ethoscan</p>
  <h1>{_esc(engagement.name)}</h1>
  <div class="meta">
    <div>Job #{job.id} — {job.status.value} — fase {job.phase}</div>
    <div>Escopo: {_esc(", ".join(engagement.scope_targets))}</div>
    <div>Gerado em {datetime.now(timezone.utc).isoformat()}</div>
  </div>
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
    path.write_text(html, encoding="utf-8")
    return path


def _esc(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
