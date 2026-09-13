from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Ethoscan CLI — pentest ético local-first")
console = Console()

DEFAULT_API = os.environ.get("ETHOSCAN_API_URL", "http://localhost:8000")


def _headers() -> dict[str, str]:
    key = os.environ.get("ETHOSCAN_API_KEY", "").strip()
    return {"X-API-Key": key} if key else {}


def _client(api: str) -> httpx.Client:
    return httpx.Client(base_url=api, timeout=60.0, headers=_headers())


@app.command()
def health(api: str = DEFAULT_API) -> None:
    """Verifica API, Redis, auth e disponibilidade das tools."""
    with _client(api) as client:
        r = client.get("/health")
        r.raise_for_status()
        data = r.json()
    console.print_json(json.dumps(data))
    tools = data.get("tools") or {}
    missing = [n for n, info in tools.items() if not info.get("available")]
    if missing:
        if data.get("mock_allowed"):
            console.print(f"[yellow]Tools em falta (mock): {', '.join(missing)}[/yellow]")
        else:
            console.print(f"[red]Tools em falta e mock off: {', '.join(missing)}[/red]")
    else:
        console.print("[green]Todas as 5 tools disponíveis (available=true)[/green]")


@app.command("create")
def create_engagement(
    name: str = typer.Option(..., "--name", "-n"),
    target: list[str] = typer.Option(..., "--target", "-t", help="Alvo no escopo (repetível)"),
    intensity: str = typer.Option(
        "safe",
        "--intensity",
        "-i",
        help="safe (recomendado), standard ou aggressive (lab/RoE explícito)",
    ),
    acknowledge: bool = typer.Option(False, "--ack", help="Confirma RoE/autorização"),
    api: str = DEFAULT_API,
) -> None:
    """Cria um engagement com escopo e RoE."""
    if not acknowledge:
        console.print("[red]É obrigatório --ack para confirmar autorização/RoE.[/red]")
        raise typer.Exit(code=2)
    payload = {
        "name": name,
        "scope_targets": target,
        "intensity": intensity,
        "roe_acknowledged": True,
    }
    with _client(api) as client:
        r = client.post("/api/engagements", json=payload)
        if r.status_code >= 400:
            console.print(r.text)
            raise typer.Exit(1)
        data = r.json()
    console.print(f"[green]Engagement #{data['id']} criado[/green]: {data['name']}")
    console.print(f"Escopo: {', '.join(data['scope_targets'])}")


@app.command("run")
def run_job(
    engagement_id: int = typer.Argument(...),
    watch: bool = typer.Option(True, "--watch/--no-watch"),
    api: str = DEFAULT_API,
) -> None:
    """Dispara pipeline F0–F6 (via worker Redis) para um engagement."""
    with _client(api) as client:
        r = client.post(f"/api/engagements/{engagement_id}/jobs")
        if r.status_code >= 400:
            console.print(r.text)
            raise typer.Exit(1)
        job = r.json()["job"]
        console.print(f"Job #{job['id']} enfileirado (fase {job['phase']})")
        if not watch:
            return
        while True:
            jr = client.get(f"/api/jobs/{job['id']}")
            jr.raise_for_status()
            j = jr.json()
            runs = j.get("tool_runs") or {}
            modes = " ".join(
                f"{name}={'mock' if info.get('mocked') else 'real'}" for name, info in runs.items()
            )
            console.print(
                f"status={j['status']} phase={j['phase']} progress={j['progress']}% "
                f"tool={j.get('current_tool')} {modes}"
            )
            if j["status"] in {"completed", "failed", "cancelled"}:
                if j.get("error"):
                    console.print(f"[red]{j['error']}[/red]")
                if j.get("report_path"):
                    console.print(f"Relatório (disco): {j['report_path']}")
                    console.print(
                        f"Download: {api.rstrip('/')}/api/jobs/{j['id']}/report "
                        f"| ou: python cli.py report {j['id']} --out report.html"
                    )
                break
            time.sleep(1.5)


@app.command("cancel")
def cancel_job(job_id: int = typer.Argument(...), api: str = DEFAULT_API) -> None:
    """Cancela um job pending/running."""
    with _client(api) as client:
        r = client.post(f"/api/jobs/{job_id}/cancel")
        if r.status_code >= 400:
            console.print(r.text)
            raise typer.Exit(1)
        j = r.json()
    console.print(f"Job #{j['id']} → {j['status']}")


@app.command("report")
def report_cmd(
    job_id: int = typer.Argument(...),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Gravar HTML neste path"),
    api: str = DEFAULT_API,
) -> None:
    """Mostra path do relatório e/ou descarrega o HTML."""
    with _client(api) as client:
        jr = client.get(f"/api/jobs/{job_id}")
        if jr.status_code >= 400:
            console.print(jr.text)
            raise typer.Exit(1)
        j = jr.json()
        if j.get("report_path"):
            console.print(f"Path: {j['report_path']}")
        rr = client.get(f"/api/jobs/{job_id}/report")
        if rr.status_code >= 400:
            console.print(rr.text)
            raise typer.Exit(1)
        if out:
            Path(out).write_bytes(rr.content)
            console.print(f"[green]Guardado em {out}[/green]")
        else:
            console.print(
                f"URL: {api.rstrip('/')}/api/jobs/{job_id}/report — use --out report.html para gravar"
            )


@app.command("findings")
def list_findings(
    engagement_id: Optional[int] = typer.Option(None, "--engagement", "-e"),
    api: str = DEFAULT_API,
) -> None:
    """Lista achados."""
    params = {}
    if engagement_id is not None:
        params["engagement_id"] = engagement_id
    with _client(api) as client:
        r = client.get("/api/findings", params=params)
        r.raise_for_status()
        rows = r.json()
    table = Table(title="Achados Ethoscan")
    table.add_column("ID")
    table.add_column("Sev")
    table.add_column("Título")
    table.add_column("Alvo")
    table.add_column("Tool")
    table.add_column("Modo")
    for f in rows:
        table.add_row(
            str(f["id"]),
            f["severity"],
            f["title"],
            f["target"],
            f["tool"],
            "mock" if f.get("mocked") else "real",
        )
    console.print(table)


if __name__ == "__main__":
    app()
