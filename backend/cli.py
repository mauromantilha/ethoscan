from __future__ import annotations

import json
import time
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Ethoscan CLI — pentest ético local-first")
console = Console()

DEFAULT_API = "http://localhost:8000"


def _client(api: str) -> httpx.Client:
    return httpx.Client(base_url=api, timeout=60.0)


@app.command()
def health(api: str = DEFAULT_API) -> None:
    """Verifica API e disponibilidade das tools."""
    with _client(api) as client:
        r = client.get("/health")
        r.raise_for_status()
        data = r.json()
    console.print_json(json.dumps(data))


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
    """Dispara pipeline F0–F6 para um engagement."""
    with _client(api) as client:
        r = client.post(f"/api/engagements/{engagement_id}/jobs")
        if r.status_code >= 400:
            console.print(r.text)
            raise typer.Exit(1)
        job = r.json()["job"]
        console.print(f"Job #{job['id']} enfileirado")
        if not watch:
            return
        while True:
            jr = client.get(f"/api/jobs/{job['id']}")
            jr.raise_for_status()
            j = jr.json()
            console.print(
                f"status={j['status']} phase={j['phase']} progress={j['progress']}% tool={j.get('current_tool')}"
            )
            if j["status"] in {"completed", "failed", "cancelled"}:
                if j.get("error"):
                    console.print(f"[red]{j['error']}[/red]")
                if j.get("report_path"):
                    console.print(f"Relatório: {j['report_path']}")
                break
            time.sleep(1.5)


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
    for f in rows:
        table.add_row(str(f["id"]), f["severity"], f["title"], f["target"], f["tool"])
    console.print(table)


if __name__ == "__main__":
    app()
