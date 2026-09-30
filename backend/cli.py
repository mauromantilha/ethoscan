from __future__ import annotations

import contextlib
import json
import os
import time

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Ethoscan CLI — pentest ético local-first")
console = Console()

DEFAULT_API = os.getenv("ETHOSCAN_API_URL", "http://localhost:8000")
API_KEY_ENV = "ETHOSCAN_API_KEY"
API_KEY_HELP = "API key do backend (header X-API-Key); default: env ETHOSCAN_API_KEY"


def _client(api: str, api_key: str = "") -> httpx.Client:
    key = api_key or os.getenv(API_KEY_ENV, "")
    headers = {"X-API-Key": key} if key else {}
    return httpx.Client(base_url=api, timeout=60.0, headers=headers)


def _fail(response: httpx.Response) -> typer.Exit:
    """Imprime o detalhe do erro e devolve o Exit para `raise`."""
    detail = response.text
    with contextlib.suppress(ValueError):  # corpo não-JSON
        detail = response.json().get("detail", detail)
    console.print(f"[red]{response.status_code} {detail}[/red]")
    if response.status_code in (401, 403):
        console.print(
            f"[yellow]Envie a API key com --api-key ou {API_KEY_ENV} (mesma do backend).[/yellow]"
        )
    elif response.status_code == 503:
        console.print(
            "[yellow]Backend sem ETHOSCAN_API_KEY configurada: "
            "ajuste o .env e reinicie a API.[/yellow]"
        )
    return typer.Exit(1)


@app.command()
def health(
    api: str = DEFAULT_API,
    api_key: str = typer.Option("", "--api-key", envvar=API_KEY_ENV, help=API_KEY_HELP),
) -> None:
    """Verifica API e disponibilidade das tools."""
    with _client(api, api_key) as client:
        r = client.get("/health")
        if r.status_code >= 400:
            raise _fail(r)
        data = r.json()
    console.print_json(json.dumps(data))


@app.command("create")
def create_engagement(
    name: str = typer.Option(..., "--name", "-n"),
    target: list[str] = typer.Option(..., "--target", "-t", help="Alvo no escopo (repetível)"),
    intensity: str = typer.Option("safe", "--intensity", "-i"),
    acknowledge: bool = typer.Option(False, "--ack", help="Confirma RoE/autorização"),
    api: str = DEFAULT_API,
    api_key: str = typer.Option("", "--api-key", envvar=API_KEY_ENV, help=API_KEY_HELP),
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
    with _client(api, api_key) as client:
        r = client.post("/api/engagements", json=payload)
        if r.status_code >= 400:
            raise _fail(r)
        data = r.json()
    console.print(f"[green]Engagement #{data['id']} criado[/green]: {data['name']}")
    console.print(f"Escopo: {', '.join(data['scope_targets'])}")


@app.command("run")
def run_job(
    engagement_id: int = typer.Argument(...),
    watch: bool = typer.Option(True, "--watch/--no-watch"),
    api: str = DEFAULT_API,
    api_key: str = typer.Option("", "--api-key", envvar=API_KEY_ENV, help=API_KEY_HELP),
) -> None:
    """Dispara pipeline F0–F6 para um engagement."""
    with _client(api, api_key) as client:
        r = client.post(f"/api/engagements/{engagement_id}/jobs")
        if r.status_code >= 400:
            raise _fail(r)
        job = r.json()["job"]
        console.print(f"Job #{job['id']} enfileirado")
        if not watch:
            return
        while True:
            jr = client.get(f"/api/jobs/{job['id']}")
            if jr.status_code >= 400:
                raise _fail(jr)
            j = jr.json()
            console.print(
                f"status={j['status']} phase={j['phase']} "
                f"progress={j['progress']}% tool={j.get('current_tool')}"
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
    engagement_id: int | None = typer.Option(None, "--engagement", "-e"),
    api: str = DEFAULT_API,
    api_key: str = typer.Option("", "--api-key", envvar=API_KEY_ENV, help=API_KEY_HELP),
) -> None:
    """Lista achados."""
    params = {}
    if engagement_id is not None:
        params["engagement_id"] = engagement_id
    with _client(api, api_key) as client:
        r = client.get("/api/findings", params=params)
        if r.status_code >= 400:
            raise _fail(r)
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


@app.command("cancel")
def cancel_job(
    job_id: int = typer.Argument(...),
    api: str = DEFAULT_API,
    api_key: str = typer.Option("", "--api-key", envvar=API_KEY_ENV, help=API_KEY_HELP),
) -> None:
    """Cancela um job pendente ou em execução."""
    with _client(api, api_key) as client:
        r = client.post(f"/api/jobs/{job_id}/cancel")
        if r.status_code >= 400:
            raise _fail(r)
        job = r.json()
    console.print(f"[green]Job #{job['id']} -> {job['status']}[/green]")


@app.command("audit")
def list_audit(
    engagement_id: int | None = typer.Option(None, "--engagement", "-e"),
    job_id: int | None = typer.Option(None, "--job", "-j"),
    action: str | None = typer.Option(None, "--action", "-a"),
    limit: int = typer.Option(50, "--limit", "-n"),
    api: str = DEFAULT_API,
    api_key: str = typer.Option("", "--api-key", envvar=API_KEY_ENV, help=API_KEY_HELP),
) -> None:
    """Mostra a trilha de auditoria (mais recentes primeiro)."""
    params: dict = {"limit": limit}
    if engagement_id is not None:
        params["engagement_id"] = engagement_id
    if job_id is not None:
        params["job_id"] = job_id
    if action:
        params["action"] = action

    with _client(api, api_key) as client:
        r = client.get("/api/audit", params=params)
        if r.status_code >= 400:
            raise _fail(r)
        rows = r.json()
        total = r.headers.get("X-Total-Count", "?")

    table = Table(title=f"Auditoria ({len(rows)} de {total})")
    table.add_column("ID")
    table.add_column("Quando")
    table.add_column("Ação")
    table.add_column("Detalhe")
    for event in rows:
        detail = json.dumps(event["detail"], ensure_ascii=False)
        table.add_row(str(event["id"]), event["created_at"][11:19], event["action"], detail[:70])
    console.print(table)


if __name__ == "__main__":
    app()
