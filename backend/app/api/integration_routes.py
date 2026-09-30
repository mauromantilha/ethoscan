"""API de conexão para automação (n8n e afins).

Objetivo: o cliente externo não precisa orquestrar várias chamadas nem conhecer o modelo interno.
Em uma chamada ele cria o engagement e enfileira o job; depois consulta um status compacto — ou
recebe um **webhook** quando o job termina.

Todas as rotas exigem ``X-API-Key`` (master key, uma ``ETHOSCAN_SERVICE_KEYS`` ou token de sessão).
Para automação, recomenda-se uma chave dedicada em ``ETHOSCAN_SERVICE_KEYS`` (revogável sem afetar
o desktop).
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.authz import validate_scope
from app.core.orchestrator import audit
from app.core.security import require_api_key
from app.db import get_db
from app.models import Engagement, Finding, Job, JobStatus
from app.queue import enqueue_job, get_callback, ping_redis, set_callback
from app.schemas import (
    IntegrationJobStatus,
    IntegrationManifest,
    IntegrationScanRequest,
    IntegrationScanResponse,
)
from app.tool_catalog import validate_selected_tools

router = APIRouter(
    prefix="/api/integrations/n8n",
    dependencies=[Depends(require_api_key)],
    tags=["integração (n8n)"],
)

TERMINAL_STATUSES = ("completed", "failed", "cancelled")
POLL_AFTER_SECONDS = 15  # ritmo sugerido de polling enquanto o job roda
INTEGRATION_VERSION = "1.0"  # contrato da integração (independente da versão da API)


def _links(job_id: int) -> dict[str, str]:
    return {
        "status_url": f"/api/integrations/n8n/jobs/{job_id}",
        "findings_url": f"/api/findings?job_id={job_id}&limit=200",
        "report_html_url": f"/api/jobs/{job_id}/report",
        "report_pdf_url": f"/api/jobs/{job_id}/report.pdf",
        "audit_url": f"/api/audit?job_id={job_id}&limit=200",
    }


def _validate_callback(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(400, "callback_url precisa ser uma URL http(s) válida")
    return url.strip()


@router.get("/manifest", response_model=IntegrationManifest)
def manifest() -> IntegrationManifest:
    """Contrato autodescritivo: endpoints, auth e exemplos de payload."""
    return IntegrationManifest(
        name="ethoscan-n8n",
        version=INTEGRATION_VERSION,
        auth_header="X-API-Key",
        auth_hint=(
            "Envie a master key (ETHOSCAN_API_KEY) ou uma chave dedicada de "
            "ETHOSCAN_SERVICE_KEYS. Tokens de /api/auth/login expiram (12h) e não servem para "
            "automação desassistida."
        ),
        endpoints={
            "scan": "POST /api/integrations/n8n/scan",
            "status": "GET /api/integrations/n8n/jobs/{job_id}",
            "cancel": "POST /api/jobs/{job_id}/cancel",
            "findings": "GET /api/findings?job_id={job_id}",
            "report_html": "GET /api/jobs/{job_id}/report",
            "report_pdf": "GET /api/jobs/{job_id}/report.pdf",
            "audit": "GET /api/audit?job_id={job_id}",
            "tools": "GET /api/tools",
            "health": "GET /health",
        },
        terminal_statuses=list(TERMINAL_STATUSES),
        example_scan_body={
            "name": "scan-n8n-01",
            "targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
            "selected_tools": ["nmap", "nuclei"],
            "external_ref": "n8n-exec-1234",
            "callback_url": "https://n8n.seudominio.com/webhook/ethoscan",
        },
        example_callback_payload={
            "job_id": 12,
            "engagement_id": 7,
            "status": "completed",
            "phase": "F6",
            "progress": 100,
            "error": None,
            "findings_count": 9,
            "report_path": "<caminho no host Ethoscan>",
            "report_pdf_path": "<caminho no host Ethoscan>",
            "finished_at": "2026-10-01T03:52:51.238377+00:00",
        },
        notes=[
            "URLs nas respostas são relativas: prefixe com o seu base URL da API.",
            "O worker envia o callback uma única vez (timeout 5s, best-effort) e registra no audit "
            "como callback_sent/callback_failed.",
            "Sem callback: faça polling do status_url até status ∈ terminal_statuses.",
            "Erros: 401 key inválida · 403 RoE não confirmado · 400 alvo/tools inválidos · "
            "503 Redis/worker fora do ar.",
        ],
    )


@router.post("/scan", response_model=IntegrationScanResponse)
def start_scan(
    payload: IntegrationScanRequest,
    db: Session = Depends(get_db),
) -> IntegrationScanResponse:
    """Cria o engagement e enfileira o pipeline em uma única chamada."""
    if not payload.roe_acknowledged:
        raise HTTPException(403, "roe_acknowledged deve ser true (autorização explícita).")

    scope = validate_scope(payload.targets)
    try:
        selected = validate_selected_tools(payload.selected_tools)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    if not ping_redis():
        raise HTTPException(
            503,
            "Redis indisponível — a API não executa scans in-process. Suba o Redis e o worker.",
        )

    callback_url = _validate_callback(payload.callback_url)
    ref = (payload.external_ref or "").strip()
    name = f"{payload.name.strip()} [{ref}]" if ref else payload.name.strip()

    engagement = Engagement(
        name=name[:200],
        scope_targets=scope,
        intensity=payload.intensity,
        roe_acknowledged=True,
        roe_text="Autorização confirmada via API de integração (n8n).",
        notes=f"origem=n8n external_ref={ref}" if ref else "origem=n8n",
        selected_tools=selected,
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    audit(
        db,
        engagement.id,
        "integration_scan_requested",
        {
            "scope": scope,
            "external_ref": ref,
            "selected_tools": selected,
            "callback_url": callback_url,
        },
    )

    job = Job(
        engagement_id=engagement.id,
        status=JobStatus.pending,
        phase="F0",
        progress=0,
        tool_runs={},
        selected_tools=selected,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(db, engagement.id, "job_queued", {"job_id": job.id, "selected_tools": selected})

    try:
        enqueue_job(job.id)
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.failed
        job.error = f"Falha ao enfileirar no Redis: {exc}"
        db.commit()
        raise HTTPException(503, job.error) from exc

    callback_registered = bool(callback_url) and set_callback(job.id, callback_url or "")
    return IntegrationScanResponse(
        engagement_id=engagement.id,
        job_id=job.id,
        status=job.status,
        phase=job.phase,
        callback_registered=callback_registered,
        message="Scan enfileirado. Acompanhe status_url ou aguarde o callback_url.",
        **_links(job.id),
    )


@router.get("/jobs/{job_id}", response_model=IntegrationJobStatus)
def job_status(job_id: int, db: Session = Depends(get_db)) -> IntegrationJobStatus:
    """Status compacto do job (ideal para polling de automação)."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")

    findings_count = db.query(Finding).filter(Finding.job_id == job.id).count()
    is_terminal = job.status.value in TERMINAL_STATUSES
    return IntegrationJobStatus(
        job_id=job.id,
        engagement_id=job.engagement_id,
        status=job.status,
        phase=job.phase,
        progress=job.progress,
        current_tool=job.current_tool,
        error=job.error,
        selected_tools=list(job.selected_tools or []),
        findings_count=findings_count,
        has_report=bool(job.report_path),
        has_report_pdf=bool(job.report_pdf_path),
        callback_registered=bool(get_callback(job.id)),
        poll_after_seconds=0 if is_terminal else POLL_AFTER_SECONDS,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        **_links(job.id),
    )
