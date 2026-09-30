from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.authz import assert_roe, assert_targets_allowed, validate_scope
from app.core.orchestrator import audit
from app.core.security import require_api_key
from app.db import get_db
from app.models import AuditEvent, Engagement, Finding, Job, JobStatus, Severity
from app.schemas import (
    AuditEventOut,
    EngagementCreate,
    EngagementOut,
    FindingOut,
    JobOut,
    JobStartResponse,
)

# Toda a superfície /api exige o header X-API-Key (fail-closed, ver app/core/security.py).
router = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


@router.get("/engagements", response_model=list[EngagementOut])
def list_engagements(db: Session = Depends(get_db)) -> list[Engagement]:
    return db.query(Engagement).order_by(Engagement.id.desc()).all()


@router.post("/engagements", response_model=EngagementOut)
def create_engagement(payload: EngagementCreate, db: Session = Depends(get_db)) -> Engagement:
    scope = validate_scope(payload.scope_targets)
    # Allowlist global (ETHOSCAN_ALLOWLIST) validada já na criação: falha rápido.
    assert_targets_allowed(scope, get_settings().allowlist_targets)
    eng = Engagement(
        name=payload.name,
        scope_targets=scope,
        intensity=payload.intensity,
        roe_acknowledged=payload.roe_acknowledged,
        roe_text=payload.roe_text
        or "Autorizo o assessment apenas nos alvos listados no escopo, em modo ético.",
        notes=payload.notes,
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    audit(db, eng.id, "engagement_created", {"name": eng.name, "scope": eng.scope_targets})
    return eng


@router.get("/engagements/{engagement_id}", response_model=EngagementOut)
def get_engagement(engagement_id: int, db: Session = Depends(get_db)) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement não encontrado")
    return eng


@router.post("/engagements/{engagement_id}/jobs", response_model=JobStartResponse)
def start_job(
    engagement_id: int,
    db: Session = Depends(get_db),
) -> JobStartResponse:
    """Enfileira o pipeline F0–F6. O worker (app/core/worker.py) reivindica o job."""
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement não encontrado")
    assert_roe(eng.roe_acknowledged)

    job = Job(engagement_id=eng.id, status=JobStatus.pending, phase="F0", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(db, eng.id, "job_queued", {"job_id": job.id})
    return JobStartResponse(job=JobOut.model_validate(job), message="Pipeline enfileirado (F0–F6)")


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(job_id: int, db: Session = Depends(get_db)) -> Job:
    """Cancela um job pendente/em execução (cancelamento cooperativo no pipeline)."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    if job.status in {JobStatus.completed, JobStatus.failed, JobStatus.cancelled}:
        raise HTTPException(
            409, f"Job {job.id} não pode ser cancelado (status={job.status.value})"
        )

    previous = job.status
    job.status = JobStatus.cancelled
    if previous == JobStatus.pending:
        job.finished_at = datetime.now(UTC)
    db.commit()
    db.refresh(job)
    audit(
        db,
        job.engagement_id,
        "job_cancelled",
        {"job_id": job.id, "previous_status": previous.value},
    )
    return job


@router.get("/jobs/{job_id}/report")
def get_job_report(
    job_id: int, download: bool = False, db: Session = Depends(get_db)
) -> FileResponse:
    """Serve o relatório HTML do job (inline por padrão; ``?download=1`` força anexo)."""
    job = db.get(Job, job_id)
    if not job or not job.report_path:
        raise HTTPException(404, "Relatório não disponível para este job")

    artifacts = get_settings().artifacts_path
    path = Path(job.report_path).resolve()
    if not path.is_relative_to(artifacts) or not path.is_file():
        raise HTTPException(404, "Arquivo de relatório não encontrado")

    return FileResponse(
        path,
        media_type="text/html",
        filename=f"ethoscan-job-{job.id}.html" if download else None,
        content_disposition_type="attachment" if download else "inline",
    )


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(engagement_id: int | None = None, db: Session = Depends(get_db)) -> list[Job]:
    q = db.query(Job)
    if engagement_id is not None:
        q = q.filter(Job.engagement_id == engagement_id)
    return q.order_by(Job.id.desc()).all()


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: int, db: Session = Depends(get_db)) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    return job


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    response: Response,
    engagement_id: int | None = None,
    job_id: int | None = None,
    severity: Severity | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[Finding]:
    """Achados (mais recentes primeiro) com paginação; total em ``X-Total-Count``."""
    q = db.query(Finding)
    if engagement_id is not None:
        q = q.filter(Finding.engagement_id == engagement_id)
    if job_id is not None:
        q = q.filter(Finding.job_id == job_id)
    if severity is not None:
        q = q.filter(Finding.severity == severity)
    response.headers["X-Total-Count"] = str(q.count())
    return q.order_by(Finding.id.desc()).offset(offset).limit(limit).all()


@router.get("/audit", response_model=list[AuditEventOut])
def list_audit(
    response: Response,
    engagement_id: int | None = None,
    job_id: int | None = None,
    action: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[AuditEvent]:
    """Trilha de auditoria (mais recentes primeiro); total em ``X-Total-Count``."""
    q = db.query(AuditEvent)
    if engagement_id is not None:
        q = q.filter(AuditEvent.engagement_id == engagement_id)
    if action:
        q = q.filter(AuditEvent.action == action)
    if job_id is not None:
        q = q.filter(AuditEvent.detail["job_id"].as_integer() == job_id)
    response.headers["X-Total-Count"] = str(q.count())
    return q.order_by(AuditEvent.id.desc()).offset(offset).limit(limit).all()
