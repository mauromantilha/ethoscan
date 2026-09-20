from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.authz import assert_roe, validate_scope
from app.core.orchestrator import PHASE_LABELS, audit
from app.core.security import require_api_key
from app.db import get_db
from app.lab_inventory import lab_tools_inventory
from app.adapters import tools_status
from app.models import Engagement, Finding, Job, JobStatus
from app.queue import enqueue_job, ping_redis, request_cancel
from app.schemas import (
    EngagementCreate,
    EngagementOut,
    FindingOut,
    JobOut,
    JobStartResponse,
    LabInventoryOut,
)

router = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


@router.get("/engagements", response_model=list[EngagementOut])
def list_engagements(db: Session = Depends(get_db)) -> list[Engagement]:
    return db.query(Engagement).order_by(Engagement.id.desc()).all()


@router.post("/engagements", response_model=EngagementOut)
def create_engagement(payload: EngagementCreate, db: Session = Depends(get_db)) -> Engagement:
    scope = validate_scope(payload.scope_targets)
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
def start_job(engagement_id: int, db: Session = Depends(get_db)) -> JobStartResponse:
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement não encontrado")
    assert_roe(eng.roe_acknowledged)

    if not ping_redis():
        raise HTTPException(
            503,
            "Redis indisponível — a API não executa scans in-process. "
            "Suba o Redis e o worker (`python -m app.worker`).",
        )

    job = Job(
        engagement_id=eng.id,
        status=JobStatus.pending,
        phase="F0",
        progress=0,
        tool_runs={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(db, eng.id, "job_queued", {"job_id": job.id})
    try:
        enqueue_job(job.id)
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.failed
        job.error = f"Falha ao enfileirar no Redis: {exc}"
        db.commit()
        raise HTTPException(503, job.error) from exc
    return JobStartResponse(
        job=job,
        message="Pipeline enfileirado no worker (F0 gate → F1–F6)",
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


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(job_id: int, db: Session = Depends(get_db)) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    if job.status in {JobStatus.completed, JobStatus.failed, JobStatus.cancelled}:
        raise HTTPException(409, f"Job já finalizado ({job.status.value})")

    request_cancel(job.id)
    if job.status == JobStatus.pending:
        job.status = JobStatus.cancelled
        job.error = "Cancelado antes de iniciar"
        db.commit()
        audit(db, job.engagement_id, "job_cancelled", {"job_id": job.id, "when": "pending"})
    else:
        audit(db, job.engagement_id, "job_cancel_requested", {"job_id": job.id})
        db.commit()
    db.refresh(job)
    return job


@router.get("/jobs/{job_id}/report")
def download_report(job_id: int, db: Session = Depends(get_db)) -> FileResponse:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    if not job.report_path:
        raise HTTPException(404, "Relatório ainda não disponível")
    path = Path(job.report_path)
    if not path.is_file():
        raise HTTPException(404, f"Ficheiro de relatório em falta: {path}")
    return FileResponse(
        path,
        media_type="text/html; charset=utf-8",
        filename=path.name,
    )


@router.get("/phases")
def list_phases() -> dict[str, str]:
    return PHASE_LABELS


@router.get("/lab/tools", response_model=LabInventoryOut)
def lab_tools() -> LabInventoryOut:
    """Inventário Kali/lab (PATH) + fases F0–F6 + tools do pipeline Ethoscan."""
    return LabInventoryOut(
        tools=lab_tools_inventory(),
        phases=PHASE_LABELS,
        pipeline_tools=tools_status(),
    )


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    engagement_id: int | None = None,
    job_id: int | None = None,
    db: Session = Depends(get_db),
) -> list[Finding]:
    q = db.query(Finding)
    if engagement_id is not None:
        q = q.filter(Finding.engagement_id == engagement_id)
    if job_id is not None:
        q = q.filter(Finding.job_id == job_id)
    return q.order_by(Finding.id.desc()).all()
