from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.authz import assert_roe, validate_scope
from app.core.orchestrator import audit, run_pipeline
from app.db import get_db
from app.models import Engagement, Finding, Job, JobStatus
from app.schemas import (
    EngagementCreate,
    EngagementOut,
    FindingOut,
    JobOut,
    JobStartResponse,
)

router = APIRouter(prefix="/api")


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
def start_job(
    engagement_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
) -> JobStartResponse:
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement não encontrado")
    assert_roe(eng.roe_acknowledged)

    job = Job(engagement_id=eng.id, status=JobStatus.pending, phase="F0", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(db, eng.id, "job_queued", {"job_id": job.id})
    background.add_task(_run_job_bg, job.id)
    return JobStartResponse(job=job, message="Pipeline enfileirado (F0–F6)")


def _run_job_bg(job_id: int) -> None:
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        run_pipeline(db, job_id)
    finally:
        db.close()


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
