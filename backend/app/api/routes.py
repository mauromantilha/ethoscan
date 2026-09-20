import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.adapters import tools_status
from app.core.authz import assert_roe, validate_scope
from app.core.orchestrator import PHASE_LABELS, audit
from app.core.reports import write_pdf_report
from app.core.security import require_api_key
from app.db import get_db
from app.lab_inventory import lab_tools_inventory
from app.models import Engagement, Finding, Job, JobStatus
from app.queue import enqueue_job, ping_redis, request_cancel
from app.schemas import (
    EngagementCreate,
    EngagementOut,
    FindingOut,
    HistoryItemOut,
    JobOut,
    JobStartRequest,
    JobStartResponse,
    LabInventoryOut,
    LaunchToolResponse,
    ToolCatalogOut,
)
from app.tool_catalog import (
    DEFAULT_PIPELINE_TOOLS,
    find_launch_binary,
    tool_catalog,
    validate_selected_tools,
)

router = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


@router.get("/engagements", response_model=list[EngagementOut])
def list_engagements(db: Session = Depends(get_db)) -> list[Engagement]:
    return db.query(Engagement).order_by(Engagement.id.desc()).all()


@router.post("/engagements", response_model=EngagementOut)
def create_engagement(payload: EngagementCreate, db: Session = Depends(get_db)) -> Engagement:
    scope = validate_scope(payload.scope_targets)
    try:
        selected = validate_selected_tools(payload.selected_tools)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    eng = Engagement(
        name=payload.name,
        scope_targets=scope,
        intensity=payload.intensity,
        roe_acknowledged=payload.roe_acknowledged,
        roe_text=payload.roe_text
        or "Autorizo o assessment apenas nos alvos listados no escopo, em modo ético.",
        notes=payload.notes,
        selected_tools=selected,
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    audit(
        db,
        eng.id,
        "engagement_created",
        {"name": eng.name, "scope": eng.scope_targets, "selected_tools": selected},
    )
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
    payload: JobStartRequest | None = None,
    db: Session = Depends(get_db),
) -> JobStartResponse:
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

    body = payload or JobStartRequest()
    try:
        if body.selected_tools is not None:
            selected = validate_selected_tools(body.selected_tools)
        else:
            selected = list(eng.selected_tools or [])
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    job = Job(
        engagement_id=eng.id,
        status=JobStatus.pending,
        phase="F0",
        progress=0,
        tool_runs={},
        selected_tools=selected,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(
        db,
        eng.id,
        "job_queued",
        {"job_id": job.id, "selected_tools": selected},
    )
    try:
        enqueue_job(job.id)
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.failed
        job.error = f"Falha ao enfileirar no Redis: {exc}"
        db.commit()
        raise HTTPException(503, job.error) from exc
    msg = (
        "Pipeline enfileirado no worker (F0 gate → F1–F6)"
        if not selected
        else f"Pipeline enfileirado com tools: {', '.join(selected)}"
    )
    return JobStartResponse(job=job, message=msg)


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(engagement_id: int | None = None, db: Session = Depends(get_db)) -> list[Job]:
    q = db.query(Job)
    if engagement_id is not None:
        q = q.filter(Job.engagement_id == engagement_id)
    return q.order_by(Job.id.desc()).all()


@router.get("/history", response_model=list[HistoryItemOut])
def list_history(
    limit: int = 50,
    engagement_id: int | None = None,
    db: Session = Depends(get_db),
) -> list[HistoryItemOut]:
    """Histórico de jobs com contagem de achados e flags de relatório."""
    lim = max(1, min(limit, 200))
    q = db.query(Job, Engagement).join(Engagement, Engagement.id == Job.engagement_id)
    if engagement_id is not None:
        q = q.filter(Job.engagement_id == engagement_id)
    rows = q.order_by(Job.id.desc()).limit(lim).all()
    items: list[HistoryItemOut] = []
    for job, eng in rows:
        count = db.query(Finding).filter(Finding.job_id == job.id).count()
        items.append(
            HistoryItemOut(
                job_id=job.id,
                engagement_id=eng.id,
                engagement_name=eng.name,
                status=job.status,
                phase=job.phase,
                progress=job.progress,
                intensity=eng.intensity,
                selected_tools=list(job.selected_tools or eng.selected_tools or []),
                findings_count=count,
                has_html_report=bool(job.report_path),
                has_pdf_report=bool(job.report_pdf_path) or job.status == JobStatus.completed,
                error=job.error,
                created_at=job.created_at,
                started_at=job.started_at,
                finished_at=job.finished_at,
            )
        )
    return items


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


@router.get("/jobs/{job_id}/report.pdf")
def download_report_pdf(job_id: int, db: Session = Depends(get_db)) -> Response:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    if job.status != JobStatus.completed:
        raise HTTPException(404, "Relatório PDF ainda não disponível")

    pdf_path = Path(job.report_pdf_path) if job.report_pdf_path else None
    if pdf_path and pdf_path.is_file():
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=pdf_path.name,
        )

    # Regenerar a partir dos findings se o ficheiro em falta.
    eng = db.get(Engagement, job.engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement não encontrado")
    findings = (
        db.query(Finding).filter(Finding.job_id == job.id).order_by(Finding.id.asc()).all()
    )
    out_dir = Path(job.report_path).parent if job.report_path else Path("/tmp")
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = write_pdf_report(eng, job, findings, out_dir)
    job.report_pdf_path = str(pdf_path)
    db.commit()
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=pdf_path.name,
    )


@router.get("/phases")
def list_phases() -> dict[str, str]:
    return PHASE_LABELS


@router.get("/tools", response_model=ToolCatalogOut)
def list_tool_catalog() -> ToolCatalogOut:
    """Catálogo runnable + inventário (disponível / runnable / lançamento GUI)."""
    return ToolCatalogOut(
        tools=tool_catalog(),
        default_pipeline=list(DEFAULT_PIPELINE_TOOLS),
    )


@router.post("/tools/burpsuite/launch", response_model=LaunchToolResponse)
def launch_burpsuite() -> LaunchToolResponse:
    """Compat: lança Burp Suite GUI."""
    return _launch_gui_tool("burpsuite")


@router.post("/tools/{tool_id}/launch", response_model=LaunchToolResponse)
def launch_tool(tool_id: str) -> LaunchToolResponse:
    """Lança tool GUI (burpsuite, wireshark, fern) se estiver no PATH — sem scan automatizado."""
    return _launch_gui_tool(tool_id.strip().lower())


def _launch_gui_tool(tool_id: str) -> LaunchToolResponse:
    binary = find_launch_binary(tool_id)
    labels = {
        "burpsuite": "Burp Suite",
        "wireshark": "Wireshark",
        "fern-wifi-cracker": "Fern WiFi Cracker",
    }
    label = labels.get(tool_id, tool_id)
    if not binary:
        return LaunchToolResponse(
            tool=tool_id,
            launched=False,
            binary=None,
            message=f"{label} não encontrado no PATH ou não é launchable.",
        )
    try:
        subprocess.Popen(  # noqa: S603
            [binary],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise HTTPException(500, f"Falha ao lançar {label}: {exc}") from exc
    extra = ""
    if tool_id == "burpsuite":
        extra = " Community Edition não tem adapter headless — use ZAP no pipeline."
    return LaunchToolResponse(
        tool=tool_id,
        launched=True,
        binary=binary,
        message=f"{label} lançado (GUI).{extra}",
    )


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
