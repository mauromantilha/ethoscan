from __future__ import annotations

import logging
import traceback
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.adapters import all_adapters
from app.adapters.base import AdapterResult, RawFinding
from app.config import get_settings
from app.core.authz import assert_in_allowlist, assert_in_scope, assert_roe
from app.core.correlator import correlate
from app.core.reports import write_html_report
from app.models import AuditEvent, Engagement, Finding, Job, JobStatus, Severity

logger = logging.getLogger(__name__)

PHASES = [
    ("F1", "recon", ["whatweb"]),
    ("F2", "enum", ["nmap", "sslscan"]),
    ("F3", "web-discovery", ["gobuster"]),
    ("F4", "vuln", ["nuclei"]),
    ("F5", "correlate", []),
    ("F6", "report", []),
]


def audit(db: Session, engagement_id: int | None, action: str, detail: dict | None = None) -> None:
    db.add(
        AuditEvent(
            engagement_id=engagement_id,
            actor="system",
            action=action,
            detail=detail or {},
        )
    )
    db.commit()


def _stop_if_cancelled(db: Session, job: Job) -> bool:
    """Cancelamento cooperativo: a API marca ``cancelled`` e o pipeline para no próximo passo."""
    db.refresh(job)
    if job.status != JobStatus.cancelled:
        return False
    job.current_tool = None
    if job.finished_at is None:
        job.finished_at = datetime.now(UTC)
    db.commit()
    logger.info(
        "job cancelado: pipeline interrompido",
        extra={"job_id": job.id, "phase": job.phase, "status": "cancelled"},
    )
    audit(db, job.engagement_id, "job_cancel_stopped", {"job_id": job.id, "phase": job.phase})
    return True


def _tool_error_result(tool_name: str, exc: BaseException) -> AdapterResult:
    return AdapterResult(
        tool=tool_name,
        mocked=False,
        command=[tool_name],
        exit_code=-1,
        error=f"{type(exc).__name__}: {exc}",
    )


def tool_error_finding(result: AdapterResult, target: str) -> RawFinding:
    """Achado explícito de falha de tool: o alvo pode ter sido avaliado de forma incompleta."""
    detail = result.error or f"exit code {result.exit_code}"
    return RawFinding(
        title=f"Ferramenta {result.tool} falhou",
        severity=Severity.info,
        target=target,
        tool=result.tool,
        category="tool_error",
        description=(
            f"A execução de {result.tool} não concluiu com sucesso ({detail}); "
            "os achados deste alvo podem estar incompletos."
        ),
        evidence=(result.stderr or result.stdout or detail)[:2000],
        remediation=(
            f"Executar '{result.tool}' manualmente no alvo e revisar instalação/permissões."
        ),
    )


def run_pipeline(db: Session, job_id: int) -> None:
    settings = get_settings()
    job = db.get(Job, job_id)
    if not job:
        return
    engagement = db.get(Engagement, job.engagement_id)
    if not engagement:
        return

    try:
        assert_roe(engagement.roe_acknowledged)
        allowlist = settings.allowlist_targets
        for target in engagement.scope_targets:
            assert_in_scope(target, engagement.scope_targets)
            assert_in_allowlist(target, allowlist)

        if job.status == JobStatus.pending:
            # normalmente o worker já reivindicou; isto cobre execução direta (testes)
            job.status = JobStatus.running
            job.started_at = datetime.now(UTC)
        job.phase = "F1"
        job.progress = 5
        db.commit()
        audit(db, engagement.id, "job_started", {"job_id": job.id})

        job_dir = settings.artifacts_path / f"engagement-{engagement.id}" / f"job-{job.id}"
        job_dir.mkdir(parents=True, exist_ok=True)

        adapters = {a.name: a for a in all_adapters()}
        raw_findings: list[RawFinding] = []
        mock_used = False
        total_steps = sum(len(tools) for _, _, tools in PHASES if tools) + 2
        step = 0

        for phase, _label, tools in PHASES:
            if _stop_if_cancelled(db, job):
                return
            job.phase = phase
            db.commit()
            logger.debug("fase iniciada", extra={"job_id": job.id, "phase": phase})

            if phase == "F5":
                correlated = correlate(raw_findings)
                raw_findings = correlated
                step += 1
                job.progress = min(95, int(step / total_steps * 100))
                db.commit()
                continue

            if phase == "F6":
                # persiste findings novos e gera o relatório com o acumulado do engagement
                new_findings = _persist_findings(db, engagement, job, raw_findings)
                findings = (
                    db.query(Finding)
                    .filter(Finding.engagement_id == engagement.id)
                    .order_by(Finding.id.asc())
                    .all()
                )
                report = write_html_report(
                    engagement,
                    job,
                    findings,
                    job_dir,
                    new_findings=new_findings,
                    mock_used=mock_used,
                )
                job.report_path = str(report)
                step += 1
                job.progress = 100
                job.phase = "F6"
                job.status = JobStatus.completed
                job.finished_at = datetime.now(UTC)
                db.commit()
                audit(
                    db,
                    engagement.id,
                    "job_completed",
                    {
                        "job_id": job.id,
                        "findings": len(findings),
                        "new_findings": new_findings,
                        "report": str(report),
                    },
                )
                logger.info(
                    "job concluído",
                    extra={
                        "job_id": job.id,
                        "phase": "F6",
                        "status": "completed",
                        "findings": len(findings),
                        "new_findings": new_findings,
                        "mocked": mock_used,
                    },
                )
                continue

            for tool_name in tools:
                if _stop_if_cancelled(db, job):
                    return
                job.current_tool = tool_name
                db.commit()
                adapter = adapters[tool_name]
                for target in engagement.scope_targets:
                    if _stop_if_cancelled(db, job):
                        return
                    assert_in_scope(target, engagement.scope_targets)
                    assert_in_allowlist(target, allowlist)
                    try:
                        result = adapter.run(target, job_dir, engagement.intensity.value)
                    except Exception as exc:  # noqa: BLE001 - isola falha de uma tool
                        result = _tool_error_result(tool_name, exc)
                    mock_used = mock_used or result.mocked
                    audit(
                        db,
                        engagement.id,
                        "tool_ran",
                        {
                            "job_id": job.id,
                            "tool": tool_name,
                            "target": target,
                            "mocked": result.mocked,
                            "ok": result.ok,
                            "exit_code": result.exit_code,
                            "error": result.error,
                            "command": result.command,
                        },
                    )
                    if result.ok:
                        raw_findings.extend(result.findings)
                    else:
                        # falha não derruba o pipeline: vira achado explícito
                        logger.warning(
                            "tool falhou: achados do alvo podem estar incompletos",
                            extra={
                                "job_id": job.id,
                                "tool": tool_name,
                                "target": target,
                                "exit_code": result.exit_code,
                            },
                        )
                        raw_findings.append(tool_error_finding(result, target))
                step += 1
                job.progress = min(90, int(step / total_steps * 100))
                db.commit()

        job.current_tool = None
        db.commit()
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.failed
        job.error = str(exc)
        job.finished_at = datetime.now(UTC)
        db.commit()
        logger.exception("job falhou", extra={"job_id": job_id, "status": "failed"})
        audit(
            db,
            engagement.id if engagement else None,
            "job_failed",
            {"job_id": job_id, "error": str(exc), "trace": traceback.format_exc()[-2000:]},
        )


def _persist_findings(
    db: Session,
    engagement: Engagement,
    job: Job,
    raw_findings,
) -> int:
    """Persiste findings ainda não vistos no engagement e devolve quantos são novos."""
    existing = {
        f.fingerprint
        for f in db.query(Finding).filter(Finding.engagement_id == engagement.id).all()
    }
    new_count = 0
    for item in raw_findings:
        fp = item.fingerprint()
        if fp in existing:
            continue
        db.add(
            Finding(
                engagement_id=engagement.id,
                job_id=job.id,
                title=item.title,
                severity=item.severity,
                target=item.target,
                tool=item.tool,
                category=item.category,
                description=item.description,
                evidence=item.evidence,
                cve=item.cve,
                cwe=item.cwe,
                remediation=item.remediation,
                fingerprint=fp,
            )
        )
        existing.add(fp)
        new_count += 1
    db.commit()
    return new_count
