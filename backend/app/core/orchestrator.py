from __future__ import annotations

import traceback
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters import all_adapters
from app.config import get_settings
from app.core.authz import assert_in_scope, assert_roe
from app.core.correlator import correlate
from app.core.reports import write_html_report
from app.models import AuditEvent, Engagement, Finding, Job, JobStatus


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
        for target in engagement.scope_targets:
            assert_in_scope(target, engagement.scope_targets)

        job.status = JobStatus.running
        job.started_at = datetime.now(timezone.utc)
        job.phase = "F1"
        job.progress = 5
        db.commit()
        audit(db, engagement.id, "job_started", {"job_id": job.id})

        job_dir = settings.artifacts_path / f"engagement-{engagement.id}" / f"job-{job.id}"
        job_dir.mkdir(parents=True, exist_ok=True)

        adapters = {a.name: a for a in all_adapters()}
        raw_findings = []
        total_steps = sum(len(tools) for _, _, tools in PHASES if tools) + 2
        step = 0

        for phase, _label, tools in PHASES:
            job.phase = phase
            db.commit()

            if phase == "F5":
                correlated = correlate(raw_findings)
                raw_findings = correlated
                step += 1
                job.progress = min(95, int(step / total_steps * 100))
                db.commit()
                continue

            if phase == "F6":
                # persist findings then report
                _persist_findings(db, engagement, job, raw_findings)
                findings = (
                    db.query(Finding)
                    .filter(Finding.job_id == job.id)
                    .order_by(Finding.id.asc())
                    .all()
                )
                report = write_html_report(engagement, job, findings, job_dir)
                job.report_path = str(report)
                step += 1
                job.progress = 100
                job.phase = "F6"
                job.status = JobStatus.completed
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
                audit(
                    db,
                    engagement.id,
                    "job_completed",
                    {"job_id": job.id, "findings": len(findings), "report": str(report)},
                )
                continue

            for tool_name in tools:
                job.current_tool = tool_name
                db.commit()
                adapter = adapters[tool_name]
                for target in engagement.scope_targets:
                    assert_in_scope(target, engagement.scope_targets)
                    result = adapter.run(target, job_dir, engagement.intensity.value)
                    audit(
                        db,
                        engagement.id,
                        "tool_ran",
                        {
                            "job_id": job.id,
                            "tool": tool_name,
                            "target": target,
                            "mocked": result.mocked,
                            "command": result.command,
                        },
                    )
                    raw_findings.extend(result.findings)
                step += 1
                job.progress = min(90, int(step / total_steps * 100))
                db.commit()

        job.current_tool = None
        db.commit()
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.failed
        job.error = str(exc)
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
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
) -> None:
    existing = {
        f.fingerprint
        for f in db.query(Finding).filter(Finding.engagement_id == engagement.id).all()
    }
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
    db.commit()
