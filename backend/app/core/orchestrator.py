from __future__ import annotations

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from app.adapters import all_adapters, tools_status
from app.adapters.base import AdapterResult, RawFinding
from app.config import get_settings
from app.core.authz import assert_in_allowlist, assert_in_scope, assert_roe
from app.core.correlator import correlate
from app.core.reports import write_html_report, write_pdf_report
from app.models import AuditEvent, Engagement, Finding, Job, JobStatus, Severity
from app.queue import clear_callback, clear_cancel, get_callback, is_cancel_requested
from app.tool_catalog import DEFAULT_PIPELINE_TOOLS, filter_by_intensity, resolve_selected_tools

logger = logging.getLogger("ethoscan.orchestrator")

# timeout do webhook de conclusão (best-effort: não pode travar o worker)
CALLBACK_TIMEOUT_SECONDS = 5.0


# F0 = gate explícito (RoE + escopo + tools). F1–F6 = execução.
# Tools opcionais só correm se selected_tools as incluir.
PHASES = [
    ("F0", "gate", []),
    ("F1", "recon", ["whatweb"]),
    (
        "F2",
        "enum",
        [
            "nmap",
            "sslscan",
            "masscan",
            "unicornscan",
            "metasploit",
            "netexec",
            "bloodhound-python",
        ],
    ),
    ("F3", "web-discovery", ["gobuster", "zap", "sqlmap"]),
    ("F4", "vuln", ["nuclei", "nikto", "hydra", "john"]),
    ("F5", "correlate", []),
    ("F6", "report", []),
]

PHASE_LABELS = {
    "F0": "Gate (RoE, escopo, tools)",
    "F1": "Recon (WhatWeb)",
    "F2": "Enum (Nmap, sslscan, masscan, unicornscan, msf-aux, nxc, BH)",
    "F3": "Web discovery (Gobuster, ZAP, sqlmap)",
    "F4": "Vuln (Nuclei, Nikto, hydra, john)",
    "F5": "Correlação",
    "F6": "Relatório",
}

# Cap de paralelismo intra-fase (adapters independentes).
_PHASE_PARALLEL_WORKERS = 3

# Em safe/standard, scanners de porta rápidos sobrepõem nmap — omitir se nmap já está selecionado.
_REDUNDANT_WITH_NMAP = frozenset({"masscan", "metasploit", "unicornscan"})


class JobCancelled(Exception):
    """Cancelamento solicitado durante o pipeline."""


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


def _check_cancel(db: Session, job: Job) -> None:
    db.refresh(job)
    if job.status == JobStatus.cancelled or is_cancel_requested(job.id):
        raise JobCancelled(f"Job #{job.id} cancelado")


def _notify_callback(
    db: Session,
    job: Job,
    engagement: Engagement | None,
    status: str,
    findings_count: int | None = None,
) -> None:
    """POST best-effort no webhook registrado pelo cliente (API de integração/n8n).

    Nunca falha o job: erro/timeout viram evento ``callback_failed`` no audit. A URL é
    validada (http/https) no momento do registro, que exige credencial válida.
    """
    url = get_callback(job.id)
    if not url:
        return
    payload = {
        "job_id": job.id,
        "engagement_id": job.engagement_id,
        "status": status,
        "phase": job.phase,
        "progress": job.progress,
        "error": job.error,
        "findings_count": findings_count,
        "report_path": job.report_path,
        "report_pdf_path": job.report_pdf_path,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }
    engagement_id = engagement.id if engagement else None
    try:
        response = httpx.post(url, json=payload, timeout=CALLBACK_TIMEOUT_SECONDS)
        audit(
            db,
            engagement_id,
            "callback_sent",
            {"job_id": job.id, "url": url, "status_code": response.status_code},
        )
        logger.info(
            "callback enviado (HTTP %s)", response.status_code, extra={"job_id": job.id}
        )
    except Exception as exc:  # noqa: BLE001 - webhook nunca derruba o pipeline
        audit(
            db,
            engagement_id,
            "callback_failed",
            {"job_id": job.id, "url": url, "error": str(exc)[:200]},
        )
        logger.warning("callback falhou: %s", exc, extra={"job_id": job.id})
    finally:
        clear_callback(job.id)


def _mark_cancelled(db: Session, job: Job, engagement: Engagement | None) -> None:
    job.status = JobStatus.cancelled
    job.finished_at = datetime.now(timezone.utc)
    job.current_tool = None
    job.error = job.error or "Cancelado pelo operador"
    db.commit()
    clear_cancel(job.id)
    logger.info(
        "job cancelado na fase %s",
        job.phase,
        extra={"job_id": job.id, "phase": job.phase, "status": JobStatus.cancelled.value},
    )
    _notify_callback(db, job, engagement, JobStatus.cancelled.value)
    audit(
        db,
        engagement.id if engagement else None,
        "job_cancelled",
        {"job_id": job.id, "phase": job.phase, "progress": job.progress},
    )


def _job_selected_tools(job: Job) -> list[str]:
    stored = list(job.selected_tools or [])
    return resolve_selected_tools(stored if stored else None)


def _prune_redundant_tools(selected: list[str], intensity: str) -> list[str]:
    """Evita scanners de porta redundantes quando nmap já cobre o escopo."""
    if intensity not in {"safe", "standard"}:
        return selected
    selected_set = set(selected)
    if "nmap" not in selected_set:
        return selected
    pruned = [t for t in selected if t not in _REDUNDANT_WITH_NMAP]
    return pruned if pruned else selected


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


def _run_adapter_targets(
    adapter,
    targets: list[str],
    scope_targets: list[str],
    job_dir,
    intensity: str,
) -> tuple[AdapterResult | None, list, str | None]:
    """Executa um adapter contra todos os alvos (thread-safe; sem sessão DB)."""
    findings: list = []
    last: AdapterResult | None = None
    last_target: str | None = None
    for target in targets:
        assert_in_scope(target, scope_targets)
        try:
            last = adapter.run(target, job_dir, intensity)
        except Exception as exc:  # noqa: BLE001 - falha de uma tool não derruba o pipeline
            logger.warning(
                "adapter %s levantou exceção: %s",
                adapter.name,
                exc,
                extra={"tool": adapter.name, "target": target},
            )
            last = AdapterResult(
                tool=adapter.name,
                mocked=False,
                command=[adapter.name],
                error=f"{type(exc).__name__}: {exc}",
            )
        findings.extend(last.findings)
        if not last.ok:
            # falha/timeout/exit != 0 vira achado explícito (audit registra ok/exit_code)
            findings.append(tool_error_finding(last, target))
        last_target = target
    return last, findings, last_target


def run_pipeline(db: Session, job_id: int) -> None:
    settings = get_settings()
    job = db.get(Job, job_id)
    if not job:
        return
    engagement = db.get(Engagement, job.engagement_id)
    if not engagement:
        return

    if job.status == JobStatus.cancelled or is_cancel_requested(job.id):
        _mark_cancelled(db, job, engagement)
        return

    try:
        selected = _prune_redundant_tools(
            filter_by_intensity(
                _job_selected_tools(job),
                engagement.intensity.value,
            ),
            engagement.intensity.value,
        )
        job.selected_tools = selected
        job.status = JobStatus.running
        job.started_at = datetime.now(timezone.utc)
        job.phase = "F0"
        job.progress = 2
        job.tool_runs = dict(job.tool_runs or {})
        db.commit()
        audit(
            db,
            engagement.id,
            "job_started",
            {"job_id": job.id, "selected_tools": selected},
        )

        _run_f0_gate(db, job, engagement, selected)
        _check_cancel(db, job)

        job_dir = settings.artifacts_path / f"engagement-{engagement.id}" / f"job-{job.id}"
        job_dir.mkdir(parents=True, exist_ok=True)

        adapters = {a.name: a for a in all_adapters()}
        raw_findings = []
        selected_set = set(selected)
        tool_steps = sum(
            1
            for phase, _, tools in PHASES
            if phase not in {"F0", "F5", "F6"}
            for t in tools
            if t in selected_set
        )
        total_steps = max(tool_steps, 1) + 2
        step = 0

        for phase, _label, tools in PHASES:
            if phase == "F0":
                continue

            _check_cancel(db, job)
            job.phase = phase
            db.commit()

            if phase == "F5":
                raw_findings = correlate(raw_findings)
                step += 1
                job.progress = min(95, int(10 + step / total_steps * 85))
                db.commit()
                continue

            if phase == "F6":
                _persist_findings(db, engagement, job, raw_findings)
                findings = (
                    db.query(Finding)
                    .filter(Finding.job_id == job.id)
                    .order_by(Finding.id.asc())
                    .all()
                )
                report = write_html_report(engagement, job, findings, job_dir)
                pdf = write_pdf_report(engagement, job, findings, job_dir)
                job.report_path = str(report)
                job.report_pdf_path = str(pdf)
                step += 1
                job.progress = 100
                job.phase = "F6"
                job.status = JobStatus.completed
                job.finished_at = datetime.now(timezone.utc)
                job.current_tool = None
                db.commit()
                clear_cancel(job.id)
                audit(
                    db,
                    engagement.id,
                    "job_completed",
                    {
                        "job_id": job.id,
                        "findings": len(findings),
                        "report": str(report),
                        "report_pdf": str(pdf),
                        "selected_tools": selected,
                    },
                )
                logger.info(
                    "job concluído (%s achados, tools=%s)",
                    len(findings),
                    ",".join(selected),
                    extra={
                        "job_id": job.id,
                        "phase": "F6",
                        "status": JobStatus.completed.value,
                        "findings": len(findings),
                    },
                )
                _notify_callback(
                    db, job, engagement, JobStatus.completed.value, findings_count=len(findings)
                )
                continue

            active = [t for t in tools if t in selected_set]
            if not active:
                # Fase vazia (conjunto pequeno de tools) — avançar sem espera.
                continue

            if len(active) == 1:
                tool_name = active[0]
                _check_cancel(db, job)
                job.current_tool = tool_name
                db.commit()
                result, findings, last_target = _run_adapter_targets(
                    adapters[tool_name],
                    list(engagement.scope_targets),
                    list(engagement.scope_targets),
                    job_dir,
                    engagement.intensity.value,
                )
                _record_tool_run(
                    db, job, engagement, tool_name, adapters[tool_name], result, last_target
                )
                raw_findings.extend(findings)
                step += 1
                job.progress = min(90, int(10 + step / total_steps * 85))
                job.current_tool = None
                db.commit()
            else:
                # Tools independentes na mesma fase em paralelo (ex.: nmap ∥ sslscan).
                job.current_tool = "+".join(active)
                db.commit()
                workers = min(_PHASE_PARALLEL_WORKERS, len(active))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(
                            _run_adapter_targets,
                            adapters[tool_name],
                            list(engagement.scope_targets),
                            list(engagement.scope_targets),
                            job_dir,
                            engagement.intensity.value,
                        ): tool_name
                        for tool_name in active
                    }
                    for fut in as_completed(futures):
                        tool_name = futures[fut]
                        _check_cancel(db, job)
                        result, findings, last_target = fut.result()
                        _record_tool_run(
                            db,
                            job,
                            engagement,
                            tool_name,
                            adapters[tool_name],
                            result,
                            last_target,
                        )
                        raw_findings.extend(findings)
                        step += 1
                        job.progress = min(90, int(10 + step / total_steps * 85))
                        job.current_tool = tool_name
                        db.commit()
                job.current_tool = None
                db.commit()

        job.current_tool = None
        db.commit()
    except JobCancelled:
        _mark_cancelled(db, job, engagement)
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.failed
        job.error = str(exc)
        job.finished_at = datetime.now(timezone.utc)
        job.current_tool = None
        db.commit()
        clear_cancel(job.id)
        logger.exception(
            "job %s falhou: %s", job_id, exc, extra={"job_id": job_id, "status": "failed"}
        )
        audit(
            db,
            engagement.id if engagement else None,
            "job_failed",
            {"job_id": job_id, "error": str(exc), "trace": traceback.format_exc()[-2000:]},
        )
        _notify_callback(db, job, engagement, JobStatus.failed.value)


def _record_tool_run(
    db: Session,
    job: Job,
    engagement: Engagement,
    tool_name: str,
    adapter,
    result: AdapterResult | None,
    last_target: str | None = None,
) -> None:
    runs = dict(job.tool_runs or {})
    prev = runs.get(tool_name, {})
    if result is None:
        runs[tool_name] = {
            "mocked": bool(prev.get("mocked")),
            "available": adapter.available(),
            "source": tool_name,
        }
    else:
        runs[tool_name] = {
            "mocked": bool(prev.get("mocked")) or result.mocked,
            "available": adapter.available(),
            "last_target": last_target,
            "command": (result.command or [])[:8],
            "source": tool_name,
            "ok": result.ok,
            "exit_code": result.exit_code,
            "error": result.error,
        }
    job.tool_runs = runs
    if result is not None and not result.ok:
        logger.warning(
            "tool %s terminou com falha (%s)",
            tool_name,
            result.error or f"exit code {result.exit_code}",
            extra={
                "job_id": job.id,
                "tool": tool_name,
                "target": last_target,
                "exit_code": result.exit_code,
            },
        )
    audit(
        db,
        engagement.id,
        "tool_ran",
        {
            "job_id": job.id,
            "tool": tool_name,
            "target": last_target,
            "mocked": bool(result.mocked) if result else False,
            "command": (result.command if result else None),
            "ok": result.ok if result else None,
            "exit_code": result.exit_code if result else None,
            "error": result.error if result else None,
        },
    )


def _run_f0_gate(
    db: Session,
    job: Job,
    engagement: Engagement,
    selected: list[str],
) -> None:
    """Gate F0: RoE, escopo e disponibilidade das tools selecionadas."""
    settings = get_settings()
    job.phase = "F0"
    job.current_tool = "gate"
    job.progress = 5
    db.commit()

    assert_roe(engagement.roe_acknowledged)
    allowlist = settings.allowlist_targets
    for target in engagement.scope_targets:
        assert_in_scope(target, engagement.scope_targets)
        # revalida a allowlist global na execução (defesa em profundidade)
        assert_in_allowlist(target, allowlist)

    required = selected or list(DEFAULT_PIPELINE_TOOLS)
    status = tools_status()
    missing = [name for name in required if not status.get(name, {}).get("available")]
    if missing and not settings.ethoscan_allow_mock:
        raise RuntimeError(
            f"F0 gate: tools em falta e mock desligado: {', '.join(missing)}. "
            "Instale os binários Kali ou defina ETHOSCAN_ALLOW_MOCK=true."
        )

    tool_runs = dict(job.tool_runs or {})
    for name in required:
        info = status.get(name, {})
        tool_runs[name] = {
            "mocked": bool(info.get("will_mock")),
            "available": bool(info.get("available")),
            "mode": info.get("mode", "unavailable"),
            "selected": True,
        }
    job.tool_runs = tool_runs
    job.progress = 10
    job.current_tool = None
    db.commit()
    audit(
        db,
        engagement.id,
        "f0_gate_passed",
        {
            "job_id": job.id,
            "missing_tools": missing,
            "mock_allowed": settings.ethoscan_allow_mock,
            "selected_tools": required,
            "tool_runs": tool_runs,
        },
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
                mocked=bool(getattr(item, "mocked", False)),
            )
        )
        existing.add(fp)
    db.commit()
