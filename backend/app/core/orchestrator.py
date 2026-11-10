from __future__ import annotations

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from ipaddress import ip_address

import httpx
from sqlalchemy.orm import Session

from app.adapters import all_adapters, tools_status
from app.adapters.base import AdapterResult, RawFinding
from app.config import get_settings
from app.core.authz import assert_in_allowlist, assert_in_scope, assert_roe
from app.core.callbacks import assert_safe_callback_url, encode_callback
from app.core.correlator import correlate
from app.core.ipdiscovery import discover_origin_ip, is_cloudflare_ip
from app.core.reports import write_html_report, write_pdf_report
from app.core.targets import target_host, target_resolution
from app.models import AuditEvent, Engagement, Finding, Job, JobFinding, JobStatus, Severity
from app.queue import clear_callback, clear_cancel, get_callback, is_cancel_requested
from app.tool_catalog import (
    DEFAULT_PIPELINE_TOOLS,
    resolve_selected_tools,
    validate_selection_for_intensity,
)

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


def audit(
    db: Session,
    engagement_id: int | None,
    action: str,
    detail: dict | None = None,
    *,
    actor: str = "system",
    client_ip: str | None = None,
) -> None:
    db.add(
        AuditEvent(
            engagement_id=engagement_id,
            actor=actor[:100],
            client_ip=client_ip[:64] if client_ip else None,
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

    Nunca falha o job: erro/timeout/SSRF viram evento de audit. A URL é revalidada
    (DNS + IP público) no momento do envio para mitigar DNS rebinding.
    """
    url = get_callback(job.id)
    if not url:
        return
    engagement_id = engagement.id if engagement else None
    try:
        assert_safe_callback_url(url)
    except Exception as exc:  # webhook nunca pode derrubar o job
        audit(
            db,
            engagement_id,
            "callback_blocked",
            {"job_id": job.id, "url": url, "error": str(exc)[:200]},
        )
        logger.warning("callback bloqueado (SSRF): %s", exc, extra={"job_id": job.id})
        clear_callback(job.id)
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
    body, headers = encode_callback(payload, get_settings().ethoscan_callback_secret)
    try:
        response = httpx.post(
            url,
            content=body,
            headers=headers,
            timeout=CALLBACK_TIMEOUT_SECONDS,
        )
        audit(
            db,
            engagement_id,
            "callback_sent",
            {
                "job_id": job.id,
                "url": url,
                "status_code": response.status_code,
                "signed": "X-Ethoscan-Signature" in headers,
            },
        )
        logger.info(
            "callback enviado (HTTP %s)", response.status_code, extra={"job_id": job.id}
        )
    except Exception as exc:
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
    job.finished_at = datetime.now(UTC)
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
        except Exception as exc:
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
        resolved = _job_selected_tools(job)
        # Jobs explícitos antigos/DB editada: falhar em vez de filtrar em silêncio
        # e acabar num pipeline diferente do pedido.
        if job.selected_tools and not resolved:
            raise RuntimeError(
                "Seleção de tools não contém nenhuma tool executável; "
                "edite o engagement/job para uma seleção válida."
            )
        if job.selected_tools:
            validate_selection_for_intensity(resolved, engagement.intensity.value)
        selected = _prune_redundant_tools(resolved, engagement.intensity.value)
        job.selected_tools = selected
        job.status = JobStatus.running
        job.started_at = datetime.now(UTC)
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
                    .join(JobFinding, JobFinding.finding_id == Finding.id)
                    .filter(JobFinding.job_id == job.id)
                    .order_by(Finding.id.asc())
                    .all()
                )
                # Estado final ANTES de gerar: o relatório deve dizer completed,
                # não "running", e o progresso deve ser 100.
                job.status = JobStatus.completed
                job.phase = "F6"
                job.progress = 100
                job.finished_at = datetime.now(UTC)
                job.current_tool = None
                db.flush()
                report = write_html_report(engagement, job, findings, job_dir)
                pdf = write_pdf_report(engagement, job, findings, job_dir)
                job.report_path = str(report)
                job.report_pdf_path = str(pdf)
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
    except Exception as exc:
        job.status = JobStatus.failed
        job.error = str(exc)
        job.finished_at = datetime.now(UTC)
        job.current_tool = None
        db.commit()
        clear_cancel(job.id)
        logger.exception(
            "job %s falhou", job_id, extra={"job_id": job_id, "status": "failed"}
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
            "command": (result.command or [])[:16],
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
    # Cobertura DNS: não falha o job (nuclei DNS ainda pode ser útil), mas
    # explica no relatório porque nmap/whatweb/sslscan/gobuster não vão ligar.
    dns_coverage = []
    for target in engagement.scope_targets:
        addresses, error = target_resolution(target)
        dns_coverage.append({"target": target, "addresses": addresses, "error": error})
    tool_runs["_coverage"] = {"dns": dns_coverage}

    # Descoberta passiva de IP de origem para domínios atrás de CDN: os
    # candidatos ficam no relatório (Cobertura) para validação manual no RoE.
    origin_ip_coverage = []
    for entry in dns_coverage:
        target = entry["target"]
        if entry["error"]:
            continue
        host = target_host(target)
        try:
            ip_address(host)
            continue  # alvo já é IP
        except ValueError:
            pass
        if not any(is_cloudflare_ip(addr) for addr in entry["addresses"]):
            continue
        try:
            discovery = discover_origin_ip(host)
        except Exception:
            logger.warning("Descoberta de IP de origem falhou para %s", host, exc_info=True)
            continue
        origin_ip_coverage.append(
            {
                "target": target,
                "cdn": discovery.get("cdn", ""),
                "origin_candidates": discovery.get("origin_candidates", [])[:5],
            }
        )
        if discovery.get("origin_candidates"):
            audit(
                db,
                engagement.id,
                "origin_ip_candidates",
                {
                    "job_id": job.id,
                    "target": target,
                    "candidates": [c["ip"] for c in discovery["origin_candidates"][:5]],
                },
                actor="worker",
            )
    if origin_ip_coverage:
        tool_runs["_coverage"]["origin_ip"] = origin_ip_coverage
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
        finding.fingerprint: finding
        for finding in db.query(Finding)
        .filter(Finding.engagement_id == engagement.id)
        .all()
    }
    linked = {
        link.finding_id
        for link in db.query(JobFinding).filter(JobFinding.job_id == job.id).all()
    }
    for item in raw_findings:
        fingerprint = item.fingerprint()
        finding = existing.get(fingerprint)
        if finding is None:
            finding = Finding(
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
                fingerprint=fingerprint,
                mocked=bool(getattr(item, "mocked", False)),
            )
            db.add(finding)
            db.flush()
            existing[fingerprint] = finding
        if finding.id not in linked:
            db.add(JobFinding(job_id=job.id, finding_id=finding.id))
            linked.add(finding.id)
    db.commit()
