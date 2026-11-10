"""Rotas do analista assistente LLM (advisory-only).

- POST /api/jobs/{id}/analyze   → triagem de findings + correlação + próximos passos
- POST /api/jobs/{id}/assistant → chat sobre o job (histórico limitado)

O modelo apenas analisa o contexto enviado (findings/metadados truncados);
nunca executa scans nem recebe artefactos brutos ou credenciais.
"""

from __future__ import annotations

import json
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import llm
from app.core.llm import (
    ANALYSIS_INSTRUCTIONS,
    ASSISTANT_INSTRUCTIONS,
    SYSTEM_PROMPT,
    LLMNotConfigured,
    LLMRequestError,
)
from app.core.orchestrator import audit
from app.core.security import credential_actor
from app.db import get_db
from app.models import Engagement, Finding, Job, JobFinding
from app.schemas import (
    AssistantChatRequest,
    AssistantChatResponse,
    FindingTriageOut,
    JobAnalysisOut,
    LLMTestOut,
)

logger = logging.getLogger("ethoscan")

router = APIRouter(prefix="/api", tags=["llm"])

_ALLOWED_VERDICTS = {"real", "false_positive", "inconclusive", "informational"}


def _actor_meta(request: Request) -> tuple[str, str | None]:
    return (
        credential_actor(request.headers.get("X-API-Key")),
        request.client.host if request.client else None,
    )


def _load_job_context(db: Session, job_id: int) -> tuple[Engagement, Job, list[Finding]]:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    eng = db.get(Engagement, job.engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement não encontrado")
    findings = (
        db.query(Finding)
        .join(JobFinding, JobFinding.finding_id == Finding.id)
        .filter(JobFinding.job_id == job.id)
        .order_by(Finding.id.asc())
        .all()
    )
    return eng, job, findings


def _require_llm() -> None:
    if not get_settings().llm_enabled:
        raise HTTPException(
            503,
            "Assistente LLM não configurado: defina ETHOSCAN_LLM_BASE_URL e "
            "ETHOSCAN_LLM_MODEL no .env da API (ex.: Ollama local).",
        )


@router.post("/llm/test", response_model=LLMTestOut)
def test_llm(request: Request, db: Session = Depends(get_db)) -> LLMTestOut:
    """Ping ao provedor LLM: valida BASE_URL/KEY/MODEL e mede a latência."""
    settings = get_settings()
    if not settings.llm_enabled:
        raise HTTPException(
            503,
            "Assistente LLM não configurado: defina ETHOSCAN_LLM_BASE_URL e "
            "ETHOSCAN_LLM_MODEL no .env da API.",
        )
    started = time.perf_counter()
    try:
        reply = llm.chat(
            [
                {"role": "system", "content": "Responda exatamente com a palavra: pong"},
                {"role": "user", "content": "ping"},
            ],
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
    except LLMNotConfigured as exc:
        raise HTTPException(503, str(exc)) from exc
    except LLMRequestError as exc:
        logger.warning("Teste do provedor LLM falhou: %s", exc)
        return LLMTestOut(
            ok=False,
            model=settings.ethoscan_llm_model.strip(),
            latency_ms=int((time.perf_counter() - started) * 1000),
            detail=str(exc)[:500],
        )
    actor, client_ip = _actor_meta(request)
    audit(
        db,
        None,
        "llm_test",
        {"model": settings.ethoscan_llm_model.strip(), "ok": True, "latency_ms": latency_ms},
        actor=actor,
        client_ip=client_ip,
    )
    return LLMTestOut(
        ok=True,
        model=settings.ethoscan_llm_model.strip(),
        latency_ms=latency_ms,
        reply=reply.strip()[:200],
    )


@router.post("/jobs/{job_id}/analyze", response_model=JobAnalysisOut)
def analyze_job(job_id: int, request: Request, db: Session = Depends(get_db)) -> JobAnalysisOut:
    """Triagem LLM dos achados do job: real/falso positivo, correlações e próximos passos."""
    _require_llm()
    eng, job, findings = _load_job_context(db, job_id)

    context = llm.job_context_payload(eng, job, findings)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Contexto do job (JSON):\n"
                f"{json.dumps(context, ensure_ascii=False, default=str)}\n\n"
                f"{ANALYSIS_INSTRUCTIONS}"
            ),
        },
    ]
    try:
        raw = llm.chat(messages, json_mode=True)
        data = llm.parse_json_object(raw)
    except LLMNotConfigured as exc:
        raise HTTPException(503, str(exc)) from exc
    except LLMRequestError as exc:
        logger.warning("Análise LLM falhou para job %s: %s", job_id, exc)
        raise HTTPException(502, str(exc)) from exc

    triage: list[FindingTriageOut] = []
    for item in data.get("triage") or []:
        try:
            entry = FindingTriageOut(
                finding_id=int(item.get("finding_id")),
                verdict=str(item.get("verdict", "inconclusive")).strip() or "inconclusive",
                confidence=max(0.0, min(1.0, float(item.get("confidence", 0.0)))),
                reasoning=str(item.get("reasoning", ""))[:1000],
            )
        except (TypeError, ValueError):
            continue
        if entry.verdict not in _ALLOWED_VERDICTS:
            entry.verdict = "inconclusive"
        triage.append(entry)

    actor, client_ip = _actor_meta(request)
    audit(
        db,
        eng.id,
        "llm_analyze",
        {
            "job_id": job.id,
            "model": get_settings().ethoscan_llm_model.strip(),
            "findings_total": len(findings),
            "triage_entries": len(triage),
        },
        actor=actor,
        client_ip=client_ip,
    )

    def _str_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(v)[:500] for v in value][:20]

    return JobAnalysisOut(
        job_id=job.id,
        model=get_settings().ethoscan_llm_model.strip(),
        summary=str(data.get("summary", ""))[:2000],
        triage=triage,
        correlations=_str_list(data.get("correlations")),
        next_steps=_str_list(data.get("next_steps")),
        limitations=_str_list(data.get("limitations")),
    )


@router.post("/jobs/{job_id}/assistant", response_model=AssistantChatResponse)
def assistant_chat(
    job_id: int,
    payload: AssistantChatRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantChatResponse:
    """Pergunte qualquer coisa sobre o job — o LLM responde com base no contexto dele."""
    _require_llm()
    eng, job, findings = _load_job_context(db, job_id)

    context = llm.job_context_payload(eng, job, findings)
    history = [
        {"role": m.role, "content": m.content[:2000]} for m in payload.history[-20:]
    ]
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Contexto do job (JSON):\n"
                f"{json.dumps(context, ensure_ascii=False, default=str)}\n\n"
                f"{ASSISTANT_INSTRUCTIONS}"
            ),
        },
        *history,
        {"role": "user", "content": payload.question},
    ]
    try:
        answer = llm.chat(messages)
    except LLMNotConfigured as exc:
        raise HTTPException(503, str(exc)) from exc
    except LLMRequestError as exc:
        logger.warning("Chat LLM falhou para job %s: %s", job_id, exc)
        raise HTTPException(502, str(exc)) from exc

    actor, client_ip = _actor_meta(request)
    audit(
        db,
        eng.id,
        "llm_assistant",
        {
            "job_id": job.id,
            "model": get_settings().ethoscan_llm_model.strip(),
            "question_chars": len(payload.question),
        },
        actor=actor,
        client_ip=client_ip,
    )
    return AssistantChatResponse(
        job_id=job.id,
        answer=answer,
        model=get_settings().ethoscan_llm_model.strip(),
    )
