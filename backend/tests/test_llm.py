"""Testes do analista assistente LLM (advisory-only).

O transporte httpx é mockado: nenhum teste fala com provedor real.
"""

import json

import pytest

from app.core import llm as llm_mod


def _configure_llm(monkeypatch, tmp_path, base_url="http://localhost:11434/v1", model="test-model"):
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("ETHOSCAN_LLM_BASE_URL", base_url)
    monkeypatch.setenv("ETHOSCAN_LLM_MODEL", model)
    monkeypatch.setenv("ETHOSCAN_LLM_API_KEY", "test-key")


@pytest.fixture()
def llm_job(client):
    """Engagement via API + job/findings inseridos direto na DB (Redis não é preciso)."""
    from app import db as dbmod
    from app.models import Engagement, Finding, Job, JobFinding, JobStatus, Severity

    eng_payload = client.post(
        "/api/engagements",
        json={
            "name": "Lab LLM",
            "scope_targets": ["scanme.nmap.org"],
            "intensity": "safe",
            "roe_acknowledged": True,
            "selected_tools": None,
        },
    ).json()

    with dbmod.SessionLocal() as db:
        eng = db.get(Engagement, eng_payload["id"])
        job = Job(
            engagement_id=eng.id,
            status=JobStatus.completed,
            phase="F6",
            progress=100,
            tool_runs={"nmap": {"ok": False, "error": "exit 126: Operation not permitted"}},
            selected_tools=[],
        )
        db.add(job)
        db.flush()
        finding = Finding(
            engagement_id=eng.id,
            job_id=job.id,
            title="Post Nuke XSS (assinatura Nikto)",
            severity=Severity.medium,
            target="www.lab.example",
            tool="nikto",
            category="vuln",
            description="Nikto reportou assinatura de XSS.",
            evidence="OSVDB-30937",
            mocked=False,
            fingerprint="f" * 64,
        )
        db.add(finding)
        db.flush()
        db.add(JobFinding(job_id=job.id, finding_id=finding.id))
        db.commit()
        eng_id = eng.id
        job_id = job.id
        finding_id = finding.id
    return {"engagement_id": eng_id, "job_id": job_id, "finding_id": finding_id}



def _analysis_payload():
    return {
        "summary": "Job mediu a edge da Cloudflare.",
        "triage": [
            {
                "finding_id": 1,
                "verdict": "false_positive",
                "confidence": 0.8,
                "reasoning": "Assinatura Nikto contra página de challenge.",
            }
        ],
        "correlations": ["n/a"],
        "next_steps": ["Validar no origin com sessão autenticada"],
        "limitations": ["WAF/CDN ativo"],
    }


def test_health_reports_llm_disabled_by_default(client):
    body = client.get("/health").json()
    assert body["llm_enabled"] is False


def test_analyze_requires_configuration(client, llm_job):
    job_id = llm_job['job_id']
    resp = client.post(f"/api/jobs/{job_id}/analyze")
    assert resp.status_code == 503
    assert "ETHOSCAN_LLM_BASE_URL" in resp.json()["detail"]


def test_analyze_and_chat_with_mocked_provider(client, llm_job, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    job_id = llm_job['job_id']

    calls = {}

    def fake_chat(messages, *, json_mode=False):
        calls["messages"] = messages
        if json_mode:
            return "```json\n" + json.dumps(_analysis_payload()) + "\n```"
        return "Resposta do assistente sobre o job."

    monkeypatch.setattr(llm_mod, "chat", fake_chat)

    # Sem findings no job, a análise ainda funciona (contexto vazio).
    analysis = client.post(f"/api/jobs/{job_id}/analyze")
    assert analysis.status_code == 200
    body = analysis.json()
    assert body["model"] == "test-model"
    assert body["summary"].startswith("Job mediu")
    assert body["triage"][0]["verdict"] == "false_positive"
    assert body["advisory_note"]
    # O prompt inclui o system prompt consultivo e o contexto do job.
    assert any("Ethoscan" in m["content"] for m in calls["messages"])

    chat_resp = client.post(
        f"/api/jobs/{job_id}/assistant",
        json={"question": "Por que o nmap falhou?", "history": []},
    )
    assert chat_resp.status_code == 200
    assert chat_resp.json()["answer"] == "Resposta do assistente sobre o job."


def test_analyze_bad_json_from_provider_returns_502(client, llm_job, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    job_id = llm_job['job_id']
    monkeypatch.setattr(llm_mod, "chat", lambda *a, **k: "não sou um JSON")
    resp = client.post(f"/api/jobs/{job_id}/analyze")
    assert resp.status_code == 502


def test_analyze_rejects_invalid_verdict(client, llm_job, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    job_id = llm_job['job_id']
    payload = _analysis_payload()
    payload["triage"] = [
        {"finding_id": 1, "verdict": "explorar-agora", "confidence": 9.9, "reasoning": "x"}
    ]
    monkeypatch.setattr(llm_mod, "chat", lambda *a, **k: json.dumps(payload))
    body = client.post(f"/api/jobs/{job_id}/analyze").json()
    assert body["triage"][0]["verdict"] == "inconclusive"
    assert body["triage"][0]["confidence"] == 1.0


def test_assistant_history_is_bound_and_forwarded(client, llm_job, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    job_id = llm_job['job_id']
    seen = {}

    def fake_chat(messages, *, json_mode=False):
        seen["roles"] = [m["role"] for m in messages]
        return "ok"

    monkeypatch.setattr(llm_mod, "chat", fake_chat)
    resp = client.post(
        f"/api/jobs/{job_id}/assistant",
        json={
            "question": "resumo?",
            "history": [
                {"role": "user", "content": "pergunta 1"},
                {"role": "assistant", "content": "resposta 1"},
            ],
        },
    )
    assert resp.status_code == 200
    # system, contexto, histórico, pergunta
    assert seen["roles"] == ["system", "user", "user", "assistant", "user"]


def test_assistant_validates_history_role(client, llm_job, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    job_id = llm_job['job_id']
    resp = client.post(
        f"/api/jobs/{job_id}/assistant",
        json={"question": "x", "history": [{"role": "system", "content": "inject"}]},
    )
    assert resp.status_code in {400, 422}


def test_assistant_job_not_found(client, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    assert client.post("/api/jobs/999/analyze").status_code == 404
    assert (
        client.post("/api/jobs/999/assistant", json={"question": "x"}).status_code == 404
    )


def test_llm_enabled_flag_in_health(client, monkeypatch, tmp_path):
    _configure_llm(monkeypatch, tmp_path)
    body = client.get("/health").json()
    assert body["llm_enabled"] is True


def test_parse_json_object_tolerates_fences_and_noise():
    obj = llm_mod.parse_json_object('Aqui está:\n```json\n{"a": 1}\n```\nEspero ter ajudado.')
    assert obj == {"a": 1}


def test_parse_json_object_rejects_garbage():
    with pytest.raises(llm_mod.LLMRequestError):
        llm_mod.parse_json_object("sem json aqui")
