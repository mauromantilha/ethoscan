"""Testes da API de conexão para automação (n8n).

Cobrem o contrato autodescritivo, o fluxo scan → status, validações, chave de serviço
e o webhook de conclusão (sem depender de rede/Redis reais).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app import db as dbmod
from app.core import security
from app.core.orchestrator import _notify_callback, run_pipeline
from app.models import AuditEvent, Engagement, Job, JobStatus

SCAN = "/api/integrations/n8n/scan"
STATUS = "/api/integrations/n8n/jobs/{job_id}"
MANIFEST = "/api/integrations/n8n/manifest"


def _run_scan(client, **overrides) -> dict:
    body = {
        "name": "scan-n8n",
        "targets": ["scanme.nmap.org"],
        "intensity": "safe",
        "roe_acknowledged": True,
        "selected_tools": ["nmap"],
    }
    body.update(overrides)
    with patch("app.api.integration_routes.ping_redis", return_value=True), patch(
        "app.api.integration_routes.enqueue_job"
    ) as enq:
        response = client.post(SCAN, json=body)
    return {"response": response, "enqueue_mock": enq}


def test_manifest_describes_the_contract(client):
    response = client.get(MANIFEST)
    assert response.status_code == 200
    data = response.json()
    assert data["auth_header"] == "X-API-Key"
    assert data["endpoints"]["scan"].startswith("POST /api/integrations/n8n/scan")
    assert set(data["terminal_statuses"]) == {"completed", "failed", "cancelled"}
    assert "roe_acknowledged" in data["example_scan_body"]
    assert data["example_callback_payload"]["status"] == "completed"


def test_integration_router_requires_api_key_dependency():
    """A API de integração é protegida pela dependência de auth (master key/serviço/sessão)."""
    from app.api.integration_routes import router as n8n_router
    from app.core.security import require_api_key

    assert require_api_key in [dep.dependency for dep in n8n_router.dependencies]


def test_manifest_is_reachable_and_scan_requires_roe(client):
    assert client.get(MANIFEST).status_code == 200
    response = client.post(
        SCAN,
        json={"name": "sem roe", "targets": ["scanme.nmap.org"], "roe_acknowledged": False},
    )
    assert response.status_code == 403


def test_scan_creates_engagement_and_job_and_status_tracks_progress(client):
    result = _run_scan(client)
    response = result["response"]
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "pending"
    assert data["job_id"] > 0
    assert data["status_url"].endswith(f"/jobs/{data['job_id']}")
    assert data["report_pdf_url"].endswith(f"/jobs/{data['job_id']}/report.pdf")
    result["enqueue_mock"].assert_called_once_with(data["job_id"])

    # estado inicial: sem achados, com polling sugerido
    before = client.get(STATUS.format(job_id=data["job_id"])).json()
    assert before["status"] in {"pending", "running"}
    assert before["findings_count"] == 0
    assert before["poll_after_seconds"] > 0
    assert before["has_report"] is False

    run_pipeline(dbmod.SessionLocal(), data["job_id"])

    after = client.get(STATUS.format(job_id=data["job_id"])).json()
    assert after["status"] == "completed"
    assert after["progress"] == 100
    assert after["findings_count"] >= 1
    assert after["has_report"] is True
    assert after["has_report_pdf"] is True
    assert after["poll_after_seconds"] == 0
    assert after["selected_tools"] == ["nmap"]


def test_scan_validations(client):
    assert _run_scan(client, roe_acknowledged=False)["response"].status_code == 403
    assert _run_scan(client, targets=["nao eh alvo!"])["response"].status_code == 400
    # GAP CONHECIDO no main atual: validate_scope aceita TLD/single-label ("com", "io", "co.uk").
    # Este assert registra o comportamento de hoje — se o hardening for aplicado, ele falha e
    # serve de sinal para atualizar o teste (e o docs/remote-access.md).
    assert _run_scan(client, targets=["com"])["response"].status_code == 200
    assert _run_scan(client, targets=[])["response"].status_code == 422
    assert _run_scan(client, selected_tools=["tool-inexistente"])["response"].status_code == 400
    bad_callback = _run_scan(client, callback_url="ftp://host/hook")["response"]
    assert bad_callback.status_code == 400


def test_scan_returns_503_without_redis(client):
    with patch("app.api.integration_routes.ping_redis", return_value=False):
        response = client.post(
            SCAN,
            json={
                "name": "sem redis",
                "targets": ["scanme.nmap.org"],
                "roe_acknowledged": True,
            },
        )
    assert response.status_code == 503
    assert "Redis" in response.json()["detail"]


def test_scan_registers_callback_when_redis_accepts(client):
    with patch("app.api.integration_routes.set_callback", return_value=True) as setter:
        data = _run_scan(client, callback_url="https://n8n.local/webhook/x")["response"].json()
    assert data["callback_registered"] is True
    setter.assert_called_once()
    assert setter.call_args[0][1] == "https://n8n.local/webhook/x"


def test_scan_reports_callback_not_registered_without_redis(client):
    with patch("app.api.integration_routes.set_callback", return_value=False):
        data = _run_scan(client, callback_url="https://n8n.local/webhook/x")["response"].json()
    assert data["callback_registered"] is False


def test_unknown_job_status_is_404(client):
    assert client.get(STATUS.format(job_id=999999)).status_code == 404


def test_service_key_is_accepted(monkeypatch):
    settings = SimpleNamespace(
        ethoscan_api_key="master-key",
        ethoscan_service_keys="n8n-key, outra-key",
    )
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    assert security.credential_accepted("master-key") is True
    assert security.credential_accepted("n8n-key") is True
    assert security.credential_accepted("outra-key") is True
    assert security.credential_accepted("nao-existe") is False
    assert security.credential_accepted("") is False


def _job_for_callback(db) -> tuple[Engagement, Job]:
    engagement = Engagement(
        name="Hook", scope_targets=["scanme.nmap.org"], roe_acknowledged=True
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    job = Job(
        engagement_id=engagement.id,
        status=JobStatus.completed,
        phase="F6",
        progress=100,
        tool_runs={},
        selected_tools=["nmap"],
        report_path="/tmp/report.html",
        report_pdf_path="/tmp/report.pdf",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return engagement, job


def test_notify_callback_posts_payload_and_audits_success(client):
    db = dbmod.SessionLocal()
    try:
        engagement, job = _job_for_callback(db)
        posted: dict = {}

        def fake_post(url, json=None, timeout=None):  # noqa: ANN001 - assinatura do httpx.post
            posted["url"] = url
            posted["payload"] = json
            return SimpleNamespace(status_code=200)

        with (
            patch(
                "app.core.orchestrator.get_callback",
                return_value="https://n8n.local/webhook/x",
            ),
            patch("app.core.orchestrator.httpx.post", side_effect=fake_post),
            patch("app.core.orchestrator.clear_callback") as cleared,
        ):
            _notify_callback(db, job, engagement, "completed", findings_count=9)

        assert posted["url"] == "https://n8n.local/webhook/x"
        assert posted["payload"]["status"] == "completed"
        assert posted["payload"]["job_id"] == job.id
        assert posted["payload"]["findings_count"] == 9
        assert posted["payload"]["report_pdf_path"] == "/tmp/report.pdf"
        cleared.assert_called_once_with(job.id)
        assert "callback_sent" in {event.action for event in db.query(AuditEvent).all()}
    finally:
        db.close()


def test_notify_callback_failure_is_recorded_and_does_not_raise(client):
    db = dbmod.SessionLocal()
    try:
        engagement, job = _job_for_callback(db)
        with (
            patch(
                "app.core.orchestrator.get_callback",
                return_value="https://n8n.local/webhook/x",
            ),
            patch("app.core.orchestrator.httpx.post", side_effect=RuntimeError("boom")),
            patch("app.core.orchestrator.clear_callback") as cleared,
        ):
            _notify_callback(db, job, engagement, "failed")  # não levanta

        assert "callback_failed" in {event.action for event in db.query(AuditEvent).all()}
        cleared.assert_called_once_with(job.id)
    finally:
        db.close()


def test_notify_callback_is_noop_without_registration(client):
    db = dbmod.SessionLocal()
    try:
        engagement, job = _job_for_callback(db)
        with (
            patch("app.core.orchestrator.get_callback", return_value=None),
            patch("app.core.orchestrator.httpx.post") as post,
        ):
            _notify_callback(db, job, engagement, "completed", findings_count=1)
        post.assert_not_called()
    finally:
        db.close()
