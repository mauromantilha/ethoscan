"""Gating de tools de infra (SSH/SMB/AD) para alvos atrás de CDN.

O F0 identifica alvos que resolvem apenas para IPs de CDN (Cloudflare) e a
execução pula hydra/netexec/bloodhound para esses alvos — o skip aparece na
cobertura como achado info, sem desperdiçar tempo de job contra a edge.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from app import db as dbmod
from app.adapters import all_adapters
from app.adapters.base import AdapterResult, BaseAdapter
from app.core.orchestrator import CDN_INAPPLICABLE_TOOLS, run_pipeline
from app.models import Finding, Job, JobStatus

CF_EDGE_IPS = ["104.18.4.243", "104.18.5.243"]


class _ExplodingAdapter(BaseAdapter):
    """Falha o teste se for executado (o gating deve pular a execução)."""

    binary = "ethoscan-stub"

    def __init__(self, name: str) -> None:
        self.name = name

    def available(self) -> bool:
        return True

    def run(self, target: str, _job_dir: Any, _intensity: str = "safe") -> AdapterResult:
        raise AssertionError(f"adapter {self.name} não deveria rodar contra alvo CDN")

    def _run_real(self, target: str, job_dir: Any, intensity: str) -> AdapterResult:
        raise NotImplementedError

    def _run_mock(self, target: str, job_dir: Any, intensity: str) -> AdapterResult:
        raise NotImplementedError


def _adapters_with(**replacements: BaseAdapter):
    def factory():
        return [replacements.get(adapter.name, adapter) for adapter in all_adapters()]

    return factory


def _create_cdn_engagement(client) -> int:
    response = client.post(
        "/api/engagements",
        json={
            "name": "Lab CDN gating",
            "scope_targets": ["www.corretorsync.com"],
            "intensity": "standard",
            "roe_acknowledged": True,
            "selected_tools": ["hydra", "netexec", "bloodhound-python", "whatweb"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _enqueue_and_run(client, engagement_id: int) -> int:
    with patch("app.api.routes.ping_redis", return_value=True), patch(
        "app.api.routes.enqueue_job"
    ):
        response = client.post(f"/api/engagements/{engagement_id}/jobs")
    assert response.status_code == 200, response.text
    job_id = response.json()["job"]["id"]
    run_pipeline(dbmod.SessionLocal(), job_id)
    return job_id


def test_cdn_gating_skips_infra_tools(client):
    engagement_id = _create_cdn_engagement(client)

    with (
        patch(
            "app.core.orchestrator.target_resolution",
            return_value=(CF_EDGE_IPS, None),
        ),
        # descoberta de origem: mockada para não tocar a rede no teste
        patch(
            "app.core.orchestrator.discover_origin_ip",
            return_value={"cdn": "cloudflare", "origin_candidates": []},
        ),
        patch(
            "app.core.orchestrator.all_adapters",
            _adapters_with(
                hydra=_ExplodingAdapter("hydra"),
                netexec=_ExplodingAdapter("netexec"),
                bloodhound_python=_ExplodingAdapter("bloodhound-python"),
            ),
        ),
    ):
        job_id = _enqueue_and_run(client, engagement_id)

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.status == JobStatus.completed

        coverage = (job.tool_runs or {}).get("_coverage") or {}
        assert "www.corretorsync.com" in (coverage.get("cdn_targets") or [])

        findings = (
            db.query(Finding)
            .filter(Finding.job_id == job_id, Finding.category == "tool_error")
            .all()
        )
        skipped = {f.tool for f in findings if "omitida" in (f.title or "")}
        assert {"hydra", "netexec", "bloodhound-python"} <= skipped
        for f in findings:
            if "omitida" in (f.title or ""):
                assert "CDN" in f.title
                assert "origin" in f.remediation
    finally:
        db.close()


def test_cdn_gating_maps_only_infra_tools():
    assert set(CDN_INAPPLICABLE_TOOLS) == {"hydra", "netexec", "bloodhound-python"}


def test_non_cdn_target_still_runs_infra_tools(client):
    """Alvo que NÃO resolve para CDN: tools de infra correm normalmente."""
    response = client.post(
        "/api/engagements",
        json={
            "name": "Lab direto",
            "scope_targets": ["203.0.113.10"],
            "intensity": "standard",
            "roe_acknowledged": True,
            "selected_tools": ["hydra", "whatweb"],
        },
    )
    assert response.status_code == 200

    ran: list[str] = []

    class _SpyAdapter(_ExplodingAdapter):
        def run(self, target: str, _job_dir: Any, _intensity: str = "safe") -> AdapterResult:
            ran.append(self.name)
            return AdapterResult(
                tool=self.name, mocked=False, command=[self.name], exit_code=0
            )

    with patch(
        "app.core.orchestrator.all_adapters", _adapters_with(hydra=_SpyAdapter("hydra"))
    ):
        job_id = _enqueue_and_run(client, response.json()["id"])

    db = dbmod.SessionLocal()
    try:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.status == JobStatus.completed
        assert "hydra" in ran  # IP direto: sem gating
        assert not (job.tool_runs or {}).get("_coverage", {}).get("cdn_targets")
    finally:
        db.close()
