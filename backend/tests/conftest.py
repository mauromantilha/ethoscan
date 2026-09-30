"""Fixtures dos testes (Sprint 3).

O ambiente dos testes é um sandbox: banco SQLite temporário, artefatos temporários,
mock forçado e allowlist própria. Ele é definido ANTES de importar a app porque
``app.config``/``app.db`` são avaliados no import.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

_SANDBOX = Path(
    os.environ.get("ETHOSCAN_TEST_DIR") or tempfile.mkdtemp(prefix="ethoscan-tests-")
)
_SANDBOX.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_SANDBOX / 'tests.db'}"
os.environ["ETHOSCAN_ARTIFACTS_DIR"] = str(_SANDBOX)
os.environ["ETHOSCAN_FORCE_MOCK"] = "true"
os.environ["ETHOSCAN_ALLOW_MOCK"] = "true"
os.environ["ETHOSCAN_ALLOWLIST"] = "scanme.nmap.org,10.10.0.0/24"
os.environ["ETHOSCAN_LOG_LEVEL"] = "WARNING"
os.environ.setdefault("ETHOSCAN_API_KEY", "test-key")

from fastapi.testclient import TestClient  # noqa: E402

from app.adapters import all_adapters  # noqa: E402
from app.adapters.base import AdapterResult, BaseAdapter  # noqa: E402
from app.core.worker import get_worker  # noqa: E402
from app.main import app  # noqa: E402

API_KEY = os.environ["ETHOSCAN_API_KEY"]
HEADERS = {"X-API-Key": API_KEY}
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
MOCK_FINDINGS = 9  # nmap 2 + whatweb 1 + gobuster 3 + sslscan 1 + nuclei 2


class StubAdapter(BaseAdapter):
    """Adapter determinístico: simula falha (exit != 0), lentidão ou achados."""

    binary = "ethoscan-stub"

    def __init__(
        self,
        name: str,
        *,
        exit_code: int = 0,
        error: str | None = None,
        delay: float = 0.0,
        findings: list[Any] | None = None,
    ) -> None:
        self.name = name
        self._exit_code = exit_code
        self._error = error
        self._delay = delay
        self._findings = findings or []

    def available(self) -> bool:
        return True

    def run(self, target: str, _job_dir: Path, _intensity: str = "safe") -> AdapterResult:
        if self._delay:
            time.sleep(self._delay)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["stub", self.name, target],
            stdout=f"stub {self.name}",
            findings=list(self._findings),
            exit_code=self._exit_code,
            error=self._error,
        )

    def _run_real(self, target: str, _job_dir: Path, _intensity: str) -> AdapterResult:
        raise NotImplementedError

    def _run_mock(self, target: str, _job_dir: Path, _intensity: str) -> AdapterResult:
        raise NotImplementedError


@pytest.fixture(scope="session", autouse=True)
def _prepare_database() -> None:
    """Garante o schema antes de qualquer teste (inclusive os que não usam HTTP)."""
    from app.db import init_db

    init_db()


@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    """App real (lifespan ligado => worker rodando) contra o banco de teste."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def headers() -> dict[str, str]:
    return dict(HEADERS)


@pytest.fixture
def make_engagement(client: TestClient) -> Callable[..., int]:
    def _make(
        name: str = "Teste", target: str = "scanme.nmap.org", roe: bool = True
    ) -> int:
        response = client.post(
            "/api/engagements",
            headers=HEADERS,
            json={"name": name, "scope_targets": [target], "roe_acknowledged": roe},
        )
        assert response.status_code == 200, response.text
        return int(response.json()["id"])

    return _make


@pytest.fixture
def start_job(client: TestClient) -> Callable[..., int]:
    def _start(engagement_id: int) -> int:
        response = client.post(f"/api/engagements/{engagement_id}/jobs", headers=HEADERS)
        assert response.status_code == 200, response.text
        return int(response.json()["job"]["id"])

    return _start


@pytest.fixture
def wait_job(client: TestClient) -> Callable[..., dict[str, Any]]:
    def _wait(job_id: int, timeout: float = 30.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        job: dict[str, Any] = {}
        while time.monotonic() < deadline:
            job = client.get(f"/api/jobs/{job_id}", headers=HEADERS).json()
            if job["status"] in TERMINAL_STATUSES:
                return job
            time.sleep(0.1)
        raise AssertionError(f"timeout esperando o job {job_id}: {job}")

    return _wait


@pytest.fixture
def mock_findings() -> int:
    """Quantidade de achados que o pipeline mock produz por alvo."""
    return MOCK_FINDINGS


@pytest.fixture
def worker() -> Any:
    """Instância do worker (para parar/retomar nos testes de cancelamento)."""
    return get_worker()


@pytest.fixture
def stub_adapter() -> type[StubAdapter]:
    return StubAdapter


@pytest.fixture
def adapters_patch() -> Callable[..., AbstractContextManager[Any]]:
    """Fábrica de patches que troca adapters por stubs no orquestrador."""

    def _patch(**replacements: BaseAdapter) -> AbstractContextManager[Any]:
        def factory() -> list[BaseAdapter]:
            return [replacements.get(adapter.name, adapter) for adapter in all_adapters()]

        return patch("app.core.orchestrator.all_adapters", factory)

    return _patch
