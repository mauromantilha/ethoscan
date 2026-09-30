from __future__ import annotations

import hashlib
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from app.config import get_settings
from app.models import Severity


@dataclass
class RawFinding:
    title: str
    severity: Severity
    target: str
    tool: str
    category: str = "general"
    description: str = ""
    evidence: str | None = None
    cve: str | None = None
    cwe: str | None = None
    remediation: str | None = None

    def fingerprint(self) -> str:
        base = f"{self.tool}|{self.target}|{self.title}|{self.cve or ''}"
        return hashlib.sha256(base.encode()).hexdigest()[:32]


@dataclass
class AdapterResult:
    tool: str
    mocked: bool
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    findings: list[RawFinding] = field(default_factory=list)
    artifact_path: str | None = None
    exit_code: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        """False quando a tool falhou (exit != 0, timeout ou exceção)."""
        return self.error is None and self.exit_code == 0


class BaseAdapter(ABC):
    name: str = "base"
    binary: str = "true"

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run(self, target: str, job_dir: Path, intensity: str = "safe") -> AdapterResult:
        settings = get_settings()
        try:
            if not settings.ethoscan_force_mock and self.available():
                return self._run_real(target, job_dir, intensity)
            if settings.ethoscan_allow_mock:
                return self._run_mock(target, job_dir, intensity)
        except subprocess.TimeoutExpired as exc:
            # Timeout não deve derrubar o pipeline: vira resultado falho isolado.
            return self._failure(f"timeout após {exc.timeout}s ao executar {self.binary}")
        except OSError as exc:
            return self._failure(f"{type(exc).__name__}: {exc}")
        return self._failure(
            f"ferramenta '{self.binary}' não encontrada e ETHOSCAN_ALLOW_MOCK=false"
        )

    @abstractmethod
    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        raise NotImplementedError

    @abstractmethod
    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        raise NotImplementedError

    def _failure(self, error: str) -> AdapterResult:
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=[self.binary],
            exit_code=-1,
            error=error,
        )

    def _exec(self, command: list[str], timeout: int = 120) -> tuple[str, str, int]:
        """Executa e devolve (stdout, stderr, exit_code) — sem levantar em exit != 0."""
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
