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
    mocked: bool = False

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
    # None = não se aplica (mock) ou desconhecido; preenchido por BaseAdapter.run
    exit_code: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """False quando a tool falhou (exit != 0, timeout ou exceção)."""
        return self.error is None and self.exit_code in (None, 0)


class BaseAdapter(ABC):
    name: str = "base"
    binary: str = "true"
    # último exit code observado em _exec (usado quando o adapter não o propaga)
    _last_exit_code: int | None = None

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run(self, target: str, job_dir: Path, intensity: str = "safe") -> AdapterResult:
        settings = get_settings()
        self._last_exit_code = None
        try:
            if self.available():
                result = self._run_real(target, job_dir, intensity)
            elif settings.ethoscan_allow_mock:
                result = self._run_mock(target, job_dir, intensity)
            else:
                result = AdapterResult(
                    tool=self.name,
                    mocked=False,
                    command=[self.binary],
                    error=(
                        f"ferramenta '{self.binary}' não encontrada e ETHOSCAN_ALLOW_MOCK=false"
                    ),
                )
        except subprocess.TimeoutExpired as exc:
            # timeout não derruba o pipeline: vira resultado falho isolado
            result = AdapterResult(
                tool=self.name,
                mocked=False,
                command=[self.binary],
                error=f"timeout após {exc.timeout}s ao executar {self.binary}",
            )
        except OSError as exc:
            result = AdapterResult(
                tool=self.name,
                mocked=False,
                command=[self.binary],
                error=f"{type(exc).__name__}: {exc}",
            )

        if result.exit_code is None and not result.mocked:
            # adapters que ignoram o 3º valor de _exec herdam o exit code real
            result.exit_code = self._last_exit_code
        for finding in result.findings:
            finding.mocked = result.mocked
        return result

    @abstractmethod
    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        raise NotImplementedError

    @abstractmethod
    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        raise NotImplementedError

    def _exec(self, command: list[str], timeout: int = 120) -> tuple[str, str, int]:
        """Executa e devolve (stdout, stderr, exit_code) — sem levantar em exit != 0."""
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        self._last_exit_code = proc.returncode
        return proc.stdout or "", proc.stderr or "", proc.returncode

