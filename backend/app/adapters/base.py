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


class BaseAdapter(ABC):
    name: str = "base"
    binary: str = "true"

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run(self, target: str, job_dir: Path, intensity: str = "safe") -> AdapterResult:
        settings = get_settings()
        if self.available():
            result = self._run_real(target, job_dir, intensity)
        elif settings.ethoscan_allow_mock:
            result = self._run_mock(target, job_dir, intensity)
        else:
            raise RuntimeError(
                f"Ferramenta '{self.binary}' não encontrada e ETHOSCAN_ALLOW_MOCK=false"
            )
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
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
