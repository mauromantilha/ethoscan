"""Hydra — brute-force limitado contra host allowlisted (intensity standard+)."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity

# Wordlists curtas embutidas (lab) — nunca rockyou completo.
_USERS = ("admin", "root", "test", "user", "guest")
_PASSWORDS = ("admin", "password", "123456", "test", "lab", "toor", "root")


class HydraAdapter(BaseAdapter):
    """Hydra SSH limitado; recusa intensity=safe."""

    name = "hydra"
    binary = "hydra"

    def available(self) -> bool:
        for name in ("hydra", "thc-hydra"):
            if shutil.which(name):
                self.binary = name
                return True
        return False

    def _bin(self) -> str:
        return shutil.which("hydra") or shutil.which("thc-hydra") or "hydra"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        if intensity == "safe":
            return self._skipped(
                target,
                job_dir,
                "Hydra requer intensidade standard+ (RoE explícito).",
            )

        host = target.split("://")[-1].split("/")[0].split(":")[0]
        users = job_dir / "hydra_users.txt"
        pwds = job_dir / "hydra_pass.txt"
        users.write_text("\n".join(_USERS) + "\n")
        pwds.write_text("\n".join(_PASSWORDS) + "\n")
        out_file = job_dir / "hydra.txt"

        # -t 4 threads, -f stop on first, -W 1 wait, service ssh only
        timeout = 120 if intensity == "standard" else 180
        cmd = [
            self._bin(),
            "-L",
            str(users),
            "-P",
            str(pwds),
            "-t",
            "4",
            "-f",
            "-W",
            "1",
            "-o",
            str(out_file),
            host,
            "ssh",
        ]
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        content = out_file.read_text() if out_file.exists() else (stdout or stderr or "")
        if not out_file.exists():
            out_file.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=cmd,
            stdout=content,
            stderr=stderr,
            findings=self._parse(content, target),
            artifact_path=str(out_file),
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        if intensity == "safe":
            return self._skipped(
                target,
                job_dir,
                "Hydra requer intensidade standard+ (RoE explícito).",
            )
        content = f"[DATA] attacking ssh://{target}\n[ERROR] mock — no valid password found\n"
        path = job_dir / "hydra.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["hydra", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _skipped(self, target: str, job_dir: Path, reason: str) -> AdapterResult:
        path = job_dir / "hydra.txt"
        path.write_text(reason + "\n")
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=["hydra", "--skipped"],
            stdout=reason,
            findings=[
                RawFinding(
                    title="Hydra omitido (intensidade insuficiente)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="cred",
                    description=reason,
                    evidence=reason,
                )
            ],
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in (content or "").splitlines():
            low = line.lower()
            if "login:" in low and "password:" in low and "host:" in low:
                findings.append(
                    RawFinding(
                        title="Credencial encontrada (Hydra)",
                        severity=Severity.high,
                        target=target,
                        tool=self.name,
                        category="cred",
                        description="Hydra reportou login válido (wordlist curta, lab).",
                        evidence=line.strip()[:500],
                        remediation="Rodar passwords fortes; desativar auth fraca.",
                    )
                )
        if not findings:
            findings.append(
                RawFinding(
                    title="Hydra concluído (sem credenciais)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="cred",
                    description="Brute-force SSH limitado sem sucesso na wordlist curta.",
                    evidence=(content or "")[:1500],
                )
            )
        return findings
