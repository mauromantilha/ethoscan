from __future__ import annotations

import shutil
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity

# Apenas módulos auxiliary/scanner — NUNCA exploit/* nem payloads.
_SAFE_AUX_MODULE = "auxiliary/scanner/portscan/tcp"


class MetasploitAdapter(BaseAdapter):
    """Metasploit limitado a resource scripts auxiliary/scanner (recon/lab)."""

    name = "metasploit"
    binary = "msfconsole"

    def available(self) -> bool:
        return shutil.which("msfconsole") is not None

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        # Portas top limitadas — sem exploit, sem payload, sem sessions.
        ports = "22,80,443" if intensity == "safe" else "1-1024"
        rc_path = job_dir / "msf_aux_scanner.rc"
        out_path = job_dir / "msf_aux.txt"
        rc = "\n".join(
            [
                f"use {_SAFE_AUX_MODULE}",
                f"set RHOSTS {host}",
                f"set PORTS {ports}",
                "set THREADS 4",
                "run",
                "exit",
                "",
            ]
        )
        rc_path.write_text(rc)
        cmd = [
            "msfconsole",
            "-q",
            "-n",
            "-r",
            str(rc_path),
        ]
        stdout, stderr, _ = self._exec(cmd, timeout=300)
        out_path.write_text(stdout or stderr or "")
        findings = self._parse(stdout, target, host)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=["msfconsole", "-q", "-n", "-r", "msf_aux_scanner.rc"],
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            artifact_path=str(out_path),
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        stdout = (
            f"[*] {host}:80 - TCP OPEN (mock aux/scanner)\n"
            f"[*] {host}:443 - TCP OPEN (mock aux/scanner)\n"
            f"[*] Scanned 1 of 1 hosts (auxiliary/scanner/portscan/tcp)\n"
        )
        path = job_dir / "msf_aux.txt"
        path.write_text(stdout)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["msfconsole", "--mock", "auxiliary/scanner/portscan/tcp", target],
            stdout=stdout,
            findings=self._parse(stdout, target, host),
            artifact_path=str(path),
        )

    def _parse(self, stdout: str, target: str, host: str) -> list[RawFinding]:
        findings: list[RawFinding] = [
            RawFinding(
                title="Metasploit aux/scanner executado (sem exploits)",
                severity=Severity.info,
                target=target,
                tool=self.name,
                category="lab",
                description=(
                    f"Resource script limitado a {_SAFE_AUX_MODULE} contra {host}. "
                    "Exploits e payloads não são automatizados pelo Ethoscan."
                ),
                evidence=(stdout or "")[:2000],
                remediation="Usar apenas em lab/RoE; revisar portas abertas com Nmap se necessário.",
            )
        ]
        for line in (stdout or "").splitlines():
            low = line.lower()
            if "tcp open" in low or "open port" in low:
                findings.append(
                    RawFinding(
                        title=line.strip()[:160],
                        severity=Severity.info,
                        target=target,
                        tool=self.name,
                        category="network",
                        description="Porta reportada pelo módulo auxiliary/scanner.",
                        evidence=line.strip(),
                    )
                )
        return findings[:30]
