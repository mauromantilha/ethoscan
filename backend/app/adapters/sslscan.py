from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class SslscanAdapter(BaseAdapter):
    name = "sslscan"
    binary = "sslscan"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        out_file = job_dir / "sslscan.txt"
        cmd = ["sslscan", "--no-colour", host]
        stdout, stderr, _ = self._exec(cmd, timeout=120)
        out_file.write_text(stdout)
        findings = self._parse(stdout, target)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=cmd,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            artifact_path=str(out_file),
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        stdout = (
            f"Version: mock\n"
            f"Connected to {target}\n"
            "Preferred TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256\n"
            "SSL 2  disabled\n"
            "SSL 3  disabled\n"
            "TLS 1.0 enabled\n"
        )
        path = job_dir / "sslscan.txt"
        path.write_text(stdout)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["sslscan", "--mock", target],
            stdout=stdout,
            findings=self._parse(stdout, target),
            artifact_path=str(path),
        )

    def _parse(self, stdout: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        lower = stdout.lower()
        if "tls 1.0 enabled" in lower or "tls1.0" in lower.replace(" ", ""):
            findings.append(
                RawFinding(
                    title="TLS 1.0 habilitado",
                    severity=Severity.medium,
                    target=target,
                    tool=self.name,
                    category="tls",
                    description="Protocolo TLS legado ainda habilitado.",
                    evidence="TLS 1.0 enabled",
                    cwe="CWE-326",
                    remediation="Desabilitar TLS 1.0/1.1; manter apenas TLS 1.2+.",
                )
            )
        if not findings:
            findings.append(
                RawFinding(
                    title="Varredura TLS concluída",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="tls",
                    description="Resultado sslscan sem finding crítico automático.",
                    evidence=stdout[:1500],
                )
            )
        return findings
