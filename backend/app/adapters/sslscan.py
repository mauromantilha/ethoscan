from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding, artifact_name
from app.core.targets import target_host
from app.models import Severity


class SslscanAdapter(BaseAdapter):
    name = "sslscan"
    binary = "sslscan"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target_host(target)
        out_file = job_dir / artifact_name(self.name, target, "txt")
        timeout = 45 if intensity == "safe" else (75 if intensity == "standard" else 120)
        cmd = ["sslscan", "--no-colour", "--no-heartbleed", host]
        if intensity == "safe":
            cmd = ["sslscan", "--no-colour", "--no-heartbleed", "--no-compression", host]
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        out_file.write_text(stdout or (f"# stderr:\n{stderr}" if stderr else ""))
        lower = stdout.lower()
        has_tls_data = any(
            marker in lower
            for marker in (
                "connected to",
                "subject:",
                "issuer:",
                "tlsv1.2   enabled",
                "tlsv1.3   enabled",
            )
        )
        if "unable to parse certificate" in lower or not has_tls_data:
            # Só a versão/handshake falhado não é um resultado de TLS: não inventar
            # "varredura concluída" quando não houve ligação/certificado utilizável.
            return AdapterResult(
                tool=self.name,
                mocked=False,
                command=cmd,
                stdout=stdout,
                stderr=stderr,
                error=(
                    "sslscan não obteve ligação TLS/certificado utilizável "
                    f"(alvo inacessível, WAF ou handshake bloqueado): "
                    f"{(stderr or 'sem stderr').strip()[:500]}"
                ),
                findings=[],
                artifact_path=str(out_file),
            )
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
        path = job_dir / artifact_name(self.name, target, "txt")
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
