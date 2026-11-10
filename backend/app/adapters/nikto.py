from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding, artifact_name
from app.core.targets import target_url
from app.models import Severity


class NiktoAdapter(BaseAdapter):
    name = "nikto"
    binary = "nikto"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target_url(target)
        out_file = job_dir / artifact_name(self.name, target, "txt")
        if intensity == "safe":
            maxtime, timeout = "60s", 90
        elif intensity == "standard":
            maxtime, timeout = "180s", 240
        else:
            maxtime, timeout = "600s", 700
        cmd = [
            "nikto",
            "-h",
            host,
            "-maxtime",
            maxtime,
            "-Format",
            "txt",
            "-output",
            str(out_file),
            "-nointeractive",
        ]
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        content = out_file.read_text() if out_file.exists() else stdout
        if not out_file.exists() and content:
            out_file.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=cmd,
            stdout=content,
            stderr=stderr,
            findings=self._parse(content, target),
            artifact_path=str(out_file) if out_file.exists() else None,
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        content = (
            f"+ Target Host: {target}\n"
            "+ Server: nginx/1.24\n"
            "+ The anti-clickjacking X-Frame-Options header is not present.\n"
            "+ The X-Content-Type-Options header is not set.\n"
        )
        path = job_dir / artifact_name(self.name, target, "txt")
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["nikto", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            text = line.lstrip("+ ").strip()
            low = text.lower()
            # Metadados do Nikto não são achados.
            if any(
                marker in low
                for marker in (
                    "target host",
                    "target port",
                    "target ip",
                    "target hostname",
                    "start time",
                    "end time",
                    "no web server found",
                    "0 host(s) tested",
                    "nikto v",
                )
            ):
                continue
            if low.startswith("server:") or len(text) < 8:
                continue
            # Título = mensagem depois do primeiro ": " (ex.: "GET /: ...").
            title_text = text.split(": ", 1)[1] if ": " in text else text
            title_text = title_text.strip()
            if len(title_text) < 8:
                continue
            if any(k in low for k in ("sql injection", "remote code", "rce", "command execution")):
                sev = Severity.high
            elif any(
                k in low
                for k in ("xss", "cross site scripting", "vulnerable", "injection", "critical")
            ):
                sev = Severity.medium
            elif "missing" in low and (
                "header" in low
                or "strict-transport-security" in low
                or "x-content-type-options" in low
                or "x-frame-options" in low
                or "content-security-policy" in low
            ):
                sev = Severity.low
            else:
                sev = Severity.info
            if sev == Severity.info:
                description = "Observação Nikto (não é vulnerabilidade por si; validar contexto)."
                category = "recon"
            elif "xss" in low or "cross site scripting" in low or "vulnerable" in low:
                description = (
                    "Nikto reportou assinatura de XSS/vulnerabilidade; validar manualmente "
                    "(pode ser falso positivo, sobretudo atrás de WAF/Cloudflare)."
                )
                category = "vuln"
            elif "missing" in low and "header" in low:
                description = "Header de segurança ausente (rever configuração web)."
                category = "vuln"
            else:
                description = "Achado Nikto (scan web passivo/ativo limitado)."
                category = "vuln"
            findings.append(
                RawFinding(
                    title=title_text[:160],
                    severity=sev,
                    target=target,
                    tool=self.name,
                    category=category,
                    description=description,
                    evidence=text[:2000],
                    remediation="Rever configuração web e headers de segurança.",
                )
            )
        # Dedup by title
        seen: set[str] = set()
        unique: list[RawFinding] = []
        for f in findings:
            if f.title in seen:
                continue
            seen.add(f.title)
            unique.append(f)
        return unique[:40]
