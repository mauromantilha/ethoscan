from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class NiktoAdapter(BaseAdapter):
    name = "nikto"
    binary = "nikto"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target if "://" in target else f"http://{target}"
        out_file = job_dir / "nikto.txt"
        maxtime = "120s" if intensity == "safe" else ("300s" if intensity == "standard" else "600s")
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
        ]
        stdout, stderr, _ = self._exec(cmd, timeout=700)
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
        path = job_dir / "nikto.txt"
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
            if not line.startswith("+") or "Target Host" in line or line.startswith("+ Server"):
                continue
            text = line.lstrip("+ ").strip()
            if len(text) < 8:
                continue
            sev = Severity.low
            low = text.lower()
            if any(k in low for k in ("xss", "sql", "rce", "injection", "critical")):
                sev = Severity.medium
            findings.append(
                RawFinding(
                    title=text[:120],
                    severity=sev,
                    target=target,
                    tool=self.name,
                    category="vuln",
                    description="Achado Nikto (scan web passivo/ativo limitado).",
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
