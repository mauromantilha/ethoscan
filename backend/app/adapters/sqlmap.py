"""sqlmap — deteção SQLi com defaults seguros (URL allowlisted)."""

from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class SqlmapAdapter(BaseAdapter):
    """sqlmap com --batch --level=1 --risk=1; sem shells/OS takeover."""

    name = "sqlmap"
    binary = "sqlmap"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        url = target if "://" in target else f"http://{target}"
        out_dir = job_dir / "sqlmap"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = job_dir / "sqlmap.txt"
        if intensity == "safe":
            level, risk, timeout = "1", "1", 120
        elif intensity == "standard":
            level, risk, timeout = "2", "1", 240
        else:
            level, risk, timeout = "2", "2", 360

        cmd = [
            "sqlmap",
            "-u",
            url,
            "--batch",
            "--smart",
            f"--level={level}",
            f"--risk={risk}",
            "--threads=1",
            "--technique=BEUST",
            "--disable-coloring",
            "--output-dir",
            str(out_dir),
            # Bloqueios éticos explícitos
            "--answers=quit=N",
        ]
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        content = stdout or stderr or ""
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
        content = (
            f"[*] testing URL: {target}\n"
            "[INFO] heuristic test shows that GET parameter 'id' might be injectable\n"
            "[WARNING] reflective value(s) found\n"
            "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable\n"
        )
        path = job_dir / "sqlmap.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["sqlmap", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        low = (content or "").lower()
        if "injectable" in low:
            findings.append(
                RawFinding(
                    title="Possível injeção SQL (sqlmap)",
                    severity=Severity.high,
                    target=target,
                    tool=self.name,
                    category="vuln",
                    description=(
                        "sqlmap reportou parâmetro potencialmente injectável "
                        "(level/risk limitados; sem OS shell)."
                    ),
                    evidence=(content or "")[:2000],
                    remediation="Validar input, prepared statements e WAF no alvo.",
                    cwe="CWE-89",
                )
            )
        else:
            findings.append(
                RawFinding(
                    title="sqlmap concluído (sem injeção confirmada)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="vuln",
                    description="Scan sqlmap seguro concluído sem confirmação de SQLi.",
                    evidence=(content or "")[:1500],
                )
            )
        return findings
