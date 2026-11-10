"""sqlmap — deteção SQLi com defaults seguros (URL allowlisted)."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding, artifact_name
from app.core.targets import target_url
from app.models import Severity


class SqlmapAdapter(BaseAdapter):
    """sqlmap com --batch --level=1 --risk=1; sem shells/OS takeover."""

    name = "sqlmap"
    binary = "sqlmap"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        url = target_url(target)
        out_file = job_dir / artifact_name(self.name, target, "txt")
        if "?" not in url:
            reason = (
                "sqlmap omitido: a URL não tem parâmetros GET para testar. "
                "Use uma URL com query string (ex.: ?id=1) ou faça crawl/inspeção manual."
            )
            out_file.write_text(reason + "\n")
            return AdapterResult(
                tool=self.name,
                mocked=False,
                command=["sqlmap", "--skipped-no-params"],
                stdout=reason,
                findings=[
                    RawFinding(
                        title="sqlmap omitido (sem parâmetros GET)",
                        severity=Severity.info,
                        target=target,
                        tool=self.name,
                        category="tool_error",
                        description=reason,
                        evidence=reason,
                    )
                ],
                artifact_path=str(out_file),
            )
        out_dir = job_dir / artifact_name(self.name, target, "out")
        out_dir.mkdir(parents=True, exist_ok=True)
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
        path = job_dir / artifact_name(self.name, target, "txt")
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
        text = content or ""
        low = text.lower()
        negative = (
            "no parameter(s) found" in low
            or "no dynamic nor injectable" in low
            or "not injectable" in low
        )
        positive = re.search(
            r"parameter\s+['\"][^'\"]+['\"]\s+(?:is|appears to be).{0,120}injectable"
            r"|sqlmap identified the following injection point"
            r"|is vulnerable to sql injection",
            low,
        )
        if positive and not negative:
            evidence_lines = [
                line.strip()
                for line in text.splitlines()
                if "injectable" in line.lower() or "injection point" in line.lower()
            ]
            return [
                RawFinding(
                    title="Possível injeção SQL (sqlmap)",
                    severity=Severity.high,
                    target=target,
                    tool=self.name,
                    category="vuln",
                    description=(
                        "sqlmap reportou parâmetro potencialmente injectável "
                        "(level/risk limitados; sem OS shell). Validar manualmente."
                    ),
                    evidence=("\n".join(evidence_lines[:6]) or text[:2000])[:2000],
                    remediation="Validar input, prepared statements e WAF no alvo.",
                    cwe="CWE-89",
                )
            ]
        return [
            RawFinding(
                title="sqlmap concluído (sem injeção confirmada)",
                severity=Severity.info,
                target=target,
                tool=self.name,
                category="vuln",
                description=(
                    "Scan sqlmap seguro concluído sem confirmação de SQLi "
                    "(403/WAF ou ausência de parâmetros podem limitar o teste)."
                ),
                evidence=text[:1500],
            )
        ]
