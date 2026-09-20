from __future__ import annotations

import json
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


_SEVERITY_MAP = {
    "info": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
    "unknown": Severity.info,
}


class NucleiAdapter(BaseAdapter):
    name = "nuclei"
    binary = "nuclei"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        out_file = job_dir / "nuclei.jsonl"
        url = target if target.startswith("http") else f"https://{target}"
        severity = "info,low,medium" if intensity == "safe" else "info,low,medium,high,critical"
        cmd = [
            "nuclei",
            "-u",
            url,
            "-severity",
            severity,
            "-jsonl",
            "-o",
            str(out_file),
            "-silent",
            "-no-interactsh",
        ]
        if intensity == "safe":
            # Rate/concurrency limitados; exclui templates pesados; sem Interactsh.
            cmd.extend(
                [
                    "-rate-limit",
                    "25",
                    "-c",
                    "15",
                    "-timeout",
                    "5",
                    "-etags",
                    "dos,fuzz,intrusive",
                ]
            )
            timeout = 300
        elif intensity == "standard":
            cmd.extend(["-rate-limit", "50", "-c", "25", "-timeout", "8", "-etags", "dos"])
            timeout = 420
        else:
            timeout = 600
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        content = out_file.read_text() if out_file.exists() else stdout
        findings = self._parse_jsonl(content, target)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=cmd,
            stdout=content,
            stderr=stderr,
            findings=findings,
            artifact_path=str(out_file) if out_file.exists() else None,
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        rows = [
            {
                "info": {
                    "name": "Missing security headers",
                    "severity": "low",
                    "description": "Headers de segurança ausentes (mock).",
                    "classification": {"cwe-id": ["CWE-693"]},
                },
                "matched-at": f"https://{target}",
            },
            {
                "info": {
                    "name": "TLS certificate issues",
                    "severity": "medium",
                    "description": "Possível problema de certificado (mock).",
                },
                "matched-at": f"https://{target}",
            },
        ]
        path = job_dir / "nuclei.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows))
        findings = self._parse_jsonl(path.read_text(), target)
        for f in findings:
            f.tool = self.name
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["nuclei", "--mock", target],
            stdout=path.read_text(),
            findings=findings,
            artifact_path=str(path),
        )

    def _parse_jsonl(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info") or {}
            sev = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.info)
            cwe_list = (info.get("classification") or {}).get("cwe-id") or []
            findings.append(
                RawFinding(
                    title=str(info.get("name") or "Nuclei finding"),
                    severity=sev,
                    target=str(row.get("matched-at") or target),
                    tool=self.name,
                    category="vuln",
                    description=str(info.get("description") or ""),
                    evidence=line[:2000],
                    cwe=cwe_list[0] if cwe_list else None,
                    remediation="Revisar template Nuclei e aplicar correção recomendada.",
                )
            )
        return findings
