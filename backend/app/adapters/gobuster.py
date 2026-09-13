from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class GobusterAdapter(BaseAdapter):
    name = "gobuster"
    binary = "gobuster"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        url = target if target.startswith("http") else f"http://{target}"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        out_file = job_dir / "gobuster.txt"
        threads = "10" if intensity == "safe" else "30"
        cmd = [
            "gobuster",
            "dir",
            "-u",
            url,
            "-w",
            wordlist,
            "-t",
            threads,
            "-o",
            str(out_file),
            "-q",
        ]
        stdout, stderr, code = self._exec(cmd, timeout=300)
        content = out_file.read_text() if out_file.exists() else stdout
        findings = self._parse(content, target)
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
        content = (
            f"http://{target}/admin (Status: 301)\n"
            f"http://{target}/login (Status: 200)\n"
            f"http://{target}/.git (Status: 403)\n"
        )
        path = job_dir / "gobuster.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["gobuster", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or "Status:" not in line:
                continue
            sev = Severity.medium if any(x in line.lower() for x in [".git", "backup", "admin"]) else Severity.info
            findings.append(
                RawFinding(
                    title=f"Caminho descoberto: {line.split()[0]}",
                    severity=sev,
                    target=target,
                    tool=self.name,
                    category="web-discovery",
                    description="Diretório/endpoint encontrado por força bruta de paths.",
                    evidence=line,
                    remediation="Remover paths sensíveis públicos ou proteger com autenticação.",
                )
            )
        return findings
