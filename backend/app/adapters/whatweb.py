from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class WhatWebAdapter(BaseAdapter):
    name = "whatweb"
    binary = "whatweb"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        url = target if target.startswith("http") else f"http://{target}"
        out_file = job_dir / "whatweb.txt"
        cmd = ["whatweb", "--color=never", "-a", "3" if intensity != "safe" else "1", url]
        stdout, stderr, _ = self._exec(cmd, timeout=120)
        out_file.write_text(stdout)
        findings = [
            RawFinding(
                title="Fingerprint de tecnologias web",
                severity=Severity.info,
                target=target,
                tool=self.name,
                category="recon",
                description="Tecnologias detectadas pelo WhatWeb.",
                evidence=stdout[:2000],
            )
        ]
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
        stdout = f"http://{target} [200 OK] Country[BR], HTML5, HTTPServer[nginx], IP[{target}], JQuery, Script, Title[Ethoscan Mock]"
        path = job_dir / "whatweb.txt"
        path.write_text(stdout)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["whatweb", "--mock", target],
            stdout=stdout,
            findings=[
                RawFinding(
                    title="Fingerprint de tecnologias web",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="recon",
                    description="Stack aparente: nginx + jQuery (mock).",
                    evidence=stdout,
                )
            ],
            artifact_path=str(path),
        )
