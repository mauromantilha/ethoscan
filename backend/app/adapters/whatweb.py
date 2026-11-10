from __future__ import annotations

from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding, artifact_name
from app.core.targets import target_url
from app.models import Severity


class WhatWebAdapter(BaseAdapter):
    name = "whatweb"
    binary = "whatweb"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        url = target_url(target)
        out_file = job_dir / artifact_name(self.name, target, "txt")
        aggression = "1" if intensity == "safe" else ("3" if intensity == "standard" else "4")
        timeout = 45 if intensity == "safe" else (90 if intensity == "standard" else 120)
        cmd = ["whatweb", "--color=never", "-a", aggression, url]
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        out_file.write_text(stdout or (f"# stderr:\n{stderr}" if stderr else ""))
        if not stdout.strip():
            # Sem output não há fingerprint: não inventar um achado "info".
            return AdapterResult(
                tool=self.name,
                mocked=False,
                command=cmd,
                stdout=stdout,
                stderr=stderr,
                error=(
                    "whatweb não devolveu output (alvo inacessível ou sem resposta): "
                    f"{(stderr or 'sem stderr').strip()[:500]}"
                ),
                findings=[],
                artifact_path=str(out_file),
            )
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
        path = job_dir / artifact_name(self.name, target, "txt")
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
