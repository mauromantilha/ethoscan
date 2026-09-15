from __future__ import annotations

import json
import re
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class NmapAdapter(BaseAdapter):
    name = "nmap"
    binary = "nmap"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        out_file = job_dir / "nmap.json"
        if intensity == "safe":
            args = ["-Pn", "-sV", "--top-ports", "100", "-T3"]
        elif intensity == "standard":
            args = ["-Pn", "-sV", "-sC", "--top-ports", "1000", "-T4"]
        else:
            args = ["-Pn", "-sV", "-sC", "-p-", "-T4"]

        cmd = ["nmap", *args, "-oX", str(out_file.with_suffix(".xml")), target]
        # Prefer grepable-ish summary via normal output as well
        cmd_text = ["nmap", *args, target]
        stdout, stderr, _ = self._exec(cmd_text, timeout=300)
        findings = self._parse_text(stdout, target)
        (job_dir / "nmap.txt").write_text(stdout)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=cmd_text,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            artifact_path=str(job_dir / "nmap.txt"),
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        stdout = (
            f"Nmap mock scan report for {target}\n"
            "PORT     STATE SERVICE VERSION\n"
            "22/tcp   open  ssh     OpenSSH 8.9\n"
            "80/tcp   open  http    nginx 1.24\n"
            "443/tcp  open  https   nginx 1.24\n"
        )
        path = job_dir / "nmap.txt"
        path.write_text(stdout)
        findings = [
            RawFinding(
                title="Serviço SSH exposto",
                severity=Severity.info,
                target=target,
                tool=self.name,
                category="network",
                description="Porta 22/tcp aberta (mock).",
                evidence="22/tcp open ssh OpenSSH 8.9",
                remediation="Restringir acesso SSH por firewall/VPN e usar chaves.",
            ),
            RawFinding(
                title="Serviço HTTP/HTTPS exposto",
                severity=Severity.info,
                target=target,
                tool=self.name,
                category="network",
                description="Portas 80/443 abertas (mock).",
                evidence="80/tcp open http; 443/tcp open https",
            ),
        ]
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["nmap", "--mock", target],
            stdout=stdout,
            findings=findings,
            artifact_path=str(path),
        )

    def _parse_text(self, stdout: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in stdout.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
            if not m:
                continue
            port, proto, service, version = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
            findings.append(
                RawFinding(
                    title=f"Porta {port}/{proto} aberta ({service})",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="network",
                    description=f"Serviço detectado: {service} {version}".strip(),
                    evidence=line.strip(),
                )
            )
        return findings
