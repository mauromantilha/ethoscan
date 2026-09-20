from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class MasscanAdapter(BaseAdapter):
    """Masscan com rate baixo e portas top — defaults seguros para lab."""

    name = "masscan"
    binary = "masscan"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        out_file = job_dir / "masscan.txt"
        if intensity == "safe":
            ports, rate, timeout = "22,80,443,8080,8443", "200", 60
        elif intensity == "standard":
            ports, rate, timeout = "1-1024,8080,8443,3306,5432", "500", 120
        else:
            ports, rate, timeout = "1-2048,8000-9000", "1000", 180

        cmd = [
            "masscan",
            host,
            "-p",
            ports,
            "--rate",
            rate,
            "-oL",
            str(out_file),
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
            f"#masscan mock\n"
            f"open tcp 80 {target.split('://')[-1].split('/')[0]} 0\n"
            f"open tcp 443 {target.split('://')[-1].split('/')[0]} 0\n"
        )
        path = job_dir / "masscan.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["masscan", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # open tcp PORT IP ...
            m = re.match(r"open\s+(tcp|udp)\s+(\d+)\s+(\S+)", line, re.I)
            if not m:
                continue
            proto, port, ip = m.group(1), m.group(2), m.group(3)
            findings.append(
                RawFinding(
                    title=f"Porta {port}/{proto} aberta (masscan)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="network",
                    description=f"Masscan reportou {port}/{proto} aberta em {ip}.",
                    evidence=line,
                )
            )
        return findings
