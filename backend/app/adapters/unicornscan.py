"""Unicornscan — enum de portas TCP limitada (estilo masscan)."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class UnicornscanAdapter(BaseAdapter):
    """Port enum conservador contra hosts allowlisted."""

    name = "unicornscan"
    binary = "unicornscan"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        out_file = job_dir / "unicornscan.txt"
        if intensity == "safe":
            ports, timeout = "22,80,443,8080,8443", 90
        elif intensity == "standard":
            ports, timeout = "1-1024,8080,8443,3306,5432", 180
        else:
            ports, timeout = "1-2048,8000-9000", 240

        # -mT TCP connect-ish; -I immediate; ports as host:p1,p2
        cmd = [
            "unicornscan",
            "-mT",
            "-I",
            f"{host}:{ports}",
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
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        content = (
            f"TCP open {host}[80]\t\tfrom 127.0.0.1  ttl 64\n"
            f"TCP open {host}[443]\t\tfrom 127.0.0.1  ttl 64\n"
        )
        path = job_dir / "unicornscan.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["unicornscan", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            # TCP open host[port] ...
            m = re.search(r"(?i)(?:TCP|UDP)\s+open\s+\S+\[(\d+)\]", line)
            if not m:
                m = re.search(r"(?i)open.*?[:=]\s*(\d+)", line)
            if not m:
                continue
            port = m.group(1)
            findings.append(
                RawFinding(
                    title=f"Porta {port} aberta (unicornscan)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="network",
                    description=f"Unicornscan reportou porta {port} aberta.",
                    evidence=line[:2000],
                )
            )
        return findings[:40]
