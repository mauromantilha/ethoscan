"""NetExec / CrackMapExec — enum segura SMB (sem spray nem exec)."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity

_BINARIES = ("nxc", "netexec", "crackmapexec")


class NetExecAdapter(BaseAdapter):
    """Enum SMB básica; deteta nxc / netexec / crackmapexec."""

    name = "netexec"
    binary = "nxc"

    def available(self) -> bool:
        for name in _BINARIES:
            if shutil.which(name):
                self.binary = name
                return True
        return False

    def _bin(self) -> str:
        for name in _BINARIES:
            path = shutil.which(name)
            if path:
                return path
        return "nxc"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        out_file = job_dir / "netexec.txt"
        timeout = 90 if intensity == "safe" else (150 if intensity == "standard" else 240)
        # Apenas enum — sem -u/-p spray, sem -x/--exec-command
        cmd = [self._bin(), "smb", host]
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
            f"SMB {host} 445 [*] Windows 10 / Server 2019 (name:LAB) (domain:LAB) "
            f"(signing:True) (SMBv1:False)\n"
        )
        path = job_dir / "netexec.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["nxc", "smb", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = [
            RawFinding(
                title="NetExec SMB enum",
                severity=Severity.info,
                target=target,
                tool=self.name,
                category="ad",
                description="Enum SMB (NetExec/CME) sem autenticação agressiva nem exec remoto.",
                evidence=(content or "")[:2000],
            )
        ]
        for line in (content or "").splitlines():
            low = line.lower()
            if "signing:false" in low or "signing: false" in low:
                findings.append(
                    RawFinding(
                        title="SMB signing desativado",
                        severity=Severity.medium,
                        target=target,
                        tool=self.name,
                        category="ad",
                        description="Host reporta SMB signing desativado.",
                        evidence=line.strip()[:500],
                        remediation="Ativar SMB signing / require security signatures.",
                    )
                )
            if "smbv1:true" in low or "smbv1: true" in low:
                findings.append(
                    RawFinding(
                        title="SMBv1 ativo",
                        severity=Severity.medium,
                        target=target,
                        tool=self.name,
                        category="ad",
                        description="SMBv1 detetado — protocolo legado.",
                        evidence=line.strip()[:500],
                        remediation="Desativar SMBv1.",
                    )
                )
        return findings[:20]
