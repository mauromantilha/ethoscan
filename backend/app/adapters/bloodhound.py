"""BloodHound.py — collection AD limitada contra DC allowlisted (standard+)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


def _load_ad_creds(job_dir: Path) -> dict[str, str]:
    """Lê credenciais de lab de ad_creds.env no job ou engagement."""
    creds: dict[str, str] = {}
    for base in (job_dir, job_dir.parent, job_dir.parent / "artifacts"):
        path = base / "ad_creds.env"
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            creds[key.strip().upper()] = val.strip().strip('"').strip("'")
        break
    # Fallback env (lab local)
    for key in ("BH_USERNAME", "BH_PASSWORD", "BH_DOMAIN", "BH_DC"):
        if key in os.environ and key not in creds:
            creds[key] = os.environ[key]
    return creds


class BloodhoundAdapter(BaseAdapter):
    """bloodhound-python collection DCOnly — requer creds + intensity standard+."""

    name = "bloodhound-python"
    binary = "bloodhound-python"

    def available(self) -> bool:
        for name in ("bloodhound-python", "bloodhound"):
            if shutil.which(name):
                self.binary = name
                return True
        return False

    def _bin(self) -> str:
        return (
            shutil.which("bloodhound-python")
            or shutil.which("bloodhound")
            or "bloodhound-python"
        )

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        out_file = job_dir / "bloodhound.txt"
        if intensity == "safe":
            msg = "BloodHound.py requer intensidade standard+ (collection AD)."
            out_file.write_text(msg + "\n")
            return AdapterResult(
                tool=self.name,
                mocked=False,
                command=["bloodhound-python", "--skipped"],
                stdout=msg,
                findings=[
                    RawFinding(
                        title="BloodHound omitido (intensidade)",
                        severity=Severity.info,
                        target=target,
                        tool=self.name,
                        category="ad",
                        description=msg,
                        evidence=msg,
                    )
                ],
                artifact_path=str(out_file),
            )

        host = target.split("://")[-1].split("/")[0].split(":")[0]
        creds = _load_ad_creds(job_dir)
        user = creds.get("BH_USERNAME") or creds.get("USERNAME")
        password = creds.get("BH_PASSWORD") or creds.get("PASSWORD")
        domain = creds.get("BH_DOMAIN") or creds.get("DOMAIN")
        dc = creds.get("BH_DC") or creds.get("DC") or host

        if not (user and password and domain):
            msg = (
                "BloodHound.py omitido: coloque ad_creds.env no engagement "
                "(BH_USERNAME, BH_PASSWORD, BH_DOMAIN[, BH_DC])."
            )
            out_file.write_text(msg + "\n")
            return AdapterResult(
                tool=self.name,
                mocked=False,
                command=["bloodhound-python", "--skipped-no-creds"],
                stdout=msg,
                findings=[
                    RawFinding(
                        title="BloodHound omitido (sem credenciais)",
                        severity=Severity.info,
                        target=target,
                        tool=self.name,
                        category="ad",
                        description=msg,
                        evidence=msg,
                    )
                ],
                artifact_path=str(out_file),
            )

        # Collection limitada — DCOnly (sem Session/LoggedOn agressivo em safe paths)
        collection = "DCOnly" if intensity == "standard" else "DCOnly,Group"
        cmd = [
            self._bin(),
            "-c",
            collection,
            "-d",
            domain,
            "-u",
            user,
            "-p",
            password,
            "-ns",
            dc,
            "--zip",
            "-op",
            str(job_dir / "bh_out"),
        ]
        timeout = 300 if intensity == "standard" else 600
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        # Não gravar password no artefacto de comando
        safe_cmd = [
            self._bin(),
            "-c",
            collection,
            "-d",
            domain,
            "-u",
            user,
            "-p",
            "***",
            "-ns",
            dc,
            "--zip",
        ]
        content = stdout or stderr or ""
        out_file.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=safe_cmd,
            stdout=content,
            stderr=stderr,
            findings=[
                RawFinding(
                    title="BloodHound.py collection (DCOnly)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="ad",
                    description=(
                        f"Collection limitada contra DC {dc} (domínio {domain}). "
                        "Sem ataques — só enum AD autorizada."
                    ),
                    evidence=(content or "")[:2000],
                )
            ],
            artifact_path=str(out_file),
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        if intensity == "safe":
            msg = "BloodHound.py requer intensidade standard+ (collection AD)."
            path = job_dir / "bloodhound.txt"
            path.write_text(msg + "\n")
            return AdapterResult(
                tool=self.name,
                mocked=True,
                command=["bloodhound-python", "--skipped"],
                stdout=msg,
                findings=[
                    RawFinding(
                        title="BloodHound omitido (intensidade)",
                        severity=Severity.info,
                        target=target,
                        tool=self.name,
                        category="ad",
                        description=msg,
                        evidence=msg,
                    )
                ],
                artifact_path=str(path),
            )
        content = "[*] mock BloodHound.py DCOnly collection complete\n"
        path = job_dir / "bloodhound.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["bloodhound-python", "--mock"],
            stdout=content,
            findings=[
                RawFinding(
                    title="BloodHound.py mock collection",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="ad",
                    description="Modo mock — sem ligação AD real.",
                    evidence=content,
                )
            ],
            artifact_path=str(path),
        )
