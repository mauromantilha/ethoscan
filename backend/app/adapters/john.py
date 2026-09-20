"""John the Ripper — crack offline só com hashes nos artefactos do engagement."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity

_HASH_NAMES = ("hashes.txt", "hashes", "john.hashes", "unshadowed.txt")


def _find_hash_file(job_dir: Path) -> Path | None:
    """Procura hashes no job_dir e no diretório pai do engagement."""
    candidates: list[Path] = []
    for name in _HASH_NAMES:
        candidates.append(job_dir / name)
    eng_dir = job_dir.parent
    for name in _HASH_NAMES:
        candidates.append(eng_dir / name)
        candidates.append(eng_dir / "artifacts" / name)
    # Qualquer *.hash sob engagement
    for base in (job_dir, eng_dir, eng_dir / "artifacts"):
        if base.is_dir():
            candidates.extend(sorted(base.glob("*.hash")))
            candidates.extend(sorted(base.glob("*.hashes")))
    for path in candidates:
        if path.is_file() and path.stat().st_size > 0:
            return path
    return None


class JohnAdapter(BaseAdapter):
    """John offline — sem ficheiro de hashes = skip informativo."""

    name = "john"
    binary = "john"

    def available(self) -> bool:
        for name in ("john", "john-the-ripper"):
            if shutil.which(name):
                self.binary = name
                return True
        return False

    def _bin(self) -> str:
        return shutil.which("john") or shutil.which("john-the-ripper") or "john"

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        hash_file = _find_hash_file(job_dir)
        out_file = job_dir / "john.txt"
        if hash_file is None:
            msg = (
                "John omitido: nenhum ficheiro de hashes nos artefactos do engagement "
                "(hashes.txt / *.hash). Coloque hashes offline sob o diretório do engagement."
            )
            out_file.write_text(msg + "\n")
            return AdapterResult(
                tool=self.name,
                mocked=False,
                command=["john", "--skipped-no-hashes"],
                stdout=msg,
                findings=[
                    RawFinding(
                        title="John omitido (sem hashes)",
                        severity=Severity.info,
                        target=target,
                        tool=self.name,
                        category="cred",
                        description=msg,
                        evidence=msg,
                    )
                ],
                artifact_path=str(out_file),
            )

        max_runtime = 60 if intensity == "safe" else (120 if intensity == "standard" else 300)
        wordlist = self._wordlist()
        cmd = [
            self._bin(),
            f"--max-run-time={max_runtime}",
            str(hash_file),
        ]
        if wordlist:
            cmd.insert(1, f"--wordlist={wordlist}")
        stdout, stderr, _ = self._exec(cmd, timeout=max_runtime + 30)
        # Show cracked
        show_cmd = [self._bin(), "--show", str(hash_file)]
        show_out, show_err, _ = self._exec(show_cmd, timeout=30)
        content = "\n".join(
            [
                f"# hash_file={hash_file}",
                stdout or "",
                stderr or "",
                "# --show",
                show_out or "",
                show_err or "",
            ]
        )
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
            "# john mock (sem hashes reais)\n"
            "Loaded 0 password hashes (mock)\n"
            "0g 0:00:00:00 DONE\n"
        )
        path = job_dir / "john.txt"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["john", "--mock"],
            stdout=content,
            findings=[
                RawFinding(
                    title="John mock (offline)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="cred",
                    description="Modo mock — sem crack real.",
                    evidence=content,
                )
            ],
            artifact_path=str(path),
        )

    def _wordlist(self) -> str | None:
        for path in (
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/john/password.lst",
            "/usr/share/wordlists/dirb/common.txt",
        ):
            if Path(path).is_file():
                return path
        return None

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in (content or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # john --show: user:password:...
            if ":" in line and "password hashes" not in line.lower() and "loaded" not in line.lower():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] and not parts[1].startswith("$"):
                    findings.append(
                        RawFinding(
                            title=f"Hash cracked (John): {parts[0]}",
                            severity=Severity.high,
                            target=target,
                            tool=self.name,
                            category="cred",
                            description="John the Ripper cracked um hash offline dos artefactos.",
                            evidence=f"{parts[0]}:***",
                            remediation="Password fraca — forçar rotação e política forte.",
                        )
                    )
        if not findings:
            findings.append(
                RawFinding(
                    title="John concluído (sem cracks)",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="cred",
                    description="Crack offline sem passwords recuperadas no tempo limite.",
                    evidence=(content or "")[:1500],
                )
            )
        return findings[:20]
