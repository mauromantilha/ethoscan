from __future__ import annotations

import re
import shutil
from pathlib import Path

from app.adapters.base import AdapterResult, BaseAdapter, RawFinding
from app.models import Severity


class ZapAdapter(BaseAdapter):
    """OWASP ZAP — alternativa headless ao Burp Community para relatório automatizado."""

    name = "zap"
    binary = "zap.sh"

    def available(self) -> bool:
        return shutil.which("zap.sh") is not None or shutil.which("zap") is not None or shutil.which(
            "zaproxy"
        ) is not None

    def _binary(self) -> str:
        for name in ("zap.sh", "zap", "zaproxy"):
            path = shutil.which(name)
            if path:
                return path
        return self.binary

    def _run_real(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        url = target if target.startswith("http") else f"http://{target}"
        out_html = job_dir / "zap-report.html"
        binary = self._binary()
        # Quick scan: spider + passive/active light — sem scripting de exploits.
        cmd = [
            binary,
            "-cmd",
            "-quickurl",
            url,
            "-quickout",
            str(out_html),
            "-quickprogress",
        ]
        timeout = 300 if intensity == "safe" else 600
        stdout, stderr, _ = self._exec(cmd, timeout=timeout)
        content = out_html.read_text(errors="ignore") if out_html.exists() else stdout
        summary = job_dir / "zap.txt"
        summary.write_text(content[:50000] if content else stdout)
        return AdapterResult(
            tool=self.name,
            mocked=False,
            command=cmd,
            stdout=stdout or content[:5000],
            stderr=stderr,
            findings=self._parse(content or stdout, target),
            artifact_path=str(out_html if out_html.exists() else summary),
        )

    def _run_mock(self, target: str, job_dir: Path, intensity: str) -> AdapterResult:
        content = (
            f"<html><body><h1>ZAP Mock Report</h1>"
            f"<p>Target: {target}</p>"
            f"<li>Missing Anti-clickjacking Header</li>"
            f"<li>Content Security Policy (CSP) Header Not Set</li>"
            f"</body></html>"
        )
        path = job_dir / "zap-report.html"
        path.write_text(content)
        return AdapterResult(
            tool=self.name,
            mocked=True,
            command=["zap.sh", "--mock", target],
            stdout=content,
            findings=self._parse(content, target),
            artifact_path=str(path),
        )

    def _parse(self, content: str, target: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        # Extrair itens de lista / alertas simples do HTML ou texto.
        for m in re.finditer(r"<li[^>]*>(.*?)</li>", content, re.I | re.S):
            title = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if len(title) < 5:
                continue
            findings.append(
                RawFinding(
                    title=title[:160],
                    severity=Severity.low,
                    target=target,
                    tool=self.name,
                    category="web",
                    description="Alerta OWASP ZAP (scan rápido).",
                    evidence=title[:2000],
                    remediation="Corrigir conforme orientação OWASP / headers de segurança.",
                )
            )
        if not findings and content.strip():
            findings.append(
                RawFinding(
                    title="Scan ZAP concluído",
                    severity=Severity.info,
                    target=target,
                    tool=self.name,
                    category="web",
                    description="ZAP executou quick scan; rever artefacto HTML completo.",
                    evidence=content[:500],
                )
            )
        # Dedup
        seen: set[str] = set()
        unique: list[RawFinding] = []
        for f in findings:
            if f.title in seen:
                continue
            seen.add(f.title)
            unique.append(f)
        return unique[:50]
