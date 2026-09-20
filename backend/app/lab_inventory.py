"""Inventário Kali/lab — verificação de existência no PATH (sem executar ataques)."""

from __future__ import annotations

import shutil
from typing import Any

# Tools do pipeline Ethoscan (F1–F4) — mantidas em /health via adapters.
PIPELINE_BINARIES: dict[str, str] = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "gobuster": "gobuster",
    "sslscan": "sslscan",
    "nuclei": "nuclei",
}

# Inventário alargado orientado a Kali / docs de lab do projeto.
# Cada entrada: id do catálogo → candidatos de binário no PATH (primeiro encontrado).
LAB_TOOL_CANDIDATES: list[tuple[str, tuple[str, ...]]] = [
    ("nmap", ("nmap",)),
    ("whatweb", ("whatweb",)),
    ("gobuster", ("gobuster",)),
    ("sslscan", ("sslscan",)),
    ("nuclei", ("nuclei",)),
    ("masscan", ("masscan",)),
    ("unicornscan", ("unicornscan",)),
    ("nikto", ("nikto",)),
    ("zap", ("zap.sh", "zap", "zaproxy")),
    ("burpsuite", ("burpsuite", "burp")),
    ("metasploit", ("msfconsole", "msfvenom")),
    ("wireshark", ("wireshark", "wireshark-qt", "wireshark-gtk")),
    ("tcpdump", ("tcpdump",)),
    ("john", ("john", "john-the-ripper")),
    ("hydra", ("hydra", "thc-hydra")),
    ("aircrack-ng", ("aircrack-ng",)),
    ("kismet", ("kismet",)),
    ("wifite", ("wifite", "wifite.py")),
    ("fern-wifi-cracker", ("fern-wifi-cracker", "fern", "fern-wifi")),
    ("bettercap", ("bettercap",)),
    ("arpwatch", ("arpwatch",)),
    ("sqlmap", ("sqlmap",)),
    ("setoolkit", ("setoolkit", "set", "se-toolkit")),
    ("netcat", ("nc", "ncat", "netcat")),
    ("bloodhound-python", ("bloodhound-python", "bloodhound")),
    ("netexec", ("nxc", "netexec", "crackmapexec")),
]


def _resolve_binary(candidates: tuple[str, ...]) -> tuple[str, bool]:
    for binary in candidates:
        if shutil.which(binary):
            return binary, True
    return candidates[0], False


def lab_tools_inventory() -> list[dict[str, Any]]:
    """Lista `{ name, binary, available }` sem correr scanners."""
    out: list[dict[str, Any]] = []
    for name, candidates in LAB_TOOL_CANDIDATES:
        binary, available = _resolve_binary(candidates)
        out.append({"name": name, "binary": binary, "available": available})
    return out
