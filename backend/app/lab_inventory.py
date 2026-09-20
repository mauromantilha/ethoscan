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
# Cada entrada: nome de exibição → candidatos de binário no PATH (primeiro encontrado).
LAB_TOOL_CANDIDATES: list[tuple[str, tuple[str, ...]]] = [
    ("nmap", ("nmap",)),
    ("whatweb", ("whatweb",)),
    ("gobuster", ("gobuster",)),
    ("sslscan", ("sslscan",)),
    ("nuclei", ("nuclei",)),
    ("masscan", ("masscan",)),
    ("unicornscan", ("unicornscan",)),
    ("nikto", ("nikto",)),
    ("bettercap", ("bettercap",)),
    ("kismet", ("kismet",)),
    ("wifite", ("wifite", "wifite.py")),
    ("fern-wifi-cracker", ("fern-wifi-cracker", "fern", "fern-wifi")),
    ("arpwatch", ("arpwatch",)),
    ("setoolkit", ("setoolkit", "set", "se-toolkit")),
    ("netexec", ("nxc", "netexec")),
    ("bloodhound-python", ("bloodhound-python", "bloodhound")),
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
