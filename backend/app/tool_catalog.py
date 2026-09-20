"""Catálogo de tools Ethoscan — inventário + metadados de execução (pt-BR)."""

from __future__ import annotations

import shutil
from typing import Any

from app.adapters import REQUIRED_TOOLS, all_adapters, tools_status
from app.config import get_settings
from app.lab_inventory import LAB_TOOL_CANDIDATES, _resolve_binary

# Pipeline clássico F1–F4 (backward compatible quando selected_tools vazio).
DEFAULT_PIPELINE_TOOLS: tuple[str, ...] = REQUIRED_TOOLS

# Ordem de fase por categoria para UI / worker.
CATEGORY_PHASE: dict[str, str] = {
    "recon": "F1",
    "enum": "F2",
    "web": "F3",
    "vuln": "F4",
    "proxy": "F3",
    "lab": "F2",
}

# Metadados estáticos do catálogo executável / especial.
# runnable=True → tem adapter no pipeline; launchable → só GUI; inventory → só PATH.
_CATALOG_DEFS: list[dict[str, Any]] = [
    {
        "id": "nmap",
        "display_name": "Nmap",
        "category": "enum",
        "binary_candidates": ("nmap",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Enumera portas e serviços no alvo allowlisted (defaults conservadores).",
        "default_args_hint": "-Pn -sV --top-ports 100 -T3",
    },
    {
        "id": "whatweb",
        "display_name": "WhatWeb",
        "category": "recon",
        "binary_candidates": ("whatweb",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Fingerprint de tecnologias web no alvo do escopo.",
        "default_args_hint": "--color=never --log-verbose=…",
    },
    {
        "id": "gobuster",
        "display_name": "Gobuster",
        "category": "web",
        "binary_candidates": ("gobuster",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Descoberta de caminhos HTTP com wordlist comum (threads limitadas).",
        "default_args_hint": "dir -w common.txt -t 10",
    },
    {
        "id": "sslscan",
        "display_name": "sslscan",
        "category": "enum",
        "binary_candidates": ("sslscan",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Análise TLS/SSL do serviço HTTPS no alvo.",
        "default_args_hint": "--no-failed <host>",
    },
    {
        "id": "nuclei",
        "display_name": "Nuclei",
        "category": "vuln",
        "binary_candidates": ("nuclei",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Templates de vulnerabilidade (severidades limitadas em safe).",
        "default_args_hint": "-severity info,low,medium -rate-limit 20",
    },
    {
        "id": "nikto",
        "display_name": "Nikto",
        "category": "vuln",
        "binary_candidates": ("nikto",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Scanner web clássico com tempo máximo e sem exploits.",
        "default_args_hint": "-h <alvo> -maxtime 120s",
    },
    {
        "id": "masscan",
        "display_name": "Masscan",
        "category": "enum",
        "binary_candidates": ("masscan",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Scan de portas rápidas com rate baixo e portas top fixas (lab).",
        "default_args_hint": "-p22,80,443,8080,8443 --rate 100",
    },
    {
        "id": "zap",
        "display_name": "OWASP ZAP",
        "category": "web",
        "binary_candidates": ("zap.sh", "zap", "zaproxy"),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": (
            "Scan web headless (alternativa ao Burp Community para relatório automatizado)."
        ),
        "default_args_hint": "-cmd -quickurl <url> -quickout report.html",
        "ethics_note": "Preferir ZAP para scans não assistidos; Burp CE é sobretudo GUI.",
    },
    {
        "id": "metasploit",
        "display_name": "Metasploit (aux/scanner)",
        "category": "lab",
        "binary_candidates": ("msfconsole", "msfvenom"),
        "runnable": True,
        "launchable": False,
        "intensity_min": "standard",
        "description": (
            "Apenas módulos auxiliary/scanner de recon contra hosts allowlisted. "
            "Não corre exploits nem payloads weaponizados."
        ),
        "default_args_hint": "auxiliary/scanner/portscan/tcp (RHOSTS allowlisted)",
        "ethics_note": (
            "Adapter limitado: resource script aux/scanner apenas. "
            "Exploits que abrem shell estão bloqueados por desenho."
        ),
        "status_label": "adapter limitado",
    },
    {
        "id": "burpsuite",
        "display_name": "Burp Suite",
        "category": "proxy",
        "binary_candidates": ("burpsuite", "burp"),
        "runnable": False,
        "launchable": True,
        "intensity_min": "safe",
        "description": (
            "Community Edition é sobretudo GUI — Ethoscan deteta no PATH e permite lançar. "
            "Para scan automatizado + PDF, use OWASP ZAP."
        ),
        "default_args_hint": "(lançamento GUI)",
        "ethics_note": "Sem adapter headless; use ZAP para pipeline automatizado.",
        "status_label": "só lançamento GUI",
    },
]


def _status_for_entry(
    *,
    available: bool,
    runnable: bool,
    launchable: bool,
    will_mock: bool,
    static_label: str | None,
) -> str:
    if static_label and available:
        return static_label
    if not available:
        return "não instalado"
    if runnable:
        return "disponível"
    if launchable:
        return "só lançamento GUI"
    return "inventário"


def runnable_adapter_ids() -> set[str]:
    return {a.name for a in all_adapters()}


def resolve_selected_tools(selected: list[str] | None) -> list[str]:
    """Vazio/None → pipeline clássico; caso contrário só adapters runnable conhecidos."""
    runnable = runnable_adapter_ids()
    if not selected:
        return [t for t in DEFAULT_PIPELINE_TOOLS if t in runnable]
    seen: list[str] = []
    for name in selected:
        key = (name or "").strip().lower()
        if key in runnable and key not in seen:
            seen.append(key)
    return seen


def validate_selected_tools(selected: list[str] | None) -> list[str]:
    """Valida IDs; ignora burp/inventory-only; rejeita desconhecidos."""
    if selected is None:
        return []
    if selected == []:
        return []
    known = {d["id"] for d in _CATALOG_DEFS}
    runnable = runnable_adapter_ids()
    cleaned: list[str] = []
    unknown: list[str] = []
    for raw in selected:
        key = (raw or "").strip().lower()
        if not key:
            continue
        if key not in known:
            unknown.append(key)
            continue
        if key not in runnable:
            # burpsuite etc. — não entram na seleção de job
            continue
        if key not in cleaned:
            cleaned.append(key)
    if unknown:
        raise ValueError(f"Tools desconhecidas: {', '.join(unknown)}")
    return cleaned


def tool_catalog() -> list[dict[str, Any]]:
    """Catálogo completo com disponibilidade PATH + flags runnable/launchable."""
    settings = get_settings()
    pipeline = tools_status()
    inventory_map = {name: _resolve_binary(cands) for name, cands in LAB_TOOL_CANDIDATES}
    # Overlay extras (burp/zap/msf) se não estiverem no inventário lab.
    extra_bins = {
        "burpsuite": ("burpsuite", "burp"),
        "zap": ("zap.sh", "zap", "zaproxy"),
        "metasploit": ("msfconsole",),
    }
    for name, cands in extra_bins.items():
        if name not in inventory_map:
            inventory_map[name] = _resolve_binary(cands)

    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for defn in _CATALOG_DEFS:
        tid = defn["id"]
        seen_ids.add(tid)
        binary, available = _resolve_binary(tuple(defn["binary_candidates"]))
        # Prefer pipeline status when adapter exists
        pipe = pipeline.get(tid)
        if pipe is not None:
            available = bool(pipe.get("available"))
            binary = str(pipe.get("binary") or binary)
            will_mock = bool(pipe.get("will_mock"))
            mode = pipe.get("mode", "unavailable")
        else:
            will_mock = (not available) and settings.ethoscan_allow_mock and defn["runnable"]
            mode = "real" if available else ("mock" if will_mock else "unavailable")

        out.append(
            {
                "id": tid,
                "display_name": defn["display_name"],
                "category": defn["category"],
                "phase": CATEGORY_PHASE.get(defn["category"]),
                "binary": binary,
                "available": available,
                "runnable": bool(defn["runnable"]),
                "launchable": bool(defn["launchable"]),
                "intensity_min": defn["intensity_min"],
                "description": defn["description"],
                "default_args_hint": defn.get("default_args_hint", ""),
                "ethics_note": defn.get("ethics_note"),
                "will_mock": will_mock,
                "mode": mode,
                "status": _status_for_entry(
                    available=available,
                    runnable=bool(defn["runnable"]),
                    launchable=bool(defn["launchable"]),
                    will_mock=will_mock,
                    static_label=defn.get("status_label"),
                ),
            }
        )

    # Entradas só-inventário (wireless etc.) — inventory-only, não expandir RF.
    for name, cands in LAB_TOOL_CANDIDATES:
        if name in seen_ids:
            continue
        binary, available = _resolve_binary(cands)
        wireless = name in {"wifite", "fern-wifi-cracker", "kismet", "bettercap"}
        out.append(
            {
                "id": name,
                "display_name": name,
                "category": "lab",
                "phase": None,
                "binary": binary,
                "available": available,
                "runnable": False,
                "launchable": False,
                "intensity_min": "safe",
                "description": (
                    "Apenas inventário PATH — RF/wireless não é executado pelo Ethoscan."
                    if wireless
                    else "Presente no inventário Kali; sem adapter Ethoscan neste release."
                ),
                "default_args_hint": "",
                "ethics_note": (
                    "Inventário apenas — não expandir ataques RF neste produto."
                    if wireless
                    else None
                ),
                "will_mock": False,
                "mode": "real" if available else "unavailable",
                "status": "disponível" if available else "não instalado",
            }
        )

    return out


def find_launch_binary(tool_id: str) -> str | None:
    for defn in _CATALOG_DEFS:
        if defn["id"] != tool_id:
            continue
        if not defn.get("launchable"):
            return None
        binary, available = _resolve_binary(tuple(defn["binary_candidates"]))
        return binary if available else None
    return None


def which_any(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None
