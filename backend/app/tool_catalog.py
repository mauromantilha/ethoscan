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
    "cred": "F4",
    "ad": "F2",
    "util": None,
    "rf": None,
}

# Intensidade ordenada para comparar intensity_min.
_INTENSITY_RANK = {"safe": 0, "standard": 1, "aggressive": 2}

# Metadados estáticos do catálogo.
# runnable=True → tem adapter no pipeline; launchable → só GUI; inventory → só PATH.
_CATALOG_DEFS: list[dict[str, Any]] = [
    # --- Pipeline clássico + selecionáveis já existentes ---
    {
        "id": "nmap",
        "display_name": "Nmap",
        "category": "enum",
        "binary_candidates": ("nmap",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Enumera portas e serviços no alvo allowlisted (defaults conservadores).",
        "default_args_hint": "-Pn -sV --top-ports 50 -T4 (safe)",
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
        "default_args_hint": "--color=never -a 1 (safe)",
    },
    {
        "id": "gobuster",
        "display_name": "Gobuster",
        "category": "web",
        "binary_candidates": ("gobuster",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Descoberta de caminhos HTTP com wordlist curta e threads limitadas.",
        "default_args_hint": "dir -w small|common.txt -t 8 (safe)",
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
        "default_args_hint": "--no-colour --no-heartbleed <host>",
    },
    {
        "id": "nuclei",
        "display_name": "Nuclei",
        "category": "vuln",
        "binary_candidates": ("nuclei",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Templates focados (misconfig/cve); severidades e rate limitados em safe.",
        "default_args_hint": "-severity info,low,medium -rate-limit 25 -c 15 -etags dos,fuzz (safe)",
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
        "default_args_hint": "-h <alvo> -maxtime 60s (safe)",
    },
    {
        "id": "masscan",
        "display_name": "Masscan",
        "category": "enum",
        "binary_candidates": ("masscan",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": (
            "Scan de portas rápidas (lab). Em safe/standard com nmap selecionado, "
            "é omitido automaticamente (redundante)."
        ),
        "default_args_hint": "-p22,80,443,8080,8443 --rate 200 (safe)",
    },
    {
        "id": "unicornscan",
        "display_name": "Unicornscan",
        "category": "enum",
        "binary_candidates": ("unicornscan",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Enum de portas TCP (estilo masscan) contra hosts allowlisted, rate limitado.",
        "default_args_hint": "-mT -I <host>:22,80,443,8080,8443 (safe)",
        "ethics_note": "Só enum de portas no escopo RoE — sem payloads.",
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
            "Scan web headless automatizado + relatório HTML. "
            "Não confundir com Burp Suite (só lançamento GUI)."
        ),
        "default_args_hint": "-cmd -quickurl <url> -quickout report.html (timeout 180s safe)",
        "ethics_note": "ZAP = scan automatizado no pipeline. Burp CE = GUI manual apenas.",
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
        "status_label": "executável (limitado)",
    },
    {
        "id": "sqlmap",
        "display_name": "sqlmap",
        "category": "vuln",
        "binary_candidates": ("sqlmap",),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": (
            "Deteção SQLi com defaults seguros (--batch --level=1 --risk=1) "
            "apenas contra URL allowlisted."
        ),
        "default_args_hint": "-u <url> --batch --level=1 --risk=1 --threads=1 --smart",
        "ethics_note": "Sem --os-shell / --sql-shell / dump agressivo automatizado.",
    },
    {
        "id": "hydra",
        "display_name": "Hydra",
        "category": "cred",
        "binary_candidates": ("hydra", "thc-hydra"),
        "runnable": True,
        "launchable": False,
        "intensity_min": "standard",
        "description": (
            "Brute-force limitado (wordlist curta, poucas tentativas) só contra "
            "host allowlisted. Requer intensidade standard+."
        ),
        "default_args_hint": "-L users.txt -P rockyou-top.txt -t 4 -f ssh://<host>",
        "ethics_note": "RoE + allowlist F0. Sem sprays massivos; intensity mínimo standard.",
        "status_label": "executável (limitado)",
    },
    {
        "id": "john",
        "display_name": "John the Ripper",
        "category": "cred",
        "binary_candidates": ("john", "john-the-ripper"),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": (
            "Crack offline apenas se existir ficheiro de hashes nos artefactos "
            "do engagement (hashes.txt). Sem captura de tráfego."
        ),
        "default_args_hint": "--wordlist=... --max-run-time=60 hashes.txt",
        "ethics_note": "Só offline sobre artefactos do engagement — sem online attacks.",
        "status_label": "executável (offline)",
    },
    {
        "id": "netexec",
        "display_name": "NetExec (CME)",
        "category": "ad",
        "binary_candidates": ("nxc", "netexec", "crackmapexec"),
        "runnable": True,
        "launchable": False,
        "intensity_min": "safe",
        "description": (
            "Enum segura SMB/LDAP (sem spray de passwords nem exec). "
            "Deteta nxc / netexec / crackmapexec."
        ),
        "default_args_hint": "nxc smb <host> (enum only)",
        "ethics_note": "Módulos de enum apenas — sem -x/--exec-command nem password spray.",
        "status_label": "executável (enum)",
    },
    {
        "id": "bloodhound-python",
        "display_name": "BloodHound.py",
        "category": "ad",
        "binary_candidates": ("bloodhound-python", "bloodhound"),
        "runnable": True,
        "launchable": False,
        "intensity_min": "standard",
        "description": (
            "Coleção AD limitada contra DC allowlisted (intensity standard+). "
            "Requer credenciais de lab nos artefactos do engagement."
        ),
        "default_args_hint": "-c DCOnly -d <domain> -u user -p … --zip",
        "ethics_note": (
            "Collection contra DC no escopo apenas; sem ataques. "
            "Credenciais lidas de artefactos do engagement (ad_creds.env)."
        ),
        "status_label": "executável (limitado)",
    },
    # --- Launchable (GUI / open only) ---
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
        "ethics_note": (
            "Burp Suite Community = só lançamento GUI (manual). "
            "Para scan automatizado no pipeline + PDF, selecione OWASP ZAP."
        ),
        "status_label": "só GUI",
    },
    {
        "id": "wireshark",
        "display_name": "Wireshark",
        "category": "util",
        "binary_candidates": ("wireshark", "wireshark-qt", "wireshark-gtk"),
        "runnable": False,
        "launchable": True,
        "intensity_min": "safe",
        "description": "Analisador de pacotes GUI — lançamento manual; sem captura automatizada.",
        "default_args_hint": "(lançamento GUI)",
        "ethics_note": "Só GUI. Capturas devem respeitar RoE e legislação local.",
        "status_label": "só GUI",
    },
    {
        "id": "fern-wifi-cracker",
        "display_name": "Fern WiFi Cracker",
        "category": "rf",
        "binary_candidates": ("fern-wifi-cracker", "fern", "fern-wifi"),
        "runnable": False,
        "launchable": True,
        "intensity_min": "safe",
        "description": "GUI wireless — lançável manualmente; Ethoscan não automatiza RF.",
        "default_args_hint": "(lançamento GUI)",
        "ethics_note": "Inventário/GUI apenas — não expandir ataques RF neste produto.",
        "status_label": "só GUI",
    },
    # --- Inventory only (ethics / utilities) ---
    {
        "id": "tcpdump",
        "display_name": "tcpdump",
        "category": "util",
        "binary_candidates": ("tcpdump",),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Utilitário de captura CLI — inventário PATH; sem jobs automatizados.",
        "default_args_hint": "",
        "ethics_note": "Utilitário — use manualmente sob RoE; sem adapter de job.",
        "status_label": "inventário",
    },
    {
        "id": "netcat",
        "display_name": "Netcat",
        "category": "util",
        "binary_candidates": ("nc", "ncat", "netcat"),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Utilitário de rede (nc/ncat) — inventário; sem shells automatizados.",
        "default_args_hint": "",
        "ethics_note": "Utilitário — sem reverse shells automatizados pelo Ethoscan.",
        "status_label": "inventário",
    },
    {
        "id": "aircrack-ng",
        "display_name": "Aircrack-ng",
        "category": "rf",
        "binary_candidates": ("aircrack-ng",),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Suite wireless — inventário apenas (ética/RF).",
        "default_args_hint": "",
        "ethics_note": "Inventário apenas — não expandir ataques RF neste produto.",
        "status_label": "inventário",
    },
    {
        "id": "kismet",
        "display_name": "Kismet",
        "category": "rf",
        "binary_candidates": ("kismet",),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Sniffer wireless — inventário apenas (ética/RF).",
        "default_args_hint": "",
        "ethics_note": "Inventário apenas — não expandir ataques RF neste produto.",
        "status_label": "inventário",
    },
    {
        "id": "wifite",
        "display_name": "Wifite",
        "category": "rf",
        "binary_candidates": ("wifite", "wifite.py"),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Ataques Wi-Fi automatizados — inventário apenas (ética/RF).",
        "default_args_hint": "",
        "ethics_note": "Inventário apenas — não expandir ataques RF neste produto.",
        "status_label": "inventário",
    },
    {
        "id": "bettercap",
        "display_name": "Bettercap",
        "category": "lab",
        "binary_candidates": ("bettercap",),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Framework MITM/recon — inventário; sem automação Ethoscan.",
        "default_args_hint": "",
        "ethics_note": "Inventário apenas — MITM/RF não são automatizados.",
        "status_label": "inventário",
    },
    {
        "id": "arpwatch",
        "display_name": "arpwatch",
        "category": "util",
        "binary_candidates": ("arpwatch",),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "Monitor ARP — inventário PATH.",
        "default_args_hint": "",
        "ethics_note": "Inventário apenas.",
        "status_label": "inventário",
    },
    {
        "id": "setoolkit",
        "display_name": "Social-Engineer Toolkit",
        "category": "lab",
        "binary_candidates": ("setoolkit", "set", "se-toolkit"),
        "runnable": False,
        "launchable": False,
        "intensity_min": "safe",
        "description": "SET — inventário apenas; sem campanhas automatizadas.",
        "default_args_hint": "",
        "ethics_note": (
            "Inventário apenas — Ethoscan não automatiza phishing/SET. "
            "RoE + allowlist F0 inalterados."
        ),
        "status_label": "inventário",
    },
]

# IDs pedidos explicitamente (21) + pipeline clássico extra.
REQUESTED_TOOL_IDS: tuple[str, ...] = (
    "nmap",
    "masscan",
    "unicornscan",
    "wireshark",
    "tcpdump",
    "metasploit",
    "burpsuite",
    "john",
    "hydra",
    "aircrack-ng",
    "kismet",
    "wifite",
    "fern-wifi-cracker",
    "bettercap",
    "arpwatch",
    "sqlmap",
    "setoolkit",
    "netcat",
    "bloodhound-python",
    "netexec",
    "nikto",
)


def _role_badge(*, runnable: bool, launchable: bool) -> str:
    if runnable:
        return "executável"
    if launchable:
        return "só GUI"
    return "inventário"


def _status_for_entry(
    *,
    available: bool,
    runnable: bool,
    launchable: bool,
    will_mock: bool,
    static_label: str | None,
) -> str:
    if not available and not will_mock:
        return "não instalado"
    if static_label:
        return static_label
    if will_mock and not available:
        return "executável (mock)"
    return _role_badge(runnable=runnable, launchable=launchable)


def catalog_defs() -> list[dict[str, Any]]:
    return list(_CATALOG_DEFS)


def intensity_allows(tool_intensity_min: str, engagement_intensity: str) -> bool:
    return _INTENSITY_RANK.get(engagement_intensity, 0) >= _INTENSITY_RANK.get(
        tool_intensity_min, 0
    )


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
            # burpsuite / inventory / GUI — não entram na seleção de job
            continue
        if key not in cleaned:
            cleaned.append(key)
    if unknown:
        raise ValueError(f"Tools desconhecidas: {', '.join(unknown)}")
    return cleaned


def filter_by_intensity(selected: list[str], intensity: str) -> list[str]:
    """Remove tools cujo intensity_min é superior à intensidade do engagement."""
    mins = {d["id"]: d.get("intensity_min", "safe") for d in _CATALOG_DEFS}
    return [t for t in selected if intensity_allows(str(mins.get(t, "safe")), intensity)]


def tool_catalog() -> list[dict[str, Any]]:
    """Catálogo completo com disponibilidade PATH + flags runnable/launchable."""
    settings = get_settings()
    pipeline = tools_status()

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

        role = _role_badge(runnable=bool(defn["runnable"]), launchable=bool(defn["launchable"]))
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
                "role": role,
                "status": _status_for_entry(
                    available=available,
                    runnable=bool(defn["runnable"]),
                    launchable=bool(defn["launchable"]),
                    will_mock=will_mock,
                    static_label=defn.get("status_label"),
                ),
            }
        )

    # Entradas só-inventário remanescentes em LAB_TOOL_CANDIDATES (não devem haver).
    for name, cands in LAB_TOOL_CANDIDATES:
        if name in seen_ids:
            continue
        binary, available = _resolve_binary(cands)
        wireless = name in {"wifite", "fern-wifi-cracker", "kismet", "bettercap", "aircrack-ng"}
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
                "role": "inventário",
                "status": "inventário" if available else "não instalado",
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
