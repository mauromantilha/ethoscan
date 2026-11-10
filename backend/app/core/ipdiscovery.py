"""Descoberta passiva do IP de origem de um domínio (atrás de CDN/WAF).

Técnicas SOMENTE PASSIVAS — nenhum pacote é enviado aos IPs candidatos:
1. Resolução A/AAAA do próprio domínio (edge) e classificação de CDN;
2. Sondagem DNS de subdomínios comuns (mail, cpanel, origin, dev...);
3. Registros MX (via ``dig``, se disponível) — mail exchangers vivem no host real;
4. Certificate Transparency (crt.sh) para enumeração de subdomínios.

O objetivo é sugerir CANDIDATOS: cada um deve ser validado manualmente
(Host/SNI apontando ao IP, dentro do RoE) antes de qualquer scan direto.
Uso ético: apenas domínios que você controla/tem autorização.
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote

import httpx

logger = logging.getLogger("ethoscan")

# Faixas públicas da Cloudflare (snapshot; refresh best-effort ao usar).
_CLOUDFLARE_V4_SNAPSHOT = (
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 "
    "141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 "
    "197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 "
    "104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
).split()

_CLOUDFLARE_V6_SNAPSHOT = ("2400:cb00::/32 2606:4700::/32 2803:f800::/32 "
                           "2405:b500::/32 2405:8100::/32 2a06:98c0::/29 "
                           "2c0f:f248::/32").split()

_cloudflare_networks: list[Any] | None = None

# Subdomínios que frequentemente apontam direto ao servidor de origem.
COMMON_HOSTNAMES = (
    "mail", "webmail", "smtp", "imap", "pop", "autodiscover",
    "cpanel", "webdisk", "whm", "direct", "direct-connect",
    "origin", "origin-server", "old", "www-old", "legacy",
    "dev", "staging", "stage", "test", "admin", "painel",
    "vpn", "ftp", "ssh", "ns1", "ns2", "webmail2", "mail2",
)

_MAX_CRTSH_NAMES = 40
_MAX_CANDIDATES = 15


def _load_cloudflare_networks() -> list[Any]:
    """Redes Cloudflare: snapshot embutido + refresh best-effort (cache no processo)."""
    global _cloudflare_networks
    if _cloudflare_networks is not None:
        return _cloudflare_networks

    from ipaddress import ip_network

    networks: list[Any] = []
    for raw in (*_CLOUDFLARE_V4_SNAPSHOT, *_CLOUDFLARE_V6_SNAPSHOT):
        try:
            networks.append(ip_network(raw))
        except ValueError:
            continue

    try:
        with httpx.Client(timeout=10) as http:
            for url in (
                "https://www.cloudflare.com/ips-v4",
                "https://www.cloudflare.com/ips-v6",
            ):
                resp = http.get(url)
                resp.raise_for_status()
                for raw in resp.text.split():
                    try:
                        networks.append(ip_network(raw))
                    except ValueError:
                        continue
        logger.debug("Faixas Cloudflare atualizadas de cloudflare.com (%d redes).", len(networks))
    except Exception as exc:
        logger.debug("Refresh das faixas Cloudflare falhou (usando snapshot): %s", exc)

    _cloudflare_networks = networks
    return networks


def is_cloudflare_ip(address: str) -> bool:
    try:
        ip = ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in _load_cloudflare_networks())


# Provedores de e-mail gerenciado: os MX deles NÃO indicam a origem do site
# (ex.: corretorsync.com usa Zoho — mx2.zoho.com não é o servidor de origem).
_MAIL_SAAS_SUFFIXES = (
    "zoho.com", "zoho.eu", "google.com", "googlemail.com", "outlook.com",
    "protection.outlook.com", "messaging.microsoft.com", "protonmail.ch",
    "protonmail.com", "mailgun.org", "sendgrid.net", "mandrillapp.com",
    "amazonses.com", "yandex.ru", "yandex.net", "improvmx.com", "fastmail.com",
    "mimecast.com", "pphosted.com", "barracudanetworks.com", "proofpoint.com",
)


def _is_mail_saas(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    return any(host == s or host.endswith("." + s) or host.endswith(s) for s in _MAIL_SAAS_SUFFIXES)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def _mx_hosts(domain: str) -> list[str]:
    """MX via dig (best-effort; container Kali traz dnsutils via whatweb/nikto deps)."""
    dig = shutil.which("dig")
    if not dig:
        return []
    try:
        result = subprocess.run(  # noqa: S603 - binário fixo, argumentos controlados
            [dig, "+short", "MX", domain],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    hosts = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].endswith("."):
            hosts.append(parts[-1].rstrip("."))
    return hosts[:5]


def _crtsh_names(domain: str) -> list[str]:
    """Subdomínios via Certificate Transparency (crt.sh). Best-effort."""
    url = f"https://crt.sh/?q=%.{quote(domain)}&output=json"
    try:
        with httpx.Client(timeout=20, follow_redirects=True) as http:
            resp = http.get(url)
            resp.raise_for_status()
            rows = json.loads(resp.text)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        logger.debug("crt.sh indisponível para %s: %s", domain, exc)
        return []
    names: set[str] = set()
    if isinstance(rows, list):
        for row in rows:
            for field in (row.get("name_value") or "", row.get("common_name") or ""):
                for name in str(field).split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(f".{domain.lower()}") and "*" not in name:
                        names.add(name)
    return sorted(names)[:_MAX_CRTSH_NAMES]


def discover_origin_ip(domain: str) -> dict[str, Any]:
    """Descoberta passiva do IP de origem de um domínio.

    Devolve edge IPs, classificação de CDN e candidatos de origem
    (IPs que NÃO pertencem à CDN) com a fonte de cada um.
    """
    domain = domain.strip().lower().removeprefix("www.")
    notes: list[str] = []
    candidates: dict[str, dict[str, str]] = {}  # ip -> {"host","source"}

    def add_candidate(host: str, ips: list[str], source: str) -> None:
        for ip in ips:
            if not is_cloudflare_ip(ip):
                if ip not in candidates and len(candidates) < _MAX_CANDIDATES:
                    candidates[ip] = {"host": host, "source": source}

    edge_raw = _resolve(domain) + _resolve(f"www.{domain}")
    edge_ips = list(dict.fromkeys(edge_raw))  # dedup preservando ordem
    edge_cloudflare = [ip for ip in edge_ips if is_cloudflare_ip(ip)]
    if edge_cloudflare:
        cdn = "cloudflare"
        notes.append(
            "Edge na Cloudflare: o job mede a borda, não a origem. "
            "Candidatos abaixo requerem validação manual (Host/SNI) dentro do RoE."
        )
    elif edge_ips:
        cdn = "desconhecido ou nenhuma"
        notes.append("Domínio resolve para IP(s) fora das faixas Cloudflare conhecidas.")
    else:
        cdn = "indeterminado"
        notes.append("Domínio não resolveu (sem A/AAAA).")

    # 1. subdomínios comuns (DNS puro)
    for name in COMMON_HOSTNAMES:
        host = f"{name}.{domain}"
        add_candidate(host, _resolve(host), "subdomínio comum")

    # 2. mail exchangers (podem viver no host real — exceto SaaS de e-mail)
    for mx in _mx_hosts(domain):
        if _is_mail_saas(mx):
            continue
        add_candidate(mx, _resolve(mx), "registro MX")

    # 3. certificate transparency
    crt_names = _crtsh_names(domain)
    if crt_names:
        for host in crt_names:
            add_candidate(host, _resolve(host), "certificate transparency")
    else:
        notes.append("crt.sh não devolveu nomes (offline/limitado) — só sondagem DNS foi feita.")

    return {
        "domain": domain,
        "edge_ips": edge_ips,
        "cdn": cdn,
        "origin_candidates": [
            {"ip": ip, "host": meta["host"], "source": meta["source"]}
            for ip, meta in sorted(candidates.items())
        ],
        "notes": notes,
        "passive": True,
        "advisory": (
            "Descoberta passiva (DNS + CT logs). Candidatos NÃO validados: confirme "
            "manualmente (curl --resolve/vhost) dentro do escopo antes de tratar como origem."
        ),
    }
