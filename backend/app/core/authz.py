from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlparse

from fastapi import HTTPException

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Um label só (ex.: "com", "io") é TLD/serviço local e não alvo de pentest.
# "localhost" é liberado explicitamente para cenários de laboratório.
_SINGLE_LABEL_ALLOWED = {"localhost"}

# Denylist pragmática de sufixos públicos de dois níveis (não é a Public Suffix List):
# impede que escopos como "co.uk" liberem todos os domínios daquele sufixo.
_PUBLIC_SUFFIX_DENYLIST = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec",
    "co.in", "net.in", "org.in", "gov.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.za", "co.kr", "com.sg", "com.hk", "com.tw", "com.tr", "com.ua", "co.il",
}


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
        return host.lower()
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            return str(network)
        except ValueError:
            pass
    return value.lower().rstrip(".")


def is_valid_target(raw: str) -> bool:
    value = raw.strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    if "://" in value:
        host = urlparse(value).hostname
        if not host:
            return False
        return _has_targetable_hostname(host) or _is_ip(host)
    return _has_targetable_hostname(value)


def _has_targetable_hostname(hostname: str) -> bool:
    """Aceita FQDN com pelo menos dois labels; rejeita TLD e sufixos públicos."""
    if not _HOSTNAME_RE.match(hostname):
        return False
    host = hostname.lower().rstrip(".")
    if host in _SINGLE_LABEL_ALLOWED:
        return True
    if "." not in host:
        return False
    return host not in _PUBLIC_SUFFIX_DENYLIST


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def assert_roe(acknowledged: bool) -> None:
    if not acknowledged:
        raise HTTPException(
            status_code=403,
            detail=(
                "RoE/autorização não confirmada. "
                "Marque roe_acknowledged=true antes de rodar scans."
            ),
        )


def validate_allowlist(entries: Iterable[str]) -> list[str]:
    """Valida/normaliza a allowlist global. Entrada inválida => erro explícito (fail-fast).

    Evita que configurações como ``ETHOSCAN_ALLOWLIST=com`` ou ``co.uk`` autorizem
    um TLD/sufixo público inteiro por casamento de sufixo.
    """
    invalid = [item for item in entries if not is_valid_target(item)]
    if invalid:
        raise ValueError(
            "ETHOSCAN_ALLOWLIST possui entradas inválidas "
            f"(use host FQDN, IP ou CIDR): {invalid}"
        )
    return [normalize_target(item) for item in entries]


def assert_in_scope(target: str, scope: list[str]) -> None:
    if not _is_covered(target, scope):
        raise HTTPException(status_code=403, detail=f"Alvo fora do escopo allowlist: {target}")


def assert_in_allowlist(target: str, allowlist: list[str]) -> None:
    """Allowlist global (ETHOSCAN_ALLOWLIST). Lista vazia => sem restrição adicional."""
    if not allowlist:
        return
    if not _is_covered(target, allowlist):
        raise HTTPException(
            status_code=403,
            detail=f"Alvo não autorizado na allowlist global (ETHOSCAN_ALLOWLIST): {target}",
        )


def assert_targets_allowed(targets: Iterable[str], allowlist: list[str]) -> None:
    for target in targets:
        assert_in_allowlist(target, allowlist)


def _is_covered(target: str, scope: Iterable[str]) -> bool:
    """True se o alvo está coberto por entrada exata, CIDR ou subdomínio do escopo.

    Entradas que não são alvo válido (ex.: um TLD como "com") são descartadas para
    que não ampliem o escopo por casamento de sufixo.
    """
    normalized = normalize_target(target)
    scope_norm = [
        normalize_target(item) for item in scope if item and is_valid_target(item)
    ]

    if normalized in scope_norm:
        return True

    # CIDR containment for IPs
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        ip = None
    if ip is not None:
        for item in scope_norm:
            try:
                if ip in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                continue

    # subdomain of scoped domain
    return any(item and normalized.endswith("." + item) for item in scope_norm)


def validate_scope(scope: list[str]) -> list[str]:
    invalid = [t for t in scope if not is_valid_target(t)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Alvos inválidos: {invalid}")
    return [normalize_target(t) for t in scope]
