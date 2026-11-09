from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from fastapi import HTTPException

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Um label só (ex.: "com", "io") é TLD/serviço local, não alvo de pentest.
# "localhost" é liberado explicitamente para laboratório.
_SINGLE_LABEL_ALLOWED = {"localhost"}

# Denylist pragmática de sufixos públicos de dois níveis (não é a Public Suffix List):
# impede que escopos/allowlist como "co.uk" liberem todos os domínios daquele sufixo.
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


def _url_host(value: str) -> str | None:
    """Host de URL http(s) sem porta/path/query/fragment.

    O escopo é deliberadamente estrito: ``https://host:8443/admin`` não pode ser
    normalizado para ``host`` (isso ampliaria o escopo e perderia a porta/path).
    """
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    try:
        if parsed.port is not None:
            return None
    except ValueError:
        return None
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    host = parsed.hostname
    if not host:
        return None
    return host


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
        host = _url_host(value)
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
            detail="RoE/autorização não confirmada. Marque roe_acknowledged=true antes de rodar scans.",
        )


def assert_in_scope(target: str, scope: list[str]) -> None:
    if not _is_covered(target, scope):
        raise HTTPException(status_code=403, detail=f"Alvo fora do escopo allowlist: {target}")


def validate_allowlist(entries: list[str]) -> list[str]:
    """Valida/normaliza a allowlist global. Entrada inválida => erro explícito (fail-fast).

    Evita que configurações como ``ETHOSCAN_ALLOWLIST=com`` ou ``co.uk`` autorizem um
    TLD/sufixo público inteiro por casamento de sufixo.
    """
    cleaned = [item.strip() for item in entries if item and item.strip()]
    invalid = [item for item in cleaned if not is_valid_target(item)]
    if invalid:
        raise ValueError(
            f"ETHOSCAN_ALLOWLIST possui entradas inválidas (use host FQDN, IP ou CIDR): {invalid}"
        )
    return [normalize_target(item) for item in cleaned]


def assert_in_allowlist(target: str, allowlist: list[str]) -> None:
    """Allowlist global (ETHOSCAN_ALLOWLIST). Lista vazia => sem restrição adicional."""
    if not allowlist:
        return
    if not _is_covered(target, allowlist):
        raise HTTPException(
            status_code=403,
            detail=f"Alvo não autorizado na allowlist global (ETHOSCAN_ALLOWLIST): {target}",
        )


def assert_targets_allowed(targets: list[str], allowlist: list[str]) -> None:
    for target in targets:
        assert_in_allowlist(target, allowlist)


def _target_kind(value: str) -> str:
    """Classifica um alvo normalizado: ip, network ou hostname."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return "network"
    except ValueError:
        pass
    return "hostname"


def _is_covered(target: str, scope: list[str]) -> bool:
    """True se o alvo está coberto pelo escopo, comparando tipos compatíveis.

    - IP só casa com IP exato ou rede que o contém (nunca por sufixo de hostname).
    - Rede só casa com rede igual/contida ou IP /32 exato.
    - Hostname só casa com hostname exato ou subdomínio de hostname.
    """
    normalized = normalize_target(target)
    target_kind = _target_kind(normalized)
    scope_entries: list[tuple[str, str]] = []
    for item in scope:
        if not item or not is_valid_target(item):
            continue
        normalized_item = normalize_target(item)
        scope_entries.append((normalized_item, _target_kind(normalized_item)))

    if target_kind == "ip":
        ip = ipaddress.ip_address(normalized)
        for item, kind in scope_entries:
            if kind == "ip" and ip == ipaddress.ip_address(item):
                return True
            if kind == "network" and ip in ipaddress.ip_network(item, strict=False):
                return True
        return False

    if target_kind == "network":
        network = ipaddress.ip_network(normalized, strict=False)
        for item, kind in scope_entries:
            if kind == "network":
                scoped = ipaddress.ip_network(item, strict=False)
                if network == scoped or network.subnet_of(scoped):
                    return True
            elif (
                kind == "ip"
                and network.num_addresses == 1
                and network.network_address == ipaddress.ip_address(item)
            ):
                return True
        return False

    return any(
        kind == "hostname"
        and (normalized == item or normalized.endswith("." + item))
        for item, kind in scope_entries
    )


def validate_scope(scope: list[str]) -> list[str]:
    invalid = [t for t in scope if not is_valid_target(t)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Alvos inválidos: {invalid}")
    return [normalize_target(t) for t in scope]
