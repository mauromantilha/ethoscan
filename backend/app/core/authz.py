from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from fastapi import HTTPException


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


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
        return bool(host and (_HOSTNAME_RE.match(host) or _is_ip(host)))
    return bool(_HOSTNAME_RE.match(value))


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
    normalized = normalize_target(target)
    scope_norm = [normalize_target(s) for s in scope]

    if normalized in scope_norm:
        return

    # CIDR containment for IPs
    try:
        ip = ipaddress.ip_address(normalized)
        for item in scope_norm:
            try:
                if ip in ipaddress.ip_network(item, strict=False):
                    return
            except ValueError:
                continue
    except ValueError:
        pass

    # subdomain of scoped domain
    for item in scope_norm:
        if normalized == item or normalized.endswith("." + item):
            return

    raise HTTPException(status_code=403, detail=f"Alvo fora do escopo allowlist: {target}")


def validate_scope(scope: list[str]) -> list[str]:
    invalid = [t for t in scope if not is_valid_target(t)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Alvos inválidos: {invalid}")
    return [normalize_target(t) for t in scope]
