"""Helpers de alvo: host para tools de rede e URL para tools web (IPv4/IPv6)."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def target_host(target: str) -> str:
    """Extrai o host de um alvo sem scheme, com suporte a IPv6.

    Exemplos: ``https://example.com/`` -> ``example.com``;
    ``2001:db8::1`` -> ``2001:db8::1``; ``[2001:db8::1]`` -> ``2001:db8::1``.
    """
    value = target.strip()
    if "://" in value:
        return urlsplit(value).hostname or ""
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    # host:port não é escopo válido, mas evita passar "host:port" às tools.
    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if host and port.isdigit():
            return host
    return value


def target_url(target: str, scheme: str = "http") -> str:
    """Devolve uma URL http(s), colocando brackets em IPv6."""
    value = target.strip()
    if "://" in value:
        return value
    host = target_host(value)
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"{scheme}://[{host}]"
    except ValueError:
        pass
    return f"{scheme}://{host}"
