"""Helpers de alvo: host para tools de rede e URL para tools web (IPv4/IPv6)."""

from __future__ import annotations

import ipaddress
import socket
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


def target_resolution(target: str) -> tuple[list[str], str | None]:
    """Resolve um alvo para endereços IP (A/AAAA).

    IPs e CIDRs não precisam de DNS. Devolve ``(addresses, error)``; ``error``
    é uma mensagem curta quando o hostname não resolve (ex.: apex sem A/AAAA).
    """
    host = target_host(target)
    if not host:
        return [], "alvo vazio"
    try:
        ipaddress.ip_address(host)
        return [host], None
    except ValueError:
        pass
    try:
        ipaddress.ip_network(host, strict=False)
        return [host], None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], f"DNS não resolveu {host!r} ({exc.strerror or exc})"
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return [], f"DNS não devolveu endereços para {host!r}"
    return addresses, None


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
