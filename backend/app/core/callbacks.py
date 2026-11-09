"""Validação anti-SSRF e assinatura HMAC dos webhooks de conclusão."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
from datetime import UTC, datetime
from urllib.parse import urlparse


def validate_callback_url(url: str) -> str:
    """Valida sintaxe http(s), sem credenciais embutidas."""
    value = url.strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("callback_url precisa ser uma URL http(s) válida")
    if parsed.username or parsed.password:
        raise ValueError("callback_url não pode conter credenciais embutidas")
    if not parsed.hostname:
        raise ValueError("callback_url precisa de um host")
    try:
        _port = parsed.port
    except ValueError as exc:
        raise ValueError("callback_url tem uma porta inválida") from exc
    return value


def _resolve_ips(host: str, port: int | None) -> set[str]:
    infos = socket.getaddrinfo(
        host, port or 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    return {str(info[4][0]) for info in infos}


def assert_safe_callback_url(url: str) -> str:
    """Resolve o host e recusa loopback/privado/link-local/reservado (SSRF)."""
    value = validate_callback_url(url)
    parsed = urlparse(value)
    host = parsed.hostname or ""
    try:
        ips = _resolve_ips(host, parsed.port)
    except OSError as exc:
        raise ValueError(f"callback_url não resolve: {host}") from exc
    if not ips:
        raise ValueError(f"callback_url não resolve: {host}")
    for raw_ip in ips:
        address = ipaddress.ip_address(raw_ip)
        if not address.is_global:
            raise ValueError(
                "callback_url aponta para IP não público (loopback/privado/link-local)"
            )
    return value


def encode_callback(
    payload: dict, secret: str
) -> tuple[bytes, dict[str, str]]:
    """Serializa o payload e assina com HMAC-SHA256 (timestamp + corpo)."""
    body = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    timestamp = str(int(datetime.now(UTC).timestamp()))
    headers = {
        "Content-Type": "application/json",
        "X-Ethoscan-Timestamp": timestamp,
    }
    if secret:
        message = f"{timestamp}.".encode() + body
        digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        headers["X-Ethoscan-Signature"] = f"sha256={digest}"
    return body, headers
