"""Descoberta passiva de IP de origem (atrás de CDN): módulo e endpoint."""

from __future__ import annotations

import json

from app.core import ipdiscovery
from app.core.ipdiscovery import discover_origin_ip, is_cloudflare_ip


def test_is_cloudflare_ip_known_ranges() -> None:
    assert is_cloudflare_ip("104.18.16.181")
    assert is_cloudflare_ip("172.64.36.1")
    assert is_cloudflare_ip("188.114.97.3")
    assert not is_cloudflare_ip("203.0.113.10")
    assert not is_cloudflare_ip("nao-e-ip")


def test_is_cloudflare_ip_uses_snapshot_without_network(monkeypatch) -> None:
    # sem rede: o snapshot embutido responde sozinho
    monkeypatch.setattr(ipdiscovery, "_cloudflare_networks", None)
    monkeypatch.setattr(
        ipdiscovery.httpx.Client,
        "__enter__",
        lambda *a, **k: (_ for _ in ()).throw(OSError("sem rede")),
        raising=False,
    )
    assert is_cloudflare_ip("104.16.132.229")


def test_discover_origin_ip_collects_non_cdn_candidates(monkeypatch) -> None:
    dns = {
        "example.com": ["104.18.0.1"],  # edge Cloudflare
        "www.example.com": ["104.18.0.1"],
        "mail.example.com": ["203.0.113.50"],  # origem candidata (não-CF)
        "cpanel.example.com": ["104.18.0.1"],  # também atrás da CDN: ignorar
    }
    monkeypatch.setattr(ipdiscovery, "_resolve", lambda h: dns.get(h, []))
    monkeypatch.setattr(ipdiscovery, "_mx_hosts", lambda d: ["mail.example.com"])
    monkeypatch.setattr(ipdiscovery, "_crtsh_names", lambda d: ["api.example.com"])
    dns["api.example.com"] = ["198.51.100.7"]

    result = discover_origin_ip("www.example.com")

    assert result["cdn"] == "cloudflare"
    assert result["edge_ips"] == ["104.18.0.1"]
    ips = {c["ip"]: c for c in result["origin_candidates"]}
    assert "203.0.113.50" in ips and ips["203.0.113.50"]["source"] in {
        "subdomínio comum",
        "registro MX",
    }
    assert "198.51.100.7" in ips and ips["198.51.100.7"]["source"] == "certificate transparency"
    assert "104.18.0.1" not in ips  # IPs da CDN nunca são candidatos
    assert result["passive"] is True
    assert "Cloudflare" in result["notes"][0]


def test_discover_origin_ip_dedupes_by_ip(monkeypatch) -> None:
    monkeypatch.setattr(ipdiscovery, "_resolve", lambda h: ["203.0.113.50"] if h == "mail.example.com" else [])
    monkeypatch.setattr(ipdiscovery, "_mx_hosts", lambda d: ["mail.example.com"])
    monkeypatch.setattr(ipdiscovery, "_crtsh_names", lambda d: [])
    result = discover_origin_ip("example.com")
    assert len(result["origin_candidates"]) == 1


def test_discover_origin_ip_domain_sem_cdn(monkeypatch) -> None:
    monkeypatch.setattr(ipdiscovery, "_resolve", lambda h: ["203.0.113.9"] if h == "example.com" else [])
    monkeypatch.setattr(ipdiscovery, "_mx_hosts", lambda d: [])
    monkeypatch.setattr(ipdiscovery, "_crtsh_names", lambda d: [])
    result = discover_origin_ip("example.com")
    assert result["cdn"] == "desconhecido ou nenhuma"
    assert result["origin_candidates"] == []


def test_discover_origin_ip_ignores_mail_saas(monkeypatch) -> None:
    # MX da Zoho/Google NÃO é origem do site — não pode virar candidato.
    monkeypatch.setattr(ipdiscovery, "_resolve", lambda h: {"example.com": ["104.18.0.1"], "mx2.zoho.com": ["204.141.43.44"]}.get(h, []))
    monkeypatch.setattr(ipdiscovery, "_mx_hosts", lambda d: ["mx2.zoho.com"])
    monkeypatch.setattr(ipdiscovery, "_crtsh_names", lambda d: [])
    result = discover_origin_ip("example.com")
    assert result["origin_candidates"] == []


def test_crtsh_names_parses_json(monkeypatch) -> None:
    class FakeResp:
        text = json.dumps(
            [
                {"name_value": "a.example.com\nb.example.com", "common_name": "a.example.com"},
                {"name_value": "*.example.com", "common_name": "example.com"},
            ]
        )

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *a, **k): ...

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            return FakeResp()

    monkeypatch.setattr(ipdiscovery.httpx, "Client", FakeClient)
    names = ipdiscovery._crtsh_names("example.com")
    assert sorted(names) == ["a.example.com", "b.example.com"]


def test_endpoint_discover_ip(client, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.core.ipdiscovery.discover_origin_ip",
        lambda d: {
            "domain": d,
            "edge_ips": ["104.18.0.1"],
            "cdn": "cloudflare",
            "origin_candidates": [{"ip": "203.0.113.50", "host": f"mail.{d}", "source": "registro MX"}],
            "notes": ["edge na Cloudflare"],
            "passive": True,
            "advisory": "validar manualmente",
        },
    )
    resp = client.post("/api/discover-ip", json={"targets": ["www.corretorsync.com"]})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["results"]) == 1
    r = body["results"][0]
    assert r["cdn"] == "cloudflare"
    assert r["origin_candidates"][0]["ip"] == "203.0.113.50"


def test_endpoint_discover_ip_rejects_ip_target_as_domain_flow(client, monkeypatch) -> None:
    # alvo IP: sem descoberta, resposta informativa
    resp = client.post("/api/discover-ip", json={"targets": ["192.0.2.10"]})
    assert resp.status_code == 200
    assert resp.json()["results"][0]["origin_candidates"] == []


def test_endpoint_discover_ip_validates_scope(client) -> None:
    resp = client.post("/api/discover-ip", json={"targets": []})
    assert resp.status_code == 422
