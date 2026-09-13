from app.adapters.base import BaseAdapter
from app.adapters.gobuster import GobusterAdapter
from app.adapters.nmap import NmapAdapter
from app.adapters.nuclei import NucleiAdapter
from app.adapters.sslscan import SslscanAdapter
from app.adapters.whatweb import WhatWebAdapter


def all_adapters() -> list[BaseAdapter]:
    return [
        NmapAdapter(),
        WhatWebAdapter(),
        GobusterAdapter(),
        SslscanAdapter(),
        NucleiAdapter(),
    ]


def tools_status() -> dict[str, dict]:
    status: dict[str, dict] = {}
    for adapter in all_adapters():
        status[adapter.name] = {
            "binary": adapter.binary,
            "available": adapter.available(),
        }
    return status
