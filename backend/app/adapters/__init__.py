from app.adapters.base import BaseAdapter
from app.adapters.gobuster import GobusterAdapter
from app.adapters.nmap import NmapAdapter
from app.adapters.nuclei import NucleiAdapter
from app.adapters.sslscan import SslscanAdapter
from app.adapters.whatweb import WhatWebAdapter
from app.config import get_settings


REQUIRED_TOOLS = ("nmap", "whatweb", "gobuster", "sslscan", "nuclei")


def all_adapters() -> list[BaseAdapter]:
    return [
        NmapAdapter(),
        WhatWebAdapter(),
        GobusterAdapter(),
        SslscanAdapter(),
        NucleiAdapter(),
    ]


def tools_status() -> dict[str, dict]:
    settings = get_settings()
    status: dict[str, dict] = {}
    for adapter in all_adapters():
        available = adapter.available()
        will_mock = (not available) and settings.ethoscan_allow_mock
        status[adapter.name] = {
            "binary": adapter.binary,
            "available": available,
            "will_mock": will_mock,
            "mode": "real" if available else ("mock" if will_mock else "unavailable"),
        }
    return status
