from app.adapters.base import BaseAdapter
from app.adapters.bloodhound import BloodhoundAdapter
from app.adapters.gobuster import GobusterAdapter
from app.adapters.hydra import HydraAdapter
from app.adapters.john import JohnAdapter
from app.adapters.masscan import MasscanAdapter
from app.adapters.metasploit import MetasploitAdapter
from app.adapters.netexec import NetExecAdapter
from app.adapters.nikto import NiktoAdapter
from app.adapters.nmap import NmapAdapter
from app.adapters.nuclei import NucleiAdapter
from app.adapters.sqlmap import SqlmapAdapter
from app.adapters.sslscan import SslscanAdapter
from app.adapters.unicornscan import UnicornscanAdapter
from app.adapters.whatweb import WhatWebAdapter
from app.adapters.zap import ZapAdapter
from app.config import get_settings


# Pipeline clássico (backward compatible quando selected_tools vazio).
REQUIRED_TOOLS = ("nmap", "whatweb", "gobuster", "sslscan", "nuclei")


def all_adapters() -> list[BaseAdapter]:
    return [
        NmapAdapter(),
        WhatWebAdapter(),
        GobusterAdapter(),
        SslscanAdapter(),
        NucleiAdapter(),
        NiktoAdapter(),
        MasscanAdapter(),
        UnicornscanAdapter(),
        ZapAdapter(),
        MetasploitAdapter(),
        SqlmapAdapter(),
        HydraAdapter(),
        JohnAdapter(),
        NetExecAdapter(),
        BloodhoundAdapter(),
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
