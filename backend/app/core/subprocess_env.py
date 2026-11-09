"""Ambiente mínimo para tools externas — não herdar segredos do processo Ethoscan."""

from __future__ import annotations

import os

_BASE_KEYS = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
_GUI_KEYS = (
    "DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "WAYLAND_DISPLAY",
)


def subprocess_env(gui: bool = False) -> dict[str, str]:
    keys = _BASE_KEYS + (_GUI_KEYS if gui else ())
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.setdefault("LANG", "C.UTF-8")
    return env
