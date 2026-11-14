"""Gateway, route and DNS inspection.

Each getter returns None / [] on a clean "not configured" state and
raises only on a genuinely broken environment (missing `ip` binary).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from netwatch_ng.core.shell import run


@dataclass
class Route:
    destination: str
    gateway: str | None
    device: str | None
    protocol: str | None


def get_default_gateway(family: str = "inet") -> Route | None:
    """Return the default route for `family` ("inet" or "inet6"), or None."""
    flag = "-4" if family == "inet" else "-6"
    result = run(["ip", flag, "-j", "route", "show", "default"], timeout=5.0)
    if not result.ok or not result.stdout.strip():
        return None
    routes = json.loads(result.stdout)
    if not routes:
        return None
    r = routes[0]
    return Route(
        destination=r.get("dst", "default"),
        gateway=r.get("gateway"),
        device=r.get("dev"),
        protocol=r.get("protocol"),
    )


def get_routes(family: str = "inet") -> list[Route]:
    flag = "-4" if family == "inet" else "-6"
    result = run(["ip", flag, "-j", "route", "show"], timeout=5.0)
    if not result.ok or not result.stdout.strip():
        return []
    raw = json.loads(result.stdout)
    return [
        Route(
            destination=r.get("dst", ""),
            gateway=r.get("gateway"),
            device=r.get("dev"),
            protocol=r.get("protocol"),
        )
        for r in raw
    ]


_NAMESERVER_RE = re.compile(r"^\s*nameserver\s+(\S+)", re.MULTILINE)


def get_dns_servers(resolv_conf: str = "/etc/resolv.conf") -> list[str]:
    """Parse nameserver entries from resolv.conf. Returns [] if unreadable."""
    path = Path(resolv_conf)
    try:
        text = path.read_text()
    except OSError:
        return []
    return _NAMESERVER_RE.findall(text)


def get_hostname() -> str:
    try:
        return Path("/proc/sys/kernel/hostname").read_text().strip()
    except OSError:
        import socket

        return socket.gethostname()
