"""Gateway, route and DNS inspection.

Each getter returns None / [] on a clean "not configured" state and
raises only on a genuinely broken environment (missing `ip` binary).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

from netwatch_ng.core.interfaces import list_interfaces
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


def get_local_subnet(family: str = "inet") -> str | None:
    """Return the CIDR subnet of the default-route interface, e.g. ``192.168.1.0/24``.

    Resolves the default gateway, finds the interface it uses, reads that
    interface's configured address + prefix length, and computes the network
    CIDR. Returns ``None`` when there is no default route or no address on the
    interface. Raises only on a genuinely broken environment (missing `ip`).
    """
    route = get_default_gateway(family)
    if route is None or not route.device:
        return None
    for iface in list_interfaces():
        if iface.name != route.device:
            continue
        addrs = iface.ipv4_addresses if family == "inet" else iface.ipv6_addresses
        for addr in addrs:
            if addr.address and addr.prefix_len:
                try:
                    network = ipaddress.ip_network(
                        f"{addr.address}/{addr.prefix_len}", strict=False
                    )
                    return str(network)
                except ValueError:
                    continue
    return None


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
