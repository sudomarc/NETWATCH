"""Orchestrates a discovery pass: always reads the kernel neighbor
table; adds an active nmap scan on top when nmap is installed and the
caller asks for it. Returns a merged, identified Device list.
"""

from __future__ import annotations

from netwatch_ng.core.shell import BinaryNotFound, which
from netwatch_ng.discovery import device_intelligence as di
from netwatch_ng.discovery import neighbors as neighbors_mod
from netwatch_ng.discovery import nmap_scan


def passive_scan(family: str = "inet") -> list[di.Device]:
    """Neighbor-table-only discovery. Works with just `ip` installed."""
    found = neighbors_mod.list_live_neighbors(family)
    return di.merge([di.from_neighbor(n) for n in found])


def active_scan(targets: str, family: str = "inet", timeout: float = 60.0) -> list[di.Device]:
    """Combine neighbor-table + nmap ping-scan discovery over `targets`.

    Raises BinaryNotFound if nmap is not installed — callers should
    fall back to passive_scan() and tell the user why.
    """
    if which("nmap") is None:
        raise BinaryNotFound("nmap")

    passive_devices = [di.from_neighbor(n) for n in neighbors_mod.list_live_neighbors(family)]
    nmap_hosts = nmap_scan.discovery_scan(targets, timeout=timeout)
    active_devices = [di.from_nmap_host(h) for h in nmap_hosts]
    return di.merge(passive_devices + active_devices)
