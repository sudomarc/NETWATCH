"""External tool detection.

NETWATCH NG never installs dependencies itself. Each optional tool is
declared once here with the module(s) that need it; the TUI's System
Manager screen and Dashboard both read this registry so the user always
sees, truthfully, what is and isn't available on this machine.
"""

from __future__ import annotations

from dataclasses import dataclass

from netwatch_ng.core.shell import which


@dataclass
class Dependency:
    binary: str
    purpose: str
    required_by: str
    mandatory: bool  # True = core features degrade hard without it


REGISTRY: list[Dependency] = [
    Dependency("ip", "interfaces, routes, gateway and neighbor inspection", "core, discovery, router intelligence, diagnostics", True),
    Dependency("nmap", "operator-triggered host discovery and per-host service detection", "device discovery and identification", False),
    Dependency("iw", "wireless interface inventory and access-point surveys", "Wi-Fi intelligence", False),
    Dependency("rfkill", "wireless radio soft/hard-block status", "Wi-Fi intelligence", False),
    Dependency("iptables", "IPv4 NETWATCH-owned forwarding rules", "firewall manager", False),
    Dependency("ip6tables", "IPv6 NETWATCH-owned forwarding rules", "firewall manager", False),
    Dependency("tc", "Linux traffic-control packet policing", "traffic manager", False),
    Dependency("ping", "gateway reachability diagnostics", "diagnostics", False),
    Dependency("getent", "system resolver lookup diagnostics", "diagnostics", False),
    Dependency("mtr", "route-path diagnostics", "diagnostics", False),
    Dependency("traceroute", "route-path diagnostics fallback", "diagnostics", False),
]


@dataclass
class DependencyStatus:
    dependency: Dependency
    installed: bool
    path: str | None


def check_all() -> list[DependencyStatus]:
    statuses = []
    for dep in REGISTRY:
        path = which(dep.binary)
        statuses.append(DependencyStatus(dependency=dep, installed=path is not None, path=path))
    return statuses


def missing_mandatory() -> list[Dependency]:
    return [d for d in REGISTRY if d.mandatory and which(d.binary) is None]
