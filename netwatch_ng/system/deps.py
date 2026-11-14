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
    Dependency("ip", "interfaces, routes, gateway, ARP/neighbor table", "core, discovery", True),
    Dependency("nmap", "host discovery, port/service and OS fingerprinting", "discovery, device intelligence, router intelligence", True),
    Dependency("iw", "Wi-Fi interface/mode and scan capability", "wifi intelligence", False),
    Dependency("rfkill", "wireless radio soft/hard-block state", "wifi intelligence", False),
    Dependency("nft", "nftables rule management", "firewall manager", False),
    Dependency("iptables", "iptables fallback rule management", "firewall manager", False),
    Dependency("ip6tables", "IPv6 firewall rule management", "firewall manager", False),
    Dependency("tc", "traffic shaping (HTB/IFB)", "traffic manager", False),
    Dependency("tcpdump", "passive packet capture", "wifi intelligence, diagnostics", False),
    Dependency("tshark", "packet capture with protocol decode", "diagnostics", False),
    Dependency("snmpwalk", "SNMP-based router/device fingerprinting", "router intelligence, device intelligence", False),
    Dependency("avahi-browse", "mDNS/Avahi service discovery", "device intelligence", False),
    Dependency("ethtool", "link speed/duplex/driver info", "diagnostics", False),
    Dependency("mtr", "combined traceroute + ping diagnostics", "diagnostics", False),
    Dependency("traceroute", "route-path diagnostics", "diagnostics", False),
    Dependency("iperf3", "throughput testing", "diagnostics", False),
    Dependency("ssh", "router SSH administration bridge", "router intelligence", False),
    Dependency("aircrack-ng", "Wi-Fi survey/audit suite", "wifi intelligence", False),
    Dependency("airodump-ng", "Wi-Fi passive capture and survey", "wifi intelligence", False),
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
