"""Network interface detection.

Uses `ip -j addr show` (iproute2 JSON output, supported since iproute2
4.15+, present on all Debian 12/13 and antiX targets). No parsing of
free-text `ip addr` output: JSON avoids locale/format fragility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from netwatch_ng.core.shell import BinaryNotFound, run


@dataclass
class InterfaceAddress:
    family: str  # "inet" or "inet6"
    address: str
    prefix_len: int
    scope: str


@dataclass
class Interface:
    name: str
    state: str  # UP / DOWN / UNKNOWN
    mac: str | None
    mtu: int | None
    addresses: list[InterfaceAddress] = field(default_factory=list)

    @property
    def ipv4_addresses(self) -> list[InterfaceAddress]:
        return [a for a in self.addresses if a.family == "inet"]

    @property
    def ipv6_addresses(self) -> list[InterfaceAddress]:
        return [a for a in self.addresses if a.family == "inet6"]

    @property
    def is_loopback(self) -> bool:
        return self.name == "lo"

    @property
    def is_up(self) -> bool:
        return self.state == "UP"


def _parse_addr_info(entry: dict) -> Interface:
    addresses = [
        InterfaceAddress(
            family=a.get("family", ""),
            address=a.get("local", ""),
            prefix_len=a.get("prefixlen", 0),
            scope=a.get("scope", ""),
        )
        for a in entry.get("addr_info", [])
        if a.get("local")
    ]
    flags = entry.get("flags", [])
    state = "UP" if "UP" in flags else "DOWN"
    return Interface(
        name=entry.get("ifname", ""),
        state=state,
        mac=entry.get("address"),
        mtu=entry.get("mtu"),
        addresses=addresses,
    )


def list_interfaces(include_loopback: bool = False) -> list[Interface]:
    """Return all network interfaces known to the kernel.

    Raises BinaryNotFound if `ip` (iproute2) is not installed — callers
    (system.deps / TUI) are responsible for surfacing that to the user
    rather than silently returning an empty list.
    """
    result = run(["ip", "-j", "addr", "show"], timeout=5.0)
    if not result.ok:
        raise RuntimeError(f"ip addr show failed: {result.stderr.strip()}")

    raw = json.loads(result.stdout) if result.stdout.strip() else []
    interfaces = [_parse_addr_info(entry) for entry in raw]
    if not include_loopback:
        interfaces = [i for i in interfaces if not i.is_loopback]
    return interfaces


def is_available() -> bool:
    from netwatch_ng.core.shell import which

    return which("ip") is not None
