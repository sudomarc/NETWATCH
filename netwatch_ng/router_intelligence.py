"""Evidence-based inspection of the locally configured default gateway."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from netwatch_ng.core import interfaces, network
from netwatch_ng.discovery import oui
from netwatch_ng.discovery.neighbors import list_live_neighbors

MANAGEMENT_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


@dataclass
class RouterReport:
    family: str
    gateway: str
    interface: str | None
    mac: str | None
    manufacturer: str | None
    local_addresses: list[str]


@dataclass
class ManagementService:
    port: int
    name: str
    state: str


def inspect_gateway(family: str = "inet") -> RouterReport | None:
    """Describe the configured gateway using local route/interface evidence.

    Manufacturer names are OUI hints only; this deliberately does not infer a
    router model or firmware version from a MAC address.
    """
    if family not in ("inet", "inet6"):
        raise ValueError("family must be 'inet' or 'inet6'")
    route = network.get_default_gateway(family)
    if route is None or route.gateway is None:
        return None

    gateway = str(ipaddress.ip_address(route.gateway))
    neighbor = next(
        (
            entry
            for entry in list_live_neighbors(family)
            if entry.ip and str(ipaddress.ip_address(entry.ip)) == gateway
        ),
        None,
    )
    mac = neighbor.mac if neighbor else None
    manufacturer = oui.lookup(mac) if mac else None

    local_addresses: list[str] = []
    if route.device:
        for interface in interfaces.list_interfaces(include_loopback=True):
            if interface.name == route.device:
                local_addresses = [address.address for address in interface.addresses]
                break

    return RouterReport(
        family=family,
        gateway=gateway,
        interface=route.device,
        mac=mac,
        manufacturer=manufacturer,
        local_addresses=local_addresses,
    )


def inspect_default_gateway() -> RouterReport | None:
    """Prefer the IPv4 gateway, falling back to IPv6 when IPv4 is absent."""
    return inspect_gateway("inet") or inspect_gateway("inet6")


def probe_management_services(
    gateway: str, timeout: float = 0.5, interface: str | None = None
) -> list[ManagementService]:
    """Check a small set of TCP management ports on one literal IP address.

    This performs connection attempts only; it does not authenticate, send
    application data, or scan a subnet. A closed or filtered port is reported
    as such rather than treated as evidence that the service is absent.
    """
    parsed_address = ipaddress.ip_address(gateway)
    address = str(parsed_address)
    if isinstance(parsed_address, ipaddress.IPv6Address) and parsed_address.is_link_local:
        if interface and not parsed_address.scope_id:
            address = f"{address}%{interface}"
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    results = []
    for port, name in MANAGEMENT_PORTS.items():
        try:
            with socket.create_connection((address, port), timeout=timeout):
                state = "reachable"
        except OSError:
            state = "not reachable (closed or filtered)"
        results.append(ManagementService(port=port, name=name, state=state))
    return results


def inspect_and_probe_gateway(
    family: str = "inet", timeout: float = 0.5
) -> tuple[RouterReport | None, list[ManagementService]]:
    """Inspect the default gateway and, when present, check management ports."""
    report = inspect_default_gateway() if family == "inet" else inspect_gateway(family)
    if report is None:
        return None, []
    return report, probe_management_services(
        report.gateway, timeout=timeout, interface=report.interface
    )
