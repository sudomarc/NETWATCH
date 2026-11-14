"""Device identification: merge multiple weak signals into one record,
and always say where each piece of information came from and how sure
we are of it. Nothing here is ever upgraded to a flat certainty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netwatch_ng.discovery import oui
from netwatch_ng.discovery.neighbors import Neighbor
from netwatch_ng.discovery.nmap_scan import NmapHost


class Confidence(Enum):
    CERTAIN = "certain"  # e.g. the kernel's own ARP/NDP table entry for this host
    LIKELY = "likely"  # e.g. OUI vendor match, nmap-reported hostname
    UNVERIFIED = "unverified"  # e.g. a guess with no corroborating signal


@dataclass
class IdentificationField:
    value: str
    source: str
    confidence: Confidence


@dataclass
class Device:
    ip: str
    mac: str | None = None
    hostname: IdentificationField | None = None
    vendor: IdentificationField | None = None
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    up: bool = True

    def describe_vendor(self) -> str:
        if self.vendor is None:
            return "Unknown (no OUI match in local database)"
        tag = "" if self.vendor.confidence == Confidence.CERTAIN else " (unverified)"
        return f"{self.vendor.value}{tag}"


def _vendor_field(mac: str | None, nmap_vendor: str | None) -> IdentificationField | None:
    if nmap_vendor:
        return IdentificationField(value=nmap_vendor, source="nmap OUI database", confidence=Confidence.LIKELY)
    if mac:
        local = oui.lookup(mac)
        if local:
            return IdentificationField(value=local, source="local OUI table", confidence=Confidence.LIKELY)
    return None


def from_neighbor(neighbor: Neighbor) -> Device:
    return Device(
        ip=neighbor.ip,
        mac=neighbor.mac,
        vendor=_vendor_field(neighbor.mac, None),
        up=neighbor.state in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"),
    )


def from_nmap_host(host: NmapHost) -> Device:
    hostname = None
    if host.hostname:
        hostname = IdentificationField(value=host.hostname, source="nmap reverse DNS/NetBIOS", confidence=Confidence.LIKELY)

    ports = [p.number for p in host.ports if p.state == "open"]
    services = sorted({p.service for p in host.ports if p.service and p.state == "open"})

    return Device(
        ip=host.ip,
        mac=host.mac,
        hostname=hostname,
        vendor=_vendor_field(host.mac, host.nmap_vendor),
        open_ports=ports,
        services=services,
        up=host.up,
    )


def merge(devices: list[Device]) -> list[Device]:
    """Merge multiple Device records for the same IP (e.g. one from the
    neighbor table, one from an nmap scan) into one, preferring the
    higher-confidence / more complete field each time.
    """
    by_ip: dict[str, Device] = {}
    for d in devices:
        if d.ip not in by_ip:
            by_ip[d.ip] = d
            continue
        existing = by_ip[d.ip]
        existing.mac = existing.mac or d.mac
        existing.hostname = existing.hostname or d.hostname
        existing.vendor = existing.vendor or d.vendor
        existing.open_ports = sorted(set(existing.open_ports) | set(d.open_ports))
        existing.services = sorted(set(existing.services) | set(d.services))
        existing.up = existing.up or d.up
    return list(by_ip.values())
