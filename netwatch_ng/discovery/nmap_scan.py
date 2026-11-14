"""Active discovery and service/OS fingerprinting via nmap.

Always invoked with an explicit argv list (never shell=True) and a
bounded timeout. XML output (`-oX -`) is parsed with the stdlib
ElementTree instead of scraping human-readable text, so results don't
break on locale or formatting changes.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from netwatch_ng.core.shell import run, run_cancellable
from threading import Event


class InvalidTarget(ValueError):
    pass


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None


@dataclass
class NmapHost:
    ip: str
    mac: str | None
    nmap_vendor: str | None  # vendor string from nmap's own OUI database, if present
    hostname: str | None
    up: bool
    ports: list[Port] = field(default_factory=list)


def _validate_targets(targets: str) -> None:
    """Minimal sanity check before handing a string to nmap's argv slot.

    This is not a full CIDR/hostname grammar — it just rejects the
    obvious shell-metacharacter injection surface. nmap itself still
    validates/rejects malformed targets.
    """
    forbidden = set(";|&`$(){}<>\n")
    if (
        not isinstance(targets, str)
        or not targets
        or targets.startswith("-")
        or any(c.isspace() for c in targets)
        or any(c in forbidden for c in targets)
    ):
        raise InvalidTarget(f"invalid Nmap target expression: {targets!r}")


def _parse_host(host_elem: ET.Element) -> NmapHost | None:
    status = host_elem.find("status")
    up = status is not None and status.get("state") == "up"

    ip = None
    mac = None
    vendor = None
    for addr in host_elem.findall("address"):
        addrtype = addr.get("addrtype")
        if addrtype in ("ipv4", "ipv6"):
            ip = addr.get("addr")
        elif addrtype == "mac":
            mac = addr.get("addr")
            vendor = addr.get("vendor") or None

    if ip is None:
        return None

    hostname = None
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        hn = hostnames_elem.find("hostname")
        if hn is not None:
            hostname = hn.get("name") or None

    ports: list[Port] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")
            ports.append(
                Port(
                    number=int(port_elem.get("portid", "0")),
                    protocol=port_elem.get("protocol", ""),
                    state=state_elem.get("state") if state_elem is not None else "unknown",
                    service=service_elem.get("name") if service_elem is not None else None,
                    product=service_elem.get("product") if service_elem is not None else None,
                    version=service_elem.get("version") if service_elem is not None else None,
                )
            )

    return NmapHost(ip=ip, mac=mac, nmap_vendor=vendor, hostname=hostname, up=up, ports=ports)


def _parse_nmap_xml(xml_text: str) -> list[NmapHost]:
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    hosts = []
    for host_elem in root.findall("host"):
        parsed = _parse_host(host_elem)
        if parsed is not None:
            hosts.append(parsed)
    return hosts


def discovery_scan(
    targets: str,
    timeout: float = 60.0,
    cancel_event: Event | None = None,
) -> list[NmapHost]:
    """Ping-style host discovery (`nmap -sn`) across `targets`
    (an IP, hostname, CIDR, or nmap range expression)."""
    _validate_targets(targets)
    argv = ["nmap", "-sn", "-oX", "-", targets]
    result = (
        run(argv, timeout=timeout)
        if cancel_event is None
        else run_cancellable(argv, timeout=timeout, cancel_event=cancel_event)
    )
    if not result.ok:
        raise RuntimeError(f"nmap discovery scan failed: {result.stderr.strip()}")
    return _parse_nmap_xml(result.stdout)


def service_scan(target: str, timeout: float = 120.0) -> NmapHost | None:
    """Service/version detection (`nmap -sV`) against a single host.

    Only accepts a single IP/hostname (never a range) — this is the
    slow, invasive scan and should be operator-initiated per host, not
    run automatically across a subnet.
    """
    _validate_targets(target)
    try:
        ipaddress.ip_network(target, strict=False)
        is_single_ip = "/" not in target
    except ValueError:
        is_single_ip = True  # hostname

    if "/" in target and not is_single_ip:
        raise InvalidTarget("service_scan accepts a single host, not a CIDR range")

    result = run(["nmap", "-sV", "-oX", "-", target], timeout=timeout)
    if not result.ok:
        raise RuntimeError(f"nmap service scan failed: {result.stderr.strip()}")
    hosts = _parse_nmap_xml(result.stdout)
    return hosts[0] if hosts else None
