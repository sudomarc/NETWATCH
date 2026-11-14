"""Read-only SSDP/UPnP discovery restricted to the configured gateway."""
from __future__ import annotations

import http.client
import ipaddress
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass
class UpnpDevice:
    source_ip: str
    server: str | None
    search_target: str | None
    usn: str | None
    location: str | None
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    serial_number: str | None = None


def parse_ssdp_headers(payload: bytes) -> dict[str, str]:
    """Parse an SSDP response without trusting header order or casing."""
    text = payload.decode("iso-8859-1", errors="replace")
    headers: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key and key not in headers:
            headers[key] = value.strip()
    return headers


def _location_path(location: str, gateway: str) -> tuple[int, str] | None:
    try:
        parsed = urlsplit(location)
        host = str(ipaddress.ip_address(parsed.hostname or ""))
        port = parsed.port or 80
    except (ValueError, TypeError):
        return None
    if (
        parsed.scheme.lower() != "http"
        or host != gateway
        or parsed.username is not None
        or parsed.password is not None
        or not 1 <= port <= 65535
    ):
        return None
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return port, path


def parse_description(xml_body: bytes) -> dict[str, str]:
    """Extract common UPnP root-device fields using namespace-insensitive tags."""
    root = ET.fromstring(xml_body)
    wanted = {
        "friendlyName",
        "manufacturer",
        "modelName",
        "modelNumber",
        "serialNumber",
    }
    fields: dict[str, str] = {}
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name in wanted and element.text and element.text.strip():
            fields.setdefault(local_name, element.text.strip()[:160])
    return fields


def _read_description(gateway: str, location: str, timeout: float) -> dict[str, str]:
    parsed = _location_path(location, gateway)
    if parsed is None:
        return {}
    port, path = parsed
    connection = http.client.HTTPConnection(gateway, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/xml"})
        response = connection.getresponse()
        if response.status != 200:
            return {}
        body = response.read(65537)
        if len(body) > 65536:
            return {}
        return parse_description(body)
    except (OSError, http.client.HTTPException, ET.ParseError, ValueError):
        return {}
    finally:
        connection.close()


def discover_upnp(gateway: str, timeout: float = 3.0, max_responses: int = 8) -> list[UpnpDevice]:
    """Send one bounded SSDP M-SEARCH and accept responses only from gateway.

    The description URL is fetched only when it is plain HTTP on the same
    literal gateway IP. No redirects, credentials, arbitrary hosts, or
    configuration writes are followed/performed.
    """
    try:
        address = ipaddress.ip_address(gateway)
    except ValueError as exc:
        raise ValueError(f"invalid gateway address: {gateway!r}") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private:
        raise ValueError("UPnP discovery requires a private IPv4 gateway address")
    if not 0.2 <= timeout <= 10:
        raise ValueError("timeout must be between 0.2 and 10 seconds")
    if not 1 <= max_responses <= 32:
        raise ValueError("max_responses must be between 1 and 32")

    gateway = str(address)
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    ).encode("ascii")

    found: dict[str, UpnpDevice] = {}
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(min(0.25, timeout))
        sock.sendto(request, ("239.255.255.250", 1900))
        while len(found) < max_responses and time.monotonic() < deadline:
            sock.settimeout(max(0.05, min(0.25, deadline - time.monotonic())))
            try:
                payload, peer = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                peer_ip = str(ipaddress.ip_address(peer[0]))
            except ValueError:
                continue
            if peer_ip != gateway:
                continue

            headers = parse_ssdp_headers(payload)
            location = headers.get("location")
            key = headers.get("usn") or headers.get("st") or location or peer_ip
            if key in found:
                continue

            device = UpnpDevice(
                source_ip=peer_ip,
                server=headers.get("server"),
                search_target=headers.get("st"),
                usn=headers.get("usn"),
                location=location,
            )
            if location:
                fields = _read_description(gateway, location, timeout=min(timeout, 2.0))
                device.friendly_name = fields.get("friendlyName")
                device.manufacturer = fields.get("manufacturer")
                device.model_name = fields.get("modelName")
                device.model_number = fields.get("modelNumber")
                device.serial_number = fields.get("serialNumber")
            found[key] = device

    return list(found.values())
