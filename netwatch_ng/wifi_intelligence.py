"""Linux Wi-Fi inventory and operator-triggered access-point survey via iw."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from netwatch_ng.core.shell import run, run_cancellable

_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_PHY_NAME = re.compile(r"^phy\d+$")
_PHY_RE = re.compile(r"^\s*phy#(\d+)\s*$")
_INTERFACE_RE = re.compile(r"^\s*Interface\s+(\S+)\s*$")
_ADDRESS_RE = re.compile(r"^\s*addr\s+(\S+)\s*$")
_TYPE_RE = re.compile(r"^\s*type\s+(\S+)\s*$")
_CHANNEL_RE = re.compile(
    r"^\s*channel\s+(\d+)\s+\((\d+)\s+MHz\)", re.MULTILINE
)
_BSS_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})(?:\s+\(on\s+[^)]+\))?")
_FREQUENCY_RE = re.compile(r"^\s*freq:\s*(\d+)\s*$", re.MULTILINE)
_SIGNAL_RE = re.compile(r"^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm\s*$", re.MULTILINE)
_SSID_RE = re.compile(r"^\s*SSID:[ \t]?(.*)$", re.MULTILINE)


@dataclass
class WirelessInterface:
    name: str
    phy: str | None
    interface_type: str | None
    mac: str | None
    channel: int | None
    frequency_mhz: int | None


@dataclass
class RadioState:
    soft_blocked: bool | None
    hard_blocked: bool | None


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    frequency_mhz: int | None
    channel: int | None
    signal_dbm: float | None
    advertised_security: str


def list_wireless_interfaces() -> list[WirelessInterface]:
    """Return wireless interfaces reported by `iw dev`."""
    result = run(["iw", "dev"], timeout=5.0)
    if not result.ok:
        raise RuntimeError(f"iw dev failed: {result.stderr.strip()}")

    interfaces: list[WirelessInterface] = []
    phy: str | None = None
    current: WirelessInterface | None = None
    for line in result.stdout.splitlines():
        match = _PHY_RE.match(line)
        if match:
            phy = f"phy{match.group(1)}"
            continue
        match = _INTERFACE_RE.match(line)
        if match:
            current = WirelessInterface(
                name=match.group(1),
                phy=phy,
                interface_type=None,
                mac=None,
                channel=None,
                frequency_mhz=None,
            )
            interfaces.append(current)
            continue
        if current is None:
            continue
        if match := _ADDRESS_RE.match(line):
            current.mac = match.group(1)
        elif match := _TYPE_RE.match(line):
            current.interface_type = match.group(1)
        elif match := _CHANNEL_RE.match(line):
            current.channel = int(match.group(1))
            current.frequency_mhz = int(match.group(2))
    return interfaces


def get_radio_state() -> RadioState:
    """Return the aggregate Wi-Fi soft/hard block state reported by rfkill."""
    result = run(["rfkill", "list", "wifi"], timeout=5.0)
    if not result.ok:
        raise RuntimeError(f"rfkill list wifi failed: {result.stderr.strip()}")
    soft: list[bool] = []
    hard: list[bool] = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*Soft blocked:\s*(yes|no)\s*$", line, re.IGNORECASE)
        if match:
            soft.append(match.group(1).lower() == "yes")
        match = re.match(r"\s*Hard blocked:\s*(yes|no)\s*$", line, re.IGNORECASE)
        if match:
            hard.append(match.group(1).lower() == "yes")
    return RadioState(
        soft_blocked=any(soft) if soft else None,
        hard_blocked=any(hard) if hard else None,
    )


def get_supported_modes(phy: str) -> list[str]:
    """Return supported interface modes for one wireless PHY reported by iw."""
    if not _PHY_NAME.fullmatch(phy):
        raise ValueError(f"invalid wireless PHY name: {phy!r}")
    result = run(["iw", "phy", phy, "info"], timeout=5.0)
    if not result.ok:
        raise RuntimeError(f"iw phy {phy} info failed: {result.stderr.strip()}")

    modes: list[str] = []
    in_modes = False
    for line in result.stdout.splitlines():
        if line.strip() == "Supported interface modes:":
            in_modes = True
            continue
        if not in_modes:
            continue
        match = re.match(r"^\s*\*\s+(.+?)\s*$", line)
        if match:
            modes.append(match.group(1))
        elif line.strip():
            break
    return modes


def _channel_for_frequency(frequency_mhz: int) -> int | None:
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz < 5925:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    return None


def _parse_access_point(block: str) -> AccessPoint | None:
    bss = _BSS_RE.search(block)
    if not bss:
        return None
    frequency_match = _FREQUENCY_RE.search(block)
    signal_match = _SIGNAL_RE.search(block)
    ssid_match = _SSID_RE.search(block)
    frequency = int(frequency_match.group(1)) if frequency_match else None
    security_markers = []
    if re.search(r"^\s*RSN:", block, re.MULTILINE):
        security_markers.append("RSN")
    if re.search(r"^\s*WPA:", block, re.MULTILINE):
        security_markers.append("WPA")
    if security_markers:
        security = "/".join(security_markers) + " advertised"
    elif re.search(r"^\s*capability:.*\bPrivacy\b", block, re.MULTILINE):
        security = "legacy privacy advertised"
    else:
        security = "no encryption advertised"
    return AccessPoint(
        ssid=ssid_match.group(1) if ssid_match else "",
        bssid=bss.group(1).lower(),
        frequency_mhz=frequency,
        channel=_channel_for_frequency(frequency) if frequency else None,
        signal_dbm=float(signal_match.group(1)) if signal_match else None,
        advertised_security=security,
    )


def parse_scan_output(output: str) -> list[AccessPoint]:
    """Parse `iw dev <interface> scan` output without claiming verification."""
    blocks = re.split(r"(?m)^(?=BSS\s)", output)
    access_points = [_parse_access_point(block) for block in blocks if block.strip()]
    return [access_point for access_point in access_points if access_point is not None]


def scan_networks(
    interface: str,
    timeout: float = 30.0,
    cancel_event: threading.Event | None = None,
) -> list[AccessPoint]:
    """Perform an operator-requested survey on one local wireless interface."""
    if not _INTERFACE_NAME.fullmatch(interface):
        raise ValueError(f"invalid wireless interface name: {interface!r}")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    result = (
        run(["iw", "dev", interface, "scan"], timeout=timeout)
        if cancel_event is None
        else run_cancellable(
            ["iw", "dev", interface, "scan"],
            timeout=timeout,
            cancel_event=cancel_event,
        )
    )
    if not result.ok:
        detail = result.stderr.strip() or "scan command returned a failure status"
        raise RuntimeError(f"Wi-Fi scan failed on {interface}: {detail}")
    return parse_scan_output(result.stdout)


def scan_available_networks(
    timeout: float = 30.0,
    cancel_event: threading.Event | None = None,
) -> tuple[str, list[AccessPoint]]:
    """Survey using the first managed wireless interface reported by `iw`."""
    interfaces = list_wireless_interfaces()
    if not interfaces:
        raise RuntimeError("no wireless interface is reported by iw")
    interface = next(
        (item for item in interfaces if item.interface_type == "managed"),
        interfaces[0],
    ).name
    return interface, scan_networks(
        interface, timeout=timeout, cancel_event=cancel_event
    )


def channel_occupancy(access_points: list[AccessPoint]) -> dict[int, int]:
    """Count observed access points per channel (a survey, not RF utilization)."""
    occupancy: dict[int, int] = {}
    for access_point in access_points:
        if access_point.channel is not None:
            occupancy[access_point.channel] = occupancy.get(access_point.channel, 0) + 1
    return dict(sorted(occupancy.items()))
