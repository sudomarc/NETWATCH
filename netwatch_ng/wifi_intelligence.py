"""Linux Wi-Fi inventory and operator-triggered survey via the Aircrack-ng suite.

This module replaces the previous iw/rfkill-based implementation:

* interface detection and monitor-mode handling rely on ``airmon-ng``;
* access-point and station discovery rely on ``airodump-ng`` in CSV output
  mode, run for a bounded operator-controlled duration.

The perimeter is interface management and passive Wi-Fi discovery only:
no key is cracked, no frame is injected and no station is deauthenticated.
``airmon-ng check kill`` is never run automatically, as it can interrupt the
machine's connectivity.
"""

from __future__ import annotations

import csv
import io
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from netwatch_ng.core import network
from netwatch_ng.core.shell import CommandCancelled, run, run_cancellable

AIRMON_NG = "airmon-ng"
AIRODUMP_NG = "airodump-ng"

_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_PHY_NAME = re.compile(r"^phy\d+$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_AIRMON_TABLE_RE = re.compile(
    r"^(?P<phy>\S+)\s+(?P<interface>\S+)\s+(?P<driver>\S+)\s+(?P<chipset>.*)$"
)
_MONITOR_ENABLED_RE = re.compile(
    r"mac80211 monitor mode vif enabled for \[[^\]]+\](?P<iface>[^\s)]+) "
    r"on \[[^\]]+\](?P<monitor>[^\s)]+)"
)
_MONITOR_ALREADY_RE = re.compile(
    r"mac80211 monitor mode already enabled for \[[^\]]+\](?P<iface>[^\s)]+) "
    r"on \[[^\]]+\](?P<monitor>[^\s)]+)"
)
_MONITOR_DISABLED_RE = re.compile(r"mac80211 monitor mode vif disabled for")

# nl80211 interface types exposed through /sys/class/net/<interface>/type.
_TYPE_MANAGED = "1"
_TYPE_MONITOR = "803"

_SYS_CLASS_NET = Path("/sys/class/net")


@dataclass
class WirelessInterface:
    """A wireless interface as reported by airmon-ng plus kernel state."""

    name: str
    phy: str | None
    driver: str | None
    chipset: str | None
    mode: str  # "managed", "monitor" or "unknown"
    mac: str | None


@dataclass
class RadioState:
    """Aggregate Wi-Fi radio block state.

    Aircrack-ng does not report rfkill soft/hard block state, so both fields
    are ``None`` (information not available via this engine). Consult rfkill
    directly for this state.
    """

    soft_blocked: bool | None
    hard_blocked: bool | None


@dataclass
class AccessPoint:
    """An access point observed by airodump-ng."""

    ssid: str
    bssid: str
    frequency_mhz: int | None
    channel: int | None
    signal_dbm: float | None
    advertised_security: str


@dataclass
class Station:
    """A client station observed by airodump-ng."""

    bssid: str  # associated AP BSSID, or "(not associated)"
    station: str
    signal_dbm: float | None
    rate: str | None
    lost: int | None
    frames: int | None
    probes: str | None


@dataclass
class WifiSurvey:
    """Result of one operator-triggered airodump-ng survey."""

    interface: str
    access_points: list[AccessPoint]
    stations: list[Station]


def _interface_property(interface: str, file_name: str) -> str | None:
    """Read a /sys/class/net/<interface> attribute without ever crashing."""
    try:
        value = (
            (_SYS_CLASS_NET / interface / file_name)
            .read_text(encoding="ascii", errors="replace")
            .strip()
        )
    except OSError:
        return None
    return value or None


def _interface_mode(interface: str) -> str:
    """Current interface type read from kernel state (not from iw)."""
    raw = _interface_property(interface, "type")
    if raw == _TYPE_MONITOR:
        return "monitor"
    if raw == _TYPE_MANAGED:
        return "managed"
    if raw is not None:
        return f"unknown ({raw})"
    return "unknown"


def _interface_mac(interface: str) -> str | None:
    return _interface_property(interface, "address")


def _default_route_interfaces() -> set[str]:
    """Interfaces currently carrying an IPv4/IPv6 default route.

    These are the links the machine is actually using for connectivity, so a
    survey that forces one of them into monitor mode will drop that
    connectivity. The set is best-effort: a missing ``ip`` binary yields an
    empty set rather than an error.
    """
    devices: set[str] = set()
    for family in ("inet", "inet6"):
        try:
            route = network.get_default_gateway(family)
        except Exception:
            continue
        if route is not None and route.device:
            devices.add(route.device)
    return devices


def list_wireless_interfaces() -> list[WirelessInterface]:
    """Return wireless interfaces reported by ``airmon-ng``.

    ``airmon-ng`` requires root privileges; without them it exits with a
    permission error that is surfaced explicitly. Interface modes come from
    kernel state (``/sys/class/net/<iface>/type``), not from iw.
    """
    result = run([AIRMON_NG], timeout=10.0)
    if not result.ok:
        detail = (
            result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        )
        raise RuntimeError(f"airmon-ng failed: {detail}")

    interfaces: list[WirelessInterface] = []
    for line in result.stdout.splitlines():
        match = _AIRMON_TABLE_RE.match(line)
        if not match:
            continue
        name = match.group("interface")
        if name in ("Interface", "") or match.group("phy") in ("PHY", ""):
            continue  # header line
        interfaces.append(
            WirelessInterface(
                name=name,
                phy=match.group("phy") or None,
                driver=match.group("driver") or None,
                chipset=(match.group("chipset") or "").strip() or None,
                mode=_interface_mode(name),
                mac=_interface_mac(name),
            )
        )
    return interfaces


def get_radio_state() -> RadioState:
    """Return the radio block state.

    Aircrack-ng does not expose rfkill soft/hard block state; both fields are
    ``None``. This is deliberate: the engine does not silently fall back to
    rfkill. Operators who need block state should consult rfkill directly.
    """
    return RadioState(soft_blocked=None, hard_blocked=None)


def get_supported_modes(phy: str) -> list[str]:
    """Return the interface modes supported on one PHY.

    Aircrack-ng has no equivalent of ``iw phy <phy> info``; the list of
    supported modes is not available via this engine and is reported as such
    (empty list) rather than faked. The PHY name is still validated so an
    operator cannot inject shell metacharacters through this entry point.
    """
    if not isinstance(phy, str) or not _PHY_NAME.fullmatch(phy):
        raise ValueError(f"invalid wireless PHY name: {phy!r}")
    return []


def start_monitor_mode(interface: str, channel: int | None = None) -> str:
    """Put an interface in monitor mode with ``airmon-ng start``.

    Returns the name of the monitor interface created (for example
    ``wlan0mon``), parsed from the real ``airmon-ng`` output.

    This is an explicit operator action: it can interrupt the active Wi-Fi
    connection of the interface. ``airmon-ng check kill`` is never run.
    """
    if not _INTERFACE_NAME.fullmatch(interface):
        raise ValueError(f"invalid wireless interface name: {interface!r}")
    argv = [AIRMON_NG, "start", interface]
    if channel is not None:
        if not isinstance(channel, int) or channel <= 0:
            raise ValueError("channel must be a positive integer")
        argv.append(str(channel))
    result = run(argv, timeout=20.0)
    output = result.stdout + "\n" + result.stderr
    match = _MONITOR_ENABLED_RE.search(output) or _MONITOR_ALREADY_RE.search(output)
    if match:
        return match.group("monitor")
    detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
    raise RuntimeError(f"could not enable monitor mode on {interface}: {detail}")


def stop_monitor_mode(interface: str) -> None:
    """Stop monitor mode on an interface with ``airmon-ng stop``.

    The monitor virtual interface is removed and the underlying interface is
    restored to managed mode when the driver supports it.
    """
    if not _INTERFACE_NAME.fullmatch(interface):
        raise ValueError(f"invalid wireless interface name: {interface!r}")
    result = run([AIRMON_NG, "stop", interface], timeout=20.0)
    output = result.stdout + "\n" + result.stderr
    if result.returncode == 0 and _MONITOR_DISABLED_RE.search(output):
        return
    detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
    raise RuntimeError(f"could not stop monitor mode on {interface}: {detail}")


def _frequency_for_channel(channel: int) -> int | None:
    """Derive the center frequency (MHz) from a 2.4 GHz / 5 GHz channel number.

    airodump-ng's CSV does not carry the band, so 6 GHz channels overlap with
    2.4 GHz channel numbers and cannot be disambiguated: they are reported as
    unavailable here.
    """
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel == 14:
        return 2484
    if 34 <= channel <= 165:
        return 5000 + channel * 5
    return None


def _security_label(enc: str, cipher: str, auth: str) -> str:
    """Build a human security label from airodump-ng ENC/CIPHER/AUTH fields."""
    enc = (enc or "").strip().upper()
    cipher = (cipher or "").strip()
    auth = (auth or "").strip()
    extras = [part for part in (cipher, auth) if part and part not in ("-", "OPN")]
    if not enc or enc in ("-", "OPN"):
        return "Open" if not extras else f"Open ({' / '.join(extras)})"
    if enc == "WEP":
        return "WEP" if not extras else f"WEP ({' / '.join(extras)})"
    label = enc
    if extras:
        label += f" ({' / '.join(extras)})"
    return label


def _parse_access_point_row(row: list[str]) -> AccessPoint | None:
    if len(row) < 11:
        return None
    bssid = row[0].strip()
    if not _MAC_RE.match(bssid):
        return None
    channel_raw = row[5].strip() if len(row) > 5 else ""
    try:
        channel = int(channel_raw) if channel_raw and channel_raw != "-1" else None
    except ValueError:
        channel = None
    signal_raw = row[1].strip() if len(row) > 1 else ""
    try:
        signal = float(signal_raw) if signal_raw and signal_raw != "-1" else None
    except ValueError:
        signal = None
    essid = row[10].strip() if len(row) > 10 else ""
    enc = row[7].strip() if len(row) > 7 else ""
    cipher = row[8].strip() if len(row) > 8 else ""
    auth = row[9].strip() if len(row) > 9 else ""
    frequency = _frequency_for_channel(channel) if channel is not None else None
    return AccessPoint(
        ssid=essid,
        bssid=bssid.lower(),
        frequency_mhz=frequency,
        channel=channel,
        signal_dbm=signal,
        advertised_security=_security_label(enc, cipher, auth),
    )


def _parse_station_row(row: list[str]) -> Station | None:
    if len(row) < 7:
        return None
    station = row[1].strip()
    if not _MAC_RE.match(station):
        return None
    bssid = row[0].strip()
    signal_raw = row[2].strip() if len(row) > 2 else ""
    try:
        signal = float(signal_raw) if signal_raw and signal_raw != "-1" else None
    except ValueError:
        signal = None
    rate = row[3].strip() if len(row) > 3 else "" or None
    lost_raw = row[4].strip() if len(row) > 4 else ""
    try:
        lost = int(lost_raw) if lost_raw else None
    except ValueError:
        lost = None
    frames_raw = row[5].strip() if len(row) > 5 else ""
    try:
        frames = int(frames_raw) if frames_raw else None
    except ValueError:
        frames = None
    probes = row[6].strip() if len(row) > 6 else "" or None
    return Station(
        bssid=bssid or "(not associated)",
        station=station.lower(),
        signal_dbm=signal,
        rate=rate,
        lost=lost,
        frames=frames,
        probes=probes,
    )


def parse_airodump_csv(
    text: str,
) -> tuple[list[AccessPoint], list[Station]]:
    """Parse ``airodump-ng --output-format csv`` output without claiming verification.

    The output holds an access-point section (header ``BSSID, PWR, ... ESSID``)
    followed by a station section (header ``BSSID, STATION, ...``). Malformed
    rows are skipped; the parse never crashes on unexpected input.
    """
    access_points: list[AccessPoint] = []
    stations: list[Station] = []
    section: str | None = None
    for row in csv.reader(io.StringIO(text)):
        if not row or all(not cell.strip() for cell in row):
            continue
        first = row[0].strip()
        second = row[1].strip() if len(row) > 1 else ""
        if first == "BSSID" and second == "PWR":
            section = "access_points"
            continue
        if first == "BSSID" and second == "STATION":
            section = "stations"
            continue
        if section == "access_points":
            point = _parse_access_point_row(row)
            if point is not None:
                access_points.append(point)
        elif section == "stations":
            station = _parse_station_row(row)
            if station is not None:
                stations.append(station)
    return access_points, stations


def _read_latest_airodump_csv(directory: str, prefix: str = "scan-") -> str:
    """Return the text of the most recent airodump-ng CSV file, or ``""``.

    "Most recent" is decided by modification time, not by name: airodump-ng
    keeps updating its single ``scan-01.csv`` in place, and a name-based sort
    would also order ``scan-10.csv`` before ``scan-2.csv``.
    """
    candidates = list(Path(directory).glob(f"{prefix}*.csv"))
    if not candidates:
        return ""
    newest = max(candidates, key=lambda path: path.stat().st_mtime)
    return newest.read_text(encoding="utf-8", errors="replace")


def scan_networks(
    interface: str,
    timeout: float = 30.0,
    cancel_event: threading.Event | None = None,
) -> WifiSurvey:
    """Passively survey one interface with ``airodump-ng`` in CSV mode.

    ``airodump-ng`` captures until it is stopped, so the operator timeout (or
    cancellation) ends the capture normally: partial CSV output written before
    the stop is parsed and returned. A positive exit code (for example missing
    root privileges) is a real failure.
    """
    if not _INTERFACE_NAME.fullmatch(interface):
        raise ValueError(f"invalid wireless interface name: {interface!r}")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    # airodump-ng forces its interface into monitor mode, which drops any
    # connection that interface is carrying. Refuse to do that implicitly to
    # the adapter holding the machine's default route: the operator must put a
    # dedicated adapter in monitor mode first (airmon-ng start, or the TUI's
    # explicit 'm' action) so connectivity is never lost by accident.
    if _interface_mode(interface) != "monitor" and interface in _default_route_interfaces():
        raise RuntimeError(
            f"refusing to survey {interface}: it carries the machine's default "
            "route, so forcing monitor mode would drop the active connection. "
            "Use a dedicated adapter already in monitor mode (airmon-ng start "
            f"{interface}, or press m on the Wi-Fi screen) and survey that one."
        )

    with tempfile.TemporaryDirectory(prefix="netwatch-ng-airodump-") as directory:
        prefix = str(Path(directory) / "scan")
        argv = [
            AIRODUMP_NG,
            "--output-format",
            "csv",
            "--write-interval",
            "1",
            "--write",
            prefix,
            interface,
        ]
        result = None
        try:
            result = run_cancellable(argv, timeout=timeout, cancel_event=cancel_event)
        except subprocess.TimeoutExpired:
            # airodump-ng runs until stopped: a timeout is a normal stop.
            result = None
        except CommandCancelled:
            # Operator cancellation: parse whatever was written before the stop.
            result = None

        if result is not None and result.returncode > 0:
            detail = (
                result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
            )
            raise RuntimeError(f"airodump-ng survey failed on {interface}: {detail}")

        text = _read_latest_airodump_csv(directory)
        access_points, stations = parse_airodump_csv(text)
        return WifiSurvey(
            interface=interface, access_points=access_points, stations=stations
        )


def scan_available_networks(
    timeout: float = 30.0,
    cancel_event: threading.Event | None = None,
) -> WifiSurvey:
    """Survey a wireless interface reported by ``airmon-ng``.

    An interface already in monitor mode is preferred, because surveying it
    does not disturb the machine's connectivity. Falling back to a managed
    interface is allowed only when it is not carrying the default route;
    otherwise :func:`scan_networks` refuses the survey rather than dropping
    the active connection.
    """
    interfaces = list_wireless_interfaces()
    if not interfaces:
        raise RuntimeError("no wireless interface is detected by airmon-ng")
    for interface in interfaces:
        if interface.mode == "monitor":
            return scan_networks(interface.name, timeout=timeout, cancel_event=cancel_event)
    default_route = _default_route_interfaces()
    for interface in interfaces:
        if interface.name not in default_route:
            return scan_networks(interface.name, timeout=timeout, cancel_event=cancel_event)
    return scan_networks(interfaces[0].name, timeout=timeout, cancel_event=cancel_event)


def channel_occupancy(access_points: list[AccessPoint]) -> dict[int, int]:
    """Count observed access points per channel (a survey, not RF utilization)."""
    occupancy: dict[int, int] = {}
    for access_point in access_points:
        if access_point.channel is not None:
            occupancy[access_point.channel] = occupancy.get(access_point.channel, 0) + 1
    return dict(sorted(occupancy.items()))
