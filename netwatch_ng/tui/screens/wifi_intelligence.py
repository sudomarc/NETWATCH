"""Wi-Fi Intelligence screen and operator-triggered survey presentation.

Backed by the Aircrack-ng engine in :mod:`netwatch_ng.wifi_intelligence`
(airmon-ng for interfaces and monitor mode, airodump-ng for the survey).
No simulated data, no fake buttons and no channel-change action are ever
shown: only information the engine can really provide.
"""

from __future__ import annotations

from datetime import datetime

from netwatch_ng.core.shell import BinaryNotFound, which
from netwatch_ng.wifi_intelligence import (
    AccessPoint,
    AIRODUMP_NG,
    AIRMON_NG,
    Station,
    channel_occupancy,
    list_wireless_interfaces,
)


def _backend_line() -> list[str]:
    airmon = which(AIRMON_NG) is not None
    airodump = which(AIRODUMP_NG) is not None
    if airmon and airodump:
        return ["  Engine: Aircrack-ng (airmon-ng / airodump-ng) [READY]"]
    missing = []
    if not airmon:
        missing.append(AIRMON_NG)
    if not airodump:
        missing.append(AIRODUMP_NG)
    return [
        "  Engine: Aircrack-ng [MISSING]",
        f"  Missing system binary(-ies) or not in PATH: {', '.join(missing)}.",
        "  Install the aircrack-ng system package (e.g. apt install aircrack-ng).",
    ]


def build_wifi_lines(
    access_points: list[AccessPoint] | None = None,
    interface_name: str | None = None,
    message: str | None = None,
    stations: list[Station] | None = None,
) -> list[str]:
    lines = ["WI-FI INTELLIGENCE", "", "BACKEND"]
    lines.extend(_backend_line())

    try:
        interfaces = list_wireless_interfaces()
    except BinaryNotFound as exc:
        lines.extend(
            [
                "",
                f"  [ERROR] Interface detection impossible: {exc}",
                "  airmon-ng not found: install the aircrack-ng system package.",
            ]
        )
        _append_message(lines, message)
        return lines
    except RuntimeError as exc:
        lines.extend(
            [
                "",
                f"  [ERROR] Interface detection impossible: {exc}",
                "  airmon-ng requires root privileges: run NETWATCH as root.",
            ]
        )
        _append_message(lines, message)
        return lines

    lines.append("")
    lines.append("WIRELESS INTERFACES")
    if not interfaces:
        lines.append("  [DEGRADED] no wireless interfaces detected by airmon-ng.")
    for interface in interfaces:
        lines.append(
            f"  {interface.name}: phy={interface.phy or '-'} "
            f"mode={interface.mode} driver={interface.driver or '-'} "
            f"chipset={interface.chipset or '-'} mac={interface.mac or '-'}"
        )

    lines.append("")
    lines.append("RADIO STATE")
    lines.append(
        "  rfkill soft/hard block: not reported by the Aircrack-ng engine "
        "(information not available via this engine; consult rfkill directly)."
    )

    lines.append("")
    lines.append("SURVEY")
    if access_points is None:
        lines.extend(
            [
                "  [INFO] press s to survey nearby access points (airodump-ng; root required).",
                "  [INFO] the survey refuses to use the adapter carrying the default route, so",
                "          your active connection is not dropped: put a dedicated adapter in",
                "          monitor mode first.",
                "  [INFO] press m to start/stop monitor mode on an interface (explicit action,",
                "          confirmation required: the active Wi-Fi connection of that interface",
                "          is interrupted; NETWATCH restores it when it exits).",
                "  r: refresh",
            ]
        )
    else:
        stamp = datetime.now().strftime("%H:%M:%S")
        station_count = len(stations) if stations is not None else 0
        lines.append(
            f"  Access points and stations observed via {interface_name or '-'}: "
            f"[READY] {len(access_points)} AP / {station_count} station(s)"
        )
        lines.append(f"  Last update: {stamp}")
        lines.append(
            "  SSID / BSSID                    Ch  Signal   Security advertised"
        )
        for point in access_points:
            ssid = point.ssid or "<hidden>"
            channel = str(point.channel) if point.channel is not None else "?"
            signal = f"{point.signal_dbm:.1f} dBm" if point.signal_dbm is not None else "?"
            lines.append(
                f"  {ssid[:28]:<28} {point.bssid:<17} {channel:>3}  "
                f"{signal:>8}  {point.advertised_security}"
            )
        if stations:
            lines.append("")
            lines.append(
                "  Stations detected (BSSID / Station / Signal / Rate / Frames):"
            )
            for station in stations:
                signal = (
                    f"{station.signal_dbm:.1f} dBm"
                    if station.signal_dbm is not None
                    else "?"
                )
                rate = station.rate or "-"
                frames = station.frames if station.frames is not None else "-"
                lines.append(
                    f"  {station.bssid:<17} {station.station:<17} "
                    f"{signal:>8}  {rate:>5}  {frames}"
                )
        occupancy = channel_occupancy(access_points)
        lines.append(
            "  Observed APs per channel: "
            + (", ".join(f"{channel}: {count}" for channel, count in occupancy.items()) or "none")
        )
        lines.append("  Channel counts indicate observed APs, not measured RF utilization.")

    if message:
        lines.extend(["", message])
    return lines


def _append_message(lines: list[str], message: str | None) -> None:
    if message:
        lines.extend(["", message])
