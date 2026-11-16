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


def _backend_line() -> list:
    airmon = which(AIRMON_NG) is not None
    airodump = which(AIRODUMP_NG) is not None
    if airmon and airodump:
        return [
            ("TABLE", ["Backend", "Status"], [
                ["Aircrack-ng", "[READY] airmon-ng / airodump-ng available"],
            ])
        ]
    missing = []
    if not airmon:
        missing.append(AIRMON_NG)
    if not airodump:
        missing.append(AIRODUMP_NG)
    return [
        ("TABLE", ["Backend", "Status"], [
            ["Aircrack-ng", "[MISSING]"],
        ]),
        f"  Missing system binary(-ies) or not in PATH: {', '.join(missing)}.",
        "  Install the aircrack-ng system package (e.g. apt install aircrack-ng).",
    ]


def _append_message(lines: list, message: str | None) -> None:
    if message:
        lines.extend(["", message])


def build_wifi_lines(
    access_points: list[AccessPoint] | None = None,
    interface_name: str | None = None,
    message: str | None = None,
    stations: list[Station] | None = None,
) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines = ["WI-FI INTELLIGENCE", "", "BACKEND"]
    lines.extend(_backend_line())

    try:
        interfaces = list_wireless_interfaces()
    except BinaryNotFound as exc:
        lines.extend(
            [
                "",
                ("TABLE", ["Error", "Detail"], [
                    ["Interface detection", f"impossible: {exc}"],
                ]),
                "  airmon-ng not found: install the aircrack-ng system package.",
            ]
        )
        _append_message(lines, message)
        return lines
    except RuntimeError as exc:
        lines.extend(
            [
                "",
                ("TABLE", ["Error", "Detail"], [
                    ["Interface detection", f"impossible: {exc}"],
                ]),
                "  airmon-ng requires root privileges: run NETWATCH as root.",
            ]
        )
        _append_message(lines, message)
        return lines

    lines.append("")
    lines.append("WIRELESS INTERFACES")
    if not interfaces:
        lines.append("  [DEGRADED] no wireless interfaces detected by airmon-ng.")
    else:
        iface_rows = []
        for interface in interfaces:
            iface_rows.append([
                interface.name,
                interface.phy or "-",
                interface.mode,
                interface.driver or "-",
                interface.chipset or "-",
                interface.mac or "-",
            ])
        lines.append(
            (
                "TABLE",
                ["Interface", "PHY", "Mode", "Driver", "Chipset", "MAC"],
                iface_rows,
                [12, 8, 10, 12, 16, 18],
            )
        )

    lines.append("")
    lines.append("RADIO STATE")
    lines.append(
        ("TABLE", ["Item", "Detail"], [
            ["rfkill soft/hard block", "not reported by the Aircrack-ng engine (consult rfkill directly)."],
        ])
    )

    lines.append("")
    lines.append("SURVEY")
    if access_points is None:
        lines.extend(
            [
                ("TABLE", ["Action", "Detail"], [
                    ["s", "survey nearby access points (airodump-ng; root required)."],
                    ["m", "start/stop monitor mode on an interface (confirmation required)."],
                    ["r", "refresh."],
                ]),
                "  The survey refuses to use the adapter carrying the default route, so",
                "  your active connection is not dropped: put a dedicated adapter in",
                "  monitor mode first.",
            ]
        )
    else:
        stamp = datetime.now().strftime("%H:%M:%S")
        station_count = len(stations) if stations is not None else 0
        lines.append(
            ("TABLE", ["Survey", "Result"], [
                ["Interface", interface_name or "-"],
                ["Access points", f"[READY] {len(access_points)} AP"],
                ["Stations", f"{station_count} station(s)"],
                ["Last update", stamp],
            ])
        )
        lines.append(
            ("TABLE", ["SSID", "BSSID", "Ch", "Signal", "Security advertised"], [
                [
                    point.ssid or "<hidden>",
                    point.bssid or "-",
                    str(point.channel) if point.channel is not None else "?",
                    f"{point.signal_dbm:.1f} dBm" if point.signal_dbm is not None else "?",
                    point.advertised_security,
                ]
                for point in access_points
            ], [24, 18, 4, 10, 20])
        )
        if stations:
            lines.append("")
            lines.append("Stations detected:")
            station_rows = []
            for station in stations:
                signal = (
                    f"{station.signal_dbm:.1f} dBm"
                    if station.signal_dbm is not None
                    else "?"
                )
                rate = station.rate or "-"
                frames = station.frames if station.frames is not None else "-"
                station_rows.append([
                    station.bssid or "-",
                    station.station or "-",
                    signal,
                    rate,
                    str(frames),
                ])
            lines.append(
                ("TABLE", ["BSSID", "Station", "Signal", "Rate", "Frames"], station_rows, [18, 18, 10, 8, 8])
            )
        occupancy = channel_occupancy(access_points)
        lines.append(
            ("TABLE", ["Channel", "AP count"], [
                [str(channel), str(count)] for channel, count in sorted(occupancy.items())
            ] or [["-", "none"]])
        )
        lines.append("  Channel counts indicate observed APs, not measured RF utilization.")

    if message:
        lines.extend(["", message])
    return lines