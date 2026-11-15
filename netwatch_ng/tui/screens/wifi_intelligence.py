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
        return ["  Moteur : Aircrack-ng (airmon-ng / airodump-ng) [READY]"]
    missing = []
    if not airmon:
        missing.append(AIRMON_NG)
    if not airodump:
        missing.append(AIRODUMP_NG)
    return [
        "  Moteur : Aircrack-ng [MISSING]",
        f"  Binaire(s) système absent(s) ou hors PATH : {', '.join(missing)}.",
        "  Installez le paquet système aircrack-ng (par exemple: apt install aircrack-ng).",
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
                f"  [ERROR] Détection des interfaces impossible: {exc}",
                "  airmon-ng est introuvable : installez le paquet système aircrack-ng.",
            ]
        )
        _append_message(lines, message)
        return lines
    except RuntimeError as exc:
        lines.extend(
            [
                "",
                f"  [ERROR] Détection des interfaces impossible: {exc}",
                "  airmon-ng requiert les privilèges root : exécutez NETWATCH en root.",
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
        "(information indisponible via ce moteur; consultez rfkill directement)."
    )

    lines.append("")
    lines.append("SURVEY")
    if access_points is None:
        lines.extend(
            [
                "  [INFO] press s to survey nearby access points (airodump-ng; root required).",
                "  [INFO] press m to start/stop monitor mode on an interface (explicit action,",
                "          confirmation required: the active Wi-Fi connection of that interface",
                "          is interrupted).",
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
        lines.append(f"  Dernière MAJ: {stamp}")
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
