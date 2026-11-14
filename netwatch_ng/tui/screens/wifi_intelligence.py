"""Wi-Fi Intelligence screen and operator-triggered survey presentation."""

from __future__ import annotations

from netwatch_ng.core.shell import BinaryNotFound
from netwatch_ng.wifi_intelligence import (
    AccessPoint,
    channel_occupancy,
    get_radio_state,
    get_supported_modes,
    list_wireless_interfaces,
)


def build_wifi_lines(
    access_points: list[AccessPoint] | None = None,
    interface_name: str | None = None,
    message: str | None = None,
) -> list[str]:
    try:
        interfaces = list_wireless_interfaces()
    except (BinaryNotFound, RuntimeError) as exc:
        return [f"Wi-Fi inventory unavailable: {exc}", "Check System Manager for dependencies."]

    lines = ["Wi-Fi Intelligence"]
    if not interfaces:
        lines.append("No wireless interfaces are reported by iw.")
    for interface in interfaces:
        channel = (
            f"channel {interface.channel} ({interface.frequency_mhz} MHz)"
            if interface.channel is not None
            else "not associated / channel unknown"
        )
        lines.append(
            f"  {interface.name}: phy={interface.phy or '-'} "
            f"type={interface.interface_type or '-'} mac={interface.mac or '-'} {channel}"
        )
        if interface.phy:
            try:
                modes = get_supported_modes(interface.phy)
                lines.append(f"    Supported modes: {', '.join(modes) or 'not reported'}")
            except (BinaryNotFound, RuntimeError) as exc:
                lines.append(f"    Supported modes unavailable: {exc}")

    try:
        radio = get_radio_state()
        lines.append(
            "  Radio block: "
            f"soft={'blocked' if radio.soft_blocked else 'clear' if radio.soft_blocked is False else 'unknown'}, "
            f"hard={'blocked' if radio.hard_blocked else 'clear' if radio.hard_blocked is False else 'unknown'}"
        )
    except BinaryNotFound:
        lines.append("  Radio block: rfkill is not installed.")
    except RuntimeError as exc:
        lines.append(f"  Radio block status unavailable: {exc}")

    if access_points is None:
        lines.extend(
            [
                "",
                "Press s to survey nearby access points (requires iw scan permission).",
                "Client capture and Aircrack-ng audit actions are not implemented.",
            ]
        )
    else:
        lines.extend(["", f"Access points observed via {interface_name or 'iw'}: {len(access_points)}"])
        lines.append("SSID / BSSID                    Channel  Signal   Security advertised")
        for point in access_points:
            ssid = point.ssid or "<hidden>"
            channel = str(point.channel) if point.channel is not None else "?"
            signal = f"{point.signal_dbm:.1f} dBm" if point.signal_dbm is not None else "?"
            lines.append(
                f"  {ssid[:28]:<28} {point.bssid:<17} {channel:>3}  "
                f"{signal:>8}  {point.advertised_security}"
            )
        occupancy = channel_occupancy(access_points)
        lines.append(
            "Observed APs per channel: "
            + (", ".join(f"{channel}: {count}" for channel, count in occupancy.items()) or "none")
        )
        lines.append("Channel counts indicate observed APs, not measured RF utilization.")
        lines.append("Client capture and Aircrack-ng audit actions are not implemented.")

    if message:
        lines.extend(["", message])
    return lines
