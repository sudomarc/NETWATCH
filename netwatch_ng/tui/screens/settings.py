"""Settings screen for validated persistent NETWATCH NG preferences."""

from __future__ import annotations

from netwatch_ng import settings


def build_settings_lines(message: str | None = None) -> list[str]:
    values = settings.load_settings()
    lines = [
        "SETTINGS",
        "",
        "PREFERENCES",
        f"  Automatic refresh: [READY] {'disabled' if values['refresh_seconds'] == 0 else str(values['refresh_seconds']) + ' seconds'}",
        f"  Default scan timeout: [READY] {values['scan_timeout_seconds']} seconds",
        f"  Preferred Wi-Fi interface: [READY] {values['preferred_interface'] or 'automatic'}",
        f"  Color mode: [READY] {values['color_mode']}",
        "",
        "KEYS",
        "  + / -: adjust refresh interval   0: disable it   t: set Nmap timeout.",
        "  i: select a preferred Wi-Fi interface   c: cycle auto/color/mono   r: refresh.",
        "  Settings are stored in the user/system NETWATCH NG configuration directory.",
    ]
    if message:
        lines.extend(["", message])
    return lines
