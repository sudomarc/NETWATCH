"""Settings screen for validated persistent NETWATCH NG preferences."""
from __future__ import annotations

from netwatch_ng import settings


def build_settings_lines(message: str | None = None) -> list[str]:
    values = settings.load_settings()
    lines = [
        "Settings",
        f"Automatic refresh: {'disabled' if values['refresh_seconds'] == 0 else str(values['refresh_seconds']) + ' seconds'}",
        f"Default scan timeout: {values['scan_timeout_seconds']} seconds",
        f"Preferred interface: {values['preferred_interface'] or 'automatic'}",
        f"Color mode: {values['color_mode']}",
        "",
        "Keys: + increase refresh interval, - decrease, 0 disable automatic refresh.",
        "Settings are stored in the user/system NETWATCH NG configuration directory.",
    ]
    if message:
        lines.extend(["", message])
    return lines
