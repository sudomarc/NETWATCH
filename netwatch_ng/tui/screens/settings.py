"""Settings screen for validated persistent NETWATCH NG preferences."""

from __future__ import annotations

from netwatch_ng import settings


def build_settings_lines(message: str | None = None) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    values = settings.load_settings()
    refresh_val = "disabled" if values["refresh_seconds"] == 0 else f"{values['refresh_seconds']} seconds"
    lines = [
        "SETTINGS",
        "",
        "PREFERENCES",
        ("TABLE", ["Setting", "Value"], [
            ["Automatic refresh", f"[READY] {refresh_val}"],
            ["Default scan timeout", f"[READY] {values['scan_timeout_seconds']} seconds"],
            ["Preferred Wi-Fi interface", f"[READY] {values['preferred_interface'] or 'automatic'}"],
            ["Color mode", f"[READY] {values['color_mode']}"],
        ]),
        "",
        "KEYS",
        ("TABLE", ["Key", "Action"], [
            ["+ / -", "adjust refresh interval"],
            ["0", "disable refresh"],
            ["t", "set Nmap timeout"],
            ["i", "select a preferred Wi-Fi interface"],
            ["c", "cycle auto/color/mono"],
            ["r", "refresh"],
        ]),
        ("TABLE", ["Note", "Detail"], [
            ["Storage", "Settings are stored in the user/system NETWATCH NG configuration directory."],
        ]),
    ]
    if message:
        lines.extend(["", message])
    return lines