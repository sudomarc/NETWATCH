"""Traffic Manager overview for NETWATCH-owned packet policers."""
from __future__ import annotations

from netwatch_ng.traffic import list_limits


def build_traffic_lines(message: str | None = None) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines = [
        "TRAFFIC MANAGER",
        "",
        "ENGINE",
        ("TABLE", ["Item", "Detail"], [
            ["Backend", "tc clsact packet policing (excess packets are dropped)."],
            ["Type", "Not smooth queue-based HTB shaping."],
        ]),
        "",
        "POLICERS",
    ]
    try:
        limits = list_limits()
    except Exception as exc:
        return [*lines, ("TABLE", ["Error", "Detail"], [
            ["Traffic state", f"unavailable: {exc}"],
        ])]
    if not limits:
        lines.append("  [INFO] no NETWATCH-owned rate policers are currently active.")
        lines.append("  l: add rate limit   c: clear rate limit   r: refresh")
        if message:
            lines.extend(["", message])
        return lines
    policer_rows = []
    for limit in limits:
        policer_rows.append([
            limit.interface,
            limit.direction,
            f"{limit.rate_kbps} kbit/s",
        ])
    lines.append(
        ("TABLE", ["Interface", "Direction", "Rate"], policer_rows, [14, 12, 14])
    )
    lines.append(f"  [ACTIVE] {len(limits)} NETWATCH rate policer(s):")
    if message:
        lines.extend(["", message])
    lines.extend(["", "l: add rate limit   c: clear rate limit   r: refresh"])
    return lines