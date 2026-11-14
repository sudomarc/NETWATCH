"""Traffic Manager overview for NETWATCH-owned packet policers."""
from __future__ import annotations

from netwatch_ng.traffic import list_limits


def build_traffic_lines(message: str | None = None) -> list[str]:
    lines = [
        "Traffic Manager",
        "Backend: tc clsact packet policing (excess packets are dropped).",
        "This is not smooth queue-based HTB shaping.",
    ]
    try:
        limits = list_limits()
    except Exception as exc:
        return [*lines, f"Traffic state unavailable: {exc}"]
    if not limits:
        lines.append("No NETWATCH-owned rate policers are currently active.")
        lines.append("Use l to add a limit or c to clear a NETWATCH limit.")
        if message:
            lines.extend(["", message])
        return lines
    lines.append("Active NETWATCH rate policers:")
    for limit in limits:
        lines.append(f"  {limit.interface} {limit.direction}: {limit.rate_kbps} kbit/s")
    if message:
        lines.extend(["", message])
    lines.extend(["", "l: add rate limit   c: clear rate limit"])
    return lines
