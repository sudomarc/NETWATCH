"""Traffic Manager overview for NETWATCH-owned packet policers."""
from __future__ import annotations

from netwatch_ng.traffic import list_limits


def build_traffic_lines(message: str | None = None) -> list[str]:
    lines = [
        "TRAFFIC MANAGER",
        "",
        "ENGINE",
        "  Backend: tc clsact packet policing (excess packets are dropped).",
        "  This is not smooth queue-based HTB shaping.",
        "",
        "POLICERS",
    ]
    try:
        limits = list_limits()
    except Exception as exc:
        return [*lines, f"  [ERROR] traffic state unavailable: {exc}"]
    if not limits:
        lines.append("  [INFO] no NETWATCH-owned rate policers are currently active.")
        lines.append("  l: add rate limit   c: clear rate limit   r: refresh")
        if message:
            lines.extend(["", message])
        return lines
    lines.append(f"  [ACTIVE] {len(limits)} NETWATCH rate policer(s):")
    for limit in limits:
        lines.append(f"  {limit.interface:<12} {limit.direction:<10} {limit.rate_kbps} kbit/s")
    if message:
        lines.extend(["", message])
    lines.extend(["", "l: add rate limit   c: clear rate limit   r: refresh"])
    return lines
