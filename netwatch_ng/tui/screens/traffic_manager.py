"""Traffic Manager screen for egress limits only."""

from __future__ import annotations

from netwatch_ng.traffic import list_limits


def build_traffic_lines() -> list[str]:
    lines = ["Traffic Manager"]
    limits = list_limits()
    if not limits:
        lines.extend([
            "No NETWATCH-managed tc qdisc is currently active.",
            "Ingress IFB shaping is not implemented; only egress rate caps are exposed.",
        ])
        return lines

    lines.append("Active NETWATCH egress limits:")
    for limit in limits:
        lines.append(f"  {limit.interface}: {limit.rate_kbps} kbit/s")
    return lines
