"""Firewall overview based on real NETWATCH-owned rules."""
from __future__ import annotations

from netwatch_ng.firewall import list_netwatch_rules


def build_firewall_lines(message: str | None = None) -> list[str]:
    lines = [
        "Firewall Manager",
        "Current engine: iptables/ip6tables NETWATCH-owned FORWARD rules.",
        "Blocking applies to forwarded traffic; it is not a universal LAN client block.",
    ]
    try:
        rules = list_netwatch_rules("inet") + list_netwatch_rules("inet6")
    except Exception as exc:
        return [*lines, f"Firewall state unavailable: {exc}"]
    if not rules:
        lines.append("No NETWATCH-owned firewall rules are currently present.")
        lines.append("Use b to block or u to unblock a single IP on the forwarding path.")
        if message:
            lines.extend(["", message])
        return lines
    lines.append("NETWATCH-owned rules:")
    for rule in rules:
        lines.append(
            f"  [{rule.family}] {rule.chain:<12} source={rule.source or '-':<16} target={rule.target}"
        )
    if message:
        lines.extend(["", message])
    lines.extend(["", "b: block IP   u: unblock IP"])
    return lines
