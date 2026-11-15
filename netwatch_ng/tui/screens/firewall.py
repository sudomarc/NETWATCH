"""Firewall overview based on real NETWATCH-owned rules."""
from __future__ import annotations

from netwatch_ng.firewall import list_netwatch_rules


def build_firewall_lines(message: str | None = None) -> list[str]:
    lines = [
        "FIREWALL MANAGER",
        "",
        "ENGINE",
        "  iptables/ip6tables NETWATCH-owned FORWARD rules.",
        "  Blocking applies to forwarded traffic only; it is not a universal LAN client block.",
        "",
        "RULES",
    ]
    try:
        rules = list_netwatch_rules("inet") + list_netwatch_rules("inet6")
    except Exception as exc:
        return [*lines, f"  [ERROR] firewall state unavailable: {exc}"]
    if not rules:
        lines.append("  [INFO] no NETWATCH-owned firewall rules are currently present.")
        lines.append("  b: block IP   u: unblock IP   r: refresh")
        if message:
            lines.extend(["", message])
        return lines
    lines.append(f"  [ACTIVE] {len(rules)} NETWATCH-owned rule(s):")
    for rule in rules:
        lines.append(
            f"  [{rule.family}]  {rule.chain:<12} source={rule.source or '-':<16} target={rule.target}"
        )
    if message:
        lines.extend(["", message])
    lines.extend(["", "b: block IP   u: unblock IP   r: refresh"])
    return lines
