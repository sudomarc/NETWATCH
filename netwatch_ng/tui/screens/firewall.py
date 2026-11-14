"""Firewall management screen based on real NETWATCH-owned rules."""

from __future__ import annotations

from netwatch_ng.firewall import list_netwatch_rules


def build_firewall_lines() -> list[str]:
    lines = ["Firewall Manager"]
    rules = list_netwatch_rules("inet") + list_netwatch_rules("inet6")
    if not rules:
        lines.extend([
            "No NETWATCH-owned firewall rules are currently present.",
            "Use the firewall module API to add an IP block, or inspect the system state.",
        ])
        return lines

    lines.append("NETWATCH-owned rules:")
    for rule in rules:
        lines.append(
            f"  [{rule.family}] {rule.chain:<12} source={rule.source or '-':<16} target={rule.target}"
        )
    return lines
