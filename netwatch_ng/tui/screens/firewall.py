"""Firewall overview based on real NETWATCH-owned rules."""
from __future__ import annotations

from netwatch_ng.firewall import list_netwatch_rules


def build_firewall_lines(message: str | None = None) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines = [
        "FIREWALL MANAGER",
        "",
        "ENGINE",
        ("TABLE", ["Item", "Detail"], [
            ["Backend", "iptables/ip6tables NETWATCH-owned FORWARD rules."],
            ["Scope", "Blocking applies to forwarded traffic only; not a universal LAN client block."],
        ]),
        "",
        "RULES",
    ]
    try:
        rules = list_netwatch_rules("inet") + list_netwatch_rules("inet6")
    except Exception as exc:
        return [*lines, ("TABLE", ["Error", "Detail"], [
            ["Firewall state", f"unavailable: {exc}"],
        ])]
    if not rules:
        lines.append("  [INFO] no NETWATCH-owned firewall rules are currently present.")
        lines.append("  b: block IP   u: unblock IP   r: refresh")
        if message:
            lines.extend(["", message])
        return lines
    rule_rows = []
    for rule in rules:
        rule_rows.append([
            f"[{rule.family}]",
            rule.chain,
            rule.source or "-",
            rule.target,
        ])
    lines.append(
        ("TABLE", ["Family", "Chain", "Source", "Target"], rule_rows, [10, 12, 18, 12])
    )
    lines.append(f"  [ACTIVE] {len(rules)} NETWATCH-owned rule(s):")
    if message:
        lines.extend(["", message])
    lines.extend(["", "b: block IP   u: unblock IP   r: refresh"])
    return lines