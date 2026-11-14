"""Reset Manager screen: show what NETWATCH can safely clear."""

from __future__ import annotations

from netwatch_ng.reset_manager import reset_all


def build_reset_lines() -> list[str]:
    report = reset_all()
    lines = ["Reset Manager"]
    if not report.firewall_actions and not report.traffic_actions:
        lines.extend([
            "No NETWATCH-managed firewall rules or tc limits remain to reset.",
            "This safely preserves unrelated system rules and qdiscs.",
        ])
        return lines

    lines.append("Operations that would be removed only if NETWATCH created them:")
    for action in report.firewall_actions:
        lines.append(f"  firewall: {action.target} -> {'ok' if action.success else 'failed'}")
    for action in report.traffic_actions:
        lines.append(f"  traffic: {action.target} -> {'ok' if action.success else 'failed'}")
    return lines
