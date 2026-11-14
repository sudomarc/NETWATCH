"""Read-only Reset Manager preview screen."""
from __future__ import annotations

from netwatch_ng.reset_manager import preview_all


def build_reset_lines(message: str | None = None) -> list[str]:
    """Render a read-only preview; mutations require an explicit TUI action."""
    report = preview_all()
    lines = ["Reset Manager", "Read-only preview — no changes have been made."]
    total = len(report.firewall_actions) + len(report.traffic_actions)
    if total == 0:
        lines.append("No NETWATCH-owned firewall rules or traffic limits were detected.")
    else:
        lines.append(f"Resources/actions found: {total}")
        for action in report.firewall_actions:
            if action.target == "unavailable":
                lines.append(f"  firewall preview unavailable: {action.detail}")
            else:
                lines.append(f"  firewall: {action.target} (requires confirmation)")
        for action in report.traffic_actions:
            if action.target == "unavailable":
                lines.append(f"  traffic preview unavailable: {action.detail}")
            else:
                lines.append(f"  traffic: {action.target} (requires confirmation)")
    if message:
        lines.extend(["", message])
    lines.extend(["", "Press x to review and confirm a reset."])
    return lines
