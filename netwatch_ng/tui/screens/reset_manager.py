"""Read-only Reset Manager preview screen."""
from __future__ import annotations

from netwatch_ng.reset_manager import preview_all


def build_reset_lines(message: str | None = None) -> list[str]:
    """Render a read-only preview; mutations require an explicit TUI action."""
    report = preview_all()
    lines = [
        "RESET MANAGER",
        "",
        "READ-ONLY PREVIEW",
        "  No changes have been made.",
    ]
    total = len(report.firewall_actions) + len(report.traffic_actions)
    lines.append("")
    lines.append("RESOURCES")
    if total == 0:
        lines.append("  [INFO] no NETWATCH-owned firewall rules or traffic limits were detected.")
    else:
        lines.append(f"  [ACTIVE] {total} resource(s) would be removed on confirmation:")
        for action in report.firewall_actions:
            if action.target == "unavailable":
                lines.append(f"  [ERROR] firewall preview unavailable: {action.detail}")
            else:
                lines.append(f"  firewall: {action.target}  (pending confirmation)")
        for action in report.traffic_actions:
            if action.target == "unavailable":
                lines.append(f"  [ERROR] traffic preview unavailable: {action.detail}")
            else:
                lines.append(f"  traffic: {action.target}  (pending confirmation)")
    if message:
        lines.extend(["", message])
    lines.extend(["", "x: review and confirm reset   r: refresh"])
    return lines
