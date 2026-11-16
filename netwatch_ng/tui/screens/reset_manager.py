"""Read-only Reset Manager preview screen."""
from __future__ import annotations

from netwatch_ng.reset_manager import preview_all


def build_reset_lines(message: str | None = None) -> list:
    """Render a read-only preview; mutations require an explicit TUI action.

    Returns screen content lines, including table specs.
    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    report = preview_all()
    lines = [
        "RESET MANAGER",
        "",
        "READ-ONLY PREVIEW",
        ("TABLE", ["Item", "Detail"], [
            ["Changes", "No changes have been made."],
        ]),
    ]
    total = len(report.firewall_actions) + len(report.traffic_actions)
    lines.append("")
    lines.append("RESOURCES")
    if total == 0:
        lines.append("  [INFO] no NETWATCH-owned firewall rules or traffic limits were detected.")
    else:
        lines.append(
            ("TABLE", ["Item", "Count"], [
                ["Resources to remove on confirmation", f"[ACTIVE] {total}"],
            ])
        )
        for action in report.firewall_actions:
            if action.target == "unavailable":
                lines.append(("TABLE", ["Error", "Detail"], [
                    ["firewall preview", action.detail],
                ]))
            else:
                lines.append(
                    ("TABLE", ["Type", "Target", "Status"], [
                        ["firewall", action.target, "(pending confirmation)"],
                    ])
                )
        for action in report.traffic_actions:
            if action.target == "unavailable":
                lines.append(("TABLE", ["Error", "Detail"], [
                    ["traffic preview", action.detail],
                ]))
            else:
                lines.append(
                    ("TABLE", ["Type", "Target", "Status"], [
                        ["traffic", action.target, "(pending confirmation)"],
                    ])
                )
    if message:
        lines.extend(["", message])
    lines.extend(["", "x: review and confirm reset   r: refresh"])
    return lines