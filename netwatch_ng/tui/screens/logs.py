"""Activity log screen."""
from __future__ import annotations

from netwatch_ng.activity_log import read_events


def build_logs_lines() -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines = ["LOGS", "", "ACTIVITY HISTORY"]
    lines.append(("TABLE", ["Item", "Detail"], [
        ["Source", "Recent NETWATCH NG activity (newest first):"],
    ]))
    try:
        events = read_events(20)
    except Exception as exc:
        return [*lines, ("TABLE", ["Error", "Detail"], [
            ["Log", f"unavailable: {exc}"],
        ])]
    if not events:
        lines.append("  [INFO] no activity events have been recorded.")
        return lines
    log_rows = []
    for event in events:
        timestamp = str(event.get("timestamp", "?"))[-14:]
        module = str(event.get("module", "?"))[:12]
        action = str(event.get("action", "?"))[:24]
        status = str(event.get("status", "?"))[:8]
        detail = str(event.get("detail", ""))[:55]
        log_rows.append([timestamp, f"[{status:<7}]", module, action, detail])
    lines.append(("TABLE", ["Time", "Status", "Module", "Action", "Detail"], log_rows, [14, 10, 12, 24, 55]))
    return lines