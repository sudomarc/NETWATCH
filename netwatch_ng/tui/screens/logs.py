"""Activity log screen."""
from __future__ import annotations

from netwatch_ng.activity_log import read_events


def build_logs_lines() -> list[str]:
    lines = ["Logs", "Recent NETWATCH NG activity (newest first):"]
    try:
        events = read_events(20)
    except Exception as exc:
        return [*lines, f"Log unavailable: {exc}"]
    if not events:
        lines.append("No activity events have been recorded.")
        return lines
    for event in events:
        timestamp = str(event.get("timestamp", "?"))[-14:]
        module = str(event.get("module", "?"))[:12]
        action = str(event.get("action", "?"))[:24]
        status = str(event.get("status", "?"))[:8]
        detail = str(event.get("detail", ""))[:55]
        lines.append(f"{timestamp} [{status:<7}] {module:<12} {action:<24} {detail}")
    return lines
