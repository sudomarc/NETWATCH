"""Small JSONL activity log with bounded rotation and no secret collection."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_BYTES = 512 * 1024
BACKUPS = 3


def _log_path() -> Path:
    if os.geteuid() == 0:
        return Path("/var/log/netwatch-ng/events.jsonl")
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "netwatch-ng" / "events.jsonl"


def record_event(
    module: str,
    action: str,
    status: str,
    detail: str | None = None,
) -> None:
    """Append a bounded event. Callers must never pass passwords or secrets."""
    if not module or not action or status not in ("info", "success", "warning", "error"):
        raise ValueError("module/action are required and status must be info, success, warning or error")
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750 if os.geteuid() == 0 else 0o700)
    if os.geteuid() == 0:
        st = path.parent.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise PermissionError(f"unsafe activity-log directory: {path.parent}")
    if path.exists() and path.stat().st_size >= MAX_BYTES:
        oldest = path.with_suffix(path.suffix + f".{BACKUPS}")
        try:
            oldest.unlink()
        except FileNotFoundError:
            pass
        for index in range(BACKUPS - 1, 0, -1):
            source = path.with_suffix(path.suffix + f".{index}")
            destination = path.with_suffix(path.suffix + f".{index + 1}")
            if source.exists():
                os.replace(source, destination)
        os.replace(path, path.with_suffix(path.suffix + ".1"))

    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "module": module[:40],
        "action": action[:80],
        "status": status,
    }
    if detail:
        event["detail"] = detail.replace("\r", " ").replace("\n", " ")[:240]
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    fd = os.open(path, flags, 0o640 if os.geteuid() == 0 else 0o600)
    try:
        os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def read_events(limit: int = 30) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be an integer from 1 to 500")
    path = _log_path()
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError as exc:
        raise RuntimeError(f"cannot read activity log {path}: {exc}") from exc
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return list(reversed(events))
