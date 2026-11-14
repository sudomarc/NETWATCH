"""Validated persistent settings for NETWATCH NG."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from netwatch_ng.system.config import get_config_dir

DEFAULTS: dict[str, Any] = {
    "refresh_seconds": 0,
    "scan_timeout_seconds": 60,
    "preferred_interface": None,
    "color_mode": "auto",
}
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class SettingsError(ValueError):
    """Raised when persisted or requested settings are invalid."""


def _settings_path() -> Path:
    return get_config_dir() / "settings.json"


def validate_settings(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SettingsError("settings must be a JSON object")
    unknown = set(value) - set(DEFAULTS)
    if unknown:
        raise SettingsError(f"unknown settings: {', '.join(sorted(unknown))}")
    result = dict(DEFAULTS)
    result.update(value)

    refresh = result["refresh_seconds"]
    if isinstance(refresh, bool) or not isinstance(refresh, int) or refresh not in (0, *range(5, 301, 5)):
        raise SettingsError("refresh_seconds must be 0 (disabled) or a multiple of 5 from 5 to 300")

    timeout = result["scan_timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 10 <= timeout <= 300:
        raise SettingsError("scan_timeout_seconds must be an integer from 10 to 300")

    interface = result["preferred_interface"]
    if interface is not None and (
        not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface)
    ):
        raise SettingsError("preferred_interface must be a valid interface name or null")

    if result["color_mode"] not in ("auto", "color", "mono"):
        raise SettingsError("color_mode must be auto, color or mono")
    return result


def load_settings() -> dict[str, Any]:
    path = _settings_path()
    if not path.exists():
        return dict(DEFAULTS)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError(f"cannot read settings file {path}: {exc}") from exc
    return validate_settings(raw)


def save_settings(value: dict[str, Any]) -> dict[str, Any]:
    validated = validate_settings(value)
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".settings-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(validated, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return validated


def update_setting(key: str, value: Any) -> dict[str, Any]:
    current = load_settings()
    if key not in DEFAULTS:
        raise SettingsError(f"unknown setting: {key}")
    current[key] = value
    return save_settings(current)
