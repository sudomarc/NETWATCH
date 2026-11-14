"""System Manager screen: dependency detection, config dir, version info."""

from __future__ import annotations

from netwatch_ng import __version__
from netwatch_ng.system import config, deps


def build_system_manager_lines() -> list[str]:
    lines: list[str] = []
    lines.append(f"NETWATCH NG version: {__version__}")
    lines.append(f"Running as root: {'yes' if config.is_root() else 'no'}")

    try:
        cfg_dir = config.get_config_dir()
        lines.append(f"Config/state directory: {cfg_dir}")
    except config.UnsafeConfigDir as exc:
        lines.append(f"Config/state directory: REJECTED — {exc}")

    lines.append("")
    lines.append("Dependencies:")
    for status in deps.check_all():
        mark = "OK " if status.installed else "-- "
        req = "mandatory" if status.dependency.mandatory else "optional"
        lines.append(
            f"  [{mark}] {status.dependency.binary:<14} ({req:<9}) "
            f"used by: {status.dependency.required_by}"
        )
    return lines
