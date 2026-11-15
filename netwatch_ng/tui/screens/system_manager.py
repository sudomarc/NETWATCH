"""System Manager screen: dependency detection, config dir, version info."""

from __future__ import annotations

from netwatch_ng import __version__
from netwatch_ng.system import config, deps


def build_system_manager_lines() -> list[str]:
    lines: list[str] = []
    lines.append("SYSTEM MANAGER")
    lines.append("")
    lines.append("VERSION")
    lines.append(f"  NETWATCH NG version: {__version__}")
    lines.append("")
    lines.append("RUNTIME")
    lines.append(f"  Running as root: [READY] yes" if config.is_root() else "  Running as root: [DEGRADED] no")

    try:
        cfg_dir = config.get_config_dir()
        lines.append(f"  Config/state directory: {cfg_dir}")
    except config.UnsafeConfigDir as exc:
        lines.append(f"  Config/state directory: [ERROR] REJECTED — {exc}")

    lines.append("")
    lines.append("DEPENDENCIES")
    for status in deps.check_all():
        mark = "[READY]" if status.installed else "[DEGRADED]"
        req = "mandatory" if status.dependency.mandatory else "optional"
        lines.append(
            f"  {mark} {status.dependency.binary:<14} ({req:<9}) "
            f"used by: {status.dependency.required_by}"
        )
    return lines
