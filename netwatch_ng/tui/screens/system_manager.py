"""System Manager screen: dependency detection, config dir, version info."""

from __future__ import annotations

from netwatch_ng import __version__
from netwatch_ng.system import config, deps


def build_system_manager_lines() -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines: list = []
    lines.append("SYSTEM MANAGER")
    lines.append("")
    lines.append("VERSION")
    lines.append(
        ("TABLE", ["Item", "Value"], [
            ["NETWATCH NG version", __version__],
        ])
    )
    lines.append("")
    lines.append("RUNTIME")
    root_status = "[READY] yes" if config.is_root() else "[DEGRADED] no"
    try:
        cfg_dir = config.get_config_dir()
        cfg_status = str(cfg_dir)
    except config.UnsafeConfigDir as exc:
        cfg_status = f"[ERROR] REJECTED — {exc}"
    lines.append(
        ("TABLE", ["Item", "Value"], [
            ["Running as root", root_status],
            ["Config/state directory", cfg_status],
        ])
    )
    lines.append("")
    lines.append("DEPENDENCIES")
    dep_rows = []
    for status in deps.check_all():
        mark = "[READY]" if status.installed else "[DEGRADED]"
        req = "mandatory" if status.dependency.mandatory else "optional"
        dep_rows.append([
            f"{mark} {status.dependency.binary}",
            req,
            status.dependency.required_by,
        ])
    lines.append(("TABLE", ["Binary", "Type", "Used by"], dep_rows, [20, 12, 24]))
    return lines