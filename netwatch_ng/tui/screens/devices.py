"""Devices screen.

Sprint 2 scope: passive discovery only (kernel ARP/NDP neighbor table).
Active nmap scans are available in netwatch_ng.discovery.devices.active_scan
but are NOT run automatically here — an active scan touches the network
and should be an explicit operator action, planned for the Settings/
Devices action bar in a later TUI sprint. This screen says so rather
than silently only doing half the job.
"""

from __future__ import annotations

from netwatch_ng.core.shell import which
from netwatch_ng.discovery import devices as devices_mod
from netwatch_ng.discovery import history
from netwatch_ng.system.config import get_config_dir


def build_devices_lines() -> list[str]:
    lines: list[str] = []

    if which("ip") is None:
        return [
            "Devices: 'ip' (iproute2) not installed — cannot read the neighbor table.",
            "See System Manager.",
        ]

    found = devices_mod.passive_scan("inet")

    config_dir = get_config_dir()
    history.save_scan(config_dir, found)
    diff = history.diff_last_two_scans(config_dir)

    lines.append(f"Devices (passive ARP/NDP table scan): {len(found)} found")
    lines.append("(active nmap scan not wired into the TUI yet — see AGENTS.md)")
    lines.append("")
    if not found:
        lines.append("No live neighbor-table entries. Generate traffic (e.g. ping the")
        lines.append("subnet) or wait for ARP cache to populate, then revisit.")
    for d in found:
        hostname = d.hostname.value if d.hostname else "-"
        lines.append(f"  {d.ip:<16} mac={d.mac or '-':<17} vendor={d.describe_vendor():<30} host={hostname}")

    if diff is not None:
        lines.append("")
        lines.append(f"Since last scan — new: {len(diff.new)}  missing: {len(diff.missing)}  reappeared: {len(diff.reappeared)}")
        if diff.new:
            lines.append(f"  new: {', '.join(diff.new)}")
        if diff.missing:
            lines.append(f"  missing: {', '.join(diff.missing)}")
        if diff.reappeared:
            lines.append(f"  reappeared: {', '.join(diff.reappeared)}")

    return lines
