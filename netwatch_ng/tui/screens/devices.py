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


def build_devices_lines(active_devices=None, message: str | None = None) -> list[str]:
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

    display_devices = active_devices if active_devices is not None else found
    mode = "active Nmap + neighbor discovery" if active_devices is not None else "passive ARP/NDP neighbor table"
    lines.append(f"Devices ({mode}): {len(display_devices)} found")
    if active_devices is None:
        lines.append("Press n to run an explicit Nmap discovery scan.")
    lines.append("")
    if not found:
        lines.append("No live neighbor-table entries. Generate traffic (e.g. ping the")
        lines.append("subnet) or wait for ARP cache to populate, then revisit.")
    for d in display_devices:
        hostname = d.hostname.value if d.hostname else "-"
        ports = ",".join(str(port) for port in d.open_ports) or "-"
        services = ",".join(d.services) or "-"
        lines.append(
            f"  {d.ip:<16} mac={d.mac or '-':<17} vendor={d.describe_vendor():<30} host={hostname}"
        )
        if active_devices is not None:
            lines.append(f"    open ports={ports} services={services}")
            if d.hostname:
                lines.append(f"    hostname source={d.hostname.source} confidence={d.hostname.confidence.value}")
            if d.vendor:
                lines.append(f"    vendor source={d.vendor.source} confidence={d.vendor.confidence.value}")

    if diff is not None:
        lines.append("")
        lines.append(f"Since last scan — new: {len(diff.new)}  missing: {len(diff.missing)}  reappeared: {len(diff.reappeared)}")
        if diff.new:
            lines.append(f"  new: {', '.join(diff.new)}")
        if diff.missing:
            lines.append(f"  missing: {', '.join(diff.missing)}")
        if diff.reappeared:
            lines.append(f"  reappeared: {', '.join(diff.reappeared)}")

    if message:
        lines.extend(["", message])
    return lines
