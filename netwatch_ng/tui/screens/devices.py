"""Devices screen for passive inventory and automatic Nmap discovery + service scan."""

from __future__ import annotations

from netwatch_ng.core.shell import which
from netwatch_ng.discovery import devices as devices_mod
from netwatch_ng.discovery import history
from netwatch_ng.system.config import get_config_dir


def build_devices_lines(active_devices=None, message: str | None = None) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines: list = []

    if which("ip") is None:
        return [
            "DEVICES",
            "",
            "ENGINE",
            ("TABLE", ["Issue", "Detail"], [
                ["'ip' (iproute2)", "not installed — cannot read the neighbor table."],
                ["Action", "See System Manager."],
            ]),
        ]

    found = devices_mod.passive_scan("inet")

    config_dir = get_config_dir()
    history_warning: str | None = None
    try:
        history.save_scan(config_dir, found)
        diff = history.diff_last_two_scans(config_dir)
    except Exception as exc:
        # A failing history cache must not take down the whole screen;
        # the operator still sees the live inventory plus this notice.
        diff = None
        history_warning = f"Scan history unavailable: {exc}"

    display_devices = active_devices if active_devices is not None else found
    mode = "active Nmap + neighbor discovery" if active_devices is not None else "passive ARP/NDP neighbor table"
    lines.append("DEVICES")
    lines.append("")
    lines.append("INVENTORY")
    lines.append(
        ("TABLE", ["Field", "Value"], [
            ["Mode", mode],
            ["Devices detected", f"[READY] {len(display_devices)}"],
        ])
    )
    if active_devices is None:
        lines.append("  n: active Nmap discovery   v: service/version scan for one host")
        lines.append("  e: export current inventory to JSON or CSV   r: refresh")
    lines.append("")

    if not display_devices:
        lines.append("  [DEGRADED] no live neighbor-table entries.")
        lines.append("     Generate traffic (e.g. ping the subnet) or wait for the ARP cache")
        lines.append("     to populate, then revisit.")
    else:
        device_rows = []
        for d in display_devices:
            hostname = d.hostname.value if d.hostname else "-"
            ports = ",".join(str(port) for port in d.open_ports) or "-"
            services = ",".join(d.services) or "-"
            device_rows.append([
                d.ip,
                d.mac or "-",
                d.describe_vendor(),
                hostname,
                ports,
                services,
            ])
        lines.append(
            (
                "TABLE",
                ["IP", "MAC", "Vendor", "Hostname", "Open ports", "Services"],
                device_rows,
                [16, 18, 24, 20, 12, 12],
            )
        )
        if active_devices is not None:
            for d in display_devices:
                if d.hostname:
                    lines.append(
                        f"    {d.ip}: hostname source={d.hostname.source} confidence={d.hostname.confidence.value}"
                    )
                if d.vendor:
                    lines.append(
                        f"    {d.ip}: vendor source={d.vendor.source} confidence={d.vendor.confidence.value}"
                    )

    if diff is not None:
        lines.append("")
        lines.append("DETECTION DELTA")
        lines.append(
            ("TABLE", ["Change", "Count"], [
                ["New", f"[READY] {len(diff.new)}"],
                ["Missing", f"[WARNING] {len(diff.missing)}"],
                ["Reappeared", f"[INFO] {len(diff.reappeared)}"],
            ])
        )
        if diff.new:
            lines.append(f"  new: {', '.join(diff.new)}")
        if diff.missing:
            lines.append(f"  missing: {', '.join(diff.missing)}")
        if diff.reappeared:
            lines.append(f"  reappeared: {', '.join(diff.reappeared)}")

    if history_warning:
        lines.append("")
        lines.append(f"  [WARNING] {history_warning}")

    if message:
        lines.extend(["", message])
    return lines