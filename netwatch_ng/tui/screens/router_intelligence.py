"""Router Intelligence screen, based on the configured local gateway."""

from __future__ import annotations

from netwatch_ng.router_intelligence import (
    ManagementService,
    RouterReport,
    inspect_default_gateway,
)


def build_router_lines(
    report: RouterReport | None = None,
    services: list[ManagementService] | None = None,
    message: str | None = None,
) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    try:
        if report is None:
            report = inspect_default_gateway()
    except Exception as exc:
        return [
            "ROUTER INTELLIGENCE",
            "",
            ("TABLE", ["Error", "Detail"], [
                ["Router inspection", f"failed: {exc}"],
            ]),
        ]

    if report is None:
        return [
            "ROUTER INTELLIGENCE",
            "",
            "GATEWAY",
            ("TABLE", ["Status", "Detail"], [
                ["[DEGRADED]", "no default IPv4 or IPv6 gateway is configured."],
            ]),
        ]

    lines = [
        "ROUTER INTELLIGENCE",
        "",
        "GATEWAY",
    ]
    gateway_rows = [
        ["Gateway", f"{report.gateway} ({report.family})"],
        ["Interface", report.interface or "unknown"],
        ["Gateway MAC", report.mac or "not present in neighbor table"],
    ]
    if report.manufacturer:
        gateway_rows.append(
            ["Manufacturer hint", f"{report.manufacturer} (local OUI match; model/firmware unverified)"]
        )
    else:
        gateway_rows.append(["Manufacturer hint", "unavailable (no local OUI match)"])
    gateway_rows.append(
        ["Local interface addresses", ", ".join(report.local_addresses) or "unavailable"]
    )
    lines.append(("TABLE", ["Field", "Value"], gateway_rows))

    lines.append("")
    lines.append("MANAGEMENT PORTS")
    if services is None:
        lines.append(
            ("TABLE", ["Action", "Detail"], [
                ["p", "check common TCP management ports on this gateway."],
                ["u", "read-only UPnP/SSDP check."],
                ["r", "refresh."],
            ])
        )
    else:
        port_rows = []
        for service in services:
            port_rows.append([
                f"TCP/{service.port}",
                service.name,
                service.state,
            ])
        lines.append(
            ("TABLE", ["Port", "Service", "State"], port_rows, [10, 20, 10])
        )
        lines.append("  These are reachability checks, not service/version verification.")
    if message:
        lines.extend(["", message])
    return lines