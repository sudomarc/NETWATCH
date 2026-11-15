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
) -> list[str]:
    try:
        if report is None:
            report = inspect_default_gateway()
    except Exception as exc:
        return [f"ROUTER INTELLIGENCE", "", f"  [ERROR] router inspection failed: {exc}"]

    if report is None:
        return [
            "ROUTER INTELLIGENCE",
            "",
            "GATEWAY",
            "  [DEGRADED] no default IPv4 or IPv6 gateway is configured.",
        ]

    lines = [
        "ROUTER INTELLIGENCE",
        "",
        "GATEWAY",
        f"  Gateway: [READY] {report.gateway} ({report.family})",
        f"  Interface: {report.interface or 'unknown'}",
        f"  Gateway MAC: {report.mac or 'not present in neighbor table'}",
    ]
    if report.manufacturer:
        lines.append(
            f"  Manufacturer hint: {report.manufacturer} "
            "(local OUI match; model/firmware unverified)"
        )
    else:
        lines.append("  Manufacturer hint: unavailable (no local OUI match)")
    lines.append(f"  Local interface addresses: {', '.join(report.local_addresses) or 'unavailable'}")
    lines.append("")
    lines.append("MANAGEMENT PORTS")
    if services is None:
        lines.append("  [INFO] press p to check common TCP management ports on this gateway.")
        lines.append("         u: read-only UPnP/SSDP check   r: refresh")
    else:
        lines.append(f"  TCP management port reachability ({len(services)} port(s)):")
        for service in services:
            lines.append(f"    TCP/{service.port} {service.name}: {service.state}")
        lines.append("  These are reachability checks, not service/version verification.")
    if message:
        lines.extend(["", message])
    return lines
