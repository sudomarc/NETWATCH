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
        return [f"Router inspection failed: {exc}"]

    if report is None:
        return [
            "Router Intelligence",
            "No default IPv4 or IPv6 gateway is configured.",
        ]

    lines = [
        "Router Intelligence (local route and neighbor-table evidence)",
        f"  Gateway: {report.gateway} ({report.family})",
        f"  Interface: {report.interface or 'unknown'}",
        f"  Gateway MAC: {report.mac or 'not present in neighbor table'}",
        (
            f"  Manufacturer hint: {report.manufacturer} "
            "(local OUI match; model/firmware unverified)"
            if report.manufacturer
            else "  Manufacturer hint: unavailable (no local OUI match)"
        ),
        f"  Local interface addresses: {', '.join(report.local_addresses) or 'unavailable'}",
        "  SNMP/UPnP discovery and model/firmware fingerprinting are not implemented.",
        "",
    ]
    if services is None:
        lines.append("Press p to check common TCP management ports on this gateway.")
    else:
        lines.append("Management port reachability (not service/version verification):")
        for service in services:
            lines.append(f"  TCP/{service.port} {service.name}: {service.state}")
    if message:
        lines.extend(["", message])
    return lines
