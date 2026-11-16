"""Network diagnostics overview and real result rendering."""
from __future__ import annotations

from netwatch_ng.core import network
from netwatch_ng.diagnostics import DiagnosticResult


def build_diagnostics_lines(
    result: DiagnosticResult | None = None,
    message: str | None = None,
) -> list:
    """Return screen content lines, including table specs.

    A table spec is a tuple: ``("TABLE", headers, rows[, col_widths])``.
    """
    lines = ["NETWORK DIAGNOSTICS"]
    try:
        route = network.get_default_gateway("inet") or network.get_default_gateway("inet6")
    except Exception as exc:
        route = None
        lines.append("")
        lines.append("GATEWAY")
        lines.append(("TABLE", ["Error", "Detail"], [
            ["Gateway inspection", f"failed: {exc}"],
        ]))
    if route is None:
        lines.append("")
        lines.append("GATEWAY")
        lines.append(("TABLE", ["Status", "Detail"], [
            ["[DEGRADED]", "default gateway: unavailable"],
        ]))
    else:
        lines.append("")
        lines.append("GATEWAY")
        lines.append(
            ("TABLE", ["Field", "Value"], [
                ["Default gateway", f"{route.gateway or 'unknown'} via {route.device or 'unknown'}"],
                ["Status", "[READY]"],
            ])
        )
    dns = network.get_dns_servers()
    lines.append("")
    lines.append("DNS")
    lines.append(
        ("TABLE", ["Configured DNS", "Value"], [
            ["resolv.conf", ", ".join(dns) if dns else "not found"],
        ])
    )
    lines.extend([
        "",
        "ACTIONS",
        ("TABLE", ["Key", "Action"], [
            ["p", "ping the default gateway"],
            ["t", "trace a route to a host/IP"],
            ["d", "look up DNS for a hostname"],
            ["r", "refresh"],
        ]),
    ])
    if result is not None:
        lines.extend(["", ("TABLE", ["Result", "Detail"], [
            [result.name, result.summary],
        ])])
        if result.details:
            for detail_line in result.details.splitlines()[:12]:
                lines.append(f"  {detail_line}")
    if message:
        lines.extend(["", message])
    return lines