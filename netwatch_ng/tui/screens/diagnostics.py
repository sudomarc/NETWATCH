"""Network diagnostics overview and real result rendering."""
from __future__ import annotations

from netwatch_ng.core import network
from netwatch_ng.diagnostics import DiagnosticResult


def build_diagnostics_lines(
    result: DiagnosticResult | None = None,
    message: str | None = None,
) -> list[str]:
    lines = ["NETWORK DIAGNOSTICS"]
    try:
        route = network.get_default_gateway("inet") or network.get_default_gateway("inet6")
    except Exception as exc:
        route = None
        lines.append("")
        lines.append("GATEWAY")
        lines.append(f"  [ERROR] gateway inspection failed: {exc}")
    if route is None:
        lines.append("")
        lines.append("GATEWAY")
        lines.append("  [DEGRADED] default gateway: unavailable")
    else:
        lines.append("")
        lines.append("GATEWAY")
        lines.append(f"  Default gateway: [READY] {route.gateway or 'unknown'} via {route.device or 'unknown'}")
    dns = network.get_dns_servers()
    lines.append("")
    lines.append("DNS")
    lines.append(f"  Configured DNS: {', '.join(dns) if dns else 'not found in resolv.conf'}")
    lines.extend([
        "",
        "ACTIONS",
        "  p ping the default gateway   t trace a route to a host/IP   d look up DNS for a hostname   r refresh",
    ])
    if result is not None:
        lines.extend(["", f"{result.name}: {result.summary}"])
        if result.details:
            lines.extend(result.details.splitlines()[:12])
    if message:
        lines.extend(["", message])
    return lines
