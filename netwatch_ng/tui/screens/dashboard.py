"""Dashboard screen: global network state, built only from real data.

Every line here comes from core.interfaces / core.network / system.deps.
Nothing is simulated; if a value can't be determined, we say so instead
of guessing.
"""

from __future__ import annotations

from netwatch_ng.core import interfaces as iface_mod
from netwatch_ng.core import network as net_mod
from netwatch_ng.core.shell import BinaryNotFound
from netwatch_ng.system import deps


def build_dashboard_lines() -> list[str]:
    lines: list[str] = []

    try:
        ifaces = iface_mod.list_interfaces()
    except BinaryNotFound:
        lines.append("Interfaces: 'ip' (iproute2) not installed — cannot read interface state.")
        ifaces = []
    except RuntimeError as exc:
        lines.append(f"Interfaces: error reading state — {exc}")
        ifaces = []

    up_ifaces = [i for i in ifaces if i.is_up]
    lines.append(f"Interfaces detected: {len(ifaces)}  (up: {len(up_ifaces)})")
    for i in ifaces:
        v4 = ", ".join(a.address for a in i.ipv4_addresses) or "-"
        v6 = ", ".join(a.address for a in i.ipv6_addresses) or "-"
        lines.append(f"  [{i.state:<4}] {i.name:<10} mac={i.mac or '-':<17} ipv4={v4} ipv6={v6}")

    try:
        gw4 = net_mod.get_default_gateway("inet")
    except BinaryNotFound:
        gw4 = None
        lines.append("Gateway (IPv4): unavailable ('ip' not installed)")
    if gw4:
        lines.append(f"Gateway (IPv4): {gw4.gateway} via {gw4.device}")
    else:
        lines.append("Gateway (IPv4): none configured")

    dns = net_mod.get_dns_servers()
    lines.append(f"DNS servers: {', '.join(dns) if dns else 'none found in /etc/resolv.conf'}")

    missing = deps.missing_mandatory()
    if missing:
        names = ", ".join(d.binary for d in missing)
        lines.append(f"WARNING: missing mandatory tools: {names} — see System Manager")
    else:
        lines.append("Mandatory tools: all present")

    return lines
