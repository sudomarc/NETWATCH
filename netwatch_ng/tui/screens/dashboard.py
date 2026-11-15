"""Dashboard screen: real-time network supervision center.

Every figure comes from live system state; nothing is simulated. When a
source cannot be determined, the screen says so instead of guessing. The
dashboard is read-only supervision: it displays state and offers a refresh
action only, never configuration.
"""

from __future__ import annotations

from netwatch_ng import activity_log, firewall, traffic
from netwatch_ng.core import interfaces as iface_mod
from netwatch_ng.core import network as net_mod
from netwatch_ng.core.shell import BinaryNotFound
from netwatch_ng.discovery import devices as devices_mod
from netwatch_ng.system import deps

MAX_INTERFACES = 6
MAX_EVENTS = 5


def _count_firewall_rules() -> int | None:
    """Return the number of NETWATCH-owned rules, or None when unavailable."""
    try:
        rules = []
        for family in ("inet", "inet6"):
            rules.extend(firewall.list_netwatch_rules(family))
        return len(rules)
    except Exception:
        return None


def _count_traffic_policers() -> int | None:
    """Return the number of active NETWATCH traffic policers, or None."""
    try:
        return len(traffic.list_limits())
    except Exception:
        return None


def build_dashboard_lines() -> list[str]:
    lines: list[str] = []

    # --- Connection ---
    lines.append("CONNECTION")
    try:
        gw4 = net_mod.get_default_gateway("inet")
        gw6 = net_mod.get_default_gateway("inet6")
    except BinaryNotFound:
        gw4 = gw6 = None
        lines.append("  Default gateway: [ERROR] 'ip' (iproute2) not installed — interface state unavailable")
    except Exception as exc:  # pragma: no cover - defensive
        gw4 = gw6 = None
        lines.append(f"  Default gateway: [ERROR] {exc}")
    else:
        gateway = gw4 or gw6
        if gateway:
            lines.append(f"  Default gateway: [READY] {gateway.gateway} via {gateway.device or '-'}")
        else:
            lines.append("  Default gateway: [DEGRADED] none configured")

    # --- Interfaces ---
    lines.append("")
    lines.append("INTERFACES")
    try:
        ifaces = iface_mod.list_interfaces()
    except BinaryNotFound:
        lines.append("  [ERROR] 'ip' (iproute2) not installed — interface state unavailable")
        ifaces = []
    except Exception as exc:  # pragma: no cover - defensive
        lines.append(f"  [ERROR] {exc}")
        ifaces = []
    up = sum(1 for i in ifaces if i.is_up)
    if ifaces:
        lines.append(f"  {len(ifaces)} interface(s) detected  [ACTIVE] {up} up")
    else:
        lines.append("  [DEGRADED] no interfaces detected")
    for i in ifaces[:MAX_INTERFACES]:
        state = "[UP]" if i.is_up else "[DOWN]"
        v4 = ", ".join(a.address for a in i.ipv4_addresses) or "-"
        v6 = ", ".join(a.address for a in i.ipv6_addresses) or "-"
        lines.append(f"  {state} {i.name:<10} ipv4={v4:<15} ipv6={v6} mac={i.mac or '-'}")
    if len(ifaces) > MAX_INTERFACES:
        lines.append(f"  ... and {len(ifaces) - MAX_INTERFACES} more interface(s)")

    # --- Devices ---
    lines.append("")
    lines.append("DEVICES")
    try:
        found = devices_mod.passive_scan("inet")
        lines.append(f"  Devices detected: [READY] {len(found)} on the local subnet")
    except Exception as exc:
        lines.append(f"  Devices detected: [ERROR] {exc}")

    # --- NETWATCH control ---
    lines.append("")
    lines.append("NETWATCH CONTROL")
    fw_count = _count_firewall_rules()
    if fw_count is not None:
        lines.append(f"  Active firewall rules: [ACTIVE] {fw_count}")
    else:
        lines.append("  Active firewall rules: [DEGRADED] engine unavailable")
    policer_count = _count_traffic_policers()
    if policer_count is not None:
        lines.append(f"  Active traffic policers: [ACTIVE] {policer_count}")
    else:
        lines.append("  Active traffic policers: [DEGRADED] engine unavailable")

    # --- Recent activity ---
    lines.append("")
    lines.append("RECENT ACTIVITY")
    try:
        events = activity_log.read_events(MAX_EVENTS)
    except Exception:
        events = []
    if events:
        for event in events:
            timestamp = str(event.get("timestamp", ""))[-14:]
            module = str(event.get("module", "?"))[:10]
            action = str(event.get("action", "?"))[:22]
            status = str(event.get("status", "?"))
            lines.append(f"  {timestamp}  [{status.upper():<7}] {module:<10} {action}")
    else:
        lines.append("  [INFO] no activity recorded yet")

    # --- System ---
    lines.append("")
    lines.append("SYSTEM")
    missing = deps.missing_mandatory()
    if missing:
        names = ", ".join(d.binary for d in missing)
        lines.append(f"  Missing mandatory tools: [WARNING] {names} — see System Manager")
    else:
        lines.append("  Mandatory tools: [READY] all present")

    return lines
