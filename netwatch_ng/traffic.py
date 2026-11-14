"""Traffic shaper helper for egress shaping via Linux `tc`.

NETWATCH NG only exposes the subset that is both technically feasible and
operator-visible: egress bandwidth limiting on a specific interface. Ingress
shaping via IFB is intentionally not advertised unless it is implemented and
validated in a later sprint.
"""

from __future__ import annotations

from dataclasses import dataclass

from netwatch_ng.core.shell import BinaryNotFound, run, which


@dataclass
class TrafficLimit:
    interface: str
    direction: str
    rate_kbps: int
    qdisc_id: str | None = None


def list_limits(interface: str | None = None) -> list[TrafficLimit]:
    """Return NETWATCH-managed tc limits for one interface, if present."""
    if which("tc") is None:
        return []
    argv = ["tc", "qdisc", "show"] if interface is None else ["tc", "qdisc", "show", "dev", interface]
    result = run(argv, timeout=5.0)
    if not result.ok:
        return []

    limits: list[TrafficLimit] = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if "htb" not in line.lower() or "NETWATCH" not in line:
            continue
        parts = line.split()
        interface_name = interface or parts[4] if len(parts) > 4 else "unknown"
        limits.append(
            TrafficLimit(
                interface=interface_name,
                direction="egress",
                rate_kbps=0,
                qdisc_id=parts[0] if parts else None,
            )
        )
    return limits


def set_limit(interface: str, rate_kbps: int, direction: str = "egress", dry_run: bool = False) -> TrafficLimit:
    """Set a NETWATCH egress rate cap on `interface` in kbit/s."""
    if not interface:
        raise ValueError("interface must not be empty")
    if rate_kbps <= 0:
        raise ValueError("rate_kbps must be positive")
    if direction != "egress":
        raise NotImplementedError("only egress shaping is implemented; ingress IFB shaping is not yet available")
    if which("tc") is None:
        raise BinaryNotFound("tc")

    commands = [
        ["tc", "qdisc", "replace", "dev", interface, "root", "handle", "1:", "htb", "default", "1"],
        ["tc", "class", "replace", "dev", interface, "parent", "1:", "classid", "1:1", "htb", "rate", f"{rate_kbps}kbit", "ceil", f"{rate_kbps}kbit"],
    ]
    if not dry_run:
        for cmd in commands:
            result = run(cmd, timeout=5.0)
            if not result.ok:
                raise RuntimeError(f"tc failed for {interface}: {result.stderr.strip()}")
    return TrafficLimit(interface=interface, direction=direction, rate_kbps=rate_kbps, qdisc_id="1:")


def clear_limit(interface: str, dry_run: bool = False) -> bool:
    """Remove an egress qdisc from `interface` if NETWATCH created it."""
    if not interface:
        raise ValueError("interface must not be empty")
    if which("tc") is None:
        raise BinaryNotFound("tc")
    if dry_run:
        return True
    result = run(["tc", "qdisc", "delete", "dev", interface, "root"], timeout=5.0)
    return result.ok
