"""Passive device discovery via the kernel neighbor (ARP/NDP) table.

This needs only `ip` (already mandatory for core.interfaces), so it is
the discovery path that still works when `nmap` is not installed.
It only reports devices the kernel has already talked to — it does not
actively probe the subnet (that's nmap_scan.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from netwatch_ng.core.shell import BinaryNotFound, run


@dataclass
class Neighbor:
    ip: str
    mac: str | None
    device: str | None
    state: str  # REACHABLE, STALE, DELAY, PROBE, FAILED, PERMANENT, NOARP, INCOMPLETE


# States that mean "the kernel currently believes this host answered",
# as opposed to a stale/failed/incomplete cache entry.
LIVE_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}


def _parse_entry(entry: dict) -> Neighbor:
    states = entry.get("state", [])
    state = states[0] if states else "UNKNOWN"
    return Neighbor(
        ip=entry.get("dst", ""),
        mac=entry.get("lladdr"),
        device=entry.get("dev"),
        state=state,
    )


def list_neighbors(family: str = "inet") -> list[Neighbor]:
    """Return the current ARP (inet) or NDP (inet6) neighbor table.

    Returns [] (rather than raising) when `ip` is missing or the
    command fails — the same "no binary, no crash" contract as
    core.network. Callers that need to distinguish "empty table" from
    "ip not installed" should check system.deps themselves.
    """
    flag = "-4" if family == "inet" else "-6"
    try:
        result = run(["ip", flag, "-j", "neigh", "show"], timeout=5.0)
    except BinaryNotFound:
        return []
    if not result.ok or not result.stdout.strip():
        return []
    raw = json.loads(result.stdout)
    return [_parse_entry(e) for e in raw]


def list_live_neighbors(family: str = "inet") -> list[Neighbor]:
    """Neighbors whose MAC is known and whose state suggests they're reachable."""
    return [n for n in list_neighbors(family) if n.mac and n.state in LIVE_STATES]
