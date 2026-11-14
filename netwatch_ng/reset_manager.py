"""Preview and execute removal of NETWATCH-owned firewall and traffic rules."""
from __future__ import annotations

from dataclasses import dataclass

from netwatch_ng import firewall, traffic


@dataclass
class ResetAction:
    kind: str
    target: str
    success: bool
    detail: str | None = None


@dataclass
class ResetReport:
    firewall_actions: list[ResetAction]
    traffic_actions: list[ResetAction]


def preview_all() -> ResetReport:
    """Read-only preview. It never issues firewall or traffic mutations."""
    firewall_actions: list[ResetAction] = []
    traffic_actions: list[ResetAction] = []
    for family in ("inet", "inet6"):
        try:
            rules = firewall.list_netwatch_rules(family)
        except Exception as exc:
            firewall_actions.append(ResetAction("firewall", "unavailable", False, str(exc)))
            continue
        for rule in rules:
            if rule.chain != "FORWARD" or rule.source is None or rule.comment != firewall.NETWATCH_COMMENT:
                continue
            firewall_actions.append(
                ResetAction("firewall", f"{family}:{rule.source}", False, "pending confirmation")
            )
    try:
        limits = traffic.list_limits()
        for limit in limits:
            traffic_actions.append(
                ResetAction("traffic", f"{limit.interface}:{limit.direction}", False, "pending confirmation")
            )
    except Exception as exc:
        traffic_actions.append(ResetAction("traffic", "unavailable", False, str(exc)))
    return ResetReport(firewall_actions, traffic_actions)


def reset_firewall() -> list[ResetAction]:
    """Delete only NETWATCH-owned FORWARD rules supported by the firewall API."""
    actions: list[ResetAction] = []
    for family in ("inet", "inet6"):
        for rule in firewall.list_netwatch_rules(family):
            # unblock_ip() removes only from FORWARD. Never try to delete a
            # rule discovered in another chain through that API.
            if rule.chain != "FORWARD" or rule.source is None or rule.comment != firewall.NETWATCH_COMMENT:
                continue
            try:
                ok = firewall.unblock_ip(rule.source, family=family)
                actions.append(
                    ResetAction(
                        "firewall", f"{family}:{rule.source}", ok,
                        "removed" if ok else "rule already absent",
                    )
                )
            except Exception as exc:
                actions.append(ResetAction("firewall", f"{family}:{rule.source}", False, str(exc)))
    return actions


def reset_traffic() -> list[ResetAction]:
    """Delete only traffic filters verified against NETWATCH's protected state."""
    actions: list[ResetAction] = []
    for limit in traffic.list_limits():
        try:
            ok = traffic.clear_limit(limit.interface, direction=limit.direction)
            actions.append(
                ResetAction(
                    "traffic", f"{limit.interface}:{limit.direction}", ok,
                    "removed" if ok else "rule already absent",
                )
            )
        except Exception as exc:
            actions.append(ResetAction("traffic", f"{limit.interface}:{limit.direction}", False, str(exc)))
    return actions


def reset_all() -> ResetReport:
    """Execute reset. The TUI must call this only after explicit confirmation."""
    try:
        firewall_actions = reset_firewall()
    except Exception as exc:
        firewall_actions = [ResetAction("firewall", "unavailable", False, str(exc))]
    try:
        traffic_actions = reset_traffic()
    except Exception as exc:
        traffic_actions = [ResetAction("traffic", "unavailable", False, str(exc))]
    return ResetReport(firewall_actions, traffic_actions)
