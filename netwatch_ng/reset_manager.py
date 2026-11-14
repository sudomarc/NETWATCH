"""Reset support for NETWATCH-managed firewall and egress traffic rules.

This module intentionally removes only data created by NETWATCH: rules that
carry the NETWATCH comment and tc qdiscs that are known to be managed by
NETWATCH. It never clears unrelated firewall rules or global traffic shaping.
"""

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


def reset_firewall() -> list[ResetAction]:
    """Delete only NETWATCH-owned firewall rules."""
    actions: list[ResetAction] = []
    for family in ("inet", "inet6"):
        for rule in firewall.list_netwatch_rules(family):
            if rule.source is None or rule.comment != firewall.NETWATCH_COMMENT:
                continue
            try:
                ok = firewall.unblock_ip(rule.source, family=family)
                actions.append(
                    ResetAction(
                        kind="firewall",
                        target=f"{family}:{rule.source}",
                        success=ok,
                        detail=f"rule on {rule.chain}",
                    )
                )
            except Exception as exc:  # pragma: no cover - surfaced as a failed action
                actions.append(
                    ResetAction(
                        kind="firewall",
                        target=f"{family}:{rule.source}",
                        success=False,
                        detail=str(exc),
                    )
                )
    return actions


def reset_traffic() -> list[ResetAction]:
    """Delete only NETWATCH-managed egress tc qdiscs."""
    actions: list[ResetAction] = []
    for limit in traffic.list_limits():
        try:
            ok = traffic.clear_limit(limit.interface)
            actions.append(
                ResetAction(
                    kind="traffic",
                    target=limit.interface,
                    success=ok,
                    detail=f"{limit.direction} limit",
                )
            )
        except Exception as exc:  # pragma: no cover - surfaced as a failed action
            actions.append(
                ResetAction(
                    kind="traffic",
                    target=limit.interface,
                    success=False,
                    detail=str(exc),
                )
            )
    return actions


def reset_all() -> ResetReport:
    """Remove only NETWATCH-managed firewall and traffic state."""
    return ResetReport(
        firewall_actions=reset_firewall(),
        traffic_actions=reset_traffic(),
    )
