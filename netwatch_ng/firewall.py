"""Firewall management helpers for NETWATCH-owned blocking rules.

This module intentionally stays narrow: it operates on explicit IP targets,
uses the Linux iptables/ip6tables toolchain directly, and refuses to block
known default gateways or malformed addresses. It never touches unrelated
chains or broad firewall rulesets.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from netwatch_ng.core import network
from netwatch_ng.core.shell import BinaryNotFound, run, which

NETWATCH_COMMENT = "NETWATCH"


@dataclass
class FirewallRule:
    family: str
    chain: str
    source: str | None
    target: str
    comment: str | None = None


def _binary_for_family(family: str) -> str:
    if family == "inet":
        return "iptables"
    if family == "inet6":
        return "ip6tables"
    raise ValueError("family must be 'inet' or 'inet6'")


def _parse_iptables_rules(text: str, family: str) -> list[FirewallRule]:
    rules: list[FirewallRule] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("-A "):
            continue
        parts = stripped.split()
        if len(parts) < 6:
            continue
        chain = parts[1]
        target = parts[-1]
        source = None
        comment = None
        for idx, token in enumerate(parts):
            if token == "-s" and idx + 1 < len(parts):
                source = parts[idx + 1]
            if token == "--comment" and idx + 1 < len(parts):
                comment = parts[idx + 1].strip('"')
        if comment == NETWATCH_COMMENT:
            if source is not None:
                try:
                    ip = ipaddress.ip_address(source)
                except ValueError:
                    continue
                if family == "inet" and not isinstance(ip, ipaddress.IPv4Address):
                    continue
                if family == "inet6" and not isinstance(ip, ipaddress.IPv6Address):
                    continue
            rules.append(
                FirewallRule(
                    family=family,
                    chain=chain,
                    source=source,
                    target=target,
                    comment=comment,
                )
            )
    return rules


def list_netwatch_rules(family: str = "inet") -> list[FirewallRule]:
    """Return NETWATCH-owned firewall rules for this family, if any."""
    binary = _binary_for_family(family)
    if which(binary) is None:
        return []
    result = run([binary, "-S"], timeout=5.0)
    if not result.ok:
        return []
    return _parse_iptables_rules(result.stdout, family)


def _reject_gateway(target: str, family: str) -> None:
    route = network.get_default_gateway(family)
    if route is None or route.gateway is None:
        return
    gateway = str(ipaddress.ip_address(route.gateway))
    if gateway == target:
        raise ValueError(f"refusing to block the configured default {family} gateway: {target}")


def validate_ip_target(target: str) -> str:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:  # pragma: no cover - exercised by tests
        raise ValueError(f"invalid target address: {target!r}") from exc
    return str(ip)


def block_ip(target: str, family: str = "inet", dry_run: bool = False) -> bool:
    """Add a NETWATCH-owned DROP rule for a single IP address.

    Returns True when the rule was added, False when it was already present.
    """
    clean = validate_ip_target(target)
    _reject_gateway(clean, family)

    binary = _binary_for_family(family)
    if which(binary) is None:
        raise BinaryNotFound(binary)

    check = run([binary, "-C", "FORWARD", "-s", clean, "-m", "comment", "--comment", NETWATCH_COMMENT, "-j", "DROP"], timeout=5.0)
    if check.ok:
        return False

    if dry_run:
        return True

    result = run([binary, "-I", "FORWARD", "-s", clean, "-m", "comment", "--comment", NETWATCH_COMMENT, "-j", "DROP"], timeout=5.0)
    if not result.ok:
        raise RuntimeError(f"failed to add {family} firewall block: {result.stderr.strip()}")
    return True


def unblock_ip(target: str, family: str = "inet", dry_run: bool = False) -> bool:
    """Remove a NETWATCH-owned DROP rule for a single IP address."""
    clean = validate_ip_target(target)
    binary = _binary_for_family(family)
    if which(binary) is None:
        raise BinaryNotFound(binary)

    check = run([binary, "-C", "FORWARD", "-s", clean, "-m", "comment", "--comment", NETWATCH_COMMENT, "-j", "DROP"], timeout=5.0)
    if not check.ok:
        return False

    if dry_run:
        return True

    result = run([binary, "-D", "FORWARD", "-s", clean, "-m", "comment", "--comment", NETWATCH_COMMENT, "-j", "DROP"], timeout=5.0)
    if not result.ok:
        raise RuntimeError(f"failed to remove {family} firewall block: {result.stderr.strip()}")
    return True
