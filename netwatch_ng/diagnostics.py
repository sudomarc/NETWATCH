"""Bounded, input-validated network diagnostics."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from netwatch_ng.core import network
from netwatch_ng.core.shell import BinaryNotFound, run, which

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


@dataclass
class DiagnosticResult:
    name: str
    ok: bool
    summary: str
    details: str = ""


def validate_target(target: str) -> str:
    if not isinstance(target, str) or not target or len(target) > 253:
        raise ValueError("target must be an IP address or hostname")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        if not _HOST_RE.fullmatch(target):
            raise ValueError(f"invalid diagnostic target: {target!r}")
        labels = target.rstrip(".").split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise ValueError(f"invalid diagnostic hostname: {target!r}")
        return target


def ping_target(target: str, count: int = 3, timeout_seconds: int = 2) -> DiagnosticResult:
    clean = validate_target(target)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 10:
        raise ValueError("count must be an integer from 1 to 10")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 10:
        raise ValueError("timeout_seconds must be an integer from 1 to 10")
    try:
        address = ipaddress.ip_address(clean)
        family_flag = ["-6"] if address.version == 6 else ["-4"]
    except ValueError:
        family_flag = []
    argv = ["ping", *family_flag, "-n", "-c", str(count), "-W", str(timeout_seconds), clean]
    result = run(argv, timeout=count * (timeout_seconds + 1) + 3)
    details = (result.stdout or result.stderr).strip()[-2000:]
    summary = "Ping succeeded" if result.ok else "Ping failed or packets were not returned"
    return DiagnosticResult("Ping", result.ok, summary, details)


def ping_gateway(count: int = 3, timeout_seconds: int = 2) -> DiagnosticResult:
    route = network.get_default_gateway("inet") or network.get_default_gateway("inet6")
    if route is None or route.gateway is None:
        return DiagnosticResult("Gateway ping", False, "No default gateway is configured")
    result = ping_target(route.gateway, count=count, timeout_seconds=timeout_seconds)
    result.name = "Gateway ping"
    result.summary = f"{result.summary}: {route.gateway}"
    return result


def resolve_dns(hostname: str) -> DiagnosticResult:
    clean = validate_target(hostname)
    if which("getent") is None:
        raise BinaryNotFound("getent")
    result = run(["getent", "ahosts", clean], timeout=5.0)
    addresses = sorted({line.split()[0] for line in result.stdout.splitlines() if line.split()})
    ok = result.ok and bool(addresses)
    details = "\n".join(addresses) if addresses else (result.stderr or result.stdout).strip()
    return DiagnosticResult("DNS lookup", ok, f"{len(addresses)} address(es) resolved" if ok else "DNS lookup failed", details[:2000])


def trace_route(target: str, max_hops: int = 20, timeout_seconds: int = 30) -> DiagnosticResult:
    clean = validate_target(target)
    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= 64:
        raise ValueError("max_hops must be an integer from 1 to 64")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 5 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be an integer from 5 to 120")
    if which("mtr") is not None:
        argv = ["mtr", "--report", "--report-cycles", "1", "--max-ttl", str(max_hops), clean]
        name = "MTR"
    elif which("traceroute") is not None:
        argv = ["traceroute", "-m", str(max_hops), "-w", "1", "-q", "1", clean]
        name = "Traceroute"
    else:
        raise BinaryNotFound("mtr or traceroute")
    result = run(argv, timeout=timeout_seconds)
    details = (result.stdout or result.stderr).strip()[-3000:]
    return DiagnosticResult(name, result.ok, "Route trace completed" if result.ok else "Route trace failed", details)
