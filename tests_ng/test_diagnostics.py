from __future__ import annotations

import pytest

from netwatch_ng.core.network import Route
from netwatch_ng.core.shell import CommandResult
from netwatch_ng import diagnostics


def test_validate_target_accepts_ips_and_hostnames():
    assert diagnostics.validate_target("192.0.2.1") == "192.0.2.1"
    assert diagnostics.validate_target("2001:db8::1") == "2001:db8::1"
    assert diagnostics.validate_target("router.local") == "router.local"


def test_validate_target_rejects_shell_syntax():
    for target in (";id", "router;id", "--help", "bad host"):
        with pytest.raises(ValueError):
            diagnostics.validate_target(target)


def test_ping_target_uses_argv_and_ipv6_flag(monkeypatch):
    calls = []
    monkeypatch.setattr("netwatch_ng.diagnostics.run", lambda argv, timeout: calls.append((argv, timeout)) or CommandResult(argv, 0, "3 packets transmitted\n", ""))
    result = diagnostics.ping_target("2001:db8::1", count=2, timeout_seconds=1)
    assert result.ok is True
    assert calls[0][0][:3] == ["ping", "-6", "-n"]


def test_ping_gateway_uses_default_route(monkeypatch):
    monkeypatch.setattr(diagnostics.network, "get_default_gateway", lambda family: Route("default", "192.0.2.1", "eth0", None) if family == "inet" else None)
    monkeypatch.setattr(diagnostics, "ping_target", lambda target, count, timeout_seconds: diagnostics.DiagnosticResult("Ping", True, target))
    result = diagnostics.ping_gateway()
    assert result.ok is True
    assert "192.0.2.1" in result.summary


def test_trace_route_refuses_invalid_input(monkeypatch):
    monkeypatch.setattr(diagnostics, "which", lambda name: "/usr/bin/mtr")
    with pytest.raises(ValueError):
        diagnostics.trace_route("example.com;id")


def test_resolve_dns_uses_getent_and_returns_sorted_unique_addresses(monkeypatch):
    calls = []

    def fake_run(argv, timeout):
        calls.append((argv, timeout))
        return CommandResult(
            argv,
            0,
            "192.0.2.2 STREAM example.com\n192.0.2.1 DGRAM example.com\n192.0.2.2 RAW example.com\n",
            "",
        )

    monkeypatch.setattr(diagnostics, "which", lambda name: "/usr/bin/getent" if name == "getent" else None)
    monkeypatch.setattr(diagnostics, "run", fake_run)

    result = diagnostics.resolve_dns("example.com")

    assert result.ok is True
    assert result.summary == "2 address(es) resolved"
    assert result.details.splitlines() == ["192.0.2.1", "192.0.2.2"]
    assert calls == [(["getent", "ahosts", "example.com"], 5.0)]


def test_resolve_dns_reports_empty_lookup_as_failure(monkeypatch):
    monkeypatch.setattr(diagnostics, "which", lambda name: "/usr/bin/getent")
    monkeypatch.setattr(
        diagnostics,
        "run",
        lambda argv, timeout: CommandResult(argv, 2, "", "Name or service not known"),
    )

    result = diagnostics.resolve_dns("missing.invalid")

    assert result.ok is False
    assert result.summary == "DNS lookup failed"
    assert "Name or service not known" in result.details


def test_trace_route_uses_mtr_for_the_requested_target(monkeypatch):
    calls = []

    def fake_run(argv, timeout):
        calls.append((argv, timeout))
        return CommandResult(argv, 0, "1. 192.0.2.1\n", "")

    monkeypatch.setattr(diagnostics, "which", lambda name: "/usr/bin/mtr" if name == "mtr" else None)
    monkeypatch.setattr(diagnostics, "run", fake_run)

    result = diagnostics.trace_route("example.com", max_hops=12, timeout_seconds=20)

    assert result.ok is True
    assert result.name == "MTR"
    assert calls == [
        (["mtr", "--report", "--report-cycles", "1", "--max-ttl", "12", "example.com"], 20)
    ]


def test_trace_route_falls_back_to_traceroute(monkeypatch):
    calls = []

    def fake_run(argv, timeout):
        calls.append((argv, timeout))
        return CommandResult(argv, 0, "1 192.0.2.1\n", "")

    monkeypatch.setattr(
        diagnostics, "which",
        lambda name: "/usr/sbin/traceroute" if name == "traceroute" else None,
    )
    monkeypatch.setattr(diagnostics, "run", fake_run)

    result = diagnostics.trace_route("192.0.2.10", max_hops=8, timeout_seconds=15)

    assert result.ok is True
    assert result.name == "Traceroute"
    assert calls == [
        (["traceroute", "-m", "8", "-w", "1", "-q", "1", "192.0.2.10"], 15)
    ]
