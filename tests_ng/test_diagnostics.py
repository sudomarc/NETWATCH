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
