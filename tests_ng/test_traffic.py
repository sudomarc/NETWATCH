from __future__ import annotations

import pytest

from netwatch_ng.core.shell import CommandResult
from netwatch_ng.traffic import clear_limit, list_limits, set_limit


def test_list_limits_parses_tc_output(monkeypatch):
    output = """
    qdisc htb 1: root dev eth0
    qdisc htb 1: root dev wlan0
    qdisc htb 1: root dev eth0 NETWATCH
    """
    monkeypatch.setattr("netwatch_ng.traffic.which", lambda binary: "/usr/sbin/tc")
    monkeypatch.setattr("netwatch_ng.traffic.run", lambda argv, timeout=5.0: CommandResult(argv, 0, output, ""))
    limits = list_limits("eth0")
    assert len(limits) == 1
    assert limits[0].interface == "eth0"


def test_set_limit_rejects_ingress(monkeypatch):
    monkeypatch.setattr("netwatch_ng.traffic.which", lambda binary: "/usr/sbin/tc")
    with pytest.raises(NotImplementedError):
        set_limit("eth0", 1000, direction="ingress")


def test_set_limit_runs_egress_commands(monkeypatch):
    calls = []

    def fake_run(argv, timeout=5.0):
        calls.append(tuple(argv))
        return CommandResult(argv, 0, "", "")

    monkeypatch.setattr("netwatch_ng.traffic.which", lambda binary: "/usr/sbin/tc")
    monkeypatch.setattr("netwatch_ng.traffic.run", fake_run)
    limit = set_limit("eth0", 512)
    assert limit.interface == "eth0"
    assert limit.rate_kbps == 512
    assert any(cmd[:3] == ("tc", "qdisc", "replace") for cmd in calls)


def test_clear_limit_deletes_qdisc(monkeypatch):
    monkeypatch.setattr("netwatch_ng.traffic.which", lambda binary: "/usr/sbin/tc")
    monkeypatch.setattr("netwatch_ng.traffic.run", lambda argv, timeout=5.0: CommandResult(argv, 0, "", ""))
    assert clear_limit("eth0") is True
