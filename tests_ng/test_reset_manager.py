from __future__ import annotations

import pytest

from netwatch_ng import firewall, reset_manager, traffic


def test_reset_firewall_removes_only_netwatch_rules(monkeypatch):
    rules = [
        firewall.FirewallRule("inet", "FORWARD", "192.168.1.50", "DROP", "NETWATCH"),
        firewall.FirewallRule("inet", "OUTPUT", "8.8.8.8", "ACCEPT", None),
    ]
    monkeypatch.setattr(firewall, "list_netwatch_rules", lambda family: rules if family == "inet" else [])
    seen = []

    def fake_unblock(target, family="inet", dry_run=False):
        seen.append((target, family, dry_run))
        return True

    monkeypatch.setattr(firewall, "unblock_ip", fake_unblock)
    actions = reset_manager.reset_firewall()
    assert len(actions) == 1
    assert actions[0].target == "inet:192.168.1.50"
    assert seen == [("192.168.1.50", "inet", False)]


def test_reset_traffic_clears_netwatch_qdiscs(monkeypatch):
    limits = [traffic.TrafficLimit("eth0", "egress", 512, "1:")]
    monkeypatch.setattr(traffic, "list_limits", lambda interface=None: limits)
    seen = []

    def fake_clear(interface, dry_run=False):
        seen.append((interface, dry_run))
        return True

    monkeypatch.setattr(traffic, "clear_limit", fake_clear)
    actions = reset_manager.reset_traffic()
    assert len(actions) == 1
    assert actions[0].target == "eth0"
    assert seen == [("eth0", False)]


def test_reset_all_combines_firewall_and_traffic(monkeypatch):
    monkeypatch.setattr(reset_manager, "reset_firewall", lambda: ["firewall"])
    monkeypatch.setattr(reset_manager, "reset_traffic", lambda: ["traffic"])
    report = reset_manager.reset_all()
    assert report.firewall_actions == ["firewall"]
    assert report.traffic_actions == ["traffic"]
