from __future__ import annotations

from netwatch_ng import firewall, reset_manager, traffic
from netwatch_ng.tui.screens import reset_manager as reset_screen


def _flatten_lines(lines):
    """Convert screen content (strings + table specs) to plain strings."""
    flat = []
    for line in lines:
        if isinstance(line, tuple) and len(line) >= 3 and line[0] == "TABLE":
            _, headers, rows = line[0], line[1], line[2]
            flat.append(" | ".join(str(h) for h in headers))
            for row in rows:
                flat.append(" | ".join(str(c) for c in row))
        else:
            flat.append(str(line))
    return flat


def test_preview_reset_is_read_only(monkeypatch):
    rules = [firewall.FirewallRule("inet", "FORWARD", "192.168.1.50", "DROP", "NETWATCH")]
    limits = [traffic.TrafficLimit("eth0", "egress", 512, "pref-49152")]
    monkeypatch.setattr(firewall, "list_netwatch_rules", lambda family: rules if family == "inet" else [])
    monkeypatch.setattr(traffic, "list_limits", lambda interface=None: limits)
    monkeypatch.setattr(
        firewall, "unblock_ip",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("preview mutated firewall")),
    )
    monkeypatch.setattr(
        traffic, "clear_limit",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("preview mutated traffic")),
    )
    report = reset_manager.preview_all()
    assert [item.target for item in report.firewall_actions] == ["inet:192.168.1.50"]
    assert [item.target for item in report.traffic_actions] == ["eth0:egress"]


def test_reset_screen_never_calls_destructive_reset(monkeypatch):
    monkeypatch.setattr(reset_manager, "preview_all", lambda: reset_manager.ResetReport([], []))
    monkeypatch.setattr(
        reset_manager, "reset_all",
        lambda: (_ for _ in ()).throw(AssertionError("screen triggered reset")),
    )
    lines = reset_screen.build_reset_lines()
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert any("No changes have been made" in line for line in flat)
    assert "preview" in text.lower()
    assert "reset" in text.lower()


def test_reset_firewall_does_not_delete_other_chains(monkeypatch):
    rules = [
        firewall.FirewallRule("inet", "FORWARD", "192.168.1.50", "DROP", "NETWATCH"),
        firewall.FirewallRule("inet", "OUTPUT", "192.168.1.60", "DROP", "NETWATCH"),
    ]
    monkeypatch.setattr(firewall, "list_netwatch_rules", lambda family: rules if family == "inet" else [])
    seen = []
    monkeypatch.setattr(firewall, "unblock_ip", lambda target, family="inet", dry_run=False: seen.append(target) or True)
    actions = reset_manager.reset_firewall()
    assert [action.target for action in actions] == ["inet:192.168.1.50"]
    assert seen == ["192.168.1.50"]


def test_reset_all_combines_firewall_and_traffic(monkeypatch):
    monkeypatch.setattr(reset_manager, "reset_firewall", lambda: ["firewall"])
    monkeypatch.setattr(reset_manager, "reset_traffic", lambda: ["traffic"])
    report = reset_manager.reset_all()
    assert report.firewall_actions == ["firewall"]
    assert report.traffic_actions == ["traffic"]
