"""Dashboard screen: real supervision data, nothing simulated. Fully mocked."""

from __future__ import annotations

from netwatch_ng.tui.screens import dashboard as dashboard_screen


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


def _stub_all(monkeypatch):
    monkeypatch.setattr(
        dashboard_screen.net_mod, "get_default_gateway", lambda family: None
    )
    monkeypatch.setattr(dashboard_screen.iface_mod, "list_interfaces", lambda: [])
    monkeypatch.setattr(
        dashboard_screen.devices_mod, "passive_scan", lambda family="inet": []
    )
    monkeypatch.setattr(dashboard_screen.firewall, "list_netwatch_rules", lambda family: [])
    monkeypatch.setattr(dashboard_screen.traffic, "list_limits", lambda: [])
    monkeypatch.setattr(dashboard_screen.activity_log, "read_events", lambda limit: [])


def test_dashboard_is_read_only_supervision(monkeypatch):
    _stub_all(monkeypatch)
    lines = dashboard_screen.build_dashboard_lines()
    flat = _flatten_lines(lines)
    text = "\n".join(flat)

    assert "CONNECTION" in text
    assert "[DEGRADED] none configured" in text
    assert "INTERFACES" in text
    assert "[DEGRADED] no interfaces detected" in text
    assert "DEVICES" in text
    assert "Devices detected" in text and "[READY]" in text and "0" in text
    assert "NETWATCH CONTROL" in text
    assert "Firewall rules" in text
    assert "Traffic policers" in text
    assert "RECENT ACTIVITY" in text
    assert "[INFO] no activity recorded yet" in text
    assert "SYSTEM" in text


def test_dashboard_reports_degraded_when_engine_unavailable(monkeypatch):
    _stub_all(monkeypatch)
    monkeypatch.setattr(
        dashboard_screen.firewall, "list_netwatch_rules", lambda family: (_ for _ in ()).throw(RuntimeError("iptables missing"))
    )
    monkeypatch.setattr(
        dashboard_screen.traffic, "list_limits", lambda: (_ for _ in ()).throw(RuntimeError("tc missing"))
    )
    lines = dashboard_screen.build_dashboard_lines()
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert "Firewall rules" in text and "[DEGRADED]" in text
    assert "Traffic policers" in text and "[DEGRADED]" in text


def test_dashboard_reports_ready_gateway_and_devices(monkeypatch):
    class FakeGateway:
        gateway = "192.168.1.1"
        device = "eth0"

    class FakeInterface:
        is_up = True
        name = "eth0"
        mac = "aa:bb:cc:dd:ee:ff"
        ipv4_addresses = []
        ipv6_addresses = []

    class FakeDevice:
        pass

    monkeypatch.setattr(
        dashboard_screen.net_mod, "get_default_gateway", lambda family: FakeGateway()
    )
    monkeypatch.setattr(dashboard_screen.iface_mod, "list_interfaces", lambda: [FakeInterface()])
    monkeypatch.setattr(
        dashboard_screen.devices_mod, "passive_scan", lambda family="inet": [FakeDevice()]
    )
    monkeypatch.setattr(dashboard_screen.firewall, "list_netwatch_rules", lambda family: [])
    monkeypatch.setattr(dashboard_screen.traffic, "list_limits", lambda: [])
    monkeypatch.setattr(dashboard_screen.activity_log, "read_events", lambda limit: [])

    lines = dashboard_screen.build_dashboard_lines()
    flat = _flatten_lines(lines)
    text = "\n".join(flat)

    assert "192.168.1.1" in text and "eth0" in text
    assert "[UP]" in text and "eth0" in text
    assert "Devices detected" in text and "[READY]" in text and "1" in text