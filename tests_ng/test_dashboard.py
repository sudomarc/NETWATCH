"""Dashboard screen: real supervision data, nothing simulated. Fully mocked."""

from __future__ import annotations

from netwatch_ng.tui.screens import dashboard as dashboard_screen


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
    text = "\n".join(lines)

    assert "CONNECTION" in text
    assert "Default gateway: [DEGRADED] none configured" in text
    assert "INTERFACES" in text
    assert "[DEGRADED] no interfaces detected" in text
    assert "DEVICES" in text
    assert "Devices detected: [READY] 0" in text
    assert "NETWATCH CONTROL" in text
    assert "Active firewall rules:" in text
    assert "Active traffic policers:" in text
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
    text = "\n".join(lines)
    assert "Active firewall rules: [DEGRADED] engine unavailable" in text
    assert "Active traffic policers: [DEGRADED] engine unavailable" in text


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
    text = "\n".join(lines)

    assert "Default gateway: [READY] 192.168.1.1 via eth0" in text
    assert "[UP] eth0" in text
    assert "Devices detected: [READY] 1" in text
