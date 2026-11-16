from __future__ import annotations

from netwatch_ng.router_intelligence import RouterReport
from netwatch_ng.tui.screens import diagnostics as diagnostics_screen
from netwatch_ng.tui.screens import router_intelligence, wifi_intelligence
from netwatch_ng.wifi_intelligence import AccessPoint, Station, WirelessInterface


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


def test_router_screen_labels_oui_match_as_unverified():
    lines = router_intelligence.build_router_lines(
        RouterReport(
            family="inet",
            gateway="192.168.1.1",
            interface="eth0",
            mac="b8:27:eb:11:22:33",
            manufacturer="Raspberry Pi Foundation",
            local_addresses=["192.168.1.2"],
        )
    )
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert "model/firmware unverified" in text
    assert "Raspberry Pi Foundation" in text


def test_wifi_screen_discloses_backend_and_channel_count_limitation(monkeypatch):
    monkeypatch.setattr(
        wifi_intelligence,
        "list_wireless_interfaces",
        lambda: [
            WirelessInterface(
                name="wlan0", phy="phy0", driver="ath9k_htc",
                chipset="Atheros AR9271", mode="managed",
                mac="aa:bb:cc:dd:ee:ff",
            )
        ],
    )
    lines = wifi_intelligence.build_wifi_lines(
        [
            AccessPoint(
                "home", "aa:bb:cc:dd:ee:ff", 2412, 1, -45.0, "WPA2 (CCMP / PSK)"
            )
        ],
        "wlan0",
    )
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert "Aircrack-ng" in text
    assert "wlan0" in text and "managed" in text
    assert "Channel | AP count" in text
    assert "not measured RF utilization" in text
    assert "rfkill soft/hard block" in text


def test_wifi_screen_shows_stations_and_last_update(monkeypatch):
    monkeypatch.setattr(
        wifi_intelligence,
        "list_wireless_interfaces",
        lambda: [
            WirelessInterface(
                name="wlan0", phy="phy0", driver="ath9k_htc",
                chipset="Atheros AR9271", mode="monitor",
                mac="aa:bb:cc:dd:ee:ff",
            )
        ],
    )
    stations = [
        Station(
            bssid="aa:bb:cc:dd:ee:ff",
            station="11:22:33:44:55:66",
            signal_dbm=-50.0,
            rate="54e",
            lost=0,
            frames=100,
            probes=None,
        )
    ]
    lines = wifi_intelligence.build_wifi_lines(
        [AccessPoint("home", "aa:bb:cc:dd:ee:ff", 2412, 1, -45.0, "WPA2")],
        "wlan0",
        stations=stations,
    )
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert "Last update" in text
    assert "11:22:33:44:55:66" in text
    assert "Stations detected" in text


def test_wifi_screen_reports_missing_backend(monkeypatch):
    monkeypatch.setattr(
        wifi_intelligence,
        "list_wireless_interfaces",
        lambda: [],
    )
    monkeypatch.setattr(wifi_intelligence, "which", lambda binary: None)
    lines = wifi_intelligence.build_wifi_lines(None, None)
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert "Missing system binary" in text
    assert "apt install aircrack-ng" in text


def test_diagnostics_screen_documents_available_tui_actions(monkeypatch):
    monkeypatch.setattr(diagnostics_screen.network, "get_default_gateway", lambda family: None)
    monkeypatch.setattr(diagnostics_screen.network, "get_dns_servers", lambda: [])

    lines = diagnostics_screen.build_diagnostics_lines()
    flat = _flatten_lines(lines)
    text = "\n".join(flat)

    assert "ping the default gateway" in text
    assert "trace a route to a host/IP" in text
    assert "look up DNS" in text