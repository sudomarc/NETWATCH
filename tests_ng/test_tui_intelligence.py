from __future__ import annotations

from netwatch_ng.router_intelligence import RouterReport
from netwatch_ng.tui.screens import diagnostics as diagnostics_screen
from netwatch_ng.tui.screens import router_intelligence, wifi_intelligence
from netwatch_ng.wifi_intelligence import AccessPoint, Station, WirelessInterface


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
    assert any("model/firmware unverified" in line for line in lines)
    assert any("Raspberry Pi Foundation" in line for line in lines)


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
    assert any("Moteur : Aircrack-ng" in line for line in lines)
    assert any("wlan0" in line and "managed" in line for line in lines)
    assert any("Observed APs per channel" in line for line in lines)
    assert any("not measured RF utilization" in line for line in lines)
    assert any("rfkill soft/hard block: not reported" in line for line in lines)


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
    assert any("Dernière MAJ:" in line for line in lines)
    assert any("11:22:33:44:55:66" in line for line in lines)
    assert any("Stations detected" in line for line in lines)


def test_wifi_screen_reports_missing_backend(monkeypatch):
    monkeypatch.setattr(
        wifi_intelligence,
        "list_wireless_interfaces",
        lambda: [],
    )
    monkeypatch.setattr(wifi_intelligence, "which", lambda binary: None)
    lines = wifi_intelligence.build_wifi_lines(None, None)
    assert any("Binaire(s) système absent(s)" in line for line in lines)
    assert any("apt install aircrack-ng" in line for line in lines)


def test_diagnostics_screen_documents_available_tui_actions(monkeypatch):
    monkeypatch.setattr(diagnostics_screen.network, "get_default_gateway", lambda family: None)
    monkeypatch.setattr(diagnostics_screen.network, "get_dns_servers", lambda: [])

    lines = diagnostics_screen.build_diagnostics_lines()

    assert any("p ping the default gateway" in line for line in lines)
    assert any("t trace a route to a host/IP" in line for line in lines)
    assert any("d look up DNS" in line for line in lines)
