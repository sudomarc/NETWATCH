from __future__ import annotations

from netwatch_ng.router_intelligence import RouterReport
from netwatch_ng.tui.screens import router_intelligence, wifi_intelligence
from netwatch_ng.wifi_intelligence import AccessPoint, RadioState, WirelessInterface


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


def test_wifi_screen_discloses_channel_count_limitation(monkeypatch):
    monkeypatch.setattr(
        wifi_intelligence,
        "list_wireless_interfaces",
        lambda: [WirelessInterface("wlan0", "phy0", "managed", None, None, None)],
    )
    monkeypatch.setattr(
        wifi_intelligence, "get_radio_state", lambda: RadioState(False, False)
    )
    lines = wifi_intelligence.build_wifi_lines(
        [AccessPoint("home", "aa:bb:cc:dd:ee:ff", 2412, 1, -45.0, "RSN advertised")],
        "wlan0",
    )
    assert any("Observed APs per channel" in line for line in lines)
    assert any("not measured RF utilization" in line for line in lines)
