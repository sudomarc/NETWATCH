from __future__ import annotations

import pytest

from netwatch_ng.core.shell import CommandResult
from netwatch_ng.wifi_intelligence import (
    channel_occupancy,
    get_radio_state,
    get_supported_modes,
    list_wireless_interfaces,
    parse_scan_output,
    scan_networks,
)


def test_list_wireless_interfaces_parses_iw_dev(monkeypatch):
    output = """phy#0
\tInterface wlan0
\t\tifindex 3
\t\taddr aa:bb:cc:dd:ee:ff
\t\ttype managed
\t\tchannel 6 (2437 MHz), width: 20 MHz
"""
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: CommandResult(argv, 0, output, ""),
    )
    interfaces = list_wireless_interfaces()
    assert len(interfaces) == 1
    assert interfaces[0].name == "wlan0"
    assert interfaces[0].phy == "phy0"
    assert interfaces[0].interface_type == "managed"
    assert interfaces[0].mac == "aa:bb:cc:dd:ee:ff"
    assert interfaces[0].channel == 6
    assert interfaces[0].frequency_mhz == 2437


def test_get_radio_state_aggregates_rfkill_blocks(monkeypatch):
    output = """0: phy0: Wireless LAN
\tSoft blocked: no
\tHard blocked: yes
1: phy1: Wireless LAN
\tSoft blocked: yes
\tHard blocked: no
"""
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: CommandResult(argv, 0, output, ""),
    )
    state = get_radio_state()
    assert state.soft_blocked is True
    assert state.hard_blocked is True


def test_get_supported_modes_parses_phy_capabilities(monkeypatch):
    output = """Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * AP
\t\t * monitor
\tBand 1:
\t\tCapabilities: 0x1234
"""
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: CommandResult(argv, 0, output, ""),
    )
    assert get_supported_modes("phy0") == ["managed", "AP", "monitor"]


def test_get_supported_modes_rejects_invalid_phy(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda *args, **kwargs: pytest.fail("invalid phy must not run"),
    )
    with pytest.raises(ValueError):
        get_supported_modes("phy0;id")


def test_parse_scan_output_captures_security_signal_and_channel():
    output = """BSS AA:BB:CC:DD:EE:FF(on wlan0)
\tfreq: 2412
\tsignal: -47.50 dBm
\tSSID: home-wifi
\tRSN:
\t\t* Version: 1
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 5180
\tSSID:
\tcapability: ESS
"""
    points = parse_scan_output(output)
    assert len(points) == 2
    assert points[0].ssid == "home-wifi"
    assert points[0].channel == 1
    assert points[0].signal_dbm == -47.5
    assert points[0].advertised_security == "RSN advertised"
    assert points[1].ssid == ""
    assert points[1].channel == 36
    assert points[1].advertised_security == "no encryption advertised"


def test_channel_occupancy_counts_only_known_channels():
    points = parse_scan_output(
        """BSS AA:BB:CC:DD:EE:FF(on wlan0)
\tfreq: 2412
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 2412
BSS 22:33:44:55:66:77(on wlan0)
\tfreq: 5180
"""
    )
    assert channel_occupancy(points) == {1: 2, 36: 1}


def test_scan_networks_uses_argv_and_validates_interface(monkeypatch):
    calls = []

    def fake_run(argv, timeout):
        calls.append((argv, timeout))
        return CommandResult(argv, 0, "", "")

    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run", fake_run)
    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run_cancellable", fake_run)
    assert scan_networks("wlan0", timeout=2) == []
    assert calls == [(["iw", "dev", "wlan0", "scan"], 2)]
    with pytest.raises(ValueError):
        scan_networks("wlan0;ip")
    assert len(calls) == 1


def test_scan_networks_passes_cancellation_to_child_runner(monkeypatch):
    import threading

    event = threading.Event()
    calls = []

    def fake_run(argv, timeout, cancel_event):
        calls.append((argv, timeout, cancel_event))
        return CommandResult(argv, 0, "", "")

    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run_cancellable", fake_run)
    assert scan_networks("wlan0", timeout=2, cancel_event=event) == []
    assert calls == [(["iw", "dev", "wlan0", "scan"], 2, event)]
