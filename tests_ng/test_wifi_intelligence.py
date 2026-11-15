from __future__ import annotations

import subprocess
import threading
from datetime import datetime

import pytest

from netwatch_ng.core.shell import (
    BinaryNotFound,
    CommandCancelled,
    CommandResult,
    run,
    run_cancellable,
)
from netwatch_ng.wifi_intelligence import (
    AIRMON_NG,
    AIRODUMP_NG,
    AccessPoint,
    RadioState,
    Station,
    WifiSurvey,
    channel_occupancy,
    get_radio_state,
    get_supported_modes,
    list_wireless_interfaces,
    parse_airodump_csv,
    scan_available_networks,
    scan_networks,
    start_monitor_mode,
    stop_monitor_mode,
)

AIRMON_OUTPUT = """PHY\tInterface\tDriver\t\tChipset

phy0\twlan0\t\tath9k_htc\tAtheros Communications AR9271
phy1\twlan1\t\tiwlwifi\tIntel Corporation Wireless 7260
"""

AIRMON_OUTPUT_MONITOR = """PHY\tInterface\tDriver\t\tChipset

phy0\twlan0mon\t\tath9k_htc\tAtheros Communications AR9271
"""

AIRODUMP_CSV = """BSSID, PWR, Beacons, #Data, #/s, CH, MB, ENC, CIPHER, AUTH, ESSID
AA:BB:CC:DD:EE:FF, -45, 100, 50, 1, 6, 54e, WPA2, CCMP, PSK, home-wifi
11:22:33:44:55:66, -70, 10, 0, 0, 36, 86e, WPA, TKIP, PSK, office
-1, -1, 0, 0, 0, -1, 0, -1, -1, -1,

BSSID, STATION, PWR, Rate, Lost, Frames, Probes
AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66, -50, 54e, 0, 100,
AA:BB:CC:DD:EE:FF, 22:33:44:55:66:77, -80, 11e, 5, 20, probe1 probe2
-1, -1, -1, -1, -1, -1,
"""


def _fake_command_result(stdout: str, stderr: str = "", returncode: int = 0):
    return CommandResult([], returncode, stdout, stderr)


def test_list_wireless_interfaces_parses_airmon_output(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(AIRMON_OUTPUT),
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence._SYS_CLASS_NET",
        tmp_path,
    )
    (tmp_path / "wlan0").mkdir()
    (tmp_path / "wlan0" / "type").write_text("1")
    (tmp_path / "wlan0" / "address").write_text("aa:bb:cc:dd:ee:ff")
    (tmp_path / "wlan1").mkdir()
    (tmp_path / "wlan1" / "type").write_text("803")
    (tmp_path / "wlan1" / "address").write_text("11:22:33:44:55:66")

    interfaces = list_wireless_interfaces()
    assert len(interfaces) == 2
    assert interfaces[0].name == "wlan0"
    assert interfaces[0].phy == "phy0"
    assert interfaces[0].driver == "ath9k_htc"
    assert interfaces[0].chipset == "Atheros Communications AR9271"
    assert interfaces[0].mode == "managed"
    assert interfaces[0].mac == "aa:bb:cc:dd:ee:ff"
    assert interfaces[1].name == "wlan1"
    assert interfaces[1].mode == "monitor"
    assert interfaces[1].mac == "11:22:33:44:55:66"


def test_list_wireless_interfaces_skips_header_and_empty_lines(monkeypatch):
    output = "PHY\tInterface\tDriver\t\tChipset\n\n"
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(output),
    )
    assert list_wireless_interfaces() == []


def test_list_wireless_interfaces_binary_not_found(monkeypatch):
    def fake_run(argv, timeout=None):
        raise BinaryNotFound("airmon-ng")

    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run", fake_run)
    with pytest.raises(BinaryNotFound):
        list_wireless_interfaces()


def test_list_wireless_interfaces_airmon_failure(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(
            "", "Run it as root\n", returncode=1
        ),
    )
    with pytest.raises(RuntimeError, match="airmon-ng failed"):
        list_wireless_interfaces()


def test_get_radio_state_returns_none_via_aircrack_engine():
    state = get_radio_state()
    assert state == RadioState(soft_blocked=None, hard_blocked=None)


def test_get_supported_modes_returns_empty_list(monkeypatch):
    called = []

    def fake_run(argv, timeout):
        called.append(argv)
        return _fake_command_result("")

    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run", fake_run)
    assert get_supported_modes("phy0") == []
    assert called == []  # iw phy info must never be invoked


def test_get_supported_modes_rejects_invalid_phy(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda *args, **kwargs: pytest.fail("run must not be invoked"),
    )
    with pytest.raises(ValueError):
        get_supported_modes("")
    with pytest.raises(ValueError):
        get_supported_modes("phy0;id")


def test_start_monitor_mode_parses_created_interface(monkeypatch):
    output = (
        "\t\t(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(output),
    )
    name = start_monitor_mode("wlan0")
    assert name == "wlan0mon"
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(output),
    )
    assert start_monitor_mode("wlan0", channel=6) == "wlan0mon"


def test_start_monitor_mode_already_enabled(monkeypatch):
    output = (
        "\t\t(mac80211 monitor mode already enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(output),
    )
    assert start_monitor_mode("wlan0") == "wlan0mon"


def test_start_monitor_mode_validates_interface(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda *args, **kwargs: pytest.fail("run must not be invoked"),
    )
    with pytest.raises(ValueError):
        start_monitor_mode("wlan0;ip")
    with pytest.raises(ValueError):
        start_monitor_mode("wlan0", channel=-1)


def test_start_monitor_mode_failure(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(
            "", "ERROR adding monitor mode interface: busy\n", returncode=1
        ),
    )
    with pytest.raises(RuntimeError, match="could not enable monitor mode"):
        start_monitor_mode("wlan0")


def test_start_monitor_mode_binary_not_found(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: (_ for _ in ()).throw(BinaryNotFound("airmon-ng")),
    )
    with pytest.raises(BinaryNotFound):
        start_monitor_mode("wlan0")


def test_stop_monitor_mode_success(monkeypatch):
    output = "\t\t(mac80211 monitor mode vif disabled for [phy0]wlan0mon)\n"
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(output, returncode=0),
    )
    stop_monitor_mode("wlan0mon")  # must not raise


def test_stop_monitor_mode_failure(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: _fake_command_result(
            "", "You are trying to stop a device that isn't in monitor mode.\n",
            returncode=1,
        ),
    )
    with pytest.raises(RuntimeError, match="could not stop monitor mode"):
        stop_monitor_mode("wlan0mon")


def test_start_stop_never_run_check_kill(monkeypatch):
    calls = []

    def fake_run(argv, timeout):
        calls.append(list(argv))
        if argv[1] == "start":
            return _fake_command_result(
                "\t\t(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
            )
        return _fake_command_result(
            "\t\t(mac80211 monitor mode vif disabled for [phy0]wlan0mon)\n",
            returncode=0,
        )

    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run", fake_run)
    start_monitor_mode("wlan0")
    stop_monitor_mode("wlan0mon")
    assert all(cmd[1] != "check" for cmd in calls)
    assert not any("kill" in cmd for cmd in calls)


def test_parse_airodump_csv_captures_aps_and_stations():
    aps, stations = parse_airodump_csv(AIRODUMP_CSV)
    assert len(aps) == 2
    assert aps[0].ssid == "home-wifi"
    assert aps[0].bssid == "aa:bb:cc:dd:ee:ff"
    assert aps[0].channel == 6
    assert aps[0].signal_dbm == -45.0
    assert aps[0].advertised_security == "WPA2 (CCMP / PSK)"
    assert aps[1].ssid == "office"
    assert aps[1].channel == 36
    assert aps[1].signal_dbm == -70.0
    assert aps[1].advertised_security == "WPA (TKIP / PSK)"

    assert len(stations) == 2
    assert stations[0].station == "11:22:33:44:55:66"
    assert stations[0].signal_dbm == -50.0
    assert stations[0].rate == "54e"
    assert stations[0].frames == 100
    assert stations[1].station == "22:33:44:55:66:77"
    assert stations[1].probes == "probe1 probe2"


def test_parse_airodump_csv_handles_empty_and_malformed():
    assert parse_airodump_csv("") == ([], [])
    assert parse_airodump_csv("\n\n") == ([], [])
    # rows without the right section header are ignored
    assert parse_airodump_csv("garbage,line\n") == ([], [])
    # malformed AP row (bad MAC, too few columns) is skipped
    text = "BSSID, PWR, Beacons, #Data, #/s, CH, MB, ENC, CIPHER, AUTH, ESSID\nnot-a-mac, -1, 0, 0, 0, 1, 0, -, -, -, ssid\n"
    assert parse_airodump_csv(text) == ([], [])


def test_channel_occupancy_counts_known_channels():
    aps = [
        AccessPoint("a", "aa:bb:cc:dd:ee:ff", 2412, 1, -45.0, "WPA2"),
        AccessPoint("b", "11:22:33:44:55:66", 2412, 1, -50.0, "WPA2"),
        AccessPoint("c", "22:33:44:55:66:77", 5180, 36, -60.0, "WPA"),
    ]
    assert channel_occupancy(aps) == {1: 2, 36: 1}
    assert channel_occupancy([]) == {}


def test_scan_networks_validates_and_uses_argv(monkeypatch, tmp_path):
    calls = []

    def fake_run_cancellable(argv, timeout, cancel_event):
        calls.append((list(argv), timeout))
        return _fake_command_result("")

    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable", fake_run_cancellable
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence._read_latest_airodump_csv",
        lambda directory, prefix="scan-": AIRODUMP_CSV,
    )
    survey = scan_networks("wlan0", timeout=5)
    assert isinstance(survey, WifiSurvey)
    assert survey.interface == "wlan0"
    assert len(survey.access_points) == 2
    assert len(survey.stations) == 2
    assert calls[0][0][0:5] == ["airodump-ng", "--output-format", "csv", "--write-interval", "1"]
    assert calls[0][0][-1] == "wlan0"

    with pytest.raises(ValueError):
        scan_networks("wlan0;ip")
    with pytest.raises(ValueError):
        scan_networks("wlan0", timeout=0)


def test_scan_networks_airodump_binary_not_found(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable",
        lambda argv, timeout, cancel_event: (_ for _ in ()).throw(
            BinaryNotFound("airodump-ng")
        ),
    )
    with pytest.raises(BinaryNotFound):
        scan_networks("wlan0")


def test_scan_networks_airodump_failure(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable",
        lambda argv, timeout, cancel_event: _fake_command_result(
            "", "Interface wlan0 doesn't support monitor mode\n", returncode=1
        ),
    )
    with pytest.raises(RuntimeError, match="airodump-ng survey failed"):
        scan_networks("wlan0")


def test_scan_networks_timeout_is_normal_stop(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable",
        lambda argv, timeout, cancel_event: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(argv, timeout)
        ),
    )
    survey = scan_networks("wlan0", timeout=1)
    assert survey.access_points == []
    assert survey.stations == []


def test_scan_networks_cancellation_is_normal_stop(monkeypatch, tmp_path):
    event = threading.Event()
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable",
        lambda argv, timeout, cancel_event: (_ for _ in ()).throw(
            CommandCancelled("command cancelled: airodump-ng")
        ),
    )
    survey = scan_networks("wlan0", timeout=5, cancel_event=event)
    assert survey.access_points == []


def test_scan_available_networks_no_interface(monkeypatch):
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.list_wireless_interfaces",
        lambda: [],
    )
    with pytest.raises(RuntimeError, match="no wireless interface"):
        scan_available_networks()


def test_scan_available_networks_uses_first_interface(monkeypatch, tmp_path):
    calls = []

    def fake_list():
        return [
            type("IF", (), {"name": "wlan0"})(),
            type("IF", (), {"name": "wlan1"})(),
        ]

    def fake_scan(interface, timeout=30.0, cancel_event=None):
        calls.append(interface)
        return WifiSurvey(interface=interface, access_points=[], stations=[])

    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.list_wireless_interfaces", fake_list
    )
    monkeypatch.setattr("netwatch_ng.wifi_intelligence.scan_networks", fake_scan)
    survey = scan_available_networks()
    assert survey.interface == "wlan0"
    assert calls == ["wlan0"]


def test_run_and_run_cancellable_used_for_aircrack_binaries(monkeypatch):
    """airmon-ng uses run; airodump-ng uses run_cancellable; never shell=True."""
    seen = []
    pathlib = __import__("pathlib")

    def fake_run(argv, timeout):
        seen.append(("run", list(argv)))
        if argv[1:] == ["start", "wlan0"]:
            return _fake_command_result(
                "\t\t(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
            )
        if argv[1:] == ["stop", "wlan0mon"]:
            return _fake_command_result(
                "\t\t(mac80211 monitor mode vif disabled for [phy0]wlan0mon)\n",
                returncode=0,
            )
        return _fake_command_result("")

    def fake_run_cancellable(argv, timeout, cancel_event):
        seen.append(("run_cancellable", list(argv)))
        return _fake_command_result("")

    monkeypatch.setattr("netwatch_ng.wifi_intelligence.run", fake_run)
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable", fake_run_cancellable
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence._SYS_CLASS_NET", pathlib.Path("/nonexistent-sys")
    )
    list_wireless_interfaces()
    start_monitor_mode("wlan0")
    stop_monitor_mode("wlan0mon")
    assert seen[0] == ("run", ["airmon-ng"])
    assert seen[1] == ("run", ["airmon-ng", "start", "wlan0"])
    assert seen[2] == ("run", ["airmon-ng", "stop", "wlan0mon"])


def test_scan_networks_invokes_run_cancellable_never_run(monkeypatch):
    """airodump-ng must be launched through run_cancellable, never run."""
    seen = []

    def fake_run_cancellable(argv, timeout, cancel_event):
        seen.append(list(argv))
        return _fake_command_result("")

    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run_cancellable", fake_run_cancellable
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence.run",
        lambda argv, timeout: (_ for _ in ()).throw(
            AssertionError("run must not be used for airodump-ng")
        ),
    )
    monkeypatch.setattr(
        "netwatch_ng.wifi_intelligence._read_latest_airodump_csv",
        lambda directory, prefix="scan-": "",
    )
    scan_networks("wlan0", timeout=2)
    assert seen and seen[0][0] == "airodump-ng"
