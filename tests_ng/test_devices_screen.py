"""Devices screen builder: history-cache failure must degrade visibly,
never take down the whole screen. Fully mocked; no network access.
"""

from __future__ import annotations

from netwatch_ng.discovery import device_intelligence
from netwatch_ng.tui.screens import devices as devices_screen


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


def _fake_device(ip: str) -> device_intelligence.Device:
    return device_intelligence.Device(ip=ip, mac="aa:bb:cc:dd:ee:ff")


def test_history_failure_renders_warning_instead_of_raising(monkeypatch, tmp_path):
    monkeypatch.setattr(devices_screen, "which", lambda _binary: "/sbin/ip")
    monkeypatch.setattr(
        devices_screen.devices_mod, "passive_scan",
        lambda family="inet": [_fake_device("192.168.1.9")],
    )
    monkeypatch.setattr(devices_screen, "get_config_dir", lambda: tmp_path)

    def _boom(*_args, **_kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(devices_screen.history, "save_scan", _boom)

    lines = devices_screen.build_devices_lines()
    flat = _flatten_lines(lines)
    text = "\n".join(flat)
    assert "192.168.1.9" in text
    assert "Scan history unavailable" in text


def test_history_success_renders_without_warning(monkeypatch, tmp_path):
    monkeypatch.setattr(devices_screen, "which", lambda _binary: "/sbin/ip")
    monkeypatch.setattr(
        devices_screen.devices_mod, "passive_scan",
        lambda family="inet": [_fake_device("192.168.1.9")],
    )
    monkeypatch.setattr(devices_screen, "get_config_dir", lambda: tmp_path)
    monkeypatch.setattr(devices_screen.history, "save_scan", lambda *_a, **_k: None)
    monkeypatch.setattr(devices_screen.history, "diff_last_two_scans", lambda *_a, **_k: None)

    lines = devices_screen.build_devices_lines()
    flat = _flatten_lines(lines)
    assert not any("Scan history unavailable" in line for line in flat)


def test_missing_ip_binary_shows_notice_not_crash(monkeypatch):
    monkeypatch.setattr(devices_screen, "which", lambda _binary: None)
    lines = devices_screen.build_devices_lines()
    flat = _flatten_lines(lines)
    assert any("iproute2" in line for line in flat)