"""App shell rendering: header, navigation sidebar, footer and content panel.

Uses a fake window so the rendering logic is exercised without a real
terminal. No curses interaction, no network, no mutations.
"""

from __future__ import annotations

import curses

from netwatch_ng.discovery import device_intelligence
from netwatch_ng.discovery.nmap_scan import NmapHost, Port
from netwatch_ng.tui import app as app_module


class FakeStdscr:
    def __init__(self, height: int = 24, width: int = 100):
        self.maxyx = (height, width)
        self.writes: list[tuple[int, int, str, int]] = []
        self.erased = False
        self.refreshed = False

    def getmaxyx(self):
        return self.maxyx

    def erase(self):
        self.erased = True

    def refresh(self):
        self.refreshed = True

    def addstr(self, y: int, x: int, text: str, attr: int = 0):
        self.writes.append((y, x, text, attr))


def _writes_at(stdscr, y: int):
    return [w for w in stdscr.writes if w[0] == y]


def test_draw_header_identity_version_mode_and_separator():
    stdscr = FakeStdscr(width=100)
    app_module._draw_header(stdscr, 24, 100, "Dashboard", enabled=False)
    row0 = [w[2] for w in _writes_at(stdscr, 0)]
    assert any("NETWATCH NG" in text for text in row0)
    assert any(f"v{app_module.__version__}" in text for text in row0)
    assert any("[Dashboard]" in text for text in row0)
    row1 = [w[2] for w in _writes_at(stdscr, 1)]
    assert any(set(text) == {"─"} for text in row1)


def test_draw_menu_highlights_selected_in_mono():
    stdscr = FakeStdscr(width=100)
    app_module._draw_menu(stdscr, 24, 0, enabled=False)
    row = _writes_at(stdscr, 2)
    assert row and "Dashboard" in row[0][2]
    # SELECTION in mono is A_REVERSE
    assert row[0][3] == curses.A_REVERSE


def test_draw_menu_planned_item_is_muted():
    stdscr = FakeStdscr(width=100)
    original = app_module.MENU
    app_module.MENU = [("Dashboard", "implemented"), ("Planned Thing", "planned")]
    try:
        app_module._draw_menu(stdscr, 24, 0, enabled=False)
        # row 1 (screen y = 3) is the planned, non-selected item -> dim
        row = _writes_at(stdscr, 3)
        assert row and "Planned Thing" in row[0][2]
        assert row[0][3] == curses.A_DIM
    finally:
        app_module.MENU = original


def test_draw_footer_contains_global_and_contextual():
    stdscr = FakeStdscr(width=100)
    app_module._draw_footer(stdscr, 24, 100, "Devices", enabled=False)
    last = _writes_at(stdscr, 23)
    assert last
    text = last[0][2]
    assert "Navigate" in text
    assert "q Quit" in text
    assert "discover" in text


def test_paint_content_renders_lines_inside_panel():
    stdscr = FakeStdscr(height=24, width=100)
    lines = ["DASHBOARD", "CONNECTION", "  Default gateway: [READY] 192.168.1.1"]
    app_module._paint_content(stdscr, 24, 100, lines, enabled=False)
    contents = [w[2] for w in stdscr.writes]
    assert "DASHBOARD" in contents
    # the token-splitting paint_line writes the line in segments
    assert any("Default gateway:" in text for text in contents)
    assert "[READY]" in contents
    assert any("192.168.1.1" in text for text in contents)
    # content starts inside the panel border (x > 0)
    assert all(w[1] > 0 for w in stdscr.writes)


def test_restore_monitor_interface_stops_and_swallows_errors(monkeypatch):
    """NETWATCH must not leave an adapter in monitor mode when it exits."""
    calls = []
    monkeypatch.setattr(
        app_module.wifi_intelligence,
        "stop_monitor_mode",
        lambda interface: calls.append(interface),
    )
    app_module._restore_monitor_interface("wlan0mon")
    assert calls == ["wlan0mon"]

    # A None interface (nothing was put in monitor mode) is a no-op.
    app_module._restore_monitor_interface(None)
    assert calls == ["wlan0mon"]

    # A failing restore must not raise out of the exit path.
    def boom(interface):
        raise RuntimeError("airmon-ng missing")

    monkeypatch.setattr(app_module.wifi_intelligence, "stop_monitor_mode", boom)
    app_module._restore_monitor_interface("wlan0mon")  # must not raise


class _QuitScreen(FakeStdscr):
    """Fake screen that quits immediately and records addstr calls."""

    def keypad(self, value):
        pass

    def timeout(self, value):
        pass

    def getch(self):
        return ord("q")

    def move(self, y, x):
        pass

    def clrtoeol(self):
        pass

    def addstr(self, y, x, text, attr=0):
        self.writes.append((y, x, text, attr))


def test_run_restores_monitor_interface_on_exit(monkeypatch):
    """Driving the real run() loop to quit must restore monitor mode."""
    restored = []
    monkeypatch.setattr(curses, "curs_set", lambda value: None)
    monkeypatch.setattr(app_module, "_configure_colors", lambda mode: False)
    monkeypatch.setattr(app_module, "_restore_monitor_interface", restored.append)
    monkeypatch.setattr(app_module, "_screen_lines", lambda *a, **k: ["DASHBOARD"])
    app_module.run(_QuitScreen())
    assert restored  # exit path invoked the restore helper


class _RefreshScreen(FakeStdscr):
    """Fake screen: DOWN to Devices, then 'r' refresh, then 'q' quit."""

    def __init__(self):
        super().__init__()
        self._keys = iter([curses.KEY_DOWN, ord("r"), ord("q")])

    def keypad(self, value):
        pass

    def timeout(self, value):
        pass

    def getch(self):
        return next(self._keys)

    def move(self, y, x):
        pass

    def clrtoeol(self):
        pass

    def addstr(self, y, x, text, attr=0):
        self.writes.append((y, x, text, attr))


def test_refresh_devices_relaunches_active_scan(monkeypatch):
    """Pressing 'r' on the Devices screen re-launches an active Nmap scan."""

    class _FakeFuture:
        def __init__(self, result):
            self._result = result

        def done(self):
            return True

        def result(self):
            return self._result

        def cancel(self):
            return False

    class _FakeExecutor:
        """Executor that runs submitted tasks synchronously (deterministic tests)."""

        def submit(self, fn, *args, **kwargs):
            result = fn(*args, **kwargs)
            return _FakeFuture(result)

        def shutdown(self, **kwargs):
            pass

    submitted_targets = []

    def fake_active_scan(targets, timeout=60.0, cancel_event=None):
        submitted_targets.append(targets)
        return _FakeFuture([])

    monkeypatch.setattr(curses, "curs_set", lambda value: None)
    monkeypatch.setattr(app_module, "_configure_colors", lambda mode: False)
    monkeypatch.setattr(app_module, "_restore_monitor_interface", lambda interface: None)
    monkeypatch.setattr(app_module, "_test_utf8_box", lambda stdscr: True)
    monkeypatch.setattr(app_module, "show_splash", lambda stdscr, colors: None)
    monkeypatch.setattr(app_module, "_screen_lines", lambda *a, **k: ["DASHBOARD"])
    monkeypatch.setattr(app_module, "ThreadPoolExecutor", lambda *a, **k: _FakeExecutor())
    monkeypatch.setattr(
        app_module.settings,
        "load_settings",
        lambda: {
            "refresh_seconds": 0,
            "color_mode": "mono",
            "scan_timeout_seconds": 60.0,
            "preferred_interface": None,
        },
    )
    monkeypatch.setattr(
        app_module.network, "get_local_subnet", lambda family="inet": "192.168.1.0/24"
    )
    monkeypatch.setattr(app_module.devices_mod, "active_scan", fake_active_scan)

    class _RefreshScreen(FakeStdscr):
        """Fake screen: DOWN to Devices, then 'r' refresh, then 'q' quit."""

        def __init__(self):
            super().__init__()
            self._keys = iter([curses.KEY_DOWN, ord("r"), ord("q")])

        def keypad(self, value):
            pass

        def timeout(self, value):
            pass

        def getch(self):
            return next(self._keys)

        def move(self, y, x):
            pass

        def clrtoeol(self):
            pass

        def addstr(self, y, x, text, attr=0):
            self.writes.append((y, x, text, attr))

    app_module.run(_RefreshScreen())

    # First active scan: auto-launched on first entry to Devices.
    # Second active scan: triggered by pressing 'r' (refresh).
    assert len(submitted_targets) == 2
    assert submitted_targets[0] == "192.168.1.0/24"
    assert submitted_targets[1] == "192.168.1.0/24"


def test_auto_service_scan_runs_for_all_discovered_devices(monkeypatch):
    """Every device discovered by the automatic active scan gets an
    automatic service/version scan without operator intervention."""

    class _FakeFuture:
        def __init__(self, result):
            self._result = result

        def done(self):
            return True

        def result(self):
            return self._result

        def cancel(self):
            return False

    class _FakeExecutor:
        def submit(self, fn, *args, **kwargs):
            result = fn(*args, **kwargs)
            return _FakeFuture(result)

        def shutdown(self, **kwargs):
            pass

    discovered_devices = [
        device_intelligence.Device(ip="192.168.1.10"),
        device_intelligence.Device(ip="192.168.1.11"),
        device_intelligence.Device(ip="192.168.1.12"),
    ]

    service_scan_targets: list[str] = []

    def fake_active_scan(targets, timeout=60.0, cancel_event=None):
        return discovered_devices

    def fake_service_scan(target, timeout=120.0, cancel_event=None):
        service_scan_targets.append(target)
        return NmapHost(
            ip=target,
            mac=None,
            nmap_vendor=None,
            hostname=None,
            up=True,
            ports=[
                Port(
                    number=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                    product=None,
                    version=None,
                )
            ],
        )

    monkeypatch.setattr(curses, "curs_set", lambda value: None)
    monkeypatch.setattr(app_module, "_configure_colors", lambda mode: False)
    monkeypatch.setattr(app_module, "_restore_monitor_interface", lambda interface: None)
    monkeypatch.setattr(app_module, "_test_utf8_box", lambda stdscr: True)
    monkeypatch.setattr(app_module, "show_splash", lambda stdscr, colors: None)
    monkeypatch.setattr(app_module, "_screen_lines", lambda *a, **k: ["DASHBOARD"])
    monkeypatch.setattr(app_module, "ThreadPoolExecutor", lambda *a, **k: _FakeExecutor())
    monkeypatch.setattr(
        app_module.settings,
        "load_settings",
        lambda: {
            "refresh_seconds": 0,
            "color_mode": "mono",
            "scan_timeout_seconds": 60.0,
            "preferred_interface": None,
        },
    )
    monkeypatch.setattr(
        app_module.network, "get_local_subnet", lambda family="inet": "192.168.1.0/24"
    )
    monkeypatch.setattr(app_module.devices_mod, "active_scan", fake_active_scan)
    monkeypatch.setattr(app_module.nmap_scan, "service_scan", fake_service_scan)

    class _DevicesScreen(FakeStdscr):
        """Fake screen: DOWN to Devices, then 'q' quit."""

        def __init__(self):
            super().__init__()
            self._keys = iter([curses.KEY_DOWN, ord("q")])

        def keypad(self, value):
            pass

        def timeout(self, value):
            pass

        def getch(self):
            return next(self._keys)

        def move(self, y, x):
            pass

        def clrtoeol(self):
            pass

        def addstr(self, y, x, text, attr=0):
            self.writes.append((y, x, text, attr))

    app_module.run(_DevicesScreen())

    # Every discovered host must receive an automatic service scan.
    assert len(service_scan_targets) == 3
    assert "192.168.1.10" in service_scan_targets
    assert "192.168.1.11" in service_scan_targets
    assert "192.168.1.12" in service_scan_targets
