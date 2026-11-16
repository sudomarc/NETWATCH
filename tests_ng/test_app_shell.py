"""App shell rendering: header, navigation sidebar, footer and content panel.

Uses a fake window so the rendering logic is exercised without a real
terminal. No curses interaction, no network, no mutations.
"""

from __future__ import annotations

import curses

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
    assert any("v2.0.0.dev1" in text for text in row0)
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
