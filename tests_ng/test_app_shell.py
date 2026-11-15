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
    assert any("v2.0.0-dev" in text for text in row0)
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
