"""Shared visual components: header/section/border styling and token coloring."""

from __future__ import annotations

import curses

from netwatch_ng.tui import components, theme


class FakeStdscr:
    """Minimal stand-in for a curses window that records addstr calls."""

    def __init__(self, height: int = 24, width: int = 80):
        self.maxyx = (height, width)
        self.writes: list[tuple[int, int, str, int]] = []

    def getmaxyx(self):
        return self.maxyx

    def addstr(self, y: int, x: int, text: str, attr: int = 0):
        self.writes.append((y, x, text, attr))


def test_addstr_safe_truncates_to_width():
    stdscr = FakeStdscr(height=5, width=10)
    text = "this is way too long"
    components.addstr_safe(stdscr, 0, 0, text, attr=theme.attr(theme.BODY, False))
    assert stdscr.writes == [(0, 0, text[:9], 0)]


def test_addstr_safe_ignores_out_of_bounds():
    stdscr = FakeStdscr(height=5, width=10)
    components.addstr_safe(stdscr, -1, 0, "nope")
    components.addstr_safe(stdscr, 99, 0, "nope")
    components.addstr_safe(stdscr, 0, 99, "nope")
    assert stdscr.writes == []


def test_is_section_header():
    assert components.is_section_header("CONNECTION") is True
    assert components.is_section_header("NETWATCH CONTROL") is True
    assert components.is_section_header("[UP]") is False
    assert components.is_section_header("[READY]") is False
    assert components.is_section_header("") is False
    assert components.is_section_header("ipv4 address") is False
    assert components.is_section_header("  DEVICES  ") is True


def test_is_border_line():
    assert components.is_border_line("┌────────────┐") is True
    assert components.is_border_line("│ content │") is True
    assert components.is_border_line("└────────────┘") is True
    assert components.is_border_line("normal text") is False
    assert components.is_border_line("") is False


def test_paint_line_title_and_section_are_bold_in_mono():
    stdscr = FakeStdscr()
    components.paint_line(stdscr, 0, 0, 80, "DASHBOARD", enabled=False, title=True)
    components.paint_line(stdscr, 1, 0, 80, "CONNECTION", enabled=False, title=False)
    assert stdscr.writes[0][3] == curses.A_BOLD
    assert stdscr.writes[1][3] == curses.A_BOLD


def test_paint_line_status_token_colored_in_mono():
    stdscr = FakeStdscr()
    components.paint_line(stdscr, 0, 0, 80, "Gateway: [READY] 192.168.1.1", enabled=False, title=False)
    bodies = [w for w in stdscr.writes if "[READY]" not in w[2]]
    tokens = [w for w in stdscr.writes if "[READY]" in w[2]]
    assert tokens, "the [READY] token should be written"
    assert tokens[0][3] == curses.A_BOLD  # success -> bold in mono
    assert all(w[3] == curses.A_NORMAL for w in bodies)


def test_paint_line_writes_full_when_no_token():
    stdscr = FakeStdscr()
    components.paint_line(stdscr, 0, 0, 80, "Default gateway: none configured", enabled=False, title=False)
    assert stdscr.writes == [(0, 0, "Default gateway: none configured", curses.A_NORMAL)]
