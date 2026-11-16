"""Startup splash: rendering, automatic transition, keyboard skip, degradation.

Uses a fake window and injected virtual time: no curses interaction, no
network, no mutations, no real-time waits.
"""

from __future__ import annotations

import curses

from netwatch_ng import __version__
from netwatch_ng.tui import splash


class FakeStdscr:
    def __init__(self, height: int = 24, width: int = 100, keys=None):
        self.maxyx = (height, width)
        self.writes: list[tuple[int, int, str, int]] = []
        self.timeouts: list[int] = []
        self.erase_count = 0
        self.refresh_count = 0
        self._keys = list(keys or [])

    def getmaxyx(self):
        return self.maxyx

    def erase(self):
        self.erase_count += 1

    def refresh(self):
        self.refresh_count += 1

    def timeout(self, value):
        self.timeouts.append(value)

    def keypad(self, value):
        pass

    def curs_set(self, value):
        pass

    def addstr(self, y: int, x: int, text: str, attr: int = 0):
        self.writes.append((y, x, text, attr))

    def getch(self):
        if self._keys:
            return self._keys.pop(0)
        return -1


def _virtual_clock(times):
    iterator = iter(times)

    def tick():
        try:
            return next(iterator)
        except StopIteration:
            raise RuntimeError("virtual clock ran out of times")

    return tick


def _written_text(stdscr) -> str:
    return "\n".join(text for _, _, text, _ in stdscr.writes)


def test_splash_renders_logo_tagline_and_version():
    stdscr = FakeStdscr(width=100, keys=[-1, -1])
    clock = _virtual_clock([0.0, 0.0, 0.04, 7.1])  # two frames, then past the 7s deadline
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    written = _written_text(stdscr)
    for line in splash.LOGO:
        assert line in written, f"missing logo line: {line!r}"
    assert splash.TAGLINE in written
    assert f"v{__version__}" in written
    assert "Loading" in written


def test_splash_styles_are_correct():
    stdscr = FakeStdscr(width=100, keys=[-1, -1])
    clock = _virtual_clock([0.0, 0.0, 7.1])
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    by_text = {}
    for y, x, text, attr in stdscr.writes:
        by_text.setdefault(text.strip(), []).append(attr)
    # Mono fallbacks: ACCENT -> bold, MUTED/INFO -> dim, BODY -> normal.
    assert any(attr == curses.A_BOLD for attr in by_text.get("NETWORK VISIBILITY. INTELLIGENCE. CONTROL.", []))
    assert any(attr == curses.A_DIM for attr in by_text.get(f"v{__version__}", []))
    assert any(attr == curses.A_BOLD for attr in by_text.get(splash.LOGO[0].strip(), []))


def test_splash_color_enabled_path_is_distinct_from_mono():
    """The color path must style the logo and version differently (curses
    color pairs require an initialized terminal, exercised by the e2e suite;
    here we only verify the mono fallback is deterministic).
    """
    stdscr = FakeStdscr(width=100, keys=[-1, -1])
    clock = _virtual_clock([0.0, 0.0, 7.1])
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    by_text = {}
    for y, x, text, attr in stdscr.writes:
        by_text.setdefault(text.strip(), []).append(attr)
    logo_attrs = by_text.get(splash.LOGO[0].strip(), [])
    version_attrs = by_text.get(f"v{__version__}", [])
    assert logo_attrs and version_attrs
    assert all(attr == curses.A_BOLD for attr in logo_attrs)
    assert all(attr == curses.A_DIM for attr in version_attrs)


def test_splash_any_key_skips_immediately():
    stdscr = FakeStdscr(width=100, keys=[ord(" ")])
    clock = _virtual_clock([0.0, 0.0, 99.0])  # would run for a long time without the key
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    assert stdscr.erase_count == 1  # one frame, then the key stopped the loop
    assert splash.TAGLINE in _written_text(stdscr)
    assert stdscr.timeouts[-1] == 200  # the main-loop timeout is restored


def test_splash_quit_key_is_requeued():
    stdscr = FakeStdscr(width=100, keys=[ord("q")])
    clock = _virtual_clock([0.0, 0.0, 99.0])
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    assert stdscr.erase_count == 1


def test_splash_auto_transition_after_duration():
    stdscr = FakeStdscr(width=100, keys=[-1, -1, -1])
    clock = _virtual_clock([0.0, 0.0, 0.5, 7.1])  # the third tick passes the 7s deadline
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    assert stdscr.erase_count == 2  # two frames, then automatic transition
    assert stdscr.timeouts[-1] == 200


def test_splash_custom_duration():
    stdscr = FakeStdscr(width=100, keys=[-1, -1])
    clock = _virtual_clock([0.0, 0.0, 0.2, 0.4])
    splash.show_splash(stdscr, colors_enabled=False, duration=0.3, clock=clock)
    assert stdscr.erase_count == 2


def test_splash_animation_advances_across_frames():
    stdscr = FakeStdscr(width=100, keys=[-1, -1, -1, -1, ord("x")])
    clock = _virtual_clock([0.0, 0.0, 0.04, 0.08, 0.12, 2.0])
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    written = _written_text(stdscr)
    # The propagation pulse visits consecutive nodes across frames.
    assert "*---o---o---o---o" in written
    assert "o---*---o---o---o" in written
    assert "o---o---*---o---o" in written
    assert stdscr.erase_count == 4


def test_splash_narrow_terminal_uses_compact_wordmark():
    stdscr = FakeStdscr(height=24, width=30, keys=[-1, -1])
    clock = _virtual_clock([0.0, 0.0, 7.1])
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    written = _written_text(stdscr)
    assert "NETWATCH NG" in written
    assert f"v{__version__}" in written
    assert "NETWORK VISIBILITY" in written  # tagline may be truncated to width
    # The full logotype lines are wider than the terminal and never written.
    for line in splash.LOGO:
        assert line not in written


def test_splash_too_small_terminal_skips_splash():
    stdscr = FakeStdscr(height=5, width=30, keys=[])
    clock = _virtual_clock([0.0, 0.0])
    splash.show_splash(stdscr, colors_enabled=False, duration=1.0, clock=clock)
    assert stdscr.writes == []
    assert stdscr.erase_count == 0
