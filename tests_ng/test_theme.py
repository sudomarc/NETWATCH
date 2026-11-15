"""Theme module: mono attributes always work; color path degrades gracefully."""

from __future__ import annotations

import curses

from netwatch_ng.tui import theme


def test_attr_mono_never_raises():
    for kind in theme.PAIRS:
        value = theme.attr(kind, False)
        assert isinstance(value, int)
        assert value >= 0


def test_attr_mono_selection_is_reverse():
    assert theme.attr(theme.SELECTION, False) == curses.A_REVERSE


def test_attr_mono_body_is_normal():
    assert theme.attr(theme.BODY, False) == curses.A_NORMAL


def test_init_palette_mono_returns_false():
    assert theme.init_palette(False) is False


def test_init_palette_color_skips_without_terminal(monkeypatch):
    monkeypatch.setattr(curses, "has_colors", lambda: False)
    assert theme.init_palette(True) is False
