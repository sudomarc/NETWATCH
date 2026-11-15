"""Visual theme for the NETWATCH NG TUI.

Defines a dark, modern, NOC-inspired palette (electric blue, cyan, green,
orange/yellow and red) built on terminal-native curses colors so it follows
the operator's terminal theme. Colors are always paired with words: the
interface never relies on color alone.

When colors are disabled (``mono`` mode, or a terminal without color
support) every style degrades to a monochrome attribute (bold, dim, reverse,
underline) so the interface remains usable on any terminal.
"""

from __future__ import annotations

import curses

# Style kinds referenced by the TUI shell and the screen builders.
BODY = "body"
MUTED = "muted"
ACCENT = "accent"
SUCCESS = "success"
WARNING = "warning"
DANGER = "danger"
INFO = "info"
HEADER = "header"
SELECTION = "selection"
BORDER = "border"
BADGE_SUCCESS = "badge_success"
BADGE_WARNING = "badge_warning"
BADGE_DANGER = "badge_danger"
BADGE_INFO = "badge_info"

# Curses color pairs. Background -1 = terminal default (transparent), so the
# palette respects a dark terminal without forcing RGB values.
PAIRS = {
    BODY: 1,
    MUTED: 2,
    ACCENT: 3,
    SUCCESS: 4,
    WARNING: 5,
    DANGER: 6,
    HEADER: 7,
    BORDER: 8,
    BADGE_SUCCESS: 9,
    BADGE_WARNING: 10,
    BADGE_DANGER: 11,
    BADGE_INFO: 12,
    SELECTION: 13,
}

_FOREGROUNDS = {
    BODY: -1,
    MUTED: curses.COLOR_CYAN,
    ACCENT: curses.COLOR_BLUE,
    SUCCESS: curses.COLOR_GREEN,
    WARNING: curses.COLOR_YELLOW,
    DANGER: curses.COLOR_RED,
    INFO: curses.COLOR_CYAN,
    HEADER: curses.COLOR_CYAN,
    BORDER: curses.COLOR_CYAN,
    BADGE_SUCCESS: curses.COLOR_GREEN,
    BADGE_WARNING: curses.COLOR_YELLOW,
    BADGE_DANGER: curses.COLOR_RED,
    BADGE_INFO: curses.COLOR_CYAN,
    SELECTION: curses.COLOR_WHITE,
}

_BACKGROUNDS = {
    BODY: -1,
    MUTED: -1,
    ACCENT: -1,
    SUCCESS: -1,
    WARNING: -1,
    DANGER: -1,
    INFO: -1,
    HEADER: -1,
    BORDER: -1,
    BADGE_SUCCESS: -1,
    BADGE_WARNING: -1,
    BADGE_DANGER: -1,
    BADGE_INFO: -1,
    SELECTION: curses.COLOR_BLUE,
}

# Monochrome fallbacks (attributes only, no color).
MONO_ATTR = {
    BODY: curses.A_NORMAL,
    MUTED: curses.A_DIM,
    ACCENT: curses.A_BOLD,
    SUCCESS: curses.A_BOLD,
    WARNING: curses.A_BOLD,
    DANGER: curses.A_BOLD,
    INFO: curses.A_DIM,
    HEADER: curses.A_BOLD | curses.A_UNDERLINE,
    BORDER: curses.A_DIM,
    BADGE_SUCCESS: curses.A_BOLD,
    BADGE_WARNING: curses.A_BOLD,
    BADGE_DANGER: curses.A_BOLD,
    BADGE_INFO: curses.A_DIM,
    SELECTION: curses.A_REVERSE,
}


def init_palette(enabled: bool) -> bool:
    """Initialize the curses color palette.

    Returns ``True`` when color initialization was performed. A no-op (and
    ``False``) when colors are disabled or the terminal does not support
    them; callers then render with :func:`attr` monochrome fallbacks.
    """
    if not enabled or not curses.has_colors():
        return False
    try:
        curses.start_color()
        curses.use_default_colors()
        for kind, pair in PAIRS.items():
            try:
                curses.init_pair(pair, _FOREGROUNDS[kind], _BACKGROUNDS[kind])
            except curses.error:
                # Some terminals cannot redefine every pair; skip it and
                # keep the others.
                pass
    except curses.error:
        pass
    return True


def attr(kind: str, enabled: bool, bold: bool = False) -> int:
    """Return the curses attribute for a style kind."""
    if not enabled:
        return MONO_ATTR.get(kind, curses.A_NORMAL)
    pair = PAIRS.get(kind)
    value = curses.color_pair(pair) if pair else 0
    if bold:
        value |= curses.A_BOLD
    return value
