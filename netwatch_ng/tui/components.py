"""Shared visual components for the NETWATCH NG TUI.

Primitives draw directly onto ``stdscr`` using the theme from
:mod:`netwatch_ng.tui.theme`. Every helper truncates instead of raising so
short terminals never crash the interface.
"""

from __future__ import annotations

import curses
import re

from netwatch_ng.tui import theme

BOX_CHARS = set("┌┐└┘├┤┬┴┼│─")

# When True, panels use ASCII borders (+ - |) instead of UTF-8 box drawing.
# Set by the TUI shell after testing the terminal's capability.
USE_ASCII_BOX = False

# Inline status tokens such as ``[READY]`` or ``[FAILED]`` are painted with a
# semantic color while the surrounding text stays in the body style. The token
# text is always meaningful, so color is never the only carrier of information.
_STATUS_TOKEN_RE = re.compile(r"\[([A-Z][A-Z ]{1,20})\]")

TOKEN_STYLE = {
    "READY": theme.SUCCESS,
    "ACTIVE": theme.SUCCESS,
    "SCANNING": theme.INFO,
    "CONNECTING": theme.INFO,
    "APPLYING": theme.ACCENT,
    "DEGRADED": theme.WARNING,
    "WARNING": theme.WARNING,
    "FAILED": theme.DANGER,
    "ERROR": theme.DANGER,
    "INFO": theme.INFO,
    "SUCCESS": theme.SUCCESS,
    "DRY RUN": theme.WARNING,
}


def addstr_safe(stdscr, y: int, x: int, text: str, attr: int = 0) -> None:
    """Add ``text`` at ``(y, x)`` without ever raising on a short terminal.

    Any rendering error (missing terminal capability, encoding problem with
    non-ASCII box-drawing characters, etc.) is caught and degraded to an
    ASCII-safe fallback so the TUI never crashes on a strange terminal.
    """
    try:
        height, width = stdscr.getmaxyx()
    except curses.error:
        return
    if y < 0 or y >= height or x < 0 or x >= width:
        return
    available = width - x - 1
    if available <= 0:
        return
    chunk = text[:available]
    try:
        stdscr.addstr(y, x, chunk, attr)
    except (curses.error, UnicodeEncodeError, UnicodeError, ValueError):
        # Fall back: replace every non-ASCII code point with '?' so the line
        # still renders even if the terminal cannot display box-drawing chars.
        safe = "".join(c if ord(c) < 128 else "?" for c in chunk)
        try:
            stdscr.addstr(y, x, safe, attr)
        except Exception:
            pass


def is_section_header(line: str) -> bool:
    """True when a line is a short, all-caps section title.

    Bracketed status tokens such as ``[UP]`` are excluded so they keep their
    inline semantic coloring instead of being promoted to a header.
    """
    text = line.strip()
    if not text or len(text) < 3 or len(text) > 40:
        return False
    if not text.isupper():
        return False
    if "[" in text or "]" in text:
        return False
    return True


def is_border_line(line: str) -> bool:
    """True when a line is a box-drawing border line."""
    stripped = line.strip()
    return bool(stripped) and stripped[0] in BOX_CHARS


def paint_line(stdscr, y: int, x: int, max_x: int, line: str, enabled: bool, title: bool = False) -> int:
    """Render a single content line with the appropriate style.

    - title lines: accent, bold
    - box-drawing lines: border color
    - short all-caps section titles: accent, bold
    - everything else: body with inline ``[TOKEN]`` badges colored semantically

    Returns the number of rows consumed (always 1 here).
    """
    width = max_x - x
    if width <= 0 or y < 0:
        return 0
    if title:
        addstr_safe(stdscr, y, x, line[:width], theme.attr(theme.ACCENT, enabled, bold=True))
        return 1
    if is_border_line(line):
        addstr_safe(stdscr, y, x, line[:width], theme.attr(theme.BORDER, enabled))
        return 1
    if is_section_header(line):
        addstr_safe(stdscr, y, x, line[:width], theme.attr(theme.ACCENT, enabled, bold=True))
        return 1
    pos = 0
    for match in _STATUS_TOKEN_RE.finditer(line):
        start, end = match.span()
        if start > pos:
            addstr_safe(stdscr, y, x + pos, line[pos:start], theme.attr(theme.BODY, enabled))
        token = match.group(1)
        style = TOKEN_STYLE.get(token, theme.BODY)
        addstr_safe(stdscr, y, x + start, match.group(0), theme.attr(style, enabled, bold=True))
        pos = end
    if pos < len(line):
        addstr_safe(stdscr, y, x + pos, line[pos:], theme.attr(theme.BODY, enabled))
    return 1


def draw_panel(stdscr, y: int, x: int, h: int, w: int, title: str | None = None,
               enabled: bool = False) -> tuple[int, int, int, int]:
    """Draw a bordered panel and return the inner content region.

    The returned ``(content_y, content_x, content_h, content_w)`` is the area
    where screen content should be painted, just inside the border.
    """
    if h < 3 or w < 3:
        return (y, x, max(h, 0), max(w, 0))
    border_attr = theme.attr(theme.BORDER, enabled)
    if USE_ASCII_BOX:
        top = "+" + "-" * (w - 2) + "+"
        mid = "|"
        bot = "+" + "-" * (w - 2) + "+"
    else:
        top = "┌" + "─" * (w - 2) + "┐"
        mid = "│"
        bot = "└" + "─" * (w - 2) + "┘"
    addstr_safe(stdscr, y, x, top, border_attr)
    addstr_safe(stdscr, y + h - 1, x, bot, border_attr)
    for row in range(1, h - 1):
        addstr_safe(stdscr, y + row, x, mid, border_attr)
        addstr_safe(stdscr, y + row, x + w - 1, mid, border_attr)
    content_y = y + 1
    content_x = x + 1
    content_h = h - 2
    content_w = w - 2
    if title:
        t_attr = theme.attr(theme.ACCENT, enabled, bold=True)
        addstr_safe(stdscr, content_y, content_x, title[: max(content_w - 2, 0)], t_attr)
        content_y += 1
        content_h -= 1
    return (content_y, content_x, content_h, content_w)
