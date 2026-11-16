"""Animated startup splash screen for NETWATCH NG.

Shown once at launch, before the Dashboard opens. It runs for several
seconds or until the operator presses any key, then returns so the existing
curses shell can open the Dashboard.

The rendering is terminal-native and degrades gracefully:

- ASCII only: no box-drawing or UTF-8 dependencies.
- Theme attributes (restrained blue/cyan accents) when color is available,
  monochrome bold/dim/reverse otherwise; color is never the only carrier of
  information.
- Centered, vertically balanced layout; compact wordmark on small
  terminals; skipped entirely when the terminal is too small to hold it.
- No network requests, system scans, or privileged operations are performed.
"""

from __future__ import annotations

import curses
import time

from netwatch_ng import __version__
from netwatch_ng.tui import components, theme

TAGLINE = "NETWORK VISIBILITY. INTELLIGENCE. CONTROL."
WORDMARK = "NETWATCH NG"

DURATION = 7.0          # seconds the splash runs unless skipped
FRAME_DELAY = 0.05      # targeted seconds between animation frames (~20 fps)
MIN_HEIGHT = 8
MIN_WIDTH = 30

# Eight-letter block logotype, ASCII only.
LOGO = (
    " ____  ____  ____  ____  ____  ____  ____  ____",
    "||N  |||E  |||T  |||W  |||A  |||T  |||C  |||H  ||",
    "||__||||__||||__||||__||||__||||__||||__||||__||",
    " |/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|",
)
LOGO_WIDTH = max(len(line) for line in LOGO)
SUBTITLE = "network supervision terminal"

# Five connected nodes; a traveling pulse marks signal propagation.
NODES = "o---o---o---o---o"
_NODE_POSITIONS = (0, 4, 8, 12, 16)
_PULSE_SEQUENCE = (0, 1, 2, 3, 4, 3, 2, 1)  # ping-pong across the nodes
_SPINNER = ("-", "\\", "|", "/")

_STYLE = {
    "logo": (theme.ACCENT, True),
    "subtitle": (theme.MUTED, False),
    "nodes": (theme.INFO, False),
    "tagline": (theme.ACCENT, True),
    "version": (theme.MUTED, False),
    "indicator": (theme.BODY, False),
    "body": (theme.BODY, False),
}


def _nodes_frame(frame: int) -> str:
    """Return the node row with the propagation pulse at one node."""
    position = _NODE_POSITIONS[_PULSE_SEQUENCE[frame % len(_PULSE_SEQUENCE)]]
    chars = list(NODES)
    chars[position] = "*"
    return "".join(chars)


def _center_x(width: int, text: str) -> int:
    return max(0, (width - len(text)) // 2)


def _splash_rows(width: int, frame: int) -> list[tuple[str, str]]:
    """Build the centered rows to render, each as ``(text, style_key)``."""
    wide = width >= LOGO_WIDTH + 4
    rows: list[tuple[str, str]] = []
    if wide:
        for line in LOGO:
            rows.append((line, "logo"))
        rows.append(("", "body"))
        rows.append((SUBTITLE, "subtitle"))
        rows.append(("", "body"))
    else:
        # Compact wordmark for small terminals.
        rows.append((WORDMARK, "logo"))
    rows.append((_nodes_frame(frame), "nodes"))
    rows.append(("", "body"))
    rows.append((TAGLINE, "tagline"))
    rows.append((f"v{__version__}", "version"))
    dots = "." * (1 + frame % 3)
    spinner = _SPINNER[frame % len(_SPINNER)]
    rows.append((f"{spinner} Loading{dots}", "indicator"))
    return rows


def show_splash(
    stdscr,
    colors_enabled: bool,
    duration: float = DURATION,
    clock=time.monotonic,
) -> None:
    """Render the animated splash until ``duration`` elapses or any key is pressed.
    ``clock`` is injected so tests can drive virtual time instead of real
    time. Any key press skips the splash immediately; ``q``/``Q`` is
    re-queued so the operator can quit straight from the splash.
    """
    if duration <= 0:
        return
    addstr = components.addstr_safe
    enabled = bool(colors_enabled)
    start = clock()
    deadline = start + duration
    frame = 0
    try:
        stdscr.timeout(max(1, int(FRAME_DELAY * 1000)))
    except curses.error:
        pass
    try:
        while True:
            if clock() >= deadline:
                return
            try:
                height, width = stdscr.getmaxyx()
            except curses.error:
                return
            if height < MIN_HEIGHT or width < MIN_WIDTH:
                # Too small for a centered layout: open the Dashboard directly.
                return
            stdscr.erase()
            start_y = max(1, (height - len(_splash_rows(width, 0))) // 2)
            for offset, (text, style_key) in enumerate(
                _splash_rows(width, frame)
            ):
                y = start_y + offset
                if y >= height - 1:
                    break
                x = _center_x(width, text)
                kind, bold = _STYLE[style_key]
                addstr(stdscr, y, x, text, theme.attr(kind, enabled, bold=bold))
            try:
                stdscr.refresh()
            except curses.error:
                pass
            frame += 1
            key = stdscr.getch()
            if key == -1:
                continue
            if key in (ord("q"), ord("Q")):
                try:
                    curses.ungetch(key)
                except curses.error:
                    pass
            return
    finally:
        try:
            stdscr.timeout(200)
        except curses.error:
            pass
