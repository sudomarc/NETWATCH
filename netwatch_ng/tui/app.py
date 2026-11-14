"""NETWATCH NG TUI shell.

Sprint 1 status: only Dashboard and System Manager are backed by real,
tested code. Every other menu entry opens an honest status screen that
says so explicitly — this is a progress view, not a fake button. No
screen here claims a capability that isn't implemented and tested.
"""

from __future__ import annotations

import curses

from netwatch_ng.tui.screens.dashboard import build_dashboard_lines
from netwatch_ng.tui.screens.system_manager import build_system_manager_lines

IMPLEMENTED = "implemented"
PLANNED = "planned"

MENU: list[tuple[str, str]] = [
    ("Dashboard", IMPLEMENTED),
    ("Devices", PLANNED),
    ("Router Intelligence", PLANNED),
    ("Wi-Fi Intelligence", PLANNED),
    ("Firewall", PLANNED),
    ("Traffic Manager", PLANNED),
    ("Network Diagnostics", PLANNED),
    ("System Manager", IMPLEMENTED),
    ("Settings", PLANNED),
    ("Logs", PLANNED),
    ("About", IMPLEMENTED),
]


def _about_lines() -> list[str]:
    return [
        "NETWATCH NG — Linux network supervision/administration TUI",
        "Sprint 1: network engine (interfaces, gateway, DNS) + dependency",
        "detection. Discovery, Wi-Fi, firewall, traffic shaping, router",
        "intelligence and diagnostics are not implemented yet.",
        "Repository: github.com/sudomarc/NETWATCH (branch v2/python-rewrite)",
    ]


def _planned_lines(label: str) -> list[str]:
    return [
        f"{label}: not implemented yet.",
        "This module is scheduled in a later sprint of the NETWATCH NG",
        "rewrite and intentionally shows no simulated data or buttons.",
    ]


def _screen_lines(label: str, status: str) -> list[str]:
    if label == "Dashboard":
        return build_dashboard_lines()
    if label == "System Manager":
        return build_system_manager_lines()
    if label == "About":
        return _about_lines()
    return _planned_lines(label)


def run(stdscr) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected row
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # warnings / planned

    selected = 0
    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        stdscr.addstr(0, 0, "NETWATCH NG".ljust(max(width - 1, 0)), curses.A_BOLD)
        stdscr.addstr(1, 0, "-" * max(width - 1, 0))

        menu_width = 24
        for row, (label, status) in enumerate(MENU):
            y = row + 2
            if y >= height - 1:
                break
            marker = " " if status == IMPLEMENTED else "~"
            text = f"{marker} {label}"[: menu_width - 1]
            attr = curses.color_pair(1) if row == selected else curses.A_NORMAL
            if status != IMPLEMENTED and row != selected:
                attr = curses.color_pair(2)
            stdscr.addstr(y, 0, text.ljust(menu_width), attr)

        label, status = MENU[selected]
        try:
            lines = _screen_lines(label, status)
        except Exception as exc:  # pragma: no cover - defensive, surfaced to user
            lines = [f"Error building screen: {exc}"]

        for i, line in enumerate(lines):
            y = i + 2
            if y >= height - 1:
                break
            stdscr.addstr(y, menu_width + 2, line[: max(width - menu_width - 3, 0)])

        footer = "Up/Down: navigate   q: quit"
        stdscr.addstr(height - 1, 0, footer[: max(width - 1, 0)], curses.A_DIM)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            break
        elif key in (curses.KEY_UP,):
            selected = (selected - 1) % len(MENU)
        elif key in (curses.KEY_DOWN,):
            selected = (selected + 1) % len(MENU)


def main() -> None:
    curses.wrapper(run)
