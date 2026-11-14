"""NETWATCH NG TUI shell with explicit status for implemented modules."""

from __future__ import annotations

import curses
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event

from netwatch_ng.tui.screens.dashboard import build_dashboard_lines
from netwatch_ng.tui.screens.devices import build_devices_lines
from netwatch_ng.tui.screens.router_intelligence import build_router_lines
from netwatch_ng.tui.screens.system_manager import build_system_manager_lines
from netwatch_ng.tui.screens.wifi_intelligence import build_wifi_lines
from netwatch_ng import router_intelligence, wifi_intelligence

IMPLEMENTED = "implemented"
PLANNED = "planned"

MENU: list[tuple[str, str]] = [
    ("Dashboard", IMPLEMENTED),
    ("Devices", IMPLEMENTED),
    ("Router Intelligence", IMPLEMENTED),
    ("Wi-Fi Intelligence", IMPLEMENTED),
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
        "Implemented: network engine, device discovery and identification,",
        "router gateway intelligence, Wi-Fi inventory and AP survey.",
        "Still planned: firewall, traffic shaping, diagnostics and settings.",
        "Repository: github.com/sudomarc/NETWATCH",
    ]


def _planned_lines(label: str) -> list[str]:
    return [
        f"{label}: not implemented yet.",
        "This module is scheduled in a later sprint of the NETWATCH NG",
        "rewrite and intentionally shows no simulated data or buttons.",
    ]


def _screen_lines(
    label: str,
    status: str,
    router_result: tuple | None = None,
    router_message: str | None = None,
    wifi_result: tuple | None = None,
    wifi_message: str | None = None,
) -> list[str]:
    if label == "Dashboard":
        return build_dashboard_lines()
    if label == "Devices":
        return build_devices_lines()
    if label == "Router Intelligence":
        report, services = router_result if router_result is not None else (None, None)
        return build_router_lines(report, services, router_message)
    if label == "Wi-Fi Intelligence":
        interface, access_points = wifi_result if wifi_result is not None else (None, None)
        return build_wifi_lines(access_points, interface, wifi_message)
    if label == "System Manager":
        return build_system_manager_lines()
    if label == "About":
        return _about_lines()
    return _planned_lines(label)


def run(stdscr) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(200)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected row
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # warnings / planned

    selected = 0
    executor = ThreadPoolExecutor(max_workers=1)
    router_probe: Future | None = None
    wifi_scan: Future | None = None
    router_result = None
    wifi_result = None
    router_message = None
    wifi_message = None
    wifi_cancel = Event()
    previous_selected = None
    lines: list[str] = []
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
        if selected != previous_selected:
            try:
                lines = _screen_lines(
                    label, status, router_result, router_message, wifi_result, wifi_message
                )
            except Exception as exc:  # pragma: no cover - defensive, surfaced to user
                lines = [f"Error building screen: {exc}"]
            previous_selected = selected

        if router_probe is not None and router_probe.done():
            try:
                router_result = router_probe.result()
                router_message = None
            except Exception as exc:
                router_message = f"Management port checks failed: {exc}"
            router_probe = None
            if label == "Router Intelligence":
                lines = _screen_lines(
                    label, status, router_result, router_message, wifi_result, wifi_message
                )

        if wifi_scan is not None and wifi_scan.done():
            try:
                wifi_result = wifi_scan.result()
                wifi_message = None
            except Exception as exc:
                wifi_message = f"Wi-Fi survey failed: {exc}"
            wifi_scan = None
            if label == "Wi-Fi Intelligence":
                lines = _screen_lines(
                    label, status, router_result, router_message, wifi_result, wifi_message
                )

        for i, line in enumerate(lines):
            y = i + 2
            if y >= height - 1:
                break
            stdscr.addstr(y, menu_width + 2, line[: max(width - menu_width - 3, 0)])

        footer = "Up/Down: navigate   r: refresh   q: quit"
        if label == "Router Intelligence":
            footer = "Up/Down: navigate   p: check gateway ports   r: refresh   q: quit"
        elif label == "Wi-Fi Intelligence":
            footer = "Up/Down: navigate   s: survey access points   r: refresh   q: quit"
        stdscr.addstr(height - 1, 0, footer[: max(width - 1, 0)], curses.A_DIM)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            wifi_cancel.set()
            break
        elif key in (curses.KEY_UP,):
            selected = (selected - 1) % len(MENU)
        elif key in (curses.KEY_DOWN,):
            selected = (selected + 1) % len(MENU)
        elif key in (ord("r"), ord("R")):
            previous_selected = None
        elif key in (ord("p"), ord("P")) and label == "Router Intelligence":
            if router_probe is None:
                router_message = "Checking common TCP management ports on the gateway..."
                lines = _screen_lines(
                    label, status, router_result, router_message, wifi_result, wifi_message
                )
                router_probe = executor.submit(router_intelligence.inspect_and_probe_gateway)
        elif key in (ord("s"), ord("S")) and label == "Wi-Fi Intelligence":
            if wifi_scan is None:
                wifi_message = "Wi-Fi survey running..."
                lines = _screen_lines(
                    label, status, router_result, router_message, wifi_result, wifi_message
                )
                wifi_scan = executor.submit(
                    wifi_intelligence.scan_available_networks,
                    cancel_event=wifi_cancel,
                )
    executor.shutdown(wait=False, cancel_futures=True)


def main() -> None:
    curses.wrapper(run)
