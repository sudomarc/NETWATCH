"""NETWATCH NG keyboard-driven terminal application."""
from __future__ import annotations

import curses
import time
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event

from netwatch_ng import activity_log, diagnostics, reset_manager, router_intelligence, settings, wifi_intelligence
from netwatch_ng.tui.screens.dashboard import build_dashboard_lines
from netwatch_ng.tui.screens.devices import build_devices_lines
from netwatch_ng.tui.screens.diagnostics import build_diagnostics_lines
from netwatch_ng.tui.screens.firewall import build_firewall_lines
from netwatch_ng.tui.screens.logs import build_logs_lines
from netwatch_ng.tui.screens.reset_manager import build_reset_lines
from netwatch_ng.tui.screens.router_intelligence import build_router_lines
from netwatch_ng.tui.screens.settings import build_settings_lines
from netwatch_ng.tui.screens.system_manager import build_system_manager_lines
from netwatch_ng.tui.screens.traffic_manager import build_traffic_lines
from netwatch_ng.tui.screens.wifi_intelligence import build_wifi_lines

IMPLEMENTED = "implemented"
PLANNED = "planned"

MENU: list[tuple[str, str]] = [
    ("Dashboard", IMPLEMENTED),
    ("Devices", IMPLEMENTED),
    ("Router Intelligence", IMPLEMENTED),
    ("Wi-Fi Intelligence", IMPLEMENTED),
    ("Firewall", IMPLEMENTED),
    ("Traffic Manager", IMPLEMENTED),
    ("Reset Manager", IMPLEMENTED),
    ("Network Diagnostics", IMPLEMENTED),
    ("System Manager", IMPLEMENTED),
    ("Settings", IMPLEMENTED),
    ("Logs", IMPLEMENTED),
    ("About", IMPLEMENTED),
]


def _about_lines() -> list[str]:
    return [
        "NETWATCH NG — Linux network supervision/administration TUI",
        "Implemented: network core, passive/Nmap discovery engine, device",
        "identification, gateway inspection, Wi-Fi inventory/survey,",
        "firewall API, tc packet policing, reset preview, diagnostics,",
        "persistent settings and bounded activity logs.",
        "Traffic limits use packet policing (excess packets are dropped),",
        "not smooth queue-based HTB shaping.",
        "Repository: github.com/sudomarc/NETWATCH",
    ]


def _planned_lines(label: str) -> list[str]:
    return [
        f"{label}: not implemented yet.",
        "This module is scheduled in a later sprint and intentionally",
        "shows no simulated data or non-functional controls.",
    ]


def _trace_gateway():
    route = (
        router_intelligence.network.get_default_gateway("inet")
        or router_intelligence.network.get_default_gateway("inet6")
    )
    if route is None or route.gateway is None:
        return diagnostics.DiagnosticResult(
            "Traceroute", False, "No default gateway is configured"
        )
    return diagnostics.trace_route(route.gateway)


def _prompt_text(stdscr, prompt: str, max_length: int = 253) -> str:
    height, width = stdscr.getmaxyx()
    stdscr.move(height - 1, 0)
    stdscr.clrtoeol()
    stdscr.addstr(height - 1, 0, prompt[: max(width - 1, 0)], curses.A_BOLD)
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    try:
        raw = stdscr.getstr(height - 1, min(len(prompt), max(width - 1, 0)), max_length)
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
    return raw.decode("utf-8", errors="replace").strip()


def _screen_lines(
    label: str,
    status: str,
    router_result: tuple | None = None,
    router_message: str | None = None,
    wifi_result: tuple | None = None,
    wifi_message: str | None = None,
    reset_message: str | None = None,
    diagnostic_result: diagnostics.DiagnosticResult | None = None,
    diagnostic_message: str | None = None,
    settings_message: str | None = None,
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
    if label == "Firewall":
        return build_firewall_lines()
    if label == "Traffic Manager":
        return build_traffic_lines()
    if label == "Reset Manager":
        return build_reset_lines(reset_message)
    if label == "Network Diagnostics":
        return build_diagnostics_lines(diagnostic_result, diagnostic_message)
    if label == "System Manager":
        return build_system_manager_lines()
    if label == "Settings":
        return build_settings_lines(settings_message)
    if label == "Logs":
        return build_logs_lines()
    if label == "About":
        return _about_lines()
    return _planned_lines(label)


def _reset_summary(report: reset_manager.ResetReport) -> str:
    actions = report.firewall_actions + report.traffic_actions
    succeeded = sum(1 for action in actions if action.success)
    failed = len(actions) - succeeded
    return f"Reset finished: {succeeded} succeeded, {failed} failed, {len(actions)} total."


def run(stdscr) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(200)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)

    selected = 0
    executor = ThreadPoolExecutor(max_workers=2)
    router_probe: Future | None = None
    wifi_scan: Future | None = None
    diagnostic_task: Future | None = None
    router_result = None
    wifi_result = None
    diagnostic_result = None
    router_message = None
    wifi_message = None
    diagnostic_message = None
    reset_message = None
    settings_message = None
    wifi_cancel = Event()
    previous_selected = None
    lines: list[str] = []
    try:
        try:
            current_settings = settings.load_settings()
            refresh_seconds = current_settings["refresh_seconds"]
        except Exception as exc:
            refresh_seconds = 0
            settings_message = f"Settings unavailable; automatic refresh disabled: {exc}"
        last_refresh = time.monotonic()

        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            if height < 5 or width < 30:
                stdscr.addstr(0, 0, "NETWATCH NG: terminal too small; resize to at least 30x5.")
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord("q"), ord("Q")):
                    break
                continue

            if refresh_seconds and time.monotonic() - last_refresh >= refresh_seconds:
                previous_selected = None
                last_refresh = time.monotonic()

            stdscr.addstr(0, 0, "NETWATCH NG".ljust(max(width - 1, 0)), curses.A_BOLD)
            stdscr.addstr(1, 0, "-" * max(width - 1, 0))
            menu_width = 24
            for row, (menu_label, menu_status) in enumerate(MENU):
                y = row + 2
                if y >= height - 1:
                    break
                marker = " " if menu_status == IMPLEMENTED else "~"
                item_text = f"{marker} {menu_label}"[: menu_width - 1]
                attr = curses.color_pair(1) if row == selected else curses.A_NORMAL
                if menu_status != IMPLEMENTED and row != selected:
                    attr = curses.color_pair(2)
                stdscr.addstr(y, 0, item_text.ljust(menu_width), attr)

            label, status = MENU[selected]
            if selected != previous_selected:
                try:
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                    )
                except Exception as exc:
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
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
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
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                    )

            if diagnostic_task is not None and diagnostic_task.done():
                try:
                    diagnostic_result = diagnostic_task.result()
                    diagnostic_message = None
                    activity_log.record_event(
                        "Diagnostics", diagnostic_result.name,
                        "success" if diagnostic_result.ok else "warning",
                        diagnostic_result.summary,
                    )
                except Exception as exc:
                    diagnostic_message = f"Diagnostic failed: {exc}"
                diagnostic_task = None
                if label == "Network Diagnostics":
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                    )

            for i, line in enumerate(lines):
                y = i + 2
                if y >= height - 1:
                    break
                stdscr.addstr(y, menu_width + 2, line[: max(width - menu_width - 3, 0)])

            footer = "Up/Down: navigate   r: refresh   q: quit"
            if label == "Router Intelligence":
                footer = "Up/Down: navigate   p: probe gateway ports   r: refresh   q: quit"
            elif label == "Wi-Fi Intelligence":
                footer = "Up/Down: navigate   s: survey access points   r: refresh   q: quit"
            elif label == "Reset Manager":
                footer = "Up/Down: navigate   x: reset (confirmation required)   r: refresh   q: quit"
            elif label == "Network Diagnostics":
                footer = "Up/Down: navigate   p: ping gateway   t: trace route   d: DNS lookup   r: refresh"
            elif label == "Settings":
                footer = "Up/Down: navigate   + / -: refresh interval   0: disable   r: refresh"
            stdscr.addstr(height - 1, 0, footer[: max(width - 1, 0)], curses.A_DIM)
            stdscr.refresh()

            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                wifi_cancel.set()
                break
            if key == curses.KEY_UP:
                selected = (selected - 1) % len(MENU)
                reset_message = None
                settings_message = None
            elif key == curses.KEY_DOWN:
                selected = (selected + 1) % len(MENU)
                reset_message = None
                settings_message = None
            elif key in (ord("r"), ord("R")):
                previous_selected = None
            elif key in (ord("x"), ord("X")) and label == "Reset Manager":
                prompt = "Remove the listed NETWATCH rules? Press y to confirm; any other key cancels."
                stdscr.move(height - 1, 0)
                stdscr.clrtoeol()
                stdscr.addstr(height - 1, 0, prompt[: max(width - 1, 0)], curses.A_BOLD)
                stdscr.refresh()
                confirmation = stdscr.getch()
                if confirmation in (ord("y"), ord("Y")):
                    report = reset_manager.reset_all()
                    reset_message = _reset_summary(report)
                    actions = report.firewall_actions + report.traffic_actions
                    ok = all(action.success for action in actions)
                    try:
                        activity_log.record_event(
                            "Reset", "reset_all", "success" if ok else "warning", reset_message
                        )
                    except Exception as exc:
                        reset_message += f" (activity log unavailable: {exc})"
                else:
                    reset_message = "Reset cancelled; no changes requested."
                previous_selected = None
            elif key in (ord("p"), ord("P")) and label == "Router Intelligence":
                if router_probe is None:
                    router_message = "Checking common TCP management ports on the gateway..."
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                    )
                    router_probe = executor.submit(router_intelligence.inspect_and_probe_gateway)
            elif key in (ord("s"), ord("S")) and label == "Wi-Fi Intelligence":
                if wifi_scan is None:
                    wifi_message = "Wi-Fi survey running..."
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                    )
                    wifi_scan = executor.submit(
                        wifi_intelligence.scan_available_networks,
                        cancel_event=wifi_cancel,
                    )
            elif key in (ord("p"), ord("P")) and label == "Network Diagnostics":
                if diagnostic_task is None:
                    diagnostic_message = "Pinging the configured default gateway..."
                    diagnostic_task = executor.submit(diagnostics.ping_gateway)
            elif key in (ord("t"), ord("T")) and label == "Network Diagnostics":
                if diagnostic_task is None:
                    diagnostic_message = "Tracing the route to the configured default gateway..."
                    diagnostic_task = executor.submit(_trace_gateway)
            elif key in (ord("d"), ord("D")) and label == "Network Diagnostics":
                hostname = _prompt_text(stdscr, "Hostname for DNS lookup: ")
                if hostname:
                    diagnostic_message = f"Resolving {hostname}..."
                    diagnostic_task = executor.submit(diagnostics.resolve_dns, hostname)
            elif key in (ord("+"), ord("=")) and label == "Settings":
                refresh_seconds = 5 if refresh_seconds == 0 else min(300, refresh_seconds + 5)
                try:
                    settings.update_setting("refresh_seconds", refresh_seconds)
                    settings_message = f"Automatic refresh set to {refresh_seconds} seconds."
                    activity_log.record_event("Settings", "refresh_changed", "success", settings_message)
                except Exception as exc:
                    settings_message = f"Could not save refresh setting: {exc}"
                previous_selected = None
            elif key == ord("-") and label == "Settings":
                refresh_seconds = max(0, refresh_seconds - 5)
                try:
                    settings.update_setting("refresh_seconds", refresh_seconds)
                    settings_message = (
                        "Automatic refresh disabled."
                        if refresh_seconds == 0
                        else f"Automatic refresh set to {refresh_seconds} seconds."
                    )
                    activity_log.record_event("Settings", "refresh_changed", "success", settings_message)
                except Exception as exc:
                    settings_message = f"Could not save refresh setting: {exc}"
                previous_selected = None
            elif key == ord("0") and label == "Settings":
                refresh_seconds = 0
                try:
                    settings.update_setting("refresh_seconds", 0)
                    settings_message = "Automatic refresh disabled."
                    activity_log.record_event("Settings", "refresh_changed", "success", settings_message)
                except Exception as exc:
                    settings_message = f"Could not save refresh setting: {exc}"
                previous_selected = None
    finally:
        wifi_cancel.set()
        executor.shutdown(wait=False, cancel_futures=True)


def main() -> None:
    curses.wrapper(run)
