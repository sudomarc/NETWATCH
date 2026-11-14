"""NETWATCH NG keyboard-driven terminal application."""
from __future__ import annotations

import curses
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from netwatch_ng import activity_log, diagnostics, firewall, reset_manager, router_intelligence, settings, traffic, wifi_intelligence
from netwatch_ng.discovery import device_intelligence, devices as devices_mod, export as device_export, nmap_scan
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
from netwatch_ng.system.config import get_config_dir

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




def _scan_wifi(cancel_event: Event):
    preferred = settings.load_settings()["preferred_interface"]
    if preferred:
        available = {item.name for item in wifi_intelligence.list_wireless_interfaces()}
        if preferred not in available:
            raise RuntimeError(f"preferred Wi-Fi interface is unavailable: {preferred}")
        return preferred, wifi_intelligence.scan_networks(preferred, cancel_event=cancel_event)
    return wifi_intelligence.scan_available_networks(cancel_event=cancel_event)


def _save_setting_value(key: str, value, description: str) -> tuple[bool, str]:
    try:
        settings.update_setting(key, value)
    except Exception as exc:
        return False, f"Could not save {key}: {exc}"
    try:
        activity_log.record_event("Settings", key, "success", description)
    except Exception as exc:
        return True, f"{description} (saved; activity log unavailable: {exc})"
    return True, description


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
    firewall_message: str | None = None,
    traffic_message: str | None = None,
    device_result=None,
    device_message: str | None = None,
) -> list[str]:
    if label == "Dashboard":
        return build_dashboard_lines()
    if label == "Devices":
        return build_devices_lines(device_result, device_message)
    if label == "Router Intelligence":
        report, services = router_result if router_result is not None else (None, None)
        return build_router_lines(report, services, router_message)
    if label == "Wi-Fi Intelligence":
        interface, access_points = wifi_result if wifi_result is not None else (None, None)
        return build_wifi_lines(access_points, interface, wifi_message)
    if label == "Firewall":
        return build_firewall_lines(firewall_message)
    if label == "Traffic Manager":
        return build_traffic_lines(traffic_message)
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
    device_scan: Future | None = None
    service_scan: Future | None = None
    device_result = None
    device_message = None
    router_result = None
    wifi_result = None
    diagnostic_result = None
    router_message = None
    wifi_message = None
    diagnostic_message = None
    reset_message = None
    settings_message = None
    firewall_message = None
    traffic_message = None
    wifi_cancel = Event()
    device_cancel = Event()
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
                        firewall_message, traffic_message, device_result, device_message,
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
                        firewall_message, traffic_message, device_result, device_message,
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
                        firewall_message, traffic_message, device_result, device_message,
                    )

            if service_scan is not None and service_scan.done():
                try:
                    scanned_host = service_scan.result()
                    if scanned_host is None:
                        device_message = "Nmap returned no service-scan result for that host."
                    else:
                        base_devices = device_result if device_result is not None else devices_mod.passive_scan("inet")
                        device_result = device_intelligence.merge(
                            base_devices + [device_intelligence.from_nmap_host(scanned_host)]
                        )
                        device_message = f"Service/version scan completed: {scanned_host.ip}."
                    activity_log.record_event("Devices", "service_scan", "success", device_message)
                except Exception as exc:
                    device_message = f"Service/version scan failed: {exc}"
                    try:
                        activity_log.record_event("Devices", "service_scan", "error", str(exc))
                    except Exception:
                        pass
                service_scan = None
                if label == "Devices":
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
                    )

            if device_scan is not None and device_scan.done():
                try:
                    device_result = device_scan.result()
                    device_message = f"Active Nmap discovery completed: {len(device_result)} device(s)."
                    activity_log.record_event("Devices", "active_scan", "success", device_message)
                except Exception as exc:
                    device_message = f"Active Nmap discovery failed: {exc}"
                    try:
                        activity_log.record_event("Devices", "active_scan", "error", str(exc))
                    except Exception:
                        pass
                device_scan = None
                if label == "Devices":
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
                    )

            if diagnostic_task is not None and diagnostic_task.done():
                try:
                    diagnostic_result = diagnostic_task.result()
                    diagnostic_message = None
                except Exception as exc:
                    diagnostic_message = f"Diagnostic failed: {exc}"
                else:
                    try:
                        activity_log.record_event(
                            "Diagnostics", diagnostic_result.name,
                            "success" if diagnostic_result.ok else "warning",
                            diagnostic_result.summary,
                        )
                    except Exception as exc:
                        diagnostic_message = f"Diagnostic completed; activity log unavailable: {exc}"
                diagnostic_task = None
                if label == "Network Diagnostics":
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
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
                footer = "Settings: +/- refresh interval, 0 disable, r refresh"
            elif label == "Firewall":
                footer = "Firewall: b block IP, u unblock IP, r refresh"
            elif label == "Traffic Manager":
                footer = "Traffic: l set limit, c clear limit, r refresh"
            elif label == "Devices":
                footer = "Devices: n discover, v service scan, e export, r refresh"
            stdscr.addstr(height - 1, 0, footer[: max(width - 1, 0)], curses.A_DIM)
            stdscr.refresh()

            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                wifi_cancel.set()
                device_cancel.set()
                break
            if key == curses.KEY_UP:
                selected = (selected - 1) % len(MENU)
                reset_message = None
                settings_message = None
                firewall_message = None
                traffic_message = None
            elif key == curses.KEY_DOWN:
                selected = (selected + 1) % len(MENU)
                reset_message = None
                settings_message = None
                firewall_message = None
                traffic_message = None
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
            elif key in (ord("v"), ord("V")) and label == "Devices":
                target = _prompt_text(stdscr, "Single authorized host for Nmap service scan: ", 253)
                if target and service_scan is None:
                    device_message = f"Service/version scan running for {target}..."
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
                    )
                    service_scan = executor.submit(
                        nmap_scan.service_scan,
                        target,
                        timeout=settings.load_settings()["scan_timeout_seconds"],
                        cancel_event=device_cancel,
                    )
            elif key in (ord("e"), ord("E")) and label == "Devices":
                format_name = _prompt_text(stdscr, "Export format (json/csv): ", 4).lower()
                if format_name in ("json", "csv"):
                    try:
                        current_devices = (
                            device_result if device_result is not None
                            else devices_mod.passive_scan("inet")
                        )
                        export_dir = get_config_dir() / "exports"
                        export_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        path = export_dir / f"devices-{stamp}.{format_name}"
                        content = (
                            device_export.to_json(current_devices)
                            if format_name == "json"
                            else device_export.to_csv(current_devices)
                        )
                        path.write_text(content, encoding="utf-8")
                        device_message = f"Exported {len(current_devices)} device(s): {path}"
                        activity_log.record_event("Devices", "export", "success", f"{format_name}: {len(current_devices)} devices")
                    except Exception as exc:
                        device_message = f"Device export failed: {exc}"
                    previous_selected = None
                else:
                    device_message = "Export cancelled; choose json or csv."
                    previous_selected = None
            elif key in (ord("n"), ord("N")) and label == "Devices":
                target = _prompt_text(stdscr, "Authorized target/subnet for Nmap discovery: ", 253)
                if target:
                    if device_scan is None:
                        device_message = f"Active discovery running for {target}..."
                        lines = _screen_lines(
                            label, status, router_result, router_message,
                            wifi_result, wifi_message, reset_message,
                            diagnostic_result, diagnostic_message, settings_message,
                            firewall_message, traffic_message, device_result, device_message,
                        )
                        device_scan = executor.submit(
                            devices_mod.active_scan, target,
                            timeout=settings.load_settings()["scan_timeout_seconds"],
                            cancel_event=device_cancel,
                        )
            elif key in (ord("b"), ord("B"), ord("u"), ord("U")) and label == "Firewall":
                target = _prompt_text(stdscr, "IPv4/IPv6 address: ", 64)
                if target:
                    family = "inet6" if ":" in target else "inet"
                    action = "block" if key in (ord("b"), ord("B")) else "unblock"
                    prompt = f"{action.capitalize()} {target} on the forwarding path? Press y to confirm."
                    stdscr.move(height - 1, 0)
                    stdscr.clrtoeol()
                    stdscr.addstr(height - 1, 0, prompt[: max(width - 1, 0)], curses.A_BOLD)
                    stdscr.refresh()
                    if stdscr.getch() in (ord("y"), ord("Y")):
                        try:
                            changed = firewall.block_ip(target, family=family) if action == "block" else firewall.unblock_ip(target, family=family)
                            firewall_message = f"{action.capitalize()} {'applied' if changed else 'already in requested state'}: {target}"
                            activity_log.record_event("Firewall", action, "success", target)
                        except Exception as exc:
                            firewall_message = f"{action.capitalize()} failed for {target}: {exc}"
                            try:
                                activity_log.record_event("Firewall", action, "error", str(exc))
                            except Exception:
                                pass
                    else:
                        firewall_message = f"{action.capitalize()} cancelled."
                    previous_selected = None
            elif key in (ord("l"), ord("L")) and label == "Traffic Manager":
                interface = _prompt_text(stdscr, "Interface (e.g. eth0): ", 15)
                rate_text = _prompt_text(stdscr, "Rate in kbit/s (integer): ", 12)
                direction = _prompt_text(stdscr, "Direction (egress/ingress): ", 8).lower()
                if interface and rate_text and direction:
                    try:
                        rate = int(rate_text)
                        limit = traffic.set_limit(interface, rate, direction=direction)
                        traffic_message = (
                            f"{limit.direction} packet policing set on {limit.interface}: "
                            f"{limit.rate_kbps} kbit/s. Excess packets are dropped."
                        )
                        activity_log.record_event("Traffic", "set_limit", "success", traffic_message)
                    except Exception as exc:
                        traffic_message = f"Could not set traffic limit: {exc}"
                        try:
                            activity_log.record_event("Traffic", "set_limit", "error", str(exc))
                        except Exception:
                            pass
                    previous_selected = None
            elif key in (ord("c"), ord("C")) and label == "Traffic Manager":
                interface = _prompt_text(stdscr, "Interface to clear: ", 15)
                direction = _prompt_text(stdscr, "Direction (egress/ingress): ", 8).lower()
                if interface and direction:
                    prompt = f"Remove NETWATCH {direction} policing on {interface}? Press y to confirm."
                    stdscr.move(height - 1, 0)
                    stdscr.clrtoeol()
                    stdscr.addstr(height - 1, 0, prompt[: max(width - 1, 0)], curses.A_BOLD)
                    stdscr.refresh()
                    if stdscr.getch() in (ord("y"), ord("Y")):
                        try:
                            removed = traffic.clear_limit(interface, direction=direction)
                            traffic_message = (
                                f"{'Removed' if removed else 'No active NETWATCH rule'}: {interface} {direction}"
                            )
                            activity_log.record_event("Traffic", "clear_limit", "success", traffic_message)
                        except Exception as exc:
                            traffic_message = f"Could not clear traffic limit: {exc}"
                            try:
                                activity_log.record_event("Traffic", "clear_limit", "error", str(exc))
                            except Exception:
                                pass
                    else:
                        traffic_message = "Traffic limit removal cancelled."
                    previous_selected = None
            elif key in (ord("p"), ord("P")) and label == "Router Intelligence":
                if router_probe is None:
                    router_message = "Checking common TCP management ports on the gateway..."
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
                    )
                    router_probe = executor.submit(router_intelligence.inspect_and_probe_gateway)
            elif key in (ord("s"), ord("S")) and label == "Wi-Fi Intelligence":
                if wifi_scan is None:
                    wifi_message = "Wi-Fi survey running..."
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
                    )
                    wifi_scan = executor.submit(_scan_wifi, wifi_cancel)
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
                next_value = 5 if refresh_seconds == 0 else min(300, refresh_seconds + 5)
                description = f"Automatic refresh set to {next_value} seconds."
                saved, settings_message = _save_setting_value("refresh_seconds", next_value, description)
                if saved:
                    refresh_seconds = next_value
                previous_selected = None
            elif key == ord("-") and label == "Settings":
                next_value = max(0, refresh_seconds - 5)
                description = "Automatic refresh disabled." if next_value == 0 else f"Automatic refresh set to {next_value} seconds."
                saved, settings_message = _save_setting_value("refresh_seconds", next_value, description)
                if saved:
                    refresh_seconds = next_value
                previous_selected = None
            elif key == ord("0") and label == "Settings":
                saved, settings_message = _save_setting_value(
                    "refresh_seconds", 0, "Automatic refresh disabled."
                )
                if saved:
                    refresh_seconds = 0
                previous_selected = None
            elif key in (ord("t"), ord("T")) and label == "Settings":
                timeout_text = _prompt_text(stdscr, "Nmap scan timeout (10-300 seconds): ", 3)
                if timeout_text:
                    try:
                        timeout_value = int(timeout_text)
                        description = f"Default Nmap timeout set to {timeout_value} seconds."
                        _, settings_message = _save_setting_value(
                            "scan_timeout_seconds", timeout_value, description
                        )
                    except ValueError:
                        settings_message = "Scan timeout must be an integer from 10 to 300."
                previous_selected = None
            elif key in (ord("i"), ord("I")) and label == "Settings":
                interface = _prompt_text(stdscr, "Preferred Wi-Fi interface (blank clears): ", 15)
                if not interface:
                    _, settings_message = _save_setting_value(
                        "preferred_interface", None, "Preferred Wi-Fi interface cleared."
                    )
                else:
                    try:
                        available = {item.name for item in wifi_intelligence.list_wireless_interfaces()}
                        if interface not in available:
                            settings_message = f"Not a detected Wi-Fi interface: {interface}"
                        else:
                            _, settings_message = _save_setting_value(
                                "preferred_interface", interface,
                                f"Preferred Wi-Fi interface set to {interface}.",
                            )
                    except Exception as exc:
                        settings_message = f"Could not inspect Wi-Fi interfaces: {exc}"
                previous_selected = None
    finally:
        wifi_cancel.set()
        executor.shutdown(wait=False, cancel_futures=True)


def main() -> None:
    curses.wrapper(run)
