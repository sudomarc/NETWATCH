"""NETWATCH NG keyboard-driven terminal application.

The engine and the asynchronous action handling are unchanged: only the
visual shell (header, navigation sidebar, content panels, footer) and the
color rendering are reworked into a dark NOC-inspired language. Every
``build_*_lines`` screen contract is preserved.
"""
from __future__ import annotations

import curses
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Event

from netwatch_ng import __version__
from netwatch_ng import activity_log, diagnostics, firewall, reset_manager, router_intelligence, settings, traffic, upnp, wifi_intelligence
from netwatch_ng.discovery import device_intelligence, devices as devices_mod, export as device_export, nmap_scan
from netwatch_ng.system.config import get_config_dir, is_root
from netwatch_ng.tui import components, theme
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

MENU_WIDTH = 26

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


def _test_utf8_box(stdscr) -> bool:
    """Return True when the terminal can render UTF-8 box-drawing characters.

    Some minimal terminals (or misconfigured locales) cannot display
    ┌─┐ │ └┘. When that is the case the TUI falls back to ASCII borders
    (+ - |) so panels still draw without crashing.
    """
    try:
        stdscr.addstr(0, 0, "┌─┐", curses.A_NORMAL)
        stdscr.refresh()
        return True
    except Exception:
        return False


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


def _discover_upnp_gateway():
    report = router_intelligence.inspect_default_gateway()
    if report is None:
        return None, []
    return report.gateway, upnp.discover_upnp(report.gateway)


def _prompt_text(stdscr, prompt: str, max_length: int = 253) -> str:
    """Owning line editor for prompted input.

    This deliberately does not use echo()/getstr(): run() executes the
    screen with stdscr.timeout(200), and wgetstr() with a timeout set
    returns an empty byte string immediately without consuming input.
    Every character the operator typed then reached the main dispatcher,
    where e.g. '0' cleared the refresh interval, 'r' refreshed and 'q'
    quit. Owning the keys here keeps them out of the dispatcher:
    printable characters edit the text, Enter applies it and Esc cancels
    by returning an empty string.
    """
    height, width = stdscr.getmaxyx()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    text = ""
    try:
        while True:
            line = f"{prompt}{text}"
            stdscr.move(height - 1, 0)
            stdscr.clrtoeol()
            stdscr.addstr(height - 1, 0, line[: max(width - 1, 0)], curses.A_BOLD)
            stdscr.refresh()
            key = stdscr.getch()
            if key == -1:
                continue
            if key in (10, 13):
                return text.strip()
            if key == 27:
                return ""
            if key in (curses.KEY_BACKSPACE, curses.KEY_DC, 127, 8):
                text = text[:-1]
                continue
            if key == curses.KEY_RESIZE:
                height, width = stdscr.getmaxyx()
                continue
            if 32 <= key < 127 and len(text) < max_length:
                text += chr(key)
    finally:
        try:
            curses.curs_set(0)
        except curses.error:
            pass


def _confirm(stdscr, prompt: str) -> bool:
    """Blocking y/n confirmation that owns its keys.

    run() keeps stdscr.timeout(200) active, so a single getch() would
    return -1 after 200 ms and silently cancel the action before an
    operator could answer. Loop until y/Y confirms or Esc cancels.
    """
    height, width = stdscr.getmaxyx()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    try:
        while True:
            stdscr.move(height - 1, 0)
            stdscr.clrtoeol()
            stdscr.addstr(height - 1, 0, prompt[: max(width - 1, 0)], curses.A_BOLD)
            stdscr.refresh()
            key = stdscr.getch()
            if key == -1:
                continue
            return key in (ord("y"), ord("Y"))
    finally:
        try:
            curses.curs_set(0)
        except curses.error:
            pass


def _confirm_blocking(stdscr, prompt: str) -> bool:
    """Blocking confirmation that owns its keys until the operator answers.

    The main loop runs with ``stdscr.timeout(200)``, so a plain ``getch()``
    returns -1 every 200 ms and would silently cancel the confirmation.
    This helper ignores idle returns and waits for an explicit answer:
    y/Y confirms, Esc or any other key cancels. Used for actions that can
    interrupt the operator's Wi-Fi connection.
    """
    height, width = stdscr.getmaxyx()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    try:
        while True:
            stdscr.move(height - 1, 0)
            stdscr.clrtoeol()
            stdscr.addstr(height - 1, 0, prompt[: max(width - 1, 0)], curses.A_BOLD)
            stdscr.refresh()
            key = stdscr.getch()
            if key == -1:
                continue
            if key == 27:
                return False
            return key in (ord("y"), ord("Y"))
    finally:
        try:
            curses.curs_set(0)
        except curses.error:
            pass


def _configure_colors(mode: str) -> bool:
    """Initialize the visual theme; monochrome when disabled or unsupported."""
    if mode == "mono":
        return False
    return theme.init_palette(True)


def _scan_wifi(cancel_event: Event):
    preferred = settings.load_settings()["preferred_interface"]
    timeout = settings.load_settings()["scan_timeout_seconds"]
    if preferred:
        available = {item.name for item in wifi_intelligence.list_wireless_interfaces()}
        if preferred not in available:
            raise RuntimeError(f"preferred Wi-Fi interface is unavailable: {preferred}")
        return wifi_intelligence.scan_networks(
            preferred, timeout=timeout, cancel_event=cancel_event
        )
    return wifi_intelligence.scan_available_networks(
        timeout=timeout, cancel_event=cancel_event
    )


def _restore_monitor_interface(interface: str | None) -> None:
    """Best-effort restore of a monitor interface NETWATCH created.

    Called when the TUI exits. Leaving an interface in monitor mode would
    keep the machine's Wi-Fi broken after NETWATCH quits, so the restore is
    attempted unconditionally and any failure is ignored: the operator is
    already leaving, and there is nothing actionable to show at that point.
    """
    if not interface:
        return
    try:
        wifi_intelligence.stop_monitor_mode(interface)
    except Exception:
        pass


def _log_warning(module: str, action: str, status: str, detail: str) -> str:
    try:
        activity_log.record_event(module, action, status, detail)
    except Exception as exc:
        return f" (operation completed; activity log unavailable: {exc})"
    return ""


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
        interface, access_points, stations = (
            wifi_result if wifi_result is not None else (None, None, None)
        )
        return build_wifi_lines(access_points, interface, wifi_message, stations=stations)
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


def _draw_header(stdscr, height, width, label: str, enabled: bool) -> None:
    """Top identity bar: application, version, current mode and root state."""
    addstr = components.addstr_safe
    addstr(stdscr, 0, 0, "NETWATCH NG", theme.attr(theme.ACCENT, enabled, bold=True))
    addstr(stdscr, 0, 13, f"v{__version__}", theme.attr(theme.MUTED, enabled))
    root_text = f"root:{'yes' if is_root() else 'no'}"
    mode_text = f"[{label}]  {root_text}"
    right_x = max(width - len(mode_text) - 1, 14 + len(f"v{__version__}") + 4)
    addstr(stdscr, 0, right_x, mode_text, theme.attr(theme.HEADER, enabled, bold=True))
    addstr(stdscr, 1, 0, "─" * max(width - 1, 0), theme.attr(theme.BORDER, enabled))


def _draw_menu(stdscr, height, selected: int, enabled: bool) -> None:
    """Left navigation sidebar."""
    addstr = components.addstr_safe
    for row, (menu_label, menu_status) in enumerate(MENU):
        y = row + 2
        if y >= height - 1:
            break
        if row == selected:
            prefix = "> "
            attr = theme.attr(theme.SELECTION, enabled)
        elif menu_status != IMPLEMENTED:
            prefix = "~ "
            attr = theme.attr(theme.MUTED, enabled)
        else:
            prefix = "  "
            attr = theme.attr(theme.BODY, enabled)
        item_text = f"{prefix}{menu_label}"[: MENU_WIDTH - 1]
        addstr(stdscr, y, 0, item_text.ljust(MENU_WIDTH), attr)


def _draw_footer(stdscr, height, width, label: str, enabled: bool) -> None:
    """Contextual command bar."""
    contextual = {
        "Router Intelligence": "p: probe TCP ports   u: UPnP scan   r: refresh",
        "Wi-Fi Intelligence": "s: survey access points   m: monitor mode   r: refresh",
        "Reset Manager": "x: reset (confirmation required)   r: refresh",
        "Network Diagnostics": "p: ping gateway   t: trace route   d: DNS lookup   r: refresh",
        "Settings": "+ / -: refresh interval   0: disable   t: timeout   i: interface   c: color   r: refresh",
        "Firewall": "b: block IP   u: unblock IP   r: refresh",
        "Traffic Manager": "l: set limit   c: clear limit   r: refresh",
        "Devices": "n: discover   v: service scan   e: export   r: refresh",
    }.get(label, "r: refresh")
    global_part = "↑↓ Navigate   Enter Select   r Refresh   q Quit"
    footer = f"{global_part}   {contextual}"
    addstr = components.addstr_safe
    addstr(stdscr, height - 1, 0, footer[: max(width - 1, 0)], theme.attr(theme.MUTED, enabled))


def _paint_content(stdscr, height, width, lines: list[str], enabled: bool) -> None:
    """Paint screen content inside a bordered content panel."""
    panel_x = MENU_WIDTH + 1
    panel_y = 2
    panel_w = max(width - panel_x - 1, 10)
    panel_h = max(height - panel_y - 1, 3)
    content_y, content_x, content_h, content_w = components.draw_panel(
        stdscr, panel_y, panel_x, panel_h, panel_w, title=None, enabled=enabled
    )
    for i, line in enumerate(lines):
        y = content_y + i
        if y >= content_y + content_h:
            break
        components.paint_line(
            stdscr, y, content_x, content_x + content_w, line, enabled, title=(i == 0)
        )


def run(stdscr) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(200)
    selected = 0
    executor = ThreadPoolExecutor(max_workers=2)
    router_probe: Future | None = None
    wifi_scan: Future | None = None
    upnp_scan: Future | None = None
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
    wifi_monitor_interface: str | None = None
    previous_selected = None
    lines: list[str] = []
    try:
        try:
            current_settings = settings.load_settings()
            refresh_seconds = current_settings["refresh_seconds"]
            color_mode = current_settings["color_mode"]
            colors_enabled = _configure_colors(color_mode)
        except Exception as exc:
            refresh_seconds = 0
            color_mode = "auto"
            colors_enabled = _configure_colors("auto")
            settings_message = f"Settings unavailable; automatic refresh disabled: {exc}"

        # Detect whether the terminal can render UTF-8 box-drawing characters;
        # fall back to ASCII borders if it cannot (no crash on minimal terminals).
        try:
            if not _test_utf8_box(stdscr):
                components.USE_ASCII_BOX = True
        except Exception:
            components.USE_ASCII_BOX = True

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
                    survey = wifi_scan.result()
                    wifi_result = (
                        survey.interface,
                        survey.access_points,
                        survey.stations,
                    )
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
            if upnp_scan is not None and upnp_scan.done():
                try:
                    gateway, discovered = upnp_scan.result()
                    if not gateway:
                        router_message = "UPnP discovery unavailable: no default gateway."
                    elif not discovered:
                        router_message = f"No UPnP/SSDP response received from gateway {gateway}."
                    else:
                        descriptions = []
                        for device in discovered:
                            model = " ".join(
                                value for value in (
                                    device.manufacturer, device.model_name, device.model_number
                                ) if value
                            ) or "model not reported"
                            name = device.friendly_name or "unnamed UPnP device"
                            descriptions.append(f"{name} — {model}")
                        router_message = (
                            f"UPnP/SSDP responses from {gateway}: " + "; ".join(descriptions)
                        )
                    router_message += _log_warning(
                        "Router", "upnp_discovery", "success", router_message
                    )
                except Exception as exc:
                    router_message = f"UPnP/SSDP discovery failed: {exc}"
                    router_message += _log_warning("Router", "upnp_discovery", "error", str(exc))
                upnp_scan = None
                if label == "Router Intelligence":
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
                except Exception as exc:
                    device_message = f"Service/version scan failed: {exc}"
                    device_message += _log_warning("Devices", "service_scan", "error", str(exc))
                else:
                    device_message += _log_warning("Devices", "service_scan", "success", device_message)
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
                except Exception as exc:
                    device_message = f"Active Nmap discovery failed: {exc}"
                    device_message += _log_warning("Devices", "active_scan", "error", str(exc))
                else:
                    device_message += _log_warning("Devices", "active_scan", "success", device_message)
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

            # --- Rendering (any display error is degraded, never fatal) ---
            try:
                _draw_header(stdscr, height, width, MENU[selected][0], colors_enabled)
                _draw_menu(stdscr, height, selected, colors_enabled)
                _paint_content(stdscr, height, width, lines, colors_enabled)
                _draw_footer(stdscr, height, width, label, colors_enabled)
                stdscr.refresh()
            except Exception as exc:
                # Last resort: clear and display the error so the TUI never
                # exits abruptly on a fickle terminal.
                try:
                    stdscr.erase()
                    stdscr.addstr(0, 0, "NETWATCH NG — display error:", curses.A_BOLD)
                    stdscr.addstr(1, 0, str(exc)[: max(width - 1, 0)])
                    stdscr.addstr(3, 0, "Press q to quit, r to retry.", curses.A_DIM)
                    stdscr.refresh()
                except Exception:
                    pass
                key = stdscr.getch()
                if key in (ord("q"), ord("Q")):
                    wifi_cancel.set()
                    device_cancel.set()
                    break
                if key in (ord("r"), ord("R")):
                    previous_selected = None
                continue

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
                if _confirm(stdscr, prompt):
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
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                        path = export_dir / f"devices-{stamp}.{format_name}"
                        content = (
                            device_export.to_json(current_devices)
                            if format_name == "json"
                            else device_export.to_csv(current_devices)
                        )
                        with path.open("x", encoding="utf-8") as stream:
                            stream.write(content)
                        device_message = f"Exported {len(current_devices)} device(s): {path}"
                        device_message += _log_warning(
                            "Devices", "export", "success",
                            f"{format_name}: {len(current_devices)} devices",
                        )
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
                    if _confirm(stdscr, prompt):
                        try:
                            changed = firewall.block_ip(target, family=family) if action == "block" else firewall.unblock_ip(target, family=family)
                            firewall_message = f"{action.capitalize()} {'applied' if changed else 'already in requested state'}: {target}"
                            firewall_message += _log_warning("Firewall", action, "success", target)
                        except Exception as exc:
                            firewall_message = f"{action.capitalize()} failed for {target}: {exc}"
                            firewall_message += _log_warning("Firewall", action, "error", str(exc))
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
                        traffic_message += _log_warning("Traffic", "set_limit", "success", traffic_message)
                    except Exception as exc:
                        traffic_message = f"Could not set traffic limit: {exc}"
                        traffic_message += _log_warning("Traffic", "set_limit", "error", str(exc))
                    previous_selected = None
            elif key in (ord("c"), ord("C")) and label == "Traffic Manager":
                interface = _prompt_text(stdscr, "Interface to clear: ", 15)
                direction = _prompt_text(stdscr, "Direction (egress/ingress): ", 8).lower()
                if interface and direction:
                    prompt = f"Remove NETWATCH {direction} policing on {interface}? Press y to confirm."
                    if _confirm(stdscr, prompt):
                        try:
                            removed = traffic.clear_limit(interface, direction=direction)
                            traffic_message = (
                                f"{'Removed' if removed else 'No active NETWATCH rule'}: {interface} {direction}"
                            )
                            traffic_message += _log_warning("Traffic", "clear_limit", "success", traffic_message)
                        except Exception as exc:
                            traffic_message = f"Could not clear traffic limit: {exc}"
                            traffic_message += _log_warning("Traffic", "clear_limit", "error", str(exc))
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
            elif key in (ord("u"), ord("U")) and label == "Router Intelligence":
                if upnp_scan is None:
                    router_message = "Sending a read-only UPnP/SSDP discovery request to the configured gateway..."
                    lines = _screen_lines(
                        label, status, router_result, router_message,
                        wifi_result, wifi_message, reset_message,
                        diagnostic_result, diagnostic_message, settings_message,
                        firewall_message, traffic_message, device_result, device_message,
                    )
                    upnp_scan = executor.submit(
                        _discover_upnp_gateway,
                    )
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
            elif key in (ord("m"), ord("M")) and label == "Wi-Fi Intelligence":
                if wifi_scan is not None:
                    wifi_message = "A Wi-Fi survey is in progress; try again after the survey stops."
                else:
                    try:
                        interfaces = wifi_intelligence.list_wireless_interfaces()
                    except Exception as exc:  # noqa: BLE001 - surface engine errors to the operator
                        wifi_message = f"Unable to list wireless interfaces: {exc}"
                    else:
                        preferred = settings.load_settings()["preferred_interface"]
                        candidates = [item.name for item in interfaces]
                        target = (
                            preferred
                            if preferred in candidates
                            else (candidates[0] if candidates else None)
                        )
                        if not target:
                            wifi_message = "No wireless interface detected."
                        else:
                            monitor_target = wifi_monitor_interface or next(
                                (item.name for item in interfaces if item.mode == "monitor"),
                                None,
                            )
                            if monitor_target and target == monitor_target:
                                try:
                                    wifi_intelligence.stop_monitor_mode(target)
                                    if wifi_monitor_interface == target:
                                        wifi_monitor_interface = None
                                    wifi_message = (
                                        f"Monitor mode stopped on {target}; the interface is "
                                        f"restored to managed mode."
                                    )
                                except Exception as exc:  # noqa: BLE001
                                    wifi_message = f"Stopping monitor mode on {target} failed: {exc}"
                            else:
                                prompt = (
                                    f"WARNING: switching {target} to monitor mode will interrupt "
                                    f"the active Wi-Fi connection on this interface "
                                    f"(disassociation possible). Confirm? (y/N) "
                                )
                                if _confirm_blocking(stdscr, prompt):
                                    try:
                                        monitor_name = wifi_intelligence.start_monitor_mode(target)
                                        wifi_monitor_interface = monitor_name
                                        wifi_message = (
                                            f"Monitor mode enabled on {monitor_name} (from {target}); "
                                            f"the Wi-Fi connection of {target} is interrupted."
                                        )
                                    except Exception as exc:  # noqa: BLE001
                                        wifi_message = f"Enabling monitor mode on {target} failed: {exc}"
                                else:
                                    wifi_message = "Monitor mode activation cancelled."
                previous_selected = None
            elif key in (ord("p"), ord("P")) and label == "Network Diagnostics":
                if diagnostic_task is None:
                    diagnostic_message = "Pinging the configured default gateway..."
                    diagnostic_task = executor.submit(diagnostics.ping_gateway)
            elif key in (ord("t"), ord("T")) and label == "Network Diagnostics":
                if diagnostic_task is None:
                    target = _prompt_text(stdscr, "Trace route to host/IP: ")
                    if target:
                        diagnostic_message = f"Tracing route to {target}..."
                        diagnostic_task = executor.submit(diagnostics.trace_route, target)
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
            elif key in (ord("c"), ord("C")) and label == "Settings":
                modes = ("auto", "color", "mono")
                next_mode = modes[(modes.index(color_mode) + 1) % len(modes)]
                saved, settings_message = _save_setting_value(
                    "color_mode", next_mode, f"Color mode set to {next_mode}."
                )
                if saved:
                    color_mode = next_mode
                    colors_enabled = _configure_colors(color_mode)
                    if color_mode == "color" and not colors_enabled:
                        settings_message += " Terminal does not support colors; monochrome rendering remains active."
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
        _restore_monitor_interface(wifi_monitor_interface)


def main() -> None:
    curses.wrapper(run)
