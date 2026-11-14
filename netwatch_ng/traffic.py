"""Non-destructive traffic rate policing through Linux tc's clsact hook.

NETWATCH does not replace an interface's root qdisc. It installs an
independently identified matchall/police filter on clsact instead. This is
packet policing (excess packets are dropped), not smooth HTB shaping.
A protected state file is required before a filter can be listed or removed.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netwatch_ng.core.shell import BinaryNotFound, run, which

DEFAULT_STATE_FILE = Path("/var/lib/netwatch-ng/traffic-state.json")
STATE_FILE = DEFAULT_STATE_FILE
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
PREFS = {"egress": 49152, "ingress": 49153}
STATE_VERSION = 1
BURST = "64k"


@dataclass
class TrafficLimit:
    interface: str
    direction: str
    rate_kbps: int
    qdisc_id: str | None = None


def _validate_interface(interface: str) -> str:
    if not isinstance(interface, str) or not INTERFACE_RE.fullmatch(interface):
        raise ValueError(f"invalid interface name: {interface!r}")
    return interface


def _validate_direction(direction: str) -> str:
    if direction not in PREFS:
        raise ValueError("direction must be 'egress' or 'ingress'")
    return direction


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("traffic control changes require root privileges")


def _ensure_tc() -> None:
    if which("tc") is None:
        raise BinaryNotFound("tc")


def _run_ok(argv: list[str]) -> str:
    result = run(argv, timeout=5.0)
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise RuntimeError(f"{' '.join(argv[:4])}: {detail}")
    return result.stdout


def _state_key(interface: str, direction: str) -> str:
    return f"{interface}:{direction}"


def _read_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"version": STATE_VERSION, "limits": {}}
    try:
        st = STATE_FILE.stat()
        if st.st_mode & 0o022:
            raise PermissionError(f"traffic state is group/world-writable: {STATE_FILE}")
        if STATE_FILE == DEFAULT_STATE_FILE and st.st_uid != 0:
            raise PermissionError(f"traffic state is not owned by root: {STATE_FILE}")
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read NETWATCH traffic state: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise RuntimeError("unsupported or malformed NETWATCH traffic state")
    if not isinstance(data.get("limits"), dict):
        raise RuntimeError("malformed NETWATCH traffic limits state")
    return data


def _write_state(data: dict[str, Any]) -> None:
    if STATE_FILE == DEFAULT_STATE_FILE and os.geteuid() != 0:
        raise PermissionError("writing NETWATCH traffic state requires root privileges")
    parent = STATE_FILE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if STATE_FILE == DEFAULT_STATE_FILE:
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise PermissionError(f"unsafe NETWATCH traffic state directory: {parent}")
    fd, temporary = tempfile.mkstemp(prefix=".traffic-state-", dir=parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE_FILE)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _qdisc_output(interface: str) -> str:
    return _run_ok(["tc", "qdisc", "show", "dev", interface])


def _has_clsact(output: str) -> bool:
    return any(
        len(parts := line.split()) >= 2 and parts[1] == "clsact"
        for line in output.splitlines()
        if line.strip().startswith("qdisc ")
    )


def _ensure_clsact(interface: str, dry_run: bool = False) -> None:
    if _has_clsact(_qdisc_output(interface)) or dry_run:
        return
    result = run(["tc", "qdisc", "add", "dev", interface, "clsact"], timeout=5.0)
    if result.ok:
        return
    # Another process may have created clsact between inspection and add.
    if _has_clsact(_qdisc_output(interface)):
        return
    detail = result.stderr.strip() or "unable to attach clsact"
    raise RuntimeError(f"cannot attach tc clsact to {interface}: {detail}")


def _filter_output(interface: str, direction: str) -> str:
    return _run_ok(["tc", "filter", "show", "dev", interface, direction])


def _pref_present(output: str, pref: int) -> bool:
    return re.search(rf"\bpref\s+{pref}\b", output) is not None


def _looks_like_our_filter(
    output: str,
    pref: int,
    expected_rate_kbps: int | None = None,
) -> bool:
    if (
        not _pref_present(output, pref)
        or re.search(r"\bmatchall\b", output) is None
        or re.search(r"\bpolice\b", output) is None
    ):
        return False
    if expected_rate_kbps is None:
        return True

    match = re.search(r"\brate\s+([0-9]+(?:\.[0-9]+)?)(bit|kbit|mbit|gbit)\b", output, re.IGNORECASE)
    if match is None:
        return False
    numeric = float(match.group(1))
    unit = match.group(2).lower()
    factor_to_kbit = {"bit": 0.001, "kbit": 1.0, "mbit": 1000.0, "gbit": 1_000_000.0}
    actual_rate = numeric * factor_to_kbit[unit]
    return abs(actual_rate - expected_rate_kbps) < 0.01


def _filter_argv(interface: str, direction: str, rate_kbps: int, replace: bool) -> list[str]:
    operation = "replace" if replace else "add"
    return [
        "tc", "filter", operation, "dev", interface, direction,
        "protocol", "all", "pref", str(PREFS[direction]), "matchall",
        "action", "police", "rate", f"{rate_kbps}kbit",
        "burst", BURST, "drop",
    ]


def list_limits(interface: str | None = None) -> list[TrafficLimit]:
    """Return only limits in the protected state file that still exist in tc."""
    _ensure_tc()
    if interface is not None:
        _validate_interface(interface)
    state = _read_state()
    limits: list[TrafficLimit] = []
    for key, entry in sorted(state["limits"].items()):
        try:
            iface, direction = key.rsplit(":", 1)
        except ValueError as exc:
            raise RuntimeError(f"invalid traffic state key: {key!r}") from exc
        _validate_interface(iface)
        _validate_direction(direction)
        if interface is not None and iface != interface:
            continue
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("rate_kbps"), int)
            or entry.get("pref") != PREFS[direction]
        ):
            raise RuntimeError(f"invalid traffic state entry: {key}")
        if not _has_clsact(_qdisc_output(iface)):
            raise RuntimeError(f"NETWATCH traffic state is stale: clsact missing on {iface}")
        output = _filter_output(iface, direction)
        if not _looks_like_our_filter(output, PREFS[direction], entry["rate_kbps"]):
            raise RuntimeError(f"NETWATCH traffic filter is missing or was replaced: {iface} {direction}")
        limits.append(TrafficLimit(iface, direction, entry["rate_kbps"], f"pref-{PREFS[direction]}"))
    return limits


def set_limit(
    interface: str,
    rate_kbps: int,
    direction: str = "egress",
    dry_run: bool = False,
) -> TrafficLimit:
    """Set a rate policer without replacing the interface root qdisc.

    Policing drops packets above the configured rate; it is not smooth queue-
    based shaping. Egress and ingress use separate clsact hooks. NETWATCH
    preserves existing root qdiscs and leaves clsact attached on reset because
    that qdisc may be shared with other tools.
    """
    interface = _validate_interface(interface)
    direction = _validate_direction(direction)
    if isinstance(rate_kbps, bool) or not isinstance(rate_kbps, int) or not 1 <= rate_kbps <= 10_000_000:
        raise ValueError("rate_kbps must be an integer between 1 and 10000000")
    _ensure_tc()

    qdiscs = _qdisc_output(interface)
    if not _has_clsact(qdiscs):
        if dry_run:
            return TrafficLimit(interface, direction, rate_kbps, f"pref-{PREFS[direction]}")
        _require_root()
        _ensure_clsact(interface)

    state = _read_state()
    key = _state_key(interface, direction)
    existing = state["limits"].get(key)
    pref = PREFS[direction]
    filters = _filter_output(interface, direction)
    present = _pref_present(filters, pref)
    if present and not existing:
        raise RuntimeError(
            f"tc preference {pref} is already occupied on {interface} {direction}; refusing to replace it"
        )
    if present and existing and not _looks_like_our_filter(filters, pref, existing["rate_kbps"]):
        raise RuntimeError(f"NETWATCH-owned tc filter cannot be verified on {interface} {direction}")
    if dry_run:
        return TrafficLimit(interface, direction, rate_kbps, f"pref-{pref}")

    _require_root()
    _run_ok(_filter_argv(interface, direction, rate_kbps, replace=bool(existing and present)))
    verified = _filter_output(interface, direction)
    if not _looks_like_our_filter(verified, pref, rate_kbps):
        raise RuntimeError(f"tc reported success but the NETWATCH filter could not be verified on {interface}")

    state["limits"][key] = {"rate_kbps": rate_kbps, "pref": pref}
    try:
        _write_state(state)
    except Exception as exc:
        cleanup = run(
            ["tc", "filter", "del", "dev", interface, direction, "protocol", "all", "pref", str(pref)],
            timeout=5.0,
        )
        detail = "state write failed"
        if not cleanup.ok:
            detail += "; filter cleanup also failed"
        raise RuntimeError(f"{detail}: {exc}") from exc
    return TrafficLimit(interface, direction, rate_kbps, f"pref-{pref}")


def clear_limit(interface: str, direction: str = "egress", dry_run: bool = False) -> bool:
    """Remove only a filter whose protected state entry and tc signature agree."""
    interface = _validate_interface(interface)
    direction = _validate_direction(direction)
    _ensure_tc()
    state = _read_state()
    key = _state_key(interface, direction)
    if key not in state["limits"]:
        return False
    pref = PREFS[direction]
    filters = _filter_output(interface, direction)
    if not _pref_present(filters, pref):
        if not dry_run:
            _require_root()
            del state["limits"][key]
            _write_state(state)
        return False
    if not _looks_like_our_filter(filters, pref, state["limits"][key]["rate_kbps"]):
        raise RuntimeError(f"refusing to delete an unverified tc filter on {interface} {direction}")
    if dry_run:
        return True

    _require_root()
    _run_ok([
        "tc", "filter", "del", "dev", interface, direction,
        "protocol", "all", "pref", str(pref),
    ])
    remaining = _filter_output(interface, direction)
    if _pref_present(remaining, pref):
        raise RuntimeError(f"tc filter still exists after deletion on {interface} {direction}")
    del state["limits"][key]
    _write_state(state)
    return True
