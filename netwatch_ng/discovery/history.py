"""Discovery history: persist each scan's device list and diff it
against the previous one so the Devices screen can show new, missing,
and reappeared devices — not just a flat snapshot.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from netwatch_ng.discovery.device_intelligence import Confidence, Device, IdentificationField

HISTORY_FILENAME = "discovery_history.json"


@dataclass
class ScanDiff:
    new: list[str]  # IPs present now, absent from the previous scan
    missing: list[str]  # IPs present previously, absent now
    reappeared: list[str]  # IPs that were "missing" at some point and are back
    unchanged: list[str]


def _device_to_dict(d: Device) -> dict:
    out = asdict(d)
    # asdict() turns Confidence enum into {"_value_": "...", ...} via dataclasses;
    # normalize to a plain string for stable JSON.
    for field_name in ("hostname", "vendor"):
        field_val = out.get(field_name)
        if field_val is not None:
            field_val["confidence"] = getattr(d, field_name).confidence.value
    return out


def _dict_to_device(data: dict) -> Device:
    def _field(raw: dict | None) -> IdentificationField | None:
        if raw is None:
            return None
        return IdentificationField(
            value=raw["value"], source=raw["source"], confidence=Confidence(raw["confidence"])
        )

    return Device(
        ip=data["ip"],
        mac=data.get("mac"),
        hostname=_field(data.get("hostname")),
        vendor=_field(data.get("vendor")),
        open_ports=data.get("open_ports", []),
        services=data.get("services", []),
        up=data.get("up", True),
    )


def save_scan(config_dir: Path, devices: list[Device]) -> None:
    path = config_dir / HISTORY_FILENAME
    previous = load_all_scans(config_dir)
    entry = {"timestamp": time.time(), "devices": [_device_to_dict(d) for d in devices]}
    previous.append(entry)
    # Keep a bounded amount of history (last 50 scans) so the file doesn't grow forever.
    previous = previous[-50:]
    path.write_text(json.dumps(previous, indent=2))


def load_all_scans(config_dir: Path) -> list[dict]:
    path = config_dir / HISTORY_FILENAME
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def load_latest_devices(config_dir: Path) -> list[Device]:
    scans = load_all_scans(config_dir)
    if not scans:
        return []
    return [_dict_to_device(d) for d in scans[-1]["devices"]]


def diff_last_two_scans(config_dir: Path) -> ScanDiff | None:
    scans = load_all_scans(config_dir)
    if len(scans) < 2:
        return None

    current_ips = {d["ip"] for d in scans[-1]["devices"]}
    previous_ips = {d["ip"] for d in scans[-2]["devices"]}

    # "reappeared" = seen at some point before the previous scan, absent
    # from the previous scan, present now.
    ever_seen_before_previous: set[str] = set()
    for scan in scans[:-2]:
        ever_seen_before_previous |= {d["ip"] for d in scan["devices"]}

    new = sorted(current_ips - previous_ips)
    missing = sorted(previous_ips - current_ips)
    reappeared = sorted((current_ips - previous_ips) & ever_seen_before_previous)
    new = sorted(set(new) - set(reappeared))
    unchanged = sorted(current_ips & previous_ips)

    return ScanDiff(new=new, missing=missing, reappeared=reappeared, unchanged=unchanged)
