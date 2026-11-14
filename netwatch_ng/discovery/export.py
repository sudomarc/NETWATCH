"""Machine-readable export of a device list. Kept separate from any
human-readable diagnostic text, per the brief's "export JSON/CSV" and
the legacy toolkit's own "diagnostics vs. machine output" separation.
"""

from __future__ import annotations

import csv
import io
import json

from netwatch_ng.discovery.device_intelligence import Device

CSV_FIELDS = ["ip", "mac", "hostname", "vendor", "vendor_confidence", "open_ports", "services", "up"]


def to_json(devices: list[Device]) -> str:
    rows = []
    for d in devices:
        rows.append(
            {
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.hostname.value if d.hostname else None,
                "hostname_source": d.hostname.source if d.hostname else None,
                "vendor": d.vendor.value if d.vendor else None,
                "vendor_confidence": d.vendor.confidence.value if d.vendor else None,
                "open_ports": d.open_ports,
                "services": d.services,
                "up": d.up,
            }
        )
    return json.dumps(rows, indent=2)


def to_csv(devices: list[Device]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for d in devices:
        writer.writerow(
            {
                "ip": d.ip,
                "mac": d.mac or "",
                "hostname": d.hostname.value if d.hostname else "",
                "vendor": d.vendor.value if d.vendor else "",
                "vendor_confidence": d.vendor.confidence.value if d.vendor else "",
                "open_ports": " ".join(str(p) for p in d.open_ports),
                "services": " ".join(d.services),
                "up": "1" if d.up else "0",
            }
        )
    return buf.getvalue()
