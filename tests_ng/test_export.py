from __future__ import annotations

import json

from netwatch_ng.discovery import export
from netwatch_ng.discovery.device_intelligence import Confidence, Device, IdentificationField


def _sample_device() -> Device:
    return Device(
        ip="192.168.1.1",
        mac="aa:bb:cc:dd:ee:ff",
        hostname=IdentificationField(value="host.lan", source="nmap", confidence=Confidence.LIKELY),
        vendor=IdentificationField(value="Acme", source="local OUI table", confidence=Confidence.LIKELY),
        open_ports=[22, 80],
        services=["ssh", "http"],
        up=True,
    )


def test_to_json_round_trips_core_fields():
    data = json.loads(export.to_json([_sample_device()]))
    assert data[0]["ip"] == "192.168.1.1"
    assert data[0]["hostname"] == "host.lan"
    assert data[0]["vendor"] == "Acme"
    assert data[0]["open_ports"] == [22, 80]


def test_to_csv_has_header_and_row():
    text = export.to_csv([_sample_device()])
    lines = text.strip().splitlines()
    assert lines[0] == ",".join(export.CSV_FIELDS)
    assert "192.168.1.1" in lines[1]
    assert "Acme" in lines[1]


def test_empty_device_list_still_produces_valid_output():
    assert json.loads(export.to_json([])) == []
    text = export.to_csv([])
    assert text.strip() == ",".join(export.CSV_FIELDS)
