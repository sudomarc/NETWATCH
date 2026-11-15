from __future__ import annotations

from netwatch_ng.discovery import history
from netwatch_ng.discovery.device_intelligence import Device


def _dev(ip: str) -> Device:
    return Device(ip=ip)


def test_save_and_load_roundtrip(tmp_path):
    history.save_scan(tmp_path, [_dev("192.168.1.1"), _dev("192.168.1.2")])
    loaded = history.load_latest_devices(tmp_path)
    assert {d.ip for d in loaded} == {"192.168.1.1", "192.168.1.2"}


def test_diff_requires_at_least_two_scans(tmp_path):
    history.save_scan(tmp_path, [_dev("192.168.1.1")])
    assert history.diff_last_two_scans(tmp_path) is None


def test_diff_detects_new_and_missing(tmp_path):
    history.save_scan(tmp_path, [_dev("192.168.1.1"), _dev("192.168.1.2")])
    history.save_scan(tmp_path, [_dev("192.168.1.1"), _dev("192.168.1.3")])
    diff = history.diff_last_two_scans(tmp_path)
    assert diff.new == ["192.168.1.3"]
    assert diff.missing == ["192.168.1.2"]
    assert diff.unchanged == ["192.168.1.1"]


def test_diff_detects_reappeared(tmp_path):
    history.save_scan(tmp_path, [_dev("192.168.1.1"), _dev("192.168.1.2")])  # scan 1: both present
    history.save_scan(tmp_path, [_dev("192.168.1.1")])  # scan 2: .2 missing
    history.save_scan(tmp_path, [_dev("192.168.1.1"), _dev("192.168.1.2")])  # scan 3: .2 reappeared
    diff = history.diff_last_two_scans(tmp_path)
    assert diff.reappeared == ["192.168.1.2"]
    assert diff.new == []


def test_load_all_scans_empty_when_no_file(tmp_path):
    assert history.load_all_scans(tmp_path) == []


def test_load_all_scans_handles_corrupt_file(tmp_path):
    (tmp_path / history.HISTORY_FILENAME).write_text("not valid json {{{")
    assert history.load_all_scans(tmp_path) == []


def test_load_all_scans_handles_valid_json_wrong_shape(tmp_path):
    # Regression: json.loads succeeded but returned a dict/string, which
    # crashed load_latest_devices/diff_last_two_scans with TypeError/KeyError.
    for payload in ('{"not": "a list"}', '"just a string"', "42"):
        (tmp_path / history.HISTORY_FILENAME).write_text(payload)
        assert history.load_all_scans(tmp_path) == []
        assert history.load_latest_devices(tmp_path) == []
        assert history.diff_last_two_scans(tmp_path) is None


def test_load_all_scans_skips_non_dict_entries(tmp_path):
    (tmp_path / history.HISTORY_FILENAME).write_text(
        '[{"timestamp": 1, "devices": [{"ip": "192.168.1.1"}]}, "junk", 42]\n'
    )
    scans = history.load_all_scans(tmp_path)
    assert len(scans) == 1
    assert {d.ip for d in history.load_latest_devices(tmp_path)} == {"192.168.1.1"}
