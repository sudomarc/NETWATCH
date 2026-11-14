from __future__ import annotations

from netwatch_ng import activity_log


def test_activity_log_roundtrip(monkeypatch, tmp_path):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(activity_log, "_log_path", lambda: path)
    activity_log.record_event("Settings", "refresh_changed", "success", "15 seconds")
    events = activity_log.read_events()
    assert len(events) == 1
    assert events[0]["module"] == "Settings"
    assert events[0]["status"] == "success"
    assert events[0]["detail"] == "15 seconds"


def test_activity_log_sanitizes_newlines(monkeypatch, tmp_path):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(activity_log, "_log_path", lambda: path)
    activity_log.record_event("Test", "event", "info", "line one\nline two")
    assert len(path.read_text().splitlines()) == 1
