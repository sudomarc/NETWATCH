from __future__ import annotations

import pytest

from netwatch_ng import settings


def test_settings_roundtrip(monkeypatch, tmp_path):
    path = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "_settings_path", lambda: path)
    saved = settings.update_setting("refresh_seconds", 15)
    assert saved["refresh_seconds"] == 15
    assert settings.load_settings()["refresh_seconds"] == 15


def test_settings_reject_invalid_values():
    with pytest.raises(settings.SettingsError):
        settings.validate_settings({"refresh_seconds": 4})
    with pytest.raises(settings.SettingsError):
        settings.validate_settings({"preferred_interface": "eth0;id"})
    with pytest.raises(settings.SettingsError):
        settings.validate_settings({"color_mode": "rainbow"})


def test_settings_reject_unknown_keys():
    with pytest.raises(settings.SettingsError):
        settings.validate_settings({"unknown": True})
