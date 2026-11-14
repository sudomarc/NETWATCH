from __future__ import annotations

import os

import pytest

from netwatch_ng.system import config


def test_user_config_dir_created_with_safe_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "is_root", lambda: False)
    monkeypatch.delenv("NETWATCH_NG_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    result = config.get_config_dir()
    assert result == tmp_path / "netwatch-ng"
    assert result.exists()
    mode = result.stat().st_mode & 0o777
    assert mode == 0o700


def test_explicit_override_is_respected(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "is_root", lambda: False)
    override = tmp_path / "custom-dir"
    monkeypatch.setenv("NETWATCH_NG_CONFIG", str(override))

    result = config.get_config_dir()
    assert result == override
    assert result.exists()


def test_privileged_dir_rejected_if_world_writable(tmp_path, monkeypatch):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    os.chmod(unsafe, 0o777)  # mkdir mode is affected by umask; force it

    monkeypatch.setattr(config, "is_root", lambda: True)
    monkeypatch.setenv("NETWATCH_NG_CONFIG", str(unsafe))

    with pytest.raises(config.UnsafeConfigDir):
        config.get_config_dir()


def test_privileged_dir_accepted_if_new(tmp_path, monkeypatch):
    target = tmp_path / "fresh-privileged-dir"
    monkeypatch.setattr(config, "is_root", lambda: True)
    monkeypatch.setenv("NETWATCH_NG_CONFIG", str(target))

    result = config.get_config_dir()
    assert result == target
    assert result.exists()
