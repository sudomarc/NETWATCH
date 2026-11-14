"""Config and runtime-state directory resolution.

Mirrors the contract the Bash toolkit already enforced (see legacy
README "Runtime state" section), so behavior stays predictable for
users migrating from NETWATCH 1.x:

  - unprivileged (read-only / passive) operations use
    ${XDG_CONFIG_HOME:-$HOME/.config}/netwatch-ng
  - root / privileged operations use /etc/netwatch-ng
  - NETWATCH_NG_CONFIG overrides either, but a root operation refuses
    a config directory that is not root-owned or is group/world
    writable (a world-writable config dir is a privilege-escalation
    vector for anything that later reads rules or state from it).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

APP_NAME = "netwatch-ng"
ROOT_CONFIG_DIR = Path("/etc") / APP_NAME


class UnsafeConfigDir(Exception):
    """Raised when a privileged config directory fails ownership/permission checks."""


def is_root() -> bool:
    return os.geteuid() == 0


def _user_config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / APP_NAME


def _validate_privileged_dir(path: Path) -> None:
    if not path.exists():
        return  # will be created with safe permissions by get_config_dir()
    st = path.stat()
    if st.st_uid != 0:
        raise UnsafeConfigDir(f"{path} is not owned by root (uid={st.st_uid})")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise UnsafeConfigDir(f"{path} is group- or world-writable (mode={oct(st.st_mode)})")


def get_config_dir() -> Path:
    """Resolve the active config directory, creating it with safe permissions
    if it does not exist yet. Raises UnsafeConfigDir if a privileged override
    points at an unsafe existing directory.
    """
    override = os.environ.get("NETWATCH_NG_CONFIG")
    if override:
        path = Path(override)
    elif is_root():
        path = ROOT_CONFIG_DIR
    else:
        path = _user_config_dir()

    if is_root():
        _validate_privileged_dir(path)
        path.mkdir(parents=True, exist_ok=True, mode=0o750)
    else:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)

    return path
