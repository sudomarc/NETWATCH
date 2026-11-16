"""NETWATCH NG package.

The version is read from the installed package metadata (set by pyproject.toml
at build/install time), so there is a single source of truth: the Python
project version. When run from a source checkout without installation, the
fallback matches the development version declared in pyproject.toml.
"""
from importlib.metadata import version as _metadata_version, PackageNotFoundError

try:
    __version__ = _metadata_version("netwatch-ng")
except PackageNotFoundError:
    __version__ = "2.0.0.dev1"
