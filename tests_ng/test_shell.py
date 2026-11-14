from __future__ import annotations

import pytest

from netwatch_ng.core.shell import BinaryNotFound, run


def test_run_missing_binary_raises():
    with pytest.raises(BinaryNotFound):
        run(["this-binary-does-not-exist-netwatch-ng"])


def test_run_rejects_empty_argv():
    with pytest.raises(ValueError):
        run([])


def test_run_true_succeeds():
    result = run(["true"])
    assert result.ok
    assert result.returncode == 0


def test_run_false_reports_failure_without_raising():
    result = run(["false"])
    assert not result.ok


def test_run_check_true_raises_on_failure():
    import subprocess

    with pytest.raises(subprocess.CalledProcessError):
        run(["false"], check=True)
