from __future__ import annotations

import pytest

from netwatch_ng.core import shell
from netwatch_ng.core.shell import BinaryNotFound, CommandCancelled, run, run_cancellable


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


def test_run_cancellable_terminates_child_on_cancellation(monkeypatch):
    import threading

    class FakeProcess:
        returncode = None
        terminated = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def communicate(self, timeout=None):
            return "", ""

    process = FakeProcess()
    monkeypatch.setattr(shell, "which", lambda binary: "/usr/bin/iw")
    monkeypatch.setattr(shell.subprocess, "Popen", lambda *args, **kwargs: process)
    cancelled = threading.Event()
    cancelled.set()

    with pytest.raises(CommandCancelled):
        run_cancellable(["iw", "dev", "wlan0", "scan"], 5, cancelled)

    assert process.terminated
