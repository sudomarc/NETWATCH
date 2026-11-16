"""Safe process execution helpers.

Rules enforced here (see CONTRIBUTING.md):
  - never build a shell string from user input: always pass argv lists;
  - never use shell=True;
  - always bound external calls with a timeout;
  - a missing binary is a normal, reportable condition, not a crash.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from dataclasses import dataclass


class BinaryNotFound(Exception):
    """Raised when the requested executable is not on PATH."""

    def __init__(self, binary: str):
        super().__init__(f"required binary not found: {binary}")
        self.binary = binary


class CommandCancelled(Exception):
    """Raised when an external process is stopped by its caller."""


@dataclass
class CommandResult:
    argv: list
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def which(binary: str) -> str | None:
    """Return the resolved path of `binary`, or None if it is not installed."""
    return shutil.which(binary)


def run(argv: list[str], timeout: float = 5.0, check: bool = False) -> CommandResult:
    """Run argv (never a shell string) and capture output.

    Raises BinaryNotFound if argv[0] is not on PATH.
    Raises subprocess.TimeoutExpired if the command exceeds `timeout`.
    """
    if not argv:
        raise ValueError("argv must not be empty")

    binary = argv[0]
    if which(binary) is None:
        raise BinaryNotFound(binary)

    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    result = CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
    if check and not result.ok:
        raise subprocess.CalledProcessError(
            result.returncode, argv, output=result.stdout, stderr=result.stderr
        )
    return result


def run_cancellable(
    argv: list[str],
    timeout: float,
    cancel_event: threading.Event,
) -> CommandResult:
    """Run argv with a timeout and terminate the child when cancellation is set."""
    if not argv:
        raise ValueError("argv must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    binary = argv[0]
    if which(binary) is None:
        raise BinaryNotFound(binary)

    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    while True:
        if cancel_event.is_set():
            _stop_process(proc)
            raise CommandCancelled(f"command cancelled: {binary}")

        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            _stop_process(proc)
            raise subprocess.TimeoutExpired(argv, timeout)

        try:
            stdout, stderr = proc.communicate(timeout=min(0.1, remaining))
            break
        except subprocess.TimeoutExpired:
            continue

    return CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        pass
    try:
        proc.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        proc.communicate()
