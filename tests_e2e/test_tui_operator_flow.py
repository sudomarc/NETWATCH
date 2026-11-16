from __future__ import annotations

import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOWN = b"\x1bOB"  # xterm-256color terminfo: kcud1

SPLASH_TAGLINE = "NETWORK VISIBILITY. INTELLIGENCE. CONTROL."


def _install_fake_commands(tmp_path: Path) -> tuple[Path, Path]:
    """Create a hermetic PATH: only harmless read-only command doubles exist."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    command_log = tmp_path / "commands.jsonl"

    stub = f"""#!{sys.executable}
import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["NETWATCH_E2E_COMMAND_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({{"name": name, "args": args}}) + "\\n")

if name == "ip":
    # Empty, valid iproute2 JSON for interfaces, routes and neighbors.
    print("[]")
    raise SystemExit(0)

if name in {{"iptables", "ip6tables"}}:
    forbidden = {{"-A", "-I", "-D", "-F", "-X", "-P"}}
    if forbidden.intersection(args):
        print("E2E SAFETY GUARD: firewall mutation blocked", file=sys.stderr)
        raise SystemExit(97)
    raise SystemExit(0)
"""
    for binary in ("ip", "iptables", "ip6tables"):
        executable = fake_bin / binary
        executable.write_text(stub, encoding="utf-8")
        executable.chmod(0o700)

    return fake_bin, command_log


class _TerminalSession:
    def __init__(self, project_root: Path, env: dict[str, str]) -> None:
        self.master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(
            slave_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 45, 160, 0, 0),
        )
        self.output = bytearray()
        self.process = subprocess.Popen(
            [sys.executable, "-m", "netwatch_ng"],
            cwd=project_root,
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)

    def send(self, keys: bytes) -> None:
        os.write(self.master_fd, keys)

    def expect(self, text: str, timeout: float = 8.0) -> None:
        expected = text.encode("utf-8")
        deadline = time.monotonic() + timeout

        while expected not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select(
                [self.master_fd], [], [], min(0.1, remaining)
            )
            if not readable:
                if self.process.poll() is not None:
                    break
                continue
            try:
                chunk = os.read(self.master_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.output.extend(chunk)

        if expected not in self.output:
            rendered = self.output.decode("utf-8", errors="replace")
            pytest.fail(
                f"Timed out waiting for terminal text {text!r}. "
                f"Process status: {self.process.poll()!r}. "
                f"Last terminal output:\n{rendered[-3000:]}"
            )

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.send(b"q")
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        os.close(self.master_fd)


def _base_env(tmp_path: Path) -> dict[str, str]:
    config_dir = tmp_path / "netwatch-config"
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(tmp_path),
            "NETWATCH_NG_CONFIG": str(config_dir),
            "NETWATCH_E2E_COMMAND_LOG": str(tmp_path / "commands.jsonl"),
            "PATH": str(_install_fake_commands(tmp_path)[0]),
            "PYTHONPATH": str(PROJECT_ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
    )
    return env


@pytest.mark.e2e
def test_splash_renders_and_keyboard_skip_reaches_dashboard(tmp_path: Path) -> None:
    """The splash shows brand/tagline/version, and any key skips straight to
    the Dashboard without an extra key press."""
    env = _base_env(tmp_path)
    command_log = env["NETWATCH_E2E_COMMAND_LOG"]

    session = _TerminalSession(PROJECT_ROOT, env)
    try:
        # The application starts by showing the splash.
        session.expect("NETWATCH NG")
        session.expect(SPLASH_TAGLINE)

        # Pressing any key skips the splash immediately (no extra key press).
        session.send(b" ")
        session.expect("CONNECTION")  # Dashboard content appears

        # Regression-free navigation still works after the splash.
        for _ in range(4):
            session.send(DOWN)
            time.sleep(0.03)
        session.expect("FIREWALL MANAGER")
        session.send(b"b")
        session.expect("IPv4/IPv6 address:")
        session.send(b"192.0.2.10\n")
        session.expect("Block 192.0.2.10 on the forwarding path?")
        session.send(b"n")
        session.expect("Block cancelled.")

        session.send(b"q")
        assert session.process.wait(timeout=5) == 0
    finally:
        session.close()

    calls = [
        json.loads(line)
        for line in Path(command_log).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(call["name"] == "ip" for call in calls)
    assert not any(
        call["name"] in {"iptables", "ip6tables"}
        and {"-A", "-I", "-D", "-F", "-X", "-P"}.intersection(call["args"])
        for call in calls
    )


@pytest.mark.e2e
def test_splash_auto_transitions_to_dashboard_without_keys(tmp_path: Path) -> None:
    """With no key press, the splash runs for its duration then opens the
    Dashboard automatically."""
    env = _base_env(tmp_path)

    session = _TerminalSession(PROJECT_ROOT, env)
    try:
        session.expect("NETWATCH NG")
        session.expect(SPLASH_TAGLINE)

        # No keys are sent: after roughly seven seconds the Dashboard opens.
        session.expect("CONNECTION", timeout=12.0)

        session.send(b"q")
        assert session.process.wait(timeout=5) == 0
    finally:
        session.close()


@pytest.mark.e2e
def test_operator_flow_is_safe_and_settings_persist(tmp_path: Path) -> None:
    """Exercise the real curses app without touching the host network stack."""
    env = _base_env(tmp_path)

    session = _TerminalSession(PROJECT_ROOT, env)
    try:
        # The application starts with the splash; skip it to reach the
        # Dashboard, then exercise settings and navigation as before.
        session.expect("NETWATCH NG")
        session.expect(SPLASH_TAGLINE)
        session.send(b" ")
        session.expect("CONNECTION")

        # Open Firewall and cancel a proposed block. The fake iptables
        # executable rejects every mutating operation as a second safety net.
        for _ in range(4):
            session.send(DOWN)
            time.sleep(0.03)
        session.expect("FIREWALL MANAGER")
        session.send(b"b")
        session.expect("IPv4/IPv6 address:")
        session.send(b"192.0.2.10\n")
        session.expect("Block 192.0.2.10 on the forwarding path?")
        session.send(b"n")
        session.expect("Block cancelled.")

        # Open Reset Manager, verify its preview, then cancel confirmation.
        for _ in range(2):
            session.send(DOWN)
            time.sleep(0.03)
        session.expect("READ-ONLY PREVIEW")
        session.send(b"x")
        session.expect("Remove the listed NETWATCH rules?")
        session.send(b"n")
        session.expect("Reset cancelled; no changes requested")

        # Change a setting through the TUI and verify the persisted file.
        for _ in range(3):
            session.send(DOWN)
            time.sleep(0.03)
        session.expect("adjust refresh interval")
        session.send(b"0")
        session.expect("Automatic refresh disabled.")

        config_dir = Path(env["NETWATCH_NG_CONFIG"])
        settings_file = config_dir / "settings.json"
        assert settings_file.is_file()
        assert json.loads(settings_file.read_text(encoding="utf-8"))[
            "refresh_seconds"
        ] == 0

        session.send(b"q")
        assert session.process.wait(timeout=5) == 0
    finally:
        session.close()

    calls = [
        json.loads(line)
        for line in Path(env["NETWATCH_E2E_COMMAND_LOG"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(call["name"] == "ip" for call in calls)
    assert any(
        call["name"] in {"iptables", "ip6tables"}
        and call["args"] == ["-S"]
        for call in calls
    )
    assert not any(
        call["name"] in {"iptables", "ip6tables"}
        and {"-A", "-I", "-D", "-F", "-X", "-P"}.intersection(call["args"])
        for call in calls
    )
