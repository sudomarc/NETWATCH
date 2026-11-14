from __future__ import annotations

import json

from netwatch_ng.discovery import neighbors
from netwatch_ng.core.shell import CommandResult

SAMPLE_NEIGH_JSON = json.dumps(
    [
        {"dst": "192.168.1.1", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:01", "state": ["REACHABLE"]},
        {"dst": "192.168.1.2", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:02", "state": ["STALE"]},
        {"dst": "192.168.1.3", "dev": "eth0", "state": ["FAILED"]},  # no lladdr
        {"dst": "192.168.1.4", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:04", "state": ["INCOMPLETE"]},
    ]
)


def _fake_run_factory(stdout: str):
    def _fake_run(argv, timeout=5.0, check=False):
        return CommandResult(argv=argv, returncode=0, stdout=stdout, stderr="")

    return _fake_run


def test_list_neighbors_parses_all_entries(monkeypatch):
    monkeypatch.setattr(neighbors, "run", _fake_run_factory(SAMPLE_NEIGH_JSON))
    result = neighbors.list_neighbors()
    assert len(result) == 4
    assert result[0].ip == "192.168.1.1"
    assert result[0].mac == "aa:bb:cc:00:00:01"
    assert result[0].state == "REACHABLE"


def test_list_live_neighbors_excludes_no_mac_and_bad_states(monkeypatch):
    monkeypatch.setattr(neighbors, "run", _fake_run_factory(SAMPLE_NEIGH_JSON))
    result = neighbors.list_live_neighbors()
    ips = {n.ip for n in result}
    assert ips == {"192.168.1.1", "192.168.1.2"}


def test_list_neighbors_empty_output(monkeypatch):
    monkeypatch.setattr(neighbors, "run", _fake_run_factory(""))
    assert neighbors.list_neighbors() == []


def test_list_neighbors_command_failure_returns_empty(monkeypatch):
    def _fake_run(argv, timeout=5.0, check=False):
        return CommandResult(argv=argv, returncode=1, stdout="", stderr="err")

    monkeypatch.setattr(neighbors, "run", _fake_run)
    assert neighbors.list_neighbors() == []


def test_list_neighbors_missing_binary_returns_empty_not_raise(monkeypatch):
    # Regression: this crashed the Devices TUI screen on a system
    # without iproute2 before this guard was added.
    from netwatch_ng.core.shell import BinaryNotFound

    def _fake_run(argv, timeout=5.0, check=False):
        raise BinaryNotFound("ip")

    monkeypatch.setattr(neighbors, "run", _fake_run)
    assert neighbors.list_neighbors() == []
    assert neighbors.list_live_neighbors() == []
