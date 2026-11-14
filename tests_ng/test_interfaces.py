from __future__ import annotations

import json

from netwatch_ng.core import interfaces
from netwatch_ng.core.shell import CommandResult

SAMPLE_IP_ADDR_JSON = json.dumps(
    [
        {
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "mtu": 65536,
            "address": "00:00:00:00:00:00",
            "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}
            ],
        },
        {
            "ifname": "eth0",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "mtu": 1500,
            "address": "aa:bb:cc:dd:ee:ff",
            "addr_info": [
                {"family": "inet", "local": "192.168.1.50", "prefixlen": 24, "scope": "global"},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
            ],
        },
        {
            "ifname": "wlan0",
            "flags": ["BROADCAST", "MULTICAST"],
            "mtu": 1500,
            "address": "11:22:33:44:55:66",
            "addr_info": [],
        },
    ]
)


def _fake_run_factory(stdout: str):
    def _fake_run(argv, timeout=5.0, check=False):
        return CommandResult(argv=argv, returncode=0, stdout=stdout, stderr="")

    return _fake_run


def test_list_interfaces_excludes_loopback_by_default(monkeypatch):
    monkeypatch.setattr(interfaces, "run", _fake_run_factory(SAMPLE_IP_ADDR_JSON))
    result = interfaces.list_interfaces()
    names = [i.name for i in result]
    assert "lo" not in names
    assert "eth0" in names
    assert "wlan0" in names


def test_list_interfaces_includes_loopback_when_requested(monkeypatch):
    monkeypatch.setattr(interfaces, "run", _fake_run_factory(SAMPLE_IP_ADDR_JSON))
    result = interfaces.list_interfaces(include_loopback=True)
    assert any(i.name == "lo" for i in result)


def test_interface_up_down_state(monkeypatch):
    monkeypatch.setattr(interfaces, "run", _fake_run_factory(SAMPLE_IP_ADDR_JSON))
    result = {i.name: i for i in interfaces.list_interfaces()}
    assert result["eth0"].is_up is True
    assert result["wlan0"].is_up is False


def test_ipv4_and_ipv6_address_split(monkeypatch):
    monkeypatch.setattr(interfaces, "run", _fake_run_factory(SAMPLE_IP_ADDR_JSON))
    result = {i.name: i for i in interfaces.list_interfaces()}
    eth0 = result["eth0"]
    assert [a.address for a in eth0.ipv4_addresses] == ["192.168.1.50"]
    assert [a.address for a in eth0.ipv6_addresses] == ["fe80::1"]


def test_empty_output_returns_empty_list(monkeypatch):
    monkeypatch.setattr(interfaces, "run", _fake_run_factory(""))
    assert interfaces.list_interfaces() == []


def test_command_failure_raises_runtime_error(monkeypatch):
    def _fake_run(argv, timeout=5.0, check=False):
        return CommandResult(argv=argv, returncode=1, stdout="", stderr="ip: permission denied")

    monkeypatch.setattr(interfaces, "run", _fake_run)
    import pytest

    with pytest.raises(RuntimeError):
        interfaces.list_interfaces()
