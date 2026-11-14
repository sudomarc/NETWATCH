from __future__ import annotations

import json

from netwatch_ng.core import network
from netwatch_ng.core.shell import CommandResult


def _fake_run_factory(stdout: str, returncode: int = 0):
    def _fake_run(argv, timeout=5.0, check=False):
        return CommandResult(argv=argv, returncode=returncode, stdout=stdout, stderr="")

    return _fake_run


def test_get_default_gateway_parses_route(monkeypatch):
    payload = json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0", "protocol": "dhcp"}])
    monkeypatch.setattr(network, "run", _fake_run_factory(payload))
    route = network.get_default_gateway("inet")
    assert route is not None
    assert route.gateway == "192.168.1.1"
    assert route.device == "eth0"


def test_get_default_gateway_none_when_no_default_route(monkeypatch):
    monkeypatch.setattr(network, "run", _fake_run_factory(""))
    assert network.get_default_gateway("inet") is None


def test_get_default_gateway_none_on_command_failure(monkeypatch):
    monkeypatch.setattr(network, "run", _fake_run_factory("", returncode=2))
    assert network.get_default_gateway("inet") is None


def test_get_routes_parses_multiple_entries(monkeypatch):
    payload = json.dumps(
        [
            {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"},
            {"dst": "192.168.1.0/24", "dev": "eth0"},
        ]
    )
    monkeypatch.setattr(network, "run", _fake_run_factory(payload))
    routes = network.get_routes("inet")
    assert len(routes) == 2
    assert routes[1].destination == "192.168.1.0/24"


def test_get_dns_servers_parses_resolv_conf(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n# comment\n")
    assert network.get_dns_servers(str(resolv)) == ["1.1.1.1", "8.8.8.8"]


def test_get_dns_servers_missing_file_returns_empty(tmp_path):
    missing = tmp_path / "does-not-exist.conf"
    assert network.get_dns_servers(str(missing)) == []
