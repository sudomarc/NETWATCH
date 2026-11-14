from __future__ import annotations

import pytest

from netwatch_ng.discovery import nmap_scan
from netwatch_ng.core.shell import CommandResult

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:00:00:10" addrtype="mac" vendor="Example Corp"/>
    <hostnames><hostname name="printer.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="lighttpd" version="1.4"/>
      </port>
      <port protocol="tcp" portid="9100">
        <state state="closed"/>
        <service name="jetdirect"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def _fake_run_factory(stdout: str, returncode: int = 0, stderr: str = ""):
    def _fake_run(argv, timeout=5.0, check=False):
        return CommandResult(argv=argv, returncode=returncode, stdout=stdout, stderr=stderr)

    return _fake_run


def test_discovery_scan_parses_hosts(monkeypatch):
    monkeypatch.setattr(nmap_scan, "run", _fake_run_factory(SAMPLE_NMAP_XML))
    hosts = nmap_scan.discovery_scan("192.168.1.0/24")
    assert len(hosts) == 2
    up_host = hosts[0]
    assert up_host.ip == "192.168.1.10"
    assert up_host.mac == "AA:BB:CC:00:00:10"
    assert up_host.nmap_vendor == "Example Corp"
    assert up_host.hostname == "printer.lan"
    assert up_host.up is True
    assert hosts[1].up is False


def test_discovery_scan_parses_ports(monkeypatch):
    monkeypatch.setattr(nmap_scan, "run", _fake_run_factory(SAMPLE_NMAP_XML))
    hosts = nmap_scan.discovery_scan("192.168.1.0/24")
    ports = {p.number: p for p in hosts[0].ports}
    assert ports[80].state == "open"
    assert ports[80].product == "lighttpd"
    assert ports[9100].state == "closed"


def test_discovery_scan_rejects_shell_metacharacters():
    with pytest.raises(nmap_scan.InvalidTarget):
        nmap_scan.discovery_scan("192.168.1.0/24; rm -rf /")


def test_discovery_scan_raises_on_command_failure(monkeypatch):
    monkeypatch.setattr(nmap_scan, "run", _fake_run_factory("", returncode=1, stderr="nmap error"))
    with pytest.raises(RuntimeError):
        nmap_scan.discovery_scan("192.168.1.0/24")


def test_service_scan_rejects_cidr_target():
    with pytest.raises(nmap_scan.InvalidTarget):
        nmap_scan.service_scan("192.168.1.0/24")


def test_service_scan_returns_none_on_empty_result(monkeypatch):
    monkeypatch.setattr(nmap_scan, "run", _fake_run_factory(""))
    assert nmap_scan.service_scan("192.168.1.10") is None


def test_empty_xml_returns_empty_list(monkeypatch):
    monkeypatch.setattr(nmap_scan, "run", _fake_run_factory(""))
    assert nmap_scan.discovery_scan("192.168.1.0/24") == []
