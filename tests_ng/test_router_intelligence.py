from __future__ import annotations

import pytest

from netwatch_ng.core import interfaces, network
from netwatch_ng.core.interfaces import Interface, InterfaceAddress
from netwatch_ng.core.network import Route
from netwatch_ng.discovery.neighbors import Neighbor
from netwatch_ng import router_intelligence as router


def test_inspect_gateway_joins_route_neighbor_and_interface(monkeypatch):
    monkeypatch.setattr(
        network,
        "get_default_gateway",
        lambda family: Route("default", "192.168.1.1", "eth0", "dhcp"),
    )
    monkeypatch.setattr(
        router,
        "list_live_neighbors",
        lambda family: [
            Neighbor("192.168.1.1", "b8:27:eb:11:22:33", "eth0", "REACHABLE")
        ],
    )
    monkeypatch.setattr(
        interfaces,
        "list_interfaces",
        lambda include_loopback: [
            Interface(
                "eth0",
                "UP",
                "00:11:22:33:44:55",
                1500,
                [InterfaceAddress("inet", "192.168.1.10", 24, "global")],
            )
        ],
    )

    report = router.inspect_gateway()

    assert report is not None
    assert report.gateway == "192.168.1.1"
    assert report.interface == "eth0"
    assert report.mac == "b8:27:eb:11:22:33"
    assert report.manufacturer == "Raspberry Pi Foundation"
    assert report.local_addresses == ["192.168.1.10"]


def test_inspect_gateway_does_not_invent_manufacturer(monkeypatch):
    monkeypatch.setattr(network, "get_default_gateway", lambda family: None)
    assert router.inspect_gateway() is None


def test_inspect_default_gateway_falls_back_to_ipv6(monkeypatch):
    seen = []

    def fake_get_default_gateway(family):
        seen.append(family)
        if family == "inet6":
            return Route("default", "2001:db8::1", "eth0", "ra")
        return None

    monkeypatch.setattr(network, "get_default_gateway", fake_get_default_gateway)
    monkeypatch.setattr(router, "list_live_neighbors", lambda family: [])
    monkeypatch.setattr(interfaces, "list_interfaces", lambda include_loopback: [])

    report = router.inspect_default_gateway()

    assert report is not None
    assert report.family == "inet6"
    assert seen == ["inet", "inet6"]


def test_probe_management_services_reports_refused_ports(monkeypatch):
    class OpenSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def connect(address, timeout):
        if address[1] == 80:
            raise ConnectionRefusedError()
        return OpenSocket()

    monkeypatch.setattr(router.socket, "create_connection", connect)
    results = router.probe_management_services("192.0.2.1", timeout=0.1)

    assert results[0].state == "reachable"
    assert results[1].state == "not reachable (closed or filtered)"
    assert len(results) == len(router.MANAGEMENT_PORTS)


def test_probe_management_services_rejects_non_ip_target(monkeypatch):
    monkeypatch.setattr(
        router.socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("must not connect to a hostname"),
    )
    with pytest.raises(ValueError):
        router.probe_management_services("router.example")


def test_probe_management_services_requires_positive_timeout():
    with pytest.raises(ValueError):
        router.probe_management_services("192.0.2.1", timeout=0)
