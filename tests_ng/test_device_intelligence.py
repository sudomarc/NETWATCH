from __future__ import annotations

from netwatch_ng.discovery import device_intelligence as di
from netwatch_ng.discovery.neighbors import Neighbor
from netwatch_ng.discovery.nmap_scan import NmapHost, Port


def test_from_neighbor_uses_local_oui_table():
    n = Neighbor(ip="192.168.1.50", mac="b8:27:eb:11:22:33", device="eth0", state="REACHABLE")
    d = di.from_neighbor(n)
    assert d.vendor is not None
    assert d.vendor.value == "Raspberry Pi Foundation"
    assert d.vendor.confidence == di.Confidence.LIKELY


def test_from_neighbor_unknown_vendor_is_none():
    n = Neighbor(ip="192.168.1.51", mac="ff:ff:ff:00:00:00", device="eth0", state="REACHABLE")
    d = di.from_neighbor(n)
    assert d.vendor is None
    assert d.describe_vendor() == "Unknown (no OUI match in local database)"


def test_from_nmap_host_prefers_nmap_vendor_over_local_table():
    host = NmapHost(
        ip="192.168.1.52",
        mac="b8:27:eb:11:22:33",
        nmap_vendor="Raspberry Pi Trading Ltd",  # nmap's own DB wording differs from ours
        hostname="pihole.lan",
        up=True,
        ports=[Port(number=80, protocol="tcp", state="open", service="http", product=None, version=None)],
    )
    d = di.from_nmap_host(host)
    assert d.vendor.value == "Raspberry Pi Trading Ltd"
    assert d.vendor.source == "nmap OUI database"
    assert d.hostname.value == "pihole.lan"
    assert d.open_ports == [80]
    assert d.services == ["http"]


def test_from_nmap_host_only_counts_open_ports():
    host = NmapHost(
        ip="192.168.1.53",
        mac=None,
        nmap_vendor=None,
        hostname=None,
        up=True,
        ports=[
            Port(number=80, protocol="tcp", state="open", service="http", product=None, version=None),
            Port(number=81, protocol="tcp", state="closed", service="http-alt", product=None, version=None),
        ],
    )
    d = di.from_nmap_host(host)
    assert d.open_ports == [80]


def test_merge_combines_neighbor_and_nmap_records_for_same_ip():
    neighbor_device = di.Device(ip="192.168.1.60", mac="aa:bb:cc:dd:ee:ff")
    nmap_device = di.Device(
        ip="192.168.1.60",
        hostname=di.IdentificationField(value="host.lan", source="nmap", confidence=di.Confidence.LIKELY),
        open_ports=[22],
    )
    merged = di.merge([neighbor_device, nmap_device])
    assert len(merged) == 1
    result = merged[0]
    assert result.mac == "aa:bb:cc:dd:ee:ff"
    assert result.hostname.value == "host.lan"
    assert result.open_ports == [22]


def test_merge_keeps_separate_devices_for_different_ips():
    d1 = di.Device(ip="192.168.1.1")
    d2 = di.Device(ip="192.168.1.2")
    merged = di.merge([d1, d2])
    assert {d.ip for d in merged} == {"192.168.1.1", "192.168.1.2"}
