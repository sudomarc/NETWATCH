from __future__ import annotations

import pytest

from netwatch_ng import upnp


def test_parse_ssdp_headers_is_case_insensitive():
    headers = upnp.parse_ssdp_headers(
        b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/root.xml\r\nSERVER: RouterOS\r\nST: upnp:rootdevice\r\n\r\n"
    )
    assert headers["location"] == "http://192.168.1.1/root.xml"
    assert headers["server"] == "RouterOS"
    assert headers["st"] == "upnp:rootdevice"


def test_location_is_restricted_to_literal_gateway():
    assert upnp._location_path("http://192.168.1.1/root.xml", "192.168.1.1") == (80, "/root.xml")
    assert upnp._location_path("http://192.168.1.2/root.xml", "192.168.1.1") is None
    assert upnp._location_path("https://192.168.1.1/root.xml", "192.168.1.1") is None
    assert upnp._location_path("http://user@192.168.1.1/root.xml", "192.168.1.1") is None
    assert upnp._location_path("http://example.com/root.xml", "192.168.1.1") is None


def test_parse_description_extracts_model_fields():
    xml_body = b"""<root xmlns="urn:schemas-upnp-org:device-1-0">
      <device>
        <friendlyName>Home Router</friendlyName>
        <manufacturer>Example Networks</manufacturer>
        <modelName>XR-100</modelName>
        <modelNumber>100A</modelNumber>
        <serialNumber>abc123</serialNumber>
      </device>
    </root>"""
    fields = upnp.parse_description(xml_body)
    assert fields == {
        "friendlyName": "Home Router",
        "manufacturer": "Example Networks",
        "modelName": "XR-100",
        "modelNumber": "100A",
        "serialNumber": "abc123",
    }


@pytest.mark.parametrize("gateway", ["example.com", "8.8.8.8", "2001:db8::1"])
def test_discovery_rejects_non_private_ipv4_gateways(gateway):
    with pytest.raises(ValueError):
        upnp.discover_upnp(gateway)
