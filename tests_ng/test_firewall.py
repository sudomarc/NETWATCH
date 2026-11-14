from __future__ import annotations

import ipaddress

import pytest

from netwatch_ng import firewall


def _fake_run_factory(stdout: str = "", returncode: int = 0):
    def _fake_run(argv, timeout=5.0, check=False):
        return type(
            "Result",
            (),
            {"argv": argv, "returncode": returncode, "stdout": stdout, "stderr": ""},
        )()

    return _fake_run


def test_validate_ip_target_accepts_ipv4_and_ipv6():
    assert firewall.validate_ip_target("192.168.1.42") == "192.168.1.42"
    assert firewall.validate_ip_target("2001:db8::1") == "2001:db8::1"


def test_validate_ip_target_rejects_malformed_values():
    with pytest.raises(ValueError):
        firewall.validate_ip_target("not-an-ip")


def test_list_netwatch_rules_parses_iptables_save(monkeypatch):
    output = """
    -A FORWARD -s 192.168.1.10 -m comment --comment \"NETWATCH\" -j DROP
    -A OUTPUT -d 8.8.8.8 -j ACCEPT
    -A FORWARD -s 2001:db8::10 -m comment --comment \"NETWATCH\" -j DROP
    """
    monkeypatch.setattr(firewall, "which", lambda binary: "/usr/sbin/iptables")
    monkeypatch.setattr(firewall, "run", lambda argv, timeout=5.0: type("Result", (), {"ok": True, "stdout": output, "stderr": ""})())

    rules = firewall.list_netwatch_rules("inet")
    assert len(rules) == 1
    assert rules[0].source == "192.168.1.10"
    assert rules[0].comment == "NETWATCH"


def test_block_ip_rejects_default_gateway(monkeypatch):
    monkeypatch.setattr(firewall.network, "get_default_gateway", lambda family: type("Route", (), {"gateway": "192.168.1.1"})())
    with pytest.raises(ValueError):
        firewall.block_ip("192.168.1.1")


def test_block_ip_uses_iptables_and_is_idempotent(monkeypatch):
    called = []
    check_count = {"n": 0}

    def fake_run(argv, timeout=5.0, check=False):
        called.append(tuple(argv))
        if argv[1] == "-C":
            check_count["n"] += 1
            return type("Result", (), {"ok": check_count["n"] > 1, "stdout": "", "stderr": ""})()
        return type("Result", (), {"ok": True, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(firewall, "which", lambda binary: "/usr/sbin/iptables")
    monkeypatch.setattr(firewall, "run", fake_run)
    monkeypatch.setattr(firewall.network, "get_default_gateway", lambda family: None)

    assert firewall.block_ip("192.168.1.42") is True
    assert firewall.block_ip("192.168.1.42") is False
    assert any(cmd[0:2] == ("iptables", "-C") for cmd in called)


def test_unblock_ip_removes_existing_rule(monkeypatch):
    monkeypatch.setattr(firewall, "which", lambda binary: "/usr/sbin/iptables")
    monkeypatch.setattr(firewall.network, "get_default_gateway", lambda family: None)
    monkeypatch.setattr(
        firewall,
        "run",
        lambda argv, timeout=5.0, check=False: type("Result", (), {"ok": True, "stdout": "", "stderr": ""})(),
    )
    assert firewall.unblock_ip("192.168.1.42") is True
