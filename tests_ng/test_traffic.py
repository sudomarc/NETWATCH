from __future__ import annotations

import json

import pytest

from netwatch_ng.core.shell import CommandResult
from netwatch_ng.traffic import clear_limit, list_limits, set_limit


def _setup(monkeypatch, tmp_path):
    import netwatch_ng.traffic as traffic
    monkeypatch.setattr(traffic, "STATE_FILE", tmp_path / "traffic-state.json")
    monkeypatch.setattr(traffic, "_require_root", lambda: None)
    monkeypatch.setattr(traffic, "which", lambda binary: "/usr/sbin/tc")
    return traffic


def test_set_limit_uses_clsact_and_preserves_root_qdisc(monkeypatch, tmp_path):
    traffic = _setup(monkeypatch, tmp_path)
    calls = []
    installed = {"clsact": False, "egress": False}

    def fake_run(argv, timeout=5.0):
        calls.append(tuple(argv))
        if argv[1:3] == ["qdisc", "show"]:
            output = "qdisc fq_codel 0: root refcnt 2\n"
            if installed["clsact"]:
                output += "qdisc clsact ffff: parent ffff:fff1\n"
            return CommandResult(argv, 0, output, "")
        if argv[1:3] == ["qdisc", "add"]:
            installed["clsact"] = True
            return CommandResult(argv, 0, "", "")
        if argv[1:3] == ["filter", "show"]:
            if installed[argv[-1]]:
                return CommandResult(
                    argv, 0,
                    "filter protocol all pref 49152 matchall chain 0\naction order 1: police rate 512Kbit burst 64Kb\n",
                    "",
                )
            return CommandResult(argv, 0, "", "")
        if argv[1:3] == ["filter", "add"]:
            installed[argv[5]] = True
            return CommandResult(argv, 0, "", "")
        if argv[1:3] == ["filter", "replace"]:
            installed[argv[5]] = True
            return CommandResult(argv, 0, "", "")
        return CommandResult(argv, 0, "", "")

    monkeypatch.setattr(traffic, "run", fake_run)
    limit = set_limit("eth0", 512)
    assert limit.rate_kbps == 512
    assert any(call[1:3] == ("qdisc", "add") for call in calls)
    assert not any(call[1:3] == ("qdisc", "replace") for call in calls)
    assert not any(call[1:3] == ("qdisc", "delete") for call in calls)
    assert json.loads(traffic.STATE_FILE.read_text())["limits"]["eth0:egress"]["rate_kbps"] == 512


def test_set_limit_refuses_unowned_reserved_filter(monkeypatch, tmp_path):
    traffic = _setup(monkeypatch, tmp_path)
    def fake_run(argv, timeout=5.0):
        if argv[1:3] == ["qdisc", "show"]:
            return CommandResult(argv, 0, "qdisc clsact ffff: parent ffff:fff1\n", "")
        if argv[1:3] == ["filter", "show"]:
            return CommandResult(
                argv, 0,
                "filter protocol all pref 49152 matchall chain 0\naction order 1: police rate 1Mbit burst 64Kb\n",
                "",
            )
        return CommandResult(argv, 0, "", "")
    monkeypatch.setattr(traffic, "run", fake_run)
    with pytest.raises(RuntimeError, match="already occupied"):
        set_limit("eth0", 512)


def test_list_limits_reads_state_and_verifies_kernel_filter(monkeypatch, tmp_path):
    traffic = _setup(monkeypatch, tmp_path)
    traffic.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    traffic.STATE_FILE.write_text(json.dumps({"version": 1, "limits": {"eth0:egress": {"rate_kbps": 512, "pref": 49152}}}))
    def fake_run(argv, timeout=5.0):
        if argv[1:3] == ["qdisc", "show"]:
            return CommandResult(argv, 0, "qdisc clsact ffff: parent ffff:fff1\n", "")
        return CommandResult(argv, 0, "filter protocol all pref 49152 matchall chain 0\naction order 1: police rate 512Kbit burst 64Kb\n", "")
    monkeypatch.setattr(traffic, "run", fake_run)
    limits = list_limits()
    assert [(limit.interface, limit.direction, limit.rate_kbps) for limit in limits] == [("eth0", "egress", 512)]


def test_clear_limit_deletes_only_reserved_filter_not_root_qdisc(monkeypatch, tmp_path):
    traffic = _setup(monkeypatch, tmp_path)
    traffic.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    traffic.STATE_FILE.write_text(json.dumps({"version": 1, "limits": {"eth0:egress": {"rate_kbps": 512, "pref": 49152}}}))
    calls = []
    active = True
    def fake_run(argv, timeout=5.0):
        nonlocal active
        calls.append(tuple(argv))
        if argv[1:3] == ["filter", "show"]:
            output = "filter protocol all pref 49152 matchall chain 0\naction order 1: police rate 512Kbit burst 64Kb\n" if active else ""
            return CommandResult(argv, 0, output, "")
        if argv[1:3] == ["filter", "del"]:
            active = False
        return CommandResult(argv, 0, "", "")
    monkeypatch.setattr(traffic, "run", fake_run)
    assert clear_limit("eth0") is True
    assert any(call[1:3] == ("filter", "del") for call in calls)
    assert not any(call[1:3] == ("qdisc", "delete") for call in calls)
    assert "eth0:egress" not in traffic.STATE_FILE.read_text()


def test_set_limit_validates_interface_and_rate(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        set_limit("eth0;id", 512)
    with pytest.raises(ValueError):
        set_limit("eth0", 0)
