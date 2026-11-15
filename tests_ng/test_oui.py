from __future__ import annotations

from netwatch_ng.discovery import oui


def test_normalize_mac_strips_separators_and_uppercases():
    assert oui.normalize_mac("b8:27:eb:11:22:33") == "B827EB"
    assert oui.normalize_mac("B8-27-EB-11-22-33") == "B827EB"


def test_lookup_known_prefix():
    assert oui.lookup("b8:27:eb:11:22:33") == "Raspberry Pi Foundation"


def test_all_builtin_prefixes_are_six_hex_chars():
    # Regression: "52540" (5 chars) could never match normalize_mac()'s
    # 6-char output, so the QEMU/KVM entry was dead.
    assert all(len(key) == 6 for key in oui._BUILTIN_OUI)


def test_lookup_qemu_prefix():
    assert oui.lookup("52:54:00:12:34:56") == "QEMU/KVM (virtual NIC)"


def test_lookup_unknown_prefix_returns_none():
    assert oui.lookup("ff:ff:ff:11:22:33") is None


def test_load_extra_table_merges_entries(tmp_path):
    ieee_style = tmp_path / "oui.txt"
    ieee_style.write_text(
        "AA-BB-CC   (hex)\t\tTotally Fake Vendor\n"
        "not a matching line\n"
        "112233     (hex)\t\tAnother Fake Vendor\n"
    )
    count = oui.load_extra_table(ieee_style)
    assert count == 2
    assert oui.lookup("aa:bb:cc:00:00:00") == "Totally Fake Vendor"
    assert oui.lookup("11:22:33:00:00:00") == "Another Fake Vendor"
