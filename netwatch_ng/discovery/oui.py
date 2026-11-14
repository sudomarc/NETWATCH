"""MAC OUI (first 3 octets) -> vendor lookup.

This ships a small, hand-curated table of common vendor prefixes. It
is NOT a full IEEE OUI database (that's ~50k entries and would need a
network fetch NETWATCH NG doesn't do automatically). Treat a hit here
as a lead, not a certainty — see device_intelligence.py for how this
feeds into an overall confidence score. An operator can extend
EXTRA_OUI_PATHS with a full IEEE oui.txt copy if they have one locally;
nothing is downloaded by this module.
"""

from __future__ import annotations

from pathlib import Path

# A small, intentionally partial set of common OUI prefixes (uppercase,
# no separators, first 6 hex digits). Extend as needed; this is a
# starting point, not a claim of completeness.
_BUILTIN_OUI: dict[str, str] = {
    "001A11": "Google",
    "3C5AB4": "Google",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "FCECDA": "Espressif (ESP8266/ESP32)",
    "A020A6": "Espressif (ESP8266/ESP32)",
    "001E58": "WistronNeweb",
    "F4F5D8": "Google (Nest)",
    "F4F26D": "TP-Link",
    "50C7BF": "TP-Link",
    "AC84C6": "TP-Link",
    "B0487A": "D-Link",
    "1C7EE5": "D-Link",
    "0014D1": "Netgear",
    "A42B8C": "Netgear",
    "E0469A": "Netgear",
    "C83A35": "Espressif",
    "7CDD90": "ASUS",
    "D017C2": "ASUS",
    "2C56DC": "ASUS",
    "001D0F": "Cisco",
    "0050F2": "Microsoft",
    "001DD8": "Microsoft",
    "3C8375": "Microsoft (Surface)",
    "001C42": "Parallels (virtual NIC)",
    "080027": "Oracle VirtualBox (virtual NIC)",
    "000C29": "VMware (virtual NIC)",
    "005056": "VMware (virtual NIC)",
    "52540": "QEMU/KVM (virtual NIC)",
    "001124": "Apple",
    "F0DBF8": "Apple",
    "A4C361": "Apple",
    "B8F6B1": "Apple",
    "DC2B2A": "Apple",
    "001E64": "Nokia",
    "001BC5": "Samsung",
    "C4731E": "Samsung",
    "D0DFC7": "Samsung",
    "0024E4": "Withings",
    "18B430": "Nest Labs",
    "B4E62D": "Nest Labs",
}


def normalize_mac(mac: str) -> str:
    """Return the uppercase, separator-free OUI (first 6 hex chars) of a MAC."""
    cleaned = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    return cleaned[:6]


def lookup(mac: str) -> str | None:
    """Return a vendor name for `mac`'s OUI, or None if unknown locally."""
    oui = normalize_mac(mac)
    if len(oui) < 6:
        return None
    return _BUILTIN_OUI.get(oui)


def load_extra_table(path: str | Path) -> int:
    """Merge a local `oui.txt`-style file (IEEE format: 'XXXXXX   (hex)\\tVendor')
    into the lookup table at runtime. Returns the number of entries loaded.
    Never fetched automatically — the operator must supply the path.
    """
    count = 0
    text = Path(path).read_text(errors="ignore")
    for line in text.splitlines():
        if "(hex)" not in line:
            continue
        prefix, _, vendor = line.partition("(hex)")
        prefix = prefix.strip().replace("-", "")
        vendor = vendor.strip()
        if len(prefix) == 6 and vendor:
            _BUILTIN_OUI[prefix.upper()] = vendor
            count += 1
    return count
