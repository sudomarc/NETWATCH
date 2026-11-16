# NETWATCH NG

NETWATCH NG is a Linux terminal application for supervising and administering
a network you own or are authorized to manage. It runs in your terminal as a
keyboard-driven text user interface (TUI): discover devices, identify them,
inspect your gateway and Wi-Fi environment, and manage firewall and traffic
rules — without a graphical interface.

It is for system administrators, network operators, and advanced users who want
a transparent, keyboard-driven tool for local network supervision. NETWATCH NG
is the Python 3 rewrite of NETWATCH. The legacy Bash 1.x toolkit
(`netwatch.sh`, `netwatch-ipv6.sh`, `netwatch-router.sh`) remains in this
repository; this document describes NETWATCH NG.

## What it does

From the TUI you can:

- View active interfaces, the default gateway, and DNS settings (Dashboard).
- Discover devices passively (ARP/NDP) or with an operator-triggered Nmap scan
  of an authorized target or subnet (Devices).
- Identify devices using neighbor data, Nmap, and a local OUI vendor table.
  Every attribute stays labeled with its source and confidence level
  (Devices).
- Inspect the local default route and probe common management ports on the
  gateway (Router Intelligence).
- Run a read-only UPnP/SSDP query against the configured gateway only
  (Router Intelligence).
- Inventory Wi-Fi radios and survey access points with the Aircrack-ng suite
  (Wi-Fi Intelligence).
- Block or unblock a single IPv4/IPv6 address on the forwarding path, using
  NETWATCH-owned Netfilter rules (Firewall).
- Police egress/ingress traffic with `tc` — packets above the configured rate
  are dropped (Traffic Manager).
- Ping the gateway, trace a route, and look up DNS names (Network Diagnostics).
- Export the device inventory to JSON or CSV (Devices).
- Persist automatic refresh, Nmap timeout, preferred Wi-Fi interface, and
  color mode between runs (Settings).
- View a bounded activity log of operations (Logs).

## What it does not do

- It is not a full router-management stack: SNMP discovery and detailed
  vendor/model/firmware fingerprinting are not implemented.
- It does not shape traffic with smooth queues (HTB). Traffic control is
  packet policing: excess packets are dropped.
- It does not crack Wi-Fi keys, inject frames, or deauthenticate stations.
- It does not update itself automatically. The update check only reads the
  remote version and never runs downloaded code.
- Wi-Fi monitor mode is never enabled silently: it is an explicit action,
  requires root, interrupts the connection on that interface, and the
  interface carrying the default route is never forced into monitor mode.

## Requirements

- Linux, Python 3.10 or newer (standard library only; no third-party Python
  dependency).
- A terminal of at least 30 columns by 5 rows.

Optional system tools, detected when needed:

- `nmap` — active device discovery and service identification.
- `iproute2` (`ip`) — interface, route, and neighbor inspection.
- `iptables` / `ip6tables` — firewall control.
- `aircrack-ng` (`airmon-ng`, `airodump-ng`) — Wi-Fi inventory and survey
  (root required).
- `iw`, `rfkill` — Wi-Fi radio information.
- OpenSSH client — router bridge.

Missing optional tools are reported as unavailable; the features that depend on
them are not simulated.

## Installation

### Official APT repository (recommended)

NETWATCH NG is published as a signed Debian package on the official APT
repository at `https://sudomarc.github.io/NETWATCH/`.

The repository serves the `stable` suite, `main` component, for `amd64`, and
provides the `netwatch-ng` package (version 2.0.0-1). It is signed with
`InRelease` and `Release.gpg`, verifiable with the public key.

Add the repository and install:

```bash
curl -fsSL https://sudomarc.github.io/NETWATCH/public.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/netwatch-ng-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/netwatch-ng-archive-keyring.gpg] https://sudomarc.github.io/NETWATCH/ stable main" \
  | sudo tee /etc/apt/sources.list.d/netwatch-ng.list

sudo apt update
sudo apt install netwatch-ng
```

Then launch:

```bash
netwatch-ng
```

Run as a normal user for read-only inspection; use `sudo netwatch-ng` when you
need firewall, Wi-Fi, or traffic-control operations.

### From source

For development or contributing:

```bash
git clone https://github.com/sudomarc/NETWATCH.git
cd NETWATCH
python -m pip install -e .
python -m netwatch_ng
```

Or, without installing:

```bash
git clone https://github.com/sudomarc/NETWATCH.git
cd NETWATCH
PYTHONPATH=. python -m netwatch_ng
```

## Using the TUI

Start `netwatch-ng`. Move between screens with the arrow keys, open a screen
with Enter, and quit with `q`.

Each screen shows its own shortcuts at the bottom. Common ones:

| Screen | Shortcuts |
|--------|-----------|
| Devices | `n` discover, `v` Nmap service scan, `e` export JSON/CSV, `r` refresh |
| Router Intelligence | `p` probe management ports, `u` UPnP/SSDP scan, `r` refresh |
| Wi-Fi Intelligence | `s` survey access points, `m` monitor mode, `r` refresh |
| Firewall | `b` block IP, `u` unblock IP, `r` refresh |
| Traffic Manager | `l` set rate limit, `c` clear limit, `r` refresh |
| Network Diagnostics | `p` ping gateway, `t` trace route, `d` DNS lookup, `r` refresh |
| Settings | `+` / `-` refresh interval, `0` disable, `t` timeout, `i` interface, `c` color, `r` refresh |
| Reset Manager | `x` reset (confirmation required), `r` refresh |

Destructive actions (block, unblock, reset, traffic limit) always ask for
confirmation before changing anything.

## Runtime state

By default:

- unprivileged operations use `${XDG_CONFIG_HOME:-$HOME/.config}/netwatch-ng`;
- root operations use `/etc/netwatch-ng`.

`NETWATCH_NG_CONFIG` can override the location, but root operations refuse a
config directory that is not root-owned or is group/world-writable.

Runtime files include block state, scan logs, generated exports, and the
activity log. They are ignored by Git.

## More documentation

- [Signed APT repository guide](docs/apt-repository.md) — repository
  publication, GPG signing, and verification.
- [TUI design system](docs/NETWATCH_DESIGN_SYSTEM.md) — screen layout,
  semantics, and security UX rules.
- [netwatch-ng manual page](docs/netwatch-ng.1) — privileges, files, and
  optional tools.
- [CHANGELOG](CHANGELOG.md) — release history.
- [SECURITY](SECURITY.md) — authorized scope and responsible disclosure.
- [CONTRIBUTING](CONTRIBUTING.md) — how to contribute.

## License

MIT. See [LICENSE](LICENSE).
