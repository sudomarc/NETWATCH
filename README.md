# NETWATCH

NETWATCH is a Linux-only Bash toolkit for network discovery and controlled gateway administration on systems and networks you are authorized to manage.

## NETWATCH NG (2.x development)

NETWATCH NG is the Python 3 rewrite and uses an exclusively terminal-based
TUI. Launch from a source checkout with `python -m netwatch_ng`; the
Debian package build is validated in GitHub Actions for Debian 12 and 13,
but no public APT repository or stable 2.0.0 release is available yet.

Current NG capabilities:
- Dashboard and Linux interface/gateway/DNS inspection.
- Passive ARP/NDP discovery and operator-triggered Nmap host discovery from
  the Devices screen. Nmap scans run only after the operator enters a target
  or subnet; they are not launched automatically.
- Evidence-based device identification using neighbor data, Nmap and a
  local OUI table. Vendor/hostname evidence remains labelled with its source
  and confidence.
- Router inspection based on the local default route, neighbor MAC/OUI hints
  and reachability checks for common management TCP ports. A manual,
  read-only UPnP/SSDP query is restricted to the configured gateway; an HTTP
  device description is fetched only from that same literal IP. SNMP and
  deeper vendor/model/firmware fingerprinting are not implemented.
- Wi-Fi radio inventory and operator-triggered access-point survey through
  the Aircrack-ng suite (`airmon-ng` for interfaces and monitor mode,
  `airodump-ng` for the survey). Monitor mode is an explicit operator action
  requiring root privileges; it can interrupt the active Wi-Fi connection.
  The survey refuses to force the adapter that carries the default route into
  monitor mode, so a survey never silently drops the machine's connectivity;
  an interface already in monitor mode is used when available. When the TUI
  itself put an adapter into monitor mode it restores it on exit.
  `airmon-ng check kill` is never run automatically. Key cracking, frame
  injection and station deauthentication are not implemented.
- IPv4/IPv6 single-IP block/unblock through NETWATCH-owned iptables rules on
  the FORWARD chain. This affects forwarded traffic only; it is not a
  universal way to block a device on the same LAN.
- Traffic rate policing through `tc` clsact filters for egress and ingress.
  This is packet policing: packets above the configured rate are dropped.
  It is not smooth queue-based HTB shaping. The root qdisc is not replaced.
- Reset Manager read-only preview and explicit confirmation before reset.
- Diagnostics for gateway ping, DNS lookup and route trace.
- Persisted Settings for automatic refresh, Nmap timeout, preferred Wi-Fi
  interface and terminal color mode, plus a bounded JSONL activity log.
- Device inventory export to JSON/CSV and router read-only UPnP/SSDP lookup.

Optional tools are detected at runtime. Capabilities that depend on missing
tools are reported as unavailable. OUI matches and advertised Wi-Fi security
are hints, not verified device/model/security claims.

Not implemented in NG yet: SNMP router discovery and a full vendor/model/firmware
fingerprinting stack, Aircrack-ng audit workflows, detailed packet analysis,
rich device detail/search/filter views, broader advanced Settings controls,
and a public APT repository deployment. The signed APT publication workflow
and owner setup guide are prepared in [docs/apt-repository.md](docs/apt-repository.md).
There is no stable 2.0.0 release yet. The legacy 1.x capability table below
describes the Bash toolkit, not the Python rewrite.

## Current version

**1.3.1** (stabilization branch; the published `v1.3.0` release is historical).

The main script is the authoritative software-version source used by the update checker.

## Supported surface

| Capability | Status | Notes |
|---|---|---|
| IPv4 scan | Implemented | Nmap host discovery plus Linux neighbor table |
| IPv4 identify | Implemented | Nmap service/OS detection; strict IPv4 or MAC target validation |
| IPv4 block | Implemented | Linux gateway/router only; Netfilter chain is ownership-marked |
| IPv4 unblock | Implemented | Idempotent and ownership-aware |
| IPv4 monitor | Implemented | Refreshing scan |
| CSV/JSON export | Implemented | Machine-readable output is kept separate from diagnostics |
| Dry-run | Implemented | No firewall, QoS, ARP, or persistent-state writes |
| Persistent IPv4 firewall state | Optional | Requires `iptables-save` and `/etc/iptables` write access |
| ARP spoof assistance | Optional | Uses `arpspoof` only when installed; PID ownership is checked before termination |
| IPv6 scan | Implemented | On-link Linux IPv6 neighbor discovery |
| IPv6 identify | Implemented | Nmap IPv6 mode with strict validation |
| IPv6 block/unblock | Implemented | Linux IPv6 gateway/router only; ownership-marked chain |
| IPv6 reset | Implemented | Removes only state recorded by NETWATCH and only from an owned chain |
| Throttle/unthrottle | **Unavailable** | QoS is intentionally disabled until a safe `tc` design is implemented |
| Router SSH bridge | Implemented | Vendor-neutral; explicit host-key verification |
| Automatic self-update | **Disabled** | `update` only checks the remote version and never executes downloaded code |

## Requirements

Core commands need only the tools required by that command.

For scanning: Bash, `nmap`, `ip`, `awk`, `mktemp`.

For identification: Bash, `nmap`, `ip`, `awk`, `python3`.

For IPv4 firewall control: Bash, `iptables`, `ip`, `awk`, `python3`. `arpspoof` and `arping` are optional.

For IPv6 control: Bash, `ip`, `ip6tables`, `awk`, `python3`; `nmap` is needed for identification.

For the router bridge: OpenSSH client.

For NETWATCH NG Wi-Fi (airmon-ng / airodump-ng): the `aircrack-ng` system
package (provides `airmon-ng` and `airodump-ng`). Monitor mode and the survey
require root privileges; `aircrack-ng` is a system executable detected at
runtime, not a Python dependency.

Debian/Ubuntu example:

```bash
sudo apt install bash nmap iproute2 iptables python3 openssh-client
# Optional ARP support:
sudo apt install dsniff iputils-arping
```

## Installation

```bash
git clone https://github.com/sudomarc/NETWATCH.git
cd NETWATCH
chmod +x netwatch.sh netwatch-ipv6.sh netwatch-router.sh
```

No installer script is required.

## IPv4 usage

```bash
sudo ./netwatch.sh scan
sudo ./netwatch.sh scan json
sudo ./netwatch.sh scan csv

sudo ./netwatch.sh identify 192.168.1.42
sudo ./netwatch.sh identify AA:BB:CC:DD:EE:FF

sudo ./netwatch.sh --dry-run block 192.168.1.42
sudo ./netwatch.sh block 192.168.1.42
sudo ./netwatch.sh unblock 192.168.1.42

sudo ./netwatch.sh monitor 10
sudo ./netwatch.sh export json
sudo ./netwatch.sh list
sudo ./netwatch.sh reset
```

Blocking is valid only when the Linux host is actually forwarding IPv4 traffic. The default gateway itself is never an allowed target.

`block` and `unblock` use the dedicated `NETWATCH_BLOCK` chain only when that chain is explicitly marked as NETWATCH-owned. An unrelated pre-existing chain with the same name is rejected rather than modified.

## IPv6 usage

```bash
sudo ./netwatch-ipv6.sh scan
sudo ./netwatch-ipv6.sh scan json
sudo ./netwatch-ipv6.sh scan csv

sudo ./netwatch-ipv6.sh identify 2001:db8::10
sudo ./netwatch-ipv6.sh --dry-run block 2001:db8::10
sudo ./netwatch-ipv6.sh block 2001:db8::10
sudo ./netwatch-ipv6.sh unblock 2001:db8::10
sudo ./netwatch-ipv6.sh reset
```

IPv6 discovery reads the Linux neighbor table after stimulating on-link neighbor discovery when `ping` is available. It does not brute-force an IPv6 `/64`.

IPv6 blocking requires forwarding and refuses to block the configured default IPv6 gateway.

## Dry-run contract

`--dry-run` guarantees that control commands do not:

- modify `iptables` or `ip6tables`;
- modify `tc`;
- create ARP spoofing processes;
- modify persistent firewall files;
- modify NETWATCH state files.

The command still performs read-only validation and network-state discovery needed to describe what would happen.

## Persistence

`--persistent` applies to IPv4 firewall control. On successful block/unblock, NETWATCH writes an `iptables-save` snapshot to:

```text
/etc/iptables/rules.v4
```

This does not guarantee boot-time restoration on every distribution; a distribution-specific firewall restore service/package may still be required.

A persistence failure is reported as a failure. NETWATCH does not silently claim that persistence succeeded.

## Runtime state

By default:

- unprivileged operations use `${XDG_CONFIG_HOME:-$HOME/.config}/netwatch`;
- root control operations use `/etc/netwatch`.

`NETWATCH_CONFIG` can override the location, but root operations refuse non-root-owned or group/world-writable configuration directories.

Runtime files include block state, scan logs, generated exports, and ARP-spoof PID files. They are ignored by Git.

## Router bridge

The router bridge does not guess a vendor CLI.

```bash
export NETWATCH_ROUTER_HOST=192.168.1.1
export NETWATCH_ROUTER_USER=admin
export NETWATCH_ROUTER_PORT=22
export NETWATCH_ROUTER_KEY="$HOME/.ssh/router_ed25519"

./netwatch-router.sh check
./netwatch-router.sh exec show ipv6 interface
./netwatch-router.sh apply ./router-config.sh
```

Security properties:

- `BatchMode=yes`;
- explicit `StrictHostKeyChecking=yes`;
- connection timeout and server-alive limits;
- no `eval`;
- no `StrictHostKeyChecking=no`;
- no `/dev/null` `known_hosts` override.

The router command/script remains an administrator-supplied remote operation. Do not point it at systems you are not authorized to administer.

## Testing

Run locally:

```bash
bash -n netwatch.sh
bash -n netwatch-ipv6.sh
bash -n netwatch-router.sh

command -v shellcheck && shellcheck netwatch.sh netwatch-ipv6.sh netwatch-router.sh

bash tests/test_validation.sh
bash tests/test_output.sh
bash tests/test_cli.sh
bash tests/test_firewall.sh
bash tests/test_ipv6.sh
bash tests/test_router.sh
```

The firewall and IPv6 tests use mocks. They do not require a real gateway or a real firewall configuration.

NETWATCH NG (Python 3) tests:

```bash
python -m pip install -e . pytest
python -m pytest tests_ng -v
python -m pytest tests_e2e -v
```

The NG E2E suite launches the actual TUI in a pseudo-terminal with a hermetic fake command `PATH`. Firewall mutation commands are rejected by the test doubles; no real network scan or firewall change is performed.

## Security

See [SECURITY.md](SECURITY.md). Network-control operations are intended only for systems and networks you own or are explicitly authorized to administer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
