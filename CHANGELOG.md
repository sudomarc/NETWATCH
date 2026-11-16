# Changelog

## Unreleased

### Bug fixes

- fixed invalid JSON output from `netwatch.sh scan json`: the double-quote
  escaper used a pattern that stripped the quotes instead of escaping them, so
  any hostname or vendor containing `"` produced unparseable JSON. `csv` was
  unaffected;
- fixed `tests/test_output.sh` so a JSON/CSV parse failure actually fails the
  test instead of printing a traceback and exiting 0;
- fixed the Wi-Fi survey dropping the active connection: `scan_networks()` now
  refuses to force the interface that carries the default route into monitor
  mode, `scan_available_networks()` prefers an interface already in monitor
  mode, and the TUI restores any monitor interface it created when it exits;
- fixed `_read_latest_airodump_csv()` selecting the wrong capture file by name
  (it now uses modification time, so `scan-10.csv` is no longer treated as
  older than `scan-2.csv`).

### Housekeeping

- removed unused imports and placeholder-less f-strings flagged by the linters.

## 1.3.1

Stabilization release under active development.

### Correctness and security

- corrected the canonical repository URL;
- made `1.3.1` the authoritative script version;
- replaced weak IPv4 validation with `ipaddress`;
- fixed machine-readable JSON/CSV output;
- made scan diagnostics go to stderr;
- added ownership markers for IPv4 and IPv6 Netfilter chains;
- added IPv4 firewall rollback on partial rule failure;
- made block/unblock state updates occur only after successful firewall application;
- hardened ARP-spoof PID termination checks;
- made IPv4 persistence failures explicit;
- hardened router host/user/port/key validation and SSH host-key verification;
- stopped update-check failures from returning success;
- kept automatic self-update disabled;
- explicitly marked QoS throttling unavailable instead of advertising an unimplemented feature;
- implemented ownership-aware IPv4 and IPv6 reset behavior.

### Tests and CI

- added validation, CLI, output, firewall, IPv6, and router regression tests;
- added mocked destructive-system command testing;
- added GitHub Actions syntax, ShellCheck, and test execution.

### Known repository limitation

The published GitHub release `v1.3.0` predates these corrections and cannot be rewritten through the current repository automation interface. Its release notes should therefore be treated as historical until the next release is published.
