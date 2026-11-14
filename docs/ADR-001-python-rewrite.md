# ADR-001: Rewrite NETWATCH as NETWATCH NG in Python 3

## Status

Accepted (2026-11-14). Supersedes the "do not rewrite NETWATCH in another
language" rule in the pre-2.0 `CONTRIBUTING.md`.

## Context

NETWATCH 1.x is a Bash toolkit (`netwatch.sh`, `netwatch-ipv6.sh`,
`netwatch-router.sh`) plus a standalone Python/curses TUI
(`ui/netwatch_tui.py`) that shells out to the Bash scripts. It is
well-tested for what it does (scan, identify, IPv4/IPv6 block/unblock,
SSH router bridge) but:

- has no Wi-Fi intelligence, router fingerprinting beyond the SSH
  bridge, or working traffic shaping (QoS is explicitly disabled);
- has no Debian packaging or APT distribution story;
- mixes two languages across a shell boundary, which makes a unified
  TUI, a single dependency-detection model, and a single test harness
  harder to maintain as the feature set grows to the full NETWATCH NG
  scope (device/router intelligence, Wi-Fi, firewall, traffic, reset,
  diagnostics, settings, logs).

## Decision

NETWATCH NG's engine and TUI are rewritten in Python 3 (stdlib +
`curses`), replacing the Bash scripts. The Bash toolkit remains on
`main` as the 1.x line; the rewrite happens on `v2/python-rewrite`
and ships as a new major version once it reaches parity plus the new
modules described in the NETWATCH NG brief.

This decision was made explicitly by the project owner, overriding
the prior CONTRIBUTING.md language constraint, because the long-term
maintenance and feature-surface benefits of one language and one
process model outweigh the cost of losing the existing Bash
implementation's test history.

## Consequences

- `CONTRIBUTING.md` is updated to reflect Python 3 as the implementation
  language for 2.x and to carry forward the Bash project's engineering
  priorities (correctness, security, simplicity, maintainability) and
  its explicit security rules (no shell injection, no silent error
  swallowing, strict SSH host-key checking, etc.), restated for Python.
- The existing Bash test suite (`tests/`) and the Bash scripts stay in
  the repository, unmodified, as the 1.x reference implementation,
  until NETWATCH NG reaches feature parity and the project owner
  decides to retire them.
- New code lives under `netwatch_ng/` with its own test suite
  (`tests_ng/`) and its own CI job, additive to the existing `ci.yml`
  and `tui.yml` workflows (which continue to validate the 1.x Bash
  code and the legacy `ui/netwatch_tui.py` unchanged).
