# AGENTS.md

Read this file, `CONTRIBUTING.md`, `SECURITY.md`, and
`docs/ADR-001-python-rewrite.md` before making any change to this
repository.

## Two codebases, one repo

- `netwatch.sh`, `netwatch-ipv6.sh`, `netwatch-router.sh`, `ui/` —
  NETWATCH 1.x, Bash + a Python/curses TUI. Stable. Do not modify
  without a specific reason; its own test suite (`tests/`) must keep
  passing.
- `netwatch_ng/`, `tests_ng/` — NETWATCH NG 2.x, Python 3 rewrite, in
  progress across multiple sprints (see the project owner's NETWATCH
  NG brief for scope). This is where new feature work happens.

## Before changing code

1. `git status && git diff && git log --oneline -10`.
2. Read the file you're about to change in full.
3. Check whether a test already covers the behavior you're touching;
   if not, add one in the same change.
4. Do not assume a feature exists because it's mentioned in a README,
   a brief, or a comment — verify against the actual code.

## Rules that apply to every change

- Never claim a capability is implemented, fixed, or tested unless
  the code and a passing test prove it.
- Never build a shell command from unsanitized input; always pass
  argv as a list (`subprocess.run([...])`), never `shell=True`.
- Never silently swallow an error. A missing binary, a failed
  command, or an unreadable file is a reportable condition (see
  `netwatch_ng/core/shell.py`, `BinaryNotFound`), not something to
  catch-and-ignore.
- Never disable SSH host-key verification or use `StrictHostKeyChecking=no`.
- Never write a secret (token, password, key) into a tracked file.
- Firewall, IPv6, and traffic-shaping tests must use mocks; never run
  them against a real gateway or a production network.
- No placeholder screens, fake buttons, or simulated data in the TUI.
  A module that isn't implemented yet says so explicitly (see
  `netwatch_ng/tui/app.py`, `PLANNED` status) rather than pretending.

## Verification before committing

```bash
# NETWATCH NG (Python)
python3 -m py_compile $(find netwatch_ng -name "*.py")
python3 -m pytest tests_ng -v

# NETWATCH 1.x (Bash) — only if you touched it
bash -n netwatch.sh netwatch-ipv6.sh netwatch-router.sh
shellcheck netwatch.sh netwatch-ipv6.sh netwatch-router.sh
bash tests/test_validation.sh tests/test_output.sh tests/test_cli.sh tests/test_router.sh tests/test_tui.sh
```

## Git hygiene

Do not force-push, skip hooks, modify global/local Git config beyond
the author identity for this session, or create empty commits. Stage
only intended files. Write descriptive commit messages. Do not merge
`v2/python-rewrite` into `main` without the project owner's explicit
go-ahead.
