#!/usr/bin/env bash
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

python3 -m py_compile "$ROOT/ui/netwatch_tui.py" || { echo 'FAIL TUI Python syntax'; exit 1; }
grep -q 'NETWATCH' "$ROOT/ui/netwatch_tui.py" || { echo 'FAIL TUI identity'; exit 1; }
grep -q 'NETWATCH-owned' "$ROOT/ui/netwatch_tui.py" || { echo 'FAIL ownership wording'; exit 1; }
grep -q 'Enter Confirm' "$ROOT/ui/netwatch_tui.py" || { echo 'FAIL confirmation UX'; exit 1; }
grep -q 'NO DEVICES DISCOVERED' "$ROOT/ui/netwatch_tui.py" || { echo 'FAIL empty state'; exit 1; }
grep -q 'StrictHostKeyChecking=yes' "$ROOT/netwatch-router.sh" || { echo 'FAIL router verification policy'; exit 1; }

# Regression: the search filter must capture the operator's keystrokes itself.
# wgetstr() with the interactive timeout(250) active returns an empty string
# immediately, so those keystrokes used to reach handle_key(), where digits
# switch modes and b/u/i trigger device actions instead of filtering.
grep -q '\.getstr(' "$ROOT/ui/netwatch_tui.py" && { echo 'FAIL TUI search still calls getstr()'; exit 1; }
grep -q 'def search_prompt' "$ROOT/ui/netwatch_tui.py" || { echo 'FAIL TUI search prompt missing'; exit 1; }

python3 - "$ROOT/ui/netwatch_tui.py" <<'PY' || exit 1
"""Behavioural test: search_prompt must own its keys."""
import importlib.util
import sys

import curses


class FakeScreen:
    """Minimal stand-in for a curses screen: scripted keys, recorded draws."""

    def __init__(self, keys):
        self._keys = list(keys)
        self.drawn = []

    def getmaxyx(self):
        return 40, 120

    def getch(self):
        return self._keys.pop(0) if self._keys else -1

    def refresh(self):
        pass

    def addnstr(self, y, x, text, *args, **kwargs):
        self.drawn.append((y, x, str(text)))


# The prompt only needs colour/cursor helpers that require a real terminal.
_real_color_pair = curses.color_pair
_real_curs_set = curses.curs_set
curses.color_pair = lambda n: n
curses.curs_set = lambda n: None


spec = importlib.util.spec_from_file_location("netwatch_tui_under_test", sys.argv[1])
module = importlib.util.module_from_spec(spec)
# dataclasses with postponed annotations look the module up in sys.modules.
sys.modules["netwatch_tui_under_test"] = module
spec.loader.exec_module(module)


class UIStub(module.UI):
    """UI without __init__: we only exercise search_prompt."""

    def __init__(self, keys):
        self.stdscr = FakeScreen(keys)
        self.search = ""
        self.selected = 0
        self.mode = "DEVICES"


def typed(text):
    # printable characters, then Enter
    return [ord(ch) for ch in text] + [10]


# 1. typing a filter and pressing Enter applies exactly that filter.
ui = UIStub(typed("192.168.1.42"))
ui.search_prompt()
assert ui.search == "192.168.1.42", f"filter not captured: {ui.search!r}"
assert ui.mode == "DEVICES", ui.mode
assert ui.selected == 0, ui.selected

# 2. Escape cancels without changing the current filter.
ui = UIStub([ord("1"), ord("9"), 27])
ui.search = "192.168.1.42"
ui.search_prompt()
assert ui.search == "192.168.1.42", f"Esc changed the filter: {ui.search!r}"

# 3. Backspace edits the filter (retype the last character after deleting it).
keys = [ord(c) for c in "192.168.1.42"] + [curses.KEY_BACKSPACE, ord("2"), 10]
ui = UIStub(keys)
ui.search_prompt()
assert ui.search == "192.168.1.42", f"backspace editing failed: {ui.search!r}"

# 4. Every keypress is consumed by the prompt, never left for the dispatcher.
#    Typing b/u/i here must NOT reach handle_key(), where they would launch
#    block/unblock/identify on the selected device.
ui = UIStub([ord("b"), ord("u"), ord("i"), 10])
ui.search_prompt()
assert ui.stdscr._keys == [], f"keys leaked to the dispatcher: {ui.stdscr._keys!r}"
assert ui.search == "bui", f"unexpected search value: {ui.search!r}"

# 5. Enter with no edit keeps the current filter (no accidental change).
ui = UIStub([10])
ui.search = "192.168.1.42"
ui.search_prompt()
assert ui.search == "192.168.1.42", f"Enter must not clear the filter: {ui.search!r}"

# 6. Backspacing everything then Enter clears the filter.
ui = UIStub([curses.KEY_BACKSPACE] * 13 + [10])
ui.search = "192.168.1.42"
ui.search_prompt()
assert ui.search == "", f"backspace-all must clear the filter: {ui.search!r}"

curses.color_pair = _real_color_pair
curses.curs_set = _real_curs_set
print("PASS search prompt owns its keys and never leaks to the dispatcher")
PY

echo 'PASS TUI syntax and UX regression checks'
