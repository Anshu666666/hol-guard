"""Compare actual pre-repair parser behavior and preserve its public live helper seam."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
import sys
import types

import pytest

from codex_plugin_scanner.guard.runtime import shell_structure as current

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
BASELINE_BYTES = (HERE / "baseline_shell_structure.py.txt").read_bytes()
assert hashlib.sha256(BASELINE_BYTES).hexdigest() == CONFIG["heredoc_baseline"]["sha256"]
ORIGINAL = types.ModuleType("_pr2974_original_shell_structure")
ORIGINAL.__file__ = str(HERE / "baseline_shell_structure.py.txt")
sys.modules[ORIGINAL.__name__] = ORIGINAL
exec(compile(BASELINE_BYTES, ORIGINAL.__file__, "exec"), ORIGINAL.__dict__)

NO_OPERATOR_CASES = (
    "",
    "printf hello",
    "printf '%s' 'quoted < text'",
    'printf "%s" "double quoted > text"',
    r"printf escaped\ space",
    "printf 'unterminated",
    "printf λ",
    "x" * 1024,
)
OPERATOR_CASES = (
    "cat <<EOF\nbody\nEOF\n",
    "cat <<'EOF'\n$literal\nEOF\n",
    'cat <<"EOF"\n$literal\nEOF\n',
    "cat <<-EOF\n\tbody\n\tEOF\n",
    "cat <<ONE <<TWO\nfirst\nONE\nsecond\nTWO\n",
    "cat <<EOF\nmissing closing line\n",
    "cat <<EOF",
    "printf '<<EOF'\ntext\n",
    'printf "<<EOF"\ntext\n',
    r"printf \<<EOF" + "\ntext\n",
    "cat <<< value\n",
    "printf $(echo '<<EOF')\n",
    "printf \x60echo '<<EOF'\x60\n",
    "cat <<--END\nbody\n--END\n",
    "printf before\ncat <<EOF\nbody\nEOF\nprintf after\n",
)


def declarations(module, line):
    matches = module._heredoc_declarations(line)
    assert isinstance(matches, tuple)
    return tuple((match.span(), match.groupdict()) for match in matches)


def observation(module, command):
    values = module.extract_heredocs(command)
    assert isinstance(values, tuple)
    assert all(type(item) is module.ShellHeredoc for item in values)
    return {
        "values": [dataclasses.asdict(item) for item in values],
        "masked_bodies": module.mask_heredoc_bodies(command, values),
        "masked_complete": module.mask_complete_heredocs(command, values),
    }


@pytest.mark.parametrize("command", NO_OPERATOR_CASES, ids=lambda value: "empty" if not value else str(len(value)))
def test_no_operator_preserves_empty_declarations_and_source_text(command):
    assert declarations(current, command) == declarations(ORIGINAL, command) == ()
    assert observation(current, command) == observation(ORIGINAL, command)
    assert current.mask_complete_heredocs(command, ()) == command


@pytest.mark.parametrize("command", OPERATOR_CASES, ids=[f"operator-{index:02d}" for index in range(15)])
def test_possible_operators_preserve_original_matches_spans_and_body_text(command):
    first_line = command.split("\n", 1)[0]
    assert declarations(current, first_line) == declarations(ORIGINAL, first_line)
    assert observation(current, command) == observation(ORIGINAL, command)


@pytest.mark.parametrize("value", ["printf plain", "cat <<EOF"], ids=["without-operator", "with-operator"])
def test_str_subclass_keeps_original_scanner_protocol(value):
    events = []

    class ObservedStr(str):
        def __contains__(self, key):
            raise AssertionError("Do not introduce a str-subclass containment call")

        def startswith(self, *args):
            events.append(args)
            return super().startswith(*args)

    expected = declarations(ORIGINAL, ObservedStr(value))
    original_events = list(events)
    events.clear()
    actual = declarations(current, ObservedStr(value))
    assert actual == expected
    assert events == original_events and events


@pytest.mark.parametrize("command", ["printf first", "printf first\nprintf second\n"], ids=["one-line", "two-lines"])
def test_saved_public_callable_still_uses_current_private_helper(command, monkeypatch):
    saved_public = current.extract_heredocs
    calls = []

    def replacement(line):
        calls.append(line)
        return ()

    monkeypatch.setattr(current, "_heredoc_declarations", replacement)
    assert saved_public(command) == ()
    assert calls == command.splitlines()
