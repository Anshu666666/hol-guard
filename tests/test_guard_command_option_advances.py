"""Deterministic option consumption preserves conservative command matching."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import command_option_parsing as options

_VALUE_OPTIONS = frozenset({"--config", "--profile", "-c", "-p"})
_FLAGS = frozenset({"--verbose", "--dry-run", "-v", "-n"})


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        ("", None),
        ("-", None),
        ("literal", None),
        ("--", None),
        ("--config", 2),
        ("--config=", 1),
        ("--config=value", 1),
        ("--verbose", 1),
        ("--verbose=false", 1),
        ("--verbose=unknown", 1),
        ("--future", None),
        ("--future=value", 1),
        ("--=value", 1),
        ("-v", 1),
        ("-vn", 1),
        ("-vvn", 1),
        ("-c", 2),
        ("-cvalue", 1),
        ("-vc", 2),
        ("-vcvalue", 1),
        ("-cv", 1),
        ("-x", None),
        ("-vx", None),
        ("-xv", None),
        ("-xcvalue", None),
    ],
)
def test_known_option_token_consumption(argument: str, expected: int | None) -> None:
    assert options.known_option_advance(argument, options_with_values=_VALUE_OPTIONS, known_flags=_FLAGS) == expected


@pytest.mark.parametrize("argument", ["--config", "-c", "-vc"])
def test_value_option_takes_precedence_over_a_conflicting_flag_declaration(argument: str) -> None:
    assert (
        options.known_option_advance(argument, options_with_values=_VALUE_OPTIONS, known_flags=_FLAGS | _VALUE_OPTIONS)
        == 2
    )


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (("list", "purge"), False),
        (("", "purge"), False),
        (("purge", "archive"), True),
        (("--", "purge", "archive"), True),
        (("--", "list", "purge"), False),
        (("--config", "purge", "list"), False),
        (("--config", "value", "purge"), True),
        (("--config=value", "purge"), True),
        (("--future", "value", "purge"), True),
        (("--future", "purge"), True),
        (("--future=value", "list", "purge"), False),
        (("-vc", "value", "purge"), True),
        (("-vc", "purge", "list"), False),
        (("-xc", "purge"), True),
        (("$(printf list)", "purge"), False),
    ],
)
def test_literal_mismatch_and_ambiguous_options_keep_their_decisions(
    arguments: tuple[str, ...], expected: bool
) -> None:
    assert (
        options.matches_subcommands_conservatively(
            arguments, ("purge",), options_with_values=_VALUE_OPTIONS, known_flags=_FLAGS
        )
        is expected
    )


@pytest.mark.parametrize("arguments", [("list",), ("--future", "purge"), ()])
def test_exhausted_parse_budget_remains_uncertain(monkeypatch: pytest.MonkeyPatch, arguments: tuple[str, ...]) -> None:
    monkeypatch.setattr(options, "_MAX_OPTION_PARSE_STATES", 0)
    assert options.matches_subcommands_conservatively(
        arguments, ("purge",), options_with_values=_VALUE_OPTIONS, known_flags=_FLAGS
    )


def test_reaching_parse_budget_after_an_option_remains_uncertain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(options, "_MAX_OPTION_PARSE_STATES", 1)
    assert options.matches_subcommands_conservatively(
        ("--future=value", "list"), ("purge",), options_with_values=_VALUE_OPTIONS, known_flags=_FLAGS
    )
