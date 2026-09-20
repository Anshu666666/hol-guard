"""Finite evidence for actual-hit observation; no callback replay."""

from __future__ import annotations

import re
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_regex import (
    RiskRegexWitness,
    observed_risk_regex_value,
    use_risk_regex_witness,
)


def _fixture(pattern: str = "[a-z]+") -> tuple[ModuleType, re.Pattern[str], RiskRegexWitness]:
    module = ModuleType("regex_fixture")
    compiled = re.compile(pattern)
    module.Pattern = re.Pattern
    module._cache2 = {(str, pattern, 0): compiled}
    return module, compiled, RiskRegexWitness(module, re.Pattern)


def test_actual_warm_entry_is_retained_by_identity_without_replaying_regex() -> None:
    module, compiled, witness = _fixture()
    calls: list[str] = []

    def selected(pattern: str, value: str) -> object:
        calls.append("regex")
        return compiled.search(value)

    with use_risk_regex_witness(witness):
        result = selected("[a-z]+", observed_risk_regex_value("search", module, "[a-z]+", "echo"))
        assert result is not None
        assert calls == ["regex"]
        assert witness.check()
    assert not witness.check()
    assert calls == ["regex"]


def test_same_pattern_label_cannot_substitute_another_actual_entry() -> None:
    module, _, witness = _fixture()
    witness.observe("search", module, "[a-z]+", "echo")
    # Independently compile equal label after purging the test's local cache.
    re.purge()
    replacement = re.compile("[a-z]+")
    module._cache2[(str, "[a-z]+", 0)] = replacement
    assert not witness.check()


@pytest.mark.parametrize(
    ("operation", "pattern", "value", "flags", "replacement"),
    [
        ("finditer", "[a-z]+", "echo", 0, None),
        ("sub", "[a-z]+", "echo", 0, r"\1"),
        ("search", "[a-z]+", "echo", re.MULTILINE, None),
        ("search", b"[a-z]+", b"echo", 0, None),
    ],
)
def test_unadmitted_actual_route_retires_without_executing_it(
    operation: str, pattern: object, value: object, flags: object, replacement: object,
) -> None:
    module, _, witness = _fixture()
    witness.observe(operation, module, pattern, value, flags=flags, replacement=replacement)
    assert not witness.check()


def test_missing_entry_is_not_warmed_or_repaired_by_observation() -> None:
    module, _, witness = _fixture()
    before = dict(module._cache2)
    witness.observe("search", module, "missing", "echo")
    assert not witness.check()
    assert module._cache2 == before


def test_literal_empty_replacement_and_real_findall_route_are_supported() -> None:
    module, _, witness = _fixture()
    witness.observe("sub", module, "[a-z]+", "echo", replacement="")
    witness.observe("findall", module, "[a-z]+", "echo")
    assert witness.check()


def test_opaque_unused_cache_key_is_refused_before_hash_or_equality() -> None:
    module, _, witness = _fixture()
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash((str, "[a-z]+", 0))

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    module._cache2[Key()] = object()
    events.clear()
    witness.observe("search", module, "[a-z]+", "echo")
    assert not witness.check()
    assert events == []


def test_unknown_module_key_is_refused_before_namespace_lookup() -> None:
    module, _, witness = _fixture()
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("_cache2")

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    module.__dict__[Key()] = object()
    events.clear()
    witness.observe("search", module, "[a-z]+", "echo")
    assert not witness.check()
    assert events == []


def test_nested_scopes_restore_outer_and_retire_inner() -> None:
    outer_module, _, outer = _fixture()
    inner_module, _, inner = _fixture()
    with use_risk_regex_witness(outer):
        with use_risk_regex_witness(inner):
            observed_risk_regex_value("search", inner_module, "[a-z]+", "echo")
            assert inner.check()
        assert not inner.check()
        observed_risk_regex_value("search", outer_module, "[a-z]+", "echo")
        assert outer.check()
    assert not outer.check()


def test_actual_ignorecase_member_uses_the_observed_integer_key() -> None:
    module, _, witness = _fixture()
    module.RegexFlag = re.RegexFlag
    module.IGNORECASE = re.IGNORECASE
    compiled = re.compile("[a-z]+", re.IGNORECASE)
    module._cache2[(str, "[a-z]+", 2)] = compiled
    witness.observe("search", module, "[a-z]+", "Echo", flags=re.IGNORECASE)
    assert witness.check()
    del module._cache2[(str, "[a-z]+", 2)]
    assert not witness.check()


def test_flag_object_is_not_converted_or_compared() -> None:
    module, _, witness = _fixture()
    events: list[str] = []

    class Flags:
        def __int__(self) -> int:
            events.append("int")
            return 2

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    witness.observe("search", module, "[a-z]+", "echo", flags=Flags())
    assert not witness.check()
    assert events == []
