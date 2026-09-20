"""Finite fixed-provider and actual-hit controls for the private pair."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_regex_providers import check_risk_regex_providers
from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations


@pytest.fixture
def declarations() -> dict[str, SourceDeclarations]:
    import enum

    result: dict[str, SourceDeclarations] = {}
    for module in (re, enum):
        source = Path(module.__file__).read_bytes()
        result[module.__name__] = SourceDeclarations(
            module.__name__, source, hashlib.sha256(source).hexdigest()
        )
    return result


def test_stock_reached_regex_providers_are_supported(declarations: dict[str, SourceDeclarations]) -> None:
    assert check_risk_regex_providers(declarations)


@pytest.mark.parametrize("name", ["search", "findall", "sub", "_compile", "escape"])
def test_opaque_reached_regex_provider_is_not_invoked(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations], name: str,
) -> None:
    calls: list[str] = []

    def replacement(*_args: object, **_kwargs: object) -> object:
        calls.append(name)
        raise AssertionError("admission executed a provider")

    monkeypatch.setattr(re, name, replacement)
    assert not check_risk_regex_providers(declarations)
    assert calls == []


@pytest.mark.parametrize("name", ["type", "str", "isinstance", "chr"])
def test_reached_builtin_shadow_is_refused_without_call(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations], name: str,
) -> None:
    calls: list[str] = []

    def replacement(*_args: object, **_kwargs: object) -> object:
        calls.append(name)
        raise AssertionError("admission executed a shadow")

    monkeypatch.setattr(re, name, replacement, raising=False)
    assert not check_risk_regex_providers(declarations)
    assert calls == []


def test_regex_literal_default_change_is_refused(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations],
) -> None:
    monkeypatch.setattr(re.search, "__defaults__", (2,))
    assert not check_risk_regex_providers(declarations)


def test_escape_map_semantic_change_is_refused(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations],
) -> None:
    altered = dict(vars(re)["_special_chars_map"])
    altered[ord(".")] = "different"
    monkeypatch.setattr(re, "_special_chars_map", altered)
    assert not check_risk_regex_providers(declarations)


def test_opaque_module_key_is_refused_before_comparison(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations],
) -> None:
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("search")

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    key = Key()
    re.__dict__[key] = object()
    events.clear()
    try:
        assert not check_risk_regex_providers(declarations)
        assert events == []
    finally:
        del re.__dict__[key]


def test_enum_value_descriptor_override_is_refused_before_getter(
    declarations: dict[str, SourceDeclarations],
) -> None:
    events: list[str] = []

    def value(_self: object) -> int:
        events.append("value")
        return 2

    type.__setattr__(re.RegexFlag, "value", property(value))
    try:
        assert not check_risk_regex_providers(declarations)
        assert events == []
    finally:
        type.__delattr__(re.RegexFlag, "value")


def test_enum_member_value_descriptor_override_is_refused(
    declarations: dict[str, SourceDeclarations],
) -> None:
    events: list[str] = []

    def dictionary(_self: object) -> int:
        events.append("dictionary")
        return 2

    type.__setattr__(re.RegexFlag, "_value_", property(dictionary))
    try:
        assert not check_risk_regex_providers(declarations)
        assert events == []
    finally:
        type.__delattr__(re.RegexFlag, "_value_")


def test_mutable_pattern_impostor_is_refused_before_opaque_metadata(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations],
) -> None:
    events: list[str] = []

    class Label:
        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            raise AssertionError("opaque module label compared")

    class Pattern:
        pass

    monkeypatch.setattr(Pattern, "__module__", Label())
    monkeypatch.setattr(re, "Pattern", Pattern)
    assert not check_risk_regex_providers(declarations)
    assert events == []
