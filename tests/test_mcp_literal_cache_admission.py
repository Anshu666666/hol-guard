"""Data-admission controls; these do not admit transitive callable providers."""

from __future__ import annotations

import re
import weakref
from collections import OrderedDict
from dataclasses import dataclass
from typing import cast

import pytest

from codex_plugin_scanner.guard.mcp_literal_cache_admission import literal_cache_is_canonical
from codex_plugin_scanner.guard.mcp_literal_pattern_cache import StringLiteralCache


@dataclass(frozen=True)
class _Pattern:
    literals: tuple[str, ...]
    expression: str


def _factory(*tokens: str, prefix: str = "", suffix: str = "") -> _Pattern:
    return _Pattern(tokens or ("",), prefix + "(" + "|".join(re.escape(token) for token in tokens) + ")" + suffix)


def test_all_plain_cached_entries_match_their_complete_ordered_key() -> None:
    cache = StringLiteralCache(_factory, 128)
    for tokens in ((), ("curl", "wget"), ("()[]{}?*+-|^$\\.&~# \t\n\r\v\f",), ("café", "\udcff")):
        cache(*tokens)
        cache(*tokens, prefix=r"(?<![a-z0-9])", suffix=r"(?![a-z0-9])")
        cache(*tokens, suffix="", prefix="")
    before = cache.snapshot()
    assert literal_cache_is_canonical(cache, _Pattern, _factory)
    assert cache.snapshot() == before


def test_ordinary_warm_lru_order_is_fully_visible_in_the_plain_dictionary() -> None:
    cache = StringLiteralCache(_factory, 128)
    for value in ("first", "second", "third"):
        cache(value)
    cache("first")
    assert tuple(cache.entries) == tuple(key for key, _ in cache.snapshot())
    assert tuple(key[0][0] for key in cache.entries) == ("second", "third", "first")
    assert literal_cache_is_canonical(cache, _Pattern, _factory)


@pytest.mark.parametrize("poison", ["opaque", "wrong_expression", "wrong_literals", "extra_field"])
def test_unused_or_mutated_values_are_refused_without_clearing(poison: str) -> None:
    cache = StringLiteralCache(_factory, 128)
    pattern = cast(_Pattern, cache("unused"))
    key = next(iter(cache.entries))
    if poison == "opaque":
        cache.entries[key] = object()
    elif poison == "wrong_expression":
        object.__setattr__(pattern, "expression", "(different)")
    elif poison == "wrong_literals":
        object.__setattr__(pattern, "literals", ("different",))
    else:
        object.__setattr__(pattern, "extra", object())
    before = tuple((key, id(value)) for key, value in cache.snapshot())
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)
    assert tuple((key, id(value)) for key, value in cache.snapshot()) == before


def test_unused_opaque_key_cannot_run_hash_equality_or_repr_during_inspection() -> None:
    calls: list[str] = []

    class Key:
        def __hash__(self) -> int:
            calls.append("hash")
            return 5

        def __eq__(self, other: object) -> bool:
            calls.append("equality")
            return False

        def __repr__(self) -> str:
            calls.append("repr")
            return "opaque"

    cache = StringLiteralCache(_factory, 128)
    dict.__setitem__(cache.entries, Key(), object())
    calls.clear()
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)
    assert calls == []


def test_weakref_callback_on_an_unused_exact_value_is_not_admitted_or_called() -> None:
    cache = StringLiteralCache(_factory, 128)
    value = cache("unused")
    calls: list[str] = []
    reference = weakref.ref(value, lambda _: calls.append("retired"))
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)
    assert reference() is value
    assert calls == []


def test_plain_but_semantically_impossible_keyword_key_is_refused() -> None:
    cache = StringLiteralCache(_factory, 128)
    value = cache("token")
    for keywords in ((("unknown", ""),), (("prefix", ""), ("prefix", ""))):
        cache.entries[(("token",), keywords)] = value
        assert not literal_cache_is_canonical(cache, _Pattern, _factory)
        del cache.entries[(("token",), keywords)]
    assert literal_cache_is_canonical(cache, _Pattern, _factory)


def test_raw_dict_insertion_remains_visible_for_semantic_validation() -> None:
    cache = StringLiteralCache(_factory, 128)
    cache("ordinary")
    dict.__setitem__(cache.entries, (("hidden",), ()), _factory("hidden"))
    assert literal_cache_is_canonical(cache, _Pattern, _factory)
    object.__setattr__(cache.entries[(("hidden",), ())], "expression", "wrong")
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)


def test_replaced_field_descriptor_is_refused_without_calling_it(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = StringLiteralCache(_factory, 128)
    cache("ordinary")

    def opaque(_self: object) -> str:
        raise AssertionError("replaced descriptor executed")

    monkeypatch.setattr(_Pattern, "expression", property(opaque), raising=False)
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)


@pytest.mark.parametrize("field", ["maxsize", "hits", "misses"])
def test_opaque_cache_bookkeeping_is_rejected_before_operators(field: str) -> None:
    class Opaque:
        def __lt__(self, other: object) -> bool:
            raise AssertionError("opaque ordering")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("opaque equality")

    cache = StringLiteralCache(_factory, 128)
    cache("ordinary")
    setattr(cache, field, Opaque())
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)


def test_factory_identity_and_bound_are_checked_without_calling_factory() -> None:
    cache = StringLiteralCache(_factory, 128)
    cache("ordinary")
    assert not literal_cache_is_canonical(cache, _Pattern, object())
    cache.maxsize = 127
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)


def test_stale_ordered_dictionary_node_is_rejected_without_key_callbacks() -> None:
    calls: list[str] = []

    class OpaqueKey:
        def __hash__(self) -> int:
            calls.append("hash")
            return 5

        def __eq__(self, other: object) -> bool:
            calls.append("equality")
            return False

    stale: OrderedDict[object, object] = OrderedDict()
    key = OpaqueKey()
    stale[key] = object()
    dict.__delitem__(stale, key)
    assert tuple(dict.items(stale)) == ()
    cache = StringLiteralCache(_factory, 128)
    cache.entries = cast(dict, stale)
    calls.clear()
    assert not literal_cache_is_canonical(cache, _Pattern, _factory)
    assert calls == []

def test_pattern_class_unknown_namespace_key_is_refused_without_comparison() -> None:
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("__getattribute__")

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    namespace = dict(vars(_Pattern))
    namespace.pop("__dict__")
    namespace.pop("__weakref__")
    namespace[Key()] = object()
    record_type = type("Pattern", (object,), namespace)
    record = record_type(("safe",), "(safe)")
    cache = StringLiteralCache(_factory, 128)
    cache.entries[(("safe",), ())] = record
    events.clear()
    assert not literal_cache_is_canonical(cache, record_type, _factory)
    assert events == []


@pytest.mark.parametrize(
    "name",
    ["__getattribute__", "__getattr__", "__setattr__", "__delattr__", "__del__"],
)
def test_cache_class_callback_slots_refuse_without_calling_them(
    monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    cache = StringLiteralCache(_factory, 128)
    cache("curl")
    events: list[str] = []

    def opaque(*_args: object) -> object:
        events.append(name)
        raise AssertionError("cache callback ran during refusal")

    with monkeypatch.context() as patch:
        patch.setattr(StringLiteralCache, name, opaque, raising=False)
        assert not literal_cache_is_canonical(cache, _Pattern, _factory)
        assert events == []
    assert literal_cache_is_canonical(cache, _Pattern, _factory)
