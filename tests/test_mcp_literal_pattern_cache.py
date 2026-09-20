"""Finite cache behavior and inspection controls, without performance claims."""

from __future__ import annotations

import gc
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from threading import Barrier
from typing import cast

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.mcp_literal_pattern_cache import StringLiteralCache, string_literal_lru


def test_plain_call_keys_counts_order_and_eviction_match_stdlib():
    def run(decorator):
        made = []

        @decorator
        def factory(*args, **kwargs):
            result = (len(made), args, tuple(kwargs.items()))
            made.append(result)
            return result

        first = factory("a")
        assert factory("a") is first
        factory("a", prefix="", suffix="")
        factory("a", suffix="", prefix="")
        factory("b")
        # Touching one key must make the other oldest key the eviction victim.
        factory("a", prefix="", suffix="")
        factory("c")
        result = factory("a", suffix="", prefix="")
        return made, result, tuple(getattr(factory, "cache_info")()), getattr(factory, "cache_parameters")()

    assert run(string_literal_lru(maxsize=3)) == run(lru_cache(maxsize=3))


def test_exact_128_bound_and_oldest_eviction():
    @string_literal_lru(maxsize=128)
    def factory(value):
        return object()

    first = factory("0")
    for index in range(1, 128):
        factory(str(index))
    assert getattr(factory, "cache_info")().currsize == 128
    assert factory("0") is first
    factory("128")
    assert factory("0") is first
    previous_misses = getattr(factory, "cache_info")().misses
    factory("1")
    assert getattr(factory, "cache_info")().misses == previous_misses + 1
    assert getattr(factory, "cache_info")().currsize == 128


def test_factory_errors_are_not_cached_and_clear_resets_statistics():
    attempts = []

    @string_literal_lru(maxsize=2)
    def factory(value):
        attempts.append(value)
        if value == "bad":
            raise LookupError("expected")
        return object()

    for _ in range(2):
        with pytest.raises(LookupError, match="expected"):
            factory("bad")
    item = factory("ok")
    assert factory("ok") is item
    assert tuple(getattr(factory, "cache_info")()) == (1, 3, 2, 1)
    assert attempts == ["bad", "bad", "ok"]
    getattr(factory, "cache_clear")()
    assert tuple(getattr(factory, "cache_info")()) == (0, 0, 2, 0)


def test_opaque_python_keys_are_uncached_without_hash_or_equality():
    events = []

    class Opaque(str):
        def __hash__(self):
            events.append("hash")
            raise AssertionError("opaque key entered the cache")

        def __eq__(self, other):
            events.append("eq")
            raise AssertionError("opaque key compared")

    @string_literal_lru(maxsize=2)
    def factory(value):
        events.append("factory")
        return object()

    value = Opaque("private")
    assert factory(value) is not factory(value)
    assert events == ["factory", "factory"]
    assert tuple(getattr(factory, "cache_info")()) == (0, 2, 2, 0)


def test_reentrant_same_key_keeps_inner_entry_and_returns_outer_result():
    made = []

    @string_literal_lru(maxsize=2)
    def factory(value):
        outer = not made
        result = object()
        made.append(result)
        if outer:
            assert factory(value) is made[1]
        return result

    outer = factory("same")
    assert outer is made[0]
    assert factory("same") is made[1]
    assert tuple(getattr(factory, "cache_info")()) == (1, 2, 2, 1)


def test_concurrent_misses_compute_outside_lock():
    rendezvous = Barrier(2)

    @string_literal_lru(maxsize=2)
    def factory(value):
        rendezvous.wait(timeout=2)
        return object()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(factory, "same")
        second = executor.submit(factory, "same")
        values = (first.result(timeout=3), second.result(timeout=3))
    assert values[0] is not values[1]
    cached = factory("same")
    assert any(cached is value for value in values)
    assert tuple(getattr(factory, "cache_info")()) == (1, 2, 2, 1)


@pytest.mark.parametrize("operation", ["evict", "clear"])
def test_destructor_reentrancy_observes_consistent_bounded_cache(operation):
    events = []
    cache = None

    class Reentrant:
        def __del__(self):
            assert cache is not None
            events.append(("retired", cache.cache_info().currsize))
            cache("from-destructor")

    def factory(value):
        return Reentrant() if value == "old" else value

    cache = StringLiteralCache(factory, 1)
    cache("old")
    if operation == "clear":
        cache.cache_clear()
        expected_size = 0
    else:
        cache("new")
        expected_size = 1
    gc.collect()
    assert events == [("retired", expected_size)]
    assert cache.cache_info().currsize == 1
    assert cache("from-destructor") == "from-destructor"


def test_snapshot_does_not_execute_unused_value_or_key_callbacks():
    events = []

    class OpaqueKey:
        def __hash__(self):
            events.append("hash")
            return 7

        def __repr__(self):
            raise AssertionError("private key formatted")

    class OpaqueValue:
        def __repr__(self):
            raise AssertionError("private value formatted")

    cache = StringLiteralCache(lambda *_args, **_kwargs: None, 2)
    key, value = OpaqueKey(), OpaqueValue()
    cast(dict[object, object], cache.entries)[key] = value
    events.clear()
    snapshot = cache.snapshot()
    assert len(snapshot) == 1
    assert snapshot[0][0] is key and snapshot[0][1] is value
    assert events == []


def test_actual_literal_matching_and_cached_identity_are_preserved():
    clear = getattr(calls._literal_pattern, "cache_clear")
    clear()
    try:
        first = calls._literal_pattern("curl", "wget", prefix=r"(?<![a-z0-9])", suffix=r"(?![a-z0-9])")
        assert calls._literal_pattern(
            "curl", "wget", prefix=r"(?<![a-z0-9])", suffix=r"(?![a-z0-9])"
        ) is first
        assert first.literals == ("curl", "wget")
        for value, expected in (("curl x", True), ("xcurl", False), ("wget", True), ("ordinary", False)):
            assert calls._matches_any(value, (first,)) is expected
        assert getattr(calls._literal_pattern, "cache_parameters")() == {"maxsize": 128, "typed": False}
    finally:
        clear()


def test_snapshot_retains_unused_poison_and_mutated_frozen_value_for_admission(monkeypatch):
    clear = getattr(calls._literal_pattern, "cache_clear")
    clear()
    original = calls._LiteralRiskPattern
    opaque = object()
    try:
        monkeypatch.setattr(calls, "_LiteralRiskPattern", lambda *_args: opaque)
        assert calls._literal_pattern("unused-poison") is opaque
        monkeypatch.setattr(calls, "_LiteralRiskPattern", original)
        pattern = calls._literal_pattern("safe")
        object.__setattr__(pattern, "expression", "changed")
        cache = getattr(calls._literal_pattern, "_guard_literal_cache")
        rows = cache.snapshot()
        assert len(rows) == 2
        assert rows[0][1] is opaque
        assert rows[1][1] is pattern and pattern.expression == "changed"
        # Inspection is not clearance. The later pair admission must reject both
        # entries and must not clear them to obtain a warm-cache success.
    finally:
        clear()
