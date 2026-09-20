"""Warm native Mapping cache admission; the predicate never warms it."""

from __future__ import annotations

import _abc
import abc
import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_mapping import mapping_cache_supports
from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations


@pytest.fixture
def declarations() -> dict[str, SourceDeclarations]:
    source = Path(abc.__file__).read_bytes()
    return {"abc": SourceDeclarations("abc", source, hashlib.sha256(source).hexdigest())}


def _warm() -> None:
    for value in ({}, [], (), "", b"", 0, False, 0.0, None):
        isinstance(value, Mapping)


def test_actual_warm_positive_and_current_negative_hits_are_admitted(
    declarations: dict[str, SourceDeclarations],
) -> None:
    _warm()
    before = _abc._get_dump(Mapping)
    assert mapping_cache_supports(declarations, (dict, list, tuple, str, bytes, int, bool, float, type(None)))
    after = _abc._get_dump(Mapping)
    assert before == after


def test_cold_cache_is_not_repaired_by_admission(declarations: dict[str, SourceDeclarations]) -> None:
    _abc._reset_caches(Mapping)
    before = _abc._get_dump(Mapping)
    assert not mapping_cache_supports(declarations, (dict,))
    assert _abc._get_dump(Mapping) == before


@pytest.mark.parametrize("name", ["_get_dump", "_abc_instancecheck", "get_cache_token"])
def test_opaque_native_alias_is_refused_before_invocation(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations], name: str,
) -> None:
    _warm()
    events: list[str] = []

    def opaque(*_args: object) -> object:
        events.append(name)
        raise AssertionError("admission invoked an opaque alias")

    monkeypatch.setattr(_abc, name, opaque)
    assert not mapping_cache_supports(declarations, (dict, str))
    assert events == []


def test_custom_instancecheck_is_refused_before_invocation(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations],
) -> None:
    _warm()
    events: list[str] = []

    def opaque(_cls: type, _value: object) -> bool:
        events.append("instancecheck")
        return True

    monkeypatch.setattr(abc.ABCMeta, "__instancecheck__", opaque)
    assert not mapping_cache_supports(declarations, (dict, str))
    assert events == []


def test_custom_native_state_descriptor_is_refused_without_lookup(
    declarations: dict[str, SourceDeclarations],
) -> None:
    original = type.__getattribute__(Mapping, "__dict__")["_abc_impl"]
    events: list[str] = []

    class Descriptor:
        def __get__(self, _instance: object, _owner: object = None) -> object:
            events.append("descriptor")
            return original

    type.__setattr__(Mapping, "_abc_impl", Descriptor())
    try:
        assert not mapping_cache_supports(declarations, (dict,))
        assert events == []
    finally:
        type.__setattr__(Mapping, "_abc_impl", original)


def test_unadmitted_input_type_is_not_compared_or_hashed(
    declarations: dict[str, SourceDeclarations],
) -> None:
    _warm()
    events: list[str] = []

    class Meta(type):
        def __eq__(cls, _other: object) -> bool:
            events.append("comparison")
            return False

        def __hash__(cls) -> int:
            events.append("hash")
            return 1

    class Opaque(metaclass=Meta):
        pass

    assert not mapping_cache_supports(declarations, (Opaque,))
    assert events == []


def test_writable_native_module_label_is_not_consulted(
    monkeypatch: pytest.MonkeyPatch, declarations: dict[str, SourceDeclarations],
) -> None:
    _warm()
    events: list[str] = []

    class Label:
        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            raise AssertionError("opaque native module label compared")

    monkeypatch.setattr(_abc._get_dump, "__module__", Label())
    assert mapping_cache_supports(declarations, (dict, str))
    assert events == []


def test_metaclass_state_descriptor_cannot_run_before_native_dump(
    declarations: dict[str, SourceDeclarations],
) -> None:
    _warm()
    events: list[str] = []

    def state(_cls: object) -> object:
        events.append("descriptor")
        raise AssertionError("metaclass descriptor ran")

    type.__setattr__(abc.ABCMeta, "_abc_impl", property(state))
    try:
        assert not mapping_cache_supports(declarations, (dict, str))
        assert events == []
    finally:
        type.__delattr__(abc.ABCMeta, "_abc_impl")


def test_mapping_inventory_omits_unqueried_identity_scalars() -> None:
    from codex_plugin_scanner.guard.mcp_risk_pair_admission import _mapping_types

    metadata = {
        "tool_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "server_fingerprint": {"version": 7, "enabled": True},
        "mcp_server_identity": {"generation": 9, "trusted": False},
        "mcp_tool_identity": {"revision": 11},
        "unrelated": {"count": 13, "flag": True},
    }
    observed = _mapping_types({"path": "notes"}, metadata)
    assert set(observed) == {dict, str, type(None)}


def test_mapping_inventory_retains_recursive_argument_and_schema_types() -> None:
    from codex_plugin_scanner.guard.mcp_risk_pair_admission import _mapping_types

    metadata = {"tool_schema": {"items": [None, True, 3.5]}}
    observed = _mapping_types({"nested": ([2], "notes")}, metadata)
    assert set(observed) == {dict, str, type(None), list, tuple, int, bool, float}


def test_mapping_inventory_retains_direct_identity_value_types() -> None:
    from codex_plugin_scanner.guard.mcp_risk_pair_admission import _mapping_types

    metadata = {
        "server_fingerprint": 1,
        "mcp_server_identity": False,
        "mcp_tool_identity": 2.5,
    }
    observed = _mapping_types({"path": "notes"}, metadata)
    assert set(observed) == {dict, str, type(None), int, bool, float}
