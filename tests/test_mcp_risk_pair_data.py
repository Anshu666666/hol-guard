"""Callbacks and custom conversion are rejected before inspecting pair data."""

from __future__ import annotations

import math
from dataclasses import dataclass

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_data import (
    UnsupportedPairData,
    plain_json_input,
    plain_snapshot,
    slot_values,
)


def test_exact_finite_nested_json_is_inspected_without_mutation() -> None:
    value = {"ordered": [None, True, 17, 1.25, "notes"], "tuple": ("a", "b")}
    before = repr(value)
    plain_json_input(value)
    assert repr(value) == before
    assert plain_snapshot(value) == plain_snapshot(value)
    reordered = {"tuple": ("a", "b"), "ordered": value["ordered"]}
    assert plain_snapshot(value) != plain_snapshot(reordered)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, "\ud800", 1 << 1025, b"opaque-default", {"set"}])
def test_unadmitted_json_never_enters_the_native_encoder(value: object) -> None:
    with pytest.raises(UnsupportedPairData):
        plain_json_input(value)


def test_opaque_dictionary_key_is_not_compared_hashed_or_rendered() -> None:
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            events.append("hash")
            return hash("ordered")

        def __eq__(self, _other: object) -> bool:
            events.append("equality")
            return False

        def __repr__(self) -> str:
            events.append("repr")
            return "opaque"

    value = {Key(): "notes"}
    events.clear()
    with pytest.raises(UnsupportedPairData):
        plain_snapshot(value)
    assert events == []


def test_opaque_type_metaclass_is_not_compared() -> None:
    events: list[str] = []

    class Meta(type):
        def __eq__(cls, _other: object) -> bool:
            events.append("equality")
            return False

    class Value(metaclass=Meta):
        def __str__(self) -> str:
            events.append("str")
            return "notes"

    with pytest.raises(UnsupportedPairData):
        plain_snapshot(Value())
    assert events == []


def test_cycle_is_refused_but_shared_plain_children_are_supported() -> None:
    shared: list[object] = ["notes"]
    plain_json_input([shared, shared])
    shared.append(shared)
    with pytest.raises(UnsupportedPairData):
        plain_json_input(shared)


def test_slot_property_replacement_is_refused_without_getter() -> None:
    @dataclass(slots=True)
    class Record:
        name: str

    record = Record("notes")
    original = vars(Record)["name"]
    events: list[str] = []

    def getter(_self: object) -> str:
        events.append("get")
        return "notes"

    type.__setattr__(Record, "name", property(getter))
    try:
        with pytest.raises(UnsupportedPairData):
            slot_values(record, Record, ("name",))
        assert events == []
    finally:
        type.__setattr__(Record, "name", original)


def test_lookup_override_is_rejected_even_with_native_slots() -> None:
    @dataclass(slots=True)
    class Record:
        name: str

    record = Record("notes")
    events: list[str] = []

    def lookup(_self: object, _name: str) -> object:
        events.append("get")
        raise AssertionError("custom lookup")

    type.__setattr__(Record, "__getattribute__", lookup)
    try:
        with pytest.raises(UnsupportedPairData):
            slot_values(record, Record, ("name",))
        assert events == []
    finally:
        type.__delattr__(Record, "__getattribute__")
