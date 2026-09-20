"""Refusal-side module and alias inspection never calls unknown providers."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import cast

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_data import UnsupportedPairData
from codex_plugin_scanner.guard.mcp_risk_pair_providers import module_values


def test_opaque_module_registry_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class Registry:
        def get(self, _name: object) -> object:
            events.append("get")
            raise AssertionError("opaque registry called")

    with monkeypatch.context() as patch:
        patch.setattr(sys, "modules", Registry())
        with pytest.raises(UnsupportedPairData):
            module_values("json")
    assert events == []


def test_opaque_registry_key_is_not_compared() -> None:
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("json")

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    registry = cast(dict[object, object], sys.modules)
    key = Key()
    registry[key] = ModuleType("opaque")
    events.clear()
    try:
        with pytest.raises(UnsupportedPairData):
            module_values("json")
        assert events == []
    finally:
        del registry[key]


def test_unknown_sys_namespace_key_is_screened_before_registry_lookup() -> None:
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("modules")

        def __eq__(self, _other: object) -> bool:
            events.append("comparison")
            return False

    key = Key()
    namespace = cast(dict[object, object], vars(sys))
    namespace[key] = object()
    events.clear()
    try:
        with pytest.raises(UnsupportedPairData):
            module_values("json")
        assert events == []
    finally:
        del namespace[key]
