"""Finite provider controls; no application request or lock is constructed."""

from __future__ import annotations

import _hashlib
import _thread
import _weakref
import hashlib
import math
import sys
import weakref
from types import FrameType, ModuleType
from typing import cast

import pytest

from codex_plugin_scanner.guard import mcp_risk_pair_native as providers

_SUPPORTED = sys.implementation.name == "cpython" and sys.version_info[:3] in (
    (3, 12, 13), (3, 12, 14),
)


@pytest.fixture
def supported_native_profile() -> None:
    if not _SUPPORTED:
        pytest.skip("The native provider profile admits only CPython 3.12.13/.14")
    assert providers.check_native_pair_providers()


def _unexpected(*args: object, **kwargs: object) -> object:
    raise AssertionError("Provider admission must not invoke replaced callbacks")


def test_canonical_native_profile_calls_no_provider(supported_native_profile: None) -> None:
    calls: list[str] = []
    previous = sys.getprofile()
    constructor = hashlib.sha256
    finite = math.isfinite
    count = _weakref.getweakrefcount

    def observe(_frame: FrameType, event: str, argument: object) -> None:
        if event == "c_call" and (
            argument is constructor or argument is finite or argument is count
        ):
            calls.append("provider")

    sys.setprofile(observe)
    try:
        admitted = providers.check_native_pair_providers()
    finally:
        sys.setprofile(previous)
    assert admitted
    assert calls == []


@pytest.mark.parametrize(
    ("module", "name"),
    [
        (hashlib, "sha256"), (hashlib, "_hashlib"), (_hashlib, "openssl_sha256"),
        (_hashlib, "HASH"), (math, "isfinite"), (weakref, "getweakrefcount"),
        (_weakref, "getweakrefcount"), (_thread, "RLock"),
    ],
)
def test_replaced_native_provider_refuses_without_call(
    supported_native_profile: None,
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    name: str,
) -> None:
    monkeypatch.setattr(module, name, _unexpected)
    assert not providers.check_native_pair_providers()


@pytest.mark.parametrize(
    ("cls", "name"),
    [
        (_hashlib.HASH, "update"), (_hashlib.HASH, "digest"),
        (_hashlib.HASH, "hexdigest"), (_thread.RLock, "__enter__"),
        (_thread.RLock, "__exit__"),
    ],
)
def test_native_method_owner_is_immutable(
    supported_native_profile: None,
    cls: type,
    name: str,
) -> None:
    before = vars(cls)[name]
    assert cls.__flags__ & (1 << 8)
    with pytest.raises(TypeError):
        setattr(cls, name, _unexpected)
    assert vars(cls)[name] is before
    assert providers.check_native_pair_providers()


@pytest.mark.parametrize("module", (_hashlib, _thread, math, weakref))
def test_native_module_keys_checked_before_lookup(
    supported_native_profile: None,
    module: ModuleType,
) -> None:
    calls: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("__name__")

        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            return False

    key = Key()
    namespace = cast(dict[object, object], vars(module))
    namespace[key] = None
    calls.clear()
    try:
        admitted = providers.check_native_pair_providers()
        observed = calls.copy()
    finally:
        del namespace[key]
    assert not admitted
    assert observed == []


@pytest.mark.parametrize(("module", "name"), [(_hashlib, "HASH"), (_thread, "RLock")])
def test_native_class_keys_checked_before_flags(
    supported_native_profile: None,
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    name: str,
) -> None:
    calls: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("__module__")

        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            return False

    key = Key()
    namespace = {"__module__": module.__name__, key: None}
    replacement = type(name, (object,), cast(dict[str, object], namespace))
    monkeypatch.setattr(module, name, replacement)
    calls.clear()
    admitted = providers.check_native_pair_providers()
    assert not admitted
    assert calls == []


@pytest.mark.parametrize(
    ("module", "name"), [(_hashlib, "HASH"), (_thread, "RLock"), (math, "isfinite")]
)
def test_unknown_native_type_does_not_run_metaclass_equality(
    supported_native_profile: None,
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    name: str,
) -> None:
    calls: list[str] = []

    class Meta(type):
        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            return False

    class Opaque(metaclass=Meta):
        pass

    monkeypatch.setattr(module, name, Opaque())
    assert not providers.check_native_pair_providers()
    assert calls == []


def test_unknown_hashing_backend_refuses(
    supported_native_profile: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(providers, "_openssl", None)
    assert not providers.check_native_pair_providers()


def test_different_openssl_algorithm_refuses(
    supported_native_profile: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hashlib, "sha256", hashlib.sha512)
    assert not providers.check_native_pair_providers()


def test_unsupported_native_runtime_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 13, 0, "final", 0))
    assert not providers.check_native_pair_providers()
