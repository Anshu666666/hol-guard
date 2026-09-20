"""Adversarial controls for the finite Path provider condition."""

from __future__ import annotations

import builtins
import gc
import hashlib
import os
import pathlib
import posixpath
import signal
import sys
import types

import pytest

from codex_plugin_scanner.guard import mcp_risk_pair_paths as guard
from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations


@pytest.fixture
def declarations() -> dict[str, SourceDeclarations]:
    if os.name != "posix" or sys.version_info[:3] not in ((3, 12, 13), (3, 12, 14)):
        pytest.skip("positive Path admission requires the declared CPython POSIX profile")
    expected = {
        "pathlib": (pathlib, "10ba48ae8063cfe7589436041d0d4628c05f427c7709cf8e75e486f8930cc32c"),
        "posixpath": (posixpath, "03825681086638649a43480954f7f6a16b4da3bd41ece956864ae96e4f795cd9"),
    }
    result = {}
    for name, (module, digest) in expected.items():
        data = pathlib.Path(module.__file__).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        result[name] = SourceDeclarations(name, data, digest)
    assert guard.check_path_providers(result), "the declared native baseline must admit"
    return result


def test_actual_posix_provider_closure_admits_without_path_evaluation(declarations):
    assert guard.check_path_providers(declarations)


@pytest.mark.parametrize("target", ["name", "constructor", "path_property", "slot", "native", "shadow"])
def test_replaced_reached_provider_refuses_without_calling_it(declarations, monkeypatch, target):
    events = []

    def opaque(*args, **kwargs):
        events.append("called")
        raise AssertionError("opaque provider must not execute during refusal")

    if target == "name":
        monkeypatch.setattr(pathlib.PurePath, "name", property(opaque))
    elif target == "constructor":
        monkeypatch.setattr(pathlib.Path, "__init__", opaque)
    elif target == "path_property":
        monkeypatch.setattr(pathlib.Path, "root", property(opaque), raising=False)
    elif target == "slot":
        monkeypatch.setattr(pathlib.PurePath, "_raw_paths", property(opaque))
    elif target == "native":
        monkeypatch.setattr(os, "lstat", opaque)
    else:
        monkeypatch.setattr(posixpath, "isinstance", opaque, raising=False)
    assert not guard.check_path_providers(declarations)
    assert events == []


@pytest.mark.parametrize("target", ["builtin", "module"])
def test_replaced_join_map_refuses_without_calling_it(declarations, monkeypatch, target):
    events = []

    def opaque(*args, **kwargs):
        events.append("called")
        raise AssertionError("join map replacement must not execute during refusal")

    module = builtins if target == "builtin" else posixpath
    with monkeypatch.context() as patch:
        patch.setattr(module, "map", opaque, raising=False)
        admitted = guard.check_path_providers(declarations)
        observed = events.copy()
    assert not admitted
    assert observed == []


def test_mutable_native_stat_descriptor_is_not_trusted(declarations, monkeypatch):
    events = []

    def opaque(instance):
        events.append(instance)
        raise AssertionError("native result descriptor must not execute")

    monkeypatch.setattr(os.stat_result, "st_mode", property(opaque))
    assert not guard.check_path_providers(declarations)
    assert events == []


def test_fake_tuple_result_type_cannot_replace_the_native_owner(declarations, monkeypatch):
    class Forged(tuple):
        __slots__ = ()

        @property
        def st_mode(self):
            raise AssertionError("fake result descriptor")

    Forged.__name__ = "stat_result"
    Forged.__module__ = "os"
    monkeypatch.setattr(os, "stat_result", Forged)
    monkeypatch.setattr(guard.posix, "stat_result", Forged)
    assert not guard.check_path_providers(declarations)


def test_metaclass_comparison_is_not_used_on_rejected_class(declarations, monkeypatch):
    events = []

    class OpaqueMeta(type):
        def __eq__(cls, other):
            events.append("eq")
            raise AssertionError("metaclass comparison must not execute")

        def __repr__(cls):
            events.append("repr")
            raise AssertionError("metaclass repr must not execute")

    class Forged(metaclass=OpaqueMeta):
        pass

    monkeypatch.setattr(pathlib, "PosixPath", Forged)
    assert not guard.check_path_providers(declarations)
    assert events == []


def test_opaque_class_namespace_key_is_refused_before_lookup(declarations):
    events = []

    armed = False

    class Key:
        def __hash__(self):
            events.append("hash")
            return hash("__getattribute__")

        def __eq__(self, other):
            events.append("eq")
            if armed:
                raise AssertionError("opaque namespace lookup must not execute")
            return False

    namespace = next(
        value for value in gc.get_referents(vars(pathlib.PurePath)) if type(value) is dict
    )
    key = Key()
    namespace[key] = True
    events.clear()
    armed = True
    try:
        assert not guard.check_path_providers(declarations)
        assert events == []
    finally:
        armed = False
        del namespace[key]


@pytest.mark.parametrize("target", ["function_globals", "keyword_default", "flavour"])
def test_source_and_binding_repairs_cannot_be_bypassed(declarations, monkeypatch, target):
    if target == "function_globals":
        original = posixpath._joinrealpath
        copied = types.FunctionType(
            original.__code__, dict(original.__globals__), original.__name__,
            original.__defaults__, original.__closure__,
        )
        monkeypatch.setattr(posixpath, "_joinrealpath", copied)
    elif target == "keyword_default":
        monkeypatch.setattr(pathlib.Path.stat, "__kwdefaults__", {"follow_symlinks": False})
    else:
        monkeypatch.setattr(pathlib.PosixPath, "_flavour", object(), raising=False)
    assert not guard.check_path_providers(declarations)


def test_signal_callback_is_refused_without_delivery(declarations):
    events = []

    def handler(signum, frame):
        events.append(signum)

    old = signal.signal(signal.SIGUSR1, handler)
    try:
        assert not guard.check_path_providers(declarations)
        assert events == []
    finally:
        signal.signal(signal.SIGUSR1, old)
    assert guard.check_path_providers(declarations)


def test_windows_profile_remains_unadmitted(declarations, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert not guard.check_path_providers(declarations)


def test_unknown_function_defaults_refuse_without_comparison(declarations, monkeypatch):
    events = []

    class Opaque:
        def __eq__(self, other):
            events.append("eq")
            raise AssertionError("opaque default equality")

        def __repr__(self):
            events.append("repr")
            raise AssertionError("opaque default repr")

    monkeypatch.setattr(pathlib.Path.resolve, "__defaults__", (Opaque(),))
    assert not guard.check_path_providers(declarations)
    assert events == []


def test_patched_builtin_is_rejected_by_the_explicit_builtin_condition(declarations):
    events = []

    def opaque(*args):
        events.append("called")
        raise AssertionError("opaque builtin")

    namespace = vars(__import__("builtins")).copy()
    namespace["getattr"] = opaque
    assert not guard._builtin_state(namespace)
    assert events == []
