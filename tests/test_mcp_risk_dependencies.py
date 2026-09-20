"""Unexecuted dependency-capture controls for the RSP-100 proposal."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_risk_dependencies import ReviewedRiskHelpers, _plain_digest


def _namespace(body):
    # Real dataclasses resolve generated-method globals through sys.modules.
    # Use an actual scoped module and restore the previous entry exactly.
    name = "codex_plugin_scanner.guard._risk_dependency_control"
    module = ModuleType(name)
    missing = object()
    previous = sys.modules.get(name, missing)
    namespace = module.__dict__
    source = "def build_tool_call_hash(): pass\ndef evaluate_tool_call(): pass\n" + body
    sys.modules[name] = module
    try:
        exec(compile(source, "<risk_dependency_control>", "exec", dont_inherit=True), namespace)
    finally:
        if previous is missing:
            del sys.modules[name]
        else:
            sys.modules[name] = previous
    return namespace


def _config():
    # Dependency guards inspect type/dispatch only; the authority layer owns data.
    return object.__new__(GuardConfig)


def _capture(namespace):
    return ReviewedRiskHelpers(
        namespace=namespace,
        pure_roots=("risk",),
        consumers=("build_tool_call_hash", "evaluate_tool_call"),
        policy_type=GuardConfig,
        policy_methods=("resolve_action_override", "resolve_artifact_or_publisher_action_override"),
    )


@pytest.mark.parametrize("kind", ["cycle", "opaque", "oversize"])
def test_unsupported_capture_refuses_sharing_without_breaking_import(kind):
    namespace = _namespace("def risk(value=None): return value\n")
    if kind == "cycle":
        value = []
        value.append(value)
    elif kind == "oversize":
        value = list(range(5000))
    else:
        value = object()
    namespace["risk"].__defaults__ = (value,)
    helpers = _capture(namespace)
    assert helpers.available is False
    assert helpers.refusal_reason == "unsupported_helper_dependency"
    assert helpers.unchanged(_config(), namespace) is False


def test_nested_code_global_changes_are_bound():
    namespace = _namespace(
        "def transform(value): return value\ndef risk(): return tuple(transform(value) for value in range(2))\n"
    )
    helpers = _capture(namespace)
    assert helpers.available
    assert helpers.unchanged(_config(), namespace)
    namespace["transform"] = lambda value: value + 1
    assert helpers.unchanged(_config(), namespace) is False


def test_attribute_name_is_not_mistaken_for_unrelated_global():
    namespace = _namespace("def risk(value): return value.get('key')\n")
    namespace["get"] = object()
    helpers = _capture(namespace)
    assert helpers.available
    assert helpers.unchanged(_config(), namespace)
    namespace["get"] = object()
    assert helpers.unchanged(_config(), namespace)


def test_executed_module_attribute_changes_are_bound():
    namespace = _namespace("def risk(): return helper.value()\n")
    helper = ModuleType("risk_control")
    helper.value = lambda: 1
    namespace["helper"] = helper
    helpers = _capture(namespace)
    assert helpers.available
    assert helpers.unchanged(_config(), namespace)
    helper.value = lambda: 2
    assert helpers.unchanged(_config(), namespace) is False


def test_existing_constructor_code_change_is_bound(monkeypatch):
    namespace = _namespace(
        "class Value:\n    def __init__(self, value): self.value = value\ndef risk(): return Value(1).value\n"
    )
    helpers = _capture(namespace)
    assert helpers.available
    constructor = namespace["Value"].__init__

    def changed(self, value):
        self.value = value + 1

    monkeypatch.setattr(constructor, "__code__", changed.__code__)
    assert helpers.unchanged(_config(), namespace) is False


def test_mutable_set_inside_default_is_bound():
    namespace = _namespace("def risk(value={'tags': {'first'}}): return value\n")
    helpers = _capture(namespace)
    assert helpers.available
    namespace["risk"].__defaults__[0]["tags"].add("second")
    assert helpers.unchanged(_config(), namespace) is False


def test_set_and_tuple_encodings_cannot_alias():
    assert _plain_digest({"value": {"first"}}) != _plain_digest({"value": ("set", ("first",))})


def test_new_global_shadow_of_builtin_is_bound():
    namespace = _namespace("def risk(value): return len(value)\n")
    helpers = _capture(namespace)
    assert helpers.available
    namespace["len"] = lambda value: 0
    assert helpers.unchanged(_config(), namespace) is False


def test_frozen_dataclass_constructor_closure_is_supported():
    namespace = _namespace(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Value:\n"
        "    number: int\n"
        "def risk(): return Value(1).number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)


def test_cached_local_from_import_member_changes_are_bound(monkeypatch):
    import urllib.parse

    namespace = _namespace(
        "def risk(value):\n    from urllib.parse import parse_qsl, urlencode\n    return urlencode(parse_qsl(value))\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)
    monkeypatch.setattr(urllib.parse, "parse_qsl", lambda value: [])
    assert helpers.unchanged(_config(), namespace) is False


def test_cached_local_import_module_replacement_is_bound(monkeypatch):
    import sys
    import urllib.parse

    namespace = _namespace("def risk(value):\n    from urllib.parse import parse_qsl\n    return parse_qsl(value)\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    replacement = ModuleType("urllib.parse")
    replacement.parse_qsl = urllib.parse.parse_qsl
    monkeypatch.setitem(sys.modules, "urllib.parse", replacement)
    assert helpers.unchanged(_config(), namespace) is False


@pytest.mark.parametrize("statement", ["import urllib.parse", "from .unknown import value"])
def test_unreviewed_local_import_shape_declines_without_import(statement):
    namespace = _namespace("def risk():\n    " + statement + "\n    return None\n")
    helpers = _capture(namespace)
    assert helpers.available is False
    assert helpers.refusal_reason == "unsupported_helper_dependency"


def test_existing_class_method_global_change_is_bound():
    namespace = _namespace(
        "value = 1\nclass Value:\n    def __init__(self): self.number = value\ndef risk(): return Value().number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    namespace["value"] = 2
    assert helpers.unchanged(_config(), namespace) is False


def test_owned_closure_helper_global_change_is_bound():
    namespace = _namespace(
        "value = 1\n"
        "def helper(): return value\n"
        "def make(helper):\n"
        "    def risk(): return helper()\n"
        "    return risk\n"
        "risk = make(helper)\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    namespace["value"] = 2
    assert helpers.unchanged(_config(), namespace) is False


def test_unknown_closure_function_declines():
    namespace = _namespace(
        "def make(helper):\n    def risk(): return helper()\n    return risk\nrisk = make(lambda: 1)\n"
    )
    namespace["risk"].__closure__[0].cell_contents.__module__ = "unknown_plugin"
    helpers = _capture(namespace)
    assert helpers.available is False


def test_policy_instance_dispatch_mutation_is_bound(monkeypatch):
    namespace = _namespace("def risk(value): return value\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)

    def changed(self, name):
        return object.__getattribute__(self, name)

    monkeypatch.setattr(GuardConfig, "__getattribute__", changed)
    assert helpers.unchanged(_config(), namespace) is False


def test_source_class_with_opaque_existing_descriptor_declines():
    namespace = _namespace("class Value: pass\ndef risk(): return Value().number\n")

    class Descriptor:
        def __get__(self, _instance, _owner):
            return 1

    namespace["Value"].number = Descriptor()
    helpers = _capture(namespace)
    assert helpers.available is False


@pytest.mark.parametrize("name", ["__getstate__", "__setstate__", "__replace__"])
def test_generated_copy_or_serialization_hook_state_remains_bound(monkeypatch, name):
    namespace = _namespace(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Value:\n"
        "    number: int\n"
        "def risk(): return Value(1).number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    hook = getattr(namespace["Value"], name, None)
    if hook is None:
        pytest.skip("__replace__ is introduced by Python 3.13")

    def changed(self):
        return []

    monkeypatch.setattr(hook, "__code__", changed.__code__)
    assert helpers.unchanged(_config(), namespace) is False
