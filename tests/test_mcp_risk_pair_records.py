"""Finite constructor/descriptor controls, without live application callbacks."""

from __future__ import annotations

from types import FunctionType, ModuleType

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_records import frozen_pair_record_supported


def _records() -> ModuleType:
    module = ModuleType("guard_pair_records_fixture")
    # dataclasses looks up the declared module; register only this disposable
    # fixture for its construction and preserve any previous module on return.
    import sys

    previous = sys.modules.get(module.__name__)
    sys.modules[module.__name__] = module
    try:
        exec(
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class _LiteralRiskPattern:\n"
            "    literals: tuple[str, ...]\n"
            "    expression: str\n"
            "@dataclass(frozen=True, slots=True)\n"
            "class ApprovalContextToken:\n"
            "    identity_hash: str\n"
            "    content_hash: str\n"
            "    capabilities_hash: str\n"
            "    policy_hash: str\n"
            "    sandbox_hash: str\n",
            module.__dict__,
        )
    finally:
        if previous is None:
            del sys.modules[module.__name__]
        else:
            sys.modules[module.__name__] = previous
    return module


@pytest.mark.parametrize("token", [False, True])
def test_stock_generated_frozen_constructor_and_descriptors_are_admitted(token: bool) -> None:
    module = _records()
    cls = module.ApprovalContextToken if token else module._LiteralRiskPattern
    assert frozen_pair_record_supported(cls, module, token=token)


@pytest.mark.parametrize("name", ["__new__", "__init__", "__getattribute__", "__del__"])
def test_opaque_constructor_lookup_or_retirement_is_rejected_without_calling_it(name: str) -> None:
    module = _records()
    cls = module._LiteralRiskPattern
    called: list[str] = []

    def opaque(*_args: object, **_kwargs: object) -> None:
        called.append(name)

    setattr(cls, name, opaque)
    assert not frozen_pair_record_supported(cls, module, token=False)
    assert called == []


def test_same_generated_code_with_foreign_globals_is_rejected() -> None:
    module = _records()
    cls = module._LiteralRiskPattern
    original = cls.__init__
    cls.__init__ = FunctionType(
        original.__code__, {"__name__": module.__name__}, closure=original.__closure__
    )
    assert not frozen_pair_record_supported(cls, module, token=False)


def test_generated_constructor_closure_cannot_substitute_object_provider() -> None:
    module = _records()
    cls = module._LiteralRiskPattern
    cls.__init__.__closure__[0].cell_contents = type("OpaqueObject", (), {})
    assert not frozen_pair_record_supported(cls, module, token=False)


@pytest.mark.parametrize("token", [False, True])
def test_field_data_descriptor_replacement_is_rejected_without_access(token: bool) -> None:
    module = _records()
    cls = module.ApprovalContextToken if token else module._LiteralRiskPattern
    name = "identity_hash" if token else "expression"

    def opaque(_self: object) -> str:
        raise AssertionError("descriptor executed")

    setattr(cls, name, property(opaque))
    assert not frozen_pair_record_supported(cls, module, token=token)


def test_opaque_module_key_cannot_be_looked_up_or_compared() -> None:
    module = _records()
    cls = module._LiteralRiskPattern
    called: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("_LiteralRiskPattern")

        def __eq__(self, _other: object) -> bool:
            called.append("equality")
            return False

    module.__dict__[Key()] = object()
    called.clear()
    assert not frozen_pair_record_supported(cls, module, token=False)
    assert called == []


def test_opaque_class_namespace_key_is_refused_before_descriptor_lookup() -> None:
    module = _records()
    original = module._LiteralRiskPattern
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("__new__")

        def __eq__(self, _other: object) -> bool:
            events.append("equality")
            return False

    namespace = dict(vars(original))
    namespace.pop("__dict__")
    namespace.pop("__weakref__")
    namespace[Key()] = object()
    forged = type("_LiteralRiskPattern", (object,), namespace)
    module._LiteralRiskPattern = forged
    events.clear()
    assert not frozen_pair_record_supported(forged, module, token=False)
    assert events == []
