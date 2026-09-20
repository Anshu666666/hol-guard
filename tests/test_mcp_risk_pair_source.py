"""Finite controls for compile-only risk-pair declaration provenance."""

from __future__ import annotations

import hashlib
from types import FunctionType, ModuleType

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations, UnsupportedDeclaration


def _loaded(source: str) -> tuple[ModuleType, SourceDeclarations]:
    module = ModuleType("risk_pair_fixture")
    encoded = source.encode()
    declarations = SourceDeclarations(module.__name__, encoded, hashlib.sha256(encoded).hexdigest())
    exec(compile(source, module.__name__, "exec", dont_inherit=True), module.__dict__)
    return module, declarations


def test_compile_only_never_runs_module_decorators_defaults_or_class_bases() -> None:
    source = b"""
@unknown_decorator
def callback(value=unknown_default()):
    return value
class Record(unknown_base()):
    changed = unknown_factory()
raise RuntimeError("module executed")
"""
    declarations = SourceDeclarations("risk_pair_fixture", source, hashlib.sha256(source).hexdigest())
    assert declarations is not None


def test_digest_failure_does_not_compile_a_different_source() -> None:
    with pytest.raises(UnsupportedDeclaration, match="source_digest_mismatch"):
        SourceDeclarations("risk_pair_fixture", b"invalid syntax!", "0" * 64)


def test_unknown_default_does_not_prevent_an_unrelated_literal_declaration() -> None:
    source = b"""
def unknown(value=opaque()):
    return value
def plain(value=None):
    return value
"""
    declarations = SourceDeclarations("risk_pair_fixture", source, hashlib.sha256(source).hexdigest())
    module = ModuleType("risk_pair_fixture")
    exec(
        compile("def plain(value=None):\n    return value\n", module.__name__, "exec", dont_inherit=True),
        module.__dict__,
    )
    assert declarations.matches(module.plain, module, "plain")
    assert not declarations.matches(module.plain, module, "unknown")


def test_real_declaration_and_all_literal_default_kinds_match() -> None:
    module, declarations = _loaded(
        "def call(value=None, count=2, ratio=-0.0, text='x', data=b'y', enabled=True, "
        "items=('a', 3), *, mode='exact'):\n    return value\n"
    )
    assert declarations.matches(module.call, module, "call")
    module.call.__defaults__ = (None, 2, 0.0, "x", b"y", True, ("a", 3))
    assert not declarations.matches(module.call, module, "call")


def test_changed_body_forged_names_and_foreign_globals_do_not_match() -> None:
    module, declarations = _loaded("def call(value):\n    return value\n")
    stock = module.call
    foreign = FunctionType(stock.__code__, {"__name__": module.__name__})
    foreign.__module__ = stock.__module__
    foreign.__name__ = stock.__name__
    foreign.__qualname__ = stock.__qualname__
    assert not declarations.matches(foreign, module, "call")
    exec("def replacement(value):\n    return None\n", module.__dict__)
    module.replacement.__module__ = stock.__module__
    module.replacement.__name__ = stock.__name__
    module.replacement.__qualname__ = stock.__qualname__
    assert not declarations.matches(module.replacement, module, "call")


def test_same_code_opaque_default_is_rejected_without_comparison_or_repr() -> None:
    module, declarations = _loaded("def call(value=None):\n    return value\n")

    class Opaque:
        def __eq__(self, other: object) -> bool:
            raise AssertionError("opaque comparison")

        def __repr__(self) -> str:
            raise AssertionError("opaque repr")

    module.call.__defaults__ = (Opaque(),)
    assert not declarations.matches(module.call, module, "call")


def test_keyword_default_value_and_presence_are_bound() -> None:
    module, declarations = _loaded("def call(*, mode='exact', count=1):\n    return mode, count\n")
    assert declarations.matches(module.call, module, "call")
    module.call.__kwdefaults__ = {"mode": "exact", "count": 2}
    assert not declarations.matches(module.call, module, "call")
    module.call.__kwdefaults__ = {"mode": "exact"}
    assert not declarations.matches(module.call, module, "call")


def test_nested_declaration_requires_separately_proved_exact_closure_cells() -> None:
    module, declarations = _loaded(
        "def outer(owner):\n"
        "    def callback():\n"
        "        return owner\n"
        "    return callback\n"
    )
    first = object()
    second = object()
    callback = module.outer(first)
    assert not declarations.matches(callback, module, "outer.<locals>.callback")
    assert declarations.matches(callback, module, "outer.<locals>.callback", closure=(first,))
    assert not declarations.matches(callback, module, "outer.<locals>.callback", closure=(second,))
    callback.__closure__[0].cell_contents = second
    assert not declarations.matches(callback, module, "outer.<locals>.callback", closure=(first,))


def test_class_method_code_is_checked_without_constructing_a_record() -> None:
    module, declarations = _loaded(
        "class Record:\n"
        "    def method(self, value=None):\n"
        "        return value\n"
    )
    assert declarations.matches(module.Record.method, module, "Record.method")


def test_ambiguous_duplicate_and_property_setter_do_not_bless_either_body() -> None:
    module, declarations = _loaded(
        "def call():\n    return 1\n"
        "def call():\n    return 2\n"
        "class Record:\n"
        "    @property\n"
        "    def value(self):\n"
        "        return None\n"
        "    @value.setter\n"
        "    def value(self, value):\n"
        "        pass\n"
        "def plain():\n"
        "    return None\n"
    )
    assert not declarations.matches(module.call, module, "call")
    assert not declarations.matches(module.Record.value.fget, module, "Record.value")
    assert declarations.matches(module.plain, module, "plain")


def test_async_and_generator_flags_are_part_of_the_declaration() -> None:
    module, declarations = _loaded(
        "async def async_call(value):\n    return value\n"
        "def generator(value):\n    yield value\n"
        "def plain(value):\n    return value\n"
    )
    assert declarations.matches(module.async_call, module, "async_call")
    assert declarations.matches(module.generator, module, "generator")
    assert not declarations.matches(module.plain, module, "async_call")
    assert not declarations.matches(module.plain, module, "generator")


def test_same_globals_do_not_hide_a_foreign_captured_builtins_dictionary() -> None:
    module, declarations = _loaded("def call(value):\n    return len(value)\n")
    stock = module.call
    real_builtins = module.__dict__["__builtins__"]
    module.__dict__["__builtins__"] = {"len": lambda value: 0}
    foreign = FunctionType(stock.__code__, module.__dict__)
    module.__dict__["__builtins__"] = real_builtins
    assert declarations.matches(stock, module, "call")
    assert not declarations.matches(foreign, module, "call")


def test_opaque_module_name_is_rejected_without_comparison_or_repr() -> None:
    module, declarations = _loaded("def call(value):\n    return value\n")

    class Opaque:
        def __eq__(self, other: object) -> bool:
            raise AssertionError("opaque equality")

        def __ne__(self, other: object) -> bool:
            raise AssertionError("opaque inequality")

        def __repr__(self) -> str:
            raise AssertionError("opaque repr")

    module.__dict__["__name__"] = Opaque()
    assert not declarations.matches(module.call, module, "call")


def test_opaque_module_key_is_rejected_before_namespace_lookup() -> None:
    module, declarations = _loaded("def call(value):\n    return value\n")
    function = module.call
    events: list[str] = []

    class Key:
        def __hash__(self) -> int:
            return hash("__name__")

        def __eq__(self, _other: object) -> bool:
            events.append("equality")
            return False

    module.__dict__[Key()] = object()
    events.clear()
    assert not declarations.matches(function, module, "call")
    assert events == []


def test_opaque_qualified_name_is_rejected_without_hash_or_comparison() -> None:
    module, declarations = _loaded("def call(value):\n    return value\n")

    class Opaque:
        def __hash__(self) -> int:
            raise AssertionError("opaque hash")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("opaque comparison")

    assert not declarations.matches(module.call, module, Opaque())  # type: ignore[arg-type]


def test_opaque_default_metaclass_cannot_run_comparison_or_attribute_lookup() -> None:
    module, declarations = _loaded("def call(value=None):\n    return value\n")
    events: list[str] = []

    class Meta(type):
        def __eq__(cls, _other: object) -> bool:
            events.append("equality")
            return False

        def __getattribute__(cls, name: str) -> object:
            events.append("class_attribute")
            return super().__getattribute__(name)

    class Opaque(metaclass=Meta):
        pass

    module.call.__defaults__ = (Opaque(),)
    events.clear()
    assert not declarations.matches(module.call, module, "call")
    assert events == []


def test_opaque_code_constant_metaclass_is_rejected_without_callbacks() -> None:
    module, declarations = _loaded("def call(value):\n    return value\n")
    events: list[str] = []

    class Meta(type):
        def __eq__(cls, _other: object) -> bool:
            events.append("equality")
            return False

        def __getattribute__(cls, name: str) -> object:
            events.append("class_attribute")
            return super().__getattribute__(name)

    class Opaque(metaclass=Meta):
        pass

    opaque = Opaque()
    module.call.__code__ = module.call.__code__.replace(
        co_consts=(*module.call.__code__.co_consts, opaque)
    )
    events.clear()
    assert not declarations.matches(module.call, module, "call")
    assert events == []
