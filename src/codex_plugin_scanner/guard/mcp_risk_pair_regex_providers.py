"""Reached regex fast-path declarations for the bounded private risk pair."""

from __future__ import annotations

import enum
import re
import types
from types import GetSetDescriptorType, MethodDescriptorType, ModuleType
from typing import cast

from .mcp_risk_pair_providers import plain_builtin_bindings
from .mcp_risk_pair_source import SourceDeclarations


def _namespace(value: ModuleType) -> dict[str, object] | None:
    if type(value) is not ModuleType:
        return None
    raw = ModuleType.__getattribute__(value, "__dict__")
    if any(type(name) is not str for name in raw):
        return None
    return cast(dict[str, object], raw)


def check_risk_regex_providers(declarations: dict[str, SourceDeclarations]) -> bool:
    """Compiler/template paths invalidate the separate actual-call witness."""
    namespace = _namespace(re)
    enums = _namespace(enum)
    type_values = _namespace(types)
    if namespace is None or enums is None or type_values is None:
        return False
    if not plain_builtin_bindings(namespace) or not plain_builtin_bindings(enums):
        return False
    source = declarations.get("re")
    enum_source = declarations.get("enum")
    if type(source) is not SourceDeclarations or type(enum_source) is not SourceDeclarations:
        return False
    for name in ("search", "findall", "sub", "_compile", "escape"):
        if not source.matches(namespace.get(name), re, name):
            return False
    pattern = namespace.get("Pattern")
    if type(pattern) is not type:
        return False
    pattern_class = cast(type, pattern)
    if (
        not type.__getattribute__(pattern_class, "__flags__") & (1 << 8)
        or not type.__getattribute__(pattern_class, "__flags__") & (1 << 7)
        or type.__getattribute__(pattern_class, "__name__") != "Pattern"
        or type.__getattribute__(pattern_class, "__module__") != "re"
    ):
        return False
    native = type.__getattribute__(pattern_class, "__dict__")
    if any(type(name) is not str for name in native):
        return False
    for name in ("search", "findall", "sub"):
        descriptor = native.get(name)
        if (
            type(descriptor) is not MethodDescriptorType
            or descriptor.__name__ != name
            or descriptor.__objclass__ is not pattern_class
        ):
            return False
    flag_class = namespace.get("RegexFlag")
    enum_type = enums.get("EnumType")
    if type(enum_type) is not type or type(flag_class) is not enum_type:
        return False
    expected_mro = (
        flag_class, enums.get("IntFlag"), int, enums.get("ReprEnum"),
        enums.get("Flag"), enums.get("Enum"), object,
    )
    actual_mro = type.__getattribute__(flag_class, "__mro__")
    if len(actual_mro) != len(expected_mro) or any(
        actual is not expected for actual, expected in zip(actual_mro, expected_mro, strict=True)
    ):
        return False
    meta_mro = type.__getattribute__(enum_type, "__mro__")
    if len(meta_mro) != 3 or meta_mro[0] is not enum_type or meta_mro[1] is not type or meta_mro[2] is not object:
        return False
    metaclass = type.__getattribute__(enum_type, "__dict__")
    if any(type(name) is not str for name in metaclass) or "__instancecheck__" in metaclass:
        return False
    value_getter = None
    member_storage = None
    for owner in actual_mro:
        fields = type.__getattribute__(owner, "__dict__")
        if any(type(name) is not str for name in fields):
            return False
        if owner is not object and owner is not int and any(
            name in fields for name in ("__getattribute__", "__getattr__", "_value_")
        ):
            return False
        if "__dict__" in fields and member_storage is None:
            member_storage = fields["__dict__"]
            if (
                type(member_storage) is not GetSetDescriptorType
                or member_storage.__objclass__ is not owner
                or member_storage.__name__ != "__dict__"
            ):
                return False
        if "value" in fields:
            if owner is not enums.get("Enum") or value_getter is not None:
                return False
            descriptor = fields["value"]
            # enum.property subclasses DynamicClassAttribute, so its exact
            # descriptor class and fget declarations are admitted separately.
            descriptor_class = enums.get("property")
            if type(descriptor) is not descriptor_class:
                return False
            if type(descriptor_class) is not type:
                return False
            descriptor_mro = type.__getattribute__(descriptor_class, "__mro__")
            base = type_values.get("DynamicClassAttribute")
            if (
                len(descriptor_mro) != 3 or descriptor_mro[0] is not descriptor_class
                or descriptor_mro[1] is not base or descriptor_mro[2] is not object
            ):
                return False
            storage = None
            for descriptor_owner in descriptor_mro:
                declared = type.__getattribute__(descriptor_owner, "__dict__")
                if any(type(key) is not str for key in declared):
                    return False
                if descriptor_owner is not object and any(
                    key in declared for key in ("__getattribute__", "__getattr__", "fget")
                ):
                    return False
                if "__dict__" in declared:
                    if storage is not None:
                        return False
                    storage = declared["__dict__"]
                    if (
                        type(storage) is not GetSetDescriptorType
                        or storage.__objclass__ is not descriptor_owner
                        or storage.__name__ != "__dict__"
                    ):
                        return False
            if storage is None:
                return False
            own = storage.__get__(descriptor, descriptor_class)
            if type(own) is not dict or any(type(key) is not str for key in own):
                return False
            descriptor_namespace = type.__getattribute__(descriptor_class, "__dict__")
            if not enum_source.matches(descriptor_namespace.get("__get__"), enum, "property.__get__"):
                return False
            value_getter = own.get("fget")
    if not enum_source.matches(value_getter, enum, "Enum.value"):
        return False
    member = namespace.get("IGNORECASE")
    if type(member) is not flag_class:
        return False
    if member_storage is None:
        return False
    raw = member_storage.__get__(member, flag_class)
    if type(raw) is not dict or any(type(name) is not str for name in raw):
        return False
    if type(raw.get("_value_")) is not int or raw["_value_"] != 2 or int.__int__(member) != 2:
        return False
    # Escape only sees exact strings. The data validator separately proves the
    # semantic correspondence of every resulting literal cache entry.
    escape_map = namespace.get("_special_chars_map")
    if type(escape_map) is not dict or any(
        type(key) is not int or type(value) is not str for key, value in escape_map.items()
    ):
        return False
    expected_escape = {code: "\\" + chr(code) for code in b"()[]{}?*+-|^$\\.&~# \t\n\r\v\f"}
    return escape_map == expected_escape
