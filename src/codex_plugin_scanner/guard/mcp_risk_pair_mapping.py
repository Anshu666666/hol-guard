"""Admit only native ABC cache hits for the actual plain risk-input types."""

from __future__ import annotations

import _abc
import abc
import weakref
from collections import abc as collections_abc
from types import BuiltinFunctionType, ModuleType
from typing import cast

from .mcp_risk_pair_providers import plain_builtin_bindings
from .mcp_risk_pair_source import SourceDeclarations


def _module(value: object) -> dict[str, object] | None:
    if type(value) is not ModuleType:
        return None
    raw = ModuleType.__getattribute__(value, "__dict__")
    if any(type(name) is not str for name in raw):
        return None
    return cast(dict[str, object], raw)


def _native(value: object, name: str) -> bool:
    return (
        type(value) is BuiltinFunctionType
        and value.__name__ == name
        and value.__self__ is _abc
    )


def mapping_cache_supports(
    declarations: dict[str, SourceDeclarations], needed: tuple[type, ...],
) -> bool:
    """No isinstance replay, cache fill, registry mutation, or subclass hook."""
    if type(declarations) is not dict or any(type(key) is not str for key in declarations) or type(needed) is not tuple:
        return False
    standard, native, collections = _module(abc), _module(_abc), _module(collections_abc)
    if standard is None or native is None or collections is None:
        return False
    if not plain_builtin_bindings(standard):
        return False
    meta = standard.get("ABCMeta")
    mapping = collections.get("Mapping")
    if type(meta) is not type or type(mapping) is not meta:
        return False
    meta_mro = type.__getattribute__(meta, "__mro__")
    if len(meta_mro) != 3 or meta_mro[0] is not meta or meta_mro[1] is not type or meta_mro[2] is not object:
        return False
    meta_fields = type.__getattribute__(meta, "__dict__")
    if any(type(name) is not str for name in meta_fields) or any(
        name in meta_fields for name in ("__getattribute__", "__getattr__", "__eq__", "__ne__", "__hash__", "_abc_impl")
    ):
        return False
    source = declarations.get("abc")
    if type(source) is not SourceDeclarations or not source.matches(
        meta_fields.get("__instancecheck__"), abc, "ABCMeta.__instancecheck__"
    ):
        return False
    for name in ("_abc_instancecheck", "_get_dump", "get_cache_token"):
        if not _native(native.get(name), name):
            return False
    if standard.get("_abc_instancecheck") is not native["_abc_instancecheck"]:
        return False
    fields = type.__getattribute__(mapping, "__dict__")
    if any(type(name) is not str for name in fields):
        return False
    impl = fields.get("_abc_impl")
    impl_type = type(impl)
    if type(impl_type) is not type:
        return False
    impl_fields = type.__getattribute__(impl_type, "__dict__")
    if any(type(name) is not str for name in impl_fields):
        return False
    # _get_dump retrieves _abc_impl through the class. Forbid adding a live
    # descriptor to the otherwise opaque native state object before that read.
    if any(name in impl_fields for name in ("__get__", "__set__", "__delete__")):
        return False
    constructor = impl_fields.get("__new__")
    if (
        type(constructor) is not BuiltinFunctionType
        or constructor.__name__ != "__new__"
        or constructor.__self__ is not impl_type
    ):
        return False
    try:
        _, positive, negative, version = native["_get_dump"](mapping)
        current_version = native["get_cache_token"]()
    except TypeError:
        return False
    if type(positive) is not set or type(negative) is not set or type(version) is not int or type(current_version) is not int:
        return False
    reference = weakref.ReferenceType
    if (
        type(reference) is not type
        or not type.__getattribute__(reference, "__flags__") & (1 << 8)
        or type.__getattribute__(reference, "__module__") != "weakref"
        or type.__getattribute__(reference, "__name__") != "ReferenceType"
    ):
        return False
    def targets(cache: set[object]) -> tuple[type, ...] | None:
        result: list[type] = []
        for item in cache:
            if type(item) is not reference:
                return None
            target = reference.__call__(item)
            if target is None:
                continue
            # Native type equality, or ABCMeta with its equality/hash overrides
            # excluded above, cannot execute a user comparator on collisions.
            if type(target) is not type and type(target) is not meta:
                return None
            result.append(target)
        return tuple(result)

    positive_types = targets(positive)
    negative_types = targets(negative)
    if positive_types is None or negative_types is None:
        return False
    for kind in needed:
        if not any(kind is item for item in (dict, list, tuple, str, bytes, int, bool, float, type(None))):
            return False
        if kind is dict:
            if not any(kind is item for item in positive_types):
                return False
        elif any(kind is item for item in positive_types):
            return False
        elif version != current_version or not any(kind is item for item in negative_types):
            return False
    return True
