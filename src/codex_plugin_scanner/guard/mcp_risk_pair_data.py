"""Exact private input inspection for one risk pair; never invokes record properties."""

from __future__ import annotations

import math
from types import GetSetDescriptorType, MemberDescriptorType
from typing import cast


class UnsupportedPairData(ValueError):
    """Unknown data stays on the original analysis path."""


def class_namespace(cls: object) -> object:
    if type(cls) is not type:
        raise UnsupportedPairData
    namespace = type.__getattribute__(cast(type, cls), "__dict__")
    if any(type(name) is not str for name in namespace):
        raise UnsupportedPairData
    return namespace


def slot_values(value: object, expected: type, names: tuple[str, ...]) -> tuple[object, ...]:
    if type(value) is not expected or type(expected) is not type:
        raise UnsupportedPairData
    namespace = type.__getattribute__(expected, "__dict__")
    if any(type(name) is not str for name in namespace):
        raise UnsupportedPairData
    bases = type.__getattribute__(expected, "__bases__")
    if len(bases) != 1 or bases[0] is not object:
        raise UnsupportedPairData
    if any(name in namespace for name in ("__getattribute__", "__getattr__", "__del__")):
        raise UnsupportedPairData
    result: list[object] = []
    for name in names:
        descriptor = namespace.get(name)
        if (
            type(descriptor) is not MemberDescriptorType
            or descriptor.__name__ != name
            or descriptor.__objclass__ is not expected
        ):
            raise UnsupportedPairData
        result.append(descriptor.__get__(value, expected))
    return tuple(result)


def raw_instance_dict(value: object, allowed_mro: tuple[type, ...]) -> dict[str, object]:
    cls = type(value)
    if type(cls) is not type:
        raise UnsupportedPairData
    mro = type.__getattribute__(cls, "__mro__")
    if any(not any(base is allowed for allowed in allowed_mro) for base in mro):
        raise UnsupportedPairData
    descriptor = None
    for base in mro:
        namespace = type.__getattribute__(base, "__dict__")
        if any(type(name) is not str for name in namespace):
            raise UnsupportedPairData
        if base is not object and any(
            name in namespace for name in ("__getattribute__", "__getattr__", "__del__")
        ):
            raise UnsupportedPairData
        if descriptor is None and "__dict__" in namespace:
            descriptor = namespace["__dict__"]
            if (
                type(descriptor) is not GetSetDescriptorType
                or descriptor.__name__ != "__dict__"
                or descriptor.__objclass__ is not base
            ):
                raise UnsupportedPairData
    if descriptor is None:
        raise UnsupportedPairData
    raw = descriptor.__get__(value, cls)
    if type(raw) is not dict or any(type(name) is not str for name in raw):
        raise UnsupportedPairData
    return cast(dict[str, object], raw)


def path_raw_snapshot(value: object, path_type: type, pure_type: type) -> tuple[object, ...]:
    """The caller first proves the reached Path provider/class descriptor set."""
    if type(value) is not path_type:
        raise UnsupportedPairData
    namespace = type.__getattribute__(pure_type, "__dict__")
    if any(type(name) is not str for name in namespace):
        raise UnsupportedPairData
    captured = None
    semantic: dict[str, object] = {}
    # Lazy caches may legitimately appear during the preserved resolver calls.
    # Validate their exact shape but bind the actual source path components.
    for name in ("_raw_paths", "_str", "_drv", "_root", "_tail_cached", "_str_normcase_cached", "_parts_normcase_cached", "_hash"):
        descriptor = namespace.get(name)
        if (
            type(descriptor) is not MemberDescriptorType
            or descriptor.__name__ != name
            or descriptor.__objclass__ is not pure_type
        ):
            raise UnsupportedPairData
        try:
            item = descriptor.__get__(value, path_type)
        except AttributeError:
            if name == "_raw_paths":
                raise UnsupportedPairData from None
            continue
        if name == "_raw_paths" or name == "_tail_cached" or name == "_parts_normcase_cached":
            if type(item) is not list or any(type(part) is not str for part in item):
                raise UnsupportedPairData
        elif name == "_hash":
            if type(item) is not int:
                raise UnsupportedPairData
        elif type(item) is not str:
            raise UnsupportedPairData
        if name in ("_str", "_drv", "_root"):
            semantic[name] = item
        elif name == "_tail_cached":
            semantic[name] = tuple(item)
        if name == "_raw_paths":
            if (
                not item or not item[0].startswith("/") or any(part.startswith("~") for part in item)
                or any(0xD800 <= ord(char) <= 0xDFFF and not 0xDC80 <= ord(char) <= 0xDCFF for part in item for char in part)
            ):
                raise UnsupportedPairData
            captured = tuple(item)
    if captured is None or set(semantic) != {"_str", "_drv", "_root", "_tail_cached"}:
        raise UnsupportedPairData
    return ("path", captured, tuple((name, semantic[name]) for name in ("_str", "_drv", "_root", "_tail_cached")))


def plain_snapshot(
    value: object,
    *,
    records: tuple[tuple[type, tuple[str, ...]], ...] = (),
    path_types: tuple[type, type] | None = None,
    _active: set[int] | None = None,
) -> tuple[object, ...]:
    """Ordered exact scalar/container/declared-slot data; no hash of opaque keys."""
    kind = type(value)
    if value is None:
        return ("none",)
    if kind is bool:
        return ("bool", value)
    if kind is str:
        if any(0xD800 <= ord(char) <= 0xDFFF for char in cast(str, value)):
            raise UnsupportedPairData
        return ("str", value)
    if kind is bytes:
        return ("bytes", value)
    if kind is int:
        if cast(int, value).bit_length() > 1024:
            raise UnsupportedPairData
        return ("int", value)
    if kind is float:
        if not math.isfinite(cast(float, value)):
            raise UnsupportedPairData
        return ("float", cast(float, value).hex())
    active = set() if _active is None else _active
    identity = id(value)
    if identity in active:
        raise UnsupportedPairData
    active.add(identity)
    try:
        def visit(item: object) -> tuple[object, ...]:
            return plain_snapshot(item, records=records, path_types=path_types, _active=active)

        if kind is list or kind is tuple:
            return ("list" if kind is list else "tuple", tuple(visit(item) for item in cast(list[object] | tuple[object, ...], value)))
        if kind is dict:
            mapping = cast(dict[object, object], value)
            if any(type(key) is not str for key in mapping):
                raise UnsupportedPairData
            return ("dict", tuple((key, visit(item)) for key, item in mapping.items()))
        if kind is frozenset or kind is set:
            values = cast(set[object] | frozenset[object], value)
            if any(type(item) is not str for item in values):
                raise UnsupportedPairData
            return ("frozenset" if kind is frozenset else "set", tuple(sorted(cast(set[str] | frozenset[str], values))))
        if path_types is not None and kind is path_types[0]:
            return path_raw_snapshot(value, *path_types)
        for record, names in records:
            if kind is record:
                return ("record", id(record), tuple(visit(item) for item in slot_values(value, record, names)))
        raise UnsupportedPairData
    finally:
        active.remove(identity)


def plain_json_input(value: object) -> None:
    """Reject custom/default conversions before the admitted C JSON route."""
    plain_snapshot(value)
    pending = [value]
    while pending:
        item = pending.pop()
        kind = type(item)
        if kind is dict:
            pending.extend(cast(dict[str, object], item).values())
        elif kind is list or kind is tuple:
            pending.extend(cast(list[object] | tuple[object, ...], item))
        elif not (
            item is None or kind is str or kind is bool or kind is int or kind is float
        ):
            raise UnsupportedPairData
