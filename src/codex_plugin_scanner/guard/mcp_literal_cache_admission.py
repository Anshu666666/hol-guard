"""Validate every inspectable literal-cache entry before private fact reuse.

These checks are necessary data conditions only. The pair's source guard must
also prove the cache wrapper/factory, pattern constructor and called providers.
No entry is removed or repaired to obtain admission.
"""

from __future__ import annotations

import _thread
import weakref
from types import GetSetDescriptorType, MemberDescriptorType
from typing import cast

from .mcp_literal_pattern_cache import StringLiteralCache

_ESCAPE_CHARACTERS = frozenset("()[]{}?*+-|^$\\.&~# \t\n\r\v\f")
_PATTERN_FIELDS = frozenset(("literals", "expression"))
_CACHE_SLOTS = ("entries", "function", "hits", "lock", "maxsize", "misses")


def _plain_key(value: object) -> tuple[tuple[str, ...], str, str] | None:
    if type(value) is not tuple or len(cast(tuple[object, ...], value)) != 2:
        return None
    args, keywords = cast(tuple[object, object], value)
    if type(args) is not tuple or type(keywords) is not tuple:
        return None
    tokens = cast(tuple[object, ...], args)
    if any(type(item) is not str for item in tokens):
        return None
    prefix = suffix = ""
    seen: set[str] = set()
    for item in cast(tuple[object, ...], keywords):
        if type(item) is not tuple or len(cast(tuple[object, ...], item)) != 2:
            return None
        name, text = cast(tuple[object, object], item)
        if type(name) is not str or type(text) is not str:
            return None
        if name not in ("prefix", "suffix") or name in seen:
            return None
        seen.add(cast(str, name))
        if name == "prefix":
            prefix = cast(str, text)
        else:
            suffix = cast(str, text)
    return cast(tuple[str, ...], tokens), prefix, suffix


def _pattern_record(value: object, pattern_type: type) -> tuple[tuple[str, ...], str] | None:
    if type(pattern_type) is not type or type(value) is not pattern_type:
        return None
    namespace = type.__getattribute__(pattern_type, "__dict__")
    if any(type(name) is not str for name in namespace):
        return None
    bases = type.__getattribute__(pattern_type, "__bases__")
    if len(bases) != 1 or bases[0] is not object:
        return None
    if any(name in namespace for name in ("__getattribute__", "__getattr__", "__del__", "literals", "expression")):
        return None
    descriptor = namespace.get("__dict__")
    if (
        type(descriptor) is not GetSetDescriptorType
        or descriptor.__objclass__ is not pattern_type
        or descriptor.__name__ != "__dict__"
    ):
        return None
    # Even a plain frozen record can carry an external callback through weakref.
    # Skipping a second analysis must not skip a callback triggered by eviction.
    if weakref.getweakrefcount(value):
        return None
    raw = object.__getattribute__(value, "__dict__")
    if type(raw) is not dict or any(type(key) is not str for key in raw):
        return None
    if frozenset(raw) != _PATTERN_FIELDS:
        return None
    literals, expression = raw["literals"], raw["expression"]
    if type(literals) is not tuple or any(type(item) is not str for item in literals):
        return None
    if type(expression) is not str:
        return None
    return cast(tuple[str, ...], literals), cast(str, expression)


def literal_cache_is_canonical(cache: object, pattern_type: type, factory: object) -> bool:
    """Inspect unused as well as used keys/values without opaque callbacks."""
    if type(cache) is not StringLiteralCache:
        return False
    if type(StringLiteralCache) is not type:
        return False
    bases = type.__getattribute__(StringLiteralCache, "__bases__")
    mro = type.__getattribute__(StringLiteralCache, "__mro__")
    if (
        len(bases) != 1 or bases[0] is not object
        or len(mro) != 2 or mro[0] is not StringLiteralCache or mro[1] is not object
    ):
        return False
    namespace = type.__getattribute__(StringLiteralCache, "__dict__")
    if any(type(name) is not str for name in namespace):
        return False
    if any(name in namespace for name in (
        "__getattribute__", "__getattr__", "__setattr__", "__delattr__", "__del__",
    )):
        return False
    for name in _CACHE_SLOTS:
        descriptor = namespace.get(name)
        if (
            type(descriptor) is not MemberDescriptorType
            or descriptor.__objclass__ is not StringLiteralCache
            or descriptor.__name__ != name
        ):
            return False
    raw = {name: object.__getattribute__(cache, name) for name in _CACHE_SLOTS}
    if raw["function"] is not factory or type(raw["maxsize"]) is not int or raw["maxsize"] != 128:
        return False
    if any(type(raw[name]) is not int or cast(int, raw[name]) < 0 for name in ("hits", "misses")):
        return False
    entries, lock = raw["entries"], raw["lock"]
    if type(entries) is not dict or type(lock) is not _thread.RLock:
        return False
    with cast(_thread.RLock, lock):
        rows = tuple(dict.items(cast(dict[object, object], entries)))
        if len(rows) > 128:
            return False
        for key, value in rows:
            parsed = _plain_key(key)
            record = _pattern_record(value, pattern_type)
            if parsed is None or record is None:
                return False
            tokens, prefix, suffix = parsed
            escaped = tuple("".join("\\" + char if char in _ESCAPE_CHARACTERS else char for char in token) for token in tokens)
            expected = (tokens or ("",), prefix + "(" + "|".join(escaped) + ")" + suffix)
            if record != expected:
                return False
        return True
