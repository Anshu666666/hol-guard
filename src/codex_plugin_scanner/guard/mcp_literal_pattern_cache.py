"""Bounded, inspectable cache for source-owned MCP regex literals.

Only exact string arguments enter this private cache. Other Python callers keep
the wrapped computation, without caching opaque keys.
This cache never stores request-local risk facts or admission decisions.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from functools import wraps
from typing import NamedTuple, TypeVar, cast

_F = TypeVar("_F", bound=Callable[..., object])
_Key = tuple[tuple[str, ...], tuple[tuple[str, str], ...]]


class _CacheInfo(NamedTuple):
    hits: int
    misses: int
    maxsize: int
    currsize: int


class StringLiteralCache:
    """Source-owned dict LRU; every key, value and order position is inspectable."""

    __slots__ = ("entries", "function", "hits", "lock", "maxsize", "misses")

    def __init__(self, function: Callable[..., object], maxsize: int) -> None:
        self.function = function
        self.maxsize = maxsize
        self.entries: dict[_Key, object] = {}
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def __call__(self, *args: object, **kwargs: object) -> object:
        supported = all(type(value) is str for value in args) and all(
            type(name) is str and type(value) is str for name, value in kwargs.items()
        )
        if not supported:
            with self.lock:
                self.misses += 1
            return self.function(*args, **kwargs)
        key = cast(_Key, (args, tuple(kwargs.items())))
        with self.lock:
            if key in self.entries:
                self.hits += 1
                result = self.entries.pop(key)
                self.entries[key] = result
                return result
            self.misses += 1
        # As in functools.lru_cache, exceptions are not cached and the factory
        # runs outside the lock. Concurrent/reentrant misses can compute twice.
        result = self.function(*args, **kwargs)
        retired: tuple[_Key, object] | None = None
        with self.lock:
            if key not in self.entries:
                self.entries[key] = result
                if len(self.entries) > self.maxsize:
                    oldest = next(iter(self.entries))
                    retired = (oldest, self.entries.pop(oldest))
        # Publish consistent bounded state and release the lock before an old
        # value's destructor can run. Never inspect or format the retired value.
        del retired
        return result

    def cache_info(self) -> _CacheInfo:
        with self.lock:
            return _CacheInfo(self.hits, self.misses, self.maxsize, len(self.entries))

    def cache_clear(self) -> None:
        with self.lock:
            retired = self.entries
            self.entries = {}
            self.hits = 0
            self.misses = 0
        # Dropping opaque entries can call destructors; the empty cache must
        # already be visible to reentrant calls.
        del retired

    def cache_parameters(self) -> dict[str, int | bool]:
        return {"maxsize": self.maxsize, "typed": False}

    def snapshot(self) -> tuple[tuple[_Key, object], ...]:
        """Return current raw entries without calling keys or values.

        This is observation, not proof: exact key/value/class/semantic checks
        and the enclosing callable boundary are required before fact reuse.
        """
        with self.lock:
            return tuple(dict.items(self.entries))


def string_literal_lru(*, maxsize: int) -> Callable[[_F], _F]:
    if type(maxsize) is not int or maxsize < 1:
        raise ValueError("literal cache requires a positive integer bound")

    def decorate(function: _F) -> _F:
        cache = StringLiteralCache(function, maxsize)

        @wraps(function)
        def wrapped(*args: object, **kwargs: object) -> object:
            return cache(*args, **kwargs)

        setattr(wrapped, "cache_clear", cache.cache_clear)
        setattr(wrapped, "cache_info", cache.cache_info)
        setattr(wrapped, "cache_parameters", cache.cache_parameters)
        setattr(wrapped, "_guard_literal_cache", cache)
        return cast(_F, wrapped)

    return decorate
