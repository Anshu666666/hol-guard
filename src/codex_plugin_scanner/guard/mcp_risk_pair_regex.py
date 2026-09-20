"""Observe actual warm regex entries without replaying risk callbacks.

This is a per-pair necessary condition. The owner separately proves the reached
re declarations and exact argument providers before installing the witness.
Unknown calls retire observation and still execute through the original caller.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from types import ModuleType
from typing import cast


class RiskRegexWitness:
    __slots__ = ("_entries", "_module", "_pattern_type", "_valid")

    def __init__(self, module: ModuleType, pattern_type: type) -> None:
        self._module = module
        self._pattern_type = pattern_type
        self._entries: dict[tuple[type, str, int], object] = {}
        self._valid = True

    def _cache(self) -> dict[object, object] | None:
        if type(self._module) is not ModuleType or type(self._pattern_type) is not type:
            return None
        namespace = ModuleType.__getattribute__(self._module, "__dict__")
        if any(type(key) is not str for key in namespace):
            return None
        # Pattern is an immutable native type in the admitted CPython profile.
        if namespace.get("Pattern") is not self._pattern_type:
            return None
        if not type.__getattribute__(self._pattern_type, "__flags__") & (1 << 8):
            return None
        cache = namespace.get("_cache2")
        if type(cache) is not dict:
            return None
        for key, value in dict.items(cache):
            if (
                type(key) is not tuple
                or len(key) != 3
                or not (key[0] is str or key[0] is bytes)
                or type(key[1]) is not key[0]
                or type(key[2]) is not int
                or type(value) is not self._pattern_type
            ):
                return None
        return cast(dict[object, object], cache)

    def observe(
        self, operation: str, module: object, pattern: object, value: object,
        *, flags: object = 0, replacement: object = None,
    ) -> None:
        if not self._valid:
            return
        # Normalize only the one admitted native int-subclass member. The
        # owner proves RegexFlag/Enum.value declarations before installing us.
        normalized_flags = flags
        if type(flags) is not int:
            namespace = ModuleType.__getattribute__(self._module, "__dict__")
            if any(type(key) is not str for key in namespace):
                self._valid = False
                return
            if flags is not namespace.get("IGNORECASE") or type(flags) is not namespace.get("RegexFlag"):
                self._valid = False
                return
            normalized_flags = int.__int__(flags)
        # No pattern construction, regex execution, or callback happens here.
        if (
            module is not self._module
            or type(operation) is not str
            or operation not in ("search", "findall", "sub")
            or type(pattern) is not str
            or type(value) is not str
            or type(normalized_flags) is not int
            or (normalized_flags != 0 and normalized_flags != 2)
            or (
                operation == "sub"
                and (type(replacement) is not str or "\\" in replacement)
            )
        ):
            self._valid = False
            return
        cache = self._cache()
        if cache is None:
            self._valid = False
            return
        key = (str, pattern, normalized_flags)
        found = dict.get(cache, key)
        if type(found) is not self._pattern_type:
            self._valid = False
            return
        previous = dict.get(self._entries, key)
        if previous is not None and previous is not found:
            self._valid = False
            return
        self._entries[key] = found

    def invalidate(self) -> None:
        self._valid = False

    def check(self) -> bool:
        if not self._valid:
            return False
        cache = self._cache()
        if cache is None:
            self._valid = False
            return False
        for key, value in dict.items(self._entries):
            if dict.get(cache, key) is not value:
                self._valid = False
                return False
        return True

    def retire(self) -> None:
        self._valid = False
        self._entries = {}


_CURRENT: ContextVar[RiskRegexWitness | None] = ContextVar("guard_risk_regex_witness", default=None)


def observe_risk_regex(
    operation: str, module: object, pattern: object, value: object,
    *, flags: object = 0, replacement: object = None,
) -> None:
    witness = _CURRENT.get()
    if witness is not None:
        witness.observe(operation, module, pattern, value, flags=flags, replacement=replacement)


def unsupported_risk_regex_route() -> None:
    witness = _CURRENT.get()
    if witness is not None:
        witness.invalidate()


def observed_risk_regex_value(
    operation: str, module: object, pattern: object, value: str,
    *, flags: object = 0, replacement: object = None,
) -> str:
    """Observe while preserving the caller's already selected regex callable."""
    observe_risk_regex(operation, module, pattern, value, flags=flags, replacement=replacement)
    return value


@contextmanager
def use_risk_regex_witness(witness: RiskRegexWitness | None) -> Iterator[None]:
    token = _CURRENT.set(witness)
    try:
        yield
    finally:
        if witness is not None:
            witness.retire()
        _CURRENT.reset(token)
