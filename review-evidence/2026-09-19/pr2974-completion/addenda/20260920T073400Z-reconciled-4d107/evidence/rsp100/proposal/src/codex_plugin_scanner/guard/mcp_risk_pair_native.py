"""Fixed native providers reached by the private risk-analysis pair.

The caller owns exact input and HASH/RLock instance provenance and verifies this
module's source/bootstrap. This predicate constructs no hash or lock and invokes
none of the providers. Unsupported runtimes or hashing backends remain uncached.
"""

from __future__ import annotations

import _thread
import _weakref
import builtins
import hashlib
import math
import sys
import weakref
from types import (
    BuiltinFunctionType,
    MappingProxyType,
    MethodDescriptorType,
    ModuleType,
    SimpleNamespace,
)
from typing import TypeGuard

try:
    import _hashlib as _openssl
except ImportError:
    _openssl = None

_TYPE = type
_OBJECT = object
_DICT = dict
_STR = str
_INT = int
_TUPLE = tuple
_ALL = all
_LEN = len
_VERSION_TYPE = type(sys.version_info)
_IMMUTABLE_TYPE = 1 << 8


def _is_module(value: object) -> TypeGuard[ModuleType]:
    return _TYPE(value) is ModuleType


def _is_type(value: object) -> TypeGuard[type]:
    return _TYPE(value) is _TYPE


def _is_version(value: object) -> TypeGuard[tuple[object, ...]]:
    return _TYPE(value) is _VERSION_TYPE


def _text(value: object, expected: str) -> bool:
    return _TYPE(value) is _STR and value == expected


def _module_values(value: object, name: str) -> dict[str, object] | None:
    if not _is_module(value):
        return None
    values: dict[str, object] = ModuleType.__getattribute__(value, "__dict__")
    if _TYPE(values) is not _DICT or not _ALL(_TYPE(key) is _STR for key in values):
        return None
    if not _text(values.get("__name__"), name):
        return None
    return values


def _native_function(value: object, module: ModuleType, name: str) -> bool:
    if _TYPE(value) is not BuiltinFunctionType:
        return False
    return (
        _OBJECT.__getattribute__(value, "__self__") is module
        and _text(_OBJECT.__getattribute__(value, "__name__"), name)
    )


def _immutable_class(
    value: object, module_name: str, name: str, methods: tuple[str, ...]
) -> bool:
    if not _is_type(value):
        return False
    namespace: MappingProxyType[str, object] = _TYPE.__getattribute__(value, "__dict__")
    if _TYPE(namespace) is not MappingProxyType:
        return False
    if not _ALL(_TYPE(key) is _STR for key in namespace):
        return False
    flags = _TYPE.__getattribute__(value, "__flags__")
    if _TYPE(flags) is not _INT or flags & _IMMUTABLE_TYPE == 0:
        return False
    bases = _TYPE.__getattribute__(value, "__bases__")
    mro = _TYPE.__getattribute__(value, "__mro__")
    if _TYPE(bases) is not _TUPLE or _LEN(bases) != 1 or bases[0] is not _OBJECT:
        return False
    if _TYPE(mro) is not _TUPLE or _LEN(mro) != 2 or mro[0] is not value or mro[1] is not _OBJECT:
        return False
    if not _text(namespace.get("__module__"), module_name):
        return False
    if not _text(_TYPE.__getattribute__(value, "__name__"), name):
        return False
    for method_name in methods:
        descriptor = namespace.get(method_name)
        if _TYPE(descriptor) is not MethodDescriptorType:
            return False
        if _OBJECT.__getattribute__(descriptor, "__objclass__") is not value:
            return False
        if not _text(_OBJECT.__getattribute__(descriptor, "__name__"), method_name):
            return False
    return True


def _supported_runtime(namespace: dict[str, object]) -> bool:
    version = namespace.get("version_info")
    implementation = namespace.get("implementation")
    if not _is_version(version) or _TYPE(implementation) is not SimpleNamespace:
        return False
    parts = (
        _TUPLE.__getitem__(version, 0),
        _TUPLE.__getitem__(version, 1),
        _TUPLE.__getitem__(version, 2),
    )
    if not _ALL(_TYPE(part) is _INT for part in parts):
        return False
    if not (parts[0] == 3 and parts[1] == 12 and (parts[2] == 13 or parts[2] == 14)):
        return False
    values: dict[str, object] = _OBJECT.__getattribute__(implementation, "__dict__")
    if _TYPE(values) is not _DICT or not _ALL(_TYPE(key) is _STR for key in values):
        return False
    return _text(values.get("name"), "cpython")


def check_native_pair_providers() -> bool:
    """Check the fixed OpenSSL, finite-float, weakref and lock providers."""
    builtin_values = _module_values(builtins, "builtins")
    runtime = _module_values(sys, "sys")
    if builtin_values is None or runtime is None:
        return False
    for name, expected in (
        ("type", _TYPE), ("object", _OBJECT), ("dict", _DICT), ("str", _STR),
        ("int", _INT), ("tuple", _TUPLE), ("all", _ALL), ("len", _LEN),
    ):
        if builtin_values.get(name) is not expected:
            return False
    if not _supported_runtime(runtime) or not _is_module(_openssl):
        return False
    hashes = _module_values(hashlib, "hashlib")
    openssl = _module_values(_openssl, "_hashlib")
    finite = _module_values(math, "math")
    refs = _module_values(weakref, "weakref")
    native_refs = _module_values(_weakref, "_weakref")
    locks = _module_values(_thread, "_thread")
    if hashes is None or openssl is None or finite is None:
        return False
    if refs is None or native_refs is None or locks is None:
        return False
    sha256 = openssl.get("openssl_sha256")
    if hashes.get("_hashlib") is not _openssl or hashes.get("sha256") is not sha256:
        return False
    if not _native_function(sha256, _openssl, "openssl_sha256"):
        return False
    if not _immutable_class(openssl.get("HASH"), "_hashlib", "HASH", ("update", "digest", "hexdigest")):
        return False
    if not _native_function(finite.get("isfinite"), math, "isfinite"):
        return False
    count = native_refs.get("getweakrefcount")
    if refs.get("getweakrefcount") is not count:
        return False
    if not _native_function(count, _weakref, "getweakrefcount"):
        return False
    return _immutable_class(locks.get("RLock"), "_thread", "RLock", ("__enter__", "__exit__"))
