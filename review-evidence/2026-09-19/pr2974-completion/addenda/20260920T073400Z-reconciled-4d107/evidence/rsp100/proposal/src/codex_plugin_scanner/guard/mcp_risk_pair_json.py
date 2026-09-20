"""Fixed JSON/base64 provider admission for the private risk-analysis pair.

The caller proves the exact plain finite JSON inputs, supported dumps flags and
the installed CPython/source bootstrap. After visible checks, this predicate
constructs one constant native encoder without serializing or invoking an
application callback. Unsupported providers stay on the original uncached route.
It is not a generic Python-heap integrity checker.
"""

from __future__ import annotations

import _json
import base64
import binascii
import builtins
import json
import sys
from json import encoder as _encoder_module
from types import (
    BuiltinFunctionType,
    GetSetDescriptorType,
    MappingProxyType,
    MemberDescriptorType,
    ModuleType,
    SimpleNamespace,
    WrapperDescriptorType,
)
from typing import TypeGuard

from .mcp_risk_pair_source import SourceDeclarations

_TYPE = type
_OBJECT = object
_DICT = dict
_STR = str
_BYTES = bytes
_FLOAT = float
_LIST = list
_TUPLE = tuple
_BOOL = bool
_INT = int
_LEN = len
_ALL = all
_ANY = any
_FROZENSET = frozenset
_ISINSTANCE = isinstance
_VERSION_TYPE = type(sys.version_info)
_TYPE_ERROR = TypeError
_MATCH_DECLARATION = SourceDeclarations.matches
_POSITIVE_INFINITY = 1e309
_TRANSLATION = bytes(range(256)).replace(b"+", b"-").replace(b"/", b"_")
_PYTHON_CLASS_KEYS = frozenset(
    (
        "__module__", "__doc__", "__dict__", "__weakref__",
        "item_separator", "key_separator", "__init__", "default", "encode", "iterencode",
    )
)
_NATIVE_CLASS_KEYS = frozenset(
    (
        "__module__", "__doc__", "__new__", "__call__", "markers", "default",
        "encoder", "indent", "key_separator", "item_separator", "sort_keys", "skipkeys",
    )
)
_NATIVE_MEMBERS = (
    "markers", "default", "encoder", "indent",
    "key_separator", "item_separator", "sort_keys", "skipkeys",
)
_BUILTINS = (
    ("type", _TYPE), ("object", _OBJECT), ("dict", _DICT), ("str", _STR),
    ("bytes", _BYTES), ("float", _FLOAT), ("list", _LIST), ("tuple", _TUPLE),
    ("bool", _BOOL), ("int", _INT), ("len", _LEN), ("all", _ALL),
    ("frozenset", _FROZENSET), ("isinstance", _ISINSTANCE),
    ("any", _ANY), ("getattr", getattr), ("repr", repr), ("vars", vars),
    ("zip", zip), ("complex", complex), ("ValueError", ValueError),
    ("TypeError", TypeError), ("RecursionError", RecursionError),
)


def _is_module(value: object) -> TypeGuard[ModuleType]:
    return _TYPE(value) is ModuleType


def _is_type(value: object) -> TypeGuard[type]:
    return _TYPE(value) is _TYPE


def _is_str(value: object) -> TypeGuard[str]:
    return _TYPE(value) is _STR


def _is_declaration(value: object) -> TypeGuard[SourceDeclarations]:
    return _TYPE(value) is SourceDeclarations


def _is_version(value: object) -> TypeGuard[tuple[object, ...]]:
    return _TYPE(value) is _VERSION_TYPE


def _module_values(module: object) -> dict[str, object] | None:
    if not _is_module(module):
        return None
    values: dict[str, object] = ModuleType.__getattribute__(module, "__dict__")
    if _TYPE(values) is not _DICT or not _ALL(_TYPE(key) is _STR for key in values):
        return None
    return values


def _class_values(cls: object) -> MappingProxyType[str, object] | None:
    if not _is_type(cls):
        return None
    values: MappingProxyType[str, object] = _TYPE.__getattribute__(cls, "__dict__")
    if _TYPE(values) is not MappingProxyType or not _ALL(_TYPE(key) is _STR for key in values):
        return None
    bases = _TYPE.__getattribute__(cls, "__bases__")
    mro = _TYPE.__getattribute__(cls, "__mro__")
    if _TYPE(bases) is not _TUPLE or _LEN(bases) != 1 or bases[0] is not _OBJECT:
        return None
    if _TYPE(mro) is not _TUPLE or _LEN(mro) != 2 or mro[0] is not cls or mro[1] is not _OBJECT:
        return None
    return values


def _text(value: object, expected: str) -> bool:
    return _is_str(value) and value == expected


def _native_function(value: object, module: ModuleType, name: str) -> bool:
    if _TYPE(value) is not BuiltinFunctionType:
        return False
    return (
        _OBJECT.__getattribute__(value, "__self__") is module
        and _text(_OBJECT.__getattribute__(value, "__name__"), name)
    )


def _descriptor(value: object, cls: object, name: str, kind: type) -> bool:
    if _TYPE(value) is not kind:
        return False
    return (
        _OBJECT.__getattribute__(value, "__objclass__") is cls
        and _text(_OBJECT.__getattribute__(value, "__name__"), name)
    )


def _runtime_supported(values: dict[str, object]) -> bool:
    version = values.get("version_info")
    implementation = values.get("implementation")
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
    namespace: dict[str, object] = _OBJECT.__getattribute__(implementation, "__dict__")
    if _TYPE(namespace) is not _DICT or not _ALL(_TYPE(key) is _STR for key in namespace):
        return False
    return _text(namespace.get("name"), "cpython")


def _matches(
    declarations: dict[str, SourceDeclarations],
    module: ModuleType,
    namespace: dict[str, object],
    name: str,
    function: object,
) -> bool:
    module_name = namespace.get("__name__")
    if not _is_str(module_name):
        return False
    declaration = declarations.get(module_name)
    return _is_declaration(declaration) and _MATCH_DECLARATION(
        declaration, function, module, name
    )


def _python_encoder(
    declarations: dict[str, SourceDeclarations],
    module: ModuleType,
    namespace: dict[str, object],
    cls: object,
) -> bool:
    values = _class_values(cls)
    if values is None or _FROZENSET(values) != _PYTHON_CLASS_KEYS:
        return False
    if not _text(values.get("__module__"), "json.encoder"):
        return False
    if not _text(values.get("item_separator"), ", ") or not _text(values.get("key_separator"), ": "):
        return False
    if _TYPE(values.get("__doc__")) is not _STR:
        return False
    for name in ("__dict__", "__weakref__"):
        if not _descriptor(values.get(name), cls, name, GetSetDescriptorType):
            return False
    return _ALL(
        _matches(declarations, module, namespace, "JSONEncoder." + name, values.get(name))
        for name in ("__init__", "default", "encode", "iterencode")
    )


def _native_encoder(cls: object) -> bool:
    if not _is_type(cls):
        return False
    values = _class_values(cls)
    if values is None or _FROZENSET(values) != _NATIVE_CLASS_KEYS:
        return False
    if not _text(values.get("__module__"), "_json"):
        return False
    if not _text(_TYPE.__getattribute__(cls, "__name__"), "Encoder"):
        return False
    if not _text(values.get("__doc__"), "_iterencode(obj, _current_indent_level) -> iterable"):
        return False
    new = values.get("__new__")
    if _TYPE(new) is not BuiltinFunctionType:
        return False
    if _OBJECT.__getattribute__(new, "__self__") is not cls:
        return False
    if not _text(_OBJECT.__getattribute__(new, "__name__"), "__new__"):
        return False
    if not _descriptor(values.get("__call__"), cls, "__call__", WrapperDescriptorType):
        return False
    return _ALL(
        _descriptor(values.get(name), cls, name, MemberDescriptorType) for name in _NATIVE_MEMBERS
    )


def _native_constructor_ready(cls: type, encoder: object) -> bool:
    # A restored native __new__ descriptor can retain a generic allocation slot.
    # Probe only after all visible providers match, with no application values.
    try:
        probe = cls(None, None, encoder, None, ":", ",", False, False, False)
    except _TYPE_ERROR:
        return False
    return _TYPE(probe) is cls


def check_json_base64_providers(declarations_by_module: dict[str, SourceDeclarations]) -> bool:
    """Admit providers with one constant native allocation and no serialization.

    The declarations mapping must be an exact dict from the caller's verified
    source bootstrap. The fixed C encoder route requires all admitted dumps calls
    to use indent=None and either sort_keys=True or ensure_ascii=False.
    """
    if _TYPE(declarations_by_module) is not _DICT:
        return False
    if not _ALL(_TYPE(key) is _STR for key in declarations_by_module):
        return False
    modules = (builtins, sys, json, _encoder_module, base64, _json, binascii)
    namespaces = _TUPLE(_module_values(module) for module in modules)
    if _ANY(value is None for value in namespaces):
        return False
    (
        builtin_values,
        sys_values,
        json_values,
        encoder_values,
        base64_values,
        native_values,
        binascii_values,
    ) = namespaces
    assert builtin_values is not None and sys_values is not None
    assert json_values is not None and encoder_values is not None and base64_values is not None
    assert native_values is not None and binascii_values is not None
    if not _ALL(builtin_values.get(name) is expected for name, expected in _BUILTINS):
        return False
    if not _runtime_supported(sys_values):
        return False
    for name in ("isinstance", "str", "list", "tuple", "float"):
        if encoder_values.get(name, builtin_values[name]) is not builtin_values[name]:
            return False
    if not _matches(declarations_by_module, json, json_values, "dumps", json_values.get("dumps")):
        return False
    if json_values.get("encoder") is not _encoder_module:
        return False
    cls = encoder_values.get("JSONEncoder")
    if json_values.get("JSONEncoder") is not cls:
        return False
    if not _python_encoder(declarations_by_module, _encoder_module, encoder_values, cls):
        return False
    infinity = encoder_values.get("INFINITY")
    if _TYPE(infinity) is not _FLOAT or infinity != _POSITIVE_INFINITY:
        return False
    for name in ("encode_basestring_ascii", "encode_basestring"):
        native = native_values.get(name)
        if not _native_function(native, _json, name):
            return False
        if encoder_values.get(name) is not native or encoder_values.get("c_" + name) is not native:
            return False
    native_encoder = native_values.get("make_encoder")
    if encoder_values.get("c_make_encoder") is not native_encoder or not _native_encoder(native_encoder):
        return False
    for name in ("urlsafe_b64encode", "b64encode"):
        if not _matches(declarations_by_module, base64, base64_values, name, base64_values.get(name)):
            return False
    translation = base64_values.get("_urlsafe_encode_translation")
    if _TYPE(translation) is not _BYTES or translation != _TRANSLATION:
        return False
    if base64_values.get("binascii") is not binascii:
        return False
    if not _native_function(binascii_values.get("b2a_base64"), binascii, "b2a_base64"):
        return False
    if not _is_type(native_encoder):
        return False
    return _native_constructor_ready(native_encoder, native_values["encode_basestring_ascii"])
