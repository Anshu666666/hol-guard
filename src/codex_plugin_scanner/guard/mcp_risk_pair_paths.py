"""Finite POSIX providers for one private MCP hash-to-decision pair.

This is a provider condition, not input admission or a purity certificate.
The caller admits this helper and SourceDeclarations themselves, and checks
coherent exact Path slots, absolute non-tilde input and empty constructor kwargs.
Initial strings must not contain lone surrogates outside U+DC80..U+DCFF.
No path is resolved, stat'ed or reconstructed here; no facts are retained.
Windows, unknown interpreter builds and opaque signal handlers are unsupported.
"""

from __future__ import annotations

import _signal
import _stat
import builtins
import errno
import os
import pathlib
import posixpath
import sys
from types import (
    BuiltinFunctionType,
    MappingProxyType,
    MemberDescriptorType,
    ModuleType,
)

from .mcp_risk_pair_source import SourceDeclarations

try:
    import posix
except ImportError:
    posix = None

_TYPE = (0).__class__.__class__
_OBJECT = (0).__class__.__mro__[-1]
_STR = "".__class__
_INT = (0).__class__
_BOOL = True.__class__
_BYTES = b"".__class__
_TUPLE = ().__class__
_LIST = [].__class__
_DICT = {}.__class__
_SET = {0}.__class__
_IMMUTABLE = 1 << 8
_HEAP = 1 << 9
_BASETYPE = 1 << 10
_PATH_SLOTS = (
    "_raw_paths", "_drv", "_root", "_tail_cached", "_str",
    "_str_normcase_cached", "_parts_normcase_cached", "_lines_cached", "_hash",
)


def _same_items(actual: object, expected: tuple[object, ...]) -> bool:
    return (
        _TYPE(actual) is _TUPLE
        and len(actual) == len(expected)
        and all(left is right for left, right in zip(actual, expected, strict=True))
    )


def _namespace(module: object) -> dict[str, object] | None:
    if _TYPE(module) is not ModuleType:
        return None
    values = ModuleType.__getattribute__(module, "__dict__")
    if _TYPE(values) is not _DICT:
        return None
    for key in values:
        if _TYPE(key) is not _STR:
            return None
    return values


def _class_dict(cls: object) -> MappingProxyType | None:
    if _TYPE(cls) is not _TYPE:
        return None
    values = _TYPE.__getattribute__(cls, "__dict__")
    if _TYPE(values) is not MappingProxyType:
        return None
    for key in values:
        if _TYPE(key) is not _STR:
            return None
    return values


def _text(value: object, expected: str) -> bool:
    return _TYPE(value) is _STR and value == expected


def _native(function: object, owner: object, name: str) -> bool:
    return (
        _TYPE(function) is BuiltinFunctionType
        and function.__self__ is owner
        and _text(function.__name__, name)
    )


def _native_class(cls: object, name: str, module: str) -> bool:
    if _TYPE(cls) is not _TYPE:
        return False
    flags = _TYPE.__getattribute__(cls, "__flags__")
    return (
        flags & _IMMUTABLE != 0
        and flags & _HEAP == 0
        and _text(_TYPE.__getattribute__(cls, "__name__"), name)
        and _text(_TYPE.__getattribute__(cls, "__module__"), module)
    )


def _member(value: object, owner: object, name: str) -> bool:
    return (
        _TYPE(value) is MemberDescriptorType
        and value.__objclass__ is owner
        and _text(value.__name__, name)
    )


def _builtin_state(values: dict[str, object]) -> bool:
    identities = {
        "type": _TYPE, "object": _OBJECT, "str": _STR, "int": _INT,
        "bool": _BOOL, "bytes": _BYTES, "tuple": _TUPLE, "list": _LIST,
        "dict": _DICT, "set": _SET,
    }
    for name, value in identities.items():
        if values.get(name) is not value:
            return False
    for name in ("len", "isinstance", "getattr", "all", "any"):
        if not _native(values.get(name), builtins, name):
            return False
    for name in (
        "super", "property", "classmethod", "staticmethod", "range", "zip", "map",
        "AttributeError", "OSError", "RuntimeError", "ValueError",
        "TypeError", "FileNotFoundError", "BytesWarning",
    ):
        if not _native_class(values.get(name), name, "builtins"):
            return False
    error_values = _class_dict(values["OSError"])
    if error_values is None:
        return False
    return all(
        _member(error_values.get(name), values["OSError"], name)
        for name in ("errno", "filename", "filename2", "strerror")
    )


def _stat_result(values: dict[str, object]) -> bool:
    cls = values.get("stat_result")
    raw = _class_dict(cls)
    if raw is None:
        return False
    flags = _TYPE.__getattribute__(cls, "__flags__")
    if flags & _HEAP == 0 or flags & _BASETYPE:
        return False
    if not _same_items(_TYPE.__getattribute__(cls, "__mro__"), (cls, _TUPLE, _OBJECT)):
        return False
    if not _text(raw.get("__module__"), "os"):
        return False
    if not _text(_TYPE.__getattribute__(cls, "__name__"), "stat_result"):
        return False
    if not _native(raw.get("__new__"), cls, "__new__"):
        return False
    if any(name in raw for name in (
        "__getattribute__", "__getattr__", "__setattr__", "__delattr__",
        "__del__", "__dict__", "__weakref__",
    )):
        return False
    required = {
        "st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size",
        "st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns", "st_ctime_ns",
    }
    optional = {
        "st_blksize", "st_blocks", "st_rdev", "st_flags", "st_gen",
        "st_birthtime", "st_birthtime_ns", "st_file_attributes", "st_fstype", "st_reparse_tag",
    }
    fields = {name for name in raw if name.startswith("st_")}
    if not required <= fields or not fields <= required | optional:
        return False
    if any(not _member(raw[name], cls, name) for name in fields):
        return False
    return (
        _TYPE(raw.get("n_sequence_fields")) is _INT and raw["n_sequence_fields"] == 10
        and _TYPE(raw.get("n_unnamed_fields")) is _INT and raw["n_unnamed_fields"] == 3
        and _TYPE(raw.get("n_fields")) is _INT and raw["n_fields"] == len(fields) + 3
    )


def _signal_state(values: dict[str, object]) -> bool:
    for name in ("valid_signals", "getsignal", "default_int_handler"):
        if not _native(values.get(name), _signal, name):
            return False
    for name, expected in (("SIG_DFL", 0), ("SIG_IGN", 1)):
        if _TYPE(values.get(name)) is not _INT or values[name] != expected:
            return False
    numbers = values["valid_signals"]()
    if _TYPE(numbers) is not _SET or len(numbers) > 128:
        return False
    for number in numbers:
        if _TYPE(number) is not _INT or not 0 < number < 128:
            return False
        handler = values["getsignal"](number)
        if handler is values["default_int_handler"]:
            continue
        if _TYPE(handler) is _INT and handler in (0, 1):
            continue
        return False
    return True


def _match(
    declarations: dict[str, SourceDeclarations], module: ModuleType,
    name: str, value: object, closure: tuple[object, ...] = (),
) -> bool:
    module_values = _namespace(module)
    if module_values is None:
        return False
    name_value = module_values.get("__name__")
    if _TYPE(name_value) is not _STR:
        return False
    declaration = declarations.get(name_value)
    return (
        _TYPE(declaration) is SourceDeclarations
        and SourceDeclarations.matches(declaration, value, module, name, closure=closure)
    )


def _path_classes(declarations: dict[str, SourceDeclarations], values: dict[str, object]) -> bool:
    pure = values.get("PurePath")
    pure_posix = values.get("PurePosixPath")
    concrete = values.get("Path")
    concrete_posix = values.get("PosixPath")
    classes = (pure, pure_posix, concrete, concrete_posix)
    maps = tuple(_class_dict(cls) for cls in classes)
    if any(raw is None for raw in maps):
        return False
    bases = ((_OBJECT,), (pure,), (pure,), (concrete, pure_posix))
    mros = (
        (pure, _OBJECT), (pure_posix, pure, _OBJECT),
        (concrete, pure, _OBJECT), (concrete_posix, concrete, pure_posix, pure, _OBJECT),
    )
    for cls, raw, expected_bases, expected_mro in zip(classes, maps, bases, mros, strict=True):
        if not _same_items(_TYPE.__getattribute__(cls, "__bases__"), expected_bases):
            return False
        if not _same_items(_TYPE.__getattribute__(cls, "__mro__"), expected_mro):
            return False
        if any(name in raw for name in (
            "__getattribute__", "__getattr__", "__setattr__", "__delattr__",
            "__del__", "__bool__", "__len__", "__dict__", "__weakref__",
        )):
            return False
    pure_values, posix_values, path_values, instance_values = maps
    slots = pure_values.get("__slots__")
    if _TYPE(slots) is not _TUPLE or any(_TYPE(name) is not _STR for name in slots):
        return False
    if slots != _PATH_SLOTS:
        return False
    if any(not _member(pure_values.get(name), pure, name) for name in _PATH_SLOTS):
        return False
    for raw in maps[1:]:
        if _TYPE(raw.get("__slots__")) is not _TUPLE or len(raw["__slots__"]) != 0:
            return False
    if pure_values.get("_flavour") is not posixpath or posix_values.get("_flavour") is not posixpath:
        return False
    if any(name in path_values or name in instance_values for name in ("_flavour",)):
        return False
    pure_methods = (
        "__init__", "with_segments", "_load_parts", "__str__", "__fspath__", "is_absolute",
    )
    path_methods = ("expanduser", "absolute", "resolve", "stat")
    for name in pure_methods:
        if not _match(declarations, pathlib, "PurePath." + name, pure_values.get(name)):
            return False
    for name in path_methods:
        if not _match(declarations, pathlib, "Path." + name, path_values.get(name)):
            return False
    if not _match(declarations, pathlib, "Path.__init__", path_values.get("__init__"), (concrete,)):
        return False
    for cls_name, raw in (("PurePath", pure_values), ("Path", path_values)):
        value = raw.get("__new__")
        if _TYPE(value) is not staticmethod:
            return False
        if not _match(declarations, pathlib, cls_name + ".__new__", value.__func__):
            return False
    for name in ("_parse_path", "_format_parsed_parts"):
        value = pure_values.get(name)
        if _TYPE(value) is not classmethod:
            return False
        if not _match(declarations, pathlib, "PurePath." + name, value.__func__):
            return False
    for name in ("drive", "root", "_tail", "name"):
        value = pure_values.get(name)
        if _TYPE(value) is not property or value.fset is not None or value.fdel is not None:
            return False
        if not _match(declarations, pathlib, "PurePath." + name, value.fget):
            return False
    reached = set(pure_methods + path_methods + (
        "__new__", "__init__", "_parse_path", "_format_parsed_parts",
        "drive", "root", "_tail", "name", *_PATH_SLOTS,
    ))
    if any(name in posix_values or name in instance_values for name in reached):
        return False
    inherited = set(pure_methods + (
        "_parse_path", "_format_parsed_parts", "drive", "root", "_tail", "name", *_PATH_SLOTS,
    )) - {"__init__"}
    if any(name in path_values for name in inherited):
        return False
    return True


def _check_path_providers(declarations: dict[str, SourceDeclarations]) -> bool:
    builtin_values = _namespace(builtins)
    if builtin_values is None or not _builtin_state(builtin_values):
        return False
    if _TYPE(declarations) is not _DICT or any(_TYPE(key) is not _STR for key in declarations):
        return False
    modules = (builtins, sys, os, posix, pathlib, posixpath, _stat, _signal, errno)
    namespaces = tuple(_namespace(module) for module in modules)
    if any(values is None for values in namespaces):
        return False
    bv, sv, ov, pv, lv, ppv, stv, sigv, ev = namespaces
    if not _builtin_state(bv):
        return False
    version = sv.get("version_info")
    if not _native_class(_TYPE(version), "version_info", "sys"):
        return False
    parts = tuple(_TUPLE.__getitem__(version, index) for index in range(3))
    if any(_TYPE(part) is not _INT for part in parts) or parts not in ((3, 12, 13), (3, 12, 14)):
        return False
    platform = sv.get("platform")
    if not _text(platform, "linux") and not _text(platform, "darwin"):
        return False
    if not _text(ov.get("name"), "posix") or ov.get("path") is not posixpath:
        return False
    for name in ("intern", "getfilesystemencoding", "getfilesystemencodeerrors"):
        if not _native(sv.get(name), sys, name):
            return False
    if not _text(sv["getfilesystemencoding"](), "utf-8"):
        return False
    if not _text(sv["getfilesystemencodeerrors"](), "surrogateescape"):
        return False
    for name in ("fspath", "stat", "lstat", "readlink", "getcwd"):
        if not _native(pv.get(name), posix, name) or ov.get(name) is not pv[name]:
            return False
    if not _native(pv.get("_path_normpath"), posix, "_path_normpath"):
        return False
    if ppv.get("normpath") is not pv["_path_normpath"]:
        return False
    if not _native(stv.get("S_ISLNK"), _stat, "S_ISLNK"):
        return False
    stat_values = _namespace(ppv.get("stat"))
    if stat_values is None or stat_values.get("S_ISLNK") is not stv["S_ISLNK"]:
        return False
    if not _stat_result(pv) or ov.get("stat_result") is not pv.get("stat_result"):
        return False
    if not _signal_state(sigv):
        return False
    if any(lv.get(name) is not value for name, value in (
        ("os", os), ("sys", sys), ("posixpath", posixpath),
    )):
        return False
    if ppv.get("os") is not os or lv.get("ntpath") is posixpath:
        return False
    for namespace in (lv, ppv):
        for name in (
            "type", "object", "str", "bytes", "bool", "len", "isinstance", "getattr", "map",
            "super", "AttributeError", "OSError", "RuntimeError", "TypeError",
            "FileNotFoundError", "BytesWarning",
        ):
            if name in namespace and namespace[name] is not bv[name]:
                return False
    if not _text(ppv.get("sep"), "/") or ppv.get("altsep") is not None:
        return False
    if ppv.get("ALLOW_MISSING") is False:
        return False
    expected_eloop = 40 if platform == "linux" else 62
    if _TYPE(ev.get("ELOOP")) is not _INT or ev["ELOOP"] != expected_eloop:
        return False
    if _TYPE(lv.get("ELOOP")) is not _INT or lv["ELOOP"] != expected_eloop:
        return False
    if _TYPE(lv.get("_WINERROR_CANT_RESOLVE_FILENAME")) is not _INT:
        return False
    if lv["_WINERROR_CANT_RESOLVE_FILENAME"] != 1921:
        return False
    for name in (
        "realpath", "_joinrealpath", "abspath", "isabs", "_get_sep",
        "join", "split", "splitroot",
    ):
        if not _match(declarations, posixpath, name, ppv.get(name)):
            return False
    return _path_classes(declarations, lv)


def check_path_providers(declarations: dict[str, SourceDeclarations]) -> bool:
    """Admit only the pinned CPython POSIX closure, never filesystem facts."""
    try:
        return _check_path_providers(declarations)
    except (AttributeError, OSError, TypeError, ValueError):
        return False
