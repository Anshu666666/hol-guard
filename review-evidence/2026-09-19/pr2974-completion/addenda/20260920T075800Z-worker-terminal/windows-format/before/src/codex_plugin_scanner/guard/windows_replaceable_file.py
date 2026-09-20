"""Read-only Windows handles for authority files replaced by their owner.

Sharing permits another authorized handle to replace the file. It grants this
handle no write or delete access. Callers retain their existing path, ownership,
privacy, size, identity, and content checks.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import sys
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Any

from .windows_paths import _WindowsByHandleFileInformation

_GENERIC_READ = 0x80000000
_SHARE_READ_WRITE_DELETE = 0x00000007
_OPEN_EXISTING = 3
_OPEN_REPARSE_POINT = 0x00200000
_DIRECTORY_OR_REPARSE = 0x00000010 | 0x00000400
_FILE_TYPE_DISK = 1


@lru_cache(maxsize=1)
def _file_api() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("windows_replaceable_read_unavailable")
    api = win_dll("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    api.CreateFileW.restype = wintypes.HANDLE
    api.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_WindowsByHandleFileInformation),
    ]
    api.GetFileInformationByHandle.restype = wintypes.BOOL
    api.GetFileType.argtypes = [wintypes.HANDLE]
    api.GetFileType.restype = wintypes.DWORD
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api


def _windows_error() -> OSError:
    get_error = getattr(ctypes, "get_last_error", None)
    make_error = getattr(ctypes, "WinError", None)
    if get_error is None or make_error is None:
        return OSError("windows_replaceable_read_unavailable")
    return make_error(get_error())


def _validated_name(path: Path | str, flags: int) -> str:
    if os.name != "nt":
        raise OSError("windows_replaceable_read_unavailable")
    allowed = (
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    if type(flags) is not int or flags < 0 or flags & ~allowed:
        raise ValueError("replaceable_descriptor_must_be_read_only")
    name = os.fspath(path)
    if not isinstance(name, str):
        raise TypeError("replaceable_descriptor_requires_text_path")
    if "\0" in name:
        raise ValueError("embedded null character in path")
    if len(name.encode("utf-16-le", errors="surrogatepass")) // 2 > 32767:
        raise ValueError("path too long for Windows")
    return name


def _transfer_descriptor(handle: int) -> int:
    msvcrt = importlib.import_module("msvcrt")
    return int(msvcrt.open_osfhandle(
        handle, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
    ))


def _require_disk(api: Any, handle: int) -> None:
    set_error = getattr(ctypes, "set_last_error", None)
    if set_error is None:
        raise OSError("windows_replaceable_read_unavailable")
    set_error(0)
    file_type = api.GetFileType(handle)
    if file_type == 0:
        error = _windows_error()
        if getattr(error, "winerror", 0):
            raise error
    if file_type != _FILE_TYPE_DISK:
        raise OSError("windows_replaceable_read_not_disk")


def _open_descriptor(name: str) -> int:
    api = _file_api()
    handle = api.CreateFileW(
        name, _GENERIC_READ, _SHARE_READ_WRITE_DELETE, None,
        _OPEN_EXISTING, _OPEN_REPARSE_POINT, None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise _windows_error()
    try:
        information = _WindowsByHandleFileInformation()
        if not api.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise _windows_error()
        if int(information.dwFileAttributes) & _DIRECTORY_OR_REPARSE:
            raise OSError("windows_replaceable_read_not_regular")
        _require_disk(api, handle)
        descriptor = _transfer_descriptor(handle)
        if descriptor < 0:
            raise OSError("windows_replaceable_read_descriptor_invalid")
    except BaseException as error:
        try:
            if not api.CloseHandle(handle):
                raise _windows_error()
        except BaseException:
            error.add_note("windows_replaceable_read_close_failed")
        raise
    # open_osfhandle transferred ownership; the caller closes the CRT descriptor.
    return descriptor


def open_replaceable_read_descriptor(path: Path | str, flags: int) -> int:
    """Match the bounded os.open audit event before the single native open."""

    name = _validated_name(path, flags)
    sys.audit("open", name, None, flags | getattr(os, "O_NOINHERIT", 0))
    return _open_descriptor(name)


def _text_opener(path: str, flags: int) -> int:
    # FileIO emitted its original open event before invoking this callback.
    return _open_descriptor(_validated_name(path, flags))


def read_replaceable_text(path: Path) -> str:
    """Keep TextIO's UTF-8, newline, audit, and descriptor ownership behavior."""

    with open(path, encoding="utf-8", opener=_text_opener) as handle:
        return handle.read()
