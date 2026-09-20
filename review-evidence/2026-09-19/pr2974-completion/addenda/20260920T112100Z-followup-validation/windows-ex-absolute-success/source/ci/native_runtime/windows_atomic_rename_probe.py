"""Source-only probe of one Windows POSIX rename after the original writer closes.

This is a validation prototype, not a product replacement API. The caller owns
the original same-directory temporary file, snapshots its real descriptor after
flush/fsync, then closes that descriptor before calling replace_once.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import windows_replaceable_file as reader

_DELETE = 0x00010000
_READ_ATTRIBUTES = 0x00000080
_TRAVERSE = 0x00000020
_BACKUP_SEMANTICS = 0x02000000
_FILE_RENAME_INFO_EX = 22
_REPLACE_WITH_POSIX_SEMANTICS = 3
_DIRECTORY = 0x10
_REPARSE_POINT = 0x400


class _RenameInfo(ctypes.Structure):
    # The SDK has one union at offset zero, not a second BOOLEAN field.
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


@dataclass(frozen=True)
class SourceIdentity:
    volume: int
    index_high: int
    index_low: int
    size_high: int
    size_low: int


def _api() -> Any:
    api = reader._file_api()
    api.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    api.SetFileInformationByHandle.restype = wintypes.BOOL
    api.GetHandleInformation.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    api.GetHandleInformation.restype = wintypes.BOOL
    return api


def _error(source: str, destination: str) -> OSError:
    # Borrow GetLastError before formatting or any cleanup can overwrite it.
    code = ctypes.get_last_error()
    error = ctypes.WinError(code)
    return OSError(error.errno, error.strerror, source, code, destination)


def _information(api: Any, handle: int, *, directory: bool, source: str, destination: str) -> Any:
    information = reader._WindowsByHandleFileInformation()
    if not api.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise _error(source, destination)
    attributes = int(information.dwFileAttributes)
    if bool(attributes & _DIRECTORY) != directory or attributes & _REPARSE_POINT:
        raise OSError("probe_opened_object_type_invalid")
    reader._require_disk(api, handle)
    inherited = wintypes.DWORD()
    if not api.GetHandleInformation(handle, ctypes.byref(inherited)):
        raise _error(source, destination)
    if inherited.value & 1:
        raise OSError("probe_handle_inherited")
    return information


def _identity(information: Any) -> SourceIdentity:
    return SourceIdentity(
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
        int(information.nFileSizeHigh),
        int(information.nFileSizeLow),
    )


def snapshot_descriptor(descriptor: int) -> SourceIdentity:
    """Bind the already flushed original writer handle before its original close."""

    if os.name != "nt":
        raise OSError("probe_requires_windows")
    native = int(importlib.import_module("msvcrt").get_osfhandle(descriptor))
    information = _information(_api(), native, directory=False, source="", destination="")
    return _identity(information)


def _names(source: Path, destination: Path) -> tuple[str, str]:
    if os.name != "nt":
        raise OSError("probe_requires_windows")
    if not source.is_absolute() or not destination.is_absolute() or source.parent != destination.parent:
        raise ValueError("probe_requires_absolute_same_directory_paths")
    if source == destination or not destination.name or ":" in destination.name:
        raise ValueError("probe_target_name_invalid")
    names = os.fspath(source), os.fspath(destination)
    for name in names:
        if "\0" in name or len(name.encode("utf-16-le", errors="surrogatepass")) // 2 > 32767:
            raise ValueError("probe_path_invalid")
    return names


def _open(api: Any, path: str, access: int, sharing: int, attributes: int, names: tuple[str, str]) -> int:
    handle = api.CreateFileW(path, access, sharing, None, reader._OPEN_EXISTING, attributes, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise _error(*names)
    return int(handle)


def _rename_buffer(destination: Path, _parent: int) -> ctypes.Array[ctypes.c_char]:
    encoded = os.fspath(destination).encode("utf-16-le", errors="surrogatepass")
    buffer = ctypes.create_string_buffer(ctypes.sizeof(_RenameInfo) + len(encoded) + 2)
    information = _RenameInfo.from_buffer(buffer)
    information.Flags = _REPLACE_WITH_POSIX_SEMANTICS
    information.RootDirectory = None
    information.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + _RenameInfo.FileName.offset, encoded, len(encoded))
    return buffer


def replace_once(source: Path, destination: Path, expected: SourceIdentity) -> None:
    """Attempt one bound rename with no retry, legacy fallback or ACL mutation."""

    names = _names(source, destination)
    sys.audit("os.rename", *names, -1, -1)
    api = _api()
    parent = native = None
    failure = None
    try:
        parent = _open(
            api,
            str(source.parent),
            _READ_ATTRIBUTES | _TRAVERSE,
            3,
            _BACKUP_SEMANTICS | reader._OPEN_REPARSE_POINT,
            names,
        )
        parent_info = _information(api, parent, directory=True, source=names[0], destination=names[1])
        native = _open(
            api,
            names[0],
            _DELETE | _READ_ATTRIBUTES,
            reader._SHARE_READ_WRITE_DELETE,
            reader._OPEN_REPARSE_POINT,
            names,
        )
        current = _information(api, native, directory=False, source=names[0], destination=names[1])
        if _identity(current) != expected or int(parent_info.dwVolumeSerialNumber) != expected.volume:
            raise OSError("probe_source_identity_changed")
        buffer = _rename_buffer(destination, parent)
        if not api.SetFileInformationByHandle(native, _FILE_RENAME_INFO_EX, buffer, ctypes.sizeof(buffer)):
            raise _error(*names)
    except BaseException as error:
        failure = error
    finally:
        for handle in (native, parent):
            if handle is None:
                continue
            try:
                if not api.CloseHandle(handle):
                    raise _error(*names)
            except BaseException as cleanup_error:
                if failure is None:
                    failure = cleanup_error
                else:
                    failure.add_note("probe_native_handle_close_failed")
    if failure is not None:
        raise failure
