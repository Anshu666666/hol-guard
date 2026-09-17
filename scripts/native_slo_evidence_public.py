"""Dependency-free atomic publication of bounded, explicitly public receipts."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from scripts.native_slo_evidence_files import _plain_path, atomic_exclusive
from scripts.native_slo_evidence_format import require


def _windows_api() -> tuple[Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
    return kernel, create, close


@contextmanager
def _windows_ancestry(path: Path) -> Iterator[None]:
    import ctypes

    _, create, close = _windows_api()
    with ExitStack() as stack:
        for component in reversed((path, *path.parents)):
            before = component.lstat()
            handle = create(str(component), 0x80, 0x3, None, 3, 0x02200000, None)
            require(handle not in (None, ctypes.c_void_p(-1).value), "archive_path_invalid")
            stack.callback(close, handle)
            _plain_path(component)
            after = component.lstat()
            require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "archive_source_changed")
        yield


def _rename_public_handle(handle: Any, destination: Path, parent_identity: tuple[int, int]) -> None:
    """Same NT exclusive handle rename as Guard state, with stdlib-only ABI."""
    import ctypes
    from ctypes import wintypes

    class RenameInfo(ctypes.Structure):
        _fields_ = [
            ("replace", ctypes.c_ubyte),
            ("root", wintypes.HANDLE),
            ("length", wintypes.DWORD),
            ("name", wintypes.WCHAR * 1),
        ]

    class StatusBlock(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

    # Bind a root directory handle plus one basename; no ad-hoc DOS/UNC
    # namespace conversion and no path-selected source.
    name = destination.name.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(ctypes.sizeof(RenameInfo) + len(name))
    info = ctypes.cast(buffer, ctypes.POINTER(RenameInfo)).contents
    info.replace, info.length = 0, len(name)
    ctypes.memmove(ctypes.addressof(buffer) + RenameInfo.name.offset, name, len(name))
    native = ctypes.WinDLL("ntdll", use_last_error=True)
    rename = native.NtSetInformationFile
    rename.argtypes = [wintypes.HANDLE, ctypes.POINTER(StatusBlock), ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    rename.restype = ctypes.c_long
    _, create, close = _windows_api()
    _plain_path(destination.parent)
    before = destination.parent.lstat()
    require((before.st_dev, before.st_ino) == parent_identity, "archive_source_changed")
    root = create(str(destination.parent), 0xA0, 0x7, None, 3, 0x02200000, None)
    require(root not in (None, ctypes.c_void_p(-1).value), "archive_path_invalid")
    try:
        _plain_path(destination.parent)
        bound = destination.parent.lstat()
        require((bound.st_dev, bound.st_ino) == parent_identity, "archive_source_changed")
        info.root = root
        status = rename(handle, ctypes.byref(StatusBlock()), buffer, ctypes.sizeof(buffer), 10)
        require(status >= 0, "archive_output_failed")
        _plain_path(destination.parent)
        after = destination.parent.lstat()
        require((after.st_dev, after.st_ino) == parent_identity, "archive_source_changed")
    finally:
        close(root)


def _windows_public_write(path: Path, data: bytes) -> None:
    import ctypes
    import msvcrt

    _, create, close = _windows_api()
    temporary = path.parent / f".receipt-{secrets.token_hex(16)}.tmp"
    handle = None
    transferred = False
    descriptor = None
    try:
        # Pin the immediate parent throughout creation and writing, then bind
        # a share-delete parent handle for the exclusive NT rename while the
        # source handle still denies all foreign writes and deletes.
        with _windows_ancestry(path.parent):
            parent = path.parent.lstat()
            parent_identity = (parent.st_dev, parent.st_ino)
            handle = create(str(temporary), 0xC0010000, 0x1, None, 1, 0x80200000, None)
            require(handle not in (None, ctypes.c_void_p(-1).value), "archive_output_failed")
            descriptor = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            transferred = True
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, "archive_output_failed")
                view = view[written:]
            os.fsync(descriptor)
        _rename_public_handle(handle, path, parent_identity)
    finally:
        if transferred and descriptor is not None:
            os.close(descriptor)
        elif handle not in (None, ctypes.c_void_p(-1).value):
            close(handle)
    # Failed output may retain a temporary containing only this fixed public
    # receipt, outside upload patterns. Never delete an unbound pathname.


def publish_receipt(path: Path, data: bytes) -> None:
    """Publish only a bounded fixed-schema public receipt, never plaintext data."""
    require(len(data) <= 4096, "archive_bounds_exceeded")
    if os.name != "nt":
        atomic_exclusive(path, data)
        return
    path = _plain_path(path)
    missing: list[Path] = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        require(len(missing) <= 8, "archive_path_invalid")
        parent = parent.parent
    for child in reversed(missing):
        with _windows_ancestry(child.parent):
            child.mkdir()
    # Keep all ancestors above the immediate parent pinned. The source file is
    # pinned throughout rename; NT rename needs share-delete on its parent.
    with _windows_ancestry(path.parent.parent):
        _plain_path(path.parent)
        _windows_public_write(path, data)
