"""Reuse Guard's reviewed Windows descriptor/handle contract for archive I/O."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from scripts.native_slo_evidence_format import require


def _api() -> Any:
    # These are filesystem-only operations: current-user SID, protected DACL,
    # no-reparse handles and owner validation. No secret store is consulted.
    from codex_plugin_scanner.guard import native_policy_snapshot

    return native_policy_snapshot


@contextmanager
def hold_directory(path: Path) -> Iterator[list[tuple[Any, Any]]]:
    api = _api()
    with ExitStack() as stack:
        handles: list[tuple[Any, Any]] = []
        for component in reversed((path, *path.parents)):
            kernel, handle, _ = api._windows_open_handle(component, directory=True, lock=True)
            handles.append((kernel, handle))

        def close_remaining() -> None:
            for kernel, handle in reversed(handles):
                api._windows_close_handle(kernel, handle)

        stack.callback(close_remaining)
        yield handles


def create_directory(path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_windows_state import _windows_create_directory

    api = _api()
    with api._windows_private_descriptor(True) as (_, descriptor, _, owner):
        if not _windows_create_directory(path, descriptor, api):
            raise FileExistsError("archive_output_exists")
        kernel, handle, _ = api._windows_open_handle(path, directory=True, lock=True)
        try:
            api._windows_verify_private_dacl(handle, owner_sid=owner, directory=True)
        finally:
            api._windows_close_handle(kernel, handle)


def _descriptor(handle: Any, flags: int) -> int:
    import msvcrt

    value = getattr(handle, "value", handle)
    return msvcrt.open_osfhandle(value, flags | os.O_BINARY)


def write_private_file(path: Path, content: bytes) -> os.stat_result:
    api = _api()
    with api._windows_private_descriptor(False) as (_, security, _, owner):
        kernel, handle, _ = api._windows_open_handle(path, directory=False, create_new=True, descriptor=security)
        transferred = False
        try:
            api._windows_verify_private_dacl(handle, owner_sid=owner, directory=False)
            descriptor = _descriptor(handle, os.O_WRONLY)
            transferred = True
            try:
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view[:65536])
                    require(written > 0, "archive_output_failed")
                    view = view[written:]
                os.fsync(descriptor)
                return os.fstat(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if not transferred:
                api._windows_close_handle(kernel, handle)


def read_handle(path: Path, maximum: int, *, private: bool) -> tuple[bytes, os.stat_result]:
    """Withhold write/delete sharing while reading; never follow a reparse point."""
    import ctypes
    from ctypes import wintypes

    api = _api()
    kernel = api._windows_dll("kernel32")
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
    handle = create(str(path), 0x80000000, 0x1, None, 3, 0x00200000, None)
    require(handle not in (None, ctypes.c_void_p(-1).value), "archive_file_invalid")
    transferred = False
    try:
        if private:
            api._windows_verify_private_dacl(handle, owner_sid=api._windows_owner_sid(), directory=False)
        else:
            api._windows_verify_private_owner(handle, owner_sid=api._windows_owner_sid())
        descriptor = _descriptor(handle, os.O_RDONLY)
        transferred = True
        try:
            from scripts.native_slo_evidence_files import _file, fingerprint

            before = os.fstat(descriptor)
            _file(before, maximum, private=private)
            chunks: list[bytes] = []
            count = 0
            while True:
                chunk = os.read(descriptor, min(65536, maximum + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                require(count <= maximum, "archive_bounds_exceeded")
            after = os.fstat(descriptor)
            require(fingerprint(before) == fingerprint(after), "archive_source_changed")
            return b"".join(chunks), after
        finally:
            os.close(descriptor)
    finally:
        if not transferred:
            api._windows_close_handle(kernel, handle)


def atomic_private_file(path: Path, content: bytes) -> None:
    """Publish through the still-open source handle, never a temporary pathname."""
    import secrets
    from contextlib import suppress

    from codex_plugin_scanner.guard.native_policy_snapshot_windows_atomic import (
        _windows_delete_file_handle,
        _windows_rename_releasing_barrier,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_windows_support import _windows_write_chunks_and_flush

    api = _api()
    with hold_directory(path.parent) as handles, api._windows_private_descriptor(False) as (_, security, _, owner):
        temporary = path.parent / f".evidence-{secrets.token_hex(16)}.tmp"
        kernel, handle, _ = api._windows_open_handle(
            temporary,
            directory=False,
            create_new=True,
            descriptor=security,
            rename_source=True,
        )
        renamed = False
        try:
            api._windows_verify_private_dacl(handle, owner_sid=owner, directory=False)
            _windows_write_chunks_and_flush(kernel, handle, content)
            # Do not run the state replacement helper: it repairs an
            # existing target DACL. Archive publication must never modify
            # an existing destination, including its permissions.
            _windows_rename_releasing_barrier(
                api=api,
                kernel32=kernel,
                source_handle=handle,
                parent_path=path.parent,
                parent_handle=handles[-1][1],
                destination_name=path.name,
                replace_existing=False,
                directory_handles=handles,
            )
            renamed = True
        finally:
            if not renamed:
                with suppress(Exception):
                    _windows_delete_file_handle(kernel, handle)
            api._windows_close_handle(kernel, handle)
