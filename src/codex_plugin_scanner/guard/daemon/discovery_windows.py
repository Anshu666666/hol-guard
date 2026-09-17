"""Windows discovery producers: private creation without repairing existing authority."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .. import native_policy_snapshot as api
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..native_policy_snapshot_windows_state import (
    _windows_close_directory_binding,
    _windows_create_directory,
    _WindowsDirectoryBinding,
)


@contextmanager
def _directory_binding(path: Path, *, verify_existing: bool) -> Iterator[_WindowsDirectoryBinding]:
    """Retain no-reparse ancestry; create missing directories with private ACLs."""

    absolute = Path(os.path.abspath(path))
    if not absolute.anchor or absolute == Path(absolute.anchor):
        raise NativePolicySnapshotError("native_policy_windows_state_directory_invalid")
    binding = _WindowsDirectoryBinding(absolute, [])
    with api._windows_private_descriptor(True) as (_advapi32, descriptor, _dacl, owner_sid):
        try:
            current = Path(absolute.anchor)
            kernel32, handle, _information = api._windows_open_handle(current, directory=True, lock=True)
            binding.handles.append((kernel32, handle))
            for part in absolute.parts[1:]:
                current /= part
                created = _windows_create_directory(current, descriptor, api)
                kernel32, handle, _information = api._windows_open_handle(
                    current, directory=True, lock=True, add_file=current == absolute
                )
                binding.handles.append((kernel32, handle))
                if created or (verify_existing and current == absolute):
                    api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
            yield binding
        finally:
            _windows_close_directory_binding(binding, api)


def create_private_directory_if_missing(path: Path) -> None:
    """Preserve existing-directory behavior; new directories are private at birth.

    Generic setup callers neither accept discovery authority nor repair legacy
    directories. The producer independently verifies its parent before writing.
    """

    if path.is_dir():
        return
    with _directory_binding(path, verify_existing=False):
        pass


def _write(path: Path, payload: bytes, *, replace_existing: bool, maximum_bytes: int) -> None:
    with _directory_binding(path.parent, verify_existing=True) as binding:
        api._windows_write_private_file_atomic(
            parent_path=binding.path,
            parent_handle=binding.handle,
            directory_handles=binding.handles,
            temporary_name=f".{path.name}.{secrets.token_hex(16)}.tmp",
            destination_name=path.name,
            payload=payload,
            maximum_bytes=maximum_bytes,
            kind="daemon_discovery",
            replace_existing=replace_existing,
            repair_destination=False,
        )


def create_discovery_key(path: Path, payload: bytes) -> None:
    """Publish a complete private key exclusively; never touch an existing key."""

    _write(path, payload, replace_existing=False, maximum_bytes=256)


def replace_discovery_state(path: Path, text: str) -> None:
    """Replace the whole state; preserve Windows text-mode UTF-8/CRLF bytes."""

    _write(path, text.replace("\n", "\r\n").encode("utf-8"), replace_existing=True, maximum_bytes=64 * 1024)
