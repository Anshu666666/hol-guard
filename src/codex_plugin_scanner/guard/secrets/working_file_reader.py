"""Bounded, identity-checked bytes for the offline working-tree scanner.

Normal declared skips remain skips. A failure after admitting a regular input
is incomplete coverage, never a successfully scanned empty document. Hardlinks
are valid inputs; each path still receives its own detector context/findings.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from ..file_identity import full_stat_identity

_CHUNK_BYTES = 64 * 1024


class WorkingFileReadError(OSError):
    """A previously admitted input could not be read with stable identity."""


def _shared_identity(value: os.stat_result) -> tuple[int, ...]:
    # Windows path stat and CRT fstat have different ctime domains. Compare
    # ctime/attributes only within the same metadata source, never across them.
    return value.st_dev, value.st_ino, value.st_nlink, value.st_size, value.st_mtime_ns


def _directory_identity(value: os.stat_result) -> tuple[int, int, int]:
    # Sibling writes legitimately change a directory's timestamps and size.
    return value.st_dev, value.st_ino, value.st_mode


def _final_path_matches(path: Path, before: os.stat_result, opened: os.stat_result) -> bool:
    if os.name != "nt":
        return full_stat_identity(path.lstat()) == full_stat_identity(before)
    from ..windows_paths import open_windows_locked_regular_descriptor

    # A fresh compatible handle binds the final path to the retained file in
    # the same descriptor metadata domain, including its complete timestamps.
    descriptor = open_windows_locked_regular_descriptor(path)
    try:
        return full_stat_identity(os.fstat(descriptor)) == full_stat_identity(opened)
    finally:
        os.close(descriptor)


@contextmanager
def _open_regular(root: Path, path: Path, root_before: os.stat_result) -> Generator[int, None, None]:
    with ExitStack() as cleanup:
        directories: list[tuple[int, Path, tuple[int, int, int]]] = []
        if os.name == "nt":
            from ..windows_paths import open_windows_locked_regular_descriptor

            descriptor = open_windows_locked_regular_descriptor(path)
        else:
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            parent = os.open(root, flags | os.O_DIRECTORY)
            _ = cleanup.callback(os.close, parent)
            current = root
            identity = _directory_identity(os.fstat(parent))
            if identity != _directory_identity(root_before):
                raise WorkingFileReadError("working_tree_file_unavailable_or_changed")
            directories.append((parent, current, identity))
            relative = path.relative_to(root)
            for part in relative.parts[:-1]:
                current /= part
                parent = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                _ = cleanup.callback(os.close, parent)
                directories.append((parent, current, _directory_identity(os.fstat(parent))))
            descriptor = os.open(relative.name, flags, dir_fd=parent)
        _ = cleanup.callback(os.close, descriptor)
        yield descriptor
        for directory, location, identity in directories:
            if (
                _directory_identity(os.fstat(directory)) != identity
                or _directory_identity(location.lstat()) != identity
            ):
                raise WorkingFileReadError("working_tree_file_unavailable_or_changed")


def read_working_bytes(root: Path, relative_path: str, max_bytes: int) -> bytes | None:
    """Return stable bytes, preserve initial exclusions, or raise incomplete."""
    candidate = root / relative_path
    try:
        resolved_root = root.resolve(strict=True)
        root_before = resolved_root.stat()
        resolved = candidate.resolve(strict=True)
        _ = resolved.relative_to(resolved_root)
        before = resolved.lstat()
    except (OSError, ValueError, RuntimeError):
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
        return None
    try:
        with _open_regular(resolved_root, resolved, root_before) as descriptor:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _shared_identity(opened) != _shared_identity(before):
                raise WorkingFileReadError("working_tree_file_unavailable_or_changed")
            chunks: list[bytes] = []
            consumed = 0
            while consumed <= max_bytes:
                chunk = os.read(descriptor, min(_CHUNK_BYTES, max_bytes + 1 - consumed))
                if not chunk:
                    break
                chunks.append(chunk)
                consumed += len(chunk)
            if (
                consumed > max_bytes
                or consumed != opened.st_size
                or full_stat_identity(os.fstat(descriptor)) != full_stat_identity(opened)
                or not _final_path_matches(resolved, before, opened)
                or candidate.resolve(strict=True) != resolved
                or root.resolve(strict=True) != resolved_root
                or _directory_identity(resolved_root.stat()) != _directory_identity(root_before)
            ):
                raise WorkingFileReadError("working_tree_file_unavailable_or_changed")
        return b"".join(chunks)
    except (OSError, ValueError, RuntimeError) as error:
        raise WorkingFileReadError("working_tree_file_unavailable_or_changed") from error
