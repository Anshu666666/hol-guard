"""Read-only identity for trusted Linux toolchain executables, not evidence files.

Hosted Python may be root-owned; Cargo may hardlink its final executable to
the dependency output. Those are valid toolchain layouts. Neither exception
changes the stricter ownership/link contract for private evidence snapshots.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024


class IdentityError(ValueError):
    """A finite stage code, with original diagnostic details kept out of public output."""


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _admit(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or not value.st_mode & 0o111
        or value.st_mode & 0o022
        or value.st_uid not in {0, os.geteuid()}
        or value.st_nlink < 1
        or not 0 < value.st_size <= MAX_EXECUTABLE_BYTES
    ):
        raise ValueError("toolchain_executable_invalid")


def executable_digest(path: Path) -> str:
    """Hash one resolved regular executable with before/open/after identity checks."""
    if path.absolute() != path.resolve(strict=True):
        raise ValueError("toolchain_executable_unresolved")
    before = path.lstat()
    _admit(before)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        _admit(opened)
        if _fingerprint(before) != _fingerprint(opened):
            raise ValueError("toolchain_executable_changed")
        result, count = hashlib.sha256(), 0
        while chunk := os.read(descriptor, min(65536, MAX_EXECUTABLE_BYTES + 1 - count)):
            count += len(chunk)
            if count > MAX_EXECUTABLE_BYTES:
                raise ValueError("toolchain_executable_bound")
            result.update(chunk)
        if count != before.st_size or not (
            _fingerprint(before) == _fingerprint(os.fstat(descriptor)) == _fingerprint(path.lstat())
        ):
            raise ValueError("toolchain_executable_changed")
        return result.hexdigest()
    finally:
        os.close(descriptor)
