"""Read-only identity for trusted Linux toolchain executables, not evidence files.

Hosted Python may be root-owned; Cargo may hardlink its final executable to
its dependency output. Neither exception relaxes private evidence admission.
Diagnostic metadata comes from the original admission/read, never a retry.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import TypedDict

MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
EXECUTABLE_FAILURE_REASONS = (
    "unresolved_path",
    "path_resolution_failed",
    "path_stat_failed",
    "metadata_not_regular",
    "metadata_not_executable",
    "metadata_writable",
    "metadata_owner",
    "metadata_link_count",
    "metadata_size",
    "descriptor_open_failed",
    "descriptor_stat_failed",
    "identity_changed_open",
    "read_failed",
    "byte_bound",
    "identity_changed_final",
    "path_stat_final_failed",
    "descriptor_close_failed",
)
_IO_REASONS = {
    "resolve": "path_resolution_failed",
    "path_before": "path_stat_failed",
    "open": "descriptor_open_failed",
    "descriptor_before": "descriptor_stat_failed",
    "read": "read_failed",
    "descriptor_after": "descriptor_stat_failed",
    "path_after": "path_stat_final_failed",
    "close": "descriptor_close_failed",
}
_STAT_FIELDS = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")


class ExecutableDiagnostic(TypedDict):
    reason: str
    phase: str
    errno: int | None
    bytes_read: int
    metadata: dict[str, dict[str, int | None]]
    cleanup_failed: bool


class IdentityError(ValueError):
    """Finite stage code; optional numeric details stay in encrypted evidence."""

    def __init__(self, code: str, diagnostic: ExecutableDiagnostic | None = None) -> None:
        super().__init__(code)
        self.diagnostic: ExecutableDiagnostic | None = diagnostic


class ExecutableIdentityError(ValueError):
    """Finite original-read cause, wrapped by the source identity stage."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason: str = reason
        self.diagnostic: ExecutableDiagnostic | None = None


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(value, "st_" + field) for field in _STAT_FIELDS)


def _admit(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode):
        reason = "metadata_not_regular"
    elif not value.st_mode & 0o111:
        reason = "metadata_not_executable"
    elif value.st_mode & 0o022:
        reason = "metadata_writable"
    elif value.st_uid not in {0, os.geteuid()}:
        reason = "metadata_owner"
    elif value.st_nlink < 1:
        reason = "metadata_link_count"
    elif not 0 < value.st_size <= MAX_EXECUTABLE_BYTES:
        reason = "metadata_size"
    else:
        return
    raise ExecutableIdentityError("toolchain_executable_invalid", reason)


def _metadata(value: os.stat_result) -> dict[str, int | None]:
    # Fixed keys, no paths, exception text, or platform objects. Numeric values
    # outside a bounded signed 128-bit domain remain explicitly unavailable.
    return {
        key: item if type(item) is int and -(1 << 127) <= item < (1 << 127) else None
        for key, item in zip(_STAT_FIELDS, _fingerprint(value), strict=True)
    }


def _diagnostic(
    reason: str, phase: str, count: int, metadata: dict[str, dict[str, int | None]], error: BaseException
) -> ExecutableDiagnostic:
    errno = error.errno if isinstance(error, OSError) else None
    return {
        "reason": reason,
        "phase": phase,
        "errno": errno if type(errno) is int and 0 <= errno <= 65535 else None,
        "bytes_read": count,
        "metadata": metadata,
        "cleanup_failed": False,
    }


def resolved_executable_digest(path: Path) -> str:
    """Keep the caller's existing resolution, retaining resolution failures too."""
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as error:
        failure = ExecutableIdentityError("toolchain_executable_io", "path_resolution_failed")
        failure.diagnostic = _diagnostic(failure.reason, "resolve", 0, {}, error)
        raise failure from error
    return executable_digest(resolved)


def executable_digest(path: Path) -> str:
    """Hash one resolved regular executable with before/open/after identity checks."""
    phase, count, descriptor = "resolve", 0, None
    metadata: dict[str, dict[str, int | None]] = {}
    failure: ExecutableIdentityError | None = None
    active_error = False
    try:
        try:
            if path.absolute() != path.resolve(strict=True):
                raise ExecutableIdentityError("toolchain_executable_unresolved", "unresolved_path")
            phase = "path_before"
            before = path.lstat()
            metadata["before"] = _metadata(before)
            _admit(before)
            phase = "open"
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
            phase = "descriptor_before"
            opened = os.fstat(descriptor)
            metadata["opened"] = _metadata(opened)
            _admit(opened)
            if _fingerprint(before) != _fingerprint(opened):
                raise ExecutableIdentityError("toolchain_executable_changed", "identity_changed_open")
            result = hashlib.sha256()
            phase = "read"
            while chunk := os.read(descriptor, min(65536, MAX_EXECUTABLE_BYTES + 1 - count)):
                count += len(chunk)
                if count > MAX_EXECUTABLE_BYTES:
                    raise ExecutableIdentityError("toolchain_executable_bound", "byte_bound")
                result.update(chunk)
            if count != before.st_size:
                raise ExecutableIdentityError("toolchain_executable_changed", "identity_changed_final")
            phase = "descriptor_after"
            final_descriptor = os.fstat(descriptor)
            metadata["final_descriptor"] = _metadata(final_descriptor)
            if _fingerprint(before) != _fingerprint(final_descriptor):
                raise ExecutableIdentityError("toolchain_executable_changed", "identity_changed_final")
            phase = "path_after"
            final_path = path.lstat()
            metadata["final_path"] = _metadata(final_path)
            if _fingerprint(before) != _fingerprint(final_path):
                raise ExecutableIdentityError("toolchain_executable_changed", "identity_changed_final")
            return result.hexdigest()
        except (OSError, ValueError) as error:
            failure = (
                error
                if isinstance(error, ExecutableIdentityError)
                else ExecutableIdentityError("toolchain_executable_io", _IO_REASONS[phase])
            )
            failure.diagnostic = _diagnostic(failure.reason, phase, count, metadata, error)
            if failure is error:
                raise
            raise failure from error
    except BaseException:
        active_error = True
        raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                if failure is not None and failure.diagnostic is not None:
                    failure.diagnostic["cleanup_failed"] = True
                elif not active_error:
                    failure = ExecutableIdentityError("toolchain_executable_io", "descriptor_close_failed")
                    failure.diagnostic = _diagnostic(failure.reason, "close", count, metadata, error)
                    failure.diagnostic["cleanup_failed"] = True
                    raise failure from error
