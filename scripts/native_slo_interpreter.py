"""Prepare a byte-identical private interpreter for installed qualification.

Runner images may make their shared toolcache executables world writable. The
Codex installation validator must still reject those paths. Give each POSIX
qualification venv its own executable without modifying the shared source or
any wheel, and retain only bounded, path-free provenance outside timed work.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path

_MAX_INTERPRETER_BYTES = 128 * 1024 * 1024


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _metadata(metadata: os.stat_result) -> dict[str, object]:
    uid = getattr(os, "getuid", lambda: None)()
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "owner": "current_user" if metadata.st_uid == uid else "root" if metadata.st_uid == 0 else "other",
        "group_writable": bool(metadata.st_mode & stat.S_IWGRP),
        "world_writable": bool(metadata.st_mode & stat.S_IWOTH),
        "regular": stat.S_ISREG(metadata.st_mode),
    }


def prepare_private_interpreter(python: Path, *, environment_root: Path) -> dict[str, object]:
    """Copy only the selected POSIX venv executable; preserve its exact bytes.

    Windows venvs already contain executable copies and use ACL-based admission.
    The POSIX source may be shared/root-owned; only the owned environment is
    changed. Refuse non-venv destinations and changes during a bounded copy.
    """
    root = environment_root.absolute()
    invocation = python.absolute()
    expected = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if invocation != expected or root.resolve(strict=True) != root or invocation.parent.is_symlink():
        raise ValueError("qualification_interpreter_destination_invalid")
    config = root / "pyvenv.cfg"
    if config.is_symlink() or not config.is_file():
        raise ValueError("qualification_interpreter_venv_missing")
    if os.name == "nt":
        return {"schema": "hol-guard.qualification-interpreter.v1", "private_copy": False, "platform": "windows"}
    if any(path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o022 for path in (root, invocation.parent)):
        raise ValueError("qualification_interpreter_destination_owner")
    source = invocation.resolve(strict=True)
    initial_invocation = invocation.lstat()
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    temporary: Path | None = None
    try:
        with os.fdopen(descriptor, "rb") as reader:
            original = os.fstat(reader.fileno())
            if (
                not stat.S_ISREG(original.st_mode)
                or original.st_uid not in {os.getuid(), 0}
                or not original.st_mode & 0o111
                or not 0 < original.st_size <= _MAX_INTERPRETER_BYTES
            ):
                raise ValueError("qualification_interpreter_source_invalid")
            digest = hashlib.sha256()
            count = 0
            with tempfile.NamedTemporaryFile(
                dir=invocation.parent, prefix=".qualification-python-", delete=False
            ) as writer:
                temporary = Path(writer.name)
                while chunk := reader.read(1024 * 1024):
                    count += len(chunk)
                    if count > _MAX_INTERPRETER_BYTES:
                        raise ValueError("qualification_interpreter_source_limit")
                    digest.update(chunk)
                    _ = writer.write(chunk)
                writer.flush()
                os.fchmod(writer.fileno(), 0o700)
                os.fsync(writer.fileno())
            if count != original.st_size or _identity(os.fstat(reader.fileno())) != _identity(original):
                raise ValueError("qualification_interpreter_source_changed")
            if _identity(source.stat()) != _identity(original):
                raise ValueError("qualification_interpreter_source_changed")
            if _identity(invocation.lstat()) != _identity(initial_invocation):
                raise ValueError("qualification_interpreter_invocation_changed")
            copied_digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
            if copied_digest != digest.hexdigest():
                raise ValueError("qualification_interpreter_copy_mismatch")
            os.replace(temporary, invocation)
            temporary = None
        copied = invocation.stat()
        if invocation.is_symlink() or stat.S_IMODE(copied.st_mode) != 0o700 or copied.st_uid != os.getuid():
            raise ValueError("qualification_interpreter_copy_invalid")
        return {
            "schema": "hol-guard.qualification-interpreter.v1",
            "platform": "posix",
            "private_copy": True,
            "bytes": count,
            "source_sha256": digest.hexdigest(),
            "copy_sha256": copied_digest,
            "source": _metadata(original),
            "copy": _metadata(copied),
        }
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
