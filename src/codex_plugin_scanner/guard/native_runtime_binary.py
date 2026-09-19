"""Fresh full-byte identity checks for the local native executable."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def validate_native_binary(path: Path) -> tuple[Path, int, int, str] | None:
    try:
        lexical = path.expanduser()
        metadata = lexical.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None
        if os.name != "nt":
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                return None
            current_uid = os.getuid() if hasattr(os, "getuid") else None
            owner = getattr(metadata, "st_uid", current_uid)
            if current_uid is not None and owner not in {0, current_uid}:
                return None
        resolved = lexical.resolve(strict=True)
        resolved_metadata = resolved.stat()
        if metadata.st_size != resolved_metadata.st_size:
            return None
        digest = hashlib.sha256()
        buffer = bytearray(1024 * 1024)
        view = memoryview(buffer)
        with resolved.open("rb") as handle:
            while True:
                count = handle.readinto(buffer)
                if count is None:
                    raise OSError("Native binary read did not complete")
                if count == 0:
                    break
                digest.update(view[:count])
        return resolved, resolved_metadata.st_size, resolved_metadata.st_mtime_ns, digest.hexdigest()
    except (OSError, RuntimeError, ValueError):
        return None
