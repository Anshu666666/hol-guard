"""Bounded retained-directory I/O for synthetic evidence, without path following."""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path

from scripts.native_slo_evidence_format import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    require,
    valid_name,
)


def _plain_path(path: Path) -> Path:
    require(".." not in path.parts, "archive_path_invalid")
    absolute = path.absolute()
    for part in (absolute, *absolute.parents):
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            continue
        require(
            not stat.S_ISLNK(metadata.st_mode) and not getattr(metadata, "st_file_attributes", 0) & 0x400,
            "archive_path_invalid",
        )
    return absolute


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *identity(metadata),
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _file(metadata: os.stat_result, maximum: int, *, private: bool = False) -> None:
    require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and 0 <= metadata.st_size <= maximum,
        "archive_file_invalid",
    )
    require(not getattr(metadata, "st_file_attributes", 0) & 0x400, "archive_file_invalid")
    if os.name != "nt":
        require(metadata.st_uid == os.geteuid(), "archive_file_invalid")
        if private:
            require(stat.S_IMODE(metadata.st_mode) & 0o077 == 0, "archive_file_not_private")


@contextmanager
def directory(path: Path) -> Iterator[tuple[Path, int | None]]:
    absolute = _plain_path(path)
    initial = absolute.lstat()
    require(stat.S_ISDIR(initial.st_mode), "archive_path_invalid")
    with ExitStack() as stack:
        descriptor: int | None = None
        if os.name == "nt":
            from scripts.native_slo_evidence_windows import hold_directory

            stack.enter_context(hold_directory(absolute))
        else:
            descriptor = os.open(absolute, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            stack.callback(os.close, descriptor)
            require(identity(os.fstat(descriptor)) == identity(initial), "archive_source_changed")
        yield absolute, descriptor
        require(identity(absolute.lstat()) == identity(initial), "archive_source_changed")


def _stat(parent: Path, descriptor: int | None, name: str) -> os.stat_result:
    if descriptor is None:
        from scripts.native_slo_evidence_windows import metadata_handle

        return metadata_handle(parent / name)
    return os.stat(name, dir_fd=descriptor, follow_symlinks=False)


def _read_child(parent: Path, directory_fd: int | None, name: str, maximum: int, *, private: bool = False) -> bytes:
    before = _stat(parent, directory_fd, name)
    _file(before, maximum, private=private)
    if os.name == "nt":
        from scripts.native_slo_evidence_windows import read_handle

        data, after = read_handle(parent / name, maximum, private=private)
    else:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd
        )
        try:
            opened = os.fstat(descriptor)
            _file(opened, maximum, private=private)
            require(fingerprint(opened) == fingerprint(before), "archive_source_changed")
            chunks: list[bytes] = []
            count = 0
            while True:
                chunk = os.read(descriptor, min(65536, maximum + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                require(count <= maximum, "archive_bounds_exceeded")
            data, after = b"".join(chunks), os.fstat(descriptor)
        finally:
            os.close(descriptor)
    require(
        fingerprint(before) == fingerprint(after) == fingerprint(_stat(parent, directory_fd, name)),
        "archive_source_changed",
    )
    require(len(data) == before.st_size, "archive_source_changed")
    return data


def read_file(path: Path, maximum: int, *, private: bool = False) -> bytes:
    path = _plain_path(path)
    with directory(path.parent) as (parent, descriptor):
        return _read_child(parent, descriptor, path.name, maximum, private=private)


def _inventory(parent: Path, descriptor: int | None) -> dict[str, tuple[int, ...]]:
    result: dict[str, tuple[int, ...]] = {}
    folded: set[str] = set()
    with os.scandir(descriptor if descriptor is not None else parent) as entries:
        for entry in entries:
            require(len(result) < MAX_FILES, "archive_bounds_exceeded")
            require(valid_name(entry.name) and entry.name.casefold() not in folded, "archive_input_name_invalid")
            # Windows DirEntry.stat has zero identity/link fields. Use the
            # same fresh handle metadata domain as the later bounded read.
            metadata = _stat(parent, descriptor, entry.name)
            _file(metadata, MAX_FILE_BYTES)
            result[entry.name] = fingerprint(metadata)
            folded.add(entry.name.casefold())
    return result


def read_samples(path: Path) -> list[tuple[str, bytes]]:
    with directory(path) as (parent, descriptor):
        initial = _inventory(parent, descriptor)
        require(sum(item[3] for item in initial.values()) <= MAX_TOTAL_BYTES, "archive_bounds_exceeded")
        total = 0
        files: list[tuple[str, bytes]] = []
        for name in sorted(initial):
            data = _read_child(parent, descriptor, name, MAX_FILE_BYTES)
            total += len(data)
            require(total <= MAX_TOTAL_BYTES, "archive_bounds_exceeded")
            files.append((name, data))
        require(initial == _inventory(parent, descriptor), "archive_source_changed")
        return files


def _new_directory(path: Path) -> None:
    _plain_path(path)
    if os.name == "nt":
        from scripts.native_slo_evidence_windows import create_directory

        create_directory(path)
    else:
        path.mkdir(mode=0o700)
        metadata = path.lstat()
        require(
            metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) & 0o077 == 0,
            "archive_output_not_private",
        )


def ensure_parent(path: Path) -> None:
    parent = _plain_path(path).parent
    missing: list[Path] = []
    while not parent.exists():
        missing.append(parent)
        require(len(missing) <= 8, "archive_path_invalid")
        parent = parent.parent
    for child in reversed(missing):
        _new_directory(child)


def _write_child(parent: Path, directory_fd: int | None, name: str, content: bytes) -> os.stat_result:
    if os.name == "nt":
        from scripts.native_slo_evidence_windows import write_private_file

        return write_private_file(parent / name, content)
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory_fd,
    )
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


def atomic_exclusive(path: Path, content: bytes) -> None:
    path = _plain_path(path)
    ensure_parent(path)
    if os.name == "nt":
        from scripts.native_slo_evidence_windows import atomic_private_file

        atomic_private_file(path, content)
        return
    with directory(path.parent) as (parent, descriptor):
        if descriptor is None:
            raise RuntimeError("archive_directory_descriptor_missing")
        metadata = os.fstat(descriptor)
        require(
            metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) & 0o022 == 0,
            "archive_output_not_private",
        )
        temporary = f".evidence-{secrets.token_hex(16)}.tmp"
        created = _write_child(parent, descriptor, temporary, content)
        try:
            require(identity(_stat(parent, descriptor, temporary)) == identity(created), "archive_source_changed")
            if descriptor is None:
                os.link(parent / temporary, path, follow_symlinks=False)
                os.unlink(parent / temporary)
            else:
                os.link(temporary, path.name, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
                os.unlink(temporary, dir_fd=descriptor)
                os.fsync(descriptor)
            require(identity(_stat(parent, descriptor, path.name)) == identity(created), "archive_source_changed")
        finally:
            with suppress(FileNotFoundError):
                if descriptor is None:
                    os.unlink(parent / temporary)
                else:
                    os.unlink(temporary, dir_fd=descriptor)


def recover_files(path: Path, files: list[tuple[str, bytes]]) -> None:
    """Only called after full AEAD/manifest validation; never merge or overwrite."""
    path = _plain_path(path)
    # Existing parent is required. Never create a plaintext directory tree at
    # attacker-controlled manifest paths or recursively repair permissions.
    with directory(path.parent):
        _new_directory(path)
        # Keep an incomplete private recovery on I/O failure for inspection;
        # never delete an existing/replaced path during cleanup.
        with directory(path) as (parent, descriptor):
            for name, content in files:
                require(valid_name(name), "archive_input_name_invalid")
                _write_child(parent, descriptor, name, content)
            if descriptor is not None:
                os.fsync(descriptor)
