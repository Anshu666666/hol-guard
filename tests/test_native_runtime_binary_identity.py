"""Full-byte native identity checks retain content and filesystem trust boundaries."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

import pytest

from codex_plugin_scanner.guard import native_runtime

_BUFFER_BYTES = 1024 * 1024


def _runtime(tmp_path: Path, content: bytes) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "synthetic-native-runtime"
    path.write_bytes(content)
    path.chmod(0o700)
    return path


@pytest.mark.parametrize("size", [0, 1, _BUFFER_BYTES - 1, _BUFFER_BYTES, 2 * _BUFFER_BYTES + 137])
def test_validation_hashes_exact_complete_bytes(tmp_path: Path, size: int) -> None:
    content = (bytes(range(251)) * (size // 251 + 1))[:size]
    path = _runtime(tmp_path, content)

    identity = native_runtime._validate_binary(path)

    assert isinstance(identity, native_runtime.NativeRuntimeIdentity)
    assert identity.path == path.resolve()
    assert identity.size == size
    assert identity.mtime_ns == path.stat().st_mtime_ns
    assert identity.sha256 == hashlib.sha256(content).hexdigest()


def test_repeated_validation_reopens_and_rehashes_real_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"fresh full-byte identity" * 100
    path = _runtime(tmp_path, content)
    original_open = Path.open
    opens = 0

    @contextmanager
    def tracked_open(candidate: Path, mode: str) -> Iterator[BinaryIO]:
        nonlocal opens
        assert candidate == path.resolve() and mode == "rb"
        opens += 1
        with original_open(candidate, "rb") as handle:
            yield handle

    monkeypatch.setattr(Path, "open", tracked_open)
    first = native_runtime._validate_binary(path)
    second = native_runtime._validate_binary(path)

    assert first is not None and second == first
    assert opens == 2
    assert first.sha256 == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("replace", [False, True])
def test_same_size_and_mtime_changes_still_get_fresh_content_identity(tmp_path: Path, replace: bool) -> None:
    before = b"original identity" * 100
    after = b"modified identity" * 100
    assert len(before) == len(after)
    path = _runtime(tmp_path, before)
    original_stat = path.stat()
    first = native_runtime._validate_binary(path)
    assert first is not None
    if replace:
        replacement = _runtime(tmp_path / "replacement", after)
        replacement.replace(path)
    else:
        path.write_bytes(after)
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    second = native_runtime._validate_binary(path)

    assert second is not None
    assert second.size == first.size and second.mtime_ns == first.mtime_ns
    assert second.sha256 == hashlib.sha256(after).hexdigest()
    assert second.sha256 != first.sha256


class _ReadBehavior:
    def __init__(self, handle: BinaryIO, behavior: str) -> None:
        self.handle = handle
        self.behavior = behavior
        self.bytes_read = 0

    def readinto(self, buffer: bytearray) -> int | None:
        if self.bytes_read and self.behavior == "error":
            raise OSError("synthetic read failure")
        if self.bytes_read and self.behavior == "unavailable":
            return None
        content = self.handle.read(min(len(buffer), 17))
        buffer[: len(content)] = content
        self.bytes_read += len(content)
        return len(content)


@pytest.mark.parametrize("behavior", ["short", "error", "unavailable"])
def test_short_reads_are_complete_and_read_failures_never_yield_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, behavior: str
) -> None:
    content = bytes(range(251)) * 19
    path = _runtime(tmp_path, content)
    original_open = Path.open
    readers: list[_ReadBehavior] = []

    @contextmanager
    def controlled_open(candidate: Path, mode: str) -> Iterator[_ReadBehavior]:
        assert candidate == path.resolve() and mode == "rb"
        with original_open(candidate, "rb") as handle:
            reader = _ReadBehavior(handle, behavior)
            readers.append(reader)
            yield reader

    monkeypatch.setattr(Path, "open", controlled_open)

    identity = native_runtime._validate_binary(path)

    assert len(readers) == 1 and readers[0].handle.closed
    if behavior == "short":
        assert identity is not None
        assert identity.sha256 == hashlib.sha256(content).hexdigest()
        assert readers[0].bytes_read == len(content)
    else:
        assert identity is None
        assert readers[0].bytes_read == 17


@pytest.mark.skipif(os.name == "nt", reason="POSIX write-permission boundary")
@pytest.mark.parametrize("mode", [0o720, 0o702])
def test_writable_runtime_is_rejected(tmp_path: Path, mode: int) -> None:
    path = _runtime(tmp_path, b"synthetic native bytes")
    path.chmod(mode)

    assert native_runtime._validate_binary(path) is None


def test_missing_or_directory_runtime_is_rejected(tmp_path: Path) -> None:
    assert native_runtime._validate_binary(tmp_path / "missing") is None
    assert native_runtime._validate_binary(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="Symlink creation privileges vary on Windows")
def test_lexical_runtime_symlink_is_rejected(tmp_path: Path) -> None:
    path = _runtime(tmp_path, b"synthetic native bytes")
    link = tmp_path / "runtime-link"
    link.symlink_to(path)

    assert native_runtime._validate_binary(link) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner boundary")
def test_foreign_owner_metadata_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _runtime(tmp_path, b"synthetic native bytes")
    original_lstat = Path.lstat

    def foreign_owner(candidate: Path) -> os.stat_result:
        metadata = original_lstat(candidate)
        if candidate == path:
            values = list(metadata)
            values[4] = os.getuid() + 100_000
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "lstat", foreign_owner)

    assert native_runtime._validate_binary(path) is None
