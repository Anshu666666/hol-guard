"""Real owned-file mutation controls for the source/tool identity reader."""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.rsp131_inode_probe import identity


def record_descriptors(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    actual = identity.os.open
    opened: list[int] = []

    def tracked(*args: Any, **kwargs: Any) -> int:
        descriptor = actual(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(identity.os, "open", tracked)
    return opened


def assert_retired(descriptors: list[int]) -> None:
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError) as refused:
            os.fstat(descriptor)
        assert refused.value.errno == errno.EBADF


def test_regular_bytes_and_descriptor_retirement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "regular"
    data = b"owned-source-identity"
    target.write_bytes(data)
    opened = record_descriptors(monkeypatch)
    row = identity.file_identity(target)
    assert row["sha256"] == hashlib.sha256(data).hexdigest()
    assert row["bytes"] == len(data)
    assert (row["device"], row["inode"]) == (target.stat().st_dev, target.stat().st_ino)
    assert_retired(opened)


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo", "oversize"])
def test_nonregular_or_out_of_bound_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    target = tmp_path / "target"
    if kind == "symlink":
        real = tmp_path / "real"
        real.write_bytes(b"source")
        target.symlink_to(real)
    elif kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        os.mkfifo(target, 0o600)
    else:
        target.write_bytes(b"source")
    opened = record_descriptors(monkeypatch)
    with pytest.raises((OSError, ValueError)):
        identity.file_identity(target, maximum=4)
    if kind != "symlink":
        assert_retired(opened)


@pytest.mark.parametrize("mutation", ["replacement", "truncation"])
def test_real_mutation_before_final_stat_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    target = tmp_path / "source"
    target.write_bytes(b"original")
    alternate = tmp_path / "alternate"
    alternate.write_bytes(b"different")
    actual = identity.os.fstat
    calls = 0
    opened = record_descriptors(monkeypatch)

    def changed(descriptor: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            if mutation == "replacement":
                alternate.replace(target)
            else:
                target.write_bytes(b"")
        return actual(descriptor)

    monkeypatch.setattr(identity.os, "fstat", changed)
    with pytest.raises(ValueError, match="file_identity_changed"):
        identity.file_identity(target)
    assert calls == 2
    assert_retired(opened)


def test_growth_beyond_original_size_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "source"
    target.write_bytes(b"original")
    actual = identity.os.read
    opened = record_descriptors(monkeypatch)
    reads = 0

    def grow_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal reads
        block = actual(descriptor, size)
        reads += 1
        if reads == 1:
            with target.open("ab") as output:
                output.write(b"x")
        return block

    monkeypatch.setattr(identity.os, "read", grow_after_first_read)
    with pytest.raises(ValueError, match="file_grew"):
        identity.file_identity(target)
    assert reads == 2
    assert_retired(opened)
