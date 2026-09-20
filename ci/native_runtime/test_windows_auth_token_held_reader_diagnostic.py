"""Windows-only diagnostic of the original private-reader/atomic-writer pair.

This control demonstrates or rejects one concrete sharing-conflict family.
It does not identify the handle in a previous hosted failure or qualify Guard.
"""

from __future__ import annotations

import os
import queue
import threading
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import private_file_io
from codex_plugin_scanner.guard.daemon import manager

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows file sharing is required")
_CONTROL_SECONDS = 5.0


class _OwnedReaderOs:
    """Forward original operations; hold only this reader's first actual read."""

    def __init__(self, target: Path) -> None:
        self.target = target
        self.original = private_file_io.os
        self.entered = threading.Event()
        self.release = threading.Event()
        self.reader_thread: int | None = None
        self.descriptor: int | None = None
        self.open_count = 0
        self.close_count = 0
        self.held_read_count = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def open(self, path: Path, flags: int) -> int:
        descriptor = self.original.open(path, flags)
        if threading.get_ident() == self.reader_thread and path == self.target:
            self.descriptor = descriptor
            self.open_count += 1
        return descriptor

    def read(self, descriptor: int, maximum: int) -> bytes:
        if (
            threading.get_ident() == self.reader_thread
            and descriptor == self.descriptor
            and self.held_read_count == 0
        ):
            self.held_read_count += 1
            self.entered.set()
            if not self.release.wait(_CONTROL_SECONDS):
                raise TimeoutError("owned diagnostic reader was not released")
        return self.original.read(descriptor, maximum)

    def close(self, descriptor: int) -> None:
        self.original.close(descriptor)
        if threading.get_ident() == self.reader_thread and descriptor == self.descriptor:
            self.close_count += 1


def test_original_reader_blocks_atomic_token_replacement_on_windows(tmp_path, monkeypatch) -> None:
    target = tmp_path / "daemon-auth-token"
    old_value = "synthetic-old-token"
    new_value = "synthetic-new-token"
    manager._write_private_atomic_text(target, old_value)
    assert private_file_io.read_private_regular_text(
        target, max_bytes=4096, require_private_parent=True
    ) == old_value
    original_identity = target.stat().st_dev, target.stat().st_ino
    seam = _OwnedReaderOs(target)
    outcomes: queue.Queue[str | None] = queue.Queue(maxsize=1)
    errors: queue.Queue[BaseException] = queue.Queue(maxsize=1)

    def read_original() -> None:
        seam.reader_thread = threading.get_ident()
        try:
            outcomes.put_nowait(
                private_file_io.read_private_regular_text(
                    target, max_bytes=4096, require_private_parent=True
                )
            )
        except BaseException as error:
            errors.put_nowait(error)

    thread = threading.Thread(target=read_original, name="owned-token-reader-diagnostic", daemon=True)
    with monkeypatch.context() as patch:
        # Only the reader module's namespace is replaced. The real os module
        # and the original writer's os.close/os.replace remain untouched.
        patch.setattr(private_file_io, "os", seam)
        thread.start()
        try:
            assert seam.entered.wait(_CONTROL_SECONDS), "original bounded reader did not reach its opened descriptor"
            assert seam.open_count == seam.held_read_count == 1
            assert seam.descriptor is not None
            opened = os.fstat(seam.descriptor)
            assert (opened.st_dev, opened.st_ino) == original_identity
            # Exactly one failing attempt. Never suppress it or retry this
            # operation into success while the conflicting reader is held.
            with pytest.raises(PermissionError) as caught:
                manager._write_private_atomic_text(target, new_value)
            assert getattr(caught.value, "winerror", None) == 32
            assert (target.stat().st_dev, target.stat().st_ino) == original_identity
            assert not list(tmp_path.glob(".daemon-auth-token.*"))
        finally:
            seam.release.set()
            thread.join(_CONTROL_SECONDS)
        assert not thread.is_alive(), "owned diagnostic reader did not retire"
        assert errors.empty()
        assert outcomes.get_nowait() == old_value
        assert seam.open_count == seam.close_count == 1
    assert private_file_io.os is seam.original
    # A separate after-release control; the earlier failed attempt stays failed.
    manager._write_private_atomic_text(target, new_value)
    assert private_file_io.read_private_regular_text(
        target, max_bytes=4096, require_private_parent=True
    ) == new_value
    assert not list(tmp_path.glob(".daemon-auth-token.*"))
