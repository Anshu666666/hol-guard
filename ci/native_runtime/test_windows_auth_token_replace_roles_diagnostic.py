"""Separate Windows source/destination hypotheses; original f243 remains failed."""

from __future__ import annotations

import errno
import inspect
import os
import queue
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import private_file_io
from codex_plugin_scanner.guard.daemon import manager, manager_pending_launch
from test_windows_auth_token_held_reader_diagnostic import _CONTROL_SECONDS, _OwnedReaderOs

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows file sharing is required")


class _OwnedReplace:
    """Observe only this writer's actual replace boundary and one owned reader."""

    def __init__(self, destination: Path, role: str, monkeypatch) -> None:
        self.original = manager.os
        self.destination = destination
        self.role = role
        self.monkeypatch = monkeypatch
        self.owner_thread = threading.get_ident()
        self.closed_descriptors: list[int] = []
        self.replace_calls = 0
        self.exception: OSError | None = None
        self.returned = False
        self.reader: _OwnedReaderOs | None = None
        self.thread: threading.Thread | None = None
        self.outcomes: queue.Queue[str | None] = queue.Queue(maxsize=1)
        self.errors: queue.Queue[BaseException] = queue.Queue(maxsize=1)
        self.source_identity: tuple[int, int] | None = None
        self.held_identity: tuple[int, int] | None = None

    def __getattr__(self, name: str):
        return getattr(self.original, name)

    def close(self, descriptor: int) -> None:
        self.original.close(descriptor)
        if threading.get_ident() == self.owner_thread:
            self.closed_descriptors.append(descriptor)

    def replace(self, source: Path, destination: Path) -> None:
        assert threading.get_ident() == self.owner_thread
        assert self.replace_calls == 0
        assert destination == self.destination
        assert source.parent == destination.parent
        assert source.name.startswith("." + destination.name + ".")
        assert len(self.closed_descriptors) == 1
        # The writer closed its own descriptor before this actual boundary.
        # Check before opening the reader, which may reuse that descriptor.
        with pytest.raises(OSError) as closed:
            self.original.fstat(self.closed_descriptors[0])
        assert closed.value.errno == errno.EBADF
        source_metadata = source.stat()
        self.source_identity = source_metadata.st_dev, source_metadata.st_ino
        if self.role == "source":
            held = source
        else:
            assert self.role == "destination"
            held = destination
        metadata = held.stat()
        self.held_identity = metadata.st_dev, metadata.st_ino
        reader = _OwnedReaderOs(held)
        self.reader = reader

        def read_original() -> None:
            reader.reader_thread = threading.get_ident()
            try:
                self.outcomes.put_nowait(private_file_io.read_private_regular_text(
                    held, max_bytes=4096, require_private_parent=True,
                ))
            except BaseException as error:
                self.errors.put_nowait(error)

        thread = threading.Thread(target=read_original, name="owned-replace-role-reader", daemon=True)
        self.thread = thread
        # Each proxy replaces only its owning module binding. Neither mutates
        # the real os module, pathlib, tempfile, or the original OS operations.
        with self.monkeypatch.context() as patch:
            patch.setattr(private_file_io, "os", reader)
            thread.start()
            try:
                assert reader.entered.wait(_CONTROL_SECONDS), "owned reader did not reach its actual descriptor"
                assert reader.open_count == reader.held_read_count == 1
                assert reader.descriptor is not None
                opened = self.original.fstat(reader.descriptor)
                assert (opened.st_dev, opened.st_ino) == self.held_identity
                self.replace_calls += 1
                try:
                    self.original.replace(source, destination)
                except OSError as error:
                    self.exception = error
                    raise
                else:
                    self.returned = True
            finally:
                # Retire the reader before the original writer's finally
                # tries to unlink its temporary source. No replace is retried.
                reader.release.set()
                thread.join(_CONTROL_SECONDS)


def _run_role(tmp_path, monkeypatch, record_property, *, role: str, expected_code: int) -> None:
    target = tmp_path / "daemon-auth-token"
    old_value = "synthetic-before-token"
    new_value = "synthetic-after-token"
    writer = manager._write_private_atomic_text
    assert writer is manager_pending_launch._write_private_atomic_text
    assert writer.__globals__["_manager"] is manager
    assert manager.os is os and private_file_io.os is os
    helper_source = inspect.getsourcefile(_OwnedReaderOs)
    assert helper_source is not None
    assert Path(helper_source).resolve() == Path(__file__).with_name(
        "test_windows_auth_token_held_reader_diagnostic.py"
    ).resolve()
    writer(target, old_value)
    assert private_file_io.read_private_regular_text(
        target, max_bytes=4096, require_private_parent=True,
    ) == old_value
    original_identity = target.stat().st_dev, target.stat().st_ino
    observer = _OwnedReplace(target, role, monkeypatch)
    failure: OSError | None = None
    with monkeypatch.context() as patch:
        patch.setattr(manager, "os", observer)
        try:
            writer(target, new_value)
        except OSError as error:
            failure = error
    # All cleanup and after-release controls precede numeric adjudication.
    assert manager.os is observer.original
    assert private_file_io.os is os
    assert observer.replace_calls == 1
    assert observer.thread is not None and not observer.thread.is_alive()
    assert observer.reader is not None
    assert observer.reader.open_count == observer.reader.close_count == 1
    assert observer.errors.empty()
    if role == "source":
        expected_read = new_value
    else:
        expected_read = old_value
    assert observer.outcomes.get_nowait() == expected_read
    record_property("held_role", role)
    record_property("original_replace_calls", observer.replace_calls)
    record_property("original_writer_fd_closed", True)
    record_property("reader_retired", True)
    record_property("reader_open_close_count", observer.reader.close_count)
    record_property("original_exception_identity_preserved", failure is not None and failure is observer.exception)
    if failure is None:
        observed_code = None
        exception_kind = "none"
    else:
        observed_code = getattr(failure, "winerror", None)
        exception_kind = "other_os_error"
        if type(failure) is PermissionError:
            exception_kind = "PermissionError"
    record_property("observed_winerror", observed_code)
    record_property("expected_winerror_hypothesis", expected_code)
    record_property("exception_kind", exception_kind)
    record_property("exception_boundary", "original_os_replace")
    assert not list(tmp_path.glob(".daemon-auth-token.*"))
    if failure is not None:
        assert (target.stat().st_dev, target.stat().st_ino) == original_identity
        assert private_file_io.read_private_regular_text(
            target, max_bytes=4096, require_private_parent=True,
        ) == old_value
    writer(target, new_value)
    assert private_file_io.read_private_regular_text(
        target, max_bytes=4096, require_private_parent=True,
    ) == new_value
    assert not list(tmp_path.glob(".daemon-auth-token.*"))
    record_property("separate_after_release_write_read", True)
    assert failure is not None and failure is observer.exception
    assert not observer.returned
    assert type(failure) is PermissionError
    assert observed_code == expected_code


def test_held_destination_reader_has_access_denied_hypothesis(tmp_path, monkeypatch, record_property) -> None:
    _run_role(tmp_path, monkeypatch, record_property, role="destination", expected_code=5)


def test_held_temporary_source_reader_has_sharing_violation_hypothesis(tmp_path, monkeypatch, record_property) -> None:
    _run_role(tmp_path, monkeypatch, record_property, role="source", expected_code=32)
