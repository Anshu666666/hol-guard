from __future__ import annotations

import builtins
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import private_file_io
from codex_plugin_scanner.guard import windows_replaceable_file as replaceable
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth
from codex_plugin_scanner.guard.daemon import manager

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Real Windows sharing and audit semantics")
_CONTROL_SECONDS = 5.0
_ROOT = Path(__file__).resolve().parents[1]
_CHILD = _ROOT / "ci/native_runtime/windows_replaceable_reader_child.py"
_OLD = "synthetic-before-token"
_NEW = "synthetic-after-token"


def _run_child(target: Path, *arguments: str):
    command = [
        sys.executable, "-I", str(_CHILD), "--source-root", str(_ROOT),
        "--target", str(target), *arguments,
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True,
    )
    failure = None
    stdout = stderr = b""
    try:
        stdout, stderr = process.communicate(timeout=_CONTROL_SECONDS)
    except BaseException as error:
        failure = error
    finally:
        if process.poll() is None:
            try:
                process.kill()
                process.communicate(timeout=_CONTROL_SECONDS)
            except BaseException as cleanup_error:
                if failure is None:
                    failure = cleanup_error
                else:
                    failure.add_note("control_child_cleanup_failed")
    if failure is not None:
        raise failure
    if len(stdout) > 8192 or stderr:
        raise RuntimeError("control_child_output_invalid")
    return process.returncode, json.loads(stdout)


class _HeldRead:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.closed = threading.Event()
        self.owner: int | None = None
        self.descriptor: int | None = None
        self.inheritable: bool | None = None
        self.identity: tuple[int, int] | None = None

    def pause(self, descriptor):
        if threading.get_ident() != self.owner or self.descriptor is not None:
            return
        self.descriptor = descriptor
        self.inheritable = os.get_inheritable(descriptor)
        metadata = os.fstat(descriptor)
        self.identity = metadata.st_dev, metadata.st_ino
        self.entered.set()
        if not self.release.wait(_CONTROL_SECONDS):
            raise TimeoutError("control_reader_release_timeout")


class _ReaderOs:
    def __init__(self, held):
        self.held = held

    def __getattr__(self, name):
        return getattr(os, name)

    def read(self, descriptor, maximum):
        self.held.pause(descriptor)
        return os.read(descriptor, maximum)

    def close(self, descriptor):
        os.close(descriptor)
        if descriptor == self.held.descriptor and threading.get_ident() == self.held.owner:
            self.held.closed.set()


class _TextRead:
    def __init__(self, handle, held):
        self.handle = handle
        self.held = held

    def __enter__(self):
        self.handle.__enter__()
        return self

    def read(self):
        self.held.pause(self.handle.fileno())
        return self.handle.read()

    def __exit__(self, *arguments):
        try:
            return self.handle.__exit__(*arguments)
        finally:
            if self.handle.closed:
                self.held.closed.set()


@pytest.mark.parametrize("route", ["bounded_manager", "codex_text"])
@pytest.mark.parametrize("hold_crt_source", [False, True], ids=["destination_only", "separate_crt_source"])
def test_actual_reader_allows_other_process_replace_without_changing_writer(
    tmp_path, monkeypatch, record_property, route, hold_crt_source,
):
    assert Path(private_file_io.__file__).resolve() == _ROOT / "src/codex_plugin_scanner/guard/private_file_io.py"
    assert Path(replaceable.__file__).resolve() == _ROOT / "src/codex_plugin_scanner/guard/windows_replaceable_file.py"
    home = tmp_path / "guard"
    manager._ensure_private_directory(home)
    target = home / "daemon-auth-token"
    manager._write_private_atomic_text(target, _OLD)
    before = target.stat()
    old_identity = before.st_dev, before.st_ino
    held = _HeldRead()
    values = queue.Queue(maxsize=1)
    errors = queue.Queue(maxsize=1)

    def read():
        held.owner = threading.get_ident()
        try:
            if route == "bounded_manager":
                value = manager.load_guard_daemon_auth_token(home)
            else:
                value = codex_daemon_hook_auth._private_file_text(target, label="token")
            values.put_nowait(value)
        except BaseException as error:
            errors.put_nowait(error)

    def open_text(path, *arguments, **keywords):
        handle = builtins.open(path, *arguments, **keywords)
        if Path(path) == target and threading.get_ident() == held.owner:
            return _TextRead(handle, held)
        return handle

    thread = threading.Thread(target=read, name="owned-source-reader", daemon=True)
    report = None
    code = None
    held_after_child = False
    old_handle_after_child = False
    with monkeypatch.context() as patch:
        patch.setattr(private_file_io, "os", _ReaderOs(held))
        patch.setattr(replaceable, "open", open_text, raising=False)
        thread.start()
        try:
            if not held.entered.wait(_CONTROL_SECONDS):
                raise TimeoutError("control_reader_ready_timeout")
            if held.descriptor is None:
                raise RuntimeError("control_reader_descriptor_missing")
            extra = ["--hold-crt-source"] if hold_crt_source else []
            code, report = _run_child(target, "--operation", "writer", *extra)
            held_after_child = thread.is_alive() and not held.closed.is_set()
            after = os.fstat(held.descriptor)
            old_handle_after_child = (after.st_dev, after.st_ino) == old_identity
        finally:
            held.release.set()
            thread.join(_CONTROL_SECONDS)
            record_property("reader_retired", not thread.is_alive())
            record_property("reader_descriptor_closed", held.closed.is_set())
            record_property("writer_is_separate_process", True)
            record_property("source_crt_negative_control", hold_crt_source)
    assert not thread.is_alive()
    assert errors.empty()
    assert held.closed.is_set()
    assert held.inheritable is False
    assert held.identity == old_identity
    assert held_after_child and old_handle_after_child
    assert values.get_nowait() == _OLD
    assert report is not None
    assert report["writer_calls"] == report["replace_calls"] == 1
    assert report["writer_locked"] and report["writer_fd_closed_before_replace"]
    assert report["source_reader_opened"] is hold_crt_source
    assert report["source_reader_closed"] is hold_crt_source
    assert report["temporary_siblings_removed"]
    assert report["original_exception_identity_preserved"]
    if hold_crt_source:
        assert code == 1
        assert report["replace_returned"] is False
        assert report["error"] == {"kind": "PermissionError", "errno": 13, "winerror": 32}
        assert target.read_text(encoding="utf-8") == _OLD
    else:
        assert code == 0
        assert report["replace_returned"] is True
        assert report["error"] is None
        assert target.read_text(encoding="utf-8") == _NEW
        current = target.stat()
        assert (current.st_dev, current.st_ino) != old_identity
    assert not list(home.glob(".daemon-auth-token.*"))


@pytest.mark.parametrize("route", ["bounded", "text"])
@pytest.mark.parametrize("refuse", [False, True], ids=["observe", "refuse"])
def test_real_python_audit_matches_original_once(tmp_path, route, refuse):
    target = tmp_path / "authority"
    target.write_bytes(b"synthetic\r\nvalue\x1a\n")
    extra = ["--refuse"] if refuse else []
    original_code, original = _run_child(target, "--operation", "audit", "--route", route, *extra)
    candidate_code, candidate = _run_child(
        target, "--operation", "audit", "--route", route, "--candidate", *extra,
    )
    assert original_code == candidate_code == 0
    assert candidate == original
    assert len(candidate["events"]) == 1
    assert candidate["refusal_same_object"] is refuse
    assert candidate["result_matches"] is (not refuse)
