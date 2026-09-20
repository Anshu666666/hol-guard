"""Bounded source controls for token replacement with actual Python readers.

This is a test driver. Expected Windows sharing failures remain report data.
No production open flags, writer operations, or runtime deadlines are changed.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
from contextlib import ExitStack
from pathlib import Path
from types import ModuleType
from typing import Any, TextIO
from unittest.mock import patch

from codex_plugin_scanner.guard import private_file_io
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth
from codex_plugin_scanner.guard.daemon import manager

CONTROL_WAIT_SECONDS = 5.0
ROUTES = ("bounded_manager", "codex_path_read_text")
PHASES = ("no_reader", "held_reader", "released_reader")
_OLD = "synthetic-old-token"
_NEW = "synthetic-new-token"


def error_record(error: BaseException | None) -> dict[str, object] | None:
    if error is None:
        return None
    names = (PermissionError, TimeoutError, OSError, ValueError, RuntimeError)
    name = next((kind.__name__ for kind in names if isinstance(error, kind)), "unregistered_error")
    errno = getattr(error, "errno", None)
    winerror = getattr(error, "winerror", None)
    return {
        "kind": name,
        "errno": errno if type(errno) is int else None,
        "winerror": winerror if type(winerror) is int else None,
    }


def _value_record(value: object) -> str:
    if value is None:
        return "unavailable"
    if value == _OLD:
        return "old"
    if value == _NEW:
        return "new"
    return "unexpected"


class _Hold:
    def __init__(self) -> None:
        self.ready = threading.Event()
        self.release = threading.Event()
        self.closed = threading.Event()
        self.thread: threading.Thread | None = None
        self.descriptor: int | None = None
        self.open_count = 0
        self.pause_count = 0

    def owns_thread(self) -> bool:
        return self.thread is threading.current_thread()

    def opened(self, descriptor: int) -> None:
        self.descriptor = descriptor
        self.open_count += 1

    def pause(self) -> None:
        if self.pause_count:
            return
        self.pause_count += 1
        self.ready.set()
        if not self.release.wait(CONTROL_WAIT_SECONDS):
            raise TimeoutError("control_reader_release_timeout")


class _ReaderOS:
    def __init__(self, original: ModuleType, target: Path, hold: _Hold) -> None:
        self.original = original
        self.target = target
        self.hold = hold

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def open(self, path: object, *args: Any, **kwargs: Any) -> int:
        descriptor = self.original.open(path, *args, **kwargs)
        if self.hold.owns_thread() and path == self.target:
            self.hold.opened(descriptor)
        return descriptor

    def read(self, descriptor: int, count: int) -> bytes:
        if self.hold.owns_thread() and descriptor == self.hold.descriptor:
            self.hold.pause()
        return self.original.read(descriptor, count)

    def close(self, descriptor: int) -> None:
        self.original.close(descriptor)
        if self.hold.owns_thread() and descriptor == self.hold.descriptor:
            self.hold.closed.set()


class _PausedText:
    def __init__(self, handle: TextIO, hold: _Hold) -> None:
        self.handle = handle
        self.hold = hold
        hold.opened(handle.fileno())

    def __enter__(self) -> _PausedText:
        self.handle.__enter__()
        return self

    def __exit__(self, *args: Any) -> object:
        try:
            return self.handle.__exit__(*args)
        finally:
            if self.handle.closed:
                self.hold.closed.set()

    def read(self, *args: Any, **kwargs: Any) -> str:
        self.hold.pause()
        return self.handle.read(*args, **kwargs)


class _WriterOS:
    def __init__(self, original: ModuleType, target: Path) -> None:
        self.original = original
        self.target = target
        self.replace_calls = 0
        self.target_matches = True
        self.replace_error: BaseException | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def replace(self, source: Path, destination: Path) -> None:
        self.replace_calls += 1
        self.target_matches = self.target_matches and destination == self.target
        try:
            self.original.replace(source, destination)
        except BaseException as error:
            self.replace_error = error
            raise


def _read_token(route: str, home: Path) -> str | None:
    if route == "bounded_manager":
        return manager.load_guard_daemon_auth_token(home)
    return codex_daemon_hook_auth._private_file_text(manager._auth_token_path(home), label="synthetic token")


def _join(thread: threading.Thread | None) -> bool:
    if thread is None or thread.ident is None:
        return True
    thread.join(CONTROL_WAIT_SECONDS)
    return not thread.is_alive()


def run_case(route: str, phase: str) -> dict[str, object]:
    if route not in ROUTES or phase not in PHASES:
        raise ValueError("control_case_invalid")
    temporary = tempfile.TemporaryDirectory(prefix="pr2974-token-reader-")
    home = Path(temporary.name)
    token = manager._auth_token_path(home)
    hold = _Hold()
    reader_error: BaseException | None = None
    writer_error: BaseException | None = None
    control_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    reader_value: object = None
    writer: threading.Thread | None = None
    writer_calls = 0
    writer_locked = False
    reader_ready = phase == "no_reader"
    writer_finished_in_phase = False
    open_before_writer = False
    closed_before_writer = False
    reader_finished = False
    writer_finished = False
    final_value = "unavailable"
    siblings_clean = False
    writer_os = _WriterOS(manager.os, token)

    def read() -> None:
        nonlocal reader_error, reader_value
        try:
            reader_value = _read_token(route, home)
        except BaseException as error:
            reader_error = error

    def write() -> None:
        nonlocal writer_error, writer_calls, writer_locked
        writer_calls += 1
        try:
            with manager._guard_daemon_state_write_lock(home):
                writer_locked = True
                manager._write_private_atomic_text(token, _NEW)
        except BaseException as error:
            writer_error = error

    original_open = Path.open

    def open_at_read_boundary(path: Path, *args: Any, **kwargs: Any) -> Any:
        handle = original_open(path, *args, **kwargs)
        if route == "codex_path_read_text" and hold.owns_thread() and path == token:
            return _PausedText(handle, hold)
        return handle

    with ExitStack() as patches:
        try:
            manager._ensure_private_directory(home)
            token.write_text(_OLD, encoding="utf-8")
            manager._set_private_mode(token, manager._GUARD_DAEMON_PRIVATE_FILE_MODE)
            patches.enter_context(patch.object(manager, "os", writer_os))
            patches.enter_context(patch.object(private_file_io, "os", _ReaderOS(private_file_io.os, token, hold)))
            patches.enter_context(patch.object(Path, "open", open_at_read_boundary))
            if phase != "no_reader":
                hold.thread = threading.Thread(target=read, name="token-control-reader", daemon=True)
                hold.thread.start()
                reader_ready = hold.ready.wait(CONTROL_WAIT_SECONDS)
                if not reader_ready:
                    raise TimeoutError("control_reader_ready_timeout")
                if phase == "released_reader":
                    hold.release.set()
                    if not _join(hold.thread):
                        raise TimeoutError("control_reader_finish_timeout")
                    closed_before_writer = hold.closed.is_set()
                else:
                    if hold.descriptor is None:
                        raise RuntimeError("control_reader_descriptor_missing")
                    os.fstat(hold.descriptor)
                    open_before_writer = not hold.closed.is_set() and hold.thread.is_alive()
            writer = threading.Thread(target=write, name="token-control-writer", daemon=True)
            writer.start()
            writer_finished_in_phase = _join(writer)
        except BaseException as error:
            control_error = error
        finally:
            hold.release.set()
            reader_finished = _join(hold.thread)
            writer_finished = _join(writer)
            if reader_finished and writer_finished:
                try:
                    final_value = _value_record(token.read_text(encoding="utf-8"))
                    siblings_clean = not any(home.glob(".daemon-auth-token.*"))
                except BaseException as error:
                    cleanup_error = error
    try:
        temporary.cleanup()
    except BaseException as error:
        if cleanup_error is None:
            cleanup_error = error
    directory_removed = not home.exists()
    replace_failed = writer_os.replace_error is not None
    expected_sharing_failure = os.name == "nt" and phase == "held_reader"
    expected_writer = (
        isinstance(writer_error, PermissionError)
        and getattr(writer_error, "winerror", None) == 32
        and writer_error is writer_os.replace_error
        if expected_sharing_failure
        else writer_error is None and not replace_failed
    )
    allowed_reader_values = {"old"}
    if os.name != "nt" and route == "bounded_manager" and phase == "held_reader":
        allowed_reader_values.add("unavailable")
    reader_valid = phase == "no_reader" or (
        reader_error is None and _value_record(reader_value) in allowed_reader_values
    )
    lifecycle_valid = phase == "no_reader" or (
        hold.open_count == 1
        and hold.pause_count == 1
        and hold.closed.is_set()
        and (closed_before_writer if phase == "released_reader" else open_before_writer)
    )
    complete = all(
        (
            reader_ready,
            writer_calls == 1,
            writer_locked,
            writer_os.replace_calls == 1,
            writer_os.target_matches,
            writer_finished_in_phase,
            reader_finished,
            writer_finished,
            lifecycle_valid,
            reader_valid,
            expected_writer,
            final_value == ("old" if expected_sharing_failure else "new"),
            siblings_clean,
            directory_removed,
            control_error is None,
            cleanup_error is None,
        )
    )
    return {
        "route": route,
        "phase": phase,
        "control_complete": complete,
        "writer_calls": writer_calls,
        "replace_calls": writer_os.replace_calls,
        "writer_lock_acquired": writer_locked,
        "original_replace_error_retained": replace_failed and writer_error is writer_os.replace_error,
        "replace_error": error_record(writer_os.replace_error),
        "writer_error": error_record(writer_error),
        "reader_error": error_record(reader_error),
        "control_error": error_record(control_error),
        "cleanup_error": error_record(cleanup_error),
        "reader_ready": reader_ready,
        "reader_open_count": hold.open_count,
        "reader_pause_count": hold.pause_count,
        "reader_open_before_writer": open_before_writer,
        "reader_closed_before_writer": closed_before_writer,
        "reader_closed": hold.closed.is_set() if phase != "no_reader" else None,
        "reader_value": _value_record(reader_value) if phase != "no_reader" else "not_started",
        "writer_finished_before_release": writer_finished_in_phase if phase == "held_reader" else None,
        "reader_thread_finished": reader_finished,
        "writer_thread_finished": writer_finished,
        "final_value": final_value,
        "temporary_siblings_removed": siblings_clean,
        "fixture_directory_removed": directory_removed,
        "expected_windows_sharing_failure": expected_sharing_failure,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("actual_windows_required")
    report: dict[str, Any] = {
        "schema": 1,
        "scope": "actual Windows source controls with synthetic tokens",
        "cases": [],
        "case_count": 0,
        "declared_case_count": len(ROUTES) * len(PHASES),
        "control_complete": False,
        "observed_replace_failure_count": 0,
        "compatibility_failure_observed": False,
        "actual_failed_job_handle_attributed": False,
        "installed_artifact_qualification": False,
        "runtime_deadlines_or_retries_changed": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def persist() -> None:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    persist()
    cases: list[dict[str, object]] = report["cases"]
    for route in ROUTES:
        for phase in PHASES:
            case = run_case(route, phase)
            cases.append(case)
            report["case_count"] = len(cases)
            report["control_complete"] = len(cases) == report["declared_case_count"] and all(
                item["control_complete"] for item in cases
            )
            report["observed_replace_failure_count"] = sum(item["replace_error"] is not None for item in cases)
            report["compatibility_failure_observed"] = report["observed_replace_failure_count"] > 0
            persist()
            print(json.dumps(case, sort_keys=True), flush=True)
    return 0 if report["control_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
