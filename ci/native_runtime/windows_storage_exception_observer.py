"""Finite, source-bound exception-event observer for the retained 60bd wheel.

No functions are wrapped and no product operations are added. Tracing itself can
create additional 50 ms storage-gate timeouts. Observations cannot establish the
cause of historical failures or rates in an unobserved run. Event counts, product
failed-record units and unique failures are deliberately distinct.
"""

from __future__ import annotations

import hashlib
import importlib
import platform
import sqlite3
import sys
import threading
from collections import Counter
from pathlib import Path
from types import CodeType, FrameType, FunctionType
from typing import Any

SOURCE_SHA = "60bdeab2ac04ff6ba6e13778be7d6d1fc8e67773"
SOURCE_PINS = {
    "guard/store_connection_schema.py": "1fa357edd734f75d85d1f29a3cf825cad630ca82ac0023a4d2b499f4a2b74a8a",
    "guard/daemon/runtime_hook_evidence_writer.py": "0dafe976d8e905776e0e7aa129b24f38261f65aafeca5650d1c9ec092120eb09",
}
FUNCTIONS = {
    "gate": ("guard/store_connection_schema.py", "StoreConnectionSchemaMixin._hold_storage_gate"),
    "sqlite": ("guard/store_connection_schema.py", "StoreConnectionSchemaMixin._connect_once"),
    "writer": ("guard/daemon/runtime_hook_evidence_writer.py", "RuntimeHookEvidenceWriter._run"),
    "units": ("guard/daemon/runtime_hook_evidence_writer.py", "RuntimeHookEvidenceWriter._record_failure_diagnostics"),
}
GATE_STAGES = {
    212: "gate_upgrade_refusal",
    215: "gate_reentrant_body",
    221: "gate_open_or_close",
    227: "gate_initial_seek",
    228: "gate_read",
    229: "gate_write",
    230: "gate_flush",
    231: "gate_lock_seek",
    233: "gate_lock_or_fileno",
    238: "gate_non_windows_lock",
    242: "gate_timeout",
    248: "gate_body",
    256: "gate_unlock_seek",
    257: "gate_unlock_or_fileno",
    261: "gate_non_windows_unlock",
}
SQLITE_STAGES = {
    400: "sqlite_connect",
    407: "sqlite_row_factory",
    412: "sqlite_busy_timeout",
    414: "sqlite_journal_mode",
    416: "sqlite_synchronous",
    419: "sqlite_cache_size",
    420: "sqlite_mmap_size",
    421: "sqlite_changes",
    422: "sqlite_body",
    423: "sqlite_finalize_outbox",
    424: "sqlite_commit_outbox",
    427: "sqlite_notification",
    437: "sqlite_profile",
    439: "sqlite_notification_cleanup",
    440: "sqlite_close",
    442: "sqlite_permissions",
    445: "sqlite_slow_log",
    449: "sqlite_wake",
    451: "sqlite_publish_notification",
}
WRITER_SITES = {356: "receipt_persistence", 360: "receipt_persistence", 379: "command_activity_persistence"}
PHASES = frozenset(("receipt_persistence", "command_activity_persistence", "journal_append"))
ERROR_TYPES = {
    kind: kind.__name__
    for kind in (
        OSError,
        BlockingIOError,
        ChildProcessError,
        ConnectionError,
        BrokenPipeError,
        ConnectionAbortedError,
        ConnectionRefusedError,
        ConnectionResetError,
        FileExistsError,
        FileNotFoundError,
        InterruptedError,
        IsADirectoryError,
        NotADirectoryError,
        PermissionError,
        ProcessLookupError,
        TimeoutError,
        RuntimeError,
        sqlite3.Error,
        sqlite3.DatabaseError,
        sqlite3.OperationalError,
        sqlite3.IntegrityError,
        sqlite3.InternalError,
        sqlite3.ProgrammingError,
        sqlite3.InterfaceError,
        sqlite3.NotSupportedError,
        sqlite3.DataError,
    )
}
MAX_EVENTS = 4096
MAX_GROUPS = 128
MAX_UNITS = 4096
MAX_STACK = 48
MAX_SOURCE_BYTES = 128 * 1024
_MISSING = object()


class ObserverRefusalError(RuntimeError):
    """Only fixed diagnostic refusal codes are emitted."""


def require(value: bool, code: str) -> None:
    if not value:
        raise ObserverRefusalError(code)


def nested_code(code: CodeType, qualname: str) -> CodeType:
    found = [item for item in code.co_consts if type(item) is CodeType]
    for item in found:
        if item.co_qualname == qualname:
            return item
        try:
            return nested_code(item, qualname)
        except ObserverRefusalError:
            pass
    raise ObserverRefusalError("code_binding_missing")


def source_bytes(root: Path, relative: str) -> bytes:
    path = root / relative
    require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), "source_path")
    with path.open("rb") as handle:
        raw = handle.read(MAX_SOURCE_BYTES + 1)
    require(len(raw) <= MAX_SOURCE_BYTES, "source_size")
    # The retained Windows wheel has only CRLF-vs-LF differences from Git here.
    normalized = raw.replace(b"\r\n", b"\n")
    require(hashlib.sha256(normalized).hexdigest() == SOURCE_PINS[relative], "source_bytes")
    return raw


def builtin_code(error: BaseException, name: str) -> tuple[str, int | None]:
    # Called only after exact builtin type admission; no arbitrary exception
    # properties, stringification, args, traceback or context are inspected.
    value = getattr(error, name, _MISSING)
    if value is _MISSING:
        return "absent", None
    if value is None:
        return "none", None
    if type(value) is int and -(2**31) <= value <= 2**32 - 1:
        return "integer", value
    return "non_integer_or_out_of_range", None


class SourceBoundStorageObserver:
    """Observe fixed original code objects; retain no frame/exception objects."""

    def __init__(self, package_root: Path, functions: dict[str, FunctionType], *, maximum_events: int = MAX_EVENTS):
        require(platform.python_implementation() == "CPython" and sys.version_info[:2] == (3, 12), "python_unsupported")
        require(type(maximum_events) is int and 1 <= maximum_events <= MAX_EVENTS, "event_budget")
        require(set(functions) == set(FUNCTIONS), "function_selection")
        self.root = package_root
        self.functions = dict(functions)
        self.maximum_events = maximum_events
        self.source_hashes: dict[str, str] = {}
        self.codes: dict[str, CodeType] = {}
        self._validate()
        self._lock = threading.Lock()
        self._callback = self._trace
        self._events: Counter[tuple[Any, ...]] = Counter()
        self._units: Counter[tuple[str, str]] = Counter()
        self._event_total = 0
        self._unit_calls = 0
        self._overflow = False
        self._failure = False
        self._active = False
        self._entered = False
        self._restored = False
        self._trace_state_conflict = False
        self._setup_failure = False
        self._restoration_failure = False

    def _validate(self) -> None:
        compiled = {}
        for relative in SOURCE_PINS:
            raw = source_bytes(self.root, relative)
            self.source_hashes[relative] = hashlib.sha256(raw).hexdigest()
            compiled[relative] = compile(raw, str(self.root / relative), "exec", dont_inherit=True)
        for key, (relative, qualname) in FUNCTIONS.items():
            function = self.functions[key]
            require(type(function) is FunctionType, "function_type")
            expected = nested_code(compiled[relative], qualname)
            actual = function.__code__
            require(
                actual == expected and Path(actual.co_filename).resolve() == (self.root / relative).resolve(),
                "function_code",
            )
            require(function.__globals__.get("__file__") == actual.co_filename, "function_origin")
            self.codes[key] = actual
        # Source hashes bind these exact operation/caller lines; all must be
        # executable positions in the compiled code before any workload starts.
        for key, lines in (("gate", GATE_STAGES), ("sqlite", SQLITE_STAGES), ("writer", WRITER_SITES)):
            executable = {line for _start, _end, line in self.codes[key].co_lines()}
            require(set(lines) <= executable, "callsite_binding")

    def __enter__(self) -> SourceBoundStorageObserver:
        require(not self._entered, "observer_reuse")
        require(sys.gettrace() is None and threading.gettrace() is None, "preexisting_tracer")
        require(threading.enumerate() == [threading.current_thread()], "preexisting_threads")
        self._validate()
        self._entered = self._active = True
        try:
            threading.settrace(self._callback)
            sys.settrace(self._callback)
        except BaseException:
            self._active = False
            self._setup_failure = self._failure = True
            self._restore_trace_state()
            raise
        return self

    def __exit__(self, *_args: object) -> None:
        self._active = False
        self._trace_state_conflict = sys.gettrace() is not self._callback or threading.gettrace() is not self._callback
        if self._trace_state_conflict:
            self._failure = True
        self._restore_trace_state()
        before = dict(self.source_hashes)
        try:
            self._validate()
            if self.source_hashes != before:
                self._failure = True
        except BaseException:
            self._failure = True
        # Never suppress or replace the original operation's exception.

    def _restore_trace_state(self) -> None:
        # Entry admits only the current thread with no previous tracers. None
        # is therefore the exact prior state. Each restoration is attempted even
        # if another fails; failure never replaces the workload/setup exception.
        for restore in (threading.settrace_all_threads, threading.settrace, sys.settrace):
            try:
                restore(None)
            except BaseException:
                self._restoration_failure = self._failure = True
        try:
            for top in sys._current_frames().values():
                frame: FrameType | None = top
                while frame is not None:
                    if frame.f_trace is self._callback:
                        frame.f_trace = None
                        frame.f_trace_lines = True
                        frame.f_trace_opcodes = False
                    frame = frame.f_back
            self._restored = not self._restoration_failure and sys.gettrace() is None and threading.gettrace() is None
        except BaseException:
            self._restoration_failure = self._failure = True
            self._restored = False

    def _phase(self, frame: FrameType) -> str:
        current = frame.f_back
        for _ in range(MAX_STACK):
            if current is None:
                return "outside_writer"
            if current.f_code is self.codes["writer"]:
                return WRITER_SITES.get(current.f_lineno, "writer_other_callsite")
            current = current.f_back
        self._failure = True
        return "stack_bound"

    def _record_units(self, frame: FrameType) -> None:
        phase = frame.f_locals.get("phase")
        records = frame.f_locals.get("records")
        receipts = frame.f_locals.get("receipts")
        if type(phase) is not str or phase not in PHASES or type(records) is not int or type(receipts) is not int:
            self._failure = True
            return
        if not 0 <= receipts <= records <= MAX_UNITS:
            self._failure = True
            return
        if self._unit_calls >= MAX_EVENTS or sum(self._units.values()) + records + receipts > MAX_UNITS:
            self._overflow = True
            return
        self._unit_calls += 1
        self._units[phase, "all_failed_record_attempt_units"] += records
        self._units[phase, "receipt_failed_record_attempt_units"] += receipts

    def _trace(self, frame: FrameType, event: str, arg: Any) -> Any:
        if not self._active:
            return None
        code = frame.f_code
        if code is not self.codes["gate"] and code is not self.codes["sqlite"] and code is not self.codes["units"]:
            return None
        try:
            frame.f_trace_lines = False
            frame.f_trace_opcodes = False
            if event == "call" and code is self.codes["units"]:
                with self._lock:
                    self._record_units(frame)
                return None
            if event == "return":
                # Includes generator yield; resumption receives a fresh call
                # event. Suspended generators retain no observer callback.
                frame.f_trace = None
                frame.f_trace_lines = True
                frame.f_trace_opcodes = False
                return None
            if event != "exception":
                return self._callback
            error = arg[1]
            category = ERROR_TYPES.get(type(error))
            if category is None:
                category = "other_exception"
                errno = winerror = sqlite_code = ("not_admitted", None)
            else:
                errno = builtin_code(error, "errno")
                winerror = builtin_code(error, "winerror")
                sqlite_code = builtin_code(error, "sqlite_errorcode")
            stages = GATE_STAGES if code is self.codes["gate"] else SQLITE_STAGES
            stage = stages.get(frame.f_lineno)
            if stage is None:
                self._failure = True
                stage = "unmapped_exception_line"
            key = (self._phase(frame), stage, category, *errno, *winerror, *sqlite_code)
            with self._lock:
                if self._event_total >= self.maximum_events or (
                    key not in self._events and len(self._events) >= MAX_GROUPS
                ):
                    self._overflow = True
                else:
                    self._events[key] += 1
                    self._event_total += 1
            return self._callback
        except BaseException:
            self._failure = True
            frame.f_trace = None
            frame.f_trace_lines = True
            frame.f_trace_opcodes = False
            return None

    def snapshot(self) -> dict[str, Any]:
        require(not self._active, "snapshot_during_workload")
        observations = []
        for key, count in sorted(self._events.items(), key=lambda item: repr(item[0])):
            phase, stage, category, errno_kind, errno, win_kind, winerror, sql_kind, sqlcode = key
            observations.append(
                {
                    "phase": phase,
                    "stage": stage,
                    "exception_category": category,
                    "errno": {"kind": errno_kind, "value": errno},
                    "winerror": {"kind": win_kind, "value": winerror},
                    "sqlite_errorcode": {"kind": sql_kind, "value": sqlcode},
                    "exception_events": count,
                }
            )
        return {
            "schema": "hol-guard.windows-storage-exception-observer.v1",
            "source": SOURCE_SHA,
            "module_sha256": dict(self.source_hashes),
            "observations": observations,
            "failed_record_attempt_units": [
                {"phase": phase, "unit": unit, "count": count} for (phase, unit), count in sorted(self._units.items())
            ],
            "unit_recording_calls": self._unit_calls,
            "exception_events": self._event_total,
            "overflow": self._overflow,
            "observer_failure": self._failure,
            "trace_state_conflict": self._trace_state_conflict,
            "trace_setup_failure": self._setup_failure,
            "trace_restoration_failure": self._restoration_failure,
            "trace_state_restored": self._restored,
            "complete": self._entered and self._restored and not self._failure and not self._overflow,
            "line_events_enabled": False,
            "opcode_events_enabled": False,
            "functions_replaced": False,
            "frames_or_exceptions_retained": False,
            "stage_scope": "exception_line_in_selected_original_code",
            "event_to_failed_attempt_join_proven": False,
            "unique_error_count_measured": False,
            "observer_perturbation_quantified": False,
            "observer_can_create_50ms_timeouts": True,
            "historical_failure_cause_established": False,
            "unobserved_failure_rate_established": False,
            "qualification_complete": False,
        }


def bind_installed(package_root: Path, expected_source_pins: dict[str, str]) -> SourceBoundStorageObserver:
    """Driver calls only after its independent installed-wheel/source checks."""
    require(
        sys.platform == "win32" and platform.python_implementation() == "CPython" and sys.version_info[:2] == (3, 12),
        "platform_unsupported",
    )
    require(expected_source_pins == SOURCE_PINS, "expected_source_pins")
    schema = importlib.import_module("codex_plugin_scanner.guard.store_connection_schema")
    writer = importlib.import_module("codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer")
    return SourceBoundStorageObserver(
        package_root,
        {
            "gate": schema.StoreConnectionSchemaMixin._hold_storage_gate.__wrapped__,
            "sqlite": schema.StoreConnectionSchemaMixin._connect_once.__wrapped__,
            "writer": writer.RuntimeHookEvidenceWriter._run,
            "units": writer.RuntimeHookEvidenceWriter._record_failure_diagnostics,
        },
    )
