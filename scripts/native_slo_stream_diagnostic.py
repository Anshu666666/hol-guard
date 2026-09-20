"""Bounded private capture of the installed persistent client's original frames."""

from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Callable
from contextlib import ExitStack, suppress
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from codex_plugin_scanner.guard import native_resident_stream as transport
from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES

MAX_PROCESSES = 64
MAX_CALLS = 512
MAX_PROCESS_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 16_384
_PHASES = {"connect", "authenticate", "request_write_flush", "committed_response_read"}
_IO_OPERATIONS = {
    "unspecified",
    "read_timeout_configuration",
    "stream_read",
    "write_timeout_configuration",
    "flush_timeout_configuration",
    "stream_write",
    "stream_flush",
    "buffered_after_setter_error",
}
_IO_KINDS = {
    "timed_out",
    "would_block",
    "interrupted",
    "unexpected_eof",
    "broken_pipe",
    "connection_reset",
    "connection_aborted",
    "connection_refused",
    "permission_denied",
    "invalid_input",
    "unsupported",
    "other",
}
_CODES = FINITE_FAILURE_CODES | {"unregistered_error", "native_resident_private_root_missing"}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _io(value: object) -> None:
    if value is None:
        return
    _require(type(value) is dict and set(value) == {"operation", "kind", "os_code"}, "io_fields")
    assert isinstance(value, dict)
    _require(value["operation"] in _IO_OPERATIONS and value["kind"] in _IO_KINDS, "io_labels")
    code = value["os_code"]
    _require(code is None or (type(code) is int and -(2**31) <= code < 2**31), "io_code")


def parse_record(line: bytes) -> dict[str, Any]:
    """Only closed schemas with fixed labels and digests can leave the fixture."""
    _require(0 < len(line) < MAX_RECORD_BYTES, "record_bound")
    value = json.loads(line)
    _require(type(value) is dict, "record_type")
    if value.get("schema") == "hol-guard.resident-stream-diagnostic-limit.v1":
        _require(set(value) == {"schema", "maximum_frames", "dropped_frame_reports"}, "limit_fields")
        _require(type(value["maximum_frames"]) is int and value["maximum_frames"] == 128, "frame_bound")
        _require(value["dropped_frame_reports"] is True, "limit_claim")
        return value
    _require(
        set(value)
        == {
            "schema",
            "frame_sequence",
            "maximum_frames",
            "response_bytes",
            "response_sha256",
            "stdout_frame_written",
            "report",
        },
        "frame_fields",
    )
    _require(value["schema"] == "hol-guard.resident-stream-diagnostic-frame.v1", "frame_schema")
    _require(
        _integer(value["frame_sequence"], 127)
        and type(value["maximum_frames"]) is int
        and value["maximum_frames"] == 128,
        "frame_bound",
    )
    _require(
        _integer(value["response_bytes"], 2 * 1024 * 1024) and _digest(value["response_sha256"]), "response_binding"
    )
    _require(type(value["stdout_frame_written"]) is bool, "stdout_claim")
    report = value["report"]
    if report is None:  # No managed request when the original stream lease failed.
        return value
    _require(
        type(report) is dict
        and set(report)
        == {
            "schema",
            "scope",
            "operation_succeeded",
            "operation_error",
            "operation_elapsed_us",
            "deadline_budget_ms",
            "payload_bytes",
            "payload_sha256",
            "events",
            "maximum_events",
            "dropped_events",
            "original_fatal_code",
            "unassigned_io_failure",
            "detail_incomplete",
            "original_operation_result_preserved",
            "headline_timing_eligible",
            "qualification",
            "retries_added",
            "deadlines_changed",
        },
        "report_fields",
    )
    _require(report["schema"] == "hol-guard.resident-stream-request-diagnostic.v1", "report_schema")
    _require(report["scope"] == "explicit_persistent_client_original_frame_operation", "report_scope")
    _require(_integer(report["deadline_budget_ms"], 60_000), "budget_bound")
    _require(
        _integer(report["payload_bytes"], 6 * 1024 * 1024) and _digest(report["payload_sha256"]), "payload_binding"
    )
    _require(_integer(report["operation_elapsed_us"], 60_000_000), "elapsed_bound")
    _require(type(report["maximum_events"]) is int and report["maximum_events"] == 16, "event_bound")
    _require(_integer(report["dropped_events"], 2**64 - 1), "dropped_bound")
    for key in ("operation_error", "original_fatal_code"):
        _require(report[key] is None or (type(report[key]) is str and report[key] in _CODES), "error_label")
    for key in ("operation_succeeded", "detail_incomplete"):
        _require(type(report[key]) is bool, "report_boolean")
    for key in ("headline_timing_eligible", "qualification", "retries_added", "deadlines_changed"):
        _require(report[key] is False, "report_claim")
    _require(report["original_operation_result_preserved"] is True, "original_result")
    _io(report["unassigned_io_failure"])
    events = report["events"]
    _require(type(events) is list and len(events) <= 16, "events_bound")
    assert isinstance(events, list)
    for event in events:
        _require(
            type(event) is dict
            and set(event)
            == {"phase", "started_us", "duration_us", "succeeded", "error_code", "retryable_teardown", "io_failure"},
            "event_fields",
        )
        _require(type(event["phase"]) is str and event["phase"] in _PHASES, "phase_label")
        _require(all(_integer(event[key], 60_000_000) for key in ("started_us", "duration_us")), "phase_times")
        _require(all(type(event[key]) is bool for key in ("succeeded", "retryable_teardown")), "phase_boolean")
        _require(
            event["error_code"] is None or (type(event["error_code"]) is str and event["error_code"] in _CODES),
            "phase_error",
        )
        _io(event["io_failure"])
    return value


class _SubprocessProxy:
    def __init__(self, capture: StreamCapture) -> None:
        self.capture = capture

    def __getattr__(self, name: str) -> Any:
        return self.capture.original_subprocess.__dict__[name]

    def Popen(self, argv: Any, **kwargs: Any) -> subprocess.Popen[bytes]:  # noqa: N802
        return self.capture.spawn(argv, kwargs)


class StreamCapture:
    """Forward the real pool and drain only its explicitly selected children."""

    def __init__(self, runtime: Path) -> None:
        self.runtime = runtime.resolve(strict=True)
        self.original_subprocess = transport.subprocess
        self.original_popen = cast(Callable[..., subprocess.Popen[bytes]], transport.subprocess.Popen)
        self.original_request = transport._PersistentNativeClient.request
        self.stack = ExitStack()
        self.lock = threading.Lock()
        self.local = threading.local()
        self.processes: list[dict[str, Any]] = []
        self.clients: dict[int, Any] = {}
        self.calls: list[dict[str, Any]] = []
        self.total_bytes = 0
        self.dropped_bytes = 0
        self.dropped_calls = 0
        self.unobserved_spawns = 0
        self.cleanup_failed = False
        self.recording_failures = 0

    def _drain(self, entry: dict[str, Any]) -> None:
        stream = entry["process"].stderr
        try:
            while chunk := stream.read(4096):
                with self.lock:
                    room = max(0, min(MAX_PROCESS_BYTES - len(entry["raw"]), MAX_TOTAL_BYTES - self.total_bytes))
                    retained = chunk[:room]
                    entry["raw"].extend(retained)
                    self.total_bytes += len(retained)
                    self.dropped_bytes += len(chunk) - len(retained)
                    entry["dropped_bytes"] += len(chunk) - len(retained)
            entry["eof"] = True
        except (OSError, ValueError):
            entry["reader_failed"] = True
        finally:
            with suppress(OSError, ValueError):
                stream.close()

    def spawn(self, argv: Any, kwargs: dict[str, Any]) -> subprocess.Popen[bytes]:
        entry: dict[str, Any] | None = None
        selected = (
            isinstance(argv, (tuple, list))
            and len(argv) == 4
            and argv[0] == str(self.runtime)
            and tuple(argv[1:3]) == ("resident-client-stream", "--stdin")
            and kwargs.get("stderr") == subprocess.DEVNULL
        )
        with self.lock:
            admitted = selected and len(self.processes) < MAX_PROCESSES
            if selected and not admitted:
                self.unobserved_spawns += 1
            if admitted:
                entry = {
                    "index": len(self.processes),
                    "raw": bytearray(),
                    "eof": False,
                    "reader_failed": False,
                    "dropped_bytes": 0,
                }
                self.processes.append(entry)
        if not admitted:
            return self.original_popen(argv, **kwargs)
        assert entry is not None
        selected_argv = (argv[0], "resident-client-stream-diagnostic", *argv[2:])
        try:
            process = self.original_popen(selected_argv, **{**kwargs, "stderr": subprocess.PIPE})
        except BaseException:
            entry["spawn_failed"] = True
            raise
        entry["process"] = process
        if getattr(self.local, "call", None) is not None:
            self.local.call["process_index"] = entry["index"]
        reader = threading.Thread(target=self._drain, args=(entry,), daemon=True, name="native-stream-diagnostic")
        entry["reader"] = reader
        try:
            reader.start()
        except RuntimeError:
            entry["reader_failed"] = True
            assert process.stderr is not None
            process.stderr.close()  # Exporter ignores EPIPE; the original response remains intact.
        return process

    def request(self, client: Any, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        if client._executable != self.runtime:
            return self.original_request(client, payload, deadline_monotonic=deadline_monotonic)
        row: dict[str, Any] = {"process_index": None}
        with self.lock:
            if len(self.clients) < MAX_PROCESSES:
                self.clients[id(client)] = client
            for entry in self.processes:
                if entry.get("process") is client._process and client._process is not None:
                    row["process_index"] = entry["index"]
                    break
        self.local.call = row
        response = None
        try:
            response = self.original_request(client, payload, deadline_monotonic=deadline_monotonic)
            return response
        finally:
            self.local.call = None
            try:
                row.update(
                    payload_bytes=len(payload),
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                    response_bytes=None if response is None else len(response),
                    response_sha256=None if response is None else hashlib.sha256(response).hexdigest(),
                )
                with self.lock:
                    if len(self.calls) < MAX_CALLS:
                        self.calls.append(row)
                    else:
                        self.dropped_calls += 1
            except Exception:
                self.recording_failures += 1

    def __enter__(self) -> StreamCapture:
        capture = self

        def observed(client: Any, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
            return capture.request(client, payload, deadline_monotonic=deadline_monotonic)

        try:
            self.stack.enter_context(patch.object(transport, "subprocess", _SubprocessProxy(self)))
            self.stack.enter_context(patch.object(transport._PersistentNativeClient, "request", observed))
        except BaseException:
            self.stack.close()
            raise
        return self

    def __exit__(self, *_: object) -> None:
        self.stack.close()
        # The original SLO already ran its resident and session teardown. Only
        # close our retained client objects; never stop an unrelated resident.
        for client in self.clients.values():
            try:
                client.close()
            except Exception:
                self.cleanup_failed = True
        deadline = time.monotonic() + 2.0
        for entry in self.processes:
            reader = entry.get("reader")
            if reader is not None and reader.ident is not None:
                reader.join(timeout=max(0.0, deadline - time.monotonic()))

    def report(self) -> dict[str, Any]:
        entries = []
        witnessed: Counter[tuple[object, ...]] = Counter()
        invalid = missing_reports = 0
        native_loss = False
        for entry in self.processes:
            raw = bytes(entry["raw"])
            records = []
            expected_sequence = 0
            lines = raw.splitlines(keepends=True)
            for line in lines:
                try:
                    _require(line.endswith(b"\n"), "incomplete_line")
                    record = parse_record(line)
                    if record["schema"] == "hol-guard.resident-stream-diagnostic-frame.v1":
                        _require(record["frame_sequence"] == expected_sequence, "frame_sequence")
                        expected_sequence += 1
                except (ValueError, TypeError, KeyError, RecursionError):
                    invalid += 1
                    continue
                records.append(record)
                if record["schema"] == "hol-guard.resident-stream-diagnostic-limit.v1":
                    native_loss = True
                    continue
                report = record["report"]
                if report is None:
                    missing_reports += 1
                    continue
                witnessed[(entry["index"], report["payload_sha256"], record["response_sha256"])] += 1
                native_loss |= report["detail_incomplete"]
            process = entry.get("process")
            entries.append(
                {
                    "process_index": entry["index"],
                    "retained_stderr_bytes": len(raw),
                    "dropped_stderr_bytes": entry["dropped_bytes"],
                    "stderr_eof": entry["eof"],
                    "reader_failed": entry["reader_failed"],
                    "spawn_failed": entry.get("spawn_failed", False),
                    "child_reaped": process is None or process.poll() is not None,
                    "records": records,
                }
            )
        expected: Counter[tuple[object, ...]] = Counter(
            (row["process_index"], row["payload_sha256"], row["response_sha256"]) for row in self.calls
        )
        missing = sum((expected - witnessed).values())
        extra = sum((witnessed - expected).values())
        complete = bool(self.calls) and not (
            invalid
            or missing_reports
            or native_loss
            or self.dropped_bytes
            or self.dropped_calls
            or self.unobserved_spawns
            or self.cleanup_failed
            or self.recording_failures
            or missing
            or extra
        )
        complete &= all(item["stderr_eof"] and item["child_reaped"] and not item["reader_failed"] for item in entries)
        return {
            "schema": "hol-guard.installed-persistent-stream-capture.v1",
            "scope": "explicit_verified_runtime_clients_owned_by_this_python_process",
            "processes": entries,
            "calls": list(self.calls),
            "invalid_records": invalid,
            "missing_request_reports": missing_reports,
            "dropped_stderr_bytes": self.dropped_bytes,
            "dropped_calls": self.dropped_calls,
            "unobserved_spawns": self.unobserved_spawns,
            "cleanup_failed": self.cleanup_failed,
            "recording_failures": self.recording_failures,
            "missing_bound_frames": missing,
            "extra_bound_frames": extra,
            "observation_complete": complete,
            "qualification": False,
            "headline_timing_eligible": False,
            "maximum_processes": MAX_PROCESSES,
            "maximum_calls": MAX_CALLS,
            "maximum_retained_bytes": MAX_TOTAL_BYTES,
        }
