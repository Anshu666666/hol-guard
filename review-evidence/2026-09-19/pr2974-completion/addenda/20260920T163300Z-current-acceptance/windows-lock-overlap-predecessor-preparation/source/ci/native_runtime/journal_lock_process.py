"""Bounded direct-child protocol for five independent journal lock cells."""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from ci.native_runtime.journal_lock_child import JOURNAL_SHA256, OPERATIONS, error_record

CHILD = Path(__file__).with_name("journal_lock_child.py")
WAIT_SECONDS = 15.0
RELEASE_WINDOW_SECONDS = 0.25
ROLES = {"holder", "original", "blocking", "nonblocking"}
EVENTS = {"ftruncate_begin", "acquire_begin", "held", "result"}


def validate_report(value: Any) -> dict[str, Any]:
    keys = {
        "role",
        "entered",
        "error",
        "calls",
        "failures",
        "opened_descriptors",
        "original_descriptors_closed",
        "emergency_close_results",
        "callbacks_restored",
        "source_sha256",
    }
    if type(value) is not dict or set(value) != keys:
        raise ValueError("child_report_schema")
    if value["role"] not in ROLES or value["source_sha256"] != JOURNAL_SHA256:
        raise ValueError("child_report_binding")
    if any(type(value[name]) is not bool for name in ("entered", "callbacks_restored")):
        raise ValueError("child_report_boolean")
    calls = value["calls"]
    if (
        type(calls) is not dict
        or set(calls) != set(OPERATIONS)
        or any(type(count) is not int or not 0 <= count <= 8 for count in calls.values())
    ):
        raise ValueError("child_report_calls")
    if type(value["opened_descriptors"]) is not int or not 0 <= value["opened_descriptors"] <= 2:
        raise ValueError("child_report_descriptors")
    for name in ("original_descriptors_closed", "emergency_close_results"):
        if type(value[name]) is not list or len(value[name]) > 2 or any(type(item) is not bool for item in value[name]):
            raise ValueError("child_report_cleanup")
    errors = value["failures"]
    if type(errors) is not list or len(errors) > 8:
        raise ValueError("child_report_failures")
    for item in ([value["error"]] if value["error"] is not None else []) + errors:
        if type(item) is not dict or set(item) not in (
            {"kind", "errno", "winerror"},
            {"operation", "kind", "errno", "winerror"},
        ):
            raise ValueError("child_report_error_schema")
        if item["kind"] not in {"os_error", "permission", "not_found", "runtime", "unregistered"}:
            raise ValueError("child_report_error_kind")
        if "operation" in item and item["operation"] not in OPERATIONS:
            raise ValueError("child_report_operation")
        if any(
            item[name] is not None and (type(item[name]) is not int or not -(2**31) <= item[name] < 2**32)
            for name in ("errno", "winerror")
        ):
            raise ValueError("child_report_scalar")
    return value


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_child_key")
        result[key] = value
    return result


class Child:
    def __init__(self, command: list[str]) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        self.events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=32)
        self.reader_error: dict[str, object] | None = None
        self.frames = 0
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        try:
            stream = self.process.stdout
            if stream is None:
                raise RuntimeError("child_stdout_missing")
            while line := stream.readline(16385):
                self.frames += 1
                if len(line) > 16384 or self.frames > 16:
                    raise ValueError("child_output_bound")
                event = json.loads(line, object_pairs_hook=_pairs)
                if type(event) is not dict or event.get("event") not in EVENTS:
                    raise ValueError("child_event_schema")
                if event["event"] == "result":
                    if set(event) != {"event", "report"}:
                        raise ValueError("child_result_schema")
                    validate_report(event["report"])
                elif set(event) != {"event"}:
                    raise ValueError("child_event_extra")
                self.events.put_nowait(event)
        except BaseException as error:
            self.reader_error = error_record(error)
        finally:
            self.events.put_nowait({"event": "eof"})

    def event(self, timeout: float = WAIT_SECONDS) -> dict[str, Any]:
        event = self.events.get(timeout=timeout)
        if event["event"] == "eof":
            raise RuntimeError("child_protocol_ended")
        return event

    def release(self) -> None:
        stream = self.process.stdin
        if stream is None:
            raise RuntimeError("child_stdin_missing")
        stream.write("release\n")
        stream.flush()

    def retire(self) -> dict[str, object]:
        killed = False
        try:
            self.process.wait(timeout=WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            killed = True
            self.process.kill()
            self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()
        return {
            "returncode": self.process.returncode,
            "killed": killed,
            "reader_joined": not self.thread.is_alive(),
            "reader_error": self.reader_error,
            "frames": self.frames,
        }


def _child(path: Path, role: str) -> Child:
    return Child([sys.executable, "-I", str(CHILD), "--path", str(path), "--role", role])


def _until(child: Child, name: str) -> dict[str, Any]:
    for _ in range(16):
        value = child.event()
        if value["event"] == name:
            return value
        if value["event"] == "result":
            raise RuntimeError("child_ended_before_boundary")
    raise RuntimeError("child_event_count")


def run_cell(path: Path, cell: str) -> dict[str, Any]:
    """Each declared cell has one contender and at most one original holder."""
    if cell not in {"uncontended", "held", "released", "nonblocking", "blocking"}:
        raise ValueError("unknown_cell")
    report: dict[str, Any] = {
        "cell": cell,
        "controller_error": None,
        "holder": None,
        "contender": None,
        "cleanup": [],
        "completed_before_release": None,
        "release_window_seconds": RELEASE_WINDOW_SECONDS,
    }
    holder: Child | None = None
    contender: Child | None = None
    released = False
    try:
        if cell != "uncontended":
            holder = _child(path, "holder")
            _until(holder, "held")
            if cell == "released":
                holder.release()
                released = True
                report["holder"] = _until(holder, "result")["report"]
        contender = _child(path, cell if cell in ("nonblocking", "blocking") else "original")
        result: dict[str, Any] | None = None
        for _ in range(16):
            event = contender.event()
            if event["event"] == "result":
                result = event["report"]
                if holder is not None and not released:
                    report["completed_before_release"] = True
                break
            if event["event"] == "acquire_begin" and cell in ("held", "blocking"):
                try:
                    early = contender.event(timeout=RELEASE_WINDOW_SECONDS)
                except queue.Empty:
                    report["completed_before_release"] = False
                else:
                    if early["event"] != "result":
                        raise RuntimeError("unexpected_acquire_event")
                    report["completed_before_release"] = True
                    result = early["report"]
                if holder is None:
                    raise RuntimeError("holder_missing")
                holder.release()
                released = True
                if result is not None:
                    break
        if result is None:
            raise RuntimeError("contender_result_missing")
        report["contender"] = result
    except BaseException as error:
        report["controller_error"] = error_record(error)
    finally:
        if holder is not None:
            try:
                if not released:
                    holder.release()
                    released = True
                if report["holder"] is None:
                    report["holder"] = _until(holder, "result")["report"]
            except BaseException as error:
                report["holder_cleanup_error"] = error_record(error)
        for child in (contender, holder):
            if child is not None:
                try:
                    report["cleanup"].append(child.retire())
                except BaseException as error:
                    report["cleanup"].append({"retirement_error": error_record(error)})
    return report
