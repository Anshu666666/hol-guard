"""Diagnostic-only forwarding of the original full binary read and hash calls."""

from __future__ import annotations

import contextvars
import copy
import functools
import os
import threading
import time
from collections import Counter
from contextlib import ExitStack
from unittest.mock import patch

MAX_VALIDATIONS = 64
MAX_OPERATIONS = 4096


def byte_length(value):
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, memoryview):
        return value.nbytes
    return None


class ReadValue:
    def __init__(self, probe, original, record):
        self.probe, self.original, self.record = probe, original, record

    def read(self, *args, **kwargs):
        detail = {"requested": args[0] if len(args) == 1 and type(args[0]) is int else None,
                  "keyword_names": sorted(kwargs)}
        return self.probe.operation(self.record, "read", self.original.read, args, kwargs, detail)

    def __getattr__(self, name):
        return getattr(self.original, name)


class ReadContext:
    def __init__(self, probe, original, record):
        self.probe, self.original, self.record = probe, original, record

    def __enter__(self):
        value = self.probe.operation(self.record, "file_enter", self.original.__enter__, (), {})
        return ReadValue(self.probe, value, self.record)

    def __exit__(self, *args):
        return self.probe.operation(self.record, "file_exit", self.original.__exit__, args, {})

    def __getattr__(self, name):
        return getattr(self.original, name)


class DigestValue:
    def __init__(self, probe, original, record):
        self.probe, self.original, self.record = probe, original, record

    def update(self, *args, **kwargs):
        detail = {"input_bytes": byte_length(args[0]) if len(args) == 1 else None,
                  "keyword_names": sorted(kwargs)}
        return self.probe.operation(self.record, "hash_update", self.original.update, args, kwargs, detail)

    def digest(self, *args, **kwargs):
        return self.probe.operation(self.record, "hash_digest", self.original.digest, args, kwargs)

    def hexdigest(self, *args, **kwargs):
        return self.probe.operation(self.record, "hash_hexdigest", self.original.hexdigest, args, kwargs)

    def copy(self, *args, **kwargs):
        value = self.probe.operation(self.record, "hash_copy", self.original.copy, args, kwargs)
        return DigestValue(self.probe, value, self.record)

    def __getattr__(self, name):
        return getattr(self.original, name)


class ValidationHashProbe:
    """Observe only this parent's current validation context, never cache authority."""

    def __init__(self, runtime, *, route_getter=lambda: ("inert", "validation"),
                 maximum_validations=MAX_VALIDATIONS, maximum_operations=MAX_OPERATIONS):
        self.runtime, self.route_getter = runtime, route_getter
        self.maximum_validations, self.maximum_operations = maximum_validations, maximum_operations
        self.pid = os.getpid()
        self.origin = time.perf_counter()
        self.active = contextvars.ContextVar("intel_hash_validation", default=None)
        self.lock = threading.Lock()
        self.records = []
        self.started = self.in_flight = self.discarded_validations = 0
        self.operations = self.discarded_operations = 0
        self.stack = ExitStack()
        self.entered = self.restored = False
        self.original_validate = runtime._validate_binary
        self.original_open = runtime.Path.open
        self.original_sha256 = runtime.hashlib.sha256

    def current(self):
        record = self.active.get()
        if (record is None or os.getpid() != self.pid
                or record["thread_ident"] != threading.get_ident()):
            return None
        return record

    def operation(self, record, label, function, args, kwargs, detail=None):
        if self.current() is not record:
            return function(*args, **kwargs)
        started, cpu = time.perf_counter(), time.thread_time()
        returned, value, exception = False, None, None
        try:
            value = function(*args, **kwargs)
            returned = True
            return value
        except BaseException as error:
            exception = type(error).__name__
            raise
        finally:
            finished, cpu_finished = time.perf_counter(), time.thread_time()
            row = {"label": label, "started_ms": (started - self.origin) * 1000,
                   "finished_ms": (finished - self.origin) * 1000,
                   "wall_ms": (finished - started) * 1000,
                   "calling_thread_cpu_ms": (cpu_finished - cpu) * 1000,
                   "returned": returned, "exception_type": exception, **(detail or {})}
            if returned and label == "read":
                row["output_bytes"] = byte_length(value)
            if returned and label == "hash_hexdigest":
                row["hexdigest"] = value if type(value) is str and len(value) == 64 else None
            if returned and label == "hash_constructor":
                row["provider"] = {"module": type(value).__module__, "class": type(value).__qualname__}
            with self.lock:
                record["operation_counts"][label] += 1
                self.operations += 1
                if returned and label == "read" and row["output_bytes"] is not None:
                    record["logical_read_bytes"] += row["output_bytes"]
                if returned and label == "hash_update" and row.get("input_bytes") is not None:
                    record["logical_hash_update_bytes"] += row["input_bytes"]
                if len(record["operations"]) < self.maximum_operations and self.operations <= self.maximum_operations:
                    record["operations"].append(row)
                else:
                    self.discarded_operations += 1
                    record["discarded_operations"] += 1

    def validation(self, function):
        @functools.wraps(function)
        def measured(*args, **kwargs):
            route = self.route_getter()
            if os.getpid() != self.pid or route is None:
                return function(*args, **kwargs)
            with self.lock:
                self.started += 1
                self.in_flight += 1
                if len(self.records) < self.maximum_validations:
                    record = {"validation_id": self.started, "thread_ident": threading.get_ident(),
                              "route": list(route), "operations": [], "operation_counts": Counter(),
                              "logical_read_bytes": 0, "logical_hash_update_bytes": 0,
                              "discarded_operations": 0, "complete": False}
                    self.records.append(record)
                else:
                    record = None
                    self.discarded_validations += 1
            token = self.active.set(record)
            started, cpu = time.perf_counter(), time.thread_time()
            returned, value, exception = False, None, None
            try:
                value = function(*args, **kwargs)
                returned = True
                return value
            except BaseException as error:
                exception = type(error).__name__
                raise
            finally:
                finished, cpu_finished = time.perf_counter(), time.thread_time()
                self.active.reset(token)
                identity = None
                identity_type = getattr(self.runtime, "NativeRuntimeIdentity", ())
                if returned and isinstance(value, identity_type):
                    identity = {"path": str(value.path), "size": value.size,
                                "mtime_ns": value.mtime_ns, "sha256": value.sha256}
                with self.lock:
                    self.in_flight -= 1
                    if record is not None:
                        record.update(complete=True, returned=returned, returned_none=value is None,
                                      exception_type=exception, identity=identity,
                                      started_ms=(started - self.origin) * 1000,
                                      finished_ms=(finished - self.origin) * 1000,
                                      wall_ms=(finished - started) * 1000,
                                      calling_thread_cpu_ms=(cpu_finished - cpu) * 1000)
        return measured

    def open(self, path, *args, **kwargs):
        record = self.current()
        if record is None:
            return self.original_open(path, *args, **kwargs)
        detail = {"path": str(path), "mode": args[0] if args and type(args[0]) is str else kwargs.get("mode"),
                  "keyword_names": sorted(kwargs)}
        value = self.operation(record, "file_open", self.original_open, (path, *args), kwargs, detail)
        return ReadContext(self, value, record)

    def sha256(self, *args, **kwargs):
        record = self.current()
        if record is None:
            return self.original_sha256(*args, **kwargs)
        detail = {"initial_bytes": byte_length(args[0]) if args else 0,
                  "keyword_names": sorted(kwargs)}
        value = self.operation(record, "hash_constructor", self.original_sha256, args, kwargs, detail)
        return DigestValue(self, value, record)

    def __enter__(self):
        if self.entered:
            raise RuntimeError("A validation hash observer cannot be reused")
        self.entered = True
        @functools.wraps(self.original_open)
        def opened(path, *args, **kwargs):
            return self.open(path, *args, **kwargs)
        try:
            self.stack.enter_context(patch.object(self.runtime.Path, "open", opened))
            self.stack.enter_context(patch.object(self.runtime.hashlib, "sha256", self.sha256))
            self.stack.enter_context(patch.object(
                self.runtime, "_validate_binary", self.validation(self.original_validate)))
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_args):
        self.stack.close()
        self.restored = (
            self.runtime._validate_binary is self.original_validate
            and self.runtime.Path.open is self.original_open
            and self.runtime.hashlib.sha256 is self.original_sha256)

    def report(self):
        with self.lock:
            return {"schema": "pr2974.intel-binary-hash-operations.v1",
                    "records": copy.deepcopy(self.records),
                    "validation_calls": self.started, "in_flight": self.in_flight,
                    "discarded_validations": self.discarded_validations,
                    "operation_calls": self.operations, "discarded_operations": self.discarded_operations,
                    "validation_bound": self.maximum_validations, "operation_bound": self.maximum_operations,
                    "complete": not self.in_flight and not self.discarded_validations and not self.discarded_operations,
                    "patches_restored": self.restored, "scope": "parent_current_validation_calling_thread",
                    "file_contents_recorded": False, "new_reads_or_hashes": False,
                    "physical_io_measured": False, "headline_timing_eligible": False,
                    "qualification_complete": False}


def validate_hash_report(value, *, expected_size, expected_sha256, expected_path, expected_calls=16):
    """Require the observed original loop; never fill missing measurements."""
    assert value["complete"] and value["patches_restored"]
    assert value["validation_calls"] == expected_calls and len(value["records"]) == expected_calls
    assert len({row["validation_id"] for row in value["records"]}) == expected_calls
    successful = []
    for row in value["records"]:
        assert row["complete"] and row["returned"] and not row["returned_none"]
        assert row["exception_type"] is None and row["discarded_operations"] == 0
        assert row["identity"]["path"] == expected_path
        assert row["identity"]["size"] == expected_size and row["identity"]["sha256"] == expected_sha256
        assert row["logical_read_bytes"] == expected_size == row["logical_hash_update_bytes"]
        counts = row["operation_counts"]
        chunks = (expected_size + 1024 * 1024 - 1) // (1024 * 1024)
        expected_counts = {"file_open": 1, "file_enter": 1, "file_exit": 1,
                           "hash_constructor": 1, "hash_hexdigest": 1, "read": chunks + 1}
        if chunks:
            expected_counts["hash_update"] = chunks
        assert dict(counts) == expected_counts
        operations = row["operations"]
        assert len(operations) == sum(expected_counts.values())
        expected_order = ["hash_constructor", "file_open", "file_enter"]
        for _index in range(chunks):
            expected_order.extend(("read", "hash_update"))
        expected_order.extend(("read", "file_exit", "hash_hexdigest"))
        assert [item["label"] for item in operations] == expected_order
        assert all(item["returned"] and item["exception_type"] is None for item in operations)
        assert all(item["wall_ms"] >= 0 and item["calling_thread_cpu_ms"] >= 0 for item in operations)
        reads = [item for item in operations if item["label"] == "read"]
        updates = [item for item in operations if item["label"] == "hash_update"]
        expected_chunks = [1024 * 1024] * (expected_size // (1024 * 1024))
        if expected_size % (1024 * 1024):
            expected_chunks.append(expected_size % (1024 * 1024))
        assert [item["output_bytes"] for item in reads] == expected_chunks + [0]
        assert [item["input_bytes"] for item in updates] == expected_chunks
        assert all(item["requested"] == 1024 * 1024 and not item["keyword_names"] for item in reads)
        opens = [item for item in operations if item["label"] == "file_open"]
        assert opens[0]["path"] == expected_path and opens[0]["mode"] == "rb"
        constructors = [item for item in operations if item["label"] == "hash_constructor"]
        assert constructors[0]["initial_bytes"] == 0 and not constructors[0]["keyword_names"]
        assert [item["hexdigest"] for item in operations if item["label"] == "hash_hexdigest"] == [expected_sha256]
        successful.append({"validation_id": row["validation_id"], "provider": constructors[0]["provider"],
                           "logical_read_bytes": row["logical_read_bytes"],
                           "logical_hash_update_bytes": row["logical_hash_update_bytes"]})
    return {"validated_calls": expected_calls, "full_original_loop_observed": True, "calls": successful,
            "logical_total_bytes_per_boundary": expected_size * expected_calls,
            "physical_io_measured": False, "qualification_complete": False}
