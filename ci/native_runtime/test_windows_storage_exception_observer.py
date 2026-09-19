"""Finite exact-source controls: no Guard import, Windows I/O or native runtime."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from collections import deque
from pathlib import Path
from types import FunctionType, ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "storage_exception_observer_control", HERE / "windows_storage_exception_observer.py"
)
assert spec and spec.loader
observer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = observer
spec.loader.exec_module(observer)
ROOT = Path(os.environ.get("WINDOWS_STORAGE_SOURCE_ROOT", str(HERE.parents[1] / "src/codex_plugin_scanner")))


def exact_class(relative: str, name: str, methods: set[str], globals_: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    path = ROOT / relative
    tree = ast.parse(path.read_bytes())
    original = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    chosen = [n for n in original.body if isinstance(n, ast.FunctionDef) and n.name in methods]
    assert len(chosen) == len(methods)
    namespace = {"__file__": str(path), "contextmanager": contextlib.contextmanager, **globals_}
    compiled = compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
    definitions = {}
    for node in chosen:
        code = observer.nested_code(compiled, name + "." + node.name)
        function = FunctionType(
            code, namespace, node.name, tuple(ast.literal_eval(n) for n in node.args.defaults) or None
        )
        for decorator in reversed(node.decorator_list):
            assert ast.unparse(decorator) == "contextmanager"
            function = contextlib.contextmanager(function)
        definitions[node.name] = function
    return type(name, (), definitions), namespace


class Receipt:
    def __init__(self, number):
        self.record_id = number
        self.receipt = number
        self.payload_bytes = 1


class Condition:
    def __init__(self, operations):
        self.operations = operations

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def wait(self, *, timeout):
        self.operations.append(("writer_wait", timeout))


class Scenario:
    def __init__(self, stage=None, failures=0, batch=1, command=False):
        self.operations = []
        self.stage, self.remaining = stage, failures
        self.error = OSError(13, "PRIVATE_ERROR_MESSAGE")
        self.error.winerror = 32
        self.sqlite_error = sqlite3.OperationalError("PRIVATE_SQLITE_MESSAGE")
        self.sqlite_error.sqlite_errorcode = 5
        self.clock = 0.0
        self.seeks = 0
        self.saved = []
        self.time = SimpleNamespace(monotonic=self.monotonic, sleep=self.sleep)
        self.msvcrt: Any = ModuleType("msvcrt")
        self.msvcrt.LK_NBLCK, self.msvcrt.LK_NBRLCK, self.msvcrt.LK_UNLCK = 1, 2, 3
        self.msvcrt.locking = self.locking
        sql = SimpleNamespace(
            **{name: getattr(sqlite3, name) for name in ("OperationalError", "DatabaseError", "Row")},
            connect=self.connect,
        )
        self.store_class, self.store_globals = exact_class(
            "guard/store_connection_schema.py",
            "StoreConnectionSchemaMixin",
            {"_hold_storage_gate", "_connect_once"},
            {
                "os": SimpleNamespace(name="nt"),
                "time": self.time,
                "sqlite3": sql,
                "sqlite_connect_timeout_seconds": lambda: 0.05,
                "sqlite_error_is_busy_locked": lambda _e: True,
                "SQLITE_CACHE_SIZE_KIB": 1,
                "SQLITE_MMAP_SIZE_BYTES": 1,
                "store_review_event_outbox_schema": SimpleNamespace(
                    finalize_review_event_payload_hashes=lambda _c: None,
                    commit_review_event_transaction=lambda *_a: 1,
                    notify_review_event_wake=lambda *_a: None,
                ),
                "_slow_query_threshold_ms_compat": lambda: 100000,
            },
        )
        self.store = self.store_class()
        self.store._storage_gate_local = threading.local()
        self.store.guard_home = self
        self.store.path = object()
        self.store._sqlite_profiler = lambda: SimpleNamespace(
            record_connect=lambda *_: None,
            record_busy_locked=lambda: None,
            record_transaction=lambda *_: None,
            record_commit=lambda *_: None,
        )
        self.store._take_policy_integrity_state_notification = lambda _c: None
        self.store._repair_store_permissions = lambda: None
        self.store.record_native_decision_receipts = self.save
        self.writer_class, self.writer_globals = exact_class(
            "guard/daemon/runtime_hook_evidence_writer.py",
            "RuntimeHookEvidenceWriter",
            {"_run", "_record_failure_diagnostics", "_record_persistence_failure", "_record_committed"},
            {
                "_NativeDecisionReceiptRecord": Receipt,
                "sqlite_connect_timeout_override": lambda _v: contextlib.nullcontext(),
                "persist_native_decision_receipt": lambda *, store, receipt: bool(
                    store.record_native_decision_receipts((receipt,))
                ),
                "evidence_failure_code": lambda _e: "os_code_unavailable",
            },
        )
        self.writer = w = self.writer_class()
        records = [SimpleNamespace(record_id=1, payload_bytes=1)] if command else [Receipt(i) for i in range(batch)]
        w._records = deque(records)
        w._durable = {r.record_id: r for r in records}
        w._condition = Condition(self.operations)
        w._store = self.store
        w._sqlite_timeout_seconds = 0.05
        w._stopping = False
        w._failures = w._receipt_failures = w._receipt_transactions = w._processed = w._receipt_processed = (
            w._queued_bytes
        ) = 0
        w._failure_diagnostics, w._receipt_failure_diagnostics, w._retry_attempts = {}, {}, {}
        w._checkpoint_pending = set()
        w._degraded = False

        def next_batch():
            result = list(w._records)
            w._records.clear()
            if not result:
                w._stopping = True
            return result

        w._next_batch = next_batch
        w._drain_expired = lambda: False
        w._checkpoint_completed_records = lambda: None
        w._persist_command_activity = lambda _r: self.save((1,))
        self.functions = {
            "gate": self.store_class._hold_storage_gate.__wrapped__,
            "sqlite": self.store_class._connect_once.__wrapped__,
            "writer": self.writer_class._run,
            "units": self.writer_class._record_failure_diagnostics,
        }

    def fault(self, stage):
        self.operations.append((stage,))
        if self.stage == stage and self.remaining:
            self.remaining -= 1
            raise self.sqlite_error if stage == "sqlite_connect" else self.error

    def monotonic(self):
        result = self.clock
        self.clock += 0.04
        self.operations.append(("clock", result))
        return result

    def sleep(self, delay):
        self.operations.append(("sleep", delay))

    def __truediv__(self, _part):
        return self

    def open(self, _mode):
        self.fault("open")
        self.seeks = 0
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.operations.append(("file_close",))

    def seek(self, _value):
        self.seeks += 1
        self.fault("seek")

    def read(self, _n):
        self.fault("read")
        return b""

    def write(self, _raw):
        self.fault("write")
        return 1

    def flush(self):
        self.fault("flush")

    def fileno(self):
        self.operations.append(("fileno",))
        return 7

    def locking(self, _fd, mode, _length):
        self.fault("unlock" if mode == 3 else "lock")

    def connect(self, _path, *, timeout):
        self.fault("sqlite_connect")
        self.operations.append(("sqlite_timeout", timeout))
        return SimpleNamespace(
            row_factory=None,
            execute=self.execute,
            total_changes=0,
            close=lambda: self.operations.append(("sqlite_close",)),
        )

    def execute(self, statement):
        self.operations.append(("execute", statement))
        return SimpleNamespace(fetchone=lambda: ("wal",))

    def save(self, values):
        self.operations.append(("save", len(values)))
        with self.store._hold_storage_gate(exclusive=False), self.store._connect_once():
            self.saved.extend(values)
        return tuple(values)

    def result(self):
        w = self.writer
        return {
            "operations": self.operations,
            "saved": self.saved,
            "failures": w._failures,
            "receipt_failures": w._receipt_failures,
            "processed": w._processed,
            "receipt_processed": w._receipt_processed,
            "diagnostics": w._failure_diagnostics,
        }

    def run(self, observed):
        monitor = observer.SourceBoundStorageObserver(ROOT, self.functions) if observed else None
        with (
            patch.dict(sys.modules, {"msvcrt": self.msvcrt}),
            monitor if monitor is not None else contextlib.nullcontext(),
        ):
            self.writer._run()
        return self.result(), monitor.snapshot() if monitor else None


class Controls(unittest.TestCase):
    def test_source_code_and_callsite_bindings(self):
        scenario = Scenario()
        monitor = observer.SourceBoundStorageObserver(ROOT, scenario.functions)
        self.assertEqual(set(monitor.codes), {"gate", "sqlite", "writer", "units"})
        broken = dict(scenario.functions)
        broken["gate"] = lambda: None
        with self.assertRaisesRegex(observer.ObserverRefusalError, "function_code"):
            observer.SourceBoundStorageObserver(ROOT, broken)

    def test_unobserved_and_observed_operations_and_units_are_equal(self):
        for stage in (None, "open", "seek", "read", "write", "flush", "lock", "unlock", "sqlite_connect"):
            for batch in (1, 4):
                with self.subTest(stage=stage, batch=batch):
                    plain, _ = Scenario(stage, 2 if stage else 0, batch).run(False)
                    observed, report = Scenario(stage, 2 if stage else 0, batch).run(True)
                    assert report is not None
                    self.assertEqual(plain, observed)
                    self.assertTrue(report["complete"], report)
                    receipt_units = sum(
                        row["count"]
                        for row in report["failed_record_attempt_units"]
                        if row["unit"] == "receipt_failed_record_attempt_units"
                    )
                    self.assertEqual(receipt_units, observed["receipt_failures"])
                    self.assertFalse(report["event_to_failed_attempt_join_proven"])

    def test_gate_origin_error_and_replacement_timeout_are_distinct_events(self):
        _, report = Scenario("lock", 2, 4).run(True)
        assert report is not None
        events = {(r["phase"], r["stage"], r["exception_category"]): r for r in report["observations"]}
        origin = events["receipt_persistence", "gate_lock_or_fileno", "PermissionError"]
        timeout = events["receipt_persistence", "gate_timeout", "TimeoutError"]
        self.assertEqual(origin["exception_events"], 2)
        self.assertEqual(origin["errno"], {"kind": "integer", "value": 13})
        self.assertEqual(origin["winerror"], {"kind": "integer", "value": 32})
        self.assertEqual(timeout["errno"], {"kind": "none", "value": None})
        self.assertEqual(report["unit_recording_calls"], 1)
        self.assertEqual(
            sum(
                r["count"]
                for r in report["failed_record_attempt_units"]
                if r["unit"] == "receipt_failed_record_attempt_units"
            ),
            4,
        )

    def test_sqlite_failure_is_not_a_gate_timeout(self):
        _, report = Scenario("sqlite_connect", 1).run(True)
        assert report is not None
        stages = {r["stage"] for r in report["observations"]}
        self.assertIn("sqlite_connect", stages)
        self.assertNotIn("gate_timeout", stages)
        row = next(r for r in report["observations"] if r["stage"] == "sqlite_connect")
        self.assertEqual(row["exception_category"], "OperationalError")
        self.assertEqual(row["sqlite_errorcode"]["value"], 5)

    def test_activity_scope_and_record_units_remain_separate(self):
        plain, _ = Scenario("lock", 2, command=True).run(False)
        actual, report = Scenario("lock", 2, command=True).run(True)
        assert report is not None
        self.assertEqual(plain, actual)
        self.assertEqual({r["phase"] for r in report["observations"]}, {"command_activity_persistence"})
        self.assertEqual(actual["receipt_failures"], 0)

    def test_generator_yield_and_resume_does_not_retain_callback(self):
        s = Scenario()
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with patch.dict(sys.modules, {"msvcrt": s.msvcrt}), m:
            context = s.store._hold_storage_gate(exclusive=False)
            context.__enter__()
            self.assertIsNone(context.gen.gi_frame.f_trace)
            context.__exit__(None, None, None)
        self.assertTrue(m.snapshot()["complete"])
        self.assertIsNone(sys.gettrace())
        self.assertIsNone(threading.gettrace())

    def test_exact_return_and_original_exception_identity(self):
        s = Scenario("open", 1)
        original = s.store_class._hold_storage_gate
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with (
            patch.dict(sys.modules, {"msvcrt": s.msvcrt}),
            self.assertRaises(OSError) as caught,
            m,
            s.store._hold_storage_gate(exclusive=False),
        ):
            self.fail("no admission")
        self.assertIs(caught.exception, s.error)
        self.assertIs(s.store_class._hold_storage_gate, original)
        self.assertIsNone(sys.gettrace())

    def test_preexisting_sys_or_thread_trace_and_thread_refused(self):
        s = Scenario()

        def prior(*_args):
            return prior

        try:
            sys.settrace(prior)
            with (
                self.assertRaisesRegex(observer.ObserverRefusalError, "preexisting_tracer"),
                observer.SourceBoundStorageObserver(ROOT, s.functions),
            ):
                self.fail("must refuse")
            self.assertIs(sys.gettrace(), prior)
        finally:
            sys.settrace(None)
        try:
            threading.settrace(prior)
            with (
                self.assertRaisesRegex(observer.ObserverRefusalError, "preexisting_tracer"),
                observer.SourceBoundStorageObserver(ROOT, s.functions),
            ):
                self.fail("must refuse")
            self.assertIs(threading.gettrace(), prior)
        finally:
            threading.settrace(None)
        event = threading.Event()
        child = threading.Thread(target=event.wait)
        child.start()
        try:
            with (
                self.assertRaisesRegex(observer.ObserverRefusalError, "preexisting_threads"),
                observer.SourceBoundStorageObserver(ROOT, s.functions),
            ):
                self.fail("must refuse")
        finally:
            event.set()
            child.join()

    def test_future_thread_observation_and_trace_restoration(self):
        s = Scenario("lock", 2)
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with patch.dict(sys.modules, {"msvcrt": s.msvcrt}), m:
            child = threading.Thread(target=s.writer._run)
            child.start()
            child.join()
        self.assertTrue(m.snapshot()["complete"])
        self.assertEqual(m.snapshot()["unit_recording_calls"], 1)
        self.assertIsNone(threading.gettrace())

    def test_overflow_refuses_evidence_without_changing_operations(self):
        s = Scenario("lock", 2)
        m = observer.SourceBoundStorageObserver(ROOT, s.functions, maximum_events=1)
        with patch.dict(sys.modules, {"msvcrt": s.msvcrt}), m:
            s.writer._run()
        plain, _ = Scenario("lock", 2).run(False)
        self.assertEqual(s.result(), plain)
        self.assertTrue(m.snapshot()["overflow"])
        self.assertFalse(m.snapshot()["complete"])

    def test_source_byte_drift_refuses_before_workload_and_crlf_is_explicit(self):
        relative = "guard/store_connection_schema.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / relative
            destination.parent.mkdir(parents=True)
            raw = (ROOT / relative).read_bytes()
            destination.write_bytes(raw.replace(b"\n", b"\r\n"))
            self.assertEqual(observer.source_bytes(root, relative).replace(b"\r\n", b"\n"), raw)
            destination.write_bytes(raw + b"\n# changed\n")
            with self.assertRaisesRegex(observer.ObserverRefusalError, "source_bytes"):
                observer.source_bytes(root, relative)

    def test_unknown_exception_properties_are_never_read(self):
        class PrivateError(Exception):
            @property
            def errno(self):
                raise AssertionError("must never read arbitrary properties")

        s = Scenario()
        error = PrivateError("PRIVATE_UNKNOWN_MESSAGE")

        def refused_open(_mode):
            raise error

        s.open = refused_open
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with (
            patch.dict(sys.modules, {"msvcrt": s.msvcrt}),
            self.assertRaises(PrivateError) as caught,
            m,
            s.store._hold_storage_gate(exclusive=False),
        ):
            self.fail("no admission")
        self.assertIs(caught.exception, error)
        self.assertTrue(m.snapshot()["complete"])
        self.assertEqual(m.snapshot()["observations"][0]["exception_category"], "other_exception")
        self.assertEqual(m.snapshot()["observations"][0]["errno"]["kind"], "not_admitted")

    def test_trace_state_restored_for_live_new_thread_and_conflict_flagged(self):
        s = Scenario()
        ready, release = threading.Event(), threading.Event()
        state = []

        def child_body():
            ready.set()
            release.wait()
            state.append(sys.gettrace())

        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with m:
            child = threading.Thread(target=child_body)
            child.start()
            self.assertTrue(ready.wait(timeout=1))
        release.set()
        child.join(timeout=1)
        self.assertFalse(child.is_alive())
        self.assertEqual(state, [None])
        self.assertTrue(m.snapshot()["complete"])
        conflict = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with conflict:
            sys.settrace(None)
        self.assertTrue(conflict.snapshot()["trace_state_conflict"])
        self.assertFalse(conflict.snapshot()["complete"])
        self.assertIsNone(sys.gettrace())
        self.assertIsNone(threading.gettrace())

    def test_callback_failure_and_invalid_unit_shape_refuse_only_evidence(self):
        s = Scenario("open", 1)
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        m._phase = lambda _frame: 1 / 0
        with patch.dict(sys.modules, {"msvcrt": s.msvcrt}), m:
            s.writer._run()
        plain, _ = Scenario("open", 1).run(False)
        self.assertEqual(s.result(), plain)
        self.assertTrue(m.snapshot()["observer_failure"])
        self.assertFalse(m.snapshot()["complete"])
        invalid = observer.SourceBoundStorageObserver(ROOT, s.functions)
        with invalid:
            s.writer._record_failure_diagnostics("receipt_persistence", "fixed", True, 0)
        self.assertFalse(invalid.snapshot()["complete"])

    def test_missing_none_integer_and_other_exception_codes_are_distinct(self):
        error = OSError()
        self.assertEqual(observer.builtin_code(error, "errno"), ("none", None))
        self.assertEqual(observer.builtin_code(error, "unknown_fixed_control"), ("absent", None))
        error.errno = 13
        self.assertEqual(observer.builtin_code(error, "errno"), ("integer", 13))
        error.errno = True
        self.assertEqual(observer.builtin_code(error, "errno"), ("non_integer_or_out_of_range", None))

    def test_partial_trace_setup_rolls_back_and_preserves_setup_exception(self):
        s = Scenario()
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        original_settrace = sys.settrace
        failure = RuntimeError("PRIVATE_SETUP_FAILURE")

        def fail_install(value):
            if value is not None:
                raise failure
            return original_settrace(value)

        with patch.object(sys, "settrace", fail_install), self.assertRaises(RuntimeError) as caught, m:
            self.fail("entry must refuse")
        self.assertIs(caught.exception, failure)
        self.assertIsNone(sys.gettrace())
        self.assertIsNone(threading.gettrace())
        self.assertTrue(m.snapshot()["trace_setup_failure"])
        self.assertTrue(m.snapshot()["trace_state_restored"])
        self.assertFalse(m.snapshot()["complete"])
        self.assertEqual(s.operations, [])

    def test_exit_restoration_failure_never_masks_workload_exception(self):
        s = Scenario()
        m = observer.SourceBoundStorageObserver(ROOT, s.functions)
        failure = RuntimeError("PRIVATE_WORKLOAD_FAILURE")

        def fail_restore(_value):
            raise RuntimeError("PRIVATE_RESTORE_FAILURE")

        with (
            patch.object(threading, "settrace_all_threads", fail_restore),
            self.assertRaises(RuntimeError) as caught,
            m,
        ):
            raise failure
        self.assertIs(caught.exception, failure)
        self.assertIsNone(sys.gettrace())
        self.assertIsNone(threading.gettrace())
        self.assertTrue(m.snapshot()["trace_restoration_failure"])
        self.assertFalse(m.snapshot()["trace_state_restored"])
        self.assertFalse(m.snapshot()["complete"])

    def test_bounded_privacy_and_qualification_limits(self):
        _, report = Scenario("lock", 2).run(True)
        assert report is not None
        raw = json.dumps(report)
        for secret in ("PRIVATE", "storage-access.lock", str(ROOT), "record_id", "payload", "traceback"):
            self.assertNotIn(secret, raw)
        self.assertLess(len(raw), 20000)
        self.assertTrue(report["observer_can_create_50ms_timeouts"])
        self.assertFalse(report["historical_failure_cause_established"])
        self.assertFalse(report["qualification_complete"])
        with (
            self.assertRaisesRegex(observer.ObserverRefusalError, "platform_unsupported"),
            patch.object(sys, "platform", "linux"),
        ):
            observer.bind_installed(ROOT, observer.SOURCE_PINS)


if __name__ == "__main__":
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules)
    unittest.main(verbosity=2)
