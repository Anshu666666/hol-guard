"""Finite observer/driver controls using fake operations and owned Python children.

No Guard package, native runtime, daemon, socket or measured cohort is run.
"""

from __future__ import annotations

import ast
import contextvars
import copy
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


observer = load("hol_guard_macos_attribution_observer", "macos_intel_attribution_observer.py")
driver = load("macos_attribution_driver_controls", "probe_macos_intel_attribution.py")


class Clock:
    def __init__(self):
        self.value = 0

    def __call__(self):
        self.value += 10
        return self.value


def new_observer(**kwargs):
    return observer.Observer(clock=Clock(), cpu_clock=None, **kwargs)


class ObserverControls(unittest.TestCase):
    def test_nested_existing_capacity_capture_keeps_context_and_restoration(self):
        root = os.environ.get("MACOS_ATTRIBUTION_SOURCE_ROOT")
        if root is None:
            self.skipTest("exact original checkout supplied separately")
        events = []
        context: contextvars.ContextVar[str | None] = contextvars.ContextVar("control_native_failure", default=None)

        def code():
            events.append("original_code_read")
            return context.get()

        def clock():
            events.append("original_clock_read")
            return 1.0

        @contextmanager
        def collect():
            yield {}

        namespace: dict[str, Any] = {
            "native_resident_client_failure_code": code,
            "_code": lambda value: {"value": value},
            "time": SimpleNamespace(monotonic=clock),
            "collect_native_edge_stages": collect,
            "capture_native_edge_stages": collect,
            "contextmanager": contextmanager,
            "patch": patch,
            "_milliseconds": lambda value: value * 1000,
            "_number": lambda value: value,
            "Mapping": Mapping,
            "cast": cast,
            "_publisher_cached_state": lambda worker: {},
            "_MAX_NATIVE_DETAILS": 10,
        }
        statements = []
        for filename, wanted in (
            ("native_slo_native_diagnostic.py", "observe_native_call"),
            ("native_slo_capacity_diagnostic.py", "capture_native"),
        ):
            tree = ast.parse((Path(root) / "scripts" / filename).read_bytes())
            statements.append(next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == wanted))
        module = ast.Module(
            body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *statements],
            type_ignores=[],
        )
        exec(compile(ast.fix_missing_locations(module), "exact_original_capture_functions", "exec"), namespace)
        value, failure = object(), RuntimeError("PRIVATE_NATIVE_CONTROL")

        class Worker:
            def __init__(self):
                self.received = {}

            def _review_raw_hook_native(self, **kwargs):
                self.received = kwargs
                context.set("native_client_timed_out")
                if kwargs.get("raise_control"):
                    raise failure
                return value

        worker = Worker()
        diagnostic = SimpleNamespace(
            worker=worker,
            _lock=threading.Lock(),
            native_count=0,
            limit=10,
            native_count_saturated=False,
            native_missing=0,
            native_details=[],
        )
        observed = new_observer()
        original = Worker._review_raw_hook_native
        with observer.Patches() as patches:
            patches.wrap(Worker, "_review_raw_hook_native", lambda fn: observed.wrap(fn, "worker_native"))
            for raising in (False, True):
                events.clear()
                context.set(None)
                with namespace["capture_native"](diagnostic):
                    if raising:
                        with self.assertRaises(RuntimeError) as raised:
                            worker._review_raw_hook_native(deadline=10.0, raise_control=True)
                        self.assertIs(raised.exception, failure)
                        self.assertEqual(events, ["original_code_read", "original_clock_read"])
                    else:
                        self.assertIs(worker._review_raw_hook_native(deadline=10.0), value)
                        self.assertEqual(
                            events,
                            ["original_code_read", "original_clock_read", "original_code_read", "original_clock_read"],
                        )
                self.assertEqual(context.get(), "native_client_timed_out")
                self.assertEqual(diagnostic.native_status, "capture_window_closed")
                self.assertNotIn("_review_raw_hook_native", vars(worker))
            self.assertEqual(worker.received["deadline"], 10.0)
        self.assertIs(Worker._review_raw_hook_native, original)
        self.assertNotIn("PRIVATE_NATIVE_CONTROL", json.dumps(observed.report()))

    def test_original_argument_deadline_return_and_exception_identity(self):
        captured, value, argument, deadline = [], object(), object(), object()

        def original(*args, **kwargs):
            captured.append((args, kwargs))
            return value

        observed = new_observer()
        self.assertIs(observed.wrap(original, "native_edge")(argument, deadline=deadline), value)
        self.assertEqual(len(captured), 1)
        self.assertIs(captured[0][0][0], argument)
        self.assertIs(captured[0][1]["deadline"], deadline)
        for failure in (
            RuntimeError("PRIVATE_VALUE"),
            KeyboardInterrupt("PRIVATE_VALUE"),
        ):
            calls = []

            def raises(calls=calls, failure=failure):
                calls.append(True)
                raise failure

            with self.assertRaises(type(failure)) as raised:
                observed.wrap(raises, "native_edge")()
            self.assertIs(raised.exception, failure)
            self.assertEqual(calls, [True])
        self.assertNotIn("PRIVATE_VALUE", json.dumps(observed.report()))

    def test_descriptor_binding_and_absent_override_restoration(self):
        class Methods:
            @staticmethod
            def static(value):
                return value

            @classmethod
            def class_method(cls, value):
                return cls, value

            def method(self, value):
                return self, value

        old = dict(vars(Methods))
        instance, value = Methods(), object()
        observed = new_observer()
        with observer.Patches() as patches:
            for name in ("static", "class_method", "method"):
                patches.wrap(
                    Methods,
                    name,
                    lambda original: observed.wrap(original, "native_edge"),
                )
            self.assertIs(instance.static(value), value)
            self.assertIs(Methods.static(value), value)
            self.assertEqual(instance.class_method(value), (Methods, value))
            self.assertEqual(instance.method(value), (instance, value))
        self.assertEqual(dict(vars(Methods)), old)
        with self.assertRaisesRegex(RuntimeError, "control"), observer.Patches() as patches:
            patches.wrap(
                instance,
                "method",
                lambda original: observed.wrap(original, "native_edge"),
            )
            self.assertEqual(instance.method(value), (instance, value))
            raise RuntimeError("control")
        self.assertNotIn("method", vars(instance))

    def test_observer_clock_or_fact_error_cannot_replace_original(self):
        def broken_clock():
            raise RuntimeError("PRIVATE_CLOCK")

        value = object()
        observed = observer.Observer(clock=broken_clock, cpu_clock=None)
        self.assertIs(observed.wrap(lambda: value, "native_edge")(), value)
        self.assertFalse(observed.report()["complete"])
        observed = new_observer()
        self.assertIs(observed.wrap(lambda: value, "scheduler_acquire")(), value)
        self.assertIn("observer_error", observed.report()["issues"])

    def test_admission_uses_returned_permit_item_without_releasing(self):
        class Permit:
            _item = SimpleNamespace(queued_at=1.0, admitted_at=1.25)

            def release(self):
                raise AssertionError("observer released permit")

        observed = new_observer()
        for permit in (Permit(), None):
            value = SimpleNamespace(permit=permit)
            self.assertIs(observed.wrap(lambda value=value: value, "scheduler_acquire")(), value)
        self.assertEqual(observed.records[0].facts["scheduler_queue_ns"], 250_000_000)
        self.assertFalse(observed.records[1].facts["admitted"])
        self.assertNotIn("scheduler_queue_ns", observed.records[1].facts)
        value = SimpleNamespace(permit=SimpleNamespace(_item=SimpleNamespace(queued_at=1.0, admitted_at=None)))
        self.assertIs(observed.wrap(lambda: value, "scheduler_acquire")(), value)
        self.assertTrue(observed.records[-1].facts["admitted"])
        self.assertNotIn("scheduler_queue_ns", observed.records[-1].facts)

    def test_same_stack_nesting_and_separate_request_domains(self):
        observed = new_observer()
        leaf = observed.wrap(lambda: True, "native_edge")
        server = observed.wrap(leaf, "server_hook")
        load_call = observed.wrap(server, "load_request")
        with observed.window("c16"):
            load_call()
        self.assertIsNone(observed.records[1].parent)
        self.assertIs(observed.records[2].parent, observed.records[1])
        report = observed.report()
        self.assertFalse(report["cross_domain_joins"])
        self.assertFalse(report["inclusive_spans_are_additive"])
        self.assertEqual({s.domain for s in observed.records}, {"load", "server"})

    def test_interleaved_threads_never_share_parent_spans(self):
        observed = observer.Observer(cpu_clock=None)
        barrier = threading.Barrier(2, timeout=2)
        failures = []
        leaf = observed.wrap(lambda: barrier.wait(), "native_edge")
        root = observed.wrap(leaf, "server_hook")

        def invoke():
            try:
                root()
            except BaseException as error:
                failures.append(type(error).__name__)

        threads = [threading.Thread(target=invoke) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
        self.assertFalse(failures)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(observed.records), 4)
        for span in observed.records:
            if span.parent:
                self.assertIs(span.owner, span.parent.owner)
        self.assertTrue(observed.report()["complete"])

    def test_copied_context_does_not_join_a_different_thread(self):
        observed = observer.Observer(cpu_clock=None)

        def original():
            context = contextvars.copy_context()
            thread = threading.Thread(target=lambda: context.run(observed.wrap(lambda: True, "native_edge")))
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

        observed.wrap(original, "server_hook")()
        self.assertIsNone(observed.records[1].parent)
        self.assertIn("cross_thread_context", observed.report()["issues"])

    def test_total_record_thread_request_and_depth_caps(self):
        observed = new_observer(maximum_records=3)
        operation = observed.wrap(lambda: True, "native_edge")
        self.assertTrue(all(operation() for _ in range(20)))
        self.assertEqual(len(observed.records), 3)
        self.assertIn("record_limit", observed.report()["issues"])
        observed = new_observer(maximum_threads=1)
        observed.wrap(lambda: True, "native_edge")()
        thread = threading.Thread(target=observed.wrap(lambda: True, "native_edge"))
        thread.start()
        thread.join(timeout=2)
        self.assertEqual(len(observed.threads), 1)
        self.assertIn("thread_limit", observed.report()["issues"])
        observed = new_observer()
        leaf = observed.wrap(lambda: True, "native_edge")
        observed.wrap(lambda: [leaf() for _ in range(140)], "server_hook")()
        self.assertEqual(len(observed.records), observer.MAX_REQUEST_RECORDS)
        self.assertIn("request_limit", observed.report()["issues"])
        observed = new_observer()

        def descend(remaining):
            return recurse(remaining - 1) if remaining else True

        recurse = observed.wrap(descend, "native_edge")
        self.assertTrue(recurse(40))
        self.assertEqual(len(observed.records), observer.MAX_DEPTH)
        self.assertIn("depth_limit", observed.report()["issues"])

    def test_write_remainder_distinguishes_no_write_failure_and_return(self):
        for written, answer, expect in (
            (None, None, None),
            (False, None, None),
            (True, None, "post_write_failure_ns"),
            (True, b"ok", "post_write_success_ns"),
        ):
            observed = new_observer()
            write = observed.wrap(lambda written=written: written, "client_write")

            def operation(written=written, write=write, answer=answer):
                if written is not None:
                    write()
                return answer

            self.assertIs(observed.wrap(operation, "client_request")(), answer)
            facts = observed.records[0].facts
            intervals = {key: value for key, value in facts.items() if key.startswith("post_write_")}
            self.assertEqual(
                [key for key, value in intervals.items() if value is not None],
                [expect] if expect else [],
            )

    def test_actual_spawn_attempts_and_reuse_are_distinct(self):
        observed = new_observer()
        process, captured = object(), []

        def create(*args, **kwargs):
            captured.append((args, kwargs))
            return process

        module = SimpleNamespace(Popen=create, PIPE=object(), TimeoutExpired=RuntimeError)
        facade = observer.SubprocessFacade(module, observed.wrap(module.Popen, "client_spawn"))
        self.assertIs(facade.PIPE, module.PIPE)
        self.assertIs(facade.TimeoutExpired, module.TimeoutExpired)
        argv, environment = object(), object()

        def start():
            self.assertIs(facade.Popen(argv, env=environment), process)
            return True

        observed.wrap(start, "client_start")()
        observed.wrap(lambda: True, "client_start")()
        self.assertIs(captured[0][0][0], argv)
        self.assertIs(captured[0][1]["env"], environment)
        self.assertEqual(observed.records[0].facts["spawn_attempts"], 1)
        self.assertFalse(observed.records[0].facts["reused_without_spawn"])
        self.assertTrue(observed.records[-1].facts["reused_without_spawn"])
        self.assertIs(module.Popen, create)

    def test_original_launcher_time_is_distinct_from_inclusive_span(self):
        observed = new_observer()
        self.assertEqual(observed.wrap(lambda: 12.5, "launcher_inclusive")(), 12.5)
        span = observed.records[0]
        self.assertEqual(span.facts["original_launcher_latency_ns"], 12_500_000)
        self.assertNotEqual(observed.interval(span.started, span.ended), 12_500_000)

    def test_creation_failure_and_post_creation_refusal_remain_distinct(self):
        for creation_fails in (True, False):
            observed = new_observer()

            def create(creation_fails=creation_fails):
                if creation_fails:
                    raise OSError("PRIVATE_CREATION_FAILURE")
                return object()

            facade = observer.SubprocessFacade(SimpleNamespace(Popen=create), observed.wrap(create, "client_spawn"))

            def start(facade=facade):
                try:
                    facade.Popen()
                except OSError:
                    return False
                return False

            self.assertIs(observed.wrap(start, "client_start")(), False)
            facts = observed.records[0].facts
            self.assertEqual(facts["spawn_attempts"], 1)
            self.assertEqual(facts["spawn_returns"], 0 if creation_fails else 1)
            self.assertFalse(facts["reused_without_spawn"])

    def test_original_launcher_aliases_forward_argv_stdin_and_authoritative_deadline(self):
        root = os.environ.get("MACOS_ATTRIBUTION_SOURCE_ROOT")
        if root is None:
            self.skipTest("exact original checkout supplied separately")
        tree = ast.parse((Path(root) / "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py").read_bytes())
        function = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_isolated_hook_process"
        )
        module = ModuleType("exact_original_launcher_alias_control")
        captured, child = [], object()

        def spawn(*args, **kwargs):
            captured.append(("spawn", args, kwargs))
            return child, None, None

        def io(*args, **kwargs):
            captured.append(("io", args, kwargs))
            return bytearray(b"safe"), bytearray(), threading.Event(), threading.Lock(), []

        def wait(*args, **kwargs):
            captured.append(("wait", args, kwargs))
            return 0, False, True, False

        def cleanup(*args, **kwargs):
            captured.append(("cleanup", args, kwargs))
            return None, True, False

        def forbidden(*args, **kwargs):
            raise AssertionError("unvisited lifecycle control")

        module.__dict__.update(
            {
                "_HOOK_PROCESS_CONTAINMENT_FAILED": threading.Event(),
                "_HOOK_SUBPROCESS_OUTPUT_LIMIT": 1_000_000,
                "_spawn_hook_process": spawn,
                "start_hook_io": io,
                "wait_for_hook_process": wait,
                "join_and_cleanup_hook_process": cleanup,
                "time": SimpleNamespace(monotonic=lambda: 1.0),
                "_retry_quarantined_hook_processes": forbidden,
                "_kill_hook_process": forbidden,
                "_quarantine_hook_process": forbidden,
                "_close_process_streams": forbidden,
                "close_windows_hook_job": forbidden,
                "_decode_combined_output": lambda out, err, limit: ("safe", ""),
                "BoundedHookProcessResult": lambda **kwargs: SimpleNamespace(**kwargs),
            }
        )
        code = ast.Module(
            body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), function],
            type_ignores=[],
        )
        exec(compile(ast.fix_missing_locations(code), "exact_original_launcher_control", "exec"), module.__dict__)
        command, environment, stdin, directory = ("python", "-c", "BOOTSTRAP", "CONFIG"), {}, "PRIVATE_STDIN", object()
        observed = new_observer()
        with observer.Patches() as patches:
            for name, label in (
                ("_spawn_hook_process", "launcher_spawn"),
                ("start_hook_io", "launcher_io_start"),
                ("wait_for_hook_process", "launcher_wait"),
                ("join_and_cleanup_hook_process", "launcher_cleanup"),
            ):
                patches.wrap(module, name, lambda fn, label=label: observed.wrap(fn, label))
            result = module.run_isolated_hook_process(
                command,
                cwd=directory,
                environment=environment,
                input_text=stdin,
                timeout_seconds=7.0,
                deadline_monotonic=9.25,
                output_limit=1234,
            )
        self.assertEqual([name for name, *_ in captured], ["spawn", "io", "wait", "cleanup"])
        self.assertIs(captured[0][1][0], command)
        self.assertIs(captured[0][2]["environment"], environment)
        self.assertIs(captured[0][2]["cwd"], directory)
        self.assertIs(captured[1][1][0], child)
        self.assertIs(captured[1][2]["input_text"], stdin)
        self.assertEqual(captured[1][2]["output_limit"], 1234)
        self.assertEqual(captured[2][2]["deadline"], 9.25)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(observed.records), 4)
        self.assertIs(module.start_hook_io, io)
        self.assertNotIn("PRIVATE_STDIN", json.dumps(observed.report()))

    def test_report_has_no_arguments_records_identifiers_or_free_text(self):
        observed = new_observer()
        observed.wrap(lambda *a, **kw: object(), "native_edge")("PRIVATE_CANARY", path="/private/home/key")
        result = observed.report()
        self.assertLessEqual(len(observer.encoded(result)), observer.MAX_OUTPUT_BYTES)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))
        self.assertNotIn("/private/home", json.dumps(result))
        self.assertFalse(result["raw_events_exported"])
        with patch.object(observer, "MAX_OUTPUT_BYTES", 1):
            self.assertEqual(observed.report()["rows"], [])


class DriverControls(unittest.TestCase):
    def test_both_modes_have_identical_parent_import_and_admission_setup(self):
        expected = [
            "scripts.native_slo_session",
            "scripts.native_slo_launcher",
            "scripts.native_slo_capacity",
            "codex_plugin_scanner.guard.daemon.server",
            "codex_plugin_scanner.guard.daemon.runtime_hook_scheduler",
            "codex_plugin_scanner.guard.daemon.hook_worker",
            "codex_plugin_scanner.guard.native_runtime",
            "codex_plugin_scanner.guard.native_resident_stream",
            "codex_plugin_scanner.guard.native_resident_client",
            "codex_plugin_scanner.guard.codex_hook_launch_runtime",
        ]
        sequences = []
        for active in (False, True):
            events, wrapped = [], []
            benchmark, observation = object(), object()
            modules = {name: object() for name in expected}

            def importing(name, events=events, modules=modules):
                events.append(("import", name))
                return modules[name]

            @contextmanager
            def activate(
                selected_benchmark,
                selected_observer,
                targets,
                benchmark=benchmark,
                observation=observation,
                modules=modules,
                wrapped=wrapped,
            ):
                self.assertIs(selected_benchmark, benchmark)
                self.assertIs(selected_observer, observation)
                self.assertEqual(list(targets.values()), list(modules.values()))
                wrapped.append("enter")
                try:
                    yield
                finally:
                    wrapped.append("exit")

            importer: Any = SimpleNamespace(verify_loaded=lambda events=events: events.append(("admission", None)))
            sys.meta_path.append(importer)
            try:
                with (
                    patch.object(driver.importlib, "import_module", importing),
                    patch.object(driver, "instrument", activate),
                    driver.prepared_measurement(benchmark, observation, importer, active),
                ):
                    self.assertNotIn(importer, sys.meta_path)
                    self.assertEqual(wrapped, ["enter"] if active else [])
                    events.append(("measure", None))
            finally:
                if importer in sys.meta_path:
                    sys.meta_path.remove(importer)
            self.assertEqual(wrapped, ["enter", "exit"] if active else [])
            sequences.append(events)
        self.assertEqual(sequences[0], sequences[1])
        self.assertEqual(
            sequences[0], [("import", name) for name in expected] + [("admission", None), ("measure", None)]
        )
        self.assertFalse(
            any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules)
        )

    def test_sampler_identity_and_total_allocation_bounds(self):
        tracked = set(range(10, 4106))
        rows = [(1, 0, 2), (2, 1, 3), (9, 0, 4)]
        with self.assertRaises(driver.DiagnosticError):
            driver.sample_tree(rows, 1, 9, tracked)
        self.assertEqual(len(tracked), 4096)
        with self.assertRaises(driver.DiagnosticError):
            driver.sample_tree(rows, 1, 99, set())
        selected, next_ids, rss = driver.sample_tree(rows, 1, 9, set())
        self.assertEqual(selected, rows[:2])
        self.assertEqual(next_ids, {2})
        self.assertEqual(rss, 4096)
        cyclic = [(1, 2, 0), (2, 1, 0), (3, 2, 0)]
        self.assertEqual(driver.descendant_rows(cyclic, 1), cyclic)

    def test_original_failed_gate_remains_failed_and_receipt_drift_rejected(self):
        source = {"revision": driver.SOURCE_SHA, "tree": driver.SOURCE_TREE, "sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = {
                "schema": "hol-guard.macos-attribution-arm.v1",
                "mode": "plain",
                "ordinal": 0,
                "source_before": source,
                "source_after": source,
                "wheel_sha256": driver.WHEEL_SHA,
                "runtime_sha256": driver.RUNTIME_SHA,
                "completed": True,
                "source_unchanged": True,
                "installed_unchanged": True,
                "observer_complete": True,
                "benchmark_returncode": 1,
            }
            latency = {"count": 16, "p50_ms": 900.0, "p95_ms": 1009.107, "p99_ms": 1009.107, "max_ms": 1009.107}
            slo: dict[str, Any] = {
                "passed": False,
                "concurrency": {"sixteen": {"latency": latency}, "sixty_four": {"latency": latency}},
                "latency": {"cold_native_oneshot": latency, "warm_all_harnesses": latency},
                "installed_launcher": {"latency": latency},
                "ignored_control_text": "PRIVATE_CANARY",
            }
            for name, item in (
                ("arm", value),
                ("slo", slo),
                ("identity", {}),
                ("default_auto", {}),
                ("pi", {}),
                ("environment-before", {}),
                ("environment-after", {}),
            ):
                driver.write_json(directory / (name + ".json"), item)
            retained = driver.arm_evidence(directory, 0, "plain", source)
            self.assertTrue(retained["complete"])
            self.assertFalse(retained["original_gates_passed"])
            self.assertEqual(retained["benchmark_returncode"], 1)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(retained))
            for key, replacement in (
                ("ordinal", False),
                ("ordinal", 1),
                ("mode", "observed"),
                ("wheel_sha256", "0" * 64),
                ("source_after", {}),
                ("benchmark_returncode", True),
                ("benchmark_returncode", 0),
            ):
                changed = value | {key: replacement}
                (directory / "arm.json").write_bytes(driver.encode(changed))
                with self.subTest(field=key, value=replacement), self.assertRaises(driver.DiagnosticError):
                    driver.arm_evidence(directory, 0, "plain", source)
            (directory / "arm.json").write_bytes(driver.encode(value))
            for replacement in (True, -1.0, "PRIVATE_LATENCY", 2_100_001):
                changed = copy.deepcopy(slo)
                changed["concurrency"]["sixteen"]["latency"]["p95_ms"] = replacement
                (directory / "slo.json").write_bytes(driver.encode(changed))
                with self.subTest(latency=replacement), self.assertRaises(driver.DiagnosticError):
                    driver.arm_evidence(directory, 0, "plain", source)

    def test_incomplete_or_failed_pair_is_never_promoted_or_replaced(self):
        rows: list[dict[str, Any]] = [
            {"ordinal": i, "mode": mode, "state": "unvisited"} for i, mode in enumerate(driver.SCHEDULE)
        ]
        self.assertTrue(all(pair["complete"] is False for pair in driver.paired_results(rows)))
        latency = {name: {"count": 2, "p95_ms": 2} for name in ("c16", "c64", "warm", "cold", "launcher")}
        for row in rows:
            row.update(
                evidence={"complete": True, "original_gates_passed": False, "latency": latency},
                observational_cleanup_unresolved=False,
                process={"elapsed_ns": 50, "resources": {"complete": True, "samples": [{"rss_bytes": 4}]}},
            )
        complete = driver.paired_results(rows)
        self.assertEqual(len(complete), 5)
        self.assertTrue(all(pair["complete"] is True for pair in complete))
        rows[3]["process"]["resources"]["complete"] = False
        rows[4]["observational_cleanup_unresolved"] = True
        changed = driver.paired_results(rows)
        self.assertEqual([pair["complete"] for pair in changed], [True, False, False, True, True])
        self.assertEqual(changed[1]["latency"], {})
        self.assertIsNone(changed[2]["resources"])

    def test_numeric_tree_requires_present_root_and_real_descendants(self):
        rows = driver.parse_processes(b"1 0 10\n2 1 20\n3 2 30\n4 0 40\n")
        self.assertEqual(driver.descendant_rows(rows, 1), rows[:3])
        with self.assertRaises(driver.DiagnosticError):
            driver.descendant_rows(rows, 9)
        for raw in (
            b"1 0 10\n1 0 20\n",
            b"1 0 PRIVATE\n",
            b"1 -1 2\n",
            b"1 0 2 extra\n",
            b"x" * (driver.MAX_PS_OUTPUT + 1),
            b"1 0 1\n" * 8193,
        ):
            with (
                self.subTest(raw_bytes=len(raw)),
                self.assertRaises(driver.DiagnosticError),
            ):
                driver.parse_processes(raw)

    def test_held_file_reader_rejects_symlink_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "file").write_bytes(b"abcd")
            (root / "link").symlink_to(root / "file")
            self.assertEqual(driver.bounded(root / "file", 4), b"abcd")
            with self.assertRaises(driver.DiagnosticError):
                driver.bounded(root / "file", 3)
            with self.assertRaises(OSError):
                driver.bounded(root / "link", 4)

    def test_import_checker_refuses_before_loading_unknown_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "module.py"
            path.write_text('raise AssertionError("must not run")\n')
            checker = driver.InstalledImports({path.resolve(strict=True): driver.digest(path.read_bytes())})
            checker.check(str(path))
            path.write_text('raise AssertionError("modified must not run")\n')
            with self.assertRaises(driver.DiagnosticError):
                checker.check(str(path))
            with self.assertRaises(driver.DiagnosticError):
                driver.InstalledImports({}).check(str(path))

    def test_import_checker_canonical_origin_with_aliased_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            path = alias / "module.py"
            path.write_text('raise AssertionError("must not run")\n')
            canonical = path.resolve(strict=True)
            self.assertNotEqual(path, canonical)
            expected = driver.digest(path.read_bytes())
            with self.assertRaises(driver.DiagnosticError):
                driver.InstalledImports({path: expected}).check(str(path))
            checker = driver.InstalledImports({canonical: expected})
            checker.check(str(path))
            checker.check(str(canonical))
            path.write_text('raise AssertionError("modified must not run")\n')
            for spelling in (path, canonical):
                with self.subTest(canonical=spelling == canonical):
                    with self.assertRaises(driver.DiagnosticError):
                        checker.check(str(spelling))
                    with self.assertRaises(driver.DiagnosticError):
                        driver.InstalledImports({}).check(str(spelling))

    def test_owned_disposable_python_child_output_and_timeout_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = driver.clean_environment(Path(temporary), Path(temporary))
            good = driver.run_bounded(
                [sys.executable, "-I", "-c", "print('bounded')"],
                cwd=Path(temporary),
                environment=environment,
                seconds=3,
            )
            self.assertEqual(good["stdout"], b"bounded\n")
            self.assertEqual(good["returncode"], 0)
            self.assertTrue(good["owned_child_reaped"])
            large = driver.run_bounded(
                [sys.executable, "-I", "-c", "print('x' * 2048)"],
                cwd=Path(temporary),
                environment=environment,
                seconds=3,
                maximum=32,
            )
            self.assertTrue(large["output_limit"])
            self.assertLessEqual(len(large["stdout"]), 32)
            timeout = driver.run_bounded(
                [sys.executable, "-I", "-c", "import time; time.sleep(10)"],
                cwd=Path(temporary),
                environment=environment,
                seconds=0.1,
            )
            self.assertTrue(timeout["timed_out"])
            self.assertTrue(timeout["owned_child_reaped"])

    def test_fixed_schedule_and_no_qualification_or_retry_claim(self):
        self.assertEqual(
            driver.SCHEDULE,
            (
                "plain",
                "observed",
                "observed",
                "plain",
                "plain",
                "observed",
                "observed",
                "plain",
                "plain",
                "observed",
            ),
        )
        self.assertEqual(
            (driver.ARM_SECONDS, driver.CLEANUP_SECONDS, driver.COHORT_SECONDS),
            (180, 20, 2100),
        )
        self.assertEqual(len(driver.EXPECTED_DEPENDENCIES), 48)
        self.assertEqual(driver.EXPECTED_DEPENDENCIES["anyio"], "4.13.0")
        self.assertNotIn("psutil", driver.EXPECTED_DEPENDENCIES)

    def test_original_measurement_call_shape_and_launcher_bindings(self):
        tree = ast.parse((HERE / "probe_macos_intel_attribution.py").read_bytes())
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "run_slo"
        ]
        self.assertEqual(len(calls), 1)
        values = {item.arg: ast.literal_eval(item.value) for item in calls[0].keywords}
        self.assertEqual(
            values,
            dict(
                warm_iterations=2,
                cold_iterations=2,
                recovery_iterations=2,
                readiness_samples=2,
                include_capacity=True,
                launcher_iterations=2,
            ),
        )
        text = (HERE / "probe_macos_intel_attribution.py").read_text()
        for name in (
            "start_hook_io",
            "wait_for_hook_process",
            "join_and_cleanup_hook_process",
        ):
            self.assertIn('(launch, "' + name + '"', text)
        self.assertNotIn("sitecustomize", text)
        self.assertNotIn("cache_clear()", text)
        self.assertNotIn("os.killpg", text)

    def test_every_instrumented_consumer_exists_in_the_exact_original_source(self):
        root = os.environ.get("MACOS_ATTRIBUTION_SOURCE_ROOT")
        if root is None:
            self.skipTest("exact original checkout supplied separately")
        paths = {
            name: "scripts/" + path + ".py"
            for name, path in (
                ("session", "native_slo_session"),
                ("launcher", "native_slo_launcher"),
                ("capacity", "native_slo_capacity"),
                ("benchmark", "bench_guard_native_installed_slo"),
            )
        }
        paths.update(
            {
                name: "src/codex_plugin_scanner/guard/" + path + ".py"
                for name, path in (
                    ("server", "daemon/server"),
                    ("scheduler", "daemon/runtime_hook_scheduler"),
                    ("worker", "daemon/hook_worker"),
                    ("runtime", "native_runtime"),
                    ("stream", "native_resident_stream"),
                    ("client", "native_resident_client"),
                    ("launch", "codex_hook_launch_runtime"),
                )
            }
        )
        trees = {name: ast.parse((Path(root) / path).read_bytes()) for name, path in paths.items()}
        tree = ast.parse((HERE / "probe_macos_intel_attribution.py").read_bytes())
        instrument = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "instrument")
        selected = next(
            n.value
            for n in ast.walk(instrument)
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "selected" for t in n.targets)
        )
        phases = next(
            n.iter
            for n in ast.walk(instrument)
            if isinstance(n, ast.For)
            and isinstance(n.target, ast.Tuple)
            and ast.unparse(n.target) == "(owner, name, phase)"
        )
        assert isinstance(selected, ast.List) and isinstance(phases, ast.List)
        self.assertEqual(len(selected.elts), 26)
        self.assertEqual(len(phases.elts), 8)
        for item in [*selected.elts, *phases.elts]:
            assert isinstance(item, ast.Tuple)
            owner, name, _label = item.elts
            dotted = ast.unparse(owner).split(".")
            body = trees[dotted[0]].body
            if len(dotted) == 2:
                body = next(n.body for n in body if isinstance(n, ast.ClassDef) and n.name == dotted[1])
            target = ast.literal_eval(name)
            definitions = [
                n for n in body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == target
            ]
            imports = [
                alias
                for n in body
                if isinstance(n, ast.ImportFrom)
                for alias in n.names
                if (alias.asname or alias.name) == target
            ]
            with self.subTest(consumer=ast.unparse(owner), target=target):
                self.assertEqual(len(definitions) + len(imports), 1)
        stream_class = next(
            n for n in trees["stream"].body if isinstance(n, ast.ClassDef) and n.name == "_PersistentNativeClient"
        )
        writer = next(n for n in stream_class.body if isinstance(n, ast.FunctionDef) and n.name == "_write_frame")
        self.assertEqual([ast.unparse(n) for n in writer.decorator_list], ["staticmethod"])
        start = next(n for n in stream_class.body if isinstance(n, ast.FunctionDef) and n.name == "_start")
        self.assertTrue(
            any(isinstance(n, ast.Call) and ast.unparse(n.func) == "subprocess.Popen" for n in ast.walk(start))
        )

    def test_source_control_can_bind_original_without_importing_guard(self):
        root = os.environ.get("MACOS_ATTRIBUTION_SOURCE_ROOT")
        if root is None:
            self.skipTest("exact original checkout supplied separately")
        binding = driver.source_binding(Path(root))
        self.assertEqual(binding["revision"], driver.SOURCE_SHA)
        self.assertEqual(binding["tree"], driver.SOURCE_TREE)
        self.assertGreater(binding["files"], 4000)


if __name__ == "__main__":
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules)
    unittest.main(verbosity=2)
