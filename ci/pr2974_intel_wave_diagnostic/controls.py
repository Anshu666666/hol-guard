"""Inert forwarding controls only; these are not product or SLO cases."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from probes import ContextProbe, Events
from observe import ScheduleObserver


class ForwardingControls(unittest.TestCase):
    def test_return_identity_and_arguments(self):
        event = Events()
        sentinel = object()
        calls = []
        def function(*args, **kwargs):
            calls.append((args, kwargs))
            return sentinel
        self.assertIs(event.call(function, "call", ("a", "b"), 1, key=2), sentinel)
        self.assertEqual(calls, [((1,), {"key": 2})])

    def test_original_exception_identity(self):
        error = RuntimeError("inert")
        event = Events()
        def function():
            raise error
        with self.assertRaises(RuntimeError) as observed:
            event.call(function, "call", None)
        self.assertIs(observed.exception, error)
        self.assertEqual(event.snapshot()["events"][0]["outcome"], "raised")

    def test_context_enter_and_suppression(self):
        sentinel = object()
        calls = []
        class Context:
            def __enter__(self):
                calls.append("enter")
                return sentinel
            def __exit__(self, *args):
                calls.append(args)
                return True
        with ContextProbe(Context(), Events(), "context", None) as result:
            self.assertIs(result, sentinel)
            raise ValueError("inert")
        self.assertEqual(calls[0], "enter")
        self.assertIs(calls[1][0], ValueError)

    def test_context_unsuppressed_exception(self):
        error = ValueError("inert")
        class Context:
            def __enter__(self):
                return None
            def __exit__(self, *args):
                return False
        with self.assertRaises(ValueError) as observed:
            with ContextProbe(Context(), Events(), "context", None):
                raise error
        self.assertIs(observed.exception, error)

    def test_bound_retains_complete_counts(self):
        event = Events(maximum=2)
        for _ in range(5):
            self.assertIs(event.call(lambda: None, "same", None), None)
        value = event.snapshot()
        self.assertEqual(len(value["events"]), 2)
        self.assertEqual(value["counts"], {"same": 5})
        self.assertEqual(value["discarded"], 3)
        self.assertFalse(value["complete_at_snapshot"])

    def test_other_process_calls_are_not_counted(self):
        event = Events()
        with patch("probes.os.getpid", return_value=event.pid + 1):
            self.assertEqual(event.call(lambda x: x, "call", None, 7), 7)
        self.assertEqual(event.snapshot()["events"], [])

    def test_concurrent_route_arguments_remain_separate(self):
        event = Events()
        barrier = threading.Barrier(3, timeout=2)
        def worker(route):
            barrier.wait()
            event.call(lambda: None, "call", route)
        workers = [threading.Thread(target=worker, args=((str(i), "event"),)) for i in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(row["route"] for row in event.snapshot()["events"]), [["0", "event"], ["1", "event"]])

    def test_constructor_original_return_and_weak_reference(self):
        observer = ScheduleObserver()
        class Item:
            pass
        item = Item()
        calls = []
        def init(instance, value):
            calls.append((instance, value))
            return None
        self.assertIsNone(observer.constructor(init, "GuardStore")(item, 5))
        self.assertEqual(calls, [(item, 5)])
        self.assertIs(observer.constructed["GuardStore"][0](), item)

    def test_c16_scope_resets_after_original_exception(self):
        observer = ScheduleObserver()
        error = RuntimeError("inert")
        def original():
            self.assertTrue(observer.c16_scope.get())
            raise error
        with self.assertRaises(RuntimeError) as caught:
            observer.c16(original)()
        self.assertIs(caught.exception, error)
        self.assertFalse(observer.c16_scope.get())
        self.assertEqual(observer.c16_entries, 1)

    def test_other_capacity_wave_is_forwarded_once(self):
        observer = ScheduleObserver()
        args = (object(), (("route", "event"),), 64, object())
        calls = []
        sentinel = object()
        def original(*received):
            calls.append(received)
            return sentinel
        self.assertIs(observer.capacity_wave(original)(*args), sentinel)
        self.assertEqual(calls, [args])
        self.assertEqual(observer.wave_calls, [])

    def test_stage_context_preserves_value_and_scope(self):
        observer = ScheduleObserver()
        sentinel = object()
        class Context:
            def __enter__(self):
                self.asserted = True
                return sentinel
            def __exit__(self, *args):
                return False
        wrapper = observer.progress(lambda *args, **kwargs: Context())
        with wrapper(None, "warm") as value:
            self.assertIs(value, sentinel)
            self.assertEqual(observer.phase.get(), "warm")
        self.assertEqual(observer.phase.get(), "outside_named_stage")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ForwardingControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    value = {"schema": "pr2974.intel-observer-inert-controls.v1", "tests_run": result.testsRun,
             "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
             "successful": result.wasSuccessful(), "scope": "inert_forwarding_controls_only",
             "product_test_cases": 0, "qualification_complete": False}
    Path(sys.argv[1]).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 11 else 1)
