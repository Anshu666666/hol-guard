"""Bounded controls for terminal observation; no production test is invoked."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.ci.prewarm_terminal_capture import (
    COUNTERS, TOOL_ID, TerminalCapture, project_boundary, supported_interpreter,
)


class Review:
    def __init__(self, reason=None):
        self.reason_code = reason


def fixture(*, error=None, nested_error=False, elapsed_value=0.125):
    state = {"closed": False, "body_counts": [], "marker": object()}

    def case():
        results = [Review() for _ in range(24)]
        runner_stats = {key: 0 for key in COUNTERS}
        elapsed, timing_scale = elapsed_value, 1.0
        try:
            state["body_counts"].append(state["capture"].return_count)

            def nested():
                state["body_counts"].append(state["capture"].return_count)
                if nested_error:
                    raise error

            nested()
            if error is not None:
                raise error
        finally:
            state["closed"] = True
        return state["marker"]

    def project(frame):
        if not state["closed"]:
            raise AssertionError("before_cleanup")
        return project_boundary(frame, Review)

    state["capture"] = TerminalCapture(case.__code__, case.__globals__, project)
    return case, state


class FakeMonitoring:
    """Only API fault/admission controls use this model; it enables no events."""

    def __init__(self, *, global_mask=0, fail_set=False, fail_clear=False):
        self.events = SimpleNamespace(PY_RETURN=4)
        self.owner = None
        self.global_mask = global_mask
        self.local_mask = 0
        self.callback = None
        self.fail_set, self.fail_clear = fail_set, fail_clear
        self.freed = False

    def get_tool(self, tool_id):
        return self.owner

    def get_events(self, tool_id):
        return self.global_mask

    def get_local_events(self, tool_id, code):
        return self.local_mask

    def use_tool_id(self, tool_id, name):
        if self.owner is not None:
            raise ValueError("occupied")
        self.owner = name

    def register_callback(self, tool_id, event, callback):
        previous, self.callback = self.callback, callback
        return previous

    def set_local_events(self, tool_id, code, mask):
        if (mask and self.fail_set) or (not mask and self.fail_clear):
            raise RuntimeError("injected_api_failure")
        self.local_mask = mask

    def free_tool_id(self, tool_id):
        self.owner, self.freed = None, True


class TerminalControls(unittest.TestCase):
    def setUp(self):
        self.assertTrue(supported_interpreter())
        self.assertIsNone(sys.monitoring.get_tool(TOOL_ID))
        self.assertEqual(sys.monitoring.get_events(TOOL_ID), 0)

    def tearDown(self):
        self.assertIsNone(sys.monitoring.get_tool(TOOL_ID))
        self.assertEqual(sys.monitoring.get_events(TOOL_ID), 0)

    def test_success_only_captures_after_cleanup(self):
        case, state = fixture()
        capture = state["capture"]
        self.assertTrue(capture.install())
        try:
            result = case()
        finally:
            capture.close()
        self.assertIs(result, state["marker"])
        self.assertEqual(state["body_counts"], [0, 0])
        self.assertTrue(state["closed"])
        self.assertTrue(capture.snapshot(False)["complete"])
        self.assertEqual(capture.return_count, 1)
        self.assertEqual(capture.values["elapsed"], 0.125)
        self.assertEqual(sys.monitoring.get_local_events(TOOL_ID, case.__code__), 0)

    def test_escaping_failure_preserves_exception(self):
        error = AssertionError("private-control-message")
        case, state = fixture(error=error)
        capture = state["capture"]
        self.assertTrue(capture.install())
        observed = None
        try:
            case()
        except BaseException as caught:
            observed = caught
        finally:
            capture.close()
        self.assertIs(observed, error)
        capture.capture_failure(observed)
        self.assertEqual(state["body_counts"], [0, 0])
        self.assertTrue(state["closed"])
        self.assertTrue(capture.snapshot(True)["complete"])
        self.assertEqual((capture.return_count, capture.failure_count), (0, 1))
        self.assertNotIn("private-control-message", json.dumps(capture.snapshot(True)))

    def test_nested_failure_refuses_other_terminal_frame(self):
        error = AssertionError("private-control-message")
        case, state = fixture(error=error, nested_error=True)
        capture = state["capture"]
        self.assertTrue(capture.install())
        observed = None
        try:
            case()
        except BaseException as caught:
            observed = caught
        finally:
            capture.close()
        self.assertIs(observed, error)
        capture.capture_failure(observed)
        self.assertFalse(capture.snapshot(True)["complete"])
        self.assertIn("failure_identity", capture.errors)

    def test_duplicate_capture_is_incomplete(self):
        case, state = fixture()
        capture = state["capture"]
        self.assertTrue(capture.install())
        try:
            first, second = case(), case()
        finally:
            capture.close()
        self.assertIs(first, state["marker"])
        self.assertIs(second, state["marker"])
        self.assertEqual(capture.return_count, 2)
        self.assertFalse(capture.snapshot(False)["complete"])

    def test_missing_capture_is_incomplete(self):
        case, state = fixture()
        capture = state["capture"]
        self.assertTrue(capture.install())
        capture.close()
        self.assertFalse(capture.snapshot(False)["complete"])
        self.assertEqual(capture.return_count, 0)

    def test_collector_error_preserves_return(self):
        case, state = fixture()
        capture = state["capture"]

        def broken(frame):
            raise RuntimeError("private-control-message")

        capture.projector = broken
        self.assertTrue(capture.install())
        try:
            result = case()
        finally:
            capture.close()
        self.assertIs(result, state["marker"])
        self.assertFalse(capture.snapshot(False)["complete"])
        self.assertEqual(capture.errors, ["collector_failure"])

    def test_collector_error_preserves_escaping_exception(self):
        error = AssertionError("private-control-message")
        case, state = fixture(error=error)
        capture = state["capture"]

        def broken(frame):
            raise RuntimeError("private-control-message")

        capture.projector = broken
        self.assertTrue(capture.install())
        observed = None
        try:
            case()
        except BaseException as caught:
            observed = caught
        finally:
            capture.close()
        self.assertIs(observed, error)
        capture.capture_failure(observed)
        self.assertIs(observed, error)
        self.assertFalse(capture.snapshot(True)["complete"])
        self.assertEqual(capture.errors, ["collector_failure"])
        self.assertEqual((capture.return_count, capture.failure_count), (0, 1))

    def test_invalid_values_remain_closed(self):
        for value in (float("nan"), float("inf"), True, -1, "private-control-message"):
            with self.subTest(value_type=type(value).__name__):
                case, state = fixture(elapsed_value=value)
                capture = state["capture"]
                self.assertTrue(capture.install())
                try:
                    result = case()
                finally:
                    capture.close()
                self.assertIs(result, state["marker"])
                self.assertFalse(capture.snapshot(False)["complete"])
                self.assertNotIn("private-control-message", json.dumps(capture.snapshot(False)))
        case, state = fixture()
        capture = state["capture"]
        capture.projector = lambda frame: {"complete": True, "canary": "private-control-message"}
        self.assertTrue(capture.install())
        try:
            result = case()
        finally:
            capture.close()
        self.assertIs(result, state["marker"])
        self.assertFalse(capture.snapshot(False)["complete"])
        self.assertNotIn("private-control-message", json.dumps(capture.snapshot(False)))

    def test_wrong_callback_frame_is_incomplete(self):
        case, state = fixture()
        capture = state["capture"]
        self.assertTrue(capture.install())
        try:
            capture.callback(case.__code__, 0, None)
        finally:
            capture.close()
        self.assertFalse(capture.snapshot(False)["complete"])
        self.assertIn("return_identity", capture.errors)

    def test_occupied_lease_is_preserved(self):
        case, state = fixture()
        capture = state["capture"]
        sentinel = lambda *args: None
        sys.monitoring.use_tool_id(TOOL_ID, "control-owner")
        sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.PY_RETURN, sentinel)
        try:
            self.assertFalse(capture.install())
            capture.close()
            self.assertEqual(sys.monitoring.get_tool(TOOL_ID), "control-owner")
            previous = sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.PY_RETURN, None)
            self.assertIs(previous, sentinel)
        finally:
            sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.PY_RETURN, None)
            sys.monitoring.free_tool_id(TOOL_ID)

    def test_stale_local_mask_is_preserved(self):
        case, state = fixture()
        capture = state["capture"]
        sys.monitoring.use_tool_id(TOOL_ID, "control-owner")
        sys.monitoring.set_local_events(TOOL_ID, case.__code__, sys.monitoring.events.PY_RETURN)
        sys.monitoring.free_tool_id(TOOL_ID)
        try:
            self.assertFalse(capture.install())
            capture.close()
            self.assertEqual(sys.monitoring.get_local_events(TOOL_ID, case.__code__), sys.monitoring.events.PY_RETURN)
        finally:
            sys.monitoring.use_tool_id(TOOL_ID, "control-cleanup")
            sys.monitoring.set_local_events(TOOL_ID, case.__code__, 0)
            sys.monitoring.free_tool_id(TOOL_ID)

    def test_prior_callback_is_restored(self):
        case, state = fixture()
        capture = state["capture"]
        sentinel = lambda *args: None
        sys.monitoring.use_tool_id(TOOL_ID, "control-owner")
        sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.PY_RETURN, sentinel)
        sys.monitoring.free_tool_id(TOOL_ID)
        try:
            self.assertFalse(capture.install())
            self.assertIn("prior_callback", capture.errors)
            self.assertIsNone(sys.monitoring.get_tool(TOOL_ID))
            sys.monitoring.use_tool_id(TOOL_ID, "control-inspection")
            previous = sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.PY_RETURN, None)
            self.assertIs(previous, sentinel)
        finally:
            if sys.monitoring.get_tool(TOOL_ID) is None:
                sys.monitoring.use_tool_id(TOOL_ID, "control-cleanup")
            sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.PY_RETURN, None)
            sys.monitoring.free_tool_id(TOOL_ID)

    def test_nonzero_global_mask_is_refused_without_enabling_events(self):
        case, state = fixture()
        api = FakeMonitoring(global_mask=4)
        capture = TerminalCapture(case.__code__, case.__globals__, api=api)
        self.assertFalse(capture.install())
        capture.close()
        self.assertEqual(api.global_mask, 4)
        self.assertIsNone(api.owner)
        self.assertIsNone(api.callback)
        self.assertFalse(api.freed)

    def test_partial_install_failure_cleans_owned_state(self):
        case, state = fixture()
        api = FakeMonitoring(fail_set=True)
        capture = TerminalCapture(case.__code__, case.__globals__, api=api)
        self.assertFalse(capture.install())
        self.assertTrue(capture.cleanup["complete"])
        self.assertTrue(api.freed)
        self.assertIsNone(api.owner)
        self.assertIsNone(api.callback)
        self.assertEqual(api.local_mask, 0)

    def test_cleanup_fault_does_not_replace_escaping_exception(self):
        error = AssertionError("private-control-message")
        case, state = fixture(error=error)
        api = FakeMonitoring(fail_clear=True)
        capture = TerminalCapture(case.__code__, case.__globals__, api=api)
        state["capture"] = capture
        self.assertTrue(capture.install())
        observed = None
        try:
            case()
        except BaseException as caught:
            observed = caught
        finally:
            capture.close()
        self.assertIs(observed, error)
        self.assertFalse(capture.cleanup["complete"])
        self.assertFalse(api.freed)
        self.assertIn("cleanup_failure", capture.errors)


def main():
    names = unittest.defaultTestLoader.getTestCaseNames(TerminalControls)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TerminalControls)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    report = {"schema": "guard.prewarm-terminal-controls.v1", "names": names,
              "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "successful": result.wasSuccessful(),
              "python": list(sys.version_info[:3]), "globalEventsEnabled": False,
              "originalTestInvoked": False}
    Path(os.environ["ORACLE_READY_CONTROL_OUTPUT"]).write_text(json.dumps(report, sort_keys=True) + "\n")
    return 0 if result.wasSuccessful() and result.testsRun == 15 else 1


if __name__ == "__main__":
    raise SystemExit(main())
