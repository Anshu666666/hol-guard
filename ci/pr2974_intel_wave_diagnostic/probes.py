"""Bounded forwarding observations; no product result or deadline is replaced."""

from __future__ import annotations

import functools
import os
import threading
import time
from collections import Counter
from contextlib import ExitStack
from unittest.mock import patch

MAX_EVENTS = 4096


def outcome(value):
    return ("returned_none" if value is None else "returned_false" if value is False
            else "returned_true" if value is True else "returned_value")


class Events:
    def __init__(self, maximum=MAX_EVENTS):
        self.maximum = maximum
        self.pid = os.getpid()
        self.origin = time.perf_counter()
        self.lock = threading.Lock()
        self.rows = []
        self.counts = Counter()
        self.active = 0
        self.discarded = 0

    def call(self, function, label, route, *args, **kwargs):
        # Only the original parent process is observed; spawn children are separate.
        if os.getpid() != self.pid:
            return function(*args, **kwargs)
        started = time.perf_counter()
        cpu = time.thread_time()
        with self.lock:
            self.active += 1
        result_kind = "raised"
        error_type = None
        try:
            result = function(*args, **kwargs)
            result_kind = outcome(result)
            return result
        except BaseException as error:
            error_type = type(error).__name__
            raise
        finally:
            finished, cpu_finished = time.perf_counter(), time.thread_time()
            row = {"label": label, "route": list(route) if route else None,
                   "started_ms": (started - self.origin) * 1000,
                   "finished_ms": (finished - self.origin) * 1000,
                   "wall_ms": (finished - started) * 1000,
                   "calling_thread_cpu_ms": (cpu_finished - cpu) * 1000,
                   "outcome": result_kind, "exception_type": error_type}
            with self.lock:
                self.active -= 1
                self.counts[label] += 1
                if len(self.rows) < self.maximum:
                    self.rows.append(row)
                else:
                    self.discarded += 1

    def snapshot(self):
        with self.lock:
            return {"events": [dict(row) for row in self.rows], "counts": dict(self.counts),
                    "in_flight": self.active, "discarded": self.discarded, "event_bound": self.maximum,
                    "complete_at_snapshot": self.active == 0 and self.discarded == 0,
                    "scope": "parent_process_calling_thread_only",
                    "span_semantics": "inclusive_do_not_sum",
                    "headline_timing_eligible": False}


class ContextProbe:
    """Preserve the original enter value, exit value and suppression behavior."""
    def __init__(self, original, events, label, route):
        self.original, self.events, self.label, self.route = original, events, label, route

    def __enter__(self):
        return self.events.call(self.original.__enter__, self.label + "_enter", self.route)

    def __exit__(self, *args):
        return self.events.call(self.original.__exit__, self.label + "_exit", self.route, *args)


class WaveProbes:
    def __init__(self):
        from scripts.native_slo_phases import PhaseProfiler
        self.profiler = PhaseProfiler()
        self.events = Events()
        self.stack = ExitStack()
        self.entered = False
        self.restored = False
        self.install_lock = None

    def wrap(self, function, label, *, root=False):
        from scripts.native_slo_phases import _ROUTE
        # Reuse the source's exact trusted route-root forwarding wrapper.
        measured = self.profiler._wrap(function, label, root=root)
        original_call = self.profiler.call
        if not hasattr(self, "_original_call"):
            self._original_call = original_call

            def event_call(callback, name, *args, **kwargs):
                route = _ROUTE.get()
                if route is None:
                    return callback(*args, **kwargs)
                return self.events.call(self._original_call, name, route, callback, name, *args, **kwargs)

            self.profiler.call = event_call
        return measured

    def __enter__(self):
        from codex_plugin_scanner.guard import native_hook_edge, native_runtime
        from codex_plugin_scanner.guard.daemon import hook_worker_native
        from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
        from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
        from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
        from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
        from scripts.native_slo_phase_waits import install_wait_probes
        from scripts.native_slo_phases import _INSTALL_LOCK, _ROUTE
        if self.entered:
            raise RuntimeError("Wave probes cannot be reused")
        self.entered = True
        if not _INSTALL_LOCK.acquire(blocking=False):
            raise RuntimeError("Another phase observer is active")
        self.install_lock = _INSTALL_LOCK
        targets = [
            (_GuardDaemonHandler, "_handle_runtime_hook", "daemon_hook_inclusive", True),
            (_GuardDaemonHandler, "_handle_runtime_hook_fast", "shared_worker_fast_path", False),
            (_GuardDaemonHandler, "_handle_runtime_hook_compatibility_cli", "compatibility_cli_path", False),
            (HookWorker, "review_http_payload", "worker_review_inclusive", False),
            (HookWorker, "prepare_workspace_policy", "policy_prepare_inclusive", False),
            (HookWorker, "_native_policy_snapshot", "policy_snapshot_inclusive", False),
            (HookWorker, "_record_native_decision_receipt", "receipt_validate_submit_inclusive", False),
            (NativePolicySnapshotPublisher, "register_workspace", "policy_workspace_registration", False),
            (NativePolicySnapshotPublisher, "wait_until_ready", "policy_readiness_wait", False),
            (NativePolicySnapshotPublisher, "current_snapshot_binding", "policy_current_binding", False),
            (native_runtime, "_validate_binary", "runtime_identity_including_hash", False),
            (native_hook_edge, "native_resident_client_request", "native_client_inclusive", False),
            (RuntimeHookEvidenceWriter, "submit_command_activity", "activity_submission", False),
            (RuntimeHookEvidenceWriter, "submit_native_decision_receipt", "receipt_submission", False),
        ]
        try:
            for owner, name, label, root in targets:
                self.stack.enter_context(patch.object(owner, name, self.wrap(getattr(owner, name), label, root=root)))
            self.stack.enter_context(patch.object(
                _GuardDaemonHandler, "do_POST", self.profiler._http_root(_GuardDaemonHandler.do_POST)))
            original = hook_worker_native.native_review_fence

            @functools.wraps(original)
            def fence(*args, **kwargs):
                # Construct the original context exactly once, before entering it.
                context = original(*args, **kwargs)
                return ContextProbe(context, self.events, "authority_fence", _ROUTE.get())

            self.stack.enter_context(patch.object(hook_worker_native, "native_review_fence", fence))
            # Exact existing scoped wait probes; no global unscoped wait measurement.
            install_wait_probes(self.stack, self.profiler)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_args):
        try:
            self.stack.close()
            self.restored = True
        finally:
            if self.install_lock is not None:
                self.install_lock.release()
                self.install_lock = None

    def report(self):
        return {"calls": self.events.snapshot(), "existing_phase_aggregates": self.profiler.report(),
                "patches_restored": self.restored,
                "native_connection_only": "not_measured_rust_owned",
                "native_evaluation_only": "not_measured_rust_owned",
                "receipt_submission_is_not_durable_persistence": True}
