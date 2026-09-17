"""Opt-in, scripts-only inclusive spans for synthetic daemon profiling.

Instrumentation runs separately from uninstrumented SLO samples. No production
module imports this helper, and it never stores arguments or response bodies.
"""

from __future__ import annotations

import contextvars
import functools
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from contextlib import ExitStack
from unittest.mock import patch

from scripts.native_slo_adapter import route_matrix
from scripts.native_slo_contract import summarize

_MAX_SAMPLES_PER_SPAN = 100_000
_ROUTE = contextvars.ContextVar[tuple[str, str] | None]("native_benchmark_route", default=None)


class PhaseProfiler:
    """Measure actual callable boundaries without inventing substage precision."""

    def __init__(self) -> None:
        self._stack = ExitStack()
        self._lock = threading.Lock()
        self._samples: dict[tuple[str, str, str], list[float]] = defaultdict(list)
        self._dropped: Counter[str] = Counter()
        self._allowed = frozenset(route_matrix())

    def _record(self, name: str, elapsed_ms: float, route: tuple[str, str]) -> None:
        with self._lock:
            values = self._samples[(route[0], route[1], name)]
            if len(values) < _MAX_SAMPLES_PER_SPAN:
                values.append(elapsed_ms)
            else:
                self._dropped[name] += 1

    def _wrap(self, function: Callable[..., object], name: str, *, root: bool = False) -> Callable[..., object]:
        @functools.wraps(function)
        def measured(*args: object, **kwargs: object) -> object:
            token = None
            if root:
                payload = args[1] if len(args) > 1 else kwargs.get("payload")
                harness = kwargs.get("default_harness")
                event = payload.get("hook_event_name") if isinstance(payload, dict) else None
                pair = (str(harness), str(event))
                token = _ROUTE.set(pair if pair in self._allowed else ("other", "other"))
            route = _ROUTE.get()
            started = time.perf_counter() if route is not None else 0.0
            try:
                return function(*args, **kwargs)
            finally:
                if route is not None:
                    self._record(name, (time.perf_counter() - started) * 1000, route)
                if token is not None:
                    _ROUTE.reset(token)

        return measured

    def __enter__(self) -> PhaseProfiler:
        from codex_plugin_scanner.guard import config, native_hook_edge, native_runtime
        from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
        from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
        from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

        targets = (
            (_GuardDaemonHandler, "_handle_runtime_hook", "daemon_hook_inclusive", True),
            (native_runtime, "_validate_binary", "runtime_identity_including_hash", False),
            (config, "load_guard_config", "config_lookup", False),
            (native_hook_edge, "_encode_hook_envelope", "envelope_encode", False),
            (native_hook_edge, "_decode_edge", "response_decode_validate", False),
            (RuntimeHookScheduler, "reserve_bytes", "byte_admission", False),
            (RuntimeHookScheduler, "acquire", "admission_and_queue", False),
            (native_hook_edge, "native_resident_client_request", "native_client_inclusive", False),
            (RuntimeHookEvidenceWriter, "submit_command_activity", "activity_submission", False),
            (RuntimeHookEvidenceWriter, "submit_native_decision_receipt", "receipt_submission", False),
            (_GuardDaemonHandler, "_write_json", "response_encode_write", False),
        )
        try:
            for owner, name, label, root in targets:
                self._stack.enter_context(patch.object(owner, name, self._wrap(getattr(owner, name), label, root=root)))
        except BaseException:
            self._stack.close()
            raise
        return self

    def __exit__(self, *_args: object) -> None:
        self._stack.close()

    def report(self) -> dict[str, object]:
        with self._lock:
            return {
                "scope": "diagnostic_instrumented_run",
                "span_semantics": "inclusive_do_not_sum",
                "headline_timing_eligible": False,
                "by_route": {
                    f"{harness}.{event}": {
                        phase: summarize(values)
                        for (candidate_harness, candidate_event, phase), values in sorted(self._samples.items())
                        if (candidate_harness, candidate_event) == (harness, event)
                    }
                    for harness, event in sorted({key[:2] for key in self._samples})
                },
                "discarded_samples": sum(self._dropped.values()),
                "separate_hash_only": "not_measured",
                "separate_queue_only": "not_measured",
                "native_connection_only": "not_measured",
                "native_evaluation_only": "not_measured",
                "inbound_json_only": "not_measured",
            }
