"""Foreground evidence attribution at existing, unmodified Python callables.

Only the diagnostic daemon installs these probes. They do not serialize inputs
for measurement, change writer capacity, or infer queue/durability milestones
from a boolean submission result. Every elapsed span is inclusive.
"""

from __future__ import annotations

import functools
import inspect
import threading
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from typing import Any, cast
from unittest.mock import patch

from scripts.native_slo_phase_calls import Recorder, byte_size, hashlib_probe, json_probe

_BINDINGS = (
    "receipt_validation_module",
    "receipt_validation_submission",
    "receipt_validation_journal",
    "receipt_identity_serialization",
    "activity_record_serialization",
    "activity_record_validation",
    "writer_json",
    "receipt_json",
    "receipt_hash",
)


class _BoundRecorder:
    def __init__(self, observer: EvidencePhaseObserver, binding: str) -> None:
        self._observer, self._binding = observer, binding

    def call(self, function: Callable[..., Any], name: str, *args: Any, **kwargs: Any) -> Any:
        return self._observer.call(self._binding, function, name, *args, **kwargs)

    def work(self, name: str, unit: str, count: int) -> None:
        self._observer.work(name, unit, count)


class EvidencePhaseObserver:
    """Track fixed binding coverage separately from observed callable outcomes."""

    def __init__(self, recorder: Recorder, *, foreground: Callable[[], bool]) -> None:
        self.recorder, self._foreground = recorder, foreground
        self._lock = threading.Lock()
        self._states: dict[str, str] = dict.fromkeys(_BINDINGS, "not_installed")
        self._entries: Counter[str] = Counter()
        self._installed: list[tuple[str, Any, str, Any]] = []
        self._accepting = False
        self._active = 0
        self._foreground_seen = False

    def call(self, binding: str, function: Callable[..., Any], phase: str, *args: Any, **kwargs: Any) -> Any:
        if not self._foreground():
            return function(*args, **kwargs)
        with self._lock:
            if not self._accepting:
                admitted = False
            else:
                admitted = True
                self._entries[binding] += 1
                self._active += 1
        if not admitted:
            return function(*args, **kwargs)
        try:
            return self.recorder.call(function, phase, *args, **kwargs)
        finally:
            with self._lock:
                self._active -= 1

    def _wrap(self, function: Callable[..., Any], binding: str, *, encoded: bool = False) -> Callable[..., Any]:
        @functools.wraps(function)
        def measured(*args: Any, **kwargs: Any) -> Any:
            result = self.call(binding, function, binding, *args, **kwargs)
            # Count the already returned buffer. Do not encode, copy or walk
            # a request/receipt merely to discover its size.
            if encoded:
                size = byte_size(result)
                if size is not None:
                    self.work(binding, "returned_bytes", size)
            return result

        return measured

    def work(self, phase: str, unit: str, count: int) -> None:
        if not self._foreground():
            return
        with self._lock:
            accepting = self._accepting
        if accepting:
            self.recorder.work(phase, unit, count)

    def _patch(self, stack: ExitStack, binding: str, owner: Any, name: str, measured: Any) -> None:
        stack.enter_context(patch.object(owner, name, measured))
        self._installed.append((binding, owner, name, measured))
        self._states[binding] = "observing"

    def install(self, stack: ExitStack) -> None:
        from codex_plugin_scanner.guard import native_decision_receipt
        from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal, runtime_hook_evidence_writer

        activity = runtime_hook_evidence_journal._CommandActivityRecord
        # Capture existing imported aliases before replacing the canonical
        # binding. Each label describes the binding used, not an inferred caller.
        targets = (
            (native_decision_receipt, "validate_native_decision_receipt", "receipt_validation_module", False),
            (runtime_hook_evidence_writer, "validate_native_decision_receipt", "receipt_validation_submission", False),
            (runtime_hook_evidence_journal, "validate_native_decision_receipt", "receipt_validation_journal", False),
            (native_decision_receipt, "canonical_receipt_bytes", "receipt_identity_serialization", True),
            (activity, "serialized", "activity_record_serialization", True),
        )
        originals = [
            (owner, name, binding, encoded, getattr(owner, name, None)) for owner, name, binding, encoded in targets
        ]
        validation = inspect.getattr_static(activity, "from_json", None)
        with self._lock:
            self._accepting = True
        for owner, name, binding, encoded, original in originals:
            if not callable(original):
                self._states[binding] = "unsupported"
                continue
            self._patch(stack, binding, owner, name, self._wrap(original, binding, encoded=encoded))
        binding = "activity_record_validation"
        if isinstance(validation, classmethod):
            # Keep descriptor binding and subclass construction identical.
            measured = classmethod(self._wrap(validation.__func__, binding))
            self._patch(stack, binding, activity, "from_json", measured)
        else:
            self._states[binding] = "unsupported"
        for owner, name, binding, prefix, factory in (
            (runtime_hook_evidence_writer, "json", "writer_json", "writer_evidence", json_probe),
            (native_decision_receipt, "json", "receipt_json", "receipt_validation", json_probe),
            (native_decision_receipt, "hashlib", "receipt_hash", "receipt_identity", hashlib_probe),
        ):
            original = getattr(owner, name, None)
            if original is None:
                self._states[binding] = "unsupported"
                continue
            measured = factory(original, _BoundRecorder(self, binding), prefix)
            self._patch(stack, binding, owner, name, measured)

    def finish(
        self, *, foreground_in_flight: bool, foreground_at_installation: bool, foreground_context_observed: bool
    ) -> None:
        with self._lock:
            self._accepting = False
            in_flight = foreground_in_flight or self._active > 0
            self._foreground_seen = foreground_context_observed
        for binding, owner, name, measured in self._installed:
            if self._states[binding] == "observing":
                self._states[binding] = (
                    "binding_changed"
                    if inspect.getattr_static(owner, name, None) is not measured
                    else "in_flight_at_teardown"
                    if in_flight
                    else "foreground_at_installation"
                    if foreground_at_installation
                    else "complete"
                )

    def failed(self, status: str) -> None:
        with self._lock:
            self._accepting = False
            for binding, _owner, _name, _measured in self._installed:
                self._states[binding] = status

    def report(self) -> dict[str, object]:
        with self._lock:
            observed = self._foreground_seen or bool(self._entries)
            return {
                "schema": "hol-guard.foreground-evidence-observation.v1",
                "scope": "declared_bindings_in_foreground_route_context_only",
                "foreground_context_observed": observed,
                "bindings": {
                    binding: {
                        "status": status,
                        "entries": self._entries[binding] if status not in {"not_installed", "unsupported"} else None,
                        "zero_calls_observed": status == "complete" and observed and self._entries[binding] == 0,
                    }
                    for binding, status in self._states.items()
                },
                "span_semantics": "inclusive_do_not_sum",
                "submission_true": "accepted_or_deduplicated_not_distinguished_by_return_value",
                "submission_false": "rejected_reason_not_inferred_from_return_value",
                "queue_admission_only": "not_isolated_from_inclusive_submission",
                "receipt_mapping_copy_only": "not_isolated_from_inclusive_validation",
                "persistence": "not_measured_by_foreground_probes",
            }


def validate_evidence_phase_counts(report: Mapping[str, object], attempts: int) -> None:
    """Require complete observed evidence work for the normal PostTool fixture.

    Counts prove observation, not memory/durable acceptance. Invalid receipts,
    exceptions and submission rejections remain visible in each span's outcomes.
    """
    coverage = report.get("evidence_submission_coverage")
    if (
        not isinstance(coverage, Mapping)
        or coverage.get("schema") != "hol-guard.foreground-evidence-observation.v1"
        or coverage.get("foreground_context_observed") is not True
    ):
        raise RuntimeError("qualification foreground evidence coverage missing")
    bindings = coverage.get("bindings")
    if not isinstance(bindings, Mapping) or set(bindings) != set(_BINDINGS):
        raise RuntimeError("qualification foreground evidence bindings missing")
    for value in bindings.values():
        entries = value.get("entries") if isinstance(value, Mapping) else None
        if (
            not isinstance(value, Mapping)
            or value.get("status") != "complete"
            or type(entries) is not int
            or entries < 0
        ):
            raise RuntimeError("qualification foreground evidence observation incomplete")
    routes = report.get("by_route")
    hook = routes.get("claude-code.PostToolUse") if isinstance(routes, Mapping) else None
    if not isinstance(hook, Mapping):
        raise RuntimeError("qualification foreground evidence route missing")

    def require(phase: str, minimum: int) -> Mapping[str, object]:
        span = hook.get(phase)
        if span is None and minimum == 0:
            return {}
        count = span.get("count") if isinstance(span, Mapping) else None
        if type(count) is not int or count < minimum:
            raise RuntimeError("qualification foreground evidence call counts incomplete")
        assert isinstance(span, Mapping)
        return span

    def outcome_count(phase: str, outcome: str) -> int:
        span = require(phase, attempts)
        outcomes = span.get("outcomes")
        if (
            not isinstance(outcomes, Mapping)
            or set(outcomes) - {"returned_none", "returned_false", "returned_true", "returned_value", "raised"}
            or any(type(value) is not int or value < 0 for value in outcomes.values())
        ):
            raise RuntimeError("qualification foreground evidence outcomes incomplete")
        counts = cast(Mapping[str, int], outcomes)
        if sum(counts.values()) != span["count"]:
            raise RuntimeError("qualification foreground evidence outcomes incomplete")
        return counts.get(outcome, 0)

    activity_accepted = outcome_count("activity_submission", "returned_true")
    # Receipt submission true may be a duplicate. Do not call it an enqueue.
    _ = outcome_count("receipt_submission", "returned_true")
    module_validated = outcome_count("receipt_validation_module", "returned_value")
    submission_validated = outcome_count("receipt_validation_submission", "returned_value")
    validated = module_validated + submission_validated
    minimum_calls = {
        "receipt_identity_serialization": validated,
        "activity_record_serialization": 2 * activity_accepted,
        "activity_record_validation": activity_accepted,
        "writer_evidence_json_loads": activity_accepted,
        "receipt_validation_json_dumps": 2 * validated,
        "receipt_identity_sha256_init": validated,
        "receipt_identity_sha256_finalize": validated,
        "receipt_record_serialization": submission_validated,
    }
    for phase, minimum in minimum_calls.items():
        _ = require(phase, minimum)
