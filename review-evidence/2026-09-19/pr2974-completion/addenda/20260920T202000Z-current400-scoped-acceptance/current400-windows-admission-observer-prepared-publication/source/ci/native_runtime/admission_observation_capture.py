"""Observe only the original default-auto corpus's existing caller boundaries."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from types import ModuleType
from typing import Any

from ci.native_runtime import admission_observation_values as values

ROSTER = (
    ("claude-code", "PreToolUse"),
    ("claude-code", "PostToolUse"),
    ("cline", "PreToolUse"),
    ("cline", "PostToolUse"),
    ("codex", "PreToolUse"),
    ("codex", "PostToolUse"),
    ("copilot", "PreToolUse"),
    ("copilot", "PostToolUse"),
    ("cursor", "PreToolUse"),
    ("cursor", "PostToolUse"),
    ("grok", "PreToolUse"),
    ("hermes", "PreToolUse"),
    ("kimi", "PreToolUse"),
    ("kimi", "PostToolUse"),
    ("omp", "PreToolUse"),
    ("omp", "PostToolUse"),
    ("openclaw", "PreToolUse"),
    ("opencode", "PreToolUse"),
    ("pi", "PreToolUse"),
    ("pi", "PostToolUse"),
    ("zcode", "PreToolUse"),
)


class AdmissionCapture:
    """No product request, retry, polling or change to the original return path."""

    def __init__(
        self, probe: ModuleType, routes: ModuleType, *, read_snapshot: Callable[[Any], dict[str, Any]] = values.snapshot
    ):
        self._owner = threading.get_ident()
        self._reader = read_snapshot
        self._active = False
        self._daemon: Any = None
        self._entered = False
        self._restored = False
        self._rows: list[dict[str, Any]] = []
        self._faults: set[str] = set()
        self._baseline: dict[str, Any] | None = None
        self._worker: dict[str, object] | None = None
        self._receipts: dict[str, int] | None = None
        self._ended = False
        self._slots = [
            (probe, "bind_corpus", self._bind),
            (routes, "_installed_hook_request", self._request),
            (probe, "observe_corpus", self._aggregate),
            (probe, "end_corpus", self._end),
        ]
        self._originals = [getattr(module, name) for module, name, _ in self._slots]
        self._installed: list[int] = []

    def __enter__(self) -> AdmissionCapture:
        if self._entered:
            raise RuntimeError("admission_observer_reused")
        self._entered = True
        try:
            for index, (module, name, callback) in enumerate(self._slots):
                if getattr(module, name) is not self._originals[index]:
                    raise RuntimeError("admission_observer_alias_changed")
                setattr(module, name, callback)
                self._installed.append(index)
        except BaseException:
            try:
                self._restore()
            except BaseException:
                self._faults.add("alias_restore_failed")
            raise
        return self

    def _restore(self) -> None:
        for index in self._installed[::-1]:
            module, name, callback = self._slots[index]
            try:
                if getattr(module, name) is not callback:
                    self._faults.add("alias_ownership_lost")
                    continue
                setattr(module, name, self._originals[index])
            except BaseException:
                self._faults.add("alias_restore_failed")
        self._restored = all(
            getattr(module, name) is original
            for (module, name, _), original in zip(self._slots, self._originals, strict=True)
        )

    def __exit__(self, *_args: object) -> None:
        try:
            self._restore()
        except BaseException:
            self._faults.add("alias_restore_failed")
        self._active = False
        self._daemon = None

    def _observe(self, operation: Callable[[], None]) -> None:
        try:
            if threading.get_ident() != self._owner:
                self._faults.add("wrong_observer_thread")
                return
            operation()
        except BaseException:
            self._faults.add("capture_failed")

    def _take(self) -> dict[str, Any]:
        result = self._reader(self._daemon._server)
        if not values.complete_snapshot(result):
            self._faults.add("snapshot_incomplete")
        return result

    def _bind(self, *args: Any, **kwargs: Any) -> Any:
        result = self._originals[0](*args, **kwargs)

        def observe() -> None:
            if self._daemon is not None or len(args) != 1 or kwargs:
                self._faults.add("corpus_binding_invalid")
                return
            self._daemon = args[0]
            self._active = True
            self._baseline = self._take()

        self._observe(observe)
        return result

    def _request(self, *args: Any, **kwargs: Any) -> Any:
        if not self._active:
            return self._originals[1](*args, **kwargs)
        row: dict[str, Any] | None = None

        def before() -> None:
            nonlocal row
            index = len(self._rows)
            if index >= len(ROSTER):
                self._faults.add("delivery_overflow")
                return
            if (
                len(args) != 6
                or kwargs
                or args[0] is not self._daemon
                or type(args[3]) is not str
                or type(args[4]) is not str
                or (args[3], args[4]) != ROSTER[index]
            ):
                self._faults.add("delivery_contract_changed")
                return
            row = {
                "index": index,
                "harness": ROSTER[index][0],
                "event": ROSTER[index][1],
                "before": self._take(),
                "returned": False,
            }
            self._rows.append(row)

        self._observe(before)
        try:
            result = self._originals[1](*args, **kwargs)
        except BaseException:
            self._observe(lambda: self._after(row, None, returned=False))
            raise
        self._observe(lambda: self._after(row, result, returned=True))
        return result

    def _after(self, row: dict[str, Any] | None, result: object, *, returned: bool) -> None:
        if row is None:
            return
        row["returned"] = returned
        row["response"] = values.response(result)
        row["after"] = self._take()
        if returned and (
            row["response"].get("available") is not True
            or any(
                row["response"].get(name)
                for name in ("reason_code_unknown", "decision_unknown", "observed_review_failure_invalid")
            )
        ):
            self._faults.add("response_projection_incomplete")

    def _aggregate(self, *args: Any, **kwargs: Any) -> Any:
        result = self._originals[2](*args, **kwargs)

        def observe() -> None:
            if len(args) != 2 or kwargs or args[0] is not self._daemon:
                self._faults.add("aggregate_contract_changed")
                return
            self._worker = values.worker_stats(args[1])

        self._observe(observe)
        self._active = False  # Original off/shadow calls are outside the corpus.
        return result

    def _end(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return self._originals[3](*args, **kwargs)
        finally:

            def observe() -> None:
                if len(args) != 3 or kwargs or args[0] is not self._daemon:
                    self._faults.add("end_contract_changed")
                    return
                self._receipts = values.receipt_stats(args[2])
                self._ended = True

            self._observe(observe)
            self._active = False

    def report(self) -> dict[str, Any]:
        return json.loads(
            json.dumps(
                {
                    "schema": "hol-guard.default-auto-admission-observation.v1",
                    "baseline": self._baseline,
                    "deliveries": self._rows,
                    "original_worker_snapshot": self._worker,
                    "original_receipt_snapshot": self._receipts,
                    "receipt_snapshot_scope": "original_end_corpus_argument_sampled_before_callback",
                    "end_boundary_scope": "callback_exit_observed_not_shutdown_success",
                    "faults": sorted(self._faults),
                    "callbacks_restored": self._restored,
                    "observation_complete": self._entered
                    and self._restored
                    and self._ended
                    and len(self._rows) == 21
                    and self._worker is not None
                    and not self._faults,
                    "counter_scope": "sequential_nonatomic_observed_boundaries_not_automatic_request_cause",
                    "extra_product_requests": 0,
                    "retries_added": False,
                    "deadlines_changed": False,
                    "qualification": False,
                }
            )
        )
