"""Bounded, non-authoritative diagnostics for an original capacity-wave None."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import patch

from scripts.native_slo_source_witness import _CLIENT_FAILURE_CODES, _HARNESSES, _client_failure

_LIMIT = 64
_EVENTS = frozenset({"PreToolUse", "PostToolUse"})
_CODES = _CLIENT_FAILURE_CODES | {"not_recorded", "unsupported", "unavailable", "other"}
_SNAPSHOTS = frozenset({"missing", "other", "positive_generation", "invalid_generation"})


def _known(value: object, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "other"


def _bounded(value: object, maximum: int) -> int | None:
    return value if type(value) is int and 0 <= value <= maximum else None


def capacity_none_report(value: object) -> dict[str, object]:
    """Project a closed schema again before it reaches public failure evidence."""
    source = value if isinstance(value, Mapping) else {}
    records = source.get("records")
    records = records if isinstance(records, (list, tuple)) else ()
    projected: list[dict[str, object]] = []
    for record in records[:_LIMIT]:
        record = record if isinstance(record, Mapping) else {}
        before = _known(record.get("client_failure_before"), _CODES)
        after = _known(record.get("client_failure_after"), _CODES)
        projected.append(
            {
                "harness": _known(record.get("harness"), _HARNESSES),
                "event": _known(record.get("event"), _EVENTS),
                "snapshot": _known(record.get("snapshot"), _SNAPSHOTS),
                "deadline_remaining_after_ms": _bounded(record.get("deadline_remaining_after_ms"), 9_000),
                "client_failure_before": before,
                "client_failure_after": after,
                "client_context_changed": before != after,
            }
        )
    return {
        "schema": "hol-guard.native-capacity-none-witness.v1",
        "scope": "owned_worker_original_none_returns",
        "supported": source.get("supported") is True,
        "incomplete": (
            source.get("incomplete") is not False
            or source.get("supported") is not True
            or source.get("observer_error") is True
            or source.get("overflow") is True
            or len(records) > _LIMIT
        ),
        "observer_error": source.get("observer_error") is True,
        "overflow": source.get("overflow") is True or len(records) > _LIMIT,
        "record_limit": _LIMIT,
        "records_retained": len(projected),
        "none_returns_capped_at_65": _bounded(source.get("none_returns_capped_at_65"), _LIMIT + 1),
        "client_failure_scope": "thread_context_before_after_may_be_stale",
        "current_request_client_call_proven": False,
        "bridge_stages_observed": False,
        "per_request_native_route_proven": False,
        "diagnostic_callback_in_request_budget": True,
        "records": projected,
    }


class CapacityNoneWitness:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[dict[str, object]] = []
        self._none_count = 0
        self._supported = False
        self._observer_error = False
        self._closed = False
        self._bookkeeping_complete = False

    def _projection_failed(self) -> None:
        with self._lock:
            if not self._closed:
                self._observer_error = True

    def _code(self) -> str:
        try:
            return _client_failure()
        except Exception:
            self._projection_failed()
            return "unavailable"

    def wrap(self, original: Any) -> Any:
        def capture(*args: object, **kwargs: object) -> object:
            before = self._code()
            # Original exceptions propagate unchanged. Never hold the observer
            # lock across evaluation and never issue a diagnostic native call.
            edge = original(*args, **kwargs)
            if edge is not None:
                return edge
            after = self._code()
            try:
                snapshot = kwargs.get("policy_snapshot")
                state = "missing" if snapshot is None else "other"
                if isinstance(snapshot, Mapping):
                    generation = snapshot.get("generation")
                    state = (
                        "positive_generation" if type(generation) is int and generation > 0 else "invalid_generation"
                    )
                deadline = kwargs.get("deadline")
                remaining = (
                    int(max(0, min(9_000, (deadline - time.monotonic()) * 1_000)))
                    if (type(deadline) is float or type(deadline) is int) and math.isfinite(deadline)
                    else None
                )
                record: dict[str, object] | None = {
                    "harness": _known(kwargs.get("harness"), _HARNESSES),
                    "event": _known(kwargs.get("event"), _EVENTS),
                    "snapshot": state,
                    "deadline_remaining_after_ms": remaining,
                    "client_failure_before": before,
                    "client_failure_after": after,
                }
            except Exception:
                self._projection_failed()
                record = None
            with self._lock:
                if not self._closed:
                    self._none_count = min(_LIMIT + 1, self._none_count + 1)
                    if record is not None and len(self._records) < _LIMIT:
                        self._records.append(record)
            return edge

        return capture

    def finish(self, *, bookkeeping_complete: bool) -> None:
        with self._lock:
            self._bookkeeping_complete = bookkeeping_complete

    def close(self) -> None:
        with self._lock:
            # A late callback can complete its original call but cannot mutate
            # the frozen report. Missing bookkeeping remains explicit below.
            self._closed = True

    def report(self) -> dict[str, object]:
        with self._lock:
            return capacity_none_report(
                {
                    "supported": self._supported,
                    "incomplete": (
                        not self._closed
                        or not self._supported
                        or not self._bookkeeping_complete
                        or self._observer_error
                        or self._none_count > _LIMIT
                    ),
                    "observer_error": self._observer_error,
                    "overflow": self._none_count > _LIMIT,
                    "none_returns_capped_at_65": self._none_count,
                    "records": self._records,
                }
            )


@contextmanager
def capacity_none_witness(worker: Any) -> Iterator[CapacityNoneWitness]:
    witness = CapacityNoneWitness()
    try:
        with ExitStack() as stack:
            try:
                original = getattr(worker, "_review_raw_hook_native", None)
                if callable(original):
                    stack.enter_context(patch.object(worker, "_review_raw_hook_native", witness.wrap(original)))
                    witness._supported = True
            except Exception:
                stack.close()
                witness._projection_failed()
            yield witness
    finally:
        witness.close()
