"""Observe the original recovery request without adding native work or waits."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from typing import Any, cast
from unittest.mock import patch

from scripts.native_slo_bridge_witness import native_bridge_witness
from scripts.native_slo_source_witness import _client_failure

_PATCH_OWNER = threading.Lock()
_STOP_STATES = frozenset({"contained", "already-stopped", "not-run", "failed", "contained_client_cleanup_failed"})
_STOP_FIELDS = ("acknowledged", "authenticated", "generation_present", "owner_lock", "marker_lock", "serving_shutdown")
_STOP_VALUES = frozenset({"true", "false", "free", "busy", "verified", "unverified", "absent", "present", "unknown"})


def _finite_number(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        number = float(cast(float, value))
        return number if math.isfinite(number) else None
    except (OverflowError, TypeError):
        return None


def _milliseconds(value: object) -> float | None:
    number = _finite_number(value)
    return round(number, 3) if number is not None and 0 <= number <= 60_000 else None


def _exception_category(error: BaseException) -> str:
    for kind in (TimeoutError, OSError, ValueError, TypeError, RuntimeError):
        if isinstance(error, kind):
            return kind.__name__
    return "other"


def _stop_evidence(session: object) -> dict[str, object]:
    value = getattr(session, "last_stop_diagnostic", None)
    if not isinstance(value, Mapping):
        return {"capture": "unavailable"}

    def known(item: object, allowed: frozenset[str]) -> str:
        return item if isinstance(item, str) and item in allowed else "other"

    # Read the prior stop's existing finite fields now; close() can overwrite
    # the shared stop artifact later. Absence never proves successful cleanup.
    return {
        "capture": "existing_diagnostic_after_original_stop",
        "status": known(value.get("status"), _STOP_STATES),
        "client_cleanup": "failed" if value.get("client_cleanup") == "failed" else "not_recorded",
        "address_presence": known(value.get("endpoint"), _STOP_VALUES),
        **{field: known(value.get(field), _STOP_VALUES) for field in _STOP_FIELDS},
    }


class RecoveryWitness:
    """Two bounded stage records; a missing observation is never a zero cost."""

    def __init__(self) -> None:
        self.state = "not_started"
        self.records: list[dict[str, Any]] = []
        self.extra_calls = False
        self.projection_failed = False
        self.active = True
        self.captured: dict[str, object] | None = None
        self.record_lock = threading.Lock()
        self.stop: dict[str, object] = {"capture": "unavailable"}

    def report(self, elapsed_ms: object) -> dict[str, object]:
        if self.captured is not None:
            return self.captured
        # Snapshot at the caller's original observe-return boundary. Do not
        # wait for an in-flight worker or let its later completion rewrite the
        # failure evidence. All copied fields are bounded projections below.
        capture_state = "available"
        try:
            # Entries are replaced as a whole. No published entry contains
            # the bridge's live mutable state, so a worker completing during
            # this copy cannot change any dictionary being copied.
            records = list(deepcopy(tuple(self.records)))
        except Exception:
            records = []
            capture_state = "unavailable"
            self.projection_failed = True
        self.captured = {
            "schema": "hol-guard.native-recovery-witness.v1",
            "scope": "original_recovery_call_fixture_worker",
            "capture_boundary": "original_observe_return",
            "timing_scope": "instrumented_diagnostic_original_request",
            "client_failure_scope": "thread_context_before_after_may_be_stale",
            "observer_state": self.state,
            "capture_state": capture_state,
            "observer_error": self.projection_failed,
            "observe_elapsed_ms": _milliseconds(elapsed_ms),
            "calls_capped_at_two": len(records) if self.state == "available" and capture_state == "available" else None,
            "additional_calls_observed": self.extra_calls if self.state == "available" else None,
            "observations": records,
            "prior_stop": self.stop,
            "raised_observe_export": "unavailable_original_exception_preserved",
        }
        return self.captured


def _entry(session: object, args: tuple[Any, ...], kwargs: dict[str, Any], entered: float) -> dict[str, Any]:
    deadline = _finite_number(kwargs.get("deadline"))
    request = kwargs.get("payload")
    return {
        "completion": "entered",
        "exception_category": "not_observed",
        "keyword_call": not args,
        "expected_hook": kwargs.get("harness") == "claude-code" and kwargs.get("event") == "PostToolUse",
        "fixture_binding": kwargs.get("guard_home") == getattr(session, "guard_home", None)
        and kwargs.get("cwd") == getattr(session, "workspace", None),
        "request_kind": (
            "source_reference"
            if isinstance(request, Mapping) and "guard_source_ref" in request
            else "inline"
            if isinstance(request, Mapping)
            else "other"
        ),
        "deadline_remaining_ms": _milliseconds(max(0.0, (deadline - entered) * 1_000))
        if deadline is not None
        else None,
        "deadline_exhausted_before": entered >= deadline if deadline is not None else None,
        "deadline_exhausted_after": None,
        "native_elapsed_ms": None,
        "native_return": "not_observed",
        "rust_authority": None,
        "client_failure_before": _client_failure(),
        "client_failure_after": "not_observed",
        "bridge": {"observer_state": "in_flight_unavailable", "calls_capped_at_two": None},
    }


@contextmanager
def recovery_request_witness(session: object) -> Iterator[RecoveryWitness]:
    """Wrap the fixture's existing edge call on its real worker thread.

    Arguments, call order, return objects and raised exceptions are preserved.
    The existing bridge taps status/encode/client/decode/receipt/failure calls;
    this wrapper only reads the thread-local client failure category and two
    clocks. No status query, transport call, retry, cleanup or wait is added.
    Setup/teardown is outside the outer recovery timer. Stage observation cost
    is included in that timer, so these samples are diagnostic measurements.
    """
    witness = RecoveryWitness()
    owned = _PATCH_OWNER.acquire(blocking=False)
    if not owned:
        witness.state = "overlap_unavailable"
        yield witness
        return
    try:
        try:
            witness.stop = _stop_evidence(session)
        except Exception:
            witness.projection_failed = True
        try:
            worker = getattr(getattr(getattr(session, "daemon", None), "_server", None), "hook_worker", None)
            original = getattr(worker, "_review_raw_hook_native", None)
            if not callable(original):
                raise AttributeError
        except AttributeError:
            witness.state = "fixture_unsupported"
            yield witness
            return
        except Exception:
            witness.state = "setup_unavailable"
            yield witness
            return

        def capture(*args: Any, **kwargs: Any) -> Any:
            if not witness.active:
                return original(*args, **kwargs)
            # The fixture is sequential; still bound the observer under an
            # unexpected concurrent call without making an original wait.
            if not witness.record_lock.acquire(blocking=False):
                witness.extra_calls = True
                return original(*args, **kwargs)
            try:
                index = len(witness.records)
                if index < 2:
                    witness.records.append({"completion": "entered", "bridge": {}})
            finally:
                witness.record_lock.release()
            if index >= 2:
                witness.extra_calls = True
                return original(*args, **kwargs)
            entered = time.monotonic()
            try:
                record = _entry(session, args, kwargs, entered)
            except Exception:
                witness.projection_failed = True
                record = {"completion": "entered", "bridge": {}}
            witness.records[index] = record
            with native_bridge_witness(kwargs.get("policy_snapshot")) as bridge:
                result = None
                raised = None
                try:
                    result = original(*args, **kwargs)
                    return result
                except BaseException as error:
                    raised = error
                    raise
                finally:
                    finished = time.monotonic()
                    try:
                        deadline = _finite_number(kwargs.get("deadline"))
                        witness.records[index] = {
                            **record,
                            "completion": "raised" if raised is not None else "returned",
                            "exception_category": _exception_category(raised) if raised is not None else "none",
                            "deadline_exhausted_after": finished >= deadline if deadline is not None else None,
                            "native_elapsed_ms": _milliseconds((finished - entered) * 1_000),
                            "native_return": "not_returned"
                            if raised is not None
                            else "none"
                            if result is None
                            else "mapping"
                            if isinstance(result, Mapping)
                            else "other",
                            "rust_authority": result.get("authority") == "rust"
                            if isinstance(result, Mapping)
                            else None,
                            "client_failure_after": _client_failure(),
                            # This is the bridge owner's thread after its
                            # original call. Publish a finished copy only;
                            # never expose its live dict to the observer.
                            "bridge": {
                                ("client_reply" if key == "client_output" else key): deepcopy(value)
                                for key, value in bridge.items()
                            },
                        }
                    except Exception:
                        witness.projection_failed = True

        with ExitStack() as stack:
            try:
                stack.enter_context(patch.object(worker, "_review_raw_hook_native", capture))
                witness.state = "available"
            except Exception:
                stack.close()
                witness.state = "setup_unavailable"
            yield witness
    finally:
        witness.active = False
        _PATCH_OWNER.release()
