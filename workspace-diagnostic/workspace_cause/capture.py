"""Bounded fixture-only call records; never substitute original operation results."""

from __future__ import annotations

import contextvars
import math
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

STAGES = frozenset(
    {
        "publication",
        "publication_context",
        "configuration_compile",
        "authority_capture",
        "input_fingerprint",
        "input_reconcile",
        "configuration_changed",
        "request_publish",
        "record_error",
        "mark_expired",
        "resident_confirm",
        "resident_generation",
        "resident_directory",
        "resident_paths",
        "wait_ready",
        "service_constructor",
        "hook_worker_constructor",
        "request_services",
        "http_bind",
        "http_activate",
        "authority_registry_read",
        "extension_runtime_constructor",
        "extension_api_constructor",
        "local_cli_constructor",
        "approval_attention_constructor",
        "request_executor_constructor",
        "await_ack",
        "publisher_start",
        "publisher_close",
        "workspace_register",
    }
)
ERROR_CODES = frozenset(
    {
        "native_policy_snapshot_resident_changed",
        "native_command_control_binding_changed",
        "native_policy_snapshot_ack_invalid",
        "native_policy_snapshot_ack_mismatch",
        "native_policy_snapshot_expired",
        "native_policy_snapshot_workspace_capacity",
        "native_policy_snapshot_integrity_key_unavailable",
        "native_policy_snapshot_runtime_unavailable",
        "native_policy_snapshot_protocol_unsupported",
        "native_policy_snapshot_native_disabled",
        "native_resident_live_request_failed",
        "native_resident_start_timeout",
        "native_resident_restart_circuit_open",
        "native_command_control_key_unavailable",
        "native_command_control_authority_invalid",
    }
)
DETAIL_KEYS = frozenset(
    {
        "error",
        "before_present",
        "before_observed_equal",
        "observed_count",
        "changed_hint_count",
        "deadline_from_origin_ms",
        "executor_kind",
        "observed_directory_present",
        "confirmation_directory_equal",
        "prior_input_present",
        "configuration_metadata_changed",
        "resident_metadata_changed",
    }
)
MAX_ROWS = 512
MAX_PUBLISHERS = 4
MAX_COUNTER = 65535
_CURRENT: contextvars.ContextVar[tuple[Any, int] | None] = contextvars.ContextVar(
    "workspace_cause_current", default=None
)


def error_code(value: object) -> str:
    if value is None:
        return "none"
    return value if type(value) is str and value in ERROR_CODES else "other"


def current_capture() -> Capture | None:
    current = _CURRENT.get()
    return current[0] if current is not None else None


class Capture:
    """Own one canonical fixture home and record only closed scalar fields."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.started = time.monotonic()
        self._lock = threading.Lock()
        self._rows: list[dict[str, Any]] = []
        self._publishers: list[Any] = []
        self._active: set[int] = set()
        self._lost = False
        self._frozen = False
        self._overflow = False

    def fault(self) -> None:
        self._lost = True

    def owns(self, value: Any) -> bool:
        try:
            home = getattr(value, "guard_home", None)
            return isinstance(home, Path) and home == self.home
        except Exception:
            self.fault()
            return False

    def _state(self, publisher: Any) -> dict[str, Any] | None:
        if publisher is None:
            return None
        sampled_before = (time.monotonic() - self.started) * 1000
        condition = publisher._condition
        if not condition.acquire(blocking=False):
            self.fault()
            return None
        try:
            epoch = publisher._epoch
            if type(epoch) is not int or not 0 <= epoch <= MAX_COUNTER:
                self._overflow = True
                epoch = None
            state = {
                "epoch": epoch,
                "acked": publisher._acked is True,
                "closed": publisher._closed is True,
                "error": error_code(publisher._last_error),
            }
        finally:
            condition.release()
        return {
            **state,
            "sample_before_ms": sampled_before,
            "sample_after_ms": (time.monotonic() - self.started) * 1000,
        }

    def _publisher_number(self, publisher: Any) -> int | None:
        if publisher is None:
            return None
        for index, value in enumerate(self._publishers):
            if value is publisher:
                return index + 1
        if len(self._publishers) >= MAX_PUBLISHERS:
            self._overflow = True
            return None
        self._publishers.append(publisher)
        return len(self._publishers)

    def _begin(self, stage: str, publisher: Any, details: Mapping[str, Any] | None) -> int | None:
        now = (time.monotonic() - self.started) * 1000
        before = self._state(publisher)
        safe_details = dict(details or {})
        if not set(safe_details) <= DETAIL_KEYS:
            raise ValueError("diagnostic_detail_key")
        for key, value in safe_details.items():
            if key == "error":
                valid = value in ERROR_CODES | {"none", "other"}
            elif key == "executor_kind":
                valid = value in {"general", "control", "other"}
            elif key in {
                "before_present",
                "before_observed_equal",
                "observed_directory_present",
                "confirmation_directory_equal",
                "prior_input_present",
                "configuration_metadata_changed",
                "resident_metadata_changed",
            }:
                valid = type(value) is bool
            elif key == "deadline_from_origin_ms":
                valid = type(value) in {int, float} and math.isfinite(value) and abs(value) < 1000000
            else:
                valid = type(value) is int and 0 <= value <= MAX_COUNTER
            if not valid:
                raise ValueError("diagnostic_detail_value")
        if not self._lock.acquire(blocking=False):
            self.fault()
            return None
        try:
            if self._frozen or len(self._rows) >= MAX_ROWS:
                self._overflow = True
                return None
            if stage not in STAGES:
                self.fault()
                return None
            parent = _CURRENT.get()
            row_id = len(self._rows)
            self._rows.append(
                {
                    "id": row_id,
                    "parent": parent[1] if parent is not None and parent[0] is self else None,
                    "stage": stage,
                    "publisher": self._publisher_number(publisher),
                    "started_ms": now,
                    "finished_ms": None,
                    "call_enter_ms": None,
                    "call_return_ms": None,
                    "before": before,
                    "after": None,
                    "outcome": "in_flight",
                    "exception": "none",
                    "details": safe_details,
                }
            )
            self._active.add(row_id)
            return row_id
        finally:
            self._lock.release()

    def _finish(
        self,
        row_id: int,
        publisher: Any,
        result: Any,
        failure: BaseException | None,
        call_enter: float | None,
        call_return: float | None,
        returned_details: Mapping[str, Any],
    ) -> None:
        after = self._state(publisher)
        now = (time.monotonic() - self.started) * 1000
        if not self._lock.acquire(blocking=False):
            self.fault()
            return
        try:
            if self._frozen:
                self.fault()
                return
            row = self._rows[row_id]
            row["finished_ms"] = now
            row["call_enter_ms"] = call_enter
            row["call_return_ms"] = call_return
            row["details"].update(returned_details)
            row["after"] = after
            if failure is not None:
                row["outcome"] = "exception"
                kind = type(failure).__name__
                row["exception"] = (
                    kind
                    if kind in {"NativePolicySnapshotError", "RuntimeError", "OSError", "ValueError", "TimeoutError"}
                    else "other"
                )
            elif result is None:
                row["outcome"] = "none"
            elif type(result) is bool:
                row["outcome"] = "true" if result else "false"
            else:
                row["outcome"] = "value"
            self._active.discard(row_id)
        finally:
            self._lock.release()

    def call(
        self,
        stage: str,
        original: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        publisher: Any = None,
        details: Mapping[str, Any] | None = None,
        summarize: Callable[[Any], Mapping[str, Any]] | None = None,
    ) -> Any:
        """Call once with the identical objects, then return or raise the same object."""
        row_id = None
        token = None
        try:
            row_id = self._begin(stage, publisher, details)
            if row_id is not None:
                token = _CURRENT.set((self, row_id))
        except Exception:
            self.fault()
        call_enter = None
        try:
            call_enter = (time.monotonic() - self.started) * 1000
        except Exception:
            self.fault()
        result: Any = None
        failure: BaseException | None = None
        try:
            result = original(*args, **kwargs)
            return result
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                if row_id is not None:
                    call_return = (time.monotonic() - self.started) * 1000
                    returned_details = dict(summarize(result)) if summarize is not None and failure is None else {}
                    if not set(returned_details) <= {
                        "confirmation_directory_equal",
                        "prior_input_present",
                        "configuration_metadata_changed",
                        "resident_metadata_changed",
                    } or any(type(value) is not bool for value in returned_details.values()):
                        raise ValueError("diagnostic_returned_detail")
                    self._finish(row_id, publisher, result, failure, call_enter, call_return, returned_details)
            except Exception:
                self.fault()
            finally:
                if token is not None:
                    try:
                        _CURRENT.reset(token)
                    except Exception:
                        self.fault()

    def freeze(self) -> dict[str, Any]:
        with self._lock:
            self._frozen = True
            rows = [
                {
                    **row,
                    "details": dict(row["details"]),
                    "before": dict(row["before"]) if row["before"] is not None else None,
                    "after": dict(row["after"]) if row["after"] is not None else None,
                }
                for row in self._rows
            ]
            return {
                "schema": "hol-guard.workspace-cause-observation.v1",
                "origin": "owned_lifecycle_dispatch_entry_monotonic",
                "state_time_scope": "interval_brackets_direct_lock_read_not_transition_commit",
                "call_time_scope": "brackets_original_call_with_diagnostic_overhead_explicit",
                "rows": rows,
                "row_bound": MAX_ROWS,
                "publisher_bound": MAX_PUBLISHERS,
                "publishers_observed": len(self._publishers),
                "calls_in_flight": len(self._active),
                "observation_lost": self._lost,
                "overflow": self._overflow,
                "observation_complete": not self._lost and not self._overflow and not self._active,
                "original_results_preserved": True,
                "additional_native_or_http_probes": 0,
                "headline_timing_eligible": False,
                "qualification_complete": False,
            }
