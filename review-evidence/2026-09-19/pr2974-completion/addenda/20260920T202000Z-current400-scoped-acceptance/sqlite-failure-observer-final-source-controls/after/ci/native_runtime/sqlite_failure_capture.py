"""Observe terminal persistence errors without retaining private exception data."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Mapping
from types import CodeType, ModuleType
from typing import Any, cast

_SQLITE_TYPES = (
    sqlite3.Error,
    sqlite3.Warning,
    sqlite3.InterfaceError,
    sqlite3.DatabaseError,
    sqlite3.DataError,
    sqlite3.OperationalError,
    sqlite3.IntegrityError,
    sqlite3.InternalError,
    sqlite3.ProgrammingError,
    sqlite3.NotSupportedError,
)
_OTHER_TYPES = (OSError, PermissionError, TimeoutError, RuntimeError, ValueError, TypeError)


def _exception_field(error: BaseException, name: str) -> Any:
    return cast(Any, vars(BaseException)[name]).__get__(error)


class SQLiteFailureCapture:
    """One original classifier call; fixed scalar capture after its return only."""

    def __init__(
        self,
        writer: ModuleType,
        *,
        scopes: Mapping[CodeType, Mapping[int, str]],
        sites: Mapping[CodeType, Mapping[int, str]],
    ) -> None:
        self._writer: Any = writer
        self._original: Callable[[BaseException], Any] = writer.evidence_failure_code
        self._callback = self._classify
        self._scopes = {code: dict(lines) for code, lines in scopes.items()}
        self._sites = {code: dict(lines) for code, lines in sites.items()}
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._entered = False
        self._closed = False
        self._lost = False
        self._overflow = False
        self._recording_failed = False
        self._classifier_failed = False
        self._restoration_failed = False

    def __enter__(self) -> SQLiteFailureCapture:
        if self._entered or self._writer.evidence_failure_code is not self._original:
            raise RuntimeError("sqlite_observer_alias_not_original")
        self._writer.evidence_failure_code = self._callback
        self._entered = True
        return self

    def __exit__(self, kind: object, error: object, traceback: object) -> None:
        del kind, traceback
        try:
            self._writer.evidence_failure_code = self._original
        except BaseException:
            self._restoration_failed = True
            if error is None:
                raise
        else:
            self._closed = True

    def _trace(self, error: BaseException) -> tuple[set[str], str, bool, bool]:
        trace = _exception_field(error, "__traceback__")
        phases: set[str] = set()
        operation = "unknown"
        after_commit = False
        for _ in range(32):
            if trace is None:
                return phases, operation, True, after_commit
            code = trace.tb_frame.f_code
            # Unknown code constants can define hash/equality hooks. Select
            # admitted frame objects by identity without invoking those hooks.
            scope = next((lines for bound, lines in self._scopes.items() if bound is code), {})
            phase = scope.get(trace.tb_lineno)
            if phase is not None:
                phases.add(phase)
            # Only the innermost actual Python frame may name the failing leaf.
            site = next((lines for bound, lines in self._sites.items() if bound is code), {})
            operation = site.get(trace.tb_lineno, "unknown")
            if operation == "post_commit_dispatch_expression":
                after_commit = True
                # This expression first reads total_changes, then may call the
                # generation reader. The shared line is not a precise leaf.
                operation = "unknown"
            trace = trace.tb_next
        return phases, operation, trace is None, after_commit

    def _project(self, error: BaseException) -> dict[str, Any] | None:
        phases, _, _, _ = self._trace(error)
        if not phases:
            return None
        chain: list[dict[str, Any]] = []
        pending = [("terminal", error)]
        seen: set[int] = set()
        complete = len(phases) == 1
        while pending and len(chain) < 4:
            relation, current = pending.pop(0)
            if id(current) in seen:
                complete = False
                continue
            seen.add(id(current))
            exact_type = type(current)
            known = next((t for t in (*_SQLITE_TYPES, *_OTHER_TYPES) if exact_type is t), None)
            _, operation, trace_complete, after_commit = self._trace(current)
            number = vars(current).get("sqlite_errorcode") if any(exact_type is t for t in _SQLITE_TYPES) else None
            code = number if type(number) is int and 0 <= number < 2**32 else None
            chain.append(
                {
                    "relation": relation,
                    "kind": known.__name__ if known is not None else "unsupported_exception",
                    "operation": operation,
                    "sqlite_errorcode": code,
                    "sqlite_primary_code": code & 255 if code is not None else None,
                    "trace_complete": trace_complete,
                    "post_commit_path_proven": after_commit,
                    "context_suppressed": _exception_field(current, "__suppress_context__"),
                }
            )
            complete = complete and known is not None and trace_complete and operation != "unknown"
            cause = _exception_field(current, "__cause__")
            context = _exception_field(current, "__context__")
            if cause is not None:
                pending.append(("cause", cause))
            if context is not None and context is not cause:
                pending.append(("context", context))
        return {
            "phase": next(iter(phases)) if len(phases) == 1 else "ambiguous",
            "chain": chain,
            "chain_truncated": bool(pending),
            "complete": complete and not pending,
        }

    def _observe(self, error: BaseException) -> None:
        event = self._project(error)
        if event is None:
            return
        if not self._lock.acquire(blocking=False):
            self._lost = True
            return
        try:
            if len(self._events) >= 128:
                self._overflow = True
            else:
                self._events.append(event)
        finally:
            self._lock.release()

    def _classify(self, error: BaseException) -> Any:
        try:
            result = self._original(error)
        except BaseException:
            self._classifier_failed = True
            raise
        try:
            self._observe(error)
        except BaseException:
            self._recording_failed = True
        return result

    def report(self) -> dict[str, Any]:
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            self._lost = True
        try:
            # Rows contain only owned JSON primitives; return detached snapshots.
            import json

            events = json.loads(json.dumps(self._events)) if acquired else []
            return {
                "schema": "hol-guard.sqlite-failure-origin.v1",
                "events": events,
                "classifier_callbacks_retained": len(events),
                "unit": "terminal_classifier_callback",
                "failed_record_units_reconciled": False,
                "failure_reproduced": bool(events),
                "callbacks_restored": self._closed,
                "overflow": self._overflow,
                "lost": self._lost,
                "recording_failed": self._recording_failed,
                "classifier_failed": self._classifier_failed,
                "restoration_failed": self._restoration_failed,
                "observation_complete": self._entered
                and self._closed
                and not (
                    self._lost
                    or self._overflow
                    or self._recording_failed
                    or self._restoration_failed
                    or self._classifier_failed
                )
                and all(event["complete"] for event in events),
                "qualification": False,
            }
        finally:
            if acquired:
                self._lock.release()
