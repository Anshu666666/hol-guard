"""Failure-only, finite journal operation capture; never retain exception text."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from types import CodeType, ModuleType
from typing import Any, cast

_KINDS = tuple(
    (kind, kind.__name__)
    for kind in (
        OSError,
        PermissionError,
        FileNotFoundError,
        FileExistsError,
        IsADirectoryError,
        NotADirectoryError,
        InterruptedError,
        BlockingIOError,
        BrokenPipeError,
        ConnectionError,
        ConnectionAbortedError,
        ConnectionRefusedError,
        ConnectionResetError,
        TimeoutError,
        ProcessLookupError,
        ChildProcessError,
        ValueError,
        TypeError,
        RuntimeError,
    )
)


def _native_number(value: object, *, signed: bool) -> int | None:
    lower = -(2**31) if signed else 0
    upper = 2**31 if signed else 2**32
    return value if type(value) is int and lower <= value < upper else None


class JournalCheckpointCapture:
    """Observe the existing classifier and corpus snapshot, preserving both calls."""

    def __init__(
        self,
        writer: ModuleType,
        probe: ModuleType,
        *,
        checkpoint_code: CodeType,
        sites: Mapping[CodeType, Mapping[int, str]],
    ) -> None:
        self._writer: Any = writer
        self._probe: Any = probe
        self._checkpoint_code = checkpoint_code
        self._sites = {code: dict(lines) for code, lines in sites.items()}
        self._original_classifier: Callable[[BaseException], Any] = writer.evidence_failure_code
        self._original_end: Callable[..., Any] = probe.end_corpus
        self._classifier_callback = self._classify
        self._end_callback = self._end_corpus
        self._lock = threading.Lock()
        self._events: list[dict[str, object]] = []
        self._lost = False
        self._overflow = False
        self._recording_failed = False
        self._snapshot_count: int | None = None
        self._snapshot_calls = 0
        self._snapshot_diagnostics: object = None
        self._closed = False

    def __enter__(self) -> JournalCheckpointCapture:
        self._writer.evidence_failure_code = self._classifier_callback
        try:
            self._probe.end_corpus = self._end_callback
        except BaseException:
            self._writer.evidence_failure_code = self._original_classifier
            raise
        return self

    def __exit__(self, *unused: object) -> None:
        try:
            self._writer.evidence_failure_code = self._original_classifier
        finally:
            self._probe.end_corpus = self._original_end
            self._closed = True

    def _trace(self, error: BaseException) -> tuple[bool, list[str], bool]:
        trace = cast(Any, vars(BaseException)["__traceback__"]).__get__(error)
        checkpoint = False
        operations: list[str] = []
        for _ in range(32):
            if trace is None:
                return checkpoint, operations, True
            code = trace.tb_frame.f_code
            checkpoint |= code is self._checkpoint_code
            operation = self._sites.get(code, {}).get(trace.tb_lineno)
            if operation is not None:
                operations.append(operation)
            trace = trace.tb_next
        return checkpoint, operations, trace is None

    def _project(self, error: BaseException) -> dict[str, object] | None:
        checkpoint, operations, trace_complete = self._trace(error)
        if not checkpoint:
            return None
        pending: list[tuple[str, BaseException]] = [("terminal", error)]
        seen: set[int] = set()
        chain: list[dict[str, object]] = []
        complete = trace_complete and bool(operations)
        while pending and len(chain) < 4:
            relation, current = pending.pop(0)
            if id(current) in seen:
                complete = False
                continue
            seen.add(id(current))
            kind = next((name for candidate, name in _KINDS if type(current) is candidate), None)
            if kind is None:
                chain.append({"relation": relation, "kind": "unsupported_exception"})
                complete = False
                continue
            _, current_sites, frames_complete = self._trace(current)
            is_os = isinstance(current, OSError)
            errno = _native_number(current.errno, signed=True) if is_os else None
            winerror = _native_number(getattr(current, "winerror", None), signed=False) if is_os else None
            chain.append(
                {
                    "relation": relation,
                    "kind": kind,
                    "errno": errno,
                    "winerror": winerror,
                    "operations": current_sites,
                    "terminal_operation": current_sites[-1] if current_sites else "unknown",
                    "trace_complete": frames_complete,
                    "context_suppressed": cast(Any, vars(BaseException)["__suppress_context__"]).__get__(current),
                }
            )
            complete = complete and frames_complete and bool(current_sites)
            cause = cast(Any, vars(BaseException)["__cause__"]).__get__(current)
            context = cast(Any, vars(BaseException)["__context__"]).__get__(current)
            if cause is not None:
                pending.append(("cause", cause))
            if context is not None and context is not cause:
                pending.append(("context", context))
        return {
            "chain": chain,
            "complete": complete and not pending,
            "chain_truncated": bool(pending),
            "terminal_errno": chain[0].get("errno") if chain else None,
        }

    def _observe(self, error: BaseException) -> None:
        event = self._project(error)
        if event is None:
            return
        if not self._lock.acquire(blocking=False):
            self._lost = True
            return
        try:
            if len(self._events) == 16:
                self._overflow = True
            else:
                self._events.append(event)
        finally:
            self._lock.release()

    def _classify(self, error: BaseException) -> Any:
        result = self._original_classifier(error)
        try:
            self._observe(error)
        except BaseException:
            self._recording_failed = True
        return result

    def _end_corpus(self, *args: Any, **kwargs: Any) -> Any:
        result = self._original_end(*args, **kwargs)
        try:
            self._snapshot_calls += 1
            if not self._lock.acquire(blocking=False):
                self._lost = True
                return result
            try:
                self._snapshot_count = len(self._events)
                # Original end_corpus receives this existing stats object positionally.
                stats = args[2] if len(args) == 3 and not kwargs else None
                diagnostics = stats.get("failure_diagnostics") if type(stats) is dict else None
                if type(diagnostics) is dict:
                    value = diagnostics.get("journal_checkpoint/os_permission", 0)
                    self._snapshot_diagnostics = value if type(value) is int and 0 <= value <= 2**63 - 1 else None
            finally:
                self._lock.release()
        except BaseException:
            self._recording_failed = True
        return result

    def report(self) -> dict[str, Any]:
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            self._lost = True
        try:
            # Report only after callback restoration. Internal rows contain primitives.
            events = list(self._events) if acquired else []
            before_snapshot = events[: self._snapshot_count] if self._snapshot_count is not None else []
            permissions = sum(event.get("terminal_errno") in (1, 13) for event in before_snapshot)
            reconciled = self._snapshot_diagnostics == permissions
            return {
                "schema": "hol-guard.journal-checkpoint-origin.v1",
                "events": events,
                "end_return_event_count": self._snapshot_count,
                "snapshot_calls": self._snapshot_calls,
                "original_snapshot_permission_count": self._snapshot_diagnostics,
                "overflow": self._overflow,
                "lost": self._lost,
                "recording_failed": self._recording_failed,
                "callbacks_restored": self._closed,
                "events_through_end_return_with_permission_errno": permissions,
                "snapshot_permission_count_reconciled": reconciled,
                "event_boundary": "after_original_end_corpus_return",
                "individual_event_snapshot_membership_proven": False,
                "failure_reproduced": bool(events),
                "observation_complete": self._closed
                and self._snapshot_calls == 1
                and reconciled
                and not (self._lost or self._overflow or self._recording_failed)
                and all(event["complete"] for event in events),
                "qualification": False,
            }
        finally:
            if acquired:
                self._lock.release()
