"""Bounded observation support; wrappers never own the forwarded operation."""

from __future__ import annotations

import contextvars
import functools
import json
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

MAX_ROWS = 88
MAX_STAGES = 32
MAX_REPORT_BYTES = 1024 * 1024
_STAGE_NAMES = frozenset(
    {
        "contained_process_call",
        "spawn",
        "io_setup",
        "wait_and_reap",
        "io_join_and_containment",
        "hook_handler",
        "admission_policy",
        "workspace_policy",
        "scheduler_acquire",
        "worker_review",
        "native_edge",
        "runtime_status",
        "encode_envelope",
        "native_client_exchange",
        "native_client_lease",
        "decode_edge",
        "receipt_submit",
        "activity_submit",
    }
)
_CURRENT: contextvars.ContextVar[tuple[Collector, Row] | None] = contextvars.ContextVar(
    "priority_launcher_phase_row", default=None
)
_STACK: contextvars.ContextVar[tuple[int, ...]] = contextvars.ContextVar("priority_launcher_phase_stack", default=())


def error_kind(error: BaseException | None) -> str | None:
    if error is None:
        return None
    for kind, label in (
        (TimeoutError, "timeout"),
        (OSError, "os_error"),
        (ValueError, "value_error"),
        (TypeError, "type_error"),
        (RuntimeError, "runtime_error"),
        (KeyboardInterrupt, "interrupt"),
        (SystemExit, "system_exit"),
    ):
        if isinstance(error, kind):
            return label
    return "other"


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


@dataclass
class Row:
    index: int
    coordinate: dict[str, object] | None
    facts: dict[str, object] = field(default_factory=dict)
    stages: list[dict[str, object]] = field(default_factory=list)
    next_stage: int = 0
    occurrences: dict[str, int] = field(default_factory=dict)
    entry: Any = None
    completed: bool = False
    outcome: str = "in_flight"


class Collector:
    def __init__(self, side: str, *, clock: Callable[[], int] = time.perf_counter_ns) -> None:
        if side not in {"parent", "daemon"}:
            raise ValueError("phase_side_invalid")
        self.side = side
        self.clock = clock
        self.lock = threading.Lock()
        self.rows: list[Row] = []
        self.faults = 0
        self.row_overflow = 0
        self.stage_overflow = 0
        self.restore_failures = 0
        self.closed = False

    def fault(self) -> None:
        # A failed observer must never replace the original return/exception.
        try:
            with self.lock:
                self.faults += 1
        except BaseException:
            pass

    def guard(self, operation: Callable[[], Any]) -> Any:
        try:
            return operation()
        except BaseException:
            self.fault()
            return None

    def begin(self, coordinate: dict[str, object] | None) -> Row | None:
        with self.lock:
            if self.closed or len(self.rows) >= MAX_ROWS:
                self.row_overflow += 1
                return None
            row = Row(len(self.rows), coordinate)
            self.rows.append(row)
            return row

    def facts(self, row: Row, **values: object) -> None:
        with self.lock:
            row.facts.update(values)

    def event(self, row: Row, name: str, value: dict[str, object]) -> None:
        with self.lock:
            values = row.facts.setdefault(name, [])
            if type(values) is not list or len(values) >= MAX_STAGES:
                self.stage_overflow += 1
                return
            values.append(value)

    def finish(self, row: Row, error: BaseException | None) -> None:
        with self.lock:
            row.outcome = "return" if error is None else "exception"
            row.facts["error_kind"] = error_kind(error)
            row.completed = True

    def snapshot(self, *, original_success: bool) -> dict[str, Any]:
        # The copy and counts share a lock, including a failed producer's tail.
        with self.lock:
            self.closed = True
            rows = [
                {
                    "row_index": row.index,
                    "coordinate": row.coordinate,
                    "outcome": row.outcome,
                    "completed": row.completed,
                    "facts": dict(row.facts),
                    "stages": list(row.stages),
                }
                for row in self.rows
            ]
            result: dict[str, object] = {
                "schema": "hol-guard.priority-launcher-phases.v1",
                "side": self.side,
                "rows": rows,
                "started": len(rows),
                "completed": sum(row.completed for row in self.rows),
                "in_flight": sum(not row.completed for row in self.rows),
                "capture_faults": self.faults,
                "row_overflow": self.row_overflow,
                "stage_overflow": self.stage_overflow,
                "restore_failures": self.restore_failures,
                "original_success": original_success,
                "tail_complete": original_success and all(row.completed for row in self.rows),
                "observation_complete": (
                    original_success
                    and all(row.completed and row.coordinate is not None for row in self.rows)
                    and not (self.faults or self.row_overflow or self.stage_overflow or self.restore_failures)
                ),
                "qualification_eligible": False,
            }
            # Deep-copy only the bounded, explicitly projected diagnostic schema.
            encoded = json_bytes(result)
        if len(encoded) > MAX_REPORT_BYTES:
            return {
                "schema": "hol-guard.priority-launcher-phases.v1",
                "side": self.side,
                "rows": [],
                "started": len(rows),
                "observation_complete": False,
                "report_overflow": True,
                "qualification_eligible": False,
            }
        return json.loads(encoded)


def current(collector: Collector) -> Row | None:
    value = _CURRENT.get()
    return value[1] if value is not None and value[0] is collector else None


def bind(collector: Collector, row: Row | None) -> tuple[Any, Any]:
    return _CURRENT.set(None if row is None else (collector, row)), _STACK.set(())


def unbind(tokens: tuple[Any, Any]) -> None:
    _STACK.reset(tokens[1])
    _CURRENT.reset(tokens[0])


def call(
    collector: Collector,
    stage: str,
    original: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    before: Callable[[Row], Any] | None = None,
    after: Callable[[Row, Any, BaseException | None, Any], None] | None = None,
) -> Any:
    row = current(collector)
    if row is None:
        return original(*args, **kwargs)
    state: Any = collector.guard(lambda: before(row)) if before is not None else None
    span: dict[str, object] | None = None
    stack_token: Any = None

    def start() -> None:
        nonlocal span, stack_token
        if stage not in _STAGE_NAMES:
            raise ValueError("phase_stage_invalid")
        started = collector.clock()
        if type(started) is not int:
            raise TypeError("phase_clock_invalid")
        with collector.lock:
            index = row.next_stage
            row.next_stage += 1
            occurrence = row.occurrences.get(stage, 0)
            row.occurrences[stage] = occurrence + 1
            if index >= MAX_STAGES:
                collector.stage_overflow += 1
                return
        stack = _STACK.get()
        span = {
            "stage": stage,
            "index": index,
            "occurrence": occurrence,
            "parent_index": stack[-1] if stack else None,
            "start_ns": started,
        }
        stack_token = _STACK.set((*stack, index))

    collector.guard(start)
    result: Any = None
    failure: BaseException | None = None
    try:
        result = original(*args, **kwargs)
        return result
    except BaseException as error:
        failure = error
        raise
    finally:

        def end() -> None:
            if span is not None:
                ended = collector.clock()
                started = span["start_ns"]
                if type(ended) is not int or type(started) is not int or ended < started:
                    raise ValueError("phase_clock_invalid")
                span.update(
                    end_ns=ended,
                    duration_ms=(ended - started) / 1_000_000,
                    outcome="return" if failure is None else "exception",
                    error_kind=error_kind(failure),
                )
                with collector.lock:
                    row.stages.append(span)

        collector.guard(end)
        if stack_token is not None:
            collector.guard(lambda: _STACK.reset(stack_token))
        if after is not None:
            collector.guard(lambda: after(row, result, failure, state))


class Patches:
    """Restore original descriptors as well as visible bound callables."""

    def __init__(self, collector: Collector) -> None:
        self.collector = collector
        self.saved: list[tuple[Any, str, bool, Any, Any]] = []

    def set(self, target: Any, name: str, replacement: Any) -> None:
        namespace = vars(target)
        own = name in namespace
        previous = namespace.get(name)
        visible = getattr(target, name)
        # Save first: a hostile setter may mutate then raise.
        self.saved.append((target, name, own, previous, visible))
        setattr(target, name, replacement)

    def wrap(
        self,
        target: Any,
        name: str,
        stage: str,
        *,
        before: Callable[[Row], Any] | None = None,
        after: Callable[[Row, Any, BaseException | None, Any], None] | None = None,
    ) -> None:
        original = getattr(target, name)

        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return call(self.collector, stage, original, args, kwargs, before=before, after=after)

        self.set(target, name, wrapper)

    def close(self) -> None:
        while self.saved:
            target, name, own, previous, visible = self.saved.pop()
            try:
                if own:
                    setattr(target, name, previous)
                else:
                    delattr(target, name)
                restored = getattr(target, name)
                if restored is not visible and restored != visible:
                    raise RuntimeError("phase_alias_restore_failed")
            except BaseException:
                self.collector.fault()
                with self.collector.lock:
                    self.collector.restore_failures += 1


def finite_milliseconds(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    numeric = float(cast(int | float, value))
    return numeric if math.isfinite(numeric) and numeric >= 0 else None
