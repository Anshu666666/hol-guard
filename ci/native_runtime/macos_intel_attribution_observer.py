"""Bounded, diagnostic-only spans around the original installed SLO operations.

Only aggregate closed labels leave the process. Arguments, return objects,
exceptions, identifiers and individual span records are never exported.
"""

from __future__ import annotations

import functools
import inspect
import json
import math
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, cast

MAX_RECORDS = 8192
MAX_THREADS = 512
MAX_REQUEST_RECORDS = 128
MAX_DEPTH = 32
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_INTERVAL_NS = 2100 * 1_000_000_000
PHASES = frozenset(
    {
        "other",
        "cold",
        "warm",
        "sizes",
        "recovery",
        "c16",
        "rss_prewarm_c64",
        "launcher",
        "readiness",
    }
)
LABELS = frozenset(
    {
        "load_request",
        "server_hook",
        "server_challenge",
        "server_execute",
        "server_response",
        "scheduler_acquire",
        "worker_native",
        "native_edge",
        "policy_prepare",
        "policy_snapshot",
        "identity_status",
        "identity_validate",
        "identity_manifest",
        "identity_capabilities",
        "runtime_process",
        "client_lease",
        "client_request",
        "client_snapshot",
        "client_start",
        "client_write",
        "client_spawn",
        "launcher_inclusive",
        "launcher_process",
        "launcher_spawn",
        "launcher_io_start",
        "launcher_wait",
        "launcher_cleanup",
    }
)
ROOT_DOMAINS = {
    "load_request": "load",
    "server_hook": "server",
    "server_challenge": "challenge",
    "launcher_inclusive": "launcher",
}
EXCEPTIONS = frozenset(
    {
        "OSError",
        "TimeoutError",
        "ValueError",
        "RuntimeError",
        "TypeError",
        "KeyError",
        "AssertionError",
        "BrokenPipeError",
        "PermissionError",
        "SystemExit",
        "KeyboardInterrupt",
    }
)
ISSUES = frozenset(
    {
        "clock",
        "record_limit",
        "thread_limit",
        "request_limit",
        "depth_limit",
        "observer_error",
        "cross_thread_context",
        "unbalanced",
        "phase_overlap",
        "invalid_fact",
        "output_limit",
    }
)
_ABSENT = object()
_THREAD_CLOCK = getattr(time, "thread_time_ns", None)


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def distribution(values: list[int]) -> dict[str, int] | None:
    if not values:
        return None
    ordered = sorted(values)
    return {
        "count": len(values),
        "minimum_ns": ordered[0],
        "maximum_ns": ordered[-1],
        "sum_ns": sum(values),
        "p50_ns": ordered[math.ceil(len(values) * 0.5) - 1],
        "p95_ns": ordered[math.ceil(len(values) * 0.95) - 1],
    }


@dataclass(slots=True)
class Span:
    label: str
    domain: str
    phase: str
    owner: threading.Thread
    parent: Span | None
    root: Span | None = None
    request_records: int = 0
    depth: int = 1
    started: int | None = None
    ended: int | None = None
    cpu_started: int | None = None
    cpu_ended: int | None = None
    recording_ns: int = 0
    recording_cpu_ns: int | None = None
    outcome: str = "unfinished"
    exception: str | None = None
    facts: dict[str, int | bool | None] = field(default_factory=dict)
    write_ended: int | None = None
    write_succeeded: bool = False
    spawn_attempts: int = 0
    spawn_returns: int = 0


class Observer:
    """Fixed aggregate allocation caps; no observer lock surrounds product code."""

    def __init__(
        self,
        *,
        clock: Callable[[], int] = time.monotonic_ns,
        cpu_clock: Callable[[], int] | None = _THREAD_CLOCK,
        maximum_records: int = MAX_RECORDS,
        maximum_threads: int = MAX_THREADS,
    ) -> None:
        if (
            type(maximum_records) is not int
            or type(maximum_threads) is not int
            or not 1 <= maximum_records <= MAX_RECORDS
            or not 1 <= maximum_threads <= MAX_THREADS
        ):
            raise ValueError("observer_limits")
        self.clock, self.cpu_clock = clock, cpu_clock
        self.maximum_records, self.maximum_threads = maximum_records, maximum_threads
        self.records: list[Span] = []
        self.threads: set[threading.Thread] = set()
        self.issues: Counter[str] = Counter()
        self.lock = threading.Lock()
        self.stack: ContextVar[tuple[Span, ...]] = ContextVar("private_attribution_stack", default=())
        self.phase = "other"
        self.phase_owner: threading.Thread | None = None
        info = time.get_clock_info("monotonic")
        cpu_info = time.get_clock_info("thread_time") if cpu_clock is getattr(time, "thread_time_ns", None) else None
        implementations = {
            "mach_absolute_time()": "mach_absolute_time",
            "clock_gettime(CLOCK_MONOTONIC)": "clock_monotonic",
            "clock_gettime(CLOCK_THREAD_CPUTIME_ID)": "clock_thread_cpu",
        }
        self.clock_metadata = {
            "elapsed_kind": "monotonic_ns" if clock is time.monotonic_ns else "injected_unit_control",
            "elapsed_resolution_ns": math.ceil(info.resolution * 1_000_000_000),
            "elapsed_monotonic": info.monotonic,
            "elapsed_implementation": implementations.get(info.implementation, "other_platform_clock"),
            "same_thread_cpu_available": cpu_clock is not None,
            "cpu_resolution_ns": math.ceil(cpu_info.resolution * 1_000_000_000) if cpu_info is not None else None,
            "cpu_implementation": implementations.get(cpu_info.implementation, "other_platform_clock")
            if cpu_info
            else None,
            "cpu_scope": "calling_thread_only_excludes_child_processes",
        }

    def invalidate(self, reason: str) -> None:
        if reason not in ISSUES:
            reason = "observer_error"
        with self.lock:
            self.issues[reason] = min(MAX_RECORDS, self.issues[reason] + 1)

    def tick(self, cpu: bool = False) -> int | None:
        operation = self.cpu_clock if cpu else self.clock
        if operation is None:
            return None
        try:
            value = operation()
            if type(value) is not int or value < 0:
                raise ValueError("clock")
            return value
        except BaseException:
            self.invalidate("clock")
            return None

    @staticmethod
    def interval(start: int | None, end: int | None) -> int | None:
        return end - start if start is not None and end is not None and 0 <= end - start <= MAX_INTERVAL_NS else None

    def begin(self, label: str) -> tuple[Span | None, Any]:
        if label not in LABELS:
            raise ValueError("observer_label")
        owner = threading.current_thread()
        stack = self.stack.get()
        if stack and (stack[-1].owner is not owner or stack[-1].ended is not None):
            self.invalidate("cross_thread_context")
            stack = ()
        parent = stack[-1] if stack else None
        # Explicit request/challenge roots remain disjoint even if a caller
        # copied a context; no transport request identifiers are inspected.
        if label in ROOT_DOMAINS:
            parent, stack = None, ()
        with self.lock:
            if len(self.records) >= self.maximum_records:
                self.issues["record_limit"] = min(MAX_RECORDS, self.issues["record_limit"] + 1)
                return None, None
            if owner not in self.threads and len(self.threads) >= self.maximum_threads:
                self.issues["thread_limit"] = min(MAX_RECORDS, self.issues["thread_limit"] + 1)
                return None, None
            if len(stack) >= MAX_DEPTH:
                self.issues["depth_limit"] = min(MAX_RECORDS, self.issues["depth_limit"] + 1)
                return None, None
            root = parent.root if parent is not None else None
            if root is not None and root.request_records >= MAX_REQUEST_RECORDS:
                self.issues["request_limit"] = min(MAX_RECORDS, self.issues["request_limit"] + 1)
                return None, None
            span = Span(
                label,
                ROOT_DOMAINS.get(label, parent.domain if parent else "background"),
                self.phase,
                owner,
                parent,
                root=root,
                depth=len(stack) + 1,
            )
            span.root = root or span
            span.root.request_records += 1
            self.threads.add(owner)
            self.records.append(span)
        return span, self.stack.set((*stack, span))

    def finish(self, span: Span, value: Any, exception: BaseException | None) -> None:
        span.ended = self.tick()
        span.cpu_ended = self.tick(cpu=True)
        if span.owner is not threading.current_thread() or self.interval(span.started, span.ended) is None:
            self.invalidate("clock")
        if self.cpu_clock is not None and self.interval(span.cpu_started, span.cpu_ended) is None:
            self.invalidate("clock")
        span.outcome = (
            "raised"
            if exception is not None
            else (
                "none"
                if value is None
                else "true"
                if value is True
                else "false"
                if value is False
                else "bytes"
                if type(value) is bytes
                else "returned"
            )
        )
        if exception is not None:
            category = type(exception).__name__
            span.exception = category if category in EXCEPTIONS else "other_exception"
        if span.label == "scheduler_acquire" and exception is None:
            permit = cast(Any, value).permit
            span.facts["admitted"] = permit is not None
            if permit is not None:
                queued, admitted = permit._item.queued_at, permit._item.admitted_at
                if type(queued) in (int, float) and type(admitted) in (int, float):
                    delta = admitted - queued
                    if math.isfinite(delta) and 0 <= delta <= 2100:
                        span.facts["scheduler_queue_ns"] = int(delta * 1_000_000_000)
        if span.label == "identity_validate" and value is not None and exception is None:
            size = cast(Any, value).size
            if type(size) is int and 0 <= size <= 64 * 1024 * 1024:
                span.facts["validated_identity_size"] = size
        stack = self.stack.get()
        if span.label == "client_spawn":
            for ancestor in reversed(stack[:-1]):
                if ancestor.label == "client_start":
                    ancestor.spawn_attempts += 1
                    ancestor.spawn_returns += int(exception is None)
                    break
        if span.label == "client_start":
            span.facts.update(
                spawn_attempts=span.spawn_attempts,
                spawn_returns=span.spawn_returns,
                reused_without_spawn=value is True and span.spawn_attempts == 0,
            )
        if span.label == "client_write":
            for ancestor in reversed(stack[:-1]):
                if ancestor.label == "client_request":
                    ancestor.write_ended, ancestor.write_succeeded = (
                        span.ended,
                        value is True and exception is None,
                    )
                    break
        if span.label == "client_request":
            span.facts["write_succeeded"] = span.write_succeeded
            remainder = self.interval(span.write_ended, span.ended) if span.write_succeeded else None
            span.facts[
                "post_write_success_ns" if type(value) is bytes and exception is None else "post_write_failure_ns"
            ] = remainder
        if (
            span.label == "launcher_inclusive"
            and exception is None
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and 0 <= value <= 2_100_000
        ):
            span.facts["original_launcher_latency_ns"] = int(value * 1_000_000)

    def wrap(self, original: Callable[..., Any], label: str) -> Callable[..., Any]:
        if label not in LABELS:
            raise ValueError("observer_label")

        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            span, token = None, None
            before = self.tick()
            cpu_before = self.tick(cpu=True)
            try:
                span, token = self.begin(label)
                if span is not None:
                    span.cpu_started = self.tick(cpu=True)
                    span.started = self.tick()
            except BaseException:
                self.invalidate("observer_error")
            value, failure = None, None
            try:
                value = original(*args, **kwargs)
                return value
            except BaseException as error:
                failure = error
                raise
            finally:
                try:
                    if span is not None:
                        self.finish(span, value, failure)
                        after = self.tick()
                        cpu_after = self.tick(cpu=True)
                        span.recording_ns = (self.interval(before, span.started) or 0) + (
                            self.interval(span.ended, after) or 0
                        )
                        first = self.interval(cpu_before, span.cpu_started)
                        last = self.interval(span.cpu_ended, cpu_after)
                        span.recording_cpu_ns = first + last if first is not None and last is not None else None
                except BaseException:
                    self.invalidate("observer_error")
                finally:
                    if token is not None:
                        try:
                            self.stack.reset(token)
                        except BaseException:
                            self.invalidate("observer_error")

        for name in ("cache_clear", "cache_info", "cache_parameters"):
            if hasattr(original, name):
                setattr(observed, name, getattr(original, name))
        return observed

    @contextmanager
    def window(self, name: str) -> Iterator[None]:
        if name not in PHASES:
            raise ValueError("observer_phase")
        previous, previous_owner = self.phase, self.phase_owner
        owner = threading.current_thread()
        if previous_owner is not None and previous_owner is not owner:
            self.invalidate("phase_overlap")
        self.phase, self.phase_owner = name, owner
        try:
            yield
        finally:
            self.phase, self.phase_owner = previous, previous_owner

    def phase_wrapper(self, original: Callable[..., Any], name: str) -> Callable[..., Any]:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            with self.window(name):
                return original(*args, **kwargs)

        return observed

    def report(self) -> dict[str, Any]:
        groups: dict[tuple[str, str, str, str], list[Span]] = {}
        for span in self.records:
            if span.ended is None:
                self.invalidate("unbalanced")
            key = (
                span.phase,
                span.domain,
                span.label,
                span.parent.label if span.parent else "root",
            )
            groups.setdefault(key, []).append(span)
        rows = []
        for (phase, domain, label, parent), values in sorted(groups.items()):
            elapsed = [n for s in values if (n := self.interval(s.started, s.ended)) is not None]
            cpu = [n for s in values if (n := self.interval(s.cpu_started, s.cpu_ended)) is not None]
            facts: dict[str, Any] = {}
            for key in sorted({key for s in values for key in s.facts}):
                selected = [s.facts[key] for s in values if key in s.facts]
                integers = [v for v in selected if type(v) is int]
                facts[key] = {
                    "available": sum(v is not None for v in selected),
                    "true": sum(v is True for v in selected),
                    "false": sum(v is False for v in selected),
                    "integer_count": len(integers),
                    "integer_sum": sum(integers),
                    "integer_min": min(integers) if integers else None,
                    "integer_max": max(integers) if integers else None,
                }
            rows.append(
                {
                    "phase_window": phase,
                    "domain": domain,
                    "label": label,
                    "same_stack_parent": parent,
                    "calls": len(values),
                    "outcomes": dict(Counter(s.outcome for s in values)),
                    "exceptions": dict(Counter(s.exception for s in values if s.exception)),
                    "inclusive_elapsed": distribution(elapsed),
                    "same_thread_cpu": distribution(cpu),
                    "recording_bracket": distribution([s.recording_ns for s in values]),
                    "recording_cpu_bracket": distribution(
                        [s.recording_cpu_ns for s in values if s.recording_cpu_ns is not None]
                    ),
                    "facts": facts,
                }
            )
        result = {
            "schema": "hol-guard.macos-attribution-observer.v1",
            "complete": not self.issues,
            "records": len(self.records),
            "thread_slots": len(self.threads),
            "issues": dict(self.issues),
            "raw_events_exported": False,
            "cross_domain_joins": False,
            "inclusive_spans_are_additive": False,
            "phase_window_is_request_identity": False,
            "clocks": self.clock_metadata,
            "observer_rss_separable_from_benchmark": False,
            "rows": rows,
        }
        if len(encoded(result)) > MAX_OUTPUT_BYTES:
            self.invalidate("output_limit")
            result.update(complete=False, issues=dict(self.issues), rows=[])
        return result


class Patches:
    """Restore original descriptors and absent instance overrides in reverse order."""

    def __init__(self) -> None:
        self.saved: list[tuple[Any, str, Any]] = []

    def value(self, owner: Any, name: str, value: Any) -> None:
        old = vars(owner).get(name, _ABSENT)
        setattr(owner, name, value)
        self.saved.append((owner, name, old))

    def wrap(
        self,
        owner: Any,
        name: str,
        factory: Callable[[Callable[..., Any]], Callable[..., Any]],
    ) -> None:
        descriptor = inspect.getattr_static(owner, name)
        if isinstance(descriptor, staticmethod):
            replacement = staticmethod(factory(descriptor.__func__))
        elif isinstance(descriptor, classmethod):
            replacement = classmethod(factory(descriptor.__func__))
        else:
            replacement = factory(getattr(owner, name))
        self.value(owner, name, replacement)

    def close(self) -> None:
        for owner, name, value in reversed(self.saved):
            if value is _ABSENT:
                delattr(owner, name)
            else:
                setattr(owner, name, value)
        self.saved.clear()

    def __enter__(self) -> Patches:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class SubprocessFacade:
    """Only one importing module receives this facade; the global module is intact."""

    def __init__(self, original: Any, create: Callable[..., Any]) -> None:
        self._original = original
        self.Popen = create

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)
