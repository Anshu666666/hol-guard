"""Opt-in fixed-code spans on the actual selected publisher thread only."""

from __future__ import annotations

import math
import sys
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from types import CodeType, FrameType
from typing import Any

_MAX_ACTIVE = 64
_MAX_CALLS = 4096
_LIMIT = 999_999
_LABELS = frozenset(
    {
        "publisher_start",
        "publication",
        "publication_context",
        "command_preparation",
        "configuration",
        "metadata_load",
        "metadata_validate",
        "control_projection",
        "control_authority_key",
        "source_capture",
        "store_connect",
        "store_permissions",
        "integrity_secret",
        "runtime_status",
        "runtime_binary_validation",
        "runtime_capabilities",
        "resident_transport",
        "stream_start",
        "stream_request",
    }
)


@dataclass
class _Span:
    frame_id: int
    label: str
    wall: float
    cpu: float
    nested_wall: float = 0.0
    nested_cpu: float = 0.0


class SelectedThreadSpans:
    """Retain only allowlisted labels, bounded counts and observed clock deltas.

    A trace hook can coexist with cProfile on both supported interpreters.
    Unselected frames are not traced; selected frames disable line/opcode events.
    Wall spans include scheduling, blocking and instrumentation. Neither clock
    establishes an optimization cause or an uninstrumented readiness result.
    """

    def __init__(self, codes: Mapping[int, tuple[CodeType, str]]) -> None:
        self._codes = {
            key: (code, label)
            for key, (code, label) in codes.items()
            if isinstance(code, CodeType) and key == id(code) and type(label) is str and label in _LABELS
        }
        self._owner: int | None = None
        self._callback = self._trace
        self._active: list[_Span] = []
        self._rows: dict[str, dict[str, Any]] = {}
        self._calls = 0
        self._origin = 0.0
        self._available = False
        self._installed = False
        self._closed = False

    @staticmethod
    def _clock() -> tuple[float, float]:
        wall, cpu = time.perf_counter(), time.thread_time()
        if not all(type(value) in {int, float} and math.isfinite(value) for value in (wall, cpu)):
            raise ValueError("span_clock_unavailable")
        return wall, cpu

    def start(self) -> None:
        if self._owner is not None or self._closed:
            return
        self._owner = threading.get_ident()
        try:
            if sys.gettrace() is not None:
                return
            self._origin, _ = self._clock()
            self._available = True
            sys.settrace(self._callback)
            self._installed = sys.gettrace() is self._callback
            self._available = self._installed
        except BaseException:
            self._available = False
            with suppress(BaseException):
                if sys.gettrace() is self._callback:
                    sys.settrace(None)

    def _trace(self, frame: FrameType, event: str, _argument: object) -> Any:
        # Never inspect event arguments, locals, filenames or function names.
        if not self._available or self._owner != threading.get_ident():
            return None
        admitted = self._codes.get(id(frame.f_code))
        if admitted is None or frame.f_code is not admitted[0]:
            return None
        try:
            if event == "call":
                if len(self._active) >= _MAX_ACTIVE or self._calls >= _MAX_CALLS:
                    raise ValueError("span_limit")
                wall, cpu = self._clock()
                if not math.isfinite(wall - self._origin) or wall < self._origin:
                    raise ValueError("span_clock_unavailable")
                frame.f_trace_lines = False
                frame.f_trace_opcodes = False
                self._calls += 1
                self._active.append(_Span(id(frame), admitted[1], wall, cpu))
            elif event == "return":
                if not self._active or self._active[-1].frame_id != id(frame):
                    raise ValueError("span_pair_unavailable")
                wall, cpu = self._clock()
                span = self._active.pop()
                elapsed_wall, elapsed_cpu = wall - span.wall, cpu - span.cpu
                if (
                    not all(math.isfinite(value) for value in (elapsed_wall, elapsed_cpu, wall - self._origin))
                    or elapsed_wall < span.nested_wall
                    or elapsed_cpu < span.nested_cpu
                ):
                    raise ValueError("span_clock_unavailable")
                row = self._rows.setdefault(
                    span.label,
                    {
                        "label": span.label,
                        "calls": 0,
                        "inclusive_wall_ms": 0.0,
                        "wall_excluding_nested_selected_ms": 0.0,
                        "inclusive_thread_cpu_ms": 0.0,
                        "thread_cpu_excluding_nested_selected_ms": 0.0,
                        "first_start_ms": (span.wall - self._origin) * 1000,
                        "last_end_ms": 0.0,
                    },
                )
                row["calls"] += 1
                row["inclusive_wall_ms"] += elapsed_wall * 1000
                row["wall_excluding_nested_selected_ms"] += (elapsed_wall - span.nested_wall) * 1000
                row["inclusive_thread_cpu_ms"] += elapsed_cpu * 1000
                row["thread_cpu_excluding_nested_selected_ms"] += (elapsed_cpu - span.nested_cpu) * 1000
                row["first_start_ms"] = min(row["first_start_ms"], (span.wall - self._origin) * 1000)
                row["last_end_ms"] = max(row["last_end_ms"], (wall - self._origin) * 1000)
                if self._active:
                    self._active[-1].nested_wall += elapsed_wall
                    self._active[-1].nested_cpu += elapsed_cpu
        except BaseException:
            self._available = False
            return None
        return self._callback

    def close(self) -> dict[str, object]:
        try:
            if self._owner != threading.get_ident():
                self._available = False
            elif self._installed:
                if sys.gettrace() is self._callback:
                    sys.settrace(None)
                else:
                    self._available = False
            if self._active:
                self._available = False
        except BaseException:
            self._available = False
        self._closed = True
        rows = []
        if self._available:
            for label in sorted(self._rows):
                row = self._rows[label]
                rows.append(
                    {
                        key: value
                        if key == "label"
                        else min(_LIMIT, value)
                        if key == "calls"
                        else round(min(_LIMIT, value), 3)
                        for key, value in row.items()
                    }
                )
        self._active.clear()
        self._rows.clear()
        return {
            "schema": "guard.selected-thread-readiness-spans.v1",
            "available": self._available,
            "rows": rows,
            "event_scope": "selected_thread_exact_code_calls_and_returns",
            "wall_semantics": "includes_waits_scheduling_and_instrumentation_not_cpu_or_cause",
            "cpu_semantics": "selected_thread_including_instrumentation_not_process_cpu_or_cause",
            "nested_semantics": "subtracts_only_nested_selected_calls_unselected_work_remains",
            "count_semantics": "calls_include_generator_resumptions",
            "window_semantics": "whole_first_call_may_complete_after_readiness_deadline",
            "values_capped_at": _LIMIT,
            "acceptance_claim": False,
        }
