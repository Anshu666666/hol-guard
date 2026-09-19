#!/usr/bin/env python3
"""Measure the original validator without changing its result or acceptance gates."""

from __future__ import annotations

import json
import statistics
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import CodeType, FrameType, ModuleType
from typing import Any

_LIMIT = 1_000
_PHASES = ("path", "trust", "digest_init", "stream", "read_loop", "digest_update", "result", "other")
_CLOCKS = ("wall", "thread_cpu", "process_cpu")


def _clock() -> tuple[int, int, int]:
    return time.perf_counter_ns(), time.thread_time_ns(), time.process_time_ns()


def _phase(offset: int) -> str:
    if offset in {2, 3, 13, 14}:
        return "path"
    if 4 <= offset <= 12 or offset in {15, 16}:
        return "trust"
    return {17: "digest_init", 18: "stream", 19: "read_loop", 20: "digest_update"}.get(
        offset, "result" if 21 <= offset <= 28 else "other"
    )


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    if not ordered:
        return {}
    return {
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "max_ms": round(ordered[-1], 3),
    }


class ValidatorPhaseObserver:
    def __init__(self, *, limit: int = _LIMIT) -> None:
        if not 1 <= limit <= _LIMIT:
            raise ValueError("invalid diagnostic limit")
        self._limit = limit
        self._seen = 0
        self._rows: list[dict[str, Any]] = []

    def call(self, original: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        code = getattr(original, "__code__", None)
        previous = sys.gettrace()
        row: dict[str, Any] = {
            "detail": "unavailable",
            "raised": False,
            "entries": 0,
            "segments": 0,
            "phases": {phase: {clock: 0 for clock in _CLOCKS} for phase in _PHASES},
        }
        last: tuple[int, int, int] | None = None
        active = "other"
        installed = False
        detail_failed = False

        def local(frame: FrameType, event: str, _arg: Any) -> Any:
            nonlocal last, active, detail_failed
            if frame.f_code is not code:
                return None
            if event not in {"line", "return"}:
                return local
            try:
                now = _clock()
                if last is not None:
                    for index, clock in enumerate(_CLOCKS):
                        row["phases"][active][clock] += max(0, now[index] - last[index])
                    row["segments"] += 1
                if event == "return":
                    last = None
                    return None
                active = _phase(frame.f_lineno - code.co_firstlineno)
                last = now
            except Exception:
                detail_failed = True
                last = None
                return None
            return local

        def trace(frame: FrameType, event: str, _arg: Any) -> Any:
            if event == "call" and frame.f_code is code:
                row["entries"] += 1
                return local
            return None

        started = _clock()
        try:
            if previous is not None:
                row["detail"] = "existing-trace"
            elif not isinstance(code, CodeType) or code.co_name != "_validate_binary" or code.co_firstlineno != 155:
                row["detail"] = "different-code"
            else:
                try:
                    sys.settrace(trace)
                    installed = True
                    row["detail"] = "traced"
                except Exception:
                    row["detail"] = "trace-unavailable"
            return original(*args, **kwargs)
        except BaseException:
            row["raised"] = True
            raise
        finally:
            if installed:
                sys.settrace(previous)
            finished = _clock()
            for index, clock in enumerate(_CLOCKS):
                row[clock] = max(0, finished[index] - started[index])
            row["unassigned_wait"] = max(0, row["wall"] - row["thread_cpu"])
            if detail_failed:
                row["detail"] = "trace-failed"
            self._seen += 1
            if len(self._rows) < self._limit:
                self._rows.append(row)

    @contextmanager
    def install(self, native: ModuleType) -> Iterator[None]:
        original = native._validate_binary
        owner_thread = threading.get_ident()

        def measured(*args: Any, **kwargs: Any) -> Any:
            if threading.get_ident() != owner_thread:
                return original(*args, **kwargs)
            return self.call(original, *args, **kwargs)

        native._validate_binary = measured
        try:
            yield
        finally:
            native._validate_binary = original

    def report(self) -> dict[str, Any]:
        def numeric(row: dict[str, Any]) -> dict[str, Any]:
            return {
                "detail": row["detail"],
                "raised": row["raised"],
                "entries": row["entries"],
                "segments": row["segments"],
                **{clock + "_ms": round(row[clock] / 1_000_000, 3) for clock in (*_CLOCKS, "unassigned_wait")},
                "phases": {
                    phase: {clock + "_ms": round(row["phases"][phase][clock] / 1_000_000, 3) for clock in _CLOCKS}
                    for phase in _PHASES
                },
            }

        ordered = sorted(self._rows, key=lambda row: row["wall"])
        sample = numeric(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]) if ordered else {}
        return {
            "schema": "hol-guard-native-validation-phases.v1",
            "samples_seen": self._seen,
            "samples_retained": len(self._rows),
            "sample_limit": self._limit,
            "complete": 0 < self._seen <= self._limit
            and all(row["detail"] == "traced" and row["entries"] == 1 for row in self._rows),
            "detail_counts": {
                key: sum(row["detail"] == key for row in self._rows)
                for key in ("traced", "existing-trace", "different-code", "trace-unavailable", "trace-failed")
            },
            "timings": {
                clock: _summary([row[clock] / 1_000_000 for row in self._rows])
                for clock in (*_CLOCKS, "unassigned_wait")
            },
            "phases": {
                phase: {
                    clock: _summary([row["phases"][phase][clock] / 1_000_000 for row in self._rows])
                    for clock in _CLOCKS
                }
                for phase in _PHASES
            },
            "validation_wall_p95_sample": sample,
            "measurement_overhead_included": True,
            "acceptance_adjusted": False,
            "waiting_attribution": "unassigned",
            "process_cpu_scope": "all-process-threads",
            "phase_scope": "original-validator-line-intervals-including-trace-and-loop-overhead",
        }


def main() -> int:
    import bench_guard_native_release_gate as benchmark
    from bench_guard_native_phase_diagnostic import ProductionPhaseObserver

    from codex_plugin_scanner.guard import native_runtime

    phases = ProductionPhaseObserver()
    detail = ValidatorPhaseObserver()
    try:
        with phases.install(benchmark, native_runtime):
            original = benchmark._bench_native_warm_production

            def production(*args: Any, **kwargs: Any) -> Any:
                with detail.install(native_runtime):
                    return original(*args, **kwargs)

            benchmark._bench_native_warm_production = production
            try:
                return benchmark.main()
            finally:
                benchmark._bench_native_warm_production = original
    finally:
        print(json.dumps(phases.report(), sort_keys=True))
        print(json.dumps(detail.report(), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
