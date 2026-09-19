#!/usr/bin/env python3
"""Attribute one unchanged release-gate run using aggregate synthetic timings.

This diagnostic does not adjust the measured samples or any acceptance gate.
Its wrappers add measurement overhead to the original production calls.
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import ModuleType
from typing import Any

_MAX_SAMPLES = 1_000


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    if not ordered:
        return {}
    return {
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "p99_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))], 3),
        "max_ms": round(ordered[-1], 3),
    }


class ProductionPhaseObserver:
    """Temporarily time the actual adapter dependencies during production samples."""

    def __init__(self, *, clock: Callable[[], float] = time.perf_counter) -> None:
        self._clock = clock
        self._rows: list[dict[str, Any]] = []
        self._seen = 0
        self._requested = 0
        self._completed = False

    @contextmanager
    def install(self, benchmark: ModuleType, native: ModuleType) -> Iterator[None]:
        original_production = benchmark._bench_native_warm_production

        def production(*args: Any, **kwargs: Any) -> Any:
            iterations = kwargs.get("iterations")
            self._requested = iterations if type(iterations) is int and iterations > 0 else 0
            with self._measure_adapter(benchmark, native):
                result = original_production(*args, **kwargs)
            self._completed = True
            return result

        benchmark._bench_native_warm_production = production
        try:
            yield
        finally:
            benchmark._bench_native_warm_production = original_production

    @contextmanager
    def _measure_adapter(self, benchmark: ModuleType, native: ModuleType) -> Iterator[None]:
        original_review = benchmark.review_post_tool_native
        original_status = native.native_runtime_status
        original_request = native.native_resident_client_request
        current: dict[str, Any] | None = None

        def phase(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
            def measured(*args: Any, **kwargs: Any) -> Any:
                started = self._clock()
                try:
                    return original(*args, **kwargs)
                finally:
                    elapsed = (self._clock() - started) * 1_000.0
                    if current is not None:
                        current[name + "_ms"] += elapsed
                        current[name + "_calls"] += 1

            return measured

        def review(*args: Any, **kwargs: Any) -> Any:
            nonlocal current
            row: dict[str, Any] = {
                "status_ms": 0.0,
                "request_ms": 0.0,
                "status_calls": 0,
                "request_calls": 0,
                "raised": False,
            }
            current = row
            started = self._clock()
            try:
                return original_review(*args, **kwargs)
            except BaseException:
                row["raised"] = True
                raise
            finally:
                row["adapter_ms"] = (self._clock() - started) * 1_000.0
                row["remaining_ms"] = max(
                    0.0, row["adapter_ms"] - row["status_ms"] - row["request_ms"]
                )
                self._seen += 1
                if len(self._rows) < _MAX_SAMPLES:
                    self._rows.append(row)
                current = None

        benchmark.review_post_tool_native = review
        native.native_runtime_status = phase("status", original_status)
        native.native_resident_client_request = phase("request", original_request)
        try:
            yield
        finally:
            benchmark.review_post_tool_native = original_review
            native.native_runtime_status = original_status
            native.native_resident_client_request = original_request

    def report(self) -> dict[str, Any]:
        complete = (
            self._completed
            and self._seen == self._requested
            and 0 < self._seen <= _MAX_SAMPLES
            and all(
                not row["raised"] and row["status_calls"] == 1 and row["request_calls"] == 1
                for row in self._rows
            )
        )
        p95_sample: dict[str, Any] = {}
        if self._rows:
            ordered = sorted(self._rows, key=lambda row: row["adapter_ms"])
            row = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
            p95_sample = {
                key: round(value, 3) if type(value) is float else value
                for key, value in row.items()
            }
        return {
            "schema": "hol-guard-native-production-phases.v1",
            "scope": "original-production-warm-calls",
            "complete": complete,
            "iterations_requested": self._requested,
            "samples_seen": self._seen,
            "samples_retained": len(self._rows),
            "sample_limit": _MAX_SAMPLES,
            "production_completed": self._completed,
            "measurement_overhead_included": True,
            "acceptance_adjusted": False,
            "timings": {
                name: _summary([row[name + "_ms"] for row in self._rows])
                for name in ("adapter", "status", "request", "remaining")
            },
            "adapter_p95_sample": p95_sample,
        }


def main() -> int:
    # Direct execution uses the original benchmark's parser, workload, results,
    # JSON artifact, and exit status. Only its production sampling call is wrapped.
    import bench_guard_native_release_gate as benchmark

    from codex_plugin_scanner.guard import native_runtime

    observer = ProductionPhaseObserver()
    try:
        with observer.install(benchmark, native_runtime):
            return benchmark.main()
    finally:
        print(json.dumps(observer.report(), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
