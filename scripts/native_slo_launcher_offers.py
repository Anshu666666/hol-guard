"""Bounded forwarding ledger around the unchanged installed launcher producer.

The ledger executes outside the original per-launch timer, but its locks and
bookkeeping affect scheduling and whole-worker CPU. No cost is subtracted.
It neither issues a request nor waits for a failed producer's executor tail.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

ROUTES = (
    "claude-code.PreToolUse",
    "claude-code.PostToolUse",
    "codex.PreToolUse",
    "codex.PostToolUse",
)
PHASES = ("preflight", "cold", "serial", "c16")
_T = TypeVar("_T")
_MAX_ROWS = 800_100


def population(plan: Mapping[str, int]) -> dict[str, int]:
    values = [plan.get(key) for key in ("priority_per_run", "cold_per_run")]
    if any(type(value) is not int or not 1 <= value <= 100_000 for value in values):
        raise ValueError("launcher_population_invalid")
    priority, cold = values
    assert isinstance(priority, int) and isinstance(cold, int)
    return {"preflight": 2, "cold": cold, "serial": priority, "c16": ((priority + 15) // 16) * 16}


class LauncherOffers:
    """One original producer invocation; recorder faults preserve its result."""

    def __init__(self, plan: Mapping[str, int]) -> None:
        self.counts = population(plan)
        self.maximum = 4 * sum(self.counts.values())
        if self.maximum > _MAX_ROWS:
            raise ValueError("launcher_offer_bound")
        self._lock = threading.Lock()
        self._rows: list[dict[str, Any]] = []
        self._faults: dict[str, int] = {}
        self._active = 0
        self._closed = False
        self._used = False
        self.report: dict[str, Any] = {}

    def _fault(self, name: str) -> None:
        self._faults[name] = min(1000, self._faults.get(name, 0) + 1)

    def _entry(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            if self._closed:
                return None
            self._active += 1
            if len(self._rows) >= self.maximum:
                self._fault("row_bound")
                return None
            try:
                launcher = args[1]
                route = f"{launcher.harness}.{launcher.event}"
                sample = kwargs["sample"]
                case = kwargs.get("case", "benign")
                if route not in ROUTES or type(sample) is not int or case not in {"benign", "block"}:
                    raise ValueError
                if sample == -1:
                    phase = "preflight"
                elif 0 <= sample < self.counts["serial"] and case == "benign":
                    phase = "serial"
                elif 1_000_000 <= sample < 1_000_000 + self.counts["c16"] and case == "benign":
                    phase = "c16"
                elif 2_000_000 <= sample < 2_000_000 + self.counts["cold"] and case == "benign":
                    phase = "cold"
                else:
                    raise ValueError
                row = {
                    "index": len(self._rows),
                    "route": route,
                    "phase": phase,
                    "sample": sample,
                    "case": case,
                    "outcome": "inflight",
                    "latency_ms": None,
                }
                self._rows.append(row)
                return row
            except Exception:
                self._fault("entry_projection")
                return None

    def _exit(self, row: dict[str, Any] | None, result: Any, returned: bool) -> None:
        with self._lock:
            if self._closed:
                return
            self._active -= 1
            if row is None:
                return
            row["outcome"] = "returned" if returned else "raised"
            if returned:
                try:
                    value = result.latency_ms
                    if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
                        raise ValueError
                    row["latency_ms"] = value
                except Exception:
                    self._fault("return_projection")

    def run(self, module: Any, original: Callable[..., Any], operation: Callable[[], _T]) -> _T:
        if self._used or module.observe_priority_launcher is not original:
            raise ValueError("launcher_offer_installation")
        self._used = True
        started = time.monotonic_ns()
        returned = False

        def forwarding(*args: Any, **kwargs: Any) -> Any:
            row = None
            try:
                row = self._entry(args, kwargs)
            except BaseException:
                with self._lock:
                    self._fault("entry_recorder")
            result = None
            complete = False
            try:
                result = original(*args, **kwargs)
                complete = True
                return result
            finally:
                try:
                    self._exit(row, result, complete)
                except BaseException:
                    with self._lock:
                        self._fault("exit_recorder")

        module.observe_priority_launcher = forwarding
        try:
            result = operation()
            returned = True
            return result
        finally:
            try:
                self._freeze(module, original, forwarding, started, returned)
            except BaseException:
                # A failed projection cannot replace the original return or
                # raised object. The deliberately incomplete packet is refused.
                self._closed = True
                try:
                    if module.observe_priority_launcher is forwarding:
                        module.observe_priority_launcher = original
                except BaseException:
                    pass
                self.report = {
                    "schema": "hol-guard.launcher-offers.v1",
                    "complete": False,
                    "faults": {"freeze_recorder": 1},
                }

    def _freeze(
        self, module: Any, original: Callable[..., Any], forwarding: Callable[..., Any], started: int, returned: bool
    ) -> None:
        # Freeze under the same lock used by callbacks. Late callbacks may
        # still forward original work; they cannot mutate this packet.
        with self._lock:
            if module.observe_priority_launcher is forwarding:
                module.observe_priority_launcher = original
            else:
                self._fault("restoration_conflict")
            self._closed = True
            self.report = {
                "schema": "hol-guard.launcher-offers.v1",
                "counts_per_route": dict(self.counts),
                "maximum": self.maximum,
                "producer_returned": returned,
                "start_monotonic_ns": started,
                "stop_monotonic_ns": time.monotonic_ns(),
                "active_at_freeze": self._active,
                "complete": returned and self._active == 0 and not self._faults,
                "faults": dict(self._faults),
                "rows": [dict(row) for row in self._rows],
                "overhead": "outside_original_launch_timers_inside_worker_CPU_and_scheduling",
            }
