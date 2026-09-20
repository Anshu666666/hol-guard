"""Opt-in resource observation around one unchanged launcher producer call.

The observed tree is the benchmark worker and all of its descendants. It
includes load-generation/control/collector CPU; it is never silently added to
the separate daemon-only sample. Individual launch latency timers are untouched.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any, TypeVar

from scripts.native_slo_lifetime_cpu import CpuSnapshot, ProtectedCgroupCpu, cpu_delta
from scripts.native_slo_resources import ResourceSampler

_T = TypeVar("_T")


class LauncherResourceObservation:
    """Recording failures cannot replace the original return or exception."""

    def __init__(self, *, lifetime_cpu: ProtectedCgroupCpu | None = None) -> None:
        self.lifetime_cpu = lifetime_cpu
        self.report: dict[str, Any] = {
            "schema": "hol-guard.launcher-resource-observation.v1",
            "scope": "benchmark_worker_and_descendants",
            "includes_load_generator_and_collector": True,
            "original_calls": 0,
            "original_returned": False,
            "observation_complete": False,
            "lifetime_cpu_complete": False,
            "full_resource_qualification": False,
            "tail_scope": "original producer returned; no independent descendant-retirement proof",
            "faults": {},
            "clock_scope": (
                "sampling surrounds the whole original launcher producer; original per-launch timers unchanged"
            ),
            "overhead": (
                "snapshot/start/stop work outside per-launch timers; "
                "concurrent sampler competes inside them; no cost subtraction"
            ),
        }

    def _fault(self, stage: str) -> None:
        faults = self.report["faults"]
        faults[stage] = min(1000, faults.get(stage, 0) + 1)

    def run(self, operation: Callable[[], _T]) -> _T:
        if self.report["original_calls"]:
            raise ValueError("resource observation is single use")
        sampler: ResourceSampler | None = None
        before: CpuSnapshot | None = None
        self.report["start_monotonic_ns"] = time.monotonic_ns()
        try:
            if self.lifetime_cpu is not None:
                before = self.lifetime_cpu.snapshot()
        except BaseException:
            self._fault("lifetime_start")
        try:
            sampler = ResourceSampler(pid=os.getpid())
            sampler.__enter__()
        except BaseException:
            self._fault("sampler_start")
        self.report["original_calls"] = 1
        try:
            result = operation()
        except BaseException:
            self.report["original_raised"] = True
            raise
        else:
            self.report["original_returned"] = True
            return result
        finally:
            try:
                self._finish(sampler, before)
            except BaseException:
                # Even an unexpected recorder failure cannot replace the
                # original operation's returned object or raised object.
                self.report["observation_complete"] = False
                self.report["lifetime_cpu_complete"] = False
                self.report["finish_failed"] = True

    def _finish(self, sampler: ResourceSampler | None, before: CpuSnapshot | None) -> None:
        # The outer guard also preserves the original result if a future
        # recorder implementation introduces a new failure in this method.
        try:
            if sampler is not None:
                try:
                    sampler.__exit__(None, None, None)
                except BaseException:
                    self._fault("sampler_stop")
                try:
                    # An operation may have failed part-way through. Do not
                    # invent an attempted-request count or CPU/request value.
                    self.report["sampled_resources"] = sampler.report(attempted=0)
                except BaseException:
                    self._fault("sampler_report")
            if self.lifetime_cpu is not None and before is not None:
                try:
                    after = self.lifetime_cpu.snapshot()
                    self.report["lifetime_cpu"] = {
                        **cpu_delta(before, after),
                        "boundary_sha256": self.lifetime_cpu.identity_sha256,
                        "source": "protected_cgroup_v2_kernel_lifetime",
                        "includes_exited_members": True,
                        "includes_external_services": False,
                    }
                    self.report["lifetime_cpu_complete"] = True
                except BaseException:
                    self._fault("lifetime_stop")
            self.report["stop_monotonic_ns"] = time.monotonic_ns()
            self.report["final_tail_complete"] = self.report["original_returned"]
            self.report["observation_complete"] = not self.report["faults"] and self.report["original_returned"]
            if self.report["faults"] or not self.report["original_returned"]:
                self.report["lifetime_cpu_complete"] = False
            if self.lifetime_cpu is None:
                self.report["lifetime_cpu_unavailable"] = "no_admitted_kernel_lifetime_boundary"
        except BaseException:
            self._fault("recorder_finish")
            self.report["observation_complete"] = False
            self.report["lifetime_cpu_complete"] = False
