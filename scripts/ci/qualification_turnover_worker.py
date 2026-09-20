"""Finite c16 process-turnover viability control; no installed hook workload.

Exactly sixteen waves of sixteen owned children allocate two MiB and sleep for
250 ms. The unchanged production-resource sampler runs at its default100 ms.
No missing sample, metric refusal or cleanup failure is hidden or retried.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from scripts.native_slo_lifetime_cpu import ProtectedCgroupCpu, cpu_delta
from scripts.native_slo_resources import ResourceSampler

WAVES = 16
WIDTH = 16
CHILDREN = WAVES * WIDTH
WORK_SECONDS = 20.0
CLEANUP_SECONDS = 3.0
METRICS = ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")
PROGRAM = "import time;memory=bytearray(2*1024*1024);memory[::4096]=b'x'*512;time.sleep(0.25)"


def run_children(facts: dict[str, Any]) -> None:
    """Every successful spawn immediately enters the independent cleanup scope."""
    owned: list[subprocess.Popen[bytes]] = []
    reaped: set[int] = set()
    deadline = time.monotonic() + WORK_SECONDS
    error: BaseException | None = None
    traceback = None
    try:
        for _wave in range(WAVES):
            wave = []
            for _slot in range(WIDTH):
                if time.monotonic() >= deadline:
                    raise TimeoutError("finite_turnover_work_deadline")
                child = subprocess.Popen(
                    [sys.executable, "-I", "-c", PROGRAM],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                owned.append(child)
                wave.append(child)
                facts["offered"] += 1
            for child in wave:
                code = child.wait(timeout=max(0.0, deadline - time.monotonic()))
                reaped.add(id(child))
                facts["returned"] += 1
                facts["exit_codes"].append(code)
                if code != 0:
                    raise RuntimeError("finite_turnover_child_exit")
            facts["waves_completed"] += 1
    except BaseException as caught:
        error, traceback = caught, caught.__traceback__
    finally:
        # First request termination for every still-live owned child; a single
        # failure must not skip another child's kill or wait attempt.
        clean = True
        for child in owned:
            if id(child) in reaped:
                continue
            try:
                child.kill()
            except ProcessLookupError:
                pass
            except BaseException:
                clean = False
        cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
        for child in owned:
            if id(child) in reaped:
                continue
            try:
                child.wait(timeout=max(0.0, cleanup_deadline - time.monotonic()))
                reaped.add(id(child))
            except BaseException:
                clean = False
        facts["locally_reaped"] = len(reaped)
        facts["local_cleanup_complete"] = clean and len(reaped) == len(owned)
    if error is not None:
        raise error.with_traceback(traceback)
    if facts["local_cleanup_complete"] is not True:
        raise RuntimeError("finite_turnover_cleanup_failed")


def _singleton(reader: ProtectedCgroupCpu) -> bool:
    # This is finite-control retirement evidence, never orphan waitpid proof.
    deadline = time.monotonic() + 2.0
    for _ in range(201):
        if reader.member_pids() == (os.getpid(),):
            return True
        if time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    return False


def run(group: Path) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.finite-turnover-resource-control.v1",
        "admitted": False,
        "admission_refusal": None,
        "passed": False,
        "original_workload_executed": False,
        "facts": {
            "planned_children": CHILDREN,
            "planned_waves": WAVES,
            "concurrency": WIDTH,
            "sampler_interval_seconds": 0.1,
            "offered": 0,
            "returned": 0,
            "exit_codes": [],
            "waves_completed": 0,
            "locally_reaped": 0,
            "local_cleanup_complete": False,
            "only_worker_live_after": False,
            "sampled_resources": None,
            "lifetime_cpu": None,
            "failure_stage": None,
        },
    }
    reader = None
    sampler = None
    entered = False
    facts = report["facts"]
    stage = "admission"
    try:
        reader = ProtectedCgroupCpu(group)
        report["admitted"] = True
        stage = "sampler_start"
        sampler = ResourceSampler(protected_members=reader.member_pids)
        before = reader.snapshot()
        sampler.__enter__()
        entered = True
        try:
            stage = "owned_children"
            run_children(facts)
        finally:
            if entered:
                entered = False
                sampler.__exit__(None, None, None)
        stage = "final_snapshot"
        facts["lifetime_cpu"] = cpu_delta(before, reader.snapshot())
        facts["only_worker_live_after"] = _singleton(reader)
    except BaseException:
        if report["admitted"] is False:
            report["admission_refusal"] = "admission_unavailable"
        else:
            facts["failure_stage"] = stage
    finally:
        if entered and sampler is not None:
            try:
                sampler.__exit__(None, None, None)
            except BaseException:
                facts["failure_stage"] = facts["failure_stage"] or "sampler_stop"
        if sampler is not None:
            try:
                facts["sampled_resources"] = sampler.report(attempted=facts["offered"])
            except BaseException:
                facts["failure_stage"] = facts["failure_stage"] or "sampler_report"
        if reader is not None:
            try:
                reader.close()
            except BaseException:
                facts["failure_stage"] = facts["failure_stage"] or "boundary_close"
    from scripts.ci.qualification_turnover_contract import measurement_complete

    report["passed"] = report["admitted"] and measurement_complete(facts)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", type=Path, required=True)
    report = run(parser.parse_args().group)
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
