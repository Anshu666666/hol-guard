"""Five finite real-process controls inside the admitted kernel boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scripts.native_slo_launcher_resources import LauncherResourceObservation
from scripts.native_slo_lifetime_cpu import LifetimeCpuUnavailableError, ProtectedCgroupCpu, cpu_delta

_LEAF = "import time; end=time.process_time()+0.08\nwhile time.process_time()<end: pass\nprint('leaf-done',flush=True)"


def _child(program: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", "-c", program], capture_output=True, check=True, timeout=8.0, start_new_session=True
    )


def exited_child_and_grandchild(reader: ProtectedCgroupCpu, _group: Path) -> dict[str, Any]:
    before = reader.snapshot()
    program = (
        "import subprocess,sys\n"
        f"subprocess.run([sys.executable,'-I','-c',{_LEAF!r}],check=True,timeout=5,start_new_session=True)\n"
        "print('child-done',flush=True)\n"
    )
    completed = _child(program)
    assert completed.stdout == b"leaf-done\nchild-done\n" and completed.stderr == b""
    after = reader.snapshot()
    delta = cpu_delta(before, after)
    assert delta["usage_seconds"] >= 0.06
    return {
        "before": asdict(before),
        "after": asdict(after),
        "delta": delta,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
    }


def orphan_new_session(reader: ProtectedCgroupCpu, _group: Path) -> dict[str, Any]:
    before = reader.snapshot()
    # The intermediate exits without waiting. The grandchild inherits the pipe
    # and its final EOF proves its finite program exited; no waitpid by worker.
    program = (
        "import os,subprocess,sys\n"
        f"subprocess.Popen([sys.executable,'-I','-c',{_LEAF!r}],start_new_session=True)\n"
        "os._exit(0)\n"
    )
    completed = _child(program)
    assert completed.stdout == b"leaf-done\n" and completed.stderr == b""
    after = reader.snapshot()
    delta = cpu_delta(before, after)
    assert delta["usage_seconds"] >= 0.06
    return {
        "before": asdict(before),
        "after": asdict(after),
        "delta": delta,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
    }


def migration_refusal(reader: ProtectedCgroupCpu, group: Path) -> dict[str, Any]:
    before = reader.snapshot()
    program = (
        "import errno,json,os\n"
        "result=False\n"
        "try:\n"
        f" fd=os.open({str(group.parent / 'cgroup.procs')!r},os.O_WRONLY)\n"
        "except OSError as error:\n"
        " result=error.errno in {errno.EACCES,errno.EPERM,errno.EROFS}\n"
        "else:\n"
        " os.close(fd)\n"
        "print(json.dumps({'open_refused':result,'same_uid':len(set(os.getresuid()))==1 and os.geteuid()!=0}))\n"
    )
    completed = _child(program)
    assert json.loads(completed.stdout) == {"open_refused": True, "same_uid": True} and not completed.stderr
    cpu_delta(before, reader.snapshot())
    return {"open_refused": True, "membership_stable": True}


def lost_handle(reader: ProtectedCgroupCpu, _group: Path) -> dict[str, Any]:
    reader.close()
    result = object()
    observer = LauncherResourceObservation(lifetime_cpu=reader)
    assert observer.run(lambda: result) is result
    assert observer.report["faults"].get("lifetime_start") == 1
    assert observer.report["lifetime_cpu_complete"] is False
    assert observer.report["observation_complete"] is False
    return {"original_return_identity": True, "lifetime_cpu_complete": False, "fault_count": 1}


def partial_tail(reader: ProtectedCgroupCpu, _group: Path) -> dict[str, Any]:
    child: subprocess.Popen[bytes] | None = None
    original = RuntimeError("finite original failure")
    observer = LauncherResourceObservation(lifetime_cpu=reader)

    def operation() -> None:
        nonlocal child
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", "import sys;print('ready',flush=True);sys.stdin.read(1)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            start_new_session=True,
        )
        assert child.stdout is not None and child.stdout.readline() == b"ready\n"
        raise original

    try:
        try:
            observer.run(operation)
        except RuntimeError as error:
            assert error is original
        else:
            raise AssertionError("original exception was replaced")
        assert child is not None and child.poll() is None
        assert observer.report["original_calls"] == 1
        assert observer.report["final_tail_complete"] is False
        assert observer.report["lifetime_cpu_complete"] is False
        assert observer.report["observation_complete"] is False
    finally:
        if child is not None:
            child.communicate(b"x", timeout=5.0)
            assert child.returncode == 0
    return {
        "exception_identity": True,
        "child_still_active_at_snapshot": True,
        "lifetime_cpu_complete": False,
        "cleanup_exit": 0,
    }


def run(group: Path) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema": "hol-guard.kernel-cpu-finite-controls.v1",
        "admitted": False,
        "controls": controls,
        "passed": False,
    }
    reader: ProtectedCgroupCpu | None = None
    try:
        # This must precede every child/grandchild and sampler thread.
        reader = ProtectedCgroupCpu(group)
        report["admitted"] = True
        operations: tuple[Callable[[ProtectedCgroupCpu, Path], dict[str, Any]], ...] = (
            exited_child_and_grandchild,
            orphan_new_session,
            migration_refusal,
            partial_tail,
            lost_handle,
        )
        for operation in operations:
            error_kind = None
            facts: dict[str, Any] = {}
            try:
                facts = operation(reader, group)
            except BaseException as error:
                error_kind = (
                    "accounting"
                    if isinstance(error, LifetimeCpuUnavailableError)
                    else "assertion"
                    if isinstance(error, AssertionError)
                    else "os"
                    if isinstance(error, OSError)
                    else "other"
                )
            controls.append(
                {"name": operation.__name__, "passed": error_kind is None, "error": error_kind, "facts": facts}
            )
        report["passed"] = all(row["passed"] for row in controls)
    except BaseException:
        report["passed"] = False
    finally:
        if reader is not None:
            reader.close()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.group)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
