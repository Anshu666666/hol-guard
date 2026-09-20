"""Three finite live-member controls; never an installed performance workload."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil

from scripts.ci.qualification_resource_contract import METRICS, NAMES, admit_facts
from scripts.native_slo_lifetime_cpu import LifetimeCpuUnavailableError, ProtectedCgroupCpu
from scripts.native_slo_resources import ResourceSampler

_LEAF = """
import ctypes,os,sys
ready,release,size,denied=map(int,sys.argv[1:])
memory=bytearray(size)
for index in range(0,size,4096): memory[index]=1
if denied:
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(4,0,0,0,0): raise OSError(ctypes.get_errno(),'control_prctl')
os.write(ready,b'ready\\n')
os.close(ready)
assert os.read(release,1)==b'x'
os.close(release)
"""


def _ready(descriptor: int, count: int) -> None:
    body = bytearray()
    deadline = time.monotonic() + 5
    with selectors.DefaultSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        while len(body) < 6 * count:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise AssertionError("control_ready_timeout")
            chunk = os.read(descriptor, 6 * count + 1 - len(body))
            if not chunk:
                raise AssertionError("control_ready_eof")
            body.extend(chunk)
    if body != b"ready\n" * count:
        raise AssertionError("control_ready_frame")


def _retired(reader: ProtectedCgroupCpu) -> None:
    # A finite-control-only live membership witness. This is not waitpid for
    # an orphan and is never introduced into the original product workload.
    deadline = time.monotonic() + 2
    for _ in range(201):
        if reader.member_pids() == (os.getpid(),):
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    raise AssertionError("control_member_still_live")


def _samples(reader: ProtectedCgroupCpu, name: str) -> dict[str, Any]:
    expected = 3 if name == "child_and_grandchild" else 2
    members = reader.member_pids()
    if len(members) != expected:
        raise AssertionError("control_member_count")
    ancestry = {child.pid for child in psutil.Process().children(recursive=True)}
    non_ancestry = len(set(members) - ancestry - {os.getpid()})
    sampler = ResourceSampler(interval_seconds=0.02, protected_members=reader.member_pids)
    with sampler:
        deadline = time.monotonic() + 3
        while sampler.samples < 32 and time.monotonic() < deadline:
            time.sleep(0.025)
    report: dict[str, Any] = sampler.report(attempted=0)
    if report["unavailable_samples"] != 0 or reader.member_pids() != members:
        raise AssertionError("control_inventory_changed")
    denied = name == "denied_private_memory"
    private_errors = report["unavailable_metrics"].get("private_bytes", {})
    if denied and (
        set(private_errors) != {"permission_denied"} or private_errors["permission_denied"] != report["samples"]
    ):
        raise AssertionError("control_private_denial_missing")
    return {
        "member_count": len(members),
        "non_ancestry_members": non_ancestry,
        "samples": report["samples"],
        "private_bytes": report["peak"]["private_bytes"],
        "rss_bytes": report["peak"]["rss_bytes"],
        "metric_minimum_met": {key: report["metric_minimum_met"][key] for key in METRICS},
        "only_worker_live_after": False,
        "orphan_reaped_by_worker": False,
        "denied_private_observed": denied,
        "sampled_peak_only": report["instantaneous_peak_proven"] is False,
    }


def control(reader: ProtectedCgroupCpu, name: str) -> dict[str, Any]:
    ready_read = ready_write = release_read = release_write = -1
    child: subprocess.Popen[bytes] | None = None
    facts: dict[str, Any] = {}
    try:
        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        if name == "child_and_grandchild":
            # The child holds4MiB; its grandchild holds6MiB. Only the grandchild
            # consumes the release byte; the child waits for that actual exit.
            program = (
                "import os,subprocess,sys\n"
                "ready,release=map(int,sys.argv[1:])\n"
                "memory=bytearray(4*1024*1024)\n"
                "for index in range(0,len(memory),4096):memory[index]=1\n"
                "os.write(ready,b'ready\\n')\n"
                f"child=subprocess.Popen([sys.executable,'-I','-c',{_LEAF!r},str(ready),str(release),str(6*1024*1024),'0'],pass_fds=(ready,release))\n"
                "os.close(ready);os.close(release)\n"
                "raise SystemExit(child.wait(timeout=8))\n"
            )
        elif name == "reparented_member":
            program = (
                "import os,subprocess,sys\n"
                "ready,release=map(int,sys.argv[1:])\n"
                f"subprocess.Popen([sys.executable,'-I','-c',{_LEAF!r},str(ready),str(release),str(8*1024*1024),'0'],pass_fds=(ready,release),start_new_session=True)\n"
                "os._exit(0)\n"
            )
        elif name == "denied_private_memory":
            program = _LEAF
        else:
            raise ValueError("control_name")
        command = [sys.executable, "-I", "-c", program, str(ready_write), str(release_read)]
        if name == "denied_private_memory":
            command.extend([str(8 * 1024 * 1024), "1"])
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(ready_write, release_read),
            start_new_session=True,
        )
        os.close(ready_write)
        ready_write = -1
        os.close(release_read)
        release_read = -1
        if name == "reparented_member" and child.wait(timeout=5) != 0:
            raise AssertionError("control_intermediate_exit")
        _ready(ready_read, 2 if name == "child_and_grandchild" else 1)
        facts = _samples(reader, name)
    finally:
        try:
            if release_write >= 0:
                os.write(release_write, b"x")
        except BrokenPipeError:
            pass
        for descriptor in (ready_read, ready_write, release_read, release_write):
            if descriptor >= 0:
                os.close(descriptor)
        if child is not None and child.wait(timeout=5) != 0:
            raise AssertionError("control_child_exit")
        _retired(reader)
    facts["only_worker_live_after"] = True
    admit_facts(name, facts)
    return facts


def run(group: Path) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.live-member-resource-controls.v1",
        "admitted": False,
        "admission_refusal": None,
        "controls": [],
        "passed": False,
    }
    reader = None
    try:
        reader = ProtectedCgroupCpu(group)
        report["admitted"] = True
        for name in NAMES:
            facts: dict[str, Any] = {}
            error_kind = None
            try:
                facts = control(reader, name)
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
            report["controls"].append({"name": name, "passed": error_kind is None, "error": error_kind, "facts": facts})
        report["passed"] = all(row["passed"] for row in report["controls"])
    except BaseException as error:
        report["admission_refusal"] = (
            "accounting"
            if isinstance(error, LifetimeCpuUnavailableError)
            else "os"
            if isinstance(error, OSError)
            else "other"
        )
    finally:
        if reader is not None:
            reader.close()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", type=Path, required=True)
    result = run(parser.parse_args().group)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
