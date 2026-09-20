"""Root-only preparation for finite CPU-accounting controls, never a benchmark.

The only privileged mutations are creation/removal of one fresh cgroup, initial
placement of its sole worker, and emergency killing inside that owned group.
The worker loses every root identity before exec and before reader admission.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import runpy
import selectors
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path("/sys/fs/cgroup")
STREAM_LIMIT = 128 * 1024
WALL_SECONDS = 30.0
CONTROL_NAMES = (
    "exited_child_and_grandchild",
    "orphan_new_session",
    "migration_refusal",
    "partial_tail",
    "lost_handle",
)

ADMISSION_LABELS = frozenset(
    {
        "admission_requires_single_thread",
        "cgroup_domain_unproved",
        "cgroup_handle_closed",
        "cgroup_hierarchy_depth",
        "cgroup_initial_hierarchy_unproved",
        "cgroup_member_size",
        "cgroup_membership_changed",
        "cgroup_migration_possible",
        "cgroup_mount_identity",
        "cgroup_mount_unsupported",
        "cgroup_not_exclusive_at_admission",
        "cgroup_owner_unproved",
        "cgroup_path_invalid",
        "cgroup_reader_process_changed",
        "cpu_counter_regressed",
        "cpu_stat_invalid",
        "cpu_stat_size",
        "metadata_size",
        "privilege_boundary_unproved",
        "protected_cgroup_platform_or_user",
        "shared_root_cgroup",
        "status_duplicate",
        "admission_os_error",
        "admission_unlisted_error",
    }
)


def duplicate_free(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def admit_facts(name: str, facts: Any) -> None:
    if name in {"exited_child_and_grandchild", "orphan_new_session"}:
        keys = {"before", "after", "delta", "stdout_sha256"}
        if name == "orphan_new_session":
            keys |= {"only_worker_live_at_final_snapshot", "orphan_reaped_by_worker"}
        if not isinstance(facts, dict) or set(facts) != keys:
            raise ValueError("cpu_facts_schema")
        if name == "orphan_new_session" and (
            facts["only_worker_live_at_final_snapshot"] is not True or facts["orphan_reaped_by_worker"] is not False
        ):
            raise ValueError("orphan_live_member_witness")
        counters = {"usage_usec", "user_usec", "system_usec"}
        for field in ("before", "after"):
            values = facts[field]
            if (
                not isinstance(values, dict)
                or set(values) != counters
                or any(type(v) is not int or not 0 <= v <= 2**63 - 1 for v in values.values())
            ):
                raise ValueError("cpu_facts_counters")
        expected = {
            key.replace("_usec", "_seconds"): (facts["after"][key] - facts["before"][key]) / 1_000_000
            for key in counters
        }
        delta = facts["delta"]
        if (
            not isinstance(delta, dict)
            or any(type(v) not in {int, float} or not math.isfinite(v) or v < 0 for v in delta.values())
            or delta != expected
            or delta["usage_seconds"] < 0.06
        ):
            raise ValueError("cpu_facts_delta")
        stdout = b"leaf-done\nchild-done\n" if name == "exited_child_and_grandchild" else b"leaf-done\n"
        if facts["stdout_sha256"] != hashlib.sha256(stdout).hexdigest():
            raise ValueError("cpu_facts_stdout")
    else:
        expected_facts = {
            "migration_refusal": {"open_refused": True, "membership_stable": True},
            "partial_tail": {
                "exception_identity": True,
                "child_still_active_at_snapshot": True,
                "lifetime_cpu_complete": False,
                "cleanup_exit": 0,
            },
            "lost_handle": {"original_return_identity": True, "lifetime_cpu_complete": False, "fault_count": 1},
        }[name]
        if (
            not isinstance(facts, dict)
            or facts != expected_facts
            or any(type(facts[key]) is not type(value) for key, value in expected_facts.items())
        ):
            raise ValueError("control_facts_join")


def read_worker_report(body: bytes) -> dict[str, Any]:
    if len(body) > STREAM_LIMIT:
        raise ValueError("worker_report_size")
    result = json.loads(body, object_pairs_hook=duplicate_free)
    if not isinstance(result, dict) or set(result) != {"schema", "admitted", "admission_refusal", "controls", "passed"}:
        raise ValueError("worker_report_schema")
    if result["schema"] != "hol-guard.kernel-cpu-finite-controls.v2" or type(result["admitted"]) is not bool:
        raise ValueError("worker_not_admitted")
    if result["admitted"] is False:
        if (
            type(result["admission_refusal"]) is not str
            or result["admission_refusal"] not in ADMISSION_LABELS
            or result["controls"] != []
            or result["passed"] is not False
        ):
            raise ValueError("worker_refusal_schema")
        return result
    if result["admission_refusal"] is not None:
        raise ValueError("admitted_worker_refusal")
    rows = result["controls"]
    if not isinstance(rows, list) or len(rows) != len(CONTROL_NAMES):
        raise ValueError("worker_control_count")
    for expected, row in zip(CONTROL_NAMES, rows, strict=True):
        if not isinstance(row, dict) or set(row) != {"name", "passed", "error", "facts"} or row["name"] != expected:
            raise ValueError("worker_control_order")
        if type(row["passed"]) is not bool or row["error"] not in {None, "assertion", "os", "accounting", "other"}:
            raise ValueError("worker_control_result")
        if row["passed"] != (row["error"] is None):
            raise ValueError("worker_control_error_join")
        if row["passed"]:
            admit_facts(expected, row["facts"])
        elif row["facts"] != {}:
            raise ValueError("failed_control_facts")
    if type(result["passed"]) is not bool or result["passed"] != all(row["passed"] for row in rows):
        raise ValueError("worker_summary_join")
    return result


def admit_worker_report(body: bytes) -> dict[str, Any]:
    result = read_worker_report(body)
    if result["admitted"] is not True:
        raise ValueError("worker_not_admitted")
    return result


def drop_worker_identity(group_fd: int, uid: int, gid: int, libc: Any) -> None:
    """Runs only in the controller's single-threaded fork child, before exec."""
    descriptor = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group_fd)
    try:
        value = str(os.getpid()).encode("ascii")
        if os.write(descriptor, value) != len(value):
            raise RuntimeError("initial_placement_short_write")
    finally:
        os.close(descriptor)
    os.close(group_fd)
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "worker_no_new_privileges")


def collect(process: subprocess.Popen[bytes], group_fd: int) -> tuple[bytes, bytes, str | None]:
    """Drain concurrently with a shared finite bound; never wait on EOF forever."""
    assert process.stdout is not None and process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    failure = None
    deadline = time.monotonic() + WALL_SECONDS
    with selectors.DefaultSelector() as selector:
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            if time.monotonic() >= deadline:
                failure = "worker_wall_bound"
                break
            for key, _ in selector.select(timeout=min(0.05, max(0.0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                remaining = STREAM_LIMIT - sum(len(value) for value in buffers.values())
                buffers[key.data].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    failure = "worker_stream_bound"
                    break
            if failure:
                break
    if failure is not None:
        kill_group(group_fd)
    return bytes(buffers["stdout"]), bytes(buffers["stderr"]), failure


def kill_group(group_fd: int) -> None:
    descriptor = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group_fd)
    try:
        if os.write(descriptor, b"1") != 1:
            raise RuntimeError("owned_group_kill_short_write")
    finally:
        os.close(descriptor)


def group_empty(group_fd: int) -> bool:
    descriptor = os.open("cgroup.events", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group_fd)
    with os.fdopen(descriptor, "rb") as stream:
        body = stream.read(4097)
    if len(body) > 4096:
        raise ValueError("group_events_size")
    rows = [line.split() for line in body.decode("ascii").splitlines()]
    values = duplicate_free([(key, value) for key, value in rows])
    if values.get("populated") not in {"0", "1"}:
        raise ValueError("group_population_unknown")
    return values["populated"] == "0"


def stream_evidence(stdout: bytes, stderr: bytes, failure: str | None) -> dict[str, Any]:
    return {
        "stream_capture_complete": failure is None,
        "stdout_retained_bytes": len(stdout),
        "stdout_retained_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_retained_bytes": len(stderr),
        "stderr_retained_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def run(python: Path, uid: int, gid: int, *, control_kind: str = "cpu") -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.kernel-cpu-host-controller.v1",
        "passed": False,
        "worker_launched": False,
        "worker_report": None,
        "worker_exit": None,
        "fault": None,
        "collection_failure": None,
        "cleanup_complete": False,
        "original_workload_executed": False,
    }
    group: Path | None = None
    group_fd = -1
    process: subprocess.Popen[bytes] | None = None
    try:
        if control_kind not in {"cpu", "resources", "turnover"}:
            raise ValueError("controller_kind")
        if sys.platform != "linux" or os.getresuid() != (0, 0, 0) or uid <= 0 or gid <= 0:
            raise ValueError("controller_identity")
        if sys.flags.isolated != 1 or sys.flags.no_site != 1:
            raise ValueError("controller_requires_isolated_no_site")
        if len(os.listdir("/proc/self/task")) != 1:
            raise ValueError("controller_requires_one_thread")
        python = python.absolute()
        if not python.is_file() or not os.access(python, os.X_OK):
            raise ValueError("worker_interpreter")
        worker_module = {
            "cpu": "qualification_cpu_worker",
            "resources": "qualification_resource_worker",
            "turnover": "qualification_turnover_worker",
        }[control_kind]
        worker = Path(__file__).resolve().with_name(worker_module + ".py")
        if not worker.is_file():
            raise ValueError("worker_source")
        report_reader = read_worker_report
        if control_kind in {"resources", "turnover"}:
            # This selected sibling is stdlib-only and hash-bound by the
            # finite driver. No product, psutil or worker is imported as root.
            contract_name = (
                "qualification_resource_contract.py"
                if control_kind == "resources"
                else "qualification_turnover_contract.py"
            )
            contract = Path(__file__).resolve().with_name(contract_name)
            report_reader = runpy.run_path(str(contract))["read_worker_report"]
            report["schema"] = (
                "hol-guard.kernel-resource-host-controller.v1"
                if control_kind == "resources"
                else "hol-guard.kernel-turnover-host-controller.v1"
            )
        libc: Any = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
        libc.prctl.restype = ctypes.c_int
        group = ROOT / ("hol-guard-accounting-control-" + uuid.uuid4().hex)
        group.mkdir(mode=0o555)
        group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(group_fd)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o555 or not group_empty(group_fd):
            raise ValueError("fresh_group_identity")
        # Establish cleanup capability before any child can exist.
        kill_fd = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group_fd)
        os.close(kill_fd)
        # A finite source control needs its repository package explicitly under
        # -I. This is never an installed launcher or a benchmark command.
        bootstrap = (
            "import sys;"
            f"sys.path.insert(0,{str(worker.parents[2])!r});"
            f"from scripts.ci.{worker_module} import main;"
            "raise SystemExit(main())"
        )
        command = [str(python), "-I", "-c", bootstrap, "--group", str(group)]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            pass_fds=(group_fd,),
            preexec_fn=lambda: drop_worker_identity(group_fd, uid, gid, libc),
        )
        report["worker_launched"] = True
        stdout, stderr, failure = collect(process, group_fd)
        report["collection_failure"] = failure
        report.update(stream_evidence(stdout, stderr, failure))
        report["worker_exit"] = process.wait(timeout=1.0)
        if failure is not None:
            raise RuntimeError(failure)
        # Preserve only a validated safe report before the same strict refusal.
        report["worker_report"] = report_reader(stdout)
        if report["worker_report"]["admitted"] is not True:
            raise ValueError("worker_not_admitted")
        report["passed"] = report["worker_exit"] == 0 and not stderr and report["worker_report"]["passed"]
    except BaseException as error:
        report["fault"] = "os" if isinstance(error, OSError) else "controller"
        report["passed"] = False
    finally:
        try:
            if group_fd >= 0:
                if not group_empty(group_fd):
                    kill_group(group_fd)
                if process is not None:
                    process.wait(timeout=2.0)
                deadline = time.monotonic() + 2.0
                while not group_empty(group_fd) and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not group_empty(group_fd):
                    raise RuntimeError("owned_group_not_empty")
                os.close(group_fd)
                group_fd = -1
                assert group is not None
                group.rmdir()
            report["cleanup_complete"] = group is None or not group.exists()
        except BaseException:
            report["cleanup_complete"] = False
            report["passed"] = False
        finally:
            if group_fd >= 0:
                os.close(group_fd)
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--control-kind", choices=("cpu", "resources", "turnover"), default="cpu")
    args = parser.parse_args()
    result = run(args.python, args.uid, args.gid, control_kind=args.control_kind)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] and result["cleanup_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
