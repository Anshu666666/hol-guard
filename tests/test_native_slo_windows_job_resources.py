"""Cumulative job CPU must survive unseen child exits without losing binding."""

from __future__ import annotations

import ctypes
import json
import math
import os
import queue
import subprocess
import sys
import threading
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import psutil
import pytest

from codex_plugin_scanner.guard.codex_hook_windows_job import WindowsHookJob, spawn_windows_hook_process
from scripts import native_slo_windows_job_resources as resources


class Function:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = []
        self.restype = None

    def __call__(self, *arguments):
        return self.callback(*arguments)


class Api:
    def __init__(self):
        self.pid = 321
        self.creation = 123456789
        self.time_ok = True
        self.membership_ok = True
        self.assigned = True
        self.query_ok = True
        self.length = 48
        self.values = {"total_user_time": 10, "total_kernel_time": 20, "total_processes": 2, "active_processes": 1}
        self.queries = []
        self.during_query = None
        self.GetProcessId = Function(lambda _handle: self.pid)
        self.GetProcessTimes = Function(self.times)
        self.IsProcessInJob = Function(self.membership)
        self.QueryInformationJobObject = Function(self.query)

    def times(self, handle, creation, _exit, _kernel, _user):
        assert handle.value == 88
        value = ctypes.cast(creation, ctypes.POINTER(resources._FileTime)).contents
        value.high, value.low = self.creation >> 32, self.creation & 0xFFFFFFFF
        return self.time_ok

    def membership(self, process, job, assigned):
        assert process.value == 88 and job.value == 77
        ctypes.cast(assigned, ctypes.POINTER(ctypes.c_int32)).contents.value = self.assigned
        return self.membership_ok

    def query(self, job, information_class, value, length, returned):
        assert job.value == 77  # Never NULL or the runner's implicit job.
        assert information_class == 1 and length == 48
        self.queries.append(job.value)
        result = ctypes.cast(value, ctypes.POINTER(resources._BasicAccounting)).contents
        for key, number in self.values.items():
            setattr(result, key, number)
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32)).contents.value = self.length
        if self.during_query is not None:
            self.during_query()
        return self.query_ok


@pytest.fixture
def bound(monkeypatch):
    api = Api()
    job = WindowsHookJob(77)
    process = SimpleNamespace(pid=321, _handle=88, poll=lambda: None)
    monkeypatch.setattr(resources, "_kernel32", lambda: api)
    reader = resources.WindowsJobCpuReader(job, cast("subprocess.Popen[bytes]", process))
    return api, job, process, reader


def test_windows_accounting_abi_is_exact_on_every_test_host():
    assert ctypes.sizeof(resources._BasicAccounting) == 48
    names = [name for name, _ in resources._BasicAccounting._fields_]
    assert [getattr(resources._BasicAccounting, name).offset for name in names] == [0, 8, 16, 24, 32, 36, 40, 44]
    assert ctypes.sizeof(resources._FileTime) == 8


def test_cumulative_job_cpu_retains_unseen_and_exited_children(bound):
    api, _, _, reader = bound
    first = reader()
    api.values.update(total_user_time=17, total_kernel_time=27, total_processes=5)
    second = reader()
    assert second.total_ticks - first.total_ticks == 14
    assert second.total_processes == 5 and second.active_processes == 1
    assert second.unit == "100ns" and second.collector == "windows_job_object"
    assert second.complete_exited_descendants is True
    assert reader() == second  # Equal counters are valid; nothing is inferred as zero.
    assert api.queries == [77, 77, 77]


@pytest.mark.parametrize(
    ("fault", "code"),
    [
        ("closed", "binding_changed"),
        ("job-handle", "binding_changed"),
        ("process-handle", "binding_changed"),
        ("pid", "root_mismatch"),
        ("process-pid", "binding_changed"),
        ("creation", "root_identity_changed"),
        ("creation-zero", "root_time_invalid"),
        ("creation-query", "root_time_query_failed"),
        ("exited", "root_exited"),
        ("membership-query", "membership_query_failed"),
        ("membership", "root_not_assigned"),
        ("query", "accounting_query_failed"),
        ("length-zero", "accounting_length_invalid"),
        ("length-short", "accounting_length_invalid"),
        ("length-long", "accounting_length_invalid"),
        ("negative-user", "accounting_negative"),
        ("negative-kernel", "accounting_negative"),
        ("negative-period", "accounting_negative"),
        ("no-root", "accounting_counts_invalid"),
        ("active-over-total", "accounting_counts_invalid"),
        ("terminated-over-total", "accounting_counts_invalid"),
    ],
)
def test_fault_is_unavailable_and_permanently_poisons_reader(bound, fault, code):
    api, job, process, reader = bound
    if fault == "closed":
        job.closed = True
    elif fault == "job-handle":
        job.handle = 79
    elif fault == "process-handle":
        process._handle = 89
    elif fault == "pid":
        api.pid = 322
    elif fault == "process-pid":
        process.pid = 322
    elif fault == "creation":
        api.creation += 1
    elif fault == "creation-zero":
        api.creation = 0
    elif fault == "creation-query":
        api.time_ok = False
    elif fault == "exited":
        process.poll = lambda: 0
    elif fault == "membership-query":
        api.membership_ok = False
    elif fault == "membership":
        api.assigned = False
    elif fault == "query":
        api.query_ok = False
    elif fault.startswith("length-"):
        api.length = {"length-zero": 0, "length-short": 47, "length-long": 49}[fault]
    elif fault.startswith("negative-"):
        key = {
            "negative-user": "total_user_time",
            "negative-kernel": "total_kernel_time",
            "negative-period": "period_user_time",
        }[fault]
        api.values[key] = -1
    elif fault == "no-root":
        api.values["active_processes"] = 0
    elif fault == "active-over-total":
        api.values["active_processes"] = 3
    else:
        api.values["limit_terminated_processes"] = 3
    with pytest.raises(resources.WindowsJobCpuUnavailableError) as error:
        reader()
    assert error.value.code == "windows_job_" + code
    with pytest.raises(resources.WindowsJobCpuUnavailableError, match="reader_invalidated"):
        reader()


@pytest.mark.parametrize("field", ["total_user_time", "total_kernel_time", "total_processes"])
def test_each_cumulative_counter_rejects_reset_even_if_total_cpu_increases(bound, field):
    api, _, _, reader = bound
    reader()
    api.values[field] -= 1
    if field != "total_kernel_time":
        api.values["total_kernel_time"] += 100
    else:
        api.values["total_user_time"] += 100
    with pytest.raises(resources.WindowsJobCpuUnavailableError, match="accounting_regressed"):
        reader()


def test_binding_is_rechecked_after_query(bound):
    api, job, _, reader = bound
    api.during_query = lambda: setattr(job, "closed", True)
    with pytest.raises(resources.WindowsJobCpuUnavailableError, match="binding_changed"):
        reader()


@pytest.mark.parametrize("handle", [None, 0, -1, True, "77", 2**64 - 1, 2**64])
def test_null_pseudo_and_out_of_range_handles_never_reach_query(bound, handle):
    api, job, process, _ = bound
    job.handle = handle
    with pytest.raises(resources.WindowsJobCpuUnavailableError, match="handle_invalid"):
        resources.WindowsJobCpuReader(job, process)
    assert not api.queries


def test_bad_structure_size_is_rejected_before_any_api_call(bound, monkeypatch):
    api, job, process, _ = bound
    monkeypatch.setattr(resources, "_ACCOUNTING_BYTES", 47)
    with pytest.raises(resources.WindowsJobCpuUnavailableError, match="abi_invalid"):
        resources.WindowsJobCpuReader(job, process)
    assert not api.queries


def _ready(process: subprocess.Popen[bytes]) -> dict:
    result: queue.Queue[bytes] = queue.Queue(maxsize=1)
    assert process.stdout is not None
    thread = threading.Thread(target=lambda: result.put(process.stdout.readline(4096)), daemon=True)
    thread.start()
    value = result.get(timeout=20)
    thread.join(timeout=1)
    assert not thread.is_alive()
    return json.loads(value)


def _validate_chain(rows: list[dict], launcher_pid: int, parent_pid: int) -> set[int]:
    assert 1 <= len(rows) <= 2
    assert rows[-1]["pid"] == launcher_pid and rows[-1]["parent"] == parent_pid
    for row in rows:
        assert type(row["pid"]) is int and row["pid"] > 0
        assert type(row["parent"]) is int and row["parent"] > 0
        assert math.isfinite(row["created"]) and row["created"] > 0
    for child, parent in pairwise(rows):
        assert child["parent"] == parent["pid"]
    identities = {row["pid"] for row in rows}
    assert len(identities) == len(rows) and parent_pid not in identities
    return identities


def _assert_child_exited(row: dict) -> None:
    try:
        replacement = psutil.Process(row["pid"])
        if replacement.create_time() == row["created"]:
            # Windows keeps a terminated process object while Popen retains
            # its handle. A zero-time wait proves exit without requiring PID
            # disappearance; a live original child must fail this witness.
            assert replacement.wait(timeout=0) == 0
    except psutil.NoSuchProcess:
        pass


@pytest.mark.parametrize("state", ["exited", "live", "reused", "gone"])
def test_child_exit_witness_handles_retained_windows_objects(monkeypatch, state):
    waited = []

    def wait(*, timeout):
        waited.append(timeout)
        if state == "live":
            raise psutil.TimeoutExpired(timeout, pid=101)
        return 0

    def process(pid):
        assert pid == 101
        if state == "gone":
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(create_time=lambda: 2.0 if state == "reused" else 1.0, wait=wait)

    monkeypatch.setattr(psutil, "Process", process)
    if state == "live":
        with pytest.raises(psutil.TimeoutExpired):
            _assert_child_exited({"pid": 101, "created": 1.0})
    else:
        _assert_child_exited({"pid": 101, "created": 1.0})
    assert waited == ([0] if state in {"exited", "live"} else [])


@pytest.mark.parametrize("redirected", [False, True])
def test_witness_admits_only_exact_direct_or_redirector_ancestry(redirected):
    rows = [{"pid": 101, "parent": 99, "created": 1.0}]
    if redirected:
        rows.insert(0, {"pid": 102, "parent": 101, "created": 2.0})
    assert _validate_chain(rows, 101, 99) == ({101, 102} if redirected else {101})
    with pytest.raises(AssertionError):
        _validate_chain(rows, 101, 98)
    if redirected:
        rows[0]["parent"] = 98
        with pytest.raises(AssertionError):
            _validate_chain(rows, 101, 99)


def test_witness_rejects_unexplained_third_process_and_generator_membership():
    rows = [
        {"pid": 103, "parent": 102, "created": 3.0},
        {"pid": 102, "parent": 101, "created": 2.0},
        {"pid": 101, "parent": 99, "created": 1.0},
    ]
    with pytest.raises(AssertionError):
        _validate_chain(rows, 101, 99)
    with pytest.raises(AssertionError):
        _validate_chain([{"pid": 99, "parent": 99, "created": 1.0}], 99, 99)


def test_witness_worker_reports_waited_child_and_retained_root(tmp_path):
    """Exercise the witness protocol on this host; this is not a Windows job test."""
    source = str(Path(__file__).resolve().parents[1] / "src")
    worker = Path(__file__).resolve().parent / "fixtures/native_slo_windows_job_witness.py"
    process = subprocess.Popen(
        [sys.executable, "-u", str(worker), source, "direct"],
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.stdin is not None
        process.stdin.write(f"{process.pid}\n".encode())
        process.stdin.flush()
        completed = _ready(process)
        root_rows, child_rows = completed["root_chain"], completed["child_chain"]
        _validate_chain(root_rows, process.pid, os.getpid())
        _validate_chain(child_rows, completed["child_launcher_pid"], root_rows[0]["pid"])
        assert completed["child_ticks"] > 0 and completed["root_ticks"] > 0
        assert process.poll() is None
        output, error = process.communicate(b"x", timeout=10)
        assert process.returncode == 0 and not output and not error
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows retained-job accounting")
@pytest.mark.parametrize("nested", [False, True])
def test_real_job_keeps_immediate_exited_child_cpu_before_first_poll(tmp_path, nested):
    # No CPU reader runs until the complete child launch chain has exited.
    # CPython's Windows venv redirector starts a real interpreter and waits:
    # https://github.com/python/cpython/blob/3.12/PC/venvlauncher.c
    # Witness its exact topology rather than assuming one PID per invocation.
    source = str(Path(__file__).resolve().parents[1] / "src")
    worker = Path(__file__).resolve().parent / "fixtures/native_slo_windows_job_witness.py"
    process, job = spawn_windows_hook_process(
        [sys.executable, "-u", str(worker), source, "nested" if nested else "direct"],
        cwd=tmp_path,
        environment=dict(os.environ),
        allow_breakaway=False,
    )
    try:
        assert process.stdin is not None
        process.stdin.write(f"{process.pid}\n".encode())
        process.stdin.flush()
        completed = _ready(process)
        assert completed["child_ticks"] > 0
        root_rows, child_rows = completed["root_chain"], completed["child_chain"]
        root_pids = _validate_chain(root_rows, process.pid, os.getpid())
        child_pids = _validate_chain(child_rows, completed["child_launcher_pid"], root_rows[0]["pid"])
        assert root_pids.isdisjoint(child_pids) and os.getpid() not in child_pids
        root = psutil.Process(process.pid)
        active = {item.pid: item for item in [root, *root.children(recursive=True)]}
        assert set(active) == root_pids
        for row in root_rows:
            assert active[row["pid"]].create_time() == row["created"]
            assert active[row["pid"]].ppid() == row["parent"]
        for row in child_rows:
            _assert_child_exited(row)
        reader = resources.WindowsJobCpuReader(job, process)
        snapshot = reader()
        assert snapshot.total_processes == len(root_pids) + len(child_pids)
        assert snapshot.active_processes == len(root_pids)
        assert snapshot.total_ticks >= completed["root_ticks"] + completed["child_ticks"]
        assert reader().total_ticks >= snapshot.total_ticks
        output, error = process.communicate(b"x", timeout=10)
        assert process.returncode == 0 and not output and not error
        with pytest.raises(resources.WindowsJobCpuUnavailableError, match="root_exited"):
            reader()
    finally:
        job.terminate()
        process.wait(timeout=10)
        job.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
