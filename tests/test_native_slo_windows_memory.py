from __future__ import annotations

import os
import queue
import sys
import threading
from types import SimpleNamespace

import pytest

from scripts import native_slo_adapter as adapter
from scripts import native_slo_windows_memory as memory


class ProcessError(Exception):
    pass


class Process:
    def __init__(self, api, pid):
        self.api, self.pid = api, pid

    def create_time(self):
        return self.api.identities[self.pid][0]

    def ppid(self):
        return self.api.identities[self.pid][1]

    def children(self, *, recursive):
        assert recursive and self.pid == 10
        return [Process(self.api, pid) for pid in self.api.children]

    def is_running(self):
        return self.api.running

    def memory_info(self):
        if self.api.fault is not None:
            self.api.fault(self.pid)
        return SimpleNamespace(rss=self.api.rss, private=70, peak_wset=999999, vms=999999)

    def num_threads(self):
        return 2

    def num_handles(self):
        return 3


@pytest.fixture
def api(monkeypatch):
    value = SimpleNamespace(
        Error=ProcessError,
        identities={10: (1.0, 999), 11: (2.0, 10), 12: (3.0, 11)},
        children=[11, 12],
        running=True,
        fault=None,
        rss=100,
    )
    calls = []

    def process(pid):
        calls.append(pid)
        if pid not in value.identities:
            raise ProcessError()
        return Process(value, pid)

    value.Process = process
    value.calls = calls
    monkeypatch.setattr(memory, "_psutil", lambda: value)
    monkeypatch.setattr(memory, "sys", SimpleNamespace(platform="win32"))
    return value


def test_current_working_set_private_commit_and_tree_scope_are_distinct(api):
    assert memory.sample_windows_tree_memory(10) == memory.WindowsTreeMemory(300, 210, 3, 6, 9)
    assert set(api.calls) == {10, 11, 12}


@pytest.mark.parametrize("fault", ["denied", "exited", "root-reused", "child-reused", "reparented"])
def test_unavailable_or_changed_tree_never_falls_back_to_another_root(api, fault):
    def mutate(pid):
        if fault == "denied":
            raise ProcessError()
        if fault == "exited":
            api.running = False
            raise ProcessError()
        if fault == "root-reused":
            api.identities[10] = (api.identities[10][0] + 1, 999)
        elif fault == "child-reused":
            api.identities[pid] = (api.identities[pid][0] + 1, api.identities[pid][1])
        else:
            api.identities[12] = (3.0, 999)

    api.fault = mutate
    assert memory.sample_windows_tree_memory(10) is None
    assert set(api.calls) <= {10, 11, 12}


@pytest.mark.parametrize("fault", ["duplicate", "cycle", "missing-parent", "too-many", "zero", "negative", "overflow"])
def test_tree_and_counter_bounds_fail_closed(api, monkeypatch, fault):
    if fault == "duplicate":
        api.children.append(11)
    elif fault == "cycle":
        api.identities[11] = (3.0, 12)
    elif fault == "missing-parent":
        api.identities[12] = (3.0, 999)
    elif fault == "too-many":
        monkeypatch.setattr(memory, "_MAX_PROCESSES", 2)
    else:
        api.rss = {"zero": 0, "negative": -1, "overflow": 2**63 - 1}[fault]
    assert memory.sample_windows_tree_memory(10) is None


def test_deadline_covers_all_attempts_and_rejects_late_sample(api, monkeypatch):
    clock = iter([0.0, *([0.1] * 10), *([2.0] * 30)])
    monkeypatch.setattr(memory.time, "monotonic", lambda: next(clock))
    assert memory.sample_windows_tree_memory(10) is None


@pytest.mark.parametrize("pid", [0, -1, True, 2**32, None])
def test_invalid_roots_never_open_the_current_process(api, pid):
    assert memory.sample_windows_tree_memory(pid) is None
    assert api.calls == []


def test_missing_dependency_and_other_platform_remain_unavailable(api, monkeypatch):
    def missing():
        raise ImportError()

    monkeypatch.setattr(memory, "_psutil", missing)
    assert memory.sample_windows_tree_memory(10) is None
    monkeypatch.setattr(memory, "sys", SimpleNamespace(platform="darwin"))
    assert memory.sample_windows_tree_memory(10) is None
    assert api.calls == []


def test_adapter_requires_full_windows_tree_and_preserves_metric_names(monkeypatch):
    monkeypatch.setattr(adapter, "sys", SimpleNamespace(platform="win32"))
    roots = []

    def sample(pid):
        roots.append(pid)
        return memory.WindowsTreeMemory(300, 210, 3, 6, 9)

    monkeypatch.setattr(adapter, "sample_windows_tree_memory", sample)
    result = adapter.process_resources(10)
    assert result == adapter.ProcessResources(300, 6, 0, handles=9, private_commit_bytes=210, processes=3)
    assert roots == [10]
    monkeypatch.setattr(adapter, "sample_windows_tree_memory", lambda _pid: None)
    monkeypatch.setattr(adapter, "_single_process_rss_bytes", lambda _pid: pytest.fail("root-only fallback"))
    monkeypatch.setattr(adapter, "process_tree_rss_bytes", lambda _pid: pytest.fail("POSIX fallback"))
    assert adapter.process_resources(10) is None
    assert adapter.process_rss_bytes(10) == 0  # Existing unavailable sentinel; the gate rejects it.


def _ready(process):
    result = queue.Queue(maxsize=1)
    thread = threading.Thread(target=lambda: result.put(process.stdout.readline()), daemon=True)
    thread.start()
    value = result.get(timeout=15)
    thread.join(timeout=1)
    assert not thread.is_alive() and value == b"ready\n"


def _memory_tree_program():
    leaf = (
        "import sys; allocation=bytearray(24*1024*1024); "
        "allocation[::4096]=b'x'*(len(allocation)//4096); "
        "sys.stdout.buffer.write(b'ready\\n'); sys.stdout.buffer.flush(); sys.stdin.buffer.read(1)"
    )

    def wrapper(child):
        return f"""
import subprocess,sys
child=subprocess.Popen([sys.executable,'-u','-c',{child!r}],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
try:
    assert child.stdout.readline()==b'ready\\n'
    sys.stdout.buffer.write(b'ready\\n')
    sys.stdout.buffer.flush()
    sys.stdin.buffer.read(1)
finally:
    child.communicate(b'x',timeout=10)
    assert child.returncode==0
"""

    return wrapper(wrapper(leaf))


def test_memory_tree_fixture_preserves_binary_readiness_and_clean_retirement():
    from pathlib import Path

    from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process

    # Exercise the actual nested program on every host. Binary stream writes
    # avoid Windows text-mode CRLF translation at both relay boundaries.
    result = run_isolated_hook_process(
        (sys._base_executable, "-u", "-c", _memory_tree_program()),
        cwd=Path.cwd(),
        environment=dict(os.environ),
        input_text="x",
        timeout_seconds=15,
        output_limit=4096,
    )
    assert result.returncode == 0 and result.stdout == "ready\n" and not result.stderr
    assert not result.timed_out and not result.containment_failed and not result.output_limit_exceeded


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows current working-set process-tree sampling")
def test_real_windows_tree_includes_live_grandchild_and_rejects_exited_root():
    from pathlib import Path

    from codex_plugin_scanner.guard.codex_hook_windows_job import spawn_windows_hook_process

    # The fixture needs only the standard library. Starting the base executable
    # gives exactly three interpreters rather than also starting the venv's
    # Windows redirector at every generation. Production sampling still walks
    # every actual descendant; its exact three-process assertion stays intact.
    executable = Path(sys._base_executable).resolve(strict=True)
    process, job = spawn_windows_hook_process(
        [str(executable), "-u", "-c", _memory_tree_program()],
        cwd=Path.cwd(),
        environment=dict(os.environ),
        allow_breakaway=False,
    )
    try:
        _ready(process)
        sampled = memory.sample_windows_tree_memory(process.pid)
        assert sampled is not None
        assert sampled.processes == 3
        assert sampled.rss_bytes >= 24 * 1024 * 1024
        assert sampled.private_commit_bytes >= 24 * 1024 * 1024
        assert sampled.threads >= 3 and sampled.handles > 0
        assert adapter.process_rss_bytes(process.pid) > 0
        output, errors = process.communicate(b"x", timeout=15)
        assert process.returncode == 0 and not output and not errors
        assert memory.sample_windows_tree_memory(process.pid) is None
    finally:
        job.terminate()
        process.wait(timeout=10)
        job.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
