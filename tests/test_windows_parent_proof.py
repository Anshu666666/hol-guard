from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest

from codex_plugin_scanner.guard import windows_processes as native
from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.windows_paths import windows_process_creation_time


class NativePort:
    def __init__(self, fault: str = "") -> None:
        self.fault = fault
        self.opened: list[int] = []
        self.closed: list[int] = []
        self.waits: dict[int, int] = {}
        self.times: dict[int, int] = {}
        self.queries = 0

    def open(self, access: int, inherit: bool, pid: int) -> int:
        assert access == 0x00101000 and inherit is False
        assert pid in (101, 202)
        if self.fault == f"open-{pid}-raises":
            raise OSError("controlled native refusal")
        if self.fault == f"open-{pid}-null":
            return 0
        self.opened.append(pid)
        return pid

    def query(self, handle, information_class, output, length, returned):
        assert handle == 101 and information_class == 0
        assert length == ctypes.sizeof(native._WindowsProcessBasicInformation)
        self.queries += 1
        if self.fault == "query-raises":
            raise OSError("controlled query refusal")
        row = ctypes.cast(output, ctypes.POINTER(native._WindowsProcessBasicInformation)).contents
        row.unique_process_id = 999 if self.fault == "wrong-child" else 101
        row.inherited_from_unique_process_id = {
            "zero-parent": 0,
            "self-parent": 101,
            "foreign-parent": 303,
            "oversized-parent": 0x100000000,
        }.get(self.fault, 202)
        if self.fault == "changed-parent" and self.queries == 2:
            row.inherited_from_unique_process_id = 303
        returned_length = length + {"short-query": -1, "long-query": 1, "empty-query": -length}.get(self.fault, 0)
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32)).contents.value = returned_length
        return {"error-status": -1, "informational-status": 1}.get(self.fault, 0)

    def get_times(self, handle, creation, exited, kernel, user):
        self.times[handle] = self.times.get(handle, 0) + 1
        if self.fault == f"times-{handle}-raises":
            raise OSError("controlled times refusal")
        if self.fault == f"times-{handle}-false":
            return 0
        value = 2000 if handle == 101 else 1000
        if self.fault == f"zero-time-{handle}":
            value = 0
        if self.fault == "parent-generation-mismatch" and handle == 202:
            value = 1001
        if self.fault == "child-predates-launcher" and handle == 101:
            value = 999
        if self.fault == f"changed-time-{handle}" and self.times[handle] == 2:
            value += 1
        result = ctypes.cast(creation, ctypes.POINTER(native._WindowsProcessFileTime)).contents
        result.low = value & 0xFFFFFFFF
        result.high = value >> 32
        return 1

    def wait(self, handle: int, timeout: int) -> int:
        assert timeout == 0
        self.waits[handle] = self.waits.get(handle, 0) + 1
        phase = "initial" if self.waits[handle] == 1 else "final"
        if self.fault == f"wait-{handle}-{phase}-raises":
            raise OSError("controlled wait refusal")
        if self.fault == f"wait-{handle}-{phase}-dead":
            return 0
        if self.fault == f"wait-{handle}-{phase}-unknown":
            return 0xFFFFFFFF
        return 0x102

    def close(self, handle: int) -> int:
        self.closed.append(handle)
        if self.fault == f"close-{handle}-raises":
            raise OSError("controlled close refusal")
        return 0 if self.fault == f"close-{handle}-false" else 1

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            native,
            "_load_parent_process_apis",
            lambda: (
                self.open,
                self.query,
                self.get_times,
                self.wait,
                self.close,
            ),
        )


def test_parent_proof_retains_handles_and_requires_initial_and_final_live_identity(monkeypatch):
    port = NativePort()
    port.install(monkeypatch)
    assert native.windows_process_parent_pid(101, expected_parent_pid=202, expected_parent_creation_time=1000) == 202
    assert port.opened == [101, 202] and port.closed == [202, 101]
    assert port.queries == 2 and port.times == {101: 2, 202: 2} and port.waits == {101: 2, 202: 2}
    assert ctypes.sizeof(native._WindowsProcessBasicInformation) == (48 if ctypes.sizeof(ctypes.c_void_p) == 8 else 24)
    assert ctypes.sizeof(native._WindowsProcessFileTime) == 8


@pytest.mark.parametrize(
    "fault",
    [
        "open-101-null",
        "open-101-raises",
        "open-202-null",
        "open-202-raises",
        "query-raises",
        "wrong-child",
        "zero-parent",
        "self-parent",
        "foreign-parent",
        "oversized-parent",
        "short-query",
        "long-query",
        "empty-query",
        "error-status",
        "informational-status",
        "changed-parent",
        "times-101-raises",
        "times-202-raises",
        "times-101-false",
        "times-202-false",
        "zero-time-101",
        "zero-time-202",
        "parent-generation-mismatch",
        "child-predates-launcher",
        "changed-time-101",
        "changed-time-202",
        *[
            f"wait-{pid}-{phase}-{failure}"
            for pid in (101, 202)
            for phase in ("initial", "final")
            for failure in ("raises", "dead", "unknown")
        ],
        "close-101-raises",
        "close-202-raises",
        "close-101-false",
        "close-202-false",
    ],
)
def test_parent_proof_refuses_malformed_dead_unknown_reused_or_unclosed_identity(monkeypatch, fault):
    port = NativePort(fault)
    port.install(monkeypatch)
    assert native.windows_process_parent_pid(101, expected_parent_pid=202, expected_parent_creation_time=1000) is None
    assert port.closed == list(reversed(port.opened))


@pytest.mark.parametrize(
    "field,invalid",
    [
        *[("pid", value) for value in (True, 0, -1, 2**32, "101", 101.0)],
        *[("expected_parent_pid", value) for value in (True, 0, -1, 2**32, None, 101)],
        *[("expected_parent_creation_time", value) for value in (True, 0, -1, 2**64, None, "1000", 1000.0)],
    ],
)
def test_parent_proof_invalid_request_never_loads_native_api(monkeypatch, field, invalid):
    def forbidden():
        pytest.fail("invalid request must not access native APIs")

    monkeypatch.setattr(native, "_load_parent_process_apis", forbidden)
    values = {"pid": 101, "expected_parent_pid": 202, "expected_parent_creation_time": 1000}
    values[field] = invalid
    assert native.windows_process_parent_pid(**values) is None


def test_parent_proof_missing_native_api_refuses(monkeypatch):
    monkeypatch.setattr(native, "_load_parent_process_apis", lambda: None)
    assert native.windows_process_parent_pid(101, expected_parent_pid=202, expected_parent_creation_time=1000) is None


def identity_fixture(monkeypatch, port):
    port.install(monkeypatch)
    monkeypatch.setattr(manager, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        manager,
        "_load_authenticated_daemon_identity",
        lambda _home: (
            {
                "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "port": 4781,
                "pid": 101,
            },
            "controlled-authenticated-token",
        ),
    )
    monkeypatch.setattr(manager, "_guard_daemon_pid_is_running", lambda pid: pid in (101, 202))
    monkeypatch.setattr(manager, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: True)

    class Response:
        status = 200

        def read(self):
            return b'{"compatibility_version":%d}' % manager.GUARD_DAEMON_COMPATIBILITY_VERSION

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    calls = []

    def health(request, *, timeout):
        calls.append((request.full_url, timeout))
        return Response()

    monkeypatch.setattr(manager.urllib.request, "urlopen", health)
    return calls


def test_started_wait_carries_exact_recorded_generation_to_native_parent_proof(tmp_path, monkeypatch):
    port = NativePort()
    calls = identity_fixture(monkeypatch, port)
    process = create_autospec(subprocess.Popen, instance=True, pid=202)
    process.poll.return_value = None
    url = manager._wait_for_started_guard_daemon_url(
        tmp_path, timeout=0.1, process=process, executable=tmp_path / "owned-core.exe", expected_creation_time=1000
    )
    assert url == "http://127.0.0.1:4781"
    assert calls == [("http://127.0.0.1:4781/healthz", 1.0)]
    assert port.opened == [101, 202] and port.closed == [202, 101]


def test_existing_ensure_entry_admits_child_of_recorded_windows_launcher(tmp_path, monkeypatch):
    port = NativePort()
    calls = identity_fixture(monkeypatch, port)
    events = []
    process = create_autospec(subprocess.Popen, instance=True, pid=202)
    process.poll.return_value = None
    monkeypatch.setattr(manager, "desktop_preflight_requested", lambda: False)
    monkeypatch.setattr(manager, "_trusted_daemon_home", lambda _home: tmp_path)
    monkeypatch.setattr(manager, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(manager, "_schedule_duplicate_guard_daemon_retirement", lambda _home: None)
    monkeypatch.setattr(manager, "_live_or_newer_daemon_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_guard_daemon_start_lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(manager, "_load_state", lambda _home: None)
    monkeypatch.setattr(manager, "_guard_daemon_start_in_progress", lambda _home: False)
    monkeypatch.setattr(manager, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(manager, "_candidate_ports", lambda *_args, **_kwargs: [4781])
    monkeypatch.setattr(manager, "_guard_daemon_launch_command", lambda *_args, **_kwargs: ["owned-core.exe"])
    monkeypatch.setattr(manager, "_daemon_launcher_env", lambda **_kwargs: {})
    monkeypatch.setattr(manager.subprocess, "Popen", lambda *_args, **_kwargs: process)

    def record(_home, *, process, port):
        assert process.pid == 202 and port == 4781
        events.append("record-exact-launcher-generation")
        return 1000

    monkeypatch.setattr(manager, "_record_guard_daemon_pending_launch", record)
    monkeypatch.setattr(manager, "_release_guard_daemon_launch_gate", lambda _process: events.append("release"))

    def clear(_home, *, process, creation_time):
        assert process.pid == 202 and creation_time == 1000
        events.append("clear-same-generation")
        return True

    monkeypatch.setattr(manager, "_clear_spawned_guard_daemon_pending_launch", clear)
    monkeypatch.setattr(manager, "_terminate_spawned_guard_daemon", lambda _process: True)
    url = manager.ensure_guard_daemon(
        tmp_path / "guard", home_dir=tmp_path, start_timeout=0.2, executable=tmp_path / "owned-core.exe"
    )
    assert url == "http://127.0.0.1:4781"
    assert events == ["record-exact-launcher-generation", "release", "clear-same-generation"]
    assert len(calls) == 1 and port.queries == 2


@pytest.mark.parametrize("generation", [None, 999, 1001])
def test_windows_indirect_identity_requires_original_generation_before_health(tmp_path, monkeypatch, generation):
    port = NativePort()
    calls = identity_fixture(monkeypatch, port)
    assert (
        manager._live_guard_daemon_identity(
            tmp_path, require_current_runtime=False, expected_pid=202, expected_creation_time=generation
        )
        is None
    )
    assert calls == []
    assert port.closed == list(reversed(port.opened))


def test_parent_proof_does_not_replace_authentication_health_or_home(tmp_path, monkeypatch):
    port = NativePort()
    calls = identity_fixture(monkeypatch, port)
    monkeypatch.setattr(manager, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(manager, "_daemon_healthz_details_match_guard_home", lambda *_args, **_kwargs: False)
    assert (
        manager._live_guard_daemon_identity(
            tmp_path, require_current_runtime=False, expected_pid=202, expected_creation_time=1000
        )
        is None
    )
    assert len(calls) == 1
    monkeypatch.setattr(manager, "_load_authenticated_daemon_identity", lambda _home: None)
    before = len(port.opened)
    assert (
        manager._live_guard_daemon_identity(
            tmp_path, require_current_runtime=False, expected_pid=202, expected_creation_time=1000
        )
        is None
    )
    assert len(port.opened) == before and len(calls) == 1


def test_direct_pid_behavior_does_not_gain_a_parent_lookup(monkeypatch):
    monkeypatch.setattr(manager, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        native, "_load_parent_process_apis", lambda: pytest.fail("direct PID requires no parent lookup")
    )
    assert manager._guard_daemon_pid_is_spawned_launch(202, 202) is True


@pytest.mark.skipif(os.name != "nt", reason="actual Windows native owned process APIs")
def test_native_windows_parent_proof_owned_child_foreign_generation_and_dead_process():
    generation = windows_process_creation_time(os.getpid())
    assert generation is not None
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    foreign = None
    try:
        foreign = subprocess.Popen(
            [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        foreign_generation = windows_process_creation_time(foreign.pid)
        assert foreign_generation is not None
        assert (
            native.windows_process_parent_pid(
                child.pid, expected_parent_pid=os.getpid(), expected_parent_creation_time=generation
            )
            == os.getpid()
        )
        assert (
            native.windows_process_parent_pid(
                child.pid, expected_parent_pid=os.getpid(), expected_parent_creation_time=generation + 1
            )
            is None
        )
        assert (
            native.windows_process_parent_pid(
                child.pid, expected_parent_pid=child.pid, expected_parent_creation_time=generation
            )
            is None
        )
        assert (
            native.windows_process_parent_pid(
                child.pid, expected_parent_pid=foreign.pid, expected_parent_creation_time=foreign_generation
            )
            is None
        )
    finally:
        for owned in (foreign, child):
            if owned is None:
                continue
            if owned.stdin is not None:
                owned.stdin.close()
            try:
                owned.wait(timeout=5)
            except subprocess.TimeoutExpired:
                owned.kill()
                owned.wait(timeout=5)
    assert (
        native.windows_process_parent_pid(
            child.pid, expected_parent_pid=os.getpid(), expected_parent_creation_time=generation
        )
        is None
    )
