"""Focused POSIX Guard daemon retirement regressions."""

from __future__ import annotations

import os
import signal
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


class _PosixOSProxy:
    """Expose POSIX branching without mutating process-wide ``os.name``."""

    name = "posix"

    def __getattr__(self, name: str):
        return getattr(os, name)


def test_posix_daemon_retirement_waits_for_sigkill_to_finish(monkeypatch) -> None:
    pid = 62_223
    signals: list[int] = []
    waits = iter((False, True))
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda _pid: next(waits),
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert daemon_manager_module._retire_guard_daemon_pid(pid) is True
    assert signals == [signal.SIGTERM, sigkill]


def test_retirement_process_refuses_missing_generation_marker(monkeypatch) -> None:
    def retire(*_args, **_kwargs):
        pytest.fail("unbound PID must not be signaled")

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    assert daemon_manager_module._retire_guard_daemon_process(
        {"pid": 62_228, "guard_home": "/tmp/guard-home"}
    ) is False


def test_posix_daemon_retirement_bounds_both_escalation_waits(monkeypatch) -> None:
    pid = 62_225
    signals: list[int] = []
    waits: list[float] = []
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    clock = {"value": 100.0}
    monkeypatch.setattr(daemon_manager_module.time, "monotonic", lambda: clock["value"])

    def wait(_pid: int, *, timeout: float = 1.0) -> bool:
        waits.append(timeout)
        if len(waits) == 1:
            clock["value"] += 0.20
            return False
        clock["value"] += timeout
        return True

    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", wait)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert daemon_manager_module._retire_guard_daemon_pid(pid, timeout=0.25) is True
    assert signals == [signal.SIGTERM, sigkill]
    assert waits == pytest.approx([0.25, 0.05])
    assert clock["value"] == pytest.approx(100.25)


def test_posix_daemon_retirement_rechecks_generation_before_sigkill(monkeypatch) -> None:
    pid = 62_227
    signals: list[int] = []
    waits: list[float] = []
    sigkill = getattr(signal, "SIGKILL", 9)
    markers = iter(("start-1", "start-2"))

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: next(markers))
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda _pid, *, timeout=1.0: waits.append(timeout) or False,
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_start_marker="start-1",
            timeout=0.25,
        )
        is False
    )
    assert signals == [signal.SIGTERM]
    assert waits[0] == pytest.approx(0.25, abs=0.001)


def test_windows_daemon_retirement_passes_remaining_to_exact_generation_termination(monkeypatch) -> None:
    pid = 62_226
    captured: dict[str, object] = {}

    def terminate(process_id: int, creation_time: int, *, timeout: float | None = None) -> bool:
        captured.update(pid=process_id, creation_time=creation_time, timeout=timeout)
        return True

    monkeypatch.setattr(daemon_manager_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(daemon_manager_module, "time", SimpleNamespace(monotonic=lambda: 100.0))
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: 123)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "windows_terminate_process_if_creation_time", terminate)

    assert daemon_manager_module._retire_guard_daemon_pid(pid, timeout=0.25) is True
    assert captured == {"pid": pid, "creation_time": 123, "timeout": 0.25}


@pytest.mark.parametrize("failing_signal", (signal.SIGTERM, getattr(signal, "SIGKILL", 9)))
def test_posix_daemon_retirement_does_not_accept_signal_permission_error(monkeypatch, failing_signal) -> None:
    pid = 62_224
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", lambda _pid: False)

    def deny_signal(_pid: int, sent_signal: int) -> None:
        if sent_signal == failing_signal:
            raise PermissionError("signal denied")

    monkeypatch.setattr(daemon_manager_module.os, "kill", deny_signal)

    assert daemon_manager_module._retire_guard_daemon_pid(pid) is False
