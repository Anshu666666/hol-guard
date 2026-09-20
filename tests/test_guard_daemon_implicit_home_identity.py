"""Real process identity checks; children have daemon-shaped argv, not daemon authority."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import resolve_guard_home
from codex_plugin_scanner.guard.daemon import manager

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX HOME and real process command-line identity")


@contextmanager
def _child(home: Path, arguments: list[str]) -> Iterator[subprocess.Popen[str]]:
    home.mkdir()
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,sys;from pathlib import Path;print(str(Path.home()),os.getuid(),flush=True);sys.stdin.read(1)",
            "codex_plugin_scanner.cli",
            "guard",
            "daemon",
            "--serve",
            "--port",
            "54321",
            *arguments,
        ],
        env={**os.environ, "HOME": str(home)},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=5.0), "owned child did not reach its input barrier"
        assert process.stdout.readline().strip() == f"{home} {os.getuid()}"
        assert process.poll() is None
        yield process
    finally:
        # Release the retained child's own input barrier; never signal a refused subject.
        if process.stdin is not None:
            process.stdin.close()
        process.wait(timeout=5.0)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def _inventory_of_child(process: subprocess.Popen[str], monkeypatch: pytest.MonkeyPatch) -> None:
    command = manager._guard_daemon_command_for_pid(process.pid)
    assert command is not None
    assert manager._guard_daemon_command_matches(command)
    query = manager._bounded_process_query_stdout

    def one_subject(arguments: list[str]) -> str | None:
        if arguments[-2:] == ["-axo", "pid=,command="]:
            return f"{process.pid} {command}\n"
        return query(arguments)

    # Only enumeration is scoped: the row and PID identity both use actual ps bytes.
    monkeypatch.setattr(manager, "_bounded_process_query_stdout", one_subject)


def _forbid_retirement_signal(process: subprocess.Popen[str], monkeypatch: pytest.MonkeyPatch) -> list[int]:
    sent: list[int] = []
    original_kill = os.kill

    def kill(pid: int, value: int) -> None:
        if pid == process.pid and value != 0:
            sent.append(value)
            raise AssertionError("refused child must not receive a retirement signal")
        original_kill(pid, value)

    monkeypatch.setattr(manager.os, "kill", kill)
    return sent


@pytest.mark.parametrize("arguments", [[], ["--guard-home="], ["--guard-home", ""]])
def test_foreign_home_without_explicit_identity_remains_unknown_and_unsignalled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    observer_home = resolve_guard_home(None)
    foreign_home = tmp_path / "foreign-home"
    assert foreign_home != Path.home()
    with _child(foreign_home, arguments) as process:
        _inventory_of_child(process, monkeypatch)
        sent = _forbid_retirement_signal(process, monkeypatch)
        assert manager._guard_daemon_pid_command_identity(process.pid, expected_guard_home=observer_home) is None
        assert manager._guard_daemon_process_inventory_for_guard_home(observer_home) is None
        assert not manager._retire_guard_daemon_pid(process.pid, expected_guard_home=observer_home)
        assert sent == []
        assert process.poll() is None
    assert process.returncode == 0


def test_explicit_foreign_home_is_known_foreign_and_unsignalled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observer_home = resolve_guard_home(None)
    foreign_home = tmp_path / "foreign-home"
    with _child(foreign_home, ["--guard-home", str(foreign_home)]) as process:
        _inventory_of_child(process, monkeypatch)
        sent = _forbid_retirement_signal(process, monkeypatch)
        assert manager._guard_daemon_pid_command_identity(process.pid, expected_guard_home=observer_home) is False
        assert manager._guard_daemon_process_inventory_for_guard_home(observer_home) == []
        assert manager._retire_guard_daemon_pid(process.pid, expected_guard_home=observer_home)
        assert sent == []
        assert process.poll() is None
    assert process.returncode == 0


@pytest.mark.parametrize("equals", [False, True])
def test_explicit_owned_home_preserves_actual_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, equals: bool
) -> None:
    foreign_home = tmp_path / "foreign-home"
    owned_guard_home = tmp_path / "owned-guard"
    arguments = [f"--guard-home={owned_guard_home}"] if equals else ["--guard-home", str(owned_guard_home)]
    with _child(foreign_home, arguments) as process:
        _inventory_of_child(process, monkeypatch)
        assert manager._guard_daemon_pid_command_identity(process.pid, expected_guard_home=owned_guard_home) is True
        assert manager._guard_daemon_process_inventory_for_guard_home(owned_guard_home) == [(process.pid, 54321)]
        assert manager._retire_guard_daemon_pid(process.pid, expected_guard_home=owned_guard_home)
    assert process.returncode == -signal.SIGTERM
