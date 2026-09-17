from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from scripts import native_slo_session
from scripts.native_slo_session import AdapterSession


@pytest.mark.parametrize("failure_kind", ["timeout", "invalid_ack"])
def test_successful_close_retains_the_failed_recovery_stop_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_kind: str
) -> None:
    diagnostic_path = tmp_path / "stop-diagnostic.json"
    monkeypatch.setenv("NATIVE_STOP_DIAGNOSTIC_PATH", str(diagnostic_path))
    monkeypatch.setattr(native_slo_session, "_resident_state_may_exist", lambda _path: True)
    monkeypatch.setattr(native_slo_session, "close_native_resident_clients", lambda _home: None)
    calls: list[tuple[str, ...]] = []

    def run_stop(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        assert kwargs["timeout"] == 2
        if len(calls) == 1:
            if failure_kind == "timeout":
                raise subprocess.TimeoutExpired(command, 2)
            return subprocess.CompletedProcess(command, 1, b"", b"native_resident_stop_ack_invalid\n")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(native_slo_session.subprocess, "run", run_stop)
    session = object.__new__(AdapterSession)
    session._connection = None
    session.runtime = tmp_path / "runtime"
    session.guard_home = tmp_path / "guard-home"
    session.temporary = tempfile.TemporaryDirectory(dir=tmp_path)
    session.daemon = object.__new__(GuardDaemonServer)
    monkeypatch.setattr(
        session.daemon,
        "_server",
        SimpleNamespace(
            active_hook_requests=0,
            hook_process_runner=SimpleNamespace(close_native_resident_clients=lambda: True),
        ),
        raising=False,
    )
    monkeypatch.setattr(session.daemon, "stop", lambda: None)
    session.last_stop_diagnostic = {"status": "not-run"}
    session._stop_diagnostic_written = False

    assert session.stop_resident() is False
    failure = json.loads(diagnostic_path.read_text(encoding="utf-8"))
    assert failure["status"] == "failed"
    assert failure["error"] == (
        "native_resident_stop_process_failed" if failure_kind == "timeout" else "native_resident_stop_ack_invalid"
    )

    session.close()

    assert len(calls) == 3
    assert json.loads(diagnostic_path.read_text(encoding="utf-8")) == failure
    assert session.last_stop_diagnostic == failure
