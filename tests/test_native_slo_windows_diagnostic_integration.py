from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io
from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from scripts import native_slo_daemon_fixture as fixture
from scripts import native_slo_session
from scripts.ci import installed_native_ollama_probe as ollama
from scripts.native_slo_config_observer import PublisherConfigObserver
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_windows_open_observer import WindowsOpenFailureObserver


class Publisher:
    def __init__(self) -> None:
        self.code = None
        self.recorded = []
        self.closed = False

    def _record_error(self, error):
        self.recorded.append(error)
        self.code = error

    @property
    def last_error(self):
        return self.code

    def is_ready(self):
        return False


@pytest.mark.parametrize("change_generation", (False, True))
def test_ollama_failure_captures_only_the_current_owned_publisher_generation(
    monkeypatch: pytest.MonkeyPatch, change_generation: bool
) -> None:
    class ActualPublisher(Publisher):
        @property
        def last_error(self):
            code = self.code
            if change_generation:
                self._record_error("later_error")
            return code

    publisher = ActualPublisher()
    calls = []

    def prepare(workspace, *, deadline):
        calls.append((workspace, deadline))
        try:
            try:
                raise OSError(32, "private-marker C:\\private\\config")
            except OSError as cause:
                raise GuardConfigSourceError("guard_config_source_unavailable") from cause
        except GuardConfigSourceError:
            publisher._record_error("guardconfigsourceerror")
        return None

    worker = SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
    session = SimpleNamespace(
        workspace=Path("fixture"), daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    )
    clock = iter((100.0, 100.0))
    monkeypatch.setattr(ollama.time, "monotonic", lambda: next(clock))
    original = publisher._record_error
    with PublisherConfigObserver(publisher) as observer, pytest.raises(FixtureFailureError) as caught:
        ollama.ready_binding(
            cast(native_slo_session.AdapterSession, cast(object, session)), 1, phase="enabled", observer=observer
        )
    detail = failure_evidence(caught.value)
    assert publisher._record_error == original
    assert calls == [(Path("fixture"), 100.4)]
    readiness = detail["readiness"]
    assert isinstance(readiness, dict)
    assert readiness["publisher_error_value"] == "guardconfigsourceerror"
    assert readiness["budget_ms"] == 400.0
    assert readiness["elapsed_ms"] == 0.0
    if change_generation:
        assert "publisher_config_failure" not in readiness
        assert publisher.recorded == ["guardconfigsourceerror", "later_error"]
    else:
        assert readiness["publisher_config_failure"]["config_cause_1_errno"] == 32
        assert publisher.recorded == ["guardconfigsourceerror"]
    assert "private-marker" not in str(detail)


def test_ollama_authority_setup_failure_restores_observer_and_closes_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = Publisher()
    original = publisher._record_error
    closed = []
    session = SimpleNamespace(
        store=object(),
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
        ),
        close=lambda: closed.append(True),
    )
    error = RuntimeError("private setup failure")

    def fail_authority(store):
        assert store is session.store
        assert publisher._record_error != original
        raise error

    monkeypatch.setattr(ollama, "artifact_identity", lambda _expected: (Path("runtime"), {"build_sha": "a" * 40}))
    monkeypatch.setattr(ollama, "AdapterSession", lambda *_args, **_kwargs: session)
    monkeypatch.setattr(ollama, "prepare_fixture_authority", fail_authority)
    report = ollama.run_probe({})
    assert report["passed"] is False
    assert report["completed_case_count"] == 0
    assert report["failure"] == failure_evidence(error)
    assert publisher._record_error == original
    assert closed == [True]


@pytest.mark.parametrize("failure_stage", ("construct", "start", None))
def test_daemon_startup_observer_retires_before_hooks_and_preserves_exact_failure(
    monkeypatch: pytest.MonkeyPatch, failure_stage: str | None
) -> None:
    error = NativePolicySnapshotError("native_policy_windows_path_open_failed")
    calls = []

    def original(path, *, create_new):
        calls.append((path, create_new))
        raise error

    def fail_open():
        windows_io._windows_raise_open_error(Path("private-marker"), create_new=False)

    class Session:
        def __init__(self, *_args, **_kwargs):
            if failure_stage == "construct":
                fail_open()

        def __enter__(self):
            if failure_stage == "start":
                fail_open()
            return self

        def __exit__(self, *_args):
            pass

    def serve(*_args):
        assert windows_io._windows_raise_open_error is original

    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(windows_io, "_windows_raise_open_error", original)
    monkeypatch.setattr(native_slo_session, "AdapterSession", Session)
    monkeypatch.setattr(fixture, "_serve_session", serve)
    monkeypatch.setattr(fixture, "_emit", lambda _value: None)
    observer = WindowsOpenFailureObserver()
    if failure_stage is None:
        assert fixture._serve(Path("runtime"), open_observer=observer) == 0
        assert calls == []
    else:
        with pytest.raises(NativePolicySnapshotError) as caught:
            fixture._serve(Path("runtime"), open_observer=observer)
        assert caught.value is error
        assert calls == [(Path("private-marker"), False)]
        observed = observer.failure_evidence(error)["windows_open_failure"]
        assert isinstance(observed, dict)
        assert observed["winerror"] == 32
    assert windows_io._windows_raise_open_error is original
