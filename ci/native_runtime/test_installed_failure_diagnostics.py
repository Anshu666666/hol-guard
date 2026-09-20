from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import FunctionType, SimpleNamespace
from typing import Literal, cast

import pytest

from ci.native_runtime import installed_hook_failure_diagnostic as diagnostic
from ci.native_runtime import probe_installed_native_extensions as extension_probe
from ci.native_runtime import probe_installed_scoped_policy as probe
from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_publication_diagnostic as publication_diagnostic
from scripts.native_publication_diagnostic import PublicationObservation
from tests.native_policy_snapshot_test_fixtures import _ack, _status


def test_timeout_keeps_original_exception_and_call_count_without_private_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    error = TimeoutError("synthetic-private-timeout-canary")
    calls = 0
    with (
        pytest.raises(TimeoutError) as caught,
        diagnostic.report_hook_transport_timeout(case="external-reenabled", completed_cases=6, control_revision=4),
    ):
        calls += 1
        raise error
    assert caught.value is error and calls == 1
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["failure"] == "timeout" and report["case"] == "external-reenabled"
    assert report["completed_cases"] == 6 and report["control_revision"] == 4
    assert "private" not in output and "canary" not in output


@pytest.mark.parametrize("raises", [False, True])
def test_success_or_other_exception_never_samples_threads(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raises: bool
) -> None:
    def forbidden():
        pytest.fail("A non-timeout path sampled threads")

    monkeypatch.setattr(diagnostic, "describe_active_phases", forbidden)
    error = ValueError("original")
    if raises:
        with (
            pytest.raises(ValueError) as caught,
            diagnostic.report_hook_transport_timeout(case="external-off", completed_cases=0, control_revision=0),
        ):
            raise error
        assert caught.value is error
    else:
        with diagnostic.report_hook_transport_timeout(case="external-off", completed_cases=0, control_revision=0):
            pass
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("fault", ["observe", "serialize", "print"])
def test_observation_failure_cannot_replace_timeout(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic-private-observation-canary")

    if fault == "observe":
        monkeypatch.setattr(diagnostic, "describe_active_phases", fail)
    elif fault == "serialize":
        monkeypatch.setattr(diagnostic.json, "dumps", fail)
    else:
        monkeypatch.setattr(diagnostic, "print", fail, raising=False)
    error = TimeoutError("original")
    with (
        pytest.raises(TimeoutError) as caught,
        diagnostic.report_hook_transport_timeout(case="external-off", completed_cases=0, control_revision=0),
    ):
        raise error
    assert caught.value is error


def test_case_and_counts_reject_unknown_private_values(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        pytest.raises(TimeoutError),
        diagnostic.report_hook_transport_timeout(
            case="synthetic-private-canary", completed_cases=True, control_revision=10000
        ),
    ):
        raise TimeoutError
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["case"] == "other" and report["completed_cases"] is None and report["control_revision"] == 999
    assert "private" not in output and "canary" not in output


def test_actual_blocked_thread_is_observed_without_reading_frame_material(monkeypatch: pytest.MonkeyPatch) -> None:
    entered, release = threading.Event(), threading.Event()

    class Private:
        def __repr__(self) -> str:
            pytest.fail("Private frame material was rendered")

    def blocked() -> None:
        private_request = {"synthetic-private-canary": Private()}
        entered.set()
        assert release.wait(5)
        assert len(private_request) == 1

    monkeypatch.setattr(diagnostic, "_PHASE_CODES", ((blocked.__code__, "native_review"),))
    worker = threading.Thread(target=blocked)
    worker.start()
    try:
        assert entered.wait(2)
        report = diagnostic.describe_active_phases()
        assert report["available"] is True
        phases = report["phases"]
        assert isinstance(phases, dict) and phases["native_review"] == 1
        assert "private" not in json.dumps(report) and "canary" not in json.dumps(report)
        assert worker.is_alive()
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()


def test_thread_count_frame_depth_and_unavailable_observation_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    frames = {index: sys._getframe() for index in range(diagnostic._MAX_THREADS + 3)}
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: frames)
    report = diagnostic.describe_active_phases()
    assert report["threads_sampled"] == diagnostic._MAX_THREADS and report["threads_truncated"] is True
    assert frames == {}

    def unavailable():
        raise RuntimeError("synthetic-private-canary")

    monkeypatch.setattr(diagnostic.sys, "_current_frames", unavailable)
    assert diagnostic.describe_active_phases() == {"available": False}
    assert diagnostic._stack_phase(object()) == ("unknown", "unavailable")

    def nested(depth: int):
        return nested(depth - 1) if depth else diagnostic._stack_phase(sys._getframe())

    assert nested(diagnostic._MAX_FRAMES + 1) == ("unknown", "truncated")


def test_spoofed_function_name_and_filename_do_not_match_trusted_code() -> None:
    def sample():
        return diagnostic._stack_phase(sys._getframe())

    trusted = NativePolicySnapshotPublisher._publish_once.__code__
    spoofed = FunctionType(sample.__code__.replace(co_name=trusted.co_name, co_filename=trusted.co_filename), globals())
    assert spoofed() == ("unknown", "complete")


@pytest.mark.parametrize("ready", [False, True])
def test_initial_readiness_keeps_registration_inside_original_deadline_and_restores_observer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, ready: bool
) -> None:
    clock = [100.0]
    calls: list[object] = []

    class Publisher:
        _client_request = None
        _epoch = 0
        last_error = "synthetic-private-publisher-canary"

        def register_workspace(self, workspace: Path) -> None:
            assert workspace == tmp_path
            assert self._client_request is not None
            calls.append("register")
            clock[0] += 0.125

        def start(self) -> None:
            calls.append("start")
            clock[0] += 0.2

        def wait_until_ready(self, deadline: float) -> bool:
            calls.append(("wait", deadline))
            assert deadline == 100.4 and deadline - clock[0] == pytest.approx(0.075)
            return ready

    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    publisher = Publisher()
    if ready:
        probe.require_initial_readiness(cast(NativePolicySnapshotPublisher, cast(object, publisher)), tmp_path)
    else:
        with pytest.raises(probe.ProbeError, match=r"^readiness_deadline$"):
            probe.require_initial_readiness(cast(NativePolicySnapshotPublisher, cast(object, publisher)), tmp_path)
    assert calls == ["register", "start", ("wait", 100.4)]
    assert publisher._client_request is None and "wait_until_ready" not in vars(publisher)
    output = capsys.readouterr().err
    assert ("window=before_publisher_start" in output) is (not ready)
    if not ready:
        timings = json.loads(output.splitlines()[0])
        assert timings == {
            "schema": "guard.installed-initial-readiness-failure.v1",
            "registration_elapsed_ms": 125.0,
            "start_elapsed_ms": 200.0,
            "wait_elapsed_ms": 0.0,
            "total_elapsed_ms": 325.0,
        }
    assert "private" not in output and "canary" not in output and str(tmp_path) not in output


def test_publication_window_remains_finite_for_unknown_values() -> None:
    observation = PublicationObservation()
    assert "window=after_daemon_construction;" in observation.describe(None)
    assert "window=before_publisher_start;" in observation.describe(None, window="before_publisher_start")
    assert "private" not in observation.describe(
        None, window=cast(Literal["after_daemon_construction"], cast(object, "synthetic-private-canary"))
    )


@pytest.mark.parametrize(
    "before,after,expected",
    [(1.0, 0.0, None), (0.0, float("nan"), None), (0.0, float("inf"), None), (0.0, 1_000_000.0, 999_999.0)],
)
def test_initial_readiness_timings_remain_finite(before: float, after: float, expected: float | None) -> None:
    assert probe._initial_readiness_elapsed(before, after) == expected


def test_late_ack_cannot_satisfy_the_original_initial_readiness_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clock = [100.0]
    calls: list[object] = []

    def register(workspace: Path) -> None:
        assert workspace == tmp_path
        calls.append("register")
        clock[0] += 0.125

    def start() -> None:
        calls.append("start")
        clock[0] += 0.376

    def wait(deadline: float) -> bool:
        calls.append(("wait", deadline))
        # The real wait API can return an ACK before testing an expired deadline.
        assert deadline == 100.4 and clock[0] > deadline
        return True

    publisher = SimpleNamespace(
        _client_request=None,
        register_workspace=register,
        start=start,
        wait_until_ready=wait,
        last_error=None,
    )
    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    with pytest.raises(probe.ProbeError, match=r"^readiness_deadline$"):
        probe.require_initial_readiness(cast(NativePolicySnapshotPublisher, cast(object, publisher)), tmp_path)
    assert calls == ["register", "start", ("wait", 100.4)]


def test_extension_readiness_refusal_observes_the_actual_preexisting_publisher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    entered, release = threading.Event(), threading.Event()
    calls: list[str] = []

    def transport(**kwargs):
        # The real publisher has already captured this controlled transport
        # before the extension ready() observation begins. No native claim.
        calls.append("synthetic-private-extension-transport-canary")
        entered.set()
        assert release.wait(10)
        return _ack(kwargs["payload"])

    monkeypatch.setattr(client_module, "native_resident_client_request", transport)
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path), status_provider=_status)
    worker = object.__new__(HookWorker)
    worker._publish_native_policy = True
    worker.policy_snapshot_publisher = publisher
    daemon = cast(GuardDaemonServer, cast(object, SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))))
    try:
        publisher.start()
        assert entered.wait(5)
        assert publisher._thread is not None and publisher._thread.is_alive()
        with pytest.raises(RuntimeError, match=r"^installed_native_extensions_failed:policy_not_ready$"):
            extension_probe.ready(daemon, tmp_path / "workspace", 0)
        output = capsys.readouterr()
        assert json.loads(output.out) == {
            "schema": "guard.installed-native-extension-readiness-failure.v1",
            "control_revision": 0,
            "publisher_error": "missing",
        }
        assert "window=after_daemon_construction" in output.err
        assert "started=0; completed=0" in output.err
        assert "readiness_wait=not_ready" in output.err
        assert "current_binding=missing" in output.err
        assert "worker_thread=alive" in output.err
        assert "worker_phase=snapshot_transport; worker_stack=matched" in output.err
        assert "private" not in output.err and "canary" not in output.err and str(tmp_path) not in output.err
        assert len(calls) == 1
        assert publisher._client_request is None and "wait_until_ready" not in vars(publisher)
        assert "_publish_once" not in vars(publisher)
    finally:
        release.set()
        publisher.close(timeout_seconds=2)
    assert publisher._thread is not None and not publisher._thread.is_alive()


@pytest.mark.parametrize("raises", [False, True])
def test_extension_readiness_success_or_exception_preserves_call_and_methods(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raises: bool
) -> None:
    binding: dict[str, object] = {"generation": 1}
    failure = RuntimeError("synthetic-private-original-extension-error")
    calls: list[object] = []

    class Publisher:
        def __init__(self) -> None:
            self._client_request = None

        def current_snapshot(self) -> dict[str, object]:
            calls.append("snapshot")
            return {"command_extensions": {"revision": 7}}

    publisher = Publisher()
    original = dict(vars(publisher))

    def prepare(workspace: Path, *, deadline: float) -> dict[str, object]:
        assert workspace == tmp_path and deadline == 105.0
        calls.append("prepare")
        if raises:
            raise failure
        return binding

    daemon = cast(
        GuardDaemonServer,
        cast(
            object,
            SimpleNamespace(
                _server=SimpleNamespace(
                    hook_worker=SimpleNamespace(
                        policy_snapshot_publisher=publisher,
                        prepare_workspace_policy=prepare,
                    )
                )
            ),
        ),
    )
    monkeypatch.setattr(extension_probe, "time", SimpleNamespace(monotonic=lambda: 100.0))
    if raises:
        with pytest.raises(RuntimeError) as caught:
            extension_probe.ready(daemon, tmp_path, 7)
        assert caught.value is failure and calls == ["prepare"]
    else:
        assert extension_probe.ready(daemon, tmp_path, 7) is binding
        assert calls == ["prepare", "snapshot"]
    assert vars(publisher) == original
    output = capsys.readouterr()
    assert output.out == output.err == ""


def test_extension_publication_diagnostic_output_failure_preserves_original_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail_print(*args, **kwargs):
        raise OSError("synthetic-private-diagnostic-output-error")

    publisher = SimpleNamespace(_client_request=None, last_error=None)
    calls: list[float] = []

    def prepare(workspace: Path, *, deadline: float) -> None:
        assert workspace == tmp_path
        calls.append(deadline)

    daemon = cast(
        GuardDaemonServer,
        cast(
            object,
            SimpleNamespace(
                _server=SimpleNamespace(
                    hook_worker=SimpleNamespace(
                        policy_snapshot_publisher=publisher,
                        prepare_workspace_policy=prepare,
                    )
                )
            ),
        ),
    )
    monkeypatch.setattr(extension_probe, "time", SimpleNamespace(monotonic=lambda: 100.0))
    monkeypatch.setattr(publication_diagnostic, "print", fail_print, raising=False)
    with pytest.raises(RuntimeError, match=r"^installed_native_extensions_failed:policy_not_ready$"):
        extension_probe.ready(daemon, tmp_path, 0)
    assert calls == [105.0] and vars(publisher) == {"_client_request": None, "last_error": None}
    output = capsys.readouterr()
    assert json.loads(output.out)["publisher_error"] == "missing"
    assert output.err == ""
