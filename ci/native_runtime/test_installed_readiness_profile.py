"""Real profiler/thread controls; these do not claim installed native acceptance."""

from __future__ import annotations

import cProfile
import json
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from types import FunctionType
from typing import Any, cast

import pytest

from ci.native_runtime import installed_readiness_profile as profiling
from ci.native_runtime import profile_installed_readiness as probe

_SOURCE = "1" * 40
_RUNTIME = "2" * 64


class _Publisher:
    def __init__(self, action: Callable[[], object]) -> None:
        self.action = action
        self.worker: threading.Thread | None = None
        self.value: object = None
        self.error: BaseException | None = None

    def start(self) -> None:
        self.worker = threading.Thread(target=self._publish_once, daemon=True)
        self.worker.start()

    def _publish_once(self) -> None:
        try:
            self.value = self.action()
        except BaseException as error:
            self.error = error

    def join(self) -> None:
        assert self.worker is not None
        self.worker.join(timeout=3)
        assert not self.worker.is_alive()


def _window(profile: profiling.ReadinessProfile, name: str) -> dict[str, Any]:
    windows = cast(list[dict[str, Any]], profile.snapshot()["windows"])
    return next(item for item in windows if item["window"] == name)


def _trusted() -> int:
    return 7


def _original() -> dict[str, Any]:
    return {
        "schema": "guard.installed-scoped-policy.v1",
        "source_sha": _SOURCE,
        "runtime_sha256": _RUNTIME,
        "passed": False,
        "failure": "readiness_deadline",
    }


def test_disabled_scope_preserves_actual_methods_and_remains_silent(capsys: pytest.CaptureFixture[str]) -> None:
    publisher = _Publisher(lambda: 3)
    before = vars(publisher).copy()
    observer = profiling.ReadinessProfile({"publication": publisher._publish_once}, enabled=False)
    with observer.attach(publisher):
        assert vars(publisher) == before
        publisher.start()
        publisher.join()
    assert publisher.value == 3 and publisher.error is None
    assert "start" not in vars(publisher) and "_publish_once" not in vars(publisher)
    assert all(not item["available"] for item in cast(list[dict[str, Any]], observer.snapshot()["windows"]))
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("window", ["start", "publication"])
def test_actual_thread_profile_admits_exact_code_identity_not_equal_clone(window: str) -> None:
    class NonCallable:
        __code__ = _trusted.__code__

    cloned_code = _trusted.__code__.replace()
    assert cloned_code == _trusted.__code__ and cloned_code is not _trusted.__code__
    clone = FunctionType(cloned_code, globals(), "synthetic-private-function-name")

    action_done = threading.Event()

    def invoke_targets() -> None:
        for _ in range(2):
            _trusted()
        for _ in range(5):
            clone()

    class OverlappingPublisher(_Publisher):
        def start(self) -> None:
            if window == "start":
                invoke_targets()
            super().start()
            assert action_done.wait(timeout=3)

    def action() -> int:
        if window == "publication":
            invoke_targets()
        action_done.set()
        return 19

    publisher = OverlappingPublisher(action)
    observer = profiling.ReadinessProfile(
        {
            "publisher_start": publisher.start,
            "publication": publisher._publish_once,
            "command_preparation": _trusted,
            "configuration": NonCallable(),
        },
        enabled=True,
        window=window,
    )
    with observer.attach(publisher):
        publisher.start()
        publisher.join()
    assert publisher.value == 19 and publisher.error is None
    selected = _window(observer, window)
    assert selected["completed"] is True and selected["available"] is True
    other = "publication" if window == "start" else "start"
    assert _window(observer, other) == {"window": other, "completed": False, "available": False, "rows": []}
    rows = selected["rows"]
    matched = [row for row in rows if row["label"] == "command_preparation"]
    assert len(matched) == 1 and matched[0]["calls"] == 2
    if window == "publication":
        assert {row["label"] for row in rows} <= {"publication", "command_preparation"}
    else:
        matched = [row for row in rows if row["label"] == "publisher_start"]
        assert len(matched) == 1 and matched[0]["calls"] == 1
        assert {row["label"] for row in rows} <= {"publisher_start", "publication", "command_preparation"}
    for row in rows:
        assert set(row) == {"label", "calls", "recursive_calls", "inclusive_ms", "self_ms", "values_capped_at"}
        assert all(0 <= row[key] <= 999_999 for key in ("calls", "recursive_calls", "inclusive_ms", "self_ms"))
    encoded = json.dumps(observer.snapshot(), allow_nan=False)
    assert "synthetic-private-function-name" not in encoded
    assert __file__ not in encoded
    assert observer.snapshot()["acceptance_claim"] is False
    assert observer.snapshot()["selected_window"] == window
    assert observer.snapshot()["event_scope"] == (
        "interpreter_wide_events_during_selected_window"
        if sys.version_info >= (3, 12)
        else "selected_thread_events_during_selected_window"
    )


def test_default_publication_profile_is_available_while_real_start_is_still_running() -> None:
    action_done = threading.Event()

    class HeldStartPublisher(_Publisher):
        def start(self) -> None:
            super().start()
            assert action_done.wait(timeout=3)

    def action() -> int:
        value = _trusted()
        action_done.set()
        return value

    publisher = HeldStartPublisher(action)
    observer = profiling.ReadinessProfile({"command_preparation": _trusted}, enabled=True)
    with observer.attach(publisher):
        publisher.start()
        publisher.join()
    publication = _window(observer, "publication")
    assert publication["completed"] is True and publication["available"] is True
    assert publisher.value == 7 and publisher.error is None
    assert len(publication["rows"]) == 1 and publication["rows"][0]["calls"] == 1


def test_inflight_worker_is_unavailable_until_actual_completion() -> None:
    entered, release = threading.Event(), threading.Event()

    def action() -> int:
        entered.set()
        if not release.wait(timeout=3):
            raise TimeoutError("synthetic-private-wait")
        return 11

    publisher = _Publisher(action)
    observer = profiling.ReadinessProfile({"publication": publisher._publish_once}, enabled=True)
    with observer.attach(publisher):
        try:
            publisher.start()
            assert entered.wait(timeout=3)
            pending = _window(observer, "publication")
            assert pending == {"window": "publication", "completed": False, "available": False, "rows": []}
        finally:
            release.set()
            publisher.join()
    assert _window(observer, "publication")["completed"] is True
    assert publisher.value == 11 and publisher.error is None


def test_original_exception_object_and_instance_bindings_are_preserved() -> None:
    error = RuntimeError("synthetic-private-payload")

    def refusal() -> None:
        raise error

    publisher = _Publisher(lambda: None)
    vars(publisher)["start"] = refusal
    vars(publisher)["_publish_once"] = refusal
    original_start, original_publish = publisher.start, publisher._publish_once
    observer = profiling.ReadinessProfile({"publication": refusal}, enabled=True)
    with pytest.raises(RuntimeError) as raised, observer.attach(publisher):
        publisher._publish_once()
    assert raised.value is error
    assert publisher.start is original_start and publisher._publish_once is original_publish
    encoded = json.dumps(observer.snapshot())
    assert "synthetic-private-payload" not in encoded and "refusal" not in encoded


@pytest.mark.parametrize("broken", ["enable", "getstats"])
def test_profiler_failure_preserves_original_refusal(monkeypatch: pytest.MonkeyPatch, broken: str) -> None:
    error = RuntimeError("synthetic-private-original")

    class BrokenProfile:
        def enable(self) -> None:
            if broken == "enable":
                raise OSError("synthetic-private-profiler")

        def disable(self) -> None:
            pass

        def getstats(self) -> list[object]:
            raise OSError("synthetic-private-profiler")

    def refusal() -> None:
        raise error

    monkeypatch.setattr(profiling.cProfile, "Profile", BrokenProfile)
    publisher = _Publisher(refusal)
    vars(publisher)["_publish_once"] = refusal
    observer = profiling.ReadinessProfile({"publication": refusal}, enabled=True)
    with pytest.raises(RuntimeError) as raised, observer.attach(publisher):
        publisher._publish_once()
    assert raised.value is error
    assert _window(observer, "publication")["available"] is False
    assert _window(observer, "publication")["rows"] == []
    assert "synthetic-private" not in json.dumps(observer.snapshot())


def test_preexisting_profiler_is_not_replaced_or_disabled() -> None:
    events: list[str] = []

    def prior(_frame: object, event: str, _argument: object) -> None:
        if event == "call":
            events.append(event)

    previous = sys.getprofile()
    publisher = _Publisher(lambda: None)
    observer = profiling.ReadinessProfile({"publication": publisher._publish_once}, enabled=True)
    try:
        sys.setprofile(prior)
        with observer.attach(publisher):
            publisher._publish_once()
            assert sys.getprofile() is prior
        assert sys.getprofile() is prior and events
    finally:
        sys.setprofile(previous)
    assert _window(observer, "publication")["available"] is False


def test_unknown_window_is_refused_before_any_profile() -> None:
    with pytest.raises(ValueError, match="^unknown_profile_window$"):
        profiling.ReadinessProfile({}, enabled=True, window="synthetic-private-window")


def test_preexisting_cprofile_remains_active_after_selected_window() -> None:
    publisher = _Publisher(_trusted)
    observer = profiling.ReadinessProfile({"command_preparation": _trusted}, enabled=True)
    prior = cProfile.Profile()
    prior.enable()
    try:
        with observer.attach(publisher):
            publisher._publish_once()
        _trusted()
    finally:
        prior.disable()
    entries = [entry for entry in prior.getstats() if entry.code is _trusted.__code__]
    assert len(entries) == 1 and entries[0].callcount == 2
    assert publisher.value == 7 and publisher.error is None
    assert _window(observer, "publication")["available"] is False
    assert _window(observer, "publication")["rows"] == []


def test_later_real_publications_execute_without_reprofiling_first() -> None:
    calls = 0

    def action() -> int:
        nonlocal calls
        calls += 1
        return _trusted()

    publisher = _Publisher(action)
    observer = profiling.ReadinessProfile({"command_preparation": _trusted}, enabled=True)
    with observer.attach(publisher):
        publisher._publish_once()
        first = json.dumps(observer.snapshot(), sort_keys=True)
        publisher._publish_once()
        publisher._publish_once()
    assert calls == 3 and publisher.value == 7
    assert json.dumps(observer.snapshot(), sort_keys=True) == first
    assert _window(observer, "publication")["rows"][0]["calls"] == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "other"),
        ("source_sha", "3" * 40),
        ("runtime_sha256", "4" * 63),
        ("passed", True),
        ("passed", 0),
        ("failure", "application_refused"),
    ],
)
def test_only_exact_original_failed_readiness_is_admitted(field: str, value: object) -> None:
    report = _original()
    assert probe.original_failure(report, _SOURCE) == _RUNTIME
    report[field] = value
    assert probe.original_failure(report, _SOURCE) is None


def test_report_read_is_bounded_and_requires_mapping(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_original()), encoding="utf-8")
    assert probe.read_report(path) == _original()
    path.write_bytes(b" " * (probe._REPORT_LIMIT + 1))
    assert probe.read_report(path) is None
    path.write_text("[]", encoding="utf-8")
    assert probe.read_report(path) is None
    path.write_text("{", encoding="utf-8")
    assert probe.read_report(path) is None
    assert probe.read_report(tmp_path / "missing") is None


def test_rejected_original_never_launches_diagnostic_process(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Diagnostic child must not launch.")

    monkeypatch.setattr(probe.subprocess, "run", forbidden)
    report = probe.run_trials(None, _SOURCE)
    assert report["trials"] == [] and report["acceptance_claim"] is False
    private = probe.run_trials(None, "synthetic-private-source-path")
    assert private["source_sha"] is None
    assert "synthetic-private" not in json.dumps(private)


@pytest.mark.parametrize("cleanup", ["contained", "unverified"])
def test_predeclared_trials_preserve_identity_and_discard_child_output(
    monkeypatch: pytest.MonkeyPatch,
    cleanup: str,
) -> None:
    modes: list[str] = []

    def launch(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert command[0:2] == [sys.executable, "-I"]
        assert kwargs["stdout"] == subprocess.DEVNULL and kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 30 and kwargs["check"] is False
        mode = command[command.index("--trial") + 1]
        modes.append(mode)
        assert command[command.index("--expected-source-sha") + 1] == _SOURCE
        assert command[command.index("--expected-runtime-sha256") + 1] == _RUNTIME
        output = Path(command[command.index("--json") + 1])
        output.write_text(
            json.dumps(
                {
                    "schema": "guard.installed-readiness-profile-trial.v1",
                    "trial": mode,
                    "source_sha": _SOURCE,
                    "runtime_sha256": _RUNTIME,
                    "acceptance_claim": False,
                    "outcome": "readiness_deadline",
                    "cleanup": cleanup,
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(probe.subprocess, "run", launch)
    report = probe.run_trials(_original(), _SOURCE)
    assert modes == (["control", "start", "publication"] if cleanup == "contained" else ["control"])
    assert report["acceptance_claim"] is False and report["original_failure_preserved"] is True
    assert report["readiness_budget_ms"] == 400
    assert report["unverified_cleanup_stops_remaining_trials"] is True
    assert all(item["outcome"] == "readiness_deadline" for item in cast(list[dict[str, Any]], report["trials"]))


def test_child_timeout_stops_remaining_trials_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def timeout(command: list[str], **_kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        raise subprocess.TimeoutExpired(command, 30, output=b"synthetic-private-child-output")

    monkeypatch.setattr(probe.subprocess, "run", timeout)
    report = probe.run_trials(_original(), _SOURCE)
    assert calls == 1
    assert report["trials"] == [{"trial": "control", "outcome": "trial_unavailable", "cleanup": "unverified"}]
    assert "synthetic-private" not in json.dumps(report)


def test_failure_only_workflow_keeps_original_platform_gates() -> None:
    workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/native-wheel-ci.yml").read_text()
    linux, platforms = workflow.split("\n  macos:\n", 1)
    macos, windows = platforms.split("\n  windows-x64:\n", 1)
    assert "profile_installed_readiness.py" not in linux
    assert macos.count("profile_installed_readiness.py") == windows.count("profile_installed_readiness.py") == 1
    assert macos.count("id: installed_contracts") == windows.count("id: installed_contracts") == 1
    assert (
        "failure() && steps.installed_contracts.outcome == 'failure' && matrix.target == 'x86_64-apple-darwin'" in macos
    )
    assert "failure() && steps.installed_contracts.outcome == 'failure'" in windows
    assert "continue-on-error" not in workflow
    assert "timeout-minutes: 45" in macos and "timeout-minutes: 20" in windows
    assert "Enforce installed native soak" in linux
    assert "probe_installed_consumer_readiness.py" in linux
    for platform in (macos, windows):
        assert "installed-readiness-profile.json" in platform
        assert "probe_installed_scoped_policy.py" in platform
        assert "probe_installed_managed_floors.py" in platform
