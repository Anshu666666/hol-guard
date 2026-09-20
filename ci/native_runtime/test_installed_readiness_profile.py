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
    with pytest.raises(ValueError, match=r"^unknown_profile_window$"):
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
    assert report["trials"] == [
        {
            "trial": "control",
            "outcome": "trial_unavailable",
            "cleanup": "unverified",
            "unavailable_reason": "process_timeout",
            "last_entered_phase": "unavailable",
            "phase_semantics": "last_entered_boundary_without_duration",
        }
    ]
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


def test_actual_child_exit_retains_only_fixed_checkpoint_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    real_run = subprocess.run
    calls = 0

    def launch(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        assert kwargs["timeout"] == 30
        checkpoint = command[command.index("--checkpoint") + 1]
        child = (
            "import json,sys; from pathlib import Path; "
            "Path(sys.argv[1]).write_text(json.dumps({"
            "'schema':'guard.installed-readiness-trial-checkpoint.v1',"
            "'trial':'control','source_sha':sys.argv[2],'runtime_sha256':sys.argv[3],"
            "'phase':'fixture_setup'}),encoding='utf-8'); "
            "print('synthetic-private-child-output'); "
            "print('synthetic-private-child-error',file=sys.stderr); sys.exit(17)"
        )
        return real_run([sys.executable, "-I", "-c", child, checkpoint, _SOURCE, _RUNTIME], **kwargs)

    monkeypatch.setattr(probe.subprocess, "run", launch)
    report = probe.run_trials(_original(), _SOURCE)
    results = cast(list[dict[str, Any]], report["trials"])
    assert calls == 1 and len(results) == 1
    assert results[0]["outcome"] == "trial_unavailable"
    assert results[0]["cleanup"] == "unverified"
    assert results[0]["unavailable_reason"] == "process_exit_failed"
    assert results[0]["last_entered_phase"] == "fixture_setup"
    assert report["acceptance_claim"] is False
    assert "synthetic-private" not in json.dumps(report)


def test_checkpoint_admission_is_bounded_exact_and_does_not_export_unknown_values(tmp_path: Path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    probe.write_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME, "resident_cleanup")
    original = checkpoint.read_text(encoding="utf-8")
    assert probe.read_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME) == "resident_cleanup"
    for field, value in (
        ("schema", "synthetic-private-schema"),
        ("trial", "start"),
        ("source_sha", "3" * 40),
        ("runtime_sha256", "4" * 64),
        ("phase", "synthetic-private-phase"),
        ("phase", []),
    ):
        changed = json.loads(original)
        changed[field] = value
        checkpoint.write_text(json.dumps(changed), encoding="utf-8")
        assert probe.read_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME) == "unavailable"
    checkpoint.write_bytes(b" " * (probe._CHECKPOINT_LIMIT + 1))
    assert probe.read_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME) == "unavailable"
    for payload in ("[1]", "{"):
        checkpoint.write_text(payload, encoding="utf-8")
        assert probe.read_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME) == "unavailable"
    checkpoint.unlink()
    assert probe.read_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME) == "unavailable"
    probe.write_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME, "synthetic-private-phase")
    probe.write_checkpoint(checkpoint, "control", "synthetic-private-source", _RUNTIME, "fixture_setup")
    assert not checkpoint.exists()


@pytest.mark.parametrize("invalid", ["missing", "identity"])
def test_child_report_refusal_keeps_checkpoint_without_retry(monkeypatch: pytest.MonkeyPatch, invalid: str) -> None:
    calls = 0

    def launch(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        checkpoint = Path(command[command.index("--checkpoint") + 1])
        probe.write_checkpoint(checkpoint, "control", _SOURCE, _RUNTIME, "report_write")
        if invalid == "identity":
            Path(command[command.index("--json") + 1]).write_text(
                json.dumps(
                    {
                        "schema": "guard.installed-readiness-profile-trial.v1",
                        "trial": "control",
                        "source_sha": "3" * 40,
                        "runtime_sha256": _RUNTIME,
                        "acceptance_claim": False,
                        "private": "synthetic-private-report",
                    }
                ),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(probe.subprocess, "run", launch)
    report = probe.run_trials(_original(), _SOURCE)
    results = cast(list[dict[str, Any]], report["trials"])
    assert calls == 1 and len(results) == 1
    assert results[0]["unavailable_reason"] == (
        "trial_report_unavailable" if invalid == "missing" else "trial_report_rejected"
    )
    assert results[0]["last_entered_phase"] == "report_write"
    assert results[0]["cleanup"] == "unverified"
    assert "synthetic-private" not in json.dumps(report)


def test_checkpoint_write_failure_is_best_effort(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("synthetic-private-filesystem-error")

    monkeypatch.setattr(Path, "write_text", unavailable)
    probe.write_checkpoint(tmp_path / "checkpoint.json", "control", _SOURCE, _RUNTIME, "fixture_setup")


def test_child_launch_failure_stops_without_exposing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def launch(*_args: Any, **_kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        raise OSError("synthetic-private-process-path")

    monkeypatch.setattr(probe.subprocess, "run", launch)
    report = probe.run_trials(_original(), _SOURCE)
    results = cast(list[dict[str, Any]], report["trials"])
    assert calls == 1 and len(results) == 1
    assert results[0]["unavailable_reason"] == "process_launch_failed"
    assert results[0]["last_entered_phase"] == "unavailable"
    assert results[0]["cleanup"] == "unverified"
    assert "synthetic-private" not in json.dumps(report)


def test_trial_stack_sample_observes_actual_held_owner_not_other_thread(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    entered, release = threading.Event(), threading.Event()
    foreign_entered, foreign_release = threading.Event(), threading.Event()
    ready = threading.Event()
    samplers: list[probe.TrialStackSample] = []
    outcomes: list[object] = []
    failures: list[BaseException] = []
    checkpoint = tmp_path / "checkpoint.json"
    canary = "synthetic-private-held-setup"

    def held_setup(private: str) -> str:
        entered.set()
        if not release.wait(timeout=3):
            raise TimeoutError("synthetic-private-release")
        return private

    def foreign_setup() -> None:
        foreign_entered.set()
        foreign_release.wait(timeout=3)

    def owner() -> None:
        try:
            sampler = probe.TrialStackSample(
                {"fixture_init": held_setup, "store_init": foreign_setup},
                checkpoint,
                "control",
                _SOURCE,
                _RUNTIME,
            )
            samplers.append(sampler)
            monkeypatch.setattr(sampler, "_wait_for_sample", lambda: not entered.wait(timeout=3))
            sampler.start()
            ready.set()
            try:
                outcomes.append(held_setup(canary))
            finally:
                outcomes.append(sampler.close())
        except BaseException as error:
            failures.append(error)
            ready.set()

    foreign = threading.Thread(target=foreign_setup, daemon=True)
    actual = threading.Thread(target=owner, daemon=True)
    try:
        foreign.start()
        assert foreign_entered.wait(timeout=3)
        actual.start()
        assert ready.wait(timeout=3) and len(samplers) == 1
        samplers[0]._worker.join(timeout=3)
        assert not samplers[0]._worker.is_alive()
        record = probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)
        assert record["available"] is True and record["labels"] == ["fixture_init"]
        assert record["observation"] == "one_trial_thread_stack_sample" and record["timing_claim"] is False
        encoded = checkpoint.with_suffix(".stack.json").read_text(encoding="utf-8")
        assert canary not in encoded and "foreign_setup" not in encoded and __file__ not in encoded
        assert "ident" not in encoded and "pid" not in encoded
    finally:
        release.set()
        foreign_release.set()
        if actual.ident is not None:
            actual.join(timeout=3)
        if foreign.ident is not None:
            foreign.join(timeout=3)
    assert not actual.is_alive() and not foreign.is_alive()
    assert failures == [] and outcomes == [canary, True]
    assert capsys.readouterr() == ("", "")


def test_trial_stack_sample_requires_exact_callable_code_identity(tmp_path: Path) -> None:
    def trusted() -> dict[str, object]:
        return sampler._snapshot()

    class NonCallable:
        __code__ = trusted.__code__

    cloned_code = trusted.__code__.replace()
    assert cloned_code == trusted.__code__ and cloned_code is not trusted.__code__
    clone = FunctionType(cloned_code, globals(), "synthetic-private-clone", closure=trusted.__closure__)
    sampler = probe.TrialStackSample(
        {"fixture_init": trusted, "store_init": NonCallable(), "synthetic-private-label": trusted},
        tmp_path / "checkpoint.json",
        "control",
        _SOURCE,
        _RUNTIME,
    )
    try:
        assert trusted() == {"available": True, "labels": ["fixture_init"]}
        assert clone() == {"available": False, "labels": []}
    finally:
        assert sampler.close()


def test_trial_stack_sample_bounds_frame_walk_and_omits_unknown_frames(tmp_path: Path) -> None:
    def outer() -> dict[str, object]:
        return recurse(probe._STACK_FRAME_LIMIT + 4)

    def recurse(remaining: int) -> dict[str, object]:
        if remaining:
            return recurse(remaining - 1)
        return sampler._snapshot()

    sampler = probe.TrialStackSample(
        {"fixture_init": outer, "store_schema": recurse},
        tmp_path / "checkpoint.json",
        "control",
        _SOURCE,
        _RUNTIME,
    )
    try:
        assert outer() == {"available": True, "labels": ["store_schema"]}
        assert sampler._snapshot() == {"available": False, "labels": []}
    finally:
        assert sampler.close()


def test_trial_stack_unavailable_api_and_completed_owner_remain_explicit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    samplers: list[probe.TrialStackSample] = []

    def owner() -> None:
        samplers.append(probe.TrialStackSample({"fixture_init": owner}, checkpoint, "control", _SOURCE, _RUNTIME))

    actual = threading.Thread(target=owner, daemon=True)
    actual.start()
    actual.join(timeout=3)
    assert not actual.is_alive() and len(samplers) == 1
    assert samplers[0]._snapshot() == {"available": False, "labels": []}
    assert samplers[0].close()
    current = probe.TrialStackSample({}, checkpoint, "control", _SOURCE, _RUNTIME)

    def refused() -> Any:
        raise RuntimeError("synthetic-private-frame-error")

    monkeypatch.setattr(sys, "_current_frames", refused)
    try:
        assert current._snapshot() == {"available": False, "labels": []}
    finally:
        assert current.close()
    assert not checkpoint.with_suffix(".stack.json").exists()


def test_trial_stack_cancel_joins_actual_sampler_and_preserves_original_exception(tmp_path: Path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    sampler = probe.TrialStackSample({}, checkpoint, "control", _SOURCE, _RUNTIME)
    original = RuntimeError("synthetic-private-original")
    with pytest.raises(RuntimeError) as raised:
        try:
            sampler.start()
            assert sampler._worker.is_alive()
            raise original
        finally:
            assert sampler.close()
    assert raised.value is original and not sampler._worker.is_alive()
    assert not checkpoint.with_suffix(".stack.json").exists()
    assert probe._STACK_SAMPLE_AFTER_SECONDS < probe._PROCESS_LIMIT_SECONDS == 30


def test_trial_stack_record_admission_refuses_foreign_unknown_and_oversize(tmp_path: Path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    path = checkpoint.with_suffix(".stack.json")
    value: dict[str, object] = {
        "schema": "guard.installed-readiness-trial-stack.v1",
        "trial": "control",
        "source_sha": _SOURCE,
        "runtime_sha256": _RUNTIME,
        "available": True,
        "labels": ["fixture_init"],
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    assert probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)["available"] is True
    for field, invalid in (
        ("schema", "synthetic-private-schema"),
        ("trial", "start"),
        ("source_sha", "3" * 40),
        ("runtime_sha256", "4" * 64),
        ("available", 1),
        ("available", False),
        ("labels", ["synthetic-private-frame"]),
        ("labels", ["fixture_init", "fixture_init"]),
        ("labels", [[]]),
        ("labels", []),
        ("private", "synthetic-private-payload"),
    ):
        path.write_text(json.dumps({**value, field: invalid}), encoding="utf-8")
        result = probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)
        assert result["available"] is False and result["labels"] == []
        assert "synthetic-private" not in json.dumps(result)
    path.write_bytes(b" " * (probe._CHECKPOINT_LIMIT + 1))
    assert probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)["available"] is False
    for payload in ("[]", "{", "\\ud800"):
        path.write_text(payload, encoding="utf-8")
        assert probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)["available"] is False
    path.unlink()
    assert probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)["available"] is False
    with pytest.raises(ValueError, match=r"^trial_stack_identity_invalid$"):
        probe.TrialStackSample({}, checkpoint, "control", "synthetic-private-source", _RUNTIME)
    assert not path.exists()


@pytest.mark.parametrize("broken", ["start", "write"])
def test_trial_stack_observer_failures_are_silent_and_do_not_escape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    broken: str,
) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    sampler = probe.TrialStackSample({}, checkpoint, "control", _SOURCE, _RUNTIME)

    def refused(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("synthetic-private-observer-error")

    monkeypatch.setattr(sampler, "_wait_for_sample", lambda: False)
    if broken == "start":
        monkeypatch.setattr(sampler._worker, "start", refused)
    else:
        monkeypatch.setattr(Path, "write_text", refused)
    sampler.start()
    if sampler._worker.ident is not None:
        sampler._worker.join(timeout=3)
    assert sampler.close() and not sampler._worker.is_alive()
    assert probe.read_trial_stack(checkpoint, "control", _SOURCE, _RUNTIME)["available"] is False
    assert capsys.readouterr() == ("", "")


def test_actual_child_stack_sample_survives_failure_without_retry_or_private_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_run = subprocess.run
    calls = 0

    def launch(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        assert kwargs["timeout"] == 30
        checkpoint = command[command.index("--checkpoint") + 1]
        child = (
            "import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
            "from ci.native_runtime import profile_installed_readiness as p; "
            "exec('def held():\\n s.start()\\n s._worker.join(timeout=3)\\n'); "
            "s=p.TrialStackSample({'fixture_init':held},Path(sys.argv[2]),'control',sys.argv[3],sys.argv[4]); "
            "vars(s)['_wait_for_sample']=lambda:False; held(); "
            "assert s.close(); print('synthetic-private-child-output'); sys.exit(17)"
        )
        return real_run(
            [
                sys.executable,
                "-I",
                "-c",
                child,
                str(Path(__file__).resolve().parents[2]),
                checkpoint,
                _SOURCE,
                _RUNTIME,
            ],
            **kwargs,
        )

    monkeypatch.setattr(probe.subprocess, "run", launch)
    report = probe.run_trials(_original(), _SOURCE)
    results = cast(list[dict[str, Any]], report["trials"])
    samples = cast(list[dict[str, Any]], report["trial_stack_samples"])
    assert calls == 1 and len(results) == len(samples) == 1
    assert results[0]["outcome"] == "trial_unavailable" and results[0]["cleanup"] == "unverified"
    assert results[0]["unavailable_reason"] == "process_exit_failed"
    assert samples[0]["trial"] == "control" and samples[0]["available"] is True
    assert samples[0]["labels"] == ["fixture_init"] and samples[0]["timing_claim"] is False
    assert report["acceptance_claim"] is False and "synthetic-private" not in json.dumps(report)
