"""Untimed forwarding and failure-preservation controls for the isolated driver."""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

PATH = Path(__file__).resolve().parents[1] / "scripts/ci/package_export_diagnostic.py"
SPEC = importlib.util.spec_from_file_location("package_export_diagnostic_control", PATH)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIVER
SPEC.loader.exec_module(DRIVER)


def producer(observe, measure=None):
    return SimpleNamespace(
        observe_priority_launcher=observe, measure_priority_launchers=measure
    )


def launcher():
    return SimpleNamespace(
        harness="codex", event="PreToolUse", registration_sha256="a" * 64
    )


def observation():
    return SimpleNamespace(
        latency_ms=12.5, allowed=True, route="pending_batch_validation"
    )


def test_forwarding_preserves_object_arguments_and_original_timer_value():
    returned = observation()
    session, registered, stop = object(), launcher(), object()
    calls = []

    def observe(*args, **kwargs):
        calls.append((args, kwargs))
        return returned

    owner = producer(observe)
    with DRIVER.ObservationCapture(owner) as capture:
        result = owner.observe_priority_launcher(
            session, registered, sample=123, stop_event=stop
        )
    assert result is returned
    assert calls == [((session, registered), {"sample": 123, "stop_event": stop})]
    assert owner.observe_priority_launcher is observe
    assert capture.snapshot()["rows"][0]["latency_ms"] == 12.5
    assert capture.snapshot()["rows"][0]["original_returned"] is True


def test_forwarding_preserves_exact_exception_and_restores_original():
    original = RuntimeError("original producer failure")
    count = 0

    def observe(*_args, **_kwargs):
        nonlocal count
        count += 1
        raise original

    owner = producer(observe)
    capture = DRIVER.ObservationCapture(owner)
    with pytest.raises(RuntimeError) as raised:
        with capture:
            owner.observe_priority_launcher(
                object(), launcher(), sample=-1, case="block"
            )
    assert raised.value is original
    assert count == 1
    assert owner.observe_priority_launcher is observe
    assert capture.snapshot()["rows"][0]["original_returned"] is False
    assert "original producer failure" not in repr(capture.snapshot())


@pytest.mark.parametrize("raises", [False, True], ids=["returned", "raised"])
def test_recording_failure_cannot_replace_original_result(raises):
    returned, original = observation(), RuntimeError("original")

    def observe(*_args, **_kwargs):
        if raises:
            raise original
        return returned

    owner = producer(observe)
    with DRIVER.ObservationCapture(owner) as capture:
        capture.record = lambda *_args: (_ for _ in ()).throw(ValueError("diagnostic"))
        if raises:
            with pytest.raises(RuntimeError) as caught:
                owner.observe_priority_launcher(object(), launcher(), sample=0)
            assert caught.value is original
        else:
            assert (
                owner.observe_priority_launcher(object(), launcher(), sample=0)
                is returned
            )
    assert capture.recording_faults == 1
    assert capture.rows == []


def test_capture_is_bounded_without_limiting_original_calls():
    returned = observation()
    owner = producer(lambda *_args, **_kwargs: returned)
    with DRIVER.ObservationCapture(owner) as capture:
        for sample in range(90):
            assert (
                owner.observe_priority_launcher(object(), launcher(), sample=sample)
                is returned
            )
    assert len(capture.rows) == 88
    assert capture.overflow == 2
    assert capture.rows[-1]["sample"] == 87


class Fixture:
    def __init__(self, *, enter_error=None, close_error=None):
        self.enter_error, self.close_error = enter_error, close_error
        self.enters, self.closes = 0, 0
        self.startup_ms, self.readiness_ms = 7.0, 2.0
        self.process = SimpleNamespace(poll=lambda: 0)
        self._readers = [SimpleNamespace(is_alive=lambda: False)]

    def __enter__(self):
        self.enters += 1
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def close(self):
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


def test_exact_measure_function_runs_once_with_original_plan_and_private_fixture():
    fixture = Fixture()
    calls = []
    returned = observation()
    owner = producer(lambda *_args, **_kwargs: returned)

    def measure(session, plan):
        calls.append((session, plan))
        owner.observe_priority_launcher(session, launcher(), sample=0)
        return {"contracts_passed": True}, {"original": [12.5]}

    owner.measure_priority_launchers = measure
    report = DRIVER.execute_block(fixture, owner)
    assert calls == [(fixture, {"priority_per_run": 2, "cold_per_run": 2})]
    assert fixture.enters == fixture.closes == 1
    assert report["measurements"] == {"contracts_passed": True}
    assert report["raw_samples_ms"] == {"original": [12.5]}
    assert report["completed_original_calls"] == 1
    assert report["qualification_eligible"] is False


def test_partial_observations_and_original_failure_survive_cleanup_failure():
    fixture = Fixture(close_error=RuntimeError("cleanup"))
    original = ValueError("original operation")
    owner = producer(lambda *_args, **_kwargs: observation())

    def measure(session, _plan):
        owner.observe_priority_launcher(session, launcher(), sample=0)
        raise original

    owner.measure_priority_launchers = measure
    report = DRIVER.execute_block(fixture, owner)
    assert report["original_failure"]["category"] == "ValueError"
    assert report["cleanup_failure"]["category"] == "RuntimeError"
    assert report["completed_original_calls"] == 1
    assert report["producer_completed"] is False
    assert report["fixture_cleanup_returned"] is False
    assert fixture.enters == fixture.closes == 1


def test_failed_concurrent_tail_cannot_claim_complete_or_mutate_snapshot():
    entered, release = threading.Event(), threading.Event()
    fixture = Fixture()

    def original(*_args, **_kwargs):
        entered.set()
        assert release.wait(timeout=2)
        return observation()

    owner = producer(original)
    workers = []

    def measure(session, _plan):
        worker = threading.Thread(
            target=owner.observe_priority_launcher,
            args=(session, launcher()),
            kwargs={"sample": 1_000_000},
        )
        workers.append(worker)
        worker.start()
        assert entered.wait(timeout=2)
        raise ValueError("another original concurrent request failed")

    owner.measure_priority_launchers = measure
    try:
        report = DRIVER.execute_block(fixture, owner)
        assert report["producer_completed"] is False
        assert report["observation_complete"] is False
        assert report["completed_original_calls"] == 0
        assert report["observations"]["rows"] == []
        assert owner.observe_priority_launcher is original
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=2)
            assert not worker.is_alive()
    assert report["observations"]["rows"] == []
    assert report["completed_original_calls"] == 0


def test_startup_failure_is_retained_without_calling_producer_or_retrying():
    fixture = Fixture(enter_error=RuntimeError("startup"))
    calls = []
    owner = producer(
        lambda *_args, **_kwargs: observation(), lambda *_args: calls.append(True)
    )
    report = DRIVER.execute_block(fixture, owner)
    assert not calls
    assert fixture.enters == fixture.closes == 1
    assert report["original_failure"]["category"] == "RuntimeError"
    assert report["observations"]["rows"] == []


def test_source_rejects_changed_producer_without_touching_the_producer(
    tmp_path, monkeypatch
):
    calls = []

    def fake_git(_root, *args):
        calls.append(args)
        if args == ("rev-parse", "HEAD"):
            return "a" * 40
        if args == ("rev-parse", "HEAD^{tree}"):
            return "b" * 40
        if args[0] == "status":
            return ""
        return "different" if args[-1].startswith("HEAD:") else "original"

    monkeypatch.setattr(DRIVER, "git", fake_git)
    with pytest.raises(RuntimeError, match="producer_changed"):
        DRIVER.source_binding(tmp_path, "a" * 40, "b" * 40)
    assert len(calls) == 5


def test_manifest_limits_and_original_predeclared_order():
    assert DRIVER.PLAN == {"priority_per_run": 2, "cold_per_run": 2}
    assert DRIVER.ROUTES == (
        ("claude-code", "PreToolUse"),
        ("claude-code", "PostToolUse"),
        ("codex", "PreToolUse"),
        ("codex", "PostToolUse"),
    )
    assert DRIVER.BASELINE == "017f1244f1861bc4a74620a669557b78beb6d176"
    source = PATH.read_text()
    assert 'DaemonFixture(runtime, policy="normal")' in source
    assert "producer.measure_priority_launchers(session, dict(PLAN))" in source
    assert "run_isolated_hook_process(" not in source
    assert "ThreadPoolExecutor(" not in source


def run_bound(
    monkeypatch,
    tmp_path,
    *,
    after_error=False,
    authenticated="verified",
    completed_calls=88,
):
    args = SimpleNamespace(
        artifact="017f_baseline",
        output=tmp_path / "report.json",
        plan=tmp_path / "plan.json",
        source_root=tmp_path / "source",
        expected_source_sha="a" * 40,
        expected_source_tree="b" * 40,
        driver_root=tmp_path / "driver",
        expected_driver_sha="c" * 40,
        wheel=tmp_path / "wheel.whl",
    )
    monkeypatch.setattr(
        DRIVER,
        "sys",
        SimpleNamespace(
            flags=SimpleNamespace(isolated=True), platform="darwin", path=[]
        ),
    )
    monkeypatch.setattr(DRIVER, "platform", SimpleNamespace(machine=lambda: "arm64"))
    monkeypatch.setattr(DRIVER, "host_details", lambda: {"fixture_host": True})
    monkeypatch.setattr(DRIVER, "digest", lambda *_args: DRIVER.PLAN_SHA256)
    monkeypatch.setattr(
        DRIVER,
        "source_binding",
        lambda *_args: {"source_sha": "a" * 40, "tracked_clean": True},
    )
    monkeypatch.setattr(
        DRIVER, "git", lambda _root, *parts: "" if parts[0] == "status" else "c" * 40
    )
    bindings = []

    def installed(*_args):
        bindings.append(True)
        if after_error and len(bindings) == 2:
            raise OSError("identity after failed")
        return {"wheel_sha256": "d" * 64}, tmp_path / "runtime"

    monkeypatch.setattr(DRIVER, "installed_binding", installed)
    monkeypatch.setattr(
        DRIVER,
        "stop_evidence",
        lambda _path: {"status": "contained", "authenticated": authenticated},
    )
    block = {
        "producer_completed": True,
        "completed_original_calls": completed_calls,
        "observation_complete": True,
        "fixture_cleanup_returned": True,
        "direct_fixture_child_reaped": True,
        "fixture_reader_threads_stopped": True,
        "retained_proof": [1, 2, 3],
    }
    monkeypatch.setattr(DRIVER, "execute_block", lambda *_args: block)
    modules = {
        "scripts.native_slo_contract": SimpleNamespace(
            clear_proof_environment=lambda _env: ()
        ),
        "scripts.native_slo_priority_launchers": producer(lambda *_args: observation()),
        "scripts.native_slo_daemon_fixture": SimpleNamespace(
            DaemonFixture=lambda *_args, **_kwargs: object()
        ),
    }
    monkeypatch.setattr(DRIVER.importlib, "import_module", lambda name: modules[name])
    return DRIVER.run(args)


def test_after_identity_failure_retains_original_block_and_marks_incomplete(
    monkeypatch, tmp_path
):
    report = run_bound(monkeypatch, tmp_path, after_error=True)
    assert report["block"]["retained_proof"] == [1, 2, 3]
    assert report["installed_after_failure"]["category"] == "OSError"
    assert report["complete"] is False


@pytest.mark.parametrize(
    "authenticated,completed_calls,complete",
    [("verified", 88, True), ("unverified", 88, False), ("verified", 87, False)],
    ids=["complete", "stop-unverified", "missing-call"],
)
def test_complete_requires_exact_count_and_authenticated_cleanup(
    monkeypatch, tmp_path, authenticated, completed_calls, complete
):
    report = run_bound(
        monkeypatch,
        tmp_path,
        authenticated=authenticated,
        completed_calls=completed_calls,
    )
    assert report["complete"] is complete
    assert report["qualification_eligible"] is False
    assert report["original_sample_minima_met"] is False
    assert report["original_thresholds_ms"] == {
        "serial_p95": 50,
        "serial_p99": 100,
        "c16_p99": 200,
    }
