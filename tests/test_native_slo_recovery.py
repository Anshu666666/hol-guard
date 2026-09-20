from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import scripts.bench_guard_native_installed_slo as benchmark
from scripts import native_slo_session as session_module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_capacity import CapacityMeasurements
from scripts.native_slo_contract import MAX_INSTALLED_ADAPTER_P95_MS, all_gates_pass
from scripts.native_slo_reporting import SloMeasurements, slo_gates, slo_result, summarize_measurements
from scripts.native_slo_session import AdapterSession, NativeStopResult


class _RecoverySession:
    def __init__(self, *, allowed: bool = True, route: str = "native_resident") -> None:
        self.events: list[str] = []
        self._allowed = allowed
        self._route = route
        self._stopped = False

    def observe(self, harness: str, event: str, size_class: str) -> Observation:
        self.events.append("observe")
        return Observation(
            harness,
            event,
            size_class,
            1.0,
            self._route if self._stopped else "native_resident",
            self._allowed if self._stopped else True,
        )

    def stop_resident(self, *, preserve_clients: bool = False) -> bool:
        assert preserve_clients
        self.events.append("stop")
        self._stopped = True
        return True

    def rearm_policy_after_resident_stop(self) -> None:
        self.events.append("rearm")


def test_recovery_requires_the_first_post_stop_request_without_rearm() -> None:
    session = _RecoverySession()

    assert len(benchmark._run_recovery(session, 1)) == 1

    assert session.events == ["observe", "stop", "observe"]


def test_explicit_rearm_stays_inside_the_recovery_measurement(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1.0]

    class TimedSession(_RecoverySession):
        def rearm_policy_after_resident_stop(self) -> None:
            super().rearm_policy_after_resident_stop()
            clock[0] += 0.080

        def observe(self, harness: str, event: str, size_class: str) -> Observation:
            if self._stopped:
                clock[0] += 0.020
            return super().observe(harness, event, size_class)

    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: clock[0])
    session = TimedSession()

    assert benchmark._run_recovery(session, 1, rearm_policy=True) == pytest.approx([100.0])
    assert session.events == ["observe", "stop", "rearm", "observe"]


@pytest.mark.parametrize("rearm_policy", [False, True])
@pytest.mark.parametrize(
    ("allowed", "route"),
    [(False, "native_resident"), (False, "native_fail_safe"), (True, "native_oneshot"), (True, "python_semantic")],
)
def test_recovery_never_replaces_a_failed_first_request(rearm_policy: bool, allowed: bool, route: str) -> None:
    session = _RecoverySession(allowed=allowed, route=route)

    with pytest.raises(RuntimeError, match="recovery sample 0 failed"):
        benchmark._run_recovery(session, 3, rearm_policy=rearm_policy)

    assert session.events == ["observe", "stop", *(["rearm"] if rearm_policy else []), "observe"]


def _measurements(recovery: list[float], rearmed: list[float]) -> SloMeasurements:
    observation = Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)
    return SloMeasurements(
        warm=[observation],
        sizes=[
            Observation("codex", "PostToolUse", size, 1.0, "native_resident", True) for size in ("250k", "1m", "5m")
        ],
        recovery=recovery,
        rearmed_recovery=rearmed,
        cold=[1.0],
        concurrent_16=[observation],
        concurrent_64=[observation],
        errors_16=0,
        errors_64=0,
        readiness=[1.0],
        rss_baseline=1,
        rss_peak=1,
    )


@pytest.mark.parametrize(
    ("recovery", "rearmed", "expected"),
    [
        ([1000.0], [1000.0], True),
        ([1000.01], [1.0], False),
        ([1.0], [1000.01], False),
        ([], [1.0], False),
        ([1.0], [], False),
    ],
)
def test_recovery_gates_require_both_cases_with_the_original_budget(
    recovery: list[float], rearmed: list[float], expected: bool
) -> None:
    measurements = _measurements(recovery, rearmed)
    summary = summarize_measurements(measurements)
    installed = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summary, installed, 1, include_capacity=True)

    assert MAX_INSTALLED_ADAPTER_P95_MS == 1000.0
    assert all_gates_pass(gates) is expected
    assert gates["recovery_latency"] == (bool(recovery) and max(recovery) <= 1000.0)
    assert gates["rearmed_recovery_latency"] == (bool(rearmed) and max(rearmed) <= 1000.0)


def test_report_distinguishes_autonomous_and_rearmed_recovery() -> None:
    measurements = _measurements([12.0], [34.0])
    summary = summarize_measurements(measurements)
    installed = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summary, installed, 1, include_capacity=True)

    report = slo_result({}, (("codex", "PostToolUse"),), installed, measurements, summary, gates)

    assert report["passed"] is True
    latency = report["latency"]
    assert isinstance(latency, dict)
    assert latency["resident_recovery"]["p95_ms"] == 12.0
    assert latency["resident_recovery_rearmed"]["p95_ms"] == 34.0


def test_benchmark_keeps_autonomous_and_rearmed_sessions_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions: list[_RecoverySession] = []

    class Session(_RecoverySession):
        def __init__(self, runtime: Path) -> None:
            del runtime
            super().__init__()
            self.readiness_ms = 1.0
            sessions.append(self)

        def __enter__(self) -> Session:
            return self

        def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
            pass

    monkeypatch.setattr(benchmark, "AdapterSession", Session)
    monkeypatch.setattr(benchmark, "_run_cold", lambda *_args: [1.0])
    monkeypatch.setattr(benchmark, "_run_warm", lambda *_args: [])
    monkeypatch.setattr(benchmark, "_run_sizes", lambda *_args: [])
    monkeypatch.setattr(
        benchmark, "measure_capacity", lambda *_args, **_kwargs: CapacityMeasurements([], [], 0, 0, 1, 1)
    )
    monkeypatch.setattr(benchmark, "process_rss_bytes", lambda: 1)

    measurements = benchmark._measure_slo(
        Path("synthetic-runtime"),
        (("codex", "PostToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )

    assert len(sessions) == 3
    assert sessions[1].events == ["observe", "stop", "observe", "observe"]
    assert sessions[2].events == ["observe", "stop", "rearm", "observe"]
    assert len(measurements.recovery) == len(measurements.rearmed_recovery) == 1
    assert [report["mode"] for report in measurements.recovery_diagnostics] == ["autonomous", "explicitly_rearmed"]


@pytest.mark.parametrize("allowed,route", [(True, "native_fail_safe"), (False, "native_resident")])
@pytest.mark.parametrize("error", ["native_policy_snapshot_resident_changed", "private-untrusted-error"])
def test_failed_serialized_warmup_logs_bounded_state_and_still_fails_once(
    capsys: pytest.CaptureFixture[str], allowed: bool, route: str, error: str
) -> None:
    calls: list[tuple[str, str, str]] = []

    def observe(harness: str, event: str, size: str) -> Observation:
        calls.append((harness, event, size))
        return Observation(harness, event, size, 123.4567, route, allowed)

    publisher = SimpleNamespace(last_error=error, current_snapshot_binding=lambda: None)
    session = cast(
        AdapterSession,
        cast(
            object,
            SimpleNamespace(
                observe=observe,
                daemon=SimpleNamespace(
                    _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
                ),
            ),
        ),
    )
    with pytest.raises(RuntimeError, match="serialized resident pool warmup"):
        benchmark._run_serialized_warmup(session, "claude-code", "PreToolUse")
    assert calls == [("claude-code", "PreToolUse", "1k")]
    output = capsys.readouterr().err
    diagnostic = json.loads(output)
    assert diagnostic["route"] == route
    assert diagnostic["allowed"] is allowed
    assert diagnostic["adapter_ms"] == 123.457
    assert diagnostic["publisher_ready"] is False
    assert diagnostic["policy_generation"] is None
    assert diagnostic["publisher_error"] == (error if error == "native_policy_snapshot_resident_changed" else None)
    assert "private-untrusted-error" not in output


def test_allowed_serialized_warmup_keeps_one_request_without_diagnostic(capsys: pytest.CaptureFixture[str]) -> None:
    calls: list[str] = []

    def observe(harness: str, event: str, size: str) -> Observation:
        calls.append(harness)
        return Observation(harness, event, size, 100, "native_resident", True)

    benchmark._run_serialized_warmup(
        cast(AdapterSession, cast(object, SimpleNamespace(observe=observe))), "claude-code", "PreToolUse"
    )
    assert calls == ["claude-code"]
    assert not capsys.readouterr().err


@pytest.mark.parametrize("preserve_clients", [False, True])
@pytest.mark.parametrize("contained", [False, True])
def test_resident_stop_always_verifies_containment_before_optional_client_teardown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preserve_clients: bool, contained: bool
) -> None:
    calls: list[str] = []

    def stop(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert command[1] == "resident-stop"
        calls.append("verify-resident-stop")
        return subprocess.CompletedProcess(command, 0 if contained else 1, b"", b"native_resident_stop_timeout")

    monkeypatch.setattr(session_module, "_resident_state_may_exist", lambda _path: True)
    monkeypatch.setattr(session_module.subprocess, "run", stop)
    monkeypatch.setattr(session_module, "close_native_resident_clients", lambda _home: calls.append("close-clients"))

    result = session_module.stop_native_resident(
        tmp_path / "runtime", tmp_path / "guard-home", preserve_clients=preserve_clients, write_diagnostic=False
    )

    assert bool(result) is contained
    assert calls == ["verify-resident-stop"] + (["close-clients"] if contained and not preserve_clients else [])


@pytest.mark.parametrize("preserve_clients", [False, True])
def test_session_retains_serving_worker_clients_only_when_recovery_requested(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preserve_clients: bool
) -> None:
    calls: list[str] = []

    def stop(_runtime: Path, _home: Path, **kwargs: object) -> NativeStopResult:
        assert kwargs == {"preserve_clients": preserve_clients}
        calls.append("contained")
        return NativeStopResult(True, {"status": "contained"})

    def close_clients() -> bool:
        calls.append("close-worker-clients")
        return True

    session = cast(
        AdapterSession,
        cast(
            object,
            SimpleNamespace(
                runtime=tmp_path / "runtime",
                guard_home=tmp_path,
                daemon=SimpleNamespace(
                    _server=SimpleNamespace(
                        hook_process_runner=SimpleNamespace(close_native_resident_clients=close_clients)
                    )
                ),
            ),
        ),
    )
    monkeypatch.setattr(session_module, "stop_native_resident", stop)

    assert AdapterSession.stop_resident(session, preserve_clients=preserve_clients)
    assert calls == ["contained"] + ([] if preserve_clients else ["close-worker-clients"])


def test_both_recovery_samples_keep_complete_request_timing_and_original_deadline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    clock = [0.0]
    stopped = [False]
    durations = iter((0.125, 1.031575))
    calls: list[str] = []

    def observe(_harness: str, _event: str, _size: str) -> Observation:
        recovering = stopped[0]
        stopped[0] = False
        duration = next(durations) if recovering else 0.1
        clock[0] += duration
        calls.append("recover" if recovering else "warm")
        # Keep the enclosing measurement authoritative even if adapter-only
        # timing omits a little bookkeeping from AdapterSession.observe.
        return Observation("claude-code", "PostToolUse", "1k", duration * 1000 - 2, "native_resident", True)

    def stop_resident(*, preserve_clients: bool = False) -> bool:
        assert preserve_clients
        stopped[0] = True
        calls.append("contained-stop-with-clients")
        clock[0] += 0.4
        return True

    session = cast(AdapterSession, cast(object, SimpleNamespace(observe=observe, stop_resident=stop_resident)))
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: clock[0])

    values = benchmark._run_recovery(session, 2)

    assert values == pytest.approx([125.0, 1031.575])
    assert calls == ["warm", "contained-stop-with-clients", "recover"] * 2
    diagnostics = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.startswith("{")]
    assert [item["sample"] for item in diagnostics] == [0, 1]
    assert [item["elapsed_ms"] for item in diagnostics] == pytest.approx(values)
    assert [item["adapter_ms"] for item in diagnostics] == pytest.approx([123.0, 1029.575])
    measurements = SloMeasurements(
        warm=[],
        sizes=[],
        recovery=values,
        cold=[],
        concurrent_16=[],
        concurrent_64=[],
        errors_16=0,
        errors_64=0,
        readiness=[],
        rss_baseline=1,
        rss_peak=1,
    )
    gates = slo_gates(
        measurements,
        summarize_measurements(measurements),
        {"routes": 0, "resident": 0, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0},
        0,
        include_capacity=False,
    )
    assert not gates["recovery_latency"]


def test_uncontained_stop_cannot_produce_a_recovery_sample() -> None:
    calls: list[str] = []

    def observe(*_args: object) -> Observation:
        calls.append("observe")
        return Observation("claude-code", "PostToolUse", "1k", 1.0, "native_resident", True)

    session = cast(
        AdapterSession, cast(object, SimpleNamespace(observe=observe, stop_resident=lambda **_kwargs: False))
    )
    with pytest.raises(RuntimeError, match="resident stop failed during recovery sample 0"):
        benchmark._run_recovery(session, 2)
    assert calls == ["observe"]


@pytest.mark.parametrize("stage", ["warm", "recovery"])
@pytest.mark.parametrize("failure", ["denied", "oneshot"])
def test_recovery_requires_resident_allow_before_and_after_verified_stop(stage: str, failure: str) -> None:
    calls: list[str] = []

    def observe(*_args: object) -> Observation:
        invalid = stage == "warm" or bool(calls)
        calls.append("observe")
        route = "native_oneshot" if invalid and failure == "oneshot" else "native_resident"
        allowed = not (invalid and failure == "denied")
        return Observation("claude-code", "PostToolUse", "1k", 1.0, route, allowed)

    def stop(*, preserve_clients: bool = False) -> bool:
        assert preserve_clients
        calls.append("stop")
        return True

    session = cast(AdapterSession, cast(object, SimpleNamespace(observe=observe, stop_resident=stop)))
    with pytest.raises(RuntimeError, match="recovery sample 0"):
        benchmark._run_recovery(session, 2)
    assert calls == (["observe"] if stage == "warm" else ["observe", "stop", "observe"])
