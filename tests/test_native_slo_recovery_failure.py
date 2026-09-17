from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bench_guard_native_installed_slo as installed
from scripts import native_slo_daemon_fixture, native_slo_session, qualify_guard_native
from scripts.native_slo_adapter import Observation, observation_reason_code
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_numeric_journal import NumericJournal, recover_numeric_journal
from scripts.native_slo_recovery_failure import RecoveryFailureError


def _item(**changes: object) -> Observation:
    return replace(Observation("claude-code", "PostToolUse", "1k", 125.0, "native_resident", True), **changes)


@pytest.mark.parametrize("value", [None, {}, ["native_policy_not_ready"], "PRIVATE /home/person", "native_unknown"])
def test_unknown_response_reasons_never_enter_evidence(value: object) -> None:
    assert observation_reason_code({"reason_code": value}) == "other"


@pytest.mark.parametrize("latency", [float("nan"), float("inf"), -1, 60_001, True])
def test_failed_recovery_evidence_reconstructs_only_finite_fields(latency: float) -> None:
    error = RecoveryFailureError(
        1,
        _item(),
        _item(route="PRIVATE /home/person", reason_code="PRIVATE child response", latency_ms=latency),
    )
    evidence = failure_evidence(error)
    encoded = json.dumps(evidence, allow_nan=False)
    assert evidence["recovery"] == {
        "route": "unclassified",
        "delivered_allowed": True,
        "explicit_overload": False,
        "reason_code": "other",
        "latency_ms": None,
    }
    assert "PRIVATE" not in encoded + str(error)
    assert evidence["qualification_complete"] is False


def test_failed_recovery_keeps_original_observation_and_checkpoint_without_retry(tmp_path: Path, monkeypatch) -> None:
    calls = []
    observations = iter((_item(), _item(route="native_fail_safe", reason_code="native_policy_not_ready")))

    def observe(*_args):
        calls.append("observe")
        return next(observations)

    def stop():
        calls.append("stop")
        return True

    session = SimpleNamespace(observe=observe, stop_resident=stop)
    times = iter((1.0, 1.25))
    monkeypatch.setattr(installed.time, "perf_counter", lambda: next(times))
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal, pytest.raises(RecoveryFailureError) as raised:
        installed._run_recovery(session, 2, journal=journal)
    assert calls == ["observe", "stop", "observe"]
    report = failure_evidence(raised.value)
    assert report["sample_index"] == 0
    assert report["recovery"]["reason_code"] == "native_policy_not_ready"
    assert report["recovery"]["delivered_allowed"] is True
    assert "native_fail_safe" in str(raised.value)
    recovered = recover_numeric_journal(path)
    assert recovered["series"] == {"DAEMON_INGRESS.recovery": [250.0]}
    assert recovered["batches"][-1]["status"] == "failed"


def test_failed_worker_keeps_recovery_fields_through_actual_paired_export(tmp_path: Path, monkeypatch, capsys) -> None:
    failure = failure_evidence(
        RecoveryFailureError(1, _item(), _item(route="native_fail_safe", reason_code="native_policy_not_ready"))
    )
    completed = SimpleNamespace(
        returncode=1,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
        stdout=json.dumps(failure),
        stderr="PRIVATE child diagnostic",
    )
    monkeypatch.setattr(qualify_guard_native, "run_isolated_hook_process", lambda *_args, **_kwargs: completed)
    args = SimpleNamespace(
        baseline_python=tmp_path / "baseline-python",
        candidate_python=tmp_path / "candidate-python",
        baseline_artifact=None,
        candidate_artifact=None,
        runs=1,
        mode="smoke",
        output_dir=tmp_path / "reports",
        block_timeout_seconds=10,
    )
    with pytest.raises(RuntimeError, match="paired block failed"):
        qualify_guard_native._run_pair(args)
    report = json.loads((args.output_dir / "aggregate" / "incomplete.json").read_text())
    assert len(report["failed_blocks"]) == 2
    assert report["comparison_available"] is False
    for block in report["failed_blocks"]:
        assert block["schema"] == "hol-guard.native-qualification-failure.v1"
        assert block["sample_index"] == 1
        assert block["recovery"]["reason_code"] == "native_policy_not_ready"
        assert block["recovery"]["route"] == "native_fail_safe"
    assert "PRIVATE" not in capsys.readouterr().err


@pytest.mark.parametrize("isolated", [False, True])
def test_sessions_capture_reason_after_the_original_response_timer(tmp_path: Path, monkeypatch, isolated: bool) -> None:
    counters = {"native_resident": 0}
    response = {"decision": "allow", "reason_code": "native_policy_warning"}
    ticks = []

    def now():
        ticks.append(1)
        return 1.0 if len(ticks) == 1 else 1.125

    def request(*_args, **_kwargs):
        counters["native_resident"] += 1
        return response

    module = native_slo_daemon_fixture if isolated else native_slo_session
    cls = module.DaemonFixture if isolated else module.AdapterSession
    session = cls.__new__(cls)
    session.guard_home = session.workspace = tmp_path
    session._connection = None
    session._owner_thread_id = threading.get_ident()
    session.daemon = SimpleNamespace(
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {"routes": dict(counters)}))
        )
    )

    def reason(value):
        assert ticks == [1, 1]
        assert value is response
        return observation_reason_code(value)

    monkeypatch.setattr(module.time, "perf_counter", now)
    monkeypatch.setattr(module, "_request", request)
    monkeypatch.setattr(module, "observation_reason_code", reason)
    result = session.observe("claude-code", "PostToolUse", "1k")
    assert result.latency_ms == 125.0
    assert result.reason_code == "native_policy_warning"
    assert result.allowed is True
    assert result.route == "native_resident"
