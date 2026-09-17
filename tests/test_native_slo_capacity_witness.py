from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts import native_slo_capacity as capacity
from scripts import native_slo_capacity_witness as witness_module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_capacity_failure import CapacityWarmupFailureError
from scripts.native_slo_capacity_routes import capacity_route_evidence
from scripts.native_slo_capacity_witness import capacity_none_report, capacity_none_witness
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import failure_evidence


def test_parallel_none_observations_keep_context_local_and_preserve_calls(monkeypatch):
    codes: ContextVar[str] = ContextVar("test_capacity_code", default="not_recorded")
    monkeypatch.setattr(witness_module, "_client_failure", codes.get)
    monkeypatch.setattr(witness_module.time, "monotonic", lambda: 40.0)
    barrier = threading.Barrier(16, timeout=3)
    calls = []
    call_lock = threading.Lock()
    success = {"result": {"decision": "allow"}}
    arguments = [
        {
            "harness": "codex" if index % 2 else "claude-code",
            "event": "PreToolUse" if index % 2 else "PostToolUse",
            "policy_snapshot": {"generation": 1},
            "deadline": 40.5,
            "payload": {"index": index, "command": "must never be retained"},
        }
        for index in range(16)
    ]

    def original(**kwargs):
        with call_lock:
            calls.append(kwargs)
        barrier.wait()
        if kwargs["harness"] == "codex":
            codes.set("native_client_pool_exhausted")
            return None
        return success

    worker = SimpleNamespace(_review_raw_hook_native=original)
    other_worker = SimpleNamespace(_review_raw_hook_native=original)
    with capacity_none_witness(worker) as witness:
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(worker._review_raw_hook_native, **kwargs) for kwargs in arguments]
            results = [future.result() for future in futures]
        witness.finish(bookkeeping_complete=True)
    assert worker._review_raw_hook_native is original
    assert other_worker._review_raw_hook_native is original
    assert len(calls) == 16
    assert sorted(calls, key=lambda value: value["payload"]["index"]) == arguments
    assert all(result is (None if index % 2 else success) for index, result in enumerate(results))
    report = witness.report()
    assert report["records_retained"] == report["none_returns_capped_at_65"] == 8
    assert report["incomplete"] is False
    assert all(
        record
        == {
            "harness": "codex",
            "event": "PreToolUse",
            "snapshot": "positive_generation",
            "deadline_remaining_after_ms": 500,
            "client_failure_before": "not_recorded",
            "client_failure_after": "native_client_pool_exhausted",
            "client_context_changed": True,
        }
        for record in report["records"]
    )
    assert "must never be retained" not in json.dumps(report)
    assert report["current_request_client_call_proven"] is False
    assert report["per_request_native_route_proven"] is False
    assert_privacy_safe(report)


def test_stale_code_is_retained_without_clearing_or_claiming_current_cause(monkeypatch):
    codes: ContextVar[str] = ContextVar("test_stale_capacity_code", default="native_client_timed_out")
    monkeypatch.setattr(witness_module, "_client_failure", codes.get)
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: None)
    with capacity_none_witness(worker) as witness:
        assert worker._review_raw_hook_native(policy_snapshot=None) is None
        witness.finish(bookkeeping_complete=True)
    record = witness.report()["records"][0]
    assert codes.get() == "native_client_timed_out"
    assert record["client_failure_before"] == record["client_failure_after"] == codes.get()
    assert record["client_context_changed"] is False
    assert witness.report()["client_failure_scope"] == "thread_context_before_after_may_be_stale"


def test_original_exception_preserves_identity_and_restores_callable():
    failure = RuntimeError("original failure")

    def original(**_kwargs):
        raise failure

    worker = SimpleNamespace(_review_raw_hook_native=original)
    with pytest.raises(RuntimeError) as raised, capacity_none_witness(worker) as witness:
        worker._review_raw_hook_native()
    assert raised.value is failure
    assert worker._review_raw_hook_native is original
    assert witness.report()["records_retained"] == 0
    assert witness.report()["incomplete"] is True


def test_late_none_completion_cannot_change_frozen_incomplete_report():
    entered, finish = threading.Event(), threading.Event()

    def original(**_kwargs):
        entered.set()
        assert finish.wait(timeout=3)
        return None

    worker = SimpleNamespace(_review_raw_hook_native=original)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with capacity_none_witness(worker) as witness:
            future = executor.submit(worker._review_raw_hook_native)
            assert entered.wait(timeout=3)
            witness.finish(bookkeeping_complete=False)
        before = witness.report()
        finish.set()
        assert future.result() is None
    assert worker._review_raw_hook_native is original
    assert before["incomplete"] is True
    assert before == witness.report()


def test_more_than_64_none_returns_preserve_all_original_calls_and_mark_overflow():
    calls = []

    def original(**_kwargs):
        calls.append(None)
        return None

    worker = SimpleNamespace(_review_raw_hook_native=original)
    with capacity_none_witness(worker) as witness:
        for _ in range(70):
            assert worker._review_raw_hook_native() is None
        witness.finish(bookkeeping_complete=True)
    report = witness.report()
    assert len(calls) == 70
    assert report["records_retained"] == 64
    assert report["none_returns_capped_at_65"] == 65
    assert report["overflow"] is report["incomplete"] is True


@pytest.mark.parametrize("deadline", [None, True, float("nan"), float("inf"), -1.0, 2**100, 1e308])
def test_deadline_projection_is_bounded_without_replacing_original_none(deadline):
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: None)
    with capacity_none_witness(worker) as witness:
        assert worker._review_raw_hook_native(deadline=deadline, policy_snapshot={"generation": True}) is None
        witness.finish(bookkeeping_complete=True)
    record = witness.report()["records"][0]
    assert record["deadline_remaining_after_ms"] in {None, 0, 9_000}
    assert record["snapshot"] == "invalid_generation"


def test_projection_errors_do_not_replace_original_result(monkeypatch):
    def failed_clock():
        raise RuntimeError("diagnostic failure")

    monkeypatch.setattr(witness_module.time, "monotonic", failed_clock)
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: None)
    with capacity_none_witness(worker) as witness:
        assert worker._review_raw_hook_native(deadline=1.0) is None
        witness.finish(bookkeeping_complete=True)
    assert witness.report()["observer_error"] is witness.report()["incomplete"] is True
    assert witness.report()["none_returns_capped_at_65"] == 1
    assert witness.report()["records_retained"] == 0


def test_unsupported_worker_is_explicit_not_fabricated():
    worker = SimpleNamespace()
    with capacity_none_witness(worker) as witness:
        witness.finish(bookkeeping_complete=True)
    assert not hasattr(worker, "_review_raw_hook_native")
    assert witness.report()["supported"] is False
    assert witness.report()["incomplete"] is True


def _failed_evidence():
    return capacity_route_evidence(
        [Observation("codex", "PostToolUse", "1k", 1.0, "pending_batch_validation", True)],
        attempted=1,
        errors=0,
        before={},
        after={"native_fail_safe": 1},
        bookkeeping_complete=True,
        native_overloads=0,
    )


def test_public_diagnostic_projection_cannot_leak_arbitrary_fields_or_change_gate():
    bad = "private arbitrary request text"
    diagnostic = {
        "supported": True,
        "incomplete": False,
        "none_returns_capped_at_65": True,
        "records": [{"harness": bad, "event": bad, "client_failure_after": bad, "payload": bad}] * 65,
        "payload": bad,
    }
    original = _failed_evidence()
    changed = replace(original, none_witness=diagnostic)
    assert "none_witness" not in original.report()
    assert changed == original
    assert changed.failures == original.failures
    assert not changed.qualifies(expected=1, allow_overload=True)
    report = failure_evidence(CapacityWarmupFailureError(changed, 1))
    projected = report["none_witness"]
    assert projected == capacity_none_report(diagnostic)
    assert projected["overflow"] is True
    assert projected["records_retained"] == 64
    assert projected["none_returns_capped_at_65"] is None
    assert bad not in json.dumps(report)
    assert report["qualification_complete"] is False
    assert_privacy_safe(report)


def test_capacity_wave_keeps_witness_through_bookkeeping_without_extra_calls(monkeypatch):
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: None)
    original = worker._review_raw_hook_native
    idle_calls, snapshots, native_health = [], [], []

    def idle():
        idle_calls.append(True)
        if len(idle_calls) == 2:
            assert worker._review_raw_hook_native is not original
        return True

    def snapshot():
        snapshots.append(True)
        return {} if len(snapshots) == 1 else {"native_fail_safe": 1}

    def overloads():
        native_health.append(True)
        return 0

    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
        wait_for_capacity_bookkeeping=idle,
        capacity_route_snapshot=snapshot,
        native_overload_count=overloads,
    )

    def wave(*_args):
        assert worker._review_raw_hook_native(harness="codex", event="PostToolUse") is None
        return [Observation("codex", "PostToolUse", "1k", 1.0, "pending_batch_validation", True)], 0

    monkeypatch.setattr(capacity, "_run_concurrent", wave)
    _, errors, evidence = capacity._run_capacity_wave(session, (("codex", "PostToolUse"),), 1, object())
    assert errors == 0
    assert len(idle_calls) == len(snapshots) == len(native_health) == 2
    assert worker._review_raw_hook_native is original
    assert evidence.none_witness["records_retained"] == 1
    assert evidence.failures == _failed_evidence().failures
    assert not evidence.qualifies(expected=1, allow_overload=True)
