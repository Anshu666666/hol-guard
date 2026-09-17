from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_capacity_failure import CapacityWarmupFailureError
from scripts.native_slo_capacity_routes import capacity_route_evidence
from scripts.native_slo_failure import failure_evidence


def _failed():
    return capacity_route_evidence(
        [Observation("codex", "PreToolUse", "1k", 1.0, "pending_batch_validation", True)] * 2,
        attempted=2,
        errors=0,
        before={},
        after={"native_resident": 1, "native_fail_safe": 1},
        bookkeeping_complete=True,
        native_overloads=0,
    )


def test_failed_warmup_keeps_original_wave_proof_without_retry(monkeypatch):
    evidence = _failed()
    calls = []

    def wave(*args):
        calls.append(args)
        return [], 0, evidence

    monkeypatch.setattr(capacity, "_run_capacity_wave", wave)
    with pytest.raises(CapacityWarmupFailureError, match="RSS warmup route proof failed") as raised:
        capacity._prewarm_ready_hook_workers(SimpleNamespace(), (("codex", "PreToolUse"),), 2, object())
    assert len(calls) == 1
    report = failure_evidence(raised.value)
    assert report["schema"] == "hol-guard.native-qualification-failure.v1"
    assert report["counts"]["attempted"] == report["counts"]["completed"] == 2
    assert report["engine_routes"] == {"native_fail_safe": 1, "native_resident": 1}
    assert "resident_count_mismatch" in report["proof_failures"]
    assert report["per_request_native_route_proven"] is False
    assert report["qualification_complete"] is False
    assert json.loads(str(raised.value).split("proof failed: ", 1)[1])["engine_routes"] == report["engine_routes"]


def test_counter_corruption_cannot_publish_free_text_or_false_zero():
    evidence = replace(
        _failed(),
        attempted=True,
        errors=2**80,
        native_overloads=None,
        engine_routes={"private-value": 10, "native_resident": -1},
        failures=("private-value" * 1000,),
    )
    report = failure_evidence(CapacityWarmupFailureError(evidence, 2))
    assert report["counts"]["attempted"] is None
    assert report["counts"]["errors"] is None
    assert report["counts"]["native_overloads"] is None
    assert report["engine_routes"] == {"native_resident": None}
    assert report["proof_failures"] == ["other"]
    assert "private-value" not in json.dumps(report)
