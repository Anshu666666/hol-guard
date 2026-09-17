from __future__ import annotations

import json
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_session
from scripts.native_slo_adapter import Observation, route_delta
from scripts.native_slo_capacity import _run_capacity_wave
from scripts.native_slo_capacity_routes import capacity_route_evidence
from scripts.native_slo_capacity_witness import capacity_none_report
from scripts.native_slo_contract import assert_privacy_safe, sanitize_aggregate
from scripts.native_slo_reporting import SloMeasurements, slo_gates, slo_result, summarize_measurements


def _item(*, allowed=True, overloaded=False):
    return Observation("codex", "PreToolUse", "1k", 1.0, "pending_batch_validation", allowed, overloaded)


@pytest.mark.parametrize("transport_error", [False, True])
def test_overlapping_requests_keep_actual_wave_counts_without_individual_route_inference(
    tmp_path: Path, monkeypatch, transport_error
):
    lock = threading.Lock()
    entered = threading.Barrier(2, timeout=2)
    completed = threading.Barrier(2, timeout=2)
    counters = Counter(native_resident=17, native_fail_safe=4)

    def snapshot():
        with lock:
            return {"routes": dict(counters)}

    def request(_daemon, *, harness, **_kwargs):
        entered.wait()
        with lock:
            if harness == "codex":
                counters["native_resident"] += 1
            elif not transport_error:
                counters["native_fail_safe"] += 1
        completed.wait()
        if harness == "codex":
            return {"decision": "allow"}
        if transport_error:
            raise RuntimeError("bounded synthetic transport failure")
        return {"decision": "deny", "reason_code": "native_overloaded"}

    session = native_slo_session.AdapterSession.__new__(native_slo_session.AdapterSession)
    session.guard_home = session.workspace = tmp_path
    session._connection = None
    session._owner_thread_id = threading.get_ident()
    session.daemon = SimpleNamespace(
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=snapshot)),
            hook_capacity_lock=lock,
            active_hook_requests=0,
        )
    )
    monkeypatch.setattr(native_slo_session, "_request", request)
    overloads = iter((10, 10 + int(not transport_error)))
    monkeypatch.setattr(session, "native_overload_count", lambda: next(overloads))
    with ThreadPoolExecutor(max_workers=2) as executor:
        observations, errors, evidence = _run_capacity_wave(
            session,
            (("codex", "PreToolUse"), ("claude-code", "PreToolUse")),
            2,
            executor,
        )
    assert all(item.route == "pending_batch_validation" for item in observations)
    assert evidence.attempted == 2
    assert evidence.completed == len(observations) == 2 - int(transport_error)
    assert errors == evidence.errors == int(transport_error)
    assert evidence.delivered_allowed == 1
    assert evidence.qualifies(expected=2, allow_overload=True) is (not transport_error)
    if not transport_error:
        assert evidence.engine_routes == {"native_resident": 1, "native_fail_safe": 1}
        assert evidence.explicit_overloaded == 1
        assert evidence.report()["per_request_native_route_proven"] is False
        # The former per-request shared-counter logic calls this mixed wave a
        # fail-safe even for the independently delivered successful response.
        assert route_delta(Counter(native_resident=17, native_fail_safe=4), counters) == "native_fail_safe"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_resident",
        "extra_resident",
        "excess_fail_safe",
        "oneshot",
        "python",
        "unknown",
        "regression",
        "invalid_counter",
        "noncapacity_denial",
        "missing_completion",
        "exception",
        "unfinished_bookkeeping",
        "contradictory_response",
    ],
)
def test_wave_rejects_wrong_counters_and_unaccounted_failures(mutation):
    observations = [_item(), _item(allowed=False, overloaded=True)]
    before, after = {}, {"native_resident": 1, "native_fail_safe": 1}
    attempted, errors, complete = 2, 0, True
    if mutation == "missing_resident":
        after["native_resident"] = 0
    elif mutation == "extra_resident":
        after["native_resident"] = 2
    elif mutation == "excess_fail_safe":
        after["native_fail_safe"] = 2
    elif mutation in {"oneshot", "python", "unknown"}:
        after[{"oneshot": "native_oneshot", "python": "python_semantic", "unknown": "unexpected"}[mutation]] = 1
    elif mutation == "regression":
        before["native_resident"] = 2
    elif mutation == "invalid_counter":
        after["native_resident"] = True
    elif mutation == "noncapacity_denial":
        observations[1] = _item(allowed=False)
    elif mutation == "missing_completion":
        attempted = 3
    elif mutation == "exception":
        errors = 1
    elif mutation == "unfinished_bookkeeping":
        complete = False
    else:
        observations[1] = _item(allowed=True, overloaded=True)
    evidence = capacity_route_evidence(
        observations,
        attempted=attempted,
        errors=errors,
        before=before,
        after=after,
        bookkeeping_complete=complete,
        native_overloads=1,
    )
    assert evidence.failures
    assert not evidence.qualifies(expected=2, allow_overload=True)


def _measurements():
    c16 = [_item()] * 16
    c64 = [_item()] * 32 + [_item(allowed=False, overloaded=True)] * 32
    return SloMeasurements(
        warm=[replace(_item(), route="native_resident")],
        sizes=[],
        recovery=[1.0],
        cold=[1.0],
        concurrent_16=c16,
        concurrent_64=c64,
        errors_16=0,
        errors_64=0,
        readiness=[1.0],
        rss_baseline=100,
        rss_peak=100,
        native_overloads_16=0,
        native_overloads_64=16,
        routes_16=capacity_route_evidence(
            c16,
            attempted=16,
            errors=0,
            before={},
            after={"native_resident": 16},
            bookkeeping_complete=True,
            native_overloads=0,
        ),
        routes_64=capacity_route_evidence(
            c64,
            attempted=64,
            errors=0,
            before={},
            after={"native_resident": 32, "native_fail_safe": 16},
            bookkeeping_complete=True,
            native_overloads=16,
        ),
    )


def test_reporting_keeps_engine_counts_and_exact_capacity_denominators_separate():
    measurements = _measurements()
    summary = summarize_measurements(measurements)
    corpus = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summary, corpus, 1, include_capacity=True)
    assert gates["concurrency"] and gates["concurrency_64_bounded"]
    assert summary.route_counts == {"native_resident": 49, "native_fail_safe": 16, "engine_bypassed": 16}
    report = slo_result({}, (("codex", "PreToolUse"),), corpus, measurements, summary, gates)
    assert report["corpus"]["rss_scope"] == "in_process_driver_daemon_and_descendants"
    assert report["corpus"]["rss_metric"] == "sum_current_process_working_sets"
    assert report["corpus"]["rss_includes_load_generator"] is True
    wave = report["concurrency"]["sixty_four"]
    assert wave["fail_safe"] == 16 and wave["overloaded"] == 32
    assert wave["wave_evidence"]["attempted"] == wave["wave_evidence"]["completed"] == 64
    assert wave["wave_evidence"]["per_request_native_route_proven"] is False
    for changed in (
        replace(measurements, errors_16=1),
        replace(measurements, routes_16=None),
        replace(measurements, concurrent_16=measurements.concurrent_16[:-1]),
        replace(measurements, concurrent_16=[replace(item, latency_ms=2000) for item in measurements.concurrent_16]),
    ):
        assert not slo_gates(changed, summarize_measurements(changed), corpus, 1, include_capacity=True)["concurrency"]
    for changed in (
        replace(measurements, errors_64=1),
        replace(measurements, routes_64=None),
        replace(measurements, concurrent_64=measurements.concurrent_64[:-1]),
    ):
        assert not slo_gates(changed, summarize_measurements(changed), corpus, 1, include_capacity=True)[
            "concurrency_64_bounded"
        ]


def test_matching_native_health_cannot_reclassify_generic_denials_as_capacity():
    observations = [_item()] * 32 + [_item(allowed=False)] * 32
    evidence = capacity_route_evidence(
        observations,
        attempted=64,
        errors=0,
        before={},
        after={"native_resident": 32, "native_fail_safe": 32},
        bookkeeping_complete=True,
        native_overloads=32,
    )
    assert evidence.unclassified_responses == 32 and evidence.explicit_overloaded == 0
    assert not evidence.qualifies(expected=64, allow_overload=True)
    assert all(not item.overloaded and item.route == "pending_batch_validation" for item in observations)


@pytest.mark.parametrize("health", [None, True, -1, 0, 2])
def test_native_health_mismatch_stays_failed_evidence(health):
    evidence = capacity_route_evidence(
        [_item(allowed=False, overloaded=True)],
        attempted=1,
        errors=0,
        before={},
        after={"native_fail_safe": 1},
        bookkeeping_complete=True,
        native_overloads=health,
    )
    assert "native_overload_route_mismatch" in evidence.failures
    assert not evidence.qualifies(expected=1, allow_overload=True)


def test_report_does_not_qualify_one_observation_as_a_full_concurrency_wave():
    item = _item()
    one = capacity_route_evidence(
        [item],
        attempted=1,
        errors=0,
        before={},
        after={"native_resident": 1},
        bookkeeping_complete=True,
        native_overloads=0,
    )
    measurements = replace(
        _measurements(),
        concurrent_16=[item],
        concurrent_64=[item],
        routes_16=one,
        routes_64=one,
        native_overloads_16=0,
        native_overloads_64=0,
    )
    corpus = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summarize_measurements(measurements), corpus, 1, include_capacity=True)
    assert not gates["concurrency"] and not gates["concurrency_64_bounded"]


@pytest.mark.parametrize("wave,attribute", [("sixteen", "routes_16"), ("sixty_four", "routes_64")])
def test_final_slo_report_preserves_closed_none_records_without_weakening_privacy(wave, attribute):
    private = "private arbitrary request /fixture/body"
    record = {
        "harness": "codex",
        "event": "PostToolUse",
        "snapshot": "positive_generation",
        "deadline_remaining_after_ms": 17,
        "client_failure_before": "not_recorded",
        "client_failure_after": "native_client_timed_out",
        "payload": private,
    }
    diagnostic = {
        "supported": True,
        "incomplete": False,
        "none_returns_capped_at_65": 65,
        "records": [record] * 63
        + [{**record, "client_failure_after": private, "deadline_remaining_after_ms": True}, record],
        "arbitrary": private,
    }
    expected = capacity_none_report(diagnostic)
    # This is the actual former nesting, not a shallow helper-only check.
    old_shape = {"concurrency": {wave: {"wave_evidence": {"none_witness": expected}}}}
    prior = sanitize_aggregate(old_shape)["concurrency"][wave]["wave_evidence"]["none_witness"]
    assert set(prior["records"][0].values()) == {"truncated"}

    measurements = replace(_measurements(), errors_64=1)
    corpus = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    summary = summarize_measurements(measurements)
    gates = slo_gates(measurements, summary, corpus, 1, include_capacity=True)
    original = slo_result({}, (("codex", "PreToolUse"),), corpus, measurements, summary, gates)
    assert original["gates"]["concurrency_64_bounded"] is False
    assert "capacity_none_witnesses" not in original
    evidence = getattr(measurements, attribute)
    with_diagnostic = replace(evidence, none_witness=diagnostic)
    assert with_diagnostic.report()["none_witness"] == expected
    changed = replace(measurements, **{attribute: with_diagnostic})
    assert slo_gates(changed, summarize_measurements(changed), corpus, 1, include_capacity=True) == gates
    report = slo_result({}, (("codex", "PreToolUse"),), corpus, changed, summary, gates)
    assert "none_witness" not in report["concurrency"][wave]["wave_evidence"]
    assert report["capacity_none_witnesses"][wave] == expected
    assert expected["overflow"] is True and expected["incomplete"] is True
    assert expected["records_retained"] == 64
    assert expected["records"][-1]["client_failure_after"] == "other"
    assert expected["records"][-1]["deadline_remaining_after_ms"] is None
    assert expected["current_request_client_call_proven"] is False
    assert expected["per_request_native_route_proven"] is False
    assert json.loads(json.dumps(report)) == report
    assert assert_privacy_safe(report) == report
    assert private not in json.dumps(report)
    assert report.pop("capacity_none_witnesses") == {wave: expected}
    assert report == original  # All counters, original failed gates and other report fields are unchanged.
