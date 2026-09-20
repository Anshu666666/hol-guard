"""Counter-boundary observations preserve every original caller operation."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from ci.native_runtime import admission_observation_values as values
from ci.native_runtime.admission_observation_capture import ROSTER, AdmissionCapture
from ci.native_runtime.default_auto_routes import _ownership_routes
from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler


def fixture(request: Any = None):
    metrics = HookMetricsRecorder()
    scheduler = RuntimeHookScheduler()
    server = SimpleNamespace(
        hook_worker=SimpleNamespace(metrics=metrics),
        runtime_hook_scheduler=scheduler,
        hook_capacity_lock=threading.Lock(),
        active_hook_requests=0,
        rejected_hook_requests=0,
        hook_harness_active={},
        hook_harness_rejected={},
    )
    daemon = SimpleNamespace(_server=server)
    probe: Any = ModuleType("original_probe")
    routes: Any = ModuleType("original_routes")
    token = object()
    calls = []
    probe.bind_corpus = lambda *args, **kwargs: token
    probe.observe_corpus = lambda *args, **kwargs: token
    probe.end_corpus = lambda *args, **kwargs: token

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        if request is not None:
            return request(*args, **kwargs)
        metrics.record_route("native_resident")
        return {"decision": "allow", "reason_code": "native_policy_warning"}

    routes._installed_hook_request = original
    return probe, routes, daemon, calls, token


def receipts(count=21):
    return {name: count if name in {"receipt_accepted", "receipt_processed"} else 0 for name in values._RECEIPTS}


def deliver(routes, daemon, index):
    harness, event = ROSTER[index]
    payload = {"private": "never exported"}
    return routes._installed_hook_request(
        daemon, Path("private-home"), Path("private-workspace"), harness, event, payload
    )


def test_roster_exactly_matches_original_ownership_routes():
    actual = []
    for harness, route in sorted(_ownership_routes().items()):
        for key, event in [("pre_tool_use", "PreToolUse"), ("post_tool_use", "PostToolUse")]:
            if route[key].startswith("installed_"):
                actual.append((harness, event))
    assert tuple(actual) == ROSTER and len(ROSTER) == 21


def test_all_original_calls_and_aggregate_snapshots_without_mode_population():
    probe, routes, daemon, calls, token = fixture()
    original = routes._installed_hook_request
    with AdmissionCapture(probe, routes) as capture:
        assert probe.bind_corpus(daemon) is token
        for index in range(21):
            assert deliver(routes, daemon, index)["decision"] == "allow"
        stats = daemon._server.hook_worker.metrics.snapshot()
        assert probe.observe_corpus(daemon, stats) is token
        # Original mode-invariant call forwards but cannot enter the 21-case record.
        deliver(routes, daemon, 0)
        assert probe.end_corpus(daemon, stats, receipts()) is token
    assert routes._installed_hook_request is original and len(calls) == 22
    report = capture.report()
    assert report["observation_complete"] and report["callbacks_restored"]
    assert len(report["deliveries"]) == 21 and report["extra_product_requests"] == 0
    assert report["original_worker_snapshot"]["routes"] == {"native_resident": 21}
    for index, row in enumerate(report["deliveries"]):
        assert row["before"]["metrics"]["values"]["routes"].get("native_resident", 0) == index
        assert row["after"]["metrics"]["values"]["routes"]["native_resident"] == index + 1
    assert "private" not in json.dumps(report)
    report["deliveries"].clear()
    assert len(capture.report()["deliveries"]) == 21


def test_exact_argument_and_return_object_forwarding():
    response = {"decision": "allow", "reason_code": "daemon_hook_deadline_exhausted", "observed_review_failure": True}
    probe, routes, daemon, calls, _ = fixture(lambda *args, **kwargs: response)
    payload = {"private": "original"}
    argv = (daemon, Path("home"), Path("workspace"), *ROSTER[0], payload)
    with AdmissionCapture(probe, routes) as capture:
        probe.bind_corpus(daemon)
        assert routes._installed_hook_request(*argv) is response
    assert len(calls) == 1 and all(actual is wanted for actual, wanted in zip(calls[0][0], argv, strict=True))
    row = capture.report()["deliveries"][0]["response"]
    assert row["reason_code"] == "daemon_hook_deadline_exhausted" and row["observed_review_failure"] is True


@pytest.mark.parametrize("error", [RuntimeError("private"), OSError(13, "private"), KeyboardInterrupt("private")])
def test_original_exception_identity_and_one_call(error):
    def request(*args, **kwargs):
        raise error

    probe, routes, daemon, calls, _ = fixture(request)
    with AdmissionCapture(probe, routes) as capture:
        probe.bind_corpus(daemon)
        with pytest.raises(type(error)) as caught:
            deliver(routes, daemon, 0)
        assert caught.value is error
    assert len(calls) == 1
    report = capture.report()
    assert report["deliveries"][0]["returned"] is False and not report["observation_complete"]
    assert "private" not in json.dumps(report)


def test_recording_failure_does_not_replace_return_or_invoke_extra_call():
    response = {"decision": "allow"}
    probe, routes, daemon, calls, _ = fixture(lambda *args, **kwargs: response)

    def broken(server):
        raise KeyboardInterrupt("private recorder")

    with AdmissionCapture(probe, routes, read_snapshot=broken) as capture:
        probe.bind_corpus(daemon)
        assert deliver(routes, daemon, 0) is response
    assert len(calls) == 1 and capture.report()["faults"] == ["capture_failed"]


def test_existing_scheduler_deadline_rejection_is_observed_without_another_acquire():
    _, _, daemon, calls, _ = fixture()
    server = daemon._server
    before: Any = values.snapshot(server)
    admission = server.runtime_hook_scheduler.acquire(
        harness="omp", client_key="private", lane="content-security", payload_bytes=1, deadline=0.0
    )
    assert admission.permit is None and admission.reason_code == "daemon_hook_deadline_exhausted"
    with server.hook_capacity_lock:
        server.rejected_hook_requests += 1
        server.hook_harness_rejected["omp"] = 1
    after: Any = values.snapshot(server)
    assert before["scheduler"]["values"]["rejected"] == {}
    assert after["scheduler"]["values"]["rejected"] == {"daemon_hook_deadline_exhausted": 1}
    assert after["admission"]["values"]["per_harness_rejected"] == {"omp": 1}
    assert after["metrics"]["values"]["routes"] == {} and not calls
    assert "private" not in json.dumps(after)


def test_busy_lock_is_nonblocking_and_remains_owned():
    _, _, daemon, _, _ = fixture()
    lock = daemon._server.hook_worker.metrics._lock
    with lock:
        result = values.snapshot(daemon._server)
        assert result["metrics"] == {"available": False, "reason": "lock_busy"}
        assert not lock.acquire(blocking=False)
    assert not values.complete_snapshot(result)


@pytest.mark.parametrize("value", [True, -1, 2**63, "private", object()])
def test_illegal_counter_values_are_unavailable_without_retaining_them(value):
    _, _, daemon, _, _ = fixture()
    daemon._server.runtime_hook_scheduler._admitted = value
    result = values.snapshot(daemon._server)
    assert result["scheduler"] == {"available": False, "reason": "counter_projection_failed"}
    assert "private" not in json.dumps(result)
    assert daemon._server.runtime_hook_scheduler._condition.acquire(blocking=False)
    daemon._server.runtime_hook_scheduler._condition.release()


def test_unknown_response_objects_and_keys_cannot_export_or_execute_hooks():
    class Private:
        def __str__(self):
            raise AssertionError("unexpected conversion")

        def __eq__(self, other):
            raise AssertionError("unexpected equality")

        def __hash__(self):
            raise AssertionError("unexpected hash")

    report = values.response(
        {"reason_code": Private(), "decision": Private(), "observed_review_failure": Private(), "secret": "private"}
    )
    assert report["reason_code"] is None and report["reason_code_unknown"]
    assert report["decision_unknown"] and report["observed_review_failure_invalid"]
    assert "private" not in json.dumps(report)


def test_failure_stage_buckets_omit_original_exception_names():
    result = values.failures({"failure:server:PrivateCustomerException": 2, "decision:private": 9})
    assert result == {"engine": 0, "metrics": 0, "server": 2, "unknown": 0}
    assert "Private" not in json.dumps(result)


def test_wrong_order_overflow_and_unrelated_later_alias_remain_failed():
    probe, routes, daemon, calls, _ = fixture()
    with AdmissionCapture(probe, routes) as capture:
        probe.bind_corpus(daemon)
        deliver(routes, daemon, 1)
        for index in range(21):
            deliver(routes, daemon, index)
        deliver(routes, daemon, 0)

        def later(*args, **kwargs):
            return None

        routes._installed_hook_request = later
    assert len(calls) == 23 and routes._installed_hook_request is later
    assert set(capture.report()["faults"]) == {"delivery_contract_changed", "delivery_overflow", "alias_ownership_lost"}
    assert not capture.report()["callbacks_restored"]


def test_partial_alias_install_preserves_original_exception_and_restores_prior_slots():
    probe, routes, _, calls, _ = fixture()
    original_bind = probe.bind_corpus
    original_request = routes._installed_hook_request
    error = RuntimeError("original install failure")

    class Refuse(ModuleType):
        def __setattr__(self, name, value):
            if name == "observe_corpus" and getattr(self, "refuse", False):
                raise error
            super().__setattr__(name, value)

    probe.__class__ = Refuse
    probe.refuse = True
    capture = AdmissionCapture(probe, routes)
    with pytest.raises(RuntimeError) as caught:
        capture.__enter__()
    assert caught.value is error
    assert probe.bind_corpus is original_bind and routes._installed_hook_request is original_request and not calls


def test_original_boundary_callback_error_is_not_replaced():
    probe, routes, daemon, _, _ = fixture()
    error = RuntimeError("private end failure")

    def end(*args, **kwargs):
        raise error

    probe.end_corpus = end
    with AdmissionCapture(probe, routes) as capture:
        probe.bind_corpus(daemon)
        with pytest.raises(RuntimeError) as caught:
            probe.end_corpus(daemon, {}, receipts(0))
        assert caught.value is error
    assert capture.report()["original_receipt_snapshot"] == receipts(0)
    assert not capture.report()["observation_complete"]


@pytest.mark.parametrize("busy_sample", [0, 1, 2, 42])
def test_any_busy_boundary_prevents_complete_full_corpus(busy_sample):
    probe, routes, daemon, calls, _ = fixture()
    samples = 0

    def sample(server):
        nonlocal samples
        index = samples
        samples += 1
        if index == busy_sample:
            with server.hook_worker.metrics._lock:
                return values.snapshot(server)
        return values.snapshot(server)

    with AdmissionCapture(probe, routes, read_snapshot=sample) as capture:
        probe.bind_corpus(daemon)
        for index in range(21):
            deliver(routes, daemon, index)
        stats = daemon._server.hook_worker.metrics.snapshot()
        probe.observe_corpus(daemon, stats)
        probe.end_corpus(daemon, stats, receipts())
    report = capture.report()
    assert len(calls) == 21 and len(report["deliveries"]) == 21 and samples == 43
    assert report["faults"] == ["snapshot_incomplete"] and not report["observation_complete"]


@pytest.mark.parametrize("fail_original", [False, True])
def test_snapshot_release_failure_cannot_replace_original_result_or_exception(fail_original):
    error = KeyboardInterrupt("private original")
    result = {"decision": "allow"}

    def original(*args, **kwargs):
        if fail_original:
            raise error
        return result

    class ReleaseFailure:
        def acquire(self, *, blocking):
            assert blocking is False
            return True

        def release(self):
            raise RuntimeError("private release")

    probe, routes, daemon, calls, _ = fixture(original)
    daemon._server.hook_worker.metrics._lock = ReleaseFailure()
    with AdmissionCapture(probe, routes) as capture:
        probe.bind_corpus(daemon)
        if fail_original:
            with pytest.raises(KeyboardInterrupt) as caught:
                deliver(routes, daemon, 0)
            assert caught.value is error
        else:
            assert deliver(routes, daemon, 0) is result
    assert len(calls) == 1 and capture.report()["faults"] == ["capture_failed"]
    assert not capture.report()["observation_complete"]


def test_dictionary_subclass_cannot_run_projection_overrides():
    class Hostile(dict[str, object]):
        def items(self):
            raise AssertionError("private callback")

        def __len__(self):
            raise AssertionError("private callback")

    with pytest.raises(ValueError, match="admission_counter_map_invalid"):
        values.counts(Hostile(), values._ROUTES)
    with pytest.raises(ValueError, match="admission_metric_map_invalid"):
        values.failures(Hostile())
