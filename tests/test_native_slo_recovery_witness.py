"""Keep failure stages from the original recovery attempt, with no retry."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_edge as bridge
from scripts import bench_guard_native_installed_slo as installed
from scripts import native_slo_recovery_witness as module
from scripts import native_slo_session
from scripts.native_slo_adapter import Observation
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_numeric_journal import NumericBatch, NumericJournal, recover_numeric_journal
from scripts.native_slo_recovery_failure import RecoveryFailureError


def _session(tmp_path, original):
    worker = SimpleNamespace(_review_raw_hook_native=original)
    return SimpleNamespace(
        guard_home=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
    ), worker


def _kwargs(tmp_path):
    return dict(
        payload={"tool_output": "PRIVATE original data"},
        harness="claude-code",
        event="PostToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=11.0,
        policy_snapshot={"generation": 1},
    )


@pytest.mark.parametrize("failure", ["client", "status"])
def test_failed_recovery_uses_original_bridge_and_freezes_before_journal(tmp_path, monkeypatch, failure):
    calls = []
    kwargs = _kwargs(tmp_path)
    status = SimpleNamespace(
        mode="auto",
        available=failure != "status",
        compatible=True,
        reason="native_ready" if failure != "status" else "native_unavailable",
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="c" * 64),
        capabilities=SimpleNamespace(features=("hook-envelope-v2", "native-resident-client-v1")),
    )

    def client(**sent):
        calls.append("client")
        assert json.loads(sent["payload"])["raw_payload"] == kwargs["payload"]
        assert sent["deadline_monotonic"] == kwargs["deadline"]
        return None

    def original(**received):
        calls.append("edge")
        assert all(received[key] is value for key, value in kwargs.items())
        return bridge.review_raw_hook_native(**received)

    def observe(*args):
        assert args == ("claude-code", "PostToolUse", "1k")
        if not calls:
            calls.append("preparation")
            return Observation(*args, 100.0, "native_resident", True)
        calls.append("recovery")
        assert worker._review_raw_hook_native(**kwargs) is None
        return Observation(*args, 1100.0, "native_fail_safe", True, reason_code="native_post_tool_unavailable")

    session, worker = _session(tmp_path, original)
    session.observe = observe
    session.stop_resident = lambda: calls.append("stop") or True
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: calls.append("status") or status)
    monkeypatch.setattr(bridge, "native_resident_client_request", client)
    monkeypatch.setattr(bridge, "native_record_resident_failure", lambda *_args, **_kwargs: calls.append("failure"))
    monkeypatch.setattr(bridge, "record_native_hook_result", lambda _route, result: result)
    failures = iter(("not_recorded", "native_client_timed_out"))
    monkeypatch.setattr(module, "_client_failure", lambda: next(failures))
    native_ticks = iter((10.0, 11.1))
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(native_ticks)))
    outer_ticks = iter((1.0, 2.2))
    monkeypatch.setattr(installed, "time", SimpleNamespace(perf_counter=lambda: next(outer_ticks)))
    record = NumericBatch.record

    def persist(self, values):
        calls.append("journal")
        record(self, values)

    monkeypatch.setattr(NumericBatch, "record", persist)
    path = tmp_path / "numeric.jsonl"
    with NumericJournal(path) as journal, pytest.raises(RecoveryFailureError) as raised:
        installed._run_recovery(session, 2, journal=journal)
    expected = ["preparation", "stop", "recovery", "edge", "status"]
    assert calls == expected + (["client", "failure"] if failure == "client" else []) + ["journal"]
    assert worker._review_raw_hook_native is original
    report = failure_evidence(raised.value)
    witness = report["original_request"]
    assert witness["observer_state"] == "available"
    assert witness["observe_elapsed_ms"] == 1200.0
    assert witness["capture_boundary"] == "original_observe_return"
    assert witness["client_failure_scope"] == "thread_context_before_after_may_be_stale"
    assert witness["calls_capped_at_two"] == 1
    assert witness["additional_calls_observed"] is False
    observed = witness["observations"][0]
    assert observed["completion"] == "returned"
    assert observed["native_return"] == "none"
    assert observed["expected_hook"] is observed["fixture_binding"] is observed["keyword_call"] is True
    assert observed["native_elapsed_ms"] == 1100.0
    assert observed["deadline_remaining_ms"] == 1000.0
    assert observed["deadline_exhausted_before"] is False and observed["deadline_exhausted_after"] is True
    assert observed["client_failure_before"] == "not_recorded"
    assert observed["client_failure_after"] == "native_client_timed_out"
    stages = observed["bridge"]
    assert stages["calls_capped_at_two"]["status"] == 1
    assert stages["calls_capped_at_two"]["client"] == (1 if failure == "client" else 0)
    assert stages["client_reply"] == ("none" if failure == "client" else "not_observed")
    assert "PRIVATE" not in json.dumps(report, allow_nan=False) + str(raised.value)
    assert recover_numeric_journal(path)["series"] == {"DAEMON_INGRESS.recovery": [pytest.approx(1200.0)]}


def test_unsupported_fixture_is_explicit_and_original_observe_exception_is_preserved(tmp_path):
    with module.recovery_request_witness(object()) as witness:
        report = witness.report(1.0)
    assert report["observer_state"] == "fixture_unsupported"
    assert report["calls_capped_at_two"] is None

    error = OSError("PRIVATE original failure")

    def original(*args, **kwargs):
        assert args == ("original",) and kwargs == {"argument": "PRIVATE"}
        raise error

    session, worker = _session(tmp_path, original)
    with pytest.raises(OSError) as raised, module.recovery_request_witness(session) as witness:
        worker._review_raw_hook_native("original", argument="PRIVATE")
    assert raised.value is error
    assert worker._review_raw_hook_native is original
    report = witness.report(None)
    assert report["observations"][0]["completion"] == "raised"
    assert report["observations"][0]["exception_category"] == "OSError"
    assert report["raised_observe_export"] == "unavailable_original_exception_preserved"
    assert "PRIVATE" not in json.dumps(report)


def test_report_does_not_wait_for_or_rewrite_inflight_original_call(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    sentinel = object()
    returned = []

    def original(**_kwargs):
        entered.set()
        assert release.wait(5)
        return sentinel

    session, worker = _session(tmp_path, original)
    with module.recovery_request_witness(session) as witness:
        thread = threading.Thread(target=lambda: returned.append(worker._review_raw_hook_native(**_kwargs(tmp_path))))
        thread.start()
        try:
            assert entered.wait(5)
            report = witness.report(123.0)
            assert report["observations"][0]["completion"] == "entered"
            assert report["observations"][0]["native_elapsed_ms"] is None
            assert report["observations"][0]["native_return"] == "not_observed"
            assert report["observations"][0]["bridge"] == {
                "observer_state": "in_flight_unavailable",
                "calls_capped_at_two": None,
            }
        finally:
            release.set()
            thread.join(5)
    assert returned == [sentinel]
    assert witness.report(999.0) == report
    assert worker._review_raw_hook_native is original


def test_witness_bounds_calls_and_preserves_success_objects(tmp_path):
    sentinel = object()
    calls = []

    def original(**kwargs):
        calls.append(kwargs)
        return sentinel

    session, worker = _session(tmp_path, original)
    kwargs = _kwargs(tmp_path)
    with module.recovery_request_witness(session) as witness:
        for _ in range(3):
            assert worker._review_raw_hook_native(**kwargs) is sentinel
        report = witness.report(float("nan"))
    assert len(calls) == 3
    assert report["calls_capped_at_two"] == 2
    assert report["additional_calls_observed"] is True
    assert report["observe_elapsed_ms"] is None
    assert worker._review_raw_hook_native is original


def test_prior_stop_is_bound_before_later_cleanup_without_extra_stop_calls(tmp_path):
    session, _ = _session(tmp_path, lambda **_kwargs: None)
    session.last_stop_diagnostic = {
        "status": "contained_client_cleanup_failed",
        "client_cleanup": "failed",
        "acknowledged": "true",
        "authenticated": "true",
        "owner_lock": "free",
        "marker_lock": "PRIVATE /home/person",
        "endpoint": "absent",
        "unexpected": "PRIVATE",
    }
    with module.recovery_request_witness(session) as witness:
        session.last_stop_diagnostic = {"status": "already-stopped"}
        report = witness.report(1000.0)
    stop = report["prior_stop"]
    assert stop["status"] == "contained_client_cleanup_failed"
    assert stop["client_cleanup"] == "failed"
    assert stop["acknowledged"] == stop["authenticated"] == "true"
    assert stop["owner_lock"] == "free"
    assert stop["marker_lock"] == "other"
    assert stop["address_presence"] == "absent"
    assert "PRIVATE" not in json.dumps(report)


def test_prior_stop_keeps_actual_successful_stop_projection(tmp_path):
    session, _ = _session(tmp_path, lambda **_kwargs: None)
    session.last_stop_diagnostic = native_slo_session._build_stop_diagnostic(
        "contained", fields=dict.fromkeys(native_slo_session._STOP_DIAGNOSTIC_FIELDS, "verified")
    )
    with module.recovery_request_witness(session) as witness:
        stop = witness.report(1.0)["prior_stop"]
    assert stop["status"] == "contained"
    assert stop["client_cleanup"] == "not_recorded"
    assert stop["address_presence"] == "verified"
    assert all(stop[key] == "verified" for key in module._STOP_FIELDS)


def test_snapshot_projection_failure_cannot_replace_original_return_or_invent_zero(tmp_path, monkeypatch):
    sentinel = object()
    session, worker = _session(tmp_path, lambda **_kwargs: sentinel)

    def unavailable(_value):
        raise RuntimeError("PRIVATE observer failure")

    with module.recovery_request_witness(session) as witness:
        assert worker._review_raw_hook_native(**_kwargs(tmp_path)) is sentinel
        monkeypatch.setattr(module, "deepcopy", unavailable)
        report = witness.report(123.0)
    assert report["capture_state"] == "unavailable"
    assert report["calls_capped_at_two"] is None
    assert report["observer_error"] is True
    assert report["observe_elapsed_ms"] == 123.0
    assert "PRIVATE" not in json.dumps(report)


def test_original_observe_exception_retains_identity_and_tears_down_patch(tmp_path):
    error = ValueError("PRIVATE original observe failure")

    def original(**_kwargs):
        return None

    session, worker = _session(tmp_path, original)
    calls = []

    def observe(*args):
        calls.append("observe")
        if len(calls) == 1:
            return Observation(*args, 1.0, "native_resident", True)
        raise error

    session.observe = observe
    session.stop_resident = lambda: calls.append("stop") or True
    with pytest.raises(ValueError) as raised:
        installed._run_recovery(session, 2)
    assert raised.value is error
    assert calls == ["observe", "stop", "observe"]
    assert worker._review_raw_hook_native is original


def test_worker_lookup_observer_failure_does_not_replace_working_observe():
    calls = []

    class Session:
        @property
        def daemon(self):
            raise RuntimeError("PRIVATE observer lookup failure")

        def observe(self, *args):
            calls.append("observe")
            return Observation(*args, 1.0, "native_resident", True)

        def stop_resident(self):
            calls.append("stop")
            return True

    session = Session()
    assert len(installed._run_recovery(session, 1)) == 1
    assert calls == ["observe", "stop", "observe"]
    with module.recovery_request_witness(session) as witness:
        report = witness.report(1.0)
    assert report["observer_state"] == "setup_unavailable"
    assert report["calls_capped_at_two"] is None
    assert "PRIVATE" not in json.dumps(report)
