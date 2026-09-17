from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_identity_cold_run as run
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_identity_lifecycle import LifecycleObserver
from tests.test_native_slo_identity_lifecycle import BINDING, cold_runtime
from tests.test_native_slo_identity_phases import hook
from tests.test_native_slo_phase_run import Session, rows


class ColdSession(Session):
    def __init__(self, runtime, *, setup, cold_identity, mode="normal"):
        super().__init__(mode)
        assert setup == "normal"
        self.options = cold_identity
        self.runtime, self.handler, self.publisher, _ = cold_runtime(runtime.parent)
        self.startup_ms = 0.125
        self.observer = LifecycleObserver(
            Path(cold_identity["path"]),
            cold_identity["binding"],
            runtime=self.runtime,
            handler=self.handler,
            publisher=self.publisher,
        )
        self.original_failure = OSError("private startup failure")
        self.cleanup_error = RuntimeError("private cleanup failure")
        self.closed = False
        self.process = SimpleNamespace(returncode=0)

    def __enter__(self):
        self.observer.__enter__()
        with self.observer.preparation():
            self.runtime.native_runtime_status()
        if self.mode.startswith("startup"):
            self.cold_startup_failure = failure_evidence(self.original_failure)
            self.observer.__exit__()
            self.closed = True
            raise self.cleanup_error if self.mode == "startup_cleanup" else self.original_failure
        self.observer.phase("ready")
        self.instrumented = True
        return self

    def request(self, harness, request):
        hook(self.handler)
        return super().request(harness, request)

    def __exit__(self, *args):
        self.observer.phase("cleanup")
        self.observer.__exit__()
        self.closed = True
        if self.mode in {"cleanup", "request_cleanup"}:
            raise self.cleanup_error


def collect(tmp_path, monkeypatch, mode="normal"):
    sessions = []

    def factory(runtime, **kwargs):
        session = ColdSession(runtime, mode=mode, **kwargs)
        if mode == "request_cleanup":
            session.mode = "request_failure"
            original = session.request

            def request(*args):
                try:
                    return original(*args)
                finally:
                    session.mode = "request_cleanup"

            session.request = request
        sessions.append(session)
        return session

    monkeypatch.setattr(run, "DaemonFixture", factory)
    return sessions, lambda: run.measure_cold_identity(
        tmp_path / "runtime", tmp_path / "cases.jsonl", tmp_path / "observer.jsonl", BINDING
    )


def test_cold_fixture_preparation_first_hook_and_two_controls_are_separate(tmp_path, monkeypatch):
    sessions, operation = collect(tmp_path, monkeypatch)
    report = operation()
    assert report["passed"] and report["ready"]
    assert report["planned"] == report["offered"] == report["validated"] == report["request_started"] == 3
    assert report["unoffered"] == report["request_start_unknown"] == report["request_not_started"] == 0
    assert report["observer"]["preparation_status_calls"] == 1 and report["observer"]["hook_status_calls"] == [1, 1, 1]
    assert report["binding"] == BINDING and report["cache_state_modified"] is False
    assert report["headline_timing_eligible"] is report["cold_os_cache_measured"] is False
    assert sessions[0].closed and sessions[0].requests == [1024] * 3
    assert "identity_start" not in sessions[0].operations
    assert "calls" not in report["observer"] and "hooks" not in report["observer"]
    assert report["journal_bytes"] <= run.MAX_PARENT_BYTES
    assert len(json.dumps(report).encode()) < run.MAX_SUMMARY_BYTES
    assert "private" not in (tmp_path / "cases.jsonl").read_text()


@pytest.mark.parametrize(
    "mode",
    ["startup", "startup_cleanup", "request_failure", "request_cleanup", "cleanup", "wrong_native", "missing_native"],
)
def test_failure_conservation_preserves_startup_request_and_cleanup(tmp_path, monkeypatch, mode):
    sessions, operation = collect(tmp_path, monkeypatch, mode)
    with pytest.raises(FixtureFailureError) as caught:
        operation()
    report = rows(tmp_path / "cases.jsonl")[-1]["report"]
    assert not report["passed"] and sessions[0].closed
    assert report["offered"] + report["unoffered"] == 3
    assert (
        report["request_started"] + report["request_not_started"] + report["request_start_unknown"] == report["offered"]
    )
    if mode.startswith("startup"):
        assert report["offered"] == 0 and report["unoffered"] == 3
        assert report["startup_failure"]["category"] == "OSError"
        assert report["observer"]["hooks_started"] == 0
        if mode == "startup_cleanup":
            assert report["returned_failure"]["category"] == "RuntimeError"
            assert caught.value.__cause__ is sessions[0].cleanup_error
        else:
            assert caught.value.__cause__ is sessions[0].original_failure
    if mode == "request_cleanup":
        assert report["returned_failure"]["category"] == "OSError"
        assert report["cleanup_failure"]["category"] == "RuntimeError"
    assert "private startup failure" not in json.dumps(report) and "private cleanup failure" not in json.dumps(report)


def test_missing_terminal_retains_started_unknown_without_retry(tmp_path, monkeypatch):
    sessions, operation = collect(tmp_path, monkeypatch)
    original = run._IdentityJournal.append

    def fail_terminal(self, value, **kwargs):
        if value.get("schema") == "hol-guard.phase-attempt.v1" and value.get("status") == "validated":
            raise OSError("private interrupted write")
        return original(self, value, **kwargs)

    monkeypatch.setattr(run._IdentityJournal, "append", fail_terminal)
    with pytest.raises(FixtureFailureError):
        operation()
    report = rows(tmp_path / "cases.jsonl")[-1]["report"]
    assert report["offered"] == report["request_start_unknown"] == 1 and report["unoffered"] == 2
    assert report["request_started"] == report["request_not_started"] == 0
    assert sessions[0].requests == [1024]


def test_constructor_failure_keeps_zero_offers_even_without_child_journal(tmp_path, monkeypatch):
    failure = OSError("private constructor failure")

    def failed(*args, **kwargs):
        raise failure

    monkeypatch.setattr(run, "DaemonFixture", failed)
    with pytest.raises(FixtureFailureError) as caught:
        run.measure_cold_identity(tmp_path / "runtime", tmp_path / "cases.jsonl", tmp_path / "missing.jsonl", BINDING)
    report = rows(tmp_path / "cases.jsonl")[-1]["report"]
    assert caught.value.__cause__ is failure
    assert report["unoffered"] == 3 and report["request_started"] == 0
    assert report["observer"]["available"] is False and not report["observer"]["complete"]


def test_cleanup_only_failure_is_explicit_after_three_validated_hooks(tmp_path, monkeypatch):
    sessions, operation = collect(tmp_path, monkeypatch, "cleanup")
    with pytest.raises(FixtureFailureError) as caught:
        operation()
    report = rows(tmp_path / "cases.jsonl")[-1]["report"]
    assert report["validated"] == 3 and report["startup_failure"] is None
    assert report["cleanup_failure"]["category"] == "RuntimeError"
    assert caught.value.__cause__ is sessions[0].cleanup_error


def test_reachable_cold_archive_addition_and_finite_summary_wrapper(tmp_path, monkeypatch):
    from scripts.native_slo_identity_lifecycle_record import MAX_BYTES, MAX_CALLS, MAX_RECORD_BYTES, MAX_RECORDS
    from scripts.native_slo_qualification_scenarios import _retained_scenario

    # Fixed three hooks yield <=8 parent records: header +6 attempts +summary.
    # Child has an independent enforced byte cap even with96 call pairs and
    # all reserved phase/hook/footer records. No raw stdout/payload is retained.
    assert MAX_CALLS == 96 and MAX_RECORDS == 224 and MAX_RECORD_BYTES == 4096
    assert run.MAX_PARENT_BYTES == 98304
    added_pair_bytes = 2 * (MAX_BYTES + run.MAX_PARENT_BYTES + run.MAX_SUMMARY_FILE_BYTES)
    assert added_pair_bytes == 794624 and added_pair_bytes < 1024 * 1024
    sessions, operation = collect(tmp_path, monkeypatch)
    result = _retained_scenario(
        operation, evidence_file=tmp_path / "summary.json", scope="fresh_process_preparation_first_hook_and_warm"
    )
    assert result["passed"] and sessions[0].closed
    assert (tmp_path / "summary.json").stat().st_size <= run.MAX_SUMMARY_FILE_BYTES
    assert (tmp_path / "cases.jsonl").stat().st_size <= run.MAX_PARENT_BYTES
    assert (tmp_path / "observer.jsonl").stat().st_size <= MAX_BYTES
    assert result["observer"]["hook_status_calls"] == [1, 1, 1]


def test_child_closed_shapes_fit_byte_cap_at_maximum_integer_width():
    from scripts.native_slo_identity_lifecycle_record import MAX_BYTES, MAX_CALLS, MAX_RECORDS, SCHEMA
    from scripts.native_slo_identity_phases import _COUNTERS

    common = {"schema": SCHEMA, "sequence": MAX_RECORDS - 1, "elapsed_ns": 2**63 - 1}
    start = {
        **common,
        "kind": "call_started",
        "call": MAX_CALLS - 1,
        "operation": "capability_process",
        "owner": "preparation",
        "phase": "between_hooks",
        "phase_epoch": MAX_RECORDS,
        "hook": 2,
        "parent_call": MAX_CALLS - 1,
    }
    finish = {
        **common,
        "kind": "call_finished",
        "call": MAX_CALLS - 1,
        "phase": "between_hooks",
        "phase_epoch": MAX_RECORDS,
        "outcome": "returned",
        "metrics": dict.fromkeys(_COUNTERS, 2**63 - 1),
        "identity_matches": False,
    }
    other = [
        {**common, "kind": "started", "binding": BINDING},
        {**common, "kind": "phase", "phase": "between_hooks", "phase_epoch": MAX_RECORDS},
        {**common, "kind": "hook_started", "hook": 2, "expected": False},
        {**common, "kind": "hook_finished", "hook": 2, "outcome": "returned"},
        {
            **common,
            "kind": "observer_finished",
            "drained": False,
            "unexpected": 2**63 - 1,
            "overflow": False,
            "recording_failed": False,
            "initial_cache_entries": 2**63 - 1,
        },
    ]

    def size(row):
        return len(json.dumps(row, separators=(",", ":")).encode()) + 1

    # This deliberately overstates every counter independently (some cannot
    # jointly reach these values), and reserves all32 non-call record slots.
    reachable_upper = MAX_CALLS * (size(start) + size(finish)) + 32 * max(map(size, other))
    assert reachable_upper < MAX_BYTES
