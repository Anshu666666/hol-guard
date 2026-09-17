from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from scripts.native_slo_failure import FixtureFailureError
from scripts.native_slo_identity_phases import IdentityObserver
from scripts.native_slo_identity_run import measure_evaluated_identity
from tests.test_native_slo_identity_phases import fixture_runtime, hook
from tests.test_native_slo_phase_run import Session, rows


class IdentitySession(Session):
    def __init__(self, tmp_path, mode="normal"):
        super().__init__(mode)
        self.runtime, self.handler, _ = fixture_runtime(tmp_path)
        self.observer = None

    def control(self, operation):
        if operation == "identity_start":
            self.operations.append(operation)
            self.instrumented = True
            self.observer = IdentityObserver(runtime=self.runtime, handler=self.handler)
            self.observer.__enter__()
            return {"started": self.mode != "start_ack_missing"}
        if operation == "identity_finish":
            self.operations.append(operation)
            self.instrumented = False
            self.observer.__exit__()
            result = self.observer.report()
            if self.mode == "invalid_report":
                result["private_path"] = "not admissible"
            return result
        return super().control(operation)

    def request(self, harness, request):
        hook(self.handler)
        return super().request(harness, request)


def test_first_prepared_hook_and_two_warm_requests_preserve_real_oracle(tmp_path):
    session = IdentitySession(tmp_path)
    evidence = tmp_path / "identity.jsonl"
    report = measure_evaluated_identity(session, evidence)
    assert report["passed"] and report["planned"] == report["offered"] == report["validated"] == 3
    assert report["unoffered"] == 0 and report["cold_resident_measured"] is False
    assert report["request_started"] == 3
    assert report["request_not_started"] == report["request_start_unknown"] == 0
    assert report["observer"]["complete"]
    assert [row["phase"] for row in report["observer"]["rows"]] == [
        "first_hook_prepared_resident",
        "warm_hook",
        "warm_hook",
    ]
    assert session.requests == [1024] * 3
    records = rows(evidence)
    assert sum(row.get("status") == "offered" for row in records) == 3
    outcomes = [
        row for row in records if row.get("schema") == "hol-guard.phase-attempt.v1" and row.get("status") == "validated"
    ]
    assert len(outcomes) == 3 and all(row["route"] == "native_resident" for row in outcomes)
    assert len({row["request_sha256"] for row in outcomes}) == 1
    assert session.operations.count("identity_start") == session.operations.count("identity_finish") == 1
    assert "const guard_value" not in evidence.read_text()


@pytest.mark.parametrize(
    "mode", ["request_failure", "wrong_route", "wrong_native", "missing_native", "start_ack_missing", "invalid_report"]
)
def test_original_failures_and_unoffered_work_remain_retained(tmp_path, mode):
    session = IdentitySession(tmp_path, mode)
    evidence = tmp_path / "failed.jsonl"
    with pytest.raises(FixtureFailureError) as caught:
        measure_evaluated_identity(session, evidence)
    records = rows(evidence)
    report = records[-1]["report"]
    assert not report["passed"]
    assert report["offered"] + report["unoffered"] == 3
    assert report["validated"] <= report["offered"]
    assert "identity_finish" in session.operations and not session.observer._installed
    assert caught.value.detail["identity_diagnostic"]["passed"] is False
    if mode == "request_failure":
        assert report["offered"] == 1 and report["unoffered"] == 2
        assert report["failure"]["category"] == "OSError"
        assert len(report["observer"]["rows"]) == 1
    if mode == "invalid_report":
        assert report["offered"] == report["validated"] == 3
        assert report["observer"] is None
    assert "private request contents" not in evidence.read_text() and "not admissible" not in evidence.read_text()


def test_nonfresh_fixture_is_not_relabelled_first_hook(tmp_path):
    session = IdentitySession(tmp_path)
    session.routes["native_resident"] = 1
    with pytest.raises(FixtureFailureError):
        measure_evaluated_identity(session, tmp_path / "prior-hook.jsonl")
    report = rows(tmp_path / "prior-hook.jsonl")[-1]["report"]
    assert report["offered"] == 0 and report["unoffered"] == 3
    assert report["observer"] is None and session.operations == []


@pytest.mark.parametrize("failure_stage", ["reserve", "wire", "offered_write", "terminal_write", "case_before"])
def test_offer_and_dispatch_counts_follow_retained_records(tmp_path, monkeypatch, failure_stage):
    from scripts import native_slo_identity_run as run

    session = IdentitySession(tmp_path, "reset_ack_missing" if failure_stage == "case_before" else "normal")
    original = run._Journal.append
    sentinel = OSError("synthetic journal failure")

    def fail_reserve(_journal):
        raise sentinel

    def append(journal, value, *, report=False):
        if value.get("schema") == "hol-guard.phase-attempt.v1" and (
            (failure_stage == "offered_write" and value.get("status") == "offered")
            or (failure_stage == "terminal_write" and value.get("status") != "offered")
        ):
            raise sentinel
        return original(journal, value, report=report)

    if failure_stage == "reserve":
        monkeypatch.setattr(run._IdentityJournal, "reserve_attempt", fail_reserve)
    elif failure_stage == "wire":
        cases = run.phase_cases()
        cases[0].payload["unexpected_wire_bytes"] = "changed"
        monkeypatch.setattr(run, "phase_cases", lambda: cases)
    else:
        monkeypatch.setattr(run._Journal, "append", append)
    evidence = tmp_path / "accounting.jsonl"
    with pytest.raises(FixtureFailureError) as caught:
        run.measure_evaluated_identity(session, evidence)
    records = rows(evidence)
    report = records[-1]["report"]
    attempts = [r for r in records if r.get("schema") == "hol-guard.phase-attempt.v1"]
    assert report["offered"] == sum(r["status"] == "offered" for r in attempts)
    assert report["offered"] + report["unoffered"] == 3
    assert (
        report["request_started"] + report["request_not_started"] + report["request_start_unknown"] == report["offered"]
    )
    assert report["validated"] == 0 and not report["passed"]
    if failure_stage in {"reserve", "offered_write", "terminal_write"}:
        assert caught.value.__cause__ is sentinel
    if failure_stage == "terminal_write":
        assert len(session.requests) == report["request_start_unknown"] == report["offered"] == 1
        assert report["request_started"] == report["request_not_started"] == 0
    elif failure_stage == "case_before":
        assert session.requests == [] and report["request_not_started"] == report["offered"] == 1
    else:
        assert session.requests == [] and report["offered"] == 0
    assert not session.observer._installed


def test_identity_scenario_is_additive_and_separately_retained(tmp_path, monkeypatch):
    from scripts import native_slo_qualification_scenarios as scenarios
    from scripts.native_slo_contract import assert_privacy_safe

    sessions = []

    class Fixture:
        def __init__(self, runtime, **options):
            assert options == {"setup": "normal"}
            self.session = IdentitySession(tmp_path)
            sessions.append(self.session)

        def __enter__(self):
            return self.session

        def __exit__(self, *_args):
            pass

    original = scenarios._retained_scenario

    def retained(operation, *, evidence_file, scope):
        if scope == "prepared_resident_first_hook_and_warm":
            return original(operation, evidence_file=evidence_file, scope=scope)
        return {"unchanged": True}

    monkeypatch.setattr(scenarios, "DaemonFixture", Fixture)
    monkeypatch.setattr(scenarios, "_retained_scenario", retained)
    report = scenarios.run_additional_scenarios(
        tmp_path / "runtime", raw_file=tmp_path / "arm.jsonl", receipt_profile="candidate", runtime_identity={}
    )
    assert len(sessions) == 1 and len(sessions[0].requests) == 3
    assert report["runtime_identity"]["passed"] is True
    assert report["python_phases"] == {"unchanged": True}
    summary = json.loads((tmp_path / "arm-identity-summary.json").read_text())
    assert summary == report["runtime_identity"]
    public = assert_privacy_safe({"additional_scenarios": report})
    assert public["additional_scenarios"]["runtime_identity"]["observer"]["rows"][0]["status_calls"] == 1


@pytest.mark.parametrize("terminal", ["identity_finish", "close", "phases_start"])
def test_fixture_control_restores_observer_on_finish_close_and_conflict(tmp_path, monkeypatch, terminal):
    from scripts import native_slo_daemon_fixture as fixture
    from scripts import native_slo_identity_phases as phases
    from scripts import native_slo_launcher_review as review
    from scripts import native_slo_mixed_server as mixed

    runtime, handler, _ = fixture_runtime(tmp_path)
    observer = IdentityObserver(runtime=runtime, handler=handler)
    original = runtime._inspect_native_runtime_status
    emitted, closed = [], []
    monkeypatch.setattr(phases, "IdentityObserver", lambda: observer)
    monkeypatch.setattr(
        review, "LauncherReviewFixture", lambda _s: SimpleNamespace(close=lambda: closed.append("review"))
    )
    monkeypatch.setattr(mixed, "MixedScenarioFixture", lambda _s: SimpleNamespace(close=lambda: closed.append("mixed")))
    monkeypatch.setattr(fixture, "_emit", emitted.append)
    commands = ["identity_start", terminal] + (["close"] if terminal == "identity_finish" else [])
    encoded = b"".join((json.dumps({"op": op}) + "\n").encode() for op in commands)
    monkeypatch.setattr(fixture.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(encoded)))
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        guard_home=tmp_path,
        readiness_ms=1,
        daemon=SimpleNamespace(port=1, _server=SimpleNamespace(auth_token="synthetic")),
    )
    if terminal == "phases_start":
        with pytest.raises(RuntimeError, match="unsupported daemon fixture operation"):
            fixture._serve_session(session, None)
    else:
        fixture._serve_session(session, None)
    assert not observer._installed and runtime._inspect_native_runtime_status is original
    assert closed == ["review", "mixed"]
    assert {"started": True} in emitted
    if terminal == "identity_finish":
        assert any(
            row.get("schema") == "hol-guard.evaluated-hook-identity.v1" and row["complete"] is False for row in emitted
        )
