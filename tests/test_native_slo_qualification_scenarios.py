from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.native_slo_qualification_scenarios import _retained_scenario, validate_receipt_profile


def test_legacy_receipt_path_requires_exact_audited_build() -> None:
    validate_receipt_profile("candidate", {"build_sha": "new-candidate"})
    validate_receipt_profile("baseline_2e672d2", {"build_sha": "2e672d2d950c6ec471005ddba46e49bba16dc23b"})
    for build in (None, "unknown", "2e672d2", "new-candidate"):
        with pytest.raises(ValueError, match="exact audited native build"):
            validate_receipt_profile("baseline_2e672d2", {"build_sha": build})
    with pytest.raises(ValueError, match="unsupported"):
        validate_receipt_profile("legacy", {})


def test_known_side_contract_failure_is_retained_as_failure(tmp_path: Path) -> None:
    def fail() -> dict[str, object]:
        raise RuntimeError("registered_surface_copilot_schema_mismatch")

    destination = tmp_path / "failed.json"
    result = _retained_scenario(fail, evidence_file=destination, scope="installed_delivery")
    assert result["passed"] is False
    assert result["scope"] == "installed_delivery"
    assert json.loads(destination.read_text()) == result
    with pytest.raises(FileExistsError):
        _retained_scenario(fail, evidence_file=destination, scope="installed_delivery")


def test_failed_observed_mixed_gate_cannot_become_a_pass(tmp_path: Path) -> None:
    observed = {"passed": False, "checks": {"offered_latency": False}, "failures": {"timed_out": 1}}
    assert _retained_scenario(lambda: observed, evidence_file=tmp_path / "mixed.json", scope="mixed") == observed


def test_utf8_observation_is_separate_from_original_cases_and_headline_samples(tmp_path, monkeypatch):
    from scripts import native_slo_qualification_scenarios as scenarios
    from scripts.native_slo_contract import assert_privacy_safe

    sessions, scopes = [], []

    class Fixture:
        def __init__(self, runtime, **options):
            assert runtime == tmp_path / "runtime" and options == {"setup": "normal"}
            sessions.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def retained(operation, *, evidence_file, scope):
        scopes.append(scope)
        return operation() if scope == "priority_utf8_observation" else {"existing": True}

    observed = {"passed": False, "qualification_complete": False, "headline_timing_eligible": False}

    def collect(session, *, evidence_file):
        assert session is sessions[-1]
        assert evidence_file == tmp_path / "arm-utf8-cases.jsonl"
        return observed

    monkeypatch.setattr(scenarios, "DaemonFixture", Fixture)
    monkeypatch.setattr(scenarios, "_retained_scenario", retained)
    monkeypatch.setattr(scenarios, "run_registered_utf8_observation", collect)
    report = scenarios.run_additional_scenarios(
        tmp_path / "runtime",
        raw_file=tmp_path / "arm.jsonl",
        receipt_profile="candidate",
        runtime_identity={},
        precollected_attribution=_failed_attribution(),
    )
    assert len(sessions) == 1
    assert report["priority_utf8"] == observed
    assert report["priority_input"] == {"existing": True}
    assert scopes == [
        "nonpriority_registered_delivery",
        "installed_daemon_mixed_contention",
        "priority_approval",
        "priority_input",
        "priority_utf8_observation",
    ]
    assert_privacy_safe(report)


def _failed_attribution():
    from scripts import native_slo_qualification_scenarios as scenarios
    from scripts.native_slo_failure import failure_evidence

    return {
        "schema": "hol-guard.installed-attribution-scenarios.v1",
        "receipt_profile": "candidate",
        "headline_timing_eligible": False,
        **{
            key: {"scope": scope, "passed": False, "failure": failure_evidence(RuntimeError("synthetic failure"))}
            for key, (_, scope) in scenarios._ATTRIBUTION_SCOPES.items()
        },
    }


def _successful_attribution():
    from scripts import native_slo_qualification_scenarios as scenarios

    result = _failed_attribution()
    for key, (schema, scope) in scenarios._ATTRIBUTION_SCOPES.items():
        report = {"schema": schema, "scope": scope, "passed": True, "headline_timing_eligible": False}
        if key == "python_phases":
            report.update(
                count_per_case=2,
                attempted=8,
                validated=8,
                groups={
                    name: {
                        "attempted": 4,
                        "validated": 4,
                        "phase_report": {"config_lookup_coverage": {"binding": "retained"}},
                    }
                    for name in ("small_inline", "maximum_supported_inline")
                },
            )
        else:
            report.update(
                planned=3,
                offered=3,
                request_started=3,
                validated=3,
                request_not_started=0,
                request_start_unknown=0,
                unoffered=0,
                observer={
                    "complete": True,
                    "schema": (
                        "hol-guard.evaluated-hook-identity.v1"
                        if key == "runtime_identity"
                        else "hol-guard.cold-identity-observation.v1"
                    ),
                },
            )
        result[key] = report
    return result


def _install_collectors(monkeypatch, raw_file, *, fail_phases=False):
    from scripts import native_slo_qualification_scenarios as scenarios

    calls, sessions = [], []
    reports = _successful_attribution()

    class Fixture:
        def __init__(self, runtime, **options):
            assert options == {"setup": "normal"}
            self.closed = False
            sessions.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.closed = True

    def phases(session, count, evidence_file):
        assert session is sessions[0] and count == 2
        assert evidence_file == raw_file.with_name(raw_file.stem + "-phase-cases.jsonl")
        calls.append("phases")
        evidence_file.write_bytes(b'{"status":"offered"}\n{')
        if fail_phases:
            raise RuntimeError("PRIVATE synthetic observer failure /home/customer")
        return reports["python_phases"]

    def identity(session, evidence_file):
        assert session is sessions[1] and sessions[0].closed
        assert evidence_file == raw_file.with_name(raw_file.stem + "-identity-cases.jsonl")
        calls.append("identity")
        evidence_file.write_text('{"status":"validated"}\n' * 3)
        return reports["runtime_identity"]

    def cold(runtime, cases, observer, binding):
        assert all(session.closed for session in sessions)
        assert cases == raw_file.with_name(raw_file.stem + "-identity-cold-cases.jsonl")
        assert observer == raw_file.with_name(raw_file.stem + "-identity-cold-observer.jsonl")
        assert set(binding) == {"build_sha", "runtime_sha256", "installed_package_sha256"}
        calls.append("cold")
        cases.write_text('{"status":"validated"}\n' * 3)
        observer.write_text('{"status":"observed"}\n')
        return reports["runtime_identity_cold"]

    monkeypatch.setattr(scenarios, "DaemonFixture", Fixture)
    monkeypatch.setattr(scenarios, "measure_installed_phases", phases)
    monkeypatch.setattr(scenarios, "measure_evaluated_identity", identity)
    monkeypatch.setattr(scenarios, "measure_cold_identity", cold)
    return calls, sessions


@pytest.mark.parametrize("fail_phases", [False, True])
def test_precollected_attribution_runs_once_and_preserves_original_reports(tmp_path, monkeypatch, fail_phases):
    from scripts import native_slo_qualification_scenarios as scenarios

    raw = tmp_path / "arm.json"
    calls, sessions = _install_collectors(monkeypatch, raw, fail_phases=fail_phases)
    attribution = scenarios.run_attribution_scenarios(
        tmp_path / "runtime", raw_file=raw, receipt_profile="candidate", runtime_identity={}, phase_count=2
    )
    assert calls == ["phases", "identity", "cold"] and len(sessions) == 2 and all(x.closed for x in sessions)
    assert attribution["python_phases"]["passed"] is not fail_phases
    retained = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert len(retained) == 7 and not raw.exists()
    if fail_phases:
        encoded = retained["arm-phase-summary.json"]
        assert b"PRIVATE" not in encoded and b"customer" not in encoded
        assert set(attribution["python_phases"]) == {"scope", "passed", "failure"}
    later = []

    def remaining(operation, *, evidence_file, scope):
        later.append(scope)
        return {"passed": False}

    monkeypatch.setattr(scenarios, "_retained_scenario", remaining)
    report = scenarios.run_additional_scenarios(
        tmp_path / "runtime",
        raw_file=raw,
        receipt_profile="candidate",
        runtime_identity={},
        precollected_attribution=attribution,
    )
    assert calls == ["phases", "identity", "cold"] and len(later) == 5
    for key in scenarios._ATTRIBUTION_SCOPES:
        assert report[key] is attribution[key]
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == retained


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "missing",
        "schema",
        "profile",
        "headline",
        "scope",
        "passed_bool",
        "report_schema",
        "phase_count",
        "phase_groups",
        "identity_counts",
        "observer_schema",
        "failure_empty",
        "failure_passed",
    ],
)
def test_invalid_precollected_attribution_stops_before_remaining_offers(tmp_path, monkeypatch, fault):
    from scripts import native_slo_qualification_scenarios as scenarios

    value = _successful_attribution()
    if fault == "extra":
        value["extra"] = True
    elif fault == "missing":
        value.pop("runtime_identity_cold")
    elif fault == "schema":
        value["schema"] = "other"
    elif fault == "profile":
        value["receipt_profile"] = "baseline_2e672d2"
    elif fault == "headline":
        value["headline_timing_eligible"] = True
    elif fault == "scope":
        value["runtime_identity"]["scope"] = "other"
    elif fault == "passed_bool":
        value["runtime_identity"]["passed"] = 1
    elif fault == "report_schema":
        value["runtime_identity"]["schema"] = "other"
    elif fault == "phase_count":
        value["python_phases"]["validated"] = True
    elif fault == "phase_groups":
        value["python_phases"]["groups"] = {}
    elif fault == "identity_counts":
        value["runtime_identity_cold"].pop("validated")
    elif fault == "observer_schema":
        value["runtime_identity"]["observer"]["schema"] = "other"
    else:
        value = _failed_attribution()
        if fault == "failure_empty":
            value["python_phases"]["failure"] = {}
        else:
            value["python_phases"]["passed"] = True
    monkeypatch.setattr(scenarios, "_retained_scenario", lambda *_a, **_k: pytest.fail("invalid mapping offered work"))
    with pytest.raises(ValueError, match="qualification attribution"):
        scenarios.run_additional_scenarios(
            tmp_path / "runtime",
            raw_file=tmp_path / "arm.json",
            receipt_profile="candidate",
            runtime_identity={},
            precollected_attribution=value,
        )
    assert not list(tmp_path.iterdir())
