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
        tmp_path / "runtime", raw_file=tmp_path / "arm.jsonl", receipt_profile="candidate", runtime_identity={}
    )
    assert len(sessions) == 1
    assert report["priority_utf8"] == observed
    assert report["priority_input"] == {"existing": True}
    assert scopes == [
        "nonpriority_registered_delivery",
        "installed_daemon_mixed_contention",
        "priority_approval",
        "diagnostic_instrumented_run",
        "priority_input",
        "priority_utf8_observation",
    ]
    assert_privacy_safe(report)
