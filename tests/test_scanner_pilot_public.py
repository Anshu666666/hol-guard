from __future__ import annotations

import copy
import json

import pytest

from scripts.scanner_pilot_identity import EXECUTABLE_FAILURE_REASONS
from scripts.scanner_pilot_protocol import CASES, planned
from scripts.scanner_pilot_public import aggregate, projection, validate_report
from tests.scanner_pilot_fixtures import SOURCE_SHA, encoded, snapshot


def report(case="working_provider_large", run=0, selection="full", values=None):
    return projection(
        encoded(snapshot(case, run, selection) if values is None else values),
        source_sha=SOURCE_SHA,
        case=case,
        run=run,
        selection=selection,
    )


def test_exact_fixed_denominators_and_alternating_independent_runs():
    assert len(CASES) * 5 * len(planned(CASES[0], 0)) == 840
    assert planned(CASES[0], 0)[0]["arm"] == "optimized_python"
    assert planned(CASES[0], 1)[0]["arm"] == "native_regex_pilot"
    assert planned(CASES[0], 0)[2]["arm"] == "native_regex_pilot"


def test_public_projection_excludes_all_capture_bytes_and_private_paths():
    value = report()
    text = json.dumps(value)
    assert "private synthetic stdout" not in text and "private diagnostic" not in text and "base64" not in text
    assert value["collection_complete"] and len(value["observations"]) == 24
    assert sum(row["status"] == "completed" for row in value["observations"]) == 24


@pytest.mark.parametrize(
    "change", ["extra", "bool-cpu", "negative-cpu", "nan", "fallback", "failed-complete", "null-cpu"]
)
def test_public_reader_rejects_false_completed_rows_even_with_false_summary(change):
    value = report()
    value["collection_complete"] = False
    row = next(r for r in value["observations"] if r["arm"] == "native_regex_pilot")
    if change == "extra":
        row["raw_secret"] = "must never be projected"
    elif change == "fallback":
        row["fallback_files"] = 1
    elif change == "failed-complete":
        row["failure"] = "command_deadline"
    else:
        row["cpu_ms"] = {"bool-cpu": True, "negative-cpu": -1, "nan": float("nan"), "null-cpu": None}[change]
    with pytest.raises(ValueError):
        validate_report(value)


@pytest.mark.parametrize(
    "stage,status", [("before-offer", "unoffered"), ("after-offer", "interrupted"), ("after-result", "failed")]
)
def test_first_failure_and_unoffered_work_remain_in_full_denominator(stage, status):
    values = snapshot()
    attempt = planned(CASES[0], 0)[0]
    prefix = attempt["id"]
    values.pop(prefix + ".verified.json")
    if stage != "after-result":
        values.pop(prefix + ".terminal.json")
    if stage == "before-offer":
        values.pop(prefix + ".offered.json")
    values["worker.json"]["failure"] = "controller_deadline"
    value = report(values=values)
    assert len(value["observations"]) == 24 and not value["collection_complete"]
    assert value["observations"][0]["status"] == status


def test_unverified_eviction_is_unavailable_not_a_success_or_substituted_cache_state():
    values = snapshot()
    for attempt in planned(CASES[0], 0):
        if attempt["state"] == "evicted":
            for suffix in ("offered", "terminal", "verified"):
                values.pop(attempt["id"] + f".{suffix}.json")
    values["cache-evicted.json"] = {"status": "unavailable", "reason": "cache_eviction_unverified"}
    value = report(values=values)
    assert sum(row["status"] == "cache_unavailable" for row in value["observations"]) == 12
    assert not value["collection_complete"]


def test_capture_replacement_and_result_identity_mismatch_are_rejected():
    original = snapshot()
    first = planned(CASES[0], 0)[0]["id"]
    values = copy.deepcopy(original)
    values[first + ".terminal.json"]["process"]["stdout"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        report(values=values)
    values = copy.deepcopy(original)
    values[first + ".verified.json"]["result_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        report(values=values)


def test_smoke_cannot_qualify_five_runs_even_with_a_faster_synthetic_candidate():
    value = aggregate([report(selection="smoke")], selection="smoke", source_sha=SOURCE_SHA)
    assert value["collection_complete"] and value["planned_attempts"] == 24
    assert not value["minimum_independent_runs_met"]
    assert all(row["comparison"] is None and not row["benefit_gate_passed"] for row in value["cohorts"])


def test_full_comparison_requires_exact_run_identity_and_preserves_missing_shards():
    reports = [report(case, run) for case in CASES for run in range(5)]
    result = aggregate(reports, selection="full", source_sha=SOURCE_SHA)
    assert result["collection_complete"] and result["minimum_independent_runs_met"]
    assert result["planned_attempts"] == 840 and len(result["cohorts"]) == 14
    assert all(row["samples_per_arm"] == 30 and row["benefit_gate_passed"] for row in result["cohorts"])
    missing = aggregate(reports[:-1], selection="full", source_sha=SOURCE_SHA)
    assert missing["missing_shards"] == 1 and not missing["collection_complete"]
    with pytest.raises(ValueError):
        aggregate(reports + reports[:1], selection="full", source_sha=SOURCE_SHA)


def test_changed_binary_or_dependency_cannot_form_a_paired_independent_comparison():
    reports = [report(run=run) for run in range(5)]
    reports[2]["source"]["binary_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        aggregate(reports, selection="full", source_sha=SOURCE_SHA)


def test_display_rounding_cannot_turn_a_threshold_miss_into_a_benefit():
    reports = [report(run=run) for run in range(5)]
    for value in reports:
        for row in value["observations"]:
            if row["arm"] == "native_regex_pilot":
                row["wall_ms"] = 4 * 0.7000004
                row["cpu_ms"] = 2
    value = aggregate(reports, selection="full", source_sha=SOURCE_SHA)
    for cohort in value["cohorts"]:
        if cohort["case"] == "working_provider_large":
            assert cohort["comparison"]["independent_runs"]["p95_wall"]["ci95_high"] == 0.7
            assert cohort["comparison"]["independent_runs"]["p95_wall"]["ci95_high_unrounded"] > 0.7
            assert not cohort["benefit_gate_passed"]


def identity_failure_snapshot(failure="python_executable_identity_failed", diagnostic=None):
    original = snapshot(selection="smoke")
    return {
        "plan.json": original["plan.json"],
        "worker.json": {
            "finished": False,
            "failure": failure,
            "identity_verified_after": False,
            "identity_failure": diagnostic,
        },
    }


@pytest.mark.parametrize("failure", ["python_executable_identity_failed", "native_executable_identity_failed"])
@pytest.mark.parametrize("reason", EXECUTABLE_FAILURE_REASONS)
def test_only_closed_executable_reason_is_public_and_failed_denominator_is_preserved(failure, reason):
    diagnostic = {
        "reason": reason,
        "phase": "private_phase_sentinel",
        "errno": 13,
        "bytes_read": 71,
        "metadata": {"private_path_sentinel": "/private/toolchain/executable"},
        "cleanup_failed": True,
    }
    value = report(selection="smoke", values=identity_failure_snapshot(failure, diagnostic))
    assert value["identity_failure_reason"] == reason and value["worker_failure"] == failure
    assert validate_report(value) == value
    assert value["planned"] == 24 and len(value["observations"]) == 24
    assert all(row["status"] == "unoffered" for row in value["observations"])
    assert not value["collection_complete"] and not value["installed_qualified"]
    public = json.dumps(value)
    for private in ("private_phase_sentinel", "private_path_sentinel", "/private/toolchain", "bytes_read", "errno"):
        assert private not in public
    combined = aggregate([value], selection="smoke", source_sha=SOURCE_SHA)
    assert combined["planned_attempts"] == 24 and combined["complete_shards"] == 0
    assert not combined["collection_complete"] and not combined["minimum_independent_runs_met"]
    assert all(not row["benefit_gate_passed"] and row["comparison"] is None for row in combined["cohorts"])


def test_legacy_missing_identity_diagnostic_and_public_field_remain_unknown():
    values = identity_failure_snapshot()
    values["worker.json"].pop("identity_failure")
    value = report(selection="smoke", values=values)
    assert value["identity_failure_reason"] is None
    del value["identity_failure_reason"]
    assert validate_report(value)["identity_failure_reason"] is None
    assert report()["identity_failure_reason"] is None


@pytest.mark.parametrize("reason", ["private_unrecognized_reason", "", 1, True, {}, [], None])
def test_private_diagnostic_unknown_or_missing_reason_cannot_be_projected(reason):
    with pytest.raises(ValueError):
        report(selection="smoke", values=identity_failure_snapshot(diagnostic={"reason": reason}))


@pytest.mark.parametrize("diagnostic", ["private raw diagnostic", 1, True, [], {}])
def test_private_diagnostic_wrong_shape_cannot_be_projected(diagnostic):
    with pytest.raises(ValueError):
        report(selection="smoke", values=identity_failure_snapshot(diagnostic=diagnostic))


@pytest.mark.parametrize("failure", [None, "source_identity_failed", "dependency_identity_failed", "command_deadline"])
def test_identity_reason_cannot_be_attached_to_success_or_unrelated_failure(failure):
    reason = EXECUTABLE_FAILURE_REASONS[0]
    with pytest.raises(ValueError):
        report(selection="smoke", values=identity_failure_snapshot(failure, {"reason": reason}))
    value = report()
    value.update(worker_failure=failure, collection_complete=False, identity_failure_reason=reason)
    with pytest.raises(ValueError):
        validate_report(value)


@pytest.mark.parametrize("reason", ["private_unrecognized_reason", "", 1, True, {}, []])
def test_public_reader_rejects_unknown_identity_reason_or_wrong_type(reason):
    value = report(selection="smoke", values=identity_failure_snapshot())
    value["identity_failure_reason"] = reason
    with pytest.raises(ValueError):
        validate_report(value)


@pytest.mark.parametrize("field", ["identity_failure", "identity_failure_metadata", "raw_diagnostic", "errno"])
def test_public_reader_rejects_extra_identity_diagnostic_fields(field):
    value = report(selection="smoke", values=identity_failure_snapshot())
    value[field] = {"private": "must not survive public admission"}
    with pytest.raises(ValueError):
        validate_report(value)
