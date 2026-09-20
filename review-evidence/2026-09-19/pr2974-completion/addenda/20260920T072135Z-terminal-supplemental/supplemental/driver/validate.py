"""Validate separate supplemental cohorts with complete current evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, HERE, REPORT, SOURCE, Run, sha256, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite_controls import run as finite_controls
from retain_incoming_c_builds import retain_incoming_c_builds
from retain_incoming_2433_c_builds import retain_incoming_2433_c_builds
from source_gates import source_gates
from supplemental_groups import summarize_groups, validate_schedule


def verify_retained_native_sources(value: dict, source_before: dict) -> None:
    historical = value["historical_native_and_rust_sources"]
    historical_digest = sha256(json.dumps(historical, sort_keys=True, separators=(",", ":")).encode())
    assert len(historical) == 231
    assert historical_digest == "448ee0200809d1e3338e4f9f315bd6908443cb26421b7faa9ca1f3afa0db4b86"
    assert value["historical_native_and_rust_sources_sha256"] == historical_digest
    unchanged = value["byte_identical_native_and_rust_sources"]
    changed = value["changed_native_and_rust_sources"]
    removed = value["removed_native_and_rust_sources"]
    added = value["added_native_and_rust_sources"]
    assert set(historical) == set(unchanged) | set(changed) | set(removed)
    assert len(historical) == len(unchanged) + len(changed) + len(removed)
    assert not set(added).intersection(historical)
    current = dict(unchanged)
    for path, expected in unchanged.items():
        assert expected == historical[path], path
    for path, row in changed.items():
        assert row["historical_sha256"] == historical[path], path
        assert row["current_sha256"] != historical[path], path
        assert source_before["files"][path]["git_blob"] == row["current_git_blob"], path
        current[path] = row["current_sha256"]
    for path, expected in removed.items():
        assert expected == historical[path] and path not in source_before["files"], path
        assert not (SOURCE / path).exists() and not (SOURCE / path).is_symlink(), path
    for path, row in added.items():
        assert source_before["files"][path]["git_blob"] == row["current_git_blob"], path
        current[path] = row["current_sha256"]
    assert source_before["source_sha"] == CONFIG["source_sha"]
    assert source_before["source_tree"] == CONFIG["source_tree"]
    non_rust_providers = {path for path in historical if not path.startswith("rust/")}
    observed = {
        path: row["sha256"] for path, row in source_before["files"].items()
        if path.startswith("rust/") or path in non_rust_providers
    }
    assert current == value["current_native_and_rust_sources"] == observed
    assert value["native_and_rust_source_partition_counts"] == {
        "historical": len(historical), "unchanged": len(unchanged), "changed": len(changed),
        "removed": len(removed), "added": len(added), "current": len(current),
    }
    for path, expected in current.items():
        assert sha256((SOURCE / path).read_bytes()) == expected, path


def retain_prior_outcomes(source_before: dict) -> None:
    raw = (HERE / "retained-0509.json").read_bytes()
    assert len(raw) <= 1024 * 1024
    value = json.loads(raw)
    assert value["schema"] == "pr2974-0509-retained-outcomes-not-reexecuted.v1"
    assert value["run_id"] == 35470159481 and value["job_id"] == 105969529650
    assert value["execution_source_sha"] == "3cc4fe16c42ac19dc854a4cd971fa23bb9bc7efc"
    assert value["current_source_sha"] == CONFIG["source_sha"]
    assert value["current_source_tree"] == CONFIG["source_tree"]
    assert value["original_overall_passed"] is False
    assert value["current_execution_claim"] is value["qualification_complete"] is False
    verify_retained_native_sources(value, source_before)
    write_json(REPORT / "retained-0509.json", value)
    raw = (HERE / "retained-93a.json").read_bytes()
    assert len(raw) <= 1024 * 1024
    value = json.loads(raw)
    assert value["schema"] == "pr2974-93a-retained-outcomes-not-reexecuted.v1"
    assert value["run_id"] == 35474110646 and value["job_id"] == 105980252039
    assert value["execution_source_sha"] == "9d37172d6bc1e1febeb9c7611a5a050ef5ea798a"
    assert value["current_source_sha"] == CONFIG["source_sha"]
    assert value["current_source_tree"] == CONFIG["source_tree"]
    assert value["original_overall_passed"] is False
    assert value["original_python_denominator"] == 276 and value["original_phase_denominator"] == 828
    assert value["terminal_admitted_cases"] == 0 and value["partial_observed_phases"] == 775
    assert value["current_execution_claim"] is value["qualification_complete"] is False
    write_json(REPORT / "retained-93a.json", value)
    raw = (HERE / "retained-cfeb.json").read_bytes()
    assert len(raw) <= 1024 * 1024
    value = json.loads(raw)
    assert value["schema"] == "pr2974-cfeb-retained-outcomes-not-reexecuted.v1"
    assert value["run_id"] == 35478463724 and value["job_id"] == 105991770779
    assert value["execution_source_sha"] == "245fab07bf0baba8a62f707301acb3692343b198"
    assert value["current_source_sha"] == CONFIG["source_sha"]
    assert value["current_source_tree"] == CONFIG["source_tree"]
    assert value["original_overall_passed"] is False
    assert value["original_python_denominator"] == 276 and value["original_phase_denominator"] == 828
    assert value["terminal_admitted_cases"] == value["normal_phases"] == 0
    assert value["normal_collection_attempted"] is value["normal_body_attempted"] is False
    assert value["current_execution_claim"] is value["qualification_complete"] is False
    write_json(REPORT / "retained-cfeb.json", value)


def main() -> int:
    run = Run("supplemental-review-and-incoming-controls")
    env = None
    primary = None
    errors = []
    groups = None
    c_builds = None
    c_builds_2433 = None
    full_collection_passed = False
    finite_passed = False
    quality_passed = False
    formatter_passed = False
    capture_control_passed = False
    capture_open_control_passed = False
    reap_control_passed = False
    c_retention_control_passed = False
    finite_attempted = False
    source_census_attempted = False
    source_census_integrity_passed = False
    try:
        run.before = source_witness("before")
        validate_schedule()
        retain_prior_outcomes(run.before)
        env, primary, _unused_builder = prepare_environment(run)
        quality_passed = source_gates(run, env, primary)
        formatter_passed = run.command("formatter-proposals", [
            str(primary), "-I", "-B", str(HERE / "formatter_outputs.py"),
        ], timeout=300, env=env)
        full_collection_passed = run.command("full-current-collection", [
            str(primary), "-I", "-B", str(HERE / "full_collection.py"),
        ], timeout=600, env=env)
        if not full_collection_passed:
            errors.append({"scope": "full_current_collection", "passed": False})
        if quality_passed and formatter_passed and full_collection_passed:
            capture_control_passed = run.command("incremental-capture-integrity-control", [
                str(primary), "-I", "-B", str(HERE / "control_capture_retention_control.py"),
            ], timeout=30, env=env)
            if capture_control_passed:
                capture_open_control_passed = run.command("shared-open-capture-isolation-control", [
                    str(primary), "-I", "-B", str(HERE / "control_capture_open_control.py"),
                ], timeout=30, env=env)
            if capture_open_control_passed:
                reap_control_passed = run.command("ordinary-child-reap-control", [
                    str(primary), "-I", "-B", str(HERE / "ordinary_child_reap_control.py"),
                ], timeout=30, env=env)
            if reap_control_passed:
                c_retention_control_passed = run.command("incoming-C-retention-control", [
                    str(primary), "-I", "-B", str(HERE / "incoming_c_retention_control.py"),
                ], timeout=30, env=env)
        if all((quality_passed, formatter_passed, full_collection_passed, capture_control_passed,
                capture_open_control_passed, reap_control_passed, c_retention_control_passed)):
            os.environ.clear()
            os.environ.update(env)
            finite_attempted = True
            finite_passed = finite_controls(run.steps)
            if not finite_passed:
                errors.append({"scope": "supplemental_finite_controls", "passed": False})
        else:
            errors.append({"scope": "body_admission_prerequisites", "passed": False,
                           "quality": quality_passed, "formatter_capture": formatter_passed,
                           "full_collection": full_collection_passed,
                           "capture_integrity_control": capture_control_passed,
                           "shared_open_capture_isolation_control": capture_open_control_passed,
                           "ordinary_child_reap_control": reap_control_passed,
                           "incoming_C_retention_control": c_retention_control_passed})
        write_json(REPORT / "steps.json", run.steps)
    except Exception as error:
        errors.append({"scope": "validation", "error": repr(error), "traceback": traceback.format_exc()})
    finally:
        try:
            groups = summarize_groups()
            if finite_passed and groups["passed"] is not True:
                errors.append({"scope": "supplemental_group_reconciliation", "passed": False})
        except Exception as error:
            errors.append({"scope": "supplemental_group_reconciliation", "error": repr(error)})
        if env is not None:
            incoming_passed = False
            try:
                finite_path = REPORT / "finite-controls.json"
                if finite_path.is_file():
                    raw = finite_path.read_bytes()
                    assert len(raw) <= 16 * 1024 * 1024
                    finite = json.loads(raw)
                    assert finite["source_sha"] == CONFIG["source_sha"] and finite["source_tree"] == CONFIG["source_tree"]
                    entries = [row for row in finite["cohorts"] if row["cohort"] == "incoming_python_additions"]
                    assert len(entries) <= 1
                    if entries:
                        assert entries[0]["expected_cases"] == 112 and type(entries[0]["passed"]) is bool
                        incoming_passed = entries[0]["passed"]
            except Exception as error:
                errors.append({"scope": "incoming_C_finite_outcome", "error": repr(error)})
            try:
                c_builds = retain_incoming_c_builds(
                    Path(env["VALIDATION_TEST_TMP"]), incoming_passed=incoming_passed
                )
                if c_builds["errors"]:
                    errors.append({"scope": "incoming_C_build_retention", "errors": c_builds["errors"]})
            except Exception as error:
                errors.append({"scope": "incoming_C_build_retention", "error": repr(error)})
        if env is not None:
            incoming_2433_passed = False
            try:
                finite_path = REPORT / "finite-controls.json"
                if finite_path.is_file():
                    raw = finite_path.read_bytes()
                    assert len(raw) <= 16 * 1024 * 1024
                    finite = json.loads(raw)
                    assert finite["source_sha"] == CONFIG["source_sha"] and finite["source_tree"] == CONFIG["source_tree"]
                    entries = [row for row in finite["cohorts"] if row["cohort"] == "incoming_2433_python"]
                    assert len(entries) <= 1
                    if entries:
                        assert entries[0]["expected_cases"] == 94 and type(entries[0]["passed"]) is bool
                        incoming_2433_passed = entries[0]["passed"]
            except Exception as error:
                errors.append({"scope": "incoming2433_C_finite_outcome", "error": repr(error)})
            try:
                c_builds_2433 = retain_incoming_2433_c_builds(
                    Path(env["VALIDATION_TEST_TMP"]), incoming_passed=incoming_2433_passed
                )
                if c_builds_2433["errors"]:
                    errors.append({"scope": "incoming2433_C_build_retention", "errors": c_builds_2433["errors"]})
            except Exception as error:
                errors.append({"scope": "incoming2433_C_build_retention", "error": repr(error)})
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except Exception as error:
                errors.append({"scope": "python_environment_final", "error": repr(error)})
            try:
                source_census_attempted = True
                source_census_integrity_passed = run.command("complete-pr-size-census", [
                    str(primary), "-I", "-B", str(HERE / "pr_size_census.py"),
                    "--manifest", str(HERE / "pr-size-census-manifest.json"),
                    "--manifest-sha256", CONFIG["pr_size_census_manifest_sha256"],
                    "--source", str(SOURCE), "--report", str(REPORT / "pr-size-census.json"),
                ], timeout=30, env=env)
                if not source_census_integrity_passed:
                    errors.append({"scope": "complete_pr_size_census_integrity", "passed": False})
            except Exception as error:
                errors.append({"scope": "complete_pr_size_census_integrity", "error": repr(error)})
        write_json(REPORT / "validation-summary.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "errors": errors, "full_current_collection_passed": full_collection_passed,
            "finite_controls_passed": finite_passed, "finite_control_workflow_attempted": finite_attempted,
            "source_quality_passed": quality_passed, "formatter_capture_passed": formatter_passed,
            "capture_integrity_control_passed": capture_control_passed,
            "shared_open_capture_isolation_control_passed": capture_open_control_passed,
            "ordinary_child_reap_control_passed": reap_control_passed,
            "incoming_C_retention_control_passed": c_retention_control_passed,
            "python_cases_planned": sum(row["expected_cases"] for row in CONFIG["python_cohorts"]),
            "python_phases_planned": 3 * sum(row["expected_cases"] for row in CONFIG["python_cohorts"]),
            "physical_cohorts_planned": len(CONFIG["python_cohorts"]),
            "logical_group_results": groups, "incoming_C_build_retention": c_builds,
            "incoming2433_C_build_retention": c_builds_2433,
            "dedicated_rust_test_cases_planned": 0,
            "outer_job_cap_minutes": 210,
            "original_individual_collection_and_body_deadlines_unchanged": True,
            "new_runner_outer_cap_is_not_a_retry_adjustment": True,
            "prior_workflow_results_reused_as_current_execution": False,
            "source_census_attempted": source_census_attempted,
            "source_census_integrity_passed": source_census_integrity_passed,
            "installed_phase_workload_executed": False,
            "formatter_outputs_are_proposals_only": True,
            "source_and_tests_are_required_to_remain_unchanged": True,
            "headline_timing_eligible": False, "qualification_complete": False,
        })
        if errors:
            run.error = repr(errors)
        passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
