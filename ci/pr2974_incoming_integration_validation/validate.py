"""Validate affected source checks and Python bodies, retaining prior outcomes separately."""

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
from retain_c_builds import retain_c_builds
from source_gates import source_gates


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
    raw = (HERE / "retained-222.json").read_bytes()
    assert len(raw) <= 1024 * 1024
    value = json.loads(raw)
    assert value["schema"] == "pr2974-222-retained-observer-failure.v1"
    assert value["run_id"] == 35489040512 and value["job_id"] == 106020623013
    assert value["execution_source_sha"] == "0a6df6abbe8b6efa237f58f0cbdf553813b89a61"
    assert value["current_source_sha"] == CONFIG["source_sha"]
    assert value["current_source_tree"] == CONFIG["source_tree"]
    assert value["original_overall_passed"] is False and value["original_pytest_exit_code"] == 3
    assert value["original_phase_records"] == 176 and value["original_pytest_reported_passes"] == 59
    assert value["current_execution_claim"] is value["qualification_complete"] is False
    write_json(REPORT / "retained-222.json", value)


def main() -> int:
    run = Run("affected-integration-source-and-python-controls")
    env = None
    primary = None
    errors = []
    full_collection_passed = False
    finite_passed = False
    quality_passed = False
    corpus_check_passed = False
    formatter_passed = False
    capture_control_passed = False
    reap_control_passed = False
    capture_open_control_passed = False
    finite_attempted = False
    try:
        run.before = source_witness("before")
        retain_prior_outcomes(run.before)
        env, primary, _unused_builder = prepare_environment(run)
        quality_passed = source_gates(run, env, primary)
        corpus_check_passed = run.command("command-corpus-check", [
            str(primary), "-I", "-B", str(SOURCE / "tests" / "guard_command_decision_diff.py"), "--check",
        ], timeout=75, env=env)
        if not corpus_check_passed:
            errors.append({"scope": "command_corpus_check", "passed": False})
        formatter_passed = run.command("formatter-proposals", [
            str(primary), "-I", "-B", str(HERE / "formatter_outputs.py"),
        ], timeout=300, env=env)
        full_collection_passed = run.command("full-current-collection", [
            str(primary), "-I", "-B", str(HERE / "full_collection.py"),
        ], timeout=600, env=env)
        if not full_collection_passed:
            errors.append({"scope": "full_current_collection", "passed": False})
        if quality_passed and corpus_check_passed and formatter_passed and full_collection_passed:
            capture_control_passed = run.command("incremental-capture-integrity-control", [
                str(primary), "-I", "-B", str(HERE / "control_capture_retention_control.py"),
            ], timeout=30, env=env)
            if capture_control_passed:
                capture_open_control_passed = run.command("captured-open-control", [
                    str(primary), "-I", "-B", str(HERE / "control_capture_open_control.py"),
                ], timeout=30, env=env)
            if capture_control_passed and capture_open_control_passed:
                reap_control_passed = run.command("ordinary-child-reap-control", [
                    str(primary), "-I", "-B", str(HERE / "ordinary_child_reap_control.py"),
                ], timeout=30, env=env)
        if (
            quality_passed and corpus_check_passed and formatter_passed and full_collection_passed
            and capture_control_passed and capture_open_control_passed and reap_control_passed
        ):
            os.environ.clear()
            os.environ.update(env)
            finite_attempted = True
            finite_passed = finite_controls(run.steps)
            if not finite_passed:
                errors.append({"scope": "affected_python_controls", "passed": False})
        else:
            errors.append({"scope": "body_admission_prerequisites", "passed": False,
                           "quality": quality_passed, "command_corpus_check": corpus_check_passed,
                           "formatter_capture": formatter_passed,
                           "full_collection": full_collection_passed,
                           "capture_integrity_control": capture_control_passed,
                           "captured_open_control": capture_open_control_passed,
                           "ordinary_child_reap_control": reap_control_passed})
        write_json(REPORT / "steps.json", run.steps)
    except Exception as error:
        errors.append({"scope": "validation", "error": repr(error), "traceback": traceback.format_exc()})
    finally:
        if env is not None:
            try:
                c_builds = retain_c_builds(Path(env["VALIDATION_TEST_TMP"]))
                if c_builds["errors"] or (finite_passed and c_builds["complete_builds"] != 1):
                    errors.append({"scope": "actual_c_build_retention", "result": c_builds})
            except Exception as error:
                errors.append({"scope": "actual_c_build_retention", "error": repr(error)})
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except Exception as error:
                errors.append({"scope": "python_environment_final", "error": repr(error)})
        write_json(REPORT / "validation-summary.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "errors": errors, "full_current_collection_passed": full_collection_passed,
            "finite_controls_passed": finite_passed, "finite_control_workflow_attempted": finite_attempted,
            "source_quality_passed": quality_passed, "command_corpus_check_passed": corpus_check_passed,
            "formatter_capture_passed": formatter_passed,
            "capture_integrity_control_passed": capture_control_passed,
            "captured_open_control_passed": capture_open_control_passed,
            "ordinary_child_reap_control_passed": reap_control_passed,
            "python_cases_planned": sum(row["expected_cases"] for row in CONFIG["python_cohorts"]),
            "native_cases_planned": 0, "workspace_cases_planned": 0,
            "retained_prior_outcomes": ["retained-0509.json", "retained-93a.json", "retained-cfeb.json", "retained-222.json"],
            "retained_prior_outcomes_are_not_current_execution": True,
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
