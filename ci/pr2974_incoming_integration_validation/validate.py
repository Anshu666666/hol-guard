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


def retain_prior_outcomes() -> None:
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
    for path, expected in value["byte_identical_native_and_rust_sources"].items():
        assert sha256((SOURCE / path).read_bytes()) == expected, path
    write_json(REPORT / "retained-0509.json", value)


def main() -> int:
    run = Run("affected-integration-source-and-python-controls")
    env = None
    primary = None
    errors = []
    full_collection_passed = False
    finite_passed = False
    try:
        run.before = source_witness("before")
        retain_prior_outcomes()
        env, primary, _unused_builder = prepare_environment(run)
        source_gates(run, env, primary)
        run.command("formatter-proposals", [
            str(primary), "-I", "-B", str(HERE / "formatter_outputs.py"),
        ], timeout=300, env=env)
        full_collection_passed = run.command("full-current-collection", [
            str(primary), "-I", "-B", str(HERE / "full_collection.py"),
        ], timeout=600, env=env)
        if not full_collection_passed:
            errors.append({"scope": "full_current_collection", "passed": False})
        os.environ.clear()
        os.environ.update(env)
        finite_passed = finite_controls(run.steps)
        if not finite_passed:
            errors.append({"scope": "affected_python_controls", "passed": False})
        write_json(REPORT / "steps.json", run.steps)
    except Exception as error:
        errors.append({"scope": "validation", "error": repr(error), "traceback": traceback.format_exc()})
    finally:
        if env is not None:
            try:
                c_builds = retain_c_builds()
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
            "finite_controls_passed": finite_passed,
            "python_cases_planned": sum(row["expected_cases"] for row in CONFIG["python_cohorts"]),
            "native_cases_planned": 0, "workspace_cases_planned": 0,
            "retained_prior_outcomes": "retained-0509.json",
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
