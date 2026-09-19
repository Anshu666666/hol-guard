"""Validate the immutable current source and retain every finite actual outcome."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, HERE, REPORT, Run, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite_controls import run as finite_controls
from retain_c_builds import retain_c_builds
from rust_environment import finish_rust, prepare_rust
from rust_validation import validate_rust
from source_gates import source_gates
from unicode_controls import unicode_controls


def main() -> int:
    run = Run("current-integration-and-collection")
    env = None
    primary = None
    programs = None
    errors = []
    full_collection_passed = False
    finite_passed = False
    unicode_passed = False
    try:
        run.before = source_witness("before")
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
        try:
            env, programs = prepare_rust(run, env)
            rust = validate_rust(run, env, programs)
            if rust["errors"]:
                errors.append({"scope": "rust_variants", "errors": rust["errors"]})
            if set(rust["binaries"]) == {"default", "diagnostic"}:
                env["HOL_GUARD_NATIVE_PHASE_DEFAULT_BINARY"] = rust["binaries"]["default"]["path"]
                env["HOL_GUARD_NATIVE_PHASE_DIAGNOSTIC_BINARY"] = rust["binaries"]["diagnostic"]["path"]
            unicode_passed = unicode_controls(run, env, programs)
            if not unicode_passed:
                errors.append({"scope": "current_unicode_controls", "passed": False})
        except Exception as error:
            errors.append({"scope": "rust_setup_or_validation", "error": repr(error),
                           "traceback": traceback.format_exc()})
        os.environ.clear()
        os.environ.update(env)
        finite_passed = finite_controls(run.steps)
        if not finite_passed:
            errors.append({"scope": "finite_current_controls", "passed": False})
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
        if programs is not None:
            try:
                finish_rust(programs)
            except Exception as error:
                errors.append({"scope": "rust_environment_final", "error": repr(error)})
        write_json(REPORT / "validation-summary.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "errors": errors, "full_current_collection_passed": full_collection_passed,
            "finite_controls_passed": finite_passed, "unicode_controls_passed": unicode_passed,
            "python_cases_planned": sum(row["expected_cases"] for row in CONFIG["python_cohorts"] if row["name"] != "native"),
            "native_cases_planned": sum(row["expected_cases"] for row in CONFIG["python_cohorts"] if row["name"] == "native"),
            "workspace_cases_planned": sum(row["expected_cases"] for row in CONFIG["python_cohorts"] if row["name"].startswith("workspace-")),
            "installed_phase_workload_executed": False,
            "historical_passes_not_promoted_to_current_results": True,
            "formatter_outputs_are_proposals_only": True, "source_and_tests_are_required_to_remain_unchanged": True,
            "headline_timing_eligible": False, "qualification_complete": False,
        })
        if errors:
            run.error = repr(errors)
        passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
