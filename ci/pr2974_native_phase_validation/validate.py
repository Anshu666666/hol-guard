"""Validate the exact backpressure repair without replaying passing bodies."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, REPORT, Run, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite_controls import run as finite_controls
from rust_environment import finish_rust, prepare_rust
from rust_validation import validate_rust
from source_gates import source_gates


def main() -> int:
    run = Run("native-phase-diagnostic-controls")
    env = None
    primary = None
    programs = None
    errors = []
    finite_passed = False
    try:
        run.before = source_witness("before")
        env, primary, _unused_builder = prepare_environment(run)
        source_gates(run, env, primary)
        controls_env = dict(env)
        controls_env["VALIDATION_PYTHON"] = str(primary)
        controls_ok = run.command(
            "backpressure-helper-controls",
            [str(primary), "-I", "-B", str(Path(__file__).resolve().parent / "backpressure_controls_entry.py")],
            timeout=60, env=controls_env,
        )
        if not controls_ok:
            errors.append({"scope": "backpressure_helper_controls", "passed": False})
        try:
            rust_env, programs = prepare_rust(run, env)
            env = rust_env
            rust = validate_rust(run, env, programs)
            if rust["errors"]:
                errors.append({"scope": "rust_variants", "errors": rust["errors"]})
            if set(rust["binaries"]) == {"default", "diagnostic"}:
                env["HOL_GUARD_NATIVE_PHASE_DEFAULT_BINARY"] = rust["binaries"]["default"]["path"]
                env["HOL_GUARD_NATIVE_PHASE_DIAGNOSTIC_BINARY"] = rust["binaries"]["diagnostic"]["path"]
        except Exception as error:
            errors.append({"scope": "rust_setup_or_validation", "error": repr(error),
                           "traceback": traceback.format_exc()})
        # The collector reads this exact owned child environment. The independent
        # helper controls ran above; native admission refuses any missing binary
        # before pytest import without replaying earlier passing bodies.
        os.environ.clear()
        os.environ.update(env)
        finite_passed = finite_controls(run.steps)
        if not finite_passed:
            errors.append({"scope": "affected_real_binary_control", "passed": False})
        write_json(REPORT / "steps.json", run.steps)
    except Exception as error:
        errors.append({"scope": "validation", "error": repr(error),
                       "traceback": traceback.format_exc()})
    finally:
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
            "errors": errors, "finite_controls_passed": finite_passed,
            "python_inventory_cases_planned": 0, "affected_python_bodies_planned": 0,
            "historical66_bodies_replayed": False, "real_native_cases_planned": 1,
            "selected_rust_default_cases_planned": 0, "selected_rust_feature_cases_planned": 0,
            "prior45_rust_9_python_6_native_passes_replayed": False,
            "helper_controls_planned": 26, "combined_VFS_native_validation_executed": False,
            "source_or_tests_mutated": False, "installed_phase_workload_executed": False,
            "headline_timing_eligible": False, "qualification_complete": False,
        })
        if errors:
            run.error = repr(errors)
        passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
