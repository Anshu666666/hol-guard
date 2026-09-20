"""Run only independent static diagnostics; no collection, body or guard invocation."""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from baseline_source import baseline_witness
from common import CONFIG, HERE, REPORT, Run, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from static_gates import source_gates


def main() -> int:
    run = Run("rsp100-static-only-validation")
    env = primary = before_parent = None
    errors = []
    try:
        run.before = source_witness("before")
        before_parent = baseline_witness("before")
        env, primary, _ = prepare_environment(run)
        env["VALIDATION_PYTHON"] = str(primary)
        os.environ.update(env)
        static_passed = source_gates(run, env, primary)
        write_json(REPORT / "static-only-scope.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "source_paths": CONFIG["python_source_paths"],
            "new_helper_type_paths": CONFIG["python_new_helper_paths"],
            "existing_type_paths": CONFIG["python_existing_production_paths"],
            "parent_type_source_sha": CONFIG["baseline_sha"],
            "static_prerequisites_passed": static_passed,
            "collection_attempted": False, "test_body_attempted": False,
            "guard_invocation_attempted": False, "administrative_controls_attempted": False,
            "source_package_import_attempted": False,
            "source_mutating_fix_attempted": False, "qualification_complete": False,
        })
        if not static_passed:
            errors.append("One or more independent static prerequisites failed; all original diagnostics retained")
    except BaseException as error:
        errors.append(type(error).__name__ + ": " + traceback.format_exc())
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException as error:
                errors.append(type(error).__name__ + ": " + traceback.format_exc())
        try:
            after_parent = baseline_witness("after")
            assert before_parent is not None and before_parent == after_parent
        except BaseException as error:
            errors.append(type(error).__name__ + ": " + traceback.format_exc())
        if errors:
            run.error = "\n".join(errors)
        passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
