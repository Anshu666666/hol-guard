"""Audit the original failed closure, then execute only its 25 unchanged installed controls."""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Importing the reader consumes the API token before any subprocess environment is created.
from original_artifact import archive_input, original_packages
from original_installed_cases import bind_fresh_collection, original_installed
from common import CONFIG, REPORT, Run, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite import installed_seams


def main() -> int:
    run = Run("local-supply-chain-original-wheel-installed-only")
    errors, results = [], {}
    env, primary = None, None
    try:
        run.before = source_witness("before")
        payloads = archive_input(run)
        original_cases = original_installed(payloads)
        wheel = original_packages(run, payloads)
        results["original_installed_cases_reconciled"] = len(original_cases)
        results["original_overall_passed"] = False
        results["original_lifetime_binding_complete"] = False
        del payloads
        env, primary, create_venv = prepare_environment(run)
        # Never call finite.main or run_packages: source cohorts and package builds are not repeated.
        results["fresh_installed_seams"] = installed_seams(
            run, env, wheel, create_venv,
            after_collection=lambda path: bind_fresh_collection(original_cases, path),
        )
        results["original_to_fresh_collection_bridge"] = "passed"
    except BaseException as error:
        errors.append(repr(error))
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException as error:
                errors.append("Environment finalizer: " + repr(error))
        write_json(REPORT / "installed-only-results.json", {
            "results": results, "errors": errors, "original_run": CONFIG["original"]["run"],
            "original_failure_preserved": True, "fresh_installed_expected": 25,
            "existing613_and_source25_repeated": False, "package_build_repeated": False,
            "source_or_type_cohort_repeated": False, "qualification_complete": False,
        })
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
