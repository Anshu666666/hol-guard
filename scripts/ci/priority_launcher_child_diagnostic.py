"""At most24 original calls with an explicit additional child startup profiler."""

from __future__ import annotations

import argparse
import importlib
import platform
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Keep this private namespace separate from the later source-root scripts
# package. Importing scripts.ci here would cache the driver's producer root.
_bindings = importlib.import_module("priority_launcher_phase.bindings")
_run = importlib.import_module("priority_launcher_child.run")
checkout_binding = _bindings.checkout_binding
digest = _bindings.digest
host_details = _bindings.host_details
installed_binding = _bindings.installed_binding
read_bindings = _bindings.read_bindings
require = _bindings.require
source_binding = _bindings.source_binding
write_report = _bindings.write_report
execute_block = _run.execute_block
failure = _run.failure

PLAN_SHA256 = "ed9e5815f07ad729a1f1c0a8832ee0550e6979870f47b105831c01abd0223c8b"
CLARIFICATION_SHA256 = "5a14728bc34534d1b27c43537706f463b3cd351505f7a45d85bc126d051e7672"


def run(args: argparse.Namespace) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.priority-child-diagnostic.v1",
        "expected_launches": 24,
        "subset_invocations_allowed": 1,
        "sample_plan": {"preflight": 8, "claude_post_concurrency16": 16},
        "qualification_eligible": False,
        "original_sample_minima_met": False,
        "original_thresholds_ms": {"serial_p95": 50, "serial_p99": 100, "c16_p99": 200},
        "timing_scope": "instrumented inclusive Python intervals; unchanged original launcher timer",
        "unmeasured": [
            "child_interpreter_before_startup_observer",
            "clean_uninstrumented_child_cost",
            "native_internal_phases",
            "asynchronous_sqlite_commit",
            "physical_io",
        ],
        "cross_process_clock_subtraction": False,
        "retry_or_extra_warmup": False,
    }
    manifest: dict[str, Any] | None = None
    try:
        require(bool(sys.flags.isolated), "isolated_interpreter")
        require(sys.platform == "darwin" and platform.machine() == "arm64", "platform")
        report["host_before"] = host_details()
        report["driver_before"] = checkout_binding(args.driver_root, args.expected_driver_sha)
        plan_root = args.driver_root / "scripts/ci/priority_launcher_phase"
        require(digest(plan_root / "plan-v2.json") == PLAN_SHA256, "accepted_plan")
        require(digest(plan_root / "PLAN-CLARIFICATION-v3.json") == CLARIFICATION_SHA256, "accepted_clarification")
        report["accepted_plan_sha256"] = PLAN_SHA256
        report["accepted_clarification_sha256"] = CLARIFICATION_SHA256
        child_plan_root = args.driver_root / "scripts/ci/priority_launcher_child"
        require(
            digest(child_plan_root / "PLAN-v1.json")
            == "5478d399a3545e5b7d7e8b3811f295a761d25c20c1aa6cc32c2f572d81bed24f",
            "child_plan",
        )
        require(
            digest(child_plan_root / "PLAN-CLARIFICATION-v2.json")
            == "e8179c81df0fd0dd34087e07a50da0e89ae72682ed3a4b9075360ad40e2b5621",
            "child_clarification",
        )
        report["child_plan_sha256"] = digest(child_plan_root / "PLAN-v1.json")
        report["child_clarification_sha256"] = digest(child_plan_root / "PLAN-CLARIFICATION-v2.json")
        report["additional_owned_venv_startup_observer"] = True
        manifest = read_bindings(args.bindings, args.expected_source_sha, args.expected_source_tree)
        report["source_binding_manifest_sha256"] = digest(args.bindings)
        report["source_before"] = source_binding(args.source_root, manifest)
        sys.path.insert(0, str(args.source_root.resolve()))
        contract = importlib.import_module("scripts.native_slo_contract")
        import os

        require(not contract.clear_proof_environment(dict(os.environ)), "proof_environment")
        report["installed_before"], runtime = installed_binding(args.wheel, args.expected_source_sha, manifest)
        producer = importlib.import_module("scripts.native_slo_priority_launchers")
        fixture_module = importlib.import_module("scripts.native_slo_daemon_fixture")
        launch_runtime = importlib.import_module("codex_plugin_scanner.guard.codex_hook_launch_runtime")
        for module, relative in (
            (producer, "scripts/native_slo_priority_launchers.py"),
            (fixture_module, "scripts/native_slo_daemon_fixture.py"),
        ):
            require(
                Path(cast(str, module.__file__)).resolve() == (args.source_root / relative).resolve(), "producer_import"
            )
        child = args.driver_root / "scripts/ci/priority_launcher_phase_daemon.py"
        daemon_report = args.output.with_name(args.output.stem + "-daemon.json")
        require(not daemon_report.exists(), "daemon_report_exists")
        report["block"] = execute_block(
            fixture_module.DaemonFixture(runtime, policy="normal"),
            producer,
            fixture_module,
            launch_runtime,
            source_root=args.source_root,
            child_script=child,
            daemon_report_path=daemon_report,
            package_root=Path(cast(str, importlib.import_module("codex_plugin_scanner").__file__)).parent,
            wheel=args.wheel,
        )
    except BaseException as error:
        report["driver_failure"] = failure(error)
    finally:
        operations = [
            ("host_after", host_details),
            ("driver_after", lambda: checkout_binding(args.driver_root, args.expected_driver_sha)),
        ]
        if manifest is not None:
            operations.extend(
                [
                    ("source_after", lambda: source_binding(args.source_root, manifest)),
                    ("installed_after", lambda: installed_binding(args.wheel, args.expected_source_sha, manifest)[0]),
                ]
            )
        for key, operation in operations:
            try:
                report[key] = operation()
            except BaseException as error:
                report[key + "_failure"] = failure(error)
    report["observation_complete"] = (
        not any(key.endswith("_failure") for key in report)
        and report.get("block", {}).get("observation_complete") is True
        and report.get("source_before") == report.get("source_after")
        and report.get("installed_before") == report.get("installed_after")
        and report.get("driver_before") == report.get("driver_after")
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--driver-root", type=Path, required=True)
    parser.add_argument("--expected-driver-sha", required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(args.output.parent.is_dir() and not args.output.exists(), "output_not_owned")
    report = run(args)
    write_report(args.output, report, maximum=8 * 1024 * 1024)
    return 0 if report["observation_complete"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
