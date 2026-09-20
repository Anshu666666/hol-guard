"""One installed 88-call phase diagnostic; no qualification or retry."""

from __future__ import annotations

import argparse
import importlib
import platform
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))
from priority_launcher_phase.bindings import (
    checkout_binding,
    digest,
    host_details,
    installed_binding,
    read_bindings,
    require,
    source_binding,
    write_report,
)
from priority_launcher_phase.run import execute_block, failure

PLAN_SHA256 = "ed9e5815f07ad729a1f1c0a8832ee0550e6979870f47b105831c01abd0223c8b"
CLARIFICATION_SHA256 = "5a14728bc34534d1b27c43537706f463b3cd351505f7a45d85bc126d051e7672"


def run(args: argparse.Namespace) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.priority-launcher-phase-diagnostic.v1",
        "expected_launches": 88,
        "producer_invocations_allowed": 1,
        "sample_plan": {"priority_per_run": 2, "cold_per_run": 2},
        "qualification_eligible": False,
        "original_sample_minima_met": False,
        "original_thresholds_ms": {"serial_p95": 50, "serial_p99": 100, "c16_p99": 200},
        "timing_scope": "instrumented inclusive Python intervals; unchanged original launcher timer",
        "unmeasured": [
            "child_interpreter_and_imports",
            "discovery_and_http_authentication",
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
    write_report(args.output, report)
    return 0 if report["observation_complete"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
