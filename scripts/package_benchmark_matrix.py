"""Bounded paired package source runner; workflow scheduling belongs to CI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(_ROOT))

from scripts.package_benchmark_corpus import BASELINE, digest, fixture, manifest, matrix  # noqa: E402
from scripts.package_benchmark_evidence import (  # noqa: E402
    compare_pair,
    environment_identity,
    harness_identity,
    sign_fixture,
    source_identity,
    write_private,
)
from scripts.package_benchmark_protocol import (  # noqa: E402
    MISMATCH_FIELDS,
    descriptive_summary,
    preset,
    validate_worker_report,
)


def _run(args: argparse.Namespace) -> dict[str, object]:
    if not sys.platform.startswith("linux"):
        raise ValueError("package_matrix_platform_not_qualified")
    os.umask(0o077)
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process

    all_cases = {case.id: case for case in matrix()}
    identifiers = sorted(all_cases) if args.all_cases else list(preset(args.preset)) if args.preset else args.case
    if (
        not identifiers
        or len(set(identifiers)) != len(identifiers)
        or any(name not in all_cases for name in identifiers)
    ):
        raise ValueError("package_matrix_selection_invalid")
    attempts = len(identifiers) * args.runs * args.samples * 2
    if not 1 <= args.runs <= 20 or not 1 <= args.samples <= 1000 or attempts > args.max_attempts:
        raise ValueError("package_matrix_attempt_budget_exceeded")
    if not 1 <= args.timeout_seconds <= 1800:
        raise ValueError("package_matrix_timeout_invalid")
    roots = {"baseline": args.baseline_root.resolve(strict=True), "candidate": args.candidate_root.resolve(strict=True)}
    identities = {arm: source_identity(root) for arm, root in roots.items()}
    if identities["baseline"]["commit"] != BASELINE or identities["candidate"]["commit"] != args.candidate_sha:
        raise ValueError("package_matrix_source_ref_mismatch")
    if Path(args.python).absolute() != Path(sys.executable).absolute():
        raise ValueError("package_matrix_requires_one_shared_environment")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = args.output / "private_samples"
    public = args.output / "aggregate"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    environment = environment_identity()
    driver_identity = harness_identity(_ROOT)
    write_private(
        public / "manifest.json",
        {
            **manifest(),
            "selected_cases": identifiers,
            "source": identities,
            "environment": environment,
            "harness_sha256": driver_identity,
            "runs": args.runs,
            "samples_per_run": args.samples,
            "measurement": args.measurement,
            "offered_attempts": attempts,
            "timeout_scope": "whole_worker_including_setup_and_postvalidation",
            "timeout_seconds": args.timeout_seconds,
        },
    )
    # No operator credentials/config/proof overrides are inherited by fixture HOME.
    child_environment = {
        key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR"}
    }
    child_environment["HOME"] = str(private)
    comparisons: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    observations: list[dict[str, object]] = []
    for case_index, identifier in enumerate(identifiers):
        case = all_cases[identifier]
        value = fixture(case)
        unsigned_bundle = value["bundle"]
        assert isinstance(unsigned_bundle, dict)
        response, trusted = sign_fixture(unsigned_bundle)
        fixture_file = private / f"{identifier}.fixture.json"
        write_private(fixture_file, {"fixture": value, "response": response, "trusted_fingerprint": trusted})
        for run_index in range(args.runs):
            for sample in range(args.samples):
                pair: dict[str, dict[str, object]] = {}
                order = (
                    ("baseline", "candidate")
                    if (case_index + run_index * args.samples + sample) % 2 == 0
                    else ("candidate", "baseline")
                )
                for arm in order:
                    prefix = f"{identifier}.r{run_index:02d}.s{sample:04d}.{arm}"
                    journal = private / f"{prefix}.jsonl"
                    offered = {
                        "schema": "hol-guard.package-attempt.v2",
                        "case_id": identifier,
                        "arm": arm,
                        "run": run_index,
                        "sample": sample,
                        "status": "offered",
                        "source": identities[arm],
                        "fixture_sha256": digest(value),
                        "signed_response_sha256": digest(response),
                        "environment": environment,
                        "harness_sha256": driver_identity,
                        "measurement": args.measurement,
                    }
                    write_private(journal, offered)
                    temporary = private / (prefix + ".work")
                    temporary.mkdir(mode=0o700)
                    completed = run_isolated_hook_process(
                        (
                            args.python,
                            "-I",
                            str(_ROOT / "scripts" / "package_benchmark_worker.py"),
                            "--source-root",
                            str(roots[arm]),
                            "--fixture",
                            str(fixture_file),
                            "--journal",
                            str(journal),
                            "--semantic",
                            str(private / f"{prefix}.semantic.json"),
                            "--temporary-root",
                            str(temporary),
                            "--measurement",
                            args.measurement,
                        ),
                        input_text="",
                        cwd=_ROOT,
                        environment=child_environment,
                        timeout_seconds=args.timeout_seconds,
                        output_limit=64 * 1024,
                    )
                    if not completed.containment_failed:
                        shutil.rmtree(temporary)
                    report: dict[str, object] = {
                        **offered,
                        "status": "failed",
                        "returncode": completed.returncode,
                        "timed_out": completed.timed_out,
                        "containment_failed": completed.containment_failed,
                        "output_limit_exceeded": completed.output_limit_exceeded,
                    }
                    try:
                        received = json.loads(completed.stdout)
                        if not isinstance(received, dict) or received.get("schema") != offered["schema"]:
                            raise ValueError("package_matrix_worker_output_invalid")
                        if (
                            completed.returncode == 0
                            and not completed.timed_out
                            and not completed.output_limit_exceeded
                            and not completed.containment_failed
                        ):
                            report.update(validate_worker_report(received, offered))
                        elif received.get("mismatch") in MISMATCH_FIELDS:
                            report["mismatch"] = received["mismatch"]
                    except (ValueError, TypeError):
                        report["worker_output_valid"] = False
                    if completed.timed_out:
                        report["status"] = "censored"
                    write_private(journal, report, append=True)
                    observations.append(report)
                    pair[arm] = report
                    if report["status"] != "completed":
                        failures.append(
                            {
                                key: report[key]
                                for key in (
                                    "case_id",
                                    "arm",
                                    "run",
                                    "sample",
                                    "status",
                                    "timed_out",
                                    "containment_failed",
                                    "output_limit_exceeded",
                                )
                            }
                        )
                    if completed.containment_failed:
                        write_private(
                            public / "incomplete.json",
                            {"status": "failed", "reason": "containment_failed", "failures": failures},
                        )
                        raise RuntimeError("package_matrix_containment_failed")
                comparisons.append(
                    {
                        "case_id": identifier,
                        "run": run_index,
                        "sample": sample,
                        **compare_pair(pair["baseline"], pair["candidate"]),
                    }
                )
    if {arm: source_identity(root) for arm, root in roots.items()} != identities:
        raise ValueError("package_matrix_source_identity_changed")
    report: dict[str, object] = {
        "schema": "hol-guard.package-pairs.v2",
        "status": "incomplete" if failures or any(not item["comparable"] for item in comparisons) else "completed",
        "comparisons": comparisons,
        "descriptive_summaries": descriptive_summary(comparisons),
        "failures": failures,
        "observations": observations,
        "installed_qualified": False,
        "tail_qualified": False,
        "native_activation_authorized": False,
        "threshold": {"primary_reduction": 0.30, "other_metric_max_regression": 0.05},
        "decision": "native_comparison_not_available",
    }
    write_private(public / ("incomplete.json" if report["status"] == "incomplete" else "paired.json"), report)
    return report


def run(args: argparse.Namespace) -> dict[str, object]:
    existed = args.output.exists()
    try:
        return _run(args)
    except Exception as error:
        # Never write into an earlier run, and never leave a successful comparison
        # after a controller/source/containment failure in the newly created run.
        public = args.output / "aggregate"
        if not existed and public.is_dir():
            paired = public / "paired.json"
            paired.unlink(missing_ok=True)
            incomplete = public / "incomplete.json"
            if not incomplete.exists():
                write_private(
                    incomplete,
                    {
                        "schema": "hol-guard.package-pairs.v2",
                        "status": "incomplete",
                        "reason": "controller_failure",
                        "failure_sha256": digest(str(error)),
                        "native_activation_authorized": False,
                    },
                )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--case", action="append", default=[])
    selection.add_argument("--all-cases", action="store_true")
    selection.add_argument("--preset", choices=("format-preflight", "cardinality", "unresolved", "hot-route"))
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--max-attempts", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=float, default=180)
    parser.add_argument("--measurement", choices=("validation", "timing", "attribution"), default="validation")
    args = parser.parse_args()
    try:
        report = run(args)
    except Exception as error:
        print(json.dumps({"status": "incomplete", "failure_sha256": digest(str(error))}), flush=True)
        return 1
    comparisons, failures = report["comparisons"], report["failures"]
    assert isinstance(comparisons, list) and isinstance(failures, list)
    print(
        json.dumps(
            {
                "status": report["status"],
                "case_pairs": len(comparisons),
                "failures": len(failures),
                "tail_qualified": False,
            }
        ),
        flush=True,
    )
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
