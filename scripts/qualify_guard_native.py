#!/usr/bin/env python3
"""Run paired installed-artifact performance blocks with explicit coverage gaps.

Use separate interpreters containing baseline and candidate native wheels. This
runner never silently substitutes a semantic oracle for the production baseline.
Private numeric observations and publishable aggregates are saved separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Mapping
from contextlib import nullcontext
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts.native_slo_artifact import wheel_package_digest  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_pair_comparison import _object_field, compare_blocks  # noqa: E402
from scripts.native_slo_pair_io import MANIFEST_LIMIT, digest_file, require  # noqa: E402
from scripts.native_slo_pair_record import PairRecorder  # noqa: E402
from scripts.native_slo_qualification import paired_order, sampling_plan  # noqa: E402
from scripts.native_slo_qualification_bundle import load_bundle  # noqa: E402


def _write_evidence(path: Path, report: Mapping[str, object]) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")


def _pair_recorder(
    args: argparse.Namespace, public: Path, private: Path, artifact_digests: Mapping[str, str]
) -> PairRecorder | None:
    if getattr(args, "pair_index", None) is None:
        return None
    require(args.bundle_directory is not None, "pair_bundle_required")
    bundle = load_bundle(args.bundle_directory, target=args.target, candidate_sha=args.candidate_sha)
    require(
        all(artifact_digests[arm] == bundle["arms"][arm]["wheel_sha256"] for arm in artifact_digests),
        "pair_declared_artifact_mismatch",
    )
    return PairRecorder(
        public=public,
        private=private,
        bundle=bundle,
        context={
            "build_sha": args.candidate_sha,
            "target": args.target,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "pair_index": args.pair_index,
            "runs": args.runs,
            "mode": args.mode,
            "bundle_sha256": digest_file(args.bundle_directory / "bundle.json", MANIFEST_LIMIT),
        },
    )


def _run_pair(args: argparse.Namespace) -> dict[str, object]:
    import os

    plan = sampling_plan(runs=args.runs, qualification=args.mode == "qualification")
    interpreters = {"baseline": args.baseline_python, "candidate": args.candidate_python}
    if any(interpreter is None for interpreter in interpreters.values()):
        raise ValueError("both installed-artifact interpreters are required")
    # Virtualenv interpreters may be symlinks to the same Python executable;
    # their distinct launch paths still select different installed artifacts.
    if os.path.abspath(args.baseline_python) == os.path.abspath(args.candidate_python):
        raise ValueError("baseline and candidate must use distinct installed environments")
    artifact_digests: dict[str, str] = {}
    expected_package_digests: dict[str, str] = {}
    for arm, artifact in (("baseline", args.baseline_artifact), ("candidate", args.candidate_artifact)):
        if artifact is None:
            if args.mode == "qualification":
                raise ValueError("qualification requires both installed wheel artifact files")
            artifact_digests[arm] = "unrecorded"
        else:
            digest = hashlib.sha256()
            with artifact.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            artifact_digests[arm] = digest.hexdigest()
            expected_package_digests[arm] = wheel_package_digest(artifact)
    environment = dict(os.environ)
    clear_proof_environment(environment)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    private = args.output_dir / "private_samples"
    public = args.output_dir / "aggregate"
    if (
        private.is_symlink()
        or public.is_symlink()
        or (private.exists() and any(private.iterdir()))
        or (
            public.exists()
            and any(
                item.name != "runner-resolver.json" or not item.is_file() or item.is_symlink()
                for item in public.iterdir()
            )
        )
    ):
        raise ValueError("paired sampling requires fresh aggregate and private evidence directories")
    private.mkdir(mode=0o700, exist_ok=True)
    public.mkdir(exist_ok=True)
    recorder = _pair_recorder(args, public, private, artifact_digests)
    with recorder if recorder is not None else nullcontext():
        reports: dict[str, list[dict[str, object]]] = {"baseline": [], "candidate": []}
        failures: list[dict[str, object]] = []
        for run in range(args.runs) if recorder is None else (args.pair_index,):
            for arm in paired_order(run):
                if recorder is not None:
                    recorder.offer(arm)
                raw_file = private / f"{run:02d}-{arm}.json"
                completed = run_isolated_hook_process(
                    (
                        str(interpreters[arm]),
                        str(Path(__file__).resolve()),
                        "--worker",
                        "--mode",
                        args.mode,
                        "--runs",
                        str(args.runs),
                        "--raw-file",
                        str(raw_file),
                        "--receipt-profile",
                        "baseline_2e672d2" if arm == "baseline" else "candidate",
                    ),
                    input_text="",
                    cwd=_ROOT,
                    environment=environment,
                    timeout_seconds=args.block_timeout_seconds,
                    output_limit=256 * 1024,
                )
                if (
                    completed.returncode != 0
                    or completed.timed_out
                    or completed.containment_failed
                    or completed.output_limit_exceeded
                ):
                    failure: dict[str, object] = {
                        "schema": "hol-guard.native-qualification-failure.v1",
                        "reason": "paired_worker_process_failed",
                    }
                    try:
                        parsed_failure = json.loads(completed.stdout)
                        if isinstance(parsed_failure, dict) and parsed_failure.get("schema") == failure["schema"]:
                            failure = assert_privacy_safe(parsed_failure)
                    except (ValueError, TypeError):
                        pass
                    failure.update(
                        arm=arm,
                        run=run,
                        artifact_sha256=artifact_digests[arm],
                        timed_out=completed.timed_out,
                        containment_failed=completed.containment_failed,
                    )
                    failure = assert_privacy_safe(failure)
                    _write_evidence(public / f"{run:02d}-{arm}-failure.json", failure)
                    # Raw stderr/tracebacks remain private; expose only bounded
                    # generated failure identifiers from our worker protocol.
                    print(json.dumps(failure, sort_keys=True), file=sys.stderr, flush=True)
                    failures.append(failure)
                    if recorder is not None:
                        recorder.failed(arm)
                    # A contained failed arm must not erase the other artifact's
                    # independent evidence. Failed blocks are never paired with a
                    # different run or omitted from the final result.
                    if completed.containment_failed:
                        raise RuntimeError(f"paired block failed containment: run={run} arm={arm}")
                    continue
                report = json.loads(completed.stdout)
                if not isinstance(report, dict) or report.get("schema") != "hol-guard.native-qualification-block.v1":
                    raise RuntimeError("paired block returned invalid evidence")
                safe = assert_privacy_safe(report)
                if (
                    arm in expected_package_digests
                    and _object_field(safe, "runtime").get("installed_package_sha256") != expected_package_digests[arm]
                ):
                    raise RuntimeError("paired interpreter does not contain the declared wheel artifact")
                if not raw_file.is_file():
                    raise RuntimeError("paired block did not retain numeric observations")
                safe["artifact_sha256"] = artifact_digests[arm]
                _write_evidence(public / f"{run:02d}-{arm}.json", safe)
                if recorder is not None:
                    recorder.completed(arm, safe, raw_file)
                reports[arm].append(safe)
                print(f"completed paired block {run + 1}/{args.runs} {arm}", file=sys.stderr, flush=True)
        if failures:
            incomplete = assert_privacy_safe(
                {
                    "schema": "hol-guard.native-paired-incomplete.v1",
                    "evidence_class": "qualification_sampling" if args.mode == "qualification" else "smoke",
                    "plan": plan,
                    "order": "alternating_baseline_candidate_blocks",
                    "artifact_digests": artifact_digests,
                    "completed_blocks": {arm: len(items) for arm, items in reports.items()},
                    "failed_blocks": failures,
                    "sampling_passed": False,
                    "qualification_complete": False,
                    "program_qualification_complete": False,
                    "comparison_available": False,
                }
            )
            _write_evidence(public / "incomplete.json", incomplete)
            raise RuntimeError(f"paired block failed: {len(failures)} retained failed blocks; comparison unavailable")
    if recorder is not None:
        assert recorder.report is not None
        return recorder.report
    result = compare_blocks(reports, mode=args.mode, runs=args.runs, artifact_digests=artifact_digests)
    _write_evidence(public / "comparison.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path)
    parser.add_argument("--candidate-python", type=Path)
    parser.add_argument("--baseline-artifact", type=Path)
    parser.add_argument("--candidate-artifact", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("native-qualification"))
    parser.add_argument("--mode", choices=("smoke", "qualification"), default="smoke")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--block-timeout-seconds", type=float, default=3600)
    parser.add_argument("--pair-index", type=int)
    parser.add_argument("--bundle-directory", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--candidate-sha")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-attempt", type=int)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--raw-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--receipt-profile", choices=("candidate", "baseline_2e672d2"), default="candidate", help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    try:
        plan = sampling_plan(runs=args.runs, qualification=args.mode == "qualification")
        if not 0 < args.block_timeout_seconds <= 14400:
            raise ValueError("block timeout must be positive and at most four hours")
        if args.pair_index is not None and args.block_timeout_seconds > 3600:
            raise ValueError("indexed pair worker deadline exceeds one hour")
        if args.worker:
            if args.raw_file is None:
                raise ValueError("worker numeric sample destination is required")
            from scripts.native_slo_dependency_identity import dependency_versions_digest
            from scripts.native_slo_qualification_run import run_block

            result = run_block(plan=plan, raw_file=args.raw_file, receipt_profile=args.receipt_profile)
            runtime = result.get("runtime")
            if isinstance(runtime, dict):
                runtime["dependency_versions_sha256"] = dependency_versions_digest()
            hardware = result.get("hardware")
            if isinstance(hardware, dict):
                # Hosted runner images expose these exact case-sensitive names.
                hardware["runner_image"] = os.environ.get("ImageVersion", "unavailable")  # noqa: SIM112
                hardware["runner_image_os"] = os.environ.get("ImageOS", "unavailable")  # noqa: SIM112
            result = assert_privacy_safe(result)
        else:
            result = _run_pair(args)
    except Exception as error:
        if args.worker:
            print(json.dumps(failure_evidence(error), sort_keys=True))
            return 1
        parser.exit(1, f"native qualification failed: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    # Pair jobs report collection only; the full aggregator owns acceptance.
    # Strict unsharded qualification must not return a passing process status
    # while its required scopes or sample minima remain false.
    if not args.worker and args.pair_index is None and args.mode == "qualification":
        return 0 if result.get("sampling_passed") is True and result.get("qualification_complete") is True else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
