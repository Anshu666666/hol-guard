"""Independent installed transitions from the qualification run's immutable bundle."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.ci.verify_installed_artifact_transitions import verify  # noqa: E402
from scripts.native_slo_evidence_archive import encrypt_samples, failure_receipt  # noqa: E402
from scripts.native_slo_evidence_files import _new_directory, atomic_exclusive, read_file  # noqa: E402
from scripts.native_slo_evidence_format import MAX_ARCHIVE_BYTES, context_fields  # noqa: E402
from scripts.native_slo_evidence_public import publish_receipt  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_pair_io import canonical, decode, digest_file, read_public, require, write_public  # noqa: E402
from scripts.native_slo_qualification_bundle import BASELINE_SHA, REQUIREMENTS_LIMIT, TARGETS, load_bundle  # noqa: E402

RECIPIENT_ID = "db2d2f3b5002f740768855101840eb4a02ee146d0838d92f8611256f93a7379e"
PHASES = ("clean_baseline", "candidate_upgrade", "candidate_reinstall", "baseline_rollback", "candidate_restore")
SCHEMA = "hol-guard.installed-transition-scenario.v1"
LIMIT = 256 * 1024


def plan(context: dict[str, object]) -> dict[str, object]:
    require(set(context) == {"source_sha", "target", "run_id", "run_attempt"}, "transition_context_invalid")
    context_fields(context)
    require(context["target"] in TARGETS, "transition_target_invalid")
    return {
        "schema": SCHEMA,
        "context": {
            "build_sha": context["source_sha"],
            **{key: value for key, value in context.items() if key != "source_sha"},
        },
        "baseline_sha": BASELINE_SHA,
        "scope": "stopped_artifact_replacement_shared_fixture_authority",
        "required_phases": list(PHASES),
        "required_registered_cases": 10,
        "dependency_scope": "candidate_locked_dependencies_for_every_phase",
        "maximum_contained_commands": 13,
        "contained_process_timeout_seconds": 180,
        "headline_timing_eligible": False,
        "program_qualification_complete": False,
        "production_activation_authorized": False,
    }


def _source_binding(root: Path, expected: str) -> None:
    observed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(observed.stdout.strip() == expected, "transition_checkout_mismatch")


def _bundle_binding(bundle_root: Path, context: dict[str, Any], dependency_root: Path) -> dict[str, Any]:
    bundle = load_bundle(bundle_root, target=context["target"], candidate_sha=context["source_sha"])
    _source_binding(dependency_root, context["source_sha"])
    candidate = bundle["arms"]["candidate"]
    require(
        digest_file(dependency_root / "uv.lock", REQUIREMENTS_LIMIT) == candidate["lock_sha256"],
        "transition_candidate_lock_mismatch",
    )
    version = ".".join(map(str, sys.version_info[:3]))
    require(all(arm["python_version"] == version for arm in bundle["arms"].values()), "transition_python_mismatch")
    return bundle


def _require_result(result: dict[str, Any], bundle: dict[str, Any]) -> None:
    require(result.get("passed") is True, "transition_probe_failed")
    require(
        all(
            type(result.get(key)) is int and result[key] == 5
            for key in ("completed_phase_count", "required_phase_count", "private_checkpoints_retained")
        )
        and result.get("private_checkpoints_retained") == 5
        and result.get("private_checkpoint_retention") == {"files": 5, "complete": True}
        and result.get("fixture_retained_for_unverified_retirement") is False
        and result.get("fixture_retained_for_evidence_failure") is False,
        "transition_probe_incomplete",
    )
    rows = result.get("phases")
    if not isinstance(rows, list) or len(rows) != len(PHASES):
        raise ValueError("transition_phase_count_invalid")
    require(
        all(row.get("phase") == phase and row.get("passed") is True for row, phase in zip(rows, PHASES, strict=True)),
        "transition_phase_incomplete",
    )
    candidate = bundle["arms"]["candidate"]
    require(
        result.get("dependency_lock_sha256") == candidate["lock_sha256"]
        and result.get("dependency_versions_sha256") == candidate["dependency_versions_sha256"],
        "transition_observed_dependencies_mismatch",
    )
    for arm in ("baseline", "candidate"):
        identity = result.get("identities", {}).get(arm, {})
        expected = bundle["arms"][arm]
        require(
            all(
                identity.get(key) == expected[other]
                for key, other in (
                    ("build_sha", "build_sha"),
                    ("wheel_sha256", "wheel_sha256"),
                    ("installed_package_sha256", "package_sha256"),
                    ("runtime_sha256", "runtime_sha256"),
                )
            ),
            "transition_observed_artifact_mismatch",
        )


def run(bundle_root: Path, output: Path, dependency_root: Path, context: dict[str, Any]) -> dict[str, Any]:
    offered = plan(context)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = output / "private_samples"
    _new_directory(private)
    # Both copies precede bundle admission, installation and every hook offer.
    atomic_exclusive(private / "transition-plan.json", canonical(offered) + b"\n")
    write_public(output / "aggregate/plan.json", offered)
    summary: dict[str, Any] = {**offered, "passed": False, "status": "incomplete"}
    try:
        bundle = _bundle_binding(bundle_root, context, dependency_root)
        encoded_bundle = read_file(bundle_root / "bundle.json", 16 * 1024)
        summary["bundle_sha256"] = hashlib.sha256(encoded_bundle).hexdigest()
        atomic_exclusive(private / "wheel-bundle.json", encoded_bundle)
        summary["candidate_dependency_versions_sha256"] = bundle["arms"]["candidate"]["dependency_versions_sha256"]
        summary["candidate_requirements_sha256"] = bundle["arms"]["candidate"]["requirements_sha256"]
        result = verify(
            Path(sys.executable).absolute(),
            bundle_root / "baseline" / bundle["arms"]["baseline"]["wheel"],
            bundle_root / "candidate" / bundle["arms"]["candidate"]["wheel"],
            BASELINE_SHA,
            context["source_sha"],
            dependency_root=dependency_root,
            private_evidence=private,
            expected_dependency_digest=bundle["arms"]["candidate"]["dependency_versions_sha256"],
        )
        summary["probe"] = result
        _require_result(result, bundle)
        require(_bundle_binding(bundle_root, context, dependency_root) == bundle, "transition_bundle_changed")
        summary["checkpoint_sha256"] = {
            phase: digest_file(private / f"installed-transition-{phase}.json", 64 * 1024) for phase in PHASES
        }
        summary.update(passed=True, status="completed")
    except Exception as error:
        summary["failure"] = failure_evidence(error)
    atomic_exclusive(private / "transition-summary.json", canonical(summary) + b"\n")
    write_public(output / "aggregate/summary.json", summary)
    return summary


def _validate_archive(output: Path, context: dict[str, Any]) -> tuple[dict[str, str], bool]:
    offered = plan(context)
    private, public = output / "private_samples", output / "aggregate"
    # Recover only an already-written report; checkpoints alone never imply success.
    if not (public / "summary.json").exists():
        if (private / "transition-summary.json").exists():
            recovered = read_public(private / "transition-summary.json", LIMIT)
        else:
            recovered = {**offered, "passed": False, "status": "interrupted"}
            atomic_exclusive(private / "transition-summary.json", canonical(recovered) + b"\n")
        write_public(public / "summary.json", recovered)
    summary = read_public(public / "summary.json", LIMIT)
    require(summary.get("context") == offered["context"], "transition_archive_context_mismatch")
    require(read_public(public / "plan.json") == offered, "transition_archive_plan_mismatch")
    require(
        read_file(private / "transition-plan.json", LIMIT) == canonical(offered) + b"\n",
        "transition_private_plan_mismatch",
    )
    require(
        read_file(private / "transition-summary.json", LIMIT) == canonical(summary) + b"\n",
        "transition_private_summary_mismatch",
    )
    commitments = {
        "transition-plan.json": hashlib.sha256(canonical(offered) + b"\n").hexdigest(),
        "transition-summary.json": hashlib.sha256(canonical(summary) + b"\n").hexdigest(),
    }
    if summary.get("passed") is True:
        _completed(summary, context)
        for phase in PHASES:
            checkpoint = read_file(private / f"installed-transition-{phase}.json", 64 * 1024, private=True)
            require(
                hashlib.sha256(checkpoint).hexdigest() == summary["checkpoint_sha256"][phase],
                "transition_checkpoint_changed",
            )
        bundle_bytes = read_file(private / "wheel-bundle.json", 16 * 1024, private=True)
        require(
            hashlib.sha256(bundle_bytes).hexdigest() == summary["bundle_sha256"], "transition_archive_bundle_mismatch"
        )
        _require_result(summary["probe"], decode(bundle_bytes))
        commitments["wheel-bundle.json"] = summary["bundle_sha256"]
        commitments.update(
            {f"installed-transition-{phase}.json": summary["checkpoint_sha256"][phase] for phase in PHASES}
        )
    return commitments, summary.get("passed") is True


def archive(output: Path, context: dict[str, Any], public_key: Path) -> dict[str, object]:
    validation: dict[str, Any] = {"context": plan(context)["context"], "passed": False}
    commitments: dict[str, str] | None = None
    exact_inventory = False
    try:
        commitments, exact_inventory = _validate_archive(output, context)
    except Exception as error:
        validation["failure"] = failure_evidence(error)

    def observe_snapshot(files: tuple[tuple[str, bytes], ...]) -> None:
        if commitments is None:
            return
        actual = {name: hashlib.sha256(content).hexdigest() for name, content in files}
        try:
            require(
                all(actual.get(name) == digest for name, digest in commitments.items()),
                "transition_archive_snapshot_changed",
            )
            require(not exact_inventory or set(actual) == set(commitments), "transition_archive_inventory_changed")
            validation["passed"] = True
        except Exception as error:
            validation["failure"] = failure_evidence(error)

    # A validation failure must not discard the remaining private checkpoints.
    receipt = encrypt_samples(
        source=output / "private_samples",
        output=output / "encrypted/checkpoints.hge",
        public_key=public_key,
        recipient_id=RECIPIENT_ID,
        context=context,
        snapshot_observer=observe_snapshot,
    )
    write_public(output / "aggregate/archive-validation.json", validation)
    require(receipt.get("status") == "encrypted", "transition_archive_missing")
    return receipt


def _completed(summary: dict[str, Any], context: dict[str, Any]) -> None:
    require(all(summary.get(key) == value for key, value in plan(context).items()), "transition_summary_plan_mismatch")
    require(summary.get("passed") is True and summary.get("status") == "completed", "transition_scenario_incomplete")
    require(set(summary.get("checkpoint_sha256", {})) == set(PHASES), "transition_checkpoint_inventory_invalid")


def retention(output: Path, context: dict[str, Any]) -> None:
    summary = read_public(output / "aggregate/summary.json", LIMIT)
    _completed(summary, context)
    validation = read_public(output / "aggregate/archive-validation.json", LIMIT)
    require(
        validation.get("context") == plan(context)["context"] and validation.get("passed") is True,
        "transition_archive_invalid",
    )
    receipt = read_public(output / "archive-receipt.json", 4096)
    encrypted = read_file(output / "encrypted/checkpoints.hge", MAX_ARCHIVE_BYTES)
    require(
        receipt.get("schema") == "hol-guard.native-qualification-archive-receipt.v1"
        and receipt.get("status") == "encrypted"
        and receipt.get("archive_created") is True
        and receipt.get("recipient_key_id") == RECIPIENT_ID
        and type(receipt.get("files")) is int
        and receipt["files"] == 8
        and type(receipt.get("archive_bytes")) is int
        and receipt["archive_bytes"] == len(encrypted)
        and receipt.get("archive_sha256") == hashlib.sha256(encrypted).hexdigest(),
        "transition_retention_incomplete",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("run", "archive", "retention"), required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--dependency-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--public-key", type=Path)
    args = parser.parse_args()
    context = {
        "source_sha": args.source_sha,
        "target": args.target,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
    }
    output = args.output.resolve()
    plan(context)
    if args.action == "run":
        if args.bundle is None or args.dependency_root is None:
            raise ValueError("transition_inputs_missing")
        result = run(args.bundle.resolve(), output, args.dependency_root.resolve(), context)
        return 0 if result["passed"] else 1
    if args.action == "retention":
        retention(output, context)
        return 0
    require(args.public_key is not None, "transition_recipient_missing")
    status = 0
    try:
        receipt = archive(output, context, args.public_key.resolve())
        status = 0 if read_public(output / "aggregate/archive-validation.json")["passed"] is True else 1
    except Exception:
        receipt, status = failure_receipt("archive_output_failed"), 1
    publish_receipt(output / "archive-receipt.json", canonical(receipt) + b"\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
