#!/usr/bin/env python3
"""Collect or seal one separately budgeted nonpriority installed-route pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment  # noqa: E402
from scripts.native_slo_evidence_archive import encrypt_samples, failure_receipt  # noqa: E402
from scripts.native_slo_evidence_files import atomic_exclusive, read_file  # noqa: E402
from scripts.native_slo_evidence_public import publish_receipt  # noqa: E402
from scripts.native_slo_pair_install import interpreter  # noqa: E402
from scripts.native_slo_pair_io import (  # noqa: E402
    MANIFEST_LIMIT,
    canonical,
    decode,
    digest_file,
    read_public,
    require,
    write_public,
)
from scripts.native_slo_pair_record import validate_context  # noqa: E402
from scripts.native_slo_pair_validation import RECIPIENT_ID, retained_numeric_commitments  # noqa: E402
from scripts.native_slo_qualification import paired_order  # noqa: E402
from scripts.native_slo_qualification_bundle import load_bundle  # noqa: E402
from scripts.native_slo_surface_tail_contract import (  # noqa: E402
    UNAVAILABLE_CODES,
    WORKER_SECONDS,
    plan,
    route_for,
    workload,
)
from scripts.native_slo_surface_tail_record import TailRecorder  # noqa: E402


def context_for(args: argparse.Namespace) -> dict[str, Any]:
    result = {
        "build_sha": args.candidate_sha,
        "target": args.target,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "pair_index": args.pair_index,
        "mode": args.mode,
        "runs": plan(args.mode)["runs"],
        "bundle_sha256": digest_file(args.bundle / "bundle.json", MANIFEST_LIMIT),
    }
    validate_context(result)
    return result


def collect_pair(args: argparse.Namespace) -> dict[str, Any]:
    context, route = context_for(args), route_for(args.route)
    bundle = load_bundle(args.bundle, target=args.target, candidate_sha=args.candidate_sha)
    recorder = TailRecorder(root=args.output, context=context, route=route, bundle=bundle)
    for directory in (recorder.public, recorder.private):
        existing = list(directory.iterdir()) if directory.exists() else []
        require(
            not directory.is_symlink()
            and all(
                directory == recorder.public
                and path.name == "runner-resolver.json"
                and path.is_file()
                and not path.is_symlink()
                for path in existing
            ),
            "surface_tail_fresh_destination_required",
        )
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    environment = dict(os.environ)
    clear_proof_environment(environment)
    try:
        for arm in paired_order(args.pair_index):
            recorder.offer(arm)
            raw = recorder.private / f"{args.pair_index:02d}-{arm}.json"
            completed = run_isolated_hook_process(
                (
                    str(interpreter(args.environments, arm)),
                    str(_ROOT / "scripts/native_slo_surface_tail_worker.py"),
                    "--route",
                    route.identifier,
                    "--mode",
                    args.mode,
                    "--raw-file",
                    str(raw.resolve()),
                ),
                input_text="",
                cwd=_ROOT,
                environment=environment,
                timeout_seconds=WORKER_SECONDS,
                output_limit=256 * 1024,
            )
            failed = (
                completed.returncode != 0
                or completed.timed_out
                or completed.containment_failed
                or completed.output_limit_exceeded
            )
            if not failed:
                try:
                    report = decode(completed.stdout.encode())
                    report["artifact_sha256"] = bundle["arms"][arm]["wheel_sha256"]
                    recorder.completed(arm, report, raw)
                except (ValueError, TypeError, KeyError, OSError):
                    failed = True
            if failed:
                # Failure message text is never an accepted public field.
                atomic_exclusive(
                    recorder.private / f"{args.pair_index:02d}-{arm}-diagnostic.json",
                    canonical({"worker_stdout": completed.stdout}),
                )
                failure = {
                    "schema": "hol-guard.nonpriority-tail-failure.v1",
                    "reason": "worker_failed",
                    "arm": arm,
                    "timed_out": completed.timed_out,
                    "containment_failed": completed.containment_failed,
                    "diagnostic_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                }
                try:
                    availability = decode(completed.stdout.encode()).get("availability_code")
                except (ValueError, TypeError):
                    availability = None
                if isinstance(availability, str) and availability in UNAVAILABLE_CODES:
                    failure["availability_code"] = availability
                write_public(recorder.public / f"{args.pair_index:02d}-{arm}-failure.json", failure)
                recorder.failed(arm)
                if completed.containment_failed:
                    raise RuntimeError("surface_tail_worker_containment_failed")
                continue
    finally:
        recorder.finish()
    assert recorder.report is not None
    return recorder.report


def archive_pair(args: argparse.Namespace) -> dict[str, object]:
    context, route = context_for(args), route_for(args.route)
    bundle = load_bundle(args.bundle, target=args.target, candidate_sha=args.candidate_sha, verify_files=False)
    public, private = args.output / "aggregate", args.output / "private_samples"
    public.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, mode=0o700, exist_ok=True)
    manifest = public / "pair-manifest.json"
    if not manifest.exists():
        recorder = TailRecorder(root=args.output, context=context, route=route, bundle=bundle)
        for ordinal, arm in enumerate(paired_order(args.pair_index), 1):
            offer = public / f"{args.pair_index:02d}-{arm}-offer.json"
            if offer.exists():
                require(
                    read_public(offer, MANIFEST_LIMIT)
                    == {
                        "schema": "hol-guard.nonpriority-tail-offer.v1",
                        "context": context,
                        "workload": workload(route, args.mode),
                        "arm": arm,
                        "ordinal": ordinal,
                    },
                    "surface_tail_recovery_offer_invalid",
                )
                recorder.offered.append(arm)
                recorder.states[arm] = {"status": "failed", "reason": "pair_controller_interrupted"}
        # Even complete-looking leftovers cannot recover a success claim.
        recorder.finish()
    record = read_public(manifest, MANIFEST_LIMIT)
    require(
        record.get("context") == context and record.get("workload") == workload(route, args.mode),
        "surface_tail_archive_context_mismatch",
    )
    encoded = read_file(manifest, MANIFEST_LIMIT)
    retained = private / "pair-manifest.json"
    if not retained.exists():
        atomic_exclusive(retained, encoded)
    require(read_file(retained, MANIFEST_LIMIT) == encoded, "surface_tail_archive_manifest_mismatch")
    return encrypt_samples(
        source=private,
        output=args.output / "encrypted/observations.hge",
        public_key=args.public_key,
        recipient_id=RECIPIENT_ID,
        numeric_commitments=retained_numeric_commitments(record),
        context={
            "source_sha": args.candidate_sha,
            "target": args.target,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "pair_index": args.pair_index,
            "pair_manifest_sha256": digest_file(manifest, MANIFEST_LIMIT),
            "bundle_sha256": context["bundle_sha256"],
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("collect", "conditioned-collect", "archive"), required=True)
    for name in ("bundle", "output", "environments", "public-key"):
        parser.add_argument("--" + name, type=Path, required=name in {"bundle", "output"})
    for name in ("route", "candidate-sha", "target", "mode"):
        parser.add_argument("--" + name, required=True)
    for name in ("pair-index", "run-id", "run-attempt"):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    if args.action == "conditioned-collect":
        # Match the main pair's disposable runner conditioning, equally for
        # both immutable arms; raw resolver capture flushes after collection.
        command = [
            sys.executable,
            str(_ROOT / "scripts/ci/native_loopback_resolver.py"),
            "--output",
            str(args.output / "aggregate/runner-resolver.json"),
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--action",
            "collect",
        ]
        for name in (
            "bundle",
            "output",
            "environments",
            "route",
            "candidate_sha",
            "target",
            "mode",
            "pair_index",
            "run_id",
            "run_attempt",
        ):
            value = getattr(args, name)
            require(value is not None, "surface_tail_conditioned_argument_missing")
            command.extend(("--" + name.replace("_", "-"), str(value)))
        return subprocess.call(command)
    status = 1
    try:
        if args.action == "collect":
            require(args.environments is not None, "surface_tail_environments_required")
            result = collect_pair(args)
            status = 0 if result["collection_complete"] is True else 1
        else:
            require(args.public_key is not None, "surface_tail_recipient_required")
            result = archive_pair(args)
            binding = result.get("pair_binding")
            status = (
                0
                if (
                    result.get("status") == "encrypted"
                    and isinstance(binding, dict)
                    and binding.get("numeric_commitments_verified") is True
                )
                else 1
            )
    except Exception:
        result = (
            failure_receipt("archive_output_failed")
            if args.action == "archive"
            else {
                "schema": "hol-guard.nonpriority-tail-failure.v1",
                "reason": "pair_failed",
                "collection_complete": False,
            }
        )
    if args.action == "archive":
        publish_receipt(args.output / "archive-receipt.json", canonical(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
