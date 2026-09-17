#!/usr/bin/env python3
"""Opt-in fixed scanner shards, immutable-snapshot sealing and finite aggregation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.native_slo_evidence_archive import encrypt_samples, failure_receipt
from scripts.native_slo_evidence_files import atomic_exclusive, read_file
from scripts.native_slo_evidence_format import MAX_ARCHIVE_BYTES, canonical, digest
from scripts.scanner_pilot_protocol import (
    ATTEMPTS,
    CASES,
    RECIPIENT,
    RUNS,
    SCHEMA,
    planned,
    private_write,
    read_json,
)
from scripts.scanner_pilot_public import aggregate, projection, validate_report


def matrix(selection: str) -> list[dict[str, Any]]:
    if selection == "smoke":
        return [{"case": "working_provider_large", "run": 0}]
    if selection == "full":
        return [{"case": case, "run": run} for case in CASES for run in range(RUNS)]
    raise ValueError("scanner_selection_invalid")


def initialize(output: Path, *, source_sha: str, case: str, run: int, selection: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}", source_sha) or {"case": case, "run": run} not in matrix(selection):
        raise ValueError("scanner_shard_invalid")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = output / "private_samples"
    private.mkdir(mode=0o700)
    private_write(
        private,
        "plan.json",
        {
            "schema": SCHEMA,
            "case": case,
            "run": run,
            "selection": selection,
            "source_sha": source_sha,
            "attempts": planned(case, run),
        },
    )


def seal_evidence(
    output: Path,
    *,
    public_key: Path,
    source_sha: str,
    case: str,
    run: int,
    selection: str,
    run_id: int,
    run_attempt: int,
) -> bool:
    public = output / "public"
    public.mkdir(mode=0o700, exist_ok=True)
    report: dict[str, Any] = {"schema": SCHEMA, "status": "projection_unavailable", "installed_qualified": False}
    projected = False

    def observe(snapshot: tuple[tuple[str, bytes], ...]) -> None:
        nonlocal report, projected
        try:
            report = projection(snapshot, source_sha=source_sha, case=case, run=run, selection=selection)
            projected = True
        except (ValueError, TypeError, KeyError, OverflowError):
            # Preserve the exact mismatching snapshot encrypted, without
            # claiming a public projection or exposing any private fields.
            report = {"schema": SCHEMA, "status": "projection_failed", "installed_qualified": False}

    receipt = failure_receipt("archive_output_failed")
    try:
        receipt = encrypt_samples(
            source=output / "private_samples",
            output=output / "observations.hge",
            public_key=public_key,
            recipient_id=RECIPIENT,
            context={"source_sha": source_sha, "run_id": run_id, "run_attempt": run_attempt},
            snapshot_observer=observe,
        )
    finally:
        encoded = canonical(report)
        atomic_exclusive(public / "summary.json", encoded)
        atomic_exclusive(public / "archive-receipt.json", canonical(receipt))
        atomic_exclusive(
            public / "retention.json",
            canonical(
                {
                    "schema": SCHEMA,
                    "projection_verified": projected,
                    "summary_sha256": digest(encoded),
                    "archive_receipt_sha256": digest(canonical(receipt)),
                    "source_sha": source_sha,
                    "case": case,
                    "run": run,
                    "selection": selection,
                }
            ),
        )
    return projected and receipt["status"] == "encrypted"


def admitted_public(public: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    summary = read_file(public / "summary.json", 256 * 1024)
    receipt_bytes = read_file(public / "archive-receipt.json", 4096)
    binding = read_json(public / "retention.json", 4096)
    receipt = json.loads(receipt_bytes)
    report = validate_report(json.loads(summary))
    if (
        binding
        != {
            "schema": SCHEMA,
            "projection_verified": True,
            "summary_sha256": digest(summary),
            "archive_receipt_sha256": digest(receipt_bytes),
            "source_sha": report["source_sha"],
            "case": report["case"],
            "run": report["run"],
            "selection": report["selection"],
        }
        or receipt.get("status") != "encrypted"
        or receipt.get("archive_created") is not True
        or receipt.get("schema") != "hol-guard.native-qualification-archive-receipt.v1"
        or receipt.get("recipient_key_id") != RECIPIENT
        or not isinstance(receipt.get("archive_sha256"), str)
        or re.fullmatch(r"[a-f0-9]{64}", receipt["archive_sha256"]) is None
        or type(receipt.get("archive_bytes")) is not int
        or not 0 < receipt["archive_bytes"] <= MAX_ARCHIVE_BYTES
        or type(receipt.get("files")) is not int
        or receipt["files"] != report["private_files"]
        or not 0 < receipt["files"] <= 256
    ):
        raise ValueError("scanner_retention_incomplete")
    return report, receipt


def verify_retention(output: Path) -> None:
    report, receipt = admitted_public(output / "public")
    archive = read_file(output / "observations.hge", MAX_ARCHIVE_BYTES)
    if (
        receipt["archive_sha256"] != digest(archive)
        or receipt["archive_bytes"] != len(archive)
        or not report["collection_complete"]
    ):
        raise ValueError("scanner_retention_or_collection_incomplete")


def combine(directory: Path, output: Path, *, selection: str, source_sha: str, shards_outcome: str = "unknown") -> bool:
    reports = []
    invalid = 0
    report: dict[str, Any]
    paths = sorted(directory.glob("*/summary.json"))
    if len(paths) > len(matrix(selection)):
        raise ValueError("scanner_aggregate_file_bound")
    for path in paths:
        try:
            reports.append(admitted_public(path.parent)[0])
        except (ValueError, TypeError, KeyError, OSError):
            invalid += 1
    try:
        report = aggregate(reports, selection=selection, source_sha=source_sha)
    except (ValueError, TypeError, KeyError):
        report = {
            "schema": SCHEMA,
            "selection": selection,
            "source_sha": source_sha,
            "collection_complete": False,
            "installed_qualified": False,
            "planned_attempts": len(matrix(selection)) * ATTEMPTS,
            "status": "aggregate_invalid",
        }
        invalid += 1
    report["invalid_shards"] = invalid
    report["upstream_retention_passed"] = shards_outcome == "success"
    if invalid or shards_outcome != "success":
        report["collection_complete"] = False
        report["minimum_independent_runs_met"] = False
        for cohort in report.get("cohorts", []):
            cohort["comparison"] = None
            cohort["benefit_gate_passed"] = False
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_exclusive(output, canonical(report))
    return bool(report["collection_complete"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("matrix", "init", "collect", "seal", "verify", "aggregate"))
    parser.add_argument("--selection", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--run", type=int, default=0)
    parser.add_argument("--source-sha")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--output", type=Path, default=Path("scanner-evidence"))
    parser.add_argument("--input", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--run-id", type=int, default=1)
    parser.add_argument("--run-attempt", type=int, default=1)
    parser.add_argument(
        "--shards-outcome", choices=("success", "failure", "cancelled", "skipped", "unknown"), default="unknown"
    )
    args = parser.parse_args()
    if args.operation == "matrix":
        print(json.dumps({"include": matrix(args.selection)}, separators=(",", ":")))
        return 0
    if args.operation == "verify":
        verify_retention(args.output)
        return 0
    if args.source_sha is None or re.fullmatch(r"[a-f0-9]{40}", args.source_sha) is None:
        parser.error("exact --source-sha is required")
    if args.operation == "aggregate":
        if args.input is None:
            parser.error("--input is required")
        return (
            0
            if combine(
                args.input,
                args.output,
                selection=args.selection,
                source_sha=args.source_sha,
                shards_outcome=args.shards_outcome,
            )
            else 1
        )
    if args.case is None or {"case": args.case, "run": args.run} not in matrix(args.selection):
        parser.error("case/run does not belong to fixed selection")
    if args.operation == "init":
        initialize(args.output, source_sha=args.source_sha, case=args.case, run=args.run, selection=args.selection)
        return 0
    if args.operation == "seal":
        if args.public_key is None:
            parser.error("--public-key is required")
        return (
            0
            if seal_evidence(
                args.output,
                public_key=args.public_key,
                source_sha=args.source_sha,
                case=args.case,
                run=args.run,
                selection=args.selection,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
            else 1
        )
    if args.binary is None or args.lock is None:
        parser.error("--binary and --lock are required")
    from scripts.scanner_pilot_worker import collect

    return (
        0
        if collect(
            args.root.resolve(),
            args.binary.resolve(),
            args.output.resolve() / "private_samples",
            expected_source=args.source_sha,
            lock=args.lock,
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
