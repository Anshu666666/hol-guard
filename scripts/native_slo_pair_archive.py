#!/usr/bin/env python3
"""Archive a pair, retaining interrupted collection as failed evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_evidence_archive import encrypt_samples, failure_receipt  # noqa: E402
from scripts.native_slo_evidence_files import atomic_exclusive, read_file  # noqa: E402
from scripts.native_slo_evidence_format import canonical  # noqa: E402
from scripts.native_slo_evidence_public import publish_receipt  # noqa: E402
from scripts.native_slo_pair_io import MANIFEST_LIMIT, digest_file, read_public, require  # noqa: E402
from scripts.native_slo_pair_record import PairRecorder, validate_context  # noqa: E402
from scripts.native_slo_pair_validation import retained_numeric_commitments  # noqa: E402
from scripts.native_slo_qualification import paired_order  # noqa: E402
from scripts.native_slo_qualification_bundle import load_bundle  # noqa: E402


def archive_pair(args: argparse.Namespace) -> dict[str, object]:
    bundle = load_bundle(args.bundle, target=args.target, candidate_sha=args.candidate_sha, verify_files=False)
    context = {
        "build_sha": args.candidate_sha,
        "target": args.target,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "pair_index": args.pair_index,
        "runs": args.runs,
        "mode": args.mode,
        "bundle_sha256": digest_file(args.bundle / "bundle.json", MANIFEST_LIMIT),
    }
    validate_context(context)
    public, private = args.pair_root / "aggregate", args.pair_root / "private_samples"
    public.mkdir(parents=True, exist_ok=True)
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = public / "pair-manifest.json"
    if not manifest.exists():
        recorder = PairRecorder(public=public, private=private, context=context, bundle=bundle)
        for ordinal, arm in enumerate(paired_order(args.pair_index), 1):
            offer = public / f"{args.pair_index:02d}-{arm}-offer.json"
            if offer.exists():
                value = read_public(offer, MANIFEST_LIMIT)
                require(
                    value
                    == {
                        "schema": "hol-guard.qualification-offer.v1",
                        "context": context,
                        "arm": arm,
                        "ordinal": ordinal,
                    },
                    "pair_recovery_offer_invalid",
                )
                recorder.offered.append(arm)
                recorder.states[arm] = {"status": "failed", "reason": "pair_controller_interrupted"}
        # Recovery never infers successful completion from leftover files.
        recorder.__exit__(RuntimeError, None, None)
    record = read_public(manifest, MANIFEST_LIMIT)
    require(record.get("context") == context, "pair_archive_context_mismatch")
    encoded = read_file(manifest, MANIFEST_LIMIT)
    retained = private / "pair-manifest.json"
    if not retained.exists():
        atomic_exclusive(retained, encoded)
    require(read_file(retained, MANIFEST_LIMIT) == encoded, "pair_archive_manifest_mismatch")
    return encrypt_samples(
        source=private,
        output=args.pair_root / "encrypted" / "observations.hge",
        public_key=args.public_key,
        recipient_id=args.recipient_id,
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
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--pair-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--pair-index", type=int, required=True)
    parser.add_argument("--runs", type=int, required=True)
    parser.add_argument("--mode", choices=("smoke", "qualification"), required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--recipient-id", required=True)
    args = parser.parse_args()
    status = 0
    try:
        receipt = archive_pair(args)
        require(receipt.get("status") == "encrypted", "pair_archive_missing")
        binding = receipt.get("pair_binding")
        if not isinstance(binding, dict) or binding.get("numeric_commitments_verified") is not True:
            status = 1
    except Exception:
        receipt = failure_receipt("archive_output_failed")
        status = 1
    publish_receipt(args.pair_root / "archive-receipt.json", canonical(receipt) + b"\n")
    print(canonical(receipt).decode("ascii"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
