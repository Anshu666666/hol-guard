#!/usr/bin/env python3
"""Fail-closed aggregation of every indexed, encrypted qualification pair."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_pair_comparison import compare_blocks  # noqa: E402
from scripts.native_slo_pair_io import MANIFEST_LIMIT, canonical, digest_file, require, write_public  # noqa: E402
from scripts.native_slo_pair_record import validate_context  # noqa: E402
from scripts.native_slo_pair_validation import validate_pair  # noqa: E402
from scripts.native_slo_qualification_bundle import load_bundle  # noqa: E402


def aggregate_pairs(*, pair_roots: Path, bundle_root: Path, context: dict[str, Any]) -> dict[str, object]:
    validate_context({**context, "pair_index": 0})
    bundle = load_bundle(bundle_root, target=context["target"], candidate_sha=context["build_sha"], verify_files=False)
    require(
        digest_file(bundle_root / "bundle.json", MANIFEST_LIMIT) == context["bundle_sha256"],
        "aggregate_bundle_mismatch",
    )
    evidence: list[dict[str, object]] = []
    reports: dict[str, list[dict[str, object]]] = {"baseline": [], "candidate": []}
    expected_names = {
        f"pair-{context['target']}-{index}-{context['run_id']}-{context['run_attempt']}"
        for index in range(context["runs"])
    }
    unexpected = pair_roots.exists() and any(path.name not in expected_names for path in pair_roots.iterdir())
    for index in range(context["runs"]):
        item: dict[str, object]
        root = pair_roots / f"pair-{context['target']}-{index}-{context['run_id']}-{context['run_attempt']}"
        try:
            item, blocks = validate_pair(root, {**context, "pair_index": index}, bundle)
        except (ValueError, OSError, TypeError, KeyError, OverflowError):
            item = {
                "pair_index": index,
                "collection_complete": False,
                "archive_complete": False,
                "reason": "pair_missing_or_invalid",
            }
            blocks = {}
        evidence.append(item)
        for arm, block in blocks.items():
            reports[arm].append(block)
    complete = not unexpected and all(item["collection_complete"] is True for item in evidence)
    result: dict[str, object] = {
        "schema": "hol-guard.qualification-pair-aggregation.v1",
        "context": context,
        "pairs": evidence,
        "expected_pairs": context["runs"],
        "collection_complete": complete,
        "comparison_available": False,
        "sampling_passed": False,
        "qualification_complete": False,
        "program_qualification_complete": False,
        "completed_blocks": {arm: len(values) for arm, values in reports.items()},
        "reason": "unexpected_pair_evidence" if unexpected else "pair_collection_incomplete",
    }
    if complete:
        try:
            comparison = compare_blocks(
                reports,
                mode=context["mode"],
                runs=context["runs"],
                artifact_digests={arm: bundle["arms"][arm]["wheel_sha256"] for arm in reports},
            )
        except (ValueError, RuntimeError, TypeError, KeyError, OverflowError):
            result["reason"] = "pair_comparison_contract_failed"
        else:
            result.update(
                reason="pair_comparison_complete",
                comparison_available=True,
                sampling_passed=comparison["sampling_passed"],
                qualification_complete=comparison["qualification_complete"],
                comparison=comparison,
            )
    return result


def exit_status(result: dict[str, object], mode: str) -> int:
    collected = result.get("collection_complete") is True and result.get("comparison_available") is True
    if mode == "smoke":
        return 0 if collected else 1
    return (
        0 if collected and result.get("sampling_passed") is True and result.get("qualification_complete") is True else 1
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--mode", choices=("smoke", "qualification"), required=True)
    args = parser.parse_args()
    result: dict[str, object]
    try:
        context = {
            "build_sha": args.candidate_sha,
            "target": args.target,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "runs": 5 if args.mode == "qualification" else 1,
            "mode": args.mode,
            "bundle_sha256": digest_file(args.bundle / "bundle.json", MANIFEST_LIMIT),
        }
        result = aggregate_pairs(pair_roots=args.pairs, bundle_root=args.bundle, context=context)
    except (ValueError, OSError, TypeError, KeyError, OverflowError):
        result = {
            "schema": "hol-guard.qualification-pair-aggregation.v1",
            "reason": "aggregation_context_invalid",
            "collection_complete": False,
            "comparison_available": False,
            "sampling_passed": False,
            "qualification_complete": False,
            "program_qualification_complete": False,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # The comparison remains at its original depth for the public privacy bound.
    comparison = result.pop("comparison", None)
    if isinstance(comparison, dict):
        write_public(args.output.with_name("comparison.json"), comparison)
    write_public(args.output, result)
    print(canonical(result).decode("ascii"))
    return exit_status(result, args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
