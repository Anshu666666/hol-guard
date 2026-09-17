#!/usr/bin/env python3
"""Reject incomplete companion pairs; compare exact nonpriority workloads only."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_pair_io import MANIFEST_LIMIT, digest_file, read_public, require, write_public  # noqa: E402
from scripts.native_slo_pair_record import validate_context  # noqa: E402
from scripts.native_slo_pair_validation import RECIPIENT_ID, validate_archive  # noqa: E402
from scripts.native_slo_qualification import compare_routes, paired_order  # noqa: E402
from scripts.native_slo_qualification_bundle import load_bundle  # noqa: E402
from scripts.native_slo_surface_tail_contract import (  # noqa: E402
    COHORT_FIELDS,
    NUMERIC_LIMIT,
    ROUTES,
    SCHEMA,
    TailRoute,
    plan,
    route_for,
    workload,
)
from scripts.native_slo_surface_tail_record import check_report  # noqa: E402

_HEX = frozenset("0123456789abcdef")


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def pair_name(route: TailRoute, context: Mapping[str, Any], index: int) -> str:
    return f"surface-tail-{context['target']}-{route.identifier}-{index}-{context['run_id']}-{context['run_attempt']}"


def validate_pair(
    root: Path, *, route: TailRoute, context: dict[str, Any], bundle: dict[str, Any], recipient_id: str = RECIPIENT_ID
) -> tuple[dict[str, object], dict[str, dict[str, Any]]]:
    validate_context(context)
    manifest = read_public(root / "aggregate/pair-manifest.json", MANIFEST_LIMIT)
    require(
        set(manifest)
        == {
            "schema",
            "context",
            "workload",
            "expected_order",
            "offered_order",
            "arms",
            "collection_complete",
            "qualification_complete",
            "program_qualification_complete",
        }
        and manifest["schema"] == SCHEMA,
        "surface_tail_manifest_schema",
    )
    require(
        manifest["context"] == context and manifest["workload"] == workload(route, context["mode"]),
        "surface_tail_manifest_context",
    )
    order = list(paired_order(context["pair_index"]))
    require(
        manifest["expected_order"] == order and manifest["offered_order"] in ([], order[:1], order),
        "surface_tail_manifest_order",
    )
    require(
        manifest["qualification_complete"] is False and manifest["program_qualification_complete"] is False,
        "surface_tail_premature_acceptance",
    )
    states = manifest["arms"]
    require(isinstance(states, dict) and set(states) == {"baseline", "candidate"}, "surface_tail_arm_inventory")
    reports: dict[str, dict[str, Any]] = {}
    for arm, state in states.items():
        require(
            isinstance(state, dict) and state.get("status") in {"completed", "failed", "unattempted"},
            "surface_tail_arm_state",
        )
        require(
            (arm in manifest["offered_order"]) == (state["status"] != "unattempted"), "surface_tail_offer_conservation"
        )
        prefix = f"{context['pair_index']:02d}-{arm}"
        if arm in manifest["offered_order"]:
            require(
                read_public(root / f"aggregate/{prefix}-offer.json", MANIFEST_LIMIT)
                == {
                    "schema": "hol-guard.nonpriority-tail-offer.v1",
                    "context": context,
                    "workload": workload(route, context["mode"]),
                    "arm": arm,
                    "ordinal": order.index(arm) + 1,
                },
                "surface_tail_offer_identity",
            )
        if state["status"] == "completed":
            require(
                set(state) == {"status", "numeric", "report_sha256"} and _digest(state["report_sha256"]),
                "surface_tail_completed_fields",
            )
            numeric = state["numeric"]
            require(
                isinstance(numeric, dict)
                and set(numeric) == {"sha256", "bytes", "series_counts"}
                and _digest(numeric["sha256"])
                and type(numeric["bytes"]) is int
                and 0 < numeric["bytes"] <= NUMERIC_LIMIT
                and numeric["series_counts"] == {route.series: plan(context["mode"])["samples_per_arm"]},
                "surface_tail_numeric_commitment",
            )
            path = root / f"aggregate/{prefix}.json"
            require(digest_file(path, 256 * 1024) == state["report_sha256"], "surface_tail_report_digest")
            report = read_public(path)
            check_report(report, route=route, mode=context["mode"], bundle=bundle, arm=arm)
            reports[arm] = report
        elif state["status"] == "failed":
            if set(state) == {"status", "failure_sha256"}:
                path = root / f"aggregate/{prefix}-failure.json"
                require(
                    _digest(state["failure_sha256"]) and digest_file(path, 256 * 1024) == state["failure_sha256"],
                    "surface_tail_failure_digest",
                )
                read_public(path)
            else:
                require(
                    state == {"status": "failed", "reason": "pair_controller_interrupted"}, "surface_tail_failure_state"
                )
        else:
            require(set(state) == {"status"}, "surface_tail_unattempted_state")
    require(
        type(manifest["collection_complete"]) is bool and manifest["collection_complete"] == (len(reports) == 2),
        "surface_tail_false_completion",
    )
    receipt = validate_archive(root, context, manifest, recipient_id=recipient_id)
    retained = receipt["pair_binding"]["numeric_commitments_verified"]
    require(not retained or receipt["files"] >= len(reports) + 1, "surface_tail_archive_inventory")
    return {
        "pair_index": context["pair_index"],
        "collection_complete": len(reports) == 2 and retained,
        "arms": {arm: state["status"] for arm, state in states.items()},
        "archive_complete": True,
        "numeric_commitments_verified": retained,
        "manifest_sha256": digest_file(root / "aggregate/pair-manifest.json", MANIFEST_LIMIT),
        "archive_sha256": receipt["archive_sha256"],
    }, reports if retained else {}


def compare(reports: dict[str, list[dict[str, Any]]], *, route: TailRoute, mode: str) -> dict[str, object]:
    expected = plan(mode)
    require(
        set(reports) == {"baseline", "candidate"} and all(len(items) == expected["runs"] for items in reports.values()),
        "surface_tail_paired_blocks_missing",
    )
    combined = [*reports["baseline"], *reports["candidate"]]
    for report in combined:
        require(
            all(report.get(key) == value for key, value in workload(route, mode).items()),
            "surface_tail_comparison_workload",
        )
        require(
            report["hardware"] and all(report["hardware"].get(key) is not None for key in COHORT_FIELDS),
            "surface_tail_cohort_missing",
        )
    reference = combined[0]
    require(
        all(
            tuple(report["hardware"][key] for key in COHORT_FIELDS)
            == tuple(reference["hardware"][key] for key in COHORT_FIELDS)
            for report in combined
        ),
        "surface_tail_cohort_changed",
    )
    require(len({report["runtime"]["python_version"] for report in combined}) == 1, "surface_tail_python_changed")
    for items in reports.values():
        require(
            len(
                {
                    tuple(
                        report["runtime"][key]
                        for key in (
                            "runtime_sha256",
                            "package_record_sha256",
                            "installed_package_sha256",
                            "dependency_versions_sha256",
                        )
                    )
                    for report in items
                }
            )
            == 1,
            "surface_tail_artifact_changed",
        )
    comparison = compare_routes(
        [item["measurements"] for item in reports["baseline"]], [item["measurements"] for item in reports["candidate"]]
    )
    observed = cast(Mapping[str, Any], comparison[route.series])
    sampling = expected["runs"] == 5 and all(observed[f"{arm}_samples"] == 1000 for arm in reports)
    # Intrinsic-review response latency is reported separately from ordinary
    # noninteractive allow targets. No browser or host wait is timed here.
    applicable = "/normal/" not in route.case_id
    targets = applicable and all(
        item["measurements"][route.series]["p95_ms"] <= 50 and item["measurements"][route.series]["p99_ms"] <= 100
        for item in reports["candidate"]
    )
    return {
        "comparisons": comparison,
        "sampling_passed": sampling,
        "tail_sampling_qualified": sampling,
        "comparison_available": True,
        "ordinary_c1_target_applicable": applicable,
        "ordinary_c1_target_passed": targets,
        "ordinary_c1_scope_qualified": mode == "qualification" and sampling and targets,
        "qualification_complete": False,
        "program_qualification_complete": False,
        "qualification_scope": "declared_nonpriority_ordinary_c1",
        "hardware": reference["hardware"],
        "baseline": reports["baseline"][0]["runtime"],
        "candidate": reports["candidate"][0]["runtime"],
    }


def aggregate(*, roots: Path, bundle: dict[str, Any], context: dict[str, Any], route: TailRoute) -> dict[str, Any]:
    evidence: list[dict[str, object]] = []
    reports: dict[str, list[dict[str, Any]]] = {"baseline": [], "candidate": []}
    for index in range(plan(context["mode"])["runs"]):
        item: dict[str, object]
        try:
            item, blocks = validate_pair(
                roots / pair_name(route, context, index),
                route=route,
                context={**context, "pair_index": index},
                bundle=bundle,
            )
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
    result: dict[str, Any] = {
        "schema": "hol-guard.nonpriority-tail-aggregation.v1",
        "context": context,
        "workload": workload(route, context["mode"]),
        "pairs": evidence,
        "collection_complete": all(item["collection_complete"] is True for item in evidence),
        "comparison_available": False,
        "sampling_passed": False,
        "tail_sampling_qualified": False,
        "qualification_complete": False,
        "program_qualification_complete": False,
        "reason": "pair_collection_incomplete",
    }
    if result["collection_complete"]:
        try:
            result.update(compare(reports, route=route, mode=context["mode"]))
            result["reason"] = "pair_comparison_complete"
        except (ValueError, TypeError, KeyError, OverflowError):
            result["reason"] = "pair_comparison_contract_failed"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("pairs", "bundle", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("target", "candidate-sha", "selection", "mode"):
        parser.add_argument("--" + name, required=True)
    for name in ("run-id", "run-attempt"):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    routes = ROUTES if args.selection == "all" else (route_for(args.selection),)
    bundle = load_bundle(args.bundle, target=args.target, candidate_sha=args.candidate_sha, verify_files=False)
    context: dict[str, Any] = {
        "target": args.target,
        "build_sha": args.candidate_sha,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "mode": args.mode,
        "runs": plan(args.mode)["runs"],
        "bundle_sha256": digest_file(args.bundle / "bundle.json", MANIFEST_LIMIT),
    }
    validate_context({**context, "pair_index": 0})
    expected = {pair_name(route, context, index) for route in routes for index in range(context["runs"])}
    unexpected = args.pairs.exists() and any(path.name not in expected for path in args.pairs.iterdir())
    args.output.mkdir(parents=True, exist_ok=True)
    passed = not unexpected
    for route in routes:
        result = aggregate(roots=args.pairs, bundle=bundle, context=context, route=route)
        if unexpected:
            invalidate(result, "unexpected_pair_evidence")
        # Prevent nesting confidence summaries beyond the shared public bound.
        comparison = result.pop("comparisons", None)
        if comparison is not None:
            write_public(args.output / f"{route.identifier}-comparison.json", comparison)
        write_public(args.output / f"{route.identifier}.json", result)
        passed = passed and result["collection_complete"] and result["comparison_available"]
        if args.mode == "qualification":
            # A review-response collection has no ordinary allow target. Its
            # success disposition is explicitly sampling-only, never product
            # or complete platform qualification.
            passed = passed and result.get("tail_sampling_qualified") is True
            if result.get("ordinary_c1_target_applicable") is True:
                passed = passed and result.get("ordinary_c1_scope_qualified") is True
    return 0 if passed else 1


def invalidate(result: dict[str, Any], reason: str) -> None:
    for key in (
        "collection_complete",
        "comparison_available",
        "sampling_passed",
        "tail_sampling_qualified",
        "ordinary_c1_target_passed",
        "ordinary_c1_scope_qualified",
        "qualification_complete",
        "program_qualification_complete",
    ):
        result[key] = False
    result.pop("comparisons", None)
    result["reason"] = reason


if __name__ == "__main__":
    raise SystemExit(main())
