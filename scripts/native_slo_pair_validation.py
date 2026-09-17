"""Validate retained pair commitments without decoding private observations."""

from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from scripts.native_slo_evidence_format import HEX64, MAX_ARCHIVE_BYTES, MAX_FILES, canonical, digest
from scripts.native_slo_pair_io import MANIFEST_LIMIT, REPORT_LIMIT, digest_file, read_public, require
from scripts.native_slo_pair_record import PAIR_SCHEMA, expected_counts, validate_context, validate_runtime
from scripts.native_slo_qualification import paired_order, sampling_plan

RECIPIENT_ID = "d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb"
_MANIFEST_FIELDS = {
    "schema",
    "context",
    "plan",
    "expected_order",
    "offered_order",
    "arms",
    "collection_complete",
    "sampling_passed",
    "qualification_complete",
    "program_qualification_complete",
    "comparison_available",
}


def _digest(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def retained_numeric_commitments(manifest: Mapping[str, Any]) -> dict[str, dict[str, object]]:
    index = manifest["context"]["pair_index"]
    result = {}
    for arm in ("baseline", "candidate"):
        state = manifest["arms"][arm]
        if state["status"] == "completed":
            numeric = state["numeric"]
            result[f"{index:02d}-{arm}.json"] = {"bytes": numeric["bytes"], "sha256": numeric["sha256"]}
    return result


def validate_archive(
    root: Path, context: Mapping[str, Any], manifest: Mapping[str, Any], *, recipient_id: str
) -> dict[str, Any]:
    receipt = read_public(root / "archive-receipt.json", 4096)
    require(
        set(receipt)
        == {
            "schema",
            "status",
            "archive_created",
            "files",
            "archive_bytes",
            "archive_sha256",
            "recipient_key_id",
            "pair_binding",
        },
        "pair_archive_receipt_fields_invalid",
    )
    require(
        receipt["schema"] == "hol-guard.native-qualification-archive-receipt.v1"
        and receipt["status"] == "encrypted"
        and receipt["archive_created"] is True,
        "pair_archive_not_encrypted",
    )
    require(type(receipt["files"]) is int and 1 <= receipt["files"] <= MAX_FILES, "pair_archive_inventory_invalid")
    require(
        type(receipt["archive_bytes"]) is int and 0 < receipt["archive_bytes"] <= MAX_ARCHIVE_BYTES,
        "pair_archive_size_invalid",
    )
    require(
        receipt["recipient_key_id"] == recipient_id and _digest(receipt["archive_sha256"]),
        "pair_archive_identity_invalid",
    )
    manifest_sha = digest_file(root / "aggregate/pair-manifest.json", MANIFEST_LIMIT)
    binding = receipt["pair_binding"]
    require(
        isinstance(binding, dict) and type(binding.get("numeric_commitments_verified")) is bool,
        "pair_archive_numeric_proof_invalid",
    )
    require(
        receipt["pair_binding"]
        == {
            **{
                key: context[key]
                for key in ("build_sha", "target", "run_id", "run_attempt", "pair_index", "bundle_sha256")
            },
            "pair_manifest_sha256": manifest_sha,
            "numeric_commitments_sha256": digest(canonical(retained_numeric_commitments(manifest))),
            "numeric_commitments_verified": binding["numeric_commitments_verified"],
        },
        "pair_archive_binding_mismatch",
    )
    cipher = root / "encrypted/observations.hge"
    require(
        digest_file(cipher, MAX_ARCHIVE_BYTES) == receipt["archive_sha256"]
        and cipher.stat().st_size == receipt["archive_bytes"],
        "pair_archive_ciphertext_mismatch",
    )
    return receipt


def _completed(
    root: Path, index: int, arm: str, state: Mapping[str, Any], bundle: Mapping[str, Any], plan: Mapping[str, int]
) -> dict[str, object]:
    require(
        set(state) == {"status", "report_sha256", "numeric"} and _digest(state["report_sha256"]),
        "pair_completed_fields_invalid",
    )
    numeric = state["numeric"]
    counts = expected_counts(plan)
    require(
        isinstance(numeric, dict) and set(numeric) == {"sha256", "bytes", "series_counts"},
        "pair_numeric_fields_invalid",
    )
    require(
        _digest(numeric["sha256"]) and type(numeric["bytes"]) is int and 0 < numeric["bytes"] <= 4 * 1024 * 1024,
        "pair_numeric_identity_invalid",
    )
    require(numeric["series_counts"] == counts, "pair_numeric_count_mismatch")
    report_path = root / "aggregate" / f"{index:02d}-{arm}.json"
    require(digest_file(report_path, REPORT_LIMIT) == state["report_sha256"], "pair_report_digest_mismatch")
    report = read_public(report_path)
    require(report.get("schema") == "hol-guard.native-qualification-block.v1", "pair_report_schema_invalid")
    validate_runtime(report, bundle["arms"][arm], target=bundle["target"])
    summaries = report.get("measurements")
    require(isinstance(summaries, dict) and set(summaries) == set(counts), "pair_summary_series_incomplete")
    summaries = cast(dict[str, Any], summaries)
    for series, count in counts.items():
        summary = summaries[series]
        require(
            isinstance(summary, dict) and type(summary.get("count")) is int and summary["count"] == count,
            "pair_summary_count_mismatch",
        )
        for field in ("p50_ms", "p95_ms", "p99_ms", "max_ms"):
            value: Any = summary.get(field)
            require(type(value) in {int, float} and math.isfinite(value) and value >= 0, "pair_summary_value_invalid")
    return report


def validate_pair(
    root: Path, context: Mapping[str, Any], bundle: Mapping[str, Any], *, recipient_id: str = RECIPIENT_ID
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    validate_context(context)
    manifest = read_public(root / "aggregate/pair-manifest.json", MANIFEST_LIMIT)
    require(set(manifest) == _MANIFEST_FIELDS and manifest["schema"] == PAIR_SCHEMA, "pair_manifest_fields_invalid")
    require(manifest["context"] == context, "pair_manifest_context_mismatch")
    plan = sampling_plan(runs=context["runs"], qualification=context["mode"] == "qualification")
    require(manifest["plan"] == plan, "pair_sampling_plan_mismatch")
    order = list(paired_order(context["pair_index"]))
    require(manifest["expected_order"] == order, "pair_order_mismatch")
    offered = manifest["offered_order"]
    require(isinstance(offered, list) and offered in [[], order[:1], order], "pair_offers_invalid")
    require(
        all(
            manifest[key] is False
            for key in (
                "sampling_passed",
                "qualification_complete",
                "program_qualification_complete",
                "comparison_available",
            )
        ),
        "pair_premature_acceptance",
    )
    states = manifest["arms"]
    require(isinstance(states, dict) and set(states) == {"baseline", "candidate"}, "pair_arms_incomplete")
    reports: dict[str, dict[str, object]] = {}
    statuses: dict[str, str] = {}
    for arm in ("baseline", "candidate"):
        state = states[arm]
        require(isinstance(state, dict), "pair_arm_state_invalid")
        status = state.get("status")
        require(status in {"completed", "failed", "unattempted"}, "pair_arm_status_invalid")
        statuses[arm] = status
        require((arm in offered) == (status != "unattempted"), "pair_offer_conservation_failed")
        if arm in offered:
            offer = read_public(root / "aggregate" / f"{context['pair_index']:02d}-{arm}-offer.json", MANIFEST_LIMIT)
            require(
                offer
                == {
                    "schema": "hol-guard.qualification-offer.v1",
                    "context": context,
                    "arm": arm,
                    "ordinal": order.index(arm) + 1,
                },
                "pair_offer_commitment_mismatch",
            )
        if status == "completed":
            reports[arm] = _completed(root, context["pair_index"], arm, state, bundle, plan)
        elif status == "failed":
            if set(state) == {"status", "failure_sha256"}:
                failure = root / "aggregate" / f"{context['pair_index']:02d}-{arm}-failure.json"
                require(
                    _digest(state["failure_sha256"]) and digest_file(failure, REPORT_LIMIT) == state["failure_sha256"],
                    "pair_failure_digest_mismatch",
                )
                read_public(failure)
            else:
                require(
                    set(state) == {"status", "reason"}
                    and state["reason"] in {"pair_controller_failed", "pair_controller_interrupted"},
                    "pair_failure_fields_invalid",
                )
        else:
            require(set(state) == {"status"}, "pair_unattempted_fields_invalid")
    complete = len(reports) == 2
    require(
        type(manifest["collection_complete"]) is bool and (not manifest["collection_complete"] or complete),
        "pair_collection_claim_invalid",
    )
    receipt = validate_archive(root, context, manifest, recipient_id=recipient_id)
    retained = receipt["pair_binding"]["numeric_commitments_verified"]
    require(not retained or receipt["files"] >= len(reports) + 1, "pair_archive_numeric_inventory_incomplete")
    evidence: dict[str, object] = {
        "pair_index": context["pair_index"],
        "arms": statuses,
        "collection_complete": manifest["collection_complete"] and retained,
        "numeric_commitments_verified": retained,
        "archive_complete": True,
        "manifest_sha256": digest_file(root / "aggregate/pair-manifest.json", MANIFEST_LIMIT),
        "archive_sha256": receipt["archive_sha256"],
    }
    return evidence, reports if retained else {}
