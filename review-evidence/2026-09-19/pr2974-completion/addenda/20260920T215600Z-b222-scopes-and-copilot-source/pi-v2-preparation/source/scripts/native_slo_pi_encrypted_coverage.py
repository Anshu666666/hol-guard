"""Require the original registered cohort to exercise six encrypted post results."""

from __future__ import annotations

from typing import Any

from scripts.native_slo_pi_sources import PiSourceCase, validate_delivery, validate_reference_join


def validate_encrypted_post_coverage(
    cases: tuple[PiSourceCase, ...], callbacks: list[dict[str, Any]], receipts: dict[str, Any]
) -> dict[str, object]:
    """Read already captured evidence; never replay a callback or native request."""
    expected = [
        harness + "-" + label
        for harness in ("pi", "omp")
        for label in ("pre-allow", "pre-block", "source-clean", "source-tail-secret", "source-changed")
    ]
    if [case.label for case in cases] != expected:
        raise RuntimeError("installed_pi_encrypted_declared_population")
    if [row.get("id") for row in callbacks] != [label for label in expected for _ in range(2)]:
        raise RuntimeError("installed_pi_encrypted_callback_population")
    for offered, returned in zip(callbacks[::2], callbacks[1::2], strict=True):
        if offered.get("offered") is not True or offered.get("returned") is not False:
            raise RuntimeError("installed_pi_encrypted_offer_evidence")
        if returned.get("offered") is not True or returned.get("returned") is not True:
            raise RuntimeError("installed_pi_encrypted_return_evidence")
    native_rows = receipts.get("rows")
    if receipts.get("complete") is not True or not isinstance(native_rows, dict) or set(native_rows) != set(expected):
        raise RuntimeError("installed_pi_encrypted_receipt_population")
    validate_reference_join(callbacks, receipts)
    decision_ids: set[str] = set()
    encrypted_labels = []
    for case, callback in zip(cases, callbacks[1::2], strict=True):
        validate_delivery(case, callback)
        native = native_rows[case.label]
        receipt = native.get("receipt")
        if (
            native.get("receipt_checks") is not True
            or not isinstance(receipt, dict)
            or native.get("committed_receipt") != receipt
            or not isinstance(receipt.get("decision_id"), str)
            or not receipt["decision_id"]
            or receipt["decision_id"] in decision_ids
        ):
            raise RuntimeError("installed_pi_encrypted_durable_receipt")
        decision_ids.add(receipt["decision_id"])
        if case.event == "tool_result":
            if (
                callback["fetches"][0].get("encrypted_payload_ref_present") is not True
                or native.get("source_payload_kind") != "encrypted_payload_ref"
                or receipt.get("payload_kind") != "encrypted_payload_ref"
            ):
                raise RuntimeError("installed_pi_encrypted_post_not_exercised")
            encrypted_labels.append(case.label)
    if len(encrypted_labels) != 6:
        raise RuntimeError("installed_pi_encrypted_post_population")
    return {
        "complete": True,
        "registered_callbacks": 10,
        "encrypted_posts": 6,
        "encrypted_post_labels": encrypted_labels,
        "distinct_durable_native_receipts": len(decision_ids),
        "native_requests_replayed": False,
        "windows_encrypted_reference_supported": False,
    }
