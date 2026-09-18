"""Exact review result identifiers for the two explicit proof transports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from ..native_approval_bridge import decode_native_approval_v4_proof


def _mapping(value: object) -> Mapping[str, object]:
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(code)
    return value.strip()


def exact_review_result_identifiers(job: dict[str, object]) -> tuple[str, str]:
    payload = _mapping(job.get("payload"))
    binding = _mapping(job.get("serverResolvedBinding"))
    request_id = _text(binding.get("localRequestId"), "exact_result_local_request_binding_missing")
    if "nativeApprovalContext" in payload or "nativeApprovalProof" in payload:
        if set(payload) != {"harness", "nativeApprovalContext", "nativeApprovalProof"}:
            raise ValueError("exact_result_native_binding_invalid")
        context = _mapping(payload.get("nativeApprovalContext"))
        if set(context) != {"decision", "decisionReceiptId"}:
            raise ValueError("exact_result_native_binding_invalid")
        decision = context.get("decision")
        if decision == "allow_once":
            proof = decode_native_approval_v4_proof(payload.get("nativeApprovalProof"))
            challenge = _mapping(proof.get("challenge")) if proof is not None else {}
            if challenge.get("request_id") != request_id or challenge.get("harness") != payload.get("harness"):
                raise ValueError("exact_result_native_binding_invalid")
        elif decision != "block" or payload.get("nativeApprovalProof") is not None:
            raise ValueError("exact_result_native_binding_invalid")
        return request_id, _text(context.get("decisionReceiptId"), "exact_result_receipt_missing")
    signed = _mapping(payload.get("remoteApproval"))
    signed_id = _text(signed.get("localRequestId"), "exact_result_local_request_missing")
    if request_id != signed_id:
        raise ValueError("exact_result_local_request_binding_mismatch")
    return request_id, _text(signed.get("receiptId"), "exact_result_receipt_missing")
