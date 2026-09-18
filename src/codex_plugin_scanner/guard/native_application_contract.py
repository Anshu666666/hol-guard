"""Strict content-free reporting contract for an actual consumed native proof."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from .native_approval_models import _RECEIPT_BINDING_FIELDS
from .native_approval_v4_protocol import decode_native_approval_v4_challenge, decode_native_approval_v4_result
from .review_contracts import validate_local_review_request_claim
from .stable_json import stable_json_serialize


def validated_native_application(
    result: object,
    source_claim: object,
) -> tuple[dict[str, object], dict[str, object]] | None:
    if type(result) is not dict or type(source_claim) is not dict:
        return None
    value = cast(dict[str, object], result)
    claim = cast(dict[str, object], source_claim)
    if set(value) != {"decisionReceiptId", "sourceClaimHash", "consumedAt", "receipt"}:
        return None
    try:
        validate_local_review_request_claim(claim)
        if "exactReviewCapability" in claim or value["sourceClaimHash"] != claim.get("claimHash"):
            return None
        receipt_id, consumed_at = value["decisionReceiptId"], value["consumedAt"]
        if not isinstance(receipt_id, str) or str(UUID(receipt_id)) != receipt_id or not isinstance(consumed_at, str):
            return None
        clock = datetime.fromisoformat(consumed_at)
        if clock.utcoffset() != timedelta(0):
            return None
        challenge = decode_native_approval_v4_challenge(claim.get("nativeApprovalChallenge"))
        decoded = decode_native_approval_v4_result(
            {
                "schema": "guard-native-approval-result.v4",
                "version": 4,
                "authority": "rust",
                "receipt": value["receipt"],
            },
            phase="consumed",
        )
        if challenge is None or decoded is None:
            return None
        receipt = cast(dict[str, object], decoded["receipt"])
        if (
            receipt["decision"] != "allow"
            or receipt["approved_action"] != "allow"
            or receipt["reason_code"] != "native_approval_v4_consumed"
            or receipt["replay_claimed"] is not True
            or any(
                type(receipt.get(k)) is not type(challenge.get(k)) or receipt.get(k) != challenge.get(k)
                for k in _RECEIPT_BINDING_FIELDS
            )
            or claim.get("localRequestId") != challenge["request_id"]
            or claim.get("harnessId") != challenge["harness"]
            or claim.get("artifactHash") != challenge["request_digest"]
        ):
            return None
        milliseconds = int(clock.timestamp() * 1000)
        if not cast(int, challenge["issued_at_ms"]) <= milliseconds < cast(int, challenge["expires_at_ms"]):
            return None
        if len(stable_json_serialize(value).encode("utf-8")) > 32 * 1024:
            return None
        return value, claim
    except (TypeError, ValueError, OverflowError, UnicodeError):
        return None
