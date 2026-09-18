"""Immutable original claim retained with opaque native approval delivery."""

from __future__ import annotations

import json
from typing import cast

from .native_approval_state import NativeApprovalState
from .review_contracts import validate_local_review_request_claim
from .stable_json import stable_json_serialize


def native_approval_source_claim(state: NativeApprovalState, value: object) -> str | None:
    if type(value) is not dict:
        return None
    claim = cast(dict[str, object], dict(value))
    # Advertisements are optional and outside claimHash. Completion reporting
    # never renews approval authority or depends on its later upload time.
    claim.pop("exactReviewCapability", None)
    try:
        validate_local_review_request_claim(claim)
        challenge = state.challenge
        if (
            claim.get("nativeApprovalChallenge") != challenge
            or claim.get("localRequestId") != challenge["request_id"]
            or claim.get("harnessId") != challenge["harness"]
            or claim.get("artifactHash") != challenge["request_digest"]
        ):
            return None
        encoded = stable_json_serialize(claim)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            return None
        return encoded
    except (TypeError, ValueError, UnicodeError):
        return None


def detached_native_source_claim(encoded: str) -> dict[str, object]:
    return cast(dict[str, object], json.loads(encoded))
