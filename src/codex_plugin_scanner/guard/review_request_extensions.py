"""Authenticated optional additions to an immutable queued-request claim."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .native_approval_queue import (
    has_native_approval_companion,
    is_native_approval_request,
    load_native_approval_state,
)
from .policy_memory_source import verified_request_policy_memory_source
from .policy_rule_identity import PolicyRuleIdentity
from .review_oauth_binding import GuardReviewContractError
from .review_request_policy_fields import _read_json_mapping

if TYPE_CHECKING:
    from .store import GuardStore


def extend_review_request_claim(claim: dict[str, object], *, store: GuardStore, request_row: dict[str, object]) -> None:
    identity = PolicyRuleIdentity.from_mapping(_read_json_mapping(request_row.get("decision_v2_json")))
    if identity is not None:
        claim.update(identity.to_dict())
    policy_source = verified_request_policy_memory_source(store, request_row)
    if policy_source is not None:
        claim["policyMemorySource"] = policy_source
    if not is_native_approval_request(request_row):
        if has_native_approval_companion(store, request_row.get("request_id")):
            raise GuardReviewContractError("native_approval_request_binding_invalid")
        return
    state = load_native_approval_state(store, request_row)
    if state is None:
        raise GuardReviewContractError("native_approval_request_binding_invalid")
    challenge = state.challenge
    # The native action commitment remains distinct from the ordinary envelope
    # hash. Both are committed by the final claim hash.
    claim["nativeApprovalChallenge"] = challenge
    expires = challenge["expires_at_ms"]
    assert isinstance(expires, int)
    native_expiry = datetime.fromtimestamp(expires / 1000, timezone.utc)
    current_expiry = datetime.fromisoformat(str(claim["expiresAt"]))
    claim["expiresAt"] = min(current_expiry, native_expiry).isoformat()


def exact_review_action_digest(claim: dict[str, object]) -> object:
    """Use the challenge only when it is already inside the authenticated claim."""

    from .native_approval_bridge import decode_native_approval_v4_challenge

    if "nativeApprovalChallenge" not in claim:
        return claim["actionEnvelopeHash"]
    challenge = decode_native_approval_v4_challenge(claim["nativeApprovalChallenge"])
    if challenge is None:
        raise GuardReviewContractError("native_approval_request_binding_invalid")
    if challenge["request_id"] != claim.get("localRequestId") or challenge["harness"] != claim.get("harnessId"):
        raise GuardReviewContractError("native_approval_request_binding_invalid")
    return challenge["action_digest"]
