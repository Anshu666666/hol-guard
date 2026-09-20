"""DPoP-ingested queue eligibility for exact Cloud Review requests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .review_oauth_binding import GuardReviewOAuthMetadata

if TYPE_CHECKING:
    from .store import GuardStore


def validate_exact_review_envelope_authority(
    envelope: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    *,
    capability_id: str,
) -> None:
    """Bind a signed exact decision to the current local grant and capability."""

    from .review_oauth_binding import GuardReviewContractError

    if envelope.get("grantId") != oauth.grant_id:
        raise GuardReviewContractError("remote_approval_grant_mismatch")
    if envelope.get("capabilityId") != capability_id:
        raise GuardReviewContractError("remote_approval_capability_mismatch")
    if envelope.get("runtimeId") != oauth.runtime_id:
        raise GuardReviewContractError("remote_approval_runtime_mismatch")


def exact_review_capability_advertisement(
    *,
    claim: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    store: GuardStore,
) -> dict[str, object] | None:
    """Describe queue eligibility without exporting local execution authority."""

    from .runtime.exact_cloud_review import (
        EXACT_CLOUD_REVIEW_OPERATION,
        ExactCloudReviewError,
        _capability_digest,
        _verified_capability,
    )

    try:
        capability = _verified_capability(store, revoke_binding_drift=False)
    except (AttributeError, ExactCloudReviewError):
        return None
    challenge = claim.get("nativeApprovalChallenge")
    action_digest = claim["actionEnvelopeHash"]
    if challenge is not None:
        from .native_approval_protocol import decode_native_approval_v4_challenge

        parsed = decode_native_approval_v4_challenge(challenge) if isinstance(challenge, dict) else None
        if parsed is None or parsed["request_id"] != claim["localRequestId"] or parsed["harness"] != claim["harnessId"]:
            return None
        action_digest = parsed["action_digest"]
    return {
        "actionDigest": action_digest,
        "capabilityId": _capability_digest(capability),
        "deviceId": oauth.device_id,
        "expiresAt": capability["expiresAt"],
        "grantId": oauth.grant_id,
        "issuedAt": capability["issuedAt"],
        "localRequestId": claim["localRequestId"],
        "machineId": oauth.machine_id,
        "machineInstallationId": oauth.installation_id,
        "nonce": capability["nonce"],
        "operation": EXACT_CLOUD_REVIEW_OPERATION,
        "requestVersion": claim["policyVersion"],
        "runtimeId": oauth.runtime_id,
        "sourceClaimHash": claim["claimHash"],
        "workspaceId": oauth.workspace_id,
    }


def attach_exact_review_capability(
    claim: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    store: GuardStore,
) -> dict[str, object]:
    advertisement = exact_review_capability_advertisement(claim=claim, oauth=oauth, store=store)
    if advertisement is not None:
        claim["exactReviewCapability"] = advertisement
    return claim


__all__ = [
    "attach_exact_review_capability",
    "exact_review_capability_advertisement",
    "validate_exact_review_envelope_authority",
]
