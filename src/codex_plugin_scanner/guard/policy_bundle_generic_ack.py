"""Generic v2 policy acknowledgements that are not extension-delivery proofs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT, POLICY_BUNDLE_V2_ACK_STATUSES

_GENERIC_ACK_KEYS = frozenset(
    {
        "contractVersion",
        "workspaceId",
        "deviceId",
        "bundleId",
        "bundleVersion",
        "bundleHash",
        "policyRevision",
        "payloadHash",
        "sequence",
        "status",
        "observedAt",
        "errorCode",
        "lastKnownGoodBundleHash",
    }
)
_MANAGED_PROOF_KEYS = frozenset(
    {
        "deliveryId",
        "runtimeSessionId",
        "catalogDigest",
        "effectiveProjectionDigest",
        "extensionProjectionDigest",
        "extensionAuthorityRevision",
        "appliedExtensionAuthorityRevision",
        "appliedEffectiveProjectionDigest",
    }
)
_GENERIC_ACK_TRANSITIONS = {
    "received": frozenset({"received", "validated", "applied", "failed", "offline"}),
    "validated": frozenset({"validated", "applied", "failed", "offline"}),
    "applied": frozenset({"applied", "offline"}),
    "failed": frozenset({"failed", "received", "offline"}),
    "offline": frozenset({"offline", "received"}),
}


def is_generic_policy_bundle_acknowledgement(acknowledgement: dict[str, object]) -> bool:
    """Return whether this acknowledgement is a generic-lane receipt, not a managed delivery."""

    return acknowledgement.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT and "deliveryId" not in acknowledgement


def generic_policy_bundle_acknowledgement(
    *,
    device_id: str,
    policy_bundle: dict[str, object],
    synced_at: str,
    applied: bool,
    previous: dict[str, object] | None = None,
) -> dict[str, object]:
    """Bind a generic revision/device ack without fabricating extension or delivery proofs."""

    payload = policy_bundle.get("payload")
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    revision = metadata.get("revision") if isinstance(metadata, dict) else None
    policy_revision = revision if isinstance(revision, int) and not isinstance(revision, bool) else None
    bundle_version = policy_bundle.get("bundleVersion")
    if policy_revision is None:
        policy_revision = bundle_version if isinstance(bundle_version, int) and not isinstance(bundle_version, bool) else 1
    payload_hash = policy_bundle.get("payloadHash")
    bundle_hash = policy_bundle.get("bundleHash")
    workspace_id = policy_bundle.get("workspaceId")
    if not isinstance(payload_hash, str) or not isinstance(bundle_hash, str) or not isinstance(workspace_id, str):
        return _retained_applied_previous(previous)
    matching_previous = (
        previous
        if previous is not None
        and previous.get("payloadHash") == payload_hash
        and previous.get("deviceId") == device_id
        and previous.get("bundleHash") == bundle_hash
        else None
    )
    if matching_previous is not None and matching_previous.get("status") == "applied" and not applied:
        return dict(matching_previous)
    previous_sequence = matching_previous.get("sequence") if matching_previous is not None else None
    status: Literal["received", "applied"] = "applied" if applied else "received"
    acknowledgement = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "workspaceId": workspace_id,
        "deviceId": device_id,
        "bundleId": str(metadata.get("id") if isinstance(metadata, dict) else "generic-policy"),
        "bundleVersion": bundle_version,
        "bundleHash": bundle_hash,
        "policyRevision": policy_revision,
        "payloadHash": payload_hash,
        "lastKnownGoodBundleHash": None,
        "sequence": previous_sequence + 1 if isinstance(previous_sequence, int) else 1,
        "status": status,
        "observedAt": _normalized_observed_at(synced_at),
        "errorCode": None if applied else "unverified_generic_application",
    }
    validated, _error = validated_generic_policy_bundle_acknowledgement(
        acknowledgement, previous=matching_previous
    )
    if validated is not None:
        return validated
    return _retained_applied_previous(matching_previous)


def validated_generic_policy_bundle_acknowledgement(
    acknowledgement: dict[str, object],
    *,
    previous: dict[str, object] | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate a generic-lane acknowledgement that carries no managed-delivery proofs."""

    if any(key in acknowledgement for key in _MANAGED_PROOF_KEYS):
        return None, "generic_ack_managed_fields"
    if any(key not in _GENERIC_ACK_KEYS for key in acknowledgement):
        return None, "unknown_field"
    required = _GENERIC_ACK_KEYS - {"errorCode", "lastKnownGoodBundleHash"}
    if any(key not in acknowledgement for key in required):
        return None, "missing_required_field"
    if acknowledgement.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT:
        return None, "unsupported_contract_version"
    for key in ("workspaceId", "deviceId", "bundleId", "bundleHash", "payloadHash"):
        value = acknowledgement.get(key)
        if not isinstance(value, str) or not value.strip():
            return None, "invalid_acknowledgement"
    if not isinstance(acknowledgement.get("bundleVersion"), int) or isinstance(acknowledgement.get("bundleVersion"), bool):
        return None, "invalid_acknowledgement"
    if not isinstance(acknowledgement.get("policyRevision"), int) or isinstance(acknowledgement.get("policyRevision"), bool):
        return None, "invalid_acknowledgement"
    sequence = acknowledgement.get("sequence")
    status = acknowledgement.get("status")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        return None, "invalid_acknowledgement"
    if status not in POLICY_BUNDLE_V2_ACK_STATUSES:
        return None, "invalid_acknowledgement_status"
    if previous is None:
        return acknowledgement, None
    if previous.get("status") == "applied" and status != "applied" and status != "offline":
        return None, "acknowledgement_regression"
    previous_sequence = previous.get("sequence")
    if not isinstance(previous_sequence, int):
        return None, "invalid_previous_acknowledgement"
    if sequence < previous_sequence:
        return None, "acknowledgement_replay"
    if sequence == previous_sequence:
        return (acknowledgement, None) if acknowledgement == previous else (None, "acknowledgement_sequence_conflict")
    allowed = _GENERIC_ACK_TRANSITIONS.get(str(previous.get("status")), frozenset())
    if status not in allowed:
        return None, "invalid_acknowledgement_transition"
    return acknowledgement, None


def _retained_applied_previous(previous: dict[str, object] | None) -> dict[str, object]:
    if previous is not None and previous.get("status") == "applied":
        return dict(previous)
    return {}


def _normalized_observed_at(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "generic_policy_bundle_acknowledgement",
    "is_generic_policy_bundle_acknowledgement",
    "validated_generic_policy_bundle_acknowledgement",
]
