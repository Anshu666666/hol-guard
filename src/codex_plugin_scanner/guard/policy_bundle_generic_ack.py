"""Generic v2 policy acknowledgements that are not extension-delivery proofs."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT, validated_policy_bundle_v2_acknowledgement

_GENERIC_CATALOG_DIGEST = hashlib.sha256(b"guard-policy-generic.v2").hexdigest()


def generic_policy_bundle_acknowledgement(
    *,
    device_id: str,
    policy_bundle: dict[str, object],
    synced_at: str,
    applied: bool,
    previous: dict[str, object] | None = None,
) -> dict[str, object]:
    """Bind a generic revision/device ack without fabricating extension proofs."""

    payload = policy_bundle.get("payload")
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    revision = metadata.get("revision") if isinstance(metadata, dict) else None
    policy_revision = revision if isinstance(revision, int) and not isinstance(revision, bool) else None
    bundle_version = policy_bundle.get("bundleVersion")
    if policy_revision is None:
        policy_revision = (
            bundle_version if isinstance(bundle_version, int) and not isinstance(bundle_version, bool) else 1
        )
    payload_hash = policy_bundle.get("payloadHash")
    bundle_hash = policy_bundle.get("bundleHash")
    workspace_id = policy_bundle.get("workspaceId")
    if not isinstance(payload_hash, str) or not isinstance(bundle_hash, str) or not isinstance(workspace_id, str):
        return {}
    identity = {
        "workspaceId": workspace_id,
        "deviceId": device_id,
        "deliveryId": "00000000-0000-4000-8000-0000000000f1",
        "runtimeSessionId": "generic-policy",
        "bundleId": str(metadata.get("id") if isinstance(metadata, dict) else "generic-policy"),
        "bundleVersion": bundle_version,
        "bundleHash": bundle_hash,
        "policyRevision": policy_revision,
        "extensionAuthorityRevision": 0,
        "catalogDigest": _GENERIC_CATALOG_DIGEST,
        "effectiveProjectionDigest": payload_hash,
        "payloadHash": payload_hash,
        "extensionProjectionDigest": payload_hash,
        "lastKnownGoodBundleHash": None,
        "appliedExtensionAuthorityRevision": policy_revision,
        "appliedEffectiveProjectionDigest": payload_hash,
    }
    matching_previous = (
        previous
        if previous is not None
        and previous.get("payloadHash") == payload_hash
        and previous.get("deviceId") == device_id
        and previous.get("bundleHash") == bundle_hash
        else None
    )
    previous_sequence = matching_previous.get("sequence") if matching_previous is not None else None
    status: Literal["received", "applied"] = "applied" if applied else "received"
    acknowledgement = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        **identity,
        "sequence": previous_sequence + 1 if isinstance(previous_sequence, int) else 1,
        "status": status,
        "observedAt": _normalized_observed_at(synced_at),
        "errorCode": None if applied else "unverified_generic_application",
    }
    validated, _error = validated_policy_bundle_v2_acknowledgement(acknowledgement, previous=matching_previous)
    return validated if validated is not None else {}


def _normalized_observed_at(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
