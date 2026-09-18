"""Target checks for opaque native review proof delivery.

This authorizes receipt of transport data, never execution. A live native
consume remains necessary before an original hook may continue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID

from ..native_approval_bridge import decode_native_approval_v4_proof
from ..native_approval_queue import (
    has_native_approval_companion,
    is_native_approval_request,
    load_native_approval_state,
)
from ..native_approval_state import NativeApprovalState
from ..review_contracts import build_local_review_request_claim
from ..stable_json import stable_json_serialize
from .command_capability import AuthorizedCommandJob, CommandCapabilityError, _command_job_seen
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY,
    ExactCloudReviewError,
    _exact_job_identity,
    _now,
    _oauth_metadata,
)
from .time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from ..store import GuardStore


@dataclass(frozen=True, slots=True)
class NativeReviewDelivery:
    request_id: str
    state: NativeApprovalState
    decision: str
    receipt_id: str
    proof_json: str | None
    source_claim_json: str
    request_sequence: int


def uses_native_review_delivery(job: dict[str, object]) -> bool:
    payload = job.get("payload")
    return isinstance(payload, dict) and ("nativeApprovalContext" in payload or "nativeApprovalProof" in payload)


def require_legacy_review_transport(store: GuardStore, job: dict[str, object]) -> None:
    """A retained native request cannot be resolved through legacy authority."""

    payload = job.get("payload")
    approval = payload.get("remoteApproval") if isinstance(payload, dict) else None
    request_id = approval.get("localRequestId") if isinstance(approval, dict) else None
    if not isinstance(request_id, str):
        return
    request = store.get_approval_request(request_id)
    if has_native_approval_companion(store, request_id) or (
        request is not None and is_native_approval_request(request)
    ):
        raise ValueError("native_approval_transport_required")


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("native_approval_delivery_invalid")
    return cast(dict[str, object], value)


def _uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError):
        return False


def validate_native_review_delivery(
    store: GuardStore, job: dict[str, object], *, now: str
) -> tuple[dict[str, object], NativeReviewDelivery]:
    identity = _exact_job_identity(job)
    if type(job.get("protocolVersion")) is not int:
        raise ValueError("native_approval_delivery_invalid")
    current = _now(now)
    expiry = parse_utc_timestamp(identity.get("expiresAt"))
    if expiry is None or expiry <= current or expiry > current + timedelta(hours=24):
        raise ValueError("native_approval_delivery_expired")
    if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
        raise ValueError("cloud_review_capability_revoked")
    payload = _mapping(job.get("payload"))
    if set(payload) != {"harness", "nativeApprovalContext", "nativeApprovalProof"}:
        raise ValueError("native_approval_delivery_invalid")
    context = _mapping(payload["nativeApprovalContext"])
    if set(context) != {"decision", "decisionReceiptId"} or not _uuid(context["decisionReceiptId"]):
        raise ValueError("native_approval_delivery_invalid")
    binding = _mapping(job.get("serverResolvedBinding"))
    request_id = binding.get("localRequestId")
    if not isinstance(request_id, str):
        raise ValueError("native_approval_request_binding_invalid")
    request = store.get_approval_request(request_id)
    if request is None or request.get("status") != "pending":
        raise ValueError("native_approval_request_binding_invalid")
    state = load_native_approval_state(store, request)
    if state is None:
        raise ValueError("native_approval_request_binding_invalid")
    challenge = state.challenge
    current_ms = int(current.timestamp() * 1000)
    if not cast(int, challenge["issued_at_ms"]) <= current_ms < cast(int, challenge["expires_at_ms"]):
        raise ValueError("native_approval_delivery_expired")
    oauth = _oauth_metadata(store)
    if not oauth.grant_id or not oauth.runtime_id:
        raise ValueError("native_approval_identity_missing")
    claim = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    expected = {
        "actionDigest": challenge["action_digest"],
        "approvalId": claim["approvalId"],
        "claimDigest": claim["claimHash"],
        "localRequestId": challenge["request_id"],
        "policyAction": claim["policyAction"],
        "scope": "one-time",
        "grantId": oauth.grant_id,
        "machineId": oauth.machine_id,
        "localMachineInstallationId": oauth.installation_id,
        "runtimeId": oauth.runtime_id,
    }
    if any(type(binding.get(key)) is not type(value) or binding.get(key) != value for key, value in expected.items()):
        raise ValueError("native_approval_request_binding_invalid")
    if (
        identity["deviceId"] != oauth.device_id
        or identity["workspaceId"] != oauth.workspace_id
        or payload["harness"] != challenge["harness"]
        or not all(_uuid(binding.get(key)) for key in ("machineInstallationId", "runtimeGrantId", "reviewRequestId"))
    ):
        raise ValueError("native_approval_request_binding_invalid")
    with store._connect() as connection:
        sequence = connection.execute(
            "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
            (request_id,),
        ).fetchone()
    if (
        sequence is None
        or type(binding.get("localRequestVersion")) is not int
        or binding["localRequestVersion"] != sequence[0]
    ):
        raise ValueError("native_approval_request_binding_invalid")
    capability_id = binding.get("capabilityId")
    if not isinstance(capability_id, str) or re.fullmatch(r"[0-9a-f]{64}", capability_id) is None:
        raise ValueError("native_approval_request_binding_invalid")
    advertisement = claim.get("exactReviewCapability")
    if isinstance(advertisement, dict) and binding.get("capabilityId") != advertisement.get("capabilityId"):
        raise ValueError("native_approval_request_binding_invalid")
    decision = context["decision"]
    proof = payload["nativeApprovalProof"]
    if decision == "block":
        if proof is not None:
            raise ValueError("native_approval_delivery_invalid")
        encoded = None
    elif decision == "allow_once":
        parsed = decode_native_approval_v4_proof(proof)
        if parsed is None or parsed["challenge"] != challenge:
            raise ValueError("native_approval_delivery_invalid")
        encoded = stable_json_serialize(parsed)
    else:
        raise ValueError("native_approval_delivery_invalid")
    return identity, NativeReviewDelivery(
        request_id,
        state,
        cast(str, decision),
        cast(str, context["decisionReceiptId"]),
        encoded,
        stable_json_serialize(claim),
        cast(int, binding["localRequestVersion"]),
    )


def authorize_native_review_delivery(
    store: GuardStore, job: dict[str, object], *, now: str | None = None
) -> AuthorizedCommandJob:
    try:
        identity, _ = validate_native_review_delivery(store, job, now=_now(now).isoformat())
        if _command_job_seen(store, identity, now=now):
            raise ValueError("remote_exact_job_replayed")
    except (ValueError, KeyError) as error:
        code = error.code if isinstance(error, ExactCloudReviewError) else str(error)
        raise CommandCapabilityError(code or "native_approval_delivery_invalid") from error
    return AuthorizedCommandJob(
        identity=identity, operation=EXACT_CLOUD_REVIEW_OPERATION, requires_local_approval=False
    )
