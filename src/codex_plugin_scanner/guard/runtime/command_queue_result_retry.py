"""Recover result delivery from a fresh lease without applying a decision."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict

from ..contracts.guard_cloud_review import validate_exact_command_result
from ..review_oauth_binding import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from .command_capability import _command_job_seen
from .command_queue_protocol import pending_result_is_stale
from .exact_cloud_review import ExactCloudReviewError, _exact_job_identity
from .exact_cloud_review_transport import uses_exact_transport


def exact_result_delivery_binding(store: GuardStore) -> dict[str, object] | None:
    """Snapshot the authenticated subject; tokens and private keys are excluded."""
    try:
        with store.hold_oauth_credential_lock():
            metadata = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
            credentials = store.get_oauth_local_credentials(allow_primary=False)
            if not isinstance(credentials, dict):
                return None
            return {
                **asdict(metadata),
                "source": store.guard_source,
                "issuer": credentials.get("issuer"),
                "client_id": credentials.get("client_id"),
            }
    except GuardReviewContractError:
        return None


def exact_result_subject_is_current(store: GuardStore, pending: Mapping[str, object]) -> bool:
    binding = pending.get("delivery_binding")
    return isinstance(binding, dict) and binding == exact_result_delivery_binding(store)


def rebind_exact_result(
    store: GuardStore, pending: Mapping[str, object], leased: dict[str, object]
) -> dict[str, object] | None:
    """Only transport envelope fields may change; cached observations stay exact."""
    previous = pending.get("job")
    payload = pending.get("payload")
    if not isinstance(previous, dict) or not isinstance(payload, dict):
        return None
    if not uses_exact_transport(previous) or not uses_exact_transport(leased):
        return None
    if not exact_result_subject_is_current(store, pending) or pending_result_is_stale(leased):
        return None
    try:
        old_identity = _exact_job_identity(previous)
        new_identity = _exact_job_identity(leased)
    except (ExactCloudReviewError, ValueError, TypeError):
        return None
    # Only leaseId/leaseExpiresAt are replaceable, never the job expiry or
    # signed payload. A fresh lease here cannot become execution authority.
    if old_identity != new_identity:
        return None
    if any(previous.get(key) != leased.get(key) for key in ("serverResolvedBinding", "resultContractVersion")):
        return None
    lease_id = leased.get("leaseId")
    if not isinstance(lease_id, str) or not lease_id.strip():
        return None
    if not _command_job_seen(store, _exact_job_identity(previous)):
        return None
    result = payload.get("result")
    binding = previous.get("serverResolvedBinding")
    if payload.get("status") != "succeeded" or not isinstance(result, dict) or not isinstance(binding, dict):
        return None
    try:
        validate_exact_command_result(result)
    except (TypeError, ValueError):
        return None
    request_id = result.get("localRequestId")
    if result.get("correlationId") != previous.get("id") or request_id != binding.get("localRequestId"):
        return None
    if not isinstance(request_id, str):
        return None
    original_payload = previous.get("payload")
    if not isinstance(original_payload, dict):
        return None
    native = "nativeApprovalProof" in original_payload or "nativeApprovalContext" in original_payload
    if native:
        from ..native_live_approval_state import parse_native_job

        try:
            original_request_id, original_receipt_id, _ = parse_native_job(original_payload)
        except (TypeError, ValueError):
            return None
    else:
        approval = original_payload.get("remoteApproval")
        if not isinstance(approval, dict):
            return None
        original_request_id, original_receipt_id = approval.get("localRequestId"), approval.get("receiptId")
    if request_id != original_request_id or result.get("receiptId") != original_receipt_id:
        return None
    request = store.get_approval_request(request_id)
    if result.get("applicationStatus") == "applied":
        if not isinstance(request, dict) or request.get("status") != "resolved":
            return None
        if native:
            # Detached native observations support reporting history only. They
            # are never reconstructed into native authority or used to resume.
            operation = store.get_guard_operation_for_approval_request(request_id)
            metadata = operation.get("metadata") if isinstance(operation, dict) else None
            consumed = metadata.get("native_approval_consumed_receipt") if isinstance(metadata, dict) else None
            staged = metadata.get("native_approval_pending_proof") if isinstance(metadata, dict) else None
            resume = store.get_request_resume(request_id)
            if (
                request.get("reason") != "native_approval_v4_consumed"
                or not isinstance(consumed, dict)
                or consumed.get("phase") != "consumed"
                or consumed.get("request_id") != request_id
                or not isinstance(staged, dict)
                or staged.get("receiptId") != original_receipt_id
                or staged.get("proof") != original_payload.get("nativeApprovalProof")
                or not isinstance(resume, dict)
                or resume.get("continuation_status") != "resumed"
                or result.get("continuationStatus") != "resumed"
            ):
                return None
        else:
            with store._connect() as connection:
                receipt = connection.execute(
                    "select request_id from guard_exact_cloud_review_receipts where receipt_id = ?",
                    (result.get("receiptId"),),
                ).fetchone()
            if receipt is None or receipt["request_id"] != request_id:
                return None
    return {
        **payload,
        "leaseId": lease_id,
        "idempotencyKey": f"{leased['id']}:{lease_id}:succeeded",
    }
