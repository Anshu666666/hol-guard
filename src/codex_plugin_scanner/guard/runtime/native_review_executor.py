"""Dedicated delivery of opaque native review decisions."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

from ..native_approval_block import resolve_retained_native_block
from ..native_approval_delivery import retain_native_approval_decision
from .command_payload import mapping
from .exact_cloud_review_executor import execute_exact_cloud_review_operation
from .native_review_delivery import (
    require_legacy_review_transport,
    uses_native_review_delivery,
    validate_native_review_delivery,
)

if TYPE_CHECKING:
    from ..store import GuardStore


def execute_exact_review_job(
    job: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
    resume_after_approval: Callable[..., dict[str, object]],
) -> dict[str, object]:
    if not uses_native_review_delivery(job):
        require_legacy_review_transport(store, job)
        return execute_exact_cloud_review_operation(
            payload=mapping(job.get("payload")),
            store=store,
            generated_at=generated_at,
            resume_after_approval=resume_after_approval,
        )
    _, delivery = validate_native_review_delivery(store, job, now=generated_at)
    retained = retain_native_approval_decision(
        store,
        request_id=delivery.request_id,
        expected_state=delivery.state,
        decision=delivery.decision,
        receipt_id=delivery.receipt_id,
        received_at=generated_at,
        proof=json.loads(delivery.proof_json) if delivery.proof_json is not None else None,
        source_claim=json.loads(delivery.source_claim_json),
        expected_sequence=delivery.request_sequence,
    )
    blocked = retained.decision == "block"
    if blocked:
        resolve_retained_native_block(store, request_id=delivery.request_id, state=delivery.state, decision=retained)
    # Delivery completion is distinct from application. The original live hook
    # must consume the native proof; no legacy resolution or resumption runs here.
    return {
        "generatedAt": generated_at,
        "data": {
            "status": "blocked" if blocked else "proof_received",
            "localRequestId": delivery.request_id,
            "receiptId": retained.receipt_id,
            "applicationStatus": "applied" if blocked else "failed_retryable",
            "applicationReason": None if blocked else "native_approval_waiting_for_hook",
            "applicationUpdatedAt": retained.received_at,
            "continuationStatus": "blocked_not_resumed" if blocked else "waiting",
            "continuationReason": "native_approval_blocked" if blocked else "native_approval_waiting_for_hook",
            "continuationUpdatedAt": retained.received_at,
        },
    }
