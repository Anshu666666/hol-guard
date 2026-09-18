"""Resolve a received denial without creating any reusable permission."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .native_approval_delivery import RetainedNativeApprovalDecision, _current_state, _verified_delivery
from .native_approval_state import NativeApprovalState
from .store_approvals import resolve_one_request_only

if TYPE_CHECKING:
    from .store import GuardStore


def resolve_retained_native_block(
    store: GuardStore,
    *,
    request_id: str,
    state: NativeApprovalState,
    decision: RetainedNativeApprovalDecision,
) -> None:
    if decision.decision != "block" or decision.proof is not None:
        raise ValueError("native_approval_block_invalid")
    with store._connect() as connection:
        connection.execute("begin immediate")
        current, companion = _current_state(store, connection, request_id)
        if current != state or _verified_delivery(store, current, companion["proof_json"]) != decision:
            raise ValueError("native_approval_request_binding_invalid")
        if not resolve_one_request_only(
            connection,
            request_id,
            resolution_action="block",
            resolution_scope="artifact",
            reason="Native review kept this request blocked.",
            resolved_at=decision.received_at,
        ):
            raise ValueError("native_approval_request_binding_invalid")
