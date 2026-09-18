"""Atomically retain native consumption and its immutable reporting event.

A consumed native receipt establishes application only. This module does not
claim harness delivery, resumption, or execution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import TYPE_CHECKING, cast

from .native_application_contract import validated_native_application
from .native_approval_bridge import native_approval_continuation_allowed
from .native_approval_delivery import RetainedNativeApprovalDecision, _current_state, _verified_delivery
from .native_approval_models import NativeApprovalSession, NativeConsumedReceipt
from .native_approval_queue import load_native_approval_state
from .native_approval_state import NativeApprovalState
from .stable_json import stable_json_serialize
from .store_approvals import resolve_one_request_only
from .store_review_event_outbox_writes import append_request_snapshot_event

if TYPE_CHECKING:
    from .store import GuardStore

_DOMAIN = b"guard-native-approval-application.v1\0"
_EVENT = "review.native.application_applied"


def _seal(store: GuardStore, payload: dict[str, object]) -> str:
    key, key_id = store._policy_integrity_secret_material(create=False)
    if key is None or key_id is None:
        raise ValueError("native_approval_local_key_unavailable")
    unsigned = {"payload": payload, "keyId": key_id}
    signature = hmac.new(key, _DOMAIN + stable_json_serialize(unsigned).encode(), hashlib.sha256).hexdigest()
    return stable_json_serialize({**unsigned, "signature": signature})


def _verified(store: GuardStore, encoded: object) -> dict[str, object] | None:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8", "surrogatepass")) > 128 * 1024:
        return None
    try:
        value = json.loads(encoded)
        if type(value) is not dict or set(value) != {"payload", "keyId", "signature"}:
            return None
        signature = value.pop("signature")
        key, key_id = store._policy_integrity_secret_material(create=False)
        if key is None or key_id != value["keyId"] or not isinstance(signature, str):
            return None
        expected = hmac.new(key, _DOMAIN + stable_json_serialize(value).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = value["payload"]
        if type(payload) is not dict or set(payload) != {"nativeApplicationResult", "nativeSourceClaim"}:
            return None
        if validated_native_application(payload["nativeApplicationResult"], payload["nativeSourceClaim"]) is None:
            return None
        return cast(dict[str, object], payload)
    except (ValueError, TypeError, UnicodeError):
        return None


def retain_native_consumption(
    store: GuardStore,
    *,
    session: NativeApprovalSession,
    consumed: NativeConsumedReceipt,
    state: NativeApprovalState,
    decision: RetainedNativeApprovalDecision,
    consumed_at: str,
) -> None:
    if (
        decision.decision != "allow_once"
        or state.challenge != session.challenge
        or not native_approval_continuation_allowed(
            consumed,
            session=session,
            request_id=session.request_id,
            request_digest=session.request_digest,
            action_digest=session.action_digest,
            policy_generation=session.policy_generation,
            policy_digest=session.policy_digest,
            harness=session.harness,
        )
    ):
        raise ValueError("native_approval_consumption_invalid")
    result: dict[str, object] = {
        "decisionReceiptId": decision.receipt_id,
        "sourceClaimHash": decision.source_claim.get("claimHash"),
        "consumedAt": consumed_at,
        "receipt": consumed.receipt,
    }
    if validated_native_application(result, decision.source_claim) is None:
        raise ValueError("native_approval_consumption_invalid")
    if datetime.fromisoformat(consumed_at) < datetime.fromisoformat(decision.received_at):
        raise ValueError("native_approval_consumption_invalid")
    payload: dict[str, object] = {"nativeApplicationResult": result, "nativeSourceClaim": decision.source_claim}
    with store._connect() as connection:
        connection.execute("begin immediate")
        previous = connection.execute(
            "select consumed_json from guard_native_approval_requests where request_id = ? and oauth_source = ?",
            (session.request_id, store._guard_source),
        ).fetchone()
        if previous is not None and previous["consumed_json"] is not None:
            if _verified(store, previous["consumed_json"]) == payload:
                return
            raise ValueError("native_approval_consumption_conflict")
        current, companion = _current_state(store, connection, session.request_id)
        if current != state or _verified_delivery(store, current, companion["proof_json"]) != decision:
            raise ValueError("native_approval_request_binding_invalid")
        # Revocation closes permission even after native consumption. The token
        # is spent but the original action remains denied if this fence fails.
        if (
            connection.execute(
                "select 1 from sync_state where state_key = ?", ("guard_exact_cloud_review_revocation",)
            ).fetchone()
            is not None
        ):
            raise ValueError("native_approval_delivery_authority_changed")
        connection.execute(
            "update guard_native_approval_requests set consumed_at = ?, consumed_json = ? where request_id = ?",
            (consumed_at, _seal(store, payload), session.request_id),
        )
        if (
            append_request_snapshot_event(
                connection,
                request_id=session.request_id,
                source=store._guard_source,
                event_type=_EVENT,
                occurred_at=consumed_at,
                native_application_result=result,
                native_source_claim=decision.source_claim,
            )
            != 1
        ):
            raise ValueError("native_approval_application_event_missing")
        if not resolve_one_request_only(
            connection,
            session.request_id,
            resolution_action="allow",
            resolution_scope="artifact",
            reason="The native approval was consumed for the original request.",
            resolved_at=consumed_at,
        ):
            raise ValueError("native_approval_request_binding_invalid")


def native_application_event_is_retained(
    store: GuardStore,
    *,
    request_id: str,
    result: object,
    claim: object,
) -> bool:
    row = store.get_approval_request(request_id)
    if row is None or load_native_approval_state(store, row) is None:
        return False
    with store._connect() as connection:
        exists = connection.execute(
            "select name from sqlite_master where type = 'table' and name = 'guard_native_approval_requests'"
        ).fetchone()
        if exists is None:
            return False
        value = connection.execute(
            "select consumed_json, consumed_at from guard_native_approval_requests "
            "where request_id = ? and oauth_source = ?",
            (request_id, store._guard_source),
        ).fetchone()
        if value is None:
            return False
        verified = _verified(store, value["consumed_json"])
    return (
        verified == {"nativeApplicationResult": result, "nativeSourceClaim": claim}
        and isinstance(result, dict)
        and result.get("consumedAt") == value["consumed_at"]
    )
