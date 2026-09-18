"""Integrity-bound retention of a received native approval decision.

A decoded browser proof is transport data. Only live native validation and
consumption may turn it into permission.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, cast
from uuid import UUID

from .native_approval_queue import is_native_approval_request
from .native_approval_source_claim import detached_native_source_claim, native_approval_source_claim
from .native_approval_state import NativeApprovalState, verified_native_approval_state
from .native_approval_v4_protocol import decode_native_approval_v4_proof
from .stable_json import stable_json_serialize
from .store_approvals import get_approval_request
from .store_review_event_outbox_binding import load_review_oauth_binding

if TYPE_CHECKING:
    import sqlite3

    from .store import GuardStore

_SCHEMA = "guard-native-approval-delivery.v1"
_DOMAIN = b"guard-native-approval-delivery.v1\0"
_HEX = re.compile(r"[0-9a-f]{64}")
_FIELDS = frozenset(
    (
        "schema",
        "keyId",
        "signature",
        "requestBindingDigest",
        "oauthBindingDigest",
        "challengeDigest",
        "decision",
        "receiptId",
        "receivedAt",
        "proof",
        "sourceClaim",
    )
)


@dataclass(frozen=True, slots=True)
class RetainedNativeApprovalDecision:
    decision: str
    receipt_id: str
    received_at: str
    proof_json: str | None
    source_claim_json: str

    @property
    def source_claim(self) -> dict[str, object]:
        return detached_native_source_claim(self.source_claim_json)

    @property
    def proof(self) -> dict[str, object] | None:
        return cast(dict[str, object], json.loads(self.proof_json)) if self.proof_json is not None else None


def _challenge_digest(state: NativeApprovalState) -> str:
    return hashlib.sha256(state.challenge_json.encode("utf-8")).hexdigest()


def _delivery(
    *,
    state: NativeApprovalState,
    decision: object,
    receipt_id: object,
    received_at: object,
    proof: object,
    source_claim: object,
) -> RetainedNativeApprovalDecision | None:
    if decision not in ("allow_once", "block") or not isinstance(decision, str):
        return None
    if not isinstance(receipt_id, str) or not isinstance(received_at, str):
        return None
    try:
        if str(UUID(receipt_id)) != receipt_id:
            return None
        timestamp = datetime.fromisoformat(received_at)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    current_ms = int(timestamp.timestamp() * 1000)
    challenge = state.challenge
    if not cast(int, challenge["issued_at_ms"]) <= current_ms < cast(int, challenge["expires_at_ms"]):
        return None
    claim_json = native_approval_source_claim(state, source_claim)
    if claim_json is None:
        return None
    if decision == "block":
        return (
            RetainedNativeApprovalDecision(decision, receipt_id, received_at, None, claim_json)
            if proof is None
            else None
        )
    parsed = decode_native_approval_v4_proof(proof)
    if parsed is None or parsed["challenge"] != state.challenge:
        return None
    return RetainedNativeApprovalDecision(decision, receipt_id, received_at, stable_json_serialize(parsed), claim_json)


def _seal(store: GuardStore, state: NativeApprovalState, decision: RetainedNativeApprovalDecision) -> str:
    key, key_id = store._policy_integrity_secret_material(create=False)
    if key is None or key_id is None:
        raise ValueError("native_approval_local_key_unavailable")
    unsigned = {
        "schema": _SCHEMA,
        "keyId": key_id,
        "requestBindingDigest": state.row_digest,
        "oauthBindingDigest": state.oauth_digest,
        "challengeDigest": _challenge_digest(state),
        "decision": decision.decision,
        "receiptId": decision.receipt_id,
        "receivedAt": decision.received_at,
        "proof": decision.proof,
        "sourceClaim": decision.source_claim,
    }
    signature = hmac.new(key, _DOMAIN + stable_json_serialize(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
    return stable_json_serialize({**unsigned, "signature": signature})


def _verified_delivery(
    store: GuardStore, state: NativeApprovalState, encoded: object
) -> RetainedNativeApprovalDecision | None:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8", "surrogatepass")) > 160 * 1024:
        return None
    try:
        value = json.loads(encoded)
        if not isinstance(value, dict) or set(value) != _FIELDS:
            return None
        signature = value.pop("signature")
        key, key_id = store._policy_integrity_secret_material(create=False)
        if key is None or key_id is None or value["keyId"] != key_id:
            return None
        if not isinstance(signature, str) or _HEX.fullmatch(signature) is None:
            return None
        expected = hmac.new(key, _DOMAIN + stable_json_serialize(value).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if (
            value["schema"] != _SCHEMA
            or value["requestBindingDigest"] != state.row_digest
            or value["oauthBindingDigest"] != state.oauth_digest
            or value["challengeDigest"] != _challenge_digest(state)
        ):
            return None
        return _delivery(
            state=state,
            decision=value["decision"],
            receipt_id=value["receiptId"],
            received_at=value["receivedAt"],
            proof=value["proof"],
            source_claim=value["sourceClaim"],
        )
    except (TypeError, ValueError, UnicodeError):
        return None


def _current_state(
    store: GuardStore, connection: sqlite3.Connection, request_id: str
) -> tuple[NativeApprovalState, sqlite3.Row]:
    source = store._guard_source
    request = get_approval_request(connection, request_id)
    table = connection.execute(
        "select name from sqlite_master where type = 'table' and name = 'guard_native_approval_requests'"
    ).fetchone()
    if (
        table is None
        or request is None
        or request.get("status") != "pending"
        or not is_native_approval_request(request)
    ):
        raise ValueError("native_approval_request_binding_invalid")
    companion = connection.execute(
        "select * from guard_native_approval_requests where request_id = ? and oauth_source = ?",
        (request_id, source),
    ).fetchone()
    binding = load_review_oauth_binding(connection, source)
    if companion is None or binding is None or companion["consumed_at"] is not None:
        raise ValueError("native_approval_request_binding_invalid")
    state = verified_native_approval_state(store, companion["state_json"], request_row=request, oauth_binding=binding)
    if state is None:
        raise ValueError("native_approval_request_binding_invalid")
    return state, companion


def retain_native_approval_decision(
    store: GuardStore,
    *,
    request_id: str,
    expected_state: NativeApprovalState,
    decision: str,
    receipt_id: str,
    received_at: str,
    proof: object,
    source_claim: dict[str, object],
    expected_sequence: int,
) -> RetainedNativeApprovalDecision:
    """Retain one opaque decision atomically, without resolving the request."""

    with store._connect() as connection:
        connection.execute("begin immediate")
        current, companion = _current_state(store, connection, request_id)
        sequence = connection.execute(
            "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
            (request_id,),
        ).fetchone()
        revoked = connection.execute(
            "select 1 from sync_state where state_key = ?", ("guard_exact_cloud_review_revocation",)
        ).fetchone()
        if (
            revoked is not None
            or type(expected_sequence) is not int
            or sequence is None
            or sequence[0] != expected_sequence
        ):
            raise ValueError("native_approval_delivery_authority_changed")
        if current != expected_state:
            raise ValueError("native_approval_request_binding_invalid")
        value = _delivery(
            state=current,
            decision=decision,
            receipt_id=receipt_id,
            received_at=received_at,
            proof=proof,
            source_claim=source_claim,
        )
        if value is None:
            raise ValueError("native_approval_delivery_invalid")
        if companion["proof_json"] is not None:
            previous = _verified_delivery(store, current, companion["proof_json"])
            if previous is None:
                raise ValueError("native_approval_delivery_invalid")
            if (previous.decision, previous.receipt_id, previous.proof_json, previous.source_claim_json) != (
                value.decision,
                value.receipt_id,
                value.proof_json,
                value.source_claim_json,
            ):
                raise ValueError("native_approval_delivery_conflict")
            return previous
        encoded = _seal(store, current, value)
        connection.execute(
            "update guard_native_approval_requests set proof_json = ?, proof_receipt_id = ?, "
            "proof_received_at = ? where request_id = ? and oauth_source = ? and proof_json is null",
            (encoded, value.receipt_id, value.received_at, request_id, store._guard_source),
        )
        return value


def load_native_approval_decision(
    store: GuardStore, *, request_id: str, expected_state: NativeApprovalState
) -> RetainedNativeApprovalDecision | None:
    """Return transport state only while its original local binding still holds."""

    with store._connect() as connection:
        try:
            current, companion = _current_state(store, connection, request_id)
        except ValueError:
            return None
        if current != expected_state:
            return None
        value = _verified_delivery(store, current, companion["proof_json"])
        if value is None or value.receipt_id != companion["proof_receipt_id"]:
            return None
        return value if value.received_at == companion["proof_received_at"] else None
