"""Atomic queue continuity for native approval transport.

Only a bounded challenge, its accepted snapshot, and local identity commitments
are retained. A queued challenge or received proof is never an approval grant.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .models import GuardApprovalRequest
from .native_approval_models import NativeApprovalSession
from .native_approval_state import NativeApprovalState, seal_native_approval_state, verified_native_approval_state
from .store_approvals import add_approval_request, get_approval_request
from .store_review_event_outbox_binding import bind_review_events_for_request, load_review_oauth_binding

if TYPE_CHECKING:
    from .store import GuardStore

NATIVE_APPROVAL_ARTIFACT_PREFIX = "native-approval-v4:"


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """create table if not exists guard_native_approval_requests (
           request_id text primary key references approval_requests(request_id) on delete cascade,
           oauth_source text not null,
           state_json text not null,
           proof_json text,
           proof_receipt_id text,
           proof_received_at text,
           consumed_at text,
           consumed_json text
        )"""
    )

    columns = {row[1] for row in connection.execute("pragma table_info(guard_native_approval_requests)")}
    if "consumed_json" not in columns:
        connection.execute("alter table guard_native_approval_requests add column consumed_json text")


def is_native_approval_request(row: dict[str, object]) -> bool:
    value = row.get("artifact_id")
    return isinstance(value, str) and value.startswith(NATIVE_APPROVAL_ARTIFACT_PREFIX)


def queue_native_approval_request(
    store: GuardStore,
    *,
    request: GuardApprovalRequest,
    session: NativeApprovalSession,
    snapshot: dict[str, object],
    now: str,
) -> dict[str, object]:
    """Commit the exact challenge and its first queue event in one transaction."""

    if request.request_id != session.request_id or request.harness != session.harness:
        raise ValueError("native_approval_request_mismatch")
    request = replace(
        request,
        artifact_id=NATIVE_APPROVAL_ARTIFACT_PREFIX + session.request_id,
        artifact_hash=session.request_digest,
        action_identity="native-approval-v4:" + session.request_id,
        queue_group_id="native-approval-v4:" + session.request_id,
    )
    issued = datetime.fromisoformat(now)
    if issued.tzinfo is None or issued.utcoffset() is None:
        raise ValueError("native_approval_current_time_invalid")
    milliseconds = int(issued.astimezone(timezone.utc).timestamp() * 1000)
    challenge = session.challenge
    issued_at, expires_at = challenge.get("issued_at_ms"), challenge.get("expires_at_ms")
    if type(issued_at) is not int or type(expires_at) is not int:
        raise ValueError("native_approval_challenge_time_invalid")
    if not issued_at <= milliseconds < expires_at:
        raise ValueError("native_approval_challenge_expired")
    source = store._guard_source
    with store._connect() as connection:
        connection.execute("begin immediate")
        _ensure_schema(connection)
        if get_approval_request(connection, request.request_id) is not None:
            raise ValueError("native_approval_request_already_exists")
        binding = load_review_oauth_binding(connection, source)
        if binding is None:
            raise ValueError("native_approval_identity_missing")
        request_id = add_approval_request(connection, request, now, oauth_source=source)
        if request_id != session.request_id:
            raise ValueError("native_approval_queue_identity_mismatch")
        row = get_approval_request(connection, request_id)
        if row is None:
            raise ValueError("native_approval_queue_missing")
        state = seal_native_approval_state(
            store, challenge=session.challenge, snapshot=snapshot, request_row=row, oauth_binding=binding
        )
        connection.execute(
            "insert into guard_native_approval_requests (request_id, oauth_source, state_json) values (?, ?, ?)",
            (request_id, source, state),
        )
        bind_review_events_for_request(connection, request_id=request_id, oauth_source=source)
        return row


def load_native_approval_state(store: GuardStore, request_row: dict[str, object]) -> NativeApprovalState | None:
    """Refuse an absent, replaced, or rebound companion; never infer authority."""

    if not is_native_approval_request(request_row):
        return None
    source = store._guard_source
    with store._connect() as connection:
        table = connection.execute(
            "select name from sqlite_master where type = 'table' and name = 'guard_native_approval_requests'"
        ).fetchone()
        if table is None:
            return None
        row = connection.execute(
            "select state_json from guard_native_approval_requests where request_id = ? and oauth_source = ?",
            (request_row.get("request_id"), source),
        ).fetchone()
        binding = load_review_oauth_binding(connection, source)
        if row is None or binding is None:
            return None
        current = get_approval_request(connection, str(request_row.get("request_id")))
        if current is None:
            return None
        retained = verified_native_approval_state(store, row["state_json"], request_row=current, oauth_binding=binding)
        supplied = verified_native_approval_state(
            store, row["state_json"], request_row=request_row, oauth_binding=binding
        )
        return retained if retained is not None and retained == supplied else None


def has_native_approval_companion(store: GuardStore, request_id: object) -> bool:
    """Retained native state must never silently become a legacy request."""

    if not isinstance(request_id, str):
        return False
    with store._connect() as connection:
        table = connection.execute(
            "select name from sqlite_master where type = 'table' and name = 'guard_native_approval_requests'"
        ).fetchone()
        if table is None:
            return False
        return (
            connection.execute(
                "select 1 from guard_native_approval_requests where request_id = ?", (request_id,)
            ).fetchone()
            is not None
        )
