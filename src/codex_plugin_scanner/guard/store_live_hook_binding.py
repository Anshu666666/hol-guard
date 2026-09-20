"""Persist a verified waiting Codex process with its approval, atomically.

This module records transport identity only. It never authorizes an action or
changes a native decision; live completion still requires signed exact approval,
fresh policy review and the existing one-shot continuation transaction.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config
from .continuation_snapshot import canonical_continuation_correlation_id
from .live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    bound_wait_timeout_seconds,
    process_identity_matches,
)
from .models import GuardApprovalRequest


def prepare_live_hook_binding(
    request: GuardApprovalRequest,
    payload: Mapping[str, object] | None,
    *,
    guard_home: Path,
    now: str,
) -> tuple[GuardApprovalRequest, dict[str, object] | None]:
    if request.harness != "codex" or payload is None or CODEX_BROWSER_WAIT_PROCESS_KEY not in payload:
        return request, None
    identity = payload.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    timeout = bound_wait_timeout_seconds(payload, maximum=MAX_APPROVAL_WAIT_TIMEOUT_SECONDS)
    if (
        request.policy_action not in {"review", "require-reapproval"}
        or payload.get("hook_event_name") != "PreToolUse"
        or timeout is None
        or not isinstance(identity, dict)
        or not process_identity_matches(identity)
    ):
        raise ValueError("codex_live_hook_binding_invalid")
    observed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("codex_live_hook_binding_invalid")
    config = load_guard_config(guard_home, Path(request.workspace) if request.workspace else None)
    timeout = min(timeout, config.approval_wait_timeout_seconds, MAX_APPROVAL_WAIT_TIMEOUT_SECONDS)
    if timeout <= 0:
        raise ValueError("codex_live_hook_binding_invalid")
    # Store a commitment, never another copy of the hook's raw command/content.
    digest = hashlib.sha256(
        json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    deadline = observed + timedelta(seconds=timeout)
    metadata: dict[str, object] = {
        "codex_hook_waits_for_browser_approval": True,
        "codex_browser_wait_process": dict(identity),
        "codex_browser_wait_started_at": observed.isoformat(),
        "codex_browser_wait_deadline_at": deadline.isoformat(),
        "codex_browser_wait_timeout_seconds": timeout,
        "codex_live_hook_payload_sha256": digest,
        "hook_event_name": "PreToolUse",
        "workspace": request.workspace,
    }
    snapshot = {
        "correlationId": canonical_continuation_correlation_id(
            request_id=request.request_id, request_row=request.to_dict(), operation_metadata=metadata
        ),
        "capability": "suspended-response",
        "hookAttached": True,
        "opaqueTargetId": None,
        "waitDeadline": deadline.isoformat(),
    }
    return replace(request, continuation_snapshot=snapshot), metadata


def persist_live_hook_binding(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    request: GuardApprovalRequest,
    metadata: dict[str, object],
    oauth_source: str,
    now: str,
    request_was_inserted: bool,
) -> None:
    """Run inside the same immediate transaction as approval/outbox insertion."""
    identity = metadata["codex_browser_wait_process"]
    if not process_identity_matches(identity):
        raise ValueError("codex_live_hook_process_unavailable")
    # The deterministic operation key gives a request one owner. A second live
    # process cannot steal a deduplicated pending request or extend its deadline.
    operation_id = "codex-live-" + request_id
    other = connection.execute(
        "select operation_id from guard_operations "
        "where operation_id != ? and exists "
        "(select 1 from json_each(approval_request_ids_json) where value = ?) limit 1",
        (operation_id, request_id),
    ).fetchone()
    if other is not None:
        raise ValueError("codex_live_hook_owner_conflict")
    row = connection.execute(
        "select o.metadata_json, o.status, o.harness, o.approval_request_ids_json, "
        "s.harness as session_harness, s.status as session_status, s.workspace "
        "from guard_operations o left join guard_sessions s on s.session_id = o.session_id "
        "where o.operation_id = ?",
        (operation_id,),
    ).fetchone()
    if row is None and not request_was_inserted:
        raise ValueError("codex_live_hook_owner_conflict")
    if row is not None:
        previous = json.loads(row["metadata_json"])
        if (
            row["status"] != "waiting_on_approval"
            or row["harness"] != "codex"
            or row["session_harness"] != "codex"
            or row["session_status"] != "waiting_on_approval"
            or row["workspace"] != request.workspace
            or json.loads(row["approval_request_ids_json"]) != [request_id]
            or previous.get("codex_browser_wait_process") != identity
            or previous.get("codex_live_hook_payload_sha256") != metadata["codex_live_hook_payload_sha256"]
        ):
            raise ValueError("codex_live_hook_owner_conflict")
        metadata = previous
    deadline = datetime.fromisoformat(str(metadata["codex_browser_wait_deadline_at"]))
    if deadline.tzinfo is None or deadline <= datetime.now(timezone.utc):
        raise ValueError("codex_live_hook_deadline_expired")
    request_row = connection.execute(
        "select status, harness, continuation_snapshot_json from approval_requests "
        "where request_id = ? and oauth_source = ?",
        (request_id, oauth_source),
    ).fetchone()
    if request_row is None or request_row["status"] != "pending" or request_row["harness"] != "codex":
        raise ValueError("codex_live_hook_request_unavailable")
    snapshot = json.loads(request_row["continuation_snapshot_json"])
    snapshot["waitDeadline"] = deadline.isoformat()
    connection.execute(
        "update approval_requests set continuation_snapshot_json = ? where request_id = ? and oauth_source = ?",
        (json.dumps(snapshot), request_id, oauth_source),
    )
    if row is not None:
        return
    session_id = "codex-live-" + uuid.uuid4().hex
    connection.execute(
        """insert into guard_sessions (session_id, harness, surface, status, client_name,
        client_title, client_version, workspace, capabilities_json, created_at, updated_at)
        values (?, 'codex', 'harness-adapter', 'waiting_on_approval', 'codex-hook',
        'Codex hook', '1.0.0', ?, ?, ?, ?)""",
        (session_id, request.workspace, json.dumps(["approval-resolution", "receipt-view"]), now, now),
    )
    connection.execute(
        """insert into guard_operations (operation_id, session_id, harness, operation_type,
        status, approval_request_ids_json, resume_token, metadata_json, created_at, updated_at)
        values (?, ?, 'codex', 'tool_call', 'waiting_on_approval', ?, ?, ?, ?, ?)""",
        (operation_id, session_id, json.dumps([request_id]), uuid.uuid4().hex, json.dumps(metadata), now, now),
    )
