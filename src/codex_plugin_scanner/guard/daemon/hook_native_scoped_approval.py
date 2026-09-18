"""Original-request continuation through the live native approval authority."""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from uuid import uuid4

from ..models import GuardApprovalRequest
from ..native_approval_application import retain_native_consumption
from ..native_approval_bridge import NativeApprovalBridge, native_approval_continuation_allowed
from ..native_approval_delivery import load_native_approval_decision
from ..native_approval_models import _build_envelope, _new_session
from ..native_approval_queue import load_native_approval_state, queue_native_approval_request
from ..native_approval_state import NativeApprovalState
from ..store import GuardStore
from .hook_native_review_approval import (
    _native_review_action_envelope,
    _native_review_approval_center_url,
    _native_review_launch_target,
    _native_review_tool_name,
)
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
    integrity_fail_closed_pre_tool_response,
)

_HEX = re.compile(r"[0-9a-f]{64}")


def _current(publisher: object, snapshot: dict[str, object]) -> bool:
    getter = getattr(publisher, "current_snapshot_binding", None)
    fence = getattr(publisher, "result_binding_is_current", None)
    if not callable(getter) or not callable(fence) or getter() != snapshot:
        return False
    binding = {k: v for k, v in snapshot.items() if k not in {"generation", "mode"}}
    binding.update(policy_generation=snapshot.get("generation"), selected_decision_id=None)
    return fence(binding) is True


def _failure(harness: str) -> dict[str, object]:
    return integrity_fail_closed_pre_tool_response(
        harness,
        reason="HOL Guard could not verify this native approval.",
        reason_code="native_approval_unavailable",
    )


def _pending(
    store: GuardStore,
    *,
    digest: str,
    harness: str,
    snapshot: dict[str, object],
    now_ms: int,
) -> tuple[dict[str, object], NativeApprovalState] | None:
    with store._connect() as connection:
        if (
            connection.execute(
                "select 1 from sqlite_master where type='table' and name='guard_native_approval_requests'"
            ).fetchone()
            is None
        ):
            return None
        rows = connection.execute(
            "select r.request_id from approval_requests r join guard_native_approval_requests n "
            "on r.request_id = n.request_id where r.harness = ? and r.artifact_hash = ? "
            "and n.oauth_source = ? and r.status = 'pending' order by r.created_at, r.request_id limit 17",
            (harness, digest, store._guard_source),
        ).fetchall()
    if len(rows) > 16:
        raise ValueError("native_approval_pending_ambiguous")
    for reference in rows:
        row = store.get_approval_request(str(reference["request_id"]))
        state = load_native_approval_state(store, row) if row is not None else None
        if state is None:
            raise ValueError("native_approval_request_binding_invalid")
        if state.snapshot == snapshot and cast(int, state.challenge["issued_at_ms"]) <= now_ms < cast(
            int, state.challenge["expires_at_ms"]
        ):
            return cast(dict[str, object], row), state
    return None


def _presentation(
    store: GuardStore,
    *,
    request_id: str,
    harness: str,
    payload: dict[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    guard_home: Path,
) -> GuardApprovalRequest:
    tool = _native_review_tool_name(payload)
    target = _native_review_launch_target(payload)
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id="native-approval-pending",
        artifact_name=tool,
        artifact_hash=request_id,
        policy_action=str(native_result["minimum_action"]),
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace or guard_home),
        workspace=str(workspace) if workspace is not None else None,
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"{_native_review_approval_center_url(store)}/requests/{request_id}",
        artifact_type="tool_call",
        launch_target=target,
        risk_summary=str(native_result.get("reason") or "This action requires native approval."),
        action_envelope_json=_native_review_action_envelope(
            request_id=request_id,
            harness=harness,
            tool_name=tool,
            command=pre_tool_command(payload),
            launch_target=target,
            workspace=workspace,
        ),
    )


def coordinate_scoped_native_approval(
    store: GuardStore,
    *,
    publisher: object,
    policy_snapshot: dict[str, object],
    harness: str,
    payload: dict[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path,
    deadline: float | None,
) -> dict[str, object]:
    """A queued challenge/proof never substitutes for actual resident consume."""
    try:
        digest = native_receipt.get("request_digest") if native_receipt is not None else None
        if (
            not isinstance(digest, str)
            or _HEX.fullmatch(digest) is None
            or policy_snapshot.get("mode") != "enforce"
            or not _current(publisher, policy_snapshot)
        ):
            return _failure(harness)
        now = datetime.now(timezone.utc)
        pending = _pending(
            store, digest=digest, harness=harness, snapshot=policy_snapshot, now_ms=int(now.timestamp() * 1000)
        )
        bridge = NativeApprovalBridge()
        if pending is None:
            request_id = payload.get("request_id") if payload.get("request_id") is not None else uuid4().hex
            if not isinstance(request_id, str):
                return _failure(harness)
            session = bridge.create_v4_challenge(
                payload=payload,
                harness=harness,
                guard_home=guard_home,
                home_dir=home_dir,
                cwd=workspace,
                policy_snapshot=policy_snapshot,
                deadline=deadline,
                request_id=request_id,
            )
            if session is None or session.request_digest != digest or not _current(publisher, policy_snapshot):
                return _failure(harness)
            queued = queue_native_approval_request(
                store,
                request=_presentation(
                    store,
                    request_id=session.request_id,
                    harness=harness,
                    payload=payload,
                    native_result=native_result,
                    workspace=workspace,
                    guard_home=guard_home,
                ),
                session=session,
                snapshot=policy_snapshot,
                now=datetime.now(timezone.utc).isoformat(),
            )
        else:
            queued, state = pending
            received = load_native_approval_decision(store, request_id=str(queued["request_id"]), expected_state=state)
            if received is not None:
                if received.decision != "allow_once" or received.proof is None:
                    return _failure(harness)
                remaining = min(10_000, int(((deadline or (time.monotonic() + 10)) - time.monotonic()) * 1000))
                rebuilt = _build_envelope(
                    payload=payload,
                    harness=harness,
                    guard_home=guard_home,
                    home_dir=home_dir,
                    cwd=workspace,
                    policy_snapshot=policy_snapshot,
                    deadline_budget_ms=remaining,
                    request_id=str(queued["request_id"]),
                )
                if rebuilt is None or not _current(publisher, policy_snapshot):
                    return _failure(harness)
                session = _new_session(state.challenge, rebuilt[1])
                consumed = bridge.validate_and_consume_v4(session, received.proof, deadline=deadline)
                consumed_at = datetime.now(timezone.utc).isoformat()
                if (
                    consumed is None
                    or not native_approval_continuation_allowed(
                        consumed,
                        session=session,
                        request_id=session.request_id,
                        request_digest=digest,
                        action_digest=session.action_digest,
                        policy_generation=session.policy_generation,
                        policy_digest=session.policy_digest,
                        harness=harness,
                    )
                    or not _current(publisher, policy_snapshot)
                ):
                    return _failure(harness)
                retain_native_consumption(
                    store, session=session, consumed=consumed, state=state, decision=received, consumed_at=consumed_at
                )
                if not _current(publisher, policy_snapshot):
                    return _failure(harness)
                # Render the consumed native approval; leave the earlier hashed
                # policy review receipt and its attribution unchanged.
                approved = {
                    **native_result,
                    "decision": "allow",
                    "minimum_action": "allow",
                    "policy_action": "allow",
                    "reason_code": "native_approval_v4_consumed",
                }
                response = harness_json_from_native_pre_tool(harness, approved)
                response["approval_reuse_status"] = "accepted"
                response["native_approval_request_id"] = session.request_id
                return response
        if not _current(publisher, policy_snapshot):
            return _failure(harness)
        response = harness_json_from_native_pre_tool_review(
            harness, native_result, approval=queued, guard_home=guard_home
        )
        response["native_approval_required"] = True
        response["prompted"] = True
        response["approval_center_url"] = _native_review_approval_center_url(store)
        return response
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error, KeyError):
        return _failure(harness)
