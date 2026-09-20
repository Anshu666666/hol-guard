"""Complete a waiting action only from a consumed resident approval receipt."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .native_approval_bridge import consume_presented_native_approval_v4, native_approval_continuation_allowed
from .native_approval_models import NativeApprovalSession, NativeConsumedReceipt
from .native_live_approval_state import (
    PROOF_FIELD,
    bound_request_version,
    canonical_digest,
    challenge_for_request,
    current_cloud_binding,
    live_metadata,
)

if TYPE_CHECKING:
    from .store import GuardStore

_FACTORY = object()


@dataclass(frozen=True)
class NativeLiveCompletionAuthority:
    session: NativeApprovalSession = field(repr=False)
    receipt: NativeConsumedReceipt = field(repr=False)
    payload_digest: str
    pending_digest: str
    cloud_binding: Mapping[str, object] = field(repr=False)
    deadline: datetime
    _factory: object = field(repr=False)

    def __post_init__(self) -> None:
        if self._factory is not _FACTORY:
            raise ValueError("native_live_authority_invalid")


def _receipt_current(authority: NativeLiveCompletionAuthority) -> bool:
    session = authority.session
    return native_approval_continuation_allowed(
        authority.receipt,
        session=session,
        request_id=session.request_id,
        request_digest=session.request_digest,
        action_digest=session.action_digest,
        policy_generation=session.policy_generation,
        policy_digest=session.policy_digest,
        harness="codex",
    )


def native_live_receipt_evidence(authority: object) -> dict[str, object] | None:
    """Detached observation only; JSON can never restore consumed provenance."""
    if type(authority) is not NativeLiveCompletionAuthority or not _receipt_current(authority):
        return None
    return authority.receipt.receipt


def finalize_native_live_authority(
    connection: sqlite3.Connection, request_id: str, authority: object, now: str
) -> bool:
    """Recheck live ownership and commit resolution inside the completion transaction."""
    if type(authority) is not NativeLiveCompletionAuthority or not _receipt_current(authority):
        return False
    from .store_approvals import get_approval_request
    from .store_approvals import resolve_approval_request as persist_approval_resolution

    request = get_approval_request(connection, request_id)
    if (
        request is None
        or request.get("status") != "pending"
        or request.get("policy_action") not in {"review", "require-reapproval"}
    ):
        return False
    if challenge_for_request(request) != authority.session.challenge:
        return False
    observed = datetime.now(timezone.utc)
    if authority.deadline <= observed:
        return False
    metadata = live_metadata(connection, request_id, request, now=observed)
    pending = metadata.get(PROOF_FIELD)
    if (
        metadata.get("codex_live_hook_payload_sha256") != authority.payload_digest
        or canonical_digest(pending) != authority.pending_digest
        or not isinstance(pending, Mapping)
        or pending.get("requestVersion") != bound_request_version(connection, request_id, authority.cloud_binding)
    ):
        return False
    persist_approval_resolution(
        connection,
        request_id,
        resolution_action="allow",
        resolution_scope="one-time",
        reason="native_approval_v4_consumed",
        resolved_at=now,
    )
    return True


class NativeLiveCompletion:
    """Daemon-owned short-lived replay responses, never restored from SQLite."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._completed: dict[str, NativeLiveCompletionAuthority] = {}

    def complete(
        self,
        store: GuardStore,
        request_id: str,
        payload: Mapping[str, object],
        *,
        home_dir: Path,
        policy_snapshot: Mapping[str, object] | None,
    ) -> dict[str, object]:
        try:
            with self._lock, store.hold_oauth_credential_lock():
                return self._complete(store, request_id, payload, home_dir=home_dir, policy_snapshot=policy_snapshot)
        except (ValueError, TypeError, KeyError, OSError, sqlite3.Error):
            return {"completed": False, "error": "native_live_completion_refused"}

    def _complete(
        self,
        store: GuardStore,
        request_id: str,
        payload: Mapping[str, object],
        *,
        home_dir: Path,
        policy_snapshot: Mapping[str, object] | None,
    ) -> dict[str, object]:
        now = datetime.now(timezone.utc)
        self._completed = {key: value for key, value in self._completed.items() if value.deadline > now}
        if policy_snapshot is None:
            raise ValueError("native_live_policy_unavailable")
        request = store.get_approval_request(request_id)
        if request is None or request.get("policy_action") not in {"review", "require-reapproval"}:
            raise ValueError("native_live_request_unavailable")
        challenge = challenge_for_request(request)
        if challenge is None or any(
            challenge.get(key) != policy_snapshot.get(other)
            for key, other in (
                ("policy_generation", "generation"),
                ("policy_digest", "policy_digest"),
                ("runtime_identity", "runtime_identity"),
            )
        ):
            raise ValueError("native_live_policy_changed")
        raw = payload.get("hook_input")
        if not isinstance(raw, str):
            raise ValueError("native_live_input_invalid")
        hook = json.loads(raw)
        if not isinstance(hook, dict) or hook.get("hook_event_name") != "PreToolUse":
            raise ValueError("native_live_input_invalid")
        with store._connect() as connection:
            metadata = live_metadata(connection, request_id, request, now=now)
        payload_digest = canonical_digest(hook)
        if metadata.get("codex_live_hook_payload_sha256") != payload_digest:
            raise ValueError("native_live_input_changed")
        pending = metadata.get(PROOF_FIELD)
        if not isinstance(pending, dict) or pending.get("cloudBinding") != current_cloud_binding(
            store, now=now.isoformat()
        ):
            raise ValueError("native_live_cloud_binding_changed")
        prior = self._completed.get(request_id)
        if prior is not None:
            if (
                not _receipt_current(prior)
                or prior.payload_digest != payload_digest
                or prior.pending_digest != canonical_digest(pending)
                or prior.cloud_binding != pending["cloudBinding"]
            ):
                raise ValueError("native_live_replay_binding_changed")
            if request.get("status") == "resolved":
                previous = store.get_request_resume(request_id)
                if (
                    request.get("resolution_action") != "allow"
                    or not isinstance(previous, dict)
                    or previous.get("continuation_status") != "resumed"
                ):
                    raise ValueError("native_live_replay_not_complete")
                return {
                    "completed": True,
                    "action": "allow",
                    "continuation": previous,
                    "replayed": True,
                    "nativeApprovalReceipt": prior.receipt.receipt,
                }
        if request.get("status") != "pending" or (prior is None and len(self._completed) >= 256):
            raise ValueError("native_live_request_unavailable")
        with store._connect() as connection:
            if pending.get("requestVersion") != bound_request_version(connection, request_id, pending["cloudBinding"]):
                raise ValueError("native_live_version_changed")
        challenge_expiry = challenge.get("expires_at_ms")
        if type(challenge_expiry) is not int:
            raise ValueError("native_live_challenge_invalid")
        wait_deadline = min(
            datetime.fromisoformat(str(metadata["codex_browser_wait_deadline_at"])),
            datetime.fromtimestamp(challenge_expiry / 1000, timezone.utc),
        )
        remaining = min(5.0, (wait_deadline - now).total_seconds())
        if remaining <= 0:
            raise ValueError("native_live_deadline_expired")
        proof = pending.get("proof")
        if not isinstance(proof, dict) or proof.get("challenge") != challenge:
            raise ValueError("native_live_proof_changed")
        workspace = request.get("workspace")
        authority = prior
        if authority is None:
            outcome = consume_presented_native_approval_v4(
                challenge=challenge,
                artifact=proof,
                payload=hook,
                harness="codex",
                guard_home=store.guard_home,
                home_dir=home_dir,
                cwd=Path(workspace) if isinstance(workspace, str) else None,
                policy_snapshot=policy_snapshot,
                deadline=time.monotonic() + remaining,
            )
            if outcome is None:
                raise ValueError("native_live_consume_refused")
            authority = NativeLiveCompletionAuthority(
                outcome[0],
                outcome[1],
                payload_digest,
                canonical_digest(pending),
                pending["cloudBinding"],
                wait_deadline,
                _FACTORY,
            )
            # Retain only the actual consumed object across an aborted SQLite
            # transaction. A retry must pass every current binding check above;
            # it cannot reconstruct this authority from persisted evidence.
            self._completed[request_id] = authority
        from .continuation_runtime import record_live_hook_completion

        completion = record_live_hook_completion(
            store,
            request_id=request_id,
            action="allow",
            now=datetime.now(timezone.utc).isoformat(),
            native_approval=authority,
        )
        if not isinstance(completion, dict) or completion.get("continuationStatus") != "resumed":
            raise ValueError("native_live_commit_refused")
        self._completed[request_id] = authority
        return {
            "completed": True,
            "action": "allow",
            "continuation": completion,
            "replayed": False,
            "nativeApprovalReceipt": authority.receipt.receipt,
        }
