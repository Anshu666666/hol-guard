"""Bounded transport state for a live native approval; no local allow authority."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .live_process_identity import process_identity_matches
from .native_approval_protocol import decode_native_approval_v4_proof
from .native_review_challenge_projection import project_native_review_challenge

if TYPE_CHECKING:
    from .store import GuardStore

PROOF_FIELD = "native_approval_pending_proof"


def request_version(connection: sqlite3.Connection, request_id: str) -> int:
    row = connection.execute(
        "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None or type(row[0]) is not int or row[0] < 1:
        raise ValueError("native_live_version_unavailable")
    return row[0]


def bound_request_version(connection: sqlite3.Connection, request_id: str, binding: Mapping[str, object]) -> int:
    """Join the immutable outbox subject with the current authenticated subject."""
    from .store_review_event_outbox_binding import review_event_oauth_subject_hash

    row = connection.execute(
        "select * from guard_review_outbox_request_sequences where local_request_id = ?", (request_id,)
    ).fetchone()
    grant = binding.get("grantId")
    expected = {
        "oauth_source": binding.get("oauthSource"),
        "oauth_subject_hash": review_event_oauth_subject_hash(grant if isinstance(grant, str) else None),
        "workspace_id": binding.get("workspaceId"),
        "machine_id": binding.get("machineId"),
        "machine_installation_id": binding.get("installationId"),
    }
    if row is None or any(value is None or row[key] != value for key, value in expected.items()):
        raise ValueError("native_live_original_subject_changed")
    return request_version(connection, request_id)


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def challenge_for_request(request: Mapping[str, object]) -> dict[str, object] | None:
    challenge = project_native_review_challenge(dict(request))
    if challenge is None:
        return None
    if challenge["request_id"] != request.get("request_id") or challenge["harness"] != request.get("harness"):
        raise ValueError("native_live_challenge_invalid")
    return challenge


def existing_native_waiter(
    store: GuardStore, request_id: str, payload: Mapping[str, object], policy_snapshot: Mapping[str, object]
) -> dict[str, object] | None:
    """Return only the original live pending observation; never renew it."""
    request = store.get_approval_request(request_id)
    if request is None:
        return None
    challenge = challenge_for_request(request)
    now = datetime.now(timezone.utc)
    if request.get("status") != "pending" or challenge is None:
        raise ValueError("native_live_request_unavailable")
    expiry = challenge.get("expires_at_ms")
    if (
        type(expiry) is not int
        or expiry <= now.timestamp() * 1000
        or any(
            challenge.get(key) != policy_snapshot.get(other)
            for key, other in (
                ("policy_generation", "generation"),
                ("policy_digest", "policy_digest"),
                ("runtime_identity", "runtime_identity"),
            )
        )
    ):
        raise ValueError("native_live_request_changed")
    current = current_cloud_binding(store, now=now.isoformat())
    with store._connect() as connection:
        metadata = live_metadata(connection, request_id, request, now=now)
        bound_request_version(connection, request_id, current)
    if metadata.get("codex_live_hook_payload_sha256") != canonical_digest(payload):
        raise ValueError("native_live_input_changed")
    return request


def live_metadata(
    connection: sqlite3.Connection, request_id: str, request: Mapping[str, object], *, now: datetime
) -> dict[str, object]:
    row = connection.execute(
        "select o.metadata_json, o.status, o.harness, o.approval_request_ids_json, s.harness as session_harness, "
        "s.status as session_status, s.workspace from guard_operations o join guard_sessions s "
        "on s.session_id = o.session_id where o.operation_id = ?",
        ("codex-live-" + request_id,),
    ).fetchone()
    if (
        row is None
        or row["harness"] != "codex"
        or row["session_harness"] != "codex"
        or row["workspace"] != request.get("workspace")
    ):
        raise ValueError("native_live_owner_unavailable")
    if json.loads(row["approval_request_ids_json"]) != [request_id]:
        raise ValueError("native_live_owner_unavailable")
    metadata = json.loads(row["metadata_json"])
    if not isinstance(metadata, dict) or not process_identity_matches(metadata.get("codex_browser_wait_process")):
        raise ValueError("native_live_owner_unavailable")
    deadline = datetime.fromisoformat(str(metadata.get("codex_browser_wait_deadline_at")))
    if deadline.tzinfo is None or deadline <= now:
        raise ValueError("native_live_deadline_expired")
    if request.get("status") == "pending" and (
        row["status"] != "waiting_on_approval" or row["session_status"] != "waiting_on_approval"
    ):
        raise ValueError("native_live_owner_unavailable")
    return metadata


def parse_native_job(payload: Mapping[str, object]) -> tuple[str, str, dict[str, object]]:
    if "remoteApproval" in payload:
        raise ValueError("native_live_mixed_authority")
    context = payload.get("nativeApprovalContext")
    proof = payload.get("nativeApprovalProof")
    if (
        not isinstance(context, dict)
        or set(context) != {"decision", "decisionReceiptId"}
        or context["decision"] != "allow_once"
    ):
        raise ValueError("native_live_decision_invalid")
    receipt_id = context.get("decisionReceiptId")
    if not isinstance(receipt_id, str) or not receipt_id or len(receipt_id) > 128 or receipt_id.strip() != receipt_id:
        raise ValueError("native_live_receipt_invalid")
    decoded = decode_native_approval_v4_proof(proof) if isinstance(proof, (dict, bytes)) else None
    if decoded is None:
        raise ValueError("native_live_proof_invalid")
    challenge = decoded["challenge"]
    if not isinstance(challenge, dict) or challenge.get("harness") != "codex" or payload.get("harness") != "codex":
        raise ValueError("native_live_harness_invalid")
    return str(challenge["request_id"]), receipt_id, json.loads(json.dumps(decoded, allow_nan=False))


def current_cloud_binding(store: GuardStore, *, now: str) -> dict[str, object]:
    from .runtime.exact_cloud_review import _capability_digest, _oauth_binding, _verified_capability

    capability = _verified_capability(store, now=now)
    return {**_oauth_binding(store), "oauthSource": store._guard_source, "capabilityId": _capability_digest(capability)}


def validate_native_job(
    store: GuardStore, job: Mapping[str, object], *, now: str
) -> tuple[str, str, dict[str, object], dict[str, object]]:
    payload = job.get("payload")
    binding = job.get("serverResolvedBinding")
    if not isinstance(payload, Mapping) or not isinstance(binding, Mapping):
        raise ValueError("native_live_job_invalid")
    request_id, receipt_id, proof = parse_native_job(payload)
    request = store.get_approval_request(request_id)
    if (
        not isinstance(request, dict)
        or request.get("status") != "pending"
        or request.get("policy_action") not in {"review", "require-reapproval"}
    ):
        raise ValueError("native_live_request_unavailable")
    challenge = challenge_for_request(request)
    if challenge is None or challenge != proof["challenge"]:
        raise ValueError("native_live_proof_binding_mismatch")
    observed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    issued = challenge.get("issued_at_ms")
    expires = challenge.get("expires_at_ms")
    if (
        observed.tzinfo is None
        or type(issued) is not int
        or type(expires) is not int
        or not issued <= observed.timestamp() * 1000 < expires
    ):
        raise ValueError("native_live_challenge_expired")
    current = current_cloud_binding(store, now=now)
    from .review_contracts import build_local_review_request_claim
    from .review_oauth_binding import guard_review_oauth_metadata

    claim = build_local_review_request_claim(
        request_row=request, oauth=guard_review_oauth_metadata(store, require_device_dpop_binding=True), store=store
    )
    expected = {
        "actionDigest": challenge["action_digest"],
        "approvalId": request_id,
        "claimDigest": claim["claimHash"],
        "capabilityId": current["capabilityId"],
        "localRequestId": request_id,
        "policyAction": request["policy_action"],
        "scope": "one-time",
        "grantId": current["grantId"],
        "machineId": current["machineId"],
        "localMachineInstallationId": current["installationId"],
        "runtimeId": current["runtimeId"],
    }
    if (
        any(binding.get(key) != value for key, value in expected.items())
        or job.get("workspaceId") != current["workspaceId"]
        or job.get("deviceId") != current["deviceId"]
    ):
        raise ValueError("native_live_job_binding_mismatch")
    with store._connect() as connection:
        live_metadata(connection, request_id, request, now=observed)
        version = binding.get("localRequestVersion")
        if type(version) is not int or version != bound_request_version(connection, request_id, current):
            raise ValueError("native_live_version_changed")
    return request_id, receipt_id, proof, current


def stage_native_job(store: GuardStore, job: Mapping[str, object], *, now: str) -> tuple[str, str]:
    """Store a returned assertion for the original hook, without resolving it."""
    with store.hold_oauth_credential_lock():
        request_id, receipt_id, proof, binding = validate_native_job(store, job, now=now)
        request = store.get_approval_request(request_id)
        assert isinstance(request, dict)
        with store._connect() as connection:
            connection.execute("begin immediate")
            from .store_approvals import get_approval_request

            locked = get_approval_request(connection, request_id)
            if locked != request:
                raise ValueError("native_live_request_changed")
            metadata = live_metadata(connection, request_id, request, now=datetime.now(timezone.utc))
            resolved_binding = job.get("serverResolvedBinding")
            if not isinstance(resolved_binding, Mapping):
                raise ValueError("native_live_job_invalid")
            version = bound_request_version(connection, request_id, binding)
            if resolved_binding.get("localRequestVersion") != version:
                raise ValueError("native_live_version_changed")
            pending = {"proof": proof, "receiptId": receipt_id, "cloudBinding": binding, "requestVersion": version}
            existing = metadata.get(PROOF_FIELD)
            if existing is not None and existing != pending:
                raise ValueError("native_live_proof_conflict")
            metadata[PROOF_FIELD] = pending
            connection.execute(
                "update guard_operations set metadata_json = ? where operation_id = ?",
                (json.dumps(metadata, allow_nan=False), "codex-live-" + request_id),
            )
        return request_id, receipt_id


def native_proof_ready(store: GuardStore, request: Mapping[str, object]) -> bool:
    try:
        if request.get("status") != "pending" or challenge_for_request(request) is None:
            return False
        with store._connect() as connection:
            metadata = live_metadata(connection, str(request["request_id"]), request, now=datetime.now(timezone.utc))
    except (ValueError, TypeError, KeyError, sqlite3.Error):
        return False
    return isinstance(metadata.get(PROOF_FIELD), dict)
