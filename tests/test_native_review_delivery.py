"""Actual command admission and proof retention; no native consumption is simulated."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_approval_delivery import load_native_approval_decision
from codex_plugin_scanner.guard.native_approval_queue import load_native_approval_state
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.command_capability import CommandCapabilityError
from codex_plugin_scanner.guard.runtime.command_queue_authority import authorize_transport_command_queue_job
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_result, exact_transport_job
from codex_plugin_scanner.guard.runtime.native_review_delivery import validate_native_review_delivery
from codex_plugin_scanner.guard.runtime.native_review_executor import execute_exact_review_job
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_native_approval_queue_state import _NOW, _queue
from tests.test_native_approval_v4_transport import _proof

_RECEIPT = "11111111-1111-4111-8111-111111111111"
_UUID = "22222222-2222-4222-8222-222222222222"


def _ready(tmp_path: Path):
    store = connected_exact_review_store(tmp_path)
    row, session, _ = _queue(store)
    oauth = guard_review_oauth_metadata(store)
    claim = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    proof = _proof()
    proof["challenge"] = session.challenge
    capability = claim.get("exactReviewCapability")
    binding = {
        "actionDigest": session.challenge["action_digest"],
        "approvalId": claim["approvalId"],
        "claimDigest": claim["claimHash"],
        "capabilityId": capability["capabilityId"] if isinstance(capability, dict) else "c" * 64,
        "localRequestId": row["request_id"],
        "localRequestVersion": 1,
        "policyAction": claim["policyAction"],
        "scope": "one-time",
        "grantId": oauth.grant_id,
        "machineId": oauth.machine_id,
        "localMachineInstallationId": oauth.installation_id,
        "runtimeId": oauth.runtime_id,
        "machineInstallationId": _UUID,
        "runtimeGrantId": _UUID,
        "reviewRequestId": _UUID,
    }
    job = exact_transport_job(
        {
            "id": _UUID,
            "operation": "guard.review.resolveExact",
            "protocolVersion": 2,
            "deviceId": oauth.device_id,
            "workspaceId": oauth.workspace_id,
            "nonce": "synthetic-delivery",
            "expiresAt": "2026-09-18T00:00:59+00:00",
            "idempotencyKey": "synthetic-native-delivery",
            "payload": {
                "harness": session.challenge["harness"],
                "nativeApprovalContext": {"decision": "allow_once", "decisionReceiptId": _RECEIPT},
                "nativeApprovalProof": proof,
            },
            "serverResolvedBinding": binding,
        }
    )
    return store, row, job


def _never_resume(**_kwargs):
    raise AssertionError("Proof receipt must not invoke legacy resumption")


def test_actual_transport_receives_proof_without_applying_or_resuming(tmp_path: Path) -> None:
    store, row, job = _ready(tmp_path)
    authorized = authorize_transport_command_queue_job(store, job, schema_versions={}, now=_NOW)
    assert not authorized.requires_local_approval
    execution = execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)
    result = exact_result(job, execution)
    assert result["applicationStatus"] == "failed_retryable"
    assert result["continuationStatus"] == "waiting"
    assert result["receiptId"] == _RECEIPT
    current = store.get_approval_request(str(row["request_id"]))
    assert current["status"] == "pending"
    state = load_native_approval_state(store, current)
    retained = load_native_approval_decision(store, request_id=str(row["request_id"]), expected_state=state)
    assert retained is not None and retained.proof == job["payload"]["nativeApprovalProof"]
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
        assert connection.execute("select consumed_at from guard_native_approval_requests").fetchone()[0] is None


@pytest.mark.parametrize(
    "field",
    [
        "actionDigest",
        "capabilityId",
        "approvalId",
        "claimDigest",
        "localRequestId",
        "policyAction",
        "scope",
        "grantId",
        "machineId",
        "localMachineInstallationId",
        "runtimeId",
        "machineInstallationId",
        "runtimeGrantId",
        "reviewRequestId",
        "localRequestVersion",
    ],
)
def test_substituted_target_is_rejected_before_any_proof_write(tmp_path: Path, field: str) -> None:
    store, _, job = _ready(tmp_path)
    job["serverResolvedBinding"][field] = True if field == "localRequestVersion" else "substituted"
    with pytest.raises(CommandCapabilityError):
        authorize_transport_command_queue_job(store, job, schema_versions={}, now=_NOW)
    with store._connect() as connection:
        assert connection.execute("select proof_json from guard_native_approval_requests").fetchone()[0] is None


@pytest.mark.parametrize("case", ["missing_proof", "changed_challenge", "mixed", "expired", "legacy", "lost_marker"])
def test_wrong_transport_never_reaches_legacy_resolution(tmp_path: Path, case: str) -> None:
    store, row, job = _ready(tmp_path)
    if case == "missing_proof":
        job["payload"]["nativeApprovalProof"] = None
    elif case == "changed_challenge":
        job["payload"]["nativeApprovalProof"]["challenge"]["nonce"] = "e" * 64
    elif case == "mixed":
        job["payload"]["remoteApproval"] = {"localRequestId": row["request_id"]}
    elif case == "expired":
        job["expiresAt"] = _NOW
    else:
        job["payload"] = {"remoteApproval": {"localRequestId": row["request_id"]}}
        if case == "lost_marker":
            with store._connect() as connection:
                connection.execute("update approval_requests set artifact_id = 'ordinary'")
    with pytest.raises((CommandCapabilityError, ValueError)):
        authorize_transport_command_queue_job(store, job, schema_versions={}, now=_NOW)
    with pytest.raises(ValueError):
        execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)


def test_native_action_and_source_digests_cannot_be_replaced_by_envelope_hash(tmp_path: Path) -> None:
    store, row, job = _ready(tmp_path)
    claim = build_local_review_request_claim(request_row=row, oauth=guard_review_oauth_metadata(store), store=store)
    for other in (claim["actionEnvelopeHash"], load_native_approval_state(store, row).snapshot["source_input_digest"]):
        changed = copy.deepcopy(job)
        changed["serverResolvedBinding"]["actionDigest"] = other
        with pytest.raises(ValueError, match="binding_invalid"):
            validate_native_review_delivery(store, changed, now=_NOW)


@pytest.mark.parametrize("change", ["revoked", "sequence"])
def test_admission_is_rechecked_inside_proof_transaction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str):
    from codex_plugin_scanner.guard.native_approval_delivery import retain_native_approval_decision
    from codex_plugin_scanner.guard.runtime import native_review_executor

    store, _, job = _ready(tmp_path)

    def interpose(*args, **kwargs):
        with store._connect() as connection:
            if change == "revoked":
                connection.execute(
                    "insert into sync_state(state_key,payload_json,updated_at) values(?,?,?)",
                    ("guard_exact_cloud_review_revocation", "{}", _NOW),
                )
            else:
                connection.execute("update guard_review_outbox_request_sequences set last_sequence=last_sequence+1")
        return retain_native_approval_decision(*args, **kwargs)

    monkeypatch.setattr(native_review_executor, "retain_native_approval_decision", interpose)
    with pytest.raises(ValueError, match="authority_changed"):
        execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)
    with store._connect() as connection:
        assert connection.execute("select proof_json from guard_native_approval_requests").fetchone()[0] is None


def test_block_resolves_only_the_request_without_permission(tmp_path: Path):
    store, row, job = _ready(tmp_path)
    job["payload"]["nativeApprovalContext"]["decision"] = "block"
    job["payload"]["nativeApprovalProof"] = None
    authorize_transport_command_queue_job(store, job, schema_versions={}, now=_NOW)
    execution = execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)
    result = exact_result(job, execution)
    assert result["applicationStatus"] == "applied"
    assert result["continuationStatus"] == "blocked_not_resumed"
    current = store.get_approval_request(str(row["request_id"]))
    assert current["status"] == "resolved" and current["resolution_action"] == "block"
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
        assert connection.execute("select consumed_at from guard_native_approval_requests").fetchone()[0] is None


@pytest.mark.parametrize("protocol_version", [True, False, 2.0, "2"])
def test_native_protocol_version_requires_an_actual_integer(tmp_path: Path, protocol_version: object) -> None:
    store, _, job = _ready(tmp_path)
    job["protocolVersion"] = protocol_version
    with pytest.raises(CommandCapabilityError):
        authorize_transport_command_queue_job(store, job, schema_versions={}, now=_NOW)
    with pytest.raises(ValueError):
        execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)
    with store._connect() as connection:
        assert connection.execute("select proof_json from guard_native_approval_requests").fetchone()[0] is None
