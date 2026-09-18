"""Source-built fixture-root/real-Keychain caller proof.

This is an explicit staged native component journey, with a synthetic delivered
command and test passkey. It is not production enrollment, browser MFA, an
installed-wheel/default-route claim, or evidence that a tool executed.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from codex_plugin_scanner.guard import native_approval_bridge_v3, native_hook_edge
from codex_plugin_scanner.guard.daemon import hook_worker
from codex_plugin_scanner.guard.native_approval_bridge import NativeApprovalBridge, native_approval_last_failure_code
from codex_plugin_scanner.guard.native_approval_models import _build_envelope, _new_session
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.command_queue_authority import authorize_transport_command_queue_job
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_result, exact_transport_job
from codex_plugin_scanner.guard.runtime.native_review_executor import execute_exact_review_job
from tests.native_approval_resident_fixtures import (
    connected_fixture_store,
    enroll_fixture_passkey,
    sign_fixture_assertion,
)
from tests.native_scoped_resident_fixtures import explicitly_negotiated_test_status


def _job(store, row, proof):
    oauth = guard_review_oauth_metadata(store)
    claim = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    with store._connect() as connection:
        sequence = connection.execute(
            "select last_sequence from guard_review_outbox_request_sequences where local_request_id=?",
            (row["request_id"],),
        ).fetchone()[0]
    capability = claim.get("exactReviewCapability")
    assert isinstance(capability, dict), "fixture requires actual current queue advertisement"
    return exact_transport_job(
        {
            "id": str(uuid4()),
            "operation": "guard.review.resolveExact",
            "protocolVersion": 2,
            "deviceId": oauth.device_id,
            "workspaceId": oauth.workspace_id,
            "nonce": uuid4().hex,
            "expiresAt": claim["expiresAt"],
            "idempotencyKey": uuid4().hex,
            "payload": {
                "harness": row["harness"],
                "nativeApprovalContext": {"decision": "allow_once", "decisionReceiptId": str(uuid4())},
                "nativeApprovalProof": proof,
            },
            "serverResolvedBinding": {
                "actionDigest": proof["challenge"]["action_digest"],
                "approvalId": claim["approvalId"],
                "claimDigest": claim["claimHash"],
                "capabilityId": capability["capabilityId"],
                "localRequestId": row["request_id"],
                "localRequestVersion": sequence,
                "policyAction": claim["policyAction"],
                "scope": "one-time",
                "grantId": oauth.grant_id,
                "machineId": oauth.machine_id,
                "localMachineInstallationId": oauth.installation_id,
                "runtimeId": oauth.runtime_id,
                "machineInstallationId": str(uuid4()),
                "runtimeGrantId": str(uuid4()),
                "reviewRequestId": str(uuid4()),
            },
        }
    )


def _never_resume(**_kwargs):
    raise AssertionError("Received proof cannot resume through the legacy executor")


@pytest.mark.slow
def test_actual_native_review_proof_continues_only_original_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    assert sys.platform == "darwin", "this acceptance invoker requires the actual macOS Keychain"
    for variable in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(variable, raising=False)
    status = explicitly_negotiated_test_status()
    assert status.identity is not None and status.capabilities is not None
    assert "native-approval-webauthn-v4" in status.capabilities.features
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_approval_bridge_v3, "native_runtime_status", lambda: status)
    store = connected_fixture_store(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (store.guard_home / "config.toml").write_text(
        'mode = "enforce"\ndefault_action = "review"\n[harnesses]\ncodex = "review"\n',
        encoding="utf-8",
    )
    assert store._policy_integrity_secret_material(create=True)[0] is not None
    passkey, credential = enroll_fixture_passkey(status.identity.path, store.guard_home)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    worker = hook_worker.HookWorker(store=store, wait_for_native_policy=False, publish_native_policy=False)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf Synthetic"},
        "source_scope": "project",
    }

    def review(value):
        return worker.review_http_payload(
            payload=value,
            params={},
            default_harness="codex",
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=workspace,
            deadline=time.monotonic() + 10,
        )

    try:
        publisher.register_workspace(workspace)
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        first = review(payload)
        assert first["hookSpecificOutput"]["permissionDecision"] == "deny", first.get("reason_code")
        assert first.get("native_approval_required") is True, (
            first.get("reason_code"),
            native_approval_last_failure_code(),
            publisher.last_error,
        )
        request_id = first["approval_request_id"]
        row = store.get_approval_request(request_id)
        assert row is not None and row["status"] == "pending"
        claim = build_local_review_request_claim(request_row=row, oauth=guard_review_oauth_metadata(store), store=store)
        challenge = claim["nativeApprovalChallenge"]
        proof = sign_fixture_assertion(challenge, passkey, credential)
        job = _job(store, row, proof)
        now = datetime.now(timezone.utc).isoformat()
        authorize_transport_command_queue_job(store, job, schema_versions={}, now=now)
        execution = execute_exact_review_job(job, store=store, generated_at=now, resume_after_approval=_never_resume)
        waiting = exact_result(job, execution)
        assert waiting["applicationStatus"] == "failed_retryable" and waiting["continuationStatus"] == "waiting"
        assert store.get_approval_request(request_id)["status"] == "pending"

        changed = {**payload, "tool_input": {"command": "printf Different"}}
        rejected = review(changed)
        assert rejected["hookSpecificOutput"]["permissionDecision"] != "allow"
        assert store.get_approval_request(request_id)["status"] == "pending"
        accepted = review(payload)
        assert accepted["hookSpecificOutput"]["permissionDecision"] == "allow", (
            accepted.get("reason_code"),
            native_approval_last_failure_code(),
            publisher.last_error,
        )
        assert accepted["reason_code"] == "native_approval_v4_consumed"
        with store._connect() as connection:
            events = connection.execute(
                "select *, stream_sequence as sequence from guard_review_outbox_events "
                "where local_request_id=? and event_type=?",
                (request_id, "review.native.application_applied"),
            ).fetchall()
            assert len(events) == 1
            outbox_row = dict(events[0])
            event = json.loads(outbox_row["payload_json"])
            assert event["nativeApplicationResult"]["receipt"]["replay_claimed"] is True
            assert event["nativeApplicationResult"]["sourceClaimHash"] == claim["claimHash"]
            assert event["nativeSourceClaim"]["nativeApprovalChallenge"] == challenge
            assert "continuationResult" not in event
            assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
        from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import project_cloud_review_event

        delivery_binding = {
            key: outbox_row[key]
            for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
        }
        projections = {}
        for redaction in ("full", "partial", "none"):
            projected = project_cloud_review_event(
                store,
                outbox_row=outbox_row,
                delivery_binding=delivery_binding,
                redaction_level=redaction,
                oauth=guard_review_oauth_metadata(store),
            )
            assert projected is not None
            projections[redaction] = projected[1]
            assert projected[1]["nativeApplicationResult"] == event["nativeApplicationResult"]
            assert projected[1]["reviewClaim"] == event["nativeSourceClaim"]
            assert "continuationResult" not in projected[1]
        assert projections["full"]["eventPayloadJson"] == projections["none"]["eventPayloadJson"]
        snapshot = publisher.current_snapshot_binding()
        assert snapshot is not None
        envelope = _build_envelope(
            payload=payload,
            harness="codex",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            policy_snapshot=snapshot,
            deadline_budget_ms=5000,
            request_id=request_id,
        )
        assert envelope is not None
        session = _new_session(challenge, envelope[1])
        bridge = NativeApprovalBridge(status_provider=lambda: status)
        assert bridge.validate_and_consume_v4(session, proof, deadline=time.monotonic() + 5) is None
        output_path = os.environ.get("HGP_NATIVE_APPROVAL_INTEROP_OUTPUT")
        if output_path:
            artifact = {
                "schema": "hol-guard.native-approval-synthetic-interoperability.v1",
                "fixtureRoot": True,
                "pathContext": "synthetic test temporary paths; original claim is unchanged",
                "productionAdvertisement": False,
                "installedWheel": False,
                "browserMfa": False,
                "toolExecution": False,
                "runtimeBinarySha256": status.identity.sha256,
                "sourceClaim": event["nativeSourceClaim"],
                "nativeApplicationResult": event["nativeApplicationResult"],
                "applicationEvent": projections["full"],
            }
            # The exact allowlist excludes credentials, enrollment private keys,
            # passkey private keys, browser proof, and private receiver sources.
            encoded = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
            assert len(encoded) < 200_000
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded + b"\n")
    finally:
        from scripts.native_slo_session import stop_native_resident

        worker.close()
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
