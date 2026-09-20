"""Actual Store/continuation transactions with an explicitly controlled resident.

The fixture supplies opaque, non-cryptographic browser bytes and synthetic
resident responses. It exercises Python transport and completion, not Rust
signature verification or installed-native qualification.
"""

from __future__ import annotations

import copy
import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_approval_bridge
from codex_plugin_scanner.guard.native_approval_bridge import NativeApprovalBridge
from codex_plugin_scanner.guard.native_live_approval_completion import NativeLiveCompletion
from codex_plugin_scanner.guard.native_live_approval_state import (
    current_cloud_binding,
    native_proof_ready,
    request_version,
    stage_native_job,
)
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from tests.test_guard_live_hook_binding import setup
from tests.test_native_approval_v4_transport import _artifact, _challenge, _result, _status


class NativeWait:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, challenge_seconds: int = 30) -> None:
        self.store, request, self.payload = setup(tmp_path)
        enable_exact_cloud_review(self.store)
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.challenge = _challenge()
        now = datetime.now(timezone.utc)
        self.challenge.update(
            request_id=request.request_id,
            harness="codex",
            issued_at_ms=int(now.timestamp() * 1000),
            expires_at_ms=int((now + timedelta(seconds=challenge_seconds)).timestamp() * 1000),
        )
        self.snapshot = {
            "generation": self.challenge["policy_generation"],
            "policy_digest": self.challenge["policy_digest"],
            "runtime_identity": self.challenge["runtime_identity"],
        }
        self.proof = {
            "schema": "guard-native-approval-proof.v4",
            "challenge": copy.deepcopy(self.challenge),
            "assertion": _artifact()["webauthn"],
        }
        assert isinstance(request.action_envelope_json, dict)
        request = replace(
            request,
            action_envelope_json={
                **request.action_envelope_json,
                "nativeApprovalChallenge": self.challenge,
            },
        )
        self.request_id = self.store.add_approval_request(request, now.isoformat(), live_hook_payload=self.payload)
        self.calls: list[dict[str, Any]] = []
        self.consume_allowed = True
        self.receipt_change: tuple[str, object] | None = None

        def client(**kwargs: object) -> bytes:
            encoded = kwargs["payload"]
            assert isinstance(encoded, bytes)
            wire = json.loads(encoded)
            self.calls.append(wire)
            operation = wire["operation"]
            if operation == "approval_consume_v4" and not self.consume_allowed:
                return b"{}"
            phase = "validated" if operation == "approval_validate_v4" else "consumed"
            result = _result(phase=phase)
            receipt = result["receipt"]
            assert isinstance(receipt, dict)
            for key in (set(receipt) & set(self.challenge)) - {"schema"}:
                receipt[key] = self.challenge[key]
            if self.receipt_change:
                receipt[self.receipt_change[0]] = self.receipt_change[1]
            return json.dumps(result).encode()

        bridge = NativeApprovalBridge(
            client_request=client,
            status_provider=lambda: _status(tmp_path),
            environment_provider=lambda: {},
            clock=time.monotonic,
        )
        monkeypatch.setattr(native_approval_bridge, "_DEFAULT_BRIDGE", bridge)
        self.coordinator = NativeLiveCompletion()

    def job(self) -> dict[str, Any]:
        row = self.store.get_approval_request(self.request_id)
        assert isinstance(row, dict)
        claim = build_local_review_request_claim(
            request_row=row,
            oauth=guard_review_oauth_metadata(self.store, require_device_dpop_binding=True),
            store=self.store,
        )
        current = current_cloud_binding(self.store, now=datetime.now(timezone.utc).isoformat())
        with self.store._connect() as connection:
            version = request_version(connection, self.request_id)
        return {
            "id": "native-job-1",
            "protocolVersion": 2,
            "operation": "guard.review.resolveExact",
            "workspaceId": current["workspaceId"],
            "deviceId": current["deviceId"],
            "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "nonce": "native-nonce",
            "idempotencyKey": "native-idempotency",
            "payload": {
                "harness": "codex",
                "nativeApprovalProof": copy.deepcopy(self.proof),
                "nativeApprovalContext": {"decision": "allow_once", "decisionReceiptId": "native-receipt-1"},
            },
            "serverResolvedBinding": {
                "actionDigest": self.challenge["action_digest"],
                "approvalId": self.request_id,
                "claimDigest": claim["claimHash"],
                "capabilityId": current["capabilityId"],
                "localRequestId": self.request_id,
                "localRequestVersion": version,
                "policyAction": row["policy_action"],
                "scope": "one-time",
                "grantId": current["grantId"],
                "machineId": current["machineId"],
                "localMachineInstallationId": current["installationId"],
                "runtimeId": current["runtimeId"],
            },
        }

    def stage(self) -> None:
        stage_native_job(self.store, self.job(), now=datetime.now(timezone.utc).isoformat())

    def complete(self) -> dict[str, object]:
        return self.coordinator.complete(
            self.store,
            self.request_id,
            {"hook_input": json.dumps(self.payload)},
            home_dir=self.home,
            policy_snapshot=self.snapshot,
        )


def test_proof_staging_leaves_pending_and_only_consumed_receipt_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    row = wait.store.get_approval_request(wait.request_id)
    assert isinstance(row, dict) and row["status"] == "pending"
    assert native_proof_ready(wait.store, row) and not wait.calls
    assert wait.store.get_request_resume(wait.request_id) is None
    completed = wait.complete()
    assert completed["completed"] is True
    assert [call["operation"] for call in wait.calls] == ["approval_validate_v4", "approval_consume_v4"]
    after = wait.store.get_approval_request(wait.request_id)
    assert (
        isinstance(after, dict) and after["status"] == "resolved" and after["reason"] == "native_approval_v4_consumed"
    )
    resumed = wait.store.get_request_resume(wait.request_id)
    assert isinstance(resumed, dict) and resumed["continuation_status"] == "resumed"
    operation = wait.store.get_guard_operation_for_approval_request(wait.request_id)
    assert isinstance(operation, dict)
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    evidence = metadata["native_approval_consumed_receipt"]
    assert evidence == completed["nativeApprovalReceipt"]
    assert evidence["phase"] == "consumed" and evidence["request_id"] == wait.request_id
    assert wait.complete()["replayed"] is True and len(wait.calls) == 2
    assert wait.store.get_request_resume(wait.request_id) == resumed


def test_original_outbox_subject_is_bound_before_live_snapshot_emits_second_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.store_review_event_outbox_binding import load_review_oauth_binding

    wait = NativeWait(tmp_path, monkeypatch)
    with wait.store._connect() as connection:
        binding = load_review_oauth_binding(connection, wait.store._guard_source)
        assert binding is not None
        events = connection.execute(
            "select * from guard_review_outbox_events where local_request_id = ? order by request_sequence",
            (wait.request_id,),
        ).fetchall()
        assert [row["request_sequence"] for row in events] == [1, 2]
        assert all(row["binding_status"] == "ready" for row in events)
        assert all(row[key] == value for row in events for key, value in binding.items())
    wait.stage()
    assert wait.complete()["completed"] is True


def test_new_current_consent_cannot_adopt_another_original_oauth_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.guard_oauth_token_support import oauth_binding_access_token

    wait = NativeWait(tmp_path, monkeypatch)
    oauth = wait.store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth, dict)
    oauth["grant_id"] = "different-current-grant"
    device_id, machine_id, workspace_id = oauth["device_id"], oauth["machine_id"], oauth["workspace_id"]
    assert isinstance(device_id, str) and isinstance(machine_id, str) and isinstance(workspace_id, str)
    oauth["access_token"] = oauth_binding_access_token(
        device_id=device_id,
        grant_id=oauth["grant_id"],
        machine_id=machine_id,
        workspace_id=workspace_id,
    )
    wait.store.set_sync_payload("oauth_local_credentials", oauth, datetime.now(timezone.utc).isoformat())
    # This is fresh actual local consent for the new synthetic authenticated
    # subject, so rejection must also retain the original outbox binding.
    enable_exact_cloud_review(wait.store)
    job = wait.job()
    with wait.store._connect() as connection:
        before = list(connection.iterdump())
    with pytest.raises(ValueError, match="native_live_original_subject_changed"):
        stage_native_job(wait.store, job, now=datetime.now(timezone.utc).isoformat())
    with wait.store._connect() as connection:
        assert list(connection.iterdump()) == before
    assert not wait.calls and wait.store.get_request_resume(wait.request_id) is None


def test_concurrent_producer_cannot_replace_first_challenge_or_extend_original_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review

    store, _request, payload = setup(tmp_path)
    enable_exact_cloud_review(store)
    home = tmp_path / "home"
    home.mkdir()
    snapshot = {"generation": 7, "policy_digest": "c" * 64, "runtime_identity": "a" * 64}
    first_entered, second_entered, release_second = (threading.Event() for _ in range(3))
    calls: list[dict[str, Any]] = []
    call_lock = threading.Lock()

    def client(**kwargs: Any) -> bytes:
        wire = json.loads(kwargs["payload"])
        assert wire["operation"] == "approval_challenge_v4"
        with call_lock:
            ordinal = len(calls)
            calls.append(wire)
        if ordinal == 0:
            first_entered.set()
            assert second_entered.wait(3)
        else:
            second_entered.set()
            assert release_second.wait(3)
        challenge = _challenge()
        observed = datetime.now(timezone.utc)
        challenge.update(
            request_id=wire["request"]["envelope"]["request_id"],
            harness="codex",
            nonce=str(ordinal + 1) * 64,
            issued_at_ms=int(observed.timestamp() * 1000),
            expires_at_ms=int((observed + timedelta(seconds=30)).timestamp() * 1000),
        )
        return json.dumps(challenge).encode()

    monkeypatch.setattr(
        native_approval_bridge,
        "_DEFAULT_BRIDGE",
        NativeApprovalBridge(
            client_request=client,
            status_provider=lambda: _status(tmp_path),
            environment_provider=lambda: {},
            clock=time.monotonic,
        ),
    )

    def produce() -> dict[str, object] | None:
        return queue_native_pre_tool_review(
            store,
            harness="codex",
            payload=payload,
            native_result={"reason": "controlled native review"},
            native_receipt=None,
            workspace=tmp_path / "workspace",
            guard_home=store.guard_home,
            home_dir=home,
            policy_snapshot=snapshot,
            deadline=time.monotonic() + 5,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(produce)
        assert first_entered.wait(3)
        second = pool.submit(produce)
        try:
            original = first.result(timeout=4)
            assert isinstance(original, dict)
            request_id = str(original["request_id"])
            with store._connect() as connection:
                before = list(connection.iterdump())
            release_second.set()
            assert second.result(timeout=4) is None
            with store._connect() as connection:
                assert list(connection.iterdump()) == before
            assert store.get_approval_request(request_id) == original
            assert len(calls) == 2
            assert calls[0]["request"]["envelope"]["request_id"] == calls[1]["request"]["envelope"]["request_id"]
            assert len(store.list_guard_operations()) == len(store.list_guard_sessions()) == 1
        finally:
            release_second.set()


@pytest.mark.parametrize("replacement", ["legacy", "changed-nonce"])
def test_non_live_update_cannot_replace_or_downgrade_original_native_challenge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    from tests.guard_exact_cloud_review_support import review_request

    row = wait.store.get_approval_request(wait.request_id)
    assert isinstance(row, dict)
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict)
    changed = copy.deepcopy(envelope)
    if replacement == "legacy":
        del changed["nativeApprovalChallenge"]
    else:
        changed["nativeApprovalChallenge"]["nonce"] = "f" * 64
    incoming = replace(
        review_request(wait.request_id),
        workspace=str(tmp_path / "workspace"),
        action_envelope_json=changed,
    )
    with wait.store._connect() as connection:
        before = list(connection.iterdump())
    with pytest.raises(ValueError, match="native_live_original_challenge_changed"):
        wait.store.add_approval_request(incoming, datetime.now(timezone.utc).isoformat())
    with wait.store._connect() as connection:
        assert list(connection.iterdump()) == before
    assert wait.store.get_approval_request(wait.request_id) == row


def test_identical_native_presentation_preserves_entire_original_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.guard_exact_cloud_review_support import review_request

    wait = NativeWait(tmp_path, monkeypatch)
    row = wait.store.get_approval_request(wait.request_id)
    assert isinstance(row, dict)
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict)
    incoming = replace(
        review_request(wait.request_id),
        workspace=str(tmp_path / "workspace"),
        action_envelope_json=copy.deepcopy(envelope),
        risk_summary="new description must not replace original",
    )
    with wait.store._connect() as connection:
        before = list(connection.iterdump())
    later = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    assert wait.store.add_approval_request(incoming, later) == wait.request_id
    assert wait.store.add_approval_request(incoming, later, live_hook_payload=wait.payload) == wait.request_id
    with wait.store._connect() as connection:
        assert list(connection.iterdump()) == before
    assert wait.store.get_approval_request(wait.request_id) == row


def test_existing_legacy_observation_cannot_be_upgraded_to_new_native_challenge(
    tmp_path: Path,
) -> None:
    store, request, payload = setup(tmp_path)
    request_id = store.add_approval_request(request, datetime.now(timezone.utc).isoformat(), live_hook_payload=payload)
    challenge = _challenge()
    challenge.update(request_id=request_id, harness="codex")
    assert isinstance(request.action_envelope_json, dict)
    incoming = replace(
        request, action_envelope_json={**request.action_envelope_json, "nativeApprovalChallenge": challenge}
    )
    with store._connect() as connection:
        before = list(connection.iterdump())
    with pytest.raises(ValueError, match="native_live_original_challenge_changed"):
        store.add_approval_request(incoming, datetime.now(timezone.utc).isoformat(), live_hook_payload=payload)
    with store._connect() as connection:
        assert list(connection.iterdump()) == before


def test_validated_only_cannot_resolve_or_resume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    wait.consume_allowed = False
    assert wait.complete()["completed"] is False
    assert [call["operation"] for call in wait.calls] == ["approval_validate_v4", "approval_consume_v4"]
    row = wait.store.get_approval_request(wait.request_id)
    assert isinstance(row, dict) and row["status"] == "pending"
    assert wait.store.get_request_resume(wait.request_id) is None


@pytest.mark.parametrize(
    "field", ["claimDigest", "actionDigest", "capabilityId", "grantId", "runtimeId", "machineId", "localRequestVersion"]
)
def test_wrong_native_command_binding_does_not_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    job = wait.job()
    job["serverResolvedBinding"][field] = 999 if field == "localRequestVersion" else "foreign"
    before = wait.store.get_guard_operation_for_approval_request(wait.request_id)
    with pytest.raises(ValueError):
        stage_native_job(wait.store, job, now=datetime.now(timezone.utc).isoformat())
    assert wait.store.get_guard_operation_for_approval_request(wait.request_id) == before
    assert not wait.calls


@pytest.mark.parametrize("field,value", [("resident_epoch", "e" * 64), ("request_digest", "f" * 64)])
def test_wrong_consumed_receipt_cannot_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    wait.receipt_change = (field, value)
    assert wait.complete()["completed"] is False
    row = wait.store.get_approval_request(wait.request_id)
    assert isinstance(row, dict) and row["status"] == "pending"
    assert wait.store.get_request_resume(wait.request_id) is None


def test_changed_live_input_refuses_before_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    wait.payload["tool_input"] = {"command": "different"}
    assert wait.complete()["completed"] is False and not wait.calls


def test_expired_wait_refuses_before_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    with wait.store._connect() as connection:
        connection.execute(
            "update guard_operations set metadata_json=json_set(metadata_json, '$.codex_browser_wait_deadline_at', ?)",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
        )
    assert wait.complete()["completed"] is False and not wait.calls


def test_new_coordinator_cannot_reconstruct_consumed_authority_from_sql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    assert wait.complete()["completed"] is True
    wait.coordinator = NativeLiveCompletion()
    assert wait.complete()["completed"] is False and len(wait.calls) == 2


def test_aborted_sql_commit_preserves_pending_and_only_original_consumed_object_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    with wait.store._connect() as connection:
        connection.execute(
            "create trigger reject_native_effect before insert on guard_continuation_effects "
            "begin select raise(abort, 'controlled_native_effect_failure'); end"
        )
    before = wait.store.get_approval_request(wait.request_id)
    assert wait.complete()["completed"] is False
    assert wait.store.get_approval_request(wait.request_id) == before
    assert wait.store.get_request_resume(wait.request_id) is None
    operation = wait.store.get_guard_operation_for_approval_request(wait.request_id)
    assert isinstance(operation, dict)
    metadata = operation["metadata"]
    assert isinstance(metadata, dict) and "native_approval_consumed_receipt" not in metadata
    assert len(wait.calls) == 2
    with wait.store._connect() as connection:
        connection.execute("drop trigger reject_native_effect")
    assert wait.complete()["completed"] is True and len(wait.calls) == 2


@pytest.mark.parametrize("authority", [None, {"phase": "consumed", "decision": "allow"}])
def test_completion_store_refuses_native_request_without_opaque_consumed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, authority: object
) -> None:
    from codex_plugin_scanner.guard.continuation_runtime import record_live_hook_completion

    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    before = wait.store.get_approval_request(wait.request_id)
    assert (
        record_live_hook_completion(
            wait.store,
            request_id=wait.request_id,
            action="allow",
            now=datetime.now(timezone.utc).isoformat(),
            native_approval=authority,
        )
        is None
    )
    assert wait.store.get_approval_request(wait.request_id) == before
    assert wait.store.get_request_resume(wait.request_id) is None and not wait.calls


@pytest.mark.parametrize(
    "change", ["capability-revoked", "policy", "cancelled-session", "stored-challenge", "outbox-version"]
)
def test_current_authority_or_owner_change_refuses_before_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    wait = NativeWait(tmp_path, monkeypatch)
    wait.stage()
    if change == "capability-revoked":
        from codex_plugin_scanner.guard.runtime.exact_cloud_review import disable_exact_cloud_review

        disable_exact_cloud_review(wait.store)
    elif change == "policy":
        wait.snapshot["generation"] = 8
    else:
        with wait.store._connect() as connection:
            if change == "cancelled-session":
                connection.execute("update guard_sessions set status='cancelled'")
            elif change == "stored-challenge":
                connection.execute(
                    "update approval_requests set action_envelope_json=json_set(action_envelope_json, "
                    "'$.nativeApprovalChallenge.nonce', ?)",
                    ("e" * 64,),
                )
            else:
                connection.execute("update guard_review_outbox_request_sequences set last_sequence=last_sequence+1")
    assert wait.complete()["completed"] is False and not wait.calls
    assert wait.store.get_request_resume(wait.request_id) is None


def test_challenge_expiry_cannot_be_extended_to_longer_hook_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_live_approval_completion as completion

    wait = NativeWait(tmp_path, monkeypatch, challenge_seconds=2)
    wait.stage()
    observed = datetime.now(timezone.utc) + timedelta(seconds=3)

    class ObservedDate(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            del tz
            return observed

    monkeypatch.setattr(completion, "datetime", ObservedDate)
    assert wait.complete()["completed"] is False and not wait.calls
