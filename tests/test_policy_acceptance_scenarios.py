"""Runtime acceptance scenarios for Cloud policy, review, and memory lanes."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.continuation_runtime import (
    continue_request_after_application,
    record_live_hook_completion,
)
from codex_plugin_scanner.guard.continuation_snapshot import canonical_continuation_correlation_id
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.review_contracts import payload_hash_for_decision_memory_bundle
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.runtime.exact_cloud_review_executor import execute_exact_cloud_review_operation
from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import execute_review_policy_memory
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store
from tests.guard_exact_cloud_review_support import remote_approval as signed_remote_approval
from tests.guard_exact_cloud_review_support import review_request
from tests.guard_review_signing_helpers import REVIEW_SIGNING_KEY_ID, review_verification_keys, sign_review_payload
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_runtime import _seed_guard_cloud

_WORKSPACE = "workspace-acceptance"
_NOW = "2026-09-17T12:00:00+00:00"
_CANARY = "codex:project:acceptance-canary"
_MEMORY_ARTIFACT = "plugin:hol/acceptance-memory"


class _JsonResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> _JsonResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class _StubCloud:
    def __init__(self) -> None:
        self.bundle: dict[str, object] | None = None
        self.online = True
        self.interrupt_remaining = 0
        self.acks: list[dict[str, object]] = []

    def urlopen(self, request: object, timeout: object = None) -> _JsonResponse:
        if not self.online or self.interrupt_remaining > 0:
            if self.interrupt_remaining > 0:
                self.interrupt_remaining -= 1
            raise urllib.error.URLError("acceptance cloud offline")
        payload = _request_json(request)
        context = payload.get("syncContext")
        if isinstance(context, dict):
            ack = context.get("policyBundleAcknowledgement") or context.get("policyBundleAcknowledgementV2")
            if isinstance(ack, dict):
                self.acks.append(ack)
        return _JsonResponse(
            {
                "syncedAt": "2026-09-17T12:00:01Z",
                "receiptsStored": 0,
                "policyBundle": self.bundle or {},
            }
        )


def _request_json(request: object) -> dict[str, object]:
    data = getattr(request, "data", None)
    if not data:
        return {}
    payload = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
    return payload if isinstance(payload, dict) else {}


def _install_sync_stubs(monkeypatch: pytest.MonkeyPatch, cloud: _StubCloud) -> None:
    stub_authenticated_urlopen(monkeypatch, cloud.urlopen)
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(
        runner,
        "sync_guard_events",
        lambda _store, auth_context=None: {"status": "ok", "uploaded": 0},
    )


def _device(tmp_path: Path, name: str) -> GuardStore:
    store = GuardStore(tmp_path / name)
    _seed_guard_cloud(store, workspace_id=_WORKSPACE)
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=_WORKSPACE),
        _NOW,
    )
    return store


def _device_id(store: GuardStore) -> str:
    return str(store.get_device_metadata()["installation_id"])


def _signed_bundle(
    *,
    version: str,
    device_ids: list[str],
    artifact_id: str,
    action: str,
    issued_at: str = "2026-07-15T12:00:00Z",
) -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": version,
            "bundleHash": "",
            "issuedAt": issued_at,
            "expiresAt": None,
            "verifier": {"algorithm": "rsa-pss-sha256", "keyId": "test-only-placeholder", "signature": None},
            "rolloutState": "enforcing",
            "workspaceId": _WORKSPACE,
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "allow",
                "unknownPublisherAction": "allow",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "allow",
                "subprocessAction": "allow",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [
                {
                    "ruleId": f"acceptance-{version}",
                    "action": action,
                    "reason": f"Approved revision {version}.",
                    "artifactId": artifact_id,
                    "scope": {
                        "agents": [],
                        "devices": device_ids,
                        "ecosystems": [],
                        "environments": [],
                        "harnesses": ["codex"],
                        "locations": [],
                    },
                }
            ],
            "cloudExceptions": [],
            "acknowledgements": [],
        },
        workspace_id=_WORKSPACE,
    )


def _sync(store: GuardStore) -> dict[str, object]:
    return runner.sync_receipts(store)


def _canary(store: GuardStore, artifact_id: str = _CANARY, artifact_hash: str | None = None) -> str | None:
    return store.resolve_policy(
        "codex",
        artifact_id,
        artifact_hash=artifact_hash,
        consume_one_shot=False,
    )


def _sources(store: GuardStore) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for row in store.list_policy_decisions():
        grouped.setdefault(str(row["source"]), set()).add(str(row.get("artifact_id")))
    return grouped


def test_hgp_191_two_device_approved_policy_adoption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    alpha = _device(tmp_path, "alpha")
    beta = _device(tmp_path, "beta")
    control = _device(tmp_path, "control")
    target_ids = [_device_id(alpha), _device_id(beta)]
    cloud = _StubCloud()
    cloud.bundle = _signed_bundle(version="policy-2026-09-17.1", device_ids=target_ids, artifact_id=_CANARY, action="block")
    _install_sync_stubs(monkeypatch, cloud)

    alpha_sync = _sync(alpha)
    beta_sync = _sync(beta)
    control_sync = _sync(control)

    publication = cloud.bundle["bundleHash"]
    for store, result in ((alpha, alpha_sync), (beta, beta_sync)):
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict)
        assert ack["bundleHash"] == publication
        assert ack["bundleVersion"] == "policy-2026-09-17.1"
        assert ack["deviceId"] == _device_id(store)
        assert ack["status"] == "synced"
        assert _canary(store) == "block"
        assert result["receipts_stored"] == 0
    control_ack = control.get_sync_payload("policy_bundle_ack")
    assert isinstance(control_ack, dict)
    assert control_ack["deviceId"] == _device_id(control)
    assert _canary(control) is None
    assert control.get_sync_payload("policy_bundle")["bundleHash"] == publication


def test_hgp_192_offline_reconnect_newest_revision_convergence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _device(tmp_path, "offline-target")
    device_id = _device_id(store)
    cloud = _StubCloud()
    first = _signed_bundle(
        version="policy-2026-09-17.1",
        device_ids=[device_id],
        artifact_id=_CANARY,
        action="block",
        issued_at="2026-07-15T12:00:00Z",
    )
    newest = _signed_bundle(
        version="policy-2026-09-17.3",
        device_ids=[device_id],
        artifact_id=_CANARY,
        action="allow",
        issued_at="2026-07-16T12:00:00Z",
    )
    cloud.bundle = first
    _install_sync_stubs(monkeypatch, cloud)
    _sync(store)
    applied = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(applied, dict)
    assert applied["bundleVersion"] == "policy-2026-09-17.1"
    assert _canary(store) == "block"

    cloud.online = False
    cloud.bundle = newest
    with pytest.raises(RuntimeError):
        _sync(store)
    pending = store.get_sync_payload("policy_bundle_ack")
    assert pending == applied
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == "policy-2026-09-17.1"

    cloud.online = True
    cloud.interrupt_remaining = 1
    with pytest.raises(RuntimeError):
        _sync(store)
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == "policy-2026-09-17.1"

    _sync(store)
    latest = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(latest, dict)
    assert latest["bundleVersion"] == "policy-2026-09-17.3"
    assert latest["bundleHash"] == newest["bundleHash"]
    assert latest["deviceId"] == device_id
    assert _canary(store) == "allow"


def _seed_waiting_codex(store: GuardStore, request_id: str) -> dict[str, object]:
    add_review_request(store, review_request(request_id, harness="codex"))
    request = store.get_approval_request(request_id)
    assert request is not None
    identity = current_process_identity()
    assert identity is not None
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title="codex hook",
        client_version="1.0.0",
        workspace="/workspace/repo",
        capabilities=["approval-resolution"],
        now=_NOW,
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token=None,
        metadata={
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-09-17T12:01:00+00:00",
            "codex_browser_wait_process": identity,
            "hook_event_name": "PreToolUse",
            "correlationId": "gcr_11111111-2222-4333-8444-555555555555",
        },
        now=_NOW,
    )
    refreshed = store.get_approval_request(request_id)
    assert refreshed is not None
    refreshed["_operation_metadata"] = {
        "correlationId": "gcr_11111111-2222-4333-8444-555555555555",
    }
    return refreshed


def _resume(*, store: GuardStore, request_row: dict[str, object], action: str, now: str, **_kwargs: object):
    waiting = continue_request_after_application(
        store,
        request_row=request_row,
        action=action,
        now=now,
        headless=False,
    )
    if waiting.get("capability") != "suspended-response":
        return waiting
    completed = record_live_hook_completion(
        store,
        request_id=str(request_row["request_id"]),
        action="allow",
        now="2026-09-17T12:00:01+00:00",
    )
    return dict(completed) if isinstance(completed, dict) else waiting


def test_hgp_193_review_to_continuation_without_persistent_grant(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    first = _seed_waiting_codex(store, "exact-first")
    enable_exact_cloud_review(store)
    first_approval = signed_remote_approval(store, "exact-first", receipt_id="receipt-first")
    applied = execute_exact_cloud_review_operation(
        payload={"remoteApproval": first_approval, "harness": "codex"},
        store=store,
        generated_at=datetime.now(timezone.utc).isoformat(),
        resume_after_approval=_resume,
    )["data"]
    correlation = canonical_continuation_correlation_id(
        request_id="exact-first",
        request_row=first,
        operation_metadata=first["_operation_metadata"]
        if isinstance(first.get("_operation_metadata"), dict)
        else {},
    )
    assert applied["localRequestId"] == "exact-first"
    assert applied["receiptId"] == "receipt-first"
    assert applied["applicationStatus"] == "applied"
    assert applied["continuationStatus"] in {"resumed", "waiting", "manual_retry_required"}
    assert correlation.startswith("gcr_")
    assert store.get_approval_request("exact-first")["status"] == "resolved"
    assert all(row.get("source") != "cloud-signed-memory" for row in store.list_policy_decisions())

    second = _seed_waiting_codex(store, "exact-second")
    queued = signed_remote_approval(store, "exact-second", receipt_id="receipt-second")
    assert store.get_approval_request("exact-second")["status"] == "pending"
    later = execute_exact_cloud_review_operation(
        payload={"remoteApproval": queued, "harness": "codex"},
        store=store,
        generated_at=datetime.now(timezone.utc).isoformat(),
        resume_after_approval=_resume,
    )["data"]
    assert later["localRequestId"] == "exact-second"
    assert store.get_approval_request("exact-second")["status"] == "resolved"
    assert store.get_sync_payload("guard_review_memory_registry") is None
    assert second["request_id"] == "exact-second"


def _memory_bundle(store: GuardStore, *, version: str, artifact_id: str, revocations: list[str] | None = None) -> dict[str, object]:
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    bundle: dict[str, object] = {
        "blastRadius": {"artifactCount": 1, "machineCount": 1, "workspaceCount": 1},
        "bundleVersion": version,
        "contractVersion": "guard.decision-memory-bundle.v1",
        "expiresAt": (issued_at + timedelta(days=30)).isoformat(),
        "issuedAt": issued_at.isoformat(),
        "issuerKeyId": REVIEW_SIGNING_KEY_ID,
        "memoryRules": []
        if revocations
        else [
            {
                "action": "allow",
                "approvalId": "memory-approval-1",
                "artifactHash": "b" * 64,
                "artifactId": artifact_id,
                "capabilityCategory": "tool-call",
                "expiresAt": (issued_at + timedelta(days=30)).isoformat(),
                "harnessId": "codex",
                "projectIdentity": "project:/workspace/repo",
                "reason": "Remembered in cloud.",
                "recommendedScope": "artifact",
                "riskCategory": "medium",
                "ruleId": "review-memory:acceptance-1",
                "scope": "artifact",
                "sourceReceiptIds": ["receipt-memory-1"],
                "target": {
                    "machineIds": [str(store.get_device_metadata()["installation_id"])],
                    "workspaceIds": [_WORKSPACE],
                },
            }
        ],
        "policyVersion": version,
        "revocations": revocations or [],
        "scope": "workspace",
        "scopeEvidence": {
            "approvalIds": ["memory-approval-1"],
            "sourceReceiptHashes": ["c" * 64],
            "sourceReceiptIds": ["receipt-memory-1"],
        },
        "verificationKeys": review_verification_keys(workspace_id=None, purpose="unscoped"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "workspaceId": _WORKSPACE,
    }
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = payload_hash
    bundle["payloadHash"] = payload_hash
    bundle["signature"] = sign_review_payload(bundle)
    return bundle


def _enable_memory_keys(store: GuardStore) -> None:
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=_WORKSPACE),
        _NOW,
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        review_verification_keys(workspace_id=None, purpose="unscoped"),
        _NOW,
    )


def test_hgp_194_alternating_policy_and_memory_durability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    alpha = _device(tmp_path, "alpha")
    beta = _device(tmp_path, "beta")
    target_ids = [_device_id(alpha), _device_id(beta)]
    cloud = _StubCloud()
    cloud.bundle = _signed_bundle(version="policy-2026-09-17.1", device_ids=target_ids, artifact_id=_CANARY, action="block")
    _install_sync_stubs(monkeypatch, cloud)
    for store in (alpha, beta):
        _enable_memory_keys(store)
        _sync(store)
        result = execute_review_policy_memory(
            {"decisionMemoryBundle": _memory_bundle(store, version="policy-memory.1", artifact_id=_MEMORY_ARTIFACT)},
            store=store,
            generated_at=_NOW,
        )
        assert result["status"] == "accepted"
        sources = _sources(store)
        assert _CANARY in sources.get("policy-bundle", set())
        assert _MEMORY_ARTIFACT in sources.get("cloud-signed-memory", set())
        assert _canary(store) == "block"
        assert _canary(store, _MEMORY_ARTIFACT, "b" * 64) == "allow"

    cloud.bundle = _signed_bundle(
        version="policy-2026-09-17.2",
        device_ids=target_ids,
        artifact_id=_CANARY,
        action="block",
        issued_at="2026-07-16T12:00:00Z",
    )
    for store in (alpha, beta):
        _sync(store)
        sources = _sources(store)
        assert _CANARY in sources.get("policy-bundle", set())
        assert _MEMORY_ARTIFACT in sources.get("cloud-signed-memory", set())
        revoked = execute_review_policy_memory(
            {
                "decisionMemoryBundle": _memory_bundle(
                    store,
                    version="policy-memory.2",
                    artifact_id=_MEMORY_ARTIFACT,
                    revocations=["review-memory:acceptance-1"],
                )
            },
            store=store,
            generated_at="2026-09-17T12:05:00+00:00",
        )
        assert revoked["status"] == "accepted"
        sources = _sources(store)
        assert _CANARY in sources.get("policy-bundle", set())
        assert _MEMORY_ARTIFACT not in sources.get("cloud-signed-memory", set())

    reopened_alpha = GuardStore(alpha.guard_home)
    reopened_beta = GuardStore(beta.guard_home)
    for store in (reopened_alpha, reopened_beta):
        _sync(store)
        sources = _sources(store)
        assert _CANARY in sources.get("policy-bundle", set())
        assert sources.get("cloud-signed-memory", set()) == set()
        assert _canary(store) == "block"
        assert store.get_sync_payload("guard_review_memory_registry") == []
