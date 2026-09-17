"""Real signed-apply fixtures for independent runtime authority revisions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_headless_daemon_api import _seed_guard_cloud
from tests.test_policy_bundle_delivery_daemon import _enable, _fixture
from tests.test_policy_bundle_v2_runtime_admission import _SyncResponse

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import MANAGED_CONTROLS_RUNTIME_CAPABILITIES


def advance_local_authority(store: GuardStore, count: int) -> None:
    if count == 0:
        return
    password = "synthetic-revision-test-only"
    update_settings(store.guard_home, {
        "enabled": True,
        "new_password": password,
        "confirm_password": password,
        "cooldown_seconds": 0,
    })
    authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    for revision in range(authority.revision, authority.revision + count):
        mutation = ExtensionControlMutation(
            previous_revision=revision,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(),
            actor_id="synthetic-local-admin",
            idempotency_key=f"local-revision-{revision}",
            nonce=f"local-nonce-{revision}",
        )
        proof = issue_extension_control_proof(
            store.guard_home,
            mutation,
            approval_gate_input=ApprovalGateInput(password=password),
            session_nonce=f"local-session-{revision}",
        )
        committed = store.commit_extension_control_layers(
            (),
            catalog_digest=mutation.catalog_digest,
            actor_id=mutation.actor_id,
            expected_revision=revision,
            idempotency_key=mutation.idempotency_key,
            nonce=mutation.nonce,
            proof=proof,
        )
        assert committed.revision == revision + 1
        composed = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        assert composed.managed_revision == authority.managed_revision


@dataclass
class AppliedRuntimeFixture:
    store: GuardStore
    acknowledgement: dict
    requests: list[tuple[str, dict]]
    auth: dict
    response: dict

    def capture_full_sync(self, workspace: Path) -> tuple[dict, dict]:
        self.response.clear()
        self.response.update({"syncedAt": "2026-09-17T12:00:02Z", "receiptsStored": 0})
        self.requests.clear()
        authority = self.store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        runtime = ExtensionControlRuntime(authority)
        runner.sync_local_guard_cloud_proof(
            self.store,
            auth_context=self.auth,
            home_dir=workspace,
            workspace_dir=workspace,
            managed_controls_publish=runtime.publish_after_commit,
        )
        assert [kind for kind, _ in self.requests] == ["runtime", "receipts"]
        return self.requests[0][1]["session"], self.requests[1][1]


def applied_runtime_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    local_updates: int = 0,
) -> AppliedRuntimeFixture:
    _enable(monkeypatch)
    requests: list[tuple[str, dict]] = []
    response = {"syncedAt": "2026-09-17T12:00:00Z", "receiptsStored": 0}

    def upload(request, timeout):
        body = json.loads(request.data)
        if request.full_url.endswith("/runtime/sessions/sync"):
            requests.append(("runtime", body))
            return _SyncResponse({
                "syncedAt": "2026-09-17T12:00:01Z",
                "items": [{"sessionId": body["session"]["sessionId"], "deviceId": body["session"]["deviceId"]}],
            })
        assert request.full_url.endswith("/receipts/sync")
        requests.append(("receipts", body))
        return _SyncResponse(dict(response))

    stub_authenticated_urlopen(monkeypatch, upload)
    monkeypatch.setattr(runner, "_safe_private_ip", lambda: None)
    monkeypatch.setattr(runner, "_safe_private_ipv6", lambda: None)
    monkeypatch.setattr(runner, "_safe_hostname", lambda: "synthetic-runtime")
    monkeypatch.setattr(runner, "sync_pain_signals", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(runner, "sync_guard_events", lambda *_args, **_kwargs: {"events": 0, "accepted": 0})
    store = GuardStore(tmp_path / "guard-home")
    store.set_device_label("Synthetic revision fixture", "2026-09-17T12:00:00Z")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    bundle, delivery = _fixture(store)
    advance_local_authority(store, local_updates)
    authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    runtime = ExtensionControlRuntime(authority)
    auth = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "synthetic-token",
        "dpop_key_material": None,
    }
    runner.sync_runtime_session(
        store,
        session=runner._local_guard_runtime_session(
            device_id=store.get_or_create_installation_id(),
            workspace_id=store.get_cloud_workspace_id(),
            store=store,
        ),
        auth_context=auth,
    )
    before = requests[-1][1]["session"]
    assert before["extensionAuthorityRevision"] == local_updates
    delivery.update({
        "runtimeSessionId": before["sessionId"],
        "catalogDigest": before["extensionCatalogDigest"],
        "extensionAuthorityRevision": before["extensionAuthorityRevision"],
        "effectiveProjectionDigest": before["effectiveProjectionDigest"],
    })
    response.update({
        "policyBundle": bundle,
        "policyBundleDelivery": delivery,
        "managedControlsCapabilities": sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
    })
    runner.sync_receipts(store, auth_context=auth, managed_controls_publish=runtime.publish_after_commit)
    assert store.get_sync_payload("policy_bundle") == bundle
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert acknowledgement["status"] == "applied"
    assert acknowledgement["deliveryId"] == delivery["deliveryId"]
    artifact = GuardArtifact(
        artifact_id="managed-revision-evaluation", name="Managed revision evaluation",
        harness="codex", artifact_type="tool-action", source_scope="test", config_path="/test",
        metadata={"artifactHash": "sha256:" + "a" * 64},
    )
    detection = HarnessDetection(harness="codex", installed=True, command_available=True,
        config_paths=("/test",), artifacts=(artifact,))
    runner.evaluate_detection(
        detection, store, GuardConfig(guard_home=store.guard_home, workspace=tmp_path), persist=False
    )
    assert store.list_receipts() == []
    return AppliedRuntimeFixture(store, acknowledgement, requests, auth, response)
