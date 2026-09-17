"""HGP-154: native publication is a separate visible stage from durable apply."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_activation_visibility import policy_activation_visibility
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle


class _PendingPublisher:
    def is_ready(self) -> bool:
        return False

    def current_snapshot_binding(self) -> dict[str, object] | None:
        return None

    @property
    def last_error(self) -> str | None:
        return "native_policy_snapshot_publish_failed"


class _ReadyPublisher:
    def is_ready(self) -> bool:
        return True

    def current_snapshot_binding(self) -> dict[str, object] | None:
        return {"policy_digest": "sha256:resident", "generation": 1}

    @property
    def last_error(self) -> str | None:
        return None


def test_publication_delay_cannot_claim_deployment_complete(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _signed_bundle(rollout_state="enforcing")
    applied = _activate_bundle(store, bundle, "2026-07-18T00:00:00Z")
    assert applied is not None
    pending = policy_activation_visibility(
        desired_revision=str(bundle["bundleVersion"]),
        desired_digest=str(bundle["bundleHash"]),
        durable_bundle=store.get_sync_payload("policy_bundle_last_good"),
        acknowledgement=store.get_sync_payload("policy_bundle_ack"),
        publisher=_PendingPublisher(),
    )
    assert pending["durable_revision"] == bundle["bundleVersion"]
    assert pending["publication_pending"] is True
    assert pending["deployment_complete"] is False
    assert pending["applied"] is False
    ready = policy_activation_visibility(
        desired_revision=str(bundle["bundleVersion"]),
        durable_bundle=store.get_sync_payload("policy_bundle_last_good"),
        acknowledgement=store.get_sync_payload("policy_bundle_ack"),
        publisher=_ReadyPublisher(),
    )
    assert ready["deployment_complete"] is True
    assert ready["resident_ready"] is True


def test_publisher_last_error_is_not_ready(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    try:
        assert publisher.is_ready() is False
        status = policy_activation_visibility(
            desired_revision="rev-1",
            durable_bundle={"bundleVersion": "rev-1"},
            acknowledgement={"status": "synced", "bundleVersion": "rev-1"},
            publisher=publisher,
        )
        assert status["publication_pending"] is True
        assert status["deployment_complete"] is False
    finally:
        publisher.close()
