"""Native policy authority sync-state mutations invalidate readiness immediately."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(
    "state_key",
    [
        "policy_bundle",
        "policy_bundle_keyring",
        "supply_chain_bundle_keyring",
        "policy_bundle_acceptance_checkpoint",
        "policy_bundle_materialization",
        "managed_policy_bundle_keyring_provenance",
        "guard_review_memory_registry",
        "guard_review_memory_policy_version",
        "guard_review_verification_keyring",
        "policy_integrity",
        "managed_controls_active",
        "managed_controls_revision",
    ],
)
def test_native_authority_sync_write_invalidates_registered_publisher(tmp_path, state_key: str) -> None:
    store = GuardStore(tmp_path / "guard")
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        with publisher._condition:
            publisher._acked = True
            epoch = publisher._epoch
        store.set_sync_payload(state_key, {"synthetic": True}, "2026-09-19T00:00:00Z")
        assert publisher._epoch == epoch + 1
        assert publisher._acked is False
        assert publisher._source_authority_required is True
    finally:
        publisher.close()


def test_unrelated_sync_write_does_not_invalidate_native_publisher(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        with publisher._condition:
            publisher._acked = True
            epoch = publisher._epoch
        store.set_sync_payload("synthetic_unrelated_sync_state", {"count": 1}, "2026-09-19T00:00:00Z")
        assert publisher._epoch == epoch
        assert publisher._acked is True
        assert publisher._source_authority_required is False
    finally:
        publisher.close()


def test_native_authority_sync_delete_invalidates_registered_publisher(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.set_sync_payload("policy_bundle_keyring", {"keys": []}, "2026-09-19T00:00:00Z")
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        with publisher._condition:
            publisher._acked = True
            epoch = publisher._epoch
        assert store.delete_sync_payloads(["policy_bundle_keyring"]) == 1
        assert publisher._epoch == epoch + 1
        assert publisher._acked is False
        assert publisher._source_authority_required is True
    finally:
        publisher.close()
