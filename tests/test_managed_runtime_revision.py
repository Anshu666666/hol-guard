"""Independent authenticated local and managed runtime authority observations."""

from __future__ import annotations

import pytest
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_delivery_daemon import _enable

from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    build_managed_controls_runtime_posture,
)
from codex_plugin_scanner.guard.runtime.managed_controls_sync import (
    managed_controls_runtime_sync_posture,
)
from tests.support.managed_runtime_revision import (
    advance_local_authority,
    applied_runtime_fixture,
)


@pytest.mark.parametrize("local_updates", [0, 1, 2])
def test_signed_apply_projects_each_revision_without_changing_delivery_identity(
    tmp_path, monkeypatch, local_updates
):
    fixture = applied_runtime_fixture(tmp_path, monkeypatch, local_updates=local_updates)
    runtime, receipts = fixture.capture_full_sync(tmp_path)
    ack = fixture.acknowledgement
    assert receipts["receipts"] == []
    assert receipts["syncContext"]["policyBundleAcknowledgementV2"] == ack
    assert runtime["deviceId"] == ack["deviceId"]
    assert runtime["sessionId"] == ack["runtimeSessionId"]
    assert runtime["extensionCatalogDigest"] == ack["catalogDigest"]
    assert runtime["effectiveProjectionDigest"] == ack["appliedEffectiveProjectionDigest"]
    assert runtime["extensionAuthorityRevision"] == ack["extensionAuthorityRevision"] == local_updates
    assert runtime["managedExtensionAuthorityRevision"] == ack["appliedExtensionAuthorityRevision"] == 1
    assert fixture.store.get_sync_payload("runtime_session_summary")["managedExtensionAuthorityRevision"] == 1


def test_restart_recovers_the_authenticated_managed_revision(tmp_path, monkeypatch):
    fixture = applied_runtime_fixture(tmp_path, monkeypatch, local_updates=2)
    fixture.store = GuardStore(fixture.store.guard_home)
    runtime, receipts = fixture.capture_full_sync(tmp_path)
    assert runtime["extensionAuthorityRevision"] == 2
    assert runtime["managedExtensionAuthorityRevision"] == 1
    assert receipts["syncContext"]["policyBundleAcknowledgementV2"] == fixture.acknowledgement


def test_local_change_does_not_advance_the_managed_counter(tmp_path, monkeypatch):
    fixture = applied_runtime_fixture(tmp_path, monkeypatch)
    advance_local_authority(fixture.store, 1)
    runtime, _receipts = fixture.capture_full_sync(tmp_path)
    assert runtime["extensionAuthorityRevision"] == 1
    assert fixture.acknowledgement["extensionAuthorityRevision"] == 0
    assert (
        runtime["managedExtensionAuthorityRevision"]
        == fixture.acknowledgement["appliedExtensionAuthorityRevision"]
        == 1
    )
    assert runtime["effectiveProjectionDigest"] != fixture.acknowledgement["appliedEffectiveProjectionDigest"]


def test_managed_clear_advances_only_the_authenticated_managed_counter(tmp_path, monkeypatch):
    fixture = applied_runtime_fixture(tmp_path, monkeypatch)
    fixture.store.clear_policy_bundle_authority("2026-09-17T12:00:02Z", policy_bundle_last_error={})
    runtime, receipts = fixture.capture_full_sync(tmp_path)
    assert runtime["extensionAuthorityRevision"] == fixture.acknowledgement["extensionAuthorityRevision"] == 0
    assert runtime["managedExtensionAuthorityRevision"] == 2
    assert fixture.acknowledgement["appliedExtensionAuthorityRevision"] == 1
    assert "policyBundleAcknowledgementV2" not in receipts["syncContext"]


def test_tampered_managed_state_removes_the_observation_and_stale_summary(tmp_path, monkeypatch):
    fixture = applied_runtime_fixture(tmp_path, monkeypatch)
    fixture.capture_full_sync(tmp_path)
    fixture.store.set_sync_payload(
        MANAGED_CONTROLS_REVISION_STATE_KEY, {"invalid": True}, "2026-09-17T12:00:02Z"
    )
    runtime, _receipts = fixture.capture_full_sync(tmp_path)
    assert "managedExtensionAuthorityRevision" not in runtime
    assert runtime["extensionAuthorityRevision"] is None
    assert runtime["effectiveProjectionDigest"] is None
    assert "managedExtensionAuthorityRevision" not in fixture.store.get_sync_payload("runtime_session_summary")


def test_unenrolled_authority_is_unknown_instead_of_managed_revision_zero(tmp_path, monkeypatch):
    _enable(monkeypatch)
    posture = managed_controls_runtime_sync_posture(
        GuardStore(tmp_path / "guard-home"), generated_at="2026-09-17T12:00:00Z"
    )
    assert "managedExtensionAuthorityRevision" not in posture
    assert posture["extensionAuthorityRevision"] is None


def test_older_projection_calls_do_not_invent_a_managed_revision():
    posture = build_managed_controls_runtime_posture(catalog_digest="a" * 64)
    assert "managedExtensionAuthorityRevision" not in posture


@pytest.mark.parametrize("invalid", [-1, True, 1.5, 2**53])
def test_wire_projection_rejects_invalid_managed_observation(invalid):
    with pytest.raises(ValueError):
        build_managed_controls_runtime_posture(
            catalog_digest="a" * 64, managed_extension_authority_revision=invalid
        )


def test_protected_baseline_advertises_observed_managed_revision_zero(tmp_path, monkeypatch):
    _enable(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    store._bootstrap_extension_control_authority(BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest, key=None)
    posture = managed_controls_runtime_sync_posture(store, generated_at="2026-09-17T12:00:00Z")
    assert posture["extensionAuthorityRevision"] == 0
    assert posture["managedExtensionAuthorityRevision"] == 0
