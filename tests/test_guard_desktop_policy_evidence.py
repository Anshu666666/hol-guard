from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli.desktop_policy_status import policy_application_evidence
from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from tests.test_policy_bundle_generic_acknowledgement import _generic_v2_bundle


@pytest.fixture
def authority():
    bundle = _generic_v2_bundle()
    ack = policy_bundle_acknowledgement_payload(
        device_id="device-alpha", device_name="Synthetic device", policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z", status="applied",
    )
    return bundle, ack


def test_exact_applied_evidence_preserves_policy_revision(authority):
    bundle, ack = authority
    result = policy_application_evidence(bundle, ack, workspace_id=bundle["workspaceId"], device_id="device-alpha")
    assert result["appliedRevision"] == str(bundle["payload"]["metadata"]["revision"])
    assert result["policyBundleVersion"] == str(bundle["bundleVersion"])
    assert result["policyLastAckAt"] == ack["observedAt"]


@pytest.mark.parametrize("field,value", [
    ("deviceId", "device-beta"), ("workspaceId", "another-workspace"),
    ("bundleHash", "sha256:" + "1" * 64), ("bundleVersion", 999),
    ("payloadHash", "sha256:" + "2" * 64), ("status", "received"),
])
def test_unrelated_or_received_ack_never_claims_applied(authority, field, value):
    bundle, ack = authority
    result = policy_application_evidence(
        bundle, {**ack, field: value}, workspace_id=bundle["workspaceId"], device_id="device-alpha",
    )
    assert "appliedRevision" not in result
    assert "policyLastAckAt" not in result


@pytest.mark.parametrize("ack", [None, {}, [], "applied"])
def test_absent_or_malformed_ack_is_unknown(authority, ack):
    bundle, _ = authority
    result = policy_application_evidence(bundle, ack, workspace_id=bundle["workspaceId"], device_id="device-alpha")
    assert "appliedRevision" not in result


def test_managed_controls_need_resident_application_evidence(authority):
    bundle, ack = authority
    bundle["payload"]["x-hol-extension-controls"] = {}
    result = policy_application_evidence(bundle, ack, workspace_id=bundle["workspaceId"], device_id="device-alpha")
    assert "appliedRevision" not in result
    assert "policyLastAckAt" not in result


def test_disabled_canonical_lane_does_not_reuse_historical_applied_ack(authority, monkeypatch):
    from unittest.mock import Mock

    from codex_plugin_scanner.guard.cli import desktop_policy_status as status
    bundle, ack = authority
    store = Mock()
    store.get_cloud_workspace_id.return_value = bundle["workspaceId"]
    store.get_or_create_installation_id.return_value = "installation-alpha"
    store.get_sync_payload.side_effect = lambda key: {
        "runtime_session_summary": {"runtime_device_id": "device-alpha"},
        "policy_bundle_ack": ack,
    }.get(key)
    monkeypatch.setattr(status, "synced_policy_bundle_validation", lambda _: (bundle, None))
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
    result = status.read_policy_application_evidence(store)
    assert "appliedRevision" not in result
    assert result["policyBundleVersion"] == str(bundle["bundleVersion"])
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    expected_revision = str(bundle["payload"]["metadata"]["revision"])
    assert status.read_policy_application_evidence(store)["appliedRevision"] == expected_revision
