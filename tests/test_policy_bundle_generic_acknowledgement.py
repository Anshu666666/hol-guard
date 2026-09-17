"""Generic generic-policy acknowledgements and empty-ack applied-status regressions."""

from __future__ import annotations

from codex_plugin_scanner.guard.policy_bundle_delivery import (
    effective_policy_bundle_acknowledgement,
    policy_bundle_acknowledgement_payload,
)
from codex_plugin_scanner.guard.policy_bundle_generic_ack import generic_policy_bundle_acknowledgement
from codex_plugin_scanner.guard.policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from cryptography.hazmat.primitives.asymmetric import rsa


def _generic_v2_bundle() -> dict[str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    return _signed_bundle(private_key, verification_key)


def test_generic_v2_ack_is_unverified_until_the_chosen_lane_applies() -> None:
    bundle = _generic_v2_bundle()
    unverified = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        status="validated",
    )
    applied = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        status="applied",
    )

    assert unverified["status"] == "received"
    assert unverified["errorCode"] == "unverified_generic_application"
    assert unverified["status"] != "applied"
    assert applied["status"] == "applied"
    assert applied["deviceId"] == "device-alpha"
    assert applied["payloadHash"] == bundle["payloadHash"]
    assert applied["bundleHash"] == bundle["bundleHash"]
    assert applied["appliedEffectiveProjectionDigest"] == bundle["payloadHash"]


def test_empty_acknowledgement_never_counts_as_applied() -> None:
    empty = generic_policy_bundle_acknowledgement(
        device_id="device-alpha",
        policy_bundle={"contractVersion": POLICY_BUNDLE_V2_CONTRACT},
        synced_at="2026-07-15T12:01:00Z",
        applied=True,
    )
    assert empty == {}
    assert empty.get("status") != "applied"


def test_received_generic_ack_can_become_applied_after_the_lane_commits() -> None:
    bundle = _generic_v2_bundle()
    received = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        status="validated",
    )
    applied = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:02:00Z",
        status="applied",
        previous=received,
    )
    assert received["status"] == "received"
    assert applied["status"] == "applied"
    assert applied["sequence"] == received["sequence"] + 1
    assert applied["payloadHash"] == received["payloadHash"]


def test_retained_generic_bundle_does_not_reuse_extension_delivery_as_proof() -> None:
    bundle = _generic_v2_bundle()
    ack = effective_policy_bundle_acknowledgement(
        device_id="device-alpha",
        device_name="Guard",
        effective_policy_bundle=bundle,
        validated_policy_bundle=bundle,
        validated_delivery=None,
        stored_acknowledgement=None,
        synced_at="2026-07-15T12:01:00Z",
        applied=False,
    )
    assert ack["status"] != "applied"
    assert "extension-controls" not in str(ack.get("catalogDigest"))
