"""Rejected updates remain visible even before a device has resident authority."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import _generic_v2_payload, _seed_v2_admission_store, _sync_receipts


@pytest.mark.parametrize(
    "rejection_kind,reason",
    [
        ("signature", "bundle_signature_invalid"),
        ("draft", "inactive_rollout_state"),
    ],
)
def test_first_signed_update_reports_rejection_without_inventing_resident_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rejection_kind: str, reason: str
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(private_key, workspace_id="workspace-alpha")
    payload = _generic_v2_payload(
        rule_id="rule.candidate",
        artifact_id="command:candidate",
        rollout_state="draft" if rejection_kind == "draft" else "enforcing",
    )
    candidate = _signed_bundle(private_key, verification, payload_base=payload)
    if rejection_kind == "signature":
        verifier = candidate["verifier"]
        assert isinstance(verifier, dict)
        verifier["signature"] = "AA=="
    store = _seed_v2_admission_store(tmp_path, verification)
    summary = _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:01:00Z", policy_bundle=candidate)
    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "rejected"
    assert summary["policy_rejection_reason"] == reason
    assert summary["policy_application_status"] == "rejected"
    assert not store.get_sync_payload("policy_bundle")
    assert not store.get_sync_payload("policy_bundle_ack")
    assert store.list_policy_decisions() == []


def test_rejected_refresh_preserves_the_verified_resident_and_its_application_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _signed_bundle(
        private_key,
        verification,
        payload_base=_generic_v2_payload(rule_id="rule.resident", artifact_id="command:resident"),
    )
    store = _seed_v2_admission_store(tmp_path, verification)
    initial = _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:01:00Z", policy_bundle=bundle)
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert initial["policy_application_status"] == "applied"
    invalid = _signed_bundle(
        private_key,
        verification,
        bundle_version=9,
        payload_base=_generic_v2_payload(rule_id="rule.invalid", artifact_id="command:invalid"),
    )
    verifier = invalid["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = "AA=="
    summary = _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:02:00Z", policy_bundle=invalid)
    assert summary["policy_validation_status"] == "rejected"
    assert summary["policy_application_status"] == "retained"
    assert summary["policy_rejection_reason"] == "bundle_signature_invalid"
    assert store.get_sync_payload("policy_bundle") == bundle
    assert store.get_sync_payload("policy_bundle_ack") == acknowledgement
    assert [row["artifact_id"] for row in store.list_policy_decisions()] == ["command:resident"]
