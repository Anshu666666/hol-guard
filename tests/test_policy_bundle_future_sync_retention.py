"""A real future-dated signed sync cannot replace current or last-good authority."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
)
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _sync_signed_v2_bundle,
)


def test_future_signed_sync_preserves_both_durable_policy_bundles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    live = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=8,
        payload_base=_generic_v2_payload(rule_id="retained-rule", artifact_id="command:retained"),
    )
    store = _seed_v2_admission_store(tmp_path, verification_key)
    accepted = _sync_signed_v2_bundle(store, monkeypatch, live, synced_at="2026-07-15T12:01:00Z")
    assert accepted["policy_application_status"] == "applied"
    before_current = deepcopy(store.get_sync_payload("policy_bundle"))
    before_last_good = deepcopy(store.get_sync_payload("policy_bundle_last_good"))
    assert before_current == live
    assert before_last_good == live
    before_rules = {
        (row["artifact_id"], row["action"], row["source"]) for row in store.list_policy_decisions()
    }

    candidate = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=9,
        payload_base=_generic_v2_payload(rule_id="future-rule", artifact_id="command:future"),
    )
    now = datetime.now(timezone.utc)
    candidate["issuedAt"] = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    candidate["expiresAt"] = (now + timedelta(days=2)).isoformat().replace("+00:00", "Z")
    candidate["bundleHash"] = computed_policy_bundle_v2_hash(candidate)
    verifier = candidate["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(
        private_key.sign(
            canonical_policy_bundle_v2_payload(candidate),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")

    rejected = _sync_signed_v2_bundle(store, monkeypatch, candidate, synced_at=now.isoformat())

    assert rejected["receipt_upload_status"] == "success"
    assert rejected["policy_validation_status"] == "rejected"
    assert rejected["policy_rejection_reason"] == "bundle_not_yet_valid"
    assert rejected["policy_application_status"] == "retained"
    assert store.get_sync_payload("policy_bundle") == before_current
    assert store.get_sync_payload("policy_bundle_last_good") == before_last_good
    assert {
        (row["artifact_id"], row["action"], row["source"]) for row in store.list_policy_decisions()
    } == before_rules
    ack = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(ack, dict)
    assert ack["bundleHash"] == live["bundleHash"]
    assert ack["bundleVersion"] == live["bundleVersion"]
    assert ack["bundleHash"] != candidate["bundleHash"]
