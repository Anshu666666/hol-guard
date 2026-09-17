"""Signed canonical policy bundle v2 contract tests."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_is_enforceable
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_verification_key_from_public_key,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CANONICALIZATION,
    POLICY_BUNDLE_V2_CONTRACT,
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
    validate_policy_bundle_v2_transition,
    validated_policy_bundle_v2_acknowledgement,
    validated_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.policy_document_yaml import load_policy_document
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import cached_policy_bundle_validation
from tests.support.network import stub_authenticated_urlopen

_FIXTURE = Path(__file__).parents[1] / "spec" / "guard-policy" / "v1alpha1" / "fixtures" / "valid" / "basic.yaml"


def _verification_key(
    private_key: rsa.RSAPrivateKey,
    *,
    key_id: str = "policy-v2-key-1",
    workspace_id: str | None = None,
) -> PolicyBundleVerificationKey:
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return policy_bundle_verification_key_from_public_key(
        key_id=key_id,
        public_key_pem=public_key_pem,
        workspace_id=workspace_id,
    )


def _signed_bundle(
    private_key: rsa.RSAPrivateKey,
    verification_key: PolicyBundleVerificationKey,
    *,
    bundle_version: int = 8,
    rollback: dict[str, object] | None = None,
    payload_base: dict[str, object] | None = None,
    payload_extensions: dict[str, object] | None = None,
    rollout_state: str | None = None,
) -> dict[str, object]:
    document = load_policy_document(_FIXTURE)
    payload = dict(payload_base) if payload_base is not None else document.to_mapping()
    if rollout_state is not None:
        spec = payload.get("spec")
        if isinstance(spec, dict):
            spec = dict(spec)
            spec["rolloutState"] = rollout_state
            payload["spec"] = spec
    if payload_extensions is not None:
        payload.update(payload_extensions)
    bundle: dict[str, object] = {
        "envelopeVersion": 2,
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "bundleVersion": bundle_version,
        "bundleHash": "",
        "payloadHash": "",
        "issuedAt": "2026-07-15T12:00:00Z",
        "expiresAt": "2030-07-15T12:00:00Z",
        "workspaceId": "workspace-alpha",
        "canonicalization": POLICY_BUNDLE_V2_CANONICALIZATION,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": verification_key.key_id,
            "keyFingerprint": verification_key.fingerprint_sha256,
            "publicKeyPem": verification_key.public_key_pem,
            "signature": "",
        },
        "payload": payload,
        "rollback": rollback,
    }
    bundle["payloadHash"] = payload_hash_for_policy_bundle_v2(bundle)
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    signature = private_key.sign(
        canonical_policy_bundle_v2_payload(bundle),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(signature).decode("ascii")
    return bundle


def _acknowledgement(
    *,
    sequence: int,
    status: str,
) -> dict[str, object]:
    return {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "workspaceId": "workspace-alpha",
        "deviceId": "device-alpha",
        "deliveryId": "00000000-0000-4000-8000-000000000001",
        "runtimeSessionId": "runtime-alpha",
        "bundleId": "bundle-alpha",
        "bundleVersion": 8,
        "bundleHash": "sha256:" + "a" * 64,
        "policyRevision": 8,
        "extensionAuthorityRevision": 8,
        "catalogDigest": "b" * 64,
        "effectiveProjectionDigest": "sha256:" + "c" * 64,
        "payloadHash": "sha256:" + "d" * 64,
        "extensionProjectionDigest": "sha256:" + "e" * 64,
        "appliedExtensionAuthorityRevision": 9,
        "appliedEffectiveProjectionDigest": "sha256:" + "f" * 64,
        "lastKnownGoodBundleHash": None,
        "sequence": sequence,
        "status": status,
        "observedAt": "2026-07-15T12:01:00Z",
    }


def test_shared_sync_validator_dispatches_v2_without_changing_v1_parser() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)

    validated, reason, persisted_keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring={"keys": [verification_key.to_dict()]},
    )

    assert reason is None
    assert validated == bundle
    assert persisted_keys == (verification_key,)


def test_shared_sync_validator_rejects_sync_only_v2_signing_key() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)

    validated, reason, persisted_keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring={},
        sync_payload={
            "policyBundleVerificationKeys": [verification_key.to_dict()],
        },
    )

    assert validated is None
    assert reason == "untrusted_signing_key"
    assert persisted_keys == ()


def test_v2_bundle_rejects_payload_tampering_before_apply() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    metadata = cast(dict[str, object], payload["metadata"])
    assert isinstance(metadata, dict)
    metadata["revision"] = 99

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "payload_hash_mismatch"


def test_v2_bundle_rejects_invalid_signature() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    verifier = cast(dict[str, object], bundle["verifier"])
    verifier["signature"] = "AA=="

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "bundle_signature_invalid"


def test_v2_bundle_rejects_non_contract_pss_salt_length() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    verifier = cast(dict[str, object], bundle["verifier"])
    signature = private_key.sign(
        canonical_policy_bundle_v2_payload(bundle),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=8),
        hashes.SHA256(),
    )
    verifier["signature"] = base64.b64encode(signature).decode("ascii")

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "bundle_signature_invalid"


def test_v2_bundle_rejects_expired_envelope() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2031, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "bundle_expired"


def test_v2_bundle_rejects_whitespace_padded_identifiers() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    bundle["workspaceId"] = " workspace-alpha "

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "invalid_workspace_id"


def test_v2_bundle_rejects_unsigned_unknown_fields() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    bundle["unexpected"] = "unsigned"

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "unknown_field"


def test_v2_bundle_rejects_unanchored_rotated_key() -> None:
    first_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first_key = _verification_key(first_private_key)
    rotated_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated_key = _verification_key(rotated_private_key, key_id="policy-v2-key-2")
    bundle = _signed_bundle(rotated_private_key, rotated_key)

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(first_key, rotated_key),
        anchored_verification_keys=(first_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "untrusted_signing_key"


def test_v2_bundle_rejects_malformed_rollback_hashes() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    rollback = {
        "rollbackOfBundleHash": "sha256:not-a-digest",
        "rollbackOfBundleVersion": 8,
        "lastGoodBundleHash": f"sha256:{'a' * 64}",
        "lastGoodBundleVersion": 6,
        "reason": "Restore the last verified policy.",
        "actor": "operator-alpha",
        "createdAt": "2026-07-15T12:02:00Z",
        "authorization": "approval-receipt-alpha",
    }
    bundle = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=9,
        rollback=rollback,
    )

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "invalid_rollback"


def test_v2_transition_rejects_replay_and_same_version_substitution() -> None:
    assert (
        validate_policy_bundle_v2_transition(
            {"bundleVersion": 7, "bundleHash": "sha256:old"},
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        == "bundle_downgrade_rejected"
    )
    assert (
        validate_policy_bundle_v2_transition(
            {"bundleVersion": 8, "bundleHash": "sha256:different"},
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        == "bundle_version_conflict"
    )


def test_v2_transition_accepts_only_authorized_monotonic_rollback() -> None:
    rollback: dict[str, object] = {
        "rollbackOfBundleHash": "sha256:current",
        "rollbackOfBundleVersion": 8,
        "lastGoodBundleHash": "sha256:historical-good",
        "lastGoodBundleVersion": 6,
        "reason": "Restore the last verified policy.",
        "actor": "operator-alpha",
        "createdAt": "2026-07-15T12:02:00Z",
        "authorization": "approval-receipt-alpha",
    }
    incoming: dict[str, object] = {
        "bundleVersion": 9,
        "bundleHash": "sha256:rollback-envelope",
        "rollback": rollback,
    }

    assert (
        validate_policy_bundle_v2_transition(
            incoming,
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        is None
    )
    rollback["lastGoodBundleHash"] = "sha256:unexpected"
    assert (
        validate_policy_bundle_v2_transition(
            incoming,
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
            expected_last_good_bundle_version=6,
            expected_last_good_bundle_hash="sha256:historical-good",
        )
        == "rollback_last_good_mismatch"
    )
    rollback["lastGoodBundleHash"] = "sha256:historical-good"
    rollback["rollbackOfBundleHash"] = "sha256:other"
    assert (
        validate_policy_bundle_v2_transition(
            incoming,
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        == "rollback_target_mismatch"
    )


def test_v2_acknowledgement_enforces_sequence_and_state_transitions() -> None:
    received = _acknowledgement(sequence=1, status="received")
    validated = _acknowledgement(sequence=2, status="validated")
    applied = _acknowledgement(sequence=3, status="applied")

    assert validated_policy_bundle_v2_acknowledgement(received) == (received, None)
    assert validated_policy_bundle_v2_acknowledgement(
        validated,
        previous=received,
    ) == (validated, None)
    assert validated_policy_bundle_v2_acknowledgement(
        applied,
        previous=validated,
    ) == (applied, None)
    replayed, reason = validated_policy_bundle_v2_acknowledgement(
        received,
        previous=applied,
    )
    assert replayed is None
    assert reason == "acknowledgement_replay"


def test_v2_acknowledgement_rejects_sequence_conflicts_and_terminal_reapply() -> None:
    applied = _acknowledgement(sequence=3, status="applied")
    conflict = {**applied, "status": "failed"}
    retried = _acknowledgement(sequence=4, status="received")

    assert validated_policy_bundle_v2_acknowledgement(
        conflict,
        previous=applied,
    ) == (None, "acknowledgement_sequence_conflict")
    assert validated_policy_bundle_v2_acknowledgement(
        retried,
        previous=applied,
    ) == (None, "acknowledgement_transition_rejected")


def test_runtime_canonical_enforcement_compiles_signed_v2_payload() -> None:
    policy_bundle = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "payload": {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": "policy.runtime",
                "name": "Runtime policy",
                "revision": 1,
            },
            "spec": {
                "defaults": {"mode": "prompt", "defaultAction": "warn"},
                "rules": [
                    {
                        "id": "rule.block-command",
                        "enabled": True,
                        "effect": "block",
                        "match": {
                            "artifacts": ["command:npm-test"],
                            "harnesses": ["codex"],
                        },
                        "lifetime": {"mode": "permanent", "expiresAt": None},
                        "provenance": {
                            "source": "suggested-memory",
                            "receiptIds": ["receipt-1"],
                            "suggestionId": "suggestion-1",
                            "createdAt": "2026-07-15T12:00:00Z",
                            "createdBy": "owner-1",
                        },
                    }
                ],
            },
        },
    }

    legacy = guard_runner._build_policy_bundle_decisions(
        policy_bundle,
        device_id="device-1",
        device_name="Mac",
    )
    canonical = guard_runner._build_policy_bundle_decisions(
        policy_bundle,
        device_id="device-1",
        device_name="Mac",
        canonical_enforcement=True,
    )

    assert legacy == []
    assert [decision.to_dict() for decision in canonical] == [
        {
            "harness": "codex",
            "scope": "artifact",
            "action": "block",
            "artifact_id": "command:npm-test",
            "artifact_hash": None,
            "workspace": None,
            "publisher": None,
            "reason": None,
            "owner": "rule.block-command",
            "source": "policy-bundle-canonical",
            "expires_at": None,
        }
    ]


def test_policy_shadow_comparison_uses_bounded_semantic_reason_codes() -> None:
    legacy = [
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id="command:npm-test",
            source="policy-bundle",
        )
    ]
    equivalent = [
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id="command:npm-test",
            source="policy-bundle-canonical",
        )
    ]
    changed = [
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id="command:npm-test",
            source="policy-bundle-canonical",
        ),
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id="command:pnpm-test",
            source="policy-bundle-canonical",
        ),
    ]

    assert guard_runner._policy_shadow_mismatch_reason_codes([], equivalent) == ("legacy_unavailable",)
    assert guard_runner._policy_shadow_mismatch_reason_codes(legacy, equivalent) == ()
    assert guard_runner._policy_shadow_mismatch_reason_codes(legacy, changed) == (
        "row_count",
        "selector_set",
        "action",
    )


def _generic_v2_payload(*, rollout_state: str, rule_id: str, artifact_id: str) -> dict[str, object]:
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "policy.runtime-admission", "name": "Admission", "revision": 1},
        "spec": {
            "defaults": {"mode": "prompt", "defaultAction": "warn"},
            "rolloutState": rollout_state,
            "rules": [
                {
                    "id": rule_id,
                    "enabled": True,
                    "effect": "block",
                    "match": {
                        "artifacts": [artifact_id],
                        "harnesses": ["codex"],
                    },
                    "lifetime": {"mode": "permanent", "expiresAt": None},
                    "provenance": {
                        "source": "suggested-memory",
                        "receiptIds": ["receipt-1"],
                        "suggestionId": "suggestion-1",
                        "createdAt": "2026-07-15T12:00:00Z",
                        "createdBy": "owner-1",
                    },
                }
            ],
        },
    }


class _SyncResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> _SyncResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        del exc_type, exc, tb
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _sync_signed_v2_bundle(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    bundle: dict[str, object],
    *,
    synced_at: str,
) -> dict[str, object]:
    stub_authenticated_urlopen(
        monkeypatch,
        lambda request, timeout: _SyncResponse(
            {"syncedAt": synced_at, "receiptsStored": 0, "policyBundle": bundle}
        ),
    )
    monkeypatch.setattr(guard_runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner, "sync_guard_events", lambda _store, auth_context=None: 0)
    return guard_runner.sync_receipts(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "test-token",
            "dpop_key_material": None,
        },
    )


def test_v2_publication_contract_matches_live_rollout_states() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    draft = _signed_bundle(private_key, verification_key)
    pending = _signed_bundle(private_key, verification_key, rollout_state="pending_approval")
    published = _signed_bundle(private_key, verification_key, rollout_state="enforcing")

    assert policy_bundle_is_enforceable(draft) is False
    assert policy_bundle_is_enforceable(pending) is False
    assert policy_bundle_is_enforceable(published) is True
    omitted_payload = _generic_v2_payload(
        rollout_state="enforcing",
        rule_id="rule.live",
        artifact_id="command:live",
    )
    spec = cast(dict[str, object], omitted_payload["spec"])
    spec.pop("rolloutState", None)
    omitted = _signed_bundle(private_key, verification_key, payload_base=omitted_payload)
    assert policy_bundle_is_enforceable(omitted) is True


@pytest.mark.parametrize("rollout_state", ["draft", "pending_approval"])
def test_signed_unpublished_generic_v2_bundle_is_not_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rollout_state: str,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    live = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=8,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.live-block",
            artifact_id="command:live-block",
        ),
    )
    unpublished = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=9,
        payload_base=_generic_v2_payload(
            rollout_state=rollout_state,
            rule_id="rule.draft-block",
            artifact_id="command:draft-block",
        ),
    )
    validated, reason, _keys = validate_synced_policy_bundle(
        unpublished,
        stored_keyring={"keys": [verification_key.to_dict()]},
        expected_workspace_id="workspace-alpha",
    )
    assert reason is None
    assert validated is not None
    assert policy_bundle_is_enforceable(unpublished) is False

    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-07-15T12:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-07-15T12:00:00Z")

    _sync_signed_v2_bundle(store, monkeypatch, live, synced_at="2026-07-15T12:01:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    live_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:live-block" in live_rows
    assert store.get_sync_payload("policy_bundle_ack") == {}

    _sync_signed_v2_bundle(store, monkeypatch, unpublished, synced_at="2026-07-15T12:02:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    assert store.get_sync_payload("policy_bundle_last_good") == live
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(last_error, dict)
    assert last_error.get("reason") == "inactive_rollout_state"
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert acknowledgement == {} or (
        isinstance(acknowledgement, dict) and acknowledgement.get("status") != "applied"
    )
    remaining_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:draft-block" not in remaining_rows
    assert "command:live-block" in remaining_rows

    assert cached_policy_bundle_validation(store, unpublished) == (None, "inactive_rollout_state")

    store.set_sync_payload("policy_bundle", unpublished, "2026-07-15T12:03:00Z")
    assert cached_policy_bundle_validation(store, unpublished) == (None, "inactive_rollout_state")
    assert cached_policy_bundle_validation(store, live)[0] == live


def test_signed_enforcing_generic_v2_bundle_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    published = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=10,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.published-block",
            artifact_id="command:published-block",
        ),
    )
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-07-15T12:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-07-15T12:00:00Z")

    _sync_signed_v2_bundle(store, monkeypatch, published, synced_at="2026-07-15T12:04:00Z")
    assert store.get_sync_payload("policy_bundle") == published
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert last_error in (None, {})
    assert "command:published-block" in [row["artifact_id"] for row in store.list_policy_decisions()]
    assert cached_policy_bundle_validation(store, published)[0] == published
