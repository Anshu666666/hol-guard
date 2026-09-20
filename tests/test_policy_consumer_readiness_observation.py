"""Real Store and ES256, with an explicitly synthetic native HMAC responder."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from codex_plugin_scanner.guard import policy_consumer_readiness_observation as observation
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_control import (
    _OBSERVATION_DOMAIN,
    _OBSERVATION_RESPONSE_DOMAIN,
)
from codex_plugin_scanner.guard.policy_consumer_readiness_contract import (
    ConsumerReadinessError,
    PROFILE_ID,
    mapping,
    signing_bytes,
    validate_wire,
)
from codex_plugin_scanner.guard.policy_document import canonical_json_bytes
from tests.test_native_policy_consumer_capture import _fixture

SESSION = "synthetic-readiness-session"


def challenge_for(connection, context, *, sequence=1):
    credentials = connection.credentials()
    now = int(time.time() * 1000)
    return validate_wire({
        "contractVersion": "guard.consumer-readiness-challenge.v2",
        "challengeId": "11111111-1111-4111-8111-111111111111",
        "nonce": "c" * 64,
        "profileId": PROFILE_ID,
        "subject": {
            "workspaceId": credentials["workspace_id"],
            # This server row UUID deliberately differs from the local Store ID.
            "installationId": "33333333-3333-4333-8333-333333333333",
            "machineId": credentials["machine_id"],
            "oauthGrantId": credentials["grant_id"],
            "runtimeId": credentials.get("runtime_id"),
            "runtimeSessionId": SESSION,
        },
        "subjectVersion": "55555555-5555-4555-8555-555555555555",
        "challengeSequence": sequence,
        "keyThumbprint": credentials["dpop_public_jwk_thumbprint"],
        "localContext": context,
        "issuedAtMs": now,
        "expiresAtMs": now + 60_000,
    }, "challenge")


def verify_signed(envelope, connection):
    body = mapping(envelope["body"])
    pem = connection.credentials()["dpop_private_key_pem"]
    assert isinstance(pem, str)
    private = serialization.load_pem_private_key(pem.encode(), password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    encoded = envelope["signature"]
    assert isinstance(encoded, str)
    signature = base64.urlsafe_b64decode(encoded + "==")
    private.public_key().verify(
        encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
        signing_bytes(body), ec.ECDSA(hashes.SHA256()),
    )
    return body


@pytest.mark.parametrize("change", ["none", "nonce", "mac", "epoch", "sql", "credentials"])
def test_actual_signing_requires_nonce_hmac_and_final_current_sources(tmp_path, monkeypatch, change):
    store, publisher, connection, credentials, _ = _fixture(tmp_path, monkeypatch)
    calls = []
    context = observation.capture_local_context(publisher, connection)
    assert context is not None
    challenge = challenge_for(connection, context)
    observation.validate_challenge_subject(challenge, connection, session_id=SESSION, expected_context=context)
    assert mapping(challenge["subject"])["installationId"] != store.get_or_create_installation_id()
    master, _ = store._policy_integrity_secret_material(create=False)
    assert isinstance(master, bytes)
    key = derive_native_policy_verifier_key(master)

    def native(**kwargs):
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        request = json.loads(payload)["request"]
        intent = request["intent"]
        assert request["mac"] == hmac.new(
            key, _OBSERVATION_DOMAIN + canonical_json_bytes(intent), hashlib.sha256,
        ).hexdigest()
        calls.append(intent["nonce"])
        snapshot = publisher._snapshot
        assert snapshot is not None
        response = {
            "schema": "guard-policy-snapshot-observation-response.v1",
            "runtime_identity": intent["runtime_identity"],
            "scope_digest": intent["scope_digest"],
            "nonce": "d" * 64 if change == "nonce" else intent["nonce"],
            "request_sha256": hashlib.sha256(canonical_json_bytes(request)).hexdigest(),
            "resident_generation": 1,
            "authority": {
                "fingerprint": "e" * 64, "generation_floor": snapshot["generation"],
                "policy_digest": snapshot["policy_digest"], "usable_snapshot": True,
            },
        }
        signed = {
            "response": response,
            "mac": hmac.new(key, _OBSERVATION_RESPONSE_DOMAIN + canonical_json_bytes(response), hashlib.sha256).hexdigest(),
        }
        if change == "mac":
            signed["mac"] = "0" * 64
        elif change == "epoch":
            publisher.request_publish()
        elif change == "sql":
            store.set_sync_payload("synthetic-interference", {}, "2026-09-20T00:00:00Z")
        elif change == "credentials":
            store._set_oauth_local_credentials_unlocked(**credentials)
        return canonical_json_bytes(signed)

    monkeypatch.setattr(observation, "_native_policy_control_request_owned", native)
    try:
        envelope = observation.signed_observation(store, publisher, connection, challenge)
        assert calls == [challenge["nonce"]], "No retry or unrelated native nonce"
        if change == "credentials":
            assert envelope is None
        else:
            assert envelope is not None
            body = verify_signed(envelope, connection)
            assert body["challenge"] == challenge
            assert body["readiness"] == ("ready_for_delivery" if change == "none" else "unavailable")
            encoded = canonical_json_bytes(envelope)
            assert str(store.guard_home).encode() not in encoded
            assert master not in encoded and b"private_key" not in encoded
            if change == "none":
                assert mapping(body["publisherSnapshot"])["schemaVersion"] == 3
                assert store.get_sync_payload("policy_bundle") is None
                assert store.get_sync_payload("policy_bundle_ack") is None
    finally:
        publisher.close()


@pytest.mark.parametrize("field", ["workspaceId", "oauthGrantId", "machineId", "runtimeId", "runtimeSessionId"])
def test_foreign_credential_subject_cannot_be_signed(tmp_path, monkeypatch, field):
    _, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    try:
        challenge = challenge_for(connection, None)
        subject = mapping(challenge["subject"])
        subject[field] = "66666666-6666-4666-8666-666666666666" if field.endswith("Id") else "foreign"
        with pytest.raises(ConsumerReadinessError):
            observation.validate_challenge_subject(challenge, connection, session_id=SESSION, expected_context=None)
    finally:
        publisher.close()


def test_missing_publisher_only_signs_exact_unavailable_with_current_connection(tmp_path, monkeypatch):
    store, publisher, connection, credentials, _ = _fixture(tmp_path, monkeypatch)
    try:
        challenge = challenge_for(connection, None)
        envelope = observation.signed_observation(store, None, connection, challenge)
        assert envelope is not None
        body = verify_signed(envelope, connection)
        assert body["readiness"] == "unavailable" and body["challenge"] == challenge
        assert "nativeAuthority" not in body and "publisherSnapshot" not in body
        store.set_oauth_local_credentials(**credentials)
        assert observation.signed_observation(store, None, connection, challenge) is None
    finally:
        publisher.close()
