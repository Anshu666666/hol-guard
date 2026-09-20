"""Actual credential/DPoP request construction with controlled HTTP bytes."""

from __future__ import annotations

import io
import json
import threading
import time

import pytest

from codex_plugin_scanner.guard import policy_consumer_readiness_sync as sync
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation
from codex_plugin_scanner.guard.policy_consumer_readiness_contract import PROFILE_ID, ConsumerReadinessError
from codex_plugin_scanner.guard.policy_document import JsonValue, canonical_json_bytes
from codex_plugin_scanner.guard.runtime import runner
from tests.test_native_policy_consumer_capture import _fixture
from tests.test_policy_consumer_readiness_observation import SESSION, challenge_for


def auth_for(connection):
    credentials = connection.credentials()
    return {
        "sync_url": credentials["issuer"] + "/api/guard/receipts/sync",
        "access_token": credentials["access_token"],
        "dpop_key_material": GuardDpopKeyMaterial(
            "ES256",
            credentials["dpop_private_key_pem"],
            credentials["dpop_public_jwk"],
            credentials["dpop_public_jwk_thumbprint"],
        ),
    }


def issue() -> dict[str, JsonValue]:
    return {
        "contractVersion": "guard.consumer-readiness-challenge-request.v2",
        "runtimeSessionId": SESSION,
        "profileId": PROFILE_ID,
        "localContext": None,
    }


@pytest.mark.parametrize("failure", ["duplicate", "escaped-duplicate", "float", "oversized", "unknown", "refresh"])
def test_response_rejection_preserves_one_request_and_no_credential_lock_over_http(tmp_path, monkeypatch, failure):
    store, publisher, connection, credentials, _ = _fixture(tmp_path, monkeypatch)
    challenge = challenge_for(connection, None)
    raw = canonical_json_bytes(challenge)
    if failure == "duplicate":
        raw = raw[:-1] + b',"nonce":"' + b"d" * 64 + b'"}'
    elif failure == "escaped-duplicate":
        raw = raw[:-1] + b',"\\u006eonce":"' + b"d" * 64 + b'"}'
    elif failure == "float":
        raw = raw.replace(b'"challengeSequence":1', b'"challengeSequence":1.0')
    elif failure == "oversized":
        raw = b" " * 16_385
    elif failure == "unknown":
        raw = raw[:-1] + b',"arbitrary":true}'
    calls = []

    def respond(request, timeout):
        calls.append(request)
        assert timeout == runner._RUNTIME_SYNC_TIMEOUT_SECONDS
        assert request.full_url == credentials["issuer"] + sync._CHALLENGE_PATH
        assert request.get_method() == "POST" and request.get_header("Dpop")
        assert json.loads(request.data) == issue()
        # Independent ownership avoids a false pass from a reentrant lock.
        acquired = threading.Event()

        def probe_leases():
            try:
                with (
                    hold_policy_publication_mutation(store.guard_home, timeout_seconds=0.25),
                    store.hold_oauth_credential_lock(timeout_seconds=0.25),
                ):
                    store._require_oauth_connection_unlocked(connection)
                    acquired.set()
            except Exception:
                return

        probe = threading.Thread(target=probe_leases, daemon=True)
        probe.start()
        probe.join(timeout=1)
        assert acquired.is_set() and not probe.is_alive(), "HTTP must not retain either authority lease"
        if failure == "refresh":
            refreshed_credentials = credentials.copy()
            refreshed_credentials["access_token"] = "changed"
            store.set_oauth_local_credentials(**refreshed_credentials, expected_connection=connection)
        return io.BytesIO(raw)

    monkeypatch.setattr(runner, "managed_urlopen", respond)
    try:
        with pytest.raises((ConsumerReadinessError, RuntimeError)):
            sync._post(
                store, connection, auth_for(connection), path=sync._CHALLENGE_PATH, body=issue(), kind="challenge"
            )
        assert len(calls) == 1
    finally:
        publisher.close()


def test_globally_allowed_but_different_issuer_is_rejected_before_http(tmp_path, monkeypatch):
    store, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(runner, "managed_urlopen", lambda *args, **kwargs: calls.append(args))
    context = auth_for(connection)
    context["sync_url"] = "https://staging.hol.org/api/guard/receipts/sync"
    try:
        with pytest.raises(RuntimeError):
            sync._post(store, connection, context, path=sync._CHALLENGE_PATH, body=issue(), kind="challenge")
        assert not calls
    finally:
        publisher.close()


@pytest.mark.parametrize("change", ["id", "version", "sequence", "state", "past", "future"])
def test_ack_must_match_one_challenge_and_server_bounded_validity(tmp_path, monkeypatch, change):
    _, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    challenge = challenge_for(connection, None)
    body: dict[str, JsonValue] = {"readiness": "unavailable"}
    issued_at = challenge["issuedAtMs"]
    assert type(issued_at) is int
    ack: dict[str, JsonValue] = {
        "contractVersion": "guard.consumer-readiness-ack.v2",
        "challengeId": challenge["challengeId"],
        "subjectVersion": challenge["subjectVersion"],
        "challengeSequence": challenge["challengeSequence"],
        "readiness": "unavailable",
        "receivedAtMs": int(time.time() * 1000),
        "validUntilMs": None,
    }
    changed = {
        "id": ("challengeId", "66666666-6666-4666-8666-666666666666"),
        "version": ("subjectVersion", "66666666-6666-4666-8666-666666666666"),
        "sequence": ("challengeSequence", 2),
        "state": ("readiness", "ready_for_delivery"),
        "past": ("receivedAtMs", issued_at - 1),
        "future": ("receivedAtMs", challenge["expiresAtMs"]),
    }[change]
    try:
        assert sync._accepted_ack(ack, challenge, body)["applied_policy"] is False
        ack[changed[0]] = changed[1]
        with pytest.raises(ConsumerReadinessError):
            sync._accepted_ack(ack, challenge, body)
    finally:
        publisher.close()
