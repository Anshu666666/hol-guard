"""Locally verified, connection-bound signed consumer observations."""

from __future__ import annotations

import base64
import threading
import time
from functools import partial

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .dpop_key_binding import verified_dpop_jwk_thumbprint
from .native_policy_consumer_capture import NativeConsumerCapture, capture_native_consumer
from .native_policy_control_transport import _native_policy_control_request_owned, run_native_control_worker
from .native_policy_snapshot import NativePolicySnapshotPublisher
from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS, NativePolicySnapshotError
from .native_policy_snapshot_control import NativeAuthorityObservation, _remaining, observe_native_authority
from .oauth_connection_authority import OAuthConnectionSnapshot
from .policy_consumer_readiness_contract import ConsumerReadinessError, mapping, signing_bytes, validate_wire
from .policy_document import JsonValue
from .store import GuardStore


def _active(cancelled: threading.Event, deadline: float) -> None:
    _remaining(deadline)
    if cancelled.is_set():
        raise ConsumerReadinessError()


def local_context(captured: NativeConsumerCapture, connection: OAuthConnectionSnapshot) -> dict[str, JsonValue]:
    return {
        "agentConnectionEpoch": connection.epoch,
        "publisherInstanceId": captured.publisher_instance,
        "publisherEpoch": str(captured.publisher_epoch),
        "sourceInputDigest": captured.source_input_digest,
    }


def capture_local_context(
    publisher: NativePolicySnapshotPublisher | None,
    connection: OAuthConnectionSnapshot,
) -> dict[str, JsonValue] | None:
    """Capture a prospective challenge commitment; never cache positive evidence."""
    if publisher is None:
        return None
    deadline = time.monotonic() + _PUBLISH_TIMEOUT_SECONDS

    def operation(cancelled: threading.Event) -> dict[str, JsonValue]:
        _active(cancelled, deadline)
        with capture_native_consumer(publisher, connection=connection, deadline_monotonic=deadline) as captured:
            context = local_context(captured, connection)
        _active(cancelled, deadline)
        return context

    return run_native_control_worker(operation, deadline_monotonic=deadline)


def validate_challenge_subject(
    challenge: dict[str, JsonValue],
    connection: OAuthConnectionSnapshot,
    *,
    session_id: str,
    expected_context: dict[str, JsonValue] | None,
) -> None:
    validate_wire(challenge, "challenge")
    credentials = connection.credentials()
    subject = mapping(challenge["subject"])
    if (
        subject["workspaceId"] != credentials.get("workspace_id")
        or subject["oauthGrantId"] != credentials.get("grant_id")
        or subject["machineId"] != credentials.get("machine_id")
        or subject["runtimeId"] != (credentials.get("runtime_id") or None)
        or subject["runtimeSessionId"] != session_id
        or challenge["keyThumbprint"] != credentials.get("dpop_public_jwk_thumbprint")
        or challenge["localContext"] != expected_context
    ):
        raise ConsumerReadinessError()
    # installationId is the server's registered row UUID, not the unrelated
    # local installation UUID. Schema-check and echo it exactly; the server
    # independently rechecks that row under the authenticated subject.
    now_ms = int(time.time() * 1000)
    issued, expires = challenge["issuedAtMs"], challenge["expiresAtMs"]
    if type(issued) is not int or type(expires) is not int or not issued <= now_ms < expires:
        raise ConsumerReadinessError()


def _sign(body: dict[str, JsonValue], connection: OAuthConnectionSnapshot) -> dict[str, JsonValue]:
    credentials = connection.credentials()
    pem = credentials.get("dpop_private_key_pem")
    public_jwk = credentials.get("dpop_public_jwk")
    expected = mapping(body["challenge"])["keyThumbprint"]
    if expected != verified_dpop_jwk_thumbprint(private_key_pem=pem, public_jwk=public_jwk):
        raise ConsumerReadinessError()
    if not isinstance(pem, str):
        raise ConsumerReadinessError()
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ConsumerReadinessError()
    r, s = decode_dss_signature(key.sign(signing_bytes(body), ec.ECDSA(hashes.SHA256())))
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return validate_wire(
        {
            "body": body,
            "signature": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        },
        "observation",
    )


def _ready_body(
    challenge: dict[str, JsonValue],
    captured: NativeConsumerCapture,
    observed: NativeAuthorityObservation,
) -> dict[str, JsonValue]:
    identity, capabilities = captured.runtime.identity, captured.runtime.capabilities
    authority = observed.authority
    if (
        identity is None
        or capabilities is None
        or authority is None
        or not authority.usable_snapshot
        or observed.runtime_identity != identity.sha256
        or observed.resident_generation != captured.resident_generation
        or authority.generation_floor != captured.generation
        or authority.policy_digest != captured.policy_digest
    ):
        raise ConsumerReadinessError()
    return validate_wire(
        {
            "contractVersion": "guard.consumer-readiness-observation.v2",
            "challenge": challenge,
            "signatureAlgorithm": "ES256",
            "readiness": "ready_for_delivery",
            "runtimeIdentity": identity.sha256,
            "runtimeProtocolVersion": capabilities.protocol_version,
            "runtimeRuleDigest": capabilities.rule_digest,
            "nativeScopeDigest": observed.scope_digest,
            "residentGeneration": str(observed.resident_generation),
            "nativeAuthority": {
                "fingerprint": authority.fingerprint,
                "generationFloor": str(authority.generation_floor),
                "policyDigest": authority.policy_digest,
                "usableSnapshot": True,
            },
            "publisherSnapshot": {
                "schemaVersion": captured.snapshot_version,
                "generation": str(captured.generation),
                "policyDigest": captured.policy_digest,
                "sourceInputDigest": captured.source_input_digest,
                "residentGeneration": str(captured.resident_generation),
                "mode": "enforce",
                "expiresAtMs": captured.expires_at_ms,
            },
        },
        "ready",
    )


def _observe_and_sign(
    publisher: NativePolicySnapshotPublisher,
    connection: OAuthConnectionSnapshot,
    challenge: dict[str, JsonValue],
    cancelled: threading.Event,
    deadline: float,
) -> dict[str, JsonValue]:
    with capture_native_consumer(publisher, connection=connection, deadline_monotonic=deadline) as captured:
        _active(cancelled, deadline)
        if challenge["localContext"] != local_context(captured, connection):
            raise ConsumerReadinessError()
        identity = captured.runtime.identity
        nonce = challenge["nonce"]
        if identity is None or not isinstance(nonce, str):
            raise ConsumerReadinessError()
        material = publisher.store._policy_integrity_secret_material(create=False)
        master = material[0]
        if not isinstance(master, bytes):
            raise ConsumerReadinessError()
        verifier = derive_native_policy_verifier_key(master)
        # Neither key is persisted, returned, logged, or sent to the server.
        del master, material
        observed = observe_native_authority(
            executable=identity.path,
            guard_home=publisher.guard_home,
            runtime_identity=identity.sha256,
            verifier_key=verifier,
            deadline_monotonic=deadline,
            challenge_nonce=nonce,
            client=partial(_native_policy_control_request_owned, cancelled=cancelled),
        )
        del verifier
        _active(cancelled, deadline)
        envelope = _sign(_ready_body(challenge, captured, observed), connection)
    # The context's final complete capture must succeed before any body escapes.
    _active(cancelled, deadline)
    return envelope


def signed_observation(
    store: GuardStore,
    publisher: NativePolicySnapshotPublisher | None,
    connection: OAuthConnectionSnapshot,
    challenge: dict[str, JsonValue],
) -> dict[str, JsonValue] | None:
    """One bounded local attempt. No native retry and no late signed success."""
    deadline = time.monotonic() + _PUBLISH_TIMEOUT_SECONDS
    expires = challenge["expiresAtMs"]
    if type(expires) is not int or expires <= int(time.time() * 1000):
        return None
    deadline = min(deadline, time.monotonic() + (expires / 1000 - time.time()))

    def operation(cancelled: threading.Event) -> dict[str, JsonValue]:
        _active(cancelled, deadline)
        reason = "snapshot_unavailable"
        if publisher is not None and challenge["localContext"] is not None:
            try:
                return _observe_and_sign(publisher, connection, challenge, cancelled, deadline)
            except (OSError, RuntimeError, ValueError, NativePolicySnapshotError):
                reason = "authority_changed"
        _active(cancelled, deadline)
        # A native/source refusal can clear this exact challenge only while the
        # original connection remains selected. Replacement credentials abort.
        with store.hold_oauth_credential_lock(timeout_seconds=_remaining(deadline)):
            store._require_oauth_connection_unlocked(connection)
            envelope = _sign(
                {
                    "contractVersion": "guard.consumer-readiness-observation.v2",
                    "challenge": challenge,
                    "signatureAlgorithm": "ES256",
                    "readiness": "unavailable",
                    "reason": reason,
                },
                connection,
            )
            store._require_oauth_connection_unlocked(connection)
        _active(cancelled, deadline)
        return envelope

    return run_native_control_worker(operation, deadline_monotonic=deadline)
