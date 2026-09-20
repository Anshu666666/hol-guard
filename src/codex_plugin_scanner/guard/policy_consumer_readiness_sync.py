"""One off-hook readiness handshake; delivery and applied authority stay separate."""

from __future__ import annotations

import time
import urllib.parse

from .cli.oauth_client import GuardDpopKeyMaterial, guard_api_base_path
from .native_policy_snapshot import find_native_policy_snapshot_publisher
from .oauth_connection_authority import OAuthConnectionSnapshot
from .policy_consumer_readiness_contract import (
    MAX_WIRE_BYTES,
    PROFILE_ID,
    ConsumerReadinessError,
    WireKind,
    mapping,
    parse_wire,
    validate_wire,
)
from .policy_consumer_readiness_observation import (
    capture_local_context,
    signed_observation,
    validate_challenge_subject,
)
from .policy_document import JsonValue, canonical_json_bytes
from .store import GuardStore

_CHALLENGE_PATH = "/api/guard/runtime/policy-consumer/challenges"
_OBSERVATION_PATH = "/api/guard/runtime/policy-consumer/observations"


def _require_connection(store: GuardStore, connection: OAuthConnectionSnapshot) -> None:
    with store.hold_oauth_credential_lock():
        store._require_oauth_connection_unlocked(connection)


def _post(
    store: GuardStore, connection: OAuthConnectionSnapshot, auth_context: dict[str, object],
    *, path: str, body: dict[str, JsonValue], kind: WireKind,
) -> dict[str, JsonValue]:
    # Reuse the existing allowlisted origin and DPoP request signer. This
    # one-use protocol makes no timeout, gateway, rate-limit or nonce retry.
    from .runtime import runner

    issuer = connection.credentials().get("issuer")
    if not isinstance(issuer, str):
        raise ConsumerReadinessError()
    sync_url = runner._validate_guard_sync_url(runner._auth_context_sync_url(auth_context), issuer=issuer)
    parsed = urllib.parse.urlsplit(sync_url)
    url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, guard_api_base_path(issuer) + path, "", ""))
    _require_connection(store, connection)
    request = runner._guard_sync_request(
        auth_context, request_url=url, method="POST",
        data=canonical_json_bytes(body), extra_headers=None,
    )
    _require_connection(store, connection)
    try:
        with runner.managed_urlopen(request, timeout=runner._RUNTIME_SYNC_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_WIRE_BYTES + 1)
    finally:
        _require_connection(store, connection)
    return parse_wire(raw, kind)


def _accepted_ack(
    ack: dict[str, JsonValue], challenge: dict[str, JsonValue], body: dict[str, JsonValue],
) -> dict[str, object]:
    for field in ("challengeId", "subjectVersion", "challengeSequence"):
        if ack[field] != challenge[field]:
            raise ConsumerReadinessError()
    if ack["readiness"] != body["readiness"]:
        raise ConsumerReadinessError()
    received, expires = ack["receivedAtMs"], challenge["expiresAtMs"]
    if type(received) is not int or type(expires) is not int:
        raise ConsumerReadinessError()
    issued = challenge["issuedAtMs"]
    if type(issued) is not int or not issued <= received < expires:
        raise ConsumerReadinessError()
    until = ack["validUntilMs"]
    if ack["readiness"] == "ready_for_delivery":
        native_expiry = mapping(body["publisherSnapshot"])["expiresAtMs"]
        if (
            type(until) is not int or type(native_expiry) is not int
            or not int(time.time() * 1000) < until <= min(expires, native_expiry)
        ):
            raise ConsumerReadinessError()
    # This finite display summary is never read as local enforcement authority.
    return {
        "contract_version": "guard.consumer-readiness-ack.v2",
        "readiness": ack["readiness"],
        "valid_until_ms": until,
        "applied_policy": False,
    }


def sync_consumer_readiness(
    store: GuardStore, *, connection: OAuthConnectionSnapshot | None,
    auth_context: dict[str, object], runtime_summary: dict[str, object],
) -> dict[str, object]:
    """Try the current session once; an unavailable endpoint grants nothing."""
    unavailable: dict[str, object] = {"readiness": "unavailable", "applied_policy": False}
    if connection is None or runtime_summary.get("runtime_session_synced_at") is None:
        return unavailable
    session_id = runtime_summary.get("runtime_session_id")
    key = auth_context.get("dpop_key_material")
    if (
        not isinstance(session_id, str) or not isinstance(key, GuardDpopKeyMaterial)
        or key.public_jwk_thumbprint != connection.credentials().get("dpop_public_jwk_thumbprint")
    ):
        return unavailable
    try:
        _require_connection(store, connection)
        publisher = find_native_policy_snapshot_publisher(store)
        context = capture_local_context(publisher, connection)
        issue = validate_wire({
            "contractVersion": "guard.consumer-readiness-challenge-request.v2",
            "runtimeSessionId": session_id, "profileId": PROFILE_ID, "localContext": context,
        }, "issue")
        challenge = _post(
            store, connection, auth_context, path=_CHALLENGE_PATH, body=issue, kind="challenge",
        )
        validate_challenge_subject(challenge, connection, session_id=session_id, expected_context=context)
        envelope = signed_observation(store, publisher, connection, challenge)
        if envelope is None:
            return unavailable
        _require_connection(store, connection)
        ack = _post(
            store, connection, auth_context, path=_OBSERVATION_PATH, body=envelope, kind="ack",
        )
        _require_connection(store, connection)
        return _accepted_ack(ack, challenge, mapping(envelope["body"]))
    except Exception:
        # Authentication, native transport, parsing and cleanup failures are
        # not evidence of readiness. Never persist response text or secrets.
        return unavailable
