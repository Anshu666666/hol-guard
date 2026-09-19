"""Explicit source-bound consent for legacy optional-upload transport fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial, generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workspace_preference_authority import (
    accept_workspace_preference_response,
    capture_workspace_preference_state,
)

SYNTHETIC_WORKSPACE_ID = "00000000-0000-4000-8000-000000000071"


def seed_legacy_optional_uploads(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    workspace_id: str = SYNTHETIC_WORKSPACE_ID,
    issuer: str = "https://hol.org",
    token: str = "demo-token",
    sync_url: str | None = None,
    telemetry: bool = False,
) -> GuardDpopKeyMaterial:
    """Opt a fresh transport fixture into the real selected connection's legacy contract."""
    assert str(UUID(workspace_id)) == workspace_id
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    now = datetime.now(timezone.utc)
    key = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh",
        access_token=token,
        access_token_expires_at=(now + timedelta(hours=1)).isoformat(),
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        grant_id="synthetic-grant",
        device_id="synthetic-device",
        machine_id="synthetic-machine",
        runtime_id="synthetic-runtime",
        workspace_id=workspace_id,
        now=now.isoformat(),
    )
    (store.guard_home / "config.toml").write_text(
        f"sync = true\ntelemetry = {str(telemetry).lower()}\n", encoding="utf-8"
    )
    connection = store.capture_oauth_connection()
    assert connection is not None
    assert connection.credentials()["workspace_id"] == workspace_id
    captured = capture_workspace_preference_state(store, required_connection=connection)
    accepted = accept_workspace_preference_response(
        store,
        captured,
        {"syncedAt": now.isoformat(), "receiptsStored": 0},
        sent_revision=None,
    )
    assert accepted.receipt_accepted
    assert accepted.state.confirmed and accepted.state.mode == "legacy"
    assert accepted.state.connection.same_authority(connection)
    if sync_url is not None:
        assert runner._validate_guard_sync_url(sync_url, issuer=issuer) == sync_url
        if sync_url != runner._oauth_sync_url_from_issuer(issuer):
            # Keep legacy base-path normalization under test without substituting auth.
            def requested_sync_url(selected_issuer: str) -> str:
                assert selected_issuer == issuer
                return sync_url

            monkeypatch.setattr(runner, "_oauth_sync_url_from_issuer", requested_sync_url)
    observed = []
    context = runner._resolve_guard_sync_auth_context(store, connection_observer=observed.append)
    assert observed == [connection]
    assert context["access_token"] == token
    assert context["dpop_key_material"] == key
    return key


def _decode_segment(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def assert_dpop_proof(
    proof: object,
    *,
    key: GuardDpopKeyMaterial,
    request_url: str,
    token: str,
) -> None:
    """Verify the actual ingress proof and its request/token binding."""
    assert isinstance(proof, str)
    encoded_header, encoded_claims, encoded_signature = proof.split(".")
    header = json.loads(_decode_segment(encoded_header))
    claims = json.loads(_decode_segment(encoded_claims))
    assert header == {"alg": "ES256", "jwk": key.public_jwk, "typ": "dpop+jwt"}
    assert claims["htu"] == request_url and claims["htm"] == "POST"
    assert claims["ath"] == base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip("=")
    assert type(claims["iat"]) is int and claims["iat"] > 0
    assert str(UUID(claims["jti"])) == claims["jti"]
    signature = _decode_segment(encoded_signature)
    assert len(signature) == 64
    public_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_decode_segment(key.public_jwk["x"]), "big"),
        int.from_bytes(_decode_segment(key.public_jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    public_key.verify(
        encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
        f"{encoded_header}.{encoded_claims}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )
