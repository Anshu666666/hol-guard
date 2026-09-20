"""Synthetic enrollment/server challenge around the actual installed consumer.

This fixture verifies the agent's ES256 envelope, not remote native attestation.
The inherited server checks its synthetic bearer token, not HTTP DPoP proof.
The production server has separate real SQL admission/race tests.
"""

from __future__ import annotations

import base64
import copy
import secrets
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ci.native_runtime.installed_scoped_policy_fixture import SignedPolicyFixture
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_verification_key_from_public_key
from codex_plugin_scanner.guard.policy_consumer_readiness_contract import (
    PROFILE_ID,
    ConsumerReadinessError,
    mapping,
    signing_bytes,
    validate_wire,
)
from codex_plugin_scanner.guard.policy_document import JsonValue

WORKSPACE = "22222222-2222-4222-8222-222222222222"
GRANT = "44444444-4444-4444-8444-444444444444"
INSTALLATION = "33333333-3333-4333-8333-333333333333"
SESSION = "synthetic-enrolled-agent-session"
COMMANDS = ("pwd", "true", "whoami")


class ReadinessFixture(SignedPolicyFixture):
    def __init__(self, root: Path) -> None:
        self.agent_key = generate_dpop_key_pair()
        self.sequence = 0
        self.pending: dict[str, JsonValue] | None = None
        self.accepted: list[dict[str, JsonValue]] = []
        super().__init__(root)
        try:
            self._configure_agent()
        except BaseException:
            with suppress(BaseException):
                self.close()
            raise

    def _configure_agent(self) -> None:
        # Each signed profile stage supplies its own default action. The base
        # fixture's narrower Codex review floor would make a matching review
        # rule noncausal for commands that already require that same action.
        (self.store.guard_home / "config.toml").write_text(
            'mode="enforce"\ndefault_action="review"\n', encoding="utf-8"
        )
        now = datetime.now(timezone.utc)
        self.store.set_oauth_local_credentials(
            issuer=f"https://127.0.0.1:{self.server.server_port}",
            client_id="guard-local-daemon-local",
            refresh_token=secrets.token_urlsafe(32),
            dpop_private_key_pem=self.agent_key.private_key_pem,
            dpop_public_jwk=self.agent_key.public_jwk,
            dpop_public_jwk_thumbprint=self.agent_key.public_jwk_thumbprint,
            device_id=self.agent_key.public_jwk_thumbprint,
            grant_id=GRANT,
            machine_id="synthetic-enrolled-machine",
            runtime_id=None,
            workspace_id=WORKSPACE,
            now=now.isoformat(),
            access_token=self.token,
            access_token_expires_at=(now + timedelta(minutes=10)).isoformat(),
        )
        public = (
            self.key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        self.verification = policy_bundle_verification_key_from_public_key(
            key_id="synthetic-installed-policy",
            public_key_pem=public,
            workspace_id=WORKSPACE,
        )
        self.store.set_sync_payload("policy_bundle_keyring", {"keys": [self.verification.to_dict()]}, now.isoformat())

    def response_for_request(self, path: str, request: dict[str, object]) -> dict[str, Any]:
        if path == "/api/guard/runtime/policy-consumer/challenges":
            issue = validate_wire(request, "issue")
            if issue["runtimeSessionId"] != SESSION:
                raise ConsumerReadinessError()
            self.sequence += 1
            now = int(time.time() * 1000)
            self.pending = validate_wire(
                {
                    "contractVersion": "guard.consumer-readiness-challenge.v2",
                    "challengeId": "11111111-1111-4111-8111-111111111111",
                    "nonce": secrets.token_hex(32),
                    "profileId": PROFILE_ID,
                    "subject": {
                        "workspaceId": WORKSPACE,
                        "installationId": INSTALLATION,
                        "machineId": "synthetic-enrolled-machine",
                        "oauthGrantId": GRANT,
                        "runtimeId": None,
                        "runtimeSessionId": SESSION,
                    },
                    "subjectVersion": "55555555-5555-4555-8555-555555555555",
                    "challengeSequence": self.sequence,
                    "keyThumbprint": self.agent_key.public_jwk_thumbprint,
                    "localContext": issue["localContext"],
                    "issuedAtMs": now,
                    "expiresAtMs": now + 60_000,
                },
                "challenge",
            )
            return copy.deepcopy(self.pending)
        if path == "/api/guard/runtime/policy-consumer/observations":
            return self.accept_observation(request)
        return super().response_for_request(path, request)

    def configure_profile_stage(self, effect: str) -> None:
        if effect not in {"block", "review", "allow"}:
            raise ValueError("unsupported_profile_stage")
        config = 'mode="enforce"\ndefault_action="review"\n'
        if effect == "allow":
            # An explicit artifact review is satisfiable by the exact signed
            # allow. A bare review default relaxes verified pwd to warn, which
            # signed allow correctly preserves rather than claiming to change.
            config += '[artifacts."codex:project:Bash"]\naction="review"\n'
        (self.store.guard_home / "config.toml").write_text(config, encoding="utf-8")

    def accept_observation(self, request: object) -> dict[str, JsonValue]:
        envelope = validate_wire(request, "observation")
        body = mapping(envelope["body"])
        now = int(time.time() * 1000)
        pending_expiry = self.pending["expiresAtMs"] if self.pending is not None else None
        if (
            self.pending is None
            or body["challenge"] != self.pending
            or type(pending_expiry) is not int
            or now >= pending_expiry
        ):
            raise ConsumerReadinessError()
        private = serialization.load_pem_private_key(self.agent_key.private_key_pem.encode(), password=None)
        assert isinstance(private, ec.EllipticCurvePrivateKey)
        signature = envelope["signature"]
        assert isinstance(signature, str)
        raw = base64.urlsafe_b64decode(signature + "==")
        private.public_key().verify(
            encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            signing_bytes(body),
            ec.ECDSA(hashes.SHA256()),
        )
        challenge = self.pending
        self.pending = None
        self.accepted.append(copy.deepcopy(envelope))
        until = None
        if body["readiness"] == "ready_for_delivery":
            snapshot_expiry = mapping(body["publisherSnapshot"])["expiresAtMs"]
            challenge_expiry = challenge["expiresAtMs"]
            assert type(snapshot_expiry) is int and type(challenge_expiry) is int
            until = min(challenge_expiry, snapshot_expiry)
        return validate_wire(
            {
                "contractVersion": "guard.consumer-readiness-ack.v2",
                "challengeId": challenge["challengeId"],
                "subjectVersion": challenge["subjectVersion"],
                "challengeSequence": challenge["challengeSequence"],
                "readiness": body["readiness"],
                "receivedAtMs": now,
                "validUntilMs": until,
            },
            "ack",
        )
