"""Real fixture-root enrollment and passkey signing for a source-built resident."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def enroll_fixture_passkey(binary: Path, guard_home: Path) -> tuple[Ed25519PrivateKey, bytes]:
    key_path = Path(os.environ["HGP_NATIVE_APPROVAL_FIXTURE_ROOT_KEY"])
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    root = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    public_root = root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert public_root.hex() == os.environ["HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX"]
    assert hashlib.sha256(public_root).hexdigest() == os.environ["HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX"]
    state = guard_home / "native-runtime"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.chmod(0o700)
    request = json.loads(
        subprocess.check_output(
            [
                str(binary),
                "prepare-approval-v4-enrollment",
                "--state-dir",
                str(state),
                "--rp-id",
                "example.invalid",
                "--origin",
                "https://example.invalid",
            ],
            timeout=30,
        )
    )
    assert request["schema"] == "guard-native-approval-enrollment-request.v4"
    passkey = Ed25519PrivateKey.generate()
    credential = os.urandom(32)
    public = passkey.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # Canonical CBOR COSE OKP map: kty=OKP, alg=EdDSA, crv=Ed25519, x=public key.
    cose = bytes.fromhex("a4010103272006215820") + public
    record = {
        "schema": "guard-native-approval-authority.v4",
        "version": 4,
        "key_id": hashlib.sha256(cose).hexdigest(),
        "rp_id": request["rp_id"],
        "origin": request["origin"],
        "credential_id": credential.hex(),
        "cose_public_key": cose.hex(),
        "algorithm": -8,
        "device_binding": request["device_binding"],
        "installation_binding": request["installation_binding"],
        "enrollment_generation": request["enrollment_generation"],
        "previous_key_id": None,
        "status": "active",
    }
    signature = root.sign(b"guard-native-approval-webauthn-enrollment-v4\0" + _canonical(record))
    record["enrollment_signature"] = signature.hex()
    record_path = guard_home / "fixture-approval-authority.json"
    fd = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(_canonical(record))
    subprocess.run(
        [str(binary), "enroll-approval-v4-authority", "--state-dir", str(state), "--record", str(record_path)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    record_path.unlink()
    return passkey, credential


def sign_fixture_assertion(
    challenge: dict[str, object], key: Ed25519PrivateKey, credential: bytes
) -> dict[str, object]:
    webauthn = challenge["webauthn"]
    assert isinstance(webauthn, dict)
    assert webauthn["credential_id"] == _b64(credential)
    client = _canonical(
        {"type": "webauthn.get", "challenge": webauthn["challenge"], "origin": webauthn["origin"], "crossOrigin": False}
    )
    authenticator = hashlib.sha256(str(webauthn["rp_id"]).encode()).digest() + bytes([0x05]) + (1).to_bytes(4, "big")
    assertion = {
        "id": _b64(credential),
        "rawId": _b64(credential),
        "type": "public-key",
        "response": {
            "authenticatorData": _b64(authenticator),
            "clientDataJSON": _b64(client),
            "signature": _b64(key.sign(authenticator + hashlib.sha256(client).digest())),
            "userHandle": None,
        },
    }
    return {"schema": "guard-native-approval-proof.v4", "challenge": challenge, "assertion": assertion}


def connected_fixture_store(tmp_path: Path):
    """Genuine synthetic credentials with receiver-compatible UUID identities."""
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.guard_oauth_token_support import oauth_binding_access_token
    from tests.guard_review_signing_helpers import review_trusted_keyring_payload

    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    grant_id, workspace_id = str(uuid4()), str(uuid4())
    machine_id = store.get_or_create_installation_id()
    now = datetime.now(timezone.utc).isoformat()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-fixture-refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id=grant_id,
        machine_id=machine_id,
        runtime_id="hol-guard",
        device_id=dpop.public_jwk_thumbprint,
        workspace_id=workspace_id,
        access_token=oauth_binding_access_token(
            device_id=dpop.public_jwk_thumbprint,
            grant_id=grant_id,
            machine_id=machine_id,
            workspace_id=workspace_id,
        ),
        access_token_expires_at="2099-01-01T00:00:00+00:00",
        now=now,
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        review_trusted_keyring_payload(workspace_id=workspace_id),
        now,
    )
    enable_exact_cloud_review(store, issuer="synthetic-fixture-explicit-consent", now=now)
    return store
