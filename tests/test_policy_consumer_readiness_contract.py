"""Cross-language wire vectors and finite parsing/cryptographic refusal controls."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from codex_plugin_scanner.guard.policy_consumer_readiness_contract import (
    MAX_WIRE_BYTES,
    ConsumerReadinessError,
    mapping,
    parse_wire,
    signing_bytes,
    validate_wire,
)
from codex_plugin_scanner.guard.policy_document import JsonValue, canonical_json_bytes

_FIXTURES = Path(__file__).parent / "fixtures" / "policy-consumer-readiness-v2"
_DATA = cast(dict[str, JsonValue], json.loads((_FIXTURES / "vectors.json").read_text("utf-8")))
_VECTORS = cast(list[dict[str, JsonValue]], _DATA["vectors"])
_NEGATIVE = cast(list[dict[str, JsonValue]], _DATA["negative"])


def _text(value: JsonValue) -> str:
    assert isinstance(value, str)
    return value


def _public_key() -> ec.EllipticCurvePublicKey:
    jwk = mapping(_DATA["publicJwk"])
    x = int.from_bytes(base64.urlsafe_b64decode(_text(jwk["x"]) + "="), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(_text(jwk["y"]) + "="), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


@pytest.mark.parametrize("vector", _VECTORS, ids=[_text(v["name"]) for v in _VECTORS])
def test_shared_signing_bytes_and_actual_p256_verification(vector: dict[str, JsonValue]) -> None:
    body = mapping(vector["body"])
    envelope: dict[str, JsonValue] = {"body": body, "signature": vector["signature"]}
    assert parse_wire(canonical_json_bytes(envelope), "observation") == envelope
    assert canonical_json_bytes(body).decode() == vector["canonicalBody"]
    actual = signing_bytes(body)
    assert actual == base64.b64decode(_text(vector["signingBytesBase64"]), validate=True)
    assert hashlib.sha256(actual).hexdigest() == vector["signingSha256"]
    raw = base64.urlsafe_b64decode(_text(vector["signature"]) + "==")
    signature = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    key = _public_key()
    key.verify(signature, actual, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        key.verify(signature, actual + b" ", ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("vector", _NEGATIVE, ids=[_text(v["name"]) for v in _NEGATIVE])
def test_shared_invalid_wire_is_rejected_before_signature(vector: dict[str, JsonValue]) -> None:
    with pytest.raises(ConsumerReadinessError, match=r"^guard_consumer_readiness_invalid$"):
        parse_wire(_text(vector["text"]).encode(), "observation")


def test_schema_packaging_preserves_shared_exact_bytes() -> None:
    import codex_plugin_scanner.guard.policy_consumer_readiness_contract as contract

    packaged = Path(contract.__file__).parent / "schemas" / "policy-consumer-readiness-v2.json"
    assert packaged.read_bytes() == (_FIXTURES / "schema.json").read_bytes()
    assert hashlib.sha256(packaged.read_bytes()).hexdigest() == (
        "2ea4047f3b55cb4d8ffa1ad610cb802b310423ea923bb09514489f34eb821ead"
    )
    assert _DATA["fixtureRevision"] == 2
    assert len(_VECTORS) == 3 and len(_NEGATIVE) == 21
    assert set(mapping(_DATA["publicJwk"])) == {"kty", "crv", "x", "y"}


@pytest.mark.parametrize("kind", ["issue", "challenge", "ack"])
def test_shared_outer_contracts(kind: str) -> None:
    value = _DATA[kind]
    if kind == "issue":
        assert parse_wire(canonical_json_bytes(value), "issue") == value
    elif kind == "challenge":
        assert parse_wire(canonical_json_bytes(value), "challenge") == value
    else:
        assert parse_wire(canonical_json_bytes(value), "ack") == value


def test_exact_byte_limit_and_private_errors() -> None:
    raw = canonical_json_bytes(_DATA["challenge"])
    padded = raw + b" " * (MAX_WIRE_BYTES - len(raw))
    assert parse_wire(padded, "challenge") == _DATA["challenge"]
    for invalid in (
        padded + b" ",
        b"\xff",
        b'{"private-canary": NaN}',
        b'{"private-canary": -0}',
        b"[" * 2000 + b"0" + b"]" * 2000,
    ):
        with pytest.raises(ConsumerReadinessError) as caught:
            parse_wire(invalid, "challenge")
        assert str(caught.value) == "guard_consumer_readiness_invalid"


def test_unavailable_ack_never_retains_positive_expiry() -> None:
    ack = dict(mapping(_DATA["ack"]))
    ack["readiness"] = "unavailable"
    with pytest.raises(ConsumerReadinessError):
        validate_wire(ack, "ack")
    ack["validUntilMs"] = None
    assert validate_wire(ack, "ack") == ack


def test_boolean_is_not_integer_and_signature_encoding_is_canonical() -> None:
    body = json.loads(json.dumps(_VECTORS[0]["body"]))
    body["runtimeProtocolVersion"] = True
    with pytest.raises(ConsumerReadinessError):
        validate_wire({"body": body, "signature": _VECTORS[0]["signature"]}, "observation")
    signature = _text(_VECTORS[0]["signature"])
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # Change only unused low bits of the last base64url sextet.
    noncanonical = signature[:-1] + alphabet[alphabet.index(signature[-1]) ^ 1]
    with pytest.raises(ConsumerReadinessError):
        validate_wire({"body": _VECTORS[0]["body"], "signature": noncanonical}, "observation")


def test_fixed_profile_is_exact_three_product_commands_with_distinct_agent_identity() -> None:
    from codex_plugin_scanner.guard.exact_command import exact_command_sha256

    profile = json.loads((_FIXTURES / "profile.json").read_text("utf-8"))
    assert profile["profileId"] == "guard.native-scoped-shell-exact.v1"
    assert profile["agentHarness"] == "hol-guard" and profile["harness"] == "codex"
    assert profile["mode"] == "enforce" and profile["artifact"] == "codex:project:Bash"
    assert profile["effects"] == ["allow", "block", "review"] and profile["lifetime"] == "permanent"
    assert [row["text"] for row in profile["commands"]] == ["pwd", "true", "whoami"]
    digests = {row["sha256"] for row in profile["commands"]}
    assert len(digests) == 3
    for row in profile["commands"]:
        assert exact_command_sha256(row["text"]) == row["sha256"]
        assert exact_command_sha256(row["text"] + " ") not in digests
        assert exact_command_sha256(row["text"].upper()) not in digests
    for unsupported in ("printf arbitrary", "sh -c pwd", "pwd; true", "npm install left-pad"):
        assert exact_command_sha256(unsupported) not in digests
