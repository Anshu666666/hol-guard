"""Content-free durable bindings for a resident-issued approval challenge.

This state is transport continuity only. It never verifies a browser assertion
or grants permission; the live resident must still validate and consume it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .native_approval_v4_protocol import decode_native_approval_v4_challenge
from .stable_json import stable_json_serialize

if TYPE_CHECKING:
    from .store import GuardStore

_SCHEMA = "guard-native-approval-state.v1"
_DOMAIN = b"guard-native-approval-state.v1\0"
_HEX = re.compile(r"[0-9a-f]{64}")
_SNAPSHOT_FIELDS = frozenset(
    ("generation", "policy_digest", "runtime_identity", "source_input_digest", "resident_generation", "mode")
)
_BINDING_FIELDS = (
    "request_id",
    "harness",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "action_identity",
    "queue_group_id",
    "created_at",
    "action_envelope_json",
)


def _canonical(value: object) -> str:
    return stable_json_serialize(value)


def _valid_snapshot(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or set(value) != _SNAPSHOT_FIELDS:
        return None
    if value.get("mode") != "enforce":
        return None
    for key in ("generation", "resident_generation"):
        item = value.get(key)
        if type(item) is not int or not 0 < item <= (1 << 53) - 1:
            return None
    for key in ("policy_digest", "runtime_identity", "source_input_digest"):
        item = value.get(key)
        if not isinstance(item, str) or _HEX.fullmatch(item) is None:
            return None
    return dict(value)


def _row_binding(row: Mapping[str, object]) -> str:
    value = {key: row.get(key) for key in _BINDING_FIELDS}
    envelope = value["action_envelope_json"]
    if isinstance(envelope, str):
        try:
            envelope = json.loads(envelope)
        except (TypeError, ValueError) as error:
            raise ValueError("native_approval_row_invalid") from error
    value["action_envelope_json"] = envelope
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class NativeApprovalState:
    """Immutable, detached bytes; no original hook payload is retained."""

    challenge_json: str
    snapshot_json: str
    row_digest: str
    oauth_digest: str

    @property
    def challenge(self) -> dict[str, object]:
        return cast(dict[str, object], json.loads(self.challenge_json))

    @property
    def snapshot(self) -> dict[str, object]:
        return cast(dict[str, object], json.loads(self.snapshot_json))


def seal_native_approval_state(
    store: GuardStore,
    *,
    challenge: dict[str, object],
    snapshot: dict[str, object],
    request_row: Mapping[str, object],
    oauth_binding: Mapping[str, object],
) -> str:
    parsed = decode_native_approval_v4_challenge(challenge)
    checked = _valid_snapshot(snapshot)
    if parsed is None or checked is None:
        raise ValueError("native_approval_state_invalid")
    if any(
        parsed[field] != checked[key]
        for field, key in (
            ("policy_generation", "generation"),
            ("policy_digest", "policy_digest"),
            ("runtime_identity", "runtime_identity"),
        )
    ):
        raise ValueError("native_approval_snapshot_mismatch")
    if parsed["request_id"] != request_row.get("request_id") or parsed["harness"] != request_row.get("harness"):
        raise ValueError("native_approval_request_mismatch")
    if request_row.get("artifact_hash") != parsed["request_digest"]:
        raise ValueError("native_approval_request_mismatch")
    key, key_id = store._policy_integrity_secret_material(create=True)
    if key is None or key_id is None:
        raise ValueError("native_approval_local_key_unavailable")
    unsigned = {
        "schema": _SCHEMA,
        "keyId": key_id,
        "challenge": parsed,
        "snapshot": checked,
        "requestBindingDigest": _row_binding(request_row),
        "oauthBindingDigest": hashlib.sha256(_canonical(dict(oauth_binding)).encode("utf-8")).hexdigest(),
    }
    signature = hmac.new(key, _DOMAIN + _canonical(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
    return _canonical({**unsigned, "signature": signature})


def verified_native_approval_state(
    store: GuardStore,
    raw: object,
    *,
    request_row: Mapping[str, object],
    oauth_binding: Mapping[str, object],
) -> NativeApprovalState | None:
    if not isinstance(raw, str):
        return None
    try:
        if len(raw.encode("utf-8")) > 32_768:
            return None
        state = json.loads(raw)
    except (ValueError, TypeError, UnicodeError):
        return None
    if not isinstance(state, dict) or set(state) != {
        "schema",
        "keyId",
        "challenge",
        "snapshot",
        "requestBindingDigest",
        "oauthBindingDigest",
        "signature",
    }:
        return None
    if (
        state.get("schema") != _SCHEMA
        or not isinstance(state.get("signature"), str)
        or _HEX.fullmatch(state["signature"]) is None
    ):
        return None
    key, key_id = store._policy_integrity_secret_material(create=False)
    if key is None or key_id is None or state["keyId"] != key_id:
        return None
    unsigned = {name: value for name, value in state.items() if name != "signature"}
    expected = hmac.new(key, _DOMAIN + _canonical(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, state["signature"]):
        return None
    challenge = decode_native_approval_v4_challenge(state["challenge"])
    snapshot = _valid_snapshot(state["snapshot"])
    if challenge is None or snapshot is None:
        return None
    try:
        row = _row_binding(request_row)
    except (ValueError, UnicodeError):
        return None
    oauth_digest = hashlib.sha256(_canonical(dict(oauth_binding)).encode("utf-8")).hexdigest()
    if state["requestBindingDigest"] != row or state["oauthBindingDigest"] != oauth_digest:
        return None
    return NativeApprovalState(
        _canonical(challenge),
        _canonical(snapshot),
        row,
        oauth_digest,
    )
