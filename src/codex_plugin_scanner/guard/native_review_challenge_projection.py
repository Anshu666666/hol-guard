"""Project a complete resident challenge without creating approval authority.

The existing V4 parser checks transport shape. The resident still owns issuance,
WebAuthn verification, currentness, and consumption of the resulting proof.
"""

from __future__ import annotations

import json
import re
from typing import cast

from .native_approval_protocol import decode_native_approval_v4_challenge

_CHALLENGE_KEY = "nativeApprovalChallenge"
_DIRECT_KEYS = (_CHALLENGE_KEY, "native_approval_challenge")
_NATIVE_KEYS = (*_DIRECT_KEYS, "nativeApproval", "native_approval")
_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_INVALID = "native_review_challenge_invalid"


def _has_native_json_key(value: str) -> bool:
    # Also recognize escaped keys in malformed persisted JSON. Legacy malformed
    # descriptive envelopes retain their existing display-only fallback.
    for match in _JSON_STRING.finditer(value):
        if not value[match.end() :].lstrip().startswith(":"):
            continue
        try:
            if json.loads(match.group()) in _NATIVE_KEYS:
                return True
        except ValueError:
            continue
    return False


def _envelope(value: object) -> dict[str, object]:
    if type(value) is dict:
        return cast(dict[str, object], value)
    if not isinstance(value, str):
        return {}
    duplicate = False

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal duplicate
        result: dict[str, object] = {}
        for key, item in items:
            duplicate |= key in result
            result[key] = item
        return result

    try:
        parsed: object = json.loads(value, object_pairs_hook=pairs)
    except (ValueError, RecursionError):
        if _has_native_json_key(value):
            raise ValueError(_INVALID) from None
        return {}
    if type(parsed) is not dict:
        if _has_native_json_key(value):
            raise ValueError(_INVALID)
        return {}
    envelope = cast(dict[str, object], parsed)
    if duplicate and _has_native_json_key(value):
        raise ValueError(_INVALID)
    return envelope


def _detached_challenge(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(_INVALID)
    try:
        encoded = json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        challenge = decode_native_approval_v4_challenge(json.loads(encoded))
    except (ValueError, TypeError, RecursionError):
        raise ValueError(_INVALID) from None
    if challenge is None:
        raise ValueError(_INVALID)
    return challenge


def project_native_review_challenge(request_row: dict[str, object]) -> dict[str, object] | None:
    """Return the exact nested challenge, or refuse an ambiguous native request.

    Only the annotation in the persisted action envelope can supply a challenge.
    Redundant direct aliases must agree; wrapper aliases are not producers.
    """
    envelope = _envelope(request_row.get("action_envelope_json"))
    present = any(key in source for source in (request_row, envelope) for key in _NATIVE_KEYS)
    if not present:
        return None
    if _CHALLENGE_KEY not in envelope:
        raise ValueError(_INVALID)
    challenge = _detached_challenge(envelope[_CHALLENGE_KEY])
    for source in (request_row, envelope):
        for key in _NATIVE_KEYS:
            if key not in source:
                continue
            if key not in _DIRECT_KEYS or _detached_challenge(source[key]) != challenge:
                raise ValueError(_INVALID)
    if challenge["request_id"] != request_row.get("request_id") or challenge["harness"] != request_row.get("harness"):
        raise ValueError(_INVALID)
    return challenge
