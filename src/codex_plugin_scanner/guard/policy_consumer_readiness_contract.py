"""Strict, bounded consumer-readiness v2 values; no observation grants authority."""

from __future__ import annotations

import base64
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal, cast

from jsonschema import Draft202012Validator

from .policy_document import JsonValue, canonical_json_bytes

PROFILE_ID = "guard.native-scoped-shell-exact.v1"
PROTOCOL_CAPABILITY = "policy-consumer-readiness:guard.consumer-readiness-observation.v2"
SIGNING_DOMAIN = b"guard-consumer-readiness-observation-v2\x00"
MAX_WIRE_BYTES = 16_384
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_COUNTER = (1 << 64) - 1
WireKind = Literal["issue", "challenge", "ready", "unavailable", "observation", "ack"]


class ConsumerReadinessError(ValueError):
    """Finite rejection which never contains a received value or credential."""

    def __init__(self) -> None:
        super().__init__("guard_consumer_readiness_invalid")


def _integer(text: str) -> int:
    if not text.isascii() or not text.isdigit() or (len(text) > 1 and text[0] == "0"):
        raise ConsumerReadinessError()
    value = int(text)
    if value > _MAX_SAFE_INTEGER:
        raise ConsumerReadinessError()
    return value


def _reject_number(_text: str) -> None:
    raise ConsumerReadinessError()


def _pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ConsumerReadinessError()
        result[key] = value
    return result


def _shape(value: object, depth: int = 0) -> None:
    if depth > 12:
        raise ConsumerReadinessError()
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER:
        return
    if type(value) is list:
        for child in cast(list[object], value):
            _shape(child, depth + 1)
        return
    if type(value) is dict:
        for key, child in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ConsumerReadinessError()
            _shape(child, depth + 1)
        return
    raise ConsumerReadinessError()


@lru_cache(maxsize=6)
def _validator(kind: WireKind) -> Draft202012Validator:
    # Only the packaged fixed schema is loaded. All references are local $defs;
    # neither a remote response nor a caller can choose a schema or reference.
    schema = json.loads((Path(__file__).parent / "schemas" / "policy-consumer-readiness-v2.json").read_text("utf-8"))
    return Draft202012Validator({"$defs": schema["$defs"], "$ref": f"#/$defs/{kind}"})


def mapping(value: JsonValue) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ConsumerReadinessError()
    return value


def _number(value: JsonValue) -> int:
    if type(value) is not int:
        raise ConsumerReadinessError()
    return value


def _counter(value: JsonValue) -> None:
    if type(value) is not str or int(value) > _MAX_COUNTER:
        raise ConsumerReadinessError()


def _challenge(value: dict[str, JsonValue]) -> None:
    if not 0 < _number(value["expiresAtMs"]) - _number(value["issuedAtMs"]) <= 60_000:
        raise ConsumerReadinessError()
    context = value["localContext"]
    if context is not None:
        _counter(mapping(context)["publisherEpoch"])


def _semantics(value: dict[str, JsonValue], kind: WireKind) -> None:
    if kind == "issue" and value["localContext"] is not None:
        _counter(mapping(value["localContext"])["publisherEpoch"])
    elif kind == "challenge":
        _challenge(value)
    elif kind == "observation":
        body = mapping(value["body"])
        _semantics(body, "ready" if body["readiness"] == "ready_for_delivery" else "unavailable")
        signature = value["signature"]
        assert isinstance(signature, str)
        raw = base64.urlsafe_b64decode(signature + "==")
        if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != signature:
            raise ConsumerReadinessError()
    elif kind in {"ready", "unavailable"}:
        challenge = mapping(value["challenge"])
        _challenge(challenge)
        if kind == "ready":
            context = mapping(challenge["localContext"])
            authority, snapshot = mapping(value["nativeAuthority"]), mapping(value["publisherSnapshot"])
            for counter in (
                value["residentGeneration"], authority["generationFloor"],
                snapshot["generation"], snapshot["residentGeneration"],
            ):
                _counter(counter)
            if (
                context["sourceInputDigest"] != snapshot["sourceInputDigest"]
                or authority["generationFloor"] != snapshot["generation"]
                or authority["policyDigest"] != snapshot["policyDigest"]
                or value["residentGeneration"] != snapshot["residentGeneration"]
                or _number(snapshot["expiresAtMs"]) <= _number(challenge["issuedAtMs"])
            ):
                raise ConsumerReadinessError()
    elif kind == "ack":
        if value["readiness"] == "ready_for_delivery":
            if _number(value["validUntilMs"]) <= _number(value["receivedAtMs"]):
                raise ConsumerReadinessError()
        elif value["validUntilMs"] is not None:
            raise ConsumerReadinessError()


def validate_wire(value: object, kind: WireKind) -> dict[str, JsonValue]:
    try:
        _shape(value)
        checked = mapping(cast(JsonValue, value))
        if len(canonical_json_bytes(checked)) > MAX_WIRE_BYTES:
            raise ConsumerReadinessError()
        if not _validator(kind).is_valid(checked):
            raise ConsumerReadinessError()
        _semantics(checked, kind)
        return checked
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ConsumerReadinessError() from None


def parse_wire(raw: bytes, kind: WireKind) -> dict[str, JsonValue]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
            raise ConsumerReadinessError()
        value: object = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_int=_integer, parse_float=_reject_number, parse_constant=_reject_number,
        )
        return validate_wire(value, kind)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ConsumerReadinessError() from None


def signing_bytes(body: object) -> bytes:
    candidate = mapping(cast(JsonValue, body))
    kind: WireKind = "ready" if candidate.get("readiness") == "ready_for_delivery" else "unavailable"
    return SIGNING_DOMAIN + canonical_json_bytes(validate_wire(candidate, kind))
