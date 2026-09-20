"""Closed synthetic input projections and privacy-bounded result facts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from .capture import json_bytes

MAX_INPUT_BYTES = 32768
MAX_DEPTH = 6
_ROUTES = frozenset(
    {("claude-code", "PreToolUse"), ("claude-code", "PostToolUse"), ("codex", "PreToolUse"), ("codex", "PostToolUse")}
)
_SAMPLE = re.compile(r"priority-qualification-(-1|0|1|200000[01]|10000(?:0[0-9]|1[0-5]))\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_ID = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,255}\Z")
_BROWSER_PROCESS = "guard_codex_browser_wait_process"
_BROWSER_TIMEOUT = "guard_codex_browser_wait_timeout_seconds"
_TRANSFORMED = frozenset({"guard_remaining_ms", _BROWSER_PROCESS, _BROWSER_TIMEOUT})
_SAMPLES = (-1, 2000000, 2000001, 0, 1, *range(1000000, 1000016))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("phase_duplicate_json_key")
        result[key] = value
    return result


def parse_input(value: object) -> dict[str, Any]:
    if type(value) is not str or len(value) > MAX_INPUT_BYTES:
        raise ValueError("phase_input_invalid")
    if len(value.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("phase_input_limit")
    result = json.loads(value, object_pairs_hook=_pairs)
    if type(result) is not dict:
        raise ValueError("phase_input_object_required")
    return result


def _freeze(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [MAX_INPUT_BYTES]
    if depth > MAX_DEPTH:
        raise ValueError("phase_projection_depth")
    if type(value) is dict:
        if len(value) > 16 or any(type(key) is not str for key in value):
            raise ValueError("phase_projection_dictionary")
        result = ("dict", tuple((key, _freeze(value[key], depth=depth + 1, budget=budget)) for key in sorted(value)))
        budget[0] -= sum(len(key.encode("utf-8")) + 4 for key in value) + 2
    elif type(value) is list:
        if len(value) > 16:
            raise ValueError("phase_projection_list")
        result = ("list", tuple(_freeze(item, depth=depth + 1, budget=budget) for item in value))
        budget[0] -= len(value) + 2
    elif type(value) is str:
        if len(value) > MAX_INPUT_BYTES:
            raise ValueError("phase_projection_string")
        result = value
        budget[0] -= len(value.encode("utf-8")) + 2
    elif value is None or type(value) in (bool, int):
        if type(value) is int and not -(2**63) <= value < 2**63:
            raise ValueError("phase_projection_integer")
        result = value
        budget[0] -= 24
    else:
        raise ValueError("phase_projection_type")
    if budget[0] < 0:
        raise ValueError("phase_projection_bytes")
    return result


def _plain(value: Any) -> Any:
    if type(value) is not tuple:
        return value
    tag, items = value
    if tag == "dict":
        return {key: _plain(item) for key, item in items}
    if tag == "list":
        return [_plain(item) for item in items]
    raise ValueError("phase_frozen_tag_invalid")


@dataclass(frozen=True)
class FrozenInput:
    harness: str
    event: str
    sample: int
    case: str
    semantic: tuple[Any, ...]
    full: tuple[Any, ...]
    browser_fields_present: bool

    def coordinate(self) -> dict[str, object]:
        return {"harness": self.harness, "event": self.event, "sample": self.sample, "case": self.case}

    def facts(self) -> dict[str, object]:
        return {
            "semantic_sha256": hashlib.sha256(json_bytes(self.semantic)).hexdigest(),
            "entry_projection_sha256": hashlib.sha256(json_bytes(self.full)).hexdigest(),
            "browser_fields_present": self.browser_fields_present,
            "projection_valid": True,
        }


def freeze_input(payload: object, harness: str) -> FrozenInput:
    if type(payload) is not dict:
        raise ValueError("phase_payload_exact_dictionary_required")
    return _from_frozen(_freeze(payload), harness)


def _from_frozen(full: tuple[Any, ...], harness: str) -> FrozenInput:
    # Validate only the immutable snapshot; never reread live nested containers.
    payload = _plain(full)
    event = payload.get("hook_event_name")
    if type(event) is not str or (harness, event) not in _ROUTES:
        raise ValueError("phase_route_invalid")
    identifier = payload.get("tool_use_id")
    match = _SAMPLE.fullmatch(identifier) if type(identifier) is str else None
    if match is None:
        raise ValueError("phase_sample_invalid")
    sample = int(match[1])
    expected = {
        "hook_event_name",
        "tool_use_id",
        "tool_name",
        "guard_remaining_ms",
        "tool_input" if event == "PreToolUse" else "tool_response",
    }
    extra = set(payload) - expected
    if extra not in (set(), {_BROWSER_PROCESS, _BROWSER_TIMEOUT}):
        raise ValueError("phase_payload_fields_invalid")
    if set(payload) - extra != expected:
        raise ValueError("phase_payload_fields_missing")
    remaining = payload["guard_remaining_ms"]
    if type(remaining) is not int or not 1 <= remaining <= 60000:
        raise ValueError("phase_remaining_hint_invalid")
    if extra:
        process = payload[_BROWSER_PROCESS]
        timeout = payload[_BROWSER_TIMEOUT]
        if harness != "codex" or event != "PreToolUse":
            raise ValueError("phase_browser_route_invalid")
        if type(process) is not dict or set(process) != {"pid", "startToken"}:
            raise ValueError("phase_browser_identity_invalid")
        if type(process["pid"]) is not int or not 0 < process["pid"] < 2**31:
            raise ValueError("phase_browser_pid_invalid")
        token = process["startToken"]
        if (
            type(token) is not str
            or not 1 <= len(token) <= 256
            or not token.startswith(("posix:", "linux:", "windows:"))
        ):
            raise ValueError("phase_browser_token_invalid")
        if type(timeout) is not int or not 1 <= timeout <= 600:
            raise ValueError("phase_browser_timeout_invalid")
    if event == "PreToolUse":
        tool_input = payload["tool_input"]
        if payload["tool_name"] != "Bash" or type(tool_input) is not dict or set(tool_input) != {"command"}:
            raise ValueError("phase_pretool_shape_invalid")
        command = tool_input["command"]
        if command == "pwd":
            case = "benign"
        elif command == "rm -rf /":
            case = "block"
        else:
            raise ValueError("phase_pretool_content_unknown")
    else:
        response = payload["tool_response"]
        if payload["tool_name"] != "Read" or type(response) is not list or len(response) != 1:
            raise ValueError("phase_posttool_shape_invalid")
        item = response[0]
        if type(item) is not dict or set(item) != {"type", "text"} or item["type"] != "text":
            raise ValueError("phase_posttool_content_invalid")
        content = item["text"]
        benign = ("const guard_value = 1;\n" * 49)[:1024]
        block = ("gh" + "p_" + "b" * 30 + "\n" + "const guard_value = 1;\n" * 49)[:1024]
        if content == benign:
            case = "benign"
        elif content == block:
            case = "block"
        else:
            raise ValueError("phase_posttool_content_unknown")
    if case == "block" and sample != -1:
        raise ValueError("phase_case_sample_mismatch")
    semantic = ("dict", tuple((key, value) for key, value in full[1] if key not in _TRANSFORMED))
    return FrozenInput(harness, event, sample, case, semantic, full, bool(extra))


def exit_facts(entry: FrozenInput, payload: object) -> dict[str, object]:
    frozen = _freeze(payload)
    try:
        _from_frozen(frozen, entry.harness)
        valid = True
    except (ValueError, TypeError):
        valid = False
    return {
        "exit_projection_valid": valid,
        "exit_projection_sha256": hashlib.sha256(json_bytes(frozen)).hexdigest(),
        "mutation_detected": entry.full != frozen,
    }


def harness_from_params(params: object, default: object) -> str:
    if type(params) is not dict or type(default) is not str:
        raise ValueError("phase_harness_context_invalid")
    values = params.get("runtime-harness")
    if values is None:
        value = default
    elif type(values) is list and len(values) == 1 and type(values[0]) is str:
        value = values[0]
    else:
        raise ValueError("phase_harness_ambiguous")
    value = value.strip().lower().replace("_", "-")
    if value not in {"claude-code", "codex"}:
        raise ValueError("phase_harness_unknown")
    return value


def harness_from_query(query: object, default: object) -> str:
    if type(query) is not str or len(query) > MAX_INPUT_BYTES:
        raise ValueError("phase_query_invalid")
    return harness_from_params(parse_qs(query, max_num_fields=16), default)


def byte_facts(value: object, domain: str) -> dict[str, object]:
    if type(value) is not bytes or len(value) > 6 * 1024 * 1024:
        return {f"{domain}_available": False}
    return {
        f"{domain}_available": True,
        f"{domain}_bytes": len(value),
        f"{domain}_sha256": hashlib.sha256(value).hexdigest(),
    }


def receipt_identity(value: object) -> dict[str, object] | None:
    # This is a fixed identity projection, not a replacement receipt validator.
    if type(value) is not dict:
        return None
    decision = value.get("decision_id")
    request = value.get("request_id")
    digest = value.get("request_digest")
    if (
        type(decision) is not str
        or _HEX64.fullmatch(decision) is None
        or type(request) is not str
        or _REQUEST_ID.fullmatch(request) is None
        or type(digest) is not str
        or _HEX64.fullmatch(digest) is None
        or (value.get("harness"), value.get("event_name")) not in _ROUTES
        or value.get("authority") != "rust"
    ):
        return None
    return {
        "decision_id": decision,
        "request_id": request,
        "request_digest": digest,
        "harness": value["harness"],
        "event": value["event_name"],
    }


def edge_facts(value: object) -> dict[str, object]:
    if value is None:
        return {"edge_returned": False, "edge_identity": None}
    if type(value) is not dict:
        return {"edge_returned": True, "edge_identity": None}
    identity = receipt_identity(value.get("receipt"))
    result = value.get("result")
    decision = result.get("decision") if type(result) is dict else None
    return {
        "edge_returned": True,
        "edge_identity": identity,
        "edge_authority_rust": value.get("authority") == "rust",
        "edge_decision": decision if decision in {"allow", "deny"} else None,
    }


def declared_coordinates() -> list[dict[str, object]]:
    return [
        {"harness": harness, "event": event, "sample": sample, "case": case}
        for harness, event in (
            ("claude-code", "PreToolUse"),
            ("claude-code", "PostToolUse"),
            ("codex", "PreToolUse"),
            ("codex", "PostToolUse"),
        )
        for sample in _SAMPLES
        for case in (("benign", "block") if sample == -1 else ("benign",))
    ]
