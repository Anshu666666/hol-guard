"""Closed builtin projections; private values never enter diagnostic rows."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

MAX_NODES = 32768
MAX_TEXT = 512 * 1024


def frozen(value: Any) -> Any:
    remaining = [MAX_NODES, MAX_TEXT]

    def copy(item: Any, depth: int) -> Any:
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 16:
            raise ValueError("projection_bound")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int and abs(item) < 2**64:
            return item
        if kind is float and math.isfinite(item):
            return item
        if kind is str:
            remaining[1] -= len(item.encode("utf-8"))
            if remaining[1] < 0:
                raise ValueError("projection_bound")
            return item
        if kind in {list, tuple}:
            if len(item) > remaining[0]:
                raise ValueError("projection_bound")
            return [copy(child, depth + 1) for child in item]
        if kind is dict:
            if len(item) * 2 > remaining[0] or any(type(key) is not str for key in item):
                raise ValueError("projection_shape")
            return {copy(key, depth + 1): copy(child, depth + 1) for key, child in item.items()}
        raise ValueError("projection_shape")

    return copy(value, 0)


def fingerprint(value: Any) -> str:
    raw = json.dumps(frozen(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_TEXT:
        raise ValueError("projection_bound")
    return hashlib.sha256(raw).hexdigest()


def snapshot(value: Any, *, full_digest: bool = True) -> dict[str, Any]:
    if value is None:
        return {"kind": "none"}
    if type(value) is not dict:
        raise ValueError("snapshot_shape")
    result: dict[str, Any] = {"kind": "dict"}
    for key in ("generation", "issued_at_ms", "expires_at_ms"):
        present = key in value
        item = value.get(key)
        if present and (type(item) is not int or not 0 <= item < 2**64):
            raise ValueError("snapshot_number")
        result[key] = item
    for key in ("policy_digest", "runtime_identity"):
        item = value.get(key)
        if item is not None and (
            type(item) is not str or len(item) != 64 or any(c not in "0123456789abcdef" for c in item)
        ):
            raise ValueError("snapshot_digest")
        result[key] = item
    mode = value.get("mode")
    if (mode is not None and type(mode) is not str) or mode not in {None, "enforce", "monitor", "off"}:
        raise ValueError("snapshot_mode")
    result["mode"] = mode
    result["command_present"] = "command_extensions" in value
    result["command_bound"] = value.get("command_extensions_bound") is True
    if result["command_present"]:
        result["command_sha256"] = fingerprint(value["command_extensions"])
    policy = value.get("effective_policy")
    result["effective_kind"] = "none" if policy is None else "dict" if type(policy) is dict else "other"
    if policy is not None and type(policy) is not dict:
        raise ValueError("effective_shape")
    if type(policy) is dict:
        for key, allowed in (
            ("default_action", {"allow", "review", "block", "deny", "warn"}),
            ("subprocess_action", {"allow", "review", "block", "deny", "warn"}),
            ("sandbox_analysis", {"strict", "balanced", "off"}),
        ):
            item = policy.get(key)
            if type(item) is not str or item not in allowed:
                raise ValueError("effective_enum")
            result[key] = item
    if full_digest:
        result["snapshot_sha256"] = fingerprint(value)
    return result


def outcome(value: Any) -> dict[str, Any]:
    if value is None:
        return {"kind": "none"}
    if type(value) is bool:
        return {"kind": "bool", "value": value}
    return {"kind": "other"}


def error_kind(error: BaseException) -> str:
    for kind in (RuntimeError, ValueError, TypeError, TimeoutError, OSError):
        if type(error) is kind:
            return kind.__name__
    return "other"


def error_presence(value: Any) -> dict[str, Any]:
    if value is None:
        return {"kind": "none", "nonempty": False}
    if type(value) is not str:
        raise ValueError("error_shape")
    # No arbitrary error text is serialized, even if it begins native_.
    return {"kind": "str", "nonempty": bool(value.strip())}
