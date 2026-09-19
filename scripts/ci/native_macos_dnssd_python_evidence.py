"""Strict outer Python phases around the unchanged finite DNS-SD protocol."""

from __future__ import annotations

import json
import re
from typing import Any

from scripts.ci.native_macos_dnssd_python_child import CALL_POLICY, MODES
from scripts.ci.native_macos_resolver_evidence import parse_metadata

RUNTIME_KEYS = {"python_sha256", "socket_sha256", "ctypes_sha256", "child_source_sha256", "dnssd_child_source_sha256"}
PREFIX_FAILURES = (
    frozenset(),
    {"runtime_binding", "before_load"},
    {"before_load", "after_load"},
    {"after_load"},
    {"after_load", "call_enter"},
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _runtime(row: dict[str, Any], expected: dict[str, str]) -> bool:
    return set(expected) == RUNTIME_KEYS and all(
        isinstance(row.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", row[key]) and row[key] == expected[key]
        for key in RUNTIME_KEYS
    )


def _image(row: dict[str, Any], phase: str, bridge: dict[str, Any]) -> bool:
    return (
        set(row) == {"kind", "phase", "bridge_uuid", "libinfo_uuid", "dnssd_uuid"}
        and row.get("kind") == "bridge_image"
        and row["phase"] == phase
        and all(
            isinstance(row[key], str) and re.fullmatch(r"[0-9a-f]{32}", row[key])
            for key in ("bridge_uuid", "libinfo_uuid", "dnssd_uuid")
        )
        and row["bridge_uuid"] == bridge.get("uuid")
    )


def parse_comparison(
    data: bytes, mode: str, pid: int | None, runtime: dict[str, str], bridge: dict[str, Any]
) -> dict[str, Any]:
    rejected: dict[str, Any] = {"valid": False, "complete": False, "loopback_label": False, "records": []}
    if mode not in MODES or len(data) > 16 * 1024:
        return rejected
    lines = data.splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b"\n"))
    if partial:
        lines.pop()
    if not 0 < len(lines) <= 28:
        return rejected
    try:
        rows = [json.loads(line.decode("ascii"), object_pairs_hook=_object) for line in lines]
    except (ValueError, UnicodeError, RecursionError):
        return rejected
    if any(not isinstance(row, dict) for row in rows):
        return rejected

    def admitted(complete: bool = False, loopback: bool = False) -> dict[str, Any]:
        return {
            "valid": True,
            "complete": complete and not partial,
            "partial_line": partial,
            "loopback_label": loopback and complete and not partial,
            "records": rows,
        }

    failure = rows[-1] if rows[-1].get("kind") == "failure" else None
    active = rows[:-1] if failure else rows
    if failure and (
        set(failure) != {"kind", "stage", "error_type"}
        or not isinstance(failure["stage"], str)
        or not isinstance(failure["error_type"], str)
        or failure["error_type"] not in {"OSError", "ValueError", "AttributeError"}
    ):
        return rejected
    for index, row in enumerate(active[:5]):
        if index == 0:
            if (
                set(row) != {"kind", "mode", "pid", "call_policy"} | RUNTIME_KEYS
                or row.get("kind") != "python_identity"
                or row["mode"] != mode
                or type(row["pid"]) is not int
                or not 0 < row["pid"] < 2**31
                or row["pid"] != pid
                or row["call_policy"] != CALL_POLICY
                or not _runtime(row, runtime)
            ):
                return rejected
        elif index == 3:
            if not _image(row, "before", bridge):
                return rejected
        elif row != {"kind": "phase", "phase": {1: "before_load", 2: "after_load", 4: "call_enter"}[index]}:
            return rejected
    if len(active) < 5:
        if not active or (failure and failure["stage"] not in PREFIX_FAILURES[len(active)]):
            return rejected
        return admitted()
    tail = active[5:]
    call_return = next((i for i, row in enumerate(tail) if row.get("kind") == "phase"), len(tail))
    inner, suffix = tail[:call_return], tail[call_return:]
    parsed = None
    if inner:
        encoded = b"".join(json.dumps(row).encode("ascii") + b"\n" for row in inner)
        parsed = parse_metadata(encoded, mode, pid)
        if (
            not parsed["valid"]
            or inner[0]["cpu_type"] != bridge.get("cpu_type")
            or any(inner[0][key] != active[3][key] for key in ("libinfo_uuid", "dnssd_uuid"))
        ):
            return rejected
    if not suffix:
        allowed = {"call_enter", "call_return"} if parsed and parsed["complete"] else {"call_enter"}
        if failure and failure["stage"] not in allowed:
            return rejected
        return admitted()
    if not parsed or not parsed["complete"] or len(suffix) > 3:
        return rejected
    if suffix[0] != {"kind": "phase", "phase": "call_return"}:
        return rejected
    if len(suffix) > 1 and (
        not _image(suffix[1], "after", bridge)
        or any(suffix[1][key] != active[3][key] for key in ("bridge_uuid", "libinfo_uuid", "dnssd_uuid"))
    ):
        return rejected
    if len(suffix) > 2:
        final = suffix[2]
        result = inner[-1]
        code = 2 if result["error"] or result["callback_error"] or result["overflow"] else 0
        if (
            set(final) != {"kind", "return_code", "bridge_sha256"} | RUNTIME_KEYS
            or final.get("kind") != "python_complete"
            or type(final["return_code"]) is not int
            or final["return_code"] != code
            or final["bridge_sha256"] != bridge.get("sha256")
            or not _runtime(final, runtime)
            or failure
        ):
            return rejected
    if failure and failure["stage"] not in ({"call_return"} if len(suffix) == 1 else {"call_return", "final_binding"}):
        return rejected
    return admitted(len(suffix) == 3 and not failure, bool(parsed["loopback_label"]))
