"""Bounded Mach-O and fixed-phase admission for the Python resolver comparison."""

from __future__ import annotations

import json
import re
import struct
from typing import Any

from scripts.ci.native_macos_resolver_evidence import parse_metadata

MODES = ("socket_addr", "socket_name", "c_addr", "c_name")
RUNTIME_KEYS = {"python_sha256", "socket_sha256", "ctypes_sha256", "child_source_sha256"}
# A fault may arise while emitting the last full marker or executing the
# immediately following operation. Later, unvisited stages cannot be asserted.
NATIVE_FAILURE_STAGES = (
    frozenset(),
    {"runtime_binding", "before_load"},
    {"before_load", "after_load"},
    {"after_load"},
    {"after_load", "call_enter"},
    {"call_enter"},
    {"call_enter"},
    {"call_enter", "call_return"},
    {"call_return"},
    {"call_return", "final_binding"},
)
SOCKET_FAILURE_STAGES = (
    frozenset(),
    {"runtime_binding", "call_enter"},
    {"call_enter"},
    {"call_enter", "call_return"},
    {"call_return", "final_binding"},
)
ERROR_KINDS = {"none", "herror", "gaierror", "OSError", "UnicodeError", "UnicodeDecodeError", "UnicodeEncodeError"}


def macho_identity(data: bytes) -> dict[str, Any]:
    if len(data) < 32 or len(data) > 1024 * 1024 + 32:
        raise ValueError("Mach-O size")
    magic, cpu, subtype, filetype, count, size, _flags, _reserved = struct.unpack("<IiiIIIII", data[:32])
    if magic != 0xFEEDFACF or filetype != 6 or not 0 < count <= 1024 or size != len(data) - 32:
        raise ValueError("Mach-O header")
    cursor, uuid = 32, None
    for _index in range(count):
        if len(data) - cursor < 8:
            raise ValueError("Mach-O command")
        command, length = struct.unpack("<II", data[cursor : cursor + 8])
        if length < 8 or length % 8 or length > len(data) - cursor:
            raise ValueError("Mach-O command size")
        if command == 0x1B:
            if length != 24 or uuid is not None:
                raise ValueError("Mach-O UUID")
            uuid = data[cursor + 8 : cursor + 24].hex()
        cursor += length
    if cursor != len(data) or uuid is None:
        raise ValueError("Mach-O UUID absent")
    return {"uuid": uuid, "cpu_type": cpu, "cpu_subtype": subtype}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _integer(value: Any) -> bool:
    return type(value) is int and -(2**31) <= value < 2**31


def _runtime(row: dict[str, Any], expected: dict[str, str]) -> bool:
    return set(expected) == RUNTIME_KEYS and all(
        isinstance(row.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", row[key]) and row[key] == expected[key]
        for key in RUNTIME_KEYS
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
    if not 0 < len(lines) <= 11:
        return rejected
    try:
        rows = [json.loads(line.decode("ascii"), object_pairs_hook=_object) for line in lines]
    except (ValueError, UnicodeError, RecursionError):
        return rejected
    if any(not isinstance(row, dict) for row in rows):
        return rejected
    native = mode.startswith("c_")
    order = (
        [
            "python_identity",
            "before_load",
            "after_load",
            "bridge_before",
            "call_enter",
            "identity",
            "result",
            "call_return",
            "bridge_after",
            "python_complete",
        ]
        if native
        else ["python_identity", "call_enter", "socket_result", "call_return", "python_complete"]
    )
    failure = False
    for index, row in enumerate(rows):
        if index >= len(order):
            return rejected
        stage = order[index]
        if row.get("kind") == "failure" and index > 0:
            if (
                index != len(rows) - 1
                or set(row) != {"kind", "stage", "error_type"}
                or not isinstance(row["stage"], str)
                or row["stage"] not in (NATIVE_FAILURE_STAGES if native else SOCKET_FAILURE_STAGES)[index]
                or not isinstance(row["error_type"], str)
                or row["error_type"] not in {"OSError", "ValueError", "AttributeError"}
            ):
                return rejected
            failure = True
            break
        if stage == "python_identity":
            if (
                set(row) != {"kind", "mode", "pid"} | RUNTIME_KEYS
                or row.get("kind") != stage
                or row["mode"] != mode
                or not _integer(row["pid"])
                or row["pid"] <= 0
                or row["pid"] != pid
                or not _runtime(row, runtime)
            ):
                return rejected
        elif stage in {"before_load", "after_load", "call_enter", "call_return"}:
            if row != {"kind": "phase", "phase": stage}:
                return rejected
        elif stage.startswith("bridge_"):
            phase = stage.removeprefix("bridge_")
            if (
                set(row) != {"kind", "phase", "bridge_uuid", "libinfo_uuid", "dnssd_uuid"}
                or row.get("kind") != "bridge_image"
                or row["phase"] != phase
                or any(
                    not isinstance(row[key], str) or re.fullmatch(r"[0-9a-f]{32}", row[key]) is None
                    for key in ("bridge_uuid", "libinfo_uuid", "dnssd_uuid")
                )
                or row["bridge_uuid"] != bridge["uuid"]
                or (
                    phase == "after"
                    and any(row[key] != rows[3][key] for key in ("bridge_uuid", "libinfo_uuid", "dnssd_uuid"))
                )
            ):
                return rejected
        elif stage in {"identity", "result"}:
            inner = [row] if stage == "identity" else [rows[5], row]
            encoded = b"".join(json.dumps(item).encode("ascii") + b"\n" for item in inner)
            parsed = parse_metadata(encoded, "libc_name" if mode == "c_name" else "libc_addr", pid)
            if not parsed["valid"] or (stage == "result" and not parsed["complete"]):
                return rejected
            identity = inner[0]
            if identity["cpu_type"] != bridge["cpu_type"] or any(
                identity[key] != rows[3][key] for key in ("libinfo_uuid", "dnssd_uuid")
            ):
                return rejected
        elif stage == "socket_result":
            if (
                set(row) != {"kind", "error_kind", "error_code", "loopback_label"}
                or row.get("kind") != stage
                or not isinstance(row["error_kind"], str)
                or row["error_kind"] not in ERROR_KINDS
                or not _integer(row["error_code"])
                or type(row["loopback_label"]) is not bool
                or (row["error_kind"] == "none" and row["error_code"] != 0)
                or (row["error_kind"] != "none" and row["loopback_label"])
            ):
                return rejected
        else:
            result = rows[6] if native else rows[2]
            expected_code = 2 if (result["error"] if native else result["error_kind"] != "none") else 0
            if (
                set(row) != {"kind", "return_code", "bridge_sha256"} | RUNTIME_KEYS
                or row.get("kind") != stage
                or not _integer(row["return_code"])
                or row["return_code"] != expected_code
                or row["bridge_sha256"] != (bridge["sha256"] if native else "")
                or not _runtime(row, runtime)
            ):
                return rejected
    complete = len(rows) == len(order) and not partial and not failure
    result = rows[6] if native and complete else rows[2] if complete else None
    return {
        "valid": True,
        "complete": complete,
        "partial_line": partial,
        "loopback_label": bool(complete and result and result["loopback_label"] and rows[-1]["return_code"] == 0),
        "records": rows,
    }
