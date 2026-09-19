"""Admit only the fixed lookup helper's bounded, typed metadata protocol."""

from __future__ import annotations

import json
import re
from typing import Any

MODES = ("dns_simple", "dns_shared", "libc_addr", "libc_name", "python_fqdn")
_UUID = re.compile(r"[0-9a-f]{32}\Z")


def _integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _keys(row: dict[str, Any], keys: str) -> bool:
    return set(row) == set(keys.split())


def _object(pairs):
    row = {}
    for key, value in pairs:
        if key in row:
            raise ValueError("duplicate field")
        row[key] = value
    return row


def parse_metadata(data: bytes, mode: str, pid: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": False, "complete": False, "loopback_label": False, "records": []}
    if mode not in MODES or len(data) > 16 * 1024:
        return result
    lines = data.splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b"\n"))
    if partial:
        lines.pop()
    if not lines or len(lines) > 19:
        return result | {"partial_line": partial}
    rows: list[dict[str, Any]] = []
    try:
        for line in lines:
            row = json.loads(line.decode("ascii"), object_pairs_hook=_object)
            if not isinstance(row, dict):
                raise ValueError("invalid row")
            rows.append(row)
    except (ValueError, UnicodeError):
        return result
    identity = rows[0]
    python = mode == "python_fqdn"
    identity_keys = "kind mode pid" if python else "kind mode pid libinfo_uuid dnssd_uuid cpu_type cpu_subtype"
    if (
        not _keys(identity, identity_keys)
        or identity.get("kind") != "identity"
        or identity.get("mode") != mode
        or not _integer(identity.get("pid"), 1, 2**31 - 1)
        or identity["pid"] != pid
    ):
        return result
    if not python and (
        any(
            not isinstance(identity[key], str) or _UUID.fullmatch(identity[key]) is None
            for key in ("libinfo_uuid", "dnssd_uuid")
        )
        or any(not _integer(identity[key], -(2**31), 2**31 - 1) for key in ("cpu_type", "cpu_subtype"))
    ):
        return result
    dns = mode.startswith("dns_")
    query = None
    final = None
    callbacks = []
    for index, row in enumerate(rows[1:], 1):
        kind = row.get("kind")
        if kind == "query" and dns and index == 1:
            if (
                not _keys(row, "kind shared requested_flags error")
                or type(row["shared"]) is not bool
                or row["shared"] != (mode == "dns_shared")
                or not _integer(row["requested_flags"], 0, 2**32 - 1)
                or row["requested_flags"] != (0x15000 if mode == "dns_shared" else 0)
                or not _integer(row["error"], -(2**31), 2**31 - 1)
            ):
                return result
            query = row
        elif kind == "callback" and dns and query is not None and final is None:
            if (
                not _keys(
                    row,
                    "kind sequence flags interface_index error type class data_bytes question_matches loopback_label",
                )
                or not _integer(row["sequence"], 1, 16)
                or row["sequence"] != len(callbacks) + 1
                or any(not _integer(row[key], 0, 2**32 - 1) for key in ("flags", "interface_index"))
                or not _integer(row["error"], -(2**31), 2**31 - 1)
                or any(not _integer(row[key], 0, 65535) for key in ("type", "class", "data_bytes"))
                or any(type(row[key]) is not bool for key in ("question_matches", "loopback_label"))
            ):
                return result
            if row["loopback_label"] and not (
                row["error"] == 0
                and row["flags"] & 2
                and row["question_matches"]
                and row["type"] == 12
                and row["class"] == 1
                and row["data_bytes"] == 11
            ):
                return result
            if row["error"] and any(
                row[key]
                for key in (
                    "flags",
                    "interface_index",
                    "type",
                    "class",
                    "data_bytes",
                    "question_matches",
                    "loopback_label",
                )
            ):
                return result
            if query["error"]:
                return result
            callbacks.append(row)
        elif kind == "result" and index == len(rows) - 1:
            keys = "kind error callback_error callbacks overflow loopback_label" if dns else "kind error loopback_label"
            if (
                not _keys(row, keys)
                or not _integer(row["error"], -(2**31), 2**31 - 1)
                or type(row["loopback_label"]) is not bool
            ):
                return result
            if dns and (
                query is None
                or not _integer(row["callbacks"], 0, 16)
                or row["callbacks"] != len(callbacks)
                or type(row["overflow"]) is not bool
                or not _integer(row["callback_error"], -(2**31), 2**31 - 1)
                or row["loopback_label"] != any(item["loopback_label"] for item in callbacks)
                or row["callback_error"] != next((item["error"] for item in reversed(callbacks) if item["error"]), 0)
            ):
                return result
            final = row
        else:
            return result
    complete = final is not None and not partial
    success = complete and final is not None and final["error"] == 0 and final["loopback_label"]
    if dns:
        success = (
            success
            and final is not None
            and query is not None
            and query["error"] == 0
            and final["callback_error"] == 0
            and not final["overflow"]
            and bool(callbacks)
            and not callbacks[-1]["flags"] & 1
        )
    return {
        "valid": True,
        "complete": complete,
        "partial_line": partial,
        "loopback_label": bool(success),
        "records": rows,
    }
