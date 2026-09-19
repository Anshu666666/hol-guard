"""Admit only fixed query-time signal records around the unchanged endpoint protocol."""

from __future__ import annotations

import json
import re
from typing import Any

from scripts.ci.native_macos_dnssd_endpoint_evidence import parse_context
from scripts.ci.native_macos_dnssd_endpoint_record import decimal, integer
from scripts.ci.native_macos_dnssd_python_evidence import _object
from scripts.ci.native_macos_dnssd_sigpipe_child import CONDITIONS, RUNTIME_KEY

STATE_KEYS = {
    "kind", "sequence", "stage", "requested", "pid", "main_thread", "active",
    "action_rc", "action_errno", "handler_kind", "flags", "action_mask", "action_mask_rc",
    "blocked_mask", "blocked_mask_rc", "mask_rc", "set_called", "set_rc", "set_errno",
}
SOCKET_KEYS = {"kind", "sequence", "pid", "fd", "rc", "errno", "length", "integer_bytes", "value"}
STAGES = ("before", "installed", "query", "after", "restored")


def _state(row: dict[str, Any], sequence: int, pid: int, requested: int) -> None:
    stage = STAGES[sequence - 1]
    if (
        set(row) != STATE_KEYS or row["kind"] != "sigpipe_condition"
        or type(row["sequence"]) is not int or row["sequence"] != sequence or row["stage"] != stage
        or type(row["requested"]) is not int or row["requested"] != requested
        or type(row["pid"]) is not int or row["pid"] != pid
        or type(row["main_thread"]) is not int or row["main_thread"] != 1
        or type(row["active"]) is not bool or row["active"] != (stage not in ("before", "restored"))
        or type(row["set_called"]) is not bool or row["set_called"] != (stage in ("installed", "restored"))
        or any(type(row[key]) is not int or row[key] != 0 for key in (
            "action_rc", "action_errno", "action_mask_rc", "blocked_mask_rc", "mask_rc", "set_rc", "set_errno"
        ))
        or not integer(row["handler_kind"], 0, 1) or not integer(row["flags"])
        or not decimal(row["action_mask"]) or not decimal(row["blocked_mask"])
    ):
        raise ValueError("signal state")


def _conditions(
    rows: list[dict[str, Any]], pid: int, requested: int, context: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    indices = [index for index, row in enumerate(rows) if row["kind"] == "sigpipe_condition"]
    if len(indices) not in (3, 5):
        raise ValueError("signal state population")
    states = [rows[index] for index in indices]
    for sequence, row in enumerate(states, 1):
        _state(row, sequence, pid, requested)
    before = states[0]
    for row in states[1:]:
        expected_kind = before["handler_kind"] if row["stage"] == "restored" else requested
        if row["handler_kind"] != expected_kind or any(
            row[key] != before[key] for key in ("flags", "action_mask", "blocked_mask")
        ):
            raise ValueError("signal condition changed")
    first = indices[0]
    if first != (1 if context == "native_dlopen" else 3) or indices[1] != first + 1:
        raise ValueError("signal install position")
    if context == "native_dlopen":
        predecessor, successor = {"kind": "native_host", "phase": "load_enter"}, {"kind": "native_host", "phase": "call_enter"}
    else:
        predecessor, successor = {"kind": "phase", "phase": "after_load"}, {"kind": "bridge_image", "phase": "before"}
    if any(rows[first - 1].get(key) != value for key, value in predecessor.items()) or any(
        rows[first + 2].get(key) != value for key, value in successor.items()
    ):
        raise ValueError("signal loader boundary")
    endpoint = indices[2] - 1
    if endpoint < 0 or rows[endpoint]["kind"] != "endpoint_context":
        raise ValueError("signal query position")
    endpoint_row = rows[endpoint]
    if (
        endpoint_row.get("pid") != pid or endpoint_row.get("pipe_kind") != requested
        or type(endpoint_row.get("pipe_kind")) is not int
        or endpoint_row.get("blocked_signals") != before["blocked_mask"]
    ):
        raise ValueError("signal endpoint binding")
    sockets = [index for index, row in enumerate(rows) if row["kind"] == "sigpipe_socket"]
    if sockets != [indices[2] + 1]:
        raise ValueError("signal socket position")
    socket = rows[sockets[0]]
    if (
        set(socket) != SOCKET_KEYS or socket["sequence"] != 1 or type(socket["sequence"]) is not int
        or socket["pid"] != pid or type(socket["pid"]) is not int
        or socket["fd"] != endpoint_row.get("fd") or not integer(socket["fd"], 0)
        or any(type(socket[key]) is not int or socket[key] != 0 for key in ("rc", "errno"))
        or type(socket["length"]) is not int or type(socket["integer_bytes"]) is not int
        or socket["length"] != socket["integer_bytes"] or socket["integer_bytes"] != 4
        or not integer(socket["value"])
    ):
        raise ValueError("SO_NOSIGPIPE read")
    restored = len(indices) == 5
    if restored:
        after = indices[3]
        if indices[4] != after + 1 or rows[after - 1]["kind"] != "result" or after + 2 >= len(rows):
            raise ValueError("signal restoration position")
        expected = (
            {"kind": "native_host", "phase": "complete"}
            if context == "native_dlopen" else {"kind": "phase", "phase": "call_return"}
        )
        if any(rows[after + 2].get(key) != value for key, value in expected.items()):
            raise ValueError("signal restored successor")
    excluded = set(indices + sockets)
    stripped = [dict(row) for index, row in enumerate(rows) if index not in excluded]
    return stripped, {
        "admitted": True, "requested": requested, "states": states, "socket": socket,
        "query_time_condition_observed": True, "post_query_observed": restored,
        "restoration_observed": restored, "loader_initialization_condition_claimed": False,
        "SO_NOSIGPIPE_modified": False,
    }


def parse_signal(
    data: bytes, mode: str, pid: int | None, runtime: dict[str, str], context: str,
    executable: dict[str, Any], observer: dict[str, Any], flags: int, condition: str,
) -> dict[str, Any]:
    rejected: dict[str, Any] = {
        "valid": False, "complete": False, "loopback_label": False, "records": [], "endpoint": None,
        "condition": {"admitted": False}, "condition_records": [], "partial_line": False,
    }
    if (
        len(data) > 16 * 1024 or context not in ("native_dlopen", "python")
        or condition not in CONDITIONS or type(pid) is not int or not integer(pid, 1)
    ):
        return rejected
    lines = data.splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b"\n"))
    rejected["partial_line"] = partial
    if partial:
        lines.pop()
    if not 0 < len(lines) <= 71:
        return rejected
    try:
        rows = [json.loads(line.decode("ascii"), object_pairs_hook=_object) for line in lines]
        if any(not isinstance(row, dict) or not isinstance(row.get("kind"), str) for row in rows):
            raise ValueError("signal JSON")
        rejected["condition_records"] = [
            row for row in rows if row["kind"] in ("sigpipe_condition", "sigpipe_socket", "sigpipe_overflow")
        ]
        stripped, admitted = _conditions(rows, pid, int(condition == "ignore"), context)
        base_runtime = dict(runtime)
        if context == "python":
            value = base_runtime.pop(RUNTIME_KEY)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError("signal child source")
            for row in stripped:
                if row["kind"] in ("python_identity", "python_complete") and row.pop(RUNTIME_KEY, None) != value:
                    raise ValueError("signal runtime binding")
        encoded = b"".join(json.dumps(row).encode("ascii") + b"\n" for row in stripped)
        parsed = parse_context(encoded, mode, pid, base_runtime, context, executable, observer, flags)
        if not parsed["valid"]:
            raise ValueError("original endpoint protocol")
        if parsed["complete"] != admitted["restoration_observed"]:
            raise ValueError("signal completion binding")
        complete = bool(parsed["complete"] and not partial)
        return parsed | {
            "complete": complete, "loopback_label": complete and parsed["loopback_label"],
            "partial_line": partial or parsed["partial_line"], "condition": admitted,
            "condition_records": rejected["condition_records"],
        }
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, RecursionError) as error:
        rejected["error_type"] = type(error).__name__
        rejected["reason"] = str(error)
        return rejected
