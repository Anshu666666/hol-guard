"""Validate exact new record positions before the unchanged phase protocol."""

from __future__ import annotations

import json
import re
from typing import Any

from scripts.ci.native_macos_dnssd_endpoint_child import RUNTIME_KEY
from scripts.ci.native_macos_dnssd_endpoint_record import CONTEXTS, UUID, integer, normalize
from scripts.ci.native_macos_dnssd_phase_evidence import parse_trace
from scripts.ci.native_macos_dnssd_python_evidence import _object


def _host(
    rows: list[dict[str, Any]], mode: str, pid: int, flags: int, bridge: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    prefix = {"kind": "native_host", "phase": "load_enter", "pid": pid, "mode": mode, "loader_flags": flags}
    if len(rows) < 2 or rows[0] != prefix:
        raise ValueError("native host loader")
    before = rows[1]
    if (
        set(before) != {"kind", "phase", "bridge_uuid", "libinfo_uuid", "dnssd_uuid"}
        or before["kind"] != "native_host"
        or before["phase"] != "call_enter"
        or before["bridge_uuid"] != bridge.get("uuid")
        or any(
            not isinstance(before[key], str) or UUID.fullmatch(before[key]) is None
            for key in ("bridge_uuid", "libinfo_uuid", "dnssd_uuid")
        )
    ):
        raise ValueError("native host mapped image")
    complete = rows[-1].get("kind") == "native_host" and rows[-1].get("phase") == "complete"
    body = rows[2:-1] if complete else rows[2:]
    if any(row.get("kind") in ("native_host", "native_host_failure") for row in body):
        raise ValueError("native host order or failure")
    native = next((row for row in body if row.get("kind") == "identity"), None)
    if not native or any(native.get(key) != before[key] for key in ("libinfo_uuid", "dnssd_uuid")):
        raise ValueError("native host query images")
    if complete:
        after = rows[-1]
        if (
            set(after) != set(before) | {"return_code"}
            or any(after[key] != before[key] for key in ("kind", "bridge_uuid", "libinfo_uuid", "dnssd_uuid"))
            or not integer(after["return_code"])
        ):
            raise ValueError("native host completion")
        result = next((row for row in reversed(body) if row.get("kind") == "result"), None)
        if not result or after["return_code"] != (
            2 if result.get("error") or result.get("callback_error") or result.get("overflow") else 0
        ):
            raise ValueError("native host return consistency")
    return body, complete


def parse_context(
    data: bytes,
    mode: str,
    pid: int | None,
    runtime: dict[str, str],
    context: str,
    executable: dict[str, Any],
    observer: dict[str, Any],
    loader_flags: int,
) -> dict[str, Any]:
    rejected: dict[str, Any] = {
        "valid": False,
        "complete": False,
        "loopback_label": False,
        "records": [],
        "endpoint": None,
    }
    if len(data) > 16 * 1024 or context not in CONTEXTS or type(pid) is not int or not integer(pid, 1):
        return rejected
    lines = data.splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b"\n"))
    if partial:
        lines.pop()
    if not 0 < len(lines) <= 65:
        return rejected
    try:
        rows = [json.loads(line.decode("ascii"), object_pairs_hook=_object) for line in lines]
        if any(not isinstance(row, dict) or not isinstance(row.get("kind"), str) for row in rows):
            raise ValueError("context JSON")
        host_complete = True
        if context == "native_dlopen":
            rows, host_complete = _host(rows, mode, pid, loader_flags, observer)
        elif any(row["kind"] in ("native_host", "native_host_failure") for row in rows):
            raise ValueError("unexpected native host")
        endpoints = [index for index, row in enumerate(rows) if row["kind"] == "endpoint_context"]
        if len(endpoints) != 1:
            raise ValueError("endpoint population")
        index = endpoints[0]
        if index == 0 or rows[index - 1].get("kind") != "query" or rows[index - 1].get("error") != 0:
            raise ValueError("endpoint order")
        following = rows[index + 1] if index + 1 < len(rows) else None
        if following is not None:
            if following.get("kind") == "call_trace":
                if (
                    following.get("call") != "poll"
                    or following.get("phase") != "enter"
                    or following.get("sequence") != 1
                    or following.get("fd") != rows[index].get("fd")
                ):
                    raise ValueError("endpoint poll binding")
            elif following.get("kind") != "result" or not following.get("error"):
                raise ValueError("endpoint successor")
        native = next((row for row in rows if row["kind"] == "identity"), None)
        if native is None:
            raise ValueError("native identity absent")
        endpoint = normalize(rows[index], context, pid, loader_flags, executable, observer, native)
        stripped = rows[:index] + rows[index + 1 :]
        base_runtime = dict(runtime)
        if context == "python":
            value = base_runtime.pop(RUNTIME_KEY)
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError("new child source")
            for row in stripped:
                if row["kind"] in ("python_identity", "python_complete") and row.pop(RUNTIME_KEY, None) != value:
                    raise ValueError("new runtime source binding")
        encoded = b"".join(json.dumps(row).encode("ascii") + b"\n" for row in stripped)
        parsed = parse_trace(
            encoded,
            mode,
            pid,
            base_runtime,
            observer if context == "python" else executable,
            python=context == "python",
        )
        if not parsed["valid"]:
            raise ValueError("original protocol")
        complete = bool(parsed["complete"] and host_complete and not partial)
        return parsed | {
            "complete": complete,
            "loopback_label": complete and parsed["loopback_label"],
            "partial_line": partial or parsed["partial_line"],
            "endpoint": endpoint,
            "native_host_complete": host_complete,
            "raw_endpoint_exported": False,
        }
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return rejected
