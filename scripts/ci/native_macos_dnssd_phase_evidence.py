"""Validate bounded call pairs before admitting the unchanged inner DNS-SD protocol."""

from __future__ import annotations

import errno
import json
import re
from typing import Any

from scripts.ci.native_macos_dnssd_python_child import MODES
from scripts.ci.native_macos_dnssd_python_evidence import RUNTIME_KEYS, _object, parse_comparison
from scripts.ci.native_macos_dnssd_phase_identity import CPU_TYPES
from scripts.ci.native_macos_resolver_evidence import parse_metadata

EXTRA_RUNTIME_KEY = "phase_child_source_sha256"
TRACE_LIMIT = 32


def _integers(row: dict[str, Any], *keys: str) -> bool:
    return all(type(row.get(key)) is int and -(2**31) <= row[key] < 2**31 for key in keys)


class _Trace:
    def __init__(self) -> None:
        self.state = "before_query"
        self.pending: str | None = None
        self.boundary = "before_query"
        self.count = 0
        self.overflow = False
        self.fd: int | None = None
        self.callbacks = 0
        self.silent_returns = 0
        self.expected_error: int | None = None

    def feed(self, row: dict[str, Any]) -> None:
        kind = row.get("kind")
        if not isinstance(kind, str):
            raise ValueError("record kind")
        if kind == "call_trace_overflow":
            if (
                self.overflow or self.count != TRACE_LIMIT
                or row != {"kind": kind, "sequence": TRACE_LIMIT + 1}
                or self.state not in {"poll_or_result", "repeat_poll", "ready"}
            ):
                raise ValueError("overflow boundary")
            self.overflow = True
            return
        if kind == "call_trace":
            if self.overflow or self.count >= TRACE_LIMIT:
                raise ValueError("trace after limit")
            self._call(row)
            return
        if self.overflow:
            return
        if kind == "query":
            if self.state != "before_query":
                raise ValueError("query order")
            self.state = "query_error" if row.get("error") else "poll_or_result"
            self.boundary = "query_return"
            self.expected_error = row.get("error") if row.get("error") else None
        elif kind == "callback":
            if self.state != "processing":
                raise ValueError("callback outside processing call")
            self.callbacks += 1
        elif kind == "result":
            if self.state not in {"poll_or_result", "query_error", "terminal_error"}:
                raise ValueError("result during call")
            if (
                (self.expected_error is not None and row.get("error") != self.expected_error)
                or (self.state == "terminal_error" and not row.get("error"))
                or (self.count == 0 and self.state == "poll_or_result" and not row.get("error"))
            ):
                raise ValueError("result disagrees with observed return")
            self.state, self.boundary = "finished", "query_result"

    def _call(self, row: dict[str, Any]) -> None:
        if not _integers(row, "sequence") or row["sequence"] != self.count + 1:
            raise ValueError("trace sequence")
        call, phase = row.get("call"), row.get("phase")
        base = {"kind", "sequence", "call", "phase"}
        if call == "poll" and phase == "enter":
            if (
                set(row) != base | {"fd", "events", "nfds", "timeout"}
                or self.state not in {"poll_or_result", "repeat_poll"}
                or not _integers(row, "fd", "events", "nfds", "timeout")
                or row["fd"] < 0 or row["events"] != 1 or row["nfds"] != 1 or row["timeout"] != -1
                or (self.fd is not None and row["fd"] != self.fd)
            ):
                raise ValueError("poll entry")
            self.fd, self.state, self.pending = row["fd"], "polling", "poll"
        elif call == "poll" and phase == "return":
            if (
                set(row) != base | {"result", "errno", "revents"} or self.state != "polling"
                or not _integers(row, "result", "errno", "revents")
                or row["result"] not in (-1, 0, 1) or not -(2**15) <= row["revents"] < 2**15
            ):
                raise ValueError("poll return")
            self.pending = None
            self.expected_error = None
            if row["result"] == -1 and row["errno"] == errno.EINTR:
                self.state = "repeat_poll"
            else:
                self.state = "ready" if row["result"] >= 0 and row["revents"] & 1 else "terminal_error"
        elif call == "DNSServiceProcessResult" and phase == "enter":
            if set(row) != base or self.state != "ready":
                raise ValueError("processing entry")
            self.state, self.pending, self.callbacks = "processing", call, 0
        elif call == "DNSServiceProcessResult" and phase == "return":
            if (
                set(row) != base | {"result", "errno"} or self.state != "processing"
                or not _integers(row, "result", "errno")
            ):
                raise ValueError("processing return")
            if row["result"] == 0 and self.callbacks == 0:
                self.silent_returns += 1
            self.state = "terminal_error" if row["result"] else "poll_or_result"
            self.expected_error = row["result"]
            self.pending = None
        else:
            raise ValueError("trace call or phase")
        self.count += 1
        self.boundary = str(call) + "_" + str(phase)


def parse_trace(
    data: bytes, mode: str, pid: int | None, runtime: dict[str, str], identity: dict[str, Any], *, python: bool
) -> dict[str, Any]:
    rejected: dict[str, Any] = {"valid": False, "complete": False, "loopback_label": False, "records": []}
    if (
        mode not in MODES or type(python) is not bool or len(data) > 16 * 1024
        or identity.get("filetype") != (6 if python else 2) or identity.get("cpu_type") not in CPU_TYPES.values()
    ):
        return rejected
    lines = data.splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b"\n"))
    if partial:
        lines.pop()
    if not 0 < len(lines) <= 61:
        return rejected
    trace, stripped = _Trace(), []
    try:
        rows = [json.loads(line.decode("ascii"), object_pairs_hook=_object) for line in lines]
        if any(not isinstance(row, dict) for row in rows):
            return rejected
        if python and (
            set(runtime) != RUNTIME_KEYS | {EXTRA_RUNTIME_KEY}
            or re.fullmatch(r"[0-9a-f]{64}", runtime.get(EXTRA_RUNTIME_KEY, "")) is None
        ):
            return rejected
        for row in rows:
            trace.feed(row)
            if row["kind"] in ("call_trace", "call_trace_overflow"):
                continue
            normalized = dict(row)
            if python and row["kind"] in ("python_identity", "python_complete"):
                if normalized.pop(EXTRA_RUNTIME_KEY, None) != runtime[EXTRA_RUNTIME_KEY]:
                    return rejected
            stripped.append(normalized)
        encoded = b"".join(json.dumps(row).encode("ascii") + b"\n" for row in stripped)
        base_runtime = {key: value for key, value in runtime.items() if key != EXTRA_RUNTIME_KEY}
        parsed = (
            parse_comparison(encoded, mode, pid, base_runtime, identity)
            if python else parse_metadata(encoded, mode, pid)
        )
        if not parsed["valid"]:
            return rejected
        native = next((row for row in stripped if row["kind"] == "identity"), None)
        if native and any(native[key] != identity.get(key) for key in ("cpu_type", "cpu_subtype")):
            return rejected
    except (ValueError, UnicodeError, RecursionError, TypeError, KeyError):
        return rejected
    complete = parsed["complete"] and not partial and not trace.overflow
    return {
        "valid": True, "complete": complete, "loopback_label": complete and parsed["loopback_label"],
        "partial_line": partial, "trace_overflow": trace.overflow, "trace_records": trace.count,
        "last_observed_boundary": trace.boundary, "pending_call": trace.pending,
        "process_returns_without_callback_record": trace.silent_returns,
        "callback_record_limit": 16, "records": rows,
    }
