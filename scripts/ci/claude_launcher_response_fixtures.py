"""Actual Python HTTP/response parser fixtures; no socket is created."""

from __future__ import annotations

import http.client
import io
import json
import socket
import time
from typing import cast

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as transport
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError

# Freeze the real legacy parser and delivery functions, not a restated oracle.
# pyright: reportPrivateUsage=false


class _Socket:
    def __init__(self, wire: bytes) -> None:
        self.wire: bytes = wire

    def makefile(self, *_args: object, **_kwargs: object) -> io.BytesIO:
        return io.BytesIO(self.wire)


def _deny(event: str) -> str:
    return bridge._deny_event(event, "synthetic denied response")


def body_fixtures() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for event in ("PreToolUse", "PostToolUse"):
        prefix = _deny(event)[:-1].encode()
        for name, suffix, profile in (
            ("wide_array", b',"extra":[' + b"0," * 4096 + b"0]}", "pass"),
            ("duplicate_ancillary", b',"extra":1,"extra":2}', "pass"),
            ("depth64", b',"extra":' + b"[" * 64 + b"0" + b"]" * 64 + b"}", "pass"),
            ("depth256", b',"extra":' + b"[" * 256 + b"0" + b"]" * 256 + b"}", "unsupported"),
            ("large_integer", b',"extra":1' + b"0" * 400 + b"}", "unsupported"),
            ("float_overflow", b',"extra":1e400}', "unsupported"),
            ("nan", b',"extra":NaN}', "unsupported"),
            ("infinity", b',"extra":Infinity}', "unsupported"),
            ("negative_infinity", b',"extra":-Infinity}', "unsupported"),
            ("high_surrogate", b',"extra":"\\ud800"}', "unsupported"),
            ("low_surrogate", b',"extra":"\\udc00"}', "unsupported"),
            ("invalid_utf8", b',"extra":"\xff"}', "pass"),
            ("quoted_nonfinite", b',"extra":"NaN Infinity -Infinity"}', "pass"),
            ("malformed", b',"extra":}', "availability"),
        ):
            raw = prefix + suffix
            rendered = bridge._valid_hook_json_or_degraded(
                raw.decode("utf-8", errors="replace"),
                reason="daemon returned malformed hook JSON",
                data=json.dumps({"hook_event_name": event}),
            )
            cases.append(
                {
                    "name": name,
                    "event": event,
                    "raw_hex": raw.hex(),
                    "python_hex": rendered.encode().hex(),
                    "native_profile": profile,
                }
            )
        padded = "\x1c \r\n" + _deny(event) + "\t\x1f"
        cases.append(
            {
                "name": "trim",
                "event": event,
                "raw_hex": padded.encode().hex(),
                "python_hex": bridge._valid_hook_json_or_degraded(padded, reason="fixture", data="{}").encode().hex(),
                "native_profile": "pass",
            }
        )
    return cases


def wire_fixtures() -> list[dict[str, object]]:
    body = _deny("PreToolUse").encode()
    length = f"Content-Length: {len(body)}\r\n".encode()
    response = b"HTTP/1.1 200 OK\r\n"
    wires = (
        ("explicit_length", response + length + b"\r\n" + body, "pass"),
        ("equal_lengths", response + length * 2 + b"\r\n" + body, "pass"),
        ("status_spacing", b"HTTP/1.1  200 OK\r\n" + length + b"\r\n" + body, "unsupported"),
        ("http_minor_version", b"HTTP/1.2 200 OK\r\n" + length + b"\r\n" + body, "unsupported"),
        ("informational", b"HTTP/1.1 100 Continue\r\n\r\n" + response + length + b"\r\n" + body, "unsupported"),
        ("conflicting_lengths", response + length + b"Content-Length: 1\r\n\r\n" + body, "unsupported"),
        (
            "chunked",
            response + b"Transfer-Encoding: chunked\r\n\r\n" + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n",
            "unsupported",
        ),
        ("eof_body", response + b"\r\n" + body, "unsupported"),
        ("long_header", response + length + b"X-F: " + b"a" * 5000 + b"\r\n\r\n" + body, "unsupported"),
        ("lf_only", (response + length + b"\r\n").replace(b"\r\n", b"\n") + body, "unsupported"),
        ("short_valid_body", response + f"Content-Length: {len(body) + 1}\r\n\r\n".encode() + body, "unsupported"),
        ("overflow_length", response + b"Content-Length: 184467440737095516160\r\n\r\n" + body, "unsupported"),
        ("extra_body", response + length + b"\r\n" + body + b"{}", "unsupported"),
        ("auth401_empty_truncated", b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 1\r\n\r\n", "integrity"),
        ("auth403_empty_truncated", b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\n", "integrity"),
        ("auth401_header_eof", b"HTTP/1.1 401 Unauthorized\r\n", "integrity"),
        ("auth403_header_eof", b"HTTP/1.1 403 Forbidden\r\n", "integrity"),
        ("auth401_status_eof", b"HTTP/1.1 401 Unauthorized", "unsupported"),
        ("auth403_status_eof", b"HTTP/1.1 403 Forbidden", "unsupported"),
        ("bad_status", b"invalid status\r\n" + length + b"\r\n" + body, "availability"),
    )
    cases: list[dict[str, object]] = []
    for name, wire, profile in wires:
        parsed = http.client.HTTPResponse(cast(socket.socket, cast(object, _Socket(wire))))
        try:
            parsed.begin()
            text = transport._read_hook_response(
                parsed,
                connection=http.client.HTTPConnection("127.0.0.1"),
                deadline=time.monotonic() + 10,
            )
        except (http.client.HTTPException, _DaemonResponseError) as error:
            cases.append(
                {
                    "name": name,
                    "wire_hex": wire.hex(),
                    "python_failure": bridge._daemon_failure_kind(error),
                    "native_profile": profile,
                }
            )
        else:
            if text != body.decode():
                raise AssertionError("wire fixture did not retain the actual denied response")
            cases.append(
                {"name": name, "wire_hex": wire.hex(), "python_hex": text.encode().hex(), "native_profile": profile}
            )
        finally:
            parsed.close()
    return cases
