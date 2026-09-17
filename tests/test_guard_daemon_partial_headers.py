# ruff: noqa: F811 - pytest imports and injects the same fixture name.
"""The parser may consume a header that was incomplete at worker handoff."""

from __future__ import annotations

import socket
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler

import pytest

from tests.test_guard_daemon_header_handoff import _Transport, transport  # noqa: F401


@pytest.mark.parametrize("terminator", [b"\r\n\r\n", b"\n\n", b"\n\r\n"])
def test_initially_partial_header_is_transferred_before_parser_consumption(
    transport: _Transport,
    monkeypatch: pytest.MonkeyPatch,
    terminator: bytes,
) -> None:
    parser_entered = threading.Event()
    consumed = threading.Event()
    resume_parser = threading.Event()
    original_parse = BaseHTTPRequestHandler.parse_request

    def pause_after_consuming_headers(handler: BaseHTTPRequestHandler) -> bool:
        parser_entered.set()
        parsed = original_parse(handler)
        assert parsed
        consumed.set()
        assert resume_parser.wait(2), "parser handoff barrier was not released"
        return parsed

    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", pause_after_consuming_headers)
    transport.client.sendall(b"GET /partial HTTP/1.0\r\nHost: local")
    worker = threading.Thread(target=transport.worker, name="test-partial-header-handoff", daemon=True)
    worker.start()
    try:
        assert parser_entered.wait(2)
        assert id(transport.incoming) in transport.server.unclassified_connections
        # Split the terminator across multiple sends; either recv coalescing
        # outcome must transfer complete framing before parser consumption.
        transport.client.sendall(b"host" + terminator[:-1])
        transport.client.sendall(terminator[-1:])
        assert consumed.wait(2), "the actual parser did not consume the completed header"
        transport.expire()
        transport.watchdog_pass()
    finally:
        resume_parser.set()
        worker.join(2)

    assert not worker.is_alive()
    assert transport.expired_closes == []
    assert transport.errors == []
    assert transport.dispatched.is_set()
    assert transport.client.recv(4096).startswith(b"HTTP/1.0 200 ")
    assert transport.server.active_requests == 0


def test_http09_partial_headers_keep_the_absolute_deadline(
    transport: _Transport, monkeypatch: pytest.MonkeyPatch
) -> None:
    parser_entered = threading.Event()
    original_parse = BaseHTTPRequestHandler.parse_request

    def observe_parser(handler: BaseHTTPRequestHandler) -> bool:
        parser_entered.set()
        return original_parse(handler)

    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", observe_parser)
    # CPython still parses headers for this valid two-word HTTP/0.9 GET.
    # Interpreting the request line as complete framing would remove its budget.
    transport.client.sendall(b"GET /legacy\r\nHost: partial")
    worker = threading.Thread(target=transport.worker, name="test-http09-header-expiry", daemon=True)
    worker.start()
    try:
        assert parser_entered.wait(2)
        assert id(transport.incoming) in transport.server.unclassified_connections
        transport.expire()
        transport.client.sendall(b"x")  # Wake the reader without completing headers.
        worker.join(2)
        assert not worker.is_alive()
        assert transport.errors == []
        assert not transport.dispatched.is_set()
        assert transport.server.active_requests == 0
    finally:
        with suppress(OSError):
            transport.client.shutdown(socket.SHUT_WR)
        worker.join(2)


@pytest.mark.parametrize(
    ("tail", "expected_status"),
    [
        (b"X-Large: " + b"x" * 65_536 + b"\r\n\r\n", 431),
        (b"X-Count: x\r\n" * 100 + b"\r\n", 431),
        # The existing parser permits more than 64 KiB in aggregate when each
        # header line and the header count satisfy its separate limits.
        (b"X-Valid: " + b"x" * 1_000 + b"\r\n" + (b"X: " + b"y" * 1_000 + b"\r\n") * 98 + b"\r\n", 200),
    ],
    ids=["overlong-header-line", "too-many-headers", "valid-aggregate-over-64k"],
)
def test_partial_header_reader_preserves_stdlib_header_limits(
    transport: _Transport, monkeypatch: pytest.MonkeyPatch, tail: bytes, expected_status: int
) -> None:
    parser_entered = threading.Event()
    original_parse = BaseHTTPRequestHandler.parse_request

    def observe_parser(handler: BaseHTTPRequestHandler) -> bool:
        parser_entered.set()
        return original_parse(handler)

    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", observe_parser)
    transport.client.sendall(b"GET /limits HTTP/1.0\r\n")
    worker = threading.Thread(target=transport.worker, name="test-partial-header-limits", daemon=True)
    worker.start()
    try:
        assert parser_entered.wait(2)
        assert id(transport.incoming) in transport.server.unclassified_connections
        transport.client.sendall(tail)
        response = transport.client.recv(4096)
        worker.join(2)
    finally:
        with suppress(OSError):
            transport.client.shutdown(socket.SHUT_RDWR)
        worker.join(2)

    assert not worker.is_alive()
    assert transport.errors == []
    assert transport.dispatched.is_set() is (expected_status == 200)
    assert response.startswith(f"HTTP/1.0 {expected_status} ".encode())
    assert transport.server.active_requests == 0


def test_partial_reader_preserves_stdlib_request_line_limit(transport: _Transport) -> None:
    transport.client.sendall(b"GET /")
    worker = threading.Thread(target=transport.worker, name="test-partial-request-line-limit", daemon=True)
    worker.start()
    try:
        transport.client.sendall(b"x" * 65_536 + b" HTTP/1.0\r\n\r\n")
        response = transport.client.recv(4096)
        worker.join(2)
    finally:
        with suppress(OSError):
            transport.client.shutdown(socket.SHUT_RDWR)
        worker.join(2)

    assert not worker.is_alive()
    assert transport.errors == []
    assert not transport.dispatched.is_set()
    assert response.startswith(b"HTTP/1.0 414 ")
    assert transport.server.active_requests == 0
