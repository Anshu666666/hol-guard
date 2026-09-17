"""Deterministic socket/parser handoffs at the existing absolute header deadline."""

from __future__ import annotations

import socket
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler, _GuardDaemonHttpServer

_HEADERS = b"GET /header-handoff HTTP/1.0\r\nHost: localhost\r\n\r\n"
_BARRIER_TIMEOUT = 2.0


def test_blocking_socket_is_declined_before_duplication(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbid_duplication(_request: socket.socket) -> socket.socket:
        raise AssertionError("a blocking socket must not be duplicated or have its mode changed")

    with socket.socket() as request:
        assert request.gettimeout() is None
        monkeypatch.setattr(socket.socket, "dup", forbid_duplication)
        assert not _GuardDaemonHttpServer._buffered_request_headers_complete(request)
        assert request.gettimeout() is None


class _OneWatchdogPass(threading.Event):
    def __init__(self) -> None:
        super().__init__()
        self.calls: int = 0

    def wait(self, timeout: float | None = None) -> bool:
        self.calls += 1
        return self.calls > 1


@dataclass
class _Transport:
    server: _GuardDaemonHttpServer
    incoming: socket.socket
    client: socket.socket
    now: float = 100.0
    dispatched: threading.Event = field(default_factory=threading.Event)
    errors: list[BaseException] = field(default_factory=list)
    expired_closes: list[int] = field(default_factory=list)

    def monotonic(self) -> float:
        return self.now

    def expire(self) -> None:
        self.now = 100.0 + daemon_server._DAEMON_REQUEST_READ_TIMEOUT_SECONDS + 0.001

    def watchdog_pass(self) -> None:
        self.server.unclassified_watchdog_stop = _OneWatchdogPass()
        self.server._watch_unclassified_connections()

    def worker(self) -> None:
        try:
            self.server._process_request_worker(self.incoming, ("127.0.0.1", 1))
        except BaseException as error:
            self.errors.append(error)


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Transport]:
    """Use real sockets, HTTP parsing and worker cleanup without starting a daemon."""
    server = object.__new__(_GuardDaemonHttpServer)
    incoming, client = socket.socketpair()
    incoming.settimeout(_BARRIER_TIMEOUT)
    client.settimeout(_BARRIER_TIMEOUT)
    fixture = _Transport(server, incoming, client)
    monkeypatch.setattr(daemon_server, "time", SimpleNamespace(monotonic=fixture.monotonic))
    server.request_capacity_lock = threading.Lock()
    server.unclassified_connections_lock = threading.Lock()
    server.unclassified_connections = {}
    server.request_accepted_at = {}
    server.active_connections = {}
    server.request_capacity_kinds = {}
    server.active_requests = 1
    server.rejected_requests = 0
    server.request_capacity = threading.BoundedSemaphore(1)
    server.control_request_capacity = threading.BoundedSemaphore(1)
    server.critical_request_capacity = threading.BoundedSemaphore(1)
    server.connection_capacity = threading.BoundedSemaphore(1)
    assert server.connection_capacity.acquire(blocking=False)
    monkeypatch.setattr(server, "_guard_release_request", lambda: None)

    def capture_error(_request: object, _address: object) -> None:
        error = sys.exc_info()[1]
        assert error is not None
        fixture.errors.append(error)

    monkeypatch.setattr(server, "handle_error", capture_error)

    def capture_expired_close(request: socket.socket) -> None:
        fixture.expired_closes.append(id(request))
        _GuardDaemonHttpServer._close_unclassified_socket(request)

    monkeypatch.setattr(server, "_close_unclassified_socket", capture_expired_close)

    class ProbeHandler(_GuardDaemonHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP handler override
            fixture.dispatched.set()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server.RequestHandlerClass = ProbeHandler
    server._register_unclassified_connection(incoming)
    try:
        yield fixture
    finally:
        incoming.close()
        client.close()


def test_complete_headers_consumed_before_classification_survive_watchdog(
    transport: _Transport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumed = threading.Event()
    resume_parser = threading.Event()
    original_parse = BaseHTTPRequestHandler.parse_request

    def pause_after_consuming_headers(handler: BaseHTTPRequestHandler) -> bool:
        parsed = original_parse(handler)
        assert parsed
        consumed.set()
        assert resume_parser.wait(_BARRIER_TIMEOUT), "parser handoff barrier was not released"
        return parsed

    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", pause_after_consuming_headers)
    transport.client.sendall(_HEADERS)
    worker = threading.Thread(target=transport.worker, name="test-header-consumed-handoff", daemon=True)
    worker.start()
    try:
        assert consumed.wait(_BARRIER_TIMEOUT), "the actual HTTP parser did not consume the complete headers"
        # Only the paused test thread owns this socket now. Bypass CPython's
        # positive-timeout readiness wait to isolate classification from the
        # separate MSG_DONTWAIT/timeout behavior of the original peek helper.
        transport.incoming.setblocking(False)
        transport.expire()
        transport.watchdog_pass()
    finally:
        resume_parser.set()
        worker.join(_BARRIER_TIMEOUT)

    assert not worker.is_alive(), "HTTP worker did not finish after releasing the parser barrier"
    assert transport.expired_closes == [], "watchdog closed a request after the parser consumed its complete headers"
    assert transport.errors == []
    assert transport.dispatched.is_set()
    assert transport.client.recv(4096).startswith(b"HTTP/1.0 200 ")
    assert transport.server.active_requests == 0
    assert transport.server.request_capacity.acquire(blocking=False)
    transport.server.request_capacity.release()


def test_classified_socket_is_not_closed_from_a_stale_watchdog_snapshot(
    transport: _Transport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspecting_expired = threading.Event()
    resume_watchdog = threading.Event()
    failures: list[BaseException] = []

    def pause_expired_probe(_request: socket.socket) -> bool:
        inspecting_expired.set()
        assert resume_watchdog.wait(_BARRIER_TIMEOUT), "watchdog snapshot barrier was not released"
        return False

    monkeypatch.setattr(transport.server, "_buffered_request_headers_complete", pause_expired_probe)
    transport.expire()

    def watchdog() -> None:
        try:
            transport.watchdog_pass()
        except BaseException as error:
            failures.append(error)

    observer = threading.Thread(target=watchdog, name="test-stale-header-expiry", daemon=True)
    observer.start()
    try:
        assert inspecting_expired.wait(_BARRIER_TIMEOUT), "watchdog did not inspect the expired snapshot"
        transport.server.classify_connection(transport.incoming)
        assert id(transport.incoming) not in transport.server.unclassified_connections
    finally:
        resume_watchdog.set()
        observer.join(_BARRIER_TIMEOUT)

    assert not observer.is_alive(), "watchdog did not finish after its snapshot barrier"
    assert failures == []
    assert transport.incoming.fileno() >= 0, "an obsolete expired entry closed a subsequently classified socket"
    transport.client.sendall(b"still connected")
    assert transport.incoming.recv(32) == b"still connected"


@pytest.mark.parametrize("initial", [b"", b"GET /header-handoff HTTP/1.0\r\nHost:"])
def test_empty_and_trickling_headers_keep_the_original_absolute_expiry(
    transport: _Transport,
    initial: bytes,
) -> None:
    transport.incoming.setblocking(False)
    if initial:
        transport.client.sendall(initial)
    original_deadline = transport.server.unclassified_connections[id(transport.incoming)][1]
    transport.now = original_deadline - 0.001
    transport.watchdog_pass()
    assert transport.incoming.fileno() >= 0
    if initial:
        transport.client.sendall(b" l")
    assert transport.server.unclassified_connections[id(transport.incoming)][1] == original_deadline

    transport.expire()
    transport.watchdog_pass()

    assert transport.incoming.fileno() == -1, "incomplete headers must expire despite continuing byte arrivals"
    assert not transport.dispatched.is_set()


@pytest.mark.parametrize("remove_dontwait", [False, True], ids=["platform-flags", "without-MSG_DONTWAIT"])
def test_timeout_socket_peek_does_not_wait_or_change_its_original_timeout(
    monkeypatch: pytest.MonkeyPatch,
    remove_dontwait: bool,
) -> None:
    if remove_dontwait:
        monkeypatch.delattr(socket, "MSG_DONTWAIT", raising=False)
    incoming, client = socket.socketpair()
    original_timeout = 4 * _BARRIER_TIMEOUT
    incoming.settimeout(original_timeout)
    client.settimeout(_BARRIER_TIMEOUT)
    started, completed = threading.Event(), threading.Event()
    results: list[bool] = []
    errors: list[BaseException] = []

    def peek_empty_socket() -> None:
        started.set()
        try:
            results.append(_GuardDaemonHttpServer._buffered_request_headers_complete(incoming))
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()

    observer = threading.Thread(target=peek_empty_socket, name="test-timeout-header-peek", daemon=True)
    observer.start()
    try:
        assert started.wait(_BARRIER_TIMEOUT)
        returned_without_input = completed.wait(_BARRIER_TIMEOUT)
        # Release an old timeout-based peek on failure without leaving a
        # lingering thread or waiting for its long socket timeout to expire.
        if not returned_without_input:
            client.sendall(b"release")
        observer.join(_BARRIER_TIMEOUT)
        assert not observer.is_alive()
        assert returned_without_input, "an empty header peek waited for network readiness"
        assert errors == []
        assert results == [False]
        assert incoming.gettimeout() == original_timeout

        client.sendall(_HEADERS)
        assert _GuardDaemonHttpServer._buffered_request_headers_complete(incoming) is True
        assert incoming.gettimeout() == original_timeout
        assert incoming.recv(len(_HEADERS)) == _HEADERS, "peeking must not consume the original socket's bytes"
        incoming.sendall(b"usable")
        assert client.recv(6) == b"usable"
    finally:
        client.shutdown(socket.SHUT_RDWR)
        observer.join(_BARRIER_TIMEOUT)
        incoming.close()
        client.close()
