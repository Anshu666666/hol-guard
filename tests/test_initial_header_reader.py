# pyright: reportPrivateUsage=false
"""Byte preservation, absolute expiry and cleanup for the initial header reader."""

from __future__ import annotations

import http.client
import io
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest

from codex_plugin_scanner.guard.daemon import initial_header_reader as module
from codex_plugin_scanner.guard.daemon.initial_header_reader import InitialHeaderReader

_HEADER = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"


@dataclass
class ReaderFixture:
    raw: InitialHeaderReader
    request: socket.socket
    client: socket.socket
    pending: dict[int, tuple[socket.socket, float]]
    lock: threading.Lock
    clock: list[float]


@contextmanager
def reader_fixture() -> Iterator[ReaderFixture]:
    request, client = socket.socketpair()
    request.settimeout(2)
    client.settimeout(2)
    pending = {id(request): (request, 100.4)}
    lock = threading.Lock()
    clock = [100.0]
    raw = InitialHeaderReader(request, pending=pending, lock=lock, monotonic=lambda: clock[0])
    try:
        yield ReaderFixture(raw, request, client, pending, lock, clock)
    finally:
        raw.close()
        request.close()
        client.close()


def read_exact(raw: InitialHeaderReader, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        target = bytearray(count - len(result))
        received = raw.readinto(target)
        assert received > 0
        result.extend(target[:received])
    return bytes(result)


@pytest.mark.parametrize("split", range(1, len(_HEADER)))
def test_every_header_split_preserves_bytes_and_classifies_only_at_terminator(split: int) -> None:
    with reader_fixture() as fixture:
        probe = fixture.raw._probe
        assert probe is not None
        fixture.client.sendall(_HEADER + b"body!")
        assert read_exact(fixture.raw, split) == _HEADER[:split]
        assert id(fixture.request) in fixture.pending
        assert read_exact(fixture.raw, len(_HEADER) - split + 5) == _HEADER[split:] + b"body!"
        assert fixture.pending == {}
        assert probe.fileno() == -1
        assert fixture.request.gettimeout() == 2
        fixture.client.sendall(b"next")
        assert read_exact(fixture.raw, 4) == b"next"


def test_buffered_parser_preserves_binary_body_and_next_request() -> None:
    body = b"\x00\r\n\xff!"
    next_request = b"GET /next HTTP/1.1\r\nHost: loopback\r\n\r\n"
    with reader_fixture() as fixture, io.BufferedReader(fixture.raw, buffer_size=8) as reader:
        fixture.client.sendall(_HEADER + body + next_request)
        assert reader.readline() == b"POST / HTTP/1.1\r\n"
        headers = http.client.parse_headers(reader)
        assert headers["Content-Length"] == "5"
        assert fixture.pending == {}
        assert reader.read(5) == body
        assert reader.readline() == b"GET /next HTTP/1.1\r\n"
        assert http.client.parse_headers(reader)["Host"] == "loopback"


def test_partial_bytes_do_not_restart_deadline_or_allow_retry_after_expiry() -> None:
    with reader_fixture() as fixture:
        prefix = b"GET / HTTP/1.1\r\nHost: partial"
        fixture.client.sendall(prefix)
        assert read_exact(fixture.raw, len(prefix)) == prefix
        assert fixture.pending[id(fixture.request)][1] == 100.4
        fixture.clock[0] = 100.401
        fixture.client.sendall(b"\r\n\r\n")
        for _ in range(2):
            with pytest.raises(TimeoutError, match="header deadline"):
                fixture.raw.readinto(bytearray(32))
        assert fixture.pending == {}
        assert fixture.raw._probe is None
        assert fixture.raw._selector is None


def test_readiness_wait_is_outside_lock_and_uses_remaining_original_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    with reader_fixture() as fixture:
        probe = fixture.raw._probe
        assert probe is not None
        observed: list[float] = []

        class DelayedSelector:
            closed = False

            def register(self, _socket: socket.socket, _event: int) -> None:
                fixture.clock[0] = 100.35

            def select(self, timeout: float) -> list[object]:
                assert fixture.lock.acquire(blocking=False), "readiness wait held the expiration lock"
                fixture.lock.release()
                observed.append(timeout)
                fixture.clock[0] = 100.401
                return []

            def close(self) -> None:
                self.closed = True

        selector = DelayedSelector()
        monkeypatch.setattr(module.selectors, "DefaultSelector", lambda: selector)
        with pytest.raises(TimeoutError, match="header deadline"):
            fixture.raw.readinto(bytearray(8))
        assert observed == [pytest.approx(0.05)]
        assert selector.closed
        assert probe.fileno() == -1
        assert fixture.request.gettimeout() == 2


def test_failed_probe_setup_closes_duplicate_and_preserves_original(monkeypatch: pytest.MonkeyPatch) -> None:
    request, client = socket.socketpair()
    request.settimeout(2)
    duplicates: list[socket.socket] = []
    original_dup = socket.socket.dup

    def record_duplicate(current: socket.socket) -> socket.socket:
        duplicate = original_dup(current)
        duplicates.append(duplicate)
        return duplicate

    def fail_nonblocking(_current: socket.socket, _flag: bool) -> None:
        raise OSError("injected probe setup failure")

    try:
        monkeypatch.setattr(socket.socket, "dup", record_duplicate)
        monkeypatch.setattr(socket.socket, "setblocking", fail_nonblocking)
        with pytest.raises(OSError, match="injected"):
            InitialHeaderReader(request, pending={}, lock=threading.Lock(), monotonic=lambda: 100.0)
        assert duplicates and all(duplicate.fileno() == -1 for duplicate in duplicates)
        assert request.gettimeout() == 2
        client.sendall(b"still connected")
        assert request.recv(32) == b"still connected"
    finally:
        request.close()
        client.close()


def test_blocking_reader_is_declined_without_creating_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbid_duplication(_request: socket.socket) -> socket.socket:
        raise AssertionError("blocking endpoint must not be duplicated")

    with socket.socket() as request:
        monkeypatch.setattr(socket.socket, "dup", forbid_duplication)
        with pytest.raises(ValueError, match="admitted nonblocking"):
            InitialHeaderReader(request, pending={}, lock=threading.Lock(), monotonic=lambda: 100.0)
        assert request.gettimeout() is None


def test_deadline_crossed_during_read_cannot_classify_late_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    with reader_fixture() as fixture:
        original_recv = socket.socket.recv_into

        def delayed_recv(current: socket.socket, target: bytearray) -> int:
            count = original_recv(current, target)
            fixture.clock[0] = 100.401
            return count

        fixture.client.sendall(_HEADER)
        monkeypatch.setattr(socket.socket, "recv_into", delayed_recv)
        for _ in range(2):
            with pytest.raises(TimeoutError, match="header deadline"):
                fixture.raw.readinto(bytearray(128))
        assert fixture.pending == {}
        assert fixture.raw._probe is None
        assert fixture.raw._expired


def test_selector_failure_cleanup_preserves_original_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    with reader_fixture() as fixture:
        probe = fixture.raw._probe
        assert probe is not None

        class FailingSelector:
            closed = False

            def register(self, _socket: socket.socket, _event: int) -> None:
                raise OSError("injected registration failure")

            def close(self) -> None:
                self.closed = True

        selector = FailingSelector()
        monkeypatch.setattr(module.selectors, "DefaultSelector", lambda: selector)
        with pytest.raises(OSError, match="injected registration"):
            fixture.raw.readinto(bytearray(8))
        fixture.raw.close()
        assert selector.closed
        assert probe.fileno() == -1
        assert fixture.request.gettimeout() == 2
        fixture.client.sendall(b"original survives")
        assert fixture.request.recv(32) == b"original survives"
