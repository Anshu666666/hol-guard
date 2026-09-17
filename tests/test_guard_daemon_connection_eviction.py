"""Deterministic overload eviction versus classification and final cleanup."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import TracebackType
from typing import final

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer

_BARRIER_TIMEOUT = 2.0


@final
class _SelectionBoundaryLock:
    """Pause an evictor after releasing its first selection lock, not inside it."""

    def __init__(self) -> None:
        self.inner = threading.Lock()
        self.selected = threading.Event()
        self.resume = threading.Event()
        self.owner: threading.Thread | None = None
        self.armed = True

    def __enter__(self) -> None:
        _ = self.inner.acquire()

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.inner.release()
        if self.armed and threading.current_thread() is self.owner:
            self.armed = False
            self.selected.set()
            assert self.resume.wait(_BARRIER_TIMEOUT), "eviction selection barrier was not released"


@dataclass
class _Connection:
    server: _GuardDaemonHttpServer
    incoming: socket.socket
    client: socket.socket
    guard_slots: threading.BoundedSemaphore
    guard_releases: list[int] = field(default_factory=list)
    errors: list[BaseException] = field(default_factory=list)


@pytest.fixture
def connection(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Connection]:
    server = object.__new__(_GuardDaemonHttpServer)
    incoming, client = socket.socketpair()
    incoming.settimeout(_BARRIER_TIMEOUT)
    client.settimeout(_BARRIER_TIMEOUT)
    fixture = _Connection(server, incoming, client, threading.BoundedSemaphore(1))
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
    assert fixture.guard_slots.acquire(blocking=False)

    def release_guard_slot() -> None:
        fixture.guard_releases.append(id(incoming))
        fixture.guard_slots.release()

    monkeypatch.setattr(server, "_guard_release_request", release_guard_slot)
    server._register_unclassified_connection(incoming)
    try:
        yield fixture
    finally:
        incoming.close()
        client.close()


def _assert_one_available_slot(semaphore: threading.BoundedSemaphore) -> None:
    assert semaphore.acquire(blocking=False), "the single admitted connection was not released"
    try:
        assert not semaphore.acquire(blocking=False), "cleanup released the same capacity more than once"
    finally:
        semaphore.release()


def test_classification_after_eviction_selection_keeps_connection_and_request_permits(
    connection: _Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = connection.server
    boundary = _SelectionBoundaryLock()
    monkeypatch.setattr(server, "unclassified_connections_lock", boundary)

    def evict() -> None:
        try:
            server._evict_oldest_unclassified_connection()
        except BaseException as error:
            connection.errors.append(error)

    evictor = threading.Thread(target=evict, name="test-eviction-classification-handoff", daemon=True)
    boundary.owner = evictor
    evictor.start()
    try:
        assert boundary.selected.wait(_BARRIER_TIMEOUT), "eviction did not select the admitted connection"
        server.classify_connection(connection.incoming)
        assert server.claim_request_capacity(connection.incoming, "/v1/hooks/pi")
    finally:
        boundary.resume.set()
        evictor.join(_BARRIER_TIMEOUT)

    assert not evictor.is_alive()
    assert connection.errors == []
    assert connection.incoming.fileno() >= 0, "stale overload selection closed a classified connection"
    assert server.active_requests == 1
    assert server.rejected_requests == 0
    assert connection.guard_releases == []
    assert not server.connection_capacity.acquire(blocking=False)
    assert not server.request_capacity.acquire(blocking=False)
    assert not connection.guard_slots.acquire(blocking=False)
    connection.client.sendall(b"classified")
    assert connection.incoming.recv(16) == b"classified"

    server._discard_request(connection.incoming)
    server._release_request_capacity(connection.incoming)
    assert server.active_requests == 0
    assert connection.guard_releases == [id(connection.incoming)]
    _assert_one_available_slot(server.connection_capacity)
    _assert_one_available_slot(server.request_capacity)
    _assert_one_available_slot(connection.guard_slots)


def test_actual_unclassified_eviction_releases_once_despite_late_worker_cleanup(connection: _Connection) -> None:
    server = connection.server
    server._evict_oldest_unclassified_connection()
    server._release_request_capacity(connection.incoming)
    server._discard_request(connection.incoming)

    assert connection.incoming.fileno() == -1
    assert server.active_requests == 0
    assert server.rejected_requests == 1
    assert server.unclassified_connections == {}
    assert server.active_connections == server.request_accepted_at == server.request_capacity_kinds == {}
    assert connection.guard_releases == [id(connection.incoming)]
    _assert_one_available_slot(server.connection_capacity)
    _assert_one_available_slot(connection.guard_slots)


def test_concurrent_discard_and_worker_cleanup_cannot_double_release(connection: _Connection) -> None:
    server = connection.server
    server.classify_connection(connection.incoming)
    assert server.claim_request_capacity(connection.incoming, "/v1/hooks/pi")
    start = threading.Barrier(3)

    def cleanup(*, discard: bool) -> None:
        try:
            _ = start.wait(_BARRIER_TIMEOUT)
            if discard:
                server._discard_request(connection.incoming)
            else:
                server._release_request_capacity(connection.incoming)
        except BaseException as error:
            connection.errors.append(error)

    threads = [threading.Thread(target=cleanup, kwargs={"discard": discard}, daemon=True) for discard in (False, True)]
    for thread in threads:
        thread.start()
    try:
        _ = start.wait(_BARRIER_TIMEOUT)
    finally:
        for thread in threads:
            thread.join(_BARRIER_TIMEOUT)

    assert all(not thread.is_alive() for thread in threads)
    assert connection.errors == []
    assert server.active_requests == 0
    assert connection.guard_releases == [id(connection.incoming)]
    _assert_one_available_slot(server.connection_capacity)
    _assert_one_available_slot(server.request_capacity)
    _assert_one_available_slot(connection.guard_slots)
