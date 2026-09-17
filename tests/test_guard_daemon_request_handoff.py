# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
"""Capacity handoffs retain bounded admission and the original socket deadline."""

from __future__ import annotations

import http.client
import json
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server
from tests.test_guard_daemon_adversarial_transport import _running_daemon


class ObservedSemaphore(threading.BoundedSemaphore):
    def __init__(self, limit: int) -> None:
        super().__init__(limit)
        self.wait_started: threading.Event = threading.Event()
        self.waits: list[float] = []

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:  # pyright: ignore[reportImplicitOverride]
        if timeout is not None:
            self.waits.append(timeout)
            self.wait_started.set()
        return super().acquire(blocking, timeout)


def test_challenge_hook_handoff_waits_for_previous_response_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response_sent = threading.Event()
    release_previous = threading.Event()
    original_write = daemon_server._GuardDaemonHandler._write_json

    def pause_after_response(
        self: daemon_server._GuardDaemonHandler,
        payload: dict[str, object],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        original_write(self, payload, status=status, extra_headers=extra_headers)
        if self.path == "/v1/operations/previous":
            response_sent.set()
            assert release_previous.wait(2)

    monkeypatch.setattr(daemon_server._GuardDaemonHandler, "_write_json", pause_after_response)
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        capacity = ObservedSemaphore(1)
        daemon._server.request_capacity = capacity
        daemon._server.request_capacity_limit = 1
        previous = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=2)
        next_request = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=2)
        try:
            previous.request("GET", "/v1/operations/previous", headers={"X-Guard-Token": daemon._server.auth_token})
            response = previous.getresponse()
            assert response.status == 404
            _ = response.read()
            assert response_sent.wait(1)
            # This is the production two-request connection proof, not a
            # replacement socket or synthetic admission success.
            next_request.request(
                "POST",
                "/v1/daemon/identity-challenge",
                body=json.dumps(
                    {
                        "protocol_version": 1,
                        "nonce": secrets.token_hex(32),
                        "state_id": daemon._server.runtime_session_id,
                        "hook_event": "PostToolUse",
                    }
                ),
                headers={"Content-Type": "application/json", "Connection": "keep-alive"},
            )
            challenge = next_request.getresponse()
            assert challenge.status == 200
            _ = challenge.read()
            with ThreadPoolExecutor(max_workers=1) as executor:

                def finish_request() -> int:
                    next_request.request(
                        "GET",
                        "/v1/operations/next",
                        headers={"Connection": "close", "X-Guard-Token": daemon._server.auth_token},
                    )
                    result = next_request.getresponse()
                    _ = result.read()
                    return result.status

                pending = executor.submit(finish_request)
                try:
                    assert capacity.wait_started.wait(1), "general capacity rejected without a bounded handoff"
                finally:
                    release_previous.set()
                assert pending.result(timeout=1) == 404
            assert len(capacity.waits) == 1
            assert 0 < capacity.waits[0] <= daemon_server._DAEMON_REQUEST_ADMISSION_WAIT_SECONDS
            assert daemon._server.rejected_requests == 0
        finally:
            release_previous.set()
            previous.close()
            next_request.close()


def _capacity_server(
    request: socket.socket, *, age: float
) -> tuple[daemon_server._GuardDaemonHTTPServer, ObservedSemaphore]:
    server = object.__new__(daemon_server._GuardDaemonHTTPServer)
    server.request_capacity_lock = threading.Lock()
    server.request_capacity_kinds = {}
    server.request_accepted_at = {id(request): time.monotonic() - age}
    server.rejected_requests = 0
    capacity = ObservedSemaphore(1)
    assert capacity.acquire(blocking=False)
    server.request_capacity = capacity
    return server, capacity


def test_saturated_handoff_cannot_reset_the_original_socket_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    # Make the configured wait much longer than the socket's remaining budget:
    # only the original acceptance timestamp may bound this attempt.
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_ADMISSION_WAIT_SECONDS", 30)
    with socket.socket() as request:
        server, capacity = _capacity_server(request, age=daemon_server._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS - 0.02)
        original = server.request_accepted_at[id(request)]
        assert not server.claim_request_capacity(request, "/v1/hooks/pi")
        assert server.request_accepted_at[id(request)] == original
        assert len(capacity.waits) == 1
        assert 0 < capacity.waits[0] <= 0.02
        assert server.rejected_requests == 1
        capacity.release()
        assert capacity.acquire(blocking=False), "rejected handoff leaked a permit"


def test_expired_socket_does_not_wait_or_consume_capacity() -> None:
    with socket.socket() as request:
        server, capacity = _capacity_server(request, age=daemon_server._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS + 1)
        assert not server.claim_request_capacity(request, "/v1/hooks/pi")
        assert capacity.waits == []
        assert server.rejected_requests == 1
        assert server.request_capacity_kinds == {}


def test_saturated_general_handoff_leaves_critical_capacity_available() -> None:
    with socket.socket() as request, socket.socket() as health:
        server, capacity = _capacity_server(request, age=0)
        server.critical_request_capacity = threading.BoundedSemaphore(1)
        server.request_accepted_at[id(health)] = time.monotonic()
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(server.claim_request_capacity, request, "/v1/hooks/pi")
            assert capacity.wait_started.wait(1)
            assert server.claim_request_capacity(health, "/healthz")
            assert pending.result(timeout=1) is False
        assert server.request_capacity_kinds == {id(health): "critical"}
        assert server.rejected_requests == 1
        assert capacity.waits == [pytest.approx(daemon_server._DAEMON_REQUEST_ADMISSION_WAIT_SECONDS)]
