"""The acceptance driver must offer the workload its manifest actually declares."""

from __future__ import annotations

import threading
from collections import Counter

import pytest

from tests.guard_daemon_acceptance_fixtures import (
    ClientSpec,
    _http_status_failure,
    _run_client_requests,
)


def test_clients_keep_their_own_slots_and_make_progress_together() -> None:
    clients: list[ClientSpec] = [
        {"harness": "pi", "client": "slow", "requests": 4, "concurrency": 2},
        {"harness": "codex", "client": "fast", "requests": 4, "concurrency": 2},
    ]
    initial_wave = threading.Barrier(4, timeout=2)
    fast_finished = threading.Event()
    lock = threading.Lock()
    active: Counter[str] = Counter()
    peak: Counter[str] = Counter()
    completed: Counter[str] = Counter()
    calls: Counter[tuple[str, str, int]] = Counter()
    total_peak = 0

    def review(harness: str, client: str, index: int) -> None:
        nonlocal total_peak
        with lock:
            active[client] += 1
            peak[client] = max(peak[client], active[client])
            total_peak = max(total_peak, sum(active.values()))
            calls[harness, client, index] += 1
        try:
            if index < 2:
                initial_wave.wait()
            if client == "slow":
                assert fast_finished.wait(timeout=2), "fast client could not use its declared slots"
            with lock:
                completed[client] += 1
                if completed["fast"] == 4:
                    fast_finished.set()
        finally:
            with lock:
                active[client] -= 1

    _run_client_requests(clients, review, timeout_seconds=5)

    assert completed == {"slow": 4, "fast": 4}
    assert peak == {"slow": 2, "fast": 2}
    assert total_peak == 4
    assert calls == {
        (client["harness"], client["client"], index): 1 for client in clients for index in range(client["requests"])
    }


def test_failed_review_is_not_retried() -> None:
    clients: list[ClientSpec] = [{"harness": "pi", "client": "client", "requests": 3, "concurrency": 1}]
    calls: list[int] = []

    def review(_harness: str, _client: str, index: int) -> None:
        calls.append(index)
        if index == 0:
            raise RuntimeError("synthetic hook failure")

    with pytest.raises(RuntimeError, match="synthetic hook failure"):
        _run_client_requests(clients, review, timeout_seconds=1)
    assert calls == [0, 1, 2]


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b'{"error":"daemon_overloaded","message":"private content"}', "daemon_overloaded"),
        (b'{"error":"daemon_identity_unavailable"}', "daemon_identity_unavailable"),
        (b'{"error":"request_body_timeout"}', "request_body_timeout"),
        (b'{"error":"incomplete_request_body"}', "incomplete_request_body"),
        (b"<!DOCTYPE HTML><html><p>Message: Guard daemon request capacity reached.</p></html>", "request_capacity"),
        (b'{"error":"private content"}', "unclassified"),
        (b'{"error":"Guard daemon request capacity reached"}', "unclassified"),
        (b'{"error":["private content"]}', "unclassified"),
        (b"\xff", "unclassified"),
        (b"x" * 4097, "oversized_error"),
    ],
)
def test_http_failure_diagnostic_is_bounded_and_names_only_known_boundaries(body: bytes, expected: str) -> None:
    assert str(_http_status_failure("hook", 503, body)) == f"hook-status-503:{expected}"
