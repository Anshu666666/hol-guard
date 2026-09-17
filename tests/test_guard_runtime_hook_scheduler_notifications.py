from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler


@pytest.mark.parametrize("active_limit", [0, 1])
def test_spurious_wakeup_does_not_notify_other_unchanged_waiters(
    active_limit: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = RuntimeHookScheduler(active_limit=active_limit)
    active = None
    if active_limit:
        active = scheduler.acquire(
            harness="pi",
            client_key="active",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 5,
        ).permit
        assert active is not None
    condition = scheduler._condition
    original_wait = condition.wait
    original_notify = condition.notify_all
    first_wait = threading.Event()
    second_wait = threading.Event()
    wait_count = 0
    notification_count = 0

    def observed_wait(timeout: float | None = None) -> bool:
        nonlocal wait_count
        wait_count += 1
        (first_wait if wait_count == 1 else second_wait).set()
        return original_wait(timeout)

    def observed_notify() -> None:
        nonlocal notification_count
        notification_count += 1
        original_notify()

    monkeypatch.setattr(condition, "wait", observed_wait)
    monkeypatch.setattr(condition, "notify_all", observed_notify)
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="queued",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 5,
        )
        try:
            assert first_wait.wait(timeout=1)
            with condition:
                notification_count = 0
                original_notify()  # One external/spurious wake, without a state change.
            assert second_wait.wait(timeout=1)
            with condition:
                assert notification_count == 0
                assert scheduler.stats()["queued"] == 1
                assert not waiting.done()
                scheduler.set_active_limit(active_limit)
                assert notification_count == 0
        finally:
            if active is not None:
                active.release()
            else:
                scheduler.set_active_limit(1)
            admitted = waiting.result(timeout=1)
            assert admitted.permit is not None
            admitted.permit.release()
    assert scheduler.stats()["completed"] == active_limit + 1
    assert scheduler.stats()["retained_bytes"] == 0


def test_permit_release_wakes_byte_waiter_without_queued_reviews(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = RuntimeHookScheduler(active_limit=1, retained_bytes_limit=1)
    active = scheduler.acquire(
        harness="pi",
        client_key="active",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 5,
    ).permit
    assert active is not None
    waiting_for_bytes = threading.Event()
    original_wait = scheduler._condition.wait

    def observed_wait(timeout: float | None = None) -> bool:
        waiting_for_bytes.set()
        return original_wait(timeout)

    monkeypatch.setattr(scheduler._condition, "wait", observed_wait)
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.reserve_bytes,
            payload_bytes=1,
            deadline=time.monotonic() + 5,
        )
        assert waiting_for_bytes.wait(timeout=1)
        assert scheduler.stats()["queued"] == 0
        active.release()
        reservation, reason = waiting.result(timeout=1)
    assert reason is None
    assert reservation is not None
    reservation.release()
    assert scheduler.stats()["retained_bytes"] == 0


def test_cancelled_waiter_releases_its_bytes_with_capacity_still_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = RuntimeHookScheduler(active_limit=0)
    cancellation = threading.Event()
    started_waiting = threading.Event()
    original_wait = scheduler._condition.wait

    def observed_wait(timeout: float | None = None) -> bool:
        started_waiting.set()
        return original_wait(timeout)

    monkeypatch.setattr(scheduler._condition, "wait", observed_wait)
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="cancelled",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 5,
            cancellation=cancellation,
        )
        assert started_waiting.wait(timeout=1)
        cancellation.set()
        admission = waiting.result(timeout=1)
    assert admission.permit is None
    assert admission.reason_code == "daemon_hook_deadline_exhausted"
    stats = scheduler.stats()
    assert stats["cancelled"] == 1
    assert stats["queued"] == stats["retained_bytes"] == stats["active_limit"] == 0
