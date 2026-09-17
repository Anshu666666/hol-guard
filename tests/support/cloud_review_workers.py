"""Explicit in-memory worker readiness for local HTTP authorization tests."""

from __future__ import annotations

import threading

import pytest

from codex_plugin_scanner.guard.daemon import command_queue_worker as decision_workers
from codex_plugin_scanner.guard.review_event_wake import review_event_wake_signal
from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker as event_workers
from codex_plugin_scanner.guard.store import GuardStore


class _InMemoryThread(threading.Thread):
    """A readiness double that never starts a thread or runs a delivery loop."""

    def __init__(self, stop_event: threading.Event) -> None:
        super().__init__()
        self._fixture_stop_event = stop_event

    def is_alive(self) -> bool:
        return not self._fixture_stop_event.is_set()

    def join(self, timeout: float | None = None) -> None:
        del timeout


def install_in_memory_cloud_review_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    def decision_worker(
        _store: GuardStore, existing: decision_workers.CommandQueueWorker | None = None
    ) -> decision_workers.CommandQueueWorker:
        if existing is not None:
            return existing
        stop_event = threading.Event()
        return decision_workers.CommandQueueWorker(_InMemoryThread(stop_event), stop_event)

    def event_worker(
        store: GuardStore, existing: event_workers.CloudReviewSyncWorker | None = None
    ) -> event_workers.CloudReviewSyncWorker:
        if existing is not None:
            return existing
        stop_event = threading.Event()
        return event_workers.CloudReviewSyncWorker(
            _InMemoryThread(stop_event), stop_event, review_event_wake_signal(store.path)
        )

    monkeypatch.setattr(decision_workers, "start_command_queue_worker", decision_worker)
    monkeypatch.setattr(event_workers, "start_cloud_sync_sync_worker", event_worker)
