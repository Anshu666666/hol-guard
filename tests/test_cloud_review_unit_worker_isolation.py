"""Non-worker unit fixtures must also cover the extracted refresh starters."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import command_queue_worker as queue_worker_module
from codex_plugin_scanner.guard.daemon.command_queue_worker import refresh_command_queue_worker
from codex_plugin_scanner.guard.runtime.cloud_review_sync_worker import refresh_cloud_review_sync_worker
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from tests.guard_exact_cloud_review_support import connected_exact_review_store


@pytest.mark.parametrize("worker_kind", ["decision", "events"])
def test_default_unit_fixture_prevents_worker_threads_during_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, worker_kind: str
) -> None:
    attempts: list[None] = []
    # Intercept before constructing the store or invoking either real helper.
    # The red baseline may create a Thread object, but can never start it.
    monkeypatch.setattr(threading.Thread, "start", lambda _thread: attempts.append(None))
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)

    refresh = refresh_command_queue_worker if worker_kind == "decision" else refresh_cloud_review_sync_worker
    _worker, ready = refresh(store, None, shutting_down=False)

    assert attempts == []
    assert ready is False


@pytest.mark.daemon_service_workers
def test_stopped_worker_is_retained_until_its_previous_thread_joins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    old_release = threading.Event()
    old_thread = threading.Thread(target=old_release.wait)
    old_thread.start()
    old_stop = threading.Event()
    old_stop.set()
    old_worker = queue_worker_module.CommandQueueWorker(thread=old_thread, stop_event=old_stop)
    monkeypatch.setattr(queue_worker_module, "command_queue_enabled", lambda _store: True)
    monkeypatch.setattr(queue_worker_module, "_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS", 0.01)
    try:
        assert queue_worker_module.start_command_queue_worker(store, old_worker) is old_worker
    finally:
        old_release.set()
        old_thread.join(timeout=1)
