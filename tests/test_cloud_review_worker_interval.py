"""HGP-163: worker interval configuration cannot hot-loop."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.cloud_review_sync_worker import (
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)
from codex_plugin_scanner.guard.runtime.cloud_review_worker_interval import (
    DEFAULT_SAFETY_POLL_SECONDS,
    MIN_INTERVAL_SECONDS,
    cloud_review_worker_intervals,
    normalized_cloud_review_interval,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("value", ["", "nope", "0", "-1", "nan", "inf", "-inf", None, True])
def test_malformed_intervals_fall_back(value: object) -> None:
    result = normalized_cloud_review_interval(value, default=DEFAULT_SAFETY_POLL_SECONDS, maximum=3600)
    assert result >= MIN_INTERVAL_SECONDS
    assert result == DEFAULT_SAFETY_POLL_SECONDS or result == MIN_INTERVAL_SECONDS


def test_valid_interval_is_clamped() -> None:
    poll, backoff, base = cloud_review_worker_intervals(
        poll_interval="2.5",
        error_backoff="10",
        error_backoff_base="1",
    )
    assert poll == 2.5
    assert backoff == 10.0
    assert base == 1.0
    huge, _, _ = cloud_review_worker_intervals(poll_interval="999999")
    assert huge == 3600.0


def test_bad_env_does_not_kill_startup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "nan")
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", "-5")
    worker = start_cloud_sync_sync_worker(GuardStore(tmp_path / "guard-home"))
    try:
        assert worker is not None
        assert worker.thread.is_alive()
        worker.stop_event.set()
        worker.wake_signal.notify()
        worker.thread.join(timeout=2.0)
        assert not worker.thread.is_alive()
    finally:
        stop_cloud_sync_sync_worker(worker)
