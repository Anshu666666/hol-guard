"""Resource probes must not delay a completed foreground hook review."""

from __future__ import annotations

import threading

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner


@pytest.mark.parametrize("queued", [0, 7])
def test_load_observation_wakes_supervisor_without_waiting_for_resource_probe(queued: int) -> None:
    probe_entered = threading.Event()
    release_probe = threading.Event()
    observations_returned = threading.Event()
    probe_threads: list[str] = []

    def rss_bytes() -> int:
        probe_threads.append(threading.current_thread().name)
        probe_entered.set()
        assert release_probe.wait(timeout=5)
        return 0

    runner = HookProcessRunner(rss_bytes_provider=rss_bytes, cpu_ratio_provider=lambda: 0.0)
    # Run the real supervisor without provisioning evaluator processes. Its
    # first refresh remains inside the controlled resource probe until cleanup.
    with runner._state_lock:
        runner._started = True
        runner._generation = 1
        runner._capacity_target = 0
    supervisor = threading.Thread(target=runner._supervise_capacity, args=(1,), name="capacity-supervisor")

    def observe() -> None:
        runner.observe_load(queue_p95_ms=250, queued=queued)
        runner.observe_load(queue_p95_ms=300, queued=queued)
        observations_returned.set()

    observer = threading.Thread(target=observe, name="foreground-hook")
    supervisor.start()
    try:
        observer.start()
        assert probe_entered.wait(timeout=2)
        assert observations_returned.wait(timeout=1), "foreground review waited for a resource probe"
        assert not release_probe.is_set()
        assert probe_threads == ["capacity-supervisor"]
        adaptive = runner._adaptive_capacity
        assert adaptive is not None
        with adaptive._lock:
            assert adaptive._queued == queued
            assert adaptive._queue_p95_seconds == 0.3
    finally:
        with runner._state_lock:
            runner._closed = True
        release_probe.set()
        runner._recovery_event.set()
        observer.join(timeout=2)
        supervisor.join(timeout=2)
    assert not observer.is_alive()
    assert not supervisor.is_alive()
