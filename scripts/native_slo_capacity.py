"""Installed native-runtime concurrency and in-process fixture tree RSS."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Protocol

from scripts.bench_guard_native_installed_slo_runtime import _require
from scripts.native_slo_adapter import Observation, process_rss_bytes
from scripts.native_slo_baseline import steady_state_rss_baseline as _steady_state_rss_baseline
from scripts.native_slo_capacity_routes import CapacityRouteEvidence, capacity_route_evidence
from scripts.native_slo_session import AdapterSession

_MAX_CONCURRENCY = 64
_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS = 10.0
# AdapterSession transport I/O is individually bounded at five seconds. Every
# worker is prestarted before a measured wave, and this one-second envelope lets
# those transport deadlines resolve before the executor-level no-hang bound.
_CONCURRENT_WAVE_TIMEOUT_SECONDS = 6.0
_HOOK_WORKER_STABILIZATION_TIMEOUT_SECONDS = 30.0


class _ConcurrentObserver(Protocol):
    def observe(self, harness: str, event: str, size_class: str) -> Observation: ...


@dataclass(frozen=True)
class _UnattributedObserver:
    session: AdapterSession

    def observe(self, harness: str, event: str, size_class: str) -> Observation:
        return self.session.observe_unattributed(harness, event, size_class)


@dataclass(frozen=True)
class CapacityMeasurements:
    concurrent_16: list[Observation]
    concurrent_64: list[Observation]
    errors_16: int
    errors_64: int
    rss_baseline: int
    rss_peak: int
    routes_16: CapacityRouteEvidence | None = None
    routes_64: CapacityRouteEvidence | None = None
    native_overloads_16: int | None = None
    native_overloads_64: int | None = None


def _load_executor_worker(barrier: threading.Barrier) -> int:
    barrier.wait()
    return threading.get_ident()


def _prime_load_executor(executor: ThreadPoolExecutor, concurrency: int) -> int:
    """Start every bounded load-generator thread before a measured wave."""

    _require(0 < concurrency <= _MAX_CONCURRENCY, "load executor concurrency exceeds benchmark limit")
    barrier = threading.Barrier(concurrency + 1, timeout=_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS)
    futures = [executor.submit(_load_executor_worker, barrier) for _ in range(concurrency)]
    try:
        barrier.wait()
        worker_ids = {future.result(timeout=_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS) for future in futures}
    except (threading.BrokenBarrierError, TimeoutError) as error:
        executor.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError("native_installed_slo_failed: load executor prewarm timed out") from error
    _require(len(worker_ids) == concurrency, "load executor did not reach configured concurrency")
    return len(worker_ids)


def _run_concurrent(
    session: _ConcurrentObserver,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> tuple[list[Observation], int]:
    selected = tuple(routes[index % len(routes)] for index in range(concurrency))
    observations: list[Observation] = []
    errors = 0
    _require(0 < concurrency <= _MAX_CONCURRENCY, "concurrency exceeds bounded benchmark limit")
    futures = [executor.submit(session.observe, harness, event, "1k") for harness, event in selected]
    _, unfinished = wait(futures, timeout=_CONCURRENT_WAVE_TIMEOUT_SECONDS)
    if unfinished:
        # Every worker is prestarted and AdapterSession transport calls have a
        # five-second I/O bound. Fail closed without blocking executor teardown
        # if a request ever escapes that transport contract.
        for future in unfinished:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError("native_installed_slo_failed: concurrent capacity wave timed out")
    for future in futures:
        try:
            observations.append(future.result())
        except Exception:
            errors += 1
    return observations, errors


def _stabilize_ready_hook_workers(session: AdapterSession) -> int:
    """Bring every configured steady-state hook worker to ready before RSS sampling."""

    runner = session.daemon._server.hook_process_runner
    runner.notify_queued_work()
    runner.enable_full_capacity(delay_seconds=0.0, active_deferral_seconds=0.0)
    target = runner.stats()["target"]
    _require(
        isinstance(target, int) and not isinstance(target, bool) and 1 <= target <= _MAX_CONCURRENCY,
        "hook worker stabilization target was invalid",
    )
    _require(
        runner.wait_for_capacity(
            minimum_workers=target,
            timeout_seconds=_HOOK_WORKER_STABILIZATION_TIMEOUT_SECONDS,
        ),
        "hook worker stabilization did not reach the configured target",
    )
    stabilized = runner.stats()
    _require(
        stabilized["target"] == target
        and stabilized["workers"] == target
        and stabilized["ready"] == target
        and stabilized["busy"] == 0,
        "hook worker capacity changed while stabilizing",
    )
    return target


def _prewarm_ready_hook_workers(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> tuple[list[Observation], int]:
    observations, errors, evidence = _run_capacity_wave(session, routes, concurrency, executor)
    _require(evidence.qualifies(expected=concurrency, allow_overload=False), "RSS warmup route proof failed")
    stats = session.daemon._server.hook_process_runner.stats()
    _require(
        stats["target"] == concurrency
        and stats["workers"] == concurrency
        and stats["ready"] == concurrency
        and stats["busy"] == 0,
        "hook worker capacity was not steady after prewarm",
    )
    return observations, errors


def _run_capacity_wave(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> tuple[list[Observation], int, CapacityRouteEvidence]:
    before_idle = session.wait_for_capacity_bookkeeping()
    before = session.capacity_route_snapshot()
    overloads_before = session.native_overload_count()
    untracked = _UnattributedObserver(session)
    observations, errors = _run_concurrent(untracked, routes, concurrency, executor)
    after_idle = session.wait_for_capacity_bookkeeping()
    after = session.capacity_route_snapshot()
    overloads_after = session.native_overload_count()
    overloads = (
        overloads_after - overloads_before
        if (type(overloads_before) is int and type(overloads_after) is int and overloads_before >= 0)
        else None
    )
    evidence = capacity_route_evidence(
        observations,
        attempted=concurrency,
        errors=errors,
        before=before,
        after=after,
        bookkeeping_complete=before_idle and after_idle,
        native_overloads=overloads,
    )
    return observations, errors, evidence


def _measure_c16(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    include_capacity: bool,
) -> tuple[list[Observation], int, CapacityRouteEvidence | None]:
    if not include_capacity:
        return [], 0, None
    executor = ThreadPoolExecutor(max_workers=16)
    try:
        _prime_load_executor(executor, 16)
        observations, errors, evidence = _run_capacity_wave(session, routes, 16, executor)
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return observations, errors, evidence


def _measure_rss_and_c64(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    ready_workers: int,
    *,
    include_capacity: bool,
) -> tuple[int, int, list[Observation], int, CapacityRouteEvidence | None]:
    load_concurrency = _MAX_CONCURRENCY if include_capacity else ready_workers
    observations: list[Observation] = []
    errors = 0
    evidence = None
    executor = ThreadPoolExecutor(max_workers=load_concurrency)
    try:
        _prime_load_executor(executor, load_concurrency)
        rss_baseline = _steady_state_rss_baseline(
            lambda: _prewarm_ready_hook_workers(session, routes, ready_workers, executor),
            sample_capacity=session.daemon._server.hook_process_runner.stats,
            expected_warmup_count=ready_workers,
        )
        rss_peak = rss_baseline
        if include_capacity:
            observations, errors, evidence = _run_capacity_wave(session, routes, _MAX_CONCURRENCY, executor)
        rss_sample = process_rss_bytes()
        _require(type(rss_sample) is int and rss_sample > 0, "process-tree RSS peak sample was unavailable")
        rss_peak = max(rss_peak, rss_sample)
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return rss_baseline, rss_peak, observations, errors, evidence


def measure_capacity(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    include_capacity: bool,
) -> CapacityMeasurements:
    ready_workers = _stabilize_ready_hook_workers(session)
    concurrent_16, errors_16, routes_16 = _measure_c16(session, routes, include_capacity=include_capacity)
    rss_baseline, rss_peak, concurrent_64, errors_64, routes_64 = _measure_rss_and_c64(
        session,
        routes,
        ready_workers,
        include_capacity=include_capacity,
    )
    return CapacityMeasurements(
        concurrent_16=concurrent_16,
        concurrent_64=concurrent_64,
        errors_16=errors_16,
        errors_64=errors_64,
        rss_baseline=rss_baseline,
        rss_peak=rss_peak,
        routes_16=routes_16,
        routes_64=routes_64,
        native_overloads_16=routes_16.native_overloads if routes_16 else None,
        native_overloads_64=routes_64.native_overloads if routes_64 else None,
    )
