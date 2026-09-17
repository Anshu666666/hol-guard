"""Bounded process-tree diagnostics, outside the timed response boundary."""

from __future__ import annotations

import os
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts import native_slo_darwin_resources as darwin
from scripts.native_slo_windows_job_resources import WindowsJobCpuSnapshot

_MAX_PROCESSES = 4096
_METRICS = ("rss_bytes", "private_bytes", "cpu_seconds", "processes", "threads", "descriptors", "handles")


def _psutil() -> Any:
    try:
        import psutil
    except ImportError as error:
        raise RuntimeError("qualification resources require the pinned psutil development dependency") from error
    return psutil


@dataclass(frozen=True)
class TreeResources:
    rss_bytes: int | None
    private_bytes: int | None
    cpu_seconds: float | None
    processes: int
    threads: int | None
    descriptors: int | None
    handles: int | None = None
    unavailable: dict[str, str] = field(default_factory=dict)
    # Private collector state. Never emit process identifiers into public evidence.
    process_cpu: dict[tuple[int, float], float] = field(default_factory=dict, repr=False)
    cpu_includes_reaped: bool = False
    darwin_cpu: darwin.DarwinTreeCpu | None = field(default=None, repr=False)


def _stat(pid: int, proc: Path) -> tuple[int, int, int]:
    fields = (proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[1]), int(fields[19]), sum(int(fields[index]) for index in (11, 12, 13, 14))


def _identity(process: Any) -> tuple[int, float]:
    return process.pid, process.create_time()


def _inventory(root: Any) -> dict[tuple[int, float], Any]:
    children = root.children(recursive=True)
    if len(children) >= _MAX_PROCESSES:
        raise ValueError("process tree exceeded measurement bound")
    return {_identity(process): process for process in (root, *children)}


def sample_process_tree(pid: int | None = None, *, proc: Path = Path("/proc")) -> TreeResources | None:
    """Collect available metrics separately; denied USS is not zero memory.

    PID and creation time are checked before and after enumeration. Linux CPU
    includes live processes and their waited-for children via /proc. Darwin
    retains checked Mach counters privately, but its child rollups cannot
    distinguish ordinary reaping from the kernel's ignored-child double count.
    Other platforms retain only CPU for processes observed before they exit.
    """
    psutil = _psutil()
    process_id = os.getpid() if pid is None else pid
    darwin_failure: str | None = None
    for _ in range(2):
        try:
            root = psutil.Process(process_id)
            before = _inventory(root)
            unavailable: dict[str, str] = {}
            totals: dict[str, int | float] = {name: 0 for name in _METRICS}
            process_cpu: dict[tuple[int, float], float] = {}
            darwin_cpu = None
            darwin_before: dict[tuple[int, float], darwin.DarwinProcessCpu] = {}
            darwin_timebase = (0, 0)
            if darwin_failure is not None:
                unavailable["cpu_seconds"] = darwin_failure
            elif sys.platform == "darwin":
                try:
                    darwin_timebase = darwin.timebase()
                    darwin_before = {identity: darwin.process_cpu(identity[0]) for identity in before}
                except darwin.DarwinCpuUnavailableError as error:
                    unavailable["cpu_seconds"] = error.code
                    darwin_failure = error.code

            def read(
                metric: str,
                operation: Callable[[], int | float],
                totals: dict[str, int | float] = totals,
                unavailable: dict[str, str] = unavailable,
            ) -> None:
                try:
                    totals[metric] += operation()
                except psutil.AccessDenied:
                    unavailable[metric] = "permission_denied"
                except (AttributeError, NotImplementedError):
                    unavailable[metric] = "platform_unsupported"
                except (OSError, ValueError):
                    unavailable[metric] = "metric_unavailable"

            for identity, process in before.items():
                read("rss_bytes", lambda process=process: process.memory_info().rss)
                read("private_bytes", lambda process=process: process.memory_full_info().uss)
                read("threads", process.num_threads)
                if sys.platform == "win32":
                    read("handles", process.num_handles)
                    unavailable["descriptors"] = "platform_unsupported"
                else:
                    read("descriptors", process.num_fds)
                    unavailable["handles"] = "platform_unsupported"
                if sys.platform != "darwin":
                    try:
                        cpu = process.cpu_times()
                        process_cpu[identity] = cpu.user + cpu.system
                    except psutil.AccessDenied:
                        unavailable["cpu_seconds"] = "permission_denied"
            cpu_includes_reaped = False
            if sys.platform.startswith("linux"):
                # utime/stime + cutime/cstime include reaped children without
                # counting live descendants twice. Validate process identities
                # again before accepting this inventory and these counters.
                ticks = sum(_stat(identity[0], proc)[2] for identity in before)
                totals["cpu_seconds"] = ticks / os.sysconf("SC_CLK_TCK")
                cpu_includes_reaped = True
            else:
                totals["cpu_seconds"] = sum(process_cpu.values())
            if set(_inventory(psutil.Process(process_id))) != set(before):
                continue
            if sys.platform == "darwin" and "cpu_seconds" not in unavailable:
                try:
                    after = {identity: darwin.process_cpu(identity[0]) for identity in before}
                    darwin_cpu = darwin.stable_tree_cpu(
                        process_id, darwin_before, after, darwin_timebase, darwin.timebase()
                    )
                    if set(_inventory(psutil.Process(process_id))) != set(before):
                        raise darwin.DarwinCpuUnavailableError("darwin_cpu_inventory_changed")
                    # XNU can add ignored children twice. Endpoint inventories
                    # cannot recover an unseen parent's historical disposition.
                    # Preserve the raw witness, never publish it as measured CPU.
                    unavailable["cpu_seconds"] = darwin.REAPED_CPU_UNAVAILABLE
                except darwin.DarwinCpuUnavailableError as error:
                    unavailable["cpu_seconds"] = error.code
                    darwin_cpu = None
            return TreeResources(
                rss_bytes=None if "rss_bytes" in unavailable else int(totals["rss_bytes"]),
                private_bytes=None if "private_bytes" in unavailable else int(totals["private_bytes"]),
                cpu_seconds=None if "cpu_seconds" in unavailable else float(totals["cpu_seconds"]),
                processes=len(before),
                threads=None if "threads" in unavailable else int(totals["threads"]),
                descriptors=None if "descriptors" in unavailable else int(totals["descriptors"]),
                handles=None if "handles" in unavailable else int(totals["handles"]),
                unavailable=unavailable,
                process_cpu=process_cpu,
                cpu_includes_reaped=cpu_includes_reaped,
                darwin_cpu=darwin_cpu,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError, IndexError):
            continue
    return None


class ResourceSampler:
    """Retain bounded aggregates and observed descendant CPU, never process data."""

    def __init__(
        self,
        *,
        interval_seconds: float = 0.1,
        pid: int | None = None,
        cpu_reader: Callable[[], WindowsJobCpuSnapshot] | None = None,
    ) -> None:
        _psutil()  # A missing dependency is a setup error, not an unsupported OS.
        if not 0.01 <= interval_seconds <= 1.0:
            raise ValueError("resource sample interval out of bounds")
        self.interval = interval_seconds
        self.pid = os.getpid() if pid is None else pid
        if cpu_reader is not None and self.pid == os.getpid():
            raise ValueError("fixture job accounting cannot measure the load generator")
        self._cpu_reader = cpu_reader
        self._cpu_first: WindowsJobCpuSnapshot | None = None
        self._cpu_last: WindowsJobCpuSnapshot | None = None
        self._cpu_failed = False
        self._cpu_missing = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.samples = 0
        self.missing = 0
        self.first: TreeResources | None = None
        self.last: TreeResources | None = None
        self.peaks: dict[str, int | float] = {}
        self.metric_samples: Counter[str] = Counter()
        self.unavailable: dict[str, Counter[str]] = {}
        self._observed_cpu: dict[tuple[int, float], float] = {}
        self._initial_cpu = 0.0
        self._darwin_first: darwin.DarwinTreeCpu | None = None
        self._darwin_last: darwin.DarwinTreeCpu | None = None
        self.started = 0.0
        self.stopped = 0.0

    def _sample_job_cpu(self) -> None:
        if self._cpu_reader is None:
            return
        try:
            value = self._cpu_reader()
            if not isinstance(value, WindowsJobCpuSnapshot) or type(value.total_ticks) is not int:
                raise ValueError("job accounting snapshot invalid")
            if value.total_ticks < 0 or (self._cpu_last is not None and value.total_ticks < self._cpu_last.total_ticks):
                raise ValueError("job accounting counter regressed")
        except (OSError, ValueError, RuntimeError):
            self._cpu_failed = True
            self._cpu_missing += 1
            self.unavailable.setdefault("cpu_seconds", Counter())["job_accounting_unavailable"] += 1
            return
        self.metric_samples["cpu_seconds"] += 1
        if self._cpu_first is None:
            self._cpu_first = value
        self._cpu_last = value

    def _sample(self) -> None:
        # The job's cumulative CPU counter is independent of a racy psutil
        # inventory. Never mix its terminated-member totals with observed PID
        # CPU or allow a later successful query to erase an earlier failure.
        self._sample_job_cpu()
        value = sample_process_tree(self.pid)
        if value is None:
            self.missing += 1
            return
        self.samples += 1
        if self.first is None:
            self.first = value
            self._initial_cpu = sum(value.process_cpu.values())
        self.last = value
        for name in _METRICS:
            if name == "cpu_seconds" and self._cpu_reader is not None:
                continue
            number = getattr(value, name)
            if number is not None:
                self.metric_samples[name] += 1
                self.peaks[name] = max(self.peaks.get(name, 0), number)
        for name, reason in value.unavailable.items():
            if name == "cpu_seconds" and self._cpu_reader is not None:
                continue
            self.unavailable.setdefault(name, Counter())[reason] += 1
        if value.darwin_cpu is not None:
            try:
                if self._darwin_last is not None:
                    value.darwin_cpu.seconds_since(self._darwin_last)
                if self._darwin_first is None:
                    self._darwin_first = value.darwin_cpu
                self._darwin_last = value.darwin_cpu
            except darwin.DarwinCpuUnavailableError as error:
                self.unavailable.setdefault("cpu_seconds", Counter())[error.code] += 1
        if self._cpu_reader is not None:
            return
        for identity, cpu in value.process_cpu.items():
            if len(self._observed_cpu) >= _MAX_PROCESSES and identity not in self._observed_cpu:
                self.unavailable.setdefault("cpu_seconds", Counter())["process_history_bound"] += 1
                continue
            self._observed_cpu[identity] = max(self._observed_cpu.get(identity, 0.0), cpu)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._sample()

    def __enter__(self) -> ResourceSampler:
        self.started = time.monotonic()
        self._sample()
        self._thread = threading.Thread(target=self._run, daemon=True, name="native-slo-resources")
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                raise RuntimeError("resource sampler exceeded shutdown deadline")
        self._sample()
        self.stopped = time.monotonic()

    def report(self, *, attempted: int) -> dict[str, object]:
        elapsed = max(0.0, (self.stopped or time.monotonic()) - self.started)
        cpu = None
        job_complete = (
            self._cpu_reader is not None
            and self._cpu_first is not None
            and self._cpu_last is not None
            and not self._cpu_failed
        )
        reaped = (
            self._cpu_reader is None
            and self.first is not None
            and self.last is not None
            and self.last.cpu_includes_reaped
        )
        darwin_complete = (
            self._darwin_first is not None
            and self._darwin_last is not None
            and self.first is not None
            and self.last is not None
            and self.first.darwin_cpu is self._darwin_first
            and self.last.darwin_cpu is self._darwin_last
            and self.missing == 0
            and "cpu_seconds" not in self.unavailable
        )
        if self._darwin_first is not None:
            reaped = darwin_complete
        if job_complete:
            assert self._cpu_first is not None and self._cpu_last is not None
            # Subtract exact 100ns integers before conversion, even for a job
            # whose cumulative lifetime exceeds float's exact integer range.
            cpu = (self._cpu_last.total_ticks - self._cpu_first.total_ticks) / 10_000_000
        elif (
            self._cpu_reader is None
            and self.first is not None
            and self.last is not None
            and "cpu_seconds" not in self.unavailable
        ):
            if darwin_complete:
                assert self._darwin_first is not None and self._darwin_last is not None
                difference = self._darwin_last.seconds_since(self._darwin_first)
            elif self._darwin_first is not None:
                difference = -1.0  # Incomplete Mach accounting never falls back to guessed observed CPU.
            elif reaped and self.first.cpu_seconds is not None and self.last.cpu_seconds is not None:
                difference = self.last.cpu_seconds - self.first.cpu_seconds
            else:
                difference = sum(self._observed_cpu.values()) - self._initial_cpu
            if difference >= 0:
                cpu = difference
        required = ("rss_bytes", "private_bytes", "cpu_seconds", "processes", "threads")
        required += ("handles",) if sys.platform == "win32" else ("descriptors",)
        per_metric = {
            name: self.metric_samples[name] >= 30 and name not in self.unavailable and self.missing == 0
            for name in required
        }
        if self._cpu_reader is not None:
            per_metric["cpu_seconds"] = job_complete and self.metric_samples["cpu_seconds"] >= 30
            collector = "psutil_with_windows_job_cpu"
        elif self._darwin_first is not None or sys.platform == "darwin":
            per_metric["cpu_seconds"] = darwin_complete and self.metric_samples["cpu_seconds"] >= 30
            collector = "psutil_with_darwin_rusage_cpu"
        elif reaped:
            collector = "psutil_with_linux_proc_cpu"
        else:
            collector = "psutil_observed_descendants"
        return {
            "scope": "daemon_fixture_process_tree" if self.pid != os.getpid() else "load_generator_process_tree",
            "collector": collector,
            "samples": self.samples,
            "unavailable_samples": self.missing,
            "metric_samples": dict(self.metric_samples),
            "unavailable_metrics": {name: dict(reasons) for name, reasons in self.unavailable.items()},
            "metric_minimum_met": per_metric,
            "sample_minimum_met": all(per_metric.values()),
            "elapsed_seconds": round(elapsed, 6),
            "baseline": {name: getattr(self.first, name, None) for name in _METRICS if name != "cpu_seconds"},
            "peak": {name: self.peaks.get(name) for name in _METRICS if name != "cpu_seconds"},
            "rss_growth": ((self.peaks.get("rss_bytes", 0) / self.first.rss_bytes) - 1)
            if self.first is not None and self.first.rss_bytes
            else None,
            "cpu_seconds": cpu,
            "cpu_ms_per_attempt": round(cpu * 1000 / attempted, 6) if cpu is not None and attempted > 0 else None,
            "cpu_includes_reaped_descendants": reaped or job_complete,
            "short_exited_descendants_cpu_complete": reaped or job_complete,
            "cpu_accounting_scope": "explicit_fixture_job" if self._cpu_reader is not None else "observed_process_tree",
            "cpu_unavailable_samples": self._cpu_missing
            if self._cpu_reader is not None
            else (
                self.missing + sum(self.unavailable.get("cpu_seconds", {}).values())
                if collector == "psutil_with_darwin_rusage_cpu"
                else self.missing
            ),
            "includes_load_generator": self.pid == os.getpid(),
            "fixture_control_overhead_included": self.pid != os.getpid(),
        }
