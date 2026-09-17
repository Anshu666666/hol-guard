"""Private pipe barriers for warm MCP process-tree observations on Linux.

The worker begins after its first validated call and ends before returning its
last call to run_session, while the child is still alive. These barriers belong
only to resource mode; they never supply headline latency samples.
"""

from __future__ import annotations

import math
import os
import select
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from scripts.native_slo_resources import ResourceSampler, _psutil

_MAX_FRAME = 1024
_ACK_SECONDS = 5.0
_REQUIRED = ("rss_bytes", "private_bytes", "cpu_seconds", "processes", "threads", "descriptors")


class ResourceHandshakeError(RuntimeError):
    """Finite private-protocol failure; no process identifiers in the message."""


@dataclass
class ResourcePipes:
    parent_request_fd: int
    parent_ack_fd: int
    worker_request_fd: int
    worker_ack_fd: int

    @classmethod
    def create(cls) -> ResourcePipes:
        request_read, request_write = os.pipe()
        try:
            ack_read, ack_write = os.pipe()
        except BaseException:
            os.close(request_read)
            os.close(request_write)
            raise
        return cls(request_read, ack_write, request_write, ack_read)

    @property
    def worker_fds(self) -> tuple[int, int]:
        return self.worker_request_fd, self.worker_ack_fd

    def close_worker_ends(self) -> None:
        """Parent calls this immediately after Popen(pass_fds=worker_fds)."""
        self._close("worker_request_fd", "worker_ack_fd")

    def _close(self, *names: str) -> None:
        for name in names:
            descriptor = getattr(self, name)
            if descriptor >= 0:
                setattr(self, name, -1)
                os.close(descriptor)

    def close(self) -> None:
        """Call after the observer has stopped and the worker is contained."""
        self._close("parent_request_fd", "parent_ack_fd", "worker_request_fd", "worker_ack_fd")


def _ready(fd: int, *, write: bool, deadline: float, stop: threading.Event | None = None) -> None:
    while True:
        if stop is not None and stop.is_set():
            raise ResourceHandshakeError("observer_aborted")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ResourceHandshakeError("protocol_deadline")
        readable, writable, _ = select.select([] if write else [fd], [fd] if write else [], [], min(0.1, remaining))
        if readable or writable:
            return


def _read_frame(fd: int, deadline: float, stop: threading.Event | None = None) -> bytes:
    data = bytearray()
    while True:
        _ready(fd, write=False, deadline=deadline, stop=stop)
        chunk = os.read(fd, _MAX_FRAME + 1 - len(data))
        if not chunk:
            raise ResourceHandshakeError("protocol_eof")
        data.extend(chunk)
        if len(data) > _MAX_FRAME:
            raise ResourceHandshakeError("protocol_byte_bound")
        if b"\n" in data:
            if data.count(b"\n") != 1 or not data.endswith(b"\n"):
                raise ResourceHandshakeError("protocol_frame_invalid")
            return bytes(data)


def _write_frame(fd: int, value: bytes, deadline: float) -> None:
    if not 1 <= len(value) <= _MAX_FRAME:
        raise ResourceHandshakeError("protocol_byte_bound")
    _ready(fd, write=True, deadline=deadline)
    # One writer per pipe, frames below POSIX PIPE_BUF, and one outstanding
    # request. Never interleave partial messages or queue unbounded requests.
    if os.write(fd, value) != len(value):
        raise ResourceHandshakeError("protocol_short_write")


class WorkerResourceHandshake:
    def __init__(self, request_fd: int, ack_fd: int) -> None:
        self.request_fd, self.ack_fd = request_fd, ack_fd
        self._index = 0
        self._active = False
        self._failed = False

    def _exchange(self, index: int, operation: str) -> None:
        if self._failed:
            raise ResourceHandshakeError("worker_protocol_poisoned")
        deadline = time.monotonic() + _ACK_SECONDS
        try:
            _write_frame(self.request_fd, f"{index}:{operation}\n".encode("ascii"), deadline)
            if _read_frame(self.ack_fd, deadline) != f"{index}:{operation}:ok\n".encode("ascii"):
                raise ResourceHandshakeError("ack_invalid")
        except (OSError, ValueError, ResourceHandshakeError):
            self._failed = True
            raise

    def begin(self, trace_index: int) -> None:
        if type(trace_index) is not int or trace_index != self._index or self._active:
            raise ResourceHandshakeError("worker_sequence_invalid")
        self._exchange(trace_index, "begin")
        self._active = True

    def end(self, trace_index: int, *, failed: bool = False) -> None:
        if type(trace_index) is not int or trace_index != self._index or not self._active:
            raise ResourceHandshakeError("worker_sequence_invalid")
        self._exchange(trace_index, "failed" if failed else "end")
        self._active = False
        self._index += 1


def _membership(pid: int) -> frozenset[tuple[int, float]]:
    root = _psutil().Process(pid)
    processes = [root, *root.children(recursive=True)]
    if len(processes) != 2:
        raise ResourceHandshakeError("process_membership_invalid")
    identities = frozenset((process.pid, process.create_time()) for process in processes)
    if len(identities) != 2 or not all(math.isfinite(created) and created > 0 for _, created in identities):
        raise ResourceHandshakeError("process_identity_invalid")
    return identities


def _complete(report: dict[str, Any]) -> bool:
    counts = report.get("metric_samples", {})
    unavailable = report.get("unavailable_metrics", {})
    return (
        report.get("sample_minimum_met") is True
        and report.get("unavailable_samples") == 0
        and all(type(counts.get(name)) is int and counts[name] >= 30 and name not in unavailable for name in _REQUIRED)
        and report.get("baseline", {}).get("processes") == 2
        and report.get("peak", {}).get("processes") == 2
        and report.get("cpu_seconds") is not None
        and report.get("short_exited_descendants_cpu_complete") is True
    )


class ParentResourceObserver:
    """One bounded observer for fixed ordered traces; no retry-until-complete."""

    def __init__(
        self,
        pid: int,
        request_fd: int,
        ack_fd: int,
        *,
        trace_count: int,
        warm_attempts: int = 99,
        total_timeout: float = 180.0,
    ) -> None:
        if not 1 <= trace_count <= 16 or not 1 <= warm_attempts <= 99 or not 0 < total_timeout <= 180:
            raise ValueError("resource observer bounds invalid")
        self.pid = pid
        self.trace_count, self.warm_attempts = trace_count, warm_attempts
        self._root_created = _psutil().Process(pid).create_time()
        self.request_fd = os.dup(request_fd)
        try:
            self.ack_fd = os.dup(ack_fd)
        except BaseException:
            os.close(self.request_fd)
            raise
        self._timeout = total_timeout
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._reports: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.failure: str | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise ResourceHandshakeError("observer_already_started")
        self._thread = threading.Thread(target=self._run, daemon=True, name="mcp-warm-resources")
        try:
            self._thread.start()
        except BaseException:
            os.close(self.request_fd)
            os.close(self.ack_fd)
            raise

    def _identity(self) -> frozenset[tuple[int, float]]:
        membership = _membership(self.pid)
        if (self.pid, self._root_created) not in membership:
            raise ResourceHandshakeError("root_identity_changed")
        return membership

    def _append(self, index: int, sampler: ResourceSampler | None, failure: str | None, identity: bool) -> None:
        attempted = self.warm_attempts if failure is None else None
        try:
            report = sampler.report(attempted=attempted or 0) if sampler is not None else None
        except Exception:
            report = None
            failure = failure or "observer_report_failed"
        if report is not None:
            report["scope"] = "mcp_proxy_worker_and_descendants"
        if failure is None and (report is None or not _complete(report)):
            failure = "resource_samples_incomplete"
        row = {
            "trace_index": index,
            "status": "complete" if failure is None else "incomplete",
            "failure": failure,
            "identity_verified": identity,
            "expected_warm_attempts": self.warm_attempts,
            "warm_attempts": attempted,
            "resources": report,
        }
        with self._lock:
            self._reports.append(row)

    def _run(self) -> None:
        deadline = time.monotonic() + self._timeout
        sampler: ResourceSampler | None = None
        sampler_closed = False
        index = 0
        try:
            for index in range(self.trace_count):
                frame = _read_frame(self.request_fd, deadline, self._stop)
                if frame != f"{index}:begin\n".encode("ascii"):
                    raise ResourceHandshakeError("observer_sequence_invalid")
                before = self._identity()
                sampler = ResourceSampler(interval_seconds=0.01, pid=self.pid)
                sampler_closed = False
                sampler.__enter__()
                _write_frame(self.ack_fd, f"{index}:begin:ok\n".encode("ascii"), time.monotonic() + _ACK_SECONDS)
                frame = _read_frame(self.request_fd, deadline, self._stop)
                if frame not in (f"{index}:end\n".encode("ascii"), f"{index}:failed\n".encode("ascii")):
                    raise ResourceHandshakeError("observer_sequence_invalid")
                sampler.__exit__(None, None, None)
                sampler_closed = True
                same_identity = self._identity() == before
                failed = frame.endswith(b":failed\n")
                failure = "worker_trace_failed" if failed else None
                if not same_identity:
                    failure = "process_identity_changed"
                self._append(index, sampler, failure, same_identity)
                sampler = None
                operation = "failed" if failed else "end"
                # ACK records completion of the barrier, including an explicitly
                # incomplete report. It cannot make that resource report pass.
                _write_frame(self.ack_fd, f"{index}:{operation}:ok\n".encode("ascii"), time.monotonic() + _ACK_SECONDS)
        except Exception as error:
            self.failure = str(error) if isinstance(error, ResourceHandshakeError) else "observer_operation_failed"
            if sampler is not None and not sampler_closed:
                try:
                    sampler.__exit__(None, None, None)
                except Exception:
                    self.failure = "observer_cleanup_failed"
            with self._lock:
                recorded = bool(self._reports and self._reports[-1]["trace_index"] == index)
            if not recorded:
                self._append(index, sampler, self.failure, False)
            with suppress(OSError, ResourceHandshakeError):
                _write_frame(self.ack_fd, f"{index}:error\n".encode("ascii"), time.monotonic() + _ACK_SECONDS)
        finally:
            # These are owned duplicates. A timed-out controller can close its
            # originals without making a still-unwinding thread use reused FDs.
            os.close(self.request_fd)
            os.close(self.ack_fd)

    def abort(self) -> None:
        """Wake protocol waits; controller still owns worker quarantine/reaping."""
        self._stop.set()

    @property
    def reports(self) -> list[dict[str, Any]]:
        """Already retained windows remain available even after finish fails."""
        with self._lock:
            return list(self._reports)

    def finish(self, *, timeout: float = 5.0) -> list[dict[str, Any]]:
        if not 0 < timeout <= 5.0 or self._thread is None:
            raise ValueError("resource observer finish invalid")
        self._thread.join(timeout)
        if self._thread.is_alive():
            self.abort()
            self.failure = "observer_shutdown_deadline"
            raise ResourceHandshakeError("observer_shutdown_deadline")
        return self.reports
